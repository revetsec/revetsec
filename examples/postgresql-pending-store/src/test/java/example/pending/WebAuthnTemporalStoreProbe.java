/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package example.pending;

import com.revetsec.StoreTimeObservation;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.webauthn.WebAuthnStoreCommitReceipt;
import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.NotThreadSafe;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/** Native SPI mechanics with synthetic structural records; genuine engine flows are separate. */
@NotThreadSafe
public final class WebAuthnTemporalStoreProbe {
	private static final String NS="fixture_wa_temporal",RP="login.example.com";
	private static final Duration BUDGET=Duration.ofSeconds(5);
	private static final WebAuthnStoreKey ROOT=WebAuthnStoreKey.forNamespaceClock(NS,RP);
	private static final AtomicReference<Instant> TIME=new AtomicReference<>(Instant.ofEpochSecond(1700000010));
	private static final AtomicInteger SAMPLES=new AtomicInteger();
	
	private WebAuthnTemporalStoreProbe() {}
	private static @NonNull StoreTimeObservation point() {return StoreTimeObservation.Healthy.fromObservation(WebAuthnFixtureAuthority.admission(NS),WebAuthnFixtureAuthority.clockGeneration(NS),TIME.get(),Duration.ZERO);}
	private static @NonNull PostgresqlWebAuthnStore store(PostgresqlWebAuthnStore.@NonNull ConnectionSource source,PostgresqlWebAuthnStore.@NonNull Authority authority){return new PostgresqlWebAuthnStore(NS,WebAuthnFixtureAuthority.physical(NS),source,4096,authority);}
	private static @NonNull PostgresqlWebAuthnStore ordinary(){return store(WebAuthnStoreProbe::connection,(scope,left)->{SAMPLES.incrementAndGet();return point();});}
	private static @NonNull WebAuthnStoreKey account(@NonNull String name){return WebAuthnStoreKey.forCredential(NS,RP,name.getBytes(StandardCharsets.UTF_8));}
	private static @NonNull WebAuthnStoreSnapshot snapshot(@NonNull PostgresqlWebAuthnStore store,@NonNull WebAuthnStoreKey key){
		WebAuthnStoreReadResult result=store.read(Set.of(ROOT,key),BUDGET);
		if(!(result instanceof WebAuthnStoreReadResult.Available available))throw new IllegalStateException("Temporal fixture read unavailable");return available.getSnapshot();
	}
	private static @NonNull StoreTemporalCondition condition(@NonNull WebAuthnStoreSnapshot snapshot,@NonNull Instant floor,@NonNull Instant end){return StoreTimeAccess.get().fromObservation((StoreTimeObservation.Healthy)snapshot.getTimeObservation(),floor,end);}
	private static @NonNull WebAuthnStoreWrite insert(@NonNull WebAuthnStoreSnapshot snapshot,@NonNull WebAuthnStoreKey key,@NonNull Instant floor,@NonNull Instant end){return WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,List.of(WebAuthnStoreWrite.Mutation.insert(key,new byte[]{42})),condition(snapshot,floor,end));}
	private static void check(@NonNull String label,boolean value){if(!value)throw new AssertionError(label);System.out.println("PASS "+label);}
	private static long total(@NonNull String column,@NonNull String table)throws Exception{
		try(Connection c=WebAuthnStoreProbe.connection(BUDGET);PreparedStatement s=c.prepareStatement("SELECT coalesce(sum("+column+"),0) FROM "+table+" WHERE namespace=?")){
			s.setString(1,table.equals("webauthn_store_entry")?NS:WebAuthnFixtureAuthority.physical(NS));try(ResultSet r=s.executeQuery()){r.next();return r.getLong(1);}
		}
	}
	private static @NonNull Connection identified(@NonNull Duration remaining,@NonNull AtomicInteger pid)throws java.sql.SQLException{
		Connection connection=WebAuthnStoreProbe.connection(remaining);try(Statement statement=connection.createStatement();ResultSet result=statement.executeQuery("SELECT pg_backend_pid()")){result.next();pid.set(result.getInt(1));}return connection;
	}
	private static @NonNull Connection pauseAdmission(@NonNull Connection physical,@NonNull CountDownLatch held,@NonNull CountDownLatch release){
		return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
			try{
				Object result=method.invoke(physical,args);
				if(method.getName().equals("prepareStatement") && args!=null && args.length>0 && args[0].equals("SELECT pg_advisory_xact_lock(?, ?)")){
					PreparedStatement statement=(PreparedStatement)result;
					return Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),new Class<?>[]{PreparedStatement.class},(statementProxy,statementMethod,statementArgs)->{
						try{Object value=statementMethod.invoke(statement,statementArgs);if(statementMethod.getName().equals("execute")){held.countDown();if(!release.await(4,TimeUnit.SECONDS))throw new java.sql.SQLException("Initialization admission pause timed out");}return value;}catch(InvocationTargetException failure){throw failure.getCause();}
					});
				}
				return result;
			}catch(InvocationTargetException failure){throw failure.getCause();}
		});
	}
	private static void initialized(@NonNull PostgresqlWebAuthnStore store)throws Exception{
		WebAuthnStoreReadResult.Available read=(WebAuthnStoreReadResult.Available)store.read(Set.of(ROOT),BUDGET);WebAuthnStoreSnapshot snapshot=read.getSnapshot();
		WebAuthnStoreWrite write=WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,List.of(WebAuthnStoreWrite.Mutation.insert(ROOT,new byte[]{42})),condition(snapshot,TIME.get(),TIME.get().plusSeconds(60)));
		CountDownLatch held=new CountDownLatch(1),release=new CountDownLatch(1);AtomicInteger initializerPid=new AtomicInteger(),readerPid=new AtomicInteger();ExecutorService pool=Executors.newFixedThreadPool(2);
		try{
			PostgresqlWebAuthnStore initializer=store(left->pauseAdmission(identified(left,initializerPid),held,release),(physical,left)->point());
			Future<WebAuthnStoreCommitReceipt> pending=pool.submit(()->initializer.compareAndCommit(write,BUDGET));
			check("pg-webauthn-initialization-exclusive-admission-reached",held.await(3,TimeUnit.SECONDS));
			PostgresqlWebAuthnStore reader=store(left->identified(left,readerPid),(physical,left)->point());Future<WebAuthnStoreReadResult> ordinaryRead=pool.submit(()->reader.read(Set.of(ROOT),BUDGET));
			WebAuthnPgLocks.Admission admission=WebAuthnPgLocks.admission(WebAuthnPgScope.from("WEBAUTHN",WebAuthnFixtureAuthority.physical(NS)));long deadline=System.nanoTime()+Duration.ofSeconds(3).toNanos();
			try(Connection observer=WebAuthnStoreProbe.connection(BUDGET);PreparedStatement statement=observer.prepareStatement("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objsubid=2 AND classid=?::oid AND objid=?::oid AND pid=? AND mode='ExclusiveLock' AND granted),EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objsubid=2 AND classid=?::oid AND objid=?::oid AND pid=? AND mode='ShareLock' AND NOT granted)")){
				boolean blocked=false;while(deadline-System.nanoTime()>0){statement.setLong(1,Integer.toUnsignedLong(admission.getFirst()));statement.setLong(2,Integer.toUnsignedLong(admission.getSecond()));statement.setInt(3,initializerPid.get());statement.setLong(4,Integer.toUnsignedLong(admission.getFirst()));statement.setLong(5,Integer.toUnsignedLong(admission.getSecond()));statement.setInt(6,readerPid.get());try(ResultSet result=statement.executeQuery()){result.next();if(result.getBoolean(1) && result.getBoolean(2)){blocked=true;break;}}LockSupport.parkNanos(1000000);}
				check("pg-webauthn-initialization-exclusive-admission-blocks-ordinary-shared-read",blocked && !ordinaryRead.isDone());
			}
			release.countDown();WebAuthnStoreCommitReceipt receipt=pending.get(8,TimeUnit.SECONDS);
			check("pg-webauthn-initialization-admitted-timing",receipt.getStatus()==WebAuthnStoreCommitResult.COMMITTED && receipt.getTiming().isPresent() && receipt.getTiming().orElseThrow().getCompletedTime().isEmpty());
			check("pg-webauthn-ordinary-shared-read-resumes-after-initialization",ordinaryRead.get(8,TimeUnit.SECONDS) instanceof WebAuthnStoreReadResult.Available available && available.getSnapshot().getEntry(ROOT) instanceof WebAuthnStoreEntry.Present);
		}finally{release.countDown();pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
	}
	private static void temporal(@NonNull PostgresqlWebAuthnStore store)throws Exception{
		WebAuthnStoreKey key=account("no-effects");WebAuthnStoreSnapshot snapshot=snapshot(store,key);Instant end=TIME.get().plusNanos(1);WebAuthnStoreWrite write=insert(snapshot,key,TIME.get(),end);
		long before=total("used_entries","webauthn_store_escrow");TIME.set(end);
		check("pg-webauthn-exclusive-expiry-equality",store.compareAndCommit(write,BUDGET).getStatus()==WebAuthnStoreCommitResult.TIME_EXPIRED);
		snapshot=snapshot(store,key);check("pg-webauthn-inclusive-floor-refusal",store.compareAndCommit(insert(snapshot,key,TIME.get().plusNanos(1),TIME.get().plusNanos(2)),BUDGET).getStatus()==WebAuthnStoreCommitResult.TIME_BEFORE_FLOOR);
		PostgresqlWebAuthnStore unavailable=store(WebAuthnStoreProbe::connection,(scope,left)->StoreTimeObservation.Unavailable.fromAdmission(WebAuthnFixtureAuthority.admission(NS)));
		check("pg-webauthn-time-unavailable-zero-effect",unavailable.compareAndCommit(insert(snapshot,key,TIME.get(),TIME.get().plusSeconds(60)),BUDGET).getStatus()==WebAuthnStoreCommitResult.TIME_UNAVAILABLE);
		PostgresqlWebAuthnStore fenced=store(WebAuthnStoreProbe::connection,(scope,left)->StoreTimeObservation.Healthy.fromObservation(WebAuthnFixtureAuthority.admission(NS),WebAuthnFixtureAuthority.identity("other-clock"),TIME.get(),Duration.ZERO));
		check("pg-webauthn-external-clock-mismatch-fenced",fenced.compareAndCommit(insert(snapshot,key,TIME.get(),TIME.get().plusSeconds(60)),BUDGET).getStatus()==WebAuthnStoreCommitResult.FENCED);
		check("pg-webauthn-refusals-preserve-data-and-quota",total("used_entries","webauthn_store_escrow")==before && snapshot(store,key).getEntry(key) instanceof WebAuthnStoreEntry.Absent);
		WebAuthnStoreWrite barrier=WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot(store,key),List.of(),condition(snapshot(store,key),TIME.get(),TIME.get().plusSeconds(60)));
		check("pg-webauthn-zero-mutation-barrier-committed-timing",store.compareAndCommit(barrier,BUDGET).getStatus()==WebAuthnStoreCommitResult.COMMITTED && total("used_entries","webauthn_store_escrow")==before);
	}
	private static void waitCase(@NonNull PostgresqlWebAuthnStore store,boolean bucket)throws Exception{
		WebAuthnStoreKey key=account(bucket?"quota-wait":"entity-wait");WebAuthnStoreSnapshot snapshot=snapshot(store,key);Instant end=TIME.get().plusNanos(1);WebAuthnStoreWrite write=insert(snapshot,key,TIME.get(),end);int before=SAMPLES.get();
		AtomicInteger pid=new AtomicInteger();ExecutorService pool=Executors.newSingleThreadExecutor();
		try(Connection blocker=WebAuthnStoreProbe.connection(BUDGET)){
			blocker.setAutoCommit(false);long deadline=System.nanoTime()+BUDGET.toNanos();WebAuthnPgScope scope=WebAuthnPgScope.from("WEBAUTHN",WebAuthnFixtureAuthority.physical(NS));
			WebAuthnPgLocks.sharedAdmission(blocker,scope,deadline);
			if(bucket)try(PreparedStatement s=blocker.prepareStatement("SELECT bucket FROM webauthn_store_escrow WHERE namespace=? AND bucket=? FOR UPDATE")){s.setString(1,scope.getNamespace());s.setInt(2,WebAuthnPgCapacity.bucket(key.getStorageKey()));s.executeQuery().close();}
			else WebAuthnPgLocks.entities(blocker,List.of(WebAuthnPgLocks.entity(scope,key.getStorageKey(),true)),deadline);
			PostgresqlWebAuthnStore target=store(left->{Connection connection=WebAuthnStoreProbe.connection(left);try(Statement s=connection.createStatement();ResultSet r=s.executeQuery("SELECT pg_backend_pid()")){r.next();pid.set(r.getInt(1));}return connection;},(physical,left)->{SAMPLES.incrementAndGet();return point();});
			Future<WebAuthnStoreCommitReceipt> pending=pool.submit(()->target.compareAndCommit(write,BUDGET));
			try(Connection observer=WebAuthnStoreProbe.connection(BUDGET);PreparedStatement s=observer.prepareStatement("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=? AND NOT granted)")){
				boolean held=false;while(deadline-System.nanoTime()>0){s.setInt(1,pid.get());try(ResultSet r=s.executeQuery()){r.next();if(r.getBoolean(1)){held=true;break;}}LockSupport.parkNanos(1000000);}
				check(bucket?"pg-webauthn-quota-wait-reached":"pg-webauthn-entity-wait-reached",held && SAMPLES.get()==before);
			}
			TIME.set(end);blocker.rollback();WebAuthnStoreCommitReceipt receipt=pending.get(8,TimeUnit.SECONDS);
			check(bucket?"pg-webauthn-fresh-time-after-quota-wait":"pg-webauthn-fresh-time-after-entity-wait",receipt.getStatus()==WebAuthnStoreCommitResult.TIME_EXPIRED && snapshot(store,key).getEntry(key) instanceof WebAuthnStoreEntry.Absent);
		}finally{pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
	}
	private static void lateAndUnknown(@NonNull PostgresqlWebAuthnStore store)throws Exception{
		WebAuthnStoreKey key=account("late-known");WebAuthnStoreWrite write=insert(snapshot(store,key),key,TIME.get(),TIME.get().plusSeconds(60));
		PostgresqlWebAuthnStore late=store(left->{
			Connection physical=WebAuthnStoreProbe.connection(left);return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
				try{Object result=method.invoke(physical,args);if(method.getName().equals("commit")){long end=System.nanoTime()+Duration.ofMillis(250).toNanos();while(end-System.nanoTime()>0)LockSupport.parkNanos(1000000);}return result;}catch(InvocationTargetException failure){throw failure.getCause();}
			});
		},(scope,left)->point());
		WebAuthnStoreCommitReceipt result=late.compareAndCommit(write,Duration.ofMillis(200));
		check("pg-webauthn-late-known-commit-retains-timing",result.getStatus()==WebAuthnStoreCommitResult.COMMITTED && result.getTiming().isPresent());
		check("pg-webauthn-late-known-commit-ground-truth",snapshot(store,key).getEntry(key) instanceof WebAuthnStoreEntry.Present);
		key=account("unknown");write=insert(snapshot(store,key),key,TIME.get(),TIME.get().plusSeconds(60));PostgresqlWebAuthnStore uncertain=store(WebAuthnStoreProbe::lostCommitAcknowledgement,(scope,left)->point());result=uncertain.compareAndCommit(write,BUDGET);
		check("pg-webauthn-lost-ack-no-timing-no-retry",result.getStatus()==WebAuthnStoreCommitResult.UNKNOWN && result.getTiming().isEmpty());
		check("pg-webauthn-unknown-ground-truth-present",snapshot(store,key).getEntry(key) instanceof WebAuthnStoreEntry.Present);
	}
	private static void assignedCapacity(@NonNull PostgresqlWebAuthnStore store)throws Exception{
		int bucket,limit;try(Connection c=WebAuthnStoreProbe.connection(BUDGET);PreparedStatement s=c.prepareStatement("SELECT bucket,entry_limit FROM webauthn_store_escrow WHERE namespace=? AND used_entries=0 AND entry_limit>0 ORDER BY bucket LIMIT 1")){s.setString(1,WebAuthnFixtureAuthority.physical(NS));try(ResultSet r=s.executeQuery()){r.next();bucket=r.getInt(1);limit=r.getInt(2);}}
		int inserted=0;boolean refused=false;
		for(int index=0;index<100000 && inserted<=limit;index++){
			WebAuthnStoreKey key=account("stranding-"+index);if(WebAuthnPgCapacity.bucket(key.getStorageKey())!=bucket)continue;
			WebAuthnStoreCommitReceipt result=store.compareAndCommit(insert(snapshot(store,key),key,TIME.get(),TIME.get().plusSeconds(60)),BUDGET);
			if(inserted<limit){if(result.getStatus()!=WebAuthnStoreCommitResult.COMMITTED)throw new AssertionError("Assigned capacity setup failed");inserted++;}
			else{refused=result.getStatus()==WebAuthnStoreCommitResult.CAPACITY && snapshot(store,key).getEntry(key) instanceof WebAuthnStoreEntry.Absent;break;}
		}
		check("pg-webauthn-assigned-bucket-refusal-with-free-global-capacity",refused && total("used_entries","webauthn_store_escrow")<4096);
		check("pg-webauthn-entry-only-quota-has-no-invented-byte-cap",total("used_bytes","webauthn_store_escrow")==0);
	}
	public static void main(@NonNull String @NonNull [] arguments)throws Exception{
		PostgresqlWebAuthnStore store=ordinary();
		if(arguments.length==1 && arguments[0].equals("root-loss")){
			WebAuthnStoreReadResult result=store.read(Set.of(ROOT),BUDGET);
			if(!(result instanceof WebAuthnStoreReadResult.Unavailable))throw new AssertionError("Established missing root became available absence");
			WebAuthnStoreSnapshot forged=WebAuthnStoreSnapshot.fromEntries(Set.of(ROOT),java.util.Map.of(ROOT,WebAuthnStoreEntry.Absent.confirmed()),point());
			WebAuthnStoreCommitReceipt receipt=store.compareAndCommit(WebAuthnStoreWrite.fromSnapshotAndMutations(forged,List.of(WebAuthnStoreWrite.Mutation.insert(ROOT,new byte[]{42})),condition(forged,TIME.get(),TIME.get().plusSeconds(60))),BUDGET);
			check("pg-webauthn-missing-established-root-unavailable-no-recreation",receipt.getStatus()==WebAuthnStoreCommitResult.UNAVAILABLE);return;
		}
		initialized(store);temporal(store);waitCase(store,false);waitCase(store,true);lateAndUnknown(store);assignedCapacity(store);
	}
}
