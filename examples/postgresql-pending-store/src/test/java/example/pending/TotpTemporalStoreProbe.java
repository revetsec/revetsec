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
import com.revetsec.totp.TotpStoreCommitReceipt;
import com.revetsec.totp.TotpStoreCommitResult;
import com.revetsec.totp.TotpStoreEntry;
import com.revetsec.totp.TotpStoreKey;
import com.revetsec.totp.TotpStoreReadResult;
import com.revetsec.totp.TotpStoreRecord;
import com.revetsec.totp.TotpStoreSnapshot;
import com.revetsec.totp.TotpStoreWrite;
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
public final class TotpTemporalStoreProbe {
	private static final String NS="fixture-totp-temporal",EPOCH="fixture-epoch-one";
	private static final Duration BUDGET=Duration.ofSeconds(5);
	private static final TotpStoreKey ROOT=TotpStoreKey.forNamespace(NS,EPOCH);
	private static final AtomicReference<Instant> TIME=new AtomicReference<>(Instant.ofEpochSecond(1700000010));
	private static final AtomicInteger SAMPLES=new AtomicInteger();
	private static final AtomicInteger VERSIONS=new AtomicInteger(1);
	private TotpTemporalStoreProbe() {}
	private static @NonNull StoreTimeObservation point() {return StoreTimeObservation.Healthy.fromObservation(TotpFixtureAuthority.admission(NS),TotpFixtureAuthority.clockGeneration(NS),TIME.get(),Duration.ZERO);}
	private static @NonNull PostgresqlTotpStore store(PostgresqlTotpStore.@NonNull ConnectionSource source,PostgresqlTotpStore.@NonNull Authority authority){return new PostgresqlTotpStore(NS,TotpFixtureAuthority.physical(NS),source,1024,2_000_000L,authority);}
	private static @NonNull PostgresqlTotpStore ordinary(){return store(TotpStoreProbe::connection,(scope,left)->{SAMPLES.incrementAndGet();return point();});}
	private static @NonNull TotpStoreKey account(@NonNull String name){return TotpStoreKey.forAccount(NS,EPOCH,name);}
	private static @NonNull TotpStoreSnapshot snapshot(@NonNull PostgresqlTotpStore store,@NonNull TotpStoreKey key){
		TotpStoreReadResult result=store.read(Set.of(ROOT,key),BUDGET);
		if(!(result instanceof TotpStoreReadResult.Available available))throw new IllegalStateException("Temporal fixture read unavailable");return available.getSnapshot();
	}
	private static @NonNull TotpStoreRecord record(@NonNull TotpStoreKey key){
		int version=VERSIONS.getAndIncrement();byte[] nonce=new byte[32];Arrays.fill(nonce,(byte)version);String id=Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
		byte[] raw=new byte[55];raw[0]=1;raw[1]=1;raw[2]='k';return TotpStoreRecord.fromStoredForm(key,id,Base64.getUrlEncoder().withoutPadding().encodeToString(raw).getBytes(StandardCharsets.US_ASCII));
	}
	private static @NonNull StoreTemporalCondition condition(@NonNull TotpStoreSnapshot snapshot,@NonNull Instant floor,@NonNull Instant end){return StoreTimeAccess.get().fromObservation((StoreTimeObservation.Healthy)snapshot.getTimeObservation(),floor,end);}
	private static @NonNull TotpStoreWrite insert(@NonNull TotpStoreSnapshot snapshot,@NonNull TotpStoreKey key,@NonNull Instant floor,@NonNull Instant end){return TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.UPDATE,snapshot,List.of(TotpStoreWrite.Mutation.insert(record(key))),condition(snapshot,floor,end));}
	private static void check(@NonNull String label,boolean value){if(!value)throw new AssertionError(label);System.out.println("PASS "+label);}
	private static long total(@NonNull String column,@NonNull String table)throws Exception{
		try(Connection c=TotpStoreProbe.connection(BUDGET);PreparedStatement s=c.prepareStatement("SELECT coalesce(sum("+column+"),0) FROM "+table+" WHERE namespace=?")){
			s.setString(1,table.equals("totp_store_entry")?NS:TotpFixtureAuthority.physical(NS));try(ResultSet r=s.executeQuery()){r.next();return r.getLong(1);}
		}
	}
	private static @NonNull Connection identified(@NonNull Duration remaining,@NonNull AtomicInteger pid)throws java.sql.SQLException{
		Connection connection=TotpStoreProbe.connection(remaining);try(Statement statement=connection.createStatement();ResultSet result=statement.executeQuery("SELECT pg_backend_pid()")){result.next();pid.set(result.getInt(1));}return connection;
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
	private static void initialized(@NonNull PostgresqlTotpStore store)throws Exception{
		TotpStoreReadResult.Available read=(TotpStoreReadResult.Available)store.read(Set.of(ROOT),BUDGET);TotpStoreSnapshot snapshot=read.getSnapshot();
		TotpStoreWrite write=TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE,snapshot,List.of(TotpStoreWrite.Mutation.insert(record(ROOT))),condition(snapshot,TIME.get(),TIME.get().plusSeconds(60)));
		CountDownLatch held=new CountDownLatch(1),release=new CountDownLatch(1);AtomicInteger initializerPid=new AtomicInteger(),readerPid=new AtomicInteger();ExecutorService pool=Executors.newFixedThreadPool(2);
		try{
			PostgresqlTotpStore initializer=store(left->pauseAdmission(identified(left,initializerPid),held,release),(physical,left)->point());
			Future<TotpStoreCommitReceipt> pending=pool.submit(()->initializer.compareAndCommit(write,BUDGET));
			check("pg-totp-initialization-exclusive-admission-reached",held.await(3,TimeUnit.SECONDS));
			PostgresqlTotpStore reader=store(left->identified(left,readerPid),(physical,left)->point());Future<TotpStoreReadResult> ordinaryRead=pool.submit(()->reader.read(Set.of(ROOT),BUDGET));
			TotpPgLocks.Admission admission=TotpPgLocks.admission(TotpPgScope.from("TOTP",TotpFixtureAuthority.physical(NS)));long deadline=System.nanoTime()+Duration.ofSeconds(3).toNanos();
			try(Connection observer=TotpStoreProbe.connection(BUDGET);PreparedStatement statement=observer.prepareStatement("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objsubid=2 AND classid=?::oid AND objid=?::oid AND pid=? AND mode='ExclusiveLock' AND granted),EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objsubid=2 AND classid=?::oid AND objid=?::oid AND pid=? AND mode='ShareLock' AND NOT granted)")){
				boolean blocked=false;while(deadline-System.nanoTime()>0){statement.setLong(1,Integer.toUnsignedLong(admission.getFirst()));statement.setLong(2,Integer.toUnsignedLong(admission.getSecond()));statement.setInt(3,initializerPid.get());statement.setLong(4,Integer.toUnsignedLong(admission.getFirst()));statement.setLong(5,Integer.toUnsignedLong(admission.getSecond()));statement.setInt(6,readerPid.get());try(ResultSet result=statement.executeQuery()){result.next();if(result.getBoolean(1) && result.getBoolean(2)){blocked=true;break;}}LockSupport.parkNanos(1000000);}
				check("pg-totp-initialization-exclusive-admission-blocks-ordinary-shared-read",blocked && !ordinaryRead.isDone());
			}
			release.countDown();TotpStoreCommitReceipt receipt=pending.get(8,TimeUnit.SECONDS);
			check("pg-totp-initialization-admitted-timing",receipt.getStatus()==TotpStoreCommitResult.COMMITTED && receipt.getTiming().isPresent() && receipt.getTiming().orElseThrow().getCompletedTime().isEmpty());
			check("pg-totp-ordinary-shared-read-resumes-after-initialization",ordinaryRead.get(8,TimeUnit.SECONDS) instanceof TotpStoreReadResult.Available available && available.getSnapshot().getEntry(ROOT) instanceof TotpStoreEntry.Present);
		}finally{release.countDown();pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
	}
	private static void temporal(@NonNull PostgresqlTotpStore store)throws Exception{
		TotpStoreKey key=account("no-effects");TotpStoreSnapshot snapshot=snapshot(store,key);Instant end=TIME.get().plusNanos(1);TotpStoreWrite write=insert(snapshot,key,TIME.get(),end);
		long before=total("used_entries","totp_store_escrow");TIME.set(end);
		check("pg-totp-exclusive-expiry-equality",store.compareAndCommit(write,BUDGET).getStatus()==TotpStoreCommitResult.TIME_EXPIRED);
		snapshot=snapshot(store,key);check("pg-totp-inclusive-floor-refusal",store.compareAndCommit(insert(snapshot,key,TIME.get().plusNanos(1),TIME.get().plusNanos(2)),BUDGET).getStatus()==TotpStoreCommitResult.TIME_BEFORE_FLOOR);
		PostgresqlTotpStore unavailable=store(TotpStoreProbe::connection,(scope,left)->StoreTimeObservation.Unavailable.fromAdmission(TotpFixtureAuthority.admission(NS)));
		check("pg-totp-time-unavailable-zero-effect",unavailable.compareAndCommit(insert(snapshot,key,TIME.get(),TIME.get().plusSeconds(60)),BUDGET).getStatus()==TotpStoreCommitResult.TIME_UNAVAILABLE);
		PostgresqlTotpStore fenced=store(TotpStoreProbe::connection,(scope,left)->StoreTimeObservation.Healthy.fromObservation(TotpFixtureAuthority.admission(NS),TotpFixtureAuthority.identity("other-clock"),TIME.get(),Duration.ZERO));
		check("pg-totp-external-clock-mismatch-fenced",fenced.compareAndCommit(insert(snapshot,key,TIME.get(),TIME.get().plusSeconds(60)),BUDGET).getStatus()==TotpStoreCommitResult.FENCED);
		check("pg-totp-refusals-preserve-data-and-quota",total("used_entries","totp_store_escrow")==before && snapshot(store,key).getEntry(key) instanceof TotpStoreEntry.Absent);
		TotpStoreWrite barrier=TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.UPDATE,snapshot(store,key),List.of(),condition(snapshot(store,key),TIME.get(),TIME.get().plusSeconds(60)));
		check("pg-totp-zero-mutation-barrier-committed-timing",store.compareAndCommit(barrier,BUDGET).getStatus()==TotpStoreCommitResult.COMMITTED && total("used_entries","totp_store_escrow")==before);
	}
	private static void waitCase(@NonNull PostgresqlTotpStore store,boolean bucket)throws Exception{
		TotpStoreKey key=account(bucket?"quota-wait":"entity-wait");TotpStoreSnapshot snapshot=snapshot(store,key);Instant end=TIME.get().plusNanos(1);TotpStoreWrite write=insert(snapshot,key,TIME.get(),end);int before=SAMPLES.get();
		AtomicInteger pid=new AtomicInteger();ExecutorService pool=Executors.newSingleThreadExecutor();
		try(Connection blocker=TotpStoreProbe.connection(BUDGET)){
			blocker.setAutoCommit(false);long deadline=System.nanoTime()+BUDGET.toNanos();TotpPgScope scope=TotpPgScope.from("TOTP",TotpFixtureAuthority.physical(NS));
			TotpPgLocks.sharedAdmission(blocker,scope,deadline);
			if(bucket)try(PreparedStatement s=blocker.prepareStatement("SELECT bucket FROM totp_store_escrow WHERE namespace=? AND bucket=? FOR UPDATE")){s.setString(1,scope.getNamespace());s.setInt(2,TotpPgCapacity.bucket(key.getStorageKey()));s.executeQuery().close();}
			else TotpPgLocks.entities(blocker,List.of(TotpPgLocks.entity(scope,key.getStorageKey(),true)),deadline);
			PostgresqlTotpStore target=store(left->{Connection connection=TotpStoreProbe.connection(left);try(Statement s=connection.createStatement();ResultSet r=s.executeQuery("SELECT pg_backend_pid()")){r.next();pid.set(r.getInt(1));}return connection;},(physical,left)->{SAMPLES.incrementAndGet();return point();});
			Future<TotpStoreCommitReceipt> pending=pool.submit(()->target.compareAndCommit(write,BUDGET));
			try(Connection observer=TotpStoreProbe.connection(BUDGET);PreparedStatement s=observer.prepareStatement("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=? AND NOT granted)")){
				boolean held=false;while(deadline-System.nanoTime()>0){s.setInt(1,pid.get());try(ResultSet r=s.executeQuery()){r.next();if(r.getBoolean(1)){held=true;break;}}LockSupport.parkNanos(1000000);}
				check(bucket?"pg-totp-quota-wait-reached":"pg-totp-entity-wait-reached",held && SAMPLES.get()==before);
			}
			TIME.set(end);blocker.rollback();TotpStoreCommitReceipt receipt=pending.get(8,TimeUnit.SECONDS);
			check(bucket?"pg-totp-fresh-time-after-quota-wait":"pg-totp-fresh-time-after-entity-wait",receipt.getStatus()==TotpStoreCommitResult.TIME_EXPIRED && snapshot(store,key).getEntry(key) instanceof TotpStoreEntry.Absent);
		}finally{pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
	}
	private static void lateAndUnknown(@NonNull PostgresqlTotpStore store)throws Exception{
		TotpStoreKey key=account("late-known");TotpStoreWrite write=insert(snapshot(store,key),key,TIME.get(),TIME.get().plusSeconds(60));
		PostgresqlTotpStore late=store(left->{
			Connection physical=TotpStoreProbe.connection(left);return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
				try{Object result=method.invoke(physical,args);if(method.getName().equals("commit")){long end=System.nanoTime()+Duration.ofMillis(250).toNanos();while(end-System.nanoTime()>0)LockSupport.parkNanos(1000000);}return result;}catch(InvocationTargetException failure){throw failure.getCause();}
			});
		},(scope,left)->point());
		TotpStoreCommitReceipt result=late.compareAndCommit(write,Duration.ofMillis(200));
		check("pg-totp-late-known-commit-retains-timing",result.getStatus()==TotpStoreCommitResult.COMMITTED && result.getTiming().isPresent());
		check("pg-totp-late-known-commit-ground-truth",snapshot(store,key).getEntry(key) instanceof TotpStoreEntry.Present);
		key=account("unknown");write=insert(snapshot(store,key),key,TIME.get(),TIME.get().plusSeconds(60));store.failNextCommitAcknowledgement();result=store.compareAndCommit(write,BUDGET);
		check("pg-totp-lost-ack-no-timing-no-retry",result.getStatus()==TotpStoreCommitResult.UNKNOWN && result.getTiming().isEmpty());
		check("pg-totp-unknown-ground-truth-present",snapshot(store,key).getEntry(key) instanceof TotpStoreEntry.Present);
	}
	private static void assignedCapacity(@NonNull PostgresqlTotpStore store)throws Exception{
		int bucket,limit;try(Connection c=TotpStoreProbe.connection(BUDGET);PreparedStatement s=c.prepareStatement("SELECT bucket,entry_limit FROM totp_store_escrow WHERE namespace=? AND used_entries=0 AND entry_limit>0 ORDER BY bucket LIMIT 1")){s.setString(1,TotpFixtureAuthority.physical(NS));try(ResultSet r=s.executeQuery()){r.next();bucket=r.getInt(1);limit=r.getInt(2);}}
		int inserted=0;boolean refused=false;
		for(int index=0;index<100000 && inserted<=limit;index++){
			TotpStoreKey key=account("stranding-"+index);if(TotpPgCapacity.bucket(key.getStorageKey())!=bucket)continue;
			TotpStoreCommitReceipt result=store.compareAndCommit(insert(snapshot(store,key),key,TIME.get(),TIME.get().plusSeconds(60)),BUDGET);
			if(inserted<limit){if(result.getStatus()!=TotpStoreCommitResult.COMMITTED)throw new AssertionError("Assigned capacity setup failed");inserted++;}
			else{refused=result.getStatus()==TotpStoreCommitResult.CAPACITY_REFUSED && snapshot(store,key).getEntry(key) instanceof TotpStoreEntry.Absent;break;}
		}
		check("pg-totp-assigned-bucket-refusal-with-free-global-capacity",refused && total("used_entries","totp_store_escrow")<1024);
		check("pg-totp-k64-reservation-actual-usage-bound",total("used_bytes","totp_store_escrow")==total("reserved_size","totp_store_entry"));
	}
	public static void main(@NonNull String @NonNull [] arguments)throws Exception{
		PostgresqlTotpStore store=ordinary();initialized(store);temporal(store);waitCase(store,false);waitCase(store,true);lateAndUnknown(store);assignedCapacity(store);
	}
}
