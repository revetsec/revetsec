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

package verification.sharedclock;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/** Native component controls, not generated engine transactions or a UTC proof. */
public final class PgNativeChecks {
	private static final Duration BUDGET=Duration.ofSeconds(5);
	private static final PgScope SCOPE=PgScope.from("ISSUER",identity("native-scope"));
	private static final PgPrimitives.Admission ADMISSION=new PgPrimitives.Admission(identity("authority"),identity("recovery"),identity("clock"),identity("profile"),identity("schema"),identity("metadata"),identity("writer"),identity("allocation"),2);
	private static final AtomicReference<Instant> TIME=new AtomicReference<>(Instant.ofEpochSecond(1800000000));
	private static final AtomicInteger SAMPLES=new AtomicInteger();
	private PgNativeChecks() {}
	public static void main(@NonNull String @NonNull [] arguments) throws Exception {
		try {
			if(arguments.length==2 && arguments[0].equals("ack-loss")) {
				String key="lost-ack-"+arguments[1];long started=System.nanoTime();
				PgTransactions.Outcome<PgPrimitives.Validated> result=PgPrimitives.write(PgNativeChecks::connection,SCOPE,ADMISSION,predicate(key,null),Map.of(key,row(key,"lost-v-"+arguments[1],null)),Instant.EPOCH,null,BUDGET,PgNativeChecks::observe);
				System.out.println("FACT elapsedMs="+((System.nanoTime()-started)/1000000)+" samples="+SAMPLES.get()+" completion="+result.status()+" mutation="+result.possibleMutation()+" physical="+result.completion().map(Enum::name).orElse("ABSENT")+" refusal="+result.refusal().map(Enum::name).orElse("ABSENT"));
				check("native-data-quota-lost-ack-unknown",result.status()==PgTransactions.Status.UNKNOWN && result.possibleMutation() && result.value().isEmpty());return;
			}
			pure();
			if(arguments.length==1 && arguments[0].equals("pure")) return;
			setup();
			ordinary();
			races();
			waits();
			admissionAndCommit();
		} catch (Throwable failure) {
			System.err.println("FAIL native-component-check: "+failure.getClass().getSimpleName());
			System.exit(1);
		}
	}
	static @NonNull String identity(@NonNull String text) {
		try{return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));}
		catch(Exception failure){throw new IllegalStateException("Required identity hash unavailable",failure);}
	}
	static @NonNull Connection connect(@NonNull Duration remaining) throws Exception {
		Properties properties=new Properties();
		properties.setProperty("user",System.getenv("DB_USER"));properties.setProperty("password",System.getenv("DB_PASSWORD"));
		properties.setProperty("sslmode","disable");properties.setProperty("gssEncMode","disable");
		properties.setProperty("preferQueryMode","simple");properties.setProperty("connectTimeout","2");properties.setProperty("socketTimeout","8");
		properties.setProperty("ApplicationName","scp05_native");
		return DriverManager.getConnection(System.getenv("DB_URL"),properties);
	}
	private static @NonNull Connection open() throws Exception {return connect(BUDGET);}
	private static void check(@NonNull String label,boolean result) {if(!result)throw new AssertionError(label);System.out.println("PASS "+label);}
	private static void pure() {
		PgScope scope=PgScope.from("ISSUER","scope-µ");PgLocks.Admission lock=PgLocks.admission(scope);
		check("lock-fixed-independent-UTF8-vector",lock.getFirst()==817153383 && lock.getSecond()==-1070715098 && PgLocks.entity(scope,"record:a",false).getId()==9076332401462940645L);
		List<PgLocks.Entity> merged=PgLocks.merge(List.of(PgLocks.Entity.fromId(1,false),PgLocks.Entity.fromId(-1,true),PgLocks.Entity.fromId(1,true),PgLocks.Entity.fromId(Long.MIN_VALUE,false)));
		check("lock-collision-strongest-signed-order",merged.size()==3 && merged.get(0).getId()==Long.MIN_VALUE && merged.get(1).getId()==-1 && merged.get(2).getId()==1 && merged.get(2).isExclusive());
		List<PgLocks.Admission> admissions=PgLocks.allAdmission(List.of(PgScope.from("TOTP","a"),PgScope.from("ISSUER","b"),PgScope.from("WEBAUTHN","c")));
		check("admission-all-scope-signed-pair-order",admissions.size()==3 && admissions.get(0).compareTo(admissions.get(1))<0 && admissions.get(1).compareTo(admissions.get(2))<0);
		boolean rejected=false;try{PgLocks.allAdmission(List.of(scope,PgScope.from("ISSUER","other")));}catch(IllegalArgumentException expected){rejected=true;}
		check("scope-no-second-namespace-for-family",rejected);
		String ascii="x".repeat(262144);String encoded=Base64.getUrlEncoder().withoutPadding().encodeToString(ascii.getBytes(StandardCharsets.US_ASCII));
		check("transport-WA-maximum-frame-expansion",encoded.length()==349526 && Arrays.equals(Base64.getUrlDecoder().decode(encoded),ascii.getBytes(StandardCharsets.US_ASCII)));
		check("transport-TOTP-upper-expansion-and-K64-reservation",PgCapacity.base64Length(65536)==87382 && PgCapacity.base64Length(54+64+42667)==57047 && PgCapacity.base64Length(57047)==76063);
	}
	private static void setup() throws Exception {
		try(Connection c=open()) {
			try(PreparedStatement s=c.prepareStatement("INSERT INTO scp05_admission VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")) {
				s.setString(1,SCOPE.getFamily());s.setString(2,SCOPE.getNamespace());s.setString(3,ADMISSION.authority);s.setString(4,ADMISSION.recovery);s.setString(5,ADMISSION.clock);s.setString(6,ADMISSION.profile);s.setString(7,ADMISSION.schema);s.setString(8,ADMISSION.metadata);s.setString(9,ADMISSION.writer);s.setString(10,ADMISSION.allocation);s.setInt(11,2);s.setString(12,"ACTIVE");s.executeUpdate();
			}
			try(PreparedStatement s=c.prepareStatement("INSERT INTO scp05_escrow VALUES(?,?,?,?,?,?,?,?)")) {
				for(int i=0;i<256;i++){s.setString(1,SCOPE.getFamily());s.setString(2,SCOPE.getNamespace());s.setInt(3,i);s.setString(4,ADMISSION.allocation);s.setLong(5,64);s.setLong(6,0);s.setLong(7,0);s.setLong(8,0);s.addBatch();}s.executeBatch();
			}
			try(Statement s=c.createStatement()) {
				s.execute("CREATE TABLE scp05_audit(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,kind text NOT NULL)");
				s.execute("CREATE FUNCTION scp05_trace() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO scp05_audit(kind) VALUES(TG_TABLE_NAME); RETURN NULL; END $$");
				s.execute("CREATE TRIGGER entries_trace AFTER INSERT OR UPDATE OR DELETE ON scp05_entries FOR EACH ROW EXECUTE FUNCTION scp05_trace()");
				s.execute("CREATE TRIGGER quota_trace AFTER INSERT OR UPDATE OR DELETE ON scp05_escrow FOR EACH ROW EXECUTE FUNCTION scp05_trace()");
			}
		}
	}
	private static PgPrimitives.@Nullable Point observe(@NonNull Duration remaining) {SAMPLES.incrementAndGet();return new PgPrimitives.Point(ADMISSION,TIME.get());}
	private static @NonNull Map<String,@Nullable String> predicate(@NonNull String key,@Nullable String version) {Map<String,@Nullable String> map=new LinkedHashMap<>();map.put(key,version);return map;}
	private static PgPrimitives.@NonNull Row row(@NonNull String key,@NonNull String version,@Nullable Instant expiry) {return new PgPrimitives.Row(key,identity(version),new byte[]{1},expiry,0);}
	private static PgTransactions.@NonNull Outcome<PgPrimitives.Validated> write(@NonNull String key,@Nullable String version,PgPrimitives.@Nullable Row next,@NonNull Instant floor,@Nullable Instant expiry) {
		Map<String,PgPrimitives.@Nullable Row> changes=new LinkedHashMap<>();changes.put(key,next);
		return PgPrimitives.write(remaining->{try{return connect(remaining);}catch(Exception failure){throw new java.sql.SQLException("Private fixture connection unavailable");}},SCOPE,ADMISSION,predicate(key,version),changes,floor,expiry,BUDGET,PgNativeChecks::observe);
	}
	private static long count(@NonNull String table) throws Exception {try(Connection c=open();Statement s=c.createStatement();ResultSet rs=s.executeQuery("SELECT count(*) FROM "+table)){rs.next();return rs.getLong(1);}}
	private static void ordinary() throws Exception {
		String key="ordinary";PgPrimitives.Row first=row(key,"first",Instant.ofEpochSecond(-7,123));
		PgTransactions.Outcome<PgPrimitives.Validated> insert=write(key,null,first,Instant.EPOCH,null);
		check("native-insert-data-and-quota-known-commit",insert.status()==PgTransactions.Status.COMMITTED && insert.possibleMutation() && insert.value().orElseThrow().validation.time.equals(TIME.get()));
		long before=count("scp05_audit");
		PgTransactions.Outcome<PgPrimitives.Read> read=PgPrimitives.read(PgNativeChecks::connection,SCOPE,ADMISSION,List.of(key,"absent"),BUDGET,PgNativeChecks::observe);
		check("native-read-expired-row-preserved-exact-nanos-and-absence",read.status()==PgTransactions.Status.COMMITTED && read.value().orElseThrow().rows.get(key).expiry.equals(first.expiry) && read.value().orElseThrow().rows.containsKey("absent") && read.value().orElseThrow().rows.get("absent")==null);
		check("native-read-has-zero-data-quota-cleanup-DML",count("scp05_audit")==before && !read.possibleMutation());
		PgTransactions.Outcome<PgPrimitives.Validated> barrier=PgPrimitives.write(PgNativeChecks::connection,SCOPE,ADMISSION,predicate(key,first.version),Map.of(),TIME.get(),TIME.get().plusNanos(1),BUDGET,PgNativeChecks::observe);
		check("native-barrier-validates-inclusive-floor-with-zero-DML",barrier.status()==PgTransactions.Status.COMMITTED && !barrier.possibleMutation() && count("scp05_audit")==before);
		PgTransactions.Outcome<PgPrimitives.Validated> expired=PgPrimitives.write(PgNativeChecks::connection,SCOPE,ADMISSION,predicate(key,first.version),Map.of(),Instant.EPOCH,TIME.get(),BUDGET,PgNativeChecks::observe);
		check("native-upper-bound-exclusive-at-nanosecond-equality",expired.refusal().orElseThrow()==PgTransactions.Refusal.TIME_EXPIRED && count("scp05_audit")==before);
		PgTransactions.Outcome<PgPrimitives.Validated> early=PgPrimitives.write(PgNativeChecks::connection,SCOPE,ADMISSION,predicate(key,first.version),Map.of(),TIME.get().plusNanos(1),null,BUDGET,PgNativeChecks::observe);
		check("native-before-floor-refuses-with-zero-effects",early.refusal().orElseThrow()==PgTransactions.Refusal.TIME_BEFORE_FLOOR);
		PgTransactions.Outcome<PgPrimitives.Validated> unavailable=PgPrimitives.write(PgNativeChecks::connection,SCOPE,ADMISSION,predicate(key,first.version),Map.of(),Instant.EPOCH,null,BUDGET,left->null);
		check("native-no-authority-has-no-worker-database-fallback",unavailable.refusal().orElseThrow()==PgTransactions.Refusal.TIME_UNAVAILABLE);
		PgPrimitives.Admission wrong=new PgPrimitives.Admission(identity("foreign"),ADMISSION.recovery,ADMISSION.clock,ADMISSION.profile,ADMISSION.schema,ADMISSION.metadata,ADMISSION.writer,ADMISSION.allocation,2);
		PgTransactions.Outcome<PgPrimitives.Read> fenced=PgPrimitives.read(PgNativeChecks::connection,SCOPE,wrong,List.of(key),BUDGET,PgNativeChecks::observe);
		check("native-exact-authority-metadata-fence",fenced.refusal().orElseThrow()==PgTransactions.Refusal.FENCED);
		int samples=SAMPLES.get();PgTransactions.Outcome<PgPrimitives.Validated> conflict=write(key,identity("stale"),row(key,"replacement",null),Instant.EPOCH,null);
		check("native-conflict-before-authority-and-without-DML",conflict.refusal().orElseThrow()==PgTransactions.Refusal.CONFLICT && SAMPLES.get()==samples && count("scp05_audit")==before);
		boolean rejected=false;try{PgPrimitives.write(PgNativeChecks::connection,SCOPE,ADMISSION,predicate(key,first.version),Map.of(),Instant.EPOCH,PgPrimitives.MAX_TIME.plusNanos(1),BUDGET,PgNativeChecks::observe);}catch(IllegalArgumentException expected){rejected=true;}
		check("native-temporal-condition-upper-range-refused-before-I-O",rejected);
	}
	private static @NonNull Connection connection(@NonNull Duration remaining) throws java.sql.SQLException {try{return connect(remaining);}catch(Exception failure){throw new java.sql.SQLException("Private fixture connection unavailable");}}

	private static void races() throws Exception {
		ExecutorService pool=Executors.newFixedThreadPool(2);
		try {
			CountDownLatch start=new CountDownLatch(1);
			java.util.concurrent.Callable<PgTransactions.Outcome<PgPrimitives.Validated>> action=()->{start.await(3,TimeUnit.SECONDS);return write("absent-race",null,row("absent-race","race-"+Thread.currentThread().getId(),null),Instant.EPOCH,null);};
			Future<PgTransactions.Outcome<PgPrimitives.Validated>> a=pool.submit(action),b=pool.submit(action);start.countDown();
			List<PgTransactions.Outcome<PgPrimitives.Validated>> results=List.of(a.get(8,TimeUnit.SECONDS),b.get(8,TimeUnit.SECONDS));
			check("native-absence-lock-race-one-commit-one-conflict",results.stream().filter(x->x.status()==PgTransactions.Status.COMMITTED).count()==1 && results.stream().filter(x->x.refusal().orElse(null)==PgTransactions.Refusal.CONFLICT).count()==1);
			String held="independent-held",other="independent-other";
			try(Connection blocker=open()) {
				blocker.setAutoCommit(false);PgLocks.sharedAdmission(blocker,SCOPE,System.nanoTime()+BUDGET.toNanos());PgLocks.entities(blocker,List.of(PgLocks.entity(SCOPE,held,true)),System.nanoTime()+BUDGET.toNanos());
				Future<PgTransactions.Outcome<PgPrimitives.Validated>> blocked=pool.submit(()->write(held,null,row(held,"held",null),Instant.EPOCH,null));
				PgTransactions.Outcome<PgPrimitives.Validated> progressing=write(other,null,row(other,"other",null),Instant.EPOCH,null);
				check("native-independent-entity-shared-admission-progress",progressing.status()==PgTransactions.Status.COMMITTED && !blocked.isDone());
				blocker.rollback();check("native-same-entity-waits-until-release",blocked.get(8,TimeUnit.SECONDS).status()==PgTransactions.Status.COMMITTED);
			}
		}finally{pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
	}
	private static void waits() throws Exception { waitCase(false,false);waitCase(true,false);waitCase(false,true); }
	private static void waitCase(boolean bucket,boolean advancesFromBelowFloor) throws Exception {
		String key="wait-"+bucket+"-"+advancesFromBelowFloor;Instant expiry=Instant.ofEpochSecond(1800000020);
		TIME.set(advancesFromBelowFloor?expiry.minusSeconds(3):expiry.minusNanos(1));int before=SAMPLES.get();
		AtomicInteger pid=new AtomicInteger();ExecutorService pool=Executors.newSingleThreadExecutor();
		try(Connection blocker=open()) {
			blocker.setAutoCommit(false);long deadline=System.nanoTime()+BUDGET.toNanos();
			if(bucket)try(PreparedStatement s=blocker.prepareStatement("SELECT bucket FROM scp05_escrow WHERE family=? AND namespace=? AND bucket=? FOR UPDATE")){s.setString(1,SCOPE.getFamily());s.setString(2,SCOPE.getNamespace());s.setInt(3,PgCapacity.bucket(key));s.executeQuery().close();}
			else PgLocks.entities(blocker,List.of(PgLocks.entity(SCOPE,key,true)),deadline);
			Future<PgTransactions.Outcome<PgPrimitives.Validated>> pending=pool.submit(()->PgPrimitives.write(left->{Connection c=connection(left);try(Statement s=c.createStatement();ResultSet r=s.executeQuery("SELECT pg_backend_pid()")){r.next();pid.set(r.getInt(1));}return c;},SCOPE,ADMISSION,predicate(key,null),Map.of(key,row(key,"wait-v",null)),advancesFromBelowFloor?expiry.minusSeconds(1):Instant.EPOCH,expiry,BUDGET,PgNativeChecks::observe));
			awaitWait(pid,deadline);check(bucket?"native-capacity-wait-before-sampling":advancesFromBelowFloor?"native-below-floor-wait-before-sampling":"native-entity-wait-before-sampling",SAMPLES.get()==before);
			TIME.set(advancesFromBelowFloor?expiry.minusNanos(1):expiry);blocker.rollback();
			PgTransactions.Outcome<PgPrimitives.Validated> result=pending.get(8,TimeUnit.SECONDS);
			check(bucket?"native-capacity-wait-expiry-equality-zero-effects":advancesFromBelowFloor?"native-wait-uses-current-valid-time-not-prewait-floor":"native-entity-wait-expiry-equality-zero-effects",advancesFromBelowFloor?result.status()==PgTransactions.Status.COMMITTED:result.refusal().orElseThrow()==PgTransactions.Refusal.TIME_EXPIRED);
		}finally{pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);TIME.set(Instant.ofEpochSecond(1800000000));}
	}
	private static void awaitWait(@NonNull AtomicInteger pid,long deadline) throws Exception {
		try(Connection c=open();PreparedStatement s=c.prepareStatement("SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=? AND NOT granted)")) {
			while(System.nanoTime()-deadline<0){s.setInt(1,pid.get());try(ResultSet r=s.executeQuery()){r.next();if(r.getBoolean(1))return;}LockSupport.parkNanos(1000000);}
		}
		throw new AssertionError("Native SQL wait not reached");
	}
	private static void admissionAndCommit() throws Exception {
		ExecutorService pool=Executors.newSingleThreadExecutor();
		try(Connection reader=open()) {
			reader.setAutoCommit(false);PgLocks.sharedAdmission(reader,SCOPE,System.nanoTime()+BUDGET.toNanos());
			AtomicInteger pid=new AtomicInteger();
			Future<Boolean> transition=pool.submit(()->{try(Connection controller=open()){controller.setAutoCommit(false);try(Statement s=controller.createStatement();ResultSet r=s.executeQuery("SELECT pg_backend_pid()")){r.next();pid.set(r.getInt(1));}PgLocks.exclusiveAdmission(controller,List.of(SCOPE,PgScope.from("TOTP",identity("totp-scope")),PgScope.from("WEBAUTHN",identity("wa-scope"))),System.nanoTime()+BUDGET.toNanos());controller.commit();return true;}});
			awaitWait(pid,System.nanoTime()+BUDGET.toNanos());check("native-all-scope-admission-transition-drains-shared-holder",!transition.isDone());reader.commit();check("native-admission-lock-held-through-real-commit",transition.get(8,TimeUnit.SECONDS));
		}finally{pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
	}
}
