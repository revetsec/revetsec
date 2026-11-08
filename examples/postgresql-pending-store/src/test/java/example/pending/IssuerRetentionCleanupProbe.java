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
import com.revetsec.oauth.server.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static java.util.Objects.requireNonNull;

/** Disposable native physical-retention controls; opaque mechanical fixtures are separate from genuine engine rows. */
public final class IssuerRetentionCleanupProbe {
 private static final @NonNull Instant E=Instant.parse("2026-11-01T12:00:00Z");
 private static final @NonNull Duration BUDGET=Duration.ofSeconds(5);
 private static final @NonNull String ISSUER=IssuerFixtureAuthority.identity("https://issuer.example");
 private IssuerRetentionCleanupProbe() { }
 private static void check(boolean value,@NonNull String label){IssuerRetentionBaselineProbe.check(value,label);}
 private static @NonNull Connection admin()throws SQLException{Properties properties=new Properties();properties.setProperty("user","postgres");properties.setProperty("password",requireNonNull(System.getenv("REVETSEC_CLEANUP_ADMIN_PASSWORD")));return DriverManager.getConnection(requireNonNull(System.getenv("REVETSEC_TEST_DB_URL")),properties);}
 private static void sql(@NonNull String command,@NonNull Object @NonNull ... values)throws SQLException{try(Connection connection=admin();PreparedStatement statement=connection.prepareStatement(command)){for(int i=0;i<values.length;i++)statement.setObject(i+1,values[i]);statement.executeUpdate();}}
 private static long number(@NonNull String command,@NonNull Object @NonNull ... values)throws SQLException{try(Connection connection=admin();PreparedStatement statement=connection.prepareStatement(command)){for(int i=0;i<values.length;i++)statement.setObject(i+1,values[i]);try(ResultSet rows=statement.executeQuery()){if(!rows.next())throw new AssertionError("Missing scalar");return rows.getLong(1);}}}
 private static @NonNull String text(@NonNull String command,@NonNull Object @NonNull ... values)throws SQLException{try(Connection connection=admin();PreparedStatement statement=connection.prepareStatement(command)){for(int i=0;i<values.length;i++)statement.setObject(i+1,values[i]);try(ResultSet rows=statement.executeQuery()){if(!rows.next())throw new AssertionError("Missing text");return requireNonNull(rows.getString(1));}}}
 private static @NonNull String key(@NonNull String kind,@NonNull String label){return "revetsec:as:1:"+ISSUER+":"+kind+":"+(kind.equals("ISSUER_STATE")?ISSUER:IssuerFixtureAuthority.identity(label));}
 private static StoreTimeObservation.@NonNull Healthy healthy(@NonNull String namespace,@NonNull Instant instant){return StoreTimeObservation.Healthy.fromObservation(IssuerFixtureAuthority.admission(namespace),IssuerFixtureAuthority.clock(namespace),instant,Duration.ZERO);}
 private static @NonNull PostgresqlIssuerStore store(@NonNull String namespace,@NonNull AtomicReference<@NonNull StoreTimeObservation> point){return new PostgresqlIssuerStore(namespace,IssuerFixtureAuthority.physical(namespace),PendingStoreProbe::connection,4096,(scope,budget)->point.get());}
 private static @NonNull List<@NonNull String> seed(@NonNull String namespace,int count,@NonNull Instant horizon,boolean permanent)throws Exception{
  List<String> keys=new ArrayList<>();List<String> kinds=new ArrayList<>(List.of("INTERACTION","CODE","GRANT","ACCESS_TOKEN","REFRESH_TOKEN"));
  for(int i=0;i<count+(permanent?2:0);i++){
   String kind=i<count?kinds.get(i%5):i==count?"ISSUER_STATE":"SUBJECT_STATE";String key=key(kind,namespace+"/"+i);Instant retain=i<count?horizon:Instant.ofEpochSecond(Instant.MAX.getEpochSecond());
   sql("INSERT INTO issuer_store_entry VALUES(?,?,?,?,?,?,?)",namespace,key,kind,IssuerFixtureAuthority.identity("version/"+namespace+"/"+i),retain.getEpochSecond(),retain.getNano(),"opaque-mechanical-not-authenticated");
   sql("UPDATE issuer_store_escrow SET used_entries=used_entries+1 WHERE namespace=? AND bucket=?",IssuerFixtureAuthority.physical(namespace),IssuerPgCapacity.bucket(key));
   if(i<count)keys.add(key);
  }
  return keys;
 }
 private static long rows(@NonNull String namespace)throws SQLException{return number("SELECT count(*) FROM issuer_store_entry WHERE namespace=?",namespace);}
 private static long charged(@NonNull String namespace)throws SQLException{return number("SELECT sum(used_entries) FROM issuer_store_escrow WHERE namespace=?",IssuerFixtureAuthority.physical(namespace));}
 private static @NonNull String fingerprint(@NonNull String namespace)throws Exception{
  var digest=java.security.MessageDigest.getInstance("SHA-256");
  for(String query:List.of("SELECT storage_key,kind,version,retain_seconds,retain_nanos,sealed_form FROM issuer_store_entry WHERE namespace=? ORDER BY storage_key","SELECT bucket,allocation_generation,entry_limit,used_entries FROM issuer_store_escrow WHERE namespace=? ORDER BY bucket")){
   try(Connection connection=admin();PreparedStatement statement=connection.prepareStatement(query)){statement.setString(1,query.contains("issuer_store_entry")?namespace:IssuerFixtureAuthority.physical(namespace));try(ResultSet result=statement.executeQuery()){int columns=result.getMetaData().getColumnCount();while(result.next())for(int i=1;i<=columns;i++){digest.update(requireNonNull(result.getString(i)).getBytes(java.nio.charset.StandardCharsets.UTF_8));digest.update((byte)0);}}}
  }
  return HexFormat.of().formatHex(digest.digest());
 }
 private static void noEffect(PostgresqlIssuerStore.@NonNull CleanupResult result,PostgresqlIssuerStore.@NonNull CleanupStatus status,@NonNull String namespace,@NonNull String before,@NonNull String label)throws Exception{check(result.getStatus()==status&&result.getRemovedCount().isEmpty()&&!result.isAcknowledgedWithinBudget()&&fingerprint(namespace).equals(before),label);}
 private static void boundaries()throws Exception{
  String namespace="gc_boundary";seed(namespace,5,E,true);AtomicReference<StoreTimeObservation> point=new AtomicReference<>(healthy(namespace,E.minusNanos(1)));var store=store(namespace,point);String before=fingerprint(namespace);var result=store.reclaimExpired(16,BUDGET);
  check(result.getStatus()==PostgresqlIssuerStore.CleanupStatus.COMMITTED&&result.getRemovedCount().orElseThrow()==0&&fingerprint(namespace).equals(before),"authority-E-minus-1ns-no-credential-expiry-cleanup");
  point.set(healthy(namespace,E));result=store.reclaimExpired(16,BUDGET);check(result.getStatus()==PostgresqlIssuerStore.CleanupStatus.COMMITTED&&result.getRemovedCount().orElseThrow()==5&&result.isAcknowledgedWithinBudget(),"authority-full-retention-equality-all-five-finite-kinds");
  check(rows(namespace)==2&&charged(namespace)==2,"both-permanent-kinds-and-exact-entry-charge-preserved");
  check(store.reclaimExpired(16,BUDGET).getRemovedCount().orElseThrow()==0&&charged(namespace)==2,"repeated-explicit-empty-cleanup-no-double-refund");
  namespace="gc_after";seed(namespace,5,E,false);point=new AtomicReference<>(healthy(namespace,E.plusNanos(1)));result=store(namespace,point).reclaimExpired(16,BUDGET);check(result.getRemovedCount().orElseThrow()==5&&rows(namespace)==0&&charged(namespace)==0,"authority-E-plus-1ns-exact-physical-refund");
  namespace="gc_batch";seed(namespace,19,E,true);point=new AtomicReference<>(healthy(namespace,E));store=store(namespace,point);result=store.reclaimExpired(16,BUDGET);check(result.getRemovedCount().orElseThrow()==16&&rows(namespace)==5&&charged(namespace)==5,"bounded-sixteen-row-batch-count-and-accounting");result=store.reclaimExpired(16,BUDGET);check(result.getRemovedCount().orElseThrow()==3&&rows(namespace)==2&&charged(namespace)==2,"bounded-next-batch-preserves-permanent-remainder");
  namespace="gc_nanos";seed(namespace,1,E.plusNanos(1),false);point=new AtomicReference<>(healthy(namespace,E));store=store(namespace,point);before=fingerprint(namespace);check(store.reclaimExpired(1,BUDGET).getRemovedCount().orElseThrow()==0&&fingerprint(namespace).equals(before),"SQL-full-nanos-plus-one-not-selected-at-E");point.set(healthy(namespace,E.plusNanos(1)));noEffect(store.reclaimExpired(1,BUDGET),PostgresqlIssuerStore.CleanupStatus.UNAVAILABLE,namespace,before,"nonzero-issuer-retention-nanos-refuses-without-normalization");
 }
 private static void selectionClock()throws Exception{
  for(long delta:new long[]{-1,0,1}){
   String namespace=delta<0?"gc_sample_back":delta==0?"gc_sample_same":"gc_sample_forward";seed(namespace,2,E.minusSeconds(3600),false);AtomicInteger observations=new AtomicInteger();
   var store=new PostgresqlIssuerStore(namespace,IssuerFixtureAuthority.physical(namespace),PendingStoreProbe::connection,4096,(scope,budget)->healthy(namespace,observations.getAndIncrement()==0?E:E.plusNanos(delta)));String before=fingerprint(namespace);var result=store.reclaimExpired(16,BUDGET);
   if(delta<0)noEffect(result,PostgresqlIssuerStore.CleanupStatus.TIME_UNAVAILABLE,namespace,before,"same-generation-selection-clock-rollback-older-retention-no-delete");
   else check(result.getStatus()==PostgresqlIssuerStore.CleanupStatus.COMMITTED&&result.getRemovedCount().orElseThrow()==2&&rows(namespace)==0&&charged(namespace)==0,delta==0?"selection-clock-equality-is-admissible":"selection-clock-forward-one-nanosecond-is-admissible");
   check(observations.get()==2,"exactly-two-original-budget-authority-samples");
  }
 }
 private static void purity()throws Exception{
  AtomicInteger opens=new AtomicInteger();var store=new PostgresqlIssuerStore("gc_pure",IssuerFixtureAuthority.physical("gc_pure"),budget->{opens.incrementAndGet();throw new SQLException("Denied fixture lookup");},4096,(scope,budget)->{throw new AssertionError("No authority on invalid request");});
  check(opens.get()==0,"cleanup-constructor-no-io");
  for(int batch:new int[]{Integer.MIN_VALUE,0,17,Integer.MAX_VALUE}){try{store.reclaimExpired(batch,BUDGET);throw new AssertionError("Invalid batch accepted");}catch(IllegalArgumentException expected){check(opens.get()==0,"invalid-batch-no-lookup-"+batch);}}
  for(Duration budget:List.of(Duration.ZERO,Duration.ofNanos(-1),Duration.ofSeconds(-30)))check(store.reclaimExpired(1,budget).getStatus()==PostgresqlIssuerStore.CleanupStatus.UNAVAILABLE&&opens.get()==0,"nonpositive-budget-no-lookup");
  try{Thread.currentThread().interrupt();check(store.reclaimExpired(1,BUDGET).getStatus()==PostgresqlIssuerStore.CleanupStatus.UNAVAILABLE&&opens.get()==0,"pre-entry-cancel-no-lookup");}finally{Thread.interrupted();}
  AtomicReference<Duration> seen=new AtomicReference<>();store=new PostgresqlIssuerStore("gc_pure",IssuerFixtureAuthority.physical("gc_pure"),budget->{seen.set(budget);throw new SQLException("Denied fixture lookup");},4096,(scope,budget)->{throw new AssertionError("Source denied before authority");});check(store.reclaimExpired(1,Duration.ofDays(1)).getStatus()==PostgresqlIssuerStore.CleanupStatus.UNAVAILABLE&&requireNonNull(seen.get()).compareTo(Duration.ofSeconds(30))<=0,"excessive-budget-caps-before-lookup");
 }
 private static void refusals()throws Exception{
  for(String mode:List.of("utc","authority","clock","error","null","throw","late")){
   String namespace="gc_fault_"+mode;seed(namespace,2,E,false);String before=fingerprint(namespace);PostgresqlIssuerStore.Authority authority=(scope,budget)->healthy(namespace,E);
   if(mode.equals("utc"))authority=(scope,budget)->StoreTimeObservation.Unavailable.fromAdmission(IssuerFixtureAuthority.admission(namespace));
   if(mode.equals("authority"))authority=(scope,budget)->StoreTimeObservation.Healthy.fromObservation(IssuerFixtureAuthority.admission("foreign"),IssuerFixtureAuthority.clock(namespace),E,Duration.ZERO);
   if(mode.equals("clock"))authority=(scope,budget)->StoreTimeObservation.Healthy.fromObservation(IssuerFixtureAuthority.admission(namespace),IssuerFixtureAuthority.clock("foreign"),E,Duration.ZERO);
   if(mode.equals("error"))authority=(scope,budget)->StoreTimeObservation.Healthy.fromObservation(IssuerFixtureAuthority.admission(namespace),IssuerFixtureAuthority.clock(namespace),E,Duration.ofMillis(1));
   if(mode.equals("null"))authority=(PostgresqlIssuerStore.Authority)Proxy.newProxyInstance(PostgresqlIssuerStore.Authority.class.getClassLoader(),new Class<?>[]{PostgresqlIssuerStore.Authority.class},(proxy,method,args)->null);
   if(mode.equals("throw"))authority=(scope,budget)->{throw new IllegalStateException("private-authority-secret");};
   if(mode.equals("late"))authority=(scope,budget)->{Thread.sleep(120);return healthy(namespace,E);};
   var store=new PostgresqlIssuerStore(namespace,IssuerFixtureAuthority.physical(namespace),PendingStoreProbe::connection,4096,authority);var expected=mode.equals("utc")?PostgresqlIssuerStore.CleanupStatus.TIME_UNAVAILABLE:List.of("authority","clock","error").contains(mode)?PostgresqlIssuerStore.CleanupStatus.FENCED:PostgresqlIssuerStore.CleanupStatus.UNAVAILABLE;noEffect(store.reclaimExpired(16,BUDGET),expected,namespace,before,"initial-authority-"+mode+"-whole-batch-zero-effects");
  }
  for(String mode:List.of("kind","permanent","missing-bucket","stale-allocation","undercharged")){
   String namespace="gc_bad_"+mode.replace('-','_');List<String> keys=seed(namespace,2,E,false);String key=keys.get(0);
   if(mode.equals("kind"))sql("UPDATE issuer_store_entry SET kind='CODE' WHERE namespace=? AND storage_key=?",namespace,key);
   if(mode.equals("permanent")){String permanent=key("ISSUER_STATE",namespace);sql("UPDATE issuer_store_entry SET storage_key=? WHERE namespace=? AND storage_key=?",permanent,namespace,key);}
   if(mode.equals("missing-bucket"))sql("DELETE FROM issuer_store_escrow WHERE namespace=? AND bucket=?",IssuerFixtureAuthority.physical(namespace),IssuerPgCapacity.bucket(key));
   if(mode.equals("stale-allocation"))sql("UPDATE issuer_store_escrow SET allocation_generation=? WHERE namespace=? AND bucket=?",IssuerFixtureAuthority.identity("stale-allocation"),IssuerFixtureAuthority.physical(namespace),IssuerPgCapacity.bucket(key));
   if(mode.equals("undercharged"))sql("UPDATE issuer_store_escrow SET used_entries=0 WHERE namespace=? AND bucket=?",IssuerFixtureAuthority.physical(namespace),IssuerPgCapacity.bucket(key));
   String before=fingerprint(namespace);var store=store(namespace,new AtomicReference<>(healthy(namespace,E)));noEffect(store.reclaimExpired(16,BUDGET),PostgresqlIssuerStore.CleanupStatus.UNAVAILABLE,namespace,before,"inconsistent-"+mode+"-whole-batch-refusal-no-repair");
  }
 }
 private static void waitBlocked(@NonNull Connection connection)throws Exception{long end=System.nanoTime()+Duration.ofSeconds(3).toNanos();while(System.nanoTime()-end<0){try(var statement=connection.prepareStatement("SELECT count(*) FROM pg_locks WHERE NOT granted");var rows=statement.executeQuery()){rows.next();if(rows.getLong(1)>0)return;}Thread.sleep(5);}throw new AssertionError("Actual cleanup lock wait absent");}
 private static void contention()throws Exception{
  for(String mode:List.of("entity-backward","entity-unhealthy","entity-replacement","entity-nanos","entity-retain-same","entity-form-same","escrow-backward","escrow-unhealthy")){
   String namespace="gc_wait_"+mode.replace('-','_');String key=seed(namespace,1,E,false).get(0);AtomicReference<StoreTimeObservation> point=new AtomicReference<>(healthy(namespace,E));var store=store(namespace,point);var pool=Executors.newSingleThreadExecutor();
   try(Connection holder=admin()){
    holder.setAutoCommit(false);holder.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
    if(mode.startsWith("entity"))IssuerPgLocks.entities(holder,IssuerPgLocks.entitySet(IssuerPgScope.from("ISSUER",IssuerFixtureAuthority.physical(namespace)),Map.of(key,true)),System.nanoTime()+Duration.ofSeconds(10).toNanos());
    else try(var statement=holder.prepareStatement("SELECT bucket FROM issuer_store_escrow WHERE namespace=? AND bucket=? FOR UPDATE")){statement.setString(1,IssuerFixtureAuthority.physical(namespace));statement.setInt(2,IssuerPgCapacity.bucket(key));try(var rows=statement.executeQuery()){if(!rows.next())throw new AssertionError("Missing escrow");}}
    String before=fingerprint(namespace);var waiting=pool.submit(()->store.reclaimExpired(16,BUDGET));waitBlocked(holder);
    if(mode.endsWith("backward"))point.set(healthy(namespace,E.minusNanos(1)));
    if(mode.endsWith("unhealthy"))point.set(StoreTimeObservation.Unavailable.fromAdmission(IssuerFixtureAuthority.admission(namespace)));
    if(mode.endsWith("retain-same")||mode.endsWith("form-same")){
     try(var statement=holder.prepareStatement(mode.endsWith("retain-same")?"UPDATE issuer_store_entry SET retain_seconds=retain_seconds+1 WHERE namespace=? AND storage_key=?":"UPDATE issuer_store_entry SET sealed_form='changed-opaque-carrier' WHERE namespace=? AND storage_key=?")){statement.setString(1,namespace);statement.setString(2,key);if(statement.executeUpdate()!=1)throw new AssertionError("Missing same-version replacement");}holder.commit();before=fingerprint(namespace);
    }else if(mode.endsWith("replacement")||mode.endsWith("nanos")){
     try(var statement=holder.prepareStatement("UPDATE issuer_store_entry SET version=?,retain_seconds=?,retain_nanos=? WHERE namespace=? AND storage_key=?")){statement.setString(1,IssuerFixtureAuthority.identity("replacement/"+namespace));statement.setLong(2,mode.endsWith("replacement")?E.getEpochSecond()+1:E.getEpochSecond());statement.setInt(3,mode.endsWith("nanos")?1:0);statement.setString(4,namespace);statement.setString(5,key);if(statement.executeUpdate()!=1)throw new AssertionError("Missing replacement");}holder.commit();before=fingerprint(namespace);
    }else holder.rollback();
    var expected=mode.endsWith("backward")?PostgresqlIssuerStore.CleanupStatus.TIME_UNAVAILABLE:mode.endsWith("unhealthy")?PostgresqlIssuerStore.CleanupStatus.TIME_UNAVAILABLE:(mode.endsWith("replacement")||mode.endsWith("same"))?PostgresqlIssuerStore.CleanupStatus.CONFLICT:PostgresqlIssuerStore.CleanupStatus.UNAVAILABLE;
    noEffect(waiting.get(5,TimeUnit.SECONDS),expected,namespace,before,"actual-"+mode+"-wait-fresh-authority-or-exact-reread");
   }finally{pool.shutdownNow();if(!pool.awaitTermination(3,TimeUnit.SECONDS))throw new AssertionError("Cleanup worker leaked");}
  }
  String namespace="gc_race";seed(namespace,1,E,false);var store=store(namespace,new AtomicReference<>(healthy(namespace,E)));var pool=Executors.newFixedThreadPool(2);CountDownLatch start=new CountDownLatch(1);
  try{var a=pool.submit(()->{start.await();return store.reclaimExpired(1,BUDGET);});var b=pool.submit(()->{start.await();return store.reclaimExpired(1,BUDGET);});start.countDown();var first=a.get(5,TimeUnit.SECONDS);var second=b.get(5,TimeUnit.SECONDS);check(first.getRemovedCount().orElse(0)+second.getRemovedCount().orElse(0)==1&&rows(namespace)==0&&charged(namespace)==0,"two-cleaners-one-physical-delete-one-atomic-refund");}finally{pool.shutdownNow();if(!pool.awaitTermination(3,TimeUnit.SECONDS))throw new AssertionError("Concurrent cleaners leaked");}
 }
 private static @NonNull Connection fault(@NonNull String mode,@NonNull AtomicInteger commits,@NonNull AtomicInteger deletes,@NonNull Duration budget)throws SQLException{
  Connection physical=PendingStoreProbe.connection(budget);
  return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
   try{
    if(method.getName().equals("commit")){commits.incrementAndGet();if(mode.equals("unknown-no-effect"))throw new SQLException("private-ack-secret");Object value=method.invoke(physical,args);if(mode.equals("unknown-applied"))throw new SQLException("private-ack-secret");if(mode.equals("late"))Thread.sleep(650);return value;}
    Object value=method.invoke(physical,args);
    if(method.getName().equals("prepareStatement")&&args!=null&&args.length>0&&args[0] instanceof String command&&command.startsWith("DELETE FROM issuer_store_entry")){
     PreparedStatement statement=(PreparedStatement)requireNonNull(value);
     return Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),new Class<?>[]{PreparedStatement.class},(inner,operation,arguments)->{try{if(operation.getName().equals("executeUpdate")&&deletes.incrementAndGet()==2&&mode.equals("second-delete"))throw new SQLException("private-dml-secret");return operation.invoke(statement,arguments);}catch(InvocationTargetException failure){throw failure.getCause();}});
    }
    return value;
   }catch(InvocationTargetException failure){throw failure.getCause();}
  });
 }
 private static void outcomes()throws Exception{
  for(String mode:List.of("late","unknown-applied","unknown-no-effect","second-delete")){
   String namespace="gc_outcome_"+mode.replace('-','_');seed(namespace,2,E,false);AtomicInteger commits=new AtomicInteger(),deletes=new AtomicInteger(),opens=new AtomicInteger();var store=new PostgresqlIssuerStore(namespace,IssuerFixtureAuthority.physical(namespace),budget->{opens.incrementAndGet();return fault(mode,commits,deletes,budget);},4096,(scope,budget)->healthy(namespace,E));String before=fingerprint(namespace);var result=store.reclaimExpired(16,mode.equals("late")?Duration.ofMillis(400):BUDGET);
   if(mode.equals("late"))check(result.getStatus()==PostgresqlIssuerStore.CleanupStatus.COMMITTED&&result.getRemovedCount().orElseThrow()==2&&!result.isAcknowledgedWithinBudget()&&rows(namespace)==0&&charged(namespace)==0,"late-known-commit-preserves-factual-count-not-ordinary-success");
   if(mode.startsWith("unknown")){check(result.getStatus()==PostgresqlIssuerStore.CleanupStatus.UNKNOWN&&result.getRemovedCount().isEmpty()&&!result.isAcknowledgedWithinBudget()&&commits.get()==1&&opens.get()==1,"lost-ack-"+mode+"-no-count-retry-or-read-rescue");check(mode.equals("unknown-applied")?rows(namespace)==0&&charged(namespace)==0:fingerprint(namespace).equals(before),"independent-ground-truth-"+mode);}
   if(mode.equals("second-delete"))noEffect(result,PostgresqlIssuerStore.CleanupStatus.UNAVAILABLE,namespace,before,"second-delete-failure-rolls-back-whole-batch-and-escrows");
  }
 }
 private static void genuine()throws Exception{
  String namespace=IssuerRetentionBaselineProbe.NAMESPACE;var store=IssuerFixtureAuthority.store(namespace,PendingStoreProbe::connection,4096);OAuthStoreTransaction transaction=IssuerRetentionBaselineProbe.target(store);check(store.commit(transaction,BUDGET).getStatus()==OAuthStoreCommitStatus.CAPACITY,"genuine-after-full-retention-before-cleanup-assigned-capacity-refuses");long finite=number("SELECT count(*) FROM issuer_store_entry WHERE namespace=? AND kind NOT IN ('ISSUER_STATE','SUBJECT_STATE')",namespace);check(finite==5,"genuine-normal-workflow-produced-all-five-finite-kinds");String root=text("SELECT version||':'||sealed_form FROM issuer_store_entry WHERE namespace=? AND kind='ISSUER_STATE'",namespace);String subject=text("SELECT version||':'||sealed_form FROM issuer_store_entry WHERE namespace=? AND kind='SUBJECT_STATE'",namespace);Instant horizon=Instant.ofEpochSecond(Long.parseLong(requireNonNull(System.getenv("REVETSEC_TEST_ISSUER_TIME"))));long atHorizon=number("SELECT count(*) FROM issuer_store_entry WHERE namespace=? AND kind NOT IN ('ISSUER_STATE','SUBJECT_STATE') AND retain_seconds=?",namespace,horizon.getEpochSecond());var early=store(namespace,new AtomicReference<>(healthy(namespace,horizon.minusNanos(1)))).reclaimExpired(16,BUDGET);check(early.getStatus()==PostgresqlIssuerStore.CleanupStatus.COMMITTED&&early.getRemovedCount().orElseThrow()==finite-atHorizon&&number("SELECT count(*) FROM issuer_store_entry WHERE namespace=? AND kind NOT IN ('ISSUER_STATE','SUBJECT_STATE')",namespace)==atHorizon,"genuine-E-minus-1ns-retains-every-row-at-full-horizon");var result=store.reclaimExpired(16,BUDGET);boolean oneAfter=Instant.parse(requireNonNull(System.getenv("REVETSEC_TEST_ISSUER_AUTHORITY_NOW"))).equals(horizon.plusNanos(1));check(result.getStatus()==PostgresqlIssuerStore.CleanupStatus.COMMITTED&&result.getRemovedCount().orElseThrow()==atHorizon,oneAfter?"genuine-E-plus-1ns-reclaims-only-matured-last-horizon":"genuine-full-retention-equality-reclaims-last-horizon");check(rows(namespace)==2&&charged(namespace)==2&&root.equals(text("SELECT version||':'||sealed_form FROM issuer_store_entry WHERE namespace=? AND kind='ISSUER_STATE'",namespace))&&subject.equals(text("SELECT version||':'||sealed_form FROM issuer_store_entry WHERE namespace=? AND kind='SUBJECT_STATE'",namespace)),"genuine-permanent-fences-byte-identical-and-counted");check(store.commit(transaction,BUDGET).getStatus()==OAuthStoreCommitStatus.COMMITTED&&rows(namespace)==3&&charged(namespace)==3,"same-genuine-engine-transaction-fits-exact-refunded-assigned-slot");
 }
 public static void main(@NonNull String @NonNull [] arguments)throws Exception{
  IssuerRetentionBaselineProbe.verifyCoreOrigin();
  if(arguments.length==1&&arguments[0].equals("genuine")){genuine();return;}
  purity();boundaries();selectionClock();refusals();contention();outcomes();
 }
}
