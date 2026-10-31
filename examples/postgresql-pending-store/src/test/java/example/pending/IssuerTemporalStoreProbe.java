/* Copyright 2026 Revetware LLC. Licensed under Apache-2.0. */
package example.pending;

import com.revetsec.StoreTimeObservation;
import com.revetsec.oauth.server.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/** Real engine-created transactions against independently controlled native authority time. */
public final class IssuerTemporalStoreProbe {
 private static final @NonNull String NAMESPACE="fixture_issuer_temporal";
 private static final @NonNull Instant NOW=Instant.parse("2026-10-06T12:00:00Z");
 private IssuerTemporalStoreProbe() { }
 private static void check(boolean valid,@NonNull String label){if(!valid)throw new AssertionError(label);System.out.println("PASS "+label);}
 private static @NonNull StoreTimeObservation healthy(@NonNull Instant now){return StoreTimeObservation.Healthy.fromObservation(IssuerFixtureAuthority.admission(NAMESPACE),IssuerFixtureAuthority.clock(NAMESPACE),now,Duration.ZERO);}
 private static final class Capture implements OAuthAuthorizationServerStore {
  private final @NonNull OAuthAuthorizationServerStore reads;
  private @Nullable OAuthStoreTransaction last;
  private Capture(@NonNull OAuthAuthorizationServerStore reads){this.reads=reads;}
  @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return this.reads.read(key,budget);}
  @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction txn,@NonNull Duration budget){this.last=txn;return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.CONFLICT);}
 }

 private static void waitForBlocked(java.sql.@NonNull Connection connection)throws Exception{
  long end=System.nanoTime()+Duration.ofSeconds(3).toNanos();
  while(System.nanoTime()<end){try(var statement=connection.prepareStatement("SELECT count(*) FROM pg_locks WHERE NOT granted" );var rows=statement.executeQuery()){rows.next();if(rows.getLong(1)>0)return;}Thread.sleep(10);}
  throw new AssertionError("No actual native lock wait observed");
 }
 private static void waitChecks(@NonNull PostgresqlIssuerStore store,@NonNull Capture capture,@NonNull OAuthAuthorizationServer prepared,@NonNull AtomicReference<@NonNull StoreTimeObservation> point,@NonNull String query)throws Exception{
  point.set(healthy(NOW));try{prepared.beginAuthorizationResult("GET",query,new byte[0],Map.of(),"A".repeat(43));throw new AssertionError("Capture must conflict");}catch(OAuthServerStoreException expected){if(expected.getReason()!=OAuthServerException.Reason.STORE_UNAVAILABLE)throw expected;}
  OAuthStoreTransaction txn=java.util.Objects.requireNonNull(capture.last);OAuthStoreKey changed=txn.getMutations().get(0).getKey();
  var executor=java.util.concurrent.Executors.newSingleThreadExecutor();
  try(var holder=PendingStoreProbe.connection(Duration.ofSeconds(10))){
   holder.setAutoCommit(false);holder.setTransactionIsolation(java.sql.Connection.TRANSACTION_READ_COMMITTED);
   IssuerPgLocks.entities(holder,IssuerPgLocks.entitySet(IssuerPgScope.from("ISSUER",IssuerFixtureAuthority.physical(NAMESPACE)),Map.of(changed.getStorageKey(),true)),System.nanoTime()+Duration.ofSeconds(10).toNanos());
   var waiting=executor.submit(()->store.commit(txn,Duration.ofSeconds(5)));waitForBlocked(holder);
   point.set(healthy(txn.getTemporalCondition().orElseThrow().getValidBeforeExclusive().orElseThrow()));holder.rollback();
   check(waiting.get().getStatus()==OAuthStoreCommitStatus.TIME_EXPIRED,"actual-entity-wait-uses-fresh-exclusive-upper");
   point.set(healthy(NOW));holder.setAutoCommit(false);
   try(var lock=holder.prepareStatement("SELECT bucket FROM issuer_store_escrow WHERE namespace=? AND bucket=? FOR UPDATE")){lock.setString(1,IssuerFixtureAuthority.physical(NAMESPACE));lock.setInt(2,IssuerPgCapacity.bucket(changed.getStorageKey()));try(var rows=lock.executeQuery()){if(!rows.next())throw new AssertionError("No allocated bucket");}}
   waiting=executor.submit(()->store.commit(txn,Duration.ofSeconds(5)));waitForBlocked(holder);
   point.set(healthy(txn.getTemporalCondition().orElseThrow().getNotBeforeInclusive().minusNanos(1)));holder.rollback();
   check(waiting.get().getStatus()==OAuthStoreCommitStatus.TIME_BEFORE_FLOOR,"actual-escrow-wait-uses-fresh-inclusive-lower");
  }finally{executor.shutdownNow();if(!executor.awaitTermination(5,java.util.concurrent.TimeUnit.SECONDS))throw new AssertionError("Owned native wait worker leaked");}
  point.set(healthy(NOW));
  PostgresqlIssuerStore late=new PostgresqlIssuerStore(NAMESPACE,IssuerFixtureAuthority.physical(NAMESPACE),budget->{
   var physical=PendingStoreProbe.connection(budget);
   return (java.sql.Connection)java.lang.reflect.Proxy.newProxyInstance(java.sql.Connection.class.getClassLoader(),new Class<?>[]{java.sql.Connection.class},(proxy,method,arguments)->{
    try{Object value=method.invoke(physical,arguments);if(method.getName().equals("commit"))Thread.sleep(1200);return value;}catch(java.lang.reflect.InvocationTargetException failure){throw failure.getCause();}
   });
  },4096,(scope,budget)->point.get());
  OAuthStoreCommitReceipt receipt=late.commit(txn,Duration.ofSeconds(1));
  check(receipt.getStatus()==OAuthStoreCommitStatus.COMMITTED && receipt.getTiming().isPresent(),"late-known-commit-keeps-required-validation-timing");
 }
 private static void clockTransition(@NonNull PostgresqlIssuerStore store,@NonNull Capture capture,@NonNull OAuthAuthorizationServer prepared,@NonNull AtomicReference<@NonNull StoreTimeObservation> point,@NonNull String query,boolean generation)throws Exception{
  point.set(healthy(NOW));try{prepared.beginAuthorizationResult("GET",query,new byte[0],Map.of(),"A".repeat(43));throw new AssertionError("Capture must conflict");}catch(OAuthServerStoreException expected){if(expected.getReason()!=OAuthServerException.Reason.STORE_UNAVAILABLE)throw expected;}
  OAuthStoreTransaction txn=java.util.Objects.requireNonNull(capture.last);
  point.set(StoreTimeObservation.Healthy.fromObservation(IssuerFixtureAuthority.admission(NAMESPACE),generation?IssuerFixtureAuthority.identity("foreign-clock"):IssuerFixtureAuthority.clock(NAMESPACE),NOW,generation?Duration.ZERO:Duration.ofMillis(1)));
  String label=generation?"clock-generation-transition":"fixed-error-profile-transition";
  var read=store.read(txn.getConditions().get(0).getKey(),Duration.ofSeconds(5));
  check(read instanceof OAuthStoreReadResult.Available available && available.getEntry().isPresent() && available.getTimeObservation() instanceof StoreTimeObservation.Unavailable,label+"-preserves-data-admission-with-unavailable-time");
  check(store.commit(txn,Duration.ofSeconds(5)).getStatus()==OAuthStoreCommitStatus.FENCED,label+"-timed-write-fenced-zero-effect");
  OAuthAuthorizationServer server=IssuerStoreProbe.server(store);
  try{server.warmUp();throw new AssertionError("Timed service must stay closed");}catch(OAuthServerStoreException expected){check(expected.getReason()==OAuthServerException.Reason.STORE_UNAVAILABLE,label+"-ordinary-timed-service-closed");}
  String issuerDigest=IssuerFixtureAuthority.identity("https://issuer.example");
  OAuthStoreKey subjectKey=OAuthStoreKey.fromStoredForm("revetsec:as:1:"+issuerDigest+":SUBJECT_STATE:"+IssuerFixtureAuthority.identity("subject"));
  OAuthStoreKey rootKey=OAuthStoreKey.fromStoredForm("revetsec:as:1:"+issuerDigest+":ISSUER_STATE:"+issuerDigest);
  String subjectBefore=((OAuthStoreReadResult.Available)store.read(subjectKey,Duration.ofSeconds(5))).getEntry().orElseThrow().getVersion();
  String rootBefore=((OAuthStoreReadResult.Available)store.read(rootKey,Duration.ofSeconds(5))).getEntry().orElseThrow().getVersion();
  server.revokeSubject("subject");check(!subjectBefore.equals(((OAuthStoreReadResult.Available)store.read(subjectKey,Duration.ofSeconds(5))).getEntry().orElseThrow().getVersion()),label+"-genuine-existing-subject-fence-acknowledged");
  server.revokeAllGrants();check(!rootBefore.equals(((OAuthStoreReadResult.Available)store.read(rootKey,Duration.ofSeconds(5))).getEntry().orElseThrow().getVersion()),label+"-genuine-existing-issuer-fence-acknowledged");
 }
 public static void main(@NonNull String @NonNull [] args)throws Exception{
  AtomicReference<StoreTimeObservation> point=new AtomicReference<>(healthy(NOW));
  PostgresqlIssuerStore store=new PostgresqlIssuerStore(NAMESPACE,IssuerFixtureAuthority.physical(NAMESPACE),PendingStoreProbe::connection,4096,(scope,budget)->point.get());
  OAuthAuthorizationServer server=IssuerStoreProbe.server(store);
  check(server.initializeFreshIssuer().getStatus()==OAuthStoreCommitStatus.COMMITTED,"timed-root-initialization");
  server.establishNewSubject("subject");check(true,"genuine-existing-subject-for-clock-transition");
  Capture capture=new Capture(store);OAuthAuthorizationServer prepared=IssuerStoreProbe.server(capture);
  String query="client_id=client&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&resource=https%3A%2F%2Fresource.example%2Fmcp&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&state=fixture";
  try{prepared.beginAuthorizationResult("GET",query,new byte[0],Map.of(),"A".repeat(43));throw new AssertionError("Capture must conflict");}catch(OAuthServerStoreException expected){check(expected.getReason()==OAuthServerException.Reason.STORE_UNAVAILABLE,"captured-genuine-timed-attempt");}
  OAuthStoreTransaction txn=java.util.Objects.requireNonNull(capture.last);var temporal=txn.getTemporalCondition().orElseThrow();
  check(txn.getPurpose()==OAuthStoreTransaction.Purpose.TIMED && temporal.getValidBeforeExclusive().isPresent(),"timed-original-finite-condition");
  point.set(healthy(temporal.getNotBeforeInclusive().minusNanos(1)));
  check(store.commit(txn,Duration.ofSeconds(5)).getStatus()==OAuthStoreCommitStatus.TIME_BEFORE_FLOOR,"fresh-authority-lower-refusal");
  point.set(healthy(temporal.getValidBeforeExclusive().orElseThrow()));
  check(store.commit(txn,Duration.ofSeconds(5)).getStatus()==OAuthStoreCommitStatus.TIME_EXPIRED,"exclusive-upper-equality-refusal");
  point.set(StoreTimeObservation.Unavailable.fromAdmission(IssuerFixtureAuthority.admission(NAMESPACE)));
  check(store.commit(txn,Duration.ofSeconds(5)).getStatus()==OAuthStoreCommitStatus.TIME_UNAVAILABLE,"utc-outage-timed-zero-effect");
  point.set(StoreTimeObservation.Unavailable.fromAdmission(IssuerFixtureAuthority.admission("foreign")));
  check(store.commit(txn,Duration.ofSeconds(5)).getStatus()==OAuthStoreCommitStatus.FENCED,"authority-mismatch-fenced");
  point.set(healthy(NOW));
  OAuthStoreCommitReceipt committed=store.commit(txn,Duration.ofSeconds(5));
  check(committed.getStatus()==OAuthStoreCommitStatus.COMMITTED && committed.getTiming().orElseThrow().getValidatedTime().getObservedAt().equals(NOW),"timed-known-commit-validation-receipt");
  check(store.commit(txn,Duration.ofSeconds(5)).getStatus()==OAuthStoreCommitStatus.CONFLICT,"exact-absence-replay-conflict");
  waitChecks(store,capture,prepared,point,query);
  clockTransition(store,capture,prepared,point,query,true);
  clockTransition(store,capture,prepared,point,query,false);
  point.set(StoreTimeObservation.Unavailable.fromAdmission(IssuerFixtureAuthority.admission(NAMESPACE)));
  Capture fenceCapture=new Capture(store);OAuthAuthorizationServer fenceServer=IssuerStoreProbe.server(fenceCapture);
  try{fenceServer.revokeAllGrants();throw new AssertionError("Capture must conflict");}catch(OAuthServerStoreException expected){check(expected.getReason()==OAuthServerException.Reason.STORE_UNAVAILABLE,"captured-existing-fence-under-utc-outage");}
  OAuthStoreTransaction fence=java.util.Objects.requireNonNull(fenceCapture.last);
  check(fence.getPurpose()==OAuthStoreTransaction.Purpose.FENCE_ONLY && fence.getTemporalCondition().isEmpty() && fence.getConditions().size()==1 && fence.getMutations().size()==1,"narrow-existing-root-fence-shape");
  OAuthStoreCommitReceipt fenced=store.commit(fence,Duration.ofSeconds(5));
  check(fenced.getStatus()==OAuthStoreCommitStatus.COMMITTED && fenced.getAdmission().isPresent() && fenced.getTiming().isEmpty(),"no-utc-fence-factual-admission-receipt");
  check(store.commit(fence,Duration.ofSeconds(5)).getStatus()==OAuthStoreCommitStatus.CONFLICT,"fence-replay-exact-version-conflict");
  check(store.read(fence.getConditions().get(0).getKey(),Duration.ZERO) instanceof OAuthStoreReadResult.Unavailable,"zero-budget-read-unavailable");
  check(store.commit(fence,Duration.ZERO).getStatus()==OAuthStoreCommitStatus.UNAVAILABLE,"zero-budget-write-no-effect");
 }
}
