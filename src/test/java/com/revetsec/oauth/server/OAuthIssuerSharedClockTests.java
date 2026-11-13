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

package com.revetsec.oauth.server;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.ScriptedOAuthStore;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Independent worker/authority controls and genuine public issuance; no live-witness/durability claim. */
final class OAuthIssuerSharedClockTests {
 private static final @NonNull Instant NOW=Instant.parse("2026-10-04T12:00:00Z");
 private static final @NonNull String ISSUER="https://issuer.example/clock",RESOURCE="https://resource.example/mcp",REDIRECT="https://client.example/cb";
 private static final @NonNull String BROWSER="A".repeat(43),VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private final @NonNull OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture(NOW);
 private final @NonNull Worker clock=new Worker();
 private final @NonNull OAuthStoreRecordCodec codec=new OAuthStoreRecordCodec(ISSUER,sealer(),3800);
 private final @NonNull OAuthStoreCoordinator coordinator=new OAuthStoreCoordinator(this.store,this.codec,this.clock,3,255);
 private @Nullable Runnable policyHook;
 private int policies;
 private @NonNull OAuthServerObserver observer=OAuthServerObserver.disabledInstance();
 private static @NonNull StateSealer sealer(){byte[] b=new byte[32];for(int n=0;n<b.length;n++)b[n]=(byte)(n+1);return StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(b))).build();}
 private static @NonNull Deadline deadline(){return Deadline.fromNow(Duration.ofSeconds(10));}
 private void initialized(){assertEquals(OAuthStoreCommitStatus.COMMITTED,this.coordinator.initializeFreshIssuerResult(deadline()).getStatus());}
 private void subject(){this.coordinator.establishNewSubject("subject",deadline());}
 private @NonNull OAuthStoreEntry root(){return requireNonNull(this.store.rows.get(this.codec.issuerKey()));}
 private @NonNull OAuthStoreEntry subjectEntry(){return requireNonNull(this.store.rows.get(this.codec.subjectKey("subject")));}
 private static void failed(OAuthStoreFailure.@NonNull Reason reason,org.junit.jupiter.api.function.@NonNull Executable action){assertEquals(reason,assertThrows(OAuthStoreFailure.class,action).reason());}
 private @NonNull OAuthStoreEntry replacement(OAuthStoreCoordinator.@NonNull Session session){return session.seal(this.codec.subjectKey("subject"),OAuthStoreFormat.PERMANENT,session.subject("subject").toPayload());}
 private OAuthStoreRecordCodecV2.@NonNull Opened opened(@NonNull OAuthStoreEntry entry){return this.codec.openAdmitted(entry,Clock.fixed(this.store.authorityNow,ZoneOffset.UTC));}
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> migrationCatchupChecksBothImmutableMinimumAndEntityFloor(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();
  for(int shape=0;shape<3;shape++)for(int edge=-1;edge<=1;edge++){
   Instant minimum=NOW.plusSeconds(shape==0?10:1),floor=NOW.plusSeconds(shape==1?10:shape==2?20:1);
   Instant bound=minimum.isAfter(floor)?minimum:floor,now=bound.plusNanos(edge);int position=edge;
   cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG11/ISSUER/"+shape+"/"+edge,()->{
    OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();
    var root=OAuthIssuerRootV2.decode(f.opened(f.root()).payload());var pinned=OAuthIssuerRootV2.initial(root.incarnation(),f.store.admission.getAuthorityId(),minimum);
    f.store.rows.put(f.codec.issuerKey(),f.codec.sealAdmitted(f.codec.issuerKey(),OAuthStoreFormat.PERMANENT,minimum,pinned.toPayload()));
    var subject=f.subjectEntry();f.store.rows.put(subject.getKey(),f.codec.sealAdmitted(subject.getKey(),OAuthStoreFormat.PERMANENT,floor,f.opened(subject).payload().toJson()));
    f.store.authorityNow=now;f.clock.time=now;var before=Map.copyOf(f.store.rows);int commits=f.store.commits;
    if(position<0)failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->f.coordinator.begin(deadline()).subject("subject"));else assertNotNull(f.coordinator.begin(deadline()).subject("subject"));
    assertEquals(commits,f.store.commits);assertEquals(before,f.store.rows);assertEquals(minimum,f.opened(f.root()).floor());assertEquals(floor,f.opened(f.subjectEntry()).floor());
   }));
  }return cases;
 }
 @Test void ordinaryRegistrationAndBarrierNeverRewriteStableRoot(){initialized();String version=root().getVersion();subject();this.store.authorityNow=NOW.plusSeconds(1);this.clock.time=this.store.authorityNow;assertEquals(OAuthStoreCommitStatus.COMMITTED,this.coordinator.begin(deadline()).barrier());assertEquals(version,root().getVersion());assertEquals(NOW,OAuthIssuerRootV2.decode(opened(root()).payload()).minimum());assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());}
 @Test void authorityTimeNotWorkerTimeDeterminesEntityFloor(){initialized();this.clock.time=NOW.plusSeconds(1);subject();assertEquals(NOW,opened(subjectEntry()).floor());assertEquals(NOW,OAuthIssuerRootV2.decode(opened(root()).payload()).minimum());}
 @Test void alreadyFastWorkerCannotWriteOrPoisonRoot(){initialized();String version=root().getVersion();int commits=this.store.commits;this.clock.time=NOW.plusSeconds(6);failed(OAuthStoreFailure.Reason.UNAVAILABLE,this::subject);assertEquals(commits,this.store.commits);assertEquals(version,root().getVersion());}
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk01OneHourFastWorkerCannotPoisonZeroOrNearZeroSkewService(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();
  for(int skewNanos:List.of(0,1))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-01/ISSUER/fast=1h/protocolSkew="+skewNanos+"ns",()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var before=Map.copyOf(f.store.rows);int commits=f.store.commits;
   Duration skew=Duration.ofNanos(skewNanos);f.clock.time=NOW.plusSeconds(3600);OAuthAuthorizationServer fast=f.server(f.store,f.clock,skew);
   assertEquals(OAuthServerException.Reason.STORE_UNAVAILABLE,assertThrows(OAuthServerStoreException.class,()->f.code(fast)).getReason());
   assertEquals(commits,f.store.commits);assertEquals(before,f.store.rows);
   Worker healthyWorker=new Worker();healthyWorker.time=NOW.plusNanos(skewNanos);OAuthAuthorizationServer healthy=f.server(f.store,healthyWorker,skew);
   String code=f.code(healthy);assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(healthy,code));
   OAuthStoreEntry root=before.get(f.codec.issuerKey());assertNotNull(root);assertEquals(root.getVersion(),f.root().getVersion());assertEquals(root.toSealedForm(),f.root().toSealedForm());
   for(var entry:f.store.rows.values())assertEquals(NOW,f.opened(entry).floor());
  }));return cases;
 }
 @Test void workerClockIsSampledAfterReadReply(){initialized();int commits=this.store.commits;this.store.beforeRead=()->this.clock.time=NOW.plusSeconds(6);failed(OAuthStoreFailure.Reason.UNAVAILABLE,this::subject);assertEquals(commits,this.store.commits);}
 @Test void negativeMinimumIsNotSilentlyIgnored(){initialized();OAuthIssuerRootV2 old=OAuthIssuerRootV2.decode(opened(root()).payload());OAuthIssuerRootV2 migrated=OAuthIssuerRootV2.initial(old.incarnation(),this.store.admission.getAuthorityId(),Instant.ofEpochSecond(-1));this.store.rows.put(this.codec.issuerKey(),this.codec.sealAdmitted(this.codec.issuerKey(),OAuthStoreFormat.PERMANENT,migrated.minimum(),migrated.toPayload()));failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->this.coordinator.begin(deadline()));}
 @Test void futureMinimumKeepsTimedAdmissionClosed(){initialized();OAuthIssuerRootV2 old=OAuthIssuerRootV2.decode(opened(root()).payload());OAuthIssuerRootV2 migrated=OAuthIssuerRootV2.initial(old.incarnation(),this.store.admission.getAuthorityId(),NOW.plusNanos(1));this.store.rows.put(this.codec.issuerKey(),this.codec.sealAdmitted(this.codec.issuerKey(),OAuthStoreFormat.PERMANENT,migrated.minimum(),migrated.toPayload()));failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->this.coordinator.begin(deadline()));}
 @Test void negativeEntityFloorKeepsTimedAdmissionClosed(){initialized();subject();OAuthStoreEntry old=subjectEntry();this.store.rows.put(old.getKey(),this.codec.sealAdmitted(old.getKey(),old.getRetainUntil(),Instant.ofEpochSecond(-1),opened(old).payload().toJson()));failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->this.coordinator.begin(deadline()).subject("subject"));}
 @Test void futureEntityFloorKeepsTimedAdmissionClosed(){initialized();subject();OAuthStoreEntry old=subjectEntry();this.store.rows.put(old.getKey(),this.codec.sealAdmitted(old.getKey(),old.getRetainUntil(),NOW.plusNanos(1),opened(old).payload().toJson()));failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->this.coordinator.begin(deadline()).subject("subject"));}
 @Test void foreignAuthorityRootIsCorruptNotInitialization(){initialized();OAuthIssuerRootV2 old=OAuthIssuerRootV2.decode(opened(root()).payload());OAuthIssuerRootV2 other=OAuthIssuerRootV2.initial(old.incarnation(),"A".repeat(43),NOW);this.store.rows.put(this.codec.issuerKey(),this.codec.sealAdmitted(this.codec.issuerKey(),OAuthStoreFormat.PERMANENT,NOW,other.toPayload()));failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->this.coordinator.begin(deadline()));}
 @Test void recoveryChangeBetweenIndividualReadsRefusesMixedTuple(){initialized();subject();var session=this.coordinator.begin(deadline());this.store.admission=StoreAdmission.fromIdentifiers(this.store.admission.getAuthorityId(),"A".repeat(43));int commits=this.store.commits;failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->session.subject("subject"));assertEquals(commits,this.store.commits);}
 @Test void clockGenerationChangeBetweenReadsRefusesMixedProfile(){initialized();subject();var session=this.coordinator.begin(deadline());this.store.clockGeneration="A".repeat(43);failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->session.subject("subject"));}
 @Test void finalJoinDetectsChangedExactPreparedSubjectBeforeSubmit(){initialized();subject();var session=this.coordinator.begin(deadline());OAuthStoreEntry change=replacement(session);this.coordinator.revokeSubject("subject",deadline());int commits=this.store.commits;assertEquals(OAuthStoreCommitStatus.CONFLICT,session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));assertEquals(commits,this.store.commits);assertEquals(1,this.coordinator.begin(deadline()).subject("subject").epoch());}
 @Test void originalUpperIsNotExtendedByFreshFinalJoin(){initialized();subject();var session=this.coordinator.begin(deadline());OAuthStoreEntry change=replacement(session);session.requireBefore(NOW.plusSeconds(1));this.store.authorityNow=NOW.plusSeconds(1);this.clock.time=this.store.authorityNow;int commits=this.store.commits;OAuthServerAdmissionFailure failure=assertThrows(OAuthServerAdmissionFailure.class,()->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,failure.reason());assertEquals(commits,this.store.commits);}
 @Test void storeTemporalEqualityRefusesWithZeroEffect(){initialized();subject();var session=this.coordinator.begin(deadline());OAuthStoreEntry old=subjectEntry(),change=replacement(session);session.requireBefore(NOW.plusSeconds(1));this.store.beforeCommit=()->{this.store.authorityNow=NOW.plusSeconds(1);this.clock.time=this.store.authorityNow;};assertThrows(OAuthServerAdmissionFailure.class,()->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));assertEquals(old.getVersion(),subjectEntry().getVersion());}
 @Test void knownCommitFinalOutageReconcilesRatherThanBecomingUnknown(){initialized();this.store.afterCommit=()->this.store.healthy=false;failed(OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,this::subject);assertTrue(this.store.rows.containsKey(this.codec.subjectKey("subject")));}
 @Test void knownCommitDeadlineLossReconcilesRatherThanBecomingUnknown(){initialized();this.store.afterCommit=()->LockSupport.parkNanos(Duration.ofMillis(350).toNanos());failed(OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,()->this.coordinator.establishNewSubject("subject",Deadline.fromNow(Duration.ofMillis(300))));assertTrue(this.store.rows.containsKey(this.codec.subjectKey("subject")));}
 @Test void appliedUnknownNeverRetriesOrUsesFinalReadToRescue(){initialized();this.store.unknownAfter=true;int commits=this.store.commits;failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,this::subject);assertEquals(commits+1,this.store.commits);assertTrue(this.store.rows.containsKey(this.codec.subjectKey("subject")));}
 @Test void unknownEmptyBarrierIsUnavailableWithoutBusinessUncertainty(){initialized();this.store.unknownBefore=true;failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->this.coordinator.begin(deadline()).barrier());}
 @Test void missingOptionalCompletionAllowsFreshFinalRootRead(){initialized();subject();var session=this.coordinator.begin(deadline());assertEquals(OAuthStoreCommitStatus.COMMITTED,session.barrier());assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());}
 @Test void fenceOnlyWorksWithoutUtcAndWithoutUsableWorkerClock(){initialized();subject();OAuthStoreEntry before=root(),oldSubject=subjectEntry();this.store.healthy=false;this.clock.broken=true;assertEquals(1,this.coordinator.revokeSubject("subject",deadline()).epoch());assertEquals(1,this.coordinator.revokeAll(deadline()).epoch());OAuthStoreTransaction transaction=requireNonNull(this.store.lastTransaction);assertEquals(OAuthStoreTransaction.Purpose.FENCE_ONLY,transaction.getPurpose());assertTrue(transaction.getTemporalCondition().isEmpty());assertEquals(1,transaction.getConditions().size());assertEquals(1,transaction.getMutations().size());var rootAfter=this.codec.openPermanentFence(root(),this.store.admission,root());var subjectAfter=this.codec.openPermanentFence(subjectEntry(),this.store.admission,root());assertEquals(this.codec.openPermanentFence(before,this.store.admission,before).floor(),rootAfter.floor());assertEquals(this.codec.openPermanentFence(oldSubject,this.store.admission,before).floor(),subjectAfter.floor());}
 @Test void fenceOnlyFinalRecoveryLossWithholdsAckButKeepsKnownEpoch(){initialized();subject();this.store.healthy=false;this.store.afterCommit=()->this.store.admission=StoreAdmission.fromIdentifiers(this.store.admission.getAuthorityId(),"A".repeat(43));failed(OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,()->this.coordinator.revokeSubject("subject",deadline()));assertEquals(1,OAuthStoreFence.decode(this.codec.openPermanentFence(subjectEntry(),this.store.admission,root()).payload(),OAuthStoreKey.Kind.SUBJECT_STATE).epoch());}
 @Test void fenceOnlyIgnoresClockGenerationChangeButKeepsRecoveryBinding(){initialized();this.store.healthy=false;this.store.afterCommit=()->this.store.clockGeneration="A".repeat(43);assertEquals(1,this.coordinator.revokeAll(deadline()).epoch());}
 @Test void fenceOnlyNeverCreatesMissingSubject(){initialized();this.store.healthy=false;int commits=this.store.commits;failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->this.coordinator.revokeSubject("missing",deadline()));assertEquals(commits,this.store.commits);}
 @Test void rawInitializationPreservesLateKnownCommit(){this.store.afterCommit=()->LockSupport.parkNanos(Duration.ofMillis(350).toNanos());OAuthStoreCommitReceipt receipt=this.coordinator.initializeFreshIssuerResult(Deadline.fromNow(Duration.ofMillis(300)));assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());assertTrue(receipt.getTiming().isPresent());assertTrue(this.store.rows.containsKey(this.codec.issuerKey()));}
 @Test void rawResealPreservesFloorAndKnownCommitDuringPostAckOutage(){initialized();subject();OAuthStoreEntry old=subjectEntry();Instant floor=opened(old).floor();this.store.authorityNow=NOW.plusSeconds(1);this.clock.time=this.store.authorityNow;this.store.afterCommit=()->this.store.healthy=false;OAuthStoreCommitReceipt receipt=this.coordinator.reseal(old.getKey(),deadline());assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());assertNotEquals(old.getVersion(),subjectEntry().getVersion());assertEquals(floor,this.codec.openPermanentFence(subjectEntry(),this.store.admission,root()).floor());}
 @Test void rawResealUnknownPreservesFactualUncertainty(){initialized();subject();this.store.unknownAfter=true;assertEquals(OAuthStoreCommitStatus.UNKNOWN,this.coordinator.reseal(this.codec.subjectKey("subject"),deadline()).getStatus());}

 @Test void signingLifecycleUsesSuppliedAuthorityInsteadOfWorkerClock(){
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;OAuthIssuerKeySnapshot snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(1)).retirementNotBefore(Map.of("key",NOW.plusSeconds(2))).build();
  OAuthGrantRetention retention=new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO);
  OAuthIssuerKeyLifecycle lifecycle=new OAuthIssuerKeyLifecycle(OAuthIssuerKeyProvider.fromSnapshot(snapshot),Clock.fixed(NOW.plusSeconds(10),ZoneOffset.UTC),Duration.ZERO,retention,true);
  AtomicInteger samples=new AtomicInteger();String signed=lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(1),deadline(),()->{samples.incrementAndGet();return NOW;});
  assertFalse(signed.isEmpty());assertEquals(2,samples.get());
 }
 @Test void postSignRetirementCheckResamplesAuthorityBeforeOutput(){
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;OAuthIssuerKeySnapshot snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(1)).retirementNotBefore(Map.of("key",NOW.plusSeconds(2))).build();
  OAuthGrantRetention retention=new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO);
  OAuthIssuerKeyLifecycle lifecycle=new OAuthIssuerKeyLifecycle(OAuthIssuerKeyProvider.fromSnapshot(snapshot),Clock.fixed(NOW,ZoneOffset.UTC),Duration.ZERO,retention,true);
  AtomicInteger samples=new AtomicInteger();assertEquals(OAuthServerException.Reason.SIGNING_FAILED,assertThrows(OAuthServerSigningException.class,()->lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(1),deadline(),()->samples.incrementAndGet()==1?NOW:NOW.plusSeconds(3))).getReason());assertEquals(2,samples.get());
 }
 private static final class Worker extends Clock {
  private @NonNull Instant time=NOW;private boolean broken;private java.util.concurrent.@Nullable CopyOnWriteArrayList<@NonNull String> phaseTrace;
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
  @Override public @NonNull Instant instant(){var trace=this.phaseTrace;if(trace!=null)trace.add("worker-wall");if(this.broken)throw new IllegalStateException("unusable worker clock");return this.time;}
 }
 private @NonNull OAuthAuthorizationServer server(){return server(this.store);}
 private @NonNull OAuthAuthorizationServer server(@NonNull OAuthAuthorizationServerStore selected){
  return server(selected,this.clock,Duration.ZERO);
 }
 private @NonNull OAuthAuthorizationServer server(@NonNull OAuthAuthorizationServerStore selected,@NonNull Clock workerClock,@NonNull Duration skew){
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;OAuthIssuerKeySnapshot snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
  OAuthServerClientRegistration client=OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(Map.of(RESOURCE,Set.of("read"))).refreshTokenPermitted(true).build();
  return OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke")).introspectionEndpoint(URI.create(ISSUER+"/introspect"))
   .clientRepository((id,budget)->Optional.of(id.equals("resource")?resourceClient():client)).store(selected).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(snapshot)).stateSealer(sealer()).resources(Map.of(RESOURCE,Set.of("read"))).clock(workerClock).clockSkew(skew).totalDeadline(Duration.ofSeconds(1)).requestTimeout(Duration.ofSeconds(1)).observer(this.observer).refreshTokensEnabled(true)
   .grantPolicy((context,budget)->{this.policies++;Runnable hook=this.policyHook;this.policyHook=null;if(hook!=null)hook.run();return decision();}).build();
 }
 private static @NonNull OAuthServerClientRegistration resourceClient(){return OAuthServerClientRegistration.withClientId("resource").configurationVersion("r1").authorizationCodePermitted(false).introspectionResources(Set.of(RESOURCE)).authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->java.util.Arrays.equals(secret,"secret".getBytes(StandardCharsets.UTF_8)))).build();}

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi02ErrorProfileCannotChangeDuringAssemblyReceiptOrFinalRead(){
  List<org.junit.jupiter.api.DynamicTest> tests=new java.util.ArrayList<>();
  for(Duration initial:List.of(Duration.ZERO,Duration.ofMillis(250)))for(String stage:List.of("CONTROL","READ","VALIDATION","FINAL")){
   Duration changed=initial.isZero()?Duration.ofMillis(250):Duration.ZERO;
   tests.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-02/ISSUER_NORMAL/"+stage+"/"+initial,()->{
    OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.store.maximumUtcError=initial;f.initialized();f.subject();
    int commits=f.store.commits;String version=f.root().getVersion();
    if(stage.equals("READ")){
     var session=f.coordinator.begin(deadline());f.store.maximumUtcError=changed;
     failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->session.subject("subject"));assertEquals(commits,f.store.commits);
    }else{
     if(stage.equals("VALIDATION"))f.store.beforeCommit=()->f.store.maximumUtcError=changed;
     if(stage.equals("FINAL"))f.store.afterCommit=()->f.store.maximumUtcError=changed;
     if(stage.equals("CONTROL"))assertNotNull(f.coordinator.establishNewSubject("next-subject",deadline()));
     else failed(OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,()->f.coordinator.establishNewSubject("next-subject",deadline()));
     assertEquals(commits+1,f.store.commits);assertTrue(f.store.rows.containsKey(f.codec.subjectKey("next-subject")));
    }
    assertEquals(version,f.root().getVersion());
   }));
  }
  return tests;
 }
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi02FenceOnlyUsesAdmissionDomainsWithoutTimedProfile(){
  List<org.junit.jupiter.api.DynamicTest> tests=new java.util.ArrayList<>();
  for(boolean all:List.of(false,true))for(boolean healthy:List.of(false,true))for(String change:List.of("CONTROL","CLOCK","ERROR","AUTHORITY","RECOVERY")){
   tests.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-02/ISSUER_FENCE_ONLY/"+all+"/"+healthy+"/"+change,()->{
    OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();f.store.healthy=healthy;f.clock.broken=true;
    f.store.afterCommit=()->{
     if(change.equals("CLOCK"))f.store.clockGeneration="A".repeat(43);
     if(change.equals("ERROR"))f.store.maximumUtcError=Duration.ofMillis(250);
     if(change.equals("AUTHORITY"))f.store.admission=StoreAdmission.fromIdentifiers("A".repeat(43),f.store.admission.getRecoveryGeneration());
     if(change.equals("RECOVERY"))f.store.admission=StoreAdmission.fromIdentifiers(f.store.admission.getAuthorityId(),"A".repeat(43));
    };
    org.junit.jupiter.api.function.Executable action=()->{if(all)f.coordinator.revokeAll(deadline());else f.coordinator.revokeSubject("subject",deadline());};
    if(change.equals("AUTHORITY") || change.equals("RECOVERY"))failed(OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,action);
    else assertDoesNotThrow(action);
    var transaction=requireNonNull(f.store.lastTransaction);assertEquals(OAuthStoreTransaction.Purpose.FENCE_ONLY,transaction.getPurpose());
    assertTrue(transaction.getTemporalCondition().isEmpty());assertEquals(1,transaction.getMutations().size());
    assertEquals(all?1:2,transaction.getConditions().size());
   }));
  }
  return tests;
 }
 @Test void scApi02InvalidLocalSubjectDoesNotLookUpStoreInNormalOrFenceOnlyMode(){
  int reads=this.store.reads,commits=this.store.commits;
  for(String subject:List.of("","s".repeat(256),"\ud800")){
   assertThrows(IllegalArgumentException.class,()->this.coordinator.establishNewSubject(subject,deadline()));
   assertThrows(IllegalArgumentException.class,()->this.coordinator.revokeSubject(subject,deadline()));
   assertEquals(reads,this.store.reads);assertEquals(commits,this.store.commits);assertTrue(this.store.rows.isEmpty());
  }
 }
 private static @NonNull OAuthAuthorizationDecision decision(){return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(RESOURCE,Set.of("read"))).refreshTokenPermitted(true).build();}
 private static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> values){return String.join("&",values.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());}
 private static @NonNull String encode(@NonNull String value){try{return FormUrlEncoding.encode(value);}catch(com.revetsec.internal.encoding.EncodingException failure){throw new AssertionError(failure);}}
 private @NonNull String code(@NonNull OAuthAuthorizationServer server){
  String query=form(Map.of("client_id","client","response_type","code","redirect_uri",REDIRECT,"resource",RESOURCE,"code_challenge",CHALLENGE,"code_challenge_method","S256"));
  OAuthServerInteraction interaction=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,server.beginAuthorizationResult("GET",query,new byte[0],Map.of(),BROWSER)).getInteraction();
  OAuthServerResponse response=assertInstanceOf(OAuthAuthorizationResult.Completed.class,server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision())).getResponse();
  String location=response.getLocationWithCredentials().orElseThrow().toString();return location.substring(location.indexOf("code=")+5,location.indexOf("&iss="));
 }
 private static @NonNull OAuthTokenResult redeem(@NonNull OAuthAuthorizationServer server,@NonNull String code){return server.tokenResult("POST",null,form(Map.of("grant_type","authorization_code","client_id","client","resource",RESOURCE,"code",code,"code_verifier",VERIFIER,"redirect_uri",REDIRECT)).getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded")));}
 private @NonNull OAuthAuthorizationRecord record(@NonNull OAuthStoreEntry entry){return OAuthAuthorizationRecord.decode(entry.getKey().getKind(),OAuthStoreRecordCodecV2.identifier(entry.getKey()),opened(entry).payload(),new OAuthServerIngressLimits(65536,65536,65536,4096,4096,1024,64,128,128),255);}
 @Test void genuineRedemptionRejoinsAfterSlowPolicyBeforeCodeConsumption(){initialized();subject();OAuthAuthorizationServer server=server();String code=code(server);OAuthStoreKey key=this.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));this.policyHook=()->{LockSupport.parkNanos(Duration.ofMillis(120).toNanos());this.coordinator.revokeSubject("subject",deadline());};int before=this.policies;assertInstanceOf(OAuthTokenResult.Rejected.class,redeem(server,code));assertEquals(before+1,this.policies);assertEquals("UNUSED",record(requireNonNull(this.store.rows.get(key))).text("status"));assertTrue(this.store.rows.keySet().stream().noneMatch(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN));}
 @Test void genuineFullConflictRetryRepeatsPolicyWithFreshFacts(){initialized();subject();OAuthAuthorizationServer server=server();String code=code(server);this.policyHook=()->this.store.conflicts=1;int before=this.policies;assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code));assertEquals(before+2,this.policies);}
 @Test void genuineCommittedConsumptionWithWithheldOutputIsNotRescued(){initialized();subject();OAuthAuthorizationServer server=server();String code=code(server);OAuthStoreKey key=this.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));this.store.afterCommit=()->this.store.healthy=false;OAuthServerStoreException failure=assertThrows(OAuthServerStoreException.class,()->redeem(server,code));assertEquals(OAuthServerException.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,failure.getReason());assertEquals("USED",record(requireNonNull(this.store.rows.get(key))).text("status"));this.store.healthy=true;assertInstanceOf(OAuthTokenResult.Rejected.class,redeem(server,code));}
 @Test void genuineAppliedUnknownConsumptionStopsWithoutFinalReadRescue(){initialized();subject();OAuthAuthorizationServer server=server();String code=code(server);this.store.unknownAfter=true;int commits=this.store.commits;assertEquals(OAuthServerException.Reason.COMMIT_OUTCOME_UNKNOWN,assertThrows(OAuthServerStoreException.class,()->redeem(server,code)).getReason());assertEquals(commits+1,this.store.commits);}
 @Test void publicProofExpiryUsesAuthorityWhileWorkerLagsWithinHealthBound(){
  initialized();subject();OAuthAuthorizationServer server=server();String code=code(server);OAuthServerResponse response=assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code)).getResponse();JsonObject body;
  try{body=(JsonObject)JsonCodec.parse(response.toHttpBodyWithCredentials(),JsonLimits.protocolDocument(131072));}catch(com.revetsec.internal.json.JsonParseException failure){throw new AssertionError(failure);}
  String token=((com.revetsec.json.JsonString)body.find("access_token").orElseThrow()).getValue();
  OAuthStoreEntry access=this.store.rows.entrySet().stream().filter(e->e.getKey().getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).findFirst().orElseThrow().getValue();
  this.store.authorityNow=record(access).expires();this.clock.time=this.store.authorityNow.minusSeconds(4);
  com.revetsec.oauth.BearerToken bearer=assertInstanceOf(com.revetsec.oauth.BearerTokenResult.Present.class,com.revetsec.oauth.BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+token))).getToken();
  OAuthIssuerAccessTokenResult.Rejected rejected=assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,server.validateAccessTokenResult(bearer,RESOURCE));
  assertEquals(com.revetsec.oauth.AccessTokenValidationException.Reason.JWT_REJECTED,rejected.getAccessTokenReason().orElseThrow());assertEquals(com.revetsec.jose.JoseException.Reason.EXPIRED,rejected.getJoseReason().orElseThrow());
 }
 @Test void terminalObserverDelayWithholdsCommittedConsumptionAfterOneTerminalEvent(){
  initialized();subject();AtomicInteger will=new AtomicInteger(),did=new AtomicInteger(),failed=new AtomicInteger();
  this.observer=new OAuthServerObserver(){
   @Override public void willHandleEndpoint(@NonNull Endpoint endpoint){if(endpoint==Endpoint.TOKEN)will.incrementAndGet();}
   @Override public void didHandleEndpoint(@NonNull Endpoint endpoint,@Nullable Integer status,@NonNull Duration elapsed){if(endpoint==Endpoint.TOKEN){did.incrementAndGet();LockSupport.parkNanos(Duration.ofMillis(1100).toNanos());}}
   @Override public void didFailToHandleEndpoint(@NonNull Endpoint endpoint,@NonNull OAuthServerException failure,@NonNull Duration elapsed){if(endpoint==Endpoint.TOKEN)failed.incrementAndGet();}
  };
  OAuthAuthorizationServer server=server();String code=code(server);OAuthStoreKey key=this.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));
  assertEquals(OAuthServerException.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,assertThrows(OAuthServerStoreException.class,()->redeem(server,code)).getReason());
  assertEquals("USED",record(requireNonNull(this.store.rows.get(key))).text("status"));assertEquals(1,will.get());assertEquals(1,did.get());assertEquals(0,failed.get());
 }
 @Test void terminalObserverDelayCannotEraseRawInitializationTruth(){
  this.observer=new OAuthServerObserver(){@Override public void didHandleEndpoint(@NonNull Endpoint endpoint,@Nullable Integer status,@NonNull Duration elapsed){if(endpoint==Endpoint.ISSUER_INITIALIZATION){LockSupport.parkNanos(Duration.ofMillis(1100).toNanos());clock.broken=true;}}};
  OAuthStoreCommitReceipt receipt=server().initializeFreshIssuer();assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());assertTrue(receipt.getTiming().isPresent());assertTrue(this.store.rows.containsKey(this.codec.issuerKey()));
 }
 @Test void fastPublicJwksDoesNotPoisonHealthyIssuanceProofIntrospectionOrRevocation(){
  initialized();subject();OAuthAuthorizationServer server=server();this.clock.time=NOW.plusSeconds(6);assertEquals(200,server.jwksResponse("GET").getStatusCode());this.clock.time=NOW;
  String code=code(server);OAuthTokenResult result=assertDoesNotThrow(()->redeem(server,code));OAuthServerResponse response=assertInstanceOf(OAuthTokenResult.Succeeded.class,result).getResponse();JsonObject body;
  try{body=(JsonObject)JsonCodec.parse(response.toHttpBodyWithCredentials(),JsonLimits.protocolDocument(131072));}catch(com.revetsec.internal.json.JsonParseException failure){throw new AssertionError(failure);}
  String token=((com.revetsec.json.JsonString)body.find("access_token").orElseThrow()).getValue();
  com.revetsec.oauth.BearerToken bearer=assertInstanceOf(com.revetsec.oauth.BearerTokenResult.Present.class,com.revetsec.oauth.BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+token))).getToken();
  assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,assertDoesNotThrow(()->server.validateAccessTokenResult(bearer,RESOURCE)));assertDoesNotThrow(server::warmUp);
  Map<String,List<String>> headers=Map.of("Content-Type",List.of("application/x-www-form-urlencoded"),"Authorization",List.of("Basic "+Base64.getEncoder().encodeToString("resource:secret".getBytes(StandardCharsets.UTF_8))));
  assertInstanceOf(OAuthIntrospectionResult.Succeeded.class,assertDoesNotThrow(()->server.introspectionResult("POST",null,form(Map.of("token",token)).getBytes(StandardCharsets.UTF_8),headers)));
  assertInstanceOf(OAuthRevocationResult.Succeeded.class,assertDoesNotThrow(()->server.revokeResult("POST",null,form(Map.of("token",token,"client_id","client")).getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded")))));
  assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,server.validateAccessTokenResult(bearer,RESOURCE));
 }
 @Test void provisionalRetiredKeyRemovalCannotEraseAdmittedKeyHistory(){
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;OAuthIssuerSigningKey a=OAuthIssuerSigningKey.fromRsaKeyPair("a",key.getPrivateKey(),key.getPublicKey()),b=OAuthIssuerSigningKey.fromRsaKeyPair("b",key.getPrivateKey(),key.getPublicKey());
  OAuthIssuerKeySnapshot old=OAuthIssuerKeySnapshot.withActiveKey(a).generation("g1").publishedAt(NOW.minusSeconds(120)).retirementNotBefore(Map.of("a",NOW.plusSeconds(1000))).build();
  OAuthIssuerKeySnapshot future=OAuthIssuerKeySnapshot.withActiveKey(b).generation("g2").publishedAt(NOW.minusSeconds(60)).build();AtomicReference<OAuthIssuerKeySnapshot> provider=new AtomicReference<>(old);Worker worker=new Worker();
  OAuthIssuerKeyLifecycle lifecycle=new OAuthIssuerKeyLifecycle(budget->requireNonNull(provider.get()),worker,Duration.ZERO,new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO),true);
  assertNotNull(lifecycle.snapshot(deadline()));assertDoesNotThrow(()->lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(30),deadline(),()->NOW));
  provider.set(future);worker.time=NOW.plusSeconds(2000);assertEquals(Set.of("b"),lifecycle.snapshot(deadline()).getVerificationKeys().keySet());
  provider.set(old);worker.time=NOW;assertDoesNotThrow(()->lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(30),deadline(),()->NOW));
 }
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> retainedUsedCodeMaintenanceHasNoCredentialAdmissionOrExpiryGrace(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();
  for(String point:List.of("credential-equality","credential-after","retention-before","retention-equality","retention-after","authority-down","worker-broken","worker-fast")){
   cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG12/maintenance/"+point,()->{
    OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var server=f.server();String code=f.code(server);assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code));
    var key=f.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));var old=requireNonNull(f.store.rows.get(key));var payload=f.record(old);Instant floor=f.opened(old).floor();
    Instant now=switch(point){case "credential-equality"->payload.expires();case "retention-before"->old.getRetainUntil().minusNanos(1);case "retention-equality"->old.getRetainUntil();case "retention-after"->old.getRetainUntil().plusNanos(1);default->payload.expires().plusNanos(1);};
    f.store.authorityNow=now;f.clock.time=now;var before=Map.copyOf(f.store.rows);int commits=f.store.commits;
    if(point.equals("authority-down"))f.store.healthy=false;if(point.equals("worker-broken"))f.clock.broken=true;if(point.equals("worker-fast"))f.clock.time=now.plusSeconds(6);
    if(point.startsWith("authority")||point.startsWith("worker")){assertThrows(OAuthServerStoreException.class,()->server.resealStoreEntry(key));assertEquals(commits,f.store.commits);assertEquals(before,f.store.rows);}
    else if(!now.isBefore(old.getRetainUntil())){assertEquals(OAuthStoreCommitStatus.CONFLICT,server.resealStoreEntry(key).getStatus());assertEquals(commits,f.store.commits);assertEquals(before,f.store.rows);}
    else{
     assertEquals(OAuthStoreCommitStatus.COMMITTED,server.resealStoreEntry(key).getStatus());var next=requireNonNull(f.store.rows.get(key));assertNotEquals(old.getVersion(),next.getVersion());assertEquals(old.getRetainUntil(),next.getRetainUntil());assertEquals(payload.toPayload(),f.record(next).toPayload());assertEquals(floor,f.opened(next).floor());
     try{assertInstanceOf(OAuthTokenResult.Rejected.class,redeem(server,code));}
     catch(OAuthServerStoreException withheld){
      // A one-nanosecond retained interval cannot contain the final causal reply.
      assertEquals("retention-before",point);assertEquals(OAuthServerException.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,withheld.getReason());
     }
     assertEquals("USED",f.record(next).text("status"));
    }
   }));
  }return cases;
 }
 @Test void genuineRetainedUsedCodeCanResealAfterCredentialExpiry(){initialized();subject();OAuthAuthorizationServer server=server();String code=code(server);assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code));OAuthStoreKey key=this.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));OAuthStoreEntry old=requireNonNull(this.store.rows.get(key));OAuthAuthorizationRecord used=record(old);this.store.authorityNow=used.expires().plusSeconds(1);this.clock.time=this.store.authorityNow;assertFalse(this.store.authorityNow.isBefore(used.expires()));assertTrue(this.store.authorityNow.isBefore(old.getRetainUntil()));assertEquals(OAuthStoreCommitStatus.COMMITTED,server.resealStoreEntry(key).getStatus());OAuthStoreEntry next=requireNonNull(this.store.rows.get(key));assertEquals(old.getRetainUntil(),next.getRetainUntil());assertEquals(used.toPayload(),record(next).toPayload());assertEquals(opened(old).floor(),opened(next).floor());}
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig14PreparedFloorSurvivesLaterValidationAndCompletion(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();
  for(boolean initialize:List.of(false,true))for(int nano:List.of(1,123456789,999999999))for(boolean completed:List.of(false,true))for(int offset:List.of(-2,2))
   cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-14/ISSUER/timing/"+initialize+"/"+nano+"/"+completed+"/"+offset,()->{
    OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();if(!initialize)f.initialized();var before=Map.copyOf(f.store.rows);
    Instant at=NOW.plusSeconds(5).plusNanos(nano),validated=at.plusMillis(200),finished=validated.plusMillis(300);f.store.authorityNow=at;f.clock.time=at.plusSeconds(offset);
    OAuthAuthorizationServerStore delayed=new OAuthAuthorizationServerStore(){
     @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return f.store.read(key,budget);}
     @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){
      assertEquals(at,tx.getTemporalCondition().orElseThrow().getNotBeforeInclusive());f.store.authorityNow=validated;f.clock.time=validated.plusSeconds(offset);
      var receipt=f.store.commit(tx,budget);assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());var v=receipt.getTiming().orElseThrow().getValidatedTime();assertEquals(validated,v.getObservedAt());
      f.store.authorityNow=finished;f.clock.time=finished.plusSeconds(offset);var c=StoreTimeObservation.Healthy.fromObservation(v.getAdmission(),v.getClockGeneration(),finished,v.getMaximumUtcError());return OAuthStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(v,completed?c:null));
     }
    };
    var coordinator=new OAuthStoreCoordinator(delayed,f.codec,f.clock,3,255);
    if(initialize)assertEquals(OAuthStoreCommitStatus.COMMITTED,coordinator.initializeFreshIssuerResult(deadline()).getStatus());else assertEquals(0,coordinator.establishNewSubject("delayed-subject",deadline()).epoch());
    var tx=requireNonNull(f.store.lastTransaction);assertEquals(1,tx.getMutations().size());for(var mutation:tx.getMutations()){
     var input=mutation.getEntry().orElseThrow();var stored=requireNonNull(f.store.rows.get(input.getKey()));assertEquals(input.getVersion(),stored.getVersion());assertEquals(input.toSealedForm(),stored.toSealedForm());assertEquals(at,f.opened(stored).floor());
    }
    for(var key:before.keySet())assertSame(before.get(key),f.store.rows.get(key));
   }));return cases;
 }
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig14PublicProofStatusNeverRewritesFloorsOrCleansUp(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();
  for(int edge:List.of(-1,0,1))for(int offset:List.of(-2,0,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-14/ISSUER/status/"+edge+"/"+offset,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var server=f.server();String code=f.code(server);var response=assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code)).getResponse();
   var body=(JsonObject)JsonCodec.parse(response.toHttpBodyWithCredentials(),JsonLimits.protocolDocument(131072));String token=((com.revetsec.json.JsonString)body.find("access_token").orElseThrow()).getValue();var bearer=assertInstanceOf(com.revetsec.oauth.BearerTokenResult.Present.class,com.revetsec.oauth.BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+token))).getToken();
   var access=f.store.rows.entrySet().stream().filter(e->e.getKey().getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).findFirst().orElseThrow().getValue();Instant expiry=f.record(access).expires();Instant time=edge<0?expiry.minusSeconds(1):expiry.plusNanos(edge);f.store.authorityNow=time;f.clock.time=time.plusSeconds(offset);var before=Map.copyOf(f.store.rows);int commits=f.store.commits;
   var result=server.validateAccessTokenResult(bearer,RESOURCE);if(edge<0)assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,result);else assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,result);
   assertEquals(before,f.store.rows);if(f.store.commits>commits)assertTrue(requireNonNull(f.store.lastTransaction).getMutations().isEmpty());
  }));return cases;
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15BootstrapNeedsCurrentAuthorizationAndExactAbsence(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(String mode:List.of("CLEAN","CLOSED","UTC_DOWN","PRESENT"))for(int offset:List.of(-2,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/ISSUER/bootstrap/"+mode+"/"+offset,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();if(mode.equals("PRESENT"))f.initialized();f.clock.time=NOW.plusSeconds(offset);var before=Map.copyOf(f.store.rows);int commits=f.store.commits;var current=new java.util.concurrent.atomic.AtomicBoolean(!mode.equals("CLOSED"));if(mode.equals("UTC_DOWN"))f.store.healthy=false;
   OAuthAuthorizationServerStore guarded=f.mig15Guard(current);var coordinator=new OAuthStoreCoordinator(guarded,f.codec,f.clock,3,255);
   if(mode.equals("CLEAN")){assertEquals(OAuthStoreCommitStatus.COMMITTED,coordinator.initializeFreshIssuerResult(deadline()).getStatus());assertTrue(requireNonNull(f.store.lastTransaction).getConditions().get(0).getExpectedVersion().isEmpty());}
   else if(mode.equals("PRESENT")){assertEquals(OAuthStoreCommitStatus.CONFLICT,coordinator.initializeFreshIssuerResult(deadline()).getStatus());assertEquals(before,f.store.rows);assertEquals(commits,f.store.commits);}
   else {assertThrows(OAuthStoreFailure.class,()->coordinator.initializeFreshIssuerResult(deadline()));assertEquals(before,f.store.rows);assertEquals(commits,f.store.commits);current.set(true);f.store.healthy=true;assertEquals(OAuthStoreCommitStatus.COMMITTED,coordinator.initializeFreshIssuerResult(deadline()).getStatus());}
  }));return cases;
 }
 private @NonNull OAuthAuthorizationServerStore mig15Guard(@NonNull AtomicBoolean current){return new OAuthAuthorizationServerStore(){
  @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return current.get()?store.read(key,budget):OAuthStoreReadResult.Unavailable.get();}
  @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){return current.get()?store.commit(tx,budget):OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.UNAVAILABLE);}
 };}
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15KnownRootLossOrOrphansNeverBecomeFreshAbsence(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(String loss:List.of("ESTABLISHED_EMPTY","ESTABLISHED_RETAINED","ORPHAN"))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/ISSUER/root-loss/"+loss,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();if(loss.equals("ORPHAN")){var fence=OAuthStoreFence.initialSubject("A".repeat(43));var key=f.codec.subjectKey("subject");f.store.rows.put(key,f.codec.sealAdmitted(key,OAuthStoreFormat.PERMANENT,NOW,fence.toPayload()));}
   else {f.initialized();if(loss.equals("ESTABLISHED_RETAINED"))f.subject();f.store.rows.remove(f.codec.issuerKey());if(loss.equals("ESTABLISHED_EMPTY"))f.store.rows.clear();}
   var before=Map.copyOf(f.store.rows);int commits=f.store.commits;assertInstanceOf(OAuthStoreReadResult.Unavailable.class,f.store.read(f.codec.issuerKey(),Duration.ofSeconds(5)));assertThrows(OAuthStoreFailure.class,()->f.coordinator.initializeFreshIssuerResult(deadline()));assertThrows(OAuthStoreFailure.class,()->f.coordinator.begin(deadline()));assertEquals(before,f.store.rows);assertEquals(commits,f.store.commits);
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15ChangedAuthorityCannotRepairExistingRoot(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(int offset:List.of(-2,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/ISSUER/authority/"+offset,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var before=Map.copyOf(f.store.rows);int commits=f.store.commits;f.store.admission=StoreAdmission.fromIdentifiers("A".repeat(43),f.store.admission.getRecoveryGeneration());f.clock.time=NOW.plusSeconds(offset);assertThrows(OAuthStoreFailure.class,()->f.coordinator.begin(deadline()));assertThrows(OAuthStoreFailure.class,()->f.coordinator.initializeFreshIssuerResult(deadline()));assertEquals(before,f.store.rows);assertEquals(commits,f.store.commits);
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15ClockOnlyReadmissionKeepsOriginalCredentialUsable(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(boolean close:List.of(false,true))for(int offset:List.of(-2,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/ISSUER/clock/"+close+"/"+offset,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var current=new java.util.concurrent.atomic.AtomicBoolean(true);var server=f.server(f.mig15Guard(current));String code=f.code(server);var before=Map.copyOf(f.store.rows);var admission=f.store.admission;f.store.clockGeneration="A".repeat(43);f.clock.time=NOW.plusSeconds(offset);int commits=f.store.commits;
   if(close){current.set(false);assertThrows(OAuthServerStoreException.class,server::warmUp);assertEquals(before,f.store.rows);assertEquals(commits,f.store.commits);current.set(true);}
   server.warmUp();assertEquals(before,f.store.rows);assertEquals(admission,f.store.admission);assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code));assertSame(before.get(f.codec.issuerKey()),f.store.rows.get(f.codec.issuerKey()));
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15CompetingBootstrapCannotOverwriteWinner(){
  return List.of(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/ISSUER/absent-CAS",()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();AtomicReference<OAuthStoreEntry> winner=new AtomicReference<>();f.store.beforeCommit=()->{f.initialized();winner.set(f.root());};assertEquals(OAuthStoreCommitStatus.CONFLICT,f.coordinator.initializeFreshIssuerResult(deadline()).getStatus());assertSame(winner.get(),f.root());
  }));
 }

 @Test void cap09CapacityIsNotConflictOrCredentialRejectionAndNeverRetries() {
  initialized();subject();var before=Map.copyOf(this.store.rows);int commits=this.store.commits;AtomicInteger calls=new AtomicInteger();
  OAuthAuthorizationServerStore capacity=new OAuthAuthorizationServerStore(){
   @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return store.read(key,budget);}
   @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){calls.incrementAndGet();return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.CAPACITY);}
  };
  assertEquals(OAuthServerException.Reason.STORE_UNAVAILABLE,assertThrows(OAuthServerStoreException.class,()->server(capacity).establishNewSubject("cap09-subject")).getReason());
  assertEquals(1,calls.get());assertEquals(commits,this.store.commits);assertEquals(before,this.store.rows);
  assertDoesNotThrow(()->server().establishNewSubject("cap09-subject"));assertEquals(commits+1,this.store.commits);
 }


 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk02WorkerHealthLossAfterKnownCommitWithholdsOutputWithoutErasingMutation(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();for(int offset:List.of(-6,6))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-02/ISSUER_NORMAL/known-commit/worker="+offset+"s",()->{OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();OAuthStoreEntry root=f.root();int commits=f.store.commits;f.store.afterCommit=()->f.clock.time=NOW.plusSeconds(offset);failed(OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,f::subject);assertEquals(commits+1,f.store.commits);assertTrue(f.store.rows.containsKey(f.codec.subjectKey("subject")));assertEquals(root.getVersion(),f.root().getVersion());assertEquals(root.toSealedForm(),f.root().toSealedForm());}));return cells;
 }

 @Test void scClk03InitialIssuerReadMustSampleWorkerAfterItsOwnReply(){
  initialized();int commits=this.store.commits;OAuthStoreEntry before=root();this.store.beforeRead=()->this.clock.time=NOW.plusSeconds(6);failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->this.coordinator.begin(deadline()));assertEquals(commits,this.store.commits);assertEquals(before.getVersion(),root().getVersion());assertEquals(before.toSealedForm(),root().toSealedForm());
 }

 @Test void scClk03ActualReadCommitAndFinalReadKeepIdenticalNumericSamplesAfterReplies(){
  initialized();OAuthStoreEntry before=root();java.util.concurrent.CopyOnWriteArrayList<String> trace=new java.util.concurrent.CopyOnWriteArrayList<>();this.clock.phaseTrace=trace;OAuthAuthorizationServerStore traced=new OAuthAuthorizationServerStore(){
   @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){trace.add("read-call");OAuthStoreReadResult result=store.read(key,budget);trace.add("read-reply");return result;}
   @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){trace.add("commit-call");OAuthStoreCommitReceipt result=store.commit(transaction,budget);trace.add("commit-reply");return result;}
  };OAuthStoreCoordinator selected=new OAuthStoreCoordinator(traced,this.codec,this.clock,3,255);assertNotNull(selected.establishNewSubject("subject",deadline()));List<String> expected=new java.util.ArrayList<>();for(int i=0;i<4;i++)expected.addAll(List.of("read-call","read-reply","worker-wall"));expected.addAll(List.of("commit-call","commit-reply","worker-wall","read-call","read-reply","worker-wall","worker-wall"));assertEquals(expected,trace);this.clock.phaseTrace=null;assertEquals(NOW,this.store.authorityNow);assertEquals(NOW,this.clock.instant());assertEquals(before.getVersion(),root().getVersion());assertTrue(this.store.rows.containsKey(this.codec.subjectKey("subject")));
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi08KnownCommitValidationAndCompletionMatrix(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(var scenario:com.revetsec.testing.StoreReceiptMatrix.Case.values())cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-08/ISSUER_NORMAL/"+scenario,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();OAuthStoreEntry root=f.root(),before=f.subjectEntry();AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();AtomicReference<@Nullable Instant> target=new AtomicReference<>();OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){
    @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){int n=reads.incrementAndGet();OAuthStoreReadResult result=f.store.read(key,budget);Instant next=target.get();if(n==5&&next!=null)f.clock.time=next;return result;}
    @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){commits.incrementAndGet();OAuthStoreCommitReceipt result=f.store.commit(transaction,budget);assertEquals(OAuthStoreCommitStatus.COMMITTED,result.getStatus());var validated=result.getTiming().orElseThrow().getValidatedTime();var condition=transaction.getTemporalCondition().orElseThrow();Instant next=com.revetsec.testing.StoreReceiptMatrix.finalTime(scenario,validated,condition);target.set(next);OAuthStoreCommitReceipt delivered=(OAuthStoreCommitReceipt)com.revetsec.testing.StoreReceiptMatrix.apply(result,scenario,validated,condition);if(next!=null)f.store.authorityNow=next;return delivered;}
   };OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);var session=selected.begin(deadline());OAuthStoreEntry change=f.replacement(session);session.requireBefore(NOW.plusSeconds(1));if(scenario.isNormal())assertEquals(OAuthStoreCommitStatus.COMMITTED,session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));else failed(scenario.isUnknown()?OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN:OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,()->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));assertEquals(1,commits.get());assertEquals(scenario.needsFinalRead()?5:4,reads.get());assertNotEquals(before.getVersion(),f.subjectEntry().getVersion());assertEquals(NOW,f.opened(f.subjectEntry()).floor());assertEquals(root.getVersion(),f.root().getVersion());assertEquals(root.toSealedForm(),f.root().toSealedForm());
  }));return cases;
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi08NormalStatusesDistinguishZeroEffectUnknownAndExplicitConflict(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(var status:OAuthStoreCommitStatus.values())for(boolean applied:status==OAuthStoreCommitStatus.UNKNOWN?List.of(false,true):List.of(status==OAuthStoreCommitStatus.COMMITTED))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-08/ISSUER_NORMAL/status="+status+"/applied="+applied,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();OAuthStoreEntry before=f.subjectEntry(),root=f.root();AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){@Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){reads.incrementAndGet();return f.store.read(key,budget);}@Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();if(status==OAuthStoreCommitStatus.COMMITTED)return f.store.commit(tx,budget);if(status==OAuthStoreCommitStatus.UNKNOWN){if(applied)assertEquals(OAuthStoreCommitStatus.COMMITTED,f.store.commit(tx,budget).getStatus());return OAuthStoreCommitReceipt.unknownInstance();}return OAuthStoreCommitReceipt.fromRefusal(status);}};OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);var session=selected.begin(deadline());OAuthStoreEntry change=f.replacement(session);session.requireBefore(NOW.plusSeconds(1));if(status==OAuthStoreCommitStatus.COMMITTED||status==OAuthStoreCommitStatus.CONFLICT)assertEquals(status,session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));else if(status==OAuthStoreCommitStatus.TIME_EXPIRED)assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,assertThrows(OAuthServerAdmissionFailure.class,()->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change)))).reason());else failed(status==OAuthStoreCommitStatus.UNKNOWN?OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN:OAuthStoreFailure.Reason.UNAVAILABLE,()->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));assertEquals(1,commits.get());assertEquals(status==OAuthStoreCommitStatus.COMMITTED?5:4,reads.get());if(applied)assertNotEquals(before.getVersion(),f.subjectEntry().getVersion());else{assertEquals(before.getVersion(),f.subjectEntry().getVersion());assertEquals(before.toSealedForm(),f.subjectEntry().toSealedForm());}assertEquals(root.getVersion(),f.root().getVersion());assertEquals(root.toSealedForm(),f.root().toSealedForm());
  }));return cases;
 }
 @Test void scApi08IssuerTimelyConflictRetriesOnlyAfterACompleteFreshAttempt(){
  initialized();AtomicInteger calls=new AtomicInteger();OAuthStoreEntry before=root();OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){@Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return store.read(key,budget);}@Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){return calls.incrementAndGet()==1?OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.CONFLICT):store.commit(tx,budget);}};OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,this.codec,this.clock,3,255);assertNotNull(selected.establishNewSubject("subject",deadline()));assertEquals(2,calls.get());assertTrue(this.store.rows.containsKey(this.codec.subjectKey("subject")));assertEquals(before.getVersion(),root().getVersion());
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi08EnteredNullOrThrowNeverInfersRollbackFromInstrumentedEffects(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(boolean applied:List.of(false,true))for(boolean throwing:List.of(false,true))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-08/ISSUER_NORMAL/lost-receipt/applied="+applied+"/throw="+throwing,()->{OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();OAuthStoreEntry before=f.subjectEntry();AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){@Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){reads.incrementAndGet();return f.store.read(key,budget);}@Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();if(applied)assertEquals(OAuthStoreCommitStatus.COMMITTED,f.store.commit(tx,budget).getStatus());if(throwing)throw new IllegalStateException("TEST-ONLY-lost-acknowledgement");return com.revetsec.testing.StoreReceiptMatrix.brokenNull();}};OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);var session=selected.begin(deadline());var change=f.replacement(session);failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));assertEquals(1,commits.get());assertEquals(4,reads.get());if(applied)assertNotEquals(before.getVersion(),f.subjectEntry().getVersion());else{assertEquals(before.getVersion(),f.subjectEntry().getVersion());assertEquals(before.toSealedForm(),f.subjectEntry().toSealedForm());}}));return cases;
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi08FenceOnlyStatusesAndMalformedKnownReceiptsNeverNeedUtcOrWorkerTime(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();List<String> labels=new java.util.ArrayList<>();for(var status:OAuthStoreCommitStatus.values())labels.add("STATUS_"+status);labels.addAll(List.of("UNKNOWN_APPLIED","TIMED_RECEIPT","MISSING_ADMISSION","FOREIGN_AUTHORITY","FOREIGN_RECOVERY","NULL_BEFORE","NULL_AFTER","THROW_BEFORE","THROW_AFTER"));
  for(String label:labels)cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-08/ISSUER_FENCE_ONLY/"+label,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();OAuthStoreEntry root=f.root(),before=f.subjectEntry();f.store.healthy=false;f.clock.broken=true;java.util.concurrent.CopyOnWriteArrayList<String> wallTrace=new java.util.concurrent.CopyOnWriteArrayList<>();f.clock.phaseTrace=wallTrace;AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();boolean unknown=label.equals("STATUS_UNKNOWN")||label.equals("UNKNOWN_APPLIED")||label.startsWith("NULL_")||label.startsWith("THROW_"),normal=label.equals("STATUS_COMMITTED")||label.equals("STATUS_CONFLICT");OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){
    @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){reads.incrementAndGet();var result=f.store.read(key,budget);if(result instanceof OAuthStoreReadResult.Available available)assertInstanceOf(StoreTimeObservation.Unavailable.class,available.getTimeObservation());return result;}
    @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){int n=commits.incrementAndGet();assertEquals(OAuthStoreTransaction.Purpose.FENCE_ONLY,tx.getPurpose());assertTrue(tx.getTemporalCondition().isEmpty());if(label.equals("NULL_BEFORE"))return com.revetsec.testing.StoreReceiptMatrix.brokenNull();if(label.equals("THROW_BEFORE"))throw new IllegalStateException("TEST-ONLY-lost-fence-acknowledgement");if(label.startsWith("STATUS_")){var status=OAuthStoreCommitStatus.valueOf(label.substring(7));if(status==OAuthStoreCommitStatus.UNKNOWN)return OAuthStoreCommitReceipt.unknownInstance();if(status==OAuthStoreCommitStatus.CONFLICT&&n==1)return OAuthStoreCommitReceipt.fromRefusal(status);if(status!=OAuthStoreCommitStatus.COMMITTED&&status!=OAuthStoreCommitStatus.CONFLICT)return OAuthStoreCommitReceipt.fromRefusal(status);}
     OAuthStoreCommitReceipt receipt=f.store.commit(tx,budget);assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());assertTrue(receipt.getTiming().isEmpty());if(label.equals("NULL_AFTER"))return com.revetsec.testing.StoreReceiptMatrix.brokenNull();if(label.equals("THROW_AFTER"))throw new IllegalStateException("TEST-ONLY-lost-fence-acknowledgement");if(label.equals("UNKNOWN_APPLIED"))return OAuthStoreCommitReceipt.unknownInstance();if(label.equals("TIMED_RECEIPT"))return OAuthStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(StoreTimeObservation.Healthy.fromObservation(f.store.admission,f.store.clockGeneration,NOW,Duration.ZERO),null));if(label.equals("MISSING_ADMISSION"))return com.revetsec.testing.StoreReceiptMatrix.withoutAdmission();if(label.equals("FOREIGN_AUTHORITY"))return OAuthStoreCommitReceipt.fromFenceAdmission(StoreAdmission.fromIdentifiers("A".repeat(43),f.store.admission.getRecoveryGeneration()));if(label.equals("FOREIGN_RECOVERY"))return OAuthStoreCommitReceipt.fromFenceAdmission(StoreAdmission.fromIdentifiers(f.store.admission.getAuthorityId(),"A".repeat(43)));return receipt;
    }
   };OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);if(normal)assertEquals(1,selected.revokeSubject("subject",deadline()).epoch());else failed(unknown?OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN:label.startsWith("STATUS_")?OAuthStoreFailure.Reason.UNAVAILABLE:OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,()->selected.revokeSubject("subject",deadline()));assertEquals(label.equals("STATUS_CONFLICT")?2:1,commits.get());assertEquals(label.equals("STATUS_CONFLICT")?5:normal?3:2,reads.get());boolean changed=normal||label.equals("UNKNOWN_APPLIED")||(!label.startsWith("STATUS_")&&!label.endsWith("_BEFORE"));OAuthStoreFence actual=OAuthStoreFence.decode(f.codec.openPermanentFence(f.subjectEntry(),f.store.admission,f.root()).payload(),OAuthStoreKey.Kind.SUBJECT_STATE);assertEquals(changed?1:0,actual.epoch());if(changed)assertNotEquals(before.getVersion(),f.subjectEntry().getVersion());else{assertEquals(before.getVersion(),f.subjectEntry().getVersion());assertEquals(before.toSealedForm(),f.subjectEntry().toSealedForm());}assertEquals(root.getVersion(),f.root().getVersion());assertEquals(root.toSealedForm(),f.root().toSealedForm());assertTrue(wallTrace.isEmpty(),"FENCE_ONLY cannot use worker wall or manufacture UTC");
  }));return cases;
 }
 @Test void scApi08NormalMutationCannotUseAValidFenceOnlyReceiptAsTimedAcknowledgement(){
  initialized();subject();OAuthStoreEntry before=subjectEntry();AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){@Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){reads.incrementAndGet();return store.read(key,budget);}@Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();var receipt=store.commit(tx,budget);assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());return OAuthStoreCommitReceipt.fromFenceAdmission(receipt.getAdmission().orElseThrow());}};OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,this.codec,this.clock,3,255);var session=selected.begin(deadline());var change=replacement(session);failed(OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,()->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));assertEquals(1,commits.get());assertEquals(4,reads.get());assertNotEquals(before.getVersion(),subjectEntry().getVersion());
 }

 @Test void scApi01FailedAdditionalReadCannotLeaveAnEarlierIssuerAttemptUsable(){
  initialized();subject();OAuthStoreEntry before=subjectEntry();AtomicInteger commits=new AtomicInteger();OAuthStoreKey failedKey=this.codec.subjectKey("additional");OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){@Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return key.equals(failedKey)?OAuthStoreReadResult.Unavailable.get():store.read(key,budget);}@Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();return store.commit(tx,budget);}};OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,this.codec,this.clock,3,255);var session=selected.begin(deadline());var change=replacement(session);failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->session.subject("additional"));try{session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change)));}catch(RuntimeException expected){assertEquals(0,commits.get());}assertEquals(0,commits.get(),"Failed additional read must abandon all earlier prepared facts");assertEquals(before.getVersion(),subjectEntry().getVersion());assertEquals(before.toSealedForm(),subjectEntry().toSealedForm());
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi01FailedReadOrDecodeIrreversiblyClosesPreparedIssuerSession(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(String fault:List.of("UNAVAILABLE","NULL","THROW","WRONG_KEY","ADMISSION","UTC","REGRESSION","ENVELOPE","PAYLOAD","ABSENT_SUBJECT","EXPLICIT_OPEN","FUTURE_FLOOR","FOREIGN_REQUEST","READ_LIMIT","AUTHORITY_REFRESH","JOIN"))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-01/ISSUER/abandon/"+fault,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var before=Map.copyOf(f.store.rows);AtomicInteger commits=new AtomicInteger();AtomicBoolean armed=new AtomicBoolean();OAuthStoreKey additional=f.codec.subjectKey("additional");OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){
    @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){var real=f.store.read(key,budget);if(!armed.get())return real;if(fault.equals("JOIN"))return OAuthStoreReadResult.Unavailable.get();if(!key.equals(additional)&&!fault.equals("AUTHORITY_REFRESH"))return real;
     var available=assertInstanceOf(OAuthStoreReadResult.Available.class,real);var time=available.getTimeObservation();if(fault.equals("UNAVAILABLE"))return OAuthStoreReadResult.Unavailable.get();if(fault.equals("NULL"))return com.revetsec.testing.StoreReceiptMatrix.brokenNull();if(fault.equals("THROW"))throw new IllegalStateException("TEST-ONLY read failure");if(fault.equals("WRONG_KEY"))return f.store.read(f.codec.issuerKey(),budget);if(fault.equals("ADMISSION"))time=StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers("A".repeat(43),f.store.admission.getRecoveryGeneration()),f.store.clockGeneration,NOW,Duration.ZERO);if(fault.equals("UTC"))time=StoreTimeObservation.Unavailable.fromAdmission(f.store.admission);if(fault.equals("REGRESSION"))time=StoreTimeObservation.Healthy.fromObservation(f.store.admission,f.store.clockGeneration,NOW.minusNanos(1),Duration.ZERO);OAuthStoreEntry entry=available.getEntry().orElse(null);
     if(fault.equals("ENVELOPE"))entry=OAuthStoreEntry.fromStoredForm(key,"A".repeat(43),OAuthStoreFormat.PERMANENT,"broken");if(fault.equals("PAYLOAD"))entry=IssuerTestRecords.seal(f.codec,key,OAuthStoreFormat.PERMANENT,"{}");if(fault.equals("AUTHORITY_REFRESH")){var old=OAuthIssuerRootV2.decode(f.opened(f.root()).payload());entry=f.codec.sealAdmitted(key,OAuthStoreFormat.PERMANENT,NOW,OAuthIssuerRootV2.initial("A".repeat(43),old.authorityId(),old.minimum()).toPayload());}
     return OAuthStoreReadResult.Available.fromObservation(key,entry,time);
    }
    @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();return f.store.commit(tx,budget);}
   };OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);var session=selected.begin(deadline());var change=f.replacement(session);armed.set(true);
   assertThrows(RuntimeException.class,()->{switch(fault){
    case "ENVELOPE","PAYLOAD","ABSENT_SUBJECT"->session.subject("additional");
    case "EXPLICIT_OPEN"->session.open(OAuthStoreEntry.fromStoredForm(change.getKey(),change.getVersion(),OAuthStoreFormat.PERMANENT,"broken"));
    case "FUTURE_FLOOR"->session.open(f.codec.sealAdmitted(change.getKey(),OAuthStoreFormat.PERMANENT,NOW.plusNanos(1),f.opened(change).payload().toJson()));
    case "FOREIGN_REQUEST"->session.read(new OAuthStoreRecordCodec("https://foreign.example",sealer(),3800).subjectKey("other"));
    case "READ_LIMIT"->{for(int i=0;i<15;i++)session.read(f.codec.subjectKey("extra-"+i));}
    case "AUTHORITY_REFRESH"->session.authorityNow();case "JOIN"->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change)));
    default->session.read(additional);
   }});
   assertThrows(IllegalStateException.class,()->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));assertThrows(IllegalStateException.class,session::barrier);assertThrows(IllegalStateException.class,session::issuer);assertThrows(IllegalStateException.class,session::effectiveNow);assertThrows(IllegalStateException.class,()->session.open(change));assertThrows(IllegalStateException.class,()->session.seal(change.getKey(),OAuthStoreFormat.PERMANENT,"{}"));assertThrows(IllegalStateException.class,()->session.read(change.getKey()));assertEquals(0,commits.get());assertEquals(before,f.store.rows);
   armed.set(false);var fresh=selected.begin(deadline());var next=f.replacement(fresh);assertEquals(OAuthStoreCommitStatus.COMMITTED,fresh.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(next))));assertEquals(1,commits.get());assertNotEquals(requireNonNull(before.get(change.getKey())).getVersion(),f.subjectEntry().getVersion());assertEquals(before.get(f.codec.issuerKey()),f.root());
  }));return cases;
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi01EveryNormalIssuerReadPositionRejectsIncompleteForeignOrCorruptObservation(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(int position=1;position<=5;position++)for(String fault:List.of("UNAVAILABLE","NULL","THROW","WRONG_KIND","FOREIGN_SCOPE","ABSENT","ENVELOPE","AUTHENTICATED_PAYLOAD","NEGATIVE_FLOOR")){
   int target=position;cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-01/ISSUER_NORMAL/read="+target+"/"+fault,()->{
    OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var before=Map.copyOf(f.store.rows);AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){
     @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){int n=reads.incrementAndGet();var real=f.store.read(key,budget);return n==target?scApi01ReadFault(f,fault,key,real):real;}
     @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();return f.store.commit(tx,budget);}
    };OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);boolean conflict=target>=3&&target<=4&&List.of("ABSENT","ENVELOPE","AUTHENTICATED_PAYLOAD","NEGATIVE_FLOOR").contains(fault);
    org.junit.jupiter.api.function.Executable attempt=()->{var session=selected.begin(deadline());var change=f.replacement(session);var result=session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change)));assertEquals(OAuthStoreCommitStatus.CONFLICT,result);};
    if(conflict)assertDoesNotThrow(attempt);else{var failed=assertThrows(OAuthStoreFailure.class,attempt);assertEquals(target==5?OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED:target<=2&&List.of("ABSENT","ENVELOPE","AUTHENTICATED_PAYLOAD").contains(fault)?OAuthStoreFailure.Reason.CORRUPT_STATE:OAuthStoreFailure.Reason.UNAVAILABLE,failed.reason());}
    assertEquals(target,reads.get());assertEquals(target==5?1:0,commits.get());if(target==5){assertNotEquals(requireNonNull(before.get(f.codec.subjectKey("subject"))).getVersion(),f.subjectEntry().getVersion());assertEquals(before.get(f.codec.issuerKey()),f.root());}else assertEquals(before,f.store.rows);
   }));
  }return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi01FenceOnlyReadFaultsCannotUseAbsenceOrAWorkerClockAsFallback(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(int position=1;position<=3;position++)for(String fault:List.of("UNAVAILABLE","NULL","THROW","WRONG_KIND","FOREIGN_SCOPE","ABSENT","ENVELOPE","AUTHENTICATED_PAYLOAD")){
   int target=position;cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-01/ISSUER_FENCE_ONLY/read="+target+"/"+fault,()->{
    OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var before=Map.copyOf(f.store.rows);AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();java.util.concurrent.CopyOnWriteArrayList<String> wallTrace=new java.util.concurrent.CopyOnWriteArrayList<>();f.clock.phaseTrace=wallTrace;f.clock.broken=true;f.store.healthy=false;OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){
     @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){int n=reads.incrementAndGet();var real=f.store.read(key,budget);return n==target?scApi01ReadFault(f,fault,key,real):real;}
     @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();assertEquals(OAuthStoreTransaction.Purpose.FENCE_ONLY,tx.getPurpose());assertTrue(tx.getTemporalCondition().isEmpty());return f.store.commit(tx,budget);}
    };OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);var failed=assertThrows(OAuthStoreFailure.class,()->selected.revokeSubject("subject",deadline()));assertEquals(target==3?OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED:List.of("ABSENT","ENVELOPE","AUTHENTICATED_PAYLOAD").contains(fault)?OAuthStoreFailure.Reason.CORRUPT_STATE:OAuthStoreFailure.Reason.UNAVAILABLE,failed.reason());assertEquals(target,reads.get());assertEquals(target==3?1:0,commits.get());assertTrue(wallTrace.isEmpty());if(target==3){var actual=OAuthStoreFence.decode(f.codec.openPermanentFence(f.subjectEntry(),f.store.admission,f.root()).payload(),OAuthStoreKey.Kind.SUBJECT_STATE);assertEquals(1,actual.epoch());assertEquals(before.get(f.codec.issuerKey()),f.root());}else assertEquals(before,f.store.rows);
   }));
  }return cases;
 }
 private static @NonNull OAuthStoreReadResult scApi01ReadFault(@NonNull OAuthIssuerSharedClockTests f,@NonNull String fault,@NonNull OAuthStoreKey key,@NonNull OAuthStoreReadResult real){
  if(fault.equals("UNAVAILABLE"))return OAuthStoreReadResult.Unavailable.get();if(fault.equals("NULL"))return com.revetsec.testing.StoreReceiptMatrix.brokenNull();if(fault.equals("THROW"))throw new IllegalStateException("TEST-ONLY read fault");var available=assertInstanceOf(OAuthStoreReadResult.Available.class,real);var time=available.getTimeObservation();
  if(fault.equals("WRONG_KIND"))return OAuthStoreReadResult.Available.fromObservation(key.equals(f.codec.issuerKey())?f.codec.subjectKey("subject"):f.codec.issuerKey(),null,time);if(fault.equals("FOREIGN_SCOPE"))return OAuthStoreReadResult.Available.fromObservation(new OAuthStoreRecordCodec("https://foreign.example",sealer(),3800).issuerKey(),null,time);if(fault.equals("ABSENT"))return OAuthStoreReadResult.Available.fromObservation(key,null,time);
  var old=available.getEntry().orElseThrow();OAuthStoreEntry replacement;if(fault.equals("ENVELOPE"))replacement=OAuthStoreEntry.fromStoredForm(key,old.getVersion(),old.getRetainUntil(),"broken");else if(fault.equals("AUTHENTICATED_PAYLOAD"))replacement=IssuerTestRecords.seal(f.codec,key,old.getRetainUntil(),"{}");else{Instant floor=Instant.EPOCH.minusNanos(1);String payload=f.codec.openPermanentFence(old,f.store.admission,f.root()).payload().toJson();if(key.equals(f.codec.issuerKey())){var root=OAuthIssuerRootV2.decode(f.codec.openPermanentFence(old,f.store.admission,old).payload());payload=OAuthIssuerRootV2.initial(root.incarnation(),root.authorityId(),floor).toPayload();}replacement=f.codec.sealAdmitted(key,old.getRetainUntil(),floor,payload);}return OAuthStoreReadResult.Available.fromObservation(key,replacement,time);
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi03EveryNormalIssuerReadJoinAndFinalCheckpointRequiresOneExactTuple(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(int position=2;position<=5;position++)for(var fault:com.revetsec.testing.StoreProfileFaults.values()){
   int target=position;cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-03/ISSUER_NORMAL/read="+target+"/"+fault,()->{
    OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var before=Map.copyOf(f.store.rows);AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){
     @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){int n=reads.incrementAndGet();var real=f.store.read(key,budget);if(n!=target)return real;var available=assertInstanceOf(OAuthStoreReadResult.Available.class,real);var original=assertInstanceOf(StoreTimeObservation.Healthy.class,available.getTimeObservation());var changed=assertInstanceOf(StoreTimeObservation.Healthy.class,fault.apply(original));assertEquals(original.getObservedAt(),changed.getObservedAt());assertEquals(fault==com.revetsec.testing.StoreProfileFaults.CLOCK?!original.getClockGeneration().equals(changed.getClockGeneration()):original.getClockGeneration().equals(changed.getClockGeneration()),true);return OAuthStoreReadResult.Available.fromObservation(key,available.getEntry().orElse(null),changed);}
     @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();return f.store.commit(tx,budget);}
    };OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);failed(target==5?OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED:OAuthStoreFailure.Reason.UNAVAILABLE,()->{var session=selected.begin(deadline());var change=f.replacement(session);session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change)));});assertEquals(target,reads.get());assertEquals(target==5?1:0,commits.get());if(target==5){assertNotEquals(requireNonNull(before.get(f.codec.subjectKey("subject"))).getVersion(),f.subjectEntry().getVersion());assertEquals(before.get(f.codec.issuerKey()),f.root());}else assertEquals(before,f.store.rows);
   }));
  }return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi03FenceOnlyRequiresBothAdmissionDomainsAtSubjectAndFinalRootRead(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(int position:List.of(2,3))for(var fault:List.of(com.revetsec.testing.StoreProfileFaults.AUTHORITY,com.revetsec.testing.StoreProfileFaults.RECOVERY)){
   cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-03/ISSUER_FENCE_ONLY/read="+position+"/"+fault,()->{
    OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var before=Map.copyOf(f.store.rows);f.clock.broken=true;f.store.healthy=false;java.util.concurrent.CopyOnWriteArrayList<String> trace=new java.util.concurrent.CopyOnWriteArrayList<>();f.clock.phaseTrace=trace;AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){
     @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){int n=reads.incrementAndGet();var real=f.store.read(key,budget);if(n!=position)return real;var available=assertInstanceOf(OAuthStoreReadResult.Available.class,real);assertInstanceOf(StoreTimeObservation.Unavailable.class,available.getTimeObservation());return OAuthStoreReadResult.Available.fromObservation(key,available.getEntry().orElse(null),fault.apply(available.getTimeObservation()));}
     @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();assertEquals(OAuthStoreTransaction.Purpose.FENCE_ONLY,tx.getPurpose());assertTrue(tx.getTemporalCondition().isEmpty());return f.store.commit(tx,budget);}
    };OAuthStoreCoordinator selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);failed(position==3?OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED:OAuthStoreFailure.Reason.UNAVAILABLE,()->selected.revokeSubject("subject",deadline()));assertEquals(position,reads.get());assertEquals(position==3?1:0,commits.get());assertTrue(trace.isEmpty());if(position==3){assertEquals(1,OAuthStoreFence.decode(f.codec.openPermanentFence(f.subjectEntry(),f.store.admission,f.root()).payload(),OAuthStoreKey.Kind.SUBJECT_STATE).epoch());assertEquals(before.get(f.codec.issuerKey()),f.root());}else assertEquals(before,f.store.rows);
   }));
  }return cases;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scFence04PublicRevokesOrderRecoveryAtCapturedRootCheckpointUnderOriginalBudget(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();
  for(boolean all:List.of(false,true))for(boolean after:List.of(false,true))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-FENCE-04/public-"+(all?"issuer":"subject")+"/recovery-"+(after?"after":"before")+"-captured-root",()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();StoreAdmission original=f.store.admission;StoreAdmission rotated=StoreAdmission.fromIdentifiers(original.getAuthorityId(),"A".repeat(43));assertNotEquals(original,rotated);
   OAuthStoreEntry rootBefore=f.root(),subjectBefore=f.subjectEntry();int commits=f.store.commits;var committed=new AtomicBoolean();var changed=new AtomicBoolean();var transaction=new AtomicReference<@Nullable OAuthStoreTransaction>();var receipt=new AtomicReference<@Nullable OAuthStoreCommitReceipt>();var captured=new AtomicReference<@Nullable StoreTimeObservation>();List<OAuthStoreKey> finalReads=new java.util.concurrent.CopyOnWriteArrayList<>();List<Duration> budgets=new java.util.concurrent.CopyOnWriteArrayList<>();
   OAuthAuthorizationServerStore wrapper=new OAuthAuthorizationServerStore(){
    @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){budgets.add(budget);if(!committed.get())return f.store.read(key,budget);finalReads.add(key);assertEquals(f.codec.issuerKey(),key);if(!after){f.store.admission=rotated;changed.set(true);}OAuthStoreReadResult result=f.store.read(key,budget);captured.set(assertInstanceOf(OAuthStoreReadResult.Available.class,result).getTimeObservation());if(after){f.store.admission=rotated;changed.set(true);}return result;}
    @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){budgets.add(budget);transaction.set(tx);OAuthStoreCommitReceipt result=f.store.commit(tx,budget);assertEquals(OAuthStoreCommitStatus.COMMITTED,result.getStatus());receipt.set(result);committed.set(true);return result;}
   };
   f.store.healthy=false;f.clock.broken=true;var wallTrace=new java.util.concurrent.CopyOnWriteArrayList<String>();f.clock.phaseTrace=wallTrace;OAuthAuthorizationServer server=f.server(wrapper);
   org.junit.jupiter.api.function.Executable action=()->{if(all)server.revokeAllGrants();else server.revokeSubject("subject");};
   if(after)assertDoesNotThrow(action);else assertEquals(OAuthServerException.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,assertThrows(OAuthServerStoreException.class,action).getReason());
   assertTrue(changed.get());assertEquals(rotated,f.store.admission);assertEquals(commits+1,f.store.commits);assertEquals(List.of(f.codec.issuerKey()),finalReads);assertEquals(all?3:4,budgets.size());for(int n=1;n<budgets.size();n++)assertTrue(budgets.get(n).compareTo(budgets.get(n-1))<0,"Every callback must retain the shrinking original public-operation budget");
   assertEquals(after?original:rotated,requireNonNull(captured.get()).getAdmission());assertTrue(requireNonNull(captured.get()) instanceof StoreTimeObservation.Unavailable);assertTrue(wallTrace.isEmpty());var tx=requireNonNull(transaction.get());assertEquals(OAuthStoreTransaction.Purpose.FENCE_ONLY,tx.getPurpose());assertEquals(original,tx.getExpectedAdmission());assertTrue(tx.getTemporalCondition().isEmpty());assertEquals(original,requireNonNull(receipt.get()).getAdmission().orElseThrow());assertTrue(requireNonNull(receipt.get()).getTiming().isEmpty());
   OAuthIssuerRootV2 rootAfter=OAuthIssuerRootV2.decode(f.codec.openPermanentFence(f.root(),f.store.admission,f.root()).payload());OAuthStoreFence subjectAfter=OAuthStoreFence.decode(f.codec.openPermanentFence(f.subjectEntry(),f.store.admission,f.root()).payload(),OAuthStoreKey.Kind.SUBJECT_STATE);assertEquals(all?1:0,rootAfter.epoch());assertEquals(all?0:1,subjectAfter.epoch());assertEquals(rootBefore.getRetainUntil(),f.root().getRetainUntil());assertEquals(subjectBefore.getRetainUntil(),f.subjectEntry().getRetainUntil());assertEquals(f.codec.openPermanentFence(rootBefore,original,rootBefore).floor(),f.codec.openPermanentFence(f.root(),f.store.admission,f.root()).floor());assertEquals(f.codec.openPermanentFence(subjectBefore,original,rootBefore).floor(),f.codec.openPermanentFence(f.subjectEntry(),f.store.admission,f.root()).floor());
  }));return cases;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk05GoodCompletionStillRequiresFreshFinalAdmissionAndOriginalDeadline(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();
  for(String fault:List.of("UNAVAILABLE","THROW","DELAY"))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-05/ISSUER/good-completion/"+fault,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();OAuthStoreEntry root=f.root(),before=f.subjectEntry();var delivered=new AtomicReference<@Nullable StoreCommitTiming>();AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();
   OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){
    @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){int number=reads.incrementAndGet();var result=f.store.read(key,budget);if(number==5){if(fault.equals("UNAVAILABLE"))return OAuthStoreReadResult.Unavailable.get();if(fault.equals("THROW"))throw new IllegalStateException("Test-only final read failure");if(fault.equals("DELAY"))scMeasuredReleaseDelay(150_000_000L);}return result;}
    @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();var receipt=f.store.commit(tx,budget);assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());var validated=receipt.getTiming().orElseThrow().getValidatedTime();var completed=StoreTimeObservation.Healthy.fromObservation(validated.getAdmission(),validated.getClockGeneration(),f.store.authorityNow,validated.getMaximumUtcError());var timing=StoreCommitTiming.fromTimes(validated,completed);delivered.set(timing);return OAuthStoreCommitReceipt.fromCommittedTiming(timing);}
   };
   var selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);var session=selected.begin(Deadline.fromNow(Duration.ofMillis(100)));var change=f.replacement(session);session.requireBefore(NOW.plusSeconds(1));
   failed(OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,()->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));assertTrue(requireNonNull(delivered.get()).getCompletedTime().isPresent());assertEquals(1,commits.get());assertEquals(5,reads.get());assertNotEquals(before.getVersion(),f.subjectEntry().getVersion());assertEquals(NOW,f.opened(f.subjectEntry()).floor());assertEquals(root.getVersion(),f.root().getVersion());assertEquals(root.toSealedForm(),f.root().toSealedForm());
  }));return cells;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk08ActualValidationAtLastNanosecondKeepsCommitWhenFinalReleaseCrossesOriginalUpper(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();
  for(boolean finalAtExpiry:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-05+CLK-08/ISSUER/E-minus-1/finalAtE="+finalAtExpiry,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();OAuthStoreEntry root=f.root(),before=f.subjectEntry();Instant upper=NOW.plusSeconds(1);var committed=new AtomicReference<@Nullable StoreCommitTiming>();var finalSample=new AtomicReference<StoreTimeObservation.@Nullable Healthy>();var finalElapsed=new AtomicReference<@Nullable Duration>();AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();
   OAuthAuthorizationServerStore wrapped=new OAuthAuthorizationServerStore(){
    @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){int number=reads.incrementAndGet();var result=f.store.read(key,budget);if(number==5&&!finalAtExpiry){var sample=assertInstanceOf(StoreTimeObservation.Healthy.class,assertInstanceOf(OAuthStoreReadResult.Available.class,result).getTimeObservation());finalSample.set(sample);finalElapsed.set(scMeasuredReleaseDelay(2_000_000L));}return result;}
    @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){commits.incrementAndGet();assertEquals(upper,tx.getTemporalCondition().orElseThrow().getValidBeforeExclusive().orElseThrow());f.store.authorityNow=upper.minusNanos(1);f.clock.time=f.store.authorityNow;var receipt=f.store.commit(tx,budget);assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());committed.set(receipt.getTiming().orElseThrow());assertEquals(upper.minusNanos(1),receipt.getTiming().orElseThrow().getValidatedTime().getObservedAt());if(finalAtExpiry){f.store.authorityNow=upper;f.clock.time=upper;}return receipt;}
   };
   var selected=new OAuthStoreCoordinator(wrapped,f.codec,f.clock,3,255);var session=selected.begin(deadline());var change=f.replacement(session);session.requireBefore(upper);failed(OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,()->session.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(change))));
   assertEquals(1,commits.get());assertEquals(5,reads.get());assertEquals(upper.minusNanos(1),requireNonNull(committed.get()).getValidatedTime().getObservedAt());assertTrue(requireNonNull(committed.get()).getCompletedTime().isEmpty());if(!finalAtExpiry){var sample=requireNonNull(finalSample.get());assertEquals(upper.minusNanos(1),sample.getObservedAt());assertTrue(com.revetsec.internal.StoreTimeRules.isReleaseBefore(sample,Duration.ZERO,upper));assertFalse(com.revetsec.internal.StoreTimeRules.isReleaseBefore(sample,requireNonNull(finalElapsed.get()),upper),"A pre-expiry stamp is insufficient when the conservative bound crosses E");}assertNotEquals(before.getVersion(),f.subjectEntry().getVersion());assertEquals(NOW,f.opened(f.subjectEntry()).floor());assertEquals(root.getVersion(),f.root().getVersion());assertEquals(root.toSealedForm(),f.root().toSealedForm());
  }));return cells;
 }
 private static @NonNull Duration scMeasuredReleaseDelay(long nanos){long start=System.nanoTime(),end=start+nanos;long remaining;while((remaining=end-System.nanoTime())>0)LockSupport.parkNanos(remaining);Duration elapsed=com.revetsec.internal.StoreTimeRules.elapsed(start,System.nanoTime()).orElseThrow();assertTrue(elapsed.compareTo(Duration.ofNanos(nanos))>=0);return elapsed;}

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk09PublicRedemptionOrdersAuthorityRecoveryAtCapturedFinalRootCheckpoint(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();
  for(boolean authority:List.of(false,true))for(boolean after:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-09/ISSUER-public-redemption/authority="+authority+"/after-captured-checkpoint="+after,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var armed=new AtomicBoolean();var committed=new AtomicBoolean();var changed=new AtomicBoolean();var receipt=new AtomicReference<@Nullable OAuthStoreCommitReceipt>();var finalReads=new java.util.ArrayList<OAuthStoreKey>();var checkpoint=new AtomicReference<OAuthStoreReadResult.@Nullable Available>();var original=f.store.admission;
   Runnable rotate=()->{scClk09RotateAdmission(f,authority);changed.set(true);};
   OAuthAuthorizationServerStore wrapper=new OAuthAuthorizationServerStore(){
    @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){var result=f.store.read(key,budget);if(armed.get()&&committed.get()){finalReads.add(key);if(key.equals(f.codec.issuerKey())&&result instanceof OAuthStoreReadResult.Available available){checkpoint.set(available);if(after&&!changed.get())rotate.run();}}return result;}
    @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){var result=f.store.commit(transaction,budget);if(armed.get()&&result.getStatus()==OAuthStoreCommitStatus.COMMITTED&&!transaction.getMutations().isEmpty()){receipt.set(result);committed.set(true);if(!after)rotate.run();}return result;}
   };
   OAuthAuthorizationServer server=f.server(wrapper);String code=f.code(server);var codeKey=f.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));int commits=f.store.commits,policies=f.policies;armed.set(true);
   if(after){var result=assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code));byte[] body=result.getResponse().toHttpBodyWithCredentials();try{assertTrue(body.length>0);}finally{java.util.Arrays.fill(body,(byte)0);}}else{var failure=assertThrows(OAuthServerStoreException.class,()->redeem(server,code));assertEquals(OAuthServerException.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,failure.getReason());}
   assertTrue(changed.get());assertTrue(committed.get());assertEquals(commits+1,f.store.commits);assertEquals(policies+1,f.policies);assertEquals(List.of(f.codec.issuerKey()),finalReads);assertEquals(authority?"A".repeat(43):original.getAuthorityId(),f.store.admission.getAuthorityId());assertEquals(authority?original.getRecoveryGeneration():"A".repeat(43),f.store.admission.getRecoveryGeneration());assertEquals(NOW,f.store.authorityNow);assertEquals(NOW,f.clock.instant());
   var acknowledged=requireNonNull(receipt.get());assertEquals(OAuthStoreCommitStatus.COMMITTED,acknowledged.getStatus());assertEquals(original,acknowledged.getTiming().orElseThrow().getValidatedTime().getAdmission());assertEquals(NOW,acknowledged.getTiming().orElseThrow().getValidatedTime().getObservedAt());assertEquals(after?original:f.store.admission,requireNonNull(checkpoint.get()).getTimeObservation().getAdmission());assertEquals("USED",f.record(requireNonNull(f.store.rows.get(codeKey))).text("status"));assertEquals(1,f.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).count());
  }));return cells;
 }
 private static void scClk09RotateAdmission(@NonNull OAuthIssuerSharedClockTests f,boolean authority){
  synchronized(f.store.rows){var old=f.store.admission;var root=OAuthIssuerRootV2.decode(f.opened(f.root()).payload());var next=StoreAdmission.fromIdentifiers(authority?"A".repeat(43):old.getAuthorityId(),authority?old.getRecoveryGeneration():"A".repeat(43));f.store.admission=next;if(authority){var replacement=OAuthIssuerRootV2.initial(root.incarnation(),next.getAuthorityId(),root.minimum());f.store.rows.put(f.codec.issuerKey(),f.codec.sealAdmitted(f.codec.issuerKey(),OAuthStoreFormat.PERMANENT,root.minimum(),replacement.toPayload()));}}
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk04AndPub04ActualSigningHealthFailuresKeepTheirTrustedStoreClassification(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();for(String operation:List.of("TOKEN","REFRESH","WARMUP"))for(String fault:List.of("NONE","FORWARD","BACKWARD","WORKER_FAILURE","UTC_UNAVAILABLE","AUTHORITY","RECOVERY"))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-04+PUB-04/"+operation+"/"+fault,()->scClk04Child(operation+"/"+fault)));return cells;
 }
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk04ProviderFailuresCannotSpoofTrustedStoreHealth(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();for(String origin:List.of("SNAPSHOT","JCA","JCA_REFRESH"))for(String fault:List.of("RUNTIME","STORE_SIGNAL"))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-04/provider-origin/"+origin+"/"+fault,()->scClk04Child(origin+"/"+fault)));cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-04/origin-is-invocation-local",()->scClk04Child("ORIGIN/REUSE")));cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-04/provisional-clock-is-not-an-admitted-store",()->scClk04Child("PROVISIONAL/STORE_SIGNAL")));return cells;
 }
 @org.junit.jupiter.api.Test
 void scClk04TrustedStoreFailuresAlsoRunInProcessForCoverage()throws Exception{
  OAuthIssuerClockHealthTestProvider.main(new String[]{"TOKEN/UTC_UNAVAILABLE"});
  OAuthIssuerClockHealthTestProvider.main(new String[]{"REFRESH/UTC_UNAVAILABLE"});
  OAuthIssuerClockHealthTestProvider.main(new String[]{"WARMUP/NONE"});
  OAuthIssuerClockHealthTestProvider.main(new String[]{"WARMUP/UTC_UNAVAILABLE"});
 }
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk04MaterialFailuresCannotSpoofTrustedStoreHealth(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();for(String fault:List.of("RUNTIME","STORE_SIGNAL"))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-04/material-origin/"+fault,()->scClk04Child("MATERIAL/"+fault)));return cells;
 }
 private static void scClk04Child(@NonNull String mode)throws Exception{
  com.revetsec.testing.ChildJvm.Result result=com.revetsec.testing.ChildJvm.withMainClass(OAuthIssuerClockHealthTestProvider.class).arguments(List.of(mode)).build().run();assertEquals(0,result.getExitCode(),()->result.getStandardOutput()+result.getStandardError());assertFalse(result.isTimedOut());assertEquals("scenario="+mode+" passed\n",result.getStandardOutput());
 }
 static void runSigningHealthCase(@NonNull String mode)throws Exception{
  String[] parts=mode.split("/",-1);if(parts.length!=2)throw new IllegalArgumentException("Fixed signing-health case required");String operation=parts[0],fault=parts[1];
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
  if(operation.equals("PROVISIONAL")){
   var signal=new OAuthStoreFailure(OAuthStoreFailure.Reason.UNAVAILABLE);Clock provisional=new Clock(){@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}@Override public @NonNull Instant instant(){throw signal;}};var active=OAuthIssuerSigningKey.fromRsaKeyPair("key",key.getPrivateKey(),key.getPublicKey());var snapshot=OAuthIssuerKeySnapshot.withActiveKey(active).generation("g1").publishedAt(NOW.minusSeconds(120)).build();var retention=new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO);var lifecycle=new OAuthIssuerKeyLifecycle(OAuthIssuerKeyProvider.fromSnapshot(snapshot),provisional,Duration.ZERO,retention,true);var failure=assertThrows(OAuthServerAdmissionFailure.class,()->lifecycle.snapshot(deadline()));assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,failure.reason());assertEquals(0,OAuthIssuerClockHealthTestProvider.signOperations());return;
  }
  if(operation.equals("ORIGIN")){
   var signal=new OAuthStoreFailure(OAuthStoreFailure.Reason.UNAVAILABLE);var spoof=new AtomicBoolean();var active=OAuthIssuerSigningKey.fromRsaKeyPair("key",key.getPrivateKey(),key.getPublicKey());var snapshot=OAuthIssuerKeySnapshot.withActiveKey(active).generation("g1").publishedAt(NOW.minusSeconds(120)).build();OAuthIssuerKeyProvider provider=budget->{if(spoof.get())throw signal;return snapshot;};var retention=new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO);var lifecycle=new OAuthIssuerKeyLifecycle(provider,Clock.fixed(NOW,ZoneOffset.UTC),Duration.ZERO,retention,true);
   assertSame(signal,assertThrows(OAuthStoreFailure.class,()->lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(30),deadline(),()->{throw signal;})));spoof.set(true);var failure=assertThrows(OAuthServerAdmissionFailure.class,()->lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(30),deadline(),()->NOW));assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,failure.reason());assertEquals(0,OAuthIssuerClockHealthTestProvider.signOperations());return;
  }
  if(operation.equals("SNAPSHOT")){
   var provider=(OAuthIssuerKeyProvider)budget->{if(fault.equals("STORE_SIGNAL"))throw new OAuthStoreFailure(OAuthStoreFailure.Reason.UNAVAILABLE);throw new IllegalStateException("TEST-ONLY provider failure");};var retention=new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO);var lifecycle=new OAuthIssuerKeyLifecycle(provider,Clock.fixed(NOW,ZoneOffset.UTC),Duration.ZERO,retention,true);
   var failure=assertThrows(OAuthServerAdmissionFailure.class,()->lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(30),deadline(),()->NOW));assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,failure.reason());assertEquals(0,OAuthIssuerClockHealthTestProvider.signOperations());return;
  }
  if(operation.equals("MATERIAL")){
   java.security.interfaces.RSAPublicKey malformed=new java.security.interfaces.RSAPublicKey(){private static final long serialVersionUID=1L;@Override public java.math.@NonNull BigInteger getModulus(){if(fault.equals("STORE_SIGNAL"))throw new OAuthStoreFailure(OAuthStoreFailure.Reason.UNAVAILABLE);throw new IllegalStateException("TEST-ONLY material failure");}@Override public java.math.@NonNull BigInteger getPublicExponent(){return java.math.BigInteger.valueOf(65537);}@Override public @NonNull String getAlgorithm(){return "RSA";}@Override public @Nullable String getFormat(){throw new AssertionError("Public encoding not needed");}@Override public byte @Nullable [] getEncoded(){throw new AssertionError("Public encoding not needed");}};
   var active=OAuthIssuerSigningKey.fromRsaKeyPair("key",key.getPrivateKey(),key.getPublicKey());var failure=assertThrows(IllegalArgumentException.class,()->OAuthIssuerKeySnapshot.withActiveKey(active).verificationKeys(Map.of("retired",malformed)));assertNull(failure.getCause());assertEquals(0,OAuthIssuerClockHealthTestProvider.signOperations());return;
  }
  OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();OAuthAuthorizationServer server=f.server();String code=f.code(server);boolean warm=operation.equals("WARMUP"),providerFailure=operation.equals("JCA")||operation.equals("JCA_REFRESH"),refreshing=operation.equals("REFRESH")||operation.equals("JCA_REFRESH");String refresh="";
  if(refreshing){var seed=assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code));byte[] body=seed.getResponse().toHttpBodyWithCredentials();try{var payload=(JsonObject)JsonCodec.parse(body,JsonLimits.protocolDocument(131072));refresh=((com.revetsec.json.JsonString)payload.find("refresh_token").orElseThrow()).getValue();}finally{java.util.Arrays.fill(body,(byte)0);}}
  final String credential=refreshing?refresh:code;var codeKey=refreshing?f.codec.key(OAuthStoreKey.Kind.REFRESH_TOKEN,OAuthServerCredential.refreshDigest(credential)):f.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));var rows=Map.copyOf(f.store.rows);int commits=f.store.commits,policies=f.policies;
  OAuthIssuerClockHealthTestProvider.arm(()->{assertFalse(Thread.holdsLock(f.store.rows),"Signing must not run inside the store transaction");switch(fault){case "NONE"->{}case "FORWARD"->f.clock.time=NOW.plusSeconds(6);case "BACKWARD"->f.clock.time=NOW.minusSeconds(6);case "WORKER_FAILURE"->f.clock.broken=true;case "UTC_UNAVAILABLE"->f.store.healthy=false;case "AUTHORITY"->f.store.admission=StoreAdmission.fromIdentifiers("A".repeat(43),f.store.admission.getRecoveryGeneration());case "RECOVERY"->f.store.admission=StoreAdmission.fromIdentifiers(f.store.admission.getAuthorityId(),"A".repeat(43));case "RUNTIME"->throw new IllegalStateException("TEST-ONLY JCA failure");case "STORE_SIGNAL"->throw new OAuthStoreFailure(OAuthStoreFailure.Reason.UNAVAILABLE);default->throw new AssertionError("Unknown fixed failure");}});
  if(fault.equals("NONE")){if(warm)server.warmUp();else assertInstanceOf(OAuthTokenResult.Succeeded.class,refreshing?scClk04Refresh(server,credential):redeem(server,code));assertEquals(commits+1,f.store.commits);if(warm){assertEquals(rows,f.store.rows);assertTrue(requireNonNull(f.store.lastTransaction).getMutations().isEmpty());}else assertEquals("USED",f.record(requireNonNull(f.store.rows.get(codeKey))).text("status"));}
  else{var failure=assertThrows(OAuthServerException.class,()->{if(warm)server.warmUp();else if(refreshing)scClk04Refresh(server,credential);else redeem(server,code);});assertAll(()->assertEquals(providerFailure?OAuthServerException.Reason.SIGNING_FAILED:OAuthServerException.Reason.STORE_UNAVAILABLE,failure.getReason()),()->assertFalse(failure.isTemporaryCondition()),()->assertNull(failure.getCause()),()->assertEquals(0,failure.getSuppressed().length),()->assertEquals(commits,f.store.commits),()->assertEquals(rows,f.store.rows),()->assertEquals(refreshing?"ACTIVE":"UNUSED",f.record(requireNonNull(f.store.rows.get(codeKey))).text("status")),()->assertEquals(503,server.responseForFailure(failure).getStatusCode()),()->assertEquals(policies+(warm?0:1),f.policies),()->assertEquals(1,OAuthIssuerClockHealthTestProvider.signOperations()),()->assertFalse(OAuthIssuerClockHealthTestProvider.hasUnconsumedHook()));}
  assertEquals(policies+(warm?0:1),f.policies);assertEquals(1,OAuthIssuerClockHealthTestProvider.signOperations());assertFalse(OAuthIssuerClockHealthTestProvider.hasUnconsumedHook());
 }



 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scPub05IssuerPublicRawAcknowledgementsRemainFactualAfterMeasuredDeadlineAndOutage(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();for(boolean initialize:List.of(true,false))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("PUB05/public-issuer/late-known/initialize="+initialize,()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();if(!initialize){f.initialized();f.subject();}
   var committed=new AtomicBoolean();var postReads=new java.util.concurrent.atomic.AtomicInteger();var actual=new AtomicReference<@Nullable OAuthStoreCommitReceipt>();var held=new AtomicReference<Duration>();
   OAuthAuthorizationServerStore wrapper=new OAuthAuthorizationServerStore(){@Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){if(committed.get())postReads.incrementAndGet();return f.store.read(key,budget);}@Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){var receipt=f.store.commit(transaction,budget);actual.set(receipt);committed.set(true);return receipt;}};
   var server=f.server(wrapper);OAuthStoreKey key=initialize?f.codec.issuerKey():f.codec.subjectKey("subject");OAuthStoreEntry old=initialize?null:f.subjectEntry();Instant floor=initialize?NOW:f.opened(requireNonNull(old)).floor();int commits=f.store.commits,reads=f.store.reads;
   f.store.afterCommit=()->{held.set(scMeasuredReleaseDelay(Duration.ofMillis(1100).toNanos()));f.store.healthy=false;};
   var receipt=initialize?server.initializeFreshIssuer():server.resealStoreEntry(key);
   assertTrue(requireNonNull(held.get()).compareTo(Duration.ofMillis(1100))>=0);assertSame(actual.get(),receipt);assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());
   assertTrue(receipt.getTiming().orElseThrow().getCompletedTime().isEmpty());assertEquals(NOW,receipt.getTiming().orElseThrow().getValidatedTime().getObservedAt());
   assertEquals(0,postReads.get());assertEquals(commits+1,f.store.commits);assertEquals(reads+(initialize?2:4),f.store.reads);
   var retained=requireNonNull(f.store.rows.get(key));assertEquals(floor,f.codec.openPermanentFence(retained,f.store.admission,f.root()).floor());
   if(old!=null){assertNotEquals(old.getVersion(),retained.getVersion());assertEquals(old.getRetainUntil(),retained.getRetainUntil());assertEquals(f.codec.openPermanentFence(old,f.store.admission,f.root()).payload().toJson(),f.codec.openPermanentFence(retained,f.store.admission,f.root()).payload().toJson());}
   assertEquals(0,f.policies);assertFalse(f.store.healthy);
   System.out.println("PUB05 measuredHoldNanos="+requireNonNull(held.get()).toNanos()+" initialize="+initialize+" postReads="+postReads.get());
  }));return cells;
 }


 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scEng04ActualSigningWaitRejoinsChangedRowsAndRepeatsWholeConflictAttempts(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();
  for(String scenario:List.of("TOKEN/NONE","REFRESH/NONE","TOKEN/ISSUER","TOKEN/SUBJECT","TOKEN/CODE","TOKEN/GRANT","REFRESH/GRANT","TOKEN/CHURN","REFRESH/CHURN"))
   cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("ENG04/actual-sign-120ms/"+scenario,()->scEng04Child(scenario)));
  return cells;
 }
 private static void scEng04Child(@NonNull String scenario)throws Exception{
  String mode="ENG04/"+scenario;
  com.revetsec.testing.ChildJvm.Result result=com.revetsec.testing.ChildJvm.withMainClass(OAuthIssuerClockHealthTestProvider.class).arguments(List.of(mode)).build().run();
  assertEquals(0,result.getExitCode(),()->result.getStandardOutput()+result.getStandardError());assertFalse(result.isTimedOut());assertEquals("scenario="+mode+" passed\n",result.getStandardOutput());
  List<String> records=result.getStandardErrorWithoutJvmNotices().lines().toList();assertEquals(1,records.size(),result::toString);String record=records.get(0);
  String[] parts=scenario.split("/",-1);assertEquals(2,parts.length);String fault=parts[1];String rowKind=fault.equals("GRANT")?"GRANT":fault.equals("ISSUER")?"ISSUER_STATE":fault.equals("SUBJECT")?"SUBJECT_STATE":parts[0].equals("REFRESH")?"REFRESH_TOKEN":"CODE";int signs=fault.equals("CHURN")?2:1;String outcome=fault.equals("NONE")||fault.equals("CHURN")?"SUCCEEDED":"REJECTED";
  assertTrue(record.matches("ENG04 holdNanos=[0-9]+ scenario="+scenario+" rowKind="+rowKind+" signs="+signs+" result="+outcome),result::toString);
  List<String> raw=result.getStandardError().lines().toList();if(raw.size()==2){String options=System.getenv("JAVA_TOOL_OPTIONS");assertNotNull(options,result::toString);assertEquals("Picked up JAVA_TOOL_OPTIONS: "+options,raw.get(0),result::toString);}else assertEquals(1,raw.size(),result::toString);assertEquals(record,raw.get(raw.size()-1),result::toString);System.out.print(result.getStandardError());
 }
 static void runSemanticSigningCase(@NonNull String scenario)throws Exception{
  String[] parts=scenario.split("/",-1);if(parts.length!=3||!parts[0].equals("ENG04"))throw new IllegalArgumentException("Fixed semantic signing case required");
  boolean refreshing=parts[1].equals("REFRESH");String fault=parts[2];
  OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var server=f.server();String code=f.code(server),refresh="";
  if(refreshing){var seed=assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code));byte[] body=seed.getResponse().toHttpBodyWithCredentials();try{var payload=(JsonObject)JsonCodec.parse(body,JsonLimits.protocolDocument(131072));refresh=((com.revetsec.json.JsonString)payload.find("refresh_token").orElseThrow()).getValue();}finally{java.util.Arrays.fill(body,(byte)0);}}
  String credential=refreshing?refresh:code;
  OAuthStoreKey credentialKey=refreshing?f.codec.key(OAuthStoreKey.Kind.REFRESH_TOKEN,OAuthServerCredential.refreshDigest(credential)):f.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(credential));
  OAuthAuthorizationRecord original=f.record(requireNonNull(f.store.rows.get(credentialKey)));OAuthStoreKey grantKey=f.codec.key(OAuthStoreKey.Kind.GRANT,original.text("grantId"));
  int commits=f.store.commits,policies=f.policies;var held=new AtomicReference<Duration>();var replacement=new AtomicReference<@Nullable OAuthStoreEntry>();
  OAuthIssuerClockHealthTestProvider.arm(()->{
   assertEquals(1,OAuthIssuerClockHealthTestProvider.signOperations());assertFalse(Thread.holdsLock(f.store.rows));
   held.set(scMeasuredReleaseDelay(Duration.ofMillis(120).toNanos()));
   if(fault.equals("ISSUER")){assertEquals(1,f.coordinator.revokeAll(deadline()).epoch());return;}
   if(fault.equals("SUBJECT")){assertEquals(1,f.coordinator.revokeSubject("subject",deadline()).epoch());return;}
   if(fault.equals("NONE"))return;
   OAuthStoreKey selected=fault.equals("GRANT")?grantKey:credentialKey;
   synchronized(f.store.rows){var old=requireNonNull(f.store.rows.get(selected));var opened=f.opened(old);String payload=opened.payload().toJson();
    if(!fault.equals("CHURN"))payload=f.record(old).terminated(OAuthServerIngressLimits.fromDefaults(),255).toPayload();
    var next=f.codec.sealAdmitted(selected,old.getRetainUntil(),opened.floor(),payload);assertNotEquals(old.getVersion(),next.getVersion());f.store.rows.put(selected,next);replacement.set(next);
   }
  });
  boolean success=fault.equals("NONE")||fault.equals("CHURN");
  var result=refreshing?scClk04Refresh(server,credential):redeem(server,credential);
  if(success){var admitted=assertInstanceOf(OAuthTokenResult.Succeeded.class,result);byte[] body=admitted.getResponse().toHttpBodyWithCredentials();try{assertTrue(body.length>0);}finally{java.util.Arrays.fill(body,(byte)0);}}
  else{assertInstanceOf(OAuthTokenResult.Rejected.class,result);if(replacement.get()!=null){var retained=requireNonNull(f.store.rows.get(requireNonNull(replacement.get()).getKey()));assertEquals(requireNonNull(replacement.get()).getVersion(),retained.getVersion());assertEquals(requireNonNull(replacement.get()).toSealedForm(),retained.toSealedForm());}}
  assertTrue(requireNonNull(held.get()).compareTo(Duration.ofMillis(120))>=0);assertFalse(OAuthIssuerClockHealthTestProvider.hasUnconsumedHook());
  assertEquals(fault.equals("CHURN")?2:1,OAuthIssuerClockHealthTestProvider.signOperations());assertEquals(policies+(fault.equals("CHURN")?2:1),f.policies);
  int extra=success||fault.equals("ISSUER")||fault.equals("SUBJECT")||refreshing&&fault.equals("GRANT")?1:0;assertEquals(commits+extra,f.store.commits);
  if(!success)assertEquals(fault.equals("CODE")?"CANCELLED":refreshing?"ACTIVE":"UNUSED",f.record(requireNonNull(f.store.rows.get(credentialKey))).text("status"));
  System.err.println("ENG04 holdNanos="+requireNonNull(held.get()).toNanos()+" scenario="+parts[1]+"/"+fault+" rowKind="+(fault.equals("GRANT")?"GRANT":fault.equals("ISSUER")?"ISSUER_STATE":fault.equals("SUBJECT")?"SUBJECT_STATE":credentialKey.getKind().name())+" signs="+OAuthIssuerClockHealthTestProvider.signOperations()+" result="+(success?"SUCCEEDED":"REJECTED"));
 }


 private static @NonNull OAuthTokenResult scClk04Refresh(@NonNull OAuthAuthorizationServer server,@NonNull String refresh){return server.tokenResult("POST",null,form(Map.of("grant_type","refresh_token","client_id","client","resource",RESOURCE,"refresh_token",refresh)).getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded")));}

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk10PublicRedemptionKeepsCommittedResponseBeforeLaterSubjectRevocation(){
  return List.of(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-10/ISSUER/public-redemption/later-subject-revocation",()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var finalPhase=new AtomicBoolean();List<OAuthStoreKey> finalReads=new java.util.concurrent.CopyOnWriteArrayList<>();var originalReceipt=new AtomicReference<@Nullable OAuthStoreCommitReceipt>();
   OAuthAuthorizationServerStore wrapper=new OAuthAuthorizationServerStore(){@Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){var reply=f.store.read(key,budget);if(finalPhase.get())finalReads.add(key);return reply;}@Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){var receipt=f.store.commit(tx,budget);return receipt;}};
   var server=f.server(wrapper);String code=f.code(server);var root=f.root();var codeKey=f.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));int commits=f.store.commits,policies=f.policies;
   f.store.afterCommit=()->{assertFalse(Thread.holdsLock(f.store.rows));assertNotNull(f.coordinator.establishNewSubject("unrelated",deadline()));assertEquals(1,f.coordinator.revokeSubject("subject",deadline()).epoch());finalPhase.set(true);};
   // Preserve the actual original receipt before the nested operations replace the fixture's last transaction.
   OAuthAuthorizationServerStore capture=new OAuthAuthorizationServerStore(){@Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){return wrapper.read(key,budget);}@Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){var receipt=wrapper.commit(tx,budget);originalReceipt.set(receipt);return receipt;}};server=f.server(capture);
   var result=assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code));finalPhase.set(false);assertEquals(List.of(f.codec.issuerKey()),finalReads);assertEquals(commits+3,f.store.commits);assertEquals(policies+1,f.policies);assertEquals(OAuthStoreCommitStatus.COMMITTED,requireNonNull(originalReceipt.get()).getStatus());assertEquals(root.getVersion(),f.root().getVersion());assertEquals(root.toSealedForm(),f.root().toSealedForm());assertEquals("USED",f.record(requireNonNull(f.store.rows.get(codeKey))).text("status"));assertEquals(1,f.coordinator.begin(deadline()).subject("subject").epoch());assertTrue(f.store.rows.containsKey(f.codec.subjectKey("unrelated")));assertEquals(1,f.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).count());
   byte[] body=result.getResponse().toHttpBodyWithCredentials();String token;try{var json=(JsonObject)JsonCodec.parse(body,JsonLimits.protocolDocument(131072));token=((com.revetsec.json.JsonString)json.find("access_token").orElseThrow()).getValue();}finally{java.util.Arrays.fill(body,(byte)0);}var bearer=assertInstanceOf(com.revetsec.oauth.BearerTokenResult.Present.class,com.revetsec.oauth.BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+token))).getToken();assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,server.validateAccessTokenResult(bearer,RESOURCE));assertEquals(policies+1,f.policies);
  }));
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk10IssuerRootEpochAndFenceOnlySubjectChangesHaveLaterBusinessOrdering(){
  List<org.junit.jupiter.api.DynamicTest> cases=new java.util.ArrayList<>();for(boolean fenceOnly:List.of(false,true))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-10/ISSUER/"+(fenceOnly?"fence-only-later-subject-epoch":"normal-later-issuer-root-epoch"),()->{
   OAuthIssuerSharedClockTests f=new OAuthIssuerSharedClockTests();f.initialized();f.subject();var rootBefore=f.root();var pinned=OAuthIssuerRootV2.decode(f.opened(rootBefore).payload());var finalPhase=new AtomicBoolean();List<OAuthStoreKey> finalReads=new java.util.concurrent.CopyOnWriteArrayList<>();var receipt=new AtomicReference<@Nullable OAuthStoreCommitReceipt>();var transaction=new AtomicReference<@Nullable OAuthStoreTransaction>();var finalMetadata=new AtomicReference<@Nullable StoreTimeObservation>();
   OAuthAuthorizationServerStore wrapper=new OAuthAuthorizationServerStore(){@Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){var reply=f.store.read(key,budget);if(finalPhase.get()){finalReads.add(key);finalMetadata.set(assertInstanceOf(OAuthStoreReadResult.Available.class,reply).getTimeObservation());}return reply;}@Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){transaction.set(tx);var result=f.store.commit(tx,budget);receipt.set(result);return result;}};
   if(fenceOnly){
    f.store.healthy=false;f.clock.broken=true;var wallTrace=new java.util.concurrent.CopyOnWriteArrayList<String>();f.clock.phaseTrace=wallTrace;int commits=f.store.commits;var selected=new OAuthStoreCoordinator(wrapper,f.codec,f.clock,3,255);f.store.afterCommit=()->{assertFalse(Thread.holdsLock(f.store.rows));assertEquals(2,f.coordinator.revokeSubject("subject",deadline()).epoch());finalPhase.set(true);};
    var result=assertDoesNotThrow(()->selected.revokeSubject("subject",deadline()));finalPhase.set(false);assertEquals(1,result.epoch());assertEquals(commits+2,f.store.commits);assertEquals(List.of(f.codec.issuerKey()),finalReads);assertTrue(wallTrace.isEmpty());assertInstanceOf(StoreTimeObservation.Unavailable.class,requireNonNull(finalMetadata.get()));assertEquals(OAuthStoreCommitStatus.COMMITTED,requireNonNull(receipt.get()).getStatus());assertTrue(requireNonNull(receipt.get()).getTiming().isEmpty());assertEquals(f.store.admission,requireNonNull(receipt.get()).getAdmission().orElseThrow());var tx=requireNonNull(transaction.get());assertEquals(OAuthStoreTransaction.Purpose.FENCE_ONLY,tx.getPurpose());assertTrue(tx.getTemporalCondition().isEmpty());assertEquals(Set.of(f.codec.issuerKey(),f.codec.subjectKey("subject")),tx.getConditions().stream().map(c->c.getKey()).collect(java.util.stream.Collectors.toSet()));assertEquals(1,tx.getMutations().size());assertEquals(f.codec.subjectKey("subject"),tx.getMutations().get(0).getKey());assertEquals(2,OAuthStoreFence.decode(f.codec.openPermanentFence(f.subjectEntry(),f.store.admission,f.root()).payload(),OAuthStoreKey.Kind.SUBJECT_STATE).epoch());assertEquals(rootBefore.getVersion(),f.root().getVersion());assertEquals(rootBefore.toSealedForm(),f.root().toSealedForm());
   }else{
    var server=f.server(wrapper);String code=f.code(server);var codeKey=f.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));int commits=f.store.commits,policies=f.policies;f.store.afterCommit=()->{assertFalse(Thread.holdsLock(f.store.rows));assertEquals(1,f.coordinator.revokeAll(deadline()).epoch());finalPhase.set(true);};
    var result=assertInstanceOf(OAuthTokenResult.Succeeded.class,assertDoesNotThrow(()->redeem(server,code)));finalPhase.set(false);assertEquals(commits+2,f.store.commits);assertEquals(policies+1,f.policies);assertEquals(List.of(f.codec.issuerKey()),finalReads);assertInstanceOf(StoreTimeObservation.Healthy.class,requireNonNull(finalMetadata.get()));assertEquals(OAuthStoreCommitStatus.COMMITTED,requireNonNull(receipt.get()).getStatus());assertTrue(requireNonNull(receipt.get()).getTiming().isPresent());assertEquals(OAuthStoreTransaction.Purpose.TIMED,requireNonNull(transaction.get()).getPurpose());var current=OAuthIssuerRootV2.decode(f.opened(f.root()).payload());assertEquals(1,current.epoch());assertEquals(pinned.minimum(),current.minimum());assertEquals(pinned.incarnation(),current.incarnation());assertNotEquals(rootBefore.getVersion(),f.root().getVersion());assertEquals("USED",f.record(requireNonNull(f.store.rows.get(codeKey))).text("status"));assertEquals(1,f.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).count());byte[] body=result.getResponse().toHttpBodyWithCredentials();String token;try{var json=(JsonObject)JsonCodec.parse(body,JsonLimits.protocolDocument(131072));token=((com.revetsec.json.JsonString)json.find("access_token").orElseThrow()).getValue();}finally{java.util.Arrays.fill(body,(byte)0);}var bearer=assertInstanceOf(com.revetsec.oauth.BearerTokenResult.Present.class,com.revetsec.oauth.BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+token))).getToken();assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,server.validateAccessTokenResult(bearer,RESOURCE));assertEquals(policies+1,f.policies);
   }
  }));return cases;
 }
}
