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
 @Test void ordinaryRegistrationAndBarrierNeverRewriteStableRoot(){initialized();String version=root().getVersion();subject();this.store.authorityNow=NOW.plusSeconds(1);this.clock.time=this.store.authorityNow;assertEquals(OAuthStoreCommitStatus.COMMITTED,this.coordinator.begin(deadline()).barrier());assertEquals(version,root().getVersion());assertEquals(NOW,OAuthIssuerRootV2.decode(opened(root()).payload()).minimum());assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());}
 @Test void authorityTimeNotWorkerTimeDeterminesEntityFloor(){initialized();this.clock.time=NOW.plusSeconds(1);subject();assertEquals(NOW,opened(subjectEntry()).floor());assertEquals(NOW,OAuthIssuerRootV2.decode(opened(root()).payload()).minimum());}
 @Test void alreadyFastWorkerCannotWriteOrPoisonRoot(){initialized();String version=root().getVersion();int commits=this.store.commits;this.clock.time=NOW.plusSeconds(6);failed(OAuthStoreFailure.Reason.UNAVAILABLE,this::subject);assertEquals(commits,this.store.commits);assertEquals(version,root().getVersion());}
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
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;OAuthIssuerKeySnapshot snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(1)).retirementNotBefore(Map.of("key",NOW.plusSeconds(2))).build();
  OAuthGrantRetention retention=new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO);
  OAuthIssuerKeyLifecycle lifecycle=new OAuthIssuerKeyLifecycle(OAuthIssuerKeyProvider.fromSnapshot(snapshot),Clock.fixed(NOW.plusSeconds(10),ZoneOffset.UTC),Duration.ZERO,retention,true);
  AtomicInteger samples=new AtomicInteger();String signed=lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(1),deadline(),()->{samples.incrementAndGet();return NOW;});
  assertFalse(signed.isEmpty());assertEquals(2,samples.get());
 }
 @Test void postSignRetirementCheckResamplesAuthorityBeforeOutput(){
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;OAuthIssuerKeySnapshot snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(1)).retirementNotBefore(Map.of("key",NOW.plusSeconds(2))).build();
  OAuthGrantRetention retention=new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO);
  OAuthIssuerKeyLifecycle lifecycle=new OAuthIssuerKeyLifecycle(OAuthIssuerKeyProvider.fromSnapshot(snapshot),Clock.fixed(NOW,ZoneOffset.UTC),Duration.ZERO,retention,true);
  AtomicInteger samples=new AtomicInteger();assertEquals(OAuthServerException.Reason.SIGNING_FAILED,assertThrows(OAuthServerSigningException.class,()->lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(1),deadline(),()->samples.incrementAndGet()==1?NOW:NOW.plusSeconds(3))).getReason());assertEquals(2,samples.get());
 }
 private static final class Worker extends Clock {
  private @NonNull Instant time=NOW;private boolean broken;
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
  @Override public @NonNull Instant instant(){if(this.broken)throw new IllegalStateException("unusable worker clock");return this.time;}
 }
 private @NonNull OAuthAuthorizationServer server(){
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;OAuthIssuerKeySnapshot snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
  OAuthServerClientRegistration client=OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(Map.of(RESOURCE,Set.of("read"))).refreshTokenPermitted(true).build();
  return OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke")).introspectionEndpoint(URI.create(ISSUER+"/introspect"))
   .clientRepository((id,budget)->Optional.of(id.equals("resource")?resourceClient():client)).store(this.store).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(snapshot)).stateSealer(sealer()).resources(Map.of(RESOURCE,Set.of("read"))).clock(this.clock).clockSkew(Duration.ZERO).totalDeadline(Duration.ofSeconds(1)).requestTimeout(Duration.ofSeconds(1)).observer(this.observer).refreshTokensEnabled(true)
   .grantPolicy((context,budget)->{this.policies++;Runnable hook=this.policyHook;this.policyHook=null;if(hook!=null)hook.run();return decision();}).build();
 }
 private static @NonNull OAuthServerClientRegistration resourceClient(){return OAuthServerClientRegistration.withClientId("resource").configurationVersion("r1").authorizationCodePermitted(false).introspectionResources(Set.of(RESOURCE)).authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->java.util.Arrays.equals(secret,"secret".getBytes(StandardCharsets.UTF_8)))).build();}
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
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;OAuthIssuerSigningKey a=OAuthIssuerSigningKey.fromKeyPair("a",key.getPrivateKey(),key.getPublicKey()),b=OAuthIssuerSigningKey.fromKeyPair("b",key.getPrivateKey(),key.getPublicKey());
  OAuthIssuerKeySnapshot old=OAuthIssuerKeySnapshot.withActiveKey(a).generation("g1").publishedAt(NOW.minusSeconds(120)).retirementNotBefore(Map.of("a",NOW.plusSeconds(1000))).build();
  OAuthIssuerKeySnapshot future=OAuthIssuerKeySnapshot.withActiveKey(b).generation("g2").publishedAt(NOW.minusSeconds(60)).build();AtomicReference<OAuthIssuerKeySnapshot> provider=new AtomicReference<>(old);Worker worker=new Worker();
  OAuthIssuerKeyLifecycle lifecycle=new OAuthIssuerKeyLifecycle(budget->provider.get(),worker,Duration.ZERO,new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO),true);
  assertNotNull(lifecycle.snapshot(deadline()));assertDoesNotThrow(()->lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(30),deadline(),()->NOW));
  provider.set(future);worker.time=NOW.plusSeconds(2000);assertEquals(Set.of("b"),lifecycle.snapshot(deadline()).getVerificationKeys().keySet());
  provider.set(old);worker.time=NOW;assertDoesNotThrow(()->lifecycle.sign("{}".getBytes(StandardCharsets.UTF_8),NOW.plusSeconds(30),deadline(),()->NOW));
 }
 @Test void genuineRetainedUsedCodeCanResealAfterCredentialExpiry(){initialized();subject();OAuthAuthorizationServer server=server();String code=code(server);assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(server,code));OAuthStoreKey key=this.codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));OAuthStoreEntry old=requireNonNull(this.store.rows.get(key));OAuthAuthorizationRecord used=record(old);this.store.authorityNow=used.expires().plusSeconds(1);this.clock.time=this.store.authorityNow;assertFalse(this.store.authorityNow.isBefore(used.expires()));assertTrue(this.store.authorityNow.isBefore(old.getRetainUntil()));assertEquals(OAuthStoreCommitStatus.COMMITTED,server.resealStoreEntry(key).getStatus());OAuthStoreEntry next=requireNonNull(this.store.rows.get(key));assertEquals(old.getRetainUntil(),next.getRetainUntil());assertEquals(used.toPayload(),record(next).toPayload());assertEquals(opened(old).floor(),opened(next).floor());}
}
