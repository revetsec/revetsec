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
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.function.Executable;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Consent CAS/reconstruction tests with a single-process atomic fixture, not durable backend proof. */
final class OAuthAuthorizationLedgerTests {
 private static final @NonNull Instant NOW = Instant.parse("2026-10-04T00:00:00.123456789Z");
 private static final @NonNull String RESOURCE = "https://resource.example/mcp", REDIRECT = "https://client.example/cb?x=%2f";
 private static final @NonNull String BROWSER = "A".repeat(43), OTHER = "B".repeat(42) + "A";
 private static final @NonNull OAuthServerIngressLimits LIMITS = OAuthServerIngressLimits.fromDefaults();
 private final @NonNull OAuthAtomicStoreFixture store = new OAuthAtomicStoreFixture();
 private final @NonNull MutableClock clock = new MutableClock(NOW);
 private final @NonNull OAuthStoreRecordCodec codec = codec(3800);
 private final @NonNull OAuthStoreCoordinator coordinator = new OAuthStoreCoordinator(this.store, this.codec, this.clock, 3, 255);
 private final @NonNull OAuthAuthorizationLedger first = ledger(true, 3);
 private final @NonNull OAuthAuthorizationLedger second = ledger(true, 3);
 OAuthAuthorizationLedgerTests() { }
 private static @NonNull OAuthStoreRecordCodec codec(int cap) {
  byte[] key = new byte[32]; for (int n = 0; n < key.length; n++) key[n] = (byte) (n + 1);
  StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("k", Base64.getEncoder().encodeToString(key)))
   .clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
  return new OAuthStoreRecordCodec("https://issuer.example/tenant", sealer, cap);
 }
 private @NonNull OAuthAuthorizationLedger ledger(boolean refresh, int attempts) {
  return new OAuthAuthorizationLedger(this.coordinator, this.codec, LIMITS, Duration.ofMinutes(15), Duration.ofMinutes(2), attempts, 255, refresh);
 }
 private static @NonNull Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(10)); }
 private static @NonNull OAuthServerClientRegistration client() { return client("v1", true, Set.of("read", "write"), REDIRECT, false); }
 private static @NonNull OAuthServerClientRegistration client(@NonNull String version, boolean refresh,
   @NonNull Set<@NonNull String> scopes, @NonNull String redirect, boolean confidential) {
  return OAuthServerClientRegistration.withClientId("client").redirectUris(List.of(URI.create(redirect)))
   .allowedScopesByResource(Map.of(RESOURCE, scopes)).configurationVersion(version).refreshTokenPermitted(refresh)
   .authentication(confidential ? OAuthServerClientAuthentication.fromClientSecretVerifier((id, secret, budget) -> true) : null).build();
 }
 private static @NonNull String encode(@NonNull String value) {
  try { return FormUrlEncoding.encode(value); }
  catch (com.revetsec.internal.encoding.EncodingException failure) { throw new AssertionError(failure); }
 }
 private static @NonNull OAuthServerAuthorizationAdmission admission(@Nullable String state) {
  OAuthServerClientRegistration client = client();
  String query = "client_id=client&response_type=code&redirect_uri=" + encode(REDIRECT)
   + "&code_challenge_method=S256&code_challenge=" + BROWSER + "&resource=" + encode(RESOURCE)
   + (state == null ? "" : "&state=" + encode(state));
  OAuthServerRequest request = OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",query,new byte[0],Map.of(),LIMITS);
  return OAuthServerAuthorizationAdmission.admit(request, (id, budget) -> Optional.of(client), deadline(), resources(), LIMITS, false, false);
 }
 private static @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources() { return Map.of(RESOURCE,Set.of("read","write")); }
 private static @NonNull OAuthAuthorizationDecision decision(@NonNull String subject, @NonNull Set<@NonNull String> scopes, boolean refresh) {
  return OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(Map.of(RESOURCE,scopes)).refreshTokenPermitted(refresh).build();
 }
 private void initialized() {
  assertEquals(OAuthStoreCommitStatus.COMMITTED,this.coordinator.initializeFreshIssuer(deadline()));
  this.coordinator.establishNewSubject("subject",deadline());
 }
 private @NonNull String begin() { return this.first.begin(admission("state +&✓"),BROWSER,deadline()); }
 private @NonNull Optional<@NonNull String> complete(@NonNull String handle, @NonNull OAuthAuthorizationDecision decision) {
  return this.first.complete(handle,BROWSER,client(),resources(),decision,deadline());
 }
 private @NonNull String approved(@NonNull String handle) { return complete(handle,decision("subject",Set.of("read"),true)).orElseThrow(); }
 private @NonNull OAuthStoreEntry entry(OAuthStoreKey.@NonNull Kind kind) {
  return this.store.rows.values().stream().filter(e -> e.getKey().getKind()==kind).findFirst().orElseThrow();
 }
 private @NonNull JsonObject payload(OAuthStoreKey.@NonNull Kind kind) {
  return this.codec.open(entry(kind),Clock.fixed(this.clock.time,ZoneOffset.UTC));
 }
 private @NonNull OAuthAuthorizationRecord decoded(OAuthStoreKey.@NonNull Kind kind) {
  OAuthStoreEntry e=entry(kind); String key=e.getKey().getStorageKey();
  return OAuthAuthorizationRecord.decode(kind,key.substring(key.lastIndexOf(':')+1),payload(kind),LIMITS,255);
 }
 private static void invalid(@NonNull Executable call) {
  var failure=assertThrows(OAuthServerAdmissionFailure.class,call); assertNull(failure.getCause());
  assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_REQUEST,failure.reason());assertEquals("OAuth server admission failed.",failure.getMessage());
 }
 private static void failed(OAuthStoreFailure.@NonNull Reason reason,@NonNull Executable call) {
  var failure=assertThrows(OAuthStoreFailure.class,call);assertEquals(reason,failure.reason());assertNull(failure.getCause());
  assertEquals("OAuth server store operation failed.",failure.getMessage());
 }
 private static @NonNull JsonObject changed(@NonNull JsonObject object,@NonNull String key,@Nullable JsonValue value) {
  Map<String,JsonValue> map=new LinkedHashMap<>(object.getMembers());if(value==null)map.remove(key);else map.put(key,value);
  return JsonObject.fromMembers(map);
 }
 @Test void freshHandleIsRandomDigestKeyAndBrowserIsIndependent() {
  initialized();String a=begin(),b=begin();assertNotEquals(a,b);assertNotEquals(BROWSER,a);OAuthStoreFormat.nonce(a);
  String key=this.codec.key(OAuthStoreKey.Kind.INTERACTION,OAuthAuthorizationRecord.credentialDigest(a)).getStorageKey();
  assertTrue(this.store.rows.keySet().stream().anyMatch(k->k.getStorageKey().equals(key)));assertFalse(key.contains(a));
  assertNotEquals(a,payload(OAuthStoreKey.Kind.INTERACTION).findString("id").orElseThrow());
  assertEquals(NOW.plusSeconds(900).minusNanos(123456789),decoded(OAuthStoreKey.Kind.INTERACTION).expires());
 }
 @Test void resumeReconstructsExactReviewAndRequiresCompleteBarrier() {
  initialized();String handle=begin();OAuthAuthorizationRecord r=this.second.resume(handle,BROWSER,client(),deadline());
  assertEquals(REDIRECT,r.text("redirect"));assertEquals(RESOURCE,r.text("resource"));assertEquals(Set.of("read","write"),r.scopes(LIMITS));
  assertEquals("state +&✓",r.state(1024));assertEquals(List.of(),requireNonNull(this.store.lastTransaction).getMutations());
  assertEquals(2,requireNonNull(this.store.lastTransaction).getConditions().size());
 }
 @Test void absentAndEmptyStateRemainDistinct() {
  initialized();String absent=this.first.begin(admission(null),BROWSER,deadline());assertNull(this.first.resume(absent,BROWSER,client(),deadline()).state(1024));
  String empty=this.first.begin(admission(""),BROWSER,deadline());assertEquals("",this.first.resume(empty,BROWSER,client(),deadline()).state(1024));
 }
 @Test void approvalAtomicallyCompletesConsentAndCreatesCodePendingGrantAndClock() {
  initialized();String handle=begin(),code=approved(handle);OAuthServerCredential.codeDigest(code);
  OAuthAuthorizationRecord interaction=decoded(OAuthStoreKey.Kind.INTERACTION),c=decoded(OAuthStoreKey.Kind.CODE),g=decoded(OAuthStoreKey.Kind.GRANT);
  assertEquals("COMPLETED",interaction.text("status"));assertEquals("UNUSED",c.text("status"));assertEquals("PENDING",g.text("status"));
  assertEquals(OAuthServerCredential.codeDigest(code),g.text("codeId"));assertEquals(g.text("id"),c.text("grantId"));
  assertEquals(Set.of("read"),g.scopes(LIMITS));assertEquals("subject",g.text("subject"));assertTrue(g.refresh());
  var s=this.coordinator.begin(deadline());assertTrue(c.matchesIssuer(s.issuer()));assertTrue(g.matchesIssuer(s.issuer()));
  assertTrue(c.matchesSubject(s.subject("subject")));assertTrue(g.matchesSubject(s.subject("subject")));
  assertEquals(c.expires(),g.expires());assertEquals(c.expires(),entry(OAuthStoreKey.Kind.CODE).getRetainUntil());
  assertEquals(4,requireNonNull(this.store.lastTransaction).getMutations().size());
 }
 @Test void codeIsReleasedOnlyAfterBackendCommitsAllRows() {
  initialized();String handle=begin();this.store.beforeCommit=()->{assertEquals("PENDING",decoded(OAuthStoreKey.Kind.INTERACTION).text("status"));
   assertTrue(this.store.rows.keySet().stream().noneMatch(k->k.getKind()==OAuthStoreKey.Kind.CODE));};assertNotNull(approved(handle));
 }
 @Test void denialConsumesInteractionWithoutSubjectCodeOrGrant() {
  assertEquals(OAuthStoreCommitStatus.COMMITTED,this.coordinator.initializeFreshIssuer(deadline()));String handle=begin();
  assertEquals(Optional.empty(),complete(handle,OAuthAuthorizationDecision.deniedInstance()));
  assertEquals(2,this.store.rows.size());assertEquals("COMPLETED",decoded(OAuthStoreKey.Kind.INTERACTION).text("status"));invalid(()->approved(handle));
 }
 @Test void emptyExplicitScopeDecisionIsCommittedDenial() {
  initialized();String handle=begin();assertEquals(Optional.empty(),complete(handle,decision("unregistered",Set.of(),true)));
  assertTrue(this.store.rows.keySet().stream().noneMatch(k->k.getKind()==OAuthStoreKey.Kind.CODE));
 }
 @Test void duplicateApprovalCannotReemitOrCreateSecondGrant() {
  initialized();String handle=begin();approved(handle);int size=this.store.rows.size(),commits=this.store.commits;
  invalid(()->approved(handle));invalid(()->this.second.resume(handle,BROWSER,client(),deadline()));
  assertEquals(size,this.store.rows.size());assertEquals(commits,this.store.commits);
 }
 @Test void twoCompletersHaveOneWinnerAndNoSuccessRetry() {
  initialized();String handle=begin();String[] winner=new String[1];this.store.beforeCommit=()->winner[0]=this.second.complete(handle,BROWSER,client(),resources(),decision("subject",Set.of("read"),true),deadline()).orElseThrow();
  invalid(()->approved(handle));assertNotNull(winner[0]);assertEquals(1,this.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.CODE).count());
 }
 @Test void racingDenialPreventsApproval() {
  initialized();String handle=begin();this.store.beforeCommit=()->assertEquals(Optional.empty(),this.second.complete(handle,BROWSER,client(),resources(),OAuthAuthorizationDecision.deniedInstance(),deadline()));invalid(()->approved(handle));
 }
 @Test void wrongBrowserAndRandomHandleCannotPoisonConsent() {
  initialized();String handle=begin();int commits=this.store.commits;
  invalid(()->this.first.complete(handle,OTHER,client(),resources(),decision("subject",Set.of("read"),true),deadline()));
  invalid(()->this.first.resume(OTHER,BROWSER,client(),deadline()));assertEquals(commits,this.store.commits);assertNotNull(approved(handle));
 }
 @Test void changedIssuerEpochDuringCompletionAbortsReloadWithoutCode() {
  initialized();String handle=begin();this.store.beforeCommit=()->this.coordinator.revokeAll(deadline());invalid(()->approved(handle));
  assertEquals("PENDING",decoded(OAuthStoreKey.Kind.INTERACTION).text("status"));
 }
 @Test void oldIssuerIncarnationAtSameEpochRejectsPendingInteraction() {
  initialized();String handle=begin();this.store.rows.put(this.codec.issuerKey(),this.codec.seal(this.codec.issuerKey(),OAuthStoreFormat.PERMANENT,OAuthStoreFence.initialIssuer(OTHER,NOW).toPayload()));invalid(()->approved(handle));
 }
 @Test void currentSubjectFenceIsBoundAfterZeroEffectConflictReload() {
  initialized();String handle=begin();this.store.beforeCommit=()->this.coordinator.revokeSubject("subject",deadline());approved(handle);
  assertEquals(1,decoded(OAuthStoreKey.Kind.GRANT).number("subjectEpoch"));
 }
 @Test void missingEstablishedSubjectFailsClosedAndKeepsConsentPending() {
  initialized();String handle=begin();this.store.rows.remove(this.codec.subjectKey("subject"));
  failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->approved(handle));assertEquals("PENDING",decoded(OAuthStoreKey.Kind.INTERACTION).text("status"));
 }
 @Test void wrongResourceExcessScopesOrChangedServerPolicyKeepConsentPending() {
  initialized();String handle=begin();invalid(()->complete(handle,decision("subject",Set.of("admin"),false)));
  OAuthAuthorizationDecision wrong=OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of("urn:other",Set.of("read"))).build();invalid(()->complete(handle,wrong));
  invalid(()->this.first.complete(handle,BROWSER,client(),Map.of(RESOURCE,Set.of("write")),decision("subject",Set.of("read"),false),deadline()));assertNotNull(approved(handle));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> clientSecurityChangesRejectResumeAndCompletion() {
  List<OAuthServerClientRegistration> changed=List.of(client("v2",true,Set.of("read","write"),REDIRECT,false),client("v1",false,Set.of("read","write"),REDIRECT,false),
   client("v1",true,Set.of("read"),REDIRECT,false),client("v1",true,Set.of("read","write"),REDIRECT.replace("%2f","%2F"),false),client("v1",true,Set.of("read","write"),REDIRECT,true));
  return java.util.stream.IntStream.range(0,changed.size()).mapToObj(i->DynamicTest.dynamicTest("security-field-"+i,()->{
   initialized();String handle=begin();var current=changed.get(i);invalid(()->this.first.resume(handle,BROWSER,current,deadline()));
   invalid(()->this.first.complete(handle,BROWSER,current,resources(),decision("subject",Set.of("read"),true),deadline()));assertNotNull(approved(handle));this.store.rows.clear();
  }));
 }
 @Test void fingerprintIgnoresCollectionOrderAndDisplayTextOnly() {
  var a=client();var b=OAuthServerClientRegistration.withClientId("client").redirectUris(a.getRedirectUris()).allowedScopesByResource(Map.of(RESOURCE,new java.util.LinkedHashSet<>(List.of("write","read"))))
   .configurationVersion("v1").refreshTokenPermitted(true).clientName("untrusted display").build();
  assertEquals(OAuthAuthorizationRecord.clientFingerprint(a),OAuthAuthorizationRecord.clientFingerprint(b));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> refreshRequiresAllThreeExplicitPermissions() {
  return Stream.of(0,1,2,3).map(i->DynamicTest.dynamicTest("refresh-permission-"+i,()->{
   initialized();OAuthServerClientRegistration c=client("v1",i!=1,Set.of("read","write"),REDIRECT,false);
   var admit=OAuthServerAuthorizationAdmission.admit(OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",
    "client_id=client&response_type=code&redirect_uri="+encode(REDIRECT)+"&code_challenge_method=S256&code_challenge="+BROWSER+"&resource="+encode(RESOURCE),new byte[0],Map.of(),LIMITS),(id,budget)->Optional.of(c),deadline(),resources(),LIMITS,false,false);
   OAuthAuthorizationLedger ledger=ledger(i!=0,3);String h=ledger.begin(admit,BROWSER,deadline());ledger.complete(h,BROWSER,c,resources(),decision("subject",Set.of("read"),i!=2),deadline());
   assertEquals(i==3,decoded(OAuthStoreKey.Kind.GRANT).refresh());this.store.rows.clear();
  }));
 }
 @Test void conflictRetriesBoundedlyAndUnknownBeforeDoesNotRetryOrConsume() {
  initialized();String handle=begin();this.store.conflicts=2;assertNotNull(approved(handle));
  String other=begin();int commits=this.store.commits;this.store.unknownBefore=true;
  failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->approved(other));assertEquals(commits+1,this.store.commits);
  this.store.unknownBefore=false;assertNotNull(approved(other));
 }
 @Test void unknownAfterCommittedApprovalNeverReturnsOrReemitsCode() {
  initialized();String handle=begin();this.store.unknownAfter=true;int commits=this.store.commits;
  failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->approved(handle));assertEquals(commits+1,this.store.commits);
  this.store.unknownAfter=false;invalid(()->approved(handle));assertEquals("COMPLETED",decoded(OAuthStoreKey.Kind.INTERACTION).text("status"));
 }
 @Test void boundedConflictsHaveZeroWritesAndNoCodePublication() {
  initialized();String handle=begin();this.store.conflicts=8;int size=this.store.rows.size(),commits=this.store.commits;
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->approved(handle));assertEquals(commits+3,this.store.commits);assertEquals(size,this.store.rows.size());
 }
 @Test void beginAndResumeUnknownNeverReturnAHandleOrReview() {
  initialized();this.store.unknownBefore=true;failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->begin());
  this.store.unknownBefore=false;String handle=begin();this.store.unknownAfter=true;failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->this.first.resume(handle,BROWSER,client(),deadline()));
 }
 @Test void expiredInteractionIsInactiveEvenIfRowStillPhysicallyPresent() {
  initialized();String handle=begin();this.clock.time=entry(OAuthStoreKey.Kind.INTERACTION).getRetainUntil();invalid(()->approved(handle));
  invalid(()->this.first.resume(handle,BROWSER,client(),deadline()));
 }
 @Test void expiryDuringCommitPreventsCredentialReleaseEvenWhenRowsCommitted() {
  initialized();String handle=begin();this.store.afterCommit=()->this.clock.time=NOW.plusSeconds(120);
  // Code validity was rounded down, so this callback crossed the exact issuance boundary.
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->approved(handle));assertEquals("COMPLETED",payload(OAuthStoreKey.Kind.INTERACTION).findString("status").orElseThrow());
 }
 @Test void expiryBeforeBackendCommitPreventsAnyWrites() {
  initialized();String handle=begin();this.store.beforeRead=()->this.clock.time=NOW.plusSeconds(900);invalid(()->approved(handle));
 }
 @Test void originalDeadlineExpirationAfterCommitDoesNotPublishCode() {
  initialized();String handle=begin();Deadline budget=Deadline.fromNow(Duration.ofMillis(30));
  this.store.afterCommit=()->{while (!budget.isExpired()) LockSupport.parkNanos(Duration.ofMillis(1).toNanos());};
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->this.first.complete(handle,BROWSER,client(),resources(),decision("subject",Set.of("read"),false),budget));
 }
 @Test void configuredRecordCapRejectsOversizedConsentBeforeCommit() {
  initialized();OAuthStoreRecordCodec small=codec(1024);OAuthAuthorizationLedger ledger=new OAuthAuthorizationLedger(this.coordinator,small,LIMITS,Duration.ofMinutes(15),Duration.ofMinutes(2),3,255,false);
  int commits=this.store.commits;failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->ledger.begin(admission("a".repeat(1024)),BROWSER,deadline()));assertEquals(commits,this.store.commits);
 }
 @Test void forgedRetentionAndAuthenticatedWrongTypedPayloadAreCorrupt() {
  initialized();String handle=begin();OAuthStoreEntry e=entry(OAuthStoreKey.Kind.INTERACTION);JsonObject p=payload(OAuthStoreKey.Kind.INTERACTION);
  this.store.rows.put(e.getKey(),this.codec.seal(e.getKey(),e.getRetainUntil().plusSeconds(1),p.toJson()));failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->approved(handle));
  this.store.rows.put(e.getKey(),this.codec.seal(e.getKey(),e.getRetainUntil(),changed(p,"id",JsonString.fromValue(OTHER)).toJson()));failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->approved(handle));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> exactSchemasRejectMissingWrongTypeAndExtraFields() {
  initialized();String handle=begin();approved(handle);
  return Stream.of(OAuthStoreKey.Kind.INTERACTION,OAuthStoreKey.Kind.CODE,OAuthStoreKey.Kind.GRANT).flatMap(kind->{
   JsonObject p=payload(kind);String id=p.findString("id").orElseThrow();
   return Stream.concat(p.getMembers().keySet().stream().flatMap(name->Stream.of(
    DynamicTest.dynamicTest(kind+" missing "+name,()->assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(kind,id,changed(p,name,null),LIMITS,255))),
    DynamicTest.dynamicTest(kind+" null "+name,()->{if(!name.equals("state"))assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(kind,id,changed(p,name,JsonNull.defaultInstance()),LIMITS,255));else assertNull(OAuthAuthorizationRecord.decode(kind,id,changed(p,name,JsonNull.defaultInstance()),LIMITS,255).state(1024));})
   )),Stream.of(DynamicTest.dynamicTest(kind+" extra",()->assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(kind,id,changed(p,"extra",JsonString.fromValue("x")),LIMITS,255)))));
  });
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> malformedTypedValuesNeverAcquireAuthority() {
  initialized();assertNotNull(begin());JsonObject p=payload(OAuthStoreKey.Kind.INTERACTION);String id=p.findString("id").orElseThrow();
  Map<String,JsonValue> values=Map.of("issuerEpoch",com.revetsec.json.JsonNumber.fromValue(-1L),"issuerIncarnation",JsonString.fromValue("x"),
   "status",JsonString.fromValue("ACTIVE"),"expires",com.revetsec.json.JsonNumber.fromValue(Long.MAX_VALUE),"challenge",JsonString.fromValue("x"),
   "scopes",JsonArray.fromElements(List.of(JsonString.fromValue("read"),JsonString.fromValue("read"))),"resource",JsonString.fromValue("relative"),"redirect",JsonString.fromValue("https://evil.example/#fragment"));
  return values.entrySet().stream().map(e->DynamicTest.dynamicTest(e.getKey(),()->assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.INTERACTION,id,changed(p,e.getKey(),e.getValue()),LIMITS,255))));
 }
 @Test void narrowScopeSubjectAndStateBoundsAreAppliedOnDecode() {
  initialized();String h=begin();approved(h);JsonObject g=payload(OAuthStoreKey.Kind.GRANT),i=payload(OAuthStoreKey.Kind.INTERACTION);
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.GRANT,g.findString("id").orElseThrow(),changed(g,"subject",JsonString.fromValue("x".repeat(256))),LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.INTERACTION,i.findString("id").orElseThrow(),changed(i,"state",JsonString.fromValue("x".repeat(1025))),LIMITS,255));
  OAuthServerIngressLimits narrow=new OAuthServerIngressLimits(1024,1024,1024,128,256,1,1,1,1);
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.INTERACTION,i.findString("id").orElseThrow(),i,narrow,255));
 }
 @Test void unsupportedKindAndIllegalCompletionAreRejected() {
  initialized();String h=begin();approved(h);assertThrows(IllegalArgumentException.class,()->decoded(OAuthStoreKey.Kind.CODE).completed());
  assertThrows(IllegalArgumentException.class,()->decoded(OAuthStoreKey.Kind.INTERACTION).completed());
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.ACCESS_TOKEN,BROWSER,JsonObject.emptyInstance(),LIMITS,255));
 }
 @Test void diagnosticsNeverIncludeCredentialSubjectOrPayload() {
  initialized();String h=begin();approved(h);assertEquals("OAuthAuthorizationLedger{<redacted>}",this.first.toString());
  assertEquals("OAuthAuthorizationRecord{<redacted>}",decoded(OAuthStoreKey.Kind.GRANT).toString());
  assertEquals("OAuthGrantRetention{<redacted>}",retention().toString());
 }
 private static @NonNull OAuthGrantRetention retention() { return new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ofSeconds(30),Duration.ofSeconds(10),Duration.ofSeconds(60)); }
 @Test void firstRedemptionHIncludesPinnedMaximumAndAllMargins() {
  var r=retention();Instant family=NOW.plusSeconds(604800);assertEquals(family.plusSeconds(401).minusNanos(123456789),r.horizon(family));
  Instant firstToken=NOW.plusSeconds(300);assertEquals(firstToken.plusSeconds(401).minusNanos(123456789),r.horizon(firstToken));
  assertEquals(firstToken.plusSeconds(101).minusNanos(123456789),r.accessRetention(firstToken));assertEquals(Duration.ofMinutes(5),r.maximumAccessLifetime());
 }
 @Test void retentionCeilingAndValidityFloorRemainDistinctAtNegativeEpochs() {
  Instant fraction=Instant.ofEpochSecond(-2,123);assertEquals(Instant.ofEpochSecond(-1),OAuthGrantRetention.retain(fraction));
  assertEquals(Instant.ofEpochSecond(28),OAuthGrantRetention.expiry(fraction,Duration.ofSeconds(30)));
  assertEquals(Instant.ofEpochSecond(100),OAuthGrantRetention.retain(Instant.ofEpochSecond(100)));
 }
 @Test void pinnedLifetimeCannotBeIncreasedAndInvalidExpiryNeverWraps() {
  var r=retention();r.requireAccessLifetime(Duration.ofMinutes(5));assertThrows(IllegalArgumentException.class,()->r.requireAccessLifetime(Duration.ofMinutes(5).plusNanos(1)));
  assertThrows(IllegalArgumentException.class,()->r.requireAccessLifetime(Duration.ZERO));assertThrows(IllegalArgumentException.class,()->r.requireAccessLifetime(Duration.ofSeconds(-1)));
  assertThrows(IllegalArgumentException.class,()->r.horizon(Instant.MAX));assertThrows(IllegalArgumentException.class,()->r.accessRetention(OAuthStoreFormat.PERMANENT));
  assertThrows(IllegalArgumentException.class,()->OAuthGrantRetention.expiry(NOW,Duration.ZERO));assertThrows(IllegalArgumentException.class,()->OAuthGrantRetention.expiry(NOW,Duration.ofNanos(1)));
  assertThrows(IllegalArgumentException.class,()->OAuthGrantRetention.expiry(NOW,Duration.ofSeconds(Long.MAX_VALUE)));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> internalSettingsRejectOutsideApprovedBounds() {
  List<Executable> bad=List.of(()->new OAuthGrantRetention(Duration.ofSeconds(29),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO),
   ()->new OAuthGrantRetention(Duration.ofMinutes(16),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO),
   ()->new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ofSeconds(16),Duration.ofSeconds(1),Duration.ZERO),
   ()->new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ofSeconds(-1),Duration.ofSeconds(1),Duration.ZERO),
   ()->new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ZERO,Duration.ZERO,Duration.ZERO),
   ()->new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ZERO,Duration.ofSeconds(1),Duration.ofMinutes(6)),
   ()->new OAuthAuthorizationLedger(this.coordinator,this.codec,LIMITS,Duration.ofSeconds(59),Duration.ofSeconds(30),3,255,false),
   ()->new OAuthAuthorizationLedger(this.coordinator,this.codec,LIMITS,Duration.ofMinutes(1),Duration.ofMinutes(2),3,255,false),
   ()->new OAuthAuthorizationLedger(this.coordinator,this.codec,LIMITS,Duration.ofMinutes(15),Duration.ofSeconds(29),3,255,false),
   ()->ledger(false,0),()->ledger(false,9),()->new OAuthAuthorizationLedger(this.coordinator,this.codec,LIMITS,Duration.ofMinutes(15),Duration.ofMinutes(2),3,15,false));
  return java.util.stream.IntStream.range(0,bad.size()).mapToObj(n->DynamicTest.dynamicTest("invalid-setting-"+n,()->assertThrows(IllegalArgumentException.class,bad.get(n))));
 }
 @Test void consentBeginConflictsAreBoundedAndResumeReloadsCompleteReadSet() {
  initialized();this.store.conflicts=3;int count=this.store.commits;
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->begin());assertEquals(count+3,this.store.commits);
  this.store.conflicts=0;String handle=begin();this.store.conflicts=2;
  assertEquals("PENDING",this.first.resume(handle,BROWSER,client(),deadline()).text("status"));
  this.store.conflicts=3;failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->this.second.resume(handle,BROWSER,client(),deadline()));
 }
 @Test void sessionValidityBoundaryOnlyTightensAndCannotBeReused() {
  initialized();var s=this.coordinator.begin(deadline());s.requireBefore(NOW.plusSeconds(1));s.requireBefore(NOW.plusSeconds(2));
  this.clock.time=NOW.plusSeconds(1);failed(OAuthStoreFailure.Reason.UNAVAILABLE,s::barrier);
  assertThrows(IllegalStateException.class,()->s.requireBefore(NOW.plusSeconds(3)));
 }
 @Test void malformedScopeStateAndNonceBoundsAreRejected() {
  initialized();String h=begin();JsonObject p=payload(OAuthStoreKey.Kind.INTERACTION);String id=p.findString("id").orElseThrow();
  for (JsonValue value:List.of(JsonArray.emptyInstance(),JsonArray.fromElements(List.of(JsonNull.defaultInstance())),JsonArray.fromElements(List.of(JsonString.fromValue("bad scope")))))
   assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.INTERACTION,id,changed(p,"scopes",value),LIMITS,255));
  OAuthServerIngressLimits narrow=new OAuthServerIngressLimits(1024,1024,1024,128,256,1,1,4,1);
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.INTERACTION,id,p,narrow,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.INTERACTION,id,changed(p,"state",com.revetsec.json.JsonBoolean.fromValue(true)),LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.credentialDigest("not-a-random-binding"));assertNotNull(approved(h));
 }
 @Test void recordFenceBindingRequiresBothIncarnationAndEpoch() {
  initialized();String h=begin();approved(h);OAuthAuthorizationRecord c=decoded(OAuthStoreKey.Kind.CODE),g=decoded(OAuthStoreKey.Kind.GRANT);var session=this.coordinator.begin(deadline());
  assertFalse(c.matchesIssuer(session.issuer().advance(NOW)));assertFalse(g.matchesIssuer(OAuthStoreFence.initialIssuer(OTHER,NOW)));
  assertFalse(c.matchesSubject(session.subject("subject").advance(NOW)));assertFalse(g.matchesSubject(OAuthStoreFence.initialSubject(OTHER)));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> occupiedCredentialAndGrantKeysAreNeverOverwritten() {
  return Stream.of(OAuthStoreKey.Kind.INTERACTION,OAuthStoreKey.Kind.CODE,OAuthStoreKey.Kind.GRANT).map(kind->DynamicTest.dynamicTest("occupied-"+kind,()->{
   initialized();String handle=kind==OAuthStoreKey.Kind.INTERACTION?null:begin();
   OAuthAuthorizationServerStore occupied=new OAuthAuthorizationServerStore() {
    @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,@NonNull Duration budget) {
     if(key.getKind()==kind)store.rows.putIfAbsent(key,codec.seal(key,NOW.plusSeconds(3600).minusNanos(123456789),"{}"));
     return store.read(key,budget);
    }
    @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){return store.commit(transaction,budget);}
   };
   var coordinator=new OAuthStoreCoordinator(occupied,this.codec,this.clock,3,255);
   var ledger=new OAuthAuthorizationLedger(coordinator,this.codec,LIMITS,Duration.ofMinutes(15),Duration.ofMinutes(2),3,255,true);
   int commits=this.store.commits;
   if(kind==OAuthStoreKey.Kind.INTERACTION)failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->ledger.begin(admission(null),BROWSER,deadline()));
   else failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->ledger.complete(requireNonNull(handle),BROWSER,client(),resources(),decision("subject",Set.of("read"),true),deadline()));
   assertEquals(commits,this.store.commits);
   for(OAuthStoreEntry e:this.store.rows.values())if(e.getKey().getKind()==kind)assertEquals("{}",this.codec.open(e,Clock.fixed(NOW,ZoneOffset.UTC)).toJson());
   this.store.rows.clear();
  }));
 }
 private static @NonNull OAuthAuthorizationResponseEncoder encoder(int headerCap) {
  return new OAuthAuthorizationResponseEncoder(URI.create("https://issuer.example/tenant"),false,4096,headerCap,1024);
 }
 private @NonNull OAuthServerResponse wireComplete(@NonNull String handle, @NonNull OAuthAuthorizationDecision decision, int headerCap) {
  return this.first.completeResponse(handle,BROWSER,OAuthServerClientSelection.registered(client()),resources(),decision,encoder(headerCap),deadline());
 }
 @Test void preparedConsentSuccessRetainsExactQueryStateIssuerAndTypedCode() {
  initialized();String handle=begin();var response=wireComplete(handle,decision("subject",Set.of("read"),true),1024);
  assertEquals(303,response.getStatusCode());String location=response.getLocationWithCredentials().orElseThrow().toString();
  assertTrue(location.startsWith(REDIRECT+"&code=rsc1_"));assertTrue(location.endsWith("&state=state+%2B%26%E2%9C%93&iss=https%3A%2F%2Fissuer.example%2Ftenant"));
  String code=location.substring(location.indexOf("code=")+5,location.indexOf("&state="));assertEquals(OAuthServerCredential.codeDigest(code),decoded(OAuthStoreKey.Kind.GRANT).text("codeId"));
  assertFalse(response.getHeaders().containsKey("Location"));assertEquals(0,response.toHttpBodyWithCredentials().length);assertEquals(List.of("no-referrer"),response.getHeaders().get("Referrer-Policy"));
  byte[] before=response.wireHeaders();this.clock.time=NOW.plusSeconds(9999);assertArrayEquals(before,response.wireHeaders());assertEquals(location,response.getLocationWithCredentials().orElseThrow().toString());
 }
 @Test void preparedConsentDenialAndEmptyScopesConsumeWithoutCodes() {
  initialized();String handle=begin();var response=wireComplete(handle,OAuthAuthorizationDecision.deniedInstance(),1024);
  assertTrue(response.getLocationWithCredentials().orElseThrow().toString().contains("&error=access_denied&state="));
  assertEquals("COMPLETED",decoded(OAuthStoreKey.Kind.INTERACTION).text("status"));assertTrue(this.store.rows.keySet().stream().noneMatch(k->k.getKind()==OAuthStoreKey.Kind.CODE));
  String empty=begin();assertTrue(wireComplete(empty,decision("subject",Set.of(),false),1024).getLocationWithCredentials().orElseThrow().toString().contains("error=access_denied"));
 }
 @Test void responseOverflowLeavesConsentPendingAndNoCodeOrGrant() {
  initialized();String handle=this.first.begin(admission("+".repeat(300)),BROWSER,deadline());int commits=this.store.commits;
  assertThrows(IllegalArgumentException.class,()->wireComplete(handle,decision("subject",Set.of("read"),true),1024));
  assertEquals(commits,this.store.commits);assertEquals("PENDING",decoded(OAuthStoreKey.Kind.INTERACTION).text("status"));
  assertTrue(this.store.rows.keySet().stream().noneMatch(k->k.getKind()==OAuthStoreKey.Kind.CODE || k.getKind()==OAuthStoreKey.Kind.GRANT));
  assertEquals(303,wireComplete(handle,decision("subject",Set.of("read"),true),4096).getStatusCode());
 }
 @Test void denialOverflowAlsoLeavesConsentPending() {
  initialized();String handle=this.first.begin(admission("+".repeat(300)),BROWSER,deadline());int commits=this.store.commits;
  assertThrows(IllegalArgumentException.class,()->wireComplete(handle,OAuthAuthorizationDecision.deniedInstance(),1024));assertEquals(commits,this.store.commits);
  assertEquals("PENDING",decoded(OAuthStoreKey.Kind.INTERACTION).text("status"));assertEquals(303,wireComplete(handle,OAuthAuthorizationDecision.deniedInstance(),4096).getStatusCode());
 }
 @Test void preparedResponseNeverEscapesUnknownBeforeOrAfterCommit() {
  initialized();String handle=begin();this.store.unknownBefore=true;
  failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->wireComplete(handle,decision("subject",Set.of("read"),true),1024));
  assertEquals("PENDING",decoded(OAuthStoreKey.Kind.INTERACTION).text("status"));this.store.unknownBefore=false;this.store.unknownAfter=true;
  failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->wireComplete(handle,decision("subject",Set.of("read"),true),1024));
  assertEquals("COMPLETED",decoded(OAuthStoreKey.Kind.INTERACTION).text("status"));this.store.unknownAfter=false;
  invalid(()->wireComplete(handle,decision("subject",Set.of("read"),true),1024));
 }
 @Test void conflictsPrepareFreshCodeAndExposeOnlyTheCommittedOne() {
  initialized();String handle=begin();this.store.conflicts=2;int commits=this.store.commits;var response=wireComplete(handle,decision("subject",Set.of("read"),true),1024);
  assertEquals(commits+3,this.store.commits);String query=response.getLocationWithCredentials().orElseThrow().getRawQuery();String code=query.substring(query.indexOf("code=")+5,query.indexOf("&state="));
  assertEquals(OAuthServerCredential.codeDigest(code),decoded(OAuthStoreKey.Kind.GRANT).text("codeId"));
 }
 @Test void browserOrClientMismatchCannotEmitRedirectOrConsume() {
  initialized();String handle=begin();int commits=this.store.commits;
  invalid(()->this.first.completeResponse(handle,OTHER,OAuthServerClientSelection.registered(client()),resources(),decision("subject",Set.of("read"),true),encoder(1024),deadline()));
  invalid(()->this.first.completeResponse(handle,BROWSER,OAuthServerClientSelection.registered(client("v2",true,Set.of("read","write"),REDIRECT,false)),resources(),decision("subject",Set.of("read"),true),encoder(1024),deadline()));
  assertEquals(commits,this.store.commits);assertNotNull(wireComplete(handle,decision("subject",Set.of("read"),true),1024));
 }
 @Test void wireAbsentAndEmptyStateRemainDistinct() {
  initialized();String absent=this.first.begin(admission(null),BROWSER,deadline());String empty=this.first.begin(admission(""),BROWSER,deadline());
  assertFalse(wireComplete(absent,OAuthAuthorizationDecision.deniedInstance(),1024).getLocationWithCredentials().orElseThrow().toString().contains("&state="));
  assertTrue(wireComplete(empty,OAuthAuthorizationDecision.deniedInstance(),1024).getLocationWithCredentials().orElseThrow().toString().contains("&state=&iss="));
 }
 @Test void redirectWithoutQueryAndEmptyQueryArePreserved() {
  initialized();
  for(String redirect:List.of("https://client.example/cb","https://client.example/cb?")) {
   var current=client("v1",true,Set.of("read","write"),redirect,false);
   String query="client_id=client&response_type=code&redirect_uri="+encode(redirect)+"&code_challenge_method=S256&code_challenge="+BROWSER+"&resource="+encode(RESOURCE);
   var request=OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",query,new byte[0],Map.of(),LIMITS);
   var admission=OAuthServerAuthorizationAdmission.admit(request,(id,b)->Optional.of(current),deadline(),resources(),LIMITS,false,false);
   String handle=this.first.begin(admission,BROWSER,deadline());var response=this.first.completeResponse(handle,BROWSER,OAuthServerClientSelection.registered(current),resources(),OAuthAuthorizationDecision.deniedInstance(),encoder(1024),deadline());
   assertEquals("https://client.example/cb?error=access_denied&iss=https%3A%2F%2Fissuer.example%2Ftenant",response.getLocationWithCredentials().orElseThrow().toString());
  }
 }
 private static final class MutableClock extends Clock {
  @NonNull Instant time;
  private MutableClock(@NonNull Instant time){this.time=time;}
  @Override public @NonNull Instant instant(){return this.time;}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){requireNonNull(zone);return this;}
 }
}
