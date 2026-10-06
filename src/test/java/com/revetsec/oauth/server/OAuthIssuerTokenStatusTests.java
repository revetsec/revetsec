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
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.*;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.function.Executable;
import java.net.URI;
import java.nio.charset.StandardCharsets;
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
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Cryptographic admission and complete deterministic read-set barriers; no durable-backend claim. */
final class OAuthIssuerTokenStatusTests {
 private static final @NonNull Instant NOW = Instant.parse("2026-10-04T00:00:00.123456789Z");
 private static final @NonNull String ISSUER = "https://issuer.example/tenant", RESOURCE = "https://resource.example/mcp";
 private static final @NonNull String REDIRECT = "https://client.example/cb?x=%2f", BROWSER = "A".repeat(43);
 private static final @NonNull String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
 private static final @NonNull String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private static final @NonNull OAuthServerIngressLimits LIMITS = OAuthServerIngressLimits.fromDefaults();
 private static final TestJsonWebKeys.@NonNull Fixture KEY = TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
 private final @NonNull OAuthAtomicStoreFixture store = new OAuthAtomicStoreFixture();
 private final @NonNull MutableClock clock = new MutableClock(NOW);
 private final @NonNull OAuthStoreRecordCodec codec = codec();
 private final @NonNull OAuthStoreCoordinator coordinator = new OAuthStoreCoordinator(this.store, this.codec, this.clock, 3, 255);
 private final @NonNull OAuthAuthorizationLedger consent = new OAuthAuthorizationLedger(this.coordinator, this.codec, LIMITS,
  Duration.ofMinutes(15), Duration.ofMinutes(2), 3, 255, true);
 private final @NonNull OAuthGrantRetention retention = new OAuthGrantRetention(Duration.ofMinutes(5), Duration.ofSeconds(30), Duration.ofSeconds(10), Duration.ofSeconds(60));
 private final @NonNull OAuthCodeRedemption first = engine(true, signer(), 3);
 OAuthIssuerTokenStatusTests() { }
 private static @NonNull OAuthStoreRecordCodec codec() {
  byte[] key=new byte[32];for(int n=0;n<key.length;n++)key[n]=(byte)(n+1);
  return new OAuthStoreRecordCodec(ISSUER,StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key)))
   .clock(Clock.fixed(NOW,ZoneOffset.UTC)).build(),3800);
 }
 private static @NonNull JwsSigner signer() { return JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),KEY.getPublicKey(),JwsAlgorithm.RS256); }
 private @NonNull OAuthCodeRedemption engine(boolean refresh,@NonNull JwsSigner signer,int attempts) {
  return new OAuthCodeRedemption(this.coordinator,this.codec,LIMITS,this.retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer,32768,16384),
   Duration.ofMinutes(5),refresh,Duration.ofDays(1),Duration.ofDays(7),attempts,255);
 }
 private static @NonNull Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(10)); }
 private static @NonNull Map<@NonNull String,@NonNull Set<@NonNull String>> resources() { return Map.of(RESOURCE,Set.of("read","write")); }
 private static @NonNull OAuthServerClientRegistration client() { return client("client","v1",false); }
 private static @NonNull OAuthServerClientRegistration client(@NonNull String id,@NonNull String version,boolean confidential) {
  return OAuthServerClientRegistration.withClientId(id).configurationVersion(version).redirectUris(List.of(URI.create(REDIRECT)))
   .allowedScopesByResource(resources()).refreshTokenPermitted(true)
   .authentication(confidential ? OAuthServerClientAuthentication.fromClientSecretVerifier((i,s,b)->true) : null).build();
 }
 private static @NonNull String encode(@NonNull String text) {
  try { return FormUrlEncoding.encode(text); } catch(com.revetsec.internal.encoding.EncodingException failure) { throw new AssertionError(failure); }
 }
 private static @NonNull OAuthAuthorizationDecision decision(@NonNull String subject,@NonNull Set<@NonNull String> scopes,boolean refresh) {
  return OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(Map.of(RESOURCE,scopes)).refreshTokenPermitted(refresh).build();
 }
 private static @NonNull OAuthGrantPolicy allow() { return (context,budget)->decision(context.getSubject(),requireNonNull(context.getAuthorizedScopesByResource().get(RESOURCE)),context.isRefreshTokenPermitted()); }
 private @NonNull String code(boolean refresh) { return code(refresh,client()); }
 private @NonNull String code(boolean refresh,@NonNull OAuthServerClientRegistration client) {
  assertEquals(OAuthStoreCommitStatus.COMMITTED,this.coordinator.initializeFreshIssuer(deadline()));this.coordinator.establishNewSubject("subject",deadline());
  String q="client_id="+encode(client.getClientId())+"&response_type=code&redirect_uri="+encode(REDIRECT)+"&resource="+encode(RESOURCE)+"&code_challenge_method=S256&code_challenge="+CHALLENGE;
  var request=OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",q,new byte[0],Map.of(),LIMITS);
  var admission=OAuthServerAuthorizationAdmission.admit(request,(id,budget)->Optional.of(client),deadline(),resources(),LIMITS,false,false);
  String handle=this.consent.begin(admission,BROWSER,deadline());return this.consent.complete(handle,BROWSER,client,resources(),decision("subject",Set.of("read","write"),refresh),deadline()).orElseThrow();
 }
 private static @NonNull OAuthServerRequest request(@NonNull String code,@NonNull Map<@NonNull String,@NonNull String> overrides) {
  Map<String,String> fields=new LinkedHashMap<>(Map.of("grant_type","authorization_code","code",code,"code_verifier",VERIFIER,"resource",RESOURCE,"client_id","client"));fields.putAll(overrides);
  String body=String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());
  return OAuthServerRequest.parse(OAuthServerRequest.Endpoint.TOKEN,"POST",null,body.getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded")),LIMITS);
 }
 private @NonNull OAuthTokenResponse redeem(@NonNull String code) { return this.first.redeem(request(code,Map.of()),(id,budget)->Optional.of(client()),resources(),allow(),deadline()); }
 private @NonNull OAuthStoreEntry entry(OAuthStoreKey.@NonNull Kind kind) { return this.store.rows.values().stream().filter(e->e.getKey().getKind()==kind).findFirst().orElseThrow(); }
 private @NonNull JsonObject payload(OAuthStoreKey.@NonNull Kind kind) { return this.codec.open(entry(kind),Clock.fixed(this.clock.time,ZoneOffset.UTC)); }
 private @NonNull OAuthAuthorizationRecord record(OAuthStoreKey.@NonNull Kind kind) {
  String k=entry(kind).getKey().getStorageKey();return OAuthAuthorizationRecord.decode(kind,k.substring(k.lastIndexOf(':')+1),payload(kind),LIMITS,255);
 }
 private void replace(OAuthStoreKey.@NonNull Kind kind,@NonNull JsonObject payload) {
  var entry=entry(kind);this.store.rows.put(entry.getKey(),this.codec.seal(entry.getKey(),entry.getRetainUntil(),payload.toJson()));
 }
 private static @NonNull JsonObject changed(@NonNull JsonObject original,@NonNull String key,@Nullable JsonValue value) {
  Map<String,JsonValue> members=new LinkedHashMap<>(original.getMembers());if(value==null)members.remove(key);else members.put(key,value);return JsonObject.fromMembers(members);
 }
 private static @NonNull JsonObject json(byte @NonNull [] bytes) {
  try { return (JsonObject)JsonCodec.parse(bytes,JsonLimits.jose(131072)); } catch(com.revetsec.internal.json.JsonParseException failure) { throw new AssertionError(failure); }
 }
 private static @NonNull JsonObject body(@NonNull OAuthTokenResponse response) { return json(response.body()); }
 private static @NonNull String token(@NonNull OAuthTokenResponse response) { return body(response).findString("access_token").orElseThrow(); }
 private static void invalid(@NonNull Executable call) {
  var e=assertThrows(OAuthServerAdmissionFailure.class,call);assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_TOKEN,e.reason());assertNull(e.getCause());assertEquals("OAuth server admission failed.",e.getMessage());
 }
 private static void unavailable(@NonNull Executable call) { var e=assertThrows(OAuthServerAdmissionFailure.class,call);assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,e.reason());assertNull(e.getCause()); }
 private static void failed(OAuthStoreFailure.@NonNull Reason reason,@NonNull Executable call) { var e=assertThrows(OAuthStoreFailure.class,call);assertEquals(reason,e.reason());assertNull(e.getCause()); }
 private @NonNull OAuthIssuerTokenStatus status() { return status(3,Duration.ofSeconds(30),this.clock); }
 private @NonNull OAuthIssuerTokenStatus status(int attempts,@NonNull Duration skew,@NonNull Clock clock) {
  return new OAuthIssuerTokenStatus(this.coordinator,this.codec,LIMITS,clock,skew,attempts,255,16384);
 }
 private static @NonNull StaticJsonWebKeySource keys() {
  return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(TestJsonWebKeys.withFixture(KEY).kid("key").alg("RS256").toKeySetJson()));
 }
 private @NonNull JsonObject validate(@NonNull String token) { return status().validate(token,RESOURCE,keys(),deadline()); }
 private @NonNull String issued() { return token(redeem(code(true))); }
 private @NonNull String signed(@NonNull JsonObject claims) { return signer().toCompactSerialization("at+jwt","key",null,JsonCodec.toUtf8Bytes(claims),Duration.ofSeconds(10)); }
 private static @NonNull JsonObject claims(@NonNull String token) { return json(Base64.getUrlDecoder().decode(token.split("\\.",-1)[1])); }
 private void revokeGrant() { var g=record(OAuthStoreKey.Kind.GRANT);replace(OAuthStoreKey.Kind.GRANT,json(g.terminated(LIMITS,255).toPayload().getBytes(StandardCharsets.UTF_8))); }
 private void remove(OAuthStoreKey.@NonNull Kind kind) { this.store.rows.remove(entry(kind).getKey()); }
 private static @NonNull DynamicTest test(@NonNull String name,@NonNull Executable action) { return DynamicTest.dynamicTest(name,action); }
 @Test void validTokenReleasesOnlyImmutableClaimsAfterCompleteConditionOnlyBarrier() {
  String jwt=issued();Map<OAuthStoreKey,OAuthStoreEntry> before=Map.copyOf(this.store.rows);int count=this.store.commits;
  assertEquals(claims(jwt),validate(jwt));assertEquals(count+1,this.store.commits);assertEquals(before,this.store.rows);
  var t=requireNonNull(this.store.lastTransaction);assertTrue(t.getMutations().isEmpty());assertEquals(4,t.getConditions().size());
  assertEquals(Set.of(OAuthStoreKey.Kind.ISSUER_STATE,OAuthStoreKey.Kind.SUBJECT_STATE,OAuthStoreKey.Kind.ACCESS_TOKEN,OAuthStoreKey.Kind.GRANT),t.getConditions().stream().map(c->c.getKey().getKind()).collect(java.util.stream.Collectors.toSet()));
  assertTrue(t.getConditions().stream().allMatch(c->c.getExpectedVersion().isPresent()));assertFalse(validate(jwt).toString().contains(jwt));
 }
 @Test void consumedCodeReplayMakesAnOtherwiseCorrectlySignedAccessTokenInactive() {
  String code=code(true),jwt=token(redeem(code));validate(jwt);
  var e=assertThrows(OAuthServerAdmissionFailure.class,()->redeem(code));assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,e.reason());invalid(()->validate(jwt));
 }
 @Test void subjectAndIssuerRevocationInvalidateSubsequentStatus() {
  String jwt=issued();validate(jwt);this.coordinator.revokeSubject("subject",deadline());invalid(()->validate(jwt));
 }
 @Test void issuerRevocationInvalidatesSubsequentStatus() {String jwt=issued();this.coordinator.revokeAll(deadline());invalid(()->validate(jwt));}
 @Test void noPositiveStatusCache() {String jwt=issued();validate(jwt);revokeGrant();invalid(()->validate(jwt));}
 @Test void allFourVersionPredicatesAreCheckedOnEverySuccessfulBarrier() {
  for(var kind:List.of(OAuthStoreKey.Kind.ISSUER_STATE,OAuthStoreKey.Kind.SUBJECT_STATE,OAuthStoreKey.Kind.ACCESS_TOKEN,OAuthStoreKey.Kind.GRANT)) {
   var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();var row=f.entry(kind);int commits=f.store.commits;
   f.store.beforeCommit=()->f.store.rows.put(row.getKey(),f.codec.seal(row.getKey(),row.getRetainUntil(),f.codec.open(row,Clock.fixed(NOW,ZoneOffset.UTC)).toJson()));
   f.validate(jwt);assertEquals(commits+2,f.store.commits,kind.name());assertEquals(4,requireNonNull(f.store.lastTransaction).getConditions().size());
  }
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> revocationBetweenReadsAndCommitNeverAdmits() {
  return Stream.of("grant","subject","issuer","jti").map(kind->test(kind,()->{
   var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();f.store.beforeCommit=()->{
    switch(kind){case "grant"->f.revokeGrant();case "subject"->f.coordinator.revokeSubject("subject",deadline());case "issuer"->f.coordinator.revokeAll(deadline());default->f.remove(OAuthStoreKey.Kind.ACCESS_TOKEN);}
   };invalid(()->f.validate(jwt));
  }));
 }
 @Test void workAdmittedBeforeRevocationHasNoRollbackPromiseButNextAdmissionFails() {
  String jwt=issued();this.store.afterCommit=this::revokeGrant;assertEquals(claims(jwt),validate(jwt));invalid(()->validate(jwt));
 }
 @Test void absentJtiBarrierReloadsIfRowAppearsBeforeCommit() {
  String jwt=issued();var row=entry(OAuthStoreKey.Kind.ACCESS_TOKEN);remove(OAuthStoreKey.Kind.ACCESS_TOKEN);int commits=this.store.commits;
  this.store.beforeCommit=()->this.store.rows.put(row.getKey(),row);assertEquals(claims(jwt),validate(jwt));assertEquals(commits+2,this.store.commits);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> missingIssuanceAndGrantGiveCommittedInactiveVerdicts() {
  return Stream.of(OAuthStoreKey.Kind.ACCESS_TOKEN,OAuthStoreKey.Kind.GRANT).map(kind->test(kind.name(),()->{
   var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();f.remove(kind);int commits=f.store.commits;invalid(()->f.validate(jwt));assertEquals(commits+1,f.store.commits);
   assertTrue(requireNonNull(f.store.lastTransaction).getConditions().stream().anyMatch(c->c.getKey().getKind()==kind&&c.getExpectedVersion().isEmpty()));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> missingPermanentFencesAreInfrastructure() {
  return Stream.of(OAuthStoreKey.Kind.ISSUER_STATE,OAuthStoreKey.Kind.SUBJECT_STATE).map(kind->test(kind.name(),()->{var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();f.remove(kind);failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->f.validate(jwt));}));
 }
 @Test void conflictExhaustionNeverReturnsClaims() {String jwt=issued();this.store.conflicts=8;failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->validate(jwt));assertEquals(5,this.store.conflicts);}
 @Test void oneAttemptDoesNotRetryConflict() {String jwt=issued();this.store.conflicts=2;failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->status(1,Duration.ZERO,this.clock).validate(jwt,RESOURCE,keys(),deadline()));assertEquals(1,this.store.conflicts);}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unknownCommitNeverReturnsClaimsOrRetriesEvenForInactiveToken() {
  return Stream.of("before-active","after-active","before-missing","after-missing").map(name->test(name,()->{
   var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();if(name.endsWith("missing"))f.remove(OAuthStoreKey.Kind.ACCESS_TOKEN);
   f.store.unknownBefore=name.startsWith("before");f.store.unknownAfter=name.startsWith("after");int count=f.store.commits;
   failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->f.validate(jwt));assertEquals(count+1,f.store.commits);
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> backendFaultsRemainUnavailable() {
  return Stream.of("null-read","null-commit","runtime","interrupt").map(name->test(name,()->{
   var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();f.store.nullRead=name.equals("null-read");f.store.nullCommit=name.equals("null-commit");
   if(name.equals("runtime"))f.store.fault=new IllegalStateException(jwt);if(name.equals("interrupt"))f.store.fault=new InterruptedException(jwt);
   try {failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->f.validate(jwt));assertEquals(name.equals("interrupt"),Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}
  }));
 }
 @Test void fatalStoreErrorsPropagate() {String jwt=issued();TestFatal error=new TestFatal();this.store.fault=error;assertSame(error,assertThrows(TestFatal.class,()->validate(jwt)));}
 @Test void deadlineAndExistingInterruptionAreCheckedBeforeCryptoOrBackend() {
  String jwt=issued();int count=this.store.reads;unavailable(()->status().validate(jwt,RESOURCE,keys(),Deadline.fromNow(Duration.ZERO)));assertEquals(count,this.store.reads);
  Thread.currentThread().interrupt();try{unavailable(()->validate(jwt));assertTrue(Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}
 }
 @Test void tokenExpiryAndConfiguredSkewAreEnforcedAtAdmission() {
  String jwt=issued();Instant expires=record(OAuthStoreKey.Kind.ACCESS_TOKEN).expires();this.clock.time=expires.plusSeconds(29);validate(jwt);
  this.clock.time=expires.plusSeconds(30);invalid(()->validate(jwt));
 }
 @Test void grantFamilyExpiryDoesNotPrematurelyInvalidateLastAccessDescendant() {
  String jwt=token(redeem(code(false)));this.clock.time=record(OAuthStoreKey.Kind.GRANT).expires().plusSeconds(1);validate(jwt);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> lateValidityCrossingNeverReturnsSuccess() {
  return Stream.of("before","after").map(when->test(when,()->{var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();Instant expires=f.record(OAuthStoreKey.Kind.ACCESS_TOKEN).expires().plusSeconds(30);Runnable late=()->f.clock.time=expires;
   if(when.equals("before"))f.store.beforeCommit=late;else f.store.afterCommit=late;failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->f.validate(jwt));
  }));
 }
 @Test void backwardsClockCannotAdmit() {String jwt=issued();this.clock.time=NOW.minusSeconds(1);failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->validate(jwt));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> wrongSignedIdentityAndScopeNeverMatchIssuedJti() {
  Map<String,JsonValue> values=new LinkedHashMap<>();values.put("sub",JsonString.fromValue("other"));values.put("client_id",JsonString.fromValue("other"));values.put("scope",JsonString.fromValue("read"));values.put("iat",JsonNumber.fromValue(NOW.getEpochSecond()+1));values.put("exp",JsonNumber.fromValue(NOW.getEpochSecond()+299));
  return values.entrySet().stream().map(e->test(e.getKey(),()->{var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();invalid(()->f.validate(f.signed(changed(claims(jwt),e.getKey(),e.getValue()))));}));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> everyMissingOrWrongTypedFixedClaimRejects() {
  return Stream.of("iss","sub","aud","client_id","iat","exp","jti","scope").flatMap(name->Stream.of("missing","null","boolean").map(mode->test(name+"-"+mode,()->{
   var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();JsonValue value=mode.equals("missing")?null:mode.equals("null")?JsonNull.defaultInstance():JsonBoolean.fromValue(true);
   invalid(()->f.validate(f.signed(changed(claims(jwt),name,value))));
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> fixedProfileRejectsNoncanonicalClaimsAndUnknownIssuance() {
  Map<String,JsonValue> edits=new LinkedHashMap<>();edits.put("scope",JsonString.fromValue("write read"));edits.put("jti",JsonString.fromValue("x"));edits.put("extra",JsonString.fromValue("extra"));edits.put("aud",JsonArray.fromElements(List.of(JsonString.fromValue(RESOURCE))));
  return edits.entrySet().stream().map(e->test(e.getKey(),()->{var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();invalid(()->f.validate(f.signed(changed(claims(jwt),e.getKey(),e.getValue()))));}));
 }
 @Test void canonicalUnknownJtiIsInactiveWithAbsenceBarrier() {String jwt=issued();String unknown=this.codec.freshVersion();invalid(()->validate(signed(changed(claims(jwt),"jti",JsonString.fromValue(unknown)))));assertTrue(requireNonNull(this.store.lastTransaction).getConditions().stream().anyMatch(c->c.getKey().getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN&&c.getExpectedVersion().isEmpty()));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> cryptographicRejectionPrecedesBackendReads() {
  return Stream.of("signature","type","kid","no-kid","algorithm","issuer","audience","expired","future","size","syntax").map(name->test(name,()->{
   var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();JsonObject c=claims(jwt);String hostile=switch(name){
    case "signature"->jwt.substring(0,jwt.lastIndexOf('.')+1)+Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[256]);
    case "type"->signer().toCompactSerialization("JWT","key",null,JsonCodec.toUtf8Bytes(c),Duration.ofSeconds(10));
    case "kid"->signer().toCompactSerialization("at+jwt","other",null,JsonCodec.toUtf8Bytes(c),Duration.ofSeconds(10));
    case "no-kid"->signer().toCompactSerialization("at+jwt",null,null,JsonCodec.toUtf8Bytes(c),Duration.ofSeconds(10));
    case "algorithm"->JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),KEY.getPublicKey(),JwsAlgorithm.RS384).toCompactSerialization("at+jwt","key",null,JsonCodec.toUtf8Bytes(c),Duration.ofSeconds(10));
    case "issuer"->f.signed(changed(c,"iss",JsonString.fromValue(ISSUER+"/")));
    case "audience"->f.signed(changed(c,"aud",JsonString.fromValue(RESOURCE+"/")));
    case "expired"->f.signed(changed(c,"exp",JsonNumber.fromValue(NOW.getEpochSecond()-60)));
    case "future"->f.signed(changed(c,"iat",JsonNumber.fromValue(NOW.getEpochSecond()+60)));
    case "size"->"x".repeat(16385);default->"invalid";};
   int reads=f.store.reads;invalid(()->f.validate(hostile));assertEquals(reads,f.store.reads);
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> authenticatedCrossRecordContradictionsAreCorruption() {
  return Stream.of("lineage","subject","client","resource","scope","pending","pin","horizon","retention").map(name->test(name,()->{
   var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();var kind=OAuthStoreKey.Kind.ACCESS_TOKEN;JsonObject p=f.payload(kind);
   switch(name){case "lineage"->p=changed(p,"issuerEpoch",JsonNumber.fromValue(1L));case "subject"->p=changed(p,"subject",JsonString.fromValue("other"));case "client"->p=changed(p,"clientId",JsonString.fromValue("other"));case "resource"->p=changed(p,"resource",JsonString.fromValue(RESOURCE+"/other"));case "scope"->p=changed(p,"scopes",JsonArray.fromElements(List.of(JsonString.fromValue("admin"))));case "pin"->p=changed(p,"issued",JsonNumber.fromValue(NOW.getEpochSecond()-1));case "horizon"->p=changed(p,"retain",JsonNumber.fromValue(f.record(OAuthStoreKey.Kind.GRANT).horizon().plusSeconds(1).getEpochSecond()));case "retention"->p=changed(p,"retain",JsonNumber.fromValue(f.record(kind).expires().getEpochSecond()));default->{kind=OAuthStoreKey.Kind.GRANT;p=changed(f.payload(kind),"status",JsonString.fromValue("PENDING"));}}
   f.replace(kind,p);failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->f.validate(jwt));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> alteredAuthenticatedRecordsDoNotBecomeInactiveDomainProof() {
  return Stream.of(OAuthStoreKey.Kind.ACCESS_TOKEN,OAuthStoreKey.Kind.GRANT,OAuthStoreKey.Kind.SUBJECT_STATE,OAuthStoreKey.Kind.ISSUER_STATE).map(kind->test(kind.name(),()->{
   var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();var e=f.entry(kind);String envelope=e.toSealedForm();int index=envelope.length()-2;char replacement=envelope.charAt(index)=='A'?'B':'A';
   String damaged=envelope.substring(0,index)+replacement+envelope.substring(index+1);assertNotEquals(envelope,damaged);
   f.store.rows.put(e.getKey(),OAuthStoreEntry.fromStoredForm(e.getKey(),e.getVersion(),e.getRetainUntil(),damaged));failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->f.validate(jwt));
  }));
 }
 @Test @SuppressWarnings("NullAway") // Deliberate null required input verifies the constructor contract.
 void constructorIsPureAndBoundsAreChecked() {
  Clock explosive=new Clock(){@Override public @NonNull ZoneId getZone(){throw new AssertionError();}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){throw new AssertionError();}@Override public @NonNull Instant instant(){throw new AssertionError();}};
  status(3,Duration.ZERO,explosive);assertEquals(0,this.store.reads);
  for(int count:List.of(0,9))assertThrows(IllegalArgumentException.class,()->status(count,Duration.ZERO,this.clock));
  for(Duration skew:List.of(Duration.ofSeconds(-1),Duration.ofSeconds(61)))assertThrows(IllegalArgumentException.class,()->status(3,skew,this.clock));
  for(int subjects:List.of(15,1025))assertThrows(IllegalArgumentException.class,()->new OAuthIssuerTokenStatus(this.coordinator,this.codec,LIMITS,this.clock,Duration.ZERO,3,subjects,16384));
  for(int tokens:List.of(1023,65537))assertThrows(IllegalArgumentException.class,()->new OAuthIssuerTokenStatus(this.coordinator,this.codec,LIMITS,this.clock,Duration.ZERO,3,255,tokens));
  assertThrows(NullPointerException.class,()->new OAuthIssuerTokenStatus(null,this.codec,LIMITS,this.clock,Duration.ZERO,3,255,16384));
 }
 @Test void diagnosticsNeverRetainTokenOrIdentity() {String jwt=issued();assertEquals("OAuthIssuerTokenStatus{<redacted>}",status().toString());revokeGrant();invalid(()->validate(jwt));}
 @Test void missingGrantBarrierReloadsWhenGrantAppears() {
  String jwt=issued();var row=entry(OAuthStoreKey.Kind.GRANT);remove(OAuthStoreKey.Kind.GRANT);int count=this.store.commits;
  this.store.beforeCommit=()->this.store.rows.put(row.getKey(),row);validate(jwt);assertEquals(count+2,this.store.commits);
 }
 @Test void physicalExpiredRowsAreInactiveEvenWhenSignatureClockIsEarlier() {
  String jwt=issued();this.clock.time=record(OAuthStoreKey.Kind.ACCESS_TOKEN).retention();
  invalid(()->status(3,Duration.ZERO,Clock.fixed(NOW,ZoneOffset.UTC)).validate(jwt,RESOURCE,keys(),deadline()));
 }
 @Test void authenticatedRetentionMismatchIsCorruption() {
  String jwt=issued();var e=entry(OAuthStoreKey.Kind.ACCESS_TOKEN);
  this.store.rows.put(e.getKey(),this.codec.seal(e.getKey(),e.getRetainUntil().plusSeconds(1),payload(OAuthStoreKey.Kind.ACCESS_TOKEN).toJson()));
  failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->validate(jwt));
 }
 @Test void statusCannotOutliveAuthenticatedRetainedValidity() {
  String jwt=issued();var e=entry(OAuthStoreKey.Kind.ACCESS_TOKEN);Instant shortened=record(OAuthStoreKey.Kind.ACCESS_TOKEN).expires();
  JsonObject p=changed(payload(OAuthStoreKey.Kind.ACCESS_TOKEN),"retain",JsonNumber.fromValue(shortened.getEpochSecond()));
  this.store.rows.put(e.getKey(),this.codec.seal(e.getKey(),shortened,p.toJson()));failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->validate(jwt));
 }
 @Test void accessBeyondFamilyPinnedLifetimeIsCorruption() {
  String jwt=issued();var g=record(OAuthStoreKey.Kind.GRANT);JsonObject p=changed(payload(OAuthStoreKey.Kind.GRANT),"expires",JsonNumber.fromValue(NOW.getEpochSecond()-1));
  replace(OAuthStoreKey.Kind.GRANT,p);failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->validate(jwt));assertEquals(Duration.ofMinutes(5),g.maximumAccessLifetime());
 }
 @Test void signaturesCannotUseEarlierClockToBypassLedgerNotBefore() {
  String jwt=issued();Clock ahead=Clock.fixed(NOW,ZoneOffset.UTC);this.clock.time=NOW.minusSeconds(31);
  var issuer=entry(OAuthStoreKey.Kind.ISSUER_STATE);var p=this.codec.open(issuer,Clock.fixed(NOW,ZoneOffset.UTC));
  p=changed(p,"highWaterSeconds",JsonNumber.fromValue(this.clock.time.getEpochSecond()));
  this.store.rows.put(issuer.getKey(),this.codec.seal(issuer.getKey(),issuer.getRetainUntil(),p.toJson()));
  invalid(()->status(3,Duration.ofSeconds(30),ahead).validate(jwt,RESOURCE,keys(),deadline()));
 }
 @Test void cooperativeBudgetIsNotRestartedOnConflict() {
  String jwt=issued();Deadline budget=Deadline.fromNow(Duration.ofMillis(100));this.store.conflicts=1;
  this.store.beforeCommit=()->{while(!budget.isExpired())Thread.onSpinWait();};
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->status().validate(jwt,RESOURCE,keys(),budget));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> signatureClockFaultIsInfrastructureAndFatalPropagates() {
  return Stream.of("runtime","fatal").map(name->test(name,()->{
   var f=new OAuthIssuerTokenStatusTests();String jwt=f.issued();TestFatal fatal=new TestFatal();Clock bad=new Clock(){
    @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
    @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
    @Override public @NonNull Instant instant(){if(name.equals("fatal"))throw fatal;throw new IllegalStateException(jwt);}
   };var status=f.status(3,Duration.ZERO,bad);int reads=f.store.reads;
   if(name.equals("fatal"))assertSame(fatal,assertThrows(TestFatal.class,()->status.validate(jwt,RESOURCE,keys(),deadline())));
   else failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->status.validate(jwt,RESOURCE,keys(),deadline()));assertEquals(reads,f.store.reads);
  }));
 }
 @Test void lateCryptographicRejectionIsTimeoutNotInactiveProof() {
  String jwt=issued();Deadline budget=Deadline.fromNow(Duration.ofMillis(100));Clock late=new Clock(){
   @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
   @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
   @Override public @NonNull Instant instant(){while(!budget.isExpired())Thread.onSpinWait();return NOW.plusSeconds(1000);}
  };
  int reads=this.store.reads;unavailable(()->status(3,Duration.ZERO,late).validate(jwt,RESOURCE,keys(),budget));assertEquals(reads,this.store.reads);
 }
 private static final class TestFatal extends VirtualMachineError {private static final long serialVersionUID=1L;TestFatal(){super("fixture");}}
 private static final class MutableClock extends Clock {
  @NonNull Instant time;MutableClock(@NonNull Instant time){this.time=time;}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){requireNonNull(zone);return this;}
  @Override public @NonNull Instant instant(){return this.time;}
 }
 @Test void managedKeyRolloverUsesCurrentKeysAndRetainsUncachedStatusBarrier() {
  OAuthIssuerSigningKey a=OAuthIssuerSigningKey.fromKeyPair("a",KEY.getPrivateKey(),KEY.getPublicKey());
  OAuthIssuerKeySnapshot first=OAuthIssuerKeySnapshot.withActiveKey(a).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
  var current=new java.util.concurrent.atomic.AtomicReference<OAuthIssuerKeySnapshot>(first);
  var keys=new OAuthIssuerKeyLifecycle(budget->requireNonNull(current.get()),this.clock,Duration.ofSeconds(60),this.retention);
  var managed=new OAuthCodeRedemption(this.coordinator,this.codec,LIMITS,this.retention,new OAuthTokenResponse.Encoder(ISSUER,keys,32768,16384),
   Duration.ofMinutes(5),true,Duration.ofDays(1),Duration.ofDays(7),3,255);
  String code=code(true);String compact=token(managed.redeem(request(code,Map.of()),(id,budget)->Optional.of(client()),resources(),allow(),deadline()));
  assertEquals(claims(compact),status().validate(compact,RESOURCE,keys,deadline()));int commits=this.store.commits;
  var b=TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_3072;
  current.set(OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("b",b.getPrivateKey(),b.getPublicKey())).generation("g2")
   .publishedAt(NOW.minusSeconds(60)).verificationKeys(Map.of("a",a.getPublicKey())).retirementNotBefore(Map.of("a",NOW.plusSeconds(500))).build());
  assertEquals(claims(compact),status().validate(compact,RESOURCE,keys,deadline()));assertEquals(commits+1,this.store.commits);
  revokeGrant();invalid(()->status().validate(compact,RESOURCE,keys,deadline()));
 }
 @Test void managedMismatchedPairLeavesUnusedCodeAndLedgerUnchanged() {
  var b=TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_3072;
  var snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("a",KEY.getPrivateKey(),b.getPublicKey()))
   .generation("g1").publishedAt(NOW.minusSeconds(120)).build();
  var keys=new OAuthIssuerKeyLifecycle(OAuthIssuerKeyProvider.fromSnapshot(snapshot),this.clock,Duration.ofSeconds(60),this.retention);
  var managed=new OAuthCodeRedemption(this.coordinator,this.codec,LIMITS,this.retention,new OAuthTokenResponse.Encoder(ISSUER,keys,32768,16384),
   Duration.ofMinutes(5),true,Duration.ofDays(1),Duration.ofDays(7),3,255);
  String code=code(true);var before=Map.copyOf(this.store.rows);int commits=this.store.commits;
  unavailable(()->managed.redeem(request(code,Map.of()),(id,budget)->Optional.of(client()),resources(),allow(),deadline()));
  assertEquals(before,this.store.rows);assertEquals(commits,this.store.commits);assertEquals("UNUSED",record(OAuthStoreKey.Kind.CODE).text("status"));
  assertNotNull(redeem(code));
 }
 @Test void managedRotationWithoutPublicOverlapCannotCommitPreparedIssuance() {
  var b=TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_3072;var first=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("a",KEY.getPrivateKey(),KEY.getPublicKey()))
   .generation("g1").publishedAt(NOW.minusSeconds(120)).build();
  var missing=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("b",b.getPrivateKey(),b.getPublicKey()))
   .generation("g2").publishedAt(NOW.minusSeconds(60)).build();var calls=new java.util.concurrent.atomic.AtomicInteger();
  var keys=new OAuthIssuerKeyLifecycle(budget->calls.incrementAndGet()==1 ? first : missing,this.clock,Duration.ofSeconds(60),this.retention);
  var managed=new OAuthCodeRedemption(this.coordinator,this.codec,LIMITS,this.retention,new OAuthTokenResponse.Encoder(ISSUER,keys,32768,16384),
   Duration.ofMinutes(5),true,Duration.ofDays(1),Duration.ofDays(7),3,255);
  String code=code(true);var before=Map.copyOf(this.store.rows);int commits=this.store.commits;
  unavailable(()->managed.redeem(request(code,Map.of()),(id,budget)->Optional.of(client()),resources(),allow(),deadline()));
  assertEquals(before,this.store.rows);assertEquals(commits,this.store.commits);assertEquals(2,calls.get());assertNotNull(redeem(code));
 }

}
