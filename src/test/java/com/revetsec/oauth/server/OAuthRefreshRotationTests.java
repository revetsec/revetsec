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
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.function.Executable;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
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

/** First-issuance and deterministic CAS interleavings; a memory fixture is not durable backend proof. */
final class OAuthRefreshRotationTests {
 private static final @NonNull Instant NOW = Instant.parse("2026-10-04T00:00:00.123456789Z");
 private static final @NonNull String ISSUER = "https://issuer.example/tenant", RESOURCE = "https://resource.example/mcp";
 private static final @NonNull String REDIRECT = "https://client.example/cb?x=%2f", BROWSER = "A".repeat(43), OTHER = "B".repeat(42) + "A";
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
 OAuthRefreshRotationTests() { }
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
  var e=assertThrows(OAuthServerAdmissionFailure.class,call);assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,e.reason());assertNull(e.getCause());assertEquals("OAuth server admission failed.",e.getMessage());
 }
 private static void unavailable(@NonNull Executable call) { var e=assertThrows(OAuthServerAdmissionFailure.class,call);assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,e.reason());assertNull(e.getCause()); }
 private static void failed(OAuthStoreFailure.@NonNull Reason reason,@NonNull Executable call) { var e=assertThrows(OAuthStoreFailure.class,call);assertEquals(reason,e.reason());assertNull(e.getCause()); }
 private @NonNull OAuthRefreshRotation rotation(boolean enabled, @NonNull Duration lifetime,
   @NonNull OAuthGrantRetention retention, @NonNull JwsSigner signer, int attempts) {
  return new OAuthRefreshRotation(this.coordinator,this.codec,LIMITS,retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer,32768,16384),lifetime,enabled,Duration.ofDays(1),attempts,255);
 }
 private @NonNull OAuthRefreshRotation rotation() { return rotation(true,Duration.ofMinutes(5),this.retention,signer(),3); }
 private static @NonNull OAuthServerRequest refreshRequest(@NonNull String token,@NonNull Map<@NonNull String,@NonNull String> overrides) {
  Map<String,String> fields=new LinkedHashMap<>(Map.of("grant_type","refresh_token","refresh_token",token,"resource",RESOURCE,"client_id","client"));fields.putAll(overrides);
  String body=String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());
  return OAuthServerRequest.parse(OAuthServerRequest.Endpoint.TOKEN,"POST",null,body.getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded")),LIMITS);
 }
 private @NonNull OAuthTokenResponse rotate(@NonNull String token) { return rotate(token,Map.of(),allow()); }
 private @NonNull OAuthTokenResponse rotate(@NonNull String token,@NonNull Map<@NonNull String,@NonNull String> fields,@NonNull OAuthGrantPolicy policy) {
  return rotation().rotate(refreshRequest(token,fields),(id,b)->Optional.of(client()),resources(),policy,deadline());
 }
 private static @NonNull String refresh(@NonNull OAuthTokenResponse response) { return body(response).findString("refresh_token").orElseThrow(); }
 private @NonNull OAuthTokenResponse issued() { return redeem(code(true)); }
 private @NonNull OAuthStoreKey refreshKey(@NonNull String credential) { return this.codec.key(OAuthStoreKey.Kind.REFRESH_TOKEN,OAuthServerCredential.refreshDigest(credential)); }
 private @NonNull OAuthAuthorizationRecord refreshRecord(@NonNull String credential) {
  var key=refreshKey(credential);var entry=requireNonNull(this.store.rows.get(key));String id=OAuthServerCredential.refreshDigest(credential);
  return OAuthAuthorizationRecord.decode(key.getKind(),id,this.codec.open(entry,Clock.fixed(this.clock.time,ZoneOffset.UTC)),LIMITS,255);
 }
 private @NonNull JsonObject validate(@NonNull String jwt) {
  var keys=StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(TestJsonWebKeys.withFixture(KEY).kid("key").alg("RS256").toKeySetJson()));
  return new OAuthIssuerTokenStatus(this.coordinator,this.codec,LIMITS,this.clock,Duration.ofSeconds(30),3,255,16384).validate(jwt,RESOURCE,keys,deadline());
 }
 private static void inactive(@NonNull Executable action) { var e=assertThrows(OAuthServerAdmissionFailure.class,action);assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_TOKEN,e.reason()); }
 @Test void rotationAtomicallyConsumesCreatesAndPinsOriginalGrant() {
  var initial=issued();String old=refresh(initial);var before=record(OAuthStoreKey.Kind.GRANT);Instant oldExpiry=refreshRecord(old).expires();
  this.clock.time=NOW.plusSeconds(60);var response=rotate(old);var transaction=requireNonNull(this.store.lastTransaction);
  assertEquals(5,transaction.getMutations().size());assertEquals(6,transaction.getConditions().size());
  assertEquals(2,transaction.getConditions().stream().filter(c->c.getExpectedVersion().isEmpty()).count());
  assertTrue(transaction.getConditions().stream().anyMatch(c->c.getKey().getKind()==OAuthStoreKey.Kind.SUBJECT_STATE));
  var after=record(OAuthStoreKey.Kind.GRANT);assertEquals(before.horizon(),after.horizon());assertEquals(before.expires(),after.expires());assertEquals(before.maximumAccessLifetime(),after.maximumAccessLifetime());assertEquals(before.scopes(LIMITS),after.scopes(LIMITS));
  assertEquals("USED",refreshRecord(old).text("status"));assertEquals(oldExpiry,refreshRecord(old).expires());assertEquals(before.horizon(),refreshRecord(old).retention());
  assertNotEquals(old,refresh(response));assertEquals(OAuthServerCredential.refreshDigest(refresh(response)),after.text("refreshId"));assertEquals("ACTIVE",refreshRecord(refresh(response)).text("status"));
  assertEquals("read write",validate(token(response)).findString("scope").orElseThrow());assertNotNull(validate(token(initial)));
  assertTrue(new String(response.headers(),StandardCharsets.US_ASCII).contains("Cache-Control: no-store"));
 }
 @Test void narrowedAccessDoesNotNarrowRefreshAndFutureAccessCanRegainOriginalScopes() {
  var initial=issued();var narrow=rotate(refresh(initial),Map.of("scope","read"),allow());assertEquals("read",validate(token(narrow)).findString("scope").orElseThrow());
  assertEquals(Set.of("read","write"),record(OAuthStoreKey.Kind.GRANT).scopes(LIMITS));
  var wide=rotate(refresh(narrow));assertEquals("read write",validate(token(wide)).findString("scope").orElseThrow());
  assertEquals("read",body(narrow).findString("scope").orElseThrow());assertNotNull(validate(token(initial)));
 }
 @Test void usedRefreshRevokesEveryAccessAndRefreshDescendantWithoutReemission() {
  var a=issued();var b=rotate(refresh(a));var c=rotate(refresh(b));invalid(()->rotate(refresh(a)));
  assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));for(var r:List.of(a,b,c))inactive(()->validate(token(r)));invalid(()->rotate(refresh(c)));
  int rows=this.store.rows.size();invalid(()->rotate(refresh(a)));assertEquals(rows,this.store.rows.size());assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());
 }
 @Test void racingLoserReloadsUsedRefreshAndRevokesWinner() {
  var initial=issued();OAuthTokenResponse[] winner=new OAuthTokenResponse[1];this.store.beforeCommit=()->winner[0]=rotate(refresh(initial));
  invalid(()->rotate(refresh(initial)));var won=requireNonNull(winner[0]);assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));inactive(()->validate(token(won)));invalid(()->rotate(refresh(won)));
  assertEquals(2,this.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).count());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> wrongBindingCannotConsumeOrInvalidateActiveOrUsedCredential() {
  return Stream.of("client","version","resource","random","secret","auth").flatMap(mode->Stream.of(false,true).map(used->DynamicTest.dynamicTest(mode+" used="+used,()->{
   var t=new OAuthRefreshRotationTests();var initial=t.issued();String credential=refresh(initial);if(used)t.rotate(credential);
   var client=client(mode.equals("client")?"other":"client",mode.equals("version")?"v2":"v1",mode.equals("auth")||mode.equals("secret"));
   var fields=mode.equals("resource")?Map.of("resource","https://wrong.example/mcp"):mode.equals("client")?Map.of("client_id","other"):Map.<String,String>of();
   var request=refreshRequest(mode.equals("random")?OTHER:credential,fields);Map<OAuthStoreKey,OAuthStoreEntry> before=Map.copyOf(t.store.rows);
   assertThrows(OAuthServerAdmissionFailure.class,()->t.rotation().rotate(request,(id,b)->Optional.of(client),resources(),allow(),deadline()));assertEquals(before,t.store.rows);assertEquals("ACTIVE",t.record(OAuthStoreKey.Kind.GRANT).text("status"));
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidRequestedScopesNeverConsumeOrRevoke() {
  return Stream.of("admin","","read "," read","read  write","x".repeat(129),"é").flatMap(scope->Stream.of(false,true).map(used->DynamicTest.dynamicTest(scope+" used="+used,()->{
   var t=new OAuthRefreshRotationTests();String credential=refresh(t.issued());if(used)t.rotate(credential);var before=Map.copyOf(t.store.rows);
   var e=assertThrows(OAuthServerAdmissionFailure.class,()->t.rotate(credential,Map.of("scope",scope),allow()));assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_SCOPE,e.reason());assertEquals(before,t.store.rows);
  })));
 }
 @Test void usedReplayRecognizedAfterIdleExpiryAndAfterAbsoluteExpiryUntilH() {
  var initial=issued();String old=refresh(initial);Instant idle=refreshRecord(old).expires();var next=rotate(old);this.clock.time=idle;
  invalid(()->rotate(old));assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));
  this.clock.time=record(OAuthStoreKey.Kind.GRANT).expires().plusSeconds(1);invalid(()->rotate(old));assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());
  this.clock.time=record(OAuthStoreKey.Kind.GRANT).horizon();int commits=this.store.commits;invalid(()->rotate(old));assertEquals(commits,this.store.commits);assertNotEquals(old,refresh(next));
 }
 @Test void expiredUnusedRefreshNeverIssuesEvenWhenRetained() {
  String credential=refresh(issued());this.clock.time=refreshRecord(credential).expires();int commits=this.store.commits;invalid(()->rotate(credential));assertEquals(commits,this.store.commits);assertEquals("ACTIVE",refreshRecord(credential).text("status"));
 }
 @Test void lastAccessDescendantSurvivesAbsoluteFamilyExpiryAndReuseThenRevokesIt() {
  String current=refresh(issued()),first=current;Instant absolute=record(OAuthStoreKey.Kind.GRANT).expires();
  while(this.clock.time.plusSeconds(43200).isBefore(absolute)){this.clock.time=this.clock.time.plusSeconds(43200);current=refresh(rotate(current));}
  this.clock.time=absolute.minusSeconds(1);var last=rotate(current);assertEquals(absolute,refreshRecord(refresh(last)).expires());
  this.clock.time=absolute.plusSeconds(1);assertNotNull(validate(token(last)));invalid(()->rotate(first));inactive(()->validate(token(last)));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> continuingAuthorityReductionTerminatesOriginalRefreshContract() {
  return Stream.of("deny","empty","narrow","noRefresh","serverScopes","serverMissing","disabled","largerPin","largerMargins").map(mode->DynamicTest.dynamicTest(mode,()->{
   var t=new OAuthRefreshRotationTests();var initial=t.issued();String old=refresh(initial);var policy=(OAuthGrantPolicy)(c,b)->mode.equals("deny")?OAuthAuthorizationDecision.deniedInstance():decision("subject",mode.equals("empty")?Set.of():mode.equals("narrow")?Set.of("read"):Set.of("read","write"),!mode.equals("noRefresh"));
   var resources=mode.equals("serverMissing")?Map.of("https://other.example/mcp",Set.of("read")):mode.equals("serverScopes")?Map.of(RESOURCE,Set.of("read")):resources();
   var retention=mode.equals("largerPin")?new OAuthGrantRetention(Duration.ofMinutes(6),Duration.ofSeconds(30),Duration.ofSeconds(10),Duration.ofSeconds(60)):mode.equals("largerMargins")?new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ofSeconds(30),Duration.ofSeconds(10),Duration.ofMinutes(5)):t.retention;
   var engine=t.rotation(!mode.equals("disabled"),mode.equals("largerPin")?Duration.ofMinutes(6):Duration.ofMinutes(5),retention,signer(),3);
   invalid(()->engine.rotate(refreshRequest(old,Map.of("scope","read")),(id,b)->Optional.of(client()),resources,policy,deadline()));assertEquals("REVOKED",t.record(OAuthStoreKey.Kind.GRANT).text("status"));inactive(()->t.validate(token(initial)));assertEquals(1,t.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).count());
  }));
 }
 @TestFactory @SuppressWarnings("NullAway") @NonNull Stream<@NonNull DynamicTest> nullFaultIdentityAndWideningPolicyHaveNoMutations() {
  return Stream.of("null","fault","subject","widen","resource","twoResources","interrupt","fatal").map(mode->DynamicTest.dynamicTest(mode,()->{
   var t=new OAuthRefreshRotationTests();String old=refresh(t.issued());var before=Map.copyOf(t.store.rows);TestFatal fatal=new TestFatal();
   OAuthGrantPolicy policy=(c,b)->{assertEquals("refresh_token",c.getGrantType());assertEquals(Set.of("read","write"),c.getAuthorizedScopesByResource().get(RESOURCE));assertFalse(b.isZero());assertFalse(b.isNegative());
    if(mode.equals("null"))return null;if(mode.equals("fault"))throw new IllegalStateException("sensitive");if(mode.equals("interrupt"))sneaky(new InterruptedException("sensitive"));if(mode.equals("fatal"))throw fatal;
    if(mode.equals("resource"))return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of("https://other.example",Set.of("read"))).refreshTokenPermitted(true).build();
    if(mode.equals("twoResources"))return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(RESOURCE,Set.of("read"),"https://other.example",Set.of("read"))).refreshTokenPermitted(true).build();
    return decision(mode.equals("subject")?"other":"subject",mode.equals("widen")?Set.of("read","write","admin"):Set.of("read","write"),true);};
   try{if(mode.equals("fatal"))assertSame(fatal,assertThrows(TestFatal.class,()->t.rotate(old,Map.of(),policy)));else unavailable(()->t.rotate(old,Map.of(),policy));assertEquals(mode.equals("interrupt"),Thread.currentThread().isInterrupted());assertEquals(before,t.store.rows);}finally{Thread.interrupted();}
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unknownOutcomeNeverReleasesOrRetriesPreparedCredentials() {
  return Stream.of(false,true).map(applied->DynamicTest.dynamicTest("applied="+applied,()->{
   var t=new OAuthRefreshRotationTests();String old=refresh(t.issued());int commits=t.store.commits;t.store.unknownAfter=applied;t.store.unknownBefore=!applied;
   failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->t.rotate(old));assertEquals(commits+1,t.store.commits);t.store.unknownBefore=false;t.store.unknownAfter=false;
   assertEquals(applied?"USED":"ACTIVE",t.refreshRecord(old).text("status"));if(applied){invalid(()->t.rotate(old));assertEquals("REVOKED",t.record(OAuthStoreKey.Kind.GRANT).text("status"));}else assertNotNull(t.rotate(old));
  }));
 }
 @Test void conflictsReloadFreshAuthenticationAndPolicyUnderOneBudget() {
  String old=refresh(issued());this.store.conflicts=1;int[] calls={0,0};Deadline d=deadline();
  var response=rotation().rotate(refreshRequest(old,Map.of()),(id,b)->{calls[0]++;assertTrue(!b.isZero());return Optional.of(client());},resources(),(c,b)->{calls[1]++;return decision("subject",Set.of("read","write"),true);},d);
  assertArrayEquals(new int[]{2,2},calls);assertNotNull(validate(token(response)));
 }
 @Test void exhaustedConflictsKeepActiveRefreshAndDiscardAllPreparedOutputs() {
  String old=refresh(issued());var before=Map.copyOf(this.store.rows);this.store.conflicts=3;failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->rotate(old));assertEquals(before,this.store.rows);
 }
 @Test void signatureFailureLeavesRefreshUsableAndRestoresNoGuessedState() {
  String old=refresh(issued());var before=Map.copyOf(this.store.rows);var broken=JwsSigner.fromRsaKeyPair(new RefusingPrivateKey(),KEY.getPublicKey(),JwsAlgorithm.RS256);
  unavailable(()->rotation(true,Duration.ofMinutes(5),this.retention,broken,3).rotate(refreshRequest(old,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline()));assertEquals(before,this.store.rows);assertNotNull(rotate(old));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> epochAndIncarnationChangesPreventIssuanceAndDestructiveReuse() {
  return Stream.of("issuerEpoch","subjectEpoch","issuerIncarnation","subjectIncarnation").flatMap(mode->Stream.of(false,true).map(used->DynamicTest.dynamicTest(mode+" used="+used,()->{
   var t=new OAuthRefreshRotationTests();String old=refresh(t.issued());if(used)t.rotate(old);
   if(mode.equals("issuerEpoch"))t.coordinator.revokeAll(deadline());else if(mode.equals("subjectEpoch"))t.coordinator.revokeSubject("subject",deadline());else{var key=mode.equals("issuerIncarnation")?t.codec.issuerKey():t.codec.subjectKey("subject");var fence=mode.equals("issuerIncarnation")?OAuthStoreFence.initialIssuer(OTHER,NOW):OAuthStoreFence.initialSubject(OTHER);t.store.rows.put(key,t.codec.seal(key,OAuthStoreFormat.PERMANENT,fence.toPayload()));}
   int commits=t.store.commits;invalid(()->t.rotate(old));assertEquals(commits,t.store.commits);
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> missingPermanentOrGrantRowsAreInfrastructureFailure() {
  return Stream.of(OAuthStoreKey.Kind.ISSUER_STATE,OAuthStoreKey.Kind.SUBJECT_STATE,OAuthStoreKey.Kind.GRANT).map(kind->DynamicTest.dynamicTest(kind.name(),()->{
   var t=new OAuthRefreshRotationTests();String old=refresh(t.issued());t.store.rows.remove(t.entry(kind).getKey());failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->t.rotate(old));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> corruptAuthenticatedRefreshAndGrantLinksFailWithoutMutation() {
  return Stream.of("issuerEpoch","subjectIncarnation","grantId","head","horizon","status","refreshDisabled","retention").map(mode->DynamicTest.dynamicTest(mode,()->{
   var t=new OAuthRefreshRotationTests();String old=refresh(t.issued());var key=t.refreshKey(old);var entry=requireNonNull(t.store.rows.get(key));JsonObject p=t.codec.open(entry,Clock.fixed(NOW,ZoneOffset.UTC));
   if(mode.equals("head"))t.replace(OAuthStoreKey.Kind.GRANT,changed(t.payload(OAuthStoreKey.Kind.GRANT),"refreshId",JsonString.fromValue(OTHER)));
   else if(mode.equals("refreshDisabled")){var g=changed(t.payload(OAuthStoreKey.Kind.GRANT),"refresh",JsonBoolean.fromValue(false));t.replace(OAuthStoreKey.Kind.GRANT,changed(g,"refreshId",JsonNull.defaultInstance()));}
   else if(mode.equals("retention"))t.store.rows.put(key,t.codec.seal(key,entry.getRetainUntil().plusSeconds(1),p.toJson()));
   else {JsonValue value=mode.equals("issuerEpoch")?JsonNumber.fromValue(1L):mode.equals("horizon")?JsonNumber.fromValue(entry.getRetainUntil().plusSeconds(1).getEpochSecond()):JsonString.fromValue(mode.equals("status")?"USED":OTHER);t.store.rows.put(key,t.codec.seal(key,entry.getRetainUntil(),changed(p,mode,value).toJson()));}
   var before=Map.copyOf(t.store.rows);failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->t.rotate(old));assertEquals(before,t.store.rows);
  }));
 }
 @Test void policyCannotCompletePastIdleExpiryOrOriginalDeadline() {
  String old=refresh(issued());Instant expiry=refreshRecord(old).expires();int commits=this.store.commits;
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->rotate(old,Map.of(),(c,b)->{this.clock.time=expiry;return decision("subject",Set.of("read","write"),true);}));assertEquals(commits,this.store.commits);
  this.clock.time=NOW;Deadline d=Deadline.fromNow(Duration.ofMillis(30));unavailable(()->rotation().rotate(refreshRequest(old,Map.of()),(id,b)->Optional.of(client()),resources(),(c,b)->{while(!d.isExpired())Thread.onSpinWait();return decision("subject",Set.of("read","write"),true);},d));assertEquals(commits,this.store.commits);
 }
 @Test void lateCommitDoesNotReturnCredentialsAndLaterReplayRevokesAppliedWinner() {
  String old=refresh(issued());Instant expiry=refreshRecord(old).expires();this.store.afterCommit=()->this.clock.time=expiry;
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->rotate(old));assertEquals("USED",refreshRecord(old).text("status"));invalid(()->rotate(old));assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));
 }
 @Test void issuerRevocationDuringCommitConflictsAndCannotIssue() {
  String old=refresh(issued());this.store.beforeCommit=()->this.coordinator.revokeAll(deadline());invalid(()->rotate(old));assertEquals("ACTIVE",refreshRecord(old).text("status"));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> occupiedNewIdentifiersCannotOverwriteExistingRows() {
  return Stream.of(OAuthStoreKey.Kind.REFRESH_TOKEN,OAuthStoreKey.Kind.ACCESS_TOKEN).map(kind->DynamicTest.dynamicTest(kind.name(),()->{
   var t=new OAuthRefreshRotationTests();String old=refresh(t.issued());int commits=t.store.commits;
   var wrapper=new OAuthAuthorizationServerStore(){
    @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,@NonNull Duration budget){if(key.getKind()==kind&&!t.store.rows.containsKey(key))t.store.rows.put(key,t.codec.seal(key,NOW.truncatedTo(java.time.temporal.ChronoUnit.SECONDS).plusSeconds(1000),"{}"));return t.store.read(key,budget);}
    @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){return t.store.commit(tx,budget);}
   };
   var coord=new OAuthStoreCoordinator(wrapper,t.codec,t.clock,3,255);var engine=new OAuthRefreshRotation(coord,t.codec,LIMITS,t.retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,1024),Duration.ofMinutes(5),true,Duration.ofDays(1),3,255);
   failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->engine.rotate(refreshRequest(old,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline()));assertEquals(commits,t.store.commits);assertEquals("ACTIVE",t.refreshRecord(old).text("status"));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> usedRefreshSchemaRejectsEveryMissingNullAndExtraMember() {
  var t=new OAuthRefreshRotationTests();String old=refresh(t.issued());t.rotate(old);var key=t.refreshKey(old);var p=t.codec.open(requireNonNull(t.store.rows.get(key)),Clock.fixed(NOW,ZoneOffset.UTC));String id=OAuthServerCredential.refreshDigest(old);
  return Stream.concat(p.getMembers().keySet().stream().flatMap(name->Stream.of(false,true).map(isNull->DynamicTest.dynamicTest(name+" null="+isNull,()->assertThrows(RuntimeException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.REFRESH_TOKEN,id,changed(p,name,isNull?JsonNull.defaultInstance():null),LIMITS,255))))),Stream.of(DynamicTest.dynamicTest("extra",()->assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.REFRESH_TOKEN,id,changed(p,"extra",JsonBoolean.fromValue(true)),LIMITS,255)))));
 }
 @Test void recordTransitionsRejectWrongKindsReconsumptionWideningAndSameHead() {
  String old=refresh(issued());var g=record(OAuthStoreKey.Kind.GRANT);var r=refreshRecord(old);var a=record(OAuthStoreKey.Kind.ACCESS_TOKEN);
  assertThrows(IllegalArgumentException.class,()->a.refreshUsed(LIMITS,255));assertThrows(IllegalArgumentException.class,()->g.rotated(g.text("refreshId"),LIMITS,255));assertThrows(IllegalArgumentException.class,()->r.rotated(OTHER,LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->g.terminated(LIMITS,255).rotated(OTHER,LIMITS,255));assertThrows(IllegalArgumentException.class,()->r.refreshUsed(LIMITS,255).refreshUsed(LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.access(OTHER,g,NOW,NOW.truncatedTo(java.time.temporal.ChronoUnit.SECONDS).plusSeconds(300),g.horizon(),Set.of("admin"),LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.access(OTHER,g,NOW,NOW.truncatedTo(java.time.temporal.ChronoUnit.SECONDS).plusSeconds(300),g.horizon(),Set.of(),LIMITS,255));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> settingsRejectInvalidRangesWithoutCallbacks() {
  return Stream.of("zeroAttempts","nineAttempts","subjectLow","subjectHigh","idleLow","idleHigh","accessLow","accessHigh","crossField","issuer").map(mode->DynamicTest.dynamicTest(mode,()->{
   var t=new OAuthRefreshRotationTests();var retention=new OAuthGrantRetention(Duration.ofMinutes(15),Duration.ofSeconds(30),Duration.ofSeconds(10),Duration.ofSeconds(60));
   assertThrows(IllegalArgumentException.class,()->new OAuthRefreshRotation(t.coordinator,t.codec,LIMITS,retention,new OAuthTokenResponse.Encoder(mode.equals("issuer")?"https://other.example":ISSUER,"key",signer(),4096,1024),Duration.ofSeconds(mode.equals("accessLow")?29:mode.equals("accessHigh")?901:mode.equals("crossField")?900:300),true,Duration.ofSeconds(mode.equals("idleLow")?299:mode.equals("idleHigh")?604801:mode.equals("crossField")?300:86400),mode.equals("zeroAttempts")?0:mode.equals("nineAttempts")?9:3,mode.equals("subjectLow")?15:mode.equals("subjectHigh")?1025:255));
  }));
 }
 @Test void noncanonicalRefreshNeverReadsStoreAndWrongGrantHasNoAuthority() {
  String old=refresh(issued());int reads=this.store.reads;invalid(()->rotate("x"));assertEquals(reads,this.store.reads);
  assertThrows(OAuthServerAdmissionFailure.class,()->rotation().rotate(request(old,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline()));assertEquals(reads,this.store.reads);
 }
 @Test void redactedDiagnosticsContainNoIdentityOrCredential() {
  var r=issued();for(String s:List.of(rotation().toString(),r.toString(),refreshRecord(refresh(r)).toString())){assertTrue(s.contains("<redacted>"));assertFalse(s.contains(refresh(r)));assertFalse(s.contains("subject"));}
 }
 @Test void confidentialClientFreshBasicAuthenticationPrecedesEachRotationAndReuse() {
  int[] checks={0};byte @Nullable [][] captured=new byte[1][];
  var registered=OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources()).refreshTokenPermitted(true)
   .authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,b)->{checks[0]++;captured[0]=secret;return java.util.Arrays.equals(secret,"secret".getBytes(StandardCharsets.US_ASCII));})).build();
  String code=code(true,registered);
  var first=this.first.redeem(basic(request(code,Map.of()),"secret"),(id,b)->Optional.of(registered),resources(),allow(),deadline());String old=refresh(first);
  var next=rotation().rotate(basic(refreshRequest(old,Map.of()),"secret"),(id,b)->Optional.of(registered),resources(),allow(),deadline());
  int count=this.store.commits;var bad=assertThrows(OAuthServerAdmissionFailure.class,()->rotation().rotate(basic(refreshRequest(old,Map.of()),"bad"),(id,b)->Optional.of(registered),resources(),allow(),deadline()));assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,bad.reason());assertEquals(count,this.store.commits);assertEquals("ACTIVE",record(OAuthStoreKey.Kind.GRANT).text("status"));
  invalid(()->rotation().rotate(basic(refreshRequest(old,Map.of()),"secret"),(id,b)->Optional.of(registered),resources(),allow(),deadline()));assertEquals(4,checks[0]);for(byte b:requireNonNull(captured[0]))assertEquals(0,b);inactive(()->validate(token(next)));
 }
 private static @NonNull OAuthServerRequest basic(@NonNull OAuthServerRequest request,@NonNull String secret) {
  // Build explicit form from checked request values; do not serialize decoded Basic secrets into stored state.
  var fields=new LinkedHashMap<String,String>();for(String name:List.of("grant_type","code","code_verifier","refresh_token","resource")){String value=request.value(name);if(value!=null)fields.put(name,value);}
  String body=String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());String authorization="Basic "+Base64.getEncoder().encodeToString(("client:"+secret).getBytes(StandardCharsets.US_ASCII));
  return OAuthServerRequest.parse(OAuthServerRequest.Endpoint.TOKEN,"POST",null,body.getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded"),"Authorization",List.of(authorization)),LIMITS);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> storeFaultsFailClosedWithoutCredentialRelease() {
  return Stream.of("nullRead","nullCommit","fault","interrupt","fatal").map(mode->DynamicTest.dynamicTest(mode,()->{
   var t=new OAuthRefreshRotationTests();String old=refresh(t.issued());var before=Map.copyOf(t.store.rows);var fatal=new TestFatal();
   t.store.nullRead=mode.equals("nullRead");t.store.nullCommit=mode.equals("nullCommit");t.store.fault=mode.equals("fault")?new IllegalStateException("secret"):mode.equals("interrupt")?new InterruptedException("secret"):mode.equals("fatal")?fatal:null;
   try{if(mode.equals("fatal"))assertSame(fatal,assertThrows(TestFatal.class,()->t.rotate(old)));else assertThrows(OAuthStoreFailure.class,()->t.rotate(old));assertEquals(mode.equals("interrupt"),Thread.currentThread().isInterrupted());assertEquals(before,t.store.rows);}finally{Thread.interrupted();}
  }));
 }
 @Test void terminationConflictReloadsAndRechecksCurrentPolicy() {
  String old=refresh(issued());this.store.conflicts=1;int[] calls={0};invalid(()->rotate(old,Map.of(),(c,b)->{calls[0]++;return OAuthAuthorizationDecision.deniedInstance();}));assertEquals(2,calls[0]);assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));
 }
 @Test void replayRevocationConflictReloadsAndStillRequiresCommittedBarrier() {
  String old=refresh(issued());rotate(old);this.store.conflicts=1;invalid(()->rotate(old));assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));this.store.conflicts=1;invalid(()->rotate(old));assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());
 }
 @Test void revokedActiveRefreshRequiresBarrierAndNeverContinuingPolicy() {
  String old=refresh(issued());var g=record(OAuthStoreKey.Kind.GRANT);replace(OAuthStoreKey.Kind.GRANT,json(g.terminated(LIMITS,255).toPayload().getBytes(StandardCharsets.UTF_8)));invalid(()->rotate(old,Map.of(),(c,b)->{throw new AssertionError("must not be invoked");}));assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());
 }
 @Test void largerConfiguredMaximumCannotEnlargePersistedPinButShorterAccessCanIssue() {
  String old=refresh(issued());var before=record(OAuthStoreKey.Kind.GRANT);var config=new OAuthGrantRetention(Duration.ofMinutes(15),Duration.ofSeconds(30),Duration.ofSeconds(10),Duration.ofSeconds(60));
  var response=rotation(true,Duration.ofSeconds(30),config,signer(),3).rotate(refreshRequest(old,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline());
  var after=record(OAuthStoreKey.Kind.GRANT);assertEquals(before.maximumAccessLifetime(),after.maximumAccessLifetime());assertEquals(before.horizon(),after.horizon());assertEquals(29L,body(response).findLong("expires_in").orElseThrow());assertNotNull(validate(token(response)));
 }
 @Test void usedReplayRevokesEvenAfterCurrentServerDisablesRefreshAndScopes() {
  String old=refresh(issued());rotate(old);var engine=rotation(false,Duration.ofMinutes(5),this.retention,signer(),3);
  invalid(()->engine.rotate(refreshRequest(old,Map.of()),(id,b)->Optional.of(client()),Map.of("https://other.example/mcp",Set.of("other")),(c,b)->{throw new AssertionError("no replay policy callback");},deadline()));assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));
 }
 @Test void boundedResponseFailureHappensBeforeAnyRotationMutation() {
  byte[] key=new byte[32];for(int n=0;n<32;n++)key[n]=(byte)(n+1);
  var codec=new OAuthStoreRecordCodec(ISSUER,StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key))).maximumSealedLength(16384).clock(Clock.fixed(NOW,ZoneOffset.UTC)).build(),16384);
  var coord=new OAuthStoreCoordinator(this.store,codec,this.clock,3,1024);coord.initializeFreshIssuer(deadline());String subject="s".repeat(1024);coord.establishNewSubject(subject,deadline());
  Set<String> scopes=Set.of("a".repeat(128),"b".repeat(128),"c".repeat(128),"d".repeat(128),"e".repeat(128),"f".repeat(128),"g".repeat(128),"h".repeat(128));
  String clientId="c".repeat(2048);var resources=Map.of(RESOURCE,scopes);var client=OAuthServerClientRegistration.withClientId(clientId).configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources).refreshTokenPermitted(true).build();
  var policy=(OAuthGrantPolicy)(c,b)->OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(resources).refreshTokenPermitted(true).build();
  String query="client_id="+clientId+"&response_type=code&redirect_uri="+encode(REDIRECT)+"&resource="+encode(RESOURCE)+"&code_challenge_method=S256&code_challenge="+CHALLENGE;
  var admission=OAuthServerAuthorizationAdmission.admit(OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",query,new byte[0],Map.of(),LIMITS),(id,b)->Optional.of(client),deadline(),resources,LIMITS,false,false);
  var ledger=new OAuthAuthorizationLedger(coord,codec,LIMITS,Duration.ofMinutes(15),Duration.ofMinutes(2),3,1024,true);String handle=ledger.begin(admission,BROWSER,deadline());
  String code=ledger.complete(handle,BROWSER,client,resources,OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(resources).refreshTokenPermitted(true).build(),deadline()).orElseThrow();
  var first=new OAuthCodeRedemption(coord,codec,LIMITS,this.retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),32768,1024),Duration.ofMinutes(5),true,Duration.ofDays(1),Duration.ofDays(7),3,1024);
  String old=refresh(first.redeem(request(code,Map.of("client_id",clientId)),(id,b)->Optional.of(client),resources,policy,deadline()));var before=Map.copyOf(this.store.rows);
  var engine=new OAuthRefreshRotation(coord,codec,LIMITS,this.retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,1024),Duration.ofMinutes(5),true,Duration.ofDays(1),3,1024);
  unavailable(()->engine.rotate(refreshRequest(old,Map.of("client_id",clientId)),(id,b)->Optional.of(client),resources,policy,deadline()));assertEquals(before,this.store.rows);
 }
 @SuppressWarnings("unchecked") private static <T extends Throwable> void sneaky(@NonNull Throwable failure) throws T { throw (T)failure; }
 private static final class RefusingPrivateKey implements PrivateKey {
  private static final long serialVersionUID=1L;RefusingPrivateKey() { }
  @Override public @NonNull String getAlgorithm(){return "RSA";}
  @Override public @Nullable String getFormat(){return null;}
  @Override public byte @Nullable [] getEncoded(){return null;}
 }
 private static final class TestFatal extends VirtualMachineError {private static final long serialVersionUID=1L;TestFatal(){super("fixture");}}
 @Test void codeOrLegacyHandleCannotRotateBeforeStoreReads() {
  String refresh=refresh(issued());int reads=this.store.reads;
  for(String bad:List.of(OAuthServerCredential.code(BROWSER),refresh.substring(5),refresh+"=")) {
   assertThrows(OAuthServerAdmissionFailure.class,()->rotate(bad));assertEquals(reads,this.store.reads);
  }
  assertNotNull(rotate(refresh));
 }
 private static final class MutableClock extends Clock {
  @NonNull Instant time;MutableClock(@NonNull Instant time){this.time=time;}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){requireNonNull(zone);return this;}
  @Override public @NonNull Instant instant(){return this.time;}
 }
}
