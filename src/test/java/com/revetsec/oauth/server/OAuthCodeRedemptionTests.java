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
import java.security.Signature;
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
import java.util.function.Consumer;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** First-issuance and deterministic CAS interleavings; a memory fixture is not durable backend proof. */
final class OAuthCodeRedemptionTests {
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
 private final @NonNull OAuthCodeRedemption second = engine(true, signer(), 3);
 OAuthCodeRedemptionTests() { }
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
 private static @NonNull JsonObject part(@NonNull String token,int part) { return json(Base64.getUrlDecoder().decode(token.split("\\.",-1)[part])); }
 private static void invalid(@NonNull Executable call) {
  var e=assertThrows(OAuthServerAdmissionFailure.class,call);assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,e.reason());assertNull(e.getCause());assertEquals("OAuth server admission failed.",e.getMessage());
 }
 private static void unavailable(@NonNull Executable call) { var e=assertThrows(OAuthServerAdmissionFailure.class,call);assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,e.reason());assertNull(e.getCause()); }
 private static void failed(OAuthStoreFailure.@NonNull Reason reason,@NonNull Executable call) { var e=assertThrows(OAuthStoreFailure.class,call);assertEquals(reason,e.reason());assertNull(e.getCause()); }
 @Test void rfc7636S256VectorAndUnreservedVerifierBounds() {
  assertEquals(CHALLENGE,OAuthAuthorizationRecord.verifierDigest(VERIFIER));assertEquals(43,OAuthAuthorizationRecord.verifierDigest("~._-".repeat(32)).length());
  for(String v:List.of("x".repeat(42),"x".repeat(129),"x".repeat(42)+"!","x".repeat(42)+"é"))assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.verifierDigest(v));
 }
 @Test void signedJwtHasEngineOwnedClaimsAndRawJcaSignature() throws Exception {
  String code=code(true);OAuthTokenResponse response=redeem(code);String jwt=token(response);
  assertEquals(Set.of("alg","typ","kid"),part(jwt,0).getMembers().keySet());assertEquals("RS256",part(jwt,0).findString("alg").orElseThrow());assertEquals("at+jwt",part(jwt,0).findString("typ").orElseThrow());
  JsonObject claims=part(jwt,1);assertEquals(Set.of("iss","sub","aud","client_id","iat","exp","jti","scope"),claims.getMembers().keySet());
  assertEquals(ISSUER,claims.findString("iss").orElseThrow());assertEquals("subject",claims.findString("sub").orElseThrow());assertEquals(RESOURCE,claims.findString("aud").orElseThrow());assertEquals("client",claims.findString("client_id").orElseThrow());assertEquals("read write",claims.findString("scope").orElseThrow());
  assertEquals(NOW.getEpochSecond(),claims.findLong("iat").orElseThrow());assertEquals(NOW.getEpochSecond()+300,claims.findLong("exp").orElseThrow());
  String[] parts=jwt.split("\\.",-1);Signature oracle=Signature.getInstance("SHA256withRSA");oracle.initVerify(KEY.getPublicKey());oracle.update((parts[0]+"."+parts[1]).getBytes(StandardCharsets.US_ASCII));assertTrue(oracle.verify(Base64.getUrlDecoder().decode(parts[2])));
  assertEquals(record(OAuthStoreKey.Kind.ACCESS_TOKEN).text("id"),claims.findString("jti").orElseThrow());assertEquals("Bearer",body(response).findString("token_type").orElseThrow());assertEquals(299L,body(response).findLong("expires_in").orElseThrow());
 }
 @Test void commitAtomicallyConsumesCodePinsHAndWritesExactAccessAndRefreshBindings() {
  String code=code(true);int commits=this.store.commits;OAuthTokenResponse result=redeem(code);
  assertEquals(commits+1,this.store.commits);var c=record(OAuthStoreKey.Kind.CODE);var g=record(OAuthStoreKey.Kind.GRANT);var a=record(OAuthStoreKey.Kind.ACCESS_TOKEN);var r=record(OAuthStoreKey.Kind.REFRESH_TOKEN);
  assertEquals("USED",c.text("status"));assertEquals("ACTIVE",g.text("status"));assertEquals(NOW.plusSeconds(120).minusNanos(NOW.getNano()),c.expires());
  assertEquals(Duration.ofMinutes(5),g.maximumAccessLifetime());assertEquals(this.retention.horizon(g.expires()),g.horizon());assertEquals(g.horizon(),c.retention());assertEquals(g.horizon(),r.retention());
  assertEquals(this.retention.accessRetention(a.expires()),a.retention());assertEquals(g.text("id"),a.text("grantId"));assertEquals(g.text("id"),r.text("grantId"));assertTrue(a.sameLineage(g));assertTrue(c.sameLineage(g));assertTrue(r.sameLineage(g));
  String refresh=body(result).findString("refresh_token").orElseThrow();assertEquals(OAuthServerCredential.refreshDigest(refresh),g.text("refreshId"));assertEquals(g.text("refreshId"),r.text("id"));assertEquals(NOW.plusSeconds(86400).minusNanos(NOW.getNano()),r.expires());
  assertEquals(6,requireNonNull(this.store.lastTransaction).getConditions().size());assertEquals(5,requireNonNull(this.store.lastTransaction).getMutations().size());
 }
 @Test void exactWireBodyAndHeaderBytesAreRetainedAndDefensivelyCopied() {
  var response=redeem(code(false));byte[] body=response.body(),headers=response.headers();String h=new String(headers,StandardCharsets.UTF_8);
  assertEquals("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nContent-Length: "+body.length+"\r\n\r\n",h);
  OAuthServerResponse exported=response.response();assertSame(exported,response.response());assertEquals(200,exported.getStatusCode());
  assertArrayEquals(body,exported.toHttpBodyWithCredentials());assertArrayEquals(headers,exported.wireHeaders());
  assertTrue(exported.getLocationWithCredentials().isEmpty());assertEquals(List.of("no-store"),exported.getHeaders().get("Cache-Control"));
  assertEquals("OAuthServerResponse{<redacted>}",exported.toString());
  body[0]=0;headers[0]=0;assertEquals('{',response.body()[0]);assertEquals('H',response.headers()[0]);assertFalse(body(response).getMembers().containsKey("refresh_token"));
 }
 @Test void noRefreshHorizonUsesFirstAccessExpiry() {
  redeem(code(false));OAuthAuthorizationRecord g=record(OAuthStoreKey.Kind.GRANT),a=record(OAuthStoreKey.Kind.ACCESS_TOKEN);assertFalse(g.refresh());assertEquals(a.expires(),g.expires());assertEquals(this.retention.horizon(a.expires()),g.horizon());assertFalse(this.store.rows.keySet().stream().anyMatch(k->k.getKind()==OAuthStoreKey.Kind.REFRESH_TOKEN));
 }
 @Test void serverRefreshDisabledAndPolicyNarrowingAreAppliedBeforeSignature() {
  String code=code(true);var result=engine(false,signer(),3).redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),(c,b)->decision("subject",Set.of("read"),false),deadline());
  assertEquals("read",part(token(result),1).findString("scope").orElseThrow());assertEquals(Set.of("read"),record(OAuthStoreKey.Kind.GRANT).scopes(LIMITS));assertFalse(record(OAuthStoreKey.Kind.GRANT).refresh());
 }
 @Test void policyReceivesCheckedGrantNotRawCodeAndOriginalBudget() {
  String code=code(true);this.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),(c,b)->{assertEquals("authorization_code",c.getGrantType());assertEquals("subject",c.getSubject());assertEquals(record(OAuthStoreKey.Kind.GRANT).text("id"),c.getGrantValue());assertNotEquals(code,c.getGrantValue());assertTrue(b.compareTo(Duration.ofSeconds(10))<0);return decision("subject",Set.of("read"),false);},deadline());
 }
 @Test void fullBoundReplayRevokesWholeGrantIncludingInitialRefresh() {
  String code=code(true);redeem(code);invalid(()->redeem(code));assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));int size=this.store.rows.size();invalid(()->redeem(code));assertEquals(size,this.store.rows.size());assertEquals(0,requireNonNull(this.store.lastTransaction).getMutations().size());
 }
 @Test void fullBoundUsedReplayStillRevokesAfterOriginalCodeExpiry() {
  String code=code(true);redeem(code);this.clock.time=NOW.plusSeconds(121);invalid(()->redeem(code));assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));
 }
 @Test void usedReplayRejectsOnTheOnlyCommittedAttempt() {
  String code=code(true);redeem(code);
  var once=engine(true,signer(),1);
  invalid(()->once.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline()));
  assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));
 }
 @Test void unusedExpiredCodeNeverIssuesOrCallsPolicy() {
  String code=code(true);this.clock.time=record(OAuthStoreKey.Kind.CODE).expires();int count=this.store.commits;invalid(()->this.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),(c,b)->{fail("No expired policy call");return OAuthAuthorizationDecision.deniedInstance();},deadline()));assertEquals(count,this.store.commits);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> wrongBindingsCannotConsumeOrRevoke() {
  return Stream.of(Map.of("code_verifier","x".repeat(43)),Map.of("resource","https://other.example/mcp"),Map.of("redirect_uri","https://client.example/cb?x=%2F"),Map.of("code",OTHER),Map.of("client_id","other")).flatMap(overrides->Stream.of(false,true).map(used->DynamicTest.dynamicTest(overrides.keySet()+" used="+used,()->{
   OAuthCodeRedemptionTests t=new OAuthCodeRedemptionTests();String code=t.code(true);if(used)t.redeem(code);int commits=t.store.commits;
   invalid(()->t.first.redeem(request(code,overrides),(id,b)->Optional.of(client(id,"v1",false)),resources(),allow(),deadline()));assertEquals(commits,t.store.commits);assertEquals(used?"ACTIVE":"PENDING",t.record(OAuthStoreKey.Kind.GRANT).text("status"));if(!used)assertNotNull(t.redeem(code));
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> changedCurrentClientSecurityFingerprintDoesNotPoison() {
  return Stream.of(false,true).map(used->DynamicTest.dynamicTest("changed metadata used="+used,()->{OAuthCodeRedemptionTests t=new OAuthCodeRedemptionTests();String code=t.code(true);if(used)t.redeem(code);int commits=t.store.commits;invalid(()->t.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client("client","v2",false)),resources(),allow(),deadline()));assertEquals(commits,t.store.commits);}));
 }
 @Test void optionalTokenRedirectMayBeAbsentOrExact() { String code=code(false);assertNotNull(this.first.redeem(request(code,Map.of("redirect_uri",REDIRECT)),(id,b)->Optional.of(client()),resources(),allow(),deadline())); }
 @Test void codeExchangeCannotSilentlyIgnoreScopeOrRefreshGrant() {
  String code=code(false);var e=assertThrows(OAuthServerAdmissionFailure.class,()->this.first.redeem(request(code,Map.of("scope","read")),(id,b)->Optional.of(client()),resources(),allow(),deadline()));assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_REQUEST,e.reason());
  e=assertThrows(OAuthServerAdmissionFailure.class,()->this.first.redeem(request(code,Map.of("grant_type","refresh_token","refresh_token",OTHER)),(id,b)->Optional.of(client()),resources(),allow(),deadline()));assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_REQUEST,e.reason());
 }
 @Test void missingCodeExchangeResourceIsRejectedBeforeClientLookupOrStoreRead() {
  String code=code(false);int reads=this.store.reads;int[] lookups={0};
  OAuthServerAdmissionFailure failure=assertThrows(OAuthServerAdmissionFailure.class,
   ()->this.first.redeem(request(code,Map.of("resource","")),(id,budget)->{
    lookups[0]++;return Optional.of(client());
   },resources(),allow(),deadline()));
  assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_REQUEST,failure.reason());
  assertEquals(0,lookups[0]);assertEquals(reads,this.store.reads);
 }
 @Test void publicUnknownClientAndBasicFailureDoNotReadOrMutateGrant() {
  String code=code(false);int reads=this.store.reads;assertThrows(OAuthServerAdmissionFailure.class,()->this.first.redeem(request(code,Map.of()),(id,b)->Optional.empty(),resources(),allow(),deadline()));assertEquals(reads,this.store.reads);
  assertThrows(OAuthServerAdmissionFailure.class,()->this.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client("client","v1",true)),resources(),allow(),deadline()));assertEquals(reads,this.store.reads);
 }
 @Test void confidentialBasicCodeFlowChecksSecretBeforeDestructiveReplay() {
  OAuthServerClientRegistration client=client("client","v1",true);String code=code(true,client);
  String form="grant_type=authorization_code&code="+code+"&code_verifier="+VERIFIER+"&resource="+encode(RESOURCE);
  var headers=Map.of("Content-Type",List.of("application/x-www-form-urlencoded"),"Authorization",List.of("Basic "+Base64.getEncoder().encodeToString("client:secret".getBytes(StandardCharsets.US_ASCII))));
  var request=OAuthServerRequest.parse(OAuthServerRequest.Endpoint.TOKEN,"POST",null,form.getBytes(StandardCharsets.US_ASCII),headers,LIMITS);
  assertNotNull(this.first.redeem(request,(id,b)->Optional.of(client),resources(),allow(),deadline()));invalid(()->this.first.redeem(request,(id,b)->Optional.of(client),resources(),allow(),deadline()));
 }
 @Test void racingRedemptionsEmitOneResponseThenRevokeRaceWinner() {
  String code=code(true);OAuthTokenResponse[] winner=new OAuthTokenResponse[1];this.store.beforeCommit=()->winner[0]=this.second.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline());
  invalid(()->redeem(code));assertNotNull(winner[0]);assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));assertEquals(1,this.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).count());
 }
 @Test void conflictReloadReauthenticatesAndRechecksPolicyUnderOneDeadline() {
  String code=code(false);int[] auth={0},policies={0};this.store.conflicts=1;Deadline deadline=deadline();
  this.first.redeem(request(code,Map.of()),(id,b)->{auth[0]++;return Optional.of(client());},resources(),(c,b)->{policies[0]++;return decision("subject",Set.of("read"),false);},deadline);
  assertEquals(2,auth[0]);assertEquals(2,policies[0]);assertEquals(1,this.store.rows.keySet().stream().filter(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).count());
 }
 @Test void attemptsExhaustWithoutIssuance() {String code=code(false);this.store.conflicts=10;failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->redeem(code));assertEquals("UNUSED",record(OAuthStoreKey.Kind.CODE).text("status"));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unknownOutcomeNeverEmitsOrRetriesAndLaterReplayReconciles() {
  return Stream.of(false,true).map(after->DynamicTest.dynamicTest("UNKNOWN after="+after,()->{OAuthCodeRedemptionTests t=new OAuthCodeRedemptionTests();String code=t.code(true);int commits=t.store.commits;t.store.unknownBefore=!after;t.store.unknownAfter=after;failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->t.redeem(code));assertEquals(commits+1,t.store.commits);t.store.unknownBefore=false;t.store.unknownAfter=false;if(after){invalid(()->t.redeem(code));assertEquals("REVOKED",t.record(OAuthStoreKey.Kind.GRANT).text("status"));}else assertNotNull(t.redeem(code));}));
 }
 @Test void unknownReplayRevocationDoesNotBecomeProtocolSuccess() {String code=code(true);redeem(code);this.store.unknownAfter=true;failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->redeem(code));assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> denialEmptyScopeAndRemovedServerAuthorityTerminatePendingGrant() {
  return Stream.of("deny","empty","resource","scope").map(mode->DynamicTest.dynamicTest(mode,()->{OAuthCodeRedemptionTests t=new OAuthCodeRedemptionTests();String code=t.code(true);
   Map<String,Set<String>> resources=mode.equals("resource")?Map.of("https://other.example/mcp",Set.of("read")):mode.equals("scope")?Map.of(RESOURCE,Set.of("read")):resources();
   OAuthGrantPolicy policy=(c,b)->mode.equals("deny")?OAuthAuthorizationDecision.deniedInstance():mode.equals("empty")?decision("subject",Set.of(),false):decision("subject",Set.of("read"),false);
   invalid(()->t.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources,policy,deadline()));assertEquals("DENIED",t.record(OAuthStoreKey.Kind.GRANT).text("status"));assertEquals("CANCELLED",t.record(OAuthStoreKey.Kind.CODE).text("status"));invalid(()->t.redeem(code));assertFalse(t.store.rows.keySet().stream().anyMatch(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> removedAuthorityRejectsOnTheOnlyCommittedAttempt() {
  return Stream.of("resource","empty").map(mode->DynamicTest.dynamicTest(mode,()->{
   var t=new OAuthCodeRedemptionTests();String code=t.code(true);var once=t.engine(true,signer(),1);
   Map<String,Set<String>> current=mode.equals("resource")?Map.of("https://other.example/mcp",Set.of("read")):resources();
   OAuthGrantPolicy policy=(c,b)->decision("subject",mode.equals("empty")?Set.of():Set.of("read"),false);
   invalid(()->once.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),current,policy,deadline()));
   assertEquals("DENIED",t.record(OAuthStoreKey.Kind.GRANT).text("status"));
   assertEquals("CANCELLED",t.record(OAuthStoreKey.Kind.CODE).text("status"));
  }));
 }
 @Test void deniedPolicyConflictReloadsAndCannotTerminateDifferentGeneration() {
  String code=code(false);this.store.conflicts=1;invalid(()->this.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),(c,b)->OAuthAuthorizationDecision.deniedInstance(),deadline()));assertEquals("DENIED",record(OAuthStoreKey.Kind.GRANT).text("status"));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> policyFaultsAreInfrastructureAndLeaveCodeUsable() {
  Map<String,OAuthGrantPolicy> policies=new LinkedHashMap<>();policies.put("throw",(c,b)->{throw new IllegalStateException("secret");});policies.put("null",(c,b)->nullDecision());policies.put("identity",(c,b)->decision("other",Set.of("read"),false));policies.put("widen",(c,b)->decision("subject",Set.of("admin"),false));policies.put("resource",(c,b)->OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of("https://other.example/mcp",Set.of("read"))).build());policies.put("refresh",(c,b)->decision("subject",Set.of("read"),true));
  return policies.entrySet().stream().map(e->DynamicTest.dynamicTest(e.getKey(),()->{OAuthCodeRedemptionTests t=new OAuthCodeRedemptionTests();String code=t.code(false);int commits=t.store.commits;unavailable(()->t.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),e.getValue(),deadline()));assertEquals(commits,t.store.commits);assertNotNull(t.redeem(code));}));
 }
 @SuppressWarnings("NullAway") private static @NonNull OAuthAuthorizationDecision nullDecision() {return null;}
 @Test void policyFatalErrorPropagatesAndInterruptionIsRestored() {
  String code=code(false);assertThrows(TestFatal.class,()->this.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),(c,b)->{throw new TestFatal();},deadline()));
  try {unavailable(()->this.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),(c,b)->{sneaky(new InterruptedException("secret"));return OAuthAuthorizationDecision.deniedInstance();},deadline()));assertTrue(Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}
  assertNotNull(redeem(code));
 }
 @SuppressWarnings("unchecked") private static <T extends Throwable> void sneaky(@NonNull Throwable failure) throws T {throw (T)failure;}
 @Test void signerFailureBeforeCommitPreservesUnusedCode() {
  String code=code(false);var failing=JwsSigner.fromRsaKeyPair(new RefusingPrivateKey(),KEY.getPublicKey(),JwsAlgorithm.RS256);int commits=this.store.commits;unavailable(()->engine(false,failing,3).redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline()));assertEquals(commits,this.store.commits);assertNotNull(redeem(code));
 }
 @Test void interruptedSignerBeforeCommitRestoresFlagAndPreservesUnusedCode() {
  String code=code(false);int commits=this.store.commits;
  try {InterruptingSignatureProvider.around(()->unavailable(()->engine(false,signer(),3).redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline())));assertTrue(Thread.currentThread().isInterrupted());assertEquals(commits,this.store.commits);}
  finally {Thread.interrupted();}
  assertNotNull(redeem(code));
 }
 @Test void preparedCredentialsCannotBeReleasedAfterCommitValidityBoundary() {
  String code=code(false);Instant expiry=record(OAuthStoreKey.Kind.CODE).expires();this.store.afterCommit=()->this.clock.time=expiry;
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->redeem(code));assertEquals("USED",record(OAuthStoreKey.Kind.CODE).text("status"));invalid(()->redeem(code));assertEquals("REVOKED",record(OAuthStoreKey.Kind.GRANT).text("status"));
 }
 @Test void shortAccessTokenExpiryCannotBePassedBySlowCommit() {
  String code=code(false);this.store.afterCommit=()->this.clock.time=NOW.plusSeconds(31);
  var shortLived=new OAuthCodeRedemption(this.coordinator,this.codec,LIMITS,this.retention,
   new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),32768,16384),Duration.ofSeconds(30),false,
   Duration.ofDays(1),Duration.ofDays(7),3,255);
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,
   ()->shortLived.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline()));
  assertEquals("USED",record(OAuthStoreKey.Kind.CODE).text("status"));
 }
 @Test void policyCannotPushOperationPastCodeExpiryOrOriginalDeadline() {
  String code=code(false);Instant expiry=record(OAuthStoreKey.Kind.CODE).expires();int commits=this.store.commits;
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->this.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),(c,b)->{this.clock.time=expiry;return decision("subject",Set.of("read"),false);},deadline()));assertEquals(commits,this.store.commits);
  this.clock.time=NOW;Deadline deadline=Deadline.fromNow(Duration.ofMillis(30));unavailable(()->this.first.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),(c,b)->{while(!deadline.isExpired())Thread.onSpinWait();return decision("subject",Set.of("read"),false);},deadline));assertEquals(commits,this.store.commits);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> revocationOrIncarnationChangesCannotIssueOrReplayOldGrants() {
  return Stream.of("issuerEpoch","subjectEpoch","issuerIncarnation","subjectIncarnation").flatMap(mode->Stream.of(false,true).map(used->DynamicTest.dynamicTest(mode+" used="+used,()->{
   OAuthCodeRedemptionTests t=new OAuthCodeRedemptionTests();String code=t.code(true);if(used)t.redeem(code);
   if(mode.equals("issuerEpoch"))t.coordinator.revokeAll(deadline());else if(mode.equals("subjectEpoch"))t.coordinator.revokeSubject("subject",deadline());else {var key=mode.equals("issuerIncarnation")?t.codec.issuerKey():t.codec.subjectKey("subject");var fence=mode.equals("issuerIncarnation")?OAuthStoreFence.initialIssuer(OTHER,NOW):OAuthStoreFence.initialSubject(OTHER);t.store.rows.put(key,t.codec.seal(key,OAuthStoreFormat.PERMANENT,fence.toPayload()));}
   int commits=t.store.commits;invalid(()->t.redeem(code));assertEquals(commits,t.store.commits);
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> lostPermanentFenceOrReferencedGrantIsCorruptState() {
  return Stream.of(OAuthStoreKey.Kind.ISSUER_STATE,OAuthStoreKey.Kind.SUBJECT_STATE,OAuthStoreKey.Kind.GRANT).map(kind->DynamicTest.dynamicTest(kind.name(),()->{OAuthCodeRedemptionTests t=new OAuthCodeRedemptionTests();String code=t.code(false);t.store.rows.remove(t.entry(kind).getKey());failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->t.redeem(code));}));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> crossLinkLineageAndAuthenticatedRetentionSubstitutionFailClosed() {
  return Stream.of("codeId","issuerIncarnation","subjectEpoch","retention","status").map(mode->DynamicTest.dynamicTest(mode,()->{OAuthCodeRedemptionTests t=new OAuthCodeRedemptionTests();String code=t.code(true);JsonObject payload=t.payload(OAuthStoreKey.Kind.GRANT);
   if(mode.equals("retention")){var e=t.entry(OAuthStoreKey.Kind.GRANT);t.store.rows.put(e.getKey(),t.codec.seal(e.getKey(),e.getRetainUntil().plusSeconds(1),payload.toJson()));}
   else t.replace(OAuthStoreKey.Kind.GRANT,changed(payload,mode,mode.equals("subjectEpoch")?JsonNumber.fromValue(1L):JsonString.fromValue(mode.equals("status")?"ACTIVE":OTHER)));
   int commits=t.store.commits;failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->t.redeem(code));assertEquals(commits,t.store.commits);
  }));
 }
 @Test void issuerEpochRaceDuringPreparedCommitDiscardsResponseOnConflict() {
  String code=code(false);this.store.beforeCommit=()->this.coordinator.revokeAll(deadline());invalid(()->redeem(code));assertEquals("UNUSED",record(OAuthStoreKey.Kind.CODE).text("status"));
 }
 @Test void shortNoRefreshLifetimeStillRetainsCodeAndGrantThroughOriginalCodeExpiry() {
  String code=code(false);var retention=new OAuthGrantRetention(Duration.ofSeconds(30),Duration.ZERO,Duration.ofSeconds(1),Duration.ZERO);
  var e=new OAuthCodeRedemption(this.coordinator,this.codec,LIMITS,retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,1024),Duration.ofSeconds(30),false,Duration.ofMinutes(5),Duration.ofHours(1),3,255);
  assertNotNull(e.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline()));assertEquals(record(OAuthStoreKey.Kind.CODE).expires(),record(OAuthStoreKey.Kind.GRANT).horizon());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> exactIssuedSchemasRejectMissingNullAndExtraFields() {
  OAuthCodeRedemptionTests fixture=new OAuthCodeRedemptionTests();fixture.redeem(fixture.code(true));
  return Stream.of(OAuthStoreKey.Kind.CODE,OAuthStoreKey.Kind.GRANT,OAuthStoreKey.Kind.ACCESS_TOKEN,OAuthStoreKey.Kind.REFRESH_TOKEN).flatMap(kind->{JsonObject original=fixture.payload(kind);String id=original.findString("id").orElseThrow();return Stream.concat(original.getMembers().keySet().stream().flatMap(key->Stream.of("missing","null").map(mode->DynamicTest.dynamicTest(kind+" "+key+" "+mode,()->{
   JsonObject malformed=changed(original,key,mode.equals("null")?JsonNull.defaultInstance():null);
   if(kind==OAuthStoreKey.Kind.GRANT&&key.equals("refreshId")&&mode.equals("null"))assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(kind,id,malformed,LIMITS,255));else assertThrows(RuntimeException.class,()->OAuthAuthorizationRecord.decode(kind,id,malformed,LIMITS,255));
  }))),Stream.of(DynamicTest.dynamicTest(kind+" extra",()->assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(kind,id,changed(original,"extra",JsonBoolean.fromValue(true)),LIMITS,255)))));});
 }
 @Test void typedIssuanceBoundsAndIllegalTransitionsReject() {
  String code=code(true);redeem(code);var g=record(OAuthStoreKey.Kind.GRANT);var c=record(OAuthStoreKey.Kind.CODE);var a=record(OAuthStoreKey.Kind.ACCESS_TOKEN);var refresh=record(OAuthStoreKey.Kind.REFRESH_TOKEN);
  assertThrows(IllegalArgumentException.class,()->g.activated(g.expires(),g.horizon(),Duration.ofMinutes(5),Set.of("read"),OTHER,LIMITS,255));assertThrows(IllegalArgumentException.class,()->c.consumed(c.horizon(),LIMITS,255));assertThrows(IllegalArgumentException.class,()->a.terminated(LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.access(OTHER,c,NOW,a.expires(),a.retention(),LIMITS,255));assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.refresh(OTHER,g,refresh.expires(),LIMITS,255));assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.refresh(g.text("refreshId"),g,g.expires().plusSeconds(1),LIMITS,255));
  for(String key:List.of("maximumAccessSeconds","maximumAccessNanos","horizon")){JsonObject bad=changed(payload(OAuthStoreKey.Kind.GRANT),key,JsonNumber.fromValue(-1L));assertThrows(RuntimeException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.GRANT,g.text("id"),bad,LIMITS,255));}
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.ACCESS_TOKEN,a.text("id"),changed(payload(OAuthStoreKey.Kind.ACCESS_TOKEN),"retain",JsonNumber.fromValue(NOW.getEpochSecond())),LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.ACCESS_TOKEN,a.text("id"),changed(payload(OAuthStoreKey.Kind.ACCESS_TOKEN),"issued",JsonNumber.fromValue(a.expires().getEpochSecond())),LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.GRANT,g.text("id"),changed(payload(OAuthStoreKey.Kind.GRANT),"maximumAccessNanos",JsonNumber.fromValue(1000000000L)),LIMITS,255));
 }
 @Test void responseEncoderCannotSelectOtherAlgorithmOrMismatchedIssuerAndEnforcesExactByteCap() {
  assertThrows(IllegalArgumentException.class,()->new OAuthTokenResponse.Encoder(ISSUER,"key",JwsSigner.fromRsaKeyPair(KEY.getPrivateKey(),KEY.getPublicKey(),JwsAlgorithm.PS256),4096,1024));
  assertThrows(IllegalArgumentException.class,()->new OAuthCodeRedemption(this.coordinator,this.codec,LIMITS,this.retention,new OAuthTokenResponse.Encoder("https://other.example","key",signer(),4096,1024),Duration.ofMinutes(5),false,Duration.ofDays(1),Duration.ofDays(7),3,255));
  redeem(code(false));var g=record(OAuthStoreKey.Kind.GRANT);var encoder=new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,1024);
  assertThrows(IllegalArgumentException.class,()->encoder.prepare(g,OTHER,NOW,NOW.plusSeconds(300),Set.of("x".repeat(10000)),null,deadline()));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> pureSettingsRejectInvalidRangesAndCrossFields() {
  return Stream.<Consumer<OAuthCodeRedemptionTests>>of(t->new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4095,1024),t->new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),131073,1024),t->new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,1023),t->new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,65537),t->t.engine(true,signer(),0),t->t.engine(true,signer(),9),t->new OAuthCodeRedemption(t.coordinator,t.codec,LIMITS,t.retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,1024),Duration.ofMinutes(6),true,Duration.ofDays(1),Duration.ofDays(7),3,255),t->new OAuthCodeRedemption(t.coordinator,t.codec,LIMITS,t.retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,1024),Duration.ofMinutes(5),true,Duration.ofDays(2),Duration.ofDays(1),3,255)).map(call->DynamicTest.dynamicTest("invalid settings",()->assertThrows(IllegalArgumentException.class,()->call.accept(new OAuthCodeRedemptionTests()))));
 }
 @Test void diagnosticsNeverContainCredentialsOrIdentities() {
  String code=code(true);var response=redeem(code);for(String diagnostic:List.of(this.first.toString(),response.toString(),new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,1024).toString(),record(OAuthStoreKey.Kind.GRANT).toString())){assertTrue(diagnostic.contains("<redacted>"));assertFalse(diagnostic.contains(code));assertFalse(diagnostic.contains("subject"));assertFalse(diagnostic.contains(token(response)));}
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> occupiedIssuedIdentifiersNeverOverwriteOtherRecords() {
  return Stream.of(OAuthStoreKey.Kind.ACCESS_TOKEN,OAuthStoreKey.Kind.REFRESH_TOKEN).map(kind->DynamicTest.dynamicTest(kind.name(),()->{
   OAuthCodeRedemptionTests t=new OAuthCodeRedemptionTests();String code=t.code(true);int commits=t.store.commits;
   OAuthAuthorizationServerStore wrapper=new OAuthAuthorizationServerStore(){
    @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,@NonNull Duration budget){
     if(key.getKind()==kind&&!t.store.rows.containsKey(key))t.store.rows.put(key,t.codec.seal(key,NOW.truncatedTo(java.time.temporal.ChronoUnit.SECONDS).plusSeconds(1000),"{}"));return t.store.read(key,budget);
    }
    @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){return t.store.commit(tx,budget);}
   };
   var coordinator=new OAuthStoreCoordinator(wrapper,t.codec,t.clock,3,255);
   var engine=new OAuthCodeRedemption(coordinator,t.codec,LIMITS,t.retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,1024),Duration.ofMinutes(5),true,Duration.ofDays(1),Duration.ofDays(7),3,255);
   failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->engine.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline()));assertEquals(commits,t.store.commits);assertEquals("UNUSED",t.record(OAuthStoreKey.Kind.CODE).text("status"));assertEquals(3,t.store.rows.keySet().stream().filter(k->k.getKind()==kind).count());
  }));
 }
 @Test void expiredReplayRetentionHasNoCredentialAuthority() {String code=code(true);redeem(code);this.clock.time=record(OAuthStoreKey.Kind.GRANT).horizon();int commits=this.store.commits;invalid(()->redeem(code));assertEquals(commits,this.store.commits);}
 @Test void usedReplayCannotCommitAfterGrantRetentionWhenCodeIsRetainedLonger() {
  String code=code(true);redeem(code);Instant grantHorizon=record(OAuthStoreKey.Kind.GRANT).horizon();
  Instant extended=grantHorizon.plusSeconds(60);OAuthStoreEntry old=entry(OAuthStoreKey.Kind.CODE);
  JsonObject payload=changed(payload(OAuthStoreKey.Kind.CODE),"horizon",JsonNumber.fromValue(extended.getEpochSecond()));
  this.store.rows.put(old.getKey(),this.codec.seal(old.getKey(),extended,payload.toJson()));
  var wrapper=new OAuthAuthorizationServerStore(){
   @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,@NonNull Duration budget){
    if(key.getKind()==OAuthStoreKey.Kind.SUBJECT_STATE)OAuthCodeRedemptionTests.this.clock.time=grantHorizon;
    return store.read(key,budget);
   }
   @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){return store.commit(tx,budget);}
  };
  var coordinator=new OAuthStoreCoordinator(wrapper,this.codec,this.clock,3,255);
  var engine=new OAuthCodeRedemption(coordinator,this.codec,LIMITS,this.retention,
   new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),32768,16384),Duration.ofMinutes(5),true,
   Duration.ofDays(1),Duration.ofDays(7),1,255);
  int commits=this.store.commits;
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,
   ()->engine.redeem(request(code,Map.of()),(id,b)->Optional.of(client()),resources(),allow(),deadline()));
  assertEquals(commits,this.store.commits);this.clock.time=NOW;
  assertEquals("ACTIVE",record(OAuthStoreKey.Kind.GRANT).text("status"));
 }
 @Test void usedCodeWithPendingGrantOrShortenedHorizonIsCorrupt() {
  String code=code(true);JsonObject pending=payload(OAuthStoreKey.Kind.GRANT);redeem(code);replace(OAuthStoreKey.Kind.GRANT,pending);failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->redeem(code));
 }
 @Test void codeCancelledOrDeniedGrantCannotAcquireIssuanceAuthority() {
  String code=code(false);replace(OAuthStoreKey.Kind.GRANT,changed(payload(OAuthStoreKey.Kind.GRANT),"status",JsonString.fromValue("DENIED")));invalid(()->redeem(code));
 }
 @Test void pendingExpiryMismatchIsCorruptAndDoesNotConsume() {
  String code=code(false);var e=entry(OAuthStoreKey.Kind.GRANT);JsonObject p=changed(payload(OAuthStoreKey.Kind.GRANT),"expires",JsonNumber.fromValue(e.getRetainUntil().plusSeconds(1).getEpochSecond()));this.store.rows.put(e.getKey(),this.codec.seal(e.getKey(),e.getRetainUntil().plusSeconds(1),p.toJson()));failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->redeem(code));
 }
 @Test void preparedRecordFactoriesRejectFractionalRetentionAndWrongKind() {
  code(false);var c=record(OAuthStoreKey.Kind.CODE);var g=record(OAuthStoreKey.Kind.GRANT);
  assertThrows(IllegalArgumentException.class,()->c.consumed(NOW.plusSeconds(1000),LIMITS,255));assertThrows(IllegalArgumentException.class,()->c.activated(c.expires(),c.expires().plusSeconds(1000),Duration.ofMinutes(5),Set.of("read"),null,LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->g.activated(NOW.plusSeconds(300),NOW.plusSeconds(700),Duration.ofMinutes(5),Set.of("read"),null,LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->g.consumed(c.expires(),LIMITS,255));
 }
 @Test void noRefreshGrantRequiresNullRefreshHeadAndCheckedPinHorizon() {
  redeem(code(false));var g=record(OAuthStoreKey.Kind.GRANT);JsonObject p=payload(OAuthStoreKey.Kind.GRANT);
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.GRANT,g.text("id"),changed(p,"refreshId",JsonString.fromValue(OTHER)),LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.refresh(OTHER,g,g.expires(),LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.GRANT,g.text("id"),changed(p,"horizon",JsonNumber.fromValue(g.expires().plusSeconds(1).getEpochSecond())),LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.GRANT,g.text("id"),changed(p,"maximumAccessSeconds",JsonNumber.fromValue(901L)),LIMITS,255));
 }
 @Test void noncanonicalCodeAndDisallowedCurrentClientNeverReadOrMutateStore() {
  String code=code(false);int reads=this.store.reads;invalid(()->redeem("x"));assertEquals(reads,this.store.reads);
  var disallowed=OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").authorizationCodePermitted(false).redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources()).build();
  var e=assertThrows(OAuthServerAdmissionFailure.class,()->this.first.redeem(request(code,Map.of()),(id,b)->Optional.of(disallowed),resources(),allow(),deadline()));assertEquals(OAuthServerAdmissionFailure.Reason.UNAUTHORIZED_CLIENT,e.reason());assertEquals(reads,this.store.reads);
 }
 @Test void responseByteCapFailureOccursBeforeConsumingValidLargeGrant() {
  byte[] key=new byte[32];for(int n=0;n<32;n++)key[n]=(byte)(n+1);
  var codec=new OAuthStoreRecordCodec(ISSUER,StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key))).maximumSealedLength(16384).clock(Clock.fixed(NOW,ZoneOffset.UTC)).build(),16384);
  var coordinator=new OAuthStoreCoordinator(this.store,codec,this.clock,3,1024);
  coordinator.initializeFreshIssuer(deadline());String subject="s".repeat(1024);coordinator.establishNewSubject(subject,deadline());
  Set<String> scopes=Set.of("a".repeat(128),"b".repeat(128),"c".repeat(128),"d".repeat(128),"e".repeat(128),"f".repeat(128),"g".repeat(128),"h".repeat(128));
  String clientId="c".repeat(2048);var resources=Map.of(RESOURCE,scopes);var client=OAuthServerClientRegistration.withClientId(clientId).configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources).build();
  String query="client_id="+clientId+"&response_type=code&redirect_uri="+encode(REDIRECT)+"&resource="+encode(RESOURCE)+"&code_challenge_method=S256&code_challenge="+CHALLENGE;
  var admission=OAuthServerAuthorizationAdmission.admit(OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",query,new byte[0],Map.of(),LIMITS),(id,b)->Optional.of(client),deadline(),resources,LIMITS,false,false);
  var ledger=new OAuthAuthorizationLedger(coordinator,codec,LIMITS,Duration.ofMinutes(15),Duration.ofMinutes(2),3,1024,false);
  String handle=ledger.begin(admission,BROWSER,deadline());String code=ledger.complete(handle,BROWSER,client,resources,OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(resources).build(),deadline()).orElseThrow();
  var engine=new OAuthCodeRedemption(coordinator,codec,LIMITS,this.retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),4096,1024),Duration.ofMinutes(5),false,Duration.ofDays(1),Duration.ofDays(7),3,1024);int commits=this.store.commits;
  unavailable(()->engine.redeem(request(code,Map.of("client_id",clientId)),(id,b)->Optional.of(client),resources,(c,b)->OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(resources).build(),deadline()));assertEquals(commits,this.store.commits);assertFalse(this.store.rows.keySet().stream().anyMatch(k->k.getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN));
  var entry=entry(OAuthStoreKey.Kind.CODE);assertEquals("UNUSED",codec.open(entry,Clock.fixed(NOW,ZoneOffset.UTC)).findString("status").orElseThrow());
 }
 @Test void decodedIssuedFactsRejectOutOfRangeInstantsAndRetiredTransitions() {
  redeem(code(false));var g=record(OAuthStoreKey.Kind.GRANT);assertEquals("REVOKED",g.terminated(LIMITS,255).terminated(LIMITS,255).text("status"));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.GRANT,g.text("id"),changed(payload(OAuthStoreKey.Kind.GRANT),"horizon",JsonNumber.fromValue(Long.MAX_VALUE)),LIMITS,255));
  assertThrows(IllegalArgumentException.class,()->OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.ACCESS_TOKEN,record(OAuthStoreKey.Kind.ACCESS_TOKEN).text("id"),changed(payload(OAuthStoreKey.Kind.ACCESS_TOKEN),"status",JsonString.fromValue("ACTIVE")),LIMITS,255));
 }
 private static final class RefusingPrivateKey implements PrivateKey {
  private static final long serialVersionUID=1L;
  RefusingPrivateKey() { }
  @Override public @NonNull String getAlgorithm(){return "RSA";}
  @Override public @Nullable String getFormat(){return null;}
  @Override public byte @Nullable [] getEncoded(){return null;}
 }
 private static final class TestFatal extends VirtualMachineError {private static final long serialVersionUID=1L;TestFatal(){super("fixture");}}
 @Test void refreshOrLegacyHandleCannotRedeemAsCodeBeforeStoreReads() {
  String code=code(false);int reads=this.store.reads;
  for(String bad:List.of(OAuthServerCredential.refresh(BROWSER),code.substring(5),code+"=")) {
   assertThrows(OAuthServerAdmissionFailure.class,()->redeem(bad));assertEquals(reads,this.store.reads);
  }
  assertNotNull(redeem(code));
 }
 private static final class MutableClock extends Clock {
  @NonNull Instant time;MutableClock(@NonNull Instant time){this.time=time;}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){requireNonNull(zone);return this;}
  @Override public @NonNull Instant instant(){return this.time;}
 }
}
