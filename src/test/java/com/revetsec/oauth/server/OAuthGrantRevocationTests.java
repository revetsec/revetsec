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

/** Whole-grant revocation and resource-only introspection over deterministic single-process CAS. */
final class OAuthGrantRevocationTests {
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
 OAuthGrantRevocationTests() { }
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
 private @NonNull OAuthTokenResponse issued() { return redeem(code(true,client())); }
 private @NonNull String signed(@NonNull JsonObject claims) { return signer().toCompactSerialization("at+jwt","key",null,JsonCodec.toUtf8Bytes(claims),Duration.ofSeconds(10)); }
 private static @NonNull JsonObject claims(@NonNull String token) { return json(Base64.getUrlDecoder().decode(token.split("\\.",-1)[1])); }
 private void revokeGrant() { var g=record(OAuthStoreKey.Kind.GRANT);replace(OAuthStoreKey.Kind.GRANT,json(g.terminated(LIMITS,255).toPayload().getBytes(StandardCharsets.UTF_8))); }
 private void remove(OAuthStoreKey.@NonNull Kind kind) { this.store.rows.remove(entry(kind).getKey()); }
 private static @NonNull DynamicTest test(@NonNull String name,@NonNull Executable action) { return DynamicTest.dynamicTest(name,action); }

 private @NonNull OAuthGrantRevocation revocations(int attempts) {return new OAuthGrantRevocation(this.coordinator,this.codec,status(),LIMITS,attempts,255,32768,16384);}
 private @NonNull OAuthResourceIntrospection introspection() {return new OAuthResourceIntrospection(status(),LIMITS,32768,16384);}
 private static @NonNull OAuthServerClientRegistration resourceClient(@NonNull Set<@NonNull String> allowed,boolean browser) {
  var b=OAuthServerClientRegistration.withClientId("resource").configurationVersion("r1")
   .authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->java.util.Arrays.equals(secret,"secret".getBytes(StandardCharsets.UTF_8))))
   .authorizationCodePermitted(browser).introspectionResources(allowed);
  if(browser)b=b.redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources());return b.build();
 }
 private static @NonNull OAuthServerRequest endpoint(OAuthServerRequest.@NonNull Endpoint ep,@NonNull String token,@NonNull Map<@NonNull String,@NonNull String> extra,@Nullable String basic) {
  Map<String,String> fields=new LinkedHashMap<>(Map.of("token",token));if(basic==null)fields.put("client_id","client");fields.putAll(extra);
  Map<String,List<String>> headers=new LinkedHashMap<>(Map.of("Content-Type",List.of("application/x-www-form-urlencoded")));
  if(basic!=null)headers.put("Authorization",List.of("Basic "+Base64.getEncoder().encodeToString(basic.getBytes(StandardCharsets.UTF_8))));
  String form=String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());
  return OAuthServerRequest.parse(ep,"POST",null,form.getBytes(StandardCharsets.UTF_8),headers,LIMITS);
 }
 private @NonNull OAuthStatusResponse revoke(@NonNull String t) {return revocations(3).revoke(endpoint(OAuthServerRequest.Endpoint.REVOCATION,t,Map.of(),null),(id,b)->Optional.of(client()),keys(),deadline());}
 private @NonNull OAuthStatusResponse introspect(@NonNull String t) {return introspection().introspect(endpoint(OAuthServerRequest.Endpoint.INTROSPECTION,t,Map.of(),"resource:secret"),(id,b)->Optional.of(resourceClient(Set.of(RESOURCE),false)),RESOURCE,keys(),deadline());}
 private @NonNull OAuthTokenResponse rotate(@NonNull String refresh) {
  var r=new OAuthRefreshRotation(this.coordinator,this.codec,LIMITS,this.retention,new OAuthTokenResponse.Encoder(ISSUER,"key",signer(),32768,16384),Duration.ofMinutes(5),true,Duration.ofDays(1),3,255);
  var req=OAuthServerRequest.parse(OAuthServerRequest.Endpoint.TOKEN,"POST",null,("grant_type=refresh_token&client_id=client&resource="+encode(RESOURCE)+"&refresh_token="+encode(refresh)).getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded")),LIMITS);
  return r.rotate(req,(id,b)->Optional.of(client()),resources(),allow(),deadline());
 }
 private static @NonNull String refresh(@NonNull OAuthTokenResponse response) {return body(response).findString("refresh_token").orElseThrow();}
 private static void ordinary(@NonNull OAuthStatusResponse response) {
  OAuthServerResponse exported=response.response();assertSame(exported,response.response());assertEquals(200,exported.getStatusCode());
  assertArrayEquals(response.body(),exported.toHttpBodyWithCredentials());assertArrayEquals(response.headers(),exported.wireHeaders());
  assertTrue(exported.getLocationWithCredentials().isEmpty());assertEquals(List.of("no-store"),exported.getHeaders().get("Cache-Control"));
  assertEquals(List.of("no-referrer"),exported.getHeaders().get("Referrer-Policy"));
  assertEquals(0,response.body().length);String h=new String(response.headers(),StandardCharsets.UTF_8);assertTrue(h.startsWith("HTTP/1.1 200 OK\r\n"));assertTrue(h.contains("Cache-Control: no-store\r\n"));assertTrue(h.contains("Pragma: no-cache\r\n"));assertTrue(h.contains("Content-Length: 0\r\n"));
 }
 private static void inactive(@NonNull OAuthStatusResponse response) {assertEquals(JsonObject.builder().put("active",false).build(),json(response.body()));}
 private static void admission(OAuthServerAdmissionFailure.@NonNull Reason reason,@NonNull Executable call) {
  var e=assertThrows(OAuthServerAdmissionFailure.class,call);assertEquals(reason,e.reason());assertNull(e.getCause());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> revocationCascadesAllAccessAndRefreshDescendants() {
  return Stream.of("access","old-refresh","new-refresh","trusted").map(kind->test(kind,()->{
   var f=new OAuthGrantRevocationTests();var one=f.issued();var two=f.rotate(refresh(one));String first=token(one),second=token(two);
   f.validate(first);f.validate(second);
   if(kind.equals("trusted"))f.revocations(3).revokeGrant(f.record(OAuthStoreKey.Kind.GRANT).text("id"),deadline());
   else ordinary(f.revoke(kind.equals("access")?first:kind.equals("old-refresh")?refresh(one):refresh(two)));
   invalid(()->f.validate(first));invalid(()->f.validate(second));admission(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,()->f.rotate(refresh(two)));
   inactive(f.introspect(second));assertEquals("REVOKED",f.record(OAuthStoreKey.Kind.GRANT).text("status"));
  }));
 }
 @Test void expiredIssuedAccessCanRevokeItsStillRetainedRefreshGrant() {
  var one=issued();String jwt=token(one);this.clock.time=NOW.plusSeconds(331);invalid(()->validate(jwt));inactive(introspect(jwt));
  var ordinaryValidator=com.revetsec.jose.JwtValidator.withIssuer(ISSUER).jsonWebKeySource(keys()).expectedAudiences(Set.of(RESOURCE)).allowedTypes(Set.of("at+jwt")).clock(this.clock).clockSkew(Duration.ofSeconds(30)).build();
  assertEquals(com.revetsec.jose.JoseException.Reason.EXPIRED,assertThrows(com.revetsec.jose.JoseException.class,()->ordinaryValidator.validate(jwt)).getReason());ordinary(revoke(jwt));
  admission(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,()->rotate(refresh(one)));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> expiredRefreshRetainedToHStillRevokes() {
  return Stream.of(false,true).map(used->test("used="+used,()->{
   var f=new OAuthGrantRevocationTests();var one=f.issued();if(used)f.rotate(refresh(one));f.clock.time=NOW.plus(Duration.ofDays(2));ordinary(f.revoke(refresh(one)));assertEquals("REVOKED",f.record(OAuthStoreKey.Kind.GRANT).text("status"));
  }));
 }
 @Test void idempotentRevocationNeverChangesGrantVersionOnAReconciledRetry() {
  var one=issued();ordinary(revoke(refresh(one)));var row=entry(OAuthStoreKey.Kind.GRANT);var issuer=entry(OAuthStoreKey.Kind.ISSUER_STATE);
  ordinary(revoke(refresh(one)));assertSame(row,entry(OAuthStoreKey.Kind.GRANT));assertSame(issuer,entry(OAuthStoreKey.Kind.ISSUER_STATE));
  revocations(3).revokeGrant(record(OAuthStoreKey.Kind.GRANT).text("id"),deadline());assertSame(row,entry(OAuthStoreKey.Kind.GRANT));assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> wrongBindingsCannotPoisonGrant() {
  return Stream.of("client","fingerprint","resource","subject","issuer","scope","iat","exp","sub","client_id","aud").map(binding->test(binding,()->{
   var f=new OAuthGrantRevocationTests();var issued=f.issued();String jwt=token(issued);OAuthServerClientRegistration c=client();Map<String,String> extra=Map.of();
   if(binding.equals("client")){c=client("other","v1",false);extra=Map.of("client_id","other");}
   else if(binding.equals("fingerprint"))c=client("client","v2",false);
   else if(binding.equals("resource"))extra=Map.of("resource",RESOURCE+"/wrong");
   else if(binding.equals("subject"))f.coordinator.revokeSubject("subject",deadline());
   else if(binding.equals("issuer"))f.coordinator.revokeAll(deadline());
   else {JsonValue value=binding.equals("iat")||binding.equals("exp")?JsonNumber.fromValue(1L):JsonString.fromValue(binding.equals("aud")?RESOURCE+"/wrong":"wrong");jwt=f.signed(changed(claims(jwt),binding,value));}
   var chosen=c;var before=Map.copyOf(f.store.rows);ordinary(f.revocations(3).revoke(endpoint(OAuthServerRequest.Endpoint.REVOCATION,jwt,extra,null),(id,b)->Optional.of(chosen),keys(),deadline()));assertEquals(before,f.store.rows);
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> hintsDoNotSelectTokenAuthority() {
  return Stream.of("access_token","refresh_token","unknown","").flatMap(hint->Stream.of(false,true).map(refresh->test(hint+refresh,()->{
   var f=new OAuthGrantRevocationTests();var one=f.issued();ordinary(f.revocations(3).revoke(endpoint(OAuthServerRequest.Endpoint.REVOCATION,refresh?refresh(one):token(one),Map.of("token_type_hint",hint),null),(id,b)->Optional.of(client()),keys(),deadline()));invalid(()->f.validate(token(one)));
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unknownCredentialsHaveOneResponseAndNoStateChange() {
  return Stream.of("random", "A".repeat(43), "x.y.z", "x".repeat(16000)).map(raw->test("length="+raw.length(),()->{
   var f=new OAuthGrantRevocationTests();f.issued();var before=Map.copyOf(f.store.rows);ordinary(f.revoke(raw));assertEquals(before,f.store.rows);inactive(f.introspect(raw));assertEquals(before,f.store.rows);
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> malformedSignedProfilesCannotRevoke() {
  return Stream.of("iss","jti","aud","scope","exp","iat","cnf","extra").map(field->test(field,()->{
   var f=new OAuthGrantRevocationTests();String jwt=token(f.issued());JsonValue v=switch(field){case "iss"->JsonString.fromValue(ISSUER+"/other");case "jti"->JsonString.fromValue("bad");case "aud"->JsonArray.fromElements(List.of(JsonString.fromValue(RESOURCE)));case "exp","iat"->JsonString.fromValue("0");default->JsonNull.defaultInstance();};
   String changed=f.signed(changed(claims(jwt),field,v));var before=Map.copyOf(f.store.rows);ordinary(f.revoke(changed));assertEquals(before,f.store.rows);inactive(f.introspect(changed));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> signatureAndTypeFailuresNeverReachStore() {
  return Stream.of("signature","kid","type","alg").map(which->test(which,()->{
   var f=new OAuthGrantRevocationTests();String jwt=token(f.issued());String changed;
   if(which.equals("signature")){int i=jwt.lastIndexOf('.')+1;changed=jwt.substring(0,i)+(jwt.charAt(i)=='A'?'B':'A')+jwt.substring(i+1);}
   else changed=signer().toCompactSerialization(which.equals("type")?"JWT":"at+jwt",which.equals("kid")?"other":"key",null,JsonCodec.toUtf8Bytes(claims(jwt)),Duration.ofSeconds(10));
   if(which.equals("alg"))changed="eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.e30.";
   int reads=f.store.reads;ordinary(f.revoke(changed));inactive(f.introspect(changed));assertEquals(reads,f.store.reads);
  }));
 }
 @Test void activeIntrospectionReleasesExactlyCheckedClaimsAfterFourRowBarrier() {
  String jwt=token(issued());var response=introspect(jwt);var json=json(response.body());assertTrue(json.findBoolean("active").orElseThrow());assertEquals("Bearer",json.findString("token_type").orElseThrow());
  assertEquals(Set.of("active","token_type","iss","sub","aud","client_id","iat","exp","jti","scope"),json.getMembers().keySet());for(var member:claims(jwt).getMembers().entrySet())assertEquals(member.getValue(),json.getMembers().get(member.getKey()));
  var t=requireNonNull(this.store.lastTransaction);assertEquals(4,t.getConditions().size());assertTrue(t.getMutations().isEmpty());String headers=new String(response.headers(),StandardCharsets.UTF_8);assertTrue(headers.contains("Content-Length: "+response.body().length+"\r\n"));assertTrue(headers.contains("no-store"));assertTrue(headers.contains("no-cache"));
  var bytes=response.body();bytes[0]=0;assertNotEquals(0,response.body()[0]);var h=response.headers();h[0]=0;assertNotEquals(0,response.headers()[0]);assertFalse(response.toString().contains("subject"));assertFalse(introspection().toString().contains("subject"));assertFalse(revocations(3).toString().contains("subject"));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unauthorizedIntrospectionCallersHaveNoStoreOrClaimAccess() {
  return Stream.of("public","wrong-secret","wrong-resource","browser","unknown").map(kind->test(kind,()->{
   var f=new OAuthGrantRevocationTests();String jwt=token(f.issued());int reads=f.store.reads;var req=endpoint(OAuthServerRequest.Endpoint.INTROSPECTION,jwt,Map.of(),kind.equals("public")?null:kind.equals("wrong-secret")?"resource:wrong":"resource:secret");
   var caller=kind.equals("public")?client():resourceClient(Set.of(kind.equals("wrong-resource")?RESOURCE+"/other":RESOURCE),kind.equals("browser"));
   admission(kind.equals("public")||kind.equals("wrong-secret")||kind.equals("unknown")?OAuthServerAdmissionFailure.Reason.INVALID_CLIENT:OAuthServerAdmissionFailure.Reason.UNAUTHORIZED_CLIENT,
    ()->f.introspection().introspect(req,(id,b)->kind.equals("unknown")?Optional.empty():Optional.of(caller),RESOURCE,keys(),deadline()));assertEquals(reads,f.store.reads);
  }));
 }
 @Test void registeredAuthorityIsFreshOnEveryOperation() {
  String jwt=token(issued());int[] calls={0};OAuthServerClientRepository repository=(id,b)->{calls[0]++;return Optional.of(resourceClient(Set.of(calls[0]==1?RESOURCE:RESOURCE+"/wrong"),false));};var request=endpoint(OAuthServerRequest.Endpoint.INTROSPECTION,jwt,Map.of(),"resource:secret");
  assertTrue(json(introspection().introspect(request,repository,RESOURCE,keys(),deadline()).body()).findBoolean("active").orElseThrow());admission(OAuthServerAdmissionFailure.Reason.UNAUTHORIZED_CLIENT,()->introspection().introspect(request,repository,RESOURCE,keys(),deadline()));assertEquals(2,calls[0]);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> inactiveResponsesRevealNoOtherFields() {
  return Stream.of("expired","revoked","subject","issuer","missing-jti","missing-grant","wrong-audience","refresh").map(kind->test(kind,()->{
   var f=new OAuthGrantRevocationTests();var one=f.issued();String jwt=token(one);
   switch(kind){case "expired"->f.clock.time=NOW.plusSeconds(331);case "revoked"->f.revokeGrant();case "subject"->f.coordinator.revokeSubject("subject",deadline());case "issuer"->f.coordinator.revokeAll(deadline());case "missing-jti"->f.remove(OAuthStoreKey.Kind.ACCESS_TOKEN);case "missing-grant"->f.remove(OAuthStoreKey.Kind.GRANT);case "wrong-audience"->jwt=f.signed(changed(claims(jwt),"aud",JsonString.fromValue(RESOURCE+"/other")));default->jwt=refresh(one);}
   inactive(f.introspect(jwt));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> revocationRacingAStatusBarrierNeverReleasesClaims() {
  return Stream.of("grant","subject","issuer").map(kind->test(kind,()->{
   var f=new OAuthGrantRevocationTests();String jwt=token(f.issued());int commits=f.store.commits;f.store.beforeCommit=()->{switch(kind){case "grant"->f.revoke(jwt);case "subject"->f.coordinator.revokeSubject("subject",deadline());default->f.coordinator.revokeAll(deadline());}};
   inactive(f.introspect(jwt));assertTrue(f.store.commits>=commits+3);
  }));
 }
 @Test void noPositiveIntrospectionCacheAndAlreadyAdmittedWorkHasNoRollbackPromise() {
  String jwt=token(issued());this.store.afterCommit=()->ordinary(revoke(jwt));assertTrue(json(introspect(jwt).body()).findBoolean("active").orElseThrow());inactive(introspect(jwt));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> everyObservedVersionParticipatesInRevocationCas() {
  return Stream.of(false,true).flatMap(refresh->Stream.of(OAuthStoreKey.Kind.ISSUER_STATE,OAuthStoreKey.Kind.SUBJECT_STATE,OAuthStoreKey.Kind.GRANT,refresh?OAuthStoreKey.Kind.REFRESH_TOKEN:OAuthStoreKey.Kind.ACCESS_TOKEN).map(kind->test(refresh+kind.name(),()->{
   var f=new OAuthGrantRevocationTests();var one=f.issued();var row=f.entry(kind);int commits=f.store.commits;f.store.beforeCommit=()->f.store.rows.put(row.getKey(),f.codec.seal(row.getKey(),row.getRetainUntil(),f.codec.open(row,Clock.fixed(NOW,ZoneOffset.UTC)).toJson()));
   ordinary(f.revoke(refresh?refresh(one):token(one)));assertEquals(commits+2,f.store.commits);var t=requireNonNull(f.store.lastTransaction);assertEquals(4,t.getConditions().size());assertEquals(2,t.getMutations().size());invalid(()->f.validate(token(one)));
  })));
 }
 @Test void absentCredentialBarrierReloadsAnAppearingRow() {
  var one=issued();var row=entry(OAuthStoreKey.Kind.ACCESS_TOKEN);remove(OAuthStoreKey.Kind.ACCESS_TOKEN);int commits=this.store.commits;this.store.beforeCommit=()->this.store.rows.put(row.getKey(),row);ordinary(revoke(token(one)));assertEquals(commits+2,this.store.commits);invalid(()->validate(token(one)));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unknownNeverReportsSuccessOrRetries() {
  return Stream.of("revoke","trusted","intro-active","intro-absent").flatMap(op->Stream.of(false,true).map(after->test(op+after,()->{
   var f=new OAuthGrantRevocationTests();var one=f.issued();String id=f.record(OAuthStoreKey.Kind.GRANT).text("id");if(op.equals("intro-absent"))f.remove(OAuthStoreKey.Kind.ACCESS_TOKEN);f.store.unknownBefore=!after;f.store.unknownAfter=after;int commits=f.store.commits;
   failed(OAuthStoreFailure.Reason.COMMIT_OUTCOME_UNKNOWN,()->{switch(op){case "revoke"->f.revoke(refresh(one));case "trusted"->f.revocations(3).revokeGrant(id,deadline());default->f.introspect(token(one));}});assertEquals(commits+1,f.store.commits);
   f.store.unknownBefore=false;f.store.unknownAfter=false;if(op.equals("trusted")){f.revocations(3).revokeGrant(id,deadline());assertEquals("REVOKED",f.record(OAuthStoreKey.Kind.GRANT).text("status"));}
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> serviceFaultsCannotBeOrdinarySuccessOrInactive() {
  return Stream.of("throw-read","null-read","null-commit","conflicts","permanent-issuer","permanent-subject","corrupt-grant","clock-backwards").flatMap(kind->Stream.of(false,true).map(intro->test(kind+intro,()->{
   var f=new OAuthGrantRevocationTests();var one=f.issued();var reason=OAuthStoreFailure.Reason.UNAVAILABLE;
   switch(kind){case "throw-read"->f.store.fault=new IllegalStateException("must not leak");case "null-read"->f.store.nullRead=true;case "null-commit"->f.store.nullCommit=true;case "conflicts"->f.store.conflicts=20;case "permanent-issuer"->{f.remove(OAuthStoreKey.Kind.ISSUER_STATE);reason=OAuthStoreFailure.Reason.CORRUPT_STATE;}case "permanent-subject"->{f.remove(OAuthStoreKey.Kind.SUBJECT_STATE);reason=OAuthStoreFailure.Reason.CORRUPT_STATE;}case "corrupt-grant"->{f.replace(OAuthStoreKey.Kind.GRANT,changed(f.payload(OAuthStoreKey.Kind.GRANT),"clientId",JsonString.fromValue("other")));reason=OAuthStoreFailure.Reason.CORRUPT_STATE;}default->f.clock.time=NOW.minusSeconds(1);}
   var expected=reason;failed(expected,()->{if(intro)f.introspect(token(one));else f.revoke(token(one));});
  })));
 }
 @Test void conflictReauthenticatesClientAndCannotDestroyUnderChangedRegistration() {
  var one=issued();this.store.conflicts=1;int[] calls={0};var before=Map.copyOf(this.store.rows);
  ordinary(revocations(3).revoke(endpoint(OAuthServerRequest.Endpoint.REVOCATION,refresh(one),Map.of(),null),(id,b)->Optional.of(client("client",++calls[0]==1?"v1":"v2",false)),keys(),deadline()));assertEquals(2,calls[0]);assertEquals(before,this.store.rows);
 }
 @Test void trustedGrantRevocationAlsoTerminatesPendingAuthorization() {
  String code=code(true,client()),id=record(OAuthStoreKey.Kind.GRANT).text("id");revocations(3).revokeGrant(id,deadline());assertEquals("DENIED",record(OAuthStoreKey.Kind.GRANT).text("status"));admission(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,()->redeem(code));
 }
 @Test void trustedUnknownGrantNeedsAnAuthoritativeAbsenceBarrier() {
  issued();int commits=this.store.commits;revocations(3).revokeGrant("A".repeat(43),deadline());assertEquals(commits+1,this.store.commits);assertEquals(2,requireNonNull(this.store.lastTransaction).getConditions().size());assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> wrongEndpointAndMissingTokenRejectBeforeDestruction() {
  return Stream.of("revoke","intro").map(op->test(op,()->{
   var f=new OAuthGrantRevocationTests();String jwt=token(f.issued());var before=Map.copyOf(f.store.rows);
   admission(OAuthServerAdmissionFailure.Reason.INVALID_REQUEST,()->{if(op.equals("revoke"))f.revocations(3).revoke(endpoint(OAuthServerRequest.Endpoint.TOKEN,jwt,Map.of(),null),(id,b)->Optional.of(client()),keys(),deadline());else f.introspection().introspect(endpoint(OAuthServerRequest.Endpoint.REVOCATION,jwt,Map.of(),null),(id,b)->Optional.of(client()),RESOURCE,keys(),deadline());});assertEquals(before,f.store.rows);
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> callbackInterruptionAndFatalErrorsRetainTheirContract() {
  return Stream.of("repository","store").flatMap(where->Stream.of(false,true).map(fatal->test(where+fatal,()->{
   var f=new OAuthGrantRevocationTests();String jwt=token(f.issued());Throwable error=fatal?new TestFatal():new InterruptedException("fixture");
   if(where.equals("store"))f.store.fault=error;
   OAuthServerClientRepository repo=(id,b)->{if(where.equals("repository"))raise(error);return Optional.of(client());};
   Executable call=()->f.revocations(3).revoke(endpoint(OAuthServerRequest.Endpoint.REVOCATION,jwt,Map.of(),null),repo,keys(),deadline());
   try {if(fatal)assertSame(error,assertThrows(TestFatal.class,call));else {if(where.equals("repository"))unavailable(call);else failed(OAuthStoreFailure.Reason.UNAVAILABLE,call);assertTrue(Thread.currentThread().isInterrupted());}} finally {Thread.interrupted();}
  })));
 }

 @TestFactory @NonNull Stream<@NonNull DynamicTest> retainedRefreshCrossRowCorruptionIsInfrastructure() {
  return Stream.of("issuerIncarnation","issuerEpoch","subjectIncarnation","subjectEpoch","grantId","horizon","status","head","refresh-disabled").map(field->test(field,()->{
   var f=new OAuthGrantRevocationTests();var one=f.issued();
   if(field.equals("head"))f.replace(OAuthStoreKey.Kind.GRANT,changed(f.payload(OAuthStoreKey.Kind.GRANT),"refreshId",JsonString.fromValue("A".repeat(43))));
   else if(field.equals("refresh-disabled")){var g=changed(f.payload(OAuthStoreKey.Kind.GRANT),"refresh",JsonBoolean.fromValue(false));f.replace(OAuthStoreKey.Kind.GRANT,changed(g,"refreshId",JsonNull.defaultInstance()));}
   else {JsonValue value=switch(field){case "issuerEpoch","subjectEpoch"->JsonNumber.fromValue(2L);case "horizon"->JsonNumber.fromValue(NOW.plus(Duration.ofDays(8)).getEpochSecond());case "status"->JsonString.fromValue("USED");default->JsonString.fromValue("A".repeat(43));};f.replace(OAuthStoreKey.Kind.REFRESH_TOKEN,changed(f.payload(OAuthStoreKey.Kind.REFRESH_TOKEN),field,value));}
   if(field.equals("grantId")){ordinary(f.revoke(refresh(one)));return;}
   failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->f.revoke(refresh(one)));
  }));
 }
 @Test void retainedRowsCannotBeReactivatedAfterHAndMissingGrantIsAuthoritativelyInactive() {
  var one=issued();this.clock.time=record(OAuthStoreKey.Kind.GRANT).horizon();var before=Map.copyOf(this.store.rows);ordinary(revoke(refresh(one)));assertEquals(before,this.store.rows);assertEquals(2,requireNonNull(this.store.lastTransaction).getConditions().size());
 }
 @Test void missingOwningGrantRequiresAnAbsenceBarrier() {var one=issued();remove(OAuthStoreKey.Kind.GRANT);ordinary(revoke(refresh(one)));assertEquals(3,requireNonNull(this.store.lastTransaction).getConditions().size());assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());}
 @Test void introspectionOptionalResourceMismatchDoesNotInspectToken() {
  String jwt=token(issued());int reads=this.store.reads;inactive(introspection().introspect(endpoint(OAuthServerRequest.Endpoint.INTROSPECTION,jwt,Map.of("resource",RESOURCE+"/wrong"),"resource:secret"),(id,b)->Optional.of(resourceClient(Set.of(RESOURCE),false)),RESOURCE,keys(),deadline()));assertEquals(reads,this.store.reads);
 }
 @Test void noRefreshGrantCanStillBeRevokedFromAccessToken() {
  String jwt=token(redeem(code(false,client())));ordinary(revoke(jwt));invalid(()->validate(jwt));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> constructorBoundsRejectInvalidTrustedWiring() {
  return Stream.of("attempt-zero","attempt-nine","subject-short","subject-long","body-small","body-large","header-small","header-large").map(which->test(which,()->{
   var f=new OAuthGrantRevocationTests();int attempts=which.equals("attempt-zero")?0:which.equals("attempt-nine")?9:3,subject=which.equals("subject-short")?15:which.equals("subject-long")?1025:255;
   int body=which.equals("body-small")?4095:which.equals("body-large")?131073:32768,head=which.equals("header-small")?1023:which.equals("header-large")?65537:16384;
   assertThrows(IllegalArgumentException.class,()->new OAuthGrantRevocation(f.coordinator,f.codec,f.status(),LIMITS,attempts,subject,body,head));
   if(which.startsWith("body")||which.startsWith("header"))assertThrows(IllegalArgumentException.class,()->new OAuthResourceIntrospection(f.status(),LIMITS,body,head));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> responseEncodingBoundsFailBeforeAnyCommit() {
  return Stream.of("body-small","body-large","header-small","header-large","oversize").map(which->test(which,()->{
   int body=which.equals("body-small")?4095:which.equals("body-large")?131073:4096,head=which.equals("header-small")?1023:which.equals("header-large")?65537:1024;
   failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->OAuthStatusResponse.prepare(JsonObject.builder().put("value",which.equals("oversize")?"A".repeat(5000):"a").build(),body,head));
  }));
 }
 @Test void oversizedActiveIntrospectionCannotReturnClaimsOrRunBarrier() {
  String jwt=token(issued());int commits=this.store.commits;failed(OAuthStoreFailure.Reason.CORRUPT_STATE,()->status().validate(jwt,RESOURCE,keys(),deadline(),c->OAuthStatusResponse.prepare(JsonObject.builder().put("large","A".repeat(5000)).build(),4096,1024)));assertEquals(commits,this.store.commits);
 }
 @Test void originalDeadlineExpirationBeforeBarrierNeverReturnsPreparedClaims() {
  String jwt=token(issued());var budget=Deadline.fromNow(Duration.ofSeconds(1));int commits=this.store.commits;
  failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->status().validate(jwt,RESOURCE,keys(),budget,c->{while(!budget.isExpired())Thread.onSpinWait();return c;}));assertEquals(commits,this.store.commits);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> expiredBudgetsRejectEvenMalformedRevocationTokens() {
  return Stream.of("token", "malformed").map(which->test(which,()->{
   var f=new OAuthGrantRevocationTests();var one=f.issued();var d=Deadline.fromNow(Duration.ZERO);int commits=f.store.commits;
   unavailable(()->f.revocations(3).revoke(endpoint(OAuthServerRequest.Endpoint.REVOCATION,which.equals("token")?refresh(one):"bad",Map.of(),null),(id,b)->Optional.of(client()),keys(),d));assertEquals(commits,f.store.commits);
  }));
 }
 @Test void invalidClientCannotRevokeKnownOrUnknownTokens() {
  var one=issued();var before=Map.copyOf(this.store.rows);for(String t:List.of(refresh(one),"bad"))admission(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->revocations(3).revoke(endpoint(OAuthServerRequest.Endpoint.REVOCATION,t,Map.of(),null),(id,b)->Optional.empty(),keys(),deadline()));assertEquals(before,this.store.rows);
 }
 @Test void trustedConflictExhaustionIsUnavailableAndNeverAdvancesEpoch() {
  issued();String id=record(OAuthStoreKey.Kind.GRANT).text("id");var before=Map.copyOf(this.store.rows);this.store.conflicts=5;failed(OAuthStoreFailure.Reason.UNAVAILABLE,()->revocations(3).revokeGrant(id,deadline()));assertEquals(before,this.store.rows);
 }
 @Test void falseRefreshHeadAfterRacingRotationCannotLoseWinnerRevocation() {
  var one=issued();OAuthTokenResponse[] winner={one};this.store.beforeCommit=()->winner[0]=rotate(refresh(one));ordinary(revoke(refresh(one)));invalid(()->validate(token(winner[0])));admission(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,()->rotate(refresh(winner[0])));
 }
 @SuppressWarnings("unchecked") private static <T extends Throwable> void raise(@NonNull Throwable error)throws T{throw(T)error;}
 private static final class TestFatal extends VirtualMachineError {private static final long serialVersionUID=1L;TestFatal(){super("fixture");}}
 private static final class MutableClock extends Clock {
  @NonNull Instant time;MutableClock(@NonNull Instant time){this.time=time;}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){requireNonNull(zone);return this;}
  @Override public @NonNull Instant instant(){return this.time;}
 }
}
