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
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.*;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.jose.Jwks;
import com.revetsec.jose.JwksParseResult;
import com.revetsec.jose.StaticJwksSource;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.function.Executable;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZoneId;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Local credential admission precedes optional network work; fresh authentication and final store facts remain mandatory. */
final class OAuthCimdAdmissionTests {
 private static final @NonNull String ID="https://client.example.com/metadata", ISSUER="https://issuer.example.com/tenant",
  RESOURCE="https://resource.example.com/mcp", REDIRECT="https://client.example.com/callback", BROWSER="A".repeat(43),
  VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private static final @NonNull Instant NOW=Instant.parse("2026-10-06T12:00:00Z");
 private static final @NonNull OAuthServerIngressLimits LIMITS=OAuthServerIngressLimits.fromDefaults();
 private final @NonNull OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture(NOW);
 private final @NonNull Clock clock=new Clock() {
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
  @Override public @NonNull Instant instant(){return store.authorityNow;}
 };
 private final @NonNull StateSealer sealer=sealer();
 private final @NonNull OAuthStoreRecordCodec codec=new OAuthStoreRecordCodec(ISSUER,this.sealer,3800);
 private final @NonNull OAuthStoreCoordinator coordinator=new OAuthStoreCoordinator(this.store,this.codec,this.clock,3,255);
 private final @NonNull OAuthAuthorizationLedger ledger=new OAuthAuthorizationLedger(this.coordinator,this.codec,LIMITS,Duration.ofMinutes(15),Duration.ofMinutes(2),3,255,true);
 private final @NonNull OAuthGrantRetention retention=new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ofSeconds(30),Duration.ofSeconds(10),Duration.ofSeconds(60));
 private final OAuthTokenResponse.@NonNull Encoder encoder=encoder();
 private final @NonNull OAuthCodeRedemption codes=new OAuthCodeRedemption(this.coordinator,this.codec,LIMITS,this.retention,this.encoder,Duration.ofMinutes(5),true,Duration.ofDays(1),Duration.ofDays(7),3,255);
 private final @NonNull OAuthRefreshRotation refresh=new OAuthRefreshRotation(this.coordinator,this.codec,LIMITS,this.retention,this.encoder,Duration.ofMinutes(5),true,Duration.ofDays(1),3,255);
 private final @NonNull AtomicInteger fetches=new AtomicInteger(), cacheReads=new AtomicInteger(), cacheWrites=new AtomicInteger(), policies=new AtomicInteger();
 private @NonNull JsonObject document=document();
 private boolean transportFailure;
 private @Nullable Runnable fetchHook;
 private int status=200;
 private final @NonNull InMemoryOAuthClientMetadataCache memory=InMemoryOAuthClientMetadataCache.fromMaximumEntries(128);
 private final @NonNull OAuthClientMetadataCache cache=new OAuthClientMetadataCache() {
  @Override public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(@NonNull OAuthClientMetadataCacheKey key,@NonNull Duration budget) throws OAuthClientMetadataCacheException {
   cacheReads.incrementAndGet();return memory.read(key,budget);
  }
  @Override public @NonNull Boolean compareAndSet(@NonNull OAuthClientMetadataCacheKey key,@Nullable String expected,@Nullable OAuthClientMetadataCacheEntry entry,@NonNull Duration budget) throws OAuthClientMetadataCacheException {
   cacheWrites.incrementAndGet();return memory.compareAndSet(key,expected,entry,budget);
  }
 };
 private final @NonNull OAuthClientMetadataPolicy metadataPolicy=OAuthClientMetadataPolicy.withAddressResolver((host,b)->{throw new AssertionError("deterministic seam");}).cache(this.cache).build();
 private final @NonNull AtomicReference<@Nullable Deadline> observed=new AtomicReference<>();
 private final @NonNull OAuthClientMetadataFetcher fetcher=new OAuthClientMetadataFetcher(ISSUER,this.sealer,this.metadataPolicy,LIMITS,true,true,
  OutboundUriPolicy.defaultInstance(),this.clock,(uri,deadline)->{
   this.fetches.incrementAndGet();this.observed.set(deadline);Runnable hook=this.fetchHook;if(hook!=null)hook.run();
   if(this.transportFailure)throw new IllegalStateException("private transport failure");
   return new RawResponse(this.status,HttpHeaders.of(Map.of("Cache-Control",List.of("max-age=300")),(a,b)->true),this.document.toJson().getBytes(StandardCharsets.UTF_8),null,false,Duration.ZERO);
  });
 private final @NonNull OAuthServerClientSelection dynamic=selection((id,b)->Optional.empty());
 OAuthCimdAdmissionTests() { }
 private static @NonNull StateSealer sealer() {
  byte[] key=new byte[32];for(int i=0;i<32;i++)key[i]=(byte)(i+1);
  return StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key))).clock(Clock.fixed(NOW,ZoneOffset.UTC)).build();
 }
 private static OAuthTokenResponse.@NonNull Encoder encoder() {
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
  return new OAuthTokenResponse.Encoder(ISSUER,"key",JwsSigner.fromRsaKeyPair(key.getPrivateKey(),key.getPublicKey(),JwsAlgorithm.RS256),32768,16384);
 }
 private @NonNull OAuthServerClientSelection selection(@NonNull OAuthServerClientRepository repository) {return new OAuthServerClientSelection(repository,LIMITS,this.fetcher);}
 private static @NonNull Map<@NonNull String,@NonNull Set<@NonNull String>> resources() {return Map.of(RESOURCE,Set.of("read","write"));}
 private static @NonNull Deadline deadline() {return Deadline.fromNow(Duration.ofSeconds(5));}
 private static @NonNull JsonObject document() {
  return JsonObject.builder().put("client_id",ID).put("client_name","Client").put("token_endpoint_auth_method","none")
   .put("redirect_uris",JsonArray.fromElements(List.of(JsonString.fromValue(REDIRECT))))
   .put("grant_types",JsonArray.fromElements(List.of(JsonString.fromValue("authorization_code"),JsonString.fromValue("refresh_token")))).build();
 }
 private static @NonNull OAuthServerClientRegistration registered(boolean confidential) {
  return OAuthServerClientRegistration.withClientId(ID).configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources()).refreshTokenPermitted(true)
   .authentication(confidential?OAuthServerClientAuthentication.fromClientSecretVerifier((i,s,b)->true):null).build();
 }
 private static @NonNull String encode(@NonNull String value) {try{return FormUrlEncoding.encode(value);}catch(com.revetsec.internal.encoding.EncodingException failure){throw new AssertionError(failure);}}
 private static @NonNull OAuthServerRequest authorize(@Nullable String scope,@NonNull String redirect) {
  String q="client_id="+encode(ID)+"&response_type=code&redirect_uri="+encode(redirect)+"&resource="+encode(RESOURCE)+"&code_challenge_method=S256&code_challenge="+CHALLENGE+(scope==null?"":"&scope="+encode(scope));
  return OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",q,new byte[0],Map.of(),LIMITS);
 }
 private static @NonNull OAuthServerRequest token(@NonNull String credential,boolean refresh,@NonNull Map<@NonNull String,@NonNull String> overrides,@Nullable String basic) {
  var fields=new LinkedHashMap<String,String>();fields.put("grant_type",refresh?"refresh_token":"authorization_code");fields.put(refresh?"refresh_token":"code",credential);
  if(!refresh)fields.put("code_verifier",VERIFIER);fields.put("client_id",ID);fields.put("resource",RESOURCE);fields.putAll(overrides);if(basic!=null)fields.remove("client_id");
  String text=String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());
  var headers=new LinkedHashMap<String,List<String>>();headers.put("Content-Type",List.of("application/x-www-form-urlencoded"));if(basic!=null)headers.put("Authorization",List.of(basic));
  return OAuthServerRequest.parse(OAuthServerRequest.Endpoint.TOKEN,"POST",null,text.getBytes(StandardCharsets.UTF_8),headers,LIMITS);
 }
 private static @NonNull String basic() {return "Basic "+Base64.getEncoder().encodeToString((encode(ID)+":secret").getBytes(StandardCharsets.US_ASCII));}
 private static @NonNull OAuthAuthorizationDecision decision(@NonNull String subject) {return OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(resources()).refreshTokenPermitted(true).build();}
 private @NonNull OAuthGrantPolicy allow() {return (context,budget)->{this.policies.incrementAndGet();return OAuthAuthorizationDecision.withSubject(context.getSubject()).authorizedScopesByResource(context.getAuthorizedScopesByResource()).refreshTokenPermitted(context.isRefreshTokenPermitted()).build();};}
 private @NonNull String code() {return code(this.dynamic);}
 private @NonNull String code(@NonNull OAuthServerClientSelection selection) {
  assertEquals(OAuthStoreCommitStatus.COMMITTED,this.coordinator.initializeFreshIssuer(deadline()).getStatus());this.coordinator.establishNewSubject("subject",deadline());
  var admission=OAuthServerAuthorizationAdmission.admit(authorize(null,REDIRECT),selection,deadline(),resources(),LIMITS,true,true);
  String handle=this.ledger.begin(admission,BROWSER,deadline());
  return this.ledger.complete(handle,BROWSER,selection.authorization(ID,resources(),deadline()),resources(),decision("subject"),deadline()).orElseThrow();
 }
 private @NonNull OAuthTokenResponse redeem(@NonNull String credential) {return this.codes.redeem(token(credential,false,Map.of(),null),this.dynamic,resources(),allow(),deadline());}
 private @NonNull OAuthTokenResponse rotate(@NonNull String credential) {return this.refresh.rotate(token(credential,true,Map.of(),null),this.dynamic,resources(),allow(),deadline());}
 private static @NonNull JsonObject body(@NonNull OAuthTokenResponse response) {try{return (JsonObject)JsonCodec.parse(response.body(),JsonLimits.jose(131072));}catch(com.revetsec.internal.json.JsonParseException failure){throw new AssertionError(failure);}}
 private static @NonNull String refreshValue(@NonNull OAuthTokenResponse response) {return body(response).find("refresh_token").map(value -> ((com.revetsec.json.JsonString) value).getValue()).orElseThrow();}
 private @NonNull JsonObject row(OAuthStoreKey.@NonNull Kind kind) {return IssuerTestRecords.open(this.codec,this.store.rows.values().stream().filter(e->e.getKey().getKind()==kind).findFirst().orElseThrow(),Clock.fixed(NOW,ZoneOffset.UTC));}
 private static void failure(OAuthServerAdmissionFailure.@NonNull Reason reason,@NonNull Executable call) {
  var e=assertThrows(OAuthServerAdmissionFailure.class,call);assertEquals(reason,e.reason());assertNull(e.getCause());assertEquals("OAuth server admission failed.",e.getMessage());
 }
 private static void invalid(@NonNull Executable call) {failure(OAuthServerAdmissionFailure.Reason.INVALID_GRANT,call);}

 private @NonNull OAuthGrantRevocation revocations() {
  return new OAuthGrantRevocation(this.coordinator,this.codec,new OAuthIssuerTokenStatus(this.coordinator,this.codec,LIMITS,this.clock,Duration.ofSeconds(30),3,255,16384),LIMITS,3,255,32768,16384);
 }
 private static @NonNull StaticJwksSource keys() {
  return StaticJwksSource.fromJwks(assertInstanceOf(JwksParseResult.Succeeded.class,Jwks.fromJsonResult(TestJwk.withFixture(TestJwk.Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson())).getJwks());
 }
 private static @NonNull OAuthServerRequest revocation(@NonNull String value,@NonNull Map<@NonNull String,@NonNull String> overrides,@Nullable String basic) {
  var fields=new LinkedHashMap<String,String>();fields.put("token",value);fields.put("client_id",ID);fields.putAll(overrides);if(basic!=null)fields.remove("client_id");
  String text=String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());
  var headers=new LinkedHashMap<String,List<String>>();headers.put("Content-Type",List.of("application/x-www-form-urlencoded"));if(basic!=null)headers.put("Authorization",List.of(basic));
  return OAuthServerRequest.parse(OAuthServerRequest.Endpoint.REVOCATION,"POST",null,text.getBytes(StandardCharsets.UTF_8),headers,LIMITS);
 }
 private @NonNull OAuthStatusResponse revoke(@NonNull String credential,@NonNull Map<@NonNull String,@NonNull String> overrides) {
  return this.revocations().revoke(revocation(credential,overrides,null),this.dynamic,resources(),keys(),deadline());
 }
 private static void ordinary(@NonNull Supplier<@NonNull OAuthStatusResponse> action) {
  OAuthStatusResponse response=assertDoesNotThrow(action::get);assertArrayEquals(new byte[0],response.body());
  assertArrayEquals(OAuthStatusResponse.revocation(32768,16384).headers(),response.headers());
 }
 private static @NonNull String access(@NonNull OAuthTokenResponse response) {
  return body(response).find("access_token").map(value->((JsonString)value).getValue()).orElseThrow();
 }
 private @NonNull String grantStatus(){return row(OAuthStoreKey.Kind.GRANT).find("status").map(value->((JsonString)value).getValue()).orElseThrow();}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> publicRevocationRejectsUnknownTokensBeforeInvokingTheProductionResolver() {
  return Stream.of("garbage",OAuthServerCredential.refresh("A".repeat(43))).map(value->DynamicTest.dynamicTest(value,()->{
   var t=new OAuthCimdAdmissionTests();AtomicInteger resolutions=new AtomicInteger();var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
   var policy=OAuthClientMetadataPolicy.fromAddressResolverAndCache((host,budget)->{resolutions.incrementAndGet();return List.of(java.net.InetAddress.getLoopbackAddress());},InMemoryOAuthClientMetadataCache.fromMaximumEntries(16));
   var signing=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
   var server=OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token"))
    .jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke"))
    .clientRepository((id,budget)->Optional.empty()).store(t.store).stateSealer(t.sealer).clock(t.clock)
    .signingKeys(OAuthIssuerKeyProvider.fromSnapshot(signing)).resources(resources()).grantPolicy(t.allow()).clientMetadataPolicy(policy).build();
   assertEquals(OAuthStoreCommitStatus.COMMITTED,server.initializeFreshIssuer().getStatus());
   String body="client_id="+encode(ID)+"&token="+encode(value);
   var result=assertDoesNotThrow(()->server.revokeResult("POST",null,body.getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded"))));
   var response=assertInstanceOf(OAuthRevocationResult.Succeeded.class,result).getResponse();assertEquals(200,response.getStatusCode());assertArrayEquals(new byte[0],response.toHttpBodyWithCredentials());assertEquals(0,resolutions.get());
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unknownRevocationsCannotFetchMetadata() {
  return Stream.of("garbage",".bad","rsr1_bad",OAuthServerCredential.refresh("A".repeat(43)),"a.b.c").map(value->DynamicTest.dynamicTest(value,()->{
   var t=new OAuthCimdAdmissionTests();t.coordinator.initializeFreshIssuer(deadline());t.transportFailure=true;int before=t.fetches.get();
   ordinary(()->t.revoke(value,Map.of()));assertEquals(before,t.fetches.get());
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> wrongOwnerOrResourceRevocationCannotFetchMetadata() {
  return Stream.of(false,true).flatMap(refresh->Stream.of("owner","resource").map(binding->DynamicTest.dynamicTest(refresh+binding,()->{
   var t=new OAuthCimdAdmissionTests();var issued=t.redeem(t.code());String value=refresh?refreshValue(issued):access(issued);int before=t.fetches.get();var rows=Map.copyOf(t.store.rows);t.transportFailure=true;
   var overrides=binding.equals("owner")?Map.of("client_id","https://other.example.com/metadata"):Map.of("resource","https://other.example.com/api");
   ordinary(()->t.revoke(value,overrides));assertEquals(before,t.fetches.get());assertEquals(rows,t.store.rows);assertEquals("ACTIVE",t.grantStatus());
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> revokedGrantsCannotFetchAgain() {
  return Stream.of(false,true).map(refresh->DynamicTest.dynamicTest("refresh="+refresh,()->{
   var t=new OAuthCimdAdmissionTests();var issued=t.redeem(t.code());String value=refresh?refreshValue(issued):access(issued);
   ordinary(()->t.revoke(value,Map.of()));assertEquals("REVOKED",t.grantStatus());int before=t.fetches.get();t.transportFailure=true;var rows=Map.copyOf(t.store.rows);
   ordinary(()->t.revoke(value,Map.of()));assertEquals(before,t.fetches.get());assertEquals(rows,t.store.rows);
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> revokedEpochsCannotFetchMetadata() {
  return Stream.of(false,true).flatMap(refresh->Stream.of(false,true).map(issuer->DynamicTest.dynamicTest(refresh+"/issuer="+issuer,()->{
   var t=new OAuthCimdAdmissionTests();var issued=t.redeem(t.code());String value=refresh?refreshValue(issued):access(issued);
   if(issuer)t.coordinator.revokeAll(deadline());else t.coordinator.revokeSubject("subject",deadline());
   int before=t.fetches.get();t.transportFailure=true;ordinary(()->t.revoke(value,Map.of()));assertEquals(before,t.fetches.get());
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> expiredUnusedCredentialsCannotFetchMetadata() {
  return Stream.of(false,true).map(refresh->DynamicTest.dynamicTest("refresh="+refresh,()->{
   var t=new OAuthCimdAdmissionTests();String value=refresh?refreshValue(t.redeem(t.code())):t.code();int before=t.fetches.get();
   t.store.authorityNow=NOW.plus(refresh?Duration.ofDays(1):Duration.ofMinutes(2));t.transportFailure=true;
   invalid(()->{if(refresh)t.rotate(value);else t.redeem(value);});assertEquals(before,t.fetches.get());
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> cancelledOrPreviouslyRevokedCodeCannotFetchMetadata() {
  return Stream.of(false,true).map(used->DynamicTest.dynamicTest("used="+used,()->{
   var t=new OAuthCimdAdmissionTests();String value=t.code();
   if(used){t.redeem(value);invalid(()->t.redeem(value));}
   else invalid(()->t.codes.redeem(token(value,false,Map.of(),null),t.dynamic,resources(),(context,budget)->OAuthAuthorizationDecision.deniedInstance(),deadline()));
   int before=t.fetches.get();t.transportFailure=true;invalid(()->t.redeem(value));assertEquals(before,t.fetches.get());
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidCodeBindingsCannotFetchForUnusedOrUsedCode() {
  return Stream.of(false,true).flatMap(used->Stream.of("code_verifier","resource","redirect_uri").map(binding->DynamicTest.dynamicTest(used+binding,()->{
   var t=new OAuthCimdAdmissionTests();String value=t.code();if(used)t.redeem(value);int before=t.fetches.get();int commits=t.store.commits;
   String other=binding.equals("code_verifier")?"x".repeat(43):"https://other.example.com/value";t.transportFailure=true;
   invalid(()->t.codes.redeem(token(value,false,Map.of(binding,other),null),t.dynamic,resources(),t.allow(),deadline()));
   assertEquals(before,t.fetches.get());assertEquals(commits,t.store.commits);
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> wrongResourceCannotFetchForUnusedOrUsedRefresh() {
  return Stream.of(false,true).map(used->DynamicTest.dynamicTest("used="+used,()->{
   var t=new OAuthCimdAdmissionTests();String value=refreshValue(t.redeem(t.code()));if(used)t.rotate(value);int before=t.fetches.get();t.transportFailure=true;
   invalid(()->t.refresh.rotate(token(value,true,Map.of("resource","https://other.example.com/api"),null),t.dynamic,resources(),t.allow(),deadline()));assertEquals(before,t.fetches.get());
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> deadEpochsCannotDriveTokenFetches() {
  return Stream.of(false,true).flatMap(refresh->Stream.of(false,true).map(issuer->DynamicTest.dynamicTest(refresh+"/issuer="+issuer,()->{
   var t=new OAuthCimdAdmissionTests();String value=refresh?refreshValue(t.redeem(t.code())):t.code();int before=t.fetches.get();
   if(issuer)t.coordinator.revokeAll(deadline());else t.coordinator.revokeSubject("subject",deadline());t.transportFailure=true;
   invalid(()->{if(refresh)t.rotate(value);else t.redeem(value);});assertEquals(before,t.fetches.get());
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> boundReplayFetchesOnceThenRejectsWithoutNetworkWork() {
  return Stream.of(false,true).map(refresh->DynamicTest.dynamicTest("refresh="+refresh,()->{
   var t=new OAuthCimdAdmissionTests();String value=refresh?refreshValue(t.redeem(t.code())):t.code();
   if(refresh)t.rotate(value);else t.redeem(value);int before=t.fetches.get();
   invalid(()->{if(refresh)t.rotate(value);else t.redeem(value);});assertEquals(before+1,t.fetches.get());assertEquals("REVOKED",t.grantStatus());
   t.transportFailure=true;invalid(()->{if(refresh)t.rotate(value);else t.redeem(value);});assertEquals(before+1,t.fetches.get());
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> finalReadStillRejectsExpiryOrEpochChangeDuringFetch() {
  return Stream.of(false,true).flatMap(refresh->Stream.of(false,true).map(epoch->DynamicTest.dynamicTest(refresh+"/epoch="+epoch,()->{
   var t=new OAuthCimdAdmissionTests();String value=refresh?refreshValue(t.redeem(t.code())):t.code();int before=t.fetches.get();
   t.fetchHook=()->{if(epoch)t.coordinator.revokeSubject("subject",deadline());else t.store.authorityNow=NOW.plus(refresh?Duration.ofDays(1):Duration.ofMinutes(2));};
   invalid(()->{if(refresh)t.rotate(value);else t.redeem(value);});assertEquals(before+1,t.fetches.get());assertEquals(refresh?"ACTIVE":"PENDING",t.grantStatus());
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> retainedExpiredCredentialsCanStillRevokeAnActiveGrant() {
  return Stream.of(false,true).map(refresh->DynamicTest.dynamicTest("refresh="+refresh,()->{
   var t=new OAuthCimdAdmissionTests();var issued=t.redeem(t.code());String value=refresh?refreshValue(issued):access(issued);int before=t.fetches.get();
   t.store.authorityNow=NOW.plus(refresh?Duration.ofDays(2):Duration.ofMinutes(6));
   ordinary(()->t.revoke(value,Map.of()));assertEquals(before+1,t.fetches.get());assertEquals("REVOKED",t.grantStatus());
  }));
 }
 @Test void liveRevocationRequiresFreshMetadataAndRechecksAfterTheFetch() {
  var issued=redeem(code());String value=refreshValue(issued);int before=this.fetches.get();int commits=this.store.commits;this.transportFailure=true;
  failure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->revoke(value,Map.of()));assertEquals(before+1,this.fetches.get());assertEquals(commits,this.store.commits);assertEquals("ACTIVE",grantStatus());
  this.transportFailure=false;this.fetchHook=()->this.coordinator.revokeSubject("subject",deadline());ordinary(()->revoke(value,Map.of()));assertEquals("ACTIVE",grantStatus());
 }
 @Test void registeredConfidentialAndBasicAuthenticationCannotUseTheMetadataNoop() {
  var registered=selection((id,budget)->Optional.of(registered(true)));int before=this.fetches.get();
  failure(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->revocations().revoke(revocation("garbage",Map.of(),null),registered,resources(),keys(),deadline()));
  failure(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->revocations().revoke(revocation("garbage",Map.of(),basic()),this.dynamic,resources(),keys(),deadline()));
  assertEquals(before,this.fetches.get());
 }
 private void replaceField(OAuthStoreKey.@NonNull Kind kind,@NonNull String name,@NonNull JsonValue value) {
  var entry=this.store.rows.values().stream().filter(item->item.getKey().getKind()==kind).findFirst().orElseThrow();
  var members=new LinkedHashMap<>(IssuerTestRecords.open(this.codec,entry,this.clock).getMembers());members.put(name,value);
  Instant retention=kind==OAuthStoreKey.Kind.GRANT && name.equals("horizon") ? Instant.ofEpochSecond(((JsonNumber)value).getValue().longValueExact()) : entry.getRetainUntil();
  this.store.rows.put(entry.getKey(),IssuerTestRecords.seal(this.codec,entry.getKey(),retention,JsonObject.fromMembers(members).toJson()));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> contradictoryAuthenticatedRecordsCannotSpendFetchCapacity() {
  return Stream.of("code","refresh","revoke-refresh","revoke-access").map(kind->DynamicTest.dynamicTest(kind,()->{
   var t=new OAuthCimdAdmissionTests();String value;
   if(kind.equals("code")){value=t.code();t.replaceField(OAuthStoreKey.Kind.CODE,"issuerEpoch",JsonNumber.fromValue(((JsonNumber)t.row(OAuthStoreKey.Kind.CODE).find("issuerEpoch").orElseThrow()).getValue().longValueExact()+1));}
   else {
    var issued=t.redeem(t.code());value=kind.equals("revoke-access")?access(issued):refreshValue(issued);
    if(kind.equals("refresh")){
     String head=((JsonString)t.row(OAuthStoreKey.Kind.GRANT).find("refreshId").orElseThrow()).getValue();
     t.replaceField(OAuthStoreKey.Kind.GRANT,"refreshId",JsonString.fromValue((head.charAt(0)=='A'?"B":"A")+head.substring(1)));
    }
    else if(kind.equals("revoke-refresh"))t.replaceField(OAuthStoreKey.Kind.GRANT,"horizon",JsonNumber.fromValue(((JsonNumber)t.row(OAuthStoreKey.Kind.GRANT).find("horizon").orElseThrow()).getValue().longValueExact()+1));
    else t.replaceField(OAuthStoreKey.Kind.ACCESS_TOKEN,"resource",JsonString.fromValue("https://other.example.com/api"));
   }
   int before=t.fetches.get();t.transportFailure=true;
   var failed=assertThrows(OAuthStoreFailure.class,()->{if(kind.equals("code"))t.redeem(value);else if(kind.equals("refresh"))t.rotate(value);else t.revoke(value,Map.of());});
   assertEquals(OAuthStoreFailure.Reason.CORRUPT_STATE,failed.reason());assertEquals(before,t.fetches.get());
  }));
 }
 @Test void noOpBarrierKeepsCredentialExpiryAndSettlesItsExactExpiryAsOrdinaryRevocation() {
  var issued=redeem(code());String value=access(issued);
  Instant expiry=this.store.rows.values().stream().filter(item->item.getKey().getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN).findFirst().orElseThrow().getRetainUntil();
  int before=this.fetches.get();this.transportFailure=true;AtomicReference<OAuthStoreTransaction> boundary=new AtomicReference<>();
  this.store.beforeCommit=()->{boundary.set(requireNonNull(this.store.lastTransaction));this.store.authorityNow=expiry;};
  ordinary(()->revoke(value,Map.of("client_id","https://other.example.com/metadata")));
  assertEquals(before,this.fetches.get());assertEquals("ACTIVE",grantStatus());
  assertEquals(Optional.of(expiry),requireNonNull(boundary.get()).getTemporalCondition().orElseThrow().getValidBeforeExclusive());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> metadataPreReadsRetryMixedRefreshHeadWithoutFalseCorruption() {
  return Stream.of(false,true).flatMap(revocation->Stream.of(false,true).map(terminal->DynamicTest.dynamicTest("revocation="+revocation+"/terminal="+terminal,()->{
   var t=new OAuthCimdAdmissionTests();String value=refreshValue(t.redeem(t.code()));int before=t.fetches.get();
   AtomicInteger reads=new AtomicInteger();AtomicReference<Runnable> hook=new AtomicReference<>();
   hook.set(()->{
    if(reads.incrementAndGet()==3){
     t.rotate(value);
     if(terminal)t.revocations().revokeGrant(((JsonString)t.row(OAuthStoreKey.Kind.GRANT).find("id").orElseThrow()).getValue(),deadline());
    }else t.store.beforeRead=hook.get();
   });t.store.beforeRead=hook.get();
   if(revocation)ordinary(()->t.revoke(value,Map.of()));else invalid(()->t.rotate(value));
   assertEquals(before+(terminal?1:2),t.fetches.get());assertEquals("REVOKED",t.grantStatus());
  })));
 }
 @Test void unknownCredentialNoopStillConfirmsAbsenceAndBoundsConflicts() {
  this.coordinator.initializeFreshIssuer(deadline());int commits=this.store.commits;this.store.conflicts=1;this.transportFailure=true;
  ordinary(()->revoke(OAuthServerCredential.refresh("A".repeat(43)),Map.of()));assertEquals(commits+2,this.store.commits);assertEquals(0,this.fetches.get());
  commits=this.store.commits;this.store.conflicts=3;
  var failure=assertThrows(OAuthStoreFailure.class,()->revoke(OAuthServerCredential.refresh("B".repeat(42)+"A"),Map.of()));assertEquals(OAuthStoreFailure.Reason.UNAVAILABLE,failure.reason());assertEquals(commits+3,this.store.commits);assertEquals(0,this.fetches.get());
 }
}
