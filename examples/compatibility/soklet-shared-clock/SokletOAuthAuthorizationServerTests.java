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
package com.revetsec.soklet;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.oauth.server.*;
import com.revetsec.testing.ScriptedOAuthStore;
import com.soklet.*;
import java.net.URI;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.stream.Stream;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import static org.junit.jupiter.api.Assertions.*;

final class SokletOAuthAuthorizationServerTests {
 private static final String RESOURCE="https://resource.example/mcp",REDIRECT="https://client.example/cb?original=%2f";
 private static final String BINDING="A".repeat(43),VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private static final Clock CLOCK=Clock.fixed(Instant.parse("2026-10-06T12:00:00Z"),ZoneOffset.UTC);
 private static @NonNull OAuthAuthorizationServer server(boolean failing) throws Exception {
  return server(failing, OAuthServerObserver.disabledInstance());
 }
 private static @NonNull OAuthAuthorizationServer server(boolean failing, @NonNull OAuthServerObserver observer) throws Exception {
  return server(new Store(failing),observer);
 }
 private static @NonNull OAuthAuthorizationServer server(@NonNull Store store,@NonNull OAuthServerObserver observer) throws Exception {
  var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);KeyPair pair=generator.generateKeyPair();
  var client=OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT)))
    .allowedScopesByResource(Map.of(RESOURCE,Set.of("read"))).build();
  byte[] sealing=new byte[32];for(int i=0;i<32;i++)sealing[i]=(byte)(i+1);
  var server=OAuthAuthorizationServer.withIssuer("https://issuer.example").authorizationEndpoint(URI.create("https://issuer.example/authorize"))
    .tokenEndpoint(URI.create("https://issuer.example/token")).jwksEndpoint(URI.create("https://issuer.example/jwks"))
    .revocationEndpoint(URI.create("https://issuer.example/revoke")).introspectionEndpoint(URI.create("https://issuer.example/introspect"))
    .clientRepository((id,b)->Optional.of(client)).store(store).clock(CLOCK)
    .stateSealer(StateSealer.withActiveKey(SealingKey.fromBase64("seal",Base64.getEncoder().encodeToString(sealing))).build())
    .signingKeys(OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",pair.getPrivate(),pair.getPublic())).generation("g1").publishedAt(CLOCK.instant().minusSeconds(120)).build()))
    .grantPolicy((c,b)->OAuthAuthorizationDecision.withSubject(c.getSubject()).authorizedScopesByResource(c.getAuthorizedScopesByResource()).build())
    .observer(observer).resources(Map.of(RESOURCE,Set.of("read"))).build();
  if(!store.failing) {assertEquals(OAuthStoreCommitStatus.COMMITTED,server.initializeFreshIssuer().getStatus());server.establishNewSubject("subject");}
  return server;
 }
 private static @NonNull Request post(@NonNull String url,byte @NonNull [] body,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> fields) {
  return Request.withRawUrl(HttpMethod.POST,url).headers(fields).body(body).build();
 }
 private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> fields() {return Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));}
 private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> rawFields(@NonNull Request request) {
  Map<String,List<String>> out=new LinkedHashMap<>();request.getHeaders().forEach((k,v)->out.put(k,List.copyOf(v)));return out;
 }
 private static byte @NonNull [] body(@NonNull MarshaledResponse response) {
  return assertInstanceOf(MarshaledResponseBody.Bytes.class,response.getBody().orElseThrow()).getBytes();
 }
 private static void same(@NonNull OAuthServerResponse a,@NonNull OAuthServerResponse b) {
  assertEquals(a.getStatusCode(),b.getStatusCode());assertEquals(a.getHeaders(),b.getHeaders());assertArrayEquals(a.toHttpBodyWithCredentials(),b.toHttpBodyWithCredentials());assertEquals(a.getLocationWithCredentials(),b.getLocationWithCredentials());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> rawFormsRemainCoreDecisions() {
  return Stream.of("grant_type=authorization_code&code=%FF","grant_type=refresh_token&grant_type=authorization_code","grant_type=%","grant_type=client_credentials","grant_type=refresh_token&client_id=client&refresh_token=x","a="+"x".repeat(65536))
   .map(form->DynamicTest.dynamicTest("raw form bytes "+form.length(),()->{
    var s=server(false);var request=post("/token",form.getBytes(StandardCharsets.UTF_8),fields());
    same(assertInstanceOf(OAuthTokenResult.Rejected.class,s.tokenResult("POST",null,request.getBody().orElseThrow(),rawFields(request))).getResponse(),
      assertInstanceOf(OAuthTokenResult.Rejected.class,SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.tokenResultFor(s,request))).getResponse());
   }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> everyDistinctPhysicalFieldReachesCore() {
  return Stream.of("Content-Type","Authorization","Content-Encoding").map(name->DynamicTest.dynamicTest(name,()->{
   var s=server(false);var request=SokletRawInputTests.fromPhysicalHeaders(HttpMethod.POST,"/token",List.of(Map.entry("Content-Type","application/x-www-form-urlencoded"),Map.entry(name,name.equals("Content-Type")?"text/plain":"first"),Map.entry(name.toUpperCase(Locale.ROOT),"second")),"grant_type=authorization_code".getBytes(StandardCharsets.UTF_8));
   same(assertInstanceOf(OAuthTokenResult.Rejected.class,s.tokenResult("POST",null,request.getBody().orElseThrow(),rawFields(request))).getResponse(),assertInstanceOf(OAuthTokenResult.Rejected.class,SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.tokenResultFor(s,request))).getResponse());
  }));
 }
 @Test void methodAndQueryRejectionsUsePreparedCoreResponses() throws Exception {
  var s=server(false);var request=Request.fromRawUrl(HttpMethod.GET,"/token?raw=x%2By");
  same(assertInstanceOf(OAuthTokenResult.Rejected.class,s.tokenResult("GET","raw=x%2By",new byte[0],Map.of())).getResponse(),assertInstanceOf(OAuthTokenResult.Rejected.class,SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.tokenResultFor(s,request))).getResponse());
  assertEquals(405,assertInstanceOf(OAuthRevocationResult.Rejected.class,SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.revocationResultFor(s,request))).getResponse().getStatusCode());
  assertEquals(405,assertInstanceOf(OAuthIntrospectionResult.Rejected.class,SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.introspectionResultFor(s,request))).getResponse().getStatusCode());
 }
 @Test void discardedOversizedBodyFailsClosedAtEveryIssuerIngress() throws Exception {
  var calls = new java.util.concurrent.atomic.AtomicInteger();
  var observer = new OAuthServerObserver() {
   @Override public void willHandleEndpoint(@NonNull Endpoint endpoint) { calls.incrementAndGet(); }
  };
  var s=server(false, observer);
  int before=calls.get();
  var request=Request.withRawUrl(HttpMethod.POST,"/issuer")
    .headers(fields()).contentTooLarge(true).build();
  assertInstanceOf(SokletRequestResult.TooLarge.class, SokletOAuthAuthorizationServer.beginAuthorizationResultFor(s,request,BINDING));
  assertInstanceOf(SokletRequestResult.TooLarge.class, SokletOAuthAuthorizationServer.tokenResultFor(s,request));
  assertInstanceOf(SokletRequestResult.TooLarge.class, SokletOAuthAuthorizationServer.revocationResultFor(s,request));
  assertInstanceOf(SokletRequestResult.TooLarge.class, SokletOAuthAuthorizationServer.introspectionResultFor(s,request));
  assertEquals(before,calls.get(), "discarded bodies must not invoke the issuer engine");
 }
 @Test void authorizationRetainsEncodedRedirectRawQueryAndIndependentBinding() throws Exception {
  var s=server(false);String query="client_id=client&response_type=code&redirect_uri="+java.net.URLEncoder.encode(REDIRECT,StandardCharsets.UTF_8)+"&resource="+java.net.URLEncoder.encode(RESOURCE,StandardCharsets.UTF_8)+"&code_challenge="+CHALLENGE+"&code_challenge_method=S256&state=raw%2Bstate";
  var request=Request.fromRawUrl(HttpMethod.GET,"/authorize?"+query);
  var interaction=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.beginAuthorizationResultFor(s,request,BINDING))).getInteraction();
  assertInstanceOf(OAuthAuthorizationResult.Rejected.class,s.resumeAuthorizationResult(interaction.getInteractionValue(),"B".repeat(42)+"A"));
  var completed=assertInstanceOf(OAuthAuthorizationResult.Completed.class,s.completeAuthorizationResult(interaction.getInteractionValue(),BINDING,OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(RESOURCE,Set.of("read"))).build()));
  var prepared=completed.getResponse();var response=SokletOAuthAuthorizationServer.responseFor(prepared);
  assertEquals(303,response.getStatusCode());assertEquals(List.of(prepared.getLocationWithCredentials().orElseThrow().toASCIIString()),response.getHeaders().get("Location"));assertArrayEquals(prepared.toHttpBodyWithCredentials(),body(response));
  assertTrue(Objects.requireNonNull(response.getHeaders().get("Location")).iterator().next().startsWith(REDIRECT+"&code="));
  String location=prepared.getLocationWithCredentials().orElseThrow().toString();String code=location.substring(location.indexOf("code=")+5,location.indexOf("&state="));
  String form="grant_type=authorization_code&client_id=client&resource="+java.net.URLEncoder.encode(RESOURCE,StandardCharsets.UTF_8)+"&redirect_uri="+java.net.URLEncoder.encode(REDIRECT,StandardCharsets.UTF_8)+"&code="+code+"&code_verifier="+VERIFIER;
  var token=assertInstanceOf(OAuthTokenResult.Succeeded.class,SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.tokenResultFor(s,post("/token",form.getBytes(StandardCharsets.UTF_8),fields())))).getResponse();
  assertArrayEquals(token.toHttpBodyWithCredentials(),body(SokletOAuthAuthorizationServer.responseFor(token)));
 }
 @Test void metadataJwksAndHeadEmitExactBodies() throws Exception {
  var s=server(false);for(var prepared:List.of(s.metadataResponse("GET"),s.metadataResponse("HEAD"),s.jwksResponse("GET"),s.jwksResponse("HEAD"))) {
   var response=SokletOAuthAuthorizationServer.responseFor(prepared);assertEquals(prepared.getStatusCode(),response.getStatusCode());assertArrayEquals(prepared.toHttpBodyWithCredentials(),body(response));
   prepared.getHeaders().forEach((k,v)->assertEquals(List.copyOf(v),response.getHeaders().get(k)));
  }
 }
 @Test void issuerResponseRejectsEncodedControlWithoutLeakingCredential() throws Exception {
  Constructor<OAuthServerResponse> constructor=OAuthServerResponse.class.getDeclaredConstructor(int.class,Map.class,URI.class,byte[].class,byte[].class);
  constructor.setAccessible(true);
  OAuthServerResponse unsafe=constructor.newInstance(303,Map.of(),URI.create("https://client.example/cb?code=private-secret&x=%0A"),new byte[0],new byte[0]);
  IllegalArgumentException failure=assertThrows(IllegalArgumentException.class,()->SokletOAuthAuthorizationServer.responseFor(unsafe));
  assertFalse(Objects.requireNonNull(failure.getMessage()).contains("private-secret"));
 }
 @Test void infrastructureFailurePropagatesAsTypedFailure() throws Exception {
  var s=server(true);String query="client_id=client&response_type=code&redirect_uri="+java.net.URLEncoder.encode(REDIRECT,StandardCharsets.UTF_8)+"&resource="+java.net.URLEncoder.encode(RESOURCE,StandardCharsets.UTF_8)+"&code_challenge="+CHALLENGE+"&code_challenge_method=S256";
  var failure=assertThrows(OAuthServerException.class,()->SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.beginAuthorizationResultFor(s,Request.fromRawUrl(HttpMethod.GET,"/authorize?"+query),BINDING)));assertFalse(Objects.requireNonNull(failure.getMessage()).contains("private-storage-diagnostic"));
 }
 @Test @SuppressWarnings("NullAway") void requiredPrimaryArgumentsRejectNull() throws Exception {
  var s=server(false);var r=Request.fromPath(HttpMethod.GET,"/");
  assertThrows(NullPointerException.class,()->SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.tokenResultFor(null,r)));assertThrows(NullPointerException.class,()->SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.tokenResultFor(s,null)));
  assertThrows(NullPointerException.class,()->SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.beginAuthorizationResultFor(s,r,null)));assertThrows(NullPointerException.class,()->SokletOAuthAuthorizationServer.responseFor(null));
 }
 @Test void genuineConsumptionKeepsTrustedCommitReasonsAndGenericWireParity() throws Exception {
  byte[] firstBody=null;
  for(String mode:List.of("confirmed","unknown")){
   var store=new Store(false);var s=server(store,OAuthServerObserver.disabledInstance());
   String query="client_id=client&response_type=code&redirect_uri="+java.net.URLEncoder.encode(REDIRECT,StandardCharsets.UTF_8)+"&resource="+java.net.URLEncoder.encode(RESOURCE,StandardCharsets.UTF_8)+"&code_challenge="+CHALLENGE+"&code_challenge_method=S256";
   var interaction=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,s.beginAuthorizationResult("GET",query,new byte[0],Map.of(),BINDING)).getInteraction();
   var approved=assertInstanceOf(OAuthAuthorizationResult.Completed.class,s.completeAuthorizationResult(interaction.getInteractionValue(),BINDING,OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(RESOURCE,Set.of("read"))).build()));
   String location=approved.getResponse().getLocationWithCredentials().orElseThrow().toASCIIString();String code=location.substring(location.indexOf("code=")+5);
   String form="grant_type=authorization_code&client_id=client&resource="+java.net.URLEncoder.encode(RESOURCE,StandardCharsets.UTF_8)+"&redirect_uri="+java.net.URLEncoder.encode(REDIRECT,StandardCharsets.UTF_8)+"&code="+code+"&code_verifier="+VERIFIER;
   store.mode=mode;
   var failure=assertThrows(OAuthServerStoreException.class,()->SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.tokenResultFor(s,post("/token",form.getBytes(StandardCharsets.UTF_8),fields()))));
   assertEquals(mode.equals("confirmed")?OAuthServerException.Reason.COMMIT_CONFIRMED_NOT_ADMITTED:OAuthServerException.Reason.COMMIT_OUTCOME_UNKNOWN,failure.getReason());
   assertFalse(failure.isTransient());var response=SokletOAuthAuthorizationServer.responseFor(s.responseForFailure(failure));
   assertEquals(503,response.getStatusCode());assertArrayEquals("{\"error\":\"server_error\"}".getBytes(StandardCharsets.UTF_8),body(response));
   for(String header:List.of("Location","Set-Cookie","Retry-After"))assertFalse(response.getHeaders().containsKey(header));
   if(firstBody==null)firstBody=body(response);else assertArrayEquals(firstBody,body(response));
   assertEquals(1,store.effects);assertEquals(mode.equals("confirmed")?1:0,store.finalReads);
   assertNotNull(store.consumedKey);assertEquals(store.consumedVersion,store.delegate.records().get(store.consumedKey).getVersion());
   assertInstanceOf(OAuthTokenResult.Rejected.class,SokletTransportFixtures.completed(SokletOAuthAuthorizationServer.tokenResultFor(s,post("/token",form.getBytes(StandardCharsets.UTF_8),fields()))));
  }
 }
 private static final class Store implements OAuthAuthorizationServerStore {
  private final @NonNull ScriptedOAuthStore delegate=new ScriptedOAuthStore(CLOCK.instant());
  private final boolean failing;
  private @NonNull String mode="none";
  private boolean refuseFinal;
  private int effects,finalReads;
  private @Nullable OAuthStoreKey consumedKey;
  private @Nullable String consumedVersion;
  Store(boolean failing){this.failing=failing;}
  @Override public synchronized @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){
   if(this.failing)throw new IllegalStateException("private-storage-diagnostic");
   if(this.refuseFinal){this.refuseFinal=false;this.finalReads++;assertEquals(OAuthStoreKey.Kind.ISSUER_STATE,key.getKind());return OAuthStoreReadResult.Unavailable.get();}
   return this.delegate.read(key,budget);
  }
  @Override public synchronized @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction tx,@NonNull Duration budget){
   if(this.failing)throw new IllegalStateException("private-storage-diagnostic");
   var result=this.delegate.commit(tx,budget);
   boolean code=false,access=false;
   for(var mutation:tx.getMutations()){if(mutation.getKey().getKind()==OAuthStoreKey.Kind.CODE)code=true;if(mutation.getKey().getKind()==OAuthStoreKey.Kind.ACCESS_TOKEN)access=true;}
   if(result.getStatus()==OAuthStoreCommitStatus.COMMITTED && code && access && !this.mode.equals("none")){
    this.effects++;for(var mutation:tx.getMutations())if(mutation.getKey().getKind()==OAuthStoreKey.Kind.CODE){this.consumedKey=mutation.getKey();this.consumedVersion=mutation.getEntry().orElseThrow().getVersion();}
    String selected=this.mode;this.mode="none";if(selected.equals("unknown"))return OAuthStoreCommitReceipt.unknownInstance();this.refuseFinal=true;
   }
   return result;
  }
 }
}
