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
import com.revetsec.internal.http.RawResponse;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Public issuer outcomes and retained-state checks through the actual metadata coordinator; no production hook. */
final class OAuthCimdHttpStatusTests {
 private static final String ISSUER="https://issuer.example.com/tenant", ID="https://client.example.com/metadata",
   RESOURCE="https://resource.example.com/mcp", REDIRECT="https://client.example.com/callback", BROWSER="A".repeat(43),
   VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
   REMOTE="private-remote-status-diagnostic";
 private static final Instant NOW=Instant.parse("2026-10-31T12:00:00Z");
 private static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
 private static final OAuthServerIngressLimits LIMITS=OAuthServerIngressLimits.fromDefaults();
 private static final Map<String,Set<String>> RESOURCES=Map.of(RESOURCE,Set.of("read"));
 private static final List<Integer> REJECTED=List.of(401,403,404,410);
 private static @NonNull Deadline deadline(){return Deadline.fromNow(Duration.ofSeconds(5));}
 private static @NonNull String encode(@NonNull String value){try{return FormUrlEncoding.encode(value);}catch(Exception failure){throw new AssertionError(failure);}}
 private static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> values){return String.join("&",values.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());}
 private static byte @NonNull [] bytes(@NonNull String value){return value.getBytes(StandardCharsets.UTF_8);}
 private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(){return Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));}
 private static @NonNull JsonObject json(@NonNull OAuthServerResponse response){try{return (JsonObject)JsonCodec.parse(response.toHttpBodyWithCredentials(),JsonLimits.protocolDocument(131072));}catch(Exception failure){throw new AssertionError(failure);}}
 private static @NonNull String value(@NonNull OAuthServerResponse response,@NonNull String name){return ((JsonString)requireNonNull(json(response).getMembers().get(name))).getValue();}
 private static @NonNull OAuthAuthorizationDecision decision(){return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(RESOURCES).refreshTokenPermitted(true).build();}
 private static @NonNull StateSealer sealer(){byte[] key=new byte[32];for(int i=0;i<key.length;i++)key[i]=(byte)(i+1);return StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key))).clock(CLOCK).build();}
 private static byte @NonNull [] document(){return bytes(JsonObject.builder().put("client_id",ID).put("client_name","Client").put("token_endpoint_auth_method","none")
   .put("redirect_uris",JsonArray.fromElements(List.of(JsonString.fromValue(REDIRECT))))
   .put("grant_types",JsonArray.fromElements(List.of(JsonString.fromValue("authorization_code"),JsonString.fromValue("refresh_token")))).build().toJson());}
 private static @NonNull OAuthServerResponse rejection(@NonNull Object result,OAuthServerException.@NonNull Reason reason){
  if(result instanceof OAuthAuthorizationResult.Rejected rejected){assertEquals(reason,rejected.getReason());return rejected.getResponse();}
  if(result instanceof OAuthTokenResult.Rejected rejected){assertEquals(reason,rejected.getReason());return rejected.getResponse();}
  OAuthRevocationResult.Rejected rejected=assertInstanceOf(OAuthRevocationResult.Rejected.class,result);assertEquals(reason,rejected.getReason());return rejected.getResponse();
 }
 private static void localError(@NonNull OAuthServerResponse response,int status,@NonNull String error){
  assertEquals(status,response.getStatusCode());assertEquals("{\"error\":\""+error+"\"}",new String(response.toHttpBodyWithCredentials(),StandardCharsets.US_ASCII));
  assertTrue(response.getLocationWithCredentials().isEmpty());assertTrue(response.getHeaders().keySet().stream().noneMatch(n->n.equalsIgnoreCase("Location")||n.equalsIgnoreCase("WWW-Authenticate")||n.equalsIgnoreCase("Retry-After")));
  assertFalse(response.getHeaders().toString().contains(REMOTE));assertEquals(List.of("no-store"),response.getHeaders().get("Cache-Control"));
 }
 private static void admission(OAuthServerAdmissionFailure.@NonNull Reason reason,org.junit.jupiter.api.function.@NonNull Executable operation){
  var failure=assertThrows(OAuthServerAdmissionFailure.class,operation);assertEquals(reason,failure.reason());assertNull(failure.getCause());assertEquals(0,failure.getSuppressed().length);assertEquals("OAuth server admission failed.",failure.getMessage());
 }
 private static final class Fixture {
  final OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture(NOW);
  final AtomicInteger fetches=new AtomicInteger(),reads=new AtomicInteger(),writes=new AtomicInteger(),policies=new AtomicInteger(),rejected=new AtomicInteger(),failed=new AtomicInteger();
  final AtomicReference<@Nullable OAuthServerClientRegistration> registered=new AtomicReference<>();
  final InMemoryOAuthClientMetadataCache memory=InMemoryOAuthClientMetadataCache.fromMaximumEntries(8);
  final OAuthClientMetadataCache cache=new OAuthClientMetadataCache(){
   @Override public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(@NonNull OAuthClientMetadataCacheKey key,@NonNull Duration budget){reads.incrementAndGet();return memory.read(key,budget);}
   @Override public @NonNull Boolean compareAndSet(@NonNull OAuthClientMetadataCacheKey key,@Nullable String expected,@Nullable OAuthClientMetadataCacheEntry entry,@NonNull Duration budget){writes.incrementAndGet();return memory.compareAndSet(key,expected,entry,budget);}
  };
  final OAuthClientMetadataPolicy policy=OAuthClientMetadataPolicy.withAddressResolver((host,budget)->{throw new AssertionError("Deterministic transport only");}).cache(cache).maximumConcurrentFetches(1).build();
  final StateSealer sealer=sealer();
  final OAuthAuthorizationServer server;
  final OAuthClientMetadataFetcher fetcher;
  int status=200;
  String control="no-store";
  boolean dropped;
  @Nullable Runnable transportHook;
  Fixture() throws Exception {
   var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
   var snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
   server=OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token"))
     .jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke")).clientRepository((id,budget)->Optional.ofNullable(registered.get()))
     .store(store).stateSealer(sealer).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(snapshot)).resources(RESOURCES).clock(CLOCK).refreshTokensEnabled(true).clientMetadataPolicy(policy)
     .grantPolicy((context,budget)->{policies.incrementAndGet();return decision();})
     .observer(new OAuthServerObserver(){
      @Override public void didRejectEndpoint(@NonNull Endpoint endpoint,OAuthServerException.@NonNull Reason reason,@Nullable Integer httpStatus,@NonNull Duration elapsed){rejected.incrementAndGet();}
      @Override public void didFailToHandleEndpoint(@NonNull Endpoint endpoint,@NonNull OAuthServerException failure,@NonNull Duration elapsed){failed.incrementAndGet();}
     }).build();
   // Replace only the private transport for tests; public issuer methods and the constructed coordinator remain real.
   var clientsField=OAuthAuthorizationServer.class.getDeclaredField("clients");clientsField.setAccessible(true);
   var metadataField=OAuthServerClientSelection.class.getDeclaredField("metadata");metadataField.setAccessible(true);
   fetcher=(OAuthClientMetadataFetcher)requireNonNull(metadataField.get(requireNonNull(clientsField.get(server))));
   var transportField=OAuthClientMetadataFetcher.class.getDeclaredField("transport");transportField.setAccessible(true);
   transportField.set(fetcher,(OAuthClientMetadataFetcher.Transport)(uri,budget)->{
    assertEquals(URI.create(ID),uri);fetches.incrementAndGet();Runnable hook=transportHook;if(hook!=null)hook.run();
    boolean drop=status>=400&&dropped;
    return new RawResponse(status,HttpHeaders.of(Map.of("Cache-Control",List.of(status==200?control:"max-age=86400"),"Location",List.of("https://other.invalid/"+REMOTE),
      "WWW-Authenticate",List.of("Basic realm=\""+REMOTE+"\""),"Retry-After",List.of("86400")),(a,b)->true),drop?new byte[0]:status==200?document():bytes(REMOTE),null,drop,Duration.ZERO);
   });
   assertEquals(OAuthStoreCommitStatus.COMMITTED,server.initializeFreshIssuer().getStatus());server.establishNewSubject("subject");
  }
  @NonNull OAuthAuthorizationResult begin(){return server.beginAuthorizationResult("GET",form(Map.of("client_id",ID,"response_type","code","redirect_uri",REDIRECT,"resource",RESOURCE,
    "code_challenge_method","S256","code_challenge",CHALLENGE,"state","kept")),new byte[0],Map.of(),BROWSER);}
  @NonNull OAuthServerInteraction interaction(){return assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,begin()).getInteraction();}
  @NonNull String code(){var result=server.completeAuthorizationResult(interaction().getInteractionValue(),BROWSER,decision());String query=requireNonNull(assertInstanceOf(OAuthAuthorizationResult.Completed.class,result).getResponse().getLocationWithCredentials().orElseThrow().getRawQuery());return Stream.of(query.split("&")).filter(p->p.startsWith("code=")).map(p->p.substring(5)).findFirst().orElseThrow();}
  @NonNull OAuthTokenResult redeem(@NonNull String code){return server.tokenResult("POST",null,bytes(form(Map.of("grant_type","authorization_code","client_id",ID,"resource",RESOURCE,"code",code,"code_verifier",VERIFIER,"redirect_uri",REDIRECT))),headers());}
  @NonNull OAuthTokenResult rotate(@NonNull String refresh){return server.tokenResult("POST",null,bytes(form(Map.of("grant_type","refresh_token","client_id",ID,"resource",RESOURCE,"refresh_token",refresh))),headers());}
  @NonNull OAuthRevocationResult revoke(@NonNull String token){return server.revokeResult("POST",null,bytes(form(Map.of("client_id",ID,"token",token))),headers());}
  @NonNull OAuthServerResponse issued(){return assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(code())).getResponse();}
  @NonNull Supplier<@NonNull Object> operation(@NonNull String kind){
   if(kind.equals("begin"))return this::begin;
   if(kind.equals("resume")||kind.equals("complete")){String handle=interaction().getInteractionValue();return ()->kind.equals("resume")?server.resumeAuthorizationResult(handle,BROWSER):server.completeAuthorizationResult(handle,BROWSER,decision());}
   if(kind.equals("code")){String credential=code();return ()->redeem(credential);}
   OAuthServerResponse tokens=issued();String credential=value(tokens,kind.equals("refresh")?"refresh_token":"access_token");
   return ()->kind.equals("refresh")?rotate(credential):revoke(credential);
  }
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> publicEndpointsDistinguishRejectedMetadataFromUnavailableFetches(){
  return Stream.of(401,403,404,410,204,302,304,408,429,503).flatMap(status->Stream.of("begin","resume","complete","code","refresh","revoke").map(endpoint->DynamicTest.dynamicTest(status+" "+endpoint,()->{
   Fixture f=new Fixture();Supplier<Object> call=f.operation(endpoint);var rows=Map.copyOf(f.store.rows);int fetches=f.fetches.get(),writes=f.writes.get(),policies=f.policies.get(),rejected=f.rejected.get(),failed=f.failed.get();f.status=status;
   if(REJECTED.contains(status)){
    localError(rejection(assertDoesNotThrow(call::get),OAuthServerException.Reason.INVALID_CLIENT),400,"invalid_client");
    assertEquals(rejected+1,f.rejected.get());assertEquals(failed,f.failed.get());
   }else{
    OAuthServerTransportException failure=assertThrows(OAuthServerTransportException.class,call::get);assertEquals(OAuthServerException.Reason.CLIENT_METADATA_UNAVAILABLE,failure.getReason());assertFalse(failure.isTemporaryCondition());assertNull(failure.getCause());
    localError(f.server.responseForFailure(failure),503,"server_error");assertEquals(rejected,f.rejected.get());assertEquals(failed+1,f.failed.get());
   }
   assertEquals(fetches+1,f.fetches.get());assertEquals(writes,f.writes.get());assertEquals(policies,f.policies.get());assertEquals(rows,f.store.rows);
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> failuresAreNotCachedOrRetriedAndReleaseBothAdmissionPermits(){
  return REJECTED.stream().flatMap(status->Stream.of(false,true).flatMap(fresh->Stream.of(false,true).map(dropped->DynamicTest.dynamicTest(status+" fresh="+fresh+" dropped="+dropped,()->{
   Fixture f=new Fixture();f.status=status;f.dropped=dropped;
   for(int i=0;i<2;i++)admission(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->{if(fresh)f.fetcher.fresh(ID,deadline());else f.fetcher.reusable(ID,deadline());});
   assertEquals(2,f.fetches.get());assertEquals(fresh?0:2,f.reads.get());assertEquals(0,f.writes.get());
   f.status=200;assertEquals("Client",(fresh?f.fetcher.fresh(ID,deadline()):f.fetcher.reusable(ID,deadline())).clientName());assertEquals(3,f.fetches.get());assertEquals(0,f.writes.get());
  }))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> freshFailureNeitherUsesNorReplacesAnOtherwiseFreshCachedDocument(){
  return REJECTED.stream().map(status->DynamicTest.dynamicTest(status.toString(),()->{
   Fixture f=new Fixture();f.control="max-age=120";assertEquals("Client",f.fetcher.reusable(ID,deadline()).clientName());
   var codec=new OAuthClientMetadataCacheCodec(ISSUER,f.sealer,f.policy,LIMITS,false,false);var key=codec.key(ID);var old=f.memory.read(key,Duration.ofSeconds(1)).orElseThrow();int reads=f.reads.get(),writes=f.writes.get();f.status=status;
   admission(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,()->f.fetcher.fresh(ID,deadline()));assertEquals(reads,f.reads.get());assertEquals(writes,f.writes.get());assertEquals(old,f.memory.read(key,Duration.ofSeconds(1)).orElseThrow());
   assertEquals("Client",f.fetcher.reusable(ID,deadline()).clientName());assertEquals(2,f.fetches.get());
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> statusFailureCannotTriggerBoundReplayInvalidation(){
  return REJECTED.stream().flatMap(status->Stream.of(false,true).map(refresh->DynamicTest.dynamicTest(status+" refresh="+refresh,()->{
   Fixture f=new Fixture();String code=f.code();var issued=assertInstanceOf(OAuthTokenResult.Succeeded.class,f.redeem(code)).getResponse();String credential=refresh?value(issued,"refresh_token"):code;
   if(refresh)assertInstanceOf(OAuthTokenResult.Succeeded.class,f.rotate(credential));var rows=Map.copyOf(f.store.rows);f.status=status;
   Supplier<Object> call=()->refresh?f.rotate(credential):f.redeem(credential);localError(rejection(assertDoesNotThrow(call::get),OAuthServerException.Reason.INVALID_CLIENT),400,"invalid_client");assertEquals(rows,f.store.rows);
   f.status=200;localError(rejection(assertDoesNotThrow(call::get),OAuthServerException.Reason.INVALID_GRANT),400,"invalid_grant");assertNotEquals(rows,f.store.rows);
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> registryBasicAndOpaqueRevocationAdmissionStillPrecedeMetadata(){
  return REJECTED.stream().flatMap(status->Stream.of("registered","basic","unknown-revocation").map(mode->DynamicTest.dynamicTest(status+" "+mode,()->{
   Fixture f=new Fixture();String basicCode=mode.equals("basic")?f.code():"unknown";int before=f.fetches.get();f.status=status;
   if(mode.equals("registered")){
    f.registered.set(OAuthServerClientRegistration.withClientId(ID).configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(RESOURCES).refreshTokenPermitted(true).build());assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,f.begin());
   }else if(mode.equals("basic")){
    String basic=Base64.getEncoder().encodeToString(bytes(encode(ID)+":secret"));var h=Map.of("Content-Type",List.of("application/x-www-form-urlencoded"),"Authorization",List.of("Basic "+basic));
    var result=f.server.tokenResult("POST",null,bytes(form(Map.of("grant_type","authorization_code","code",basicCode,"resource",RESOURCE,"code_verifier",VERIFIER,"redirect_uri",REDIRECT))),h);
    var response=rejection(result,OAuthServerException.Reason.INVALID_CLIENT);assertEquals(401,response.getStatusCode());assertEquals(List.of("Basic realm=\"oauth\""),response.getHeaders().get("WWW-Authenticate"));assertFalse(response.getHeaders().toString().contains(REMOTE));
   }else assertEquals(200,assertInstanceOf(OAuthRevocationResult.Succeeded.class,f.revoke("unknown")).getResponse().getStatusCode());
   assertEquals(before,f.fetches.get());
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> interruptionStillWinsOverAReceivedClientRejection(){
  return REJECTED.stream().map(status->DynamicTest.dynamicTest(status.toString(),()->{
   Fixture f=new Fixture();f.status=status;f.transportHook=()->Thread.currentThread().interrupt();
   try{admission(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,()->f.fetcher.reusable(ID,deadline()));assertTrue(Thread.currentThread().isInterrupted());assertEquals(0,f.writes.get());}finally{Thread.interrupted();}
  }));
 }
}
