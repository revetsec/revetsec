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

import com.revetsec.oauth.BearerToken;
import com.revetsec.oauth.BearerTokenResult;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonArray;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit localhost authority matching and public issuer transitions; reflection supports original-source contrasts. */
final class OAuthLocalhostAnyPortTests {
 private static final String ISSUER="https://issuer.example.com/tenant",RESOURCE="https://resource.example.com/mcp",BROWSER="A".repeat(43),
   VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private static final Instant NOW=Instant.parse("2026-10-31T12:00:00Z");
 private static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
 private static final Map<String,Set<String>> RESOURCES=Map.of(RESOURCE,Set.of("read"));
 private static final OAuthServerIngressLimits LIMITS=OAuthServerIngressLimits.fromDefaults();
 private static @Nullable Method setter(){try{return OAuthAuthorizationServer.Builder.class.getMethod("allowLocalhostAnyPortRedirects",Boolean.class);}catch(NoSuchMethodException absent){return null;}}
 private static OAuthAuthorizationServer.@NonNull Builder anyPort(OAuthAuthorizationServer.@NonNull Builder builder,@Nullable Boolean value) throws Exception {
  Method method=setter();if(method==null)return builder;return (OAuthAuthorizationServer.Builder)requireNonNull(method.invoke(builder,value));
 }
 private static @NonNull OAuthServerClientRegistration client(@NonNull String @NonNull ... redirects){return OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").redirectUris(Arrays.stream(redirects).map(URI::create).toList()).allowedScopesByResource(RESOURCES).refreshTokenPermitted(true).build();}
 private static boolean matches(@NonNull String registered,@NonNull String supplied,boolean ip,boolean exact,boolean any) throws Exception {
  try{var method=OAuthServerAuthorizationAdmission.class.getDeclaredMethod("matchesRedirect",OAuthServerClientRegistration.class,String.class,boolean.class,boolean.class,boolean.class);method.setAccessible(true);return (Boolean)requireNonNull(method.invoke(null,client(registered),supplied,ip,exact,any));}
  catch(NoSuchMethodException absent){return OAuthServerAuthorizationAdmission.matchesRedirect(client(registered),supplied,ip,exact);}
  catch(InvocationTargetException failure){throw new AssertionError(failure.getCause());}
 }
 private static @NonNull JsonObject json(byte @NonNull [] body) throws Exception {return (JsonObject)JsonCodec.parse(body,JsonLimits.protocolDocument(131072));}
 private static @NonNull JsonObject claude() throws Exception {try(var input=requireNonNull(OAuthLocalhostAnyPortTests.class.getResourceAsStream("/cimd/mcp-profile/claude-code-client-metadata.json"))){return json(input.readAllBytes());}}
 private static @NonNull JsonObject document(@NonNull String redirect){return JsonObject.builder().put("client_id","https://client.example.com/metadata").put("client_name","Client").put("token_endpoint_auth_method","none").put("redirect_uris",strings(redirect)).put("grant_types",strings("authorization_code","refresh_token")).build();}
 private static @NonNull JsonArray strings(@NonNull String @NonNull ... values){return JsonArray.fromElements(Arrays.stream(values).map(JsonString::fromValue).map(v->(JsonValue)v).toList());}
 private static @NonNull String text(@NonNull JsonObject json,@NonNull String member){return ((JsonString)requireNonNull(json.getMembers().get(member))).getValue();}
 private static byte @NonNull [] bytes(@NonNull JsonObject json){return json.toJson().getBytes(StandardCharsets.UTF_8);}
 private static @NonNull OAuthClientMetadataPolicy policy(@NonNull InMemoryOAuthClientMetadataCache memory){return OAuthClientMetadataPolicy.withAddressResolver((host,budget)->{throw new AssertionError("No resolver in deterministic fixture");}).cache(memory).build();}
 private static @NonNull StateSealer sealer(){byte[] key=new byte[32];for(int i=0;i<key.length;i++)key[i]=(byte)(i+1);return StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key))).clock(CLOCK).build();}
 private static @NonNull OAuthAuthorizationDecision decision(){return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(RESOURCES).refreshTokenPermitted(true).build();}
 private static @NonNull String encode(@NonNull String value){try{return FormUrlEncoding.encode(value);}catch(Exception failure){throw new AssertionError(failure);}}
 private static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> fields){return String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());}
 private static @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(){return Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));}
 private static @NonNull OAuthServerResponse success(@NonNull OAuthTokenResult result){return assertInstanceOf(OAuthTokenResult.Succeeded.class,result).getResponse();}
 private static final class Fixture {
  final OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture(NOW);
  final AtomicInteger fetches=new AtomicInteger();
  final InMemoryOAuthClientMetadataCache memory=InMemoryOAuthClientMetadataCache.fromMaximumEntries(8);
  final OAuthClientMetadataPolicy policy=policy(memory);
  final StateSealer sealer=sealer();
  final OAuthAuthorizationServer.Builder builder;
  final OAuthAuthorizationServer server;
  final String id;
  byte[] body;
  Fixture(@NonNull JsonObject document,boolean cimd,boolean ip,boolean exact,@Nullable Boolean any) throws Exception {this(document,cimd,ip,exact,any,OAuthServerObserver.disabledInstance());}
  Fixture(@NonNull JsonObject document,boolean cimd,boolean ip,boolean exact,@Nullable Boolean any,@NonNull OAuthServerObserver observer) throws Exception {
   body=bytes(document);id=text(document,"client_id");var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;var signing=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
   List<URI> redirects=((JsonArray)requireNonNull(document.getMembers().get("redirect_uris"))).getElements().stream().map(v->URI.create(((JsonString)v).getValue())).toList();
   var registered=OAuthServerClientRegistration.withClientId(id).configurationVersion("v1").redirectUris(redirects).allowedScopesByResource(RESOURCES).refreshTokenPermitted(true).build();
   builder=OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token"))
    .jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke")).clientRepository((client,budget)->cimd?Optional.empty():Optional.of(registered))
    .store(store).stateSealer(sealer).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(signing)).resources(RESOURCES).clock(CLOCK).refreshTokensEnabled(true)
    .observer(observer).allowNativeLoopbackRedirects(ip).allowLocalhostRedirects(exact).clientMetadataPolicy(policy).grantPolicy((context,budget)->decision());
   assertSame(builder,anyPort(builder,any));server=builder.build();
   var transportField=OAuthClientMetadataFetcher.class.getDeclaredField("transport");transportField.setAccessible(true);
   // Test-only transport replacement; the public builder never exposes a transport or TLS bypass.
   transportField.set(fetcher(server),(OAuthClientMetadataFetcher.Transport)(uri,budget)->{assertEquals(URI.create(id),uri);fetches.incrementAndGet();return new RawResponse(200,HttpHeaders.of(Map.of("Cache-Control",List.of("max-age=60")),(a,b)->true),body,null,false,Duration.ZERO);});
   assertEquals(OAuthStoreCommitStatus.COMMITTED,server.initializeFreshIssuer().getStatus());server.establishNewSubject("subject");
  }
  @NonNull OAuthAuthorizationResult begin(@NonNull OAuthAuthorizationServer target,@NonNull String redirect){return begin(target,redirect,"code");}
  @NonNull OAuthAuthorizationResult begin(@NonNull OAuthAuthorizationServer target,@NonNull String redirect,@NonNull String responseType){return target.beginAuthorizationResult("GET",form(Map.of("client_id",id,"response_type",responseType,"redirect_uri",redirect,"resource",RESOURCE,"code_challenge_method","S256","code_challenge",CHALLENGE)),new byte[0],Map.of(),BROWSER);}
  @NonNull OAuthAuthorizationResult begin(@NonNull String redirect){return begin(server,redirect);}
  @NonNull String code(@NonNull String actual){var interaction=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,begin(actual)).getInteraction();assertEquals(URI.create(actual),interaction.getRedirectUri());assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,server.resumeAuthorizationResult(interaction.getInteractionValue(),BROWSER));
   URI location=assertInstanceOf(OAuthAuthorizationResult.Completed.class,server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision())).getResponse().getLocationWithCredentials().orElseThrow();assertTrue(location.toString().startsWith(actual+(actual.contains("?")?"&":"?")+"code="));return Stream.of(requireNonNull(location.getRawQuery()).split("&")).filter(p->p.startsWith("code=")).map(p->p.substring(5)).findFirst().orElseThrow();}
  @NonNull OAuthTokenResult redeem(@NonNull String code,@NonNull String redirect,@NonNull String verifier){return server.tokenResult("POST",null,form(Map.of("client_id",id,"grant_type","authorization_code","code",code,"redirect_uri",redirect,"code_verifier",verifier,"resource",RESOURCE)).getBytes(StandardCharsets.UTF_8),headers());}
  @NonNull OAuthTokenResult refresh(@NonNull String value){return server.tokenResult("POST",null,form(Map.of("client_id",id,"grant_type","refresh_token","refresh_token",value,"resource",RESOURCE)).getBytes(StandardCharsets.UTF_8),headers());}
 }
 private static @NonNull OAuthClientMetadataFetcher fetcher(@NonNull OAuthAuthorizationServer server) throws Exception {var clients=OAuthAuthorizationServer.class.getDeclaredField("clients");clients.setAccessible(true);var metadata=OAuthServerClientSelection.class.getDeclaredField("metadata");metadata.setAccessible(true);return (OAuthClientMetadataFetcher)requireNonNull(metadata.get(requireNonNull(clients.get(server))));}
 private static @NonNull OAuthClientMetadataCacheCodec codec(@NonNull OAuthAuthorizationServer server) throws Exception {var field=OAuthClientMetadataFetcher.class.getDeclaredField("codec");field.setAccessible(true);return (OAuthClientMetadataCacheCodec)requireNonNull(field.get(fetcher(server)));}
 @Test void exposesOnlyThePlannedNullableBuilderSetter(){Method method=setter();assertNotNull(method);assertEquals(OAuthAuthorizationServer.Builder.class,method.getReturnType());}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> portlessHttpLocalhostVariesOnlyThePort(){
  return Stream.of("http://localhost/callback","http://localhost/callback?tenant=%2F&x=1","HTTP://localhost/callback","http://localhost","http://localhost/","http://localhost/cb%2Fraw?x=%2f")
   .flatMap(registered->Stream.of(1,80,443,49152,65535).map(port->DynamicTest.dynamicTest(registered+" "+port,()->assertTrue(matches(registered,registered.replaceFirst("://localhost","://localhost:"+port),false,false,true)))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> fixedPortLocalhostKeepsItsExactPolicy(){
  return Stream.of(false,true).flatMap(exact->Stream.of(false,true).flatMap(any->Stream.of(3000,49152).map(port->DynamicTest.dynamicTest(exact+" "+any+" "+port,()->assertEquals(exact&&port==3000,matches("http://localhost:3000/callback","http://localhost:"+port+"/callback",false,exact,any))))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> disabledPolicyKeepsTheExistingRawExactBehavior(){
  return Stream.of(false,true).flatMap(exact->Stream.of("http://localhost/callback","http://localhost:80/callback").map(candidate->DynamicTest.dynamicTest(exact+" "+candidate,()->assertEquals(exact&&candidate.equals("http://localhost/callback"),matches("http://localhost/callback",candidate,false,exact,false)))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> localhostOptInDoesNotAdmitAliasesOrAlterOtherComponents(){
  return Stream.of("https://localhost:49152/callback","HTTP://localhost:49152/callback","http://LOCALHOST:49152/callback","http://localhost.:49152/callback","http://a.localhost:49152/callback","http://localhost.evil:49152/callback",
   "http://127.0.0.1:49152/callback","http://[::1]:49152/callback","http://localhost:49152/other","http://localhost:49152/callback/","http://localhost:49152/%63allback","http://localhost:49152/callback?","http://localhost:49152/callback?x=1",
   "http://user@localhost:49152/callback","http://localhost:49152/callback#","http://localhost:0/callback","http://localhost:65536/callback","http://localhost:/callback","http://localhost:-1/callback","http://localhost:abc/callback","http://localhost:49152/%0dcallback","custom:/callback")
   .map(candidate->DynamicTest.dynamicTest(candidate,()->assertFalse(matches("http://localhost/callback",candidate,false,false,true))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> rawQueryAndPathSpellingsStayExact(){
  return Stream.of("http://localhost:49152/cb%2Fraw?x=%2F","http://localhost:49152/cb/raw?x=%2f","http://localhost:49152/cb%2fraw?x=%2f","http://localhost:49152/cb%2Fraw?x=%2f&")
   .map(candidate->DynamicTest.dynamicTest(candidate,()->assertFalse(matches("http://localhost/cb%2Fraw?x=%2f",candidate,false,false,true))));
 }
 @Test void httpsAndIpLiteralPoliciesAreUnchanged() throws Exception {
  assertTrue(matches("https://localhost/callback","https://localhost/callback",false,false,true));assertFalse(matches("https://localhost/callback","https://localhost:49152/callback",false,false,true));
  assertFalse(matches("http://127.0.0.1/callback","http://127.0.0.1:49152/callback",false,false,true));assertTrue(matches("http://127.0.0.1/callback","http://127.0.0.1:49152/callback",true,false,false));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> registeredAndMetadataClientsCompleteTheActualPortFlow(){
  return Stream.of(false,true).flatMap(cimd->Stream.of(-1,1,49152,65535).map(port->DynamicTest.dynamicTest(cimd+" "+port,()->{
   Fixture f=new Fixture(document("http://localhost/callback?tenant=%2F"),cimd,false,false,true);String actual="http://localhost"+(port<0?"":":"+port)+"/callback?tenant=%2F",code=f.code(actual);int before=f.fetches.get();JsonObject token=json(success(f.redeem(code,actual,VERIFIER)).toHttpBodyWithCredentials());assertEquals(before+(cimd?1:0),f.fetches.get());
   var bearer=assertInstanceOf(BearerTokenResult.Present.class,BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+text(token,"access_token")))).getToken();assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,f.server.validateAccessTokenResult(bearer,RESOURCE));success(f.refresh(text(token,"refresh_token")));
  })));
 }
 @Test void unmodifiedClaudeMetadataSupportsItsPortlessLocalhostRedirect() throws Exception {
  Fixture f=new Fixture(claude(),true,true,false,true);String actual="http://localhost:49152/callback";success(f.redeem(f.code(actual),actual,VERIFIER));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> actualRedirectAndVerifierAreStillRequiredAtRedemption(){
  return Stream.of(false,true).flatMap(cimd->Stream.of("no-port","different-port","raw-query","wrong-verifier").map(fault->DynamicTest.dynamicTest(cimd+" "+fault,()->{
   Fixture f=new Fixture(document("http://localhost/callback?tenant=%2F"),cimd,false,false,true);String actual="http://localhost:49152/callback?tenant=%2F",code=f.code(actual);var rows=Map.copyOf(f.store.rows);int before=f.fetches.get();
   String supplied=switch(fault){case "no-port"->"http://localhost/callback?tenant=%2F";case "different-port"->"http://localhost:49153/callback?tenant=%2F";case "raw-query"->"http://localhost:49152/callback?tenant=%2f";default->actual;};
   var rejected=assertInstanceOf(OAuthTokenResult.Rejected.class,f.redeem(code,supplied,fault.equals("wrong-verifier")?"Z".repeat(43):VERIFIER));assertEquals(OAuthServerException.Reason.INVALID_GRANT,rejected.getReason());assertEquals(rows,f.store.rows);assertEquals(before,f.fetches.get());success(f.redeem(code,actual,VERIFIER));
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> falseAndNullDisableTheNewPolicy(){
  return Stream.of("false","null").flatMap(mode->Stream.of(false,true).map(cimd->DynamicTest.dynamicTest(mode+" "+cimd,()->{
   Fixture f=new Fixture(document("http://localhost/callback"),cimd,false,false,mode.equals("null")?null:Boolean.FALSE);var rows=Map.copyOf(f.store.rows);var rejected=assertInstanceOf(OAuthAuthorizationResult.Rejected.class,f.begin("http://localhost:49152/callback"));assertTrue(rejected.getResponse().getLocationWithCredentials().isEmpty());assertEquals(rows,f.store.rows);
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> builderResetAndSnapshotDoNotShareMutableConfiguration(){
  return Stream.of("false","null").map(mode->DynamicTest.dynamicTest(mode,()->{
   Fixture f=new Fixture(document("http://localhost/callback"),false,false,false,true);assertSame(f.builder,anyPort(f.builder,mode.equals("null")?null:Boolean.FALSE));var disabled=f.builder.build();
   assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,f.begin("http://localhost:49152/callback"));var rows=Map.copyOf(f.store.rows);assertInstanceOf(OAuthAuthorizationResult.Rejected.class,f.begin(disabled,"http://localhost:49152/callback"));assertEquals(rows,f.store.rows);
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> fixedPortMetadataStillNeedsTheExactLocalhostOptIn(){
  return Stream.of(false,true).map(exact->DynamicTest.dynamicTest("exact="+exact,()->{
   Fixture f=new Fixture(document("http://localhost:3000/callback"),true,false,exact,true);
   if(exact)assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,f.begin("http://localhost:3000/callback"));
   else assertEquals(OAuthServerException.Reason.INVALID_CLIENT,assertInstanceOf(OAuthAuthorizationResult.Rejected.class,f.begin("http://localhost:3000/callback")).getReason());
  }));
 }
 @Test void registeredPortSpellingStillParticipatesInTheFreshFingerprint() throws Exception {
  String registered="http://localhost/callback",actual="http://localhost:49152/callback";Fixture f=new Fixture(document(registered),true,false,true,true);String code=f.code(actual);var rows=Map.copyOf(f.store.rows);
  f.body=bytes(document("http://localhost:3000/callback"));var rejected=assertInstanceOf(OAuthTokenResult.Rejected.class,f.redeem(code,actual,VERIFIER));assertEquals(OAuthServerException.Reason.INVALID_GRANT,rejected.getReason());assertEquals(rows,f.store.rows);f.body=bytes(document(registered));success(f.redeem(code,actual,VERIFIER));
 }
 @Test void namespaceBindsTheNewFlagWithoutChangingLegacyFalseKeys() throws Exception {
  JsonObject document=document("http://localhost/callback");Fixture off=new Fixture(document,true,false,true,false),on=new Fixture(document,true,false,true,true),cleared=new Fixture(document,true,false,true,null);String id=text(document,"client_id");
  var legacy=new OAuthClientMetadataCacheCodec(ISSUER,off.sealer,off.policy,LIMITS,false,true);var a=codec(off.server);var b=codec(on.server);
  assertEquals(legacy.key(id),a.key(id));assertEquals(a.key(id),codec(cleared.server).key(id));assertNotEquals(a.key(id),b.key(id));
  var old=a.seal(id,bytes(document),NOW,NOW.plusSeconds(60));var fresh=b.seal(id,bytes(document),NOW,NOW.plusSeconds(60));assertTrue(a.open(id,old,NOW).isPresent());assertTrue(b.open(id,fresh,NOW).isPresent());assertTrue(a.open(id,fresh,NOW).isEmpty());assertTrue(b.open(id,old,NOW).isEmpty());
  var forged=OAuthClientMetadataCacheEntry.fromStoredForm(a.key(id),fresh.getVersion(),fresh.getExpiresAt(),fresh.toSealedForm());assertTrue(a.open(id,forged,NOW).isEmpty());
 }
 private static class Events implements OAuthServerObserver {
  int enabled,used,will,terminal;
  public void didEnableLocalhostAnyPortRedirects(){enabled++;}
  public void didUseLocalhostAnyPortRedirects(){used++;}
  @Override public void willHandleEndpoint(@NonNull Endpoint endpoint){if(endpoint==Endpoint.AUTHORIZATION)will++;}
  @Override public void didHandleEndpoint(@NonNull Endpoint endpoint,@Nullable Integer status,@NonNull Duration elapsed){if(endpoint==Endpoint.AUTHORIZATION)terminal++;}
  @Override public void didRejectEndpoint(@NonNull Endpoint endpoint,OAuthServerException.@NonNull Reason reason,@Nullable Integer status,@NonNull Duration elapsed){if(endpoint==Endpoint.AUTHORIZATION)terminal++;}
 }
 @Test void observerHooksAreDefaultVoidWithoutRequestData() throws Exception {
  for(String name:List.of("didEnableLocalhostAnyPortRedirects","didUseLocalhostAnyPortRedirects")){
   Method method=assertDoesNotThrow(()->OAuthServerObserver.class.getMethod(name));assertTrue(method.isDefault());assertEquals(void.class,method.getReturnType());
  }
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> observerDistinguishesEnabledFromActualUse(){
  return Stream.of("unused","used","later-rejected","exact").map(mode->DynamicTest.dynamicTest(mode,()->{
   Events events=new Events();Fixture f=new Fixture(document("http://localhost/callback"),false,false,mode.equals("exact"),true,events);
   assertEquals(1,events.enabled);assertEquals(0,events.used);
   String actual=mode.equals("unused")?"http://localhost:49152/other":mode.equals("exact")?"http://localhost/callback":"http://localhost:49152/callback";
   var result=f.begin(f.server,actual,mode.equals("later-rejected")?"token":"code");
   if(mode.equals("unused")||mode.equals("later-rejected"))assertInstanceOf(OAuthAuthorizationResult.Rejected.class,result);else assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,result);
   assertEquals(mode.equals("used")||mode.equals("later-rejected")?1:0,events.used);assertEquals(1,events.will);assertEquals(1,events.terminal);
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> disabledObserverPolicyDoesNotEmitEnableOrUse(){
  return Stream.of("false","null").map(mode->DynamicTest.dynamicTest(mode,()->{
   Events events=new Events();Fixture f=new Fixture(document("http://localhost/callback"),false,false,false,mode.equals("null")?null:Boolean.FALSE,events);
   assertInstanceOf(OAuthAuthorizationResult.Rejected.class,f.begin("http://localhost:49152/callback"));assertEquals(0,events.enabled);assertEquals(0,events.used);assertEquals(1,events.terminal);
  }));
 }
 @Test void observerFailuresAreContainedAndInterruptedStatusIsRestored() throws Exception {
  Events events=new Events(){public void didEnableLocalhostAnyPortRedirects(){super.didEnableLocalhostAnyPortRedirects();throw new IllegalStateException("private detail");}public void didUseLocalhostAnyPortRedirects(){super.didUseLocalhostAnyPortRedirects();Thread.currentThread().interrupt();throw new IllegalStateException("private detail");}};
  Fixture f=new Fixture(document("http://localhost/callback"),false,false,false,true,events);assertEquals(1,events.enabled);
  try{assertEquals(OAuthServerException.Reason.STORE_UNAVAILABLE,assertThrows(OAuthServerStoreException.class,()->f.begin("http://localhost:49152/callback")).getReason());assertTrue(Thread.currentThread().isInterrupted());assertEquals(1,events.used);}finally{Thread.interrupted();}
 }
 @Test void fatalObserverErrorPropagatesAtUse() throws Exception {
  Events events=new Events(){public void didUseLocalhostAnyPortRedirects(){super.didUseLocalhostAnyPortRedirects();throw new InternalError("sentinel");}};
  Fixture f=new Fixture(document("http://localhost/callback"),false,false,false,true,events);var rows=Map.copyOf(f.store.rows);assertThrows(InternalError.class,()->f.begin("http://localhost:49152/callback"));assertEquals(rows,f.store.rows);assertEquals(1,events.used);
 }
 @Test void invalidBuildDoesNotEmitEnable() throws Exception {
  Events events=new Events();var builder=OAuthAuthorizationServer.withIssuer(ISSUER).observer(events);anyPort(builder,true);assertThrows(IllegalStateException.class,builder::build);assertEquals(0,events.enabled);
 }

 @Test void retriesReportActualUseOnlyOncePerOperation() throws Exception {
  Events events=new Events();Fixture f=new Fixture(document("http://localhost/callback"),false,false,false,true,events);int commits=f.store.commits;f.store.conflicts=1;
  assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,f.begin("http://localhost:49152/callback"));assertEquals(commits+2,f.store.commits);assertEquals(1,events.enabled);assertEquals(1,events.used);assertEquals(1,events.will);assertEquals(1,events.terminal);
 }

}
