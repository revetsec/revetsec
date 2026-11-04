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
import com.revetsec.json.JsonBoolean;
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

/** Pinned document fixtures and public issuer workflows; all metadata I/O is replaced only inside the test. */
final class OAuthCimdMcpProfileTests {
 private static final String ISSUER="https://issuer.example.com/tenant",RESOURCE="https://resource.example.com/mcp",BROWSER="A".repeat(43),
   VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private static final Instant NOW=Instant.parse("2026-10-31T12:00:00Z");
 private static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
 private static final Map<String,Set<String>> RESOURCES=Map.of(RESOURCE,Set.of("read"));
 private static final OAuthServerIngressLimits LIMITS=OAuthServerIngressLimits.fromDefaults();
 private static byte[] resource(String name) throws Exception {try(var input=requireNonNull(OAuthCimdMcpProfileTests.class.getResourceAsStream("/cimd/mcp-profile/"+name))){return input.readAllBytes();}}
 private static JsonObject json(byte[] body) throws Exception {return (JsonObject)JsonCodec.parse(body,JsonLimits.protocolDocument(131072));}
 private static String text(JsonObject json,String member){return ((JsonString)requireNonNull(json.getMembers().get(member))).getValue();}
 private static byte[] bytes(JsonObject json){return json.toJson().getBytes(StandardCharsets.UTF_8);}
 private static JsonObject change(JsonObject original,String name,@Nullable JsonValue value){var fields=new LinkedHashMap<>(original.getMembers());fields.remove(name);if(value!=null)fields.put(name,value);return JsonObject.fromMembers(fields);}
 private static JsonArray strings(String... values){return JsonArray.fromElements(Arrays.stream(values).map(JsonString::fromValue).map(v->(JsonValue)v).toList());}
 private static JsonObject application(JsonObject original,String type){return change(original,"application_type",type.equals("omitted")?null:JsonString.fromValue(type));}
 private static JsonObject reference() throws Exception {return json(resource("mcp-reference.json"));}
 private static OAuthClientMetadataPolicy policy(){return OAuthClientMetadataPolicy.withAddressResolver((host,budget)->{throw new AssertionError("No DNS in parser tests");}).cache(InMemoryOAuthClientMetadataCache.fromMaximumEntries(8)).build();}
 private static OAuthClientMetadataDocument parse(JsonObject document,boolean ip,boolean localhost){return OAuthClientMetadataDocument.parse(text(document,"client_id"),bytes(document),policy(),LIMITS,ip,localhost);}
 private static void invalid(JsonObject document,boolean ip,boolean localhost){var failure=assertThrows(OAuthServerAdmissionFailure.class,()->parse(document,ip,localhost));assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,failure.reason());assertNull(failure.getCause());}
 private static StateSealer sealer(){byte[] key=new byte[32];for(int i=0;i<key.length;i++)key[i]=(byte)(i+1);return StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key))).clock(CLOCK).build();}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> exactReferenceRequiresBothExplicitPolicies(){
  return Stream.of(false,true).flatMap(ip->Stream.of(false,true).map(localhost->DynamicTest.dynamicTest(ip+" "+localhost,()->{
   JsonObject document=reference();assertFalse(document.getMembers().containsKey("application_type"));
   if(ip&&localhost){var parsed=assertDoesNotThrow(()->parse(document,ip,localhost));assertEquals(List.of(URI.create("http://127.0.0.1:3000/callback"),URI.create("http://localhost:3000/callback")),parsed.redirectUris());assertFalse(parsed.nativeApplication());assertFalse(parsed.refreshTokenPermitted());}
   else invalid(document,ip,localhost);
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> ipLiteralPolicyDoesNotRequireANativeDeclaration(){
  return Stream.of("omitted","web","native").flatMap(type->Stream.of("127.0.0.1","[::1]").flatMap(host->Stream.of(false,true).map(enabled->DynamicTest.dynamicTest(type+" "+host+" "+enabled,()->{
   JsonObject document=change(application(reference(),type),"redirect_uris",strings("http://"+host+":49152/callback"));
   if(enabled){var parsed=assertDoesNotThrow(()->parse(document,true,false));assertEquals(type.equals("native"),parsed.nativeApplication());assertEquals("http://"+host+":49152/callback",parsed.redirectUris().get(0).toString());}
   else invalid(document,false,true);
  }))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> localhostKeepsItsIndependentPolicy(){
  return Stream.of("omitted","web","native").flatMap(type->Stream.of(false,true).flatMap(ip->Stream.of(false,true).map(localhost->DynamicTest.dynamicTest(type+" "+ip+" "+localhost,()->{
   JsonObject document=change(application(reference(),type),"redirect_uris",strings("http://localhost:3000/callback"));
   if(localhost)assertDoesNotThrow(()->parse(document,ip,true));else invalid(document,ip,false);
  }))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> optInDoesNotRelaxOtherRedirectAdmission(){
  return Stream.of("omitted","native").flatMap(type->Stream.of("http://127.0.0.2/callback","http://10.0.0.1/callback","http://example.com/callback","http://foo.localhost/callback",
    "http://[::ffff:127.0.0.1]/callback","http://user@127.0.0.1/callback","http://127.0.0.1/callback#fragment","http://127.0.0.1:0/callback",
    "http://127.0.0.1:65536/callback","http://127.0.0.1/callback?code=x","http://127.0.0.1/%0dcallback","custom:/callback")
    .map(uri->DynamicTest.dynamicTest(type+" "+uri,()->invalid(change(application(reference(),type),"redirect_uris",strings(uri)),true,true))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> declaredApplicationValuesAndSecurityFingerprintRemainStable(){
  return Stream.of("service","","NATIVE").map(type->DynamicTest.dynamicTest("application_type="+type,()->invalid(application(reference(),type),true,true)));
 }
 @Test void declarationStillHasCheckedTypeAndExistingFingerprintBinding() throws Exception {
  invalid(change(reference(),"application_type",JsonBoolean.fromValue(false)),true,true);
  JsonObject https=change(reference(),"redirect_uris",strings("https://client.example.com/callback"));
  assertEquals(parse(application(https,"omitted"),false,false).fingerprint(),parse(application(https,"web"),false,false).fingerprint());
  assertNotEquals(parse(application(https,"web"),false,false).fingerprint(),parse(application(https,"native"),false,false).fingerprint());
 }
 @Test void datedClientDocumentsParseUnderTheirExplicitLoopbackPolicies() throws Exception {
  JsonObject claude=json(resource("claude-code-client-metadata.json"));assertFalse(claude.getMembers().containsKey("application_type"));
  assertTrue(assertDoesNotThrow(()->parse(claude,true,true)).refreshTokenPermitted());invalid(claude,true,false);invalid(claude,false,true);
  assertTrue(assertDoesNotThrow(()->parse(json(resource("vscode-client-metadata.json")),true,false)).refreshTokenPermitted());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> cachedReferenceIsReadmittedUnderTheActualFlags(){
  return Stream.of("omitted","web","native").map(type->DynamicTest.dynamicTest(type,()->{
   StateSealer sealer=sealer();var policy=policy();JsonObject document=application(reference(),type);String id=text(document,"client_id");
   var codec=new OAuthClientMetadataCacheCodec(ISSUER,sealer,policy,LIMITS,true,true);
   var entry=assertDoesNotThrow(()->codec.seal(id,bytes(document),NOW,NOW.plusSeconds(60)));
   assertEquals(parse(document,true,true).fingerprint(),codec.open(id,entry,NOW).orElseThrow().document().fingerprint());
   for(boolean ip:List.of(false,true))for(boolean localhost:List.of(false,true))if(!ip||!localhost){
    var restricted=new OAuthClientMetadataCacheCodec(ISSUER,sealer,policy,LIMITS,ip,localhost);assertNotEquals(codec.key(id),restricted.key(id));assertTrue(restricted.open(id,entry,NOW).isEmpty());
   }
  }));
 }
 private static final class Fixture {
  final OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture(NOW);
  final AtomicInteger fetches=new AtomicInteger();
  final String id;
  final boolean refreshRequested;
  final OAuthAuthorizationServer server;
  byte[] body;
  Fixture(JsonObject document,@Nullable Boolean ip,@Nullable Boolean localhost) throws Exception {
   body=bytes(document);id=text(document,"client_id");refreshRequested=((JsonArray)requireNonNull(document.getMembers().get("grant_types"))).getElements().contains(JsonString.fromValue("refresh_token"));var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
   var keys=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
   server=OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token"))
     .jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke")).clientRepository((client,budget)->Optional.empty())
     .store(store).stateSealer(sealer()).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys)).resources(RESOURCES).clock(CLOCK).refreshTokensEnabled(true)
     .allowNativeLoopbackRedirects(true).allowNativeLoopbackRedirects(ip).allowLocalhostRedirects(true).allowLocalhostRedirects(localhost)
     .clientMetadataPolicy(policy()).grantPolicy((context,budget)->decision(context.isRefreshTokenPermitted())).build();
   var clientsField=OAuthAuthorizationServer.class.getDeclaredField("clients");clientsField.setAccessible(true);
   var metadataField=OAuthServerClientSelection.class.getDeclaredField("metadata");metadataField.setAccessible(true);
   var fetcher=requireNonNull(metadataField.get(requireNonNull(clientsField.get(server))));
   var transportField=OAuthClientMetadataFetcher.class.getDeclaredField("transport");transportField.setAccessible(true);
   // The production constructor still owns its pinned transport; this replacement is test-only.
   transportField.set(fetcher,(OAuthClientMetadataFetcher.Transport)(uri,budget)->{assertEquals(URI.create(id),uri);fetches.incrementAndGet();return new RawResponse(200,HttpHeaders.of(Map.of("Cache-Control",List.of("max-age=60")),(a,b)->true),body,null,false,Duration.ZERO);});
   assertEquals(OAuthStoreCommitStatus.COMMITTED,server.initializeFreshIssuer().getStatus());server.establishNewSubject("subject");
  }
  OAuthAuthorizationResult begin(String redirect,String challenge){return server.beginAuthorizationResult("GET",form(Map.of("client_id",id,"response_type","code","redirect_uri",redirect,"resource",RESOURCE,"code_challenge_method","S256","code_challenge",challenge)),new byte[0],Map.of(),BROWSER);}
  String code(String redirect){var interaction=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,begin(redirect,CHALLENGE)).getInteraction();var response=assertInstanceOf(OAuthAuthorizationResult.Completed.class,server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision(refreshRequested))).getResponse();URI location=response.getLocationWithCredentials().orElseThrow();assertEquals(redirect,location.toString().substring(0,location.toString().indexOf('?')));return Stream.of(requireNonNull(location.getRawQuery()).split("&")).filter(p->p.startsWith("code=")).map(p->p.substring(5)).findFirst().orElseThrow();}
  OAuthTokenResult redeem(String code,String redirect,String verifier){return server.tokenResult("POST",null,form(Map.of("grant_type","authorization_code","client_id",id,"resource",RESOURCE,"code",code,"code_verifier",verifier,"redirect_uri",redirect)).getBytes(StandardCharsets.UTF_8),headers());}
  OAuthTokenResult refresh(String value){return server.tokenResult("POST",null,form(Map.of("grant_type","refresh_token","client_id",id,"resource",RESOURCE,"refresh_token",value)).getBytes(StandardCharsets.UTF_8),headers());}
 }
 private static OAuthAuthorizationDecision decision(boolean refresh){return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(RESOURCES).refreshTokenPermitted(refresh).build();}
 private static Map<String,List<String>> headers(){return Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));}
 private static String form(Map<String,String> fields){return String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());}
 private static String encode(String value){try{return FormUrlEncoding.encode(value);}catch(Exception failure){throw new AssertionError(failure);}}
 private static OAuthServerResponse success(OAuthTokenResult result){return assertInstanceOf(OAuthTokenResult.Succeeded.class,result).getResponse();}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> publicReferenceCompletesCodeFlowWithOnlyTheIpPortException(){
  return Stream.of("omitted","web","native").flatMap(type->Stream.of("http://127.0.0.1:49152/callback","http://localhost:3000/callback").map(redirect->DynamicTest.dynamicTest(type+" "+redirect,()->{
   Fixture f=new Fixture(application(reference(),type),true,true);String code=f.code(redirect);int before=f.fetches.get();
   var response=success(f.redeem(code,redirect,VERIFIER));assertEquals(before+1,f.fetches.get());JsonObject token=json(response.toHttpBodyWithCredentials());assertFalse(token.getMembers().containsKey("refresh_token"));
   var bearer=assertInstanceOf(BearerTokenResult.Present.class,BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+text(token,"access_token")))).getToken();assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,f.server.validateAccessTokenResult(bearer,RESOURCE));
  })));
 }
 @Test void ipv6LiteralCompletesThePublicFlowWithoutANativeLabel() throws Exception {
  JsonObject document=change(reference(),"redirect_uris",strings("http://[::1]:3000/callback"));Fixture f=new Fixture(document,true,false);
  String actual="http://[::1]:49152/callback";success(f.redeem(f.code(actual),actual,VERIFIER));
 }
 private static @Nullable Boolean flag(String mode,String enabled){if(mode.equals("cleared"))return null;return mode.equals(enabled);}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> builderDefaultFalseAndClearedPoliciesRejectTheMixedReference(){
  return Stream.of("off","cleared","ip-only","localhost-only").map(mode->DynamicTest.dynamicTest(mode,()->{
   Fixture f=new Fixture(reference(),flag(mode,"ip-only"),flag(mode,"localhost-only"));var rows=Map.copyOf(f.store.rows);
   var rejected=assertInstanceOf(OAuthAuthorizationResult.Rejected.class,f.begin("http://127.0.0.1:49152/callback",CHALLENGE));assertEquals(OAuthServerException.Reason.INVALID_CLIENT,rejected.getReason());assertTrue(rejected.getResponse().getLocationWithCredentials().isEmpty());assertEquals(rows,f.store.rows);
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> authorizationMatchesOnlyPermittedHostPathQuerySchemeAndLocalhostPort(){
  return Stream.of("http://127.0.0.2:49152/callback","http://127.0.0.1:49152/other","http://127.0.0.1:49152/callback?other=1","https://127.0.0.1:49152/callback","http://localhost:49152/callback")
    .map(redirect->DynamicTest.dynamicTest(redirect,()->{
     Fixture f=new Fixture(reference(),true,true);var rows=Map.copyOf(f.store.rows);var rejected=assertInstanceOf(OAuthAuthorizationResult.Rejected.class,f.begin(redirect,CHALLENGE));assertEquals(OAuthServerException.Reason.MALFORMED_REQUEST,rejected.getReason());assertTrue(rejected.getResponse().getLocationWithCredentials().isEmpty());assertEquals(rows,f.store.rows);
    }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> pkceAndActualRedirectStillGateRedemptionWithoutConsumingTheCode(){
  return Stream.of("registered-port","wrong-verifier").map(fault->DynamicTest.dynamicTest(fault,()->{
   Fixture f=new Fixture(reference(),true,true);String actual="http://127.0.0.1:49152/callback",code=f.code(actual);int before=f.fetches.get();var rows=Map.copyOf(f.store.rows);
   var rejected=assertInstanceOf(OAuthTokenResult.Rejected.class,f.redeem(code,fault.equals("registered-port")?"http://127.0.0.1:3000/callback":actual,fault.equals("wrong-verifier")?"Z".repeat(43):VERIFIER));assertEquals(OAuthServerException.Reason.INVALID_GRANT,rejected.getReason());assertEquals(rows,f.store.rows);assertEquals(before,f.fetches.get());success(f.redeem(code,actual,VERIFIER));
  }));
 }
 @Test void freshFingerprintChangeCannotReleaseCredentialsOrUseTheCachedReference() throws Exception {
  Fixture f=new Fixture(reference(),true,true);String actual="http://127.0.0.1:49152/callback",code=f.code(actual);var rows=Map.copyOf(f.store.rows);int before=f.fetches.get();
  f.body=bytes(change(reference(),"redirect_uris",strings("http://127.0.0.1:3000/changed","http://localhost:3000/callback")));
  var rejected=assertInstanceOf(OAuthTokenResult.Rejected.class,f.redeem(code,actual,VERIFIER));assertEquals(OAuthServerException.Reason.INVALID_GRANT,rejected.getReason());assertEquals(rows,f.store.rows);assertEquals(before+1,f.fetches.get());f.body=resource("mcp-reference.json");success(f.redeem(code,actual,VERIFIER));
 }
 @Test void explicitlyDeclaredRefreshUsesItsOwnFreshMetadataWithoutANativeLabel() throws Exception {
  JsonObject document=change(reference(),"grant_types",strings("authorization_code","refresh_token"));Fixture f=new Fixture(document,true,true);String redirect="http://127.0.0.1:49152/callback";JsonObject token=json(success(f.redeem(f.code(redirect),redirect,VERIFIER)).toHttpBodyWithCredentials());int before=f.fetches.get();success(f.refresh(text(token,"refresh_token")));assertEquals(before+1,f.fetches.get());
 }
}
