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
import com.revetsec.json.JsonNull;
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

/** Additional CIMD grant strings are inert declarations; issuer capabilities and consent remain authoritative. */
final class OAuthCimdGrantProfileTests {
 private static final String ISSUER="https://issuer.example.com/tenant",RESOURCE="https://resource.example.com/mcp",BROWSER="A".repeat(43),
   VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",REDIRECT="http://127.0.0.1:49152/";
 private static final Instant NOW=Instant.parse("2026-10-31T12:00:00Z");
 private static final Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
 private static final Map<String,Set<String>> RESOURCES=Map.of(RESOURCE,Set.of("read"));
 private static final OAuthServerIngressLimits LIMITS=OAuthServerIngressLimits.fromDefaults();
 private static final List<String> EXTRAS=List.of("urn:ietf:params:oauth:grant-type:device_code","client_credentials","password","implicit","urn:example:grant","https://client.example.com/custom-grant");
 private static JsonObject vscode() throws Exception {try(var input=requireNonNull(OAuthCimdGrantProfileTests.class.getResourceAsStream("/cimd/mcp-profile/vscode-client-metadata.json"))){return json(input.readAllBytes());}}
 private static JsonObject json(byte[] body) throws Exception {return (JsonObject)JsonCodec.parse(body,JsonLimits.protocolDocument(131072));}
 private static String text(JsonObject json,String member){return ((JsonString)requireNonNull(json.getMembers().get(member))).getValue();}
 private static byte[] bytes(JsonObject json){return json.toJson().getBytes(StandardCharsets.UTF_8);}
 private static JsonObject change(JsonObject original,String name,@Nullable JsonValue value){var fields=new LinkedHashMap<>(original.getMembers());fields.remove(name);if(value!=null)fields.put(name,value);return JsonObject.fromMembers(fields);}
 private static JsonArray strings(String... values){return JsonArray.fromElements(Arrays.stream(values).map(JsonString::fromValue).map(v->(JsonValue)v).toList());}
 private static JsonObject grants(String... values) throws Exception {return change(vscode(),"grant_types",strings(values));}
 private static OAuthClientMetadataPolicy policy(){return OAuthClientMetadataPolicy.withAddressResolver((host,budget)->{throw new AssertionError("Deterministic metadata only");}).cache(InMemoryOAuthClientMetadataCache.fromMaximumEntries(8)).build();}
 private static OAuthClientMetadataDocument parse(JsonObject document){return OAuthClientMetadataDocument.parse(text(document,"client_id"),bytes(document),policy(),LIMITS,true,false);}
 private static void invalid(JsonObject document){var failure=assertThrows(OAuthServerAdmissionFailure.class,()->parse(document));assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,failure.reason());assertNull(failure.getCause());}
 private static StateSealer sealer(){byte[] key=new byte[32];for(int i=0;i<key.length;i++)key[i]=(byte)(i+1);return StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key))).clock(CLOCK).build();}
 @Test void unmodifiedDatedVsCodeDocumentAdmitsOnlySupportedCapabilities() throws Exception {
  JsonObject document=vscode();assertTrue(((JsonArray)requireNonNull(document.getMembers().get("grant_types"))).getElements().contains(JsonString.fromValue(EXTRAS.get(0))));
  var parsed=assertDoesNotThrow(()->parse(document));assertTrue(parsed.refreshTokenPermitted());assertTrue(parsed.nativeApplication());assertEquals(2,parsed.redirectUris().size());
  assertEquals(parse(grants("authorization_code","refresh_token")).fingerprint(),parsed.fingerprint());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unsupportedGrantStringsDoNotRejectOrExpandTheCodeProfile(){
  return EXTRAS.stream().flatMap(extra->Stream.of(false,true).map(refresh->DynamicTest.dynamicTest(extra+" refresh="+refresh,()->{
   JsonObject document=refresh?grants(extra,"authorization_code","refresh_token"):grants("authorization_code",extra);
   var parsed=assertDoesNotThrow(()->parse(document));assertEquals(refresh,parsed.refreshTokenPermitted());
   assertEquals(parse(refresh?grants("authorization_code","refresh_token"):grants("authorization_code")).fingerprint(),parsed.fingerprint());
  })));
 }
 @Test void refreshDeclarationIsCaseSensitive() throws Exception {
  var parsed=assertDoesNotThrow(()->parse(grants("authorization_code","REFRESH_TOKEN")));assertFalse(parsed.refreshTokenPermitted());
  assertEquals(parse(grants("authorization_code")).fingerprint(),parsed.fingerprint());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> authorizationCodeRemainsMandatory(){
  return Stream.of("empty","refresh","extra","refresh-extra","wrong-case").map(mode->DynamicTest.dynamicTest(mode,()->{
   invalid(switch(mode){case "empty"->grants();case "refresh"->grants("refresh_token");case "extra"->grants(EXTRAS.get(0));case "refresh-extra"->grants("refresh_token",EXTRAS.get(0));default->grants("AUTHORIZATION_CODE",EXTRAS.get(0));});
  }));
 }
 @Test void omittedGrantTypesKeepTheCodeOnlyDefault() throws Exception {assertFalse(parse(change(vscode(),"grant_types",null)).refreshTokenPermitted());}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> arrayTypesAndDuplicatesStillReject(){
  return Stream.of("scalar","boolean-member","null","duplicate-code","duplicate-refresh","duplicate-extra").map(mode->DynamicTest.dynamicTest(mode,()->{
   if(mode.equals("scalar"))invalid(change(vscode(),"grant_types",JsonString.fromValue("authorization_code")));
   else if(mode.equals("boolean-member"))invalid(change(vscode(),"grant_types",JsonArray.fromElements(List.of(JsonString.fromValue("authorization_code"),JsonBoolean.fromValue(false)))));
   else if(mode.equals("null"))invalid(change(vscode(),"grant_types",JsonNull.defaultInstance()));
   else if(mode.equals("duplicate-code"))invalid(grants("authorization_code","authorization_code",EXTRAS.get(0)));
   else if(mode.equals("duplicate-refresh"))invalid(grants("authorization_code","refresh_token","refresh_token",EXTRAS.get(0)));
   else invalid(grants("authorization_code",EXTRAS.get(0),EXTRAS.get(0)));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> codeResponseAndPublicAuthenticationRulesRemainMandatory(){
  return Stream.of("implicit-response","mixed-response","secret-auth","private-key").map(mode->DynamicTest.dynamicTest(mode,()->{
   JsonObject document=grants("authorization_code",EXTRAS.get(0));
   invalid(switch(mode){case "implicit-response"->change(document,"response_types",strings("token"));case "mixed-response"->change(document,"response_types",strings("code","token"));case "secret-auth"->change(document,"token_endpoint_auth_method",JsonString.fromValue("client_secret_basic"));default->change(document,"client_secret",JsonString.fromValue("untrusted"));});
  }));
 }
 @Test void optionalCachePreservesFilteredRefreshAndFingerprintFacts() throws Exception {
  var policy=policy();var codec=new OAuthClientMetadataCacheCodec(ISSUER,sealer(),policy,LIMITS,true,false);String id=text(vscode(),"client_id");
  for(boolean refresh:List.of(false,true)){
   JsonObject document=refresh?grants("authorization_code",EXTRAS.get(0),"refresh_token"):grants("authorization_code",EXTRAS.get(0));
   var entry=assertDoesNotThrow(()->codec.seal(id,bytes(document),NOW,NOW.plusSeconds(60)));var cached=codec.open(id,entry,NOW).orElseThrow().document();
   assertEquals(refresh,cached.refreshTokenPermitted());assertEquals(parse(document).fingerprint(),cached.fingerprint());
  }
 }
 private static final class Fixture {
  final OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture(NOW);
  final AtomicInteger fetches=new AtomicInteger();
  final String id;
  final boolean approvalRefresh;
  final OAuthAuthorizationServer server;
  byte[] body;
  Fixture(JsonObject document,boolean serverRefresh,boolean approvalRefresh) throws Exception {
   body=bytes(document);id=text(document,"client_id");this.approvalRefresh=approvalRefresh;var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
   var keys=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
   server=OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token"))
     .jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke")).clientRepository((client,budget)->Optional.empty())
     .store(store).stateSealer(sealer()).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys)).resources(RESOURCES).clock(CLOCK).refreshTokensEnabled(serverRefresh)
     .allowNativeLoopbackRedirects(true)
     .clientMetadataPolicy(policy()).grantPolicy((context,budget)->decision(context.isRefreshTokenPermitted()&&approvalRefresh)).build();
   var clientsField=OAuthAuthorizationServer.class.getDeclaredField("clients");clientsField.setAccessible(true);
   var metadataField=OAuthServerClientSelection.class.getDeclaredField("metadata");metadataField.setAccessible(true);
   var fetcher=requireNonNull(metadataField.get(requireNonNull(clientsField.get(server))));
   var transportField=OAuthClientMetadataFetcher.class.getDeclaredField("transport");transportField.setAccessible(true);
   // The production constructor still owns its pinned transport; this replacement is test-only.
   transportField.set(fetcher,(OAuthClientMetadataFetcher.Transport)(uri,budget)->{assertEquals(URI.create(id),uri);fetches.incrementAndGet();return new RawResponse(200,HttpHeaders.of(Map.of("Cache-Control",List.of("max-age=60")),(a,b)->true),body,null,false,Duration.ZERO);});
   assertEquals(OAuthStoreCommitStatus.COMMITTED,server.initializeFreshIssuer().getStatus());server.establishNewSubject("subject");
  }
  OAuthAuthorizationResult begin(String redirect,String challenge){return server.beginAuthorizationResult("GET",form(Map.of("client_id",id,"response_type","code","redirect_uri",redirect,"resource",RESOURCE,"code_challenge_method","S256","code_challenge",challenge)),new byte[0],Map.of(),BROWSER);}
  String code(String redirect){var interaction=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,begin(redirect,CHALLENGE)).getInteraction();var response=assertInstanceOf(OAuthAuthorizationResult.Completed.class,server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision(approvalRefresh))).getResponse();URI location=response.getLocationWithCredentials().orElseThrow();assertEquals(redirect,location.toString().substring(0,location.toString().indexOf('?')));return Stream.of(requireNonNull(location.getRawQuery()).split("&")).filter(p->p.startsWith("code=")).map(p->p.substring(5)).findFirst().orElseThrow();}
  OAuthTokenResult redeem(String code,String redirect,String verifier){return server.tokenResult("POST",null,form(Map.of("grant_type","authorization_code","client_id",id,"resource",RESOURCE,"code",code,"code_verifier",verifier,"redirect_uri",redirect)).getBytes(StandardCharsets.UTF_8),headers());}
  OAuthTokenResult refresh(String value){return server.tokenResult("POST",null,form(Map.of("grant_type","refresh_token","client_id",id,"resource",RESOURCE,"refresh_token",value)).getBytes(StandardCharsets.UTF_8),headers());}
 }
 private static OAuthAuthorizationDecision decision(boolean refresh){return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(RESOURCES).refreshTokenPermitted(refresh).build();}
 private static Map<String,List<String>> headers(){return Map.of("Content-Type",List.of("application/x-www-form-urlencoded"));}
 private static String form(Map<String,String> fields){return String.join("&",fields.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());}
 private static String encode(String value){try{return FormUrlEncoding.encode(value);}catch(Exception failure){throw new AssertionError(failure);}}
 private static OAuthServerResponse success(OAuthTokenResult result){return assertInstanceOf(OAuthTokenResult.Succeeded.class,result).getResponse();}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> listedRefreshStillNeedsServerAndApplicationPermission(){
  return Stream.of(false,true).flatMap(listed->Stream.of(false,true).flatMap(enabled->Stream.of(false,true).map(approved->DynamicTest.dynamicTest(listed+" "+enabled+" "+approved,()->{
   JsonObject document=listed?vscode():grants("authorization_code",EXTRAS.get(0));Fixture f=new Fixture(document,enabled,approved);String code=f.code(REDIRECT);int before=f.fetches.get();
   JsonObject token=json(success(f.redeem(code,REDIRECT,VERIFIER)).toHttpBodyWithCredentials());assertEquals(before+1,f.fetches.get());assertEquals(listed&&enabled&&approved,token.getMembers().containsKey("refresh_token"));assertEquals("read",text(token,"scope"));
   var bearer=assertInstanceOf(BearerTokenResult.Present.class,BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+text(token,"access_token")))).getToken();assertEquals(Set.of("read"),assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,f.server.validateAccessTokenResult(bearer,RESOURCE)).getAccessToken().getScopes());
   if(listed&&enabled&&approved){before=f.fetches.get();success(f.refresh(text(token,"refresh_token")));assertEquals(before+1,f.fetches.get());}
  }))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unsupportedTokenRequestsNeverBecomeSupportedOrFetchMetadata(){
  return EXTRAS.stream().map(grant->DynamicTest.dynamicTest(grant,()->{
   Fixture f=new Fixture(vscode(),true,true);var rows=Map.copyOf(f.store.rows);var result=f.server.tokenResult("POST",null,form(Map.of("client_id",f.id,"grant_type",grant,"resource",RESOURCE)).getBytes(StandardCharsets.UTF_8),headers());
   var rejected=assertInstanceOf(OAuthTokenResult.Rejected.class,result);assertEquals(OAuthServerException.Reason.UNSUPPORTED_GRANT_TYPE,rejected.getReason());assertEquals(400,rejected.getResponse().getStatusCode());assertEquals("{\"error\":\"unsupported_grant_type\"}",new String(rejected.getResponse().toHttpBodyWithCredentials(),StandardCharsets.US_ASCII));assertEquals(0,f.fetches.get());assertEquals(rows,f.store.rows);
   var advertised=(JsonArray)requireNonNull(json(f.server.metadataResponse("GET").toHttpBodyWithCredentials()).getMembers().get("grant_types_supported"));assertEquals(strings("authorization_code","refresh_token"),advertised);
  }));
 }
 @Test void changingOnlyIgnoredGrantsPreservesCodeAndRefreshBindings() throws Exception {
  Fixture f=new Fixture(vscode(),true,true);String code=f.code(REDIRECT);f.body=bytes(grants("password","refresh_token","authorization_code","client_credentials"));
  JsonObject token=json(success(f.redeem(code,REDIRECT,VERIFIER)).toHttpBodyWithCredentials());f.body=bytes(grants("refresh_token","authorization_code"));int before=f.fetches.get();success(f.refresh(text(token,"refresh_token")));assertEquals(before+1,f.fetches.get());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> changingRefreshDeclarationStillRequiresTheOriginalFingerprint(){
  return Stream.of("add-before-code","remove-before-code","remove-before-refresh").map(mode->DynamicTest.dynamicTest(mode,()->{
   boolean originalRefresh=!mode.equals("add-before-code");JsonObject original=originalRefresh?vscode():grants("authorization_code",EXTRAS.get(0));Fixture f=new Fixture(original,true,true);String code=f.code(REDIRECT),credential=code;
   if(mode.equals("remove-before-refresh"))credential=text(json(success(f.redeem(code,REDIRECT,VERIFIER)).toHttpBodyWithCredentials()),"refresh_token");
   var rows=Map.copyOf(f.store.rows);f.body=bytes(originalRefresh?grants("authorization_code",EXTRAS.get(0)):vscode());
   OAuthTokenResult result=mode.equals("remove-before-refresh")?f.refresh(credential):f.redeem(code,REDIRECT,VERIFIER);assertEquals(OAuthServerException.Reason.INVALID_GRANT,assertInstanceOf(OAuthTokenResult.Rejected.class,result).getReason());assertEquals(rows,f.store.rows);
   f.body=bytes(original);if(mode.equals("remove-before-refresh"))success(f.refresh(credential));else success(f.redeem(code,REDIRECT,VERIFIER));
  }));
 }
}
