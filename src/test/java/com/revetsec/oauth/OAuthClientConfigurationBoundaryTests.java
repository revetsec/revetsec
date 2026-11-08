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

package com.revetsec.oauth;

import com.revetsec.oidc.*;
import com.revetsec.jose.*;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Public construction and real private-TLS discovery/completion classification. Synthetic fixtures only. */
final class OAuthClientConfigurationBoundaryTests {
 private static final @NonNull URI CALLBACK=URI.create("https://rp.example/callback");
 private static final @NonNull Instant NOW=Instant.parse("2026-11-05T12:00:00Z");
 private static @NonNull AuthorizationResponse response(@NonNull PendingAuthorization pending,boolean wrongIssuer){return assertInstanceOf(AuthorizationResponseParseResult.Succeeded.class,AuthorizationResponse.fromQueryStringResult("state="+pending.state()+"&code=TEST-ONLY-code"+(wrongIssuer?"&iss=https%3A%2F%2Fwrong.example":""))).getResponse();}
 private static @NonNull PendingAuthorizationSource sealed(@NonNull PendingAuthorization pending){var sealer=TestSealers.fromFixedKey();return PendingAuthorizationSource.fromSealedForm(pending.toSealedForm(sealer,"classification"),sealer,"classification");}
 private static @NonNull String metadata(@NonNull TestHttpsServer server,boolean wrong){return JsonObject.builder().put("issuer",wrong?"https://wrong.example/PRIVATE-MARKER":server.uri("/tenant").toString()).put("authorization_endpoint",server.uri("/authorize").toString()).put("token_endpoint",server.uri("/token").toString()).put("jwks_uri",server.uri("/jwks").toString()).put("subject_types_supported",com.revetsec.json.JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("public")))).put("response_types_supported",com.revetsec.json.JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("code")))).put("id_token_signing_alg_values_supported",com.revetsec.json.JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("RS256")))).build().toJson();}
 private static TestHttpsServer.@NonNull Response json(@NonNull String body){return TestHttpsServer.Response.withStatus(200).header("Content-Type","application/json").header("Cache-Control","max-age=30").body(body.getBytes(StandardCharsets.UTF_8)).build();}
 private static void fixedFailure(@NonNull OAuthConfigurationException failure){assertEquals(OAuthException.Reason.ISSUER_MISMATCH,failure.getReason());assertFalse(failure.isTemporaryCondition());assertNull(failure.getCause());assertFalse(failure.toString().contains("PRIVATE-MARKER"));}
 @TestFactory @NonNull List<@NonNull DynamicTest> discoveryIdentityFailureIsInfrastructureAndCallbackIdentityFailureIsAResult(){
  List<DynamicTest> tests=new ArrayList<>();for(boolean oidc:List.of(false,true))for(String phase:List.of("begin","complete","callback"))tests.add(DynamicTest.dynamicTest((oidc?"oidc-":"oauth-")+phase,()->{
   try(TestHttpsServer server=TestHttpsServer.start()){
    String path=oidc?"/tenant/.well-known/openid-configuration":"/.well-known/oauth-authorization-server/tenant";
    server.script(path,TestHttpsServer.Script.fromSequence(List.of(json(metadata(server,phase.equals("begin"))),json(metadata(server,true)))));
    RewindableClock clock=RewindableClock.fromInstant(NOW);AtomicInteger rejected=new AtomicInteger();
    OAuthObserver observer=new OAuthObserver(){@Override public void didRejectCallback(@NonNull OAuthValidationException failure){rejected.incrementAndGet();}};
    OidcObserver oidcObserver=new OidcObserver(){@Override public void didRejectCallback(@NonNull OAuthValidationException failure){rejected.incrementAndGet();}};
    OAuthClient oauth=OAuthClient.withIssuer(server.uri("/tenant").toString()).clientId("client").clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK).httpClient(TestTls.httpClient()).clock(clock).minimumTimeToLive(Duration.ofSeconds(30)).defaultTimeToLive(Duration.ofSeconds(30)).maximumTimeToLive(Duration.ofMinutes(1)).observer(observer).build();
    OidcClient identity=OidcClient.withIssuer(server.uri("/tenant").toString()).clientId("client").clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK).httpClient(TestTls.httpClient()).clock(clock).minimumTimeToLive(Duration.ofSeconds(30)).defaultTimeToLive(Duration.ofSeconds(30)).maximumTimeToLive(Duration.ofMinutes(1)).jwksSource(StaticJwksSource.fromJwks(assertInstanceOf(JwksParseResult.Succeeded.class,Jwks.fromJsonResult(TestJwk.withFixture(TestJwk.Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson())).getJwks())).observer(oidcObserver).build();
    if(phase.equals("begin")){
     OAuthConfigurationException first=assertThrows(OAuthConfigurationException.class,()->{if(oidc)identity.beginAuthentication();else oauth.beginAuthorization();});fixedFailure(first);
     OAuthConfigurationException second=assertThrows(OAuthConfigurationException.class,()->{if(oidc)identity.beginAuthentication();else oauth.beginAuthorization();});fixedFailure(second);assertNotSame(first,second);assertEquals(1,server.getHitCount(path));
    }else{
     PendingAuthorization pending=(oidc?identity.beginAuthentication():oauth.beginAuthorization()).getPendingAuthorization();var source=sealed(pending);clock.advance(Duration.ofSeconds(31));var callback=response(pending,phase.equals("callback"));
     if(phase.equals("callback")){
      if(oidc)assertEquals(OAuthException.Reason.ISSUER_MISMATCH,assertInstanceOf(OidcAuthenticationResult.RejectedAuthorization.class,identity.completeAuthenticationResult(callback,source,CALLBACK)).getReason());
      else assertEquals(OAuthException.Reason.ISSUER_MISMATCH,assertInstanceOf(AuthorizationCompletionResult.Rejected.class,oauth.completeAuthorizationResult(callback,source,CALLBACK)).getReason());
      assertEquals(1,rejected.get());assertEquals(1,server.getHitCount(path));
     }else{
      fixedFailure(assertThrows(OAuthConfigurationException.class,()->{if(oidc)assertNotNull(identity.completeAuthenticationResult(callback,source,CALLBACK));else assertNotNull(oauth.completeAuthorizationResult(callback,source,CALLBACK));}));
      fixedFailure(assertThrows(OAuthConfigurationException.class,()->{if(oidc)assertNotNull(identity.completeAuthenticationResult(callback,source,CALLBACK));else assertNotNull(oauth.completeAuthorizationResult(callback,source,CALLBACK));}));assertEquals(0,rejected.get());assertEquals(2,server.getHitCount(path));
     }
    }
    assertEquals(0,server.getHitCount("/token"));assertEquals(0,server.getHitCount("/jwks"));
   }
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> tokenSourceRejectsPublicAuthenticationWithoutCallbacksOrDiscovery(){
  List<DynamicTest> tests=new ArrayList<>();for(boolean discovery:List.of(false,true))tests.add(DynamicTest.dynamicTest("public-"+discovery,()->{
   OAuthClient.Builder builder=discovery?OAuthClient.withIssuer("https://issuer.example"):OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer("https://issuer.example").authorizationEndpoint(URI.create("https://issuer.example/authorize")).tokenEndpoint(URI.create("https://issuer.example/token")).build());
   OAuthClient client=builder.clientId("client").clientAuthentication(ClientAuthentication.noneInstance()).build();assertThrows(IllegalArgumentException.class,()->ClientCredentialsTokenSource.withClient(client).build());
  }));return tests;
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> confidentialStrategiesBuildWithoutSecretOrKeyProviderWork(){
  AtomicInteger calls=new AtomicInteger();List<ClientAuthentication> strategies=List.of(ClientAuthentication.fromClientSecretBasic("secret"),ClientAuthentication.fromClientSecretPost("secret"),ClientAuthentication.fromClientSecretBasic("secret",ClientSecretBasicEncoding.UNENCODED),ClientAuthentication.fromClientSecretPost(()->{calls.incrementAndGet();return "secret";}),ClientAuthentication.fromPrivateKeyJwt(budget->{calls.incrementAndGet();throw new AssertionError("construction callback");}));List<DynamicTest> tests=new ArrayList<>();
  for(int i=0;i<strategies.size();i++){ClientAuthentication authentication=strategies.get(i);tests.add(DynamicTest.dynamicTest("confidential-"+i,()->{var client=OAuthClient.withIssuer("https://issuer.example").clientId("client").clientAuthentication(authentication).build();assertNotNull(ClientCredentialsTokenSource.withClient(client).build());assertEquals(0,calls.get());}));}return tests;
 }
 @Test void directParsersRetainUnambiguousDocumentDiagnostics(){
  String document="{\"issuer\":\"https://other.example\",\"authorization_endpoint\":\"https://issuer.example/authorize\",\"token_endpoint\":\"https://issuer.example/token\"}";
  assertEquals(OAuthException.Reason.ISSUER_MISMATCH,assertInstanceOf(AuthorizationServerMetadataParseResult.Rejected.class,AuthorizationServerMetadata.fromJsonResult("https://issuer.example",document)).getReason());
  assertEquals(OAuthException.Reason.ISSUER_MISMATCH,assertInstanceOf(OidcProviderMetadataParseResult.Rejected.class,OidcProviderMetadata.fromJsonResult("https://issuer.example",document)).getReason());
 }
}
