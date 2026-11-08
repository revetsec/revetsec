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

import com.revetsec.ErrorCategory;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static com.revetsec.oauth.server.OAuthServerException.Reason.*;
import static java.util.Objects.requireNonNull;

/** Public failure categories must distinguish dependency availability, trusted decisions and client input. */
final class OAuthServerFailureClassificationTests {
 private static final @NonNull String ISSUER="https://issuer.example/tenant",RESOURCE="https://resource.example/mcp",REDIRECT="https://client.example/cb";
 private static final @NonNull String BROWSER="A".repeat(43),VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",SENSITIVE="TEST-ONLY-private-callback-data";
 private static final @NonNull Instant NOW=Instant.parse("2026-11-01T12:00:00Z");
 private enum Phase { BEGIN, CONSENT, CODE, REFRESH, REVOCATION, INTROSPECTION }
 private enum Callback { REGISTRY, VERIFIER, POLICY }
 private static final class Fatal extends VirtualMachineError {private static final long serialVersionUID=1L;}
 private static final class Events implements OAuthServerObserver {
  int will,success,rejected;final @NonNull List<@NonNull OAuthServerException> failures=new ArrayList<>();
  @Override public void willHandleEndpoint(@NonNull Endpoint e){this.will++;}
  @Override public void didHandleEndpoint(@NonNull Endpoint e,@Nullable Integer status,@NonNull Duration elapsed){this.success++;}
  @Override public void didRejectEndpoint(@NonNull Endpoint e,OAuthServerException.@NonNull Reason reason,@Nullable Integer status,@NonNull Duration elapsed){this.rejected++;}
  @Override public void didFailToHandleEndpoint(@NonNull Endpoint e,@NonNull OAuthServerException failure,@NonNull Duration elapsed){this.failures.add(failure);}
  void clear(){this.will=0;this.success=0;this.rejected=0;this.failures.clear();}
 }
 private static @NonNull OAuthAuthorizationDecision decision(@NonNull String subject,@NonNull String resource,@NonNull Set<@NonNull String> scopes,boolean refresh){
  return OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(Map.of(resource,scopes)).refreshTokenPermitted(refresh).build();
 }
 private static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> fields){
  return String.join("&",fields.entrySet().stream().map(e->{try{return FormUrlEncoding.encode(e.getKey())+"="+FormUrlEncoding.encode(e.getValue());}catch(com.revetsec.internal.encoding.EncodingException f){throw new AssertionError(f);}}).toList());
 }
 private static @NonNull String member(@NonNull OAuthServerResponse response,@NonNull String name){
  try{return ((JsonString)((JsonObject)JsonCodec.parse(response.toHttpBodyWithCredentials(),JsonLimits.protocolDocument(16384))).find(name).orElseThrow()).getValue();}catch(com.revetsec.internal.json.JsonParseException f){throw new AssertionError(f);}
 }
 private static final class Fixture {
  final @NonNull OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture(NOW);final @NonNull Events events=new Events();
  final @NonNull Fatal fatal=new Fatal();final @NonNull OAuthAuthorizationServer server;
  @Nullable String registryFault,verifierFault,policyFault,invalidPolicy;
  byte @Nullable [] lastSecret;
  boolean approvalRefresh=true;
  Fixture(){
   byte[] material=new byte[32];for(int i=0;i<material.length;i++)material[i]=(byte)(i+1);
   var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key",Base64.getEncoder().encodeToString(material))).clock(Clock.fixed(NOW,ZoneOffset.UTC)).build();
   var client=OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT)))
    .allowedScopesByResource(Map.of(RESOURCE,Set.of("read","write"))).refreshTokenPermitted(true)
    .authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->{
     this.lastSecret=secret;String mode=this.verifierFault;if(mode!=null){fault(mode);if(mode.equals("null"))return nullBoolean();}return true;
    })).build();
   var resourceClient=OAuthServerClientRegistration.withClientId("resource").configurationVersion("r1").authorizationCodePermitted(false)
    .introspectionResources(Set.of(RESOURCE)).authentication(client.getAuthentication()).build();
   var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
   this.server=OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token"))
    .jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke")).introspectionEndpoint(URI.create(ISSUER+"/introspect"))
    .clientRepository((id,budget)->{String mode=this.registryFault;if(mode!=null){fault(mode);if(mode.equals("null"))return nullRegistration();}return id.equals("resource")?Optional.of(resourceClient):id.equals("client")?Optional.of(client):Optional.empty();})
    .store(this.store).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("signing",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(NOW.minusSeconds(120)).build()))
    .stateSealer(sealer).clock(Clock.fixed(NOW,ZoneOffset.UTC)).maximumSubjectLength(255).resources(Map.of(RESOURCE,Set.of("read","write")))
    .grantPolicy((context,budget)->{
     String mode=this.policyFault;if(mode!=null){fault(mode);if(mode.equals("null"))return nullDecision();}
     String invalid=this.invalidPolicy;
     return decision("subject".equals(invalid)?"other":context.getSubject(),"resource".equals(invalid)?"https://other.example/mcp":RESOURCE,
      "scope".equals(invalid)?Set.of("admin"):requireNonNull(context.getAuthorizedScopesByResource().get(RESOURCE)),"refresh".equals(invalid)||context.isRefreshTokenPermitted());
    }).refreshTokensEnabled(true).observer(this.events).acknowledgeUnpatchedRuntime(true).build();
   assertEquals(OAuthStoreCommitStatus.COMMITTED,this.server.initializeFreshIssuer().getStatus());this.server.establishNewSubject("subject");this.events.clear();
  }
  void fault(@NonNull String mode){switch(mode){
   case "io"->raise(new IOException(SENSITIVE));case "runtime"->throw new IllegalStateException(SENSITIVE);
   case "argument"->throw new IllegalArgumentException(SENSITIVE);case "injected"->throw OAuthServerConfigurationException.fromReason(CONFIGURATION_INVALID);
   case "interrupt"->raise(new InterruptedException(SENSITIVE));case "flag"->Thread.currentThread().interrupt();case "fatal"->throw this.fatal;
   default->{ }
  }}
  void set(@NonNull Callback callback,@Nullable String mode){switch(callback){case REGISTRY->this.registryFault=mode;case VERIFIER->this.verifierFault=mode;case POLICY->this.policyFault=mode;}}
  @NonNull OAuthServerInteraction begin(){return assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,this.server.beginAuthorizationResult("GET",form(Map.of("client_id","client","response_type","code","redirect_uri",REDIRECT,"resource",RESOURCE,"scope","read write","code_challenge",CHALLENGE,"code_challenge_method","S256","state","opaque")),new byte[0],Map.of(),BROWSER)).getInteraction();}
  @NonNull OAuthAuthorizationDecision approval(){return decision("subject",RESOURCE,Set.of("read","write"),this.approvalRefresh);}
  @NonNull OAuthAuthorizationResult complete(@NonNull OAuthServerInteraction interaction,@NonNull OAuthAuthorizationDecision approval){return this.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,approval);}
  @NonNull String code(){String query=assertInstanceOf(OAuthAuthorizationResult.Completed.class,complete(begin(),approval())).getResponse().getLocationWithCredentials().orElseThrow().getRawQuery();return Stream.of(query.split("&")).filter(s->s.startsWith("code=")).findFirst().orElseThrow().substring(5);}
  @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(){return headers("client");}
  @NonNull Map<@NonNull String,@NonNull List<@NonNull String>> headers(@NonNull String client){return Map.of("Content-Type",List.of("application/x-www-form-urlencoded"),"Authorization",List.of("Basic "+Base64.getEncoder().encodeToString((client+":secret").getBytes(StandardCharsets.US_ASCII))));}
  @NonNull OAuthTokenResult redeem(@NonNull String code){return this.server.tokenResult("POST",null,form(Map.of("grant_type","authorization_code","code",code,"code_verifier",VERIFIER,"redirect_uri",REDIRECT,"resource",RESOURCE)).getBytes(StandardCharsets.UTF_8),headers());}
  @NonNull OAuthTokenResult rotate(@NonNull String token){return this.server.tokenResult("POST",null,form(Map.of("grant_type","refresh_token","refresh_token",token,"resource",RESOURCE)).getBytes(StandardCharsets.UTF_8),headers());}
  @NonNull OAuthServerResponse issued(){return assertInstanceOf(OAuthTokenResult.Succeeded.class,redeem(code())).getResponse();}
  @NonNull Supplier<@NonNull Object> attempt(@NonNull Phase phase){return switch(phase){
   case BEGIN->()->begin();
   case CONSENT->{var interaction=begin();yield ()->complete(interaction,approval());}
   case CODE->{String code=code();yield ()->redeem(code);}
   case REFRESH->{String refresh=member(issued(),"refresh_token");yield ()->rotate(refresh);}
   case REVOCATION->{String access=member(issued(),"access_token");yield ()->this.server.revokeResult("POST",null,form(Map.of("token",access)).getBytes(StandardCharsets.UTF_8),headers());}
   case INTROSPECTION->{String access=member(issued(),"access_token");yield ()->this.server.introspectionResult("POST",null,form(Map.of("token",access)).getBytes(StandardCharsets.UTF_8),headers("resource"));}
  };}
  void checkFailure(@NonNull Supplier<@NonNull Object> attempt,boolean configuration){
   var rows=Map.copyOf(this.store.rows);this.events.clear();OAuthServerException failure=assertThrows(OAuthServerException.class,attempt::get);
   if(configuration){assertInstanceOf(OAuthServerConfigurationException.class,failure);assertEquals(CONFIGURATION_INVALID,failure.getReason());assertEquals(ErrorCategory.CONFIGURATION,failure.getCategory());}
   else {assertInstanceOf(OAuthServerTransportException.class,failure);assertEquals("SERVICE_UNAVAILABLE",failure.getReason().name());assertEquals(ErrorCategory.TRANSPORT,failure.getCategory());}
   assertFalse(failure.isTemporaryCondition());assertNull(failure.getCause());assertEquals(0,failure.getSuppressed().length);assertFalse(failure.toString().contains(SENSITIVE));assertFalse(requireNonNull(failure.getMessage()).contains(SENSITIVE));
   var response=this.server.responseForFailure(failure);assertEquals(503,response.getStatusCode());assertEquals("{\"error\":\"server_error\"}",new String(response.toHttpBodyWithCredentials(),StandardCharsets.US_ASCII));assertTrue(response.getLocationWithCredentials().isEmpty());
   assertEquals(rows,this.store.rows);assertEquals(1,this.events.will);assertEquals(0,this.events.success);assertEquals(0,this.events.rejected);assertEquals(List.of(failure),this.events.failures);
  }
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> callbackAvailabilityIsNotConfigurationOrClientRejection(){
  return Stream.of(Callback.values()).flatMap(callback->Stream.of(Phase.values()).filter(phase->eligible(callback,phase)).flatMap(phase->Stream.of("io","runtime","argument","injected","null","interrupt","flag").map(mode->DynamicTest.dynamicTest(callback+"/"+phase+"/"+mode,()->{
   Fixture f=new Fixture();var attempt=f.attempt(phase);f.set(callback,mode);
   try{f.checkFailure(attempt,false);assertEquals(mode.equals("interrupt")||mode.equals("flag"),Thread.currentThread().isInterrupted());if(callback==Callback.VERIFIER){for(byte value:requireNonNull(f.lastSecret))assertEquals(0,value);}}
   finally{Thread.interrupted();f.set(callback,null);}
   recovered(phase,attempt);
  }))));
 }
 private static boolean eligible(@NonNull Callback callback,@NonNull Phase phase){return switch(callback){case REGISTRY->true;case VERIFIER->phase!=Phase.BEGIN&&phase!=Phase.CONSENT;case POLICY->phase==Phase.CONSENT||phase==Phase.CODE||phase==Phase.REFRESH;};}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> returnedPolicyContractViolationsAreConfigurationAndRetainCredentials(){
  return Stream.of(Phase.CONSENT,Phase.CODE,Phase.REFRESH).flatMap(phase->Stream.of("subject","scope","resource","refresh").filter(mode->!mode.equals("refresh")||phase!=Phase.REFRESH).map(mode->DynamicTest.dynamicTest(phase+"/"+mode,()->{
   Fixture f=new Fixture();if(mode.equals("refresh"))f.approvalRefresh=false;var attempt=f.attempt(phase);f.invalidPolicy=mode;f.checkFailure(attempt,true);f.invalidPolicy=null;recovered(phase,attempt);
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidTrustedConsentIsNotAnUntrustedRequestError(){
  return Stream.of("scope","resource","subject-cap").map(mode->DynamicTest.dynamicTest(mode,()->{
   Fixture f=new Fixture();var interaction=f.begin();var invalid=decision(mode.equals("subject-cap")?"s".repeat(256):"subject",mode.equals("resource")?"https://other.example/mcp":RESOURCE,mode.equals("scope")?Set.of("admin"):Set.of("read"),true);
   f.checkFailure(()->f.complete(interaction,invalid),true);assertInstanceOf(OAuthAuthorizationResult.Completed.class,f.complete(interaction,f.approval()));
  }));
 }
 private static void recovered(@NonNull Phase phase,@NonNull Supplier<@NonNull Object> attempt){
  Object result=assertDoesNotThrow(attempt::get);
  switch(phase){
   case BEGIN->assertInstanceOf(OAuthServerInteraction.class,result);
   case CONSENT->assertInstanceOf(OAuthAuthorizationResult.Completed.class,result);
   case CODE,REFRESH->assertInstanceOf(OAuthTokenResult.Succeeded.class,result);
   case REVOCATION->assertInstanceOf(OAuthRevocationResult.Succeeded.class,result);
   case INTROSPECTION->assertInstanceOf(OAuthIntrospectionResult.Succeeded.class,result);
  }
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> fatalCallbackFailuresRemainFatal(){return Stream.of(Callback.values()).map(callback->DynamicTest.dynamicTest(callback.name(),()->{
  Fixture f=new Fixture();var attempt=f.attempt(callback==Callback.REGISTRY?Phase.BEGIN:callback==Callback.VERIFIER?Phase.CODE:Phase.CONSENT);var rows=Map.copyOf(f.store.rows);f.set(callback,"fatal");assertSame(f.fatal,assertThrows(Fatal.class,attempt::get));assertEquals(rows,f.store.rows);
 }));}
 @Test void missingRegisteredClientRemainsValidation(){Fixture f=new Fixture();var result=assertInstanceOf(OAuthAuthorizationResult.Rejected.class,f.server.beginAuthorizationResult("GET","client_id=unknown&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&resource=https%3A%2F%2Fresource.example%2Fmcp&code_challenge="+CHALLENGE+"&code_challenge_method=S256",new byte[0],Map.of(),BROWSER));assertEquals(INVALID_CLIENT,result.getReason());assertEquals(400,result.getResponse().getStatusCode());assertEquals(1,f.events.rejected);assertTrue(f.events.failures.isEmpty());}
 @SuppressWarnings("NullAway") private static @NonNull Optional<@NonNull OAuthServerClientRegistration> nullRegistration(){return null;}
 @SuppressWarnings("NullAway") private static @NonNull Boolean nullBoolean(){return null;}
 @SuppressWarnings("NullAway") private static @NonNull OAuthAuthorizationDecision nullDecision(){return null;}
 @SuppressWarnings("unchecked") private static <T extends Throwable> void raise(@NonNull Throwable failure) throws T {throw (T)failure;}
}
