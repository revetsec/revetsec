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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.util.stream.Stream;

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;
import com.revetsec.internal.http.Deadline;
import com.revetsec.jose.*;
import com.revetsec.oauth.*;
import com.revetsec.testing.*;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;
import static com.revetsec.oauth.server.OAuthServerException.Reason.*;

/** Restricted public boundary and fixed normative wire/error/event contracts; no public engine claim. */
final class OAuthServerOutcomeTests {
 private static final @NonNull String HANDLE="A".repeat(43), RESOURCE="https://resource.example/mcp";
 private static final @NonNull Instant NOW=Instant.parse("2026-10-06T00:00:00Z");
 private static final @NonNull OAuthServerIngressLimits LIMITS=OAuthServerIngressLimits.fromDefaults();
 private static @NonNull OAuthServerResponse response() { return OAuthServerFailureBoundary.failure(OAuthServerConfigurationException.fromReason(CONFIGURATION_INVALID),32768,16384); }
 private static @NonNull OAuthAuthorizationRecord pending() {
  OAuthServerClientRegistration client=OAuthServerClientRegistration.withClientId("TEST-ONLY-client")
   .redirectUris(List.of(URI.create("https://client.example/cb?x=%2f"))).allowedScopesByResource(Map.of(RESOURCE,Set.of("read"))).configurationVersion("v1").build();
  OAuthServerRequest request=OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",
   "client_id=TEST-ONLY-client&response_type=code&redirect_uri=https%3A%2F%2Fclient.example%2Fcb%3Fx%3D%252f&code_challenge_method=S256&code_challenge="+HANDLE+"&resource=https%3A%2F%2Fresource.example%2Fmcp&state=TEST-ONLY-private-state",new byte[0],Map.of(),LIMITS);
  OAuthServerAuthorizationAdmission admitted=OAuthServerAuthorizationAdmission.admit(request,(id,b)->Optional.of(client),Deadline.fromNow(Duration.ofSeconds(10)),Map.of(RESOURCE,Set.of("read")),LIMITS,false,false);
  return OAuthAuthorizationRecord.interaction(OAuthAuthorizationRecord.credentialDigest(HANDLE),HANDLE,
   OAuthAuthorizationRecord.clientFingerprint(client),admitted,OAuthStoreFence.initialIssuer(HANDLE,NOW),NOW.plusSeconds(900),LIMITS);
 }
 private static @NonNull OAuthServerInteraction interaction() { return OAuthServerInteraction.fromRecord(HANDLE,pending(),"<TEST-ONLY-untrusted-name>",LIMITS); }
 private static @NonNull VerifiedAccessToken proof() {
  String payload="{\"iss\":\"https://issuer.example\",\"sub\":\"TEST-ONLY-subject\",\"aud\":\""+RESOURCE+"\",\"iat\":"+NOW.getEpochSecond()+",\"exp\":"+NOW.plusSeconds(300).getEpochSecond()+",\"client_id\":\"TEST-ONLY-client\",\"jti\":\"TEST-ONLY-jti\",\"scope\":\"read\"}";
  String compact=TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("key").typ("at+jwt").payload(payload).sign(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
  StaticJsonWebKeySource keys=StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(TestJsonWebKeys.withFixture(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson()));
  return JwtAccessTokenValidator.withIssuer("https://issuer.example").jsonWebKeySource(keys).expectedAudiences(Set.of(RESOURCE)).clock(Clock.fixed(NOW,ZoneOffset.UTC)).clockSkew(Duration.ZERO).build()
   .validate(BearerToken.fromAuthorizationHeaderValues(List.of("Bearer "+compact),65536).orElseThrow());
 }
 @Test void checkedPendingViewHasOnlyReviewedFactsAndImmutableScopes() {
  OAuthServerInteraction view=interaction(); assertEquals(HANDLE,view.getInteractionValue());assertEquals("TEST-ONLY-client",view.getClientId());
  assertEquals(Optional.of("<TEST-ONLY-untrusted-name>"),view.getClientName());assertEquals("https://client.example/cb?x=%2f",view.getRedirectUri().toString());
  assertEquals(Map.of(RESOURCE,Set.of("read")),view.getRequestedScopesByResource());assertEquals(NOW.plusSeconds(900),view.getExpiresAt());
  assertThrows(UnsupportedOperationException.class,()->view.getRequestedScopesByResource().put("other",Set.of("write")));
  assertThrows(UnsupportedOperationException.class,()->requireNonNull(view.getRequestedScopesByResource().get(RESOURCE)).add("write"));
  assertNotEquals(view,interaction());assertEquals("OAuthServerInteraction{<redacted>}",view.toString());
  assertTrue(OAuthServerInteraction.fromRecord(HANDLE,pending(),null,LIMITS).getClientName().isEmpty());
  Set<String> getters=new HashSet<>();for(var method:OAuthServerInteraction.class.getDeclaredMethods()) if(Modifier.isPublic(method.getModifiers())) getters.add(method.getName());
  assertEquals(Set.of("getInteractionValue","getClientId","getClientName","getRedirectUri","getRequestedScopesByResource","getExpiresAt","toString"),getters);
 }
 @Test void completedRecordWrongHandleAndUnboundedNameCannotMintPendingView() {
  assertThrows(IllegalArgumentException.class,()->OAuthServerInteraction.fromRecord(HANDLE,pending().completed(),null,LIMITS));
  assertThrows(IllegalArgumentException.class,()->OAuthServerInteraction.fromRecord("B".repeat(42)+"A",pending(),null,LIMITS));
  assertThrows(IllegalArgumentException.class,()->OAuthServerInteraction.fromRecord("bad",pending(),null,LIMITS));
  assertThrows(IllegalArgumentException.class,()->OAuthServerInteraction.fromRecord(HANDLE,pending(),"x".repeat(256),LIMITS));
 }
 @Test void outcomesAreIdentityEqualRestrictedAndRetainOnlyReviewedHolders() {
  OAuthServerInteraction view=interaction();OAuthServerResponse wire=response();
  assertSame(view,assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,OAuthAuthorizationResult.fromInteractionRequired(view)).getInteraction());
  assertSame(wire,assertInstanceOf(OAuthAuthorizationResult.Completed.class,OAuthAuthorizationResult.fromCompleted(wire)).getResponse());
  assertSame(wire,assertInstanceOf(OAuthAuthorizationResult.Denied.class,OAuthAuthorizationResult.fromDenied(wire)).getResponse());
  assertSame(wire,assertInstanceOf(OAuthTokenResult.Succeeded.class,OAuthTokenResult.fromSucceeded(wire)).getResponse());
  assertSame(wire,assertInstanceOf(OAuthRevocationResult.Succeeded.class,OAuthRevocationResult.fromSucceeded(wire)).getResponse());
  assertSame(wire,assertInstanceOf(OAuthIntrospectionResult.Succeeded.class,OAuthIntrospectionResult.fromSucceeded(wire)).getResponse());
  VerifiedAccessToken proof=proof();assertSame(proof,assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,OAuthIssuerAccessTokenResult.fromSucceeded(proof)).getAccessToken());
  for(Object outcome:List.of(OAuthAuthorizationResult.fromCompleted(wire),OAuthAuthorizationResult.fromDenied(wire),OAuthAuthorizationResult.fromInteractionRequired(view),OAuthTokenResult.fromSucceeded(wire),OAuthRevocationResult.fromSucceeded(wire),OAuthIntrospectionResult.fromSucceeded(wire),OAuthIssuerAccessTokenResult.fromSucceeded(proof))) {
   assertTrue(outcome.toString().endsWith("{<redacted>}"));assertFalse(outcome.toString().contains("TEST-ONLY"));
  }
  assertNotEquals(OAuthTokenResult.fromSucceeded(wire),OAuthTokenResult.fromSucceeded(wire));
 }
 @Test void sealedOutcomesAndErrorsHaveNoPublicMintingOrSubclassingSeam() {
  for(Class<?> base:List.of(OAuthAuthorizationResult.class,OAuthTokenResult.class,OAuthRevocationResult.class,OAuthIntrospectionResult.class,OAuthIssuerAccessTokenResult.class,OAuthServerException.class)) {
   assertTrue(base.isSealed());restricted(base);
   for(Class<?> variant:base.getPermittedSubclasses()) {assertTrue(Modifier.isFinal(variant.getModifiers()));restricted(variant);}
  }
  restricted(OAuthServerInteraction.class);
  for(Class<?> type:List.of(OAuthIssuerAccessTokenResult.Rejected.class,OAuthAuthorizationResult.Rejected.class,OAuthTokenResult.Rejected.class,OAuthRevocationResult.Rejected.class,OAuthIntrospectionResult.Rejected.class))
   for(var field:type.getDeclaredFields()) assertFalse(Throwable.class.isAssignableFrom(field.getType())||VerifiedAccessToken.class.isAssignableFrom(field.getType()));
 }
 private static void restricted(@NonNull Class<?> type) {
  for(var c:type.getDeclaredConstructors()) assertFalse(Modifier.isPublic(c.getModifiers())||Modifier.isProtected(c.getModifiers()));
  for(var m:type.getDeclaredMethods()) assertFalse(Modifier.isStatic(m.getModifiers())&&(Modifier.isPublic(m.getModifiers())||Modifier.isProtected(m.getModifiers())));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> familyCategoriesAndTransienceAreFixed() { return Stream.of(OAuthServerException.Reason.values()).map(value->DynamicTest.dynamicTest("familyCategoriesAndTransienceAreFixed["+value.name()+"]",()->familyCategoriesAndTransienceAreFixedCase(value))); }
 private void familyCategoriesAndTransienceAreFixedCase(OAuthServerException.@NonNull Reason reason) {
  OAuthServerException failure=failure(reason,false);assertEquals(reason,failure.getReason());assertInstanceOf(RevetsecException.class,failure);
  boolean unavailable=reason==STORE_UNAVAILABLE||reason==CLIENT_METADATA_UNAVAILABLE;
  assertFalse(failure.isTransient());assertEquals(unavailable,failure(reason,true).isTransient());
  assertNull(failure.getCause());failure.addSuppressed(new IllegalArgumentException("TEST-ONLY-sensitive-cause"));assertEquals(0,failure.getSuppressed().length);
  assertThrows(IllegalStateException.class,()->failure.initCause(new RuntimeException("TEST-ONLY-sensitive-cause")));
  assertFalse(requireNonNull(failure.getMessage()).contains("TEST-ONLY"));assertFalse(failure.toString().contains("TEST-ONLY"));
  if(reason==COMMIT_OUTCOME_UNKNOWN) {assertEquals(ErrorCategory.TRANSPORT,failure.getCategory());assertFalse(failure.isTransient());}
  if(reason==STORE_CORRUPT||reason==CONFIGURATION_INVALID||reason==SIGNING_FAILED) assertEquals(ErrorCategory.CONFIGURATION,failure.getCategory());
  if(validation(reason)) {
   assertInstanceOf(OAuthServerValidationException.class,failure);OAuthServerResponse response=response();
   OAuthAuthorizationResult.Rejected a=assertInstanceOf(OAuthAuthorizationResult.Rejected.class,OAuthAuthorizationResult.fromRejection(reason,response));assertEquals(reason,a.getReason());assertSame(response,a.getResponse());
   OAuthTokenResult.Rejected t=assertInstanceOf(OAuthTokenResult.Rejected.class,OAuthTokenResult.fromRejection(reason,response));assertEquals(reason,t.getReason());assertSame(response,t.getResponse());
   OAuthRevocationResult.Rejected r=assertInstanceOf(OAuthRevocationResult.Rejected.class,OAuthRevocationResult.fromRejection(reason,response));assertEquals(reason,r.getReason());assertSame(response,r.getResponse());
   OAuthIntrospectionResult.Rejected i=assertInstanceOf(OAuthIntrospectionResult.Rejected.class,OAuthIntrospectionResult.fromRejection(reason,response));assertEquals(reason,i.getReason());assertSame(response,i.getResponse());
   OAuthIssuerAccessTokenResult.Rejected v=assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,OAuthIssuerAccessTokenResult.fromRejection(reason,null,null));assertEquals(reason,v.getReason());assertTrue(v.getAccessTokenReason().isEmpty());assertTrue(v.getJoseReason().isEmpty());assertEquals(reason==MALFORMED_REQUEST?BearerError.INVALID_REQUEST:BearerError.INVALID_TOKEN,v.getBearerError());
   for(Object o:List.of(a,t,r,i,v)) assertTrue(o.toString().endsWith("{<redacted>}"));
  } else {
   assertThrows(IllegalArgumentException.class,()->OAuthTokenResult.fromRejection(reason,response()));
   assertThrows(IllegalArgumentException.class,()->OAuthIssuerAccessTokenResult.fromRejection(reason,null,null));
   assertThrows(IllegalArgumentException.class,()->OAuthServerValidationException.fromReason(reason));
  }
 }
 private static boolean validation(OAuthServerException.@NonNull Reason reason) { return switch(reason) {
  case STORE_UNAVAILABLE,STORE_CORRUPT,COMMIT_OUTCOME_UNKNOWN,CLIENT_METADATA_UNAVAILABLE,CONFIGURATION_INVALID,SIGNING_FAILED -> false;
  default -> true;
 }; }
 private static @NonNull OAuthServerException failure(OAuthServerException.@NonNull Reason reason,boolean interrupted) { return switch(reason) {
  case STORE_UNAVAILABLE,STORE_CORRUPT,COMMIT_OUTCOME_UNKNOWN -> OAuthServerStoreException.fromReason(reason,interrupted);
  case CLIENT_METADATA_UNAVAILABLE -> OAuthServerTransportException.fromReason(reason,interrupted);
  case CONFIGURATION_INVALID -> OAuthServerConfigurationException.fromReason(reason);
  case SIGNING_FAILED -> OAuthServerSigningException.fromReason(reason);
  default -> OAuthServerValidationException.fromReason(reason);
 }; }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> wrongLeafFactoriesRejectMisclassification() { return Stream.of(OAuthServerException.Reason.values()).map(value->DynamicTest.dynamicTest("wrongLeafFactoriesRejectMisclassification["+value.name()+"]",()->wrongLeafFactoriesRejectMisclassificationCase(value))); }
 private void wrongLeafFactoriesRejectMisclassificationCase(OAuthServerException.@NonNull Reason reason) {
  if(reason!=STORE_UNAVAILABLE&&reason!=STORE_CORRUPT&&reason!=COMMIT_OUTCOME_UNKNOWN) assertThrows(IllegalArgumentException.class,()->OAuthServerStoreException.fromReason(reason,false));
  if(reason!=CLIENT_METADATA_UNAVAILABLE) assertThrows(IllegalArgumentException.class,()->OAuthServerTransportException.fromReason(reason,false));
  if(reason!=CONFIGURATION_INVALID) assertThrows(IllegalArgumentException.class,()->OAuthServerConfigurationException.fromReason(reason));
  if(reason!=SIGNING_FAILED) assertThrows(IllegalArgumentException.class,()->OAuthServerSigningException.fromReason(reason));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> localWireErrorsAreFixedAndInfrastructureIsAlways503() { return Stream.of(OAuthServerException.Reason.values()).map(value->DynamicTest.dynamicTest("localWireErrorsAreFixedAndInfrastructureIsAlways503["+value.name()+"]",()->localWireErrorsAreFixedAndInfrastructureIsAlways503Case(value))); }
 private void localWireErrorsAreFixedAndInfrastructureIsAlways503Case(OAuthServerException.@NonNull Reason reason) {
  OAuthServerResponse infrastructure=OAuthServerFailureBoundary.failure(failure(reason,false),4096,1024);assertEquals(503,infrastructure.getStatusCode());assertEquals("{\"error\":\"server_error\"}",body(infrastructure));safe(infrastructure);
  if(!validation(reason)) {assertThrows(IllegalArgumentException.class,()->OAuthServerFailureBoundary.rejection(OAuthServerRequest.Endpoint.TOKEN,reason,false,4096,1024));return;}
  String expected=switch(reason) {
   case INVALID_CLIENT,UNKNOWN_CLIENT -> "invalid_client";case UNAUTHORIZED_CLIENT -> "unauthorized_client";
   case UNSUPPORTED_GRANT_TYPE -> "unsupported_grant_type";case UNSUPPORTED_RESPONSE_TYPE -> "unsupported_response_type";
   case INVALID_SCOPE -> "invalid_scope";case INVALID_RESOURCE -> "invalid_target";
   case INVALID_GRANT,REFRESH_REUSE,PKCE_MISMATCH -> "invalid_grant";case ACCESS_DENIED -> "access_denied";default -> "invalid_request";
  };
  for(OAuthServerRequest.Endpoint endpoint:OAuthServerRequest.Endpoint.values()) for(boolean basic:new boolean[]{false,true}) {
   OAuthServerResponse wire=OAuthServerFailureBoundary.rejection(endpoint,reason,basic,4096,1024);safe(wire);assertEquals("{\"error\":\""+expected+"\"}",body(wire));
   boolean challenged=expected.equals("invalid_client")&&endpoint!=OAuthServerRequest.Endpoint.AUTHORIZATION&&(basic||endpoint==OAuthServerRequest.Endpoint.INTROSPECTION);
   assertEquals(reason==METHOD_NOT_ALLOWED?405:challenged?401:400,wire.getStatusCode());
   assertEquals(challenged?List.of("Basic realm=\"oauth\""):null,wire.getHeaders().get("WWW-Authenticate"));
   assertEquals(reason==METHOD_NOT_ALLOWED?List.of(endpoint==OAuthServerRequest.Endpoint.AUTHORIZATION?"GET":"POST"):null,wire.getHeaders().get("Allow"));
  }
 }
 private static @NonNull String body(@NonNull OAuthServerResponse response) { return new String(response.toHttpBodyWithCredentials(),StandardCharsets.US_ASCII); }
 private static void safe(@NonNull OAuthServerResponse response) {
  assertTrue(response.getLocationWithCredentials().isEmpty());assertFalse(response.getHeaders().containsKey("Location"));
  assertEquals(List.of("no-store"),response.getHeaders().get("Cache-Control"));assertEquals(List.of("no-cache"),response.getHeaders().get("Pragma"));assertEquals(List.of("no-referrer"),response.getHeaders().get("Referrer-Policy"));
  assertEquals(List.of("application/json"),response.getHeaders().get("Content-Type"));assertEquals(List.of(Integer.toString(response.toHttpBodyWithCredentials().length)),response.getHeaders().get("Content-Length"));
  byte[] changed=response.toHttpBodyWithCredentials();Arrays.fill(changed,(byte)0);assertTrue(body(response).startsWith("{\"error\":"));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> internalAdmissionHasNoExternalExceptionChain() { return Stream.of(OAuthServerAdmissionFailure.Reason.values()).map(value->DynamicTest.dynamicTest("internalAdmissionHasNoExternalExceptionChain["+value.name()+"]",()->internalAdmissionHasNoExternalExceptionChainCase(value))); }
 private void internalAdmissionHasNoExternalExceptionChainCase(OAuthServerAdmissionFailure.@NonNull Reason reason) {
  OAuthServerException mapped=OAuthServerFailureBoundary.admission(new OAuthServerAdmissionFailure(reason));assertNull(mapped.getCause());assertEquals(0,mapped.getSuppressed().length);
  assertEquals(reason==OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE, mapped instanceof OAuthServerConfigurationException);
  if(reason!=OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE) assertInstanceOf(OAuthServerValidationException.class,mapped);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> storeTranslationPreservesUnknownAndInterrupt() { return Stream.of(OAuthStoreFailure.Reason.values()).map(value->DynamicTest.dynamicTest("storeTranslationPreservesUnknownAndInterrupt["+value.name()+"]",()->storeTranslationPreservesUnknownAndInterruptCase(value))); }
 private void storeTranslationPreservesUnknownAndInterruptCase(OAuthStoreFailure.@NonNull Reason reason) {
  OAuthServerStoreException mapped=OAuthServerFailureBoundary.store(new OAuthStoreFailure(reason));assertFalse(mapped.isTransient());
  try {Thread.currentThread().interrupt();assertFalse(OAuthServerFailureBoundary.store(new OAuthStoreFailure(reason)).isTransient());assertTrue(Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}
 }
 @Test void explicitTimeoutIoOrHeldBackClassificationCannotMakeUnknownOrInterruptionTransient() {
  assertTrue(OAuthServerStoreException.fromReason(STORE_UNAVAILABLE,true).isTransient());
  assertTrue(OAuthServerTransportException.fromReason(CLIENT_METADATA_UNAVAILABLE,true).isTransient());
  assertFalse(OAuthServerStoreException.fromReason(COMMIT_OUTCOME_UNKNOWN,true).isTransient());
  assertFalse(OAuthServerStoreException.fromReason(STORE_CORRUPT,true).isTransient());
  try {Thread.currentThread().interrupt();assertFalse(OAuthServerStoreException.fromReason(STORE_UNAVAILABLE,true).isTransient());
   assertFalse(OAuthServerTransportException.fromReason(CLIENT_METADATA_UNAVAILABLE,true).isTransient());assertTrue(Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}
 }
 @Test void issuerRejectionRetainsOnlyOptionalFixedM5AndJoseReasons() {
  OAuthIssuerAccessTokenResult.Rejected r=assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class,OAuthIssuerAccessTokenResult.fromRejection(TOKEN_REVOKED,AccessTokenValidationException.Reason.INACTIVE,JoseException.Reason.INVALID_TYPE));
  assertEquals(Optional.of(AccessTokenValidationException.Reason.INACTIVE),r.getAccessTokenReason());assertEquals(Optional.of(JoseException.Reason.INVALID_TYPE),r.getJoseReason());assertEquals(BearerError.INVALID_TOKEN,r.getBearerError());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> observerPairsUseCallerThreadAndOneTerminal() { return Stream.of(OAuthServerObserver.Endpoint.values()).map(value->DynamicTest.dynamicTest("observerPairsUseCallerThreadAndOneTerminal["+value.name()+"]",()->observerPairsUseCallerThreadAndOneTerminalCase(value))); }
 private void observerPairsUseCallerThreadAndOneTerminalCase(OAuthServerObserver.@NonNull Endpoint endpoint) {
  Thread caller=Thread.currentThread();List<String> events=new ArrayList<>();AtomicInteger will=new AtomicInteger();
  OAuthServerObserver observer=new OAuthServerObserver() {
   @Override public void willHandleEndpoint(@NonNull Endpoint e) {assertSame(caller,Thread.currentThread());assertSame(endpoint,e);will.incrementAndGet();}
   @Override public void didHandleEndpoint(@NonNull Endpoint e,@Nullable Integer status,@NonNull Duration elapsed) {assertSame(caller,Thread.currentThread());assertSame(endpoint,e);assertFalse(elapsed.isNegative());events.add("handled");}
   @Override public void didRejectEndpoint(@NonNull Endpoint e,OAuthServerException.@NonNull Reason reason,@Nullable Integer status,@NonNull Duration elapsed) {assertSame(caller,Thread.currentThread());assertSame(endpoint,e);assertEquals(ACCESS_DENIED,reason);events.add("rejected");}
   @Override public void didFailToHandleEndpoint(@NonNull Endpoint e,@NonNull OAuthServerException f,@NonNull Duration elapsed) {assertSame(caller,Thread.currentThread());assertSame(endpoint,e);assertEquals(COMMIT_OUTCOME_UNKNOWN,f.getReason());events.add("failed");}
  };
  Integer status=switch(endpoint){case ACCESS_TOKEN_VALIDATION,GRANT_REVOCATION,SUBJECT_REVOCATION,ISSUER_REVOCATION,STORE_RESEAL,ISSUER_INITIALIZATION,SUBJECT_REGISTRATION -> null;default -> 200;};
  OAuthServerObservation ok=new OAuthServerObservation(observer,endpoint);ok.succeeded(status);
  assertThrows(IllegalStateException.class,()->ok.succeeded(status));assertThrows(IllegalStateException.class,()->ok.rejected(ACCESS_DENIED,status));assertThrows(IllegalStateException.class,()->ok.failed(failure(COMMIT_OUTCOME_UNKNOWN,false)));
  new OAuthServerObservation(observer,endpoint).rejected(ACCESS_DENIED,status);new OAuthServerObservation(observer,endpoint).failed(failure(COMMIT_OUTCOME_UNKNOWN,false));
  assertEquals(3,will.get());assertEquals(List.of("handled","rejected","failed"),events);
 }
 @Test void observerFaultsCannotChangeOutcomesAndInterruptRemainsVisible() {
  AtomicInteger terminals=new AtomicInteger();OAuthServerObserver bad=new OAuthServerObserver() {
   @Override public void willHandleEndpoint(@NonNull Endpoint e) {throw new AssertionError("TEST-ONLY-secret");}
   @Override public void didHandleEndpoint(@NonNull Endpoint e,@Nullable Integer s,@NonNull Duration d) {terminals.incrementAndGet();throw new RuntimeException("TEST-ONLY-secret");}
   @Override public void didRejectEndpoint(@NonNull Endpoint e,OAuthServerException.@NonNull Reason r,@Nullable Integer s,@NonNull Duration d) {terminals.incrementAndGet();throw new AssertionError("TEST-ONLY-secret");}
   @Override public void didFailToHandleEndpoint(@NonNull Endpoint e,@NonNull OAuthServerException f,@NonNull Duration d) {terminals.incrementAndGet();sneaky(new InterruptedException("TEST-ONLY-secret"));}
  };
  new OAuthServerObservation(bad,OAuthServerObserver.Endpoint.TOKEN).succeeded(200);new OAuthServerObservation(bad,OAuthServerObserver.Endpoint.TOKEN).rejected(INVALID_GRANT,400);
  try {new OAuthServerObservation(bad,OAuthServerObserver.Endpoint.TOKEN).failed(failure(STORE_UNAVAILABLE,false));assertTrue(Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}
  assertEquals(3,terminals.get());
 }
 @SuppressWarnings("unchecked") private static <E extends @NonNull Throwable> void sneaky(@NonNull Throwable failure) throws E {throw (E)failure;}
 @Test void fatalObserverErrorsPropagateAndDisabledObserverIsShared() {
  OutOfMemoryError fatal=new OutOfMemoryError("TEST-ONLY-fatal");OAuthServerObserver bad=new OAuthServerObserver(){@Override public void willHandleEndpoint(@NonNull Endpoint e){throw fatal;}};
  assertSame(fatal,assertThrows(OutOfMemoryError.class,()->new OAuthServerObservation(bad,OAuthServerObserver.Endpoint.TOKEN)));
  assertSame(OAuthServerObserver.disabledInstance(),OAuthServerObserver.disabledInstance());
  OAuthServerObserver disabled=OAuthServerObserver.disabledInstance();disabled.willHandleEndpoint(OAuthServerObserver.Endpoint.TOKEN);disabled.didHandleEndpoint(OAuthServerObserver.Endpoint.TOKEN,200,Duration.ZERO);
  disabled.didRejectEndpoint(OAuthServerObserver.Endpoint.TOKEN,INVALID_GRANT,400,Duration.ZERO);disabled.didFailToHandleEndpoint(OAuthServerObserver.Endpoint.TOKEN,failure(STORE_UNAVAILABLE,false),Duration.ZERO);
 }
 @Test void observerStatusMisuseDoesNotInventACompletedEvent() {
  OAuthServerObservation http=new OAuthServerObservation(OAuthServerObserver.disabledInstance(),OAuthServerObserver.Endpoint.TOKEN);
  assertThrows(IllegalArgumentException.class,()->http.succeeded(null));assertThrows(IllegalArgumentException.class,()->http.succeeded(99));assertThrows(IllegalArgumentException.class,()->http.succeeded(600));
  assertThrows(IllegalArgumentException.class,()->http.rejected(STORE_UNAVAILABLE,503));http.succeeded(200);
  OAuthServerObservation management=new OAuthServerObservation(OAuthServerObserver.disabledInstance(),OAuthServerObserver.Endpoint.STORE_RESEAL);
  assertThrows(IllegalArgumentException.class,()->management.succeeded(200));management.succeeded(null);
 }
 @SuppressWarnings("NullAway") @Test void nullPlumbingRemainsProgrammerMisuse() {
  assertThrows(NullPointerException.class,()->OAuthServerValidationException.fromReason(null));
  assertThrows(NullPointerException.class,()->OAuthTokenResult.fromSucceeded(null));assertThrows(NullPointerException.class,()->OAuthAuthorizationResult.fromInteractionRequired(null));
  assertThrows(NullPointerException.class,()->OAuthIssuerAccessTokenResult.fromSucceeded(null));assertThrows(NullPointerException.class,()->OAuthTokenResult.fromRejection(INVALID_GRANT,null));
  assertThrows(NullPointerException.class,()->OAuthServerFailureBoundary.failure(null,4096,1024));assertThrows(NullPointerException.class,()->OAuthServerFailureBoundary.store(null));assertThrows(NullPointerException.class,()->OAuthServerFailureBoundary.admission(null));
  assertThrows(NullPointerException.class,()->new OAuthServerObservation(null,OAuthServerObserver.Endpoint.TOKEN));assertThrows(NullPointerException.class,()->new OAuthServerObservation(OAuthServerObserver.disabledInstance(),null));
 }
}
