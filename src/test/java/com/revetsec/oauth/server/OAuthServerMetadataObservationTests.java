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
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static com.revetsec.oauth.server.OAuthServerException.Reason.*;
import static java.util.Objects.requireNonNull;

/** Public ordinary errors complete observation; publication capacity is trusted configuration. */
final class OAuthServerMetadataObservationTests {
 private static final @NonNull String ISSUER="https://issuer.example/tenant",RESOURCE="https://resource.example/mcp",NONCE="A".repeat(43),PRIVATE="TEST-ONLY-private-observer-data";
 private static final @NonNull Instant NOW=Instant.parse("2026-11-01T12:00:00Z");
 private static final class Fatal extends VirtualMachineError {private static final long serialVersionUID=1L;}
 private static final class Events implements OAuthServerObserver {
  final @NonNull Thread caller=Thread.currentThread();final @NonNull Fatal fatal=new Fatal();
  final @NonNull List<@NonNull Endpoint> will=new ArrayList<>(),success=new ArrayList<>(),rejected=new ArrayList<>(),failed=new ArrayList<>();
  final @NonNull List<OAuthServerException.@NonNull Reason> reasons=new ArrayList<>();final @NonNull List<@Nullable Integer> statuses=new ArrayList<>();
  @Nullable OAuthServerException failure;@NonNull String behavior="ordinary";
  @Override public void willHandleEndpoint(@NonNull Endpoint e){assertSame(this.caller,Thread.currentThread());this.will.add(e);}
  @Override public void didHandleEndpoint(@NonNull Endpoint e,@Nullable Integer status,@NonNull Duration elapsed){assertSame(this.caller,Thread.currentThread());this.success.add(e);this.statuses.add(status);terminal(elapsed);}
  @Override public void didRejectEndpoint(@NonNull Endpoint e,OAuthServerException.@NonNull Reason reason,@Nullable Integer status,@NonNull Duration elapsed){assertSame(this.caller,Thread.currentThread());this.rejected.add(e);this.reasons.add(reason);this.statuses.add(status);terminal(elapsed);}
  @Override public void didFailToHandleEndpoint(@NonNull Endpoint e,@NonNull OAuthServerException f,@NonNull Duration elapsed){assertSame(this.caller,Thread.currentThread());this.failed.add(e);this.failure=f;terminal(elapsed);}
  void terminal(@NonNull Duration elapsed){assertFalse(elapsed.isNegative());switch(this.behavior){case "throw"->throw new IllegalStateException(PRIVATE);case "interrupt"->raise(new InterruptedException(PRIVATE));case "fatal"->throw this.fatal;default->{}}}
  void clear(){this.will.clear();this.success.clear();this.rejected.clear();this.failed.clear();this.reasons.clear();this.statuses.clear();this.failure=null;}
 }
 private static final class Fixture {
  final @NonNull OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture(NOW);final @NonNull Events events=new Events();
  final @NonNull AtomicInteger providers=new AtomicInteger(),clients=new AtomicInteger();final @NonNull StateSealer sealer;
  final @NonNull OAuthAuthorizationServer server;final @NonNull OAuthStoreRecordCodec codec;
  @Nullable String providerFault;
  Fixture(boolean largeMetadata,boolean largeJwks,int cap){
   byte[] material=new byte[32];for(int i=0;i<material.length;i++)material[i]=(byte)(i+1);
   this.sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key",Base64.getEncoder().encodeToString(material))).clock(Clock.fixed(NOW,ZoneOffset.UTC)).build();
   this.codec=new OAuthStoreRecordCodec(ISSUER,this.sealer,3800);
   var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;Map<String,PublicKey> old=new LinkedHashMap<>();if(largeJwks)for(int i=0;i<20;i++)old.put("old"+i,key.getPublicKey());
   var snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("active",key.getPrivateKey(),key.getPublicKey())).verificationKeys(old).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
   Set<String> scopes=new LinkedHashSet<>();if(largeMetadata)for(int i=0;i<64;i++)scopes.add("scope"+"x".repeat(95)+i);else scopes.add("read");
   this.server=OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token"))
    .jwksEndpoint(URI.create(ISSUER+"/jwks")).clientRepository((id,budget)->{this.clients.incrementAndGet();return Optional.empty();}).store(this.store)
    .signingKeys(budget->{this.providers.incrementAndGet();String mode=this.providerFault;if(mode!=null)switch(mode){case "io"->raise(new IOException(PRIVATE));case "null"->{return nullSnapshot();}case "interrupt"->raise(new InterruptedException(PRIVATE));case "fatal"->throw this.events.fatal;default->{}}return snapshot;})
    .stateSealer(this.sealer).clock(Clock.fixed(NOW,ZoneOffset.UTC)).resources(Map.of(RESOURCE,scopes)).grantPolicy((context,budget)->OAuthAuthorizationDecision.deniedInstance())
    .maximumScopesPerResource(64).maximumResponseBodyBytes(cap).observer(this.events).acknowledgeUnpatchedRuntime(true).build();
   assertEquals(OAuthStoreCommitStatus.COMMITTED,this.server.initializeFreshIssuer().getStatus());this.server.establishNewSubject("subject");this.events.clear();
  }
  @NonNull OAuthServerResponse response(boolean jwks,@NonNull String method){return jwks?this.server.jwksResponse(method):this.server.metadataResponse(method);}
  void untouched(@NonNull Map<@NonNull OAuthStoreKey,@NonNull OAuthStoreEntry> rows,int reads,int commits){assertEquals(rows,this.store.rows);assertEquals(reads,this.store.reads);assertEquals(commits,this.store.commits);assertEquals(0,this.clients.get());}
 }
 private static void safe(@NonNull OAuthServerException failure){assertNull(failure.getCause());assertEquals(0,failure.getSuppressed().length);assertFalse(failure.toString().contains(PRIVATE));assertFalse(failure.isTemporaryCondition());}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> trustedPublicationOverflowIsConfigurationWithOneFailureEvent(){
  return Stream.of(false,true).flatMap(jwks->Stream.of("GET","HEAD").flatMap(method->Stream.of("ordinary","throw","interrupt","fatal").map(mode->DynamicTest.dynamicTest((jwks?"JWKS":"METADATA")+"/"+method+"/"+mode,()->{
   Fixture f=new Fixture(!jwks,jwks,4096);var rows=Map.copyOf(f.store.rows);int reads=f.store.reads,commits=f.store.commits;f.events.behavior=mode;
   try{
    if(mode.equals("fatal"))assertSame(f.events.fatal,assertThrows(Fatal.class,()->f.response(jwks,method)));
    else {var failure=assertThrows(OAuthServerConfigurationException.class,()->f.response(jwks,method));assertEquals(CONFIGURATION_INVALID,failure.getReason());assertSame(failure,f.events.failure);safe(failure);var response=f.server.responseForFailure(failure);assertEquals(503,response.getStatusCode());assertEquals("{\"error\":\"server_error\"}",new String(response.toHttpBodyWithCredentials(),StandardCharsets.US_ASCII));assertTrue(response.getLocationWithCredentials().isEmpty());}
    assertEquals(List.of(jwks?OAuthServerObserver.Endpoint.JWKS:OAuthServerObserver.Endpoint.METADATA),f.events.will);assertEquals(f.events.will,f.events.failed);assertTrue(f.events.success.isEmpty());assertTrue(f.events.rejected.isEmpty());assertEquals(CONFIGURATION_INVALID,requireNonNull(f.events.failure).getReason());assertEquals(mode.equals("interrupt"),Thread.currentThread().isInterrupted());f.untouched(rows,reads,commits);
   }finally{Thread.interrupted();}
  }))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> foreignMaintenanceKeysStillRejectAndFinishTheirEvents(){
  return Stream.of(OAuthStoreKey.Kind.values()).flatMap(kind->Stream.of("ordinary","throw","interrupt","fatal").map(mode->DynamicTest.dynamicTest(kind+"/"+mode,()->{
   Fixture f=new Fixture(false,false,32768);var foreign=new OAuthStoreRecordCodec("https://other.example/tenant",f.sealer,3800);var key=switch(kind){case ISSUER_STATE->foreign.issuerKey();case SUBJECT_STATE->foreign.subjectKey("subject");default->foreign.key(kind,NONCE);};
   var rows=Map.copyOf(f.store.rows);int reads=f.store.reads,commits=f.store.commits;f.events.behavior=mode;
   try{
    if(mode.equals("fatal"))assertSame(f.events.fatal,assertThrows(Fatal.class,()->f.server.resealStoreEntry(key)));
    else {var failure=assertThrows(OAuthServerValidationException.class,()->f.server.resealStoreEntry(key));assertEquals(MALFORMED_REQUEST,failure.getReason());safe(failure);}
    assertEquals(List.of(OAuthServerObserver.Endpoint.STORE_RESEAL),f.events.will);assertEquals(f.events.will,f.events.rejected);assertEquals(List.of(MALFORMED_REQUEST),f.events.reasons);assertEquals(1,f.events.statuses.size());assertNull(f.events.statuses.get(0));assertTrue(f.events.success.isEmpty());assertTrue(f.events.failed.isEmpty());assertEquals(mode.equals("interrupt"),Thread.currentThread().isInterrupted());f.untouched(rows,reads,commits);
   }finally{Thread.interrupted();}
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> sufficientPublicationCapacityPreservesGetHeadAndCacheHeaders(){return Stream.of(false,true).map(jwks->DynamicTest.dynamicTest(jwks?"JWKS":"METADATA",()->{
  Fixture f=new Fixture(true,true,32768);var get=f.response(jwks,"GET");var head=f.response(jwks,"HEAD");assertEquals(200,get.getStatusCode());assertEquals(200,head.getStatusCode());assertTrue(get.toHttpBodyWithCredentials().length>4096);assertEquals(0,head.toHttpBodyWithCredentials().length);assertEquals(get.getHeaders(),head.getHeaders());assertTrue(requireNonNull(get.getHeaders().get("Cache-Control")).get(0).contains("must-revalidate"));assertTrue(get.getHeaders().containsKey("ETag"));assertEquals(Integer.toString(get.toHttpBodyWithCredentials().length),requireNonNull(head.getHeaders().get("Content-Length")).get(0));assertEquals(2,f.events.success.size());assertEquals(List.of(200,200),f.events.statuses);assertTrue(f.events.rejected.isEmpty());assertTrue(f.events.failed.isEmpty());assertEquals(0,f.clients.get());
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> unsupportedPublicationMethodsDoNotFetchOrReflect(){return Stream.of(false,true).flatMap(jwks->Stream.of("POST","DELETE","OPTIONS","get","GET\r\n"+PRIVATE).map(method->DynamicTest.dynamicTest((jwks?"JWKS":"METADATA")+"/unsupported/"+method.length(),()->{
  Fixture f=new Fixture(true,true,4096);f.providerFault="io";var response=f.response(jwks,method);assertEquals(405,response.getStatusCode());assertEquals(0,response.toHttpBodyWithCredentials().length);assertEquals(List.of("GET, HEAD"),response.getHeaders().get("Allow"));assertEquals(List.of("no-store"),response.getHeaders().get("Cache-Control"));assertFalse(response.getHeaders().containsKey("ETag"));assertFalse(response.getHeaders().toString().contains(PRIVATE));assertEquals(0,f.providers.get());assertEquals(0,f.clients.get());assertEquals(1,f.events.rejected.size());assertEquals(List.of(METHOD_NOT_ALLOWED),f.events.reasons);assertEquals(List.of(405),f.events.statuses);assertTrue(f.events.failed.isEmpty());
 })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> managementSuccessStillHasExactlyOneNullStatusTerminal(){return Stream.of("initialize","register","subject","issuer","grant","reseal").map(mode->DynamicTest.dynamicTest(mode,()->{
  Fixture f=new Fixture(false,false,32768);switch(mode){case "initialize"->assertEquals(OAuthStoreCommitStatus.CONFLICT,f.server.initializeFreshIssuer().getStatus());case "register"->f.server.establishNewSubject("subject");case "subject"->f.server.revokeSubject("subject");case "issuer"->f.server.revokeAllGrants();case "grant"->f.server.revokeGrant(NONCE);default->assertEquals(OAuthStoreCommitStatus.CONFLICT,f.server.resealStoreEntry(f.codec.key(OAuthStoreKey.Kind.INTERACTION,NONCE)).getStatus());}
  assertEquals(1,f.events.will.size());assertEquals(f.events.will,f.events.success);assertEquals(1,f.events.statuses.size());assertNull(f.events.statuses.get(0));assertTrue(f.events.rejected.isEmpty());assertTrue(f.events.failed.isEmpty());
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> programmerPreconditionsRemainBeforeObservation(){return Stream.of("metadata","jwks","reseal","grant","subject").map(mode->DynamicTest.dynamicTest(mode,()->{
  Fixture f=new Fixture(false,false,32768);if(mode.equals("grant"))assertThrows(IllegalArgumentException.class,()->f.server.revokeGrant("bad"));else if(mode.equals("subject"))assertThrows(IllegalArgumentException.class,()->f.server.revokeSubject(""));else assertThrows(NullPointerException.class,()->nullCall(f,mode));assertTrue(f.events.will.isEmpty());assertTrue(f.events.success.isEmpty());assertTrue(f.events.rejected.isEmpty());assertTrue(f.events.failed.isEmpty());
 }));}
 @SuppressWarnings("NullAway") private static @NonNull Object nullCall(@NonNull Fixture f,@NonNull String mode){return switch(mode){case "metadata"->f.server.metadataResponse(null);case "jwks"->f.server.jwksResponse(null);default->f.server.resealStoreEntry(null);};}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> keyProviderFailuresRetainTheirOwnClassification(){return Stream.of("GET","HEAD").flatMap(method->Stream.of("io","null","interrupt","fatal").map(mode->DynamicTest.dynamicTest(method+"/provider/"+mode,()->{
  Fixture f=new Fixture(false,true,4096);f.providerFault=mode;
  try{if(mode.equals("fatal")){assertSame(f.events.fatal,assertThrows(Fatal.class,()->f.server.jwksResponse(method)));assertTrue(f.events.failed.isEmpty());}else{var failure=assertThrows(OAuthServerTransportException.class,()->f.server.jwksResponse(method));assertEquals(SERVICE_UNAVAILABLE,failure.getReason());assertSame(failure,f.events.failure);assertEquals(1,f.events.failed.size());safe(failure);}assertEquals(1,f.events.will.size());assertTrue(f.events.rejected.isEmpty());assertTrue(f.events.success.isEmpty());assertEquals(mode.equals("interrupt"),Thread.currentThread().isInterrupted());}finally{Thread.interrupted();}
 })));
 }
 @SuppressWarnings("NullAway") private static @NonNull OAuthIssuerKeySnapshot nullSnapshot(){return null;}
 @SuppressWarnings("unchecked") private static <T extends Throwable> void raise(@NonNull Throwable failure) throws T {throw (T)failure;}
}
