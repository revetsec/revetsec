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
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static com.revetsec.oauth.server.OAuthServerException.Reason.*;

/** Hostile new input is not evidence that an authenticated store row is corrupt. */
final class OAuthAuthorizationInputBoundaryTests {
 private static final @NonNull String ISSUER="https://issuer.example/tenant",BROWSER="A".repeat(43),CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 private static final @NonNull Instant NOW=Instant.parse("2026-11-01T12:00:00Z");
 private static final class Time extends Clock {
  private @NonNull Instant now=NOW;
  @Override public @NonNull Instant instant(){return this.now;}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return Clock.fixed(this.now,zone);}
 }
 private static final class Events implements OAuthServerObserver {
  int will,success;final @NonNull List<OAuthServerException.@NonNull Reason> rejects=new ArrayList<>();final @NonNull List<@NonNull OAuthServerException> failures=new ArrayList<>();
  @Override public void willHandleEndpoint(@NonNull Endpoint e){this.will++;}
  @Override public void didHandleEndpoint(@NonNull Endpoint e,@Nullable Integer status,@NonNull Duration elapsed){this.success++;}
  @Override public void didRejectEndpoint(@NonNull Endpoint e,OAuthServerException.@NonNull Reason reason,@Nullable Integer status,@NonNull Duration elapsed){this.rejects.add(reason);}
  @Override public void didFailToHandleEndpoint(@NonNull Endpoint e,@NonNull OAuthServerException failure,@NonNull Duration elapsed){this.failures.add(failure);}
  void clear(){this.will=0;this.success=0;this.rejects.clear();this.failures.clear();}
 }
 private static final class Fixture {
  final @NonNull OAuthAtomicStoreFixture store=new OAuthAtomicStoreFixture(NOW);
  final @NonNull Time time=new Time();final @NonNull Events events=new Events();final @NonNull AtomicInteger clients=new AtomicInteger();
  final @NonNull String clientId,redirect,resource;final @NonNull StateSealer sealer;final @NonNull OAuthAuthorizationServer server;
  Fixture(){this("client","https://client.example/cb","https://resource.example/mcp","k",3800);}
  Fixture(@NonNull String clientId,@NonNull String redirect,@NonNull String resource,@NonNull String keyId,int cap){
   this.clientId=clientId;this.redirect=redirect;this.resource=resource;
   byte[] material=new byte[32];for(int i=0;i<material.length;i++)material[i]=(byte)(i+1);
   this.sealer=StateSealer.withActiveKey(SealingKey.fromBase64(keyId,Base64.getEncoder().encodeToString(material))).clock(this.time).maximumSealedLength(16384).build();
   var registered=OAuthServerClientRegistration.withClientId(clientId).configurationVersion("v1").redirectUris(List.of(URI.create(redirect))).allowedScopesByResource(Map.of(resource,Set.of("read"))).build();
   var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;
   this.server=OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).jwksEndpoint(URI.create(ISSUER+"/jwks"))
    .clientRepository((id,budget)->{this.clients.incrementAndGet();return id.equals(this.clientId)?Optional.of(registered):Optional.empty();}).store(this.store)
    .signingKeys(OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("signing",key.getPrivateKey(),key.getPublicKey())).generation("generation-1").publishedAt(NOW.minusSeconds(120)).build()))
    .stateSealer(this.sealer).clock(this.time).resources(Map.of(resource,Set.of("read"))).grantPolicy((context,budget)->OAuthAuthorizationDecision.deniedInstance()).observer(this.events).maximumStoreRecordBytes(cap).acknowledgeUnpatchedRuntime(true).build();
   assertEquals(OAuthStoreCommitStatus.COMMITTED,this.server.initializeFreshIssuer().getStatus());this.events.clear();
  }
  @NonNull String query(@Nullable String state) throws Exception {
   var fields=new LinkedHashMap<String,String>();fields.put("client_id",this.clientId);fields.put("redirect_uri",this.redirect);fields.put("resource",this.resource);fields.put("scope","read");fields.put("response_type","code");fields.put("code_challenge",CHALLENGE);fields.put("code_challenge_method","S256");if(state!=null)fields.put("state",state);
   var out=new ArrayList<String>();for(var entry:fields.entrySet())out.add(FormUrlEncoding.encode(entry.getKey())+"="+FormUrlEncoding.encode(entry.getValue()));return String.join("&",out);
  }
  @NonNull OAuthAuthorizationResult begin(@Nullable String state) throws Exception {return this.server.beginAuthorizationResult("GET",query(state),new byte[0],Map.of(),BROWSER);}
  @NonNull OAuthServerInteraction accepted(@Nullable String state) throws Exception {return assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,begin(state)).getInteraction();}
  void refuse(@NonNull String state,boolean beforeClient) throws Exception {
   String query=query(state);var rows=Map.copyOf(this.store.rows);int commits=this.store.commits,reads=this.store.reads,lookups=this.clients.get();this.events.clear();
   var result=assertDoesNotThrow(()->this.server.beginAuthorizationResult("GET",query,new byte[0],Map.of(),BROWSER));var rejected=assertInstanceOf(OAuthAuthorizationResult.Rejected.class,result);
   assertEquals(MALFORMED_REQUEST,rejected.getReason());assertEquals(400,rejected.getResponse().getStatusCode());assertEquals("{\"error\":\"invalid_request\"}",new String(rejected.getResponse().toHttpBodyWithCredentials(),java.nio.charset.StandardCharsets.US_ASCII));assertTrue(rejected.getResponse().getLocationWithCredentials().isEmpty());
   assertEquals(rows,this.store.rows);assertEquals(commits,this.store.commits);if(beforeClient){assertEquals(reads,this.store.reads);assertEquals(lookups,this.clients.get());}
   assertEquals(1,this.events.will);assertEquals(List.of(MALFORMED_REQUEST),this.events.rejects);assertEquals(0,this.events.success);assertTrue(this.events.failures.isEmpty());
  }
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> nonVscharStateIsARequestRejectionBeforeCallbacks(){
  Stream<String> controls=IntStream.rangeClosed(0,31).mapToObj(c->Character.toString((char)c));
  return Stream.concat(controls,Stream.of("\u007f","\u0080","\u00a0","é","\u2028","\u2029","\ufffd","😀")).map(state->DynamicTest.dynamicTest("state U+"+Integer.toHexString(state.codePointAt(0)),()->new Fixture().refuse(state,true)));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> everyPrintableAsciiCharacterRemainsExactlyRoundTrippable(){
  return IntStream.rangeClosed(32,126).mapToObj(c->DynamicTest.dynamicTest("state U+"+Integer.toHexString(c),()->{
   Fixture f=new Fixture();String state=Character.toString((char)c);var interaction=f.accepted(state);var denied=assertInstanceOf(OAuthAuthorizationResult.Denied.class,f.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,OAuthAuthorizationDecision.deniedInstance()));
   String location=denied.getResponse().getLocationWithCredentials().orElseThrow().toString();assertTrue(location.contains("&state="+FormUrlEncoding.encode(state)+"&iss="));
  }));
 }
 @Test void absentAndExistingEmptyStateHandlingRemainDistinct() throws Exception {
  for(String state:new String[]{"","safe state +%&=\\\"~"}){Fixture f=new Fixture();f.accepted(state);}
  new Fixture().accepted(null);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> individuallyAdmissibleFieldsCannotBecomeAStoreCorruptionAlarm(){
  return Stream.of("ascii","json-escaping","utf8").flatMap(shape->Stream.of("k","k".repeat(64)).map(key->DynamicTest.dynamicTest(shape+" key="+key.length(),()->{
   String client="c".repeat(850),redirect="https://client.example/"+"p".repeat(550),resource="https://resource.example/"+"r".repeat(550),state="s".repeat(1024);
   if(shape.equals("json-escaping"))state="\\\"".repeat(128);
   if(shape.equals("utf8")){client="c".repeat(500)+"é".repeat(80);resource="https://resource.example/"+"é".repeat(100)+"r".repeat(400);state="s".repeat(900);}
   Fixture f=new Fixture(client,redirect,resource,key,3800);String query=f.query(state);
   assertDoesNotThrow(()->OAuthServerRequest.parse(OAuthServerRequest.Endpoint.AUTHORIZATION,"GET",query,new byte[0],Map.of(),OAuthServerIngressLimits.fromDefaults()));f.refuse(state,false);
  })));
 }
 @Test void largestAdmittedInteractionCanStillBeDeniedAtNanosecondPrecision() throws Exception {
  for(String key:List.of("k","k".repeat(64))){
   int low=0,high=1024;
   while(low<high){int n=(low+high+1)/2;Fixture f=new Fixture("client","https://client.example/cb","https://resource.example/mcp",key,2048);OAuthAuthorizationResult r=assertDoesNotThrow(()->f.begin("s".repeat(n)));if(r instanceof OAuthAuthorizationResult.InteractionRequired)low=n;else{assertEquals(MALFORMED_REQUEST,assertInstanceOf(OAuthAuthorizationResult.Rejected.class,r).getReason());high=n-1;}}
   assertTrue(low>0&&low<1024);Fixture f=new Fixture("client","https://client.example/cb","https://resource.example/mcp",key,2048);String state="s".repeat(low);var interaction=f.accepted(state);f.time.now=NOW.plusSeconds(1).plusNanos(999999999);f.store.authorityNow=f.time.now;
   var denied=assertDoesNotThrow(()->f.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,OAuthAuthorizationDecision.deniedInstance()));assertInstanceOf(OAuthAuthorizationResult.Denied.class,denied);
  }
 }
 private static @NonNull OAuthStoreEntry withState(@NonNull Fixture f,@NonNull OAuthStoreEntry entry,@NonNull String state) throws Exception {
  try(var opened=SealedStateAccess.get().openRecord(f.sealer,SealedStateType.AS_RECORD,entry.toSealedForm(),OAuthStoreRecordCodecV2.context(entry.getKey()),f.time)){
   var envelope=(JsonObject)JsonCodec.parse(opened.getPlaintext().getBytes(java.nio.charset.StandardCharsets.UTF_8),JsonLimits.protocolDocument(16384));var fields=new LinkedHashMap<>(envelope.getMembers());var payload=(JsonObject)fields.get("payload");var members=new LinkedHashMap<>(java.util.Objects.requireNonNull(payload).getMembers());members.put("state",JsonString.fromValue(state));fields.put("payload",JsonObject.fromMembers(members));
   String sealed=SealedStateAccess.get().seal(f.sealer,SealedStateType.AS_RECORD,JsonObject.fromMembers(fields).toJson(),OAuthStoreRecordCodecV2.context(entry.getKey()),entry.getRetainUntil());return OAuthStoreEntry.fromStoredForm(entry.getKey(),entry.getVersion(),entry.getRetainUntil(),sealed);
  }
 }
 @Test void authenticatedMalformedStoredInteractionStillSignalsCorruption() throws Exception {
  Fixture f=new Fixture();var interaction=f.accepted("safe");var entry=f.store.rows.values().stream().filter(e->e.getKey().getKind()==OAuthStoreKey.Kind.INTERACTION).findFirst().orElseThrow();f.store.rows.put(entry.getKey(),withState(f,entry,"\n"));var rows=Map.copyOf(f.store.rows);int commits=f.store.commits;f.events.clear();
  var failure=assertThrows(OAuthServerStoreException.class,()->f.server.resumeAuthorizationResult(interaction.getInteractionValue(),BROWSER));assertEquals(STORE_CORRUPT,failure.getReason());assertNull(failure.getCause());assertEquals(rows,f.store.rows);assertEquals(commits,f.store.commits);assertEquals(1,f.events.failures.size());assertSame(failure,f.events.failures.get(0));assertTrue(f.events.rejects.isEmpty());
 }
 @Test void previouslyAuthenticatedUnicodeStateRemainsReadableWithoutCodecMigration() throws Exception {
  Fixture f=new Fixture();var interaction=f.accepted("safe");var entry=f.store.rows.values().stream().filter(e->e.getKey().getKind()==OAuthStoreKey.Kind.INTERACTION).findFirst().orElseThrow();f.store.rows.put(entry.getKey(),withState(f,entry,"é😀"));assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,f.server.resumeAuthorizationResult(interaction.getInteractionValue(),BROWSER));assertInstanceOf(OAuthAuthorizationResult.Denied.class,f.server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,OAuthAuthorizationDecision.deniedInstance()));
 }
}
