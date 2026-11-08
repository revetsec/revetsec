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
import java.time.ZoneId;
import java.time.ZoneOffset;
import javax.annotation.concurrent.ThreadSafe;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.IndependentAccountWorkload;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Real service operations on a declared atomic realtime fixture; no durable/nonblocking profile claim. */
final class OAuthIssuerIndependentAccountClockTests {
 private static final @NonNull String ISSUER="https://issuer.example/bound03",RESOURCE="https://resource.example/mcp",REDIRECT="https://client.example/cb",BROWSER="A".repeat(43),VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scBound03RealDelayedIndependentSubjectsWithSlowPreparationAndIntrospectionPoller(){return List.of(cell(8),cell(16));}
 private static org.junit.jupiter.api.@NonNull DynamicTest cell(int count){return org.junit.jupiter.api.DynamicTest.dynamicTest("SC-BOUND-03/ISSUER/accounts="+count,()->run(count));}
 private static void run(int count)throws Exception{
  var work=new IndependentAccountWorkload(count);Clock clock=Clock.systemUTC();var delegate=new OAuthAtomicStoreFixture(clock.instant());var trace=new AtomicBoolean();var conflicts=new AtomicInteger();var capacityRefusals=new AtomicInteger();List<OAuthStoreTransaction> transactions=new CopyOnWriteArrayList<>();List<Long> preparationNanos=new CopyOnWriteArrayList<>();var policyCalls=new AtomicInteger();
  var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).build();var codec=new OAuthStoreRecordCodec(ISSUER,sealer,3800);
  OAuthAuthorizationServerStore store=new OAuthAuthorizationServerStore(){
   @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){Duration left=work.beforeBackend(budget);synchronized(delegate.rows){delegate.authorityNow=clock.instant();return delegate.read(key,left);}}
   @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){Duration left=work.beforeBackend(budget);synchronized(delegate.rows){delegate.authorityNow=clock.instant();if(trace.get())transactions.add(transaction);Map<OAuthStoreKey,OAuthStoreEntry> projected=new HashMap<>(delegate.rows);for(var mutation:transaction.getMutations()){if(mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE)projected.remove(mutation.getKey());else projected.put(mutation.getKey(),mutation.getEntry().orElseThrow());}long bytes=projected.values().stream().mapToLong(e->e.toSealedForm().getBytes(StandardCharsets.UTF_8).length).sum();if(projected.size()>1024||bytes>16_777_216L){capacityRefusals.incrementAndGet();return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.CAPACITY);}var receipt=delegate.commit(transaction,left);if(receipt.getStatus()==OAuthStoreCommitStatus.CONFLICT)conflicts.incrementAndGet();return receipt;}}
  };
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;var snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(clock.instant().minusSeconds(120)).build();
  var client=OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(Map.of(RESOURCE,Set.of("read"))).build();var resource=OAuthServerClientRegistration.withClientId("resource").configurationVersion("r1").authorizationCodePermitted(false).introspectionResources(Set.of(RESOURCE)).authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id,secret,budget)->Arrays.equals(secret,"secret".getBytes(StandardCharsets.UTF_8)))).build();
  var server=OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke")).introspectionEndpoint(URI.create(ISSUER+"/introspect")).clientRepository((id,budget)->Optional.of(id.equals("resource")?resource:client)).store(store).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(snapshot)).stateSealer(sealer).resources(Map.of(RESOURCE,Set.of("read"))).clock(clock).clockSkew(Duration.ZERO).totalDeadline(IndependentAccountWorkload.budget()).requestTimeout(IndependentAccountWorkload.budget()).grantPolicy((context,budget)->{assertFalse(Thread.holdsLock(delegate.rows),"Policy must remain outside atomic backend protection");if(trace.get()){policyCalls.incrementAndGet();long began=System.nanoTime();IndependentAccountWorkload.pauseAtLeast(Duration.ofMillis(120));preparationNanos.add(System.nanoTime()-began);}return decision(context.getSubject());}).build();
  assertEquals(OAuthStoreCommitStatus.COMMITTED,server.initializeFreshIssuer().getStatus());server.establishNewSubject("poller-subject");String pollToken=token(server,code(server,"poller-subject"));List<String> codes=new ArrayList<>();Set<OAuthStoreKey> codeKeys=new HashSet<>(),grantKeys=new HashSet<>();Map<OAuthStoreKey,OAuthStoreKey> subjectsByCode=new HashMap<>();Set<OAuthStoreKey> pollKeys=delegate.rows.keySet().stream().filter(k->k.getKind()!=OAuthStoreKey.Kind.INTERACTION&&k.getKind()!=OAuthStoreKey.Kind.CODE).collect(java.util.stream.Collectors.toSet());assertEquals(4,pollKeys.size());
  for(int n=0;n<count;n++){String subject="subject-"+n;server.establishNewSubject(subject);String code=code(server,subject);codes.add(code);var codeKey=codec.key(OAuthStoreKey.Kind.CODE,OAuthServerCredential.codeDigest(code));codeKeys.add(codeKey);subjectsByCode.put(codeKey,codec.subjectKey(subject));grantKeys.add(codec.key(OAuthStoreKey.Kind.GRANT,record(codec,requireNonNull(delegate.rows.get(codeKey)),clock).text("grantId")));}
  var before=Map.copyOf(delegate.rows);var root=requireNonNull(before.get(codec.issuerKey()));trace.set(true);
  Map<String,List<String>> headers=Map.of("Content-Type",List.of("application/x-www-form-urlencoded"),"Authorization",List.of("Basic "+Base64.getEncoder().encodeToString("resource:secret".getBytes(StandardCharsets.UTF_8))));List<String> issued=new CopyOnWriteArrayList<>();
  work.run("ISSUER",()->assertDoesNotThrow(()->{var result=assertInstanceOf(OAuthIntrospectionResult.Succeeded.class,server.introspectionResult("POST",null,form(Map.of("token",pollToken)).getBytes(StandardCharsets.UTF_8),headers));byte[] body=result.getResponse().toHttpBodyWithCredentials();try{var json=(JsonObject)JsonCodec.parse(body,JsonLimits.protocolDocument(131072));assertEquals(com.revetsec.json.JsonBoolean.fromValue(true),json.find("active").orElseThrow());}catch(com.revetsec.internal.json.JsonParseException failure){throw new AssertionError(failure);}finally{Arrays.fill(body,(byte)0);}}),n->issued.add(assertDoesNotThrow(()->token(server,codes.get(n)))));
  assertEquals(count,issued.size());assertEquals(count,policyCalls.get());assertEquals(count,preparationNanos.size());assertTrue(preparationNanos.stream().allMatch(n->n>=120_000_000L));assertEquals(0,conflicts.get());assertEquals(0,capacityRefusals.get());assertEquals(root.getVersion(),requireNonNull(delegate.rows.get(codec.issuerKey())).getVersion());assertEquals(root.toSealedForm(),requireNonNull(delegate.rows.get(codec.issuerKey())).toSealedForm());
  var changed=transactions.stream().filter(t->!t.getMutations().isEmpty()).toList();assertEquals(count,changed.size());Set<OAuthStoreKey> touched=new HashSet<>();
  for(var transaction:transactions){var rootCondition=transaction.getConditions().stream().filter(c->c.getKey().equals(codec.issuerKey())).findFirst().orElseThrow();assertEquals(Optional.of(root.getVersion()),rootCondition.getExpectedVersion());for(var mutation:transaction.getMutations()){assertFalse(mutation.getKey().equals(codec.issuerKey()));touched.add(mutation.getKey());}if(!transaction.getMutations().isEmpty()){assertEquals(3,transaction.getMutations().size());var codeKey=transaction.getMutations().stream().map(m->m.getKey()).filter(k->k.getKind()==OAuthStoreKey.Kind.CODE).findFirst().orElseThrow();Set<OAuthStoreKey> exact=new HashSet<>();transaction.getMutations().forEach(m->exact.add(m.getKey()));exact.add(codec.issuerKey());exact.add(requireNonNull(subjectsByCode.get(codeKey)));assertEquals(exact,transaction.getConditions().stream().map(c->c.getKey()).collect(java.util.stream.Collectors.toSet()));assertEquals(Set.of(OAuthStoreKey.Kind.CODE,OAuthStoreKey.Kind.GRANT,OAuthStoreKey.Kind.ACCESS_TOKEN),transaction.getMutations().stream().map(m->m.getKey().getKind()).collect(java.util.stream.Collectors.toSet()));}else assertEquals(pollKeys,transaction.getConditions().stream().map(c->c.getKey()).collect(java.util.stream.Collectors.toSet()));for(var condition:transaction.getConditions()){var old=before.get(condition.getKey());assertEquals(old==null?Optional.empty():Optional.of(old.getVersion()),condition.getExpectedVersion());}}
  assertEquals(count*3,touched.size());assertTrue(touched.containsAll(codeKeys));assertTrue(touched.containsAll(grantKeys));for(var entry:before.entrySet())if(!touched.contains(entry.getKey())){var after=requireNonNull(delegate.rows.get(entry.getKey()));assertEquals(entry.getValue().getVersion(),after.getVersion());assertEquals(entry.getValue().toSealedForm(),after.toSealedForm());}for(var codeKey:codeKeys)assertEquals("USED",record(codec,requireNonNull(delegate.rows.get(codeKey)),clock).text("status"));for(var grantKey:grantKeys)assertEquals("ACTIVE",record(codec,requireNonNull(delegate.rows.get(grantKey)),clock).text("status"));
  System.out.println("SC-BOUND-03 issuerPreparationNanos="+preparationNanos);
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scBound03FenceOnlyIndependentSubjectsKeepTheirExactPermanentFactsDuringOutage(){
  return List.of(org.junit.jupiter.api.DynamicTest.dynamicTest("BOUND03/FENCE_ONLY/accounts=8",()->runFenceOnly(8)),org.junit.jupiter.api.DynamicTest.dynamicTest("BOUND03/FENCE_ONLY/accounts=16",()->runFenceOnly(16)));
 }
 private static void runFenceOnly(int count)throws Exception{
  var work=new IndependentAccountWorkload(count);var worker=new FailingWorker();var authority=Clock.systemUTC();var delegate=new OAuthAtomicStoreFixture(authority.instant());var trace=new AtomicBoolean();var polling=ThreadLocal.withInitial(()->false);var pollReads=new AtomicInteger();var polls=new AtomicInteger();var conflicts=new AtomicInteger();var capacity=new AtomicInteger();var policyCalls=new AtomicInteger();List<OAuthStoreTransaction> transactions=new CopyOnWriteArrayList<>();
  var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).build();var codec=new OAuthStoreRecordCodec(ISSUER,sealer,3800);
  OAuthAuthorizationServerStore store=new OAuthAuthorizationServerStore(){
   @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){assertFalse(Thread.holdsLock(delegate.rows));Duration left=work.beforeBackend(budget);synchronized(delegate.rows){if(!trace.get())delegate.authorityNow=authority.instant();if(trace.get()&&polling.get()){pollReads.incrementAndGet();assertEquals(codec.issuerKey(),key);}return delegate.read(key,left);}}
   @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){assertFalse(Thread.holdsLock(delegate.rows));Duration left=work.beforeBackend(budget);synchronized(delegate.rows){if(!trace.get())delegate.authorityNow=authority.instant();if(trace.get())transactions.add(transaction);Map<OAuthStoreKey,OAuthStoreEntry> projected=new HashMap<>(delegate.rows);for(var mutation:transaction.getMutations()){if(mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE)projected.remove(mutation.getKey());else projected.put(mutation.getKey(),mutation.getEntry().orElseThrow());}long bytes=projected.values().stream().mapToLong(e->e.toSealedForm().getBytes(StandardCharsets.UTF_8).length).sum();if(projected.size()>1024||bytes>16_777_216L){capacity.incrementAndGet();return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.CAPACITY);}var receipt=delegate.commit(transaction,left);if(receipt.getStatus()==OAuthStoreCommitStatus.CONFLICT)conflicts.incrementAndGet();return receipt;}}
  };
  var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;var snapshot=OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromRsaKeyPair("key",key.getPrivateKey(),key.getPublicKey())).generation("g1").publishedAt(authority.instant().minusSeconds(120)).build();
  var client=OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(Map.of(RESOURCE,Set.of("read"))).build();
  java.util.function.Function<@NonNull Clock,@NonNull OAuthAuthorizationServer> build=selectedClock->OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).jwksEndpoint(URI.create(ISSUER+"/jwks")).revocationEndpoint(URI.create(ISSUER+"/revoke")).clientRepository((id,budget)->Optional.of(client)).store(store).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(snapshot)).stateSealer(sealer).resources(Map.of(RESOURCE,Set.of("read"))).clock(selectedClock).clockSkew(Duration.ZERO).totalDeadline(IndependentAccountWorkload.budget()).requestTimeout(IndependentAccountWorkload.budget()).grantPolicy((context,budget)->{assertFalse(Thread.holdsLock(delegate.rows));if(trace.get())policyCalls.incrementAndGet();return decision(context.getSubject());}).build();
  var server=build.apply(worker);var statusServer=build.apply(authority);
  assertEquals(OAuthStoreCommitStatus.COMMITTED,server.initializeFreshIssuer().getStatus());server.establishNewSubject("poller-subject");String token=token(server,code(server,"poller-subject"));var bearer=assertInstanceOf(com.revetsec.oauth.BearerTokenResult.Present.class,com.revetsec.oauth.BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer "+token))).getToken();
  assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,statusServer.validateAccessTokenResult(bearer,RESOURCE));
  Set<OAuthStoreKey> subjects=new HashSet<>();for(int n=0;n<count;n++){String subject="fence-subject-"+n;server.establishNewSubject(subject);subjects.add(codec.subjectKey(subject));}
  Map<OAuthStoreKey,OAuthStoreEntry> before=Map.copyOf(delegate.rows);var root=requireNonNull(before.get(codec.issuerKey()));int commits=delegate.commits,reads=delegate.reads;delegate.healthy=false;worker.broken.set(true);worker.calls.set(0);trace.set(true);
  work.run("ISSUER_FENCE_ONLY",()->{polling.set(true);try{var failure=assertThrows(OAuthServerStoreException.class,()->statusServer.validateAccessTokenResult(bearer,RESOURCE));assertEquals(OAuthServerException.Reason.STORE_UNAVAILABLE,failure.getReason());assertFalse(failure.isTemporaryCondition());polls.incrementAndGet();}finally{polling.remove();}},n->assertDoesNotThrow(()->server.revokeSubject("fence-subject-"+n)));
  assertEquals(0,policyCalls.get());assertEquals(0,worker.calls.get());assertEquals(0,conflicts.get());assertEquals(0,capacity.get());assertTrue(polls.get()>=1);assertEquals(polls.get(),pollReads.get());assertEquals(commits+count,delegate.commits);assertEquals(reads+count*3+pollReads.get(),delegate.reads);
  assertEquals(count,transactions.size());Set<OAuthStoreKey> touched=new HashSet<>();
  for(var transaction:transactions){assertEquals(OAuthStoreTransaction.Purpose.FENCE_ONLY,transaction.getPurpose());assertTrue(transaction.getTemporalCondition().isEmpty());assertEquals(delegate.admission,transaction.getExpectedAdmission());assertEquals(1,transaction.getMutations().size());var mutation=transaction.getMutations().get(0);assertEquals(OAuthStoreTransaction.Mutation.Kind.PUT,mutation.getKind());assertTrue(subjects.contains(mutation.getKey()));assertTrue(touched.add(mutation.getKey()));assertEquals(Set.of(codec.issuerKey(),mutation.getKey()),transaction.getConditions().stream().map(c->c.getKey()).collect(java.util.stream.Collectors.toSet()));for(var condition:transaction.getConditions())assertEquals(Optional.of(requireNonNull(before.get(condition.getKey())).getVersion()),condition.getExpectedVersion());}
  assertEquals(subjects,touched);assertEquals(before.keySet(),delegate.rows.keySet());
  for(var entry:before.entrySet()){
   var after=requireNonNull(delegate.rows.get(entry.getKey()));if(!subjects.contains(entry.getKey())){assertEquals(entry.getValue().getVersion(),after.getVersion());assertEquals(entry.getValue().toSealedForm(),after.toSealedForm());continue;}
   var oldOpened=codec.openPermanentFence(entry.getValue(),delegate.admission,root);var nextOpened=codec.openPermanentFence(after,delegate.admission,root);var old=OAuthStoreFence.decode(oldOpened.payload(),OAuthStoreKey.Kind.SUBJECT_STATE);var next=OAuthStoreFence.decode(nextOpened.payload(),OAuthStoreKey.Kind.SUBJECT_STATE);
   assertNotEquals(entry.getValue().getVersion(),after.getVersion());assertEquals(OAuthStoreFormat.PERMANENT,after.getRetainUntil());assertEquals(entry.getValue().getRetainUntil(),after.getRetainUntil());assertEquals(oldOpened.floor(),nextOpened.floor());assertEquals(old.incarnation(),next.incarnation());assertEquals(old.highWater(),next.highWater());assertEquals(0,old.epoch());assertEquals(1,next.epoch());
  }
  assertFalse(delegate.healthy);assertEquals(0,worker.calls.get());System.out.println("BOUND03 FENCE_ONLY accounts="+count+" statusPolls="+polls.get()+" statusReads="+pollReads.get()+" committedSubjects="+transactions.size()+" workerClockCalls="+worker.calls.get()+" policyCalls="+policyCalls.get());
 }
 @ThreadSafe private static final class FailingWorker extends Clock{
  final @NonNull AtomicBoolean broken=new AtomicBoolean();final @NonNull AtomicInteger calls=new AtomicInteger();
  @Override public @NonNull Instant instant(){this.calls.incrementAndGet();if(this.broken.get())throw new IllegalStateException("TEST-ONLY worker clock unavailable");return Clock.systemUTC().instant();}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
 }


 private static @NonNull OAuthAuthorizationDecision decision(@NonNull String subject){return OAuthAuthorizationDecision.withSubject(subject).authorizedScopesByResource(Map.of(RESOURCE,Set.of("read"))).build();}
 private static @NonNull String code(@NonNull OAuthAuthorizationServer server,@NonNull String subject){String query=form(Map.of("client_id","client","response_type","code","redirect_uri",REDIRECT,"resource",RESOURCE,"code_challenge",CHALLENGE,"code_challenge_method","S256"));var interaction=assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,server.beginAuthorizationResult("GET",query,new byte[0],Map.of(),BROWSER)).getInteraction();var response=assertInstanceOf(OAuthAuthorizationResult.Completed.class,server.completeAuthorizationResult(interaction.getInteractionValue(),BROWSER,decision(subject))).getResponse();String location=response.getLocationWithCredentials().orElseThrow().toString();return location.substring(location.indexOf("code=")+5,location.indexOf("&iss="));}
 private static @NonNull String token(@NonNull OAuthAuthorizationServer server,@NonNull String code){var result=assertInstanceOf(OAuthTokenResult.Succeeded.class,server.tokenResult("POST",null,form(Map.of("grant_type","authorization_code","client_id","client","resource",RESOURCE,"code",code,"code_verifier",VERIFIER,"redirect_uri",REDIRECT)).getBytes(StandardCharsets.UTF_8),Map.of("Content-Type",List.of("application/x-www-form-urlencoded"))));byte[] body=result.getResponse().toHttpBodyWithCredentials();try{var json=(JsonObject)JsonCodec.parse(body,JsonLimits.protocolDocument(131072));return ((JsonString)json.find("access_token").orElseThrow()).getValue();}catch(com.revetsec.internal.json.JsonParseException failure){throw new AssertionError(failure);}finally{Arrays.fill(body,(byte)0);}}
 private static @NonNull OAuthAuthorizationRecord record(@NonNull OAuthStoreRecordCodec codec,@NonNull OAuthStoreEntry entry,@NonNull Clock clock){var opened=codec.openAdmitted(entry,clock);return OAuthAuthorizationRecord.decode(entry.getKey().getKind(),OAuthStoreRecordCodecV2.identifier(entry.getKey()),opened.payload(),new OAuthServerIngressLimits(65536,65536,65536,4096,4096,1024,64,128,128),255);}
 private static @NonNull String form(@NonNull Map<@NonNull String,@NonNull String> values){return String.join("&",values.entrySet().stream().map(e->encode(e.getKey())+"="+encode(e.getValue())).toList());}
 private static @NonNull String encode(@NonNull String value){try{return FormUrlEncoding.encode(value);}catch(com.revetsec.internal.encoding.EncodingException failure){throw new AssertionError(failure);}}
}
