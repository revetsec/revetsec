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

import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.function.Executable;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PSSParameterSpec;
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
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Deterministic lifecycle and independent JCA signature checks; no distributed publication or persistence proof. */
final class OAuthIssuerKeysTests {
 private static final @NonNull Instant NOW=Instant.parse("2026-10-05T12:00:00Z");
 private static final TestJsonWebKeys.@NonNull Fixture A=TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
 private static final TestJsonWebKeys.@NonNull Fixture B=TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_3072;
 private static final @NonNull String ISSUER="https://issuer.example/tenant";
 private static final @NonNull Duration FRESHNESS=Duration.ofSeconds(60);
 private static @NonNull OAuthIssuerSigningKey key(@NonNull String id,TestJsonWebKeys.@NonNull Fixture fixture) {
  return OAuthIssuerSigningKey.fromKeyPair(id,fixture.getPrivateKey(),fixture.getPublicKey());
 }
 private static @NonNull OAuthIssuerKeySnapshot snapshot(@NonNull OAuthIssuerSigningKey key,@NonNull String generation,
   @NonNull Instant publication,@NonNull Map<@NonNull String,@NonNull PublicKey> keys,@NonNull Map<@NonNull String,@NonNull Instant> retirement) {
  return OAuthIssuerKeySnapshot.withActiveKey(key).generation(generation).publishedAt(publication).verificationKeys(keys).retirementNotBefore(retirement).build();
 }
 private static @NonNull OAuthIssuerKeySnapshot initial() { return snapshot(key("a",A),"g1",NOW.minusSeconds(120),Map.of(),Map.of()); }
 private static @NonNull OAuthGrantRetention retention() { return new OAuthGrantRetention(Duration.ofMinutes(5),Duration.ofSeconds(30),Duration.ofSeconds(10),FRESHNESS); }
 private static @NonNull OAuthIssuerKeyLifecycle lifecycle(@NonNull OAuthIssuerKeyProvider provider,@NonNull Clock clock) {
  return new OAuthIssuerKeyLifecycle(provider,clock,FRESHNESS,retention());
 }
 private static @NonNull OAuthIssuerKeyLifecycle lifecycle(@NonNull OAuthIssuerKeySnapshot snapshot) {
  return lifecycle(OAuthIssuerKeyProvider.fromSnapshot(snapshot),Clock.fixed(NOW,ZoneOffset.UTC));
 }
 private static @NonNull Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(10)); }
 private static byte @NonNull [] claims() { return "{\"iss\":\"https://issuer.example/tenant\",\"exp\":1791201900}".getBytes(StandardCharsets.UTF_8); }
 private static @NonNull JsonObject json(byte @NonNull [] bytes) {
  try { return (JsonObject)JsonCodec.parse(bytes,JsonLimits.jose(131072)); }
  catch(com.revetsec.internal.json.JsonParseException fault) { throw new AssertionError(fault); }
 }
 private static void unavailable(@NonNull Executable call) {
  var fault=assertThrows(OAuthServerAdmissionFailure.class,call);
  assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,fault.reason());assertNull(fault.getCause());
  assertEquals("OAuth server admission failed.",fault.getMessage());
 }
 private static @NonNull DynamicTest test(@NonNull String name,@NonNull Executable call) { return DynamicTest.dynamicTest(name,call); }
 @Test void constructionDoesNotSignEncodeOrLookupAndDiagnosticsAreRedacted() {
  OpaquePrivate privateKey=new OpaquePrivate();
  OAuthIssuerSigningKey key=OAuthIssuerSigningKey.fromKeyPair("private-identifier",privateKey,A.getPublicKey());
  OAuthIssuerKeySnapshot snapshot=snapshot(key,"private-generation",NOW.minusSeconds(120),Map.of(),Map.of());
  AtomicInteger calls=new AtomicInteger();OAuthIssuerKeyLifecycle lifecycle=lifecycle(budget->{calls.incrementAndGet();return snapshot;},Clock.fixed(NOW,ZoneOffset.UTC));
  assertEquals(0,calls.get());assertEquals(0,privateKey.encodings);assertEquals("private-identifier",key.getKeyId());
  assertEquals("private-generation",snapshot.getGeneration());assertEquals(NOW.minusSeconds(120),snapshot.getPublishedAt());assertSame(key,snapshot.getActiveKey());
  assertEquals(Set.of("private-identifier"),snapshot.getVerificationKeys().keySet());
  assertEquals("OAuthIssuerSigningKey{<redacted>}",key.toString());
  assertEquals("OAuthIssuerKeySnapshot{<redacted>}",snapshot.toString());
  assertEquals("OAuthIssuerKeyLifecycle{<redacted>}",lifecycle.toString());
  for(Object value:List.of(key,snapshot,key.getPublicKey(),lifecycle)) assertFalse(value.toString().contains("private-"));
  unavailable(()->lifecycle.warmUp(deadline()));assertEquals(0,privateKey.encodings);
 }
 @Test void resetAndMutationIsolationApplyToEveryBuilderProperty() {
  Map<String,PublicKey> keys=new LinkedHashMap<>(Map.of("b",B.getPublicKey()));Map<String,Instant> retirement=new LinkedHashMap<>(Map.of("b",NOW.plusSeconds(1000)));
  var builder=OAuthIssuerKeySnapshot.withActiveKey(key("a",A)).generation("g").publishedAt(NOW.minusSeconds(120)).verificationKeys(keys).retirementNotBefore(retirement);
  keys.clear();retirement.clear();var first=builder.build();assertEquals(2,first.getVerificationKeys().size());assertEquals(1,first.getRetirementNotBefore().size());
  assertThrows(UnsupportedOperationException.class,()->first.getVerificationKeys().clear());assertThrows(UnsupportedOperationException.class,()->first.getRetirementNotBefore().clear());
  var reset=builder.verificationKeys(null).retirementNotBefore(null).build();assertEquals(1,reset.getVerificationKeys().size());assertTrue(reset.getRetirementNotBefore().isEmpty());
  builder=builder.generation(null);var missingGeneration=builder;assertThrows(IllegalStateException.class,missingGeneration::build);
  builder=builder.generation("g").publishedAt(null);var missingPublication=builder;assertThrows(IllegalStateException.class,missingPublication::build);
  assertEquals(2,first.getVerificationKeys().size());assertSame(first,OAuthIssuerKeyProvider.fromSnapshot(first).getSnapshot(Duration.ofSeconds(1)));
 }
 @SuppressWarnings("NullAway") // Intentional required-null boundary probes.
 @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidConfiguration() {
  List<DynamicTest> tests=new ArrayList<>();
  for(String id:List.of("","x".repeat(257),"bad\n","bad\u0000","\uD800")) {
   tests.add(test("invalid key identifier "+tests.size(),()->assertThrows(IllegalArgumentException.class,()->key(id,A))));
   tests.add(test("invalid generation "+tests.size(),()->assertThrows(IllegalArgumentException.class,()->OAuthIssuerKeySnapshot.withActiveKey(key("a",A)).generation(id))));
   tests.add(test("invalid verification identifier "+tests.size(),()->assertThrows(IllegalArgumentException.class,()->OAuthIssuerKeySnapshot.withActiveKey(key("a",A)).verificationKeys(Map.of(id,A.getPublicKey())))));
   tests.add(test("invalid retirement identifier "+tests.size(),()->assertThrows(IllegalArgumentException.class,()->OAuthIssuerKeySnapshot.withActiveKey(key("a",A)).retirementNotBefore(Map.of(id,NOW)))));
  }
  tests.add(test("missing generation",()->assertThrows(IllegalStateException.class,()->OAuthIssuerKeySnapshot.withActiveKey(key("a",A)).publishedAt(NOW).build())));
  tests.add(test("missing publication",()->assertThrows(IllegalStateException.class,()->OAuthIssuerKeySnapshot.withActiveKey(key("a",A)).generation("g").build())));
  tests.add(test("null active",()->assertThrows(NullPointerException.class,()->OAuthIssuerKeySnapshot.withActiveKey(null))));
  tests.add(test("null provider snapshot",()->assertThrows(NullPointerException.class,()->OAuthIssuerKeyProvider.fromSnapshot(null))));
  tests.add(test("retirement unknown ID",()->assertThrows(IllegalArgumentException.class,()->snapshot(key("a",A),"g",NOW,Map.of(),Map.of("b",NOW)))));
  tests.add(test("retirement before publication",()->assertThrows(IllegalArgumentException.class,()->snapshot(key("a",A),"g",NOW,Map.of(),Map.of("a",NOW.minusNanos(1))))));
  tests.add(test("publication overflow sentinel",()->assertThrows(IllegalArgumentException.class,()->OAuthIssuerKeySnapshot.withActiveKey(key("a",A)).publishedAt(Instant.MAX))));
  tests.add(test("retirement overflow sentinel",()->assertThrows(IllegalArgumentException.class,()->OAuthIssuerKeySnapshot.withActiveKey(key("a",A)).retirementNotBefore(Map.of("a",Instant.MAX)))));
  tests.add(test("active duplicate changed material",()->assertThrows(IllegalArgumentException.class,()->snapshot(key("a",A),"g",NOW,Map.of("a",B.getPublicKey()),Map.of()))));
  tests.add(test("active duplicate equal material",()->assertEquals(1,snapshot(key("a",A),"g",NOW,Map.of("a",A.getPublicKey()),Map.of()).getVerificationKeys().size())));
  for(int count:List.of(100,101)) tests.add(test("total key count "+count,()->{
   Map<String,PublicKey> keys=new LinkedHashMap<>();for(int i=0;i<count;i++) keys.put("key"+i,A.getPublicKey());
   assertThrows(IllegalArgumentException.class,()->snapshot(key("a",A),"g",NOW,keys,Map.of()));
  }));
  tests.add(test("100 including active is allowed",()->{
   Map<String,PublicKey> keys=new LinkedHashMap<>();for(int i=0;i<99;i++)keys.put("key"+i,A.getPublicKey());
   assertEquals(100,snapshot(key("a",A),"g",NOW,keys,Map.of()).getVerificationKeys().size());
  }));
  tests.add(test("retirement count bounded",()->{Map<String,Instant> keys=new LinkedHashMap<>();for(int i=0;i<101;i++)keys.put("key"+i,NOW);
   assertThrows(IllegalArgumentException.class,()->OAuthIssuerKeySnapshot.withActiveKey(key("a",A)).retirementNotBefore(keys));}));
  return tests.stream();
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> malformedPublicKeys() {
  RSAPublicKey good=(RSAPublicKey)A.getPublicKey();List<PublicKey> bad=new ArrayList<>();
  bad.add(TestJsonWebKeys.rocaFingerprintedRsaKeyPair().getPublic());
  bad.add(TestJsonWebKeys.Fixture.NEGATIVE_RSA_1024.getPublicKey());bad.add(TestJsonWebKeys.Fixture.IDP_SIGNING_EC_P256.getPublicKey());
  bad.add(new SuppliedKey(good.getModulus(),good.getPublicExponent(),"unknown",null));
  bad.add(new SuppliedKey(good.getModulus(),good.getPublicExponent(),"RSASSA-PSS",null));
  bad.add(new SuppliedKey(good.getModulus(),good.getPublicExponent(),"RSA",PSSParameterSpec.DEFAULT));
  for(BigInteger n:List.of(BigInteger.ZERO,BigInteger.ONE,BigInteger.ONE.negate(),good.getModulus().clearBit(0),BigInteger.ONE.shiftLeft(16384).add(BigInteger.ONE)))
   bad.add(new SuppliedKey(n,good.getPublicExponent(),"RSA",null));
  for(BigInteger e:List.of(BigInteger.ZERO,BigInteger.valueOf(3),BigInteger.valueOf(65538),BigInteger.ONE.shiftLeft(32)))
   bad.add(new SuppliedKey(good.getModulus(),e,"RSA",null));
  List<DynamicTest> tests=new ArrayList<>();for(PublicKey key:bad) tests.add(test("invalid public key "+tests.size(),()->
   assertThrows(IllegalArgumentException.class,()->OAuthIssuerKeySnapshot.withActiveKey(key("a",A)).verificationKeys(Map.of("bad",key)))));
  return tests.stream();
 }
 @Test void mutablePublicKeyIsSnapshottedOnceWithoutEncoding() {
  RSAPublicKey good=(RSAPublicKey)A.getPublicKey();SuppliedKey supplied=new SuppliedKey(good.getModulus(),good.getPublicExponent(),"RSA",null);
  var snapshot=snapshot(key("a",A),"g",NOW.minusSeconds(120),Map.of("b",supplied),Map.of());String before=OAuthIssuerPublicKeys.jwks(snapshot.getVerificationKeys()).toJson();
  supplied.n=BigInteger.ONE;supplied.e=BigInteger.ONE;assertEquals(before,OAuthIssuerPublicKeys.jwks(snapshot.getVerificationKeys()).toJson());
 }
 @Test void realPairMismatchFailsOnOperationAndWarmupWithoutCredentialRelease() {
  var mismatch=OAuthIssuerSigningKey.fromKeyPair("a",A.getPrivateKey(),B.getPublicKey());var lifecycle=lifecycle(snapshot(mismatch,"g",NOW.minusSeconds(120),Map.of(),Map.of()));
  unavailable(()->lifecycle.sign(claims(),NOW.plusSeconds(300),deadline()));unavailable(()->lifecycle.warmUp(deadline()));
 }
 @Test void independentOracleAndPublicJwksAgreeWithSignedToken() throws Exception {
  var lifecycle=lifecycle(initial());String jwt=lifecycle.sign(claims(),NOW.plusSeconds(300),deadline());String[] parts=jwt.split("\\.",-1);
  Signature oracle=Signature.getInstance("SHA256withRSA");oracle.initVerify(A.getPublicKey());oracle.update((parts[0]+"."+parts[1]).getBytes(StandardCharsets.US_ASCII));
  assertTrue(oracle.verify(Base64.getUrlDecoder().decode(parts[2])));assertArrayEquals(claims(),Base64.getUrlDecoder().decode(parts[1]));
  JsonObject header=json(Base64.getUrlDecoder().decode(parts[0]));assertEquals("a",header.findString("kid").orElseThrow());assertEquals("at+jwt",header.findString("typ").orElseThrow());
  String jwks=OAuthIssuerPublicKeys.jwks(initial().getVerificationKeys()).toJson();assertEquals(1,JsonWebKeySet.fromJson(jwks).getKeys().size());
  for(String field:List.of("d","p","q","dp","dq","qi","oth","k","x5u","jku")) assertFalse(jwks.contains("\""+field+"\""));
  var parsed=JsonWebKeySet.fromJson(jwks).getKeys().get(0);assertEquals("a",parsed.getKeyId().orElseThrow());
  assertNotNull(lifecycle.verificationKeys(deadline()));lifecycle.warmUp(deadline());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> publicationAndRetirementBounds() {
  List<DynamicTest> tests=new ArrayList<>();
  for(long age:List.of(-1L,0L,59L,60L,61L)) tests.add(test("publication age "+age,()->{
   var life=lifecycle(snapshot(key("a",A),"g",NOW.minusSeconds(age),Map.of(),Map.of()));
   if(age<60) unavailable(()->life.sign(claims(),NOW.plusSeconds(300),deadline()));else assertNotNull(life.sign(claims(),NOW.plusSeconds(300),deadline()));
  }));
  for(long boundary:List.of(0L,1L,399L,400L,401L)) tests.add(test("retirement boundary "+boundary,()->{
   var life=lifecycle(snapshot(key("a",A),"g",NOW.minusSeconds(120),Map.of(),Map.of("a",NOW.plusSeconds(boundary))));
   if(boundary<400) unavailable(()->life.sign(claims(),NOW.plusSeconds(300),deadline()));else assertNotNull(life.sign(claims(),NOW.plusSeconds(300),deadline()));
  }));
  tests.add(test("expired candidate",()->unavailable(()->lifecycle(initial()).sign(claims(),NOW,deadline()))));
  tests.add(test("past candidate",()->unavailable(()->lifecycle(initial()).sign(claims(),NOW.minusSeconds(1),deadline()))));
  tests.add(test("exhausted original budget",()->unavailable(()->lifecycle(initial()).snapshot(Deadline.fromNow(Duration.ZERO)))));
  tests.add(test("publication overflow",()->{Instant near=OAuthStoreFormat.PERMANENT.minusSeconds(1);var life=lifecycle(OAuthIssuerKeyProvider.fromSnapshot(snapshot(key("a",A),"g",near,Map.of(),Map.of())),Clock.fixed(near,ZoneOffset.UTC));
   unavailable(()->life.sign(claims(),OAuthStoreFormat.PERMANENT,deadline()));}));
  return tests.stream();
 }
 @Test void consistentRolloverRetainsOldPublicKeyUntilItsFinalMargin() {
  MutableClock clock=new MutableClock(NOW);AtomicReference<OAuthIssuerKeySnapshot> current=new AtomicReference<>(snapshot(key("a",A),"g1",NOW.minusSeconds(120),Map.of(),Map.of("a",NOW.plusSeconds(400))));
  var life=lifecycle(budget->requireNonNull(current.get()),clock);String old=life.sign(claims(),NOW.plusSeconds(300),deadline());
  current.set(snapshot(key("b",B),"g2",NOW.minusSeconds(60),Map.of("a",A.getPublicKey()),Map.of("a",NOW.plusSeconds(400))));
  String next=life.sign(claims(),NOW.plusSeconds(300),deadline());assertNotEquals(old,next);assertEquals(2,life.snapshot(deadline()).getVerificationKeys().size());
  current.set(snapshot(key("b",B),"g3",NOW,Map.of(),Map.of()));unavailable(()->life.snapshot(deadline()));
  clock.now=NOW.plusSeconds(400);assertEquals(Set.of("b"),life.snapshot(deadline()).getVerificationKeys().keySet());
 }
 @Test void laterShorterIssuanceCannotReduceAnEarlierKeyReservation() {
  AtomicReference<OAuthIssuerKeySnapshot> current=new AtomicReference<>(
   snapshot(key("a",A),"g1",NOW.minusSeconds(120),Map.of(),Map.of()));
  var life=lifecycle(budget->requireNonNull(current.get()),Clock.fixed(NOW,ZoneOffset.UTC));
  assertNotNull(life.sign(claims(),NOW.plusSeconds(300),deadline()));
  assertNotNull(life.sign(claims(),NOW.plusSeconds(200),deadline()));
  current.set(snapshot(key("b",B),"g2",NOW.minusSeconds(60),Map.of("a",A.getPublicKey()),
   Map.of("a",NOW.plusSeconds(350))));
  unavailable(()->life.snapshot(deadline()));
 }
 @Test void aKeyRetiredAtTheCurrentInstantCannotBePublishedAsActive() {
  var retired=snapshot(key("a",A),"g1",NOW.minusSeconds(120),Map.of(),Map.of("a",NOW));
  unavailable(()->lifecycle(retired).snapshot(deadline()));
 }
 @Test void anUnreservedVerificationKeyCanRetireAtItsDeclaredBoundary() {
  MutableClock clock=new MutableClock(NOW);
  AtomicReference<OAuthIssuerKeySnapshot> current=new AtomicReference<>(
   snapshot(key("b",B),"g1",NOW.minusSeconds(120),Map.of("a",A.getPublicKey()),
    Map.of("a",NOW.plusSeconds(100))));
  var life=lifecycle(budget->requireNonNull(current.get()),clock);
  assertEquals(2,life.snapshot(deadline()).getVerificationKeys().size());
  current.set(snapshot(key("b",B),"g2",NOW.minusSeconds(60),Map.of(),Map.of()));
  clock.now=NOW.plusSeconds(100);
  assertEquals(Set.of("b"),life.snapshot(deadline()).getVerificationKeys().keySet());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> contradictoryGenerationsFailClosed() {
  List<DynamicTest> tests=new ArrayList<>();
  List<OAuthIssuerKeySnapshot> wrong=List.of(
   snapshot(key("b",B),"g1",NOW.minusSeconds(120),Map.of("a",A.getPublicKey()),Map.of()),
   snapshot(key("a",A),"g1",NOW.minusSeconds(119),Map.of(),Map.of()),
   snapshot(key("a",A),"g2",NOW.minusSeconds(120),Map.of(),Map.of()),
   snapshot(key("a",A),"g2",NOW.minusSeconds(121),Map.of(),Map.of()),
   snapshot(key("a",B),"g2",NOW.minusSeconds(60),Map.of(),Map.of()),
   snapshot(key("b",B),"g2",NOW.minusSeconds(60),Map.of(),Map.of()),
   snapshot(key("a",A),"g1",NOW.minusSeconds(120),Map.of(),Map.of("a",NOW.plusSeconds(1000))));
  for(var value:wrong) tests.add(test("contradictory generation "+tests.size(),()->{
   AtomicReference<OAuthIssuerKeySnapshot> ref=new AtomicReference<>(initial());var life=lifecycle(budget->requireNonNull(ref.get()),Clock.fixed(NOW,ZoneOffset.UTC));
   assertNotNull(life.snapshot(deadline()));ref.set(value);unavailable(()->life.snapshot(deadline()));ref.set(initial());assertNotNull(life.snapshot(deadline()));
  }));
  return tests.stream();
 }
 @Test void earlyRetirementAndBackwardClockFailWithoutReplacingLastGoodSnapshot() {
  MutableClock clock=new MutableClock(NOW);var first=snapshot(key("a",A),"g1",NOW.minusSeconds(120),Map.of(),Map.of("a",NOW.plusSeconds(500)));
  AtomicReference<OAuthIssuerKeySnapshot> ref=new AtomicReference<>(first);var life=lifecycle(budget->requireNonNull(ref.get()),clock);assertNotNull(life.sign(claims(),NOW.plusSeconds(300),deadline()));
  ref.set(snapshot(key("a",A),"g2",NOW.minusSeconds(60),Map.of(),Map.of("a",NOW.plusSeconds(400))));unavailable(()->life.snapshot(deadline()));
  ref.set(snapshot(key("b",B),"g2",NOW.minusSeconds(60),Map.of("a",A.getPublicKey()),Map.of("a",NOW.plusSeconds(399))));unavailable(()->life.snapshot(deadline()));
  ref.set(first);clock.now=NOW.minusNanos(1);unavailable(()->life.snapshot(deadline()));clock.now=NOW;assertSame(first,life.snapshot(deadline()));
 }
 @Test void rotationDuringPreparedSigningIsRechecked() {
  AtomicInteger calls=new AtomicInteger();var before=initial();var missing=snapshot(key("b",B),"g2",NOW.minusSeconds(60),Map.of(),Map.of());
  var life=lifecycle(budget->calls.incrementAndGet()==1 ? before : missing,Clock.fixed(NOW,ZoneOffset.UTC));unavailable(()->life.sign(claims(),NOW.plusSeconds(300),deadline()));assertEquals(2,calls.get());
  calls.set(0);var retained=snapshot(key("b",B),"g2",NOW.minusSeconds(60),Map.of("a",A.getPublicKey()),Map.of("a",NOW.plusSeconds(400)));
  var okay=lifecycle(budget->calls.incrementAndGet()==1 ? before : retained,Clock.fixed(NOW,ZoneOffset.UTC));assertNotNull(okay.sign(claims(),NOW.plusSeconds(300),deadline()));
 }
 @Test void providerReceivesShrinkingOriginalBudgetAndCannotResetIt() {
  AtomicReference<Duration> first=new AtomicReference<>();AtomicInteger calls=new AtomicInteger();
  var life=lifecycle(budget->{ assertTrue(!budget.isZero() && !budget.isNegative());if(calls.incrementAndGet()==1) first.set(budget);else assertTrue(budget.compareTo(requireNonNull(first.get()))<0);return initial();},Clock.fixed(NOW,ZoneOffset.UTC));
  assertNotNull(life.sign(claims(),NOW.plusSeconds(300),deadline()));assertEquals(2,calls.get());
 }
 @SuppressWarnings("NullAway") // Intentionally broken trusted callback returns null.
 @TestFactory @NonNull Stream<@NonNull DynamicTest> providerFaults() {
  List<DynamicTest> tests=new ArrayList<>();
  for(Throwable fault:List.of(new IllegalArgumentException("private"),new AssertionError("private"),new LinkageError("private"),new InterruptedException("private")))
   tests.add(test("contained provider fault "+fault.getClass().getSimpleName(),()->{
    try { var life=lifecycle(budget->{raise(fault);return initial();},Clock.fixed(NOW,ZoneOffset.UTC));unavailable(()->life.snapshot(deadline()));assertEquals(fault instanceof InterruptedException,Thread.currentThread().isInterrupted()); }
    finally { Thread.interrupted(); }
   }));
  tests.add(test("null snapshot",()->unavailable(()->lifecycle(budget->null,Clock.fixed(NOW,ZoneOffset.UTC)).snapshot(deadline()))));
  tests.add(test("fatal escapes",()->assertThrows(InternalError.class,()->lifecycle(budget->{throw new InternalError("private");},Clock.fixed(NOW,ZoneOffset.UTC)).snapshot(deadline()))));
  tests.add(test("preinterrupted does not call provider",()->{AtomicInteger count=new AtomicInteger();try { Thread.currentThread().interrupt();
   unavailable(()->lifecycle(budget->{count.incrementAndGet();return initial();},Clock.fixed(NOW,ZoneOffset.UTC)).snapshot(deadline()));assertEquals(0,count.get());assertTrue(Thread.currentThread().isInterrupted()); }finally{Thread.interrupted();}}));
  return tests.stream();
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> interruptedSigningAndWarmupRestoreTheFlag() {
  return Stream.of("sign","warmUp").map(operation->test(operation,()->{
   var life=lifecycle(initial());
   try {
    InterruptingSignatureProvider.around(()->{if(operation.equals("sign"))unavailable(()->life.sign(claims(),NOW.plusSeconds(300),deadline()));else unavailable(()->life.warmUp(deadline()));});
    assertTrue(Thread.currentThread().isInterrupted());
   } finally {Thread.interrupted();}
  }));
 }
 @SuppressWarnings("unchecked") private static <E extends Throwable> void raise(@NonNull Throwable fault) throws E { throw (E)fault; }
 private static @NonNull OAuthIssuerMetadata metadata(@NonNull String issuer,boolean refresh,boolean extra,@NonNull Set<@NonNull String> scopes,
   @NonNull Duration freshness,int bodyCap,int headerCap,boolean loopback) {
  return new OAuthIssuerMetadata(URI.create(issuer),URI.create(issuer+"/authorize"),URI.create(issuer+"/token"),URI.create(issuer+"/jwks"),
   extra ? URI.create(issuer+"/revoke") : null,extra ? URI.create(issuer+"/introspect") : null,refresh,loopback,scopes,freshness,bodyCap,headerCap);
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> correctWellKnownPathsAndExactIssuer() {
  return Stream.of("https://issuer.example","https://issuer.example/","https://issuer.example/tenant/","https://issuer.example/a%2Fb","https://issuer.example:443/A")
   .map(issuer->test(issuer,()->{
    var metadata=metadata(issuer,false,false,Set.of(),FRESHNESS,32768,16384,false);URI uri=URI.create(issuer);String path=uri.getRawPath();if(path.endsWith("/"))path=path.substring(0,path.length()-1);
    assertEquals(uri.getScheme()+"://"+uri.getRawAuthority()+"/.well-known/oauth-authorization-server"+path,metadata.wellKnownUri().toString());
    JsonObject body=json(metadata.metadata("GET",deadline()).body());assertEquals(issuer,body.findString("issuer").orElseThrow());assertFalse(body.getMembers().containsKey("scopes_supported"));
   }));
 }
 @Test void metadataAdvertisesOnlyImplementedConfiguredCapabilities() {
  var metadata=metadata(ISSUER,true,true,Set.of("write","read"),FRESHNESS,32768,16384,false);JsonObject body=json(metadata.metadata("GET",deadline()).body());String text=body.toJson();
  assertTrue(text.contains("refresh_token"));assertTrue(text.contains("revocation_endpoint"));assertTrue(text.contains("introspection_endpoint"));assertTrue(text.contains("S256"));
  for(String unsupported:List.of("openid","id_token","registration_endpoint","client_id_metadata_document_supported","private_key_jwt","implicit","password")) assertFalse(text.contains(unsupported));
  String disabled=json(metadata(ISSUER,false,false,Set.of(),FRESHNESS,32768,16384,false).metadata("GET",deadline()).body()).toJson();
  assertFalse(disabled.contains("refresh_token"));assertFalse(disabled.contains("revocation_endpoint"));assertFalse(disabled.contains("introspection_endpoint"));
  assertEquals("OAuthIssuerMetadata{<redacted>}",metadata.toString());
 }
 @Test void metadataAndJwksHeadHeadersFiniteCacheAndCopiedBytes() {
  var metadata=metadata(ISSUER,true,true,Set.of("read"),FRESHNESS,32768,16384,false);var life=lifecycle(initial());
  for(boolean jwks:List.of(false,true)) {
   var get=jwks ? metadata.jwks("GET",life,deadline()) : metadata.metadata("GET",deadline());
   var head=jwks ? metadata.jwks("HEAD",life,deadline()) : metadata.metadata("HEAD",deadline());
   assertEquals(0,head.body().length);assertArrayEquals(get.headers(),head.headers());String header=new String(get.headers(),StandardCharsets.US_ASCII);
   assertTrue(header.contains("public, max-age=60, must-revalidate"));assertTrue(header.contains("ETag: \""));assertTrue(header.contains("Content-Length: "+get.body().length));
   byte[] body=get.body();body[0]=0;assertNotEquals(0,get.body()[0]);byte[] headers=get.headers();headers[0]=0;assertNotEquals(0,get.headers()[0]);
   assertEquals("OAuthPublicMetadataResponse{<redacted>}",get.toString());assertFalse(get.toString().contains(ISSUER));
  }
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> metadataFailuresAndMethods() {
  List<DynamicTest> tests=new ArrayList<>();
  for(String issuer:List.of("http://issuer.example","https://user@issuer.example","https://issuer.example/#bad","https://issuer.example/?bad", "urn:issuer", "https://issuer.example:65536"))
   tests.add(test("bad issuer "+issuer,()->assertThrows(IllegalArgumentException.class,()->metadata(issuer,false,false,Set.of(),FRESHNESS,32768,16384,false))));
  for(String issuer:List.of("http://127.0.0.1:8080/tenant","http://[::1]:8080/tenant")) tests.add(test("explicit loopback "+issuer,()->{
   assertThrows(IllegalArgumentException.class,()->metadata(issuer,false,false,Set.of(),FRESHNESS,32768,16384,false));assertNotNull(metadata(issuer,false,false,Set.of(),FRESHNESS,32768,16384,true));}));
  tests.add(test("localhost is not literal development permission",()->assertThrows(IllegalArgumentException.class,()->metadata("http://localhost",false,false,Set.of(),FRESHNESS,32768,16384,true))));
  for(Duration duration:List.of(Duration.ofNanos(-1),Duration.ofMinutes(5).plusNanos(1))) tests.add(test("bad freshness "+duration,()->assertThrows(IllegalArgumentException.class,()->metadata(ISSUER,false,false,Set.of(),duration,32768,16384,false))));
  for(int cap:List.of(4095,131073)) tests.add(test("bad body cap "+cap,()->assertThrows(IllegalArgumentException.class,()->metadata(ISSUER,false,false,Set.of(),FRESHNESS,cap,16384,false))));
  for(int cap:List.of(1023,65537)) tests.add(test("bad header cap "+cap,()->assertThrows(IllegalArgumentException.class,()->metadata(ISSUER,false,false,Set.of(),FRESHNESS,32768,cap,false))));
  for(String method:List.of("POST","OPTIONS","get","GET\r\nprivate")) tests.add(test("unsupported method "+tests.size(),()->{
   var metadata=metadata(ISSUER,false,false,Set.of(),FRESHNESS,32768,16384,false);var bad=lifecycle(budget->{throw new AssertionError("must not call provider");},Clock.fixed(NOW,ZoneOffset.UTC));
   for(var response:List.of(metadata.metadata(method,deadline()),metadata.jwks(method,bad,deadline()))) {
    assertEquals(0,response.body().length);String h=new String(response.headers(),StandardCharsets.US_ASCII);assertTrue(h.contains("405 Method Not Allowed"));assertTrue(h.contains("Allow: GET, HEAD"));assertTrue(h.contains("Cache-Control: no-store"));assertFalse(h.contains("private"));
   }
  }));
  tests.add(test("zero freshness revalidates",()->assertTrue(new String(metadata(ISSUER,false,false,Set.of(),Duration.ZERO,32768,16384,false).metadata("GET",deadline()).headers(),StandardCharsets.US_ASCII).contains("max-age=0, must-revalidate"))));
  tests.add(test("metadata body overflow",()->{Set<String> scopes=new java.util.HashSet<>();for(int i=0;i<64;i++)scopes.add("a".repeat(100)+i);
   var metadata=metadata(ISSUER,false,false,scopes,FRESHNESS,4096,16384,false);assertThrows(IllegalArgumentException.class,()->metadata.metadata("GET",deadline()));}));
  tests.add(test("metadata expired budget",()->unavailable(()->metadata(ISSUER,false,false,Set.of(),FRESHNESS,32768,16384,false).metadata("GET",Deadline.fromNow(Duration.ZERO)))));
  return tests.stream();
 }

 @Test void publicProjectionReportsOnlyStableRsaFacts() {
  PublicKey projection=initial().getVerificationKeys().get("a");assertNotNull(projection);
  assertEquals("RSA",projection.getAlgorithm());assertNull(projection.getFormat());assertNull(projection.getEncoded());assertNull(((RSAPublicKey)projection).getParams());
  var extra=snapshot(key("a",A),"g",NOW,Map.of("b",B.getPublicKey()),Map.of());PublicKey b=requireNonNull(extra.getVerificationKeys().get("b"));
  assertEquals("RSA",b.getAlgorithm());assertNull(b.getFormat());assertNull(b.getEncoded());assertNull(((RSAPublicKey)b).getParams());assertEquals("OAuthIssuerPublicKey{<redacted>}",b.toString());
 }
 @Test void declaredRetirementMayBeDelayedOrCancelledButCannotUndercutReservedExpiry() {
  var a=snapshot(key("a",A),"g1",NOW.minusSeconds(120),Map.of(),Map.of());var current=new AtomicReference<>(a);
  var life=lifecycle(budget->requireNonNull(current.get()),Clock.fixed(NOW,ZoneOffset.UTC));assertNotNull(life.sign(claims(),NOW.plusSeconds(300),deadline()));
  current.set(snapshot(key("a",A),"g2",NOW.minusSeconds(110),Map.of(),Map.of("a",NOW.plusSeconds(399))));unavailable(()->life.snapshot(deadline()));
  current.set(snapshot(key("a",A),"g2",NOW.minusSeconds(110),Map.of(),Map.of("a",NOW.plusSeconds(400))));assertNotNull(life.snapshot(deadline()));
  current.set(snapshot(key("a",A),"g3",NOW.minusSeconds(100),Map.of(),Map.of("a",NOW.plusSeconds(500))));assertNotNull(life.snapshot(deadline()));
  current.set(snapshot(key("a",A),"g4",NOW.minusSeconds(90),Map.of(),Map.of()));assertNotNull(life.snapshot(deadline()));
 }
 @Test void jwksOverflowUsesActualBoundedResponseWithoutPrivateMaterial() {
  Map<String,PublicKey> keys=new LinkedHashMap<>();for(int i=0;i<20;i++)keys.put("old"+i,A.getPublicKey());
  var life=lifecycle(snapshot(key("a",A),"g",NOW.minusSeconds(120),keys,Map.of()));
  var metadata=metadata(ISSUER,false,false,Set.of(),FRESHNESS,4096,16384,false);
  assertThrows(IllegalArgumentException.class,()->metadata.jwks("GET",life,deadline()));
 }
 @Test void scopeAdvertisementIncludesUnionAcrossResources() {
  Set<String> scopes=new java.util.HashSet<>();for(int i=0;i<128;i++)scopes.add("scope"+i);
  assertTrue(new String(metadata(ISSUER,false,false,scopes,FRESHNESS,32768,16384,false).metadata("GET",deadline()).body(),StandardCharsets.UTF_8).contains("scope127"));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> responseAndEncoderBounds() {
  List<DynamicTest> tests=new ArrayList<>();var life=lifecycle(initial());
  for(int body:List.of(4095,131073)) {
   tests.add(test("direct response body cap "+body,()->assertThrows(IllegalArgumentException.class,()->OAuthPublicMetadataResponse.prepare(JsonObject.builder().build(),"GET",FRESHNESS,body,16384))));
   tests.add(test("managed encoder body cap "+body,()->assertThrows(IllegalArgumentException.class,()->new OAuthTokenResponse.Encoder(ISSUER,life,body,16384))));
  }
  for(int header:List.of(1023,65537)) {
   tests.add(test("direct response header cap "+header,()->assertThrows(IllegalArgumentException.class,()->OAuthPublicMetadataResponse.prepare(JsonObject.builder().build(),"GET",FRESHNESS,32768,header))));
   tests.add(test("managed encoder header cap "+header,()->assertThrows(IllegalArgumentException.class,()->new OAuthTokenResponse.Encoder(ISSUER,life,32768,header))));
  }
  return tests.stream();
 }

 @Test void punctuationInKeyIdsCannotFlattenLifecycleDeclarations() {
  Instant aBoundary=NOW.plusSeconds(500),bBoundary=NOW.plusSeconds(600);String id="a="+aBoundary+", b";
  Map<String,PublicKey> keys=Map.of(id,B.getPublicKey(),"b",B.getPublicKey());
  var first=snapshot(key("a",A),"g1",NOW.minusSeconds(120),keys,Map.of("a",aBoundary,"b",bBoundary));
  var changed=snapshot(key("a",A),"g1",NOW.minusSeconds(120),keys,Map.of(id,bBoundary));
  assertEquals(first.getRetirementNotBefore().entrySet().stream().sorted(Map.Entry.comparingByKey()).toList().toString(),
   changed.getRetirementNotBefore().entrySet().stream().sorted(Map.Entry.comparingByKey()).toList().toString());
  var ref=new AtomicReference<>(first);var life=lifecycle(budget->requireNonNull(ref.get()),Clock.fixed(NOW,ZoneOffset.UTC));assertNotNull(life.snapshot(deadline()));
  ref.set(changed);unavailable(()->life.snapshot(deadline()));
 }
 private static final class OpaquePrivate implements PrivateKey {
  private static final long serialVersionUID=1L;private int encodings;
  @Override public @NonNull String getAlgorithm() { return "RSA"; }
  @Override public @Nullable String getFormat() { return null; }
  @Override public byte @Nullable [] getEncoded() { this.encodings++;throw new AssertionError("must not encode"); }
 }
 private static final class SuppliedKey implements RSAPublicKey {
  private static final long serialVersionUID=1L;
  private @NonNull BigInteger n,e;private final @NonNull String algorithm;private final transient @Nullable AlgorithmParameterSpec parameters;
  private SuppliedKey(@NonNull BigInteger n,@NonNull BigInteger e,@NonNull String algorithm,@Nullable AlgorithmParameterSpec parameters) {this.n=n;this.e=e;this.algorithm=algorithm;this.parameters=parameters;}
  @Override public @NonNull BigInteger getModulus(){return this.n;}
  @Override public @NonNull BigInteger getPublicExponent(){return this.e;}
  @Override public @NonNull String getAlgorithm(){return this.algorithm;}
  @Override public @Nullable AlgorithmParameterSpec getParams(){return this.parameters;}
  @Override public @Nullable String getFormat(){return null;}
  @Override public byte @Nullable [] getEncoded(){throw new AssertionError("must not encode");}
 }
 private static final class MutableClock extends Clock {
  private @NonNull Instant now;private MutableClock(@NonNull Instant now){this.now=now;}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){requireNonNull(zone);return this;}
  @Override public @NonNull Instant instant(){return this.now;}
 }
}
