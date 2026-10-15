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

import com.revetsec.internal.http.Deadline;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.json.JsonString;
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Preparation, pending-record bounds and cleanup under controlled application callbacks. */
@ResourceLock("java.security.Security")
final class OAuthRc1AssertionMutationTests {
 private static final @NonNull String ISSUER = "https://issuer.example";
 private static final @NonNull Instant NOW = Instant.parse("2026-10-14T12:00:00Z");
 private static final @NonNull Duration BUDGET = Duration.ofSeconds(30);

 @Test void conservativeStringLengthMatchesIndependentJsonEscaping() throws Exception {
  for (String value : List.of("", "plain", "\u0000\u001f", "\"", "\\", "\b\f\n\r\t", " ", "\u007f", "\u0080",
    "\u07ff", "\u0800", "\ud7ff", "\ue000", "😀", "xé€😀y")) {
   long expected = JsonString.fromValue(value).toJson().getBytes(StandardCharsets.UTF_8).length;
   // Preparation deliberately reserves six bytes even for controls having two-byte JSON short escapes.
   for (int index = 0; index < value.length(); index++) if ("\b\f\n\r\t".indexOf(value.charAt(index)) >= 0) expected += 4;
   assertEquals(expected, stringLength(value));
  }
 }

 @Test void stringLengthAllowsItsExactCharacterCap() throws Exception {
  assertEquals(32770L, stringLength("a".repeat(32768)));
  assertEquals(OAuthException.Reason.CLIENT_ASSERTION_SIGNING_FAILED,
    assertThrows(OAuthConfigurationException.class, () -> stringLength("a".repeat(32769))).getReason());
 }

 @Test void readinessChecksTheOriginalDeadlineBeforeTheClock() {
  var prepared = new ClientAssertionPreparation.Prepared("opaque", NOW, NOW.plusSeconds(60));
  CountingClock clock = new CountingClock(NOW);
  OAuthTransportException failure = assertThrows(OAuthTransportException.class,
    () -> ClientAssertionPreparation.checkReady(prepared, clock, Deadline.fromNow(Duration.ZERO)));
  assertEquals(OAuthException.Reason.NETWORK_FAILURE, failure.getReason()); assertEquals(0, clock.calls);
 }

 @Test void exhaustedPreparationWinsOverAnInvalidEndpoint() {
  AtomicInteger providers = new AtomicInteger();
  ClientAuthentication authentication = authentication(() -> { providers.incrementAndGet(); return key(); });
  var target = new ResourceServerMetadata(ISSUER, URI.create("https://other.example/token"), Set.of("private_key_jwt"));
  OAuthTransportException failure = assertThrows(OAuthTransportException.class, () -> ClientAssertionPreparation.prepare(authentication,
    "client", target, OAuthEndpoint.TOKEN, settings(new CountingClock(NOW)), new CapturingRandom(), Deadline.fromNow(Duration.ZERO)));
  assertEquals(OAuthException.Reason.NETWORK_FAILURE, failure.getReason()); assertEquals(0, providers.get());
 }

 @Test void exhaustedKeyProviderWinsOverAnExcludedAlgorithm() {
  Deadline deadline = Deadline.fromNow(BUDGET);
  ClientAuthentication authentication = authentication(() -> { expire(deadline); return key(); });
  var target = new ResourceServerMetadata(ISSUER, URI.create(ISSUER + "/token"), Set.of("private_key_jwt"), Set.of("RS384"), null);
  OAuthTransportException failure = assertThrows(OAuthTransportException.class, () -> ClientAssertionPreparation.prepare(authentication,
    "client", target, OAuthEndpoint.TOKEN, settings(new CountingClock(NOW)), new CapturingRandom(), deadline));
  assertEquals(OAuthException.Reason.NETWORK_FAILURE, failure.getReason());
 }

 @Test void nonceCancellationPreventsPrivateKeyUse() {
  CountingPrivateKey privateKey = new CountingPrivateKey();
  ClientAssertionSigningKey key = key(privateKey);
  CapturingRandom random = new CapturingRandom(); random.afterFill = () -> Thread.currentThread().interrupt();
  try {
   OAuthTransportException failure = assertThrows(OAuthTransportException.class, () -> prepare(authentication(() -> key), "client", NOW, random));
   assertEquals(OAuthException.Reason.INTERRUPTED, failure.getReason()); assertEquals(0, privateKey.reads);
   assertZero(requireNonNull(random.last));
  } finally { Thread.interrupted(); }
 }

 @Test void signingFailureRetainsCallerInterruptionPrecedence() {
  CountingPrivateKey privateKey = new CountingPrivateKey();
  privateKey.onModulus = () -> { Thread.currentThread().interrupt(); throw new IllegalStateException("private key detail"); };
  ClientAssertionSigningKey key = key(privateKey);
  try {
   OAuthTransportException failure = assertThrows(OAuthTransportException.class,
     () -> prepare(authentication(() -> key), "client", NOW, new CapturingRandom()));
   assertEquals(OAuthException.Reason.INTERRUPTED, failure.getReason()); assertTrue(privateKey.reads > 0);
  } finally { Thread.interrupted(); }
 }

 @Test void earliestSupportedIssuedSecondIsAccepted() {
  Instant first = Instant.ofEpochSecond(-377705116800L);
  assertEquals(first, prepare(authentication(OAuthRc1AssertionMutationTests::key), "client", first, new CapturingRandom()).issued());
 }

 @Test void expiryAtTheUnsupportedUpperBoundaryIsRejected() {
  CapturingRandom random = new CapturingRandom();
  OAuthConfigurationException failure = assertThrows(OAuthConfigurationException.class,
    () -> prepare(authentication(OAuthRc1AssertionMutationTests::key), "client", Instant.ofEpochSecond(253402300800L - 60), random));
  assertEquals(OAuthException.Reason.CLIENT_ASSERTION_SIGNING_FAILED, failure.getReason()); assertEquals(0, random.calls);
 }

 @Test void exactConservativeClaimsAllowanceIsAccepted() {
  // 2*(16242+2) + (22+2) + 256 == 32768.
  var prepared = prepare(authentication(OAuthRc1AssertionMutationTests::key), "a".repeat(16242), NOW, new CapturingRandom());
  assertNotNull(prepared); assertEquals(NOW, prepared.issued());
 }

 @Test void excessConservativeClaimsAreRejectedBeforeRandomness() {
  CapturingRandom random = new CapturingRandom();
  OAuthConfigurationException failure = assertThrows(OAuthConfigurationException.class,
    () -> prepare(authentication(OAuthRc1AssertionMutationTests::key), "a".repeat(16243), NOW, random));
  assertEquals(OAuthException.Reason.CLIENT_ASSERTION_SIGNING_FAILED, failure.getReason()); assertEquals(0, random.calls);
 }

 @Test void successfulPreparationZeroesTheRandomNonceArray() {
  CapturingRandom random = new CapturingRandom();
  var prepared = prepare(authentication(OAuthRc1AssertionMutationTests::key), "client", NOW, random);
  assertTrue(prepared.value().contains(".")); assertEquals(1, random.calls); assertZero(requireNonNull(random.last));
 }

 @Test void failedPreparationZeroesTheRandomNonceArray() {
  CapturingRandom random = new CapturingRandom(); random.afterFill = () -> { throw new IllegalStateException("private random detail"); };
  assertThrows(OAuthConfigurationException.class, () -> prepare(authentication(OAuthRc1AssertionMutationTests::key), "client", NOW, random));
  assertEquals(1, random.calls); assertZero(requireNonNull(random.last));
 }

 @Test void pendingRecordAtItsExactByteCapRoundTrips() {
  String empty = PendingAuthorizationCodec.encode(pending(false, NOW.plusSeconds(3600), ""), null);
  String payload = "a".repeat(65536 - empty.getBytes(StandardCharsets.UTF_8).length);
  String encoded = PendingAuthorizationCodec.encode(pending(false, NOW.plusSeconds(3600), payload), null);
  assertEquals(65536, encoded.getBytes(StandardCharsets.UTF_8).length);
  var decoded = PendingAuthorizationCodec.decode(encoded).pending();
  assertEquals(payload, decoded.getApplicationData().get("payload")); assertEquals(NOW.plusSeconds(3600), decoded.getExpiresAt());
 }

 @Test void oidcAcrRejectsTheDelBoundaryAndAllowsVisibleAscii() {
  String encoded = PendingAuthorizationCodec.encode(pending(true, NOW.plusSeconds(60), ""), null);
  for (String acr : List.of("has space", "\u007f")) {
   String changed = encoded.replace("\"!~\"", JsonString.fromValue(acr).toJson());
   assertNotEquals(encoded, changed);
   assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID,
     assertThrows(OAuthValidationException.class, () -> PendingAuthorizationCodec.decode(changed)).getReason());
  }
  assertEquals(Set.of("!~"), PendingAuthorizationCodec.decode(encoded).pending().acrValues());
 }

 @Test void bindingDigestMatchesSha256AndZeroesProviderAliases() throws Exception {
  Provider original = requireNonNull(Security.getProvider("SUN"));
  byte[] expected = MessageDigest.getInstance("SHA-256", original).digest("browser".getBytes(StandardCharsets.UTF_8));
  DigestState state = new DigestState(original);
  String name = "RevetsecRc1BindingDigestProbe";
  Provider provider = new Provider(name, "1", "Scoped binding-digest fixture") {
   private static final long serialVersionUID = 1L;
   { putService(new Service(this, "MessageDigest", "SHA-256", DigestEngine.class.getName(), List.of(), null) {
    @Override public @NonNull Object newInstance(@Nullable Object ignored) throws java.security.NoSuchAlgorithmException { return new DigestEngine(state); }
   }); }
  };
  assertNull(Security.getProvider(name)); assertEquals(1, Security.insertProviderAt(provider, 1));
  try {
   assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(expected), PendingAuthorizationCodec.bindingDigest("browser"));
   assertZero(requireNonNull(state.input)); assertZero(requireNonNull(state.digest));
  } finally { Security.removeProvider(name); }
 }

 @Test void bearerDiagnosticKeepsItsRedactedDescription() {
  BearerToken token = assertInstanceOf(BearerTokenResult.Present.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer fixture-secret"))).getToken();
  assertEquals("BearerToken{value=<redacted>}", token.toString());
 }

 @Test void assertionKeyIdentifierAllowsItsExactCharacterCap() {
  JwsSigner signer = JwsSigner.fromRsaKeyPair(TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey(),
    TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPublicKey(), JwsAlgorithm.PS256);
  String identifier = "é".repeat(256);
  assertEquals(identifier, ClientAssertionSigningKey.withSigner(signer).keyId(identifier).build().getKeyId().orElseThrow());
 }

 @Test void assertionKeyBuilderKeepsItsRedactedDescription() {
  JwsSigner signer = JwsSigner.fromRsaKeyPair(TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey(),
    TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPublicKey(), JwsAlgorithm.PS256);
  assertEquals("ClientAssertionSigningKey.Builder{key=<redacted>}", ClientAssertionSigningKey.withSigner(signer).keyId("private-marker").toString());
 }

 @Test void clientCredentialsDiscoveryFailureReportsItsAssertionRoleAndIdentity() throws Exception {
  try (TestHttpsServer server = TestHttpsServer.start()) {
   AssertionFailureObserver observer = new AssertionFailureObserver(); AtomicInteger providers = new AtomicInteger();
   OAuthClient client = failingDiscoveryClient(server, observer, providers);
   OAuthException failure = assertThrows(OAuthException.class,
     () -> client.requestClientCredentialsResult(TokenRequestOptions.builder().build()));
   observer.check(OAuthEndpoint.TOKEN, failure); assertEquals(0, providers.get()); assertDiscoveryRequested(server);
  }
 }

 @Test void callbackDiscoveryFailureReportsItsAssertionRoleAndIdentity() throws Exception {
  try (TestHttpsServer server = TestHttpsServer.start()) {
   AssertionFailureObserver observer = new AssertionFailureObserver(); AtomicInteger providers = new AtomicInteger();
   OAuthClient client = failingDiscoveryClient(server, observer, providers);
   URI callback = URI.create("https://app.example/callback");
   PendingAuthorization pending = new PendingAuthorization("oauth", server.uri("/tenant").toString(), "client", callback,
     "state", "verifier", null, Set.of(), List.of(), AuthorizationRequestOptions.ResponseMode.QUERY,
     NOW, NOW.plusSeconds(60), Map.of(), false, server.uri("/authorize"), server.uri("/token"));
   InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
   org.junit.jupiter.api.Assertions.assertEquals(PendingAuthorizationSaveResult.SAVED, pending.saveToResult(store, "browser"));
   OAuthException failure = assertThrows(OAuthException.class, () -> client.completeAuthorizationResult(
     assertInstanceOf(AuthorizationResponseParseResult.Succeeded.class, AuthorizationResponse.fromQueryStringResult("code=fixture-code&state=state")).getResponse(), PendingAuthorizationSource.fromStore(store, "browser"), callback));
   observer.check(OAuthEndpoint.TOKEN, failure); assertEquals(0, providers.get()); assertDiscoveryRequested(server);
  }
 }

 @Test void introspectionDiscoveryFailureReportsItsAssertionRoleAndIdentity() throws Exception {
  try (TestHttpsServer server = TestHttpsServer.start()) {
   AssertionFailureObserver observer = new AssertionFailureObserver(); AtomicInteger providers = new AtomicInteger();
   OAuthClient client = failingDiscoveryClient(server, observer, providers);
   TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of("api")).observer(observer).build();
   BearerToken token = assertInstanceOf(BearerTokenResult.Present.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer fixture-token"))).getToken();
   OAuthException failure = assertThrows(OAuthException.class, () -> introspection.validateResult(token));
   observer.check(OAuthEndpoint.INTROSPECTION, failure); assertEquals(0, providers.get()); assertDiscoveryRequested(server);
  }
 }

 @Test void healthyIntrospectionProbeReleasesTheNextIndependentCaller() throws Exception {
  try (TestHttpsServer server = TestHttpsServer.start()) {
   TokenIntrospectionClient client = probingIntrospection(server, ClientAuthentication.fromClientSecretPost("fixture-secret"));
   server.script("/introspect", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromStatus(503)));
   assertThrows(OAuthException.class, () -> client.validateResult(probeToken())); assertEquals(1, server.getHitCount("/introspect"));
   ageIntrospectionFailure(client);
   server.script("/introspect", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, "{\"active\":true,\"aud\":\"api\"}")));
   assertNotNull(assertInstanceOf(AccessTokenValidationResult.Succeeded.class, client.validateResult(probeToken())).getAccessToken());
   assertNotNull(validateOnIndependentCaller(client)); assertEquals(3, server.getHitCount("/introspect"));
  }
 }

 @Test void abandonedIntrospectionProbeReleasesTheNextIndependentCaller() throws Exception {
  try (TestHttpsServer server = TestHttpsServer.start()) {
   AtomicInteger secrets = new AtomicInteger();
   TokenIntrospectionClient client = probingIntrospection(server, ClientAuthentication.fromClientSecretPost(() -> {
    if (secrets.incrementAndGet() == 2) throw new IllegalStateException("fixture supplier interruption"); return "fixture-secret";
   }));
   server.script("/introspect", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromStatus(503)));
   assertThrows(OAuthException.class, () -> client.validateResult(probeToken())); assertEquals(1, server.getHitCount("/introspect"));
   ageIntrospectionFailure(client);
   assertThrows(IllegalArgumentException.class, () -> client.validateResult(probeToken()));
   assertEquals(2, secrets.get()); assertEquals(1, server.getHitCount("/introspect"));
   server.script("/introspect", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, "{\"active\":true,\"aud\":\"api\"}")));
   assertNotNull(validateOnIndependentCaller(client)); assertEquals(3, secrets.get()); assertEquals(2, server.getHitCount("/introspect"));
  }
 }

 private static @NonNull TokenIntrospectionClient probingIntrospection(@NonNull TestHttpsServer server, @NonNull ClientAuthentication authentication) {
  OAuthClient client = OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer(server.uri("/tenant").toString())
    .authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).introspectionEndpoint(server.uri("/introspect"))
    .introspectionEndpointAuthMethodsSupported(Set.of("client_secret_post")).build())
    .clientId("client").clientAuthentication(authentication).httpClient(TestTls.httpClient()).clock(Clock.fixed(NOW, ZoneOffset.UTC))
    .requestTimeout(Duration.ofSeconds(5)).totalDeadline(Duration.ofSeconds(10)).build();
  return TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of("api")).build();
 }
 private static void ageIntrospectionFailure(@NonNull TokenIntrospectionClient client) throws Exception {
  var guardField = TokenIntrospectionClient.class.getDeclaredField("guard"); guardField.setAccessible(true);
  Object guard = requireNonNull(guardField.get(client));
  var failure = guard.getClass().getDeclaredField("failure"); failure.setAccessible(true); assertNotNull(failure.get(guard));
  // Only simulate 31 elapsed seconds after the real 503; keep the actual attempt, failure and probe state.
  var timestamp = guard.getClass().getDeclaredField("failedAtNanos"); timestamp.setAccessible(true);
  timestamp.setLong(guard, System.nanoTime() - Duration.ofSeconds(31).toNanos());
 }
 private static @NonNull BearerToken probeToken() { return assertInstanceOf(BearerTokenResult.Present.class, BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer fixture-token"))).getToken(); }
 private static @NonNull VerifiedAccessToken validateOnIndependentCaller(@NonNull TokenIntrospectionClient client) {
  FutureTask<VerifiedAccessToken> future = new FutureTask<>(() -> assertInstanceOf(AccessTokenValidationResult.Succeeded.class, client.validateResult(probeToken())).getAccessToken());
  Thread thread = new Thread(future, "rc1-introspection-independent-caller"); thread.setDaemon(true); thread.start();
  try { return assertDoesNotThrow(() -> future.get(2, TimeUnit.SECONDS)); }
  finally { future.cancel(true); }
 }

 private static @NonNull OAuthClient failingDiscoveryClient(@NonNull TestHttpsServer server,
   @NonNull AssertionFailureObserver observer, @NonNull AtomicInteger providers) {
  for (URI candidate : AuthorizationServerCache.candidates(server.uri("/tenant")))
   server.script(candidate.getPath(), TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromStatus(500)));
  return OAuthClient.withIssuer(server.uri("/tenant").toString()).clientId("client")
    .clientAuthentication(authentication(() -> { providers.incrementAndGet(); return key(); }))
    .httpClient(TestTls.httpClient()).clock(Clock.fixed(NOW, ZoneOffset.UTC)).observer(observer).build();
 }
 private static void assertDiscoveryRequested(@NonNull TestHttpsServer server) {
  assertTrue(AuthorizationServerCache.candidates(server.uri("/tenant")).stream().mapToInt(uri -> server.getHitCount(uri.getPath())).sum() > 0);
  assertEquals(0, server.getHitCount("/token")); assertEquals(0, server.getHitCount("/introspect"));
 }
 private static final class AssertionFailureObserver implements AccessTokenObserver {
  private final @NonNull AtomicInteger calls = new AtomicInteger();
  private final @NonNull AtomicReference<OAuthEndpoint> role = new AtomicReference<>();
  private final @NonNull AtomicReference<OAuthException> failure = new AtomicReference<>();
  @Override public void didFailClientAssertionPreparation(@NonNull OAuthEndpoint endpoint, @NonNull OAuthException exception) {
   this.calls.incrementAndGet(); this.role.set(endpoint); this.failure.set(exception);
  }
  private void check(@NonNull OAuthEndpoint expectedRole, @NonNull OAuthException expectedFailure) {
   assertEquals(1, this.calls.get()); assertEquals(expectedRole, this.role.get()); assertSame(expectedFailure, this.failure.get());
  }
 }

 private static ClientAssertionPreparation.@NonNull Prepared prepare(@NonNull ClientAuthentication authentication,
   @NonNull String clientId, @NonNull Instant now, @NonNull CapturingRandom random) {
  return ClientAssertionPreparation.prepare(authentication, clientId,
    new ResourceServerMetadata(ISSUER, URI.create(ISSUER + "/token"), Set.of("private_key_jwt")), OAuthEndpoint.TOKEN,
    settings(new CountingClock(now)), random, Deadline.fromNow(BUDGET));
 }
 private static OAuthClient.@NonNull ResourceSettings settings(@NonNull Clock clock) {
  return OAuthClient.withIssuer(ISSUER).clientId("fixture").clientAuthentication(ClientAuthentication.noneInstance()).clock(clock).build().resourceSettings();
 }
 private static @NonNull ClientAuthentication authentication(@NonNull KeySource source) {
  return ClientAuthentication.fromPrivateKeyJwt(budget -> source.get());
 }
 private static @NonNull ClientAssertionSigningKey key() { return key(TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()); }
 private static @NonNull ClientAssertionSigningKey key(@NonNull PrivateKey privateKey) {
  return ClientAssertionSigningKey.withSigner(JwsSigner.fromRsaKeyPair(privateKey,
    TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPublicKey(), JwsAlgorithm.PS256)).keyId("fixture").build();
 }
 private static long stringLength(@NonNull String value) throws Exception {
  var method = ClientAssertionPreparation.class.getDeclaredMethod("jsonStringLength", String.class); method.setAccessible(true);
  try { return (long) requireNonNull(method.invoke(null, value)); }
  catch (InvocationTargetException failure) {
   if (failure.getCause() instanceof Exception cause) throw cause;
   if (failure.getCause() instanceof Error cause) throw cause;
   throw failure;
  }
 }
 private static void expire(@NonNull Deadline deadline) {
  try { var field = Deadline.class.getDeclaredField("totalNanos"); field.setAccessible(true); field.setLong(deadline, 0L); }
  catch (ReflectiveOperationException failure) { throw new AssertionError(failure); }
 }
 private static void assertZero(byte @NonNull [] bytes) { assertArrayEquals(new byte[bytes.length], bytes); }
 private static @NonNull PendingAuthorization pending(boolean oidc, @NonNull Instant expires, @NonNull String payload) {
  return new PendingAuthorization(oidc ? "oidc" : "oauth", ISSUER, "client", URI.create("https://app.example/callback"), "state", "verifier",
    oidc ? "nonce" : null, Set.of("openid"), List.of(), AuthorizationRequestOptions.ResponseMode.QUERY, NOW, expires,
    Map.of("payload", payload), true, URI.create(ISSUER + "/authorize"), URI.create(ISSUER + "/token"),
    null, oidc ? Set.of("!~") : Set.of(), null);
 }
 @FunctionalInterface private interface KeySource { @NonNull ClientAssertionSigningKey get(); }

 private static final class CapturingRandom extends SecureRandom {
  private static final long serialVersionUID = 1L;
  private transient byte @Nullable [] last;
  private int calls;
  private transient @NonNull Runnable afterFill = () -> {};
  @Override public void nextBytes(byte @NonNull [] bytes) { this.calls++; this.last = bytes; Arrays.fill(bytes, (byte)0x5a); this.afterFill.run(); }
 }
 private static final class CountingClock extends Clock {
  private final @NonNull Instant now;
  private int calls;
  private CountingClock(@NonNull Instant now) { this.now = now; }
  @Override public @NonNull Instant instant() { this.calls++; return this.now; }
  @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
 }
 private static final class CountingPrivateKey implements RSAPrivateCrtKey {
  private static final long serialVersionUID = 1L;
  private final @NonNull RSAPrivateCrtKey delegate = (RSAPrivateCrtKey) TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey();
  private int reads;
  private transient @NonNull Runnable onModulus = () -> {};
  @Override public @NonNull BigInteger getModulus() { this.reads++; this.onModulus.run(); return this.delegate.getModulus(); }
  @Override public @NonNull BigInteger getPrivateExponent() { this.reads++; return this.delegate.getPrivateExponent(); }
  @Override public @NonNull BigInteger getPublicExponent() { this.reads++; return this.delegate.getPublicExponent(); }
  @Override public @NonNull BigInteger getPrimeP() { this.reads++; return this.delegate.getPrimeP(); }
  @Override public @NonNull BigInteger getPrimeQ() { this.reads++; return this.delegate.getPrimeQ(); }
  @Override public @NonNull BigInteger getPrimeExponentP() { this.reads++; return this.delegate.getPrimeExponentP(); }
  @Override public @NonNull BigInteger getPrimeExponentQ() { this.reads++; return this.delegate.getPrimeExponentQ(); }
  @Override public @NonNull BigInteger getCrtCoefficient() { this.reads++; return this.delegate.getCrtCoefficient(); }
  @Override public @NonNull String getAlgorithm() { return "RSA"; }
  @Override public @Nullable String getFormat() { return null; }
  @Override public byte @Nullable [] getEncoded() { return null; }
 }
 private static final class DigestState {
  private final @NonNull Provider original;
  private final @NonNull Thread owner = Thread.currentThread();
  private byte @Nullable [] input, digest;
  private DigestState(@NonNull Provider original) { this.original = original; }
 }
 private static final class DigestEngine extends MessageDigestSpi {
  private final @NonNull DigestState state;
  private final @NonNull MessageDigest delegate;
  private DigestEngine(@NonNull DigestState state) throws java.security.NoSuchAlgorithmException { this.state = state; this.delegate = MessageDigest.getInstance("SHA-256", state.original); }
  @Override protected void engineUpdate(byte value) { this.delegate.update(value); }
  @Override protected void engineUpdate(byte @NonNull [] bytes, int offset, int length) { if (Thread.currentThread().equals(this.state.owner)) this.state.input = bytes; this.delegate.update(bytes, offset, length); }
  @Override protected byte @NonNull [] engineDigest() { byte[] digest = this.delegate.digest(); if (Thread.currentThread().equals(this.state.owner)) this.state.digest = digest; return digest; }
  @Override protected int engineGetDigestLength() { return 32; }
  @Override protected void engineReset() { this.delegate.reset(); }
 }
}
