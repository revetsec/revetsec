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

package com.revetsec.jose;

import com.revetsec.internal.http.Deadline;
import com.revetsec.json.JsonString;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Pure sizing oracles and scoped provider aliases exercise the production class loaded by PIT. */
@ResourceLock("java.security.Security")
final class JwsSignerRc1MutationTests {
 private static final @NonNull String PROVIDER_NAME = "RevetsecRc1SignerProbe";
 private static final @NonNull Duration BUDGET = Duration.ofSeconds(30);

 @Test void encodedLengthMatchesRealBase64UrlEncoding() throws Exception {
  for (int length : new int[]{0, 1, 2, 3, 4, 5, 6, 7, 31, 32, 255, 256, 2048, 32768}) {
   int actual = Base64.getUrlEncoder().withoutPadding().encode(new byte[length]).length;
   assertEquals((long) actual, call(null, "encodedLength", (long) length));
  }
 }

 @Test void jsonStringByteCountMatchesRealJsonSerialization() throws Exception {
  for (String value : List.of("", "plain", "\"\\\b\f\n\r\t", "\u0000\u0001\u001f", " ", "\u007f", "\u0080",
    "\u07ff", "\u0800", "\ud7ff", "\ue000", "😀", "xé€😀y")) {
   int actual = JsonString.fromValue(value).toJson().getBytes(StandardCharsets.UTF_8).length;
   assertEquals(actual, call(null, "jsonStringBytes", value));
  }
 }

 @Test void positiveOneBitIntegerCanBeSnapshottedBeforeRsaPolicy() throws Exception {
  assertEquals(BigInteger.ONE, call(null, "snapshotInteger", BigInteger.ONE, 32, 5));
 }

 @Test void arrayClearOverwritesTheSuppliedArrayAndAcceptsNull() throws Exception {
  byte[] bytes = {1, 2, 3}; call(null, "clear", bytes); assertZero(bytes);
  call(null, "clear", (Object) null);
 }

 @Test void exhaustedBudgetPrecedesMalformedClaimsParsing() {
  assertBudget(() -> {
   String compact = signer().toCompactSerialization("JWT", null, null,
     "{".getBytes(StandardCharsets.UTF_8), Duration.ofNanos(1));
   fail("An exhausted signing budget returned " + compact.length() + " compact characters.");
  });
 }

 @Test void expiredSignAndVerifyNeverInitializesAProvider() throws Exception {
  withProvider(state -> {
   JwsSigner signer = signer();
   assertBudget(() -> signAndVerify(signer, new byte[]{1}, Deadline.fromNow(Duration.ZERO)));
   assertEquals(0, state.signInitializations);
  });
 }

 @Test void expirationDuringInitializationPreventsParameterWork() throws Exception {
  withProvider(state -> {
   Deadline deadline = Deadline.fromNow(BUDGET); state.afterInit = () -> expire(deadline);
   assertBudget(() -> signAndVerify(signer(), new byte[]{1}, deadline));
   assertEquals(0, state.signParameters);
  });
 }

 @Test void expirationDuringParameterSetupPreventsInputUpdate() throws Exception {
  withProvider(state -> {
   Deadline deadline = Deadline.fromNow(BUDGET); state.afterParameter = () -> expire(deadline);
   assertBudget(() -> signAndVerify(signer(), new byte[]{1}, deadline));
   assertEquals(0, state.signUpdates);
  });
 }

 @Test void expirationDuringInputUpdatePreventsSigning() throws Exception {
  withProvider(state -> {
   Deadline deadline = Deadline.fromNow(BUDGET); state.afterUpdate = () -> expire(deadline);
   assertBudget(() -> signAndVerify(signer(), new byte[]{1}, deadline));
   assertEquals(0, state.signCalls);
  });
 }

 @Test void expirationDuringSigningPreventsVerificationAndClearsOutput() throws Exception {
  withProvider(state -> {
   Deadline deadline = Deadline.fromNow(BUDGET); state.afterSign = () -> expire(deadline);
   assertBudget(() -> signAndVerify(signer(), new byte[]{1}, deadline));
   assertEquals(0, state.verifyCalls);
   assertZero(requireNonNull(state.signature));
  });
 }

 @Test void expirationDuringVerificationDiscardsAndClearsTheSignature() throws Exception {
  withProvider(state -> {
   Deadline deadline = Deadline.fromNow(BUDGET); state.afterVerify = () -> expire(deadline);
   assertBudget(() -> signAndVerify(signer(), new byte[]{1}, deadline));
   assertEquals(1, state.verifyCalls);
   assertZero(requireNonNull(state.signature));
  });
 }

 @Test void expiredProviderFailureKeepsBudgetPrecedence() throws Exception {
  withProvider(state -> {
   Deadline deadline = Deadline.fromNow(BUDGET);
   state.afterUpdate = () -> { expire(deadline); throw new IllegalStateException("private provider detail"); };
   assertBudget(() -> signAndVerify(signer(), new byte[]{1}, deadline));
  });
 }

 @Test void failedPairVerificationClearsTheProviderSignature() throws Exception {
  withProvider(state -> {
   state.mismatch = true;
   JwsSigningException failure = assertThrows(JwsSigningException.class,
     () -> signAndVerify(signer(), new byte[]{1}, Deadline.fromNow(BUDGET)));
   assertEquals(JwsSigningException.Reason.KEY_PAIR_MISMATCH, failure.getReason());
   assertZero(requireNonNull(state.signature));
  });
 }

 @Test void successfulCompactEmissionClearsRetainedProviderArrays() throws Exception {
  withProvider(state -> {
   byte[] claims = "{\"claim\":\"value\"}".getBytes(StandardCharsets.UTF_8), original = claims.clone();
   byte[] digest = new byte[32]; Arrays.fill(digest, (byte)9);
   String compact = signer().toCompactSerialization("JWT", "key", digest, claims, BUDGET);
   assertEquals(3, compact.split("\\.", -1).length);
   assertArrayEquals(original, claims);
   for (byte value : digest) assertEquals((byte)9, value);
   assertZero(requireNonNull(state.input));
   assertZero(requireNonNull(state.signature));
  });
 }

 @Test void maximumAcceptedInputsStayBelowTheDefensiveWireCaps() throws Exception {
  withProvider(state -> {
   byte[] claims = ("{\"x\":\"" + "a".repeat(32760) + "\"}").getBytes(StandardCharsets.UTF_8);
   assertEquals(32768, claims.length);
   String compact = signer().toCompactSerialization("client-authentication+jwt", "\u001f".repeat(256), new byte[32], claims, BUDGET);
   String[] pieces = compact.split("\\.", -1);
   assertEquals(1651, Base64.getUrlDecoder().decode(pieces[0]).length);
   assertEquals(2202, pieces[0].length());
   assertEquals(43691, pieces[1].length());
   assertEquals(46237, compact.length());
   // Even the policy's maximum 16384-bit RSA signature remains below the compact cap.
   assertEquals(48626, pieces[0].length() + pieces[1].length() + 2
     + Base64.getUrlEncoder().withoutPadding().encode(new byte[2048]).length);
  });
 }

 @Test void failedCompactEmissionClearsRetainedProviderArrays() throws Exception {
  withProvider(state -> {
   state.mismatch = true;
   assertThrows(JwsSigningException.class, () -> signer().toCompactSerialization("JWT", "key", new byte[32],
     "{}".getBytes(StandardCharsets.UTF_8), BUDGET));
   assertZero(requireNonNull(state.input));
   assertZero(requireNonNull(state.signature));
  });
 }

 @Test void successfulWarmUpClearsRetainedProviderArrays() throws Exception {
  withProvider(state -> {
   signer().warmUp(BUDGET);
   assertZero(requireNonNull(state.input));
   assertZero(requireNonNull(state.signature));
  });
 }

 @Test void failedWarmUpClearsItsRetainedInput() throws Exception {
  withProvider(state -> {
   state.mismatch = true;
   assertThrows(JwsSigningException.class, () -> signer().warmUp(BUDGET));
   assertZero(requireNonNull(state.input));
   assertZero(requireNonNull(state.signature));
  });
 }

 @Test void providerDelegatesUnownedThreadsAndKeys() throws Exception {
  withProvider(state -> {
   state.mismatch = true;
   AtomicReference<Throwable> failure = new AtomicReference<>();
   Thread worker = new Thread(() -> {
    try {
     var fixture = TestJwk.Fixture.IDP_SIGNING_RSA_2048;
     Signature engine = Signature.getInstance("SHA256withRSA"); engine.initSign(fixture.getPrivateKey()); engine.update((byte)1);
     byte[] signature = engine.sign();
     Signature verifier = Signature.getInstance("SHA256withRSA"); verifier.initVerify(fixture.getPublicKey()); verifier.update((byte)1);
     assertTrue(verifier.verify(signature));
    } catch (Throwable problem) { failure.set(problem); }
   });
   worker.setDaemon(true); worker.start(); worker.join(5000);
   assertFalse(worker.isAlive()); assertNull(failure.get());
   assertEquals(0, state.signCalls); assertEquals(0, state.verifyCalls);
   assertNull(state.input); assertNull(state.signature);
  });
 }

 private static void assertBudget(@NonNull CheckedAction action) {
  JwsSigningException failure = assertThrows(JwsSigningException.class, action::run);
  assertEquals(JwsSigningException.Reason.BUDGET_EXHAUSTED, failure.getReason());
  assertNull(failure.getCause());
 }
 private static void assertZero(byte @NonNull [] bytes) { assertArrayEquals(new byte[bytes.length], bytes); }
 private static @NonNull JwsSigner signer() {
  var fixture = TestJwk.Fixture.IDP_SIGNING_RSA_2048;
  return JwsSigner.fromRsaKeyPair(new ProbeKey(fixture.getPrivateKey()), fixture.getPublicKey(), JwsAlgorithm.PS256);
 }
 private static byte @NonNull [] signAndVerify(@NonNull JwsSigner signer, byte @NonNull [] input, @NonNull Deadline deadline) throws Exception {
  return (byte[]) requireNonNull(call(signer, "signAndVerify", input, deadline));
 }
 private static @Nullable Object call(@Nullable JwsSigner signer, @NonNull String name, @Nullable Object @NonNull ... arguments) throws Exception {
  var method = Arrays.stream(JwsSigner.class.getDeclaredMethods()).filter(candidate -> candidate.getName().equals(name)).findFirst().orElseThrow();
  method.setAccessible(true);
  try { return method.invoke(signer, arguments); }
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
 private static void withProvider(@NonNull Scenario scenario) throws Exception {
  // Load fixture key material before installing this operation-only provider.
  assertNotNull(TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
  State state = new State(requireNonNull(Security.getProvider("SunRsaSign")));
  assertNull(Security.getProvider(PROVIDER_NAME));
  Provider provider = new FixtureProvider(state);
  assertEquals(1, Security.insertProviderAt(provider, 1));
  try { scenario.run(state); }
  finally { Security.removeProvider(PROVIDER_NAME); }
 }
 @FunctionalInterface private interface CheckedAction { void run() throws Exception; }
 @FunctionalInterface private interface Scenario { void run(@NonNull State state) throws Exception; }

 private static final class State {
  private final @NonNull Provider original;
  private final @NonNull Thread owner = Thread.currentThread();
  private @NonNull Runnable afterInit = () -> {}, afterParameter = () -> {}, afterUpdate = () -> {}, afterSign = () -> {}, afterVerify = () -> {};
  private int signInitializations, signParameters, signUpdates, signCalls, verifyCalls;
  private boolean mismatch;
  private byte @Nullable [] input, signature;
  private State(@NonNull Provider original) { this.original = original; }
 }
 private static final class FixtureProvider extends Provider {
  private static final long serialVersionUID = 1L;
  private FixtureProvider(@NonNull State state) {
   super(PROVIDER_NAME, "1", "Scoped RC1 signer fixture");
   for (String algorithm : List.of("RSASSA-PSS", "SHA256withRSA", "SHA384withRSA")) {
    putService(new Service(this, "Signature", algorithm, Engine.class.getName(), List.of(), null) {
     @Override public @NonNull Object newInstance(@Nullable Object ignored) throws java.security.NoSuchAlgorithmException { return new Engine(algorithm, state); }
    });
   }
  }
 }
 private static final class ProbeKey implements PrivateKey {
  private static final long serialVersionUID = 1L;
  private final @NonNull PrivateKey delegate;
  private ProbeKey(@NonNull PrivateKey delegate) { this.delegate = delegate; }
  @Override public @NonNull String getAlgorithm() { return "RSA"; }
  @Override public @Nullable String getFormat() { return null; }
  @Override public byte @Nullable [] getEncoded() { return null; }
 }
 private static final class Engine extends SignatureSpi {
  private final @NonNull State state;
  private final @NonNull Signature delegate;
  private boolean trackedSign, trackedVerification;
  private Engine(@NonNull String algorithm, @NonNull State state) throws java.security.NoSuchAlgorithmException {
   this.state = state; this.delegate = Signature.getInstance(algorithm, state.original);
  }
  @Override protected void engineInitSign(@NonNull PrivateKey key) throws InvalidKeyException {
   this.trackedSign = key instanceof ProbeKey && Thread.currentThread().equals(this.state.owner);
   this.trackedVerification = false;
   this.delegate.initSign(key instanceof ProbeKey probe ? probe.delegate : key);
   if (this.trackedSign) { this.state.signInitializations++; this.state.afterInit.run(); }
  }
  @Override protected void engineInitVerify(@NonNull PublicKey key) throws InvalidKeyException {
   this.trackedSign = false;
   this.trackedVerification = Thread.currentThread().equals(this.state.owner) && key.getClass().getName().equals(JwsSigner.class.getName() + "$PublicProjection");
   this.delegate.initVerify(key);
  }
  @Override protected void engineUpdate(byte value) throws SignatureException { this.delegate.update(value); }
  @Override protected void engineUpdate(byte @NonNull [] bytes, int offset, int length) throws SignatureException {
   this.delegate.update(bytes, offset, length);
   if (this.trackedSign && Thread.currentThread().equals(this.state.owner)) { this.state.input = bytes; this.state.signUpdates++; this.state.afterUpdate.run(); }
  }
  @Override protected byte @NonNull [] engineSign() throws SignatureException {
   byte[] signature = this.delegate.sign();
   if (this.trackedSign && Thread.currentThread().equals(this.state.owner)) {
    this.state.signCalls++; this.state.signature = signature; this.state.afterSign.run();
   }
   return signature;
  }
  @Override protected boolean engineVerify(byte @NonNull [] signature) throws SignatureException {
   boolean result = this.delegate.verify(signature);
   if (this.trackedVerification && Thread.currentThread().equals(this.state.owner)) {
    this.state.verifyCalls++; this.state.afterVerify.run(); return !this.state.mismatch && result;
   }
   return result;
  }
  @Override protected void engineSetParameter(@NonNull AlgorithmParameterSpec parameters) throws InvalidAlgorithmParameterException {
   this.delegate.setParameter(parameters);
   if (this.trackedSign && Thread.currentThread().equals(this.state.owner)) { this.state.signParameters++; this.state.afterParameter.run(); }
  }
  @Override @SuppressWarnings("deprecation") protected void engineSetParameter(@NonNull String name, @NonNull Object value) { throw new UnsupportedOperationException(); }
  @Override @SuppressWarnings("deprecation") protected @Nullable Object engineGetParameter(@NonNull String name) { throw new UnsupportedOperationException(); }
 }
}
