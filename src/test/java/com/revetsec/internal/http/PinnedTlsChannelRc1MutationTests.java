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

package com.revetsec.internal.http;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.time.Duration;

import static javax.net.ssl.SSLEngineResult.HandshakeStatus.*;
import static javax.net.ssl.SSLEngineResult.Status.*;
import static org.junit.jupiter.api.Assertions.*;

/** Deterministic provider and wire boundaries, without peer timing or timeout-based mutation verdicts. */
final class PinnedTlsChannelRc1MutationTests {
 @Test void exactProviderBufferCapsAreAccepted() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  PinnedTlsChannel channel = channel(engine, new MemoryWire());
  assertNotNull(channel);
 }

 @Test void expiredConstructorFailsBeforeConsultingProvider() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  HttpExchangeException failure = assertThrows(HttpExchangeException.class,
    () -> new PinnedTlsChannel(new MemoryWire(), engine, Deadline.fromNow(Duration.ZERO)));
  assertEquals(HttpExchangeException.Kind.TIMEOUT, failure.getKind());
  assertEquals(0, engine.sessionCalls);
 }

 @Test void interruptedHandshakeDoesNotInvokeProvider() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  PinnedTlsChannel channel = channel(engine, new MemoryWire());
  Thread.currentThread().interrupt();
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, channel::handshake).getKind());
   assertEquals(0, engine.beginCalls);
  } finally { Thread.interrupted(); }
 }

 @Test void handshakeBeginsAndCompletesARequiredUnwrap() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.begin = () -> engine.status = NEED_UNWRAP;
  engine.unwrap = (source, target) -> { engine.status = NOT_HANDSHAKING; return result(OK, NOT_HANDSHAKING, 1, 0); };
  channel(engine, new MemoryWire()).handshake();
  assertEquals(1, engine.beginCalls);
  assertEquals(1, engine.unwrapCalls);
 }

 @Test void handshakeTaskProgressHasAnExactFiniteBound() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.status = NEED_TASK;
  engine.task = () -> engine.taskCalls++;
  assertEquals(HttpExchangeException.Kind.IO,
    assertThrows(HttpExchangeException.class, channel(engine, new MemoryWire())::handshake).getKind());
  assertEquals(1024, engine.taskCalls);
 }

 @Test void interruptedWriteDoesNotConsultProvider() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  PinnedTlsChannel channel = channel(engine, new MemoryWire());
  Thread.currentThread().interrupt();
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, () -> channel.write(new byte[]{1})).getKind());
   assertEquals(0, engine.statusCalls);
  } finally { Thread.interrupted(); }
 }

 @Test void cancellationOnTheFinalHandshakeStepPreservesItsReason() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.status = NEED_TASK;
  engine.task = () -> { if (++engine.taskCalls == 1024) Thread.currentThread().interrupt(); };
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, channel(engine, new MemoryWire())::handshake).getKind());
   assertEquals(1024, engine.taskCalls);
  } finally { Thread.interrupted(); }
 }

 @Test void cleanupWritesAtMostEightChunksAndClosesOnce() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> { target.put(new byte[16]); return result(CLOSED, NOT_HANDSHAKING, 0, 16); };
  MemoryWire wire = new MemoryWire();
  wire.write = bytes -> { bytes.get(); return 1; };
  PinnedTlsChannel channel = channel(engine, wire);
  channel.close();
  channel.close();
  assertEquals(1, engine.closeCalls);
  assertEquals(8, wire.writeCalls);
  assertEquals(1, wire.closeCalls);
  assertEquals(0, wire.waitCalls);
 }

 @Test void interruptedCleanupSkipsProviderAndStillClosesWire() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  MemoryWire wire = new MemoryWire();
  PinnedTlsChannel channel = channel(engine, wire);
  Thread.currentThread().interrupt();
  try {
   channel.close();
   assertEquals(0, engine.closeCalls);
   assertEquals(0, engine.wrapCalls);
   assertEquals(1, wire.closeCalls);
  } finally { Thread.interrupted(); }
 }

 @Test void cleanupStopsAtZeroWriteWithoutWaiting() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> { target.put((byte)1); return result(CLOSED, NOT_HANDSHAKING, 0, 1); };
  MemoryWire wire = new MemoryWire();
  wire.write = bytes -> 0;
  channel(engine, wire).close();
  assertEquals(1, wire.writeCalls);
  assertEquals(0, wire.waitCalls);
  assertEquals(1, wire.closeCalls);
 }

 @Test void cleanupChecksCancellationBetweenChunks() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> { target.put(new byte[16]); return result(CLOSED, NOT_HANDSHAKING, 0, 16); };
  MemoryWire wire = new MemoryWire();
  wire.write = bytes -> { bytes.get(); Thread.currentThread().interrupt(); return 1; };
  try {
   channel(engine, wire).close();
   assertEquals(1, wire.writeCalls);
   assertEquals(1, wire.closeCalls);
  } finally { Thread.interrupted(); }
 }

 @Test void cleanupAccountsEveryChunkAgainstTheSharedWireCap() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> { target.put(new byte[2]); return result(CLOSED, NOT_HANDSHAKING, 0, 2); };
  MemoryWire wire = new MemoryWire();
  wire.write = bytes -> { bytes.get(); return 1; };
  PinnedTlsChannel channel = channel(engine, wire);
  wireBytes(channel, PinnedTlsChannel.MAXIMUM_WIRE_BYTES - 1);
  channel.close();
  assertEquals(1, wire.writeCalls);
  assertEquals(1, wire.closeCalls);
 }

 @Test void impossibleWireCountsCannotExceedTheRemainingBudget() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> {
   int count = source.remaining(); source.position(source.limit()); target.put((byte)1);
   return result(OK, NOT_HANDSHAKING, count, 1);
  };
  MemoryWire wire = new MemoryWire();
  wire.write = bytes -> { bytes.position(bytes.limit()); return 2; };
  PinnedTlsChannel channel = channel(engine, wire);
  wireBytes(channel, PinnedTlsChannel.MAXIMUM_WIRE_BYTES - 1);
  assertEquals(HttpExchangeException.Kind.IO,
    assertThrows(HttpExchangeException.class, () -> channel.write(new byte[]{1})).getKind());
 }

 @Test void applicationWriteAcceptsConsumedDataWithoutWireOutput() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> {
   int count = source.remaining(); source.position(source.limit()); return result(OK, NOT_HANDSHAKING, count, 0);
  };
  MemoryWire wire = new MemoryWire();
  channel(engine, wire).write(new byte[]{1});
  assertEquals(1, engine.wrapCalls);
  assertEquals(0, wire.writeCalls);
 }

 @Test void applicationWriteAcceptsBufferedWireOutputBeforeConsumingData() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> {
   if (engine.wrapCalls == 1) { target.put((byte)1); return result(OK, NOT_HANDSHAKING, 0, 1); }
   source.get(); return result(OK, NOT_HANDSHAKING, 1, 0);
  };
  MemoryWire wire = new MemoryWire();
  channel(engine, wire).write(new byte[]{1});
  assertEquals(2, engine.wrapCalls);
  assertEquals(1, wire.writeCalls);
 }

 @Test void applicationWriteAcceptsHandshakeProgressWithoutData() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> {
   if (engine.wrapCalls == 1) return result(OK, FINISHED, 0, 0);
   source.get(); return result(OK, NOT_HANDSHAKING, 1, 0);
  };
  channel(engine, new MemoryWire()).write(new byte[]{1});
  assertEquals(2, engine.wrapCalls);
 }

 @Test void applicationWriteRejectsClosedProviderStatus() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> { source.get(); return result(CLOSED, NOT_HANDSHAKING, 1, 0); };
  assertEquals(HttpExchangeException.Kind.IO,
    assertThrows(HttpExchangeException.class, () -> channel(engine, new MemoryWire()).write(new byte[]{1})).getKind());
 }

 @Test void applicationWriteRejectsNoProgressImmediately() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> result(OK, NOT_HANDSHAKING, 0, 0);
  assertEquals(HttpExchangeException.Kind.IO,
    assertThrows(HttpExchangeException.class, () -> channel(engine, new MemoryWire()).write(new byte[]{1})).getKind());
  assertEquals(1, engine.wrapCalls);
 }

 @Test void applicationWriteProgressHasAnExactFiniteBound() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> {
   if (engine.wrapCalls > 1024) throw new AssertionError("write exceeded its finite provider-step allowance");
   return result(OK, NEED_WRAP, 0, 0);
  };
  assertEquals(HttpExchangeException.Kind.IO,
    assertThrows(HttpExchangeException.class, () -> channel(engine, new MemoryWire()).write(new byte[]{1})).getKind());
  assertEquals(1024, engine.wrapCalls);
 }

 @Test void writeCompletesHandshakeBeforeWrappingApplicationData() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.status = NEED_TASK;
  engine.task = () -> { engine.taskCalls++; engine.status = NOT_HANDSHAKING; };
  engine.wrap = (source, target) -> {
   assertEquals(1, engine.taskCalls); source.get(); return result(OK, NOT_HANDSHAKING, 1, 0);
  };
  channel(engine, new MemoryWire()).write(new byte[]{1});
  assertEquals(1, engine.wrapCalls);
 }

 @Test void writeFinishesTheHandshakeStartedByItsLastWrap() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.task = () -> { engine.taskCalls++; engine.status = NOT_HANDSHAKING; };
  engine.wrap = (source, target) -> { source.get(); engine.status = NEED_TASK; return result(OK, NEED_TASK, 1, 0); };
  channel(engine, new MemoryWire()).write(new byte[]{1});
  assertEquals(1, engine.taskCalls);
 }

 @Test void cancellationBeforeWrapPreventsProviderInvocation() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.statusProbe = () -> Thread.currentThread().interrupt();
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, () -> channel(engine, new MemoryWire()).write(new byte[]{1})).getKind());
   assertEquals(0, engine.wrapCalls);
  } finally { Thread.interrupted(); }
 }

 @Test void wrapCancellationPrecedesProviderStatusFailure() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> { Thread.currentThread().interrupt(); return result(BUFFER_OVERFLOW, NOT_HANDSHAKING, 0, 0); };
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, () -> channel(engine, new MemoryWire()).write(new byte[]{1})).getKind());
  } finally { Thread.interrupted(); }
 }

 @Test void writeWaitCancellationPreventsAnotherWireWrite() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> { source.get(); target.put((byte)1); return result(OK, NOT_HANDSHAKING, 1, 1); };
  MemoryWire wire = new MemoryWire();
  wire.write = bytes -> 0;
  wire.await = () -> Thread.currentThread().interrupt();
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, () -> channel(engine, wire).write(new byte[]{1})).getKind());
   assertEquals(1, wire.writeCalls);
  } finally { Thread.interrupted(); }
 }

 @Test void wireWriteCancellationPreventsWaiting() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.wrap = (source, target) -> { source.get(); target.put((byte)1); return result(OK, NOT_HANDSHAKING, 1, 1); };
  MemoryWire wire = new MemoryWire();
  wire.write = bytes -> { Thread.currentThread().interrupt(); return 0; };
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, () -> channel(engine, wire).write(new byte[]{1})).getKind());
   assertEquals(1, wire.writeCalls);
   assertEquals(0, wire.waitCalls);
  } finally { Thread.interrupted(); }
 }

 @Test void finalWriteBudgetCheckObservesStatusCallbackCancellation() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.statusProbe = () -> { if (engine.statusCalls == 2) Thread.currentThread().interrupt(); };
  engine.wrap = (source, target) -> { source.get(); return result(OK, NOT_HANDSHAKING, 1, 0); };
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, () -> channel(engine, new MemoryWire()).write(new byte[]{1})).getKind());
  } finally { Thread.interrupted(); }
 }

 @Test void plaintextOctetsAreUnsigned() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> { target.put((byte)0x80); return result(OK, NOT_HANDSHAKING, 1, 1); };
  assertEquals(128, channel(engine, new MemoryWire()).read());
 }

 @Test void readProgressHasAnExactFiniteBound() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> result(OK, NEED_UNWRAP, 0, 0);
  assertEquals(HttpExchangeException.Kind.IO,
    assertThrows(HttpExchangeException.class, channel(engine, new MemoryWire())::read).getKind());
  assertEquals(1024, engine.unwrapCalls);
 }

 @Test void bufferedPlaintextStillHonorsCancellation() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> { target.put(new byte[]{1, 2}); return result(OK, NOT_HANDSHAKING, 1, 2); };
  PinnedTlsChannel channel = channel(engine, new MemoryWire());
  assertEquals(1, channel.read());
  Thread.currentThread().interrupt();
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, channel::read).getKind());
  } finally { Thread.interrupted(); }
 }

 @Test void readAdvancesHandshakeBeforeReturningAuthenticatedEof() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.status = NEED_TASK;
  engine.task = () -> { engine.taskCalls++; engine.inboundDone = true; engine.status = NOT_HANDSHAKING; };
  assertEquals(-1, channel(engine, new MemoryWire()).read());
  assertEquals(1, engine.taskCalls);
  assertEquals(0, engine.unwrapCalls);
 }

 @Test void providerFailureRetainsCancellationPrecedence() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> { Thread.currentThread().interrupt(); throw new IllegalStateException("private provider detail"); };
  try {
   HttpExchangeException failure = assertThrows(HttpExchangeException.class, channel(engine, new MemoryWire())::read);
   assertEquals(HttpExchangeException.Kind.INTERRUPTED, failure.getKind());
   assertNull(failure.getCause());
  } finally { Thread.interrupted(); }
 }

 @Test void underflowWaitsOnZeroAndAcceptsPositiveRead() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> {
   if (engine.unwrapCalls == 1) return result(BUFFER_UNDERFLOW, NOT_HANDSHAKING, 0, 0);
   target.put((byte)7); return result(OK, NOT_HANDSHAKING, 1, 1);
  };
  MemoryWire wire = new MemoryWire();
  wire.read = bytes -> { if (wire.readCalls == 1) return 0; bytes.put((byte)1); return 1; };
  assertEquals(7, channel(engine, wire).read());
  assertEquals(2, wire.readCalls);
  assertEquals(1, wire.waitCalls);
  assertEquals(SelectionKey.OP_READ, wire.lastOperation);
 }

 @Test void underflowWaitCancellationPreventsAnotherWireRead() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> result(BUFFER_UNDERFLOW, NOT_HANDSHAKING, 0, 0);
  MemoryWire wire = new MemoryWire();
  wire.read = bytes -> 0;
  wire.await = () -> Thread.currentThread().interrupt();
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, channel(engine, wire)::read).getKind());
   assertEquals(1, wire.readCalls);
  } finally { Thread.interrupted(); }
 }

 @Test void unwrapAcceptsConsumedCiphertextWithoutPlaintext() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> result(OK, NOT_HANDSHAKING, 1, 0);
  unwrap(channel(engine, new MemoryWire()));
  assertEquals(1, engine.unwrapCalls);
 }

 @Test void unwrapAcceptsProducedPlaintextWithoutConsumedCiphertext() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> { target.put((byte)9); return result(OK, NOT_HANDSHAKING, 0, 1); };
  assertEquals(9, channel(engine, new MemoryWire()).read());
 }

 @Test void unwrapAcceptsHandshakeProgressWithoutData() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> result(OK, NEED_TASK, 0, 0);
  unwrap(channel(engine, new MemoryWire()));
  assertEquals(1, engine.unwrapCalls);
 }

 @Test void cancellationBeforeUnwrapPreventsProviderInvocation() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.statusProbe = () -> Thread.currentThread().interrupt();
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, channel(engine, new MemoryWire())::read).getKind());
   assertEquals(0, engine.unwrapCalls);
  } finally { Thread.interrupted(); }
 }

 @Test void unwrapCancellationPrecedesProviderStatusFailure() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> { Thread.currentThread().interrupt(); return result(BUFFER_OVERFLOW, NOT_HANDSHAKING, 0, 0); };
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, channel(engine, new MemoryWire())::read).getKind());
  } finally { Thread.interrupted(); }
 }

 @Test void underflowRestrictsReadToRemainingWireBudget() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> {
   if (engine.unwrapCalls == 1) return result(BUFFER_UNDERFLOW, NOT_HANDSHAKING, 0, 0);
   target.put((byte)3); return result(OK, NOT_HANDSHAKING, 1, 1);
  };
  MemoryWire wire = new MemoryWire();
  wire.read = bytes -> { int count = bytes.remaining(); while (bytes.hasRemaining()) bytes.put((byte)1); return count; };
  PinnedTlsChannel channel = channel(engine, wire);
  wireBytes(channel, PinnedTlsChannel.MAXIMUM_WIRE_BYTES - 1);
  assertEquals(3, channel.read());
  assertEquals(1, wire.lastReadAllowance);
 }

 @Test void wireCancellationPrecedesUnauthenticatedEof() throws Exception {
  ScriptEngine engine = new ScriptEngine();
  engine.unwrap = (source, target) -> result(BUFFER_UNDERFLOW, NOT_HANDSHAKING, 0, 0);
  MemoryWire wire = new MemoryWire();
  wire.read = bytes -> { Thread.currentThread().interrupt(); return -1; };
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,
     assertThrows(HttpExchangeException.class, channel(engine, wire)::read).getKind());
  } finally { Thread.interrupted(); }
 }

 private static @NonNull PinnedTlsChannel channel(@NonNull ScriptEngine engine, @NonNull MemoryWire wire) throws Exception {
  return new PinnedTlsChannel(wire, engine, Deadline.fromNow(Duration.ofSeconds(30)));
 }

 private static @NonNull SSLEngineResult result(SSLEngineResult.@NonNull Status status,
   SSLEngineResult.@NonNull HandshakeStatus handshake, int consumed, int produced) {
  return new SSLEngineResult(status, handshake, consumed, produced);
 }

 // These probes exercise one provider transition and a near-exhausted lifetime budget directly.
 private static void unwrap(@NonNull PinnedTlsChannel channel) throws Exception {
  var method = PinnedTlsChannel.class.getDeclaredMethod("unwrap"); method.setAccessible(true);
  try { method.invoke(channel); }
  catch (InvocationTargetException failure) {
   if (failure.getCause() instanceof Exception cause) throw cause;
   throw failure;
  }
 }

 private static void wireBytes(@NonNull PinnedTlsChannel channel, int count) throws Exception {
  var field = PinnedTlsChannel.class.getDeclaredField("wireBytes"); field.setAccessible(true); field.setInt(channel, count);
 }

 @FunctionalInterface private interface EngineStep {
  @NonNull SSLEngineResult run(@NonNull ByteBuffer source, @NonNull ByteBuffer target);
 }
 @FunctionalInterface private interface WireStep { int run(@NonNull ByteBuffer bytes); }

 private static final class MemoryWire implements PinnedTlsChannel.Wire {
  private int readCalls, writeCalls, waitCalls, closeCalls, lastOperation, lastReadAllowance;
  private @NonNull WireStep read = bytes -> { bytes.put((byte)1); return 1; };
  private @NonNull WireStep write = bytes -> { int count = bytes.remaining(); bytes.position(bytes.limit()); return count; };
  private @NonNull Runnable await = () -> {};
  @Override public int read(@NonNull ByteBuffer bytes) { this.readCalls++; this.lastReadAllowance = bytes.remaining(); return this.read.run(bytes); }
  @Override public int write(@NonNull ByteBuffer bytes) { this.writeCalls++; return this.write.run(bytes); }
  @Override public void await(int operation) { this.waitCalls++; this.lastOperation = operation; this.await.run(); }
  @Override public void close() { this.closeCalls++; }
 }

 private static final class ScriptEngine extends SSLEngine {
  private final @NonNull SSLEngine delegate = SSLContext.getDefault().createSSLEngine();
  private SSLEngineResult.@NonNull HandshakeStatus status = NOT_HANDSHAKING;
  private boolean inboundDone;
  private int beginCalls, closeCalls, taskCalls, unwrapCalls, wrapCalls, sessionCalls, statusCalls;
  private @NonNull Runnable begin = () -> {};
  private @NonNull Runnable statusProbe = () -> {};
  private @NonNull Runnable task = () -> {};
  private @NonNull EngineStep unwrap = (source, target) -> result(OK, NOT_HANDSHAKING, 1, 0);
  private @NonNull EngineStep wrap = (source, target) -> result(CLOSED, NOT_HANDSHAKING, 0, 0);
  private ScriptEngine() throws Exception {}
  @Override public @NonNull SSLSession getSession() {
   this.sessionCalls++;
   return (SSLSession) Proxy.newProxyInstance(SSLSession.class.getClassLoader(), new Class<?>[]{SSLSession.class}, (proxy, method, arguments) -> {
    if (method.getName().equals("getPacketBufferSize") || method.getName().equals("getApplicationBufferSize")) return PinnedTlsChannel.BUFFER_BYTES;
    return method.invoke(this.delegate.getSession(), arguments);
   });
  }
  @Override public SSLEngineResult.@NonNull HandshakeStatus getHandshakeStatus() { this.statusCalls++; this.statusProbe.run(); return this.status; }
  @Override public @Nullable Runnable getDelegatedTask() { return this.task; }
  @Override public @NonNull SSLEngineResult wrap(@NonNull ByteBuffer @NonNull [] source, int offset, int length, @NonNull ByteBuffer target) {
   this.wrapCalls++; return this.wrap.run(source[offset], target);
  }
  @Override public @NonNull SSLEngineResult unwrap(@NonNull ByteBuffer source, @NonNull ByteBuffer @NonNull [] target, int offset, int length) {
   this.unwrapCalls++; return this.unwrap.run(source, target[offset]);
  }
  @Override public void beginHandshake() { this.beginCalls++; this.begin.run(); }
  @Override public void closeInbound() throws SSLException { this.delegate.closeInbound(); }
  @Override public boolean isInboundDone() { return this.inboundDone; }
  @Override public void closeOutbound() { this.closeCalls++; }
  @Override public boolean isOutboundDone() { return this.closeCalls > 0; }
  @Override public @NonNull String @NonNull [] getSupportedCipherSuites() { return this.delegate.getSupportedCipherSuites(); }
  @Override public @NonNull String @NonNull [] getEnabledCipherSuites() { return this.delegate.getEnabledCipherSuites(); }
  @Override public void setEnabledCipherSuites(@NonNull String @NonNull [] suites) { this.delegate.setEnabledCipherSuites(suites); }
  @Override public @NonNull String @NonNull [] getSupportedProtocols() { return this.delegate.getSupportedProtocols(); }
  @Override public @NonNull String @NonNull [] getEnabledProtocols() { return this.delegate.getEnabledProtocols(); }
  @Override public void setEnabledProtocols(@NonNull String @NonNull [] protocols) { this.delegate.setEnabledProtocols(protocols); }
  @Override public void setUseClientMode(boolean value) { this.delegate.setUseClientMode(value); }
  @Override public boolean getUseClientMode() { return this.delegate.getUseClientMode(); }
  @Override public void setNeedClientAuth(boolean value) { this.delegate.setNeedClientAuth(value); }
  @Override public boolean getNeedClientAuth() { return this.delegate.getNeedClientAuth(); }
  @Override public void setWantClientAuth(boolean value) { this.delegate.setWantClientAuth(value); }
  @Override public boolean getWantClientAuth() { return this.delegate.getWantClientAuth(); }
  @Override public void setEnableSessionCreation(boolean value) { this.delegate.setEnableSessionCreation(value); }
  @Override public boolean getEnableSessionCreation() { return this.delegate.getEnableSessionCreation(); }
 }
}
