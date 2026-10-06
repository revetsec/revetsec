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
import javax.annotation.concurrent.NotThreadSafe;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import static java.util.Objects.requireNonNull;

/** One calling-thread TLS stream over a nonblocking numeric connection; no executor or buffer growth. */
@NotThreadSafe
final class PinnedTlsChannel implements PinnedHttpResponseReader.ByteReader, AutoCloseable {
 static final int BUFFER_BYTES = 65536;
 static final int MAXIMUM_WIRE_BYTES = 524288;
 private static final int MAXIMUM_STEPS = 1024;
 interface Wire extends AutoCloseable {
  int read(@NonNull ByteBuffer bytes) throws IOException;
  int write(@NonNull ByteBuffer bytes) throws IOException;
  void await(int operation) throws IOException, HttpExchangeException;
  @Override void close() throws IOException;
 }
 private final @NonNull Wire wire;
 private final @NonNull SSLEngine engine;
 private final @NonNull Deadline deadline;
 private final @NonNull ByteBuffer inbound = ByteBuffer.allocate(BUFFER_BYTES);
 private final @NonNull ByteBuffer outbound = ByteBuffer.allocate(BUFFER_BYTES);
 private final @NonNull ByteBuffer plaintext = ByteBuffer.allocate(BUFFER_BYTES);
 private int wireBytes;
 private boolean closed;
 PinnedTlsChannel(@NonNull Wire wire, @NonNull SSLEngine engine, @NonNull Deadline deadline)
   throws HttpExchangeException {
  this.wire = requireNonNull(wire); this.engine = requireNonNull(engine); this.deadline = requireNonNull(deadline);
  this.plaintext.limit(0);
  checkBudget();
  if (engine.getSession().getPacketBufferSize() > BUFFER_BYTES
    || engine.getSession().getApplicationBufferSize() > BUFFER_BYTES) throw io();
 }
 void handshake() throws IOException, HttpExchangeException {
  checkBudget(); this.engine.beginHandshake(); checkBudget(); advance();
 }
 private void advance() throws IOException, HttpExchangeException {
  int previousWire = this.wireBytes;
  for (int step = 0; step < MAXIMUM_STEPS; step++) {
   checkBudget();
   switch (this.engine.getHandshakeStatus()) {
    case NOT_HANDSHAKING, FINISHED -> { return; }
    case NEED_TASK -> {
     @Nullable Runnable task = this.engine.getDelegatedTask();
     if (task == null) throw io();
     task.run(); checkBudget();
    }
    case NEED_WRAP -> wrap(ByteBuffer.allocate(0), false);
    case NEED_UNWRAP, NEED_UNWRAP_AGAIN -> {
     if (this.plaintext.hasRemaining()) throw io();
     unwrap();
     if (this.engine.isInboundDone()) throw io();
    }
   }
   if (this.wireBytes != previousWire) { step = -1; previousWire = this.wireBytes; }
  }
  throw io();
 }
 void write(byte @NonNull [] bytes) throws IOException, HttpExchangeException {
  ByteBuffer source = ByteBuffer.wrap(requireNonNull(bytes));
  int previousWire = this.wireBytes;
  for (int step = 0; source.hasRemaining(); step++) {
   if (step >= MAXIMUM_STEPS) throw io();
   advance(); wrap(source, false);
   if (this.wireBytes != previousWire) { step = -1; previousWire = this.wireBytes; }
  }
  advance(); checkBudget();
 }
 private void wrap(@NonNull ByteBuffer source, boolean closing) throws IOException, HttpExchangeException {
  checkBudget(); this.outbound.clear();
  SSLEngineResult result = this.engine.wrap(source, this.outbound); checkBudget();
  if (result.getStatus() != SSLEngineResult.Status.OK
    && !(closing && result.getStatus() == SSLEngineResult.Status.CLOSED)) throw io();
  if (!closing && result.bytesConsumed() == 0 && result.bytesProduced() == 0
    && result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) throw io();
  this.outbound.flip();
  while (this.outbound.hasRemaining()) {
   checkBudget(); restrict(this.outbound); int written = this.wire.write(this.outbound); account(written); checkBudget();
   if (written == 0) this.wire.await(SelectionKey.OP_WRITE);
  }
 }
 @Override public int read() throws HttpExchangeException {
  try {
   int previousWire = this.wireBytes;
   for (int step = 0; step < MAXIMUM_STEPS; step++) {
    checkBudget();
    if (this.plaintext.hasRemaining()) return this.plaintext.get() & 255;
    if (this.engine.isInboundDone()) return -1;
    advance();
    if (this.plaintext.hasRemaining()) continue;
    if (this.engine.isInboundDone()) return -1;
    unwrap();
    if (this.wireBytes != previousWire) { step = -1; previousWire = this.wireBytes; }
   }
   throw io();
  } catch (IOException | RuntimeException failure) {
   checkBudget(); throw io();
  }
 }
 private void unwrap() throws IOException, HttpExchangeException {
  checkBudget(); this.inbound.flip(); this.plaintext.clear();
  SSLEngineResult result;
  try { result = this.engine.unwrap(this.inbound, this.plaintext); }
  finally { this.inbound.compact(); this.plaintext.flip(); }
  checkBudget();
  switch (result.getStatus()) {
   case BUFFER_OVERFLOW -> throw io();
   case BUFFER_UNDERFLOW -> {
    if (!this.inbound.hasRemaining()) throw io();
    int count;
    do {
     checkBudget(); restrict(this.inbound); count = this.wire.read(this.inbound); checkBudget();
     if (count < 0) throw io(); // TCP EOF never fabricates authenticated TLS closure.
     account(count);
     if (count == 0) this.wire.await(SelectionKey.OP_READ);
    } while (count == 0);
   }
   case OK -> {
    if (result.bytesConsumed() == 0 && result.bytesProduced() == 0
      && result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) throw io();
   }
   case CLOSED -> { /* SSLEngine authenticated close_notify; buffered plaintext remains readable. */ }
  }
 }
 private void restrict(@NonNull ByteBuffer bytes) throws HttpExchangeException {
  int remaining = MAXIMUM_WIRE_BYTES - this.wireBytes;
  if (remaining == 0) throw io();
  bytes.limit(bytes.position() + Math.min(bytes.remaining(), remaining));
 }
 private void account(int count) throws HttpExchangeException {
  if (count < 0 || count > MAXIMUM_WIRE_BYTES - this.wireBytes) throw io();
  this.wireBytes += count;
 }
 private void checkBudget() throws HttpExchangeException { PinnedHttpsTransport.checkBudget(this.deadline); }
 private static @NonNull HttpExchangeException io() { return new HttpExchangeException(HttpExchangeException.Kind.IO); }
 @Override public void close() {
  if (this.closed) return;
  this.closed = true;
  try {
   if (!this.deadline.isExpired() && !Thread.currentThread().isInterrupted()) {
    this.engine.closeOutbound(); this.outbound.clear();
    this.engine.wrap(ByteBuffer.allocate(0), this.outbound); this.outbound.flip();
    // Best effort nonblocking close_notify: never wait for a peer during resource cleanup.
    for (int step = 0; step < 8 && this.outbound.hasRemaining(); step++) {
     checkBudget(); restrict(this.outbound); int written = this.wire.write(this.outbound); account(written); if (written == 0) break;
    }
   }
  } catch (IOException | HttpExchangeException | RuntimeException ignored) { /* TCP/selector still close. */ }
  finally { try { this.wire.close(); } catch (IOException ignored) { /* No remote diagnostic escapes. */ } }
 }
}
