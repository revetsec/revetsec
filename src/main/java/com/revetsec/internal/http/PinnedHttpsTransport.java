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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.HostClassifier;
import com.revetsec.internal.Limits;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.encoding.EncodingException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.NotThreadSafe;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.function.BiFunction;
import static java.util.Objects.requireNonNull;

/**
 * Internal anonymous client-metadata HTTPS GET. It never uses HttpClient, a proxy, system DNS, redirects, cookies,
 * client credentials or a caller-supplied TLS context. Every numeric answer is copied and admitted before the first
 * connection; the first answer is selected with no retry or extra resolution. The connected peer
 * and port must match that snapshot. Resolver/provider/local trust work is trusted and cooperatively bounded.
 * This method yields raw response data, not freshness, document or authorization proof. Cache/issuer wiring follows.
 */
@ThreadSafe
public final class PinnedHttpsTransport {
 private PinnedHttpsTransport() {}
 public static @NonNull RawResponse fetch(@NonNull URI uri,
   @NonNull BiFunction<@NonNull String, @NonNull Duration, @NonNull List<@NonNull InetAddress>> resolver,
   int maximumAnswers, int maximumDocumentBytes, @NonNull Duration requestTimeout, @NonNull Deadline operation)
   throws HttpExchangeException {
  requireNonNull(uri); requireNonNull(resolver); requireNonNull(requestTimeout); requireNonNull(operation);
  Limits.CIMD_MAXIMUM_RESOLVED_ADDRESSES.require(maximumAnswers);
  Limits.CIMD_MAXIMUM_DOCUMENT_BYTES.require(maximumDocumentBytes);
  if (requestTimeout.isZero() || requestTimeout.isNegative()) throw new IllegalArgumentException("A positive request timeout is required.");
  checkBudget(operation);
  Deadline deadline = operation.boundedBy(requestTimeout);
  checkBudget(deadline); byte[] request = request(uri, true);
  String host = hostname(uri); long started = System.nanoTime();
  try {
   List<InetAddress> answers = PinnedHttpsAddresses.checked(requireNonNull(resolver.apply(host, deadline.remaining())), maximumAnswers, deadline);
   byte @Nullable [] literal = HostClassifier.parseLiteral(requireNonNull(uri.getHost()));
   if (literal != null && answers.stream().anyMatch(answer -> !Arrays.equals(literal, answer.getAddress())))
    throw new HttpExchangeException(HttpExchangeException.Kind.URI_REJECTED);
   SSLContext context = PinnedTlsContext.fromDefaults(); checkBudget(deadline);
   RawResponse response = exchange(uri, answers.get(0), request, maximumDocumentBytes, context, deadline, started);
   checkBudget(deadline); return response;
  } catch (RuntimeException failure) { checkBudget(deadline); throw new HttpExchangeException(HttpExchangeException.Kind.IO); }
 }
 static @NonNull RawResponse exchange(@NonNull URI uri, @NonNull InetAddress address, byte @NonNull [] request,
   int maximumDocumentBytes, @NonNull SSLContext context, @NonNull Deadline deadline, long started)
   throws HttpExchangeException {
  requireNonNull(uri); requireNonNull(address); requireNonNull(request); requireNonNull(context); requireNonNull(deadline);
  checkBudget(deadline);
  InetSocketAddress peer = new InetSocketAddress(address, uri.getPort() < 0 ? 443 : uri.getPort());
  try (NioWire wire = NioWire.connect(peer, deadline)) {
   SSLEngine engine = context.createSSLEngine(hostname(uri), peer.getPort());
   engine.setUseClientMode(true);
   SSLParameters parameters = engine.getSSLParameters();
   parameters.setEndpointIdentificationAlgorithm("HTTPS"); parameters.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
   parameters.setApplicationProtocols(new String[]{"http/1.1"});
   String host = hostname(uri);
   if (HostClassifier.parseLiteral(requireNonNull(uri.getHost())) == null)
    parameters.setServerNames(List.of(new SNIHostName(host.endsWith(".") ? host.substring(0, host.length() - 1) : host)));
   else parameters.setServerNames(List.of());
   engine.setSSLParameters(parameters);
   try (PinnedTlsChannel stream = new PinnedTlsChannel(wire, engine, deadline)) {
    stream.handshake(); wire.checkPeer(peer);
    String protocol = engine.getApplicationProtocol();
    if (protocol != null && !protocol.isEmpty() && !"http/1.1".equals(protocol)) throw new HttpExchangeException(HttpExchangeException.Kind.IO);
    stream.write(request);
    return PinnedHttpResponseReader.read(stream, maximumDocumentBytes, deadline, started);
   }
  } catch (IOException | RuntimeException failure) { checkBudget(deadline); throw new HttpExchangeException(HttpExchangeException.Kind.IO); }
 }
 static byte @NonNull [] request(@NonNull URI uri, boolean publicOnly) throws HttpExchangeException {
  requireNonNull(uri);
  if (uri.toString().length() > 4096 || uri.toString().indexOf('*') >= 0 || !"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
    || uri.isOpaque() || uri.getRawUserInfo() != null || uri.getRawFragment() != null
    || uri.getPort() == 0 || uri.getPort() > 65535 || uri.getRawPath() == null || uri.getRawPath().isEmpty()
    || (publicOnly && !OutboundUriPolicy.publicAddressesOnlyInstance().permits(uri)))
   throw new HttpExchangeException(HttpExchangeException.Kind.URI_REJECTED);
  try {
   String decoded = FormUrlEncoding.decode(requireNonNull(uri.getRawPath()).replace("+", "%2B"));
   for (String part : decoded.split("/", -1)) if (part.equals(".") || part.equals(".."))
    throw new HttpExchangeException(HttpExchangeException.Kind.URI_REJECTED);
   for (int i = 0; i < decoded.length(); i++) if (decoded.charAt(i) == '\\' || Character.isISOControl(decoded.charAt(i)))
    throw new HttpExchangeException(HttpExchangeException.Kind.URI_REJECTED);
  } catch (EncodingException failure) { throw new HttpExchangeException(HttpExchangeException.Kind.URI_REJECTED); }
  URI ascii = URI.create(uri.toASCIIString());
  String target = requireNonNull(ascii.getRawPath()) + (ascii.getRawQuery() == null ? "" : "?" + ascii.getRawQuery());
  byte[] bytes = ("GET " + target + " HTTP/1.1\r\nHost: " + uri.getRawAuthority()
    + "\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
  if (bytes.length > 65536) throw new HttpExchangeException(HttpExchangeException.Kind.URI_REJECTED);
  return bytes;
 }
 private static @NonNull String hostname(@NonNull URI uri) {
  String host = requireNonNull(uri.getHost());
  return host.startsWith("[") ? host.substring(1, host.length() - 1) : host;
 }
 static void checkBudget(@NonNull Deadline deadline) throws HttpExchangeException {
  if (Thread.currentThread().isInterrupted()) throw new HttpExchangeException(HttpExchangeException.Kind.INTERRUPTED);
  if (deadline.isExpired()) throw new HttpExchangeException(HttpExchangeException.Kind.TIMEOUT);
 }
 @NotThreadSafe
 private static final class NioWire implements PinnedTlsChannel.Wire {
  private final @NonNull SocketChannel channel;
  private final @NonNull Selector selector;
  private final @NonNull SelectionKey key;
  private final @NonNull Deadline deadline;
  private boolean closed;
  private NioWire(@NonNull SocketChannel channel, @NonNull Selector selector, @NonNull SelectionKey key, @NonNull Deadline deadline) {
   this.channel = channel; this.selector = selector; this.key = key; this.deadline = deadline;
  }
  static @NonNull NioWire connect(@NonNull InetSocketAddress peer, @NonNull Deadline deadline)
    throws IOException, HttpExchangeException {
   SocketChannel channel = SocketChannel.open();
   try {
    Selector selector = Selector.open();
    try {
     channel.configureBlocking(false);
     NioWire wire = new NioWire(channel, selector, channel.register(selector, 0), deadline);
     checkBudget(deadline);
     if (!channel.connect(peer)) while (!channel.finishConnect()) wire.await(SelectionKey.OP_CONNECT);
     checkBudget(deadline); wire.checkPeer(peer); return wire;
    } catch (IOException | HttpExchangeException | RuntimeException failure) { selector.close(); throw failure; }
   } catch (IOException | HttpExchangeException | RuntimeException failure) { channel.close(); throw failure; }
  }
  void checkPeer(@NonNull InetSocketAddress peer) throws IOException, HttpExchangeException {
   if (!(this.channel.getRemoteAddress() instanceof InetSocketAddress actual) || !peer.equals(actual))
    throw new HttpExchangeException(HttpExchangeException.Kind.URI_REJECTED);
  }
  @Override public int read(@NonNull ByteBuffer bytes) throws IOException { return this.channel.read(bytes); }
  @Override public int write(@NonNull ByteBuffer bytes) throws IOException { return this.channel.write(bytes); }
  @Override public void await(int operation) throws IOException, HttpExchangeException {
   checkBudget(this.deadline); this.key.interestOps(operation);
   long nanos = this.deadline.remainingNanos();
   this.selector.select(Math.max(1, nanos / 1_000_000 + (nanos % 1_000_000 == 0 ? 0 : 1)));
   this.selector.selectedKeys().clear(); checkBudget(this.deadline);
  }
  @Override public void close() throws IOException { if (this.closed) return; this.closed = true; try { this.channel.close(); } finally { this.selector.close(); } }
 }
}
