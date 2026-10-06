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

import com.revetsec.ErrorCategory;
import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.util.stream.Stream;
import javax.net.ssl.SSLContext;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

final class PinnedHttpsTransportTests {
 private static final Duration WAIT = Duration.ofSeconds(10);
 private static final URI PUBLIC = URI.create("https://metadata.revetsec.com/client.json");
 private static @NonNull InetAddress address(@NonNull String bytes) throws Exception {
  String[] parts = bytes.split("\\.", -1); byte[] value = new byte[4];
  for (int i = 0; i < 4; i++) value[i] = (byte) Integer.parseInt(parts[i]);
  return InetAddress.getByAddress(value);
 }
 private static @NonNull RawResponse local(@NonNull URI uri, @NonNull Deadline deadline) throws Exception {
  SSLContext context = PinnedTlsContext.fromTrustStore(TestTls.trustStore());
  return PinnedHttpsTransport.exchange(uri, address("127.0.0.1"), PinnedHttpsTransport.request(uri, false),
    5120, context, deadline, System.nanoTime());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> ineligibleUrisNeverResolveCases() {
  return Stream.of("http://example.com/id","https://localhost/id","https://127.0.0.1/id",
   "https://[::1]/id","https://10.0.0.1/id","https://169.254.169.254/id","https://example.com",
   "https://example.com:0/id","https://example.com:65536/id","https://user@example.com/id",
   "https://example.com/id#fragment","https://example.com/id/*","https://example.com/a/../id","https://example.com/a/./id",
   "https://example.com/a/%2E%2E/id","https://example.com/a%5Cid","https://example.com/%00id","https://example.com/%FFid","https://metadata.google.internal/id","/id","https://example.com./").map(value -> DynamicTest.dynamicTest(value, () -> ineligibleUrisNeverResolve(value)));
 }
 private void ineligibleUrisNeverResolve(@NonNull String text) throws Exception {
  // A trailing-dot ordinary host is eligible; this row tests an already expired budget instead.
  AtomicInteger calls = new AtomicInteger();
  Deadline d = text.equals("https://example.com./") ? Deadline.fromNow(Duration.ZERO) : Deadline.fromNow(WAIT);
  HttpExchangeException failure = assertThrows(HttpExchangeException.class, () ->
    PinnedHttpsTransport.fetch(URI.create(text), (host,budget) -> {calls.incrementAndGet();return List.of();},16,5120,WAIT,d));
  assertEquals(text.equals("https://example.com./") ? HttpExchangeException.Kind.TIMEOUT : HttpExchangeException.Kind.URI_REJECTED,failure.getKind());
  assertEquals(0,calls.get()); assertNull(failure.getCause());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> everyUnsafeAnswerRejectsBeforeTlsCases() {
  return Stream.of("127.0.0.1","10.0.0.1","192.0.0.9","169.254.169.254","100.64.0.1").map(value -> DynamicTest.dynamicTest(value, () -> everyUnsafeAnswerRejectsBeforeTls(value)));
 }
 private void everyUnsafeAnswerRejectsBeforeTls(@NonNull String unsafe) throws Exception {
  InetAddress bad=address(unsafe),good=address("8.8.8.8"); AtomicInteger calls=new AtomicInteger();
  HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.fetch(PUBLIC,(host,budget)->{
   assertEquals("metadata.revetsec.com",host);assertTrue(!budget.isNegative() && !budget.isZero());calls.incrementAndGet();return List.of(good,bad);
  },16,5120,WAIT,Deadline.fromNow(WAIT)));
  assertEquals(HttpExchangeException.Kind.URI_REJECTED,failure.getKind());assertEquals(1,calls.get());assertNull(failure.getCause());
 }
 @Test void numericAuthorityCannotResolveToAnotherPublicAddress() throws Exception {
  InetAddress wrong=address("9.9.9.9");
  assertEquals(HttpExchangeException.Kind.URI_REJECTED,assertThrows(HttpExchangeException.class,()->
    PinnedHttpsTransport.fetch(URI.create("https://8.8.8.8/id"),(host,budget)->List.of(wrong),16,5120,WAIT,Deadline.fromNow(WAIT))).getKind());
 }
 @Test void resolverFaultsAreFixedAndDeadlineInterruptionIsPreserved() {
  HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.fetch(PUBLIC,
    (host,budget)->{throw new IllegalStateException("private-provider-value");},16,5120,WAIT,Deadline.fromNow(WAIT)));
  assertEquals(HttpExchangeException.Kind.IO,failure.getKind());assertNull(failure.getCause());assertFalse(failure.toString().contains("private-provider-value"));
  try {
   Thread.currentThread().interrupt();
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,assertThrows(HttpExchangeException.class,()->
     PinnedHttpsTransport.fetch(PUBLIC,(host,budget)->List.of(),16,5120,WAIT,Deadline.fromNow(WAIT))).getKind());
   assertTrue(Thread.currentThread().isInterrupted());
  } finally { Thread.interrupted(); }
 }
 @Test void requestHasOnlyAnonymousHeadersAndExactEncodedTarget() throws Exception {
  URI uri=URI.create("https://metadata.revetsec.com:9443/cliënt.json?a=%2B&b=+");
  String request=new String(PinnedHttpsTransport.request(uri,true),StandardCharsets.US_ASCII);
  assertEquals("GET /cli%C3%ABnt.json?a=%2B&b=+ HTTP/1.1\r\nHost: metadata.revetsec.com:9443\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",request);
  assertFalse(request.contains("Cookie"));assertFalse(request.contains("Authorization"));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> liveTlsReadsFramedResponsesAndClosesCases() {
  return Stream.of(
   "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
   "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
   "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").map(value -> DynamicTest.dynamicTest(value, () -> liveTlsReadsFramedResponsesAndCloses(value)));
 }
 private void liveTlsReadsFramedResponsesAndCloses(@NonNull String response) throws Exception {
  try (RawTlsServer server=RawTlsServer.start()) {
   server.script("/id",RawTlsServer.Script.fromString(response));
   URI uri=URI.create("https://localhost:"+server.getPort()+"/id?x=%2B");
   RawResponse result=local(uri,Deadline.fromNow(WAIT));assertEquals(200,result.status());assertArrayEquals("{}".getBytes(StandardCharsets.UTF_8),result.body());
   assertTrue(server.awaitRequestCount(1,WAIT));assertEquals("localhost:"+server.getPort(),server.getRequests().get(0).getHeader("Host").orElseThrow());
   assertEquals("GET /id?x=%2B HTTP/1.1",server.getRequests().get(0).getRequestLine());
   assertTrue(server.getConnections().get(0).awaitClientClose(WAIT));
  }
 }
 @Test void closeDelimitedSuccessRequiresTlsCloseNotify() throws Exception {
  try (RawTlsServer server=RawTlsServer.start()) {
   server.script("/id",RawTlsServer.Script.builder().write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}").endOfStream().build());
   assertArrayEquals("{}".getBytes(StandardCharsets.UTF_8),local(server.uri("/id"),Deadline.fromNow(WAIT)).body());
   assertTrue(server.getConnections().get(0).awaitClientClose(WAIT));
  }
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> rejectedLiveResponsesCloseWithoutFollowingCases() {
  return Stream.of("HTTP/1.1 302 Found\r\nLocation: https://private.invalid\r\n\r\n",
   "HTTP/1.1 304 Not Modified\r\n\r\n","HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}",
   "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
   "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}",
   "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5121\r\n\r\n").map(value -> DynamicTest.dynamicTest(value, () -> rejectedLiveResponsesCloseWithoutFollowing(value)));
 }
 private void rejectedLiveResponsesCloseWithoutFollowing(@NonNull String response) throws Exception {
  try(RawTlsServer server=RawTlsServer.start()) {
   server.script("/id",RawTlsServer.Script.fromString(response));
   HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->local(server.uri("/id"),Deadline.fromNow(WAIT)));
   assertNotEquals(HttpExchangeException.Kind.IO,failure.getKind());assertNull(failure.getCause());assertEquals(1,server.getRequests().size());
   assertTrue(server.getConnections().get(0).awaitClientClose(WAIT));
  }
 }
 @Test void stalledBodyUsesOriginalDeadlineAndCloses() throws Exception {
  SSLContext context=PinnedTlsContext.fromTrustStore(TestTls.trustStore());
  try(RawTlsServer server=RawTlsServer.start()) {
   server.script("/id",RawTlsServer.Script.builder().write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{}").stall().build());
   URI uri=server.uri("/id");
   HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.exchange(uri,address("127.0.0.1"),PinnedHttpsTransport.request(uri,false),5120,context,Deadline.fromNow(Duration.ofMillis(500)),System.nanoTime()));
   assertEquals(HttpExchangeException.Kind.TIMEOUT,failure.getKind());assertTrue(server.awaitRequestCount(1,WAIT));assertTrue(server.getConnections().get(0).awaitClientClose(WAIT));
  }
 }
 @Test void silentHandshakeTimesOutAndClosesNumericSocket() throws Exception {
  SSLContext context=PinnedTlsContext.fromTrustStore(TestTls.trustStore());
  try(ServerSocket server=new ServerSocket(0,1,address("127.0.0.1"))) {
   URI uri=URI.create("https://localhost:"+server.getLocalPort()+"/id");
   assertEquals(HttpExchangeException.Kind.TIMEOUT,assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.exchange(uri,address("127.0.0.1"),PinnedHttpsTransport.request(uri,false),5120,context,Deadline.fromNow(Duration.ofMillis(200)),System.nanoTime())).getKind());
   server.setSoTimeout(1000);try(Socket socket=server.accept()) {socket.setSoTimeout(1000);assertTrue(socket.getInputStream().readAllBytes().length>0);}
  }
 }
 @Test void hostnameMismatchNeverSendsHttp() throws Exception {
  try(RawTlsServer server=RawTlsServer.start()) {
   URI uri=URI.create("https://metadata.revetsec.com:"+server.getPort()+"/id");
   HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->local(uri,Deadline.fromNow(WAIT)));
   assertEquals(HttpExchangeException.Kind.IO,failure.getKind());assertNull(failure.getCause());assertEquals(0,server.getRequests().size());
   assertTrue(server.awaitConnectionCount(1,WAIT));assertTrue(server.getConnections().get(0).awaitClientClose(WAIT));
  }
 }
 @Test void unavailableLocalTrustIsConfigurationWithFixedDiagnostics() throws Exception {
  java.security.KeyStore empty=java.security.KeyStore.getInstance("PKCS12");empty.load(null,null);
  HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedTlsContext.fromTrustStore(empty));
  assertEquals(HttpExchangeException.Kind.PINNED_TLS_UNAVAILABLE,failure.getKind());assertEquals(ErrorCategory.CONFIGURATION,failure.getKind().getCategory());assertFalse(failure.getKind().isTransient());assertNull(failure.getCause());
 }

 @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidRequestTimeoutsDoNotInvokeResolver() {
  return Stream.of(Duration.ZERO,Duration.ofNanos(-1)).map(timeout->DynamicTest.dynamicTest(timeout.toString(),()->{
   AtomicInteger calls=new AtomicInteger();assertThrows(IllegalArgumentException.class,()->PinnedHttpsTransport.fetch(PUBLIC,(host,budget)->{calls.incrementAndGet();return List.of();},16,5120,timeout,Deadline.fromNow(WAIT)));assertEquals(0,calls.get());
  }));
 }
 @Test void requestLengthIsBoundedBeforeResolution() throws Exception {
  String prefix="https://metadata.revetsec.com/";String exact=prefix+"x".repeat(4096-prefix.length());
  assertTrue(PinnedHttpsTransport.request(URI.create(exact),true).length>4096);
  AtomicInteger calls=new AtomicInteger();
  assertEquals(HttpExchangeException.Kind.URI_REJECTED,assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.fetch(URI.create(exact+"x"),(host,budget)->{calls.incrementAndGet();return List.of();},16,5120,WAIT,Deadline.fromNow(WAIT))).getKind());
  assertEquals(0,calls.get());
 }
 @Test void resolverMustReturnWithinBudgetWithoutClearingInterruption() {
  assertEquals(HttpExchangeException.Kind.IO,assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.fetch(PUBLIC,(host,budget)->null,16,5120,WAIT,Deadline.fromNow(WAIT))).getKind());
  assertEquals(HttpExchangeException.Kind.TIMEOUT,assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.fetch(PUBLIC,(host,budget)->{
   assertTrue(budget.compareTo(Duration.ofMillis(2))<=0);long until=System.nanoTime()+Duration.ofMillis(10).toNanos();while(System.nanoTime()<until)Thread.onSpinWait();return List.of();
  },16,5120,Duration.ofMillis(2),Deadline.fromNow(WAIT))).getKind());
  try {
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.fetch(PUBLIC,(host,budget)->{Thread.currentThread().interrupt();return List.of();},16,5120,WAIT,Deadline.fromNow(WAIT))).getKind());
   assertTrue(Thread.currentThread().isInterrupted());
  } finally {Thread.interrupted();}
 }
 @Test void selectorInterruptionClosesTheStalledTlsConnection() throws Exception {
  SSLContext context=PinnedTlsContext.fromTrustStore(TestTls.trustStore());
  try(RawTlsServer server=RawTlsServer.start()) {
   server.script("/id",RawTlsServer.Script.builder().write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{}").stall().build());
   java.util.concurrent.atomic.AtomicReference<Throwable> outcome=new java.util.concurrent.atomic.AtomicReference<>();
   java.util.concurrent.atomic.AtomicBoolean preserved=new java.util.concurrent.atomic.AtomicBoolean();
   Thread worker=new Thread(()->{try{URI uri=server.uri("/id");PinnedHttpsTransport.exchange(uri,address("127.0.0.1"),PinnedHttpsTransport.request(uri,false),5120,context,Deadline.fromNow(WAIT),System.nanoTime());}catch(Throwable failure){outcome.set(failure);preserved.set(Thread.currentThread().isInterrupted());}});
   try {worker.start();assertTrue(server.awaitRequestCount(1,WAIT));worker.interrupt();worker.join(5000);assertFalse(worker.isAlive());
    Throwable failure=outcome.get();assertInstanceOf(HttpExchangeException.class,failure);assertEquals(HttpExchangeException.Kind.INTERRUPTED,((HttpExchangeException)failure).getKind());assertTrue(preserved.get());assertTrue(server.getConnections().get(0).awaitClientClose(WAIT));
   } finally {worker.interrupt();worker.join(5000);}
  }
 }
 @Test void boundedDeadlineNeverMovesTheOriginalCutoff() {
  Deadline original=Deadline.fromNow(Duration.ZERO);assertTrue(original.boundedBy(WAIT).isExpired());assertEquals(Duration.ZERO,original.boundedBy(WAIT).getTotal());
  Deadline longDeadline=Deadline.fromNow(Duration.ofDays(1000000));assertEquals(longDeadline.getTotal(),longDeadline.boundedBy(Duration.ofSeconds(Long.MAX_VALUE)).getTotal());
  Deadline shortDeadline=Deadline.fromNow(WAIT);Deadline restricted=shortDeadline.boundedBy(Duration.ofMillis(1));assertTrue(restricted.getTotal().compareTo(shortDeadline.getTotal())<0);
  assertTrue(shortDeadline.boundedBy(Duration.ZERO).isExpired());assertThrows(IllegalArgumentException.class,()->shortDeadline.boundedBy(Duration.ofNanos(-1)));
 }
}
