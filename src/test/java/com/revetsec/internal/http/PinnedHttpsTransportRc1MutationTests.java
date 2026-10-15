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
import org.junit.jupiter.api.parallel.Isolated;
import javax.net.ssl.*;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Duration;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/** Numeric loopback connection and an injected TLS engine; no external connections or TLS trust changes. */
@Isolated
final class PinnedHttpsTransportRc1MutationTests {
 private static final Duration BOUND = Duration.ofSeconds(2);
 @Test void highestPortIsAdmittedAndItsNeighborIsRejected() throws Exception {
  String request=new String(PinnedHttpsTransport.request(URI.create("https://metadata.example:65535/id"),false),StandardCharsets.US_ASCII);
  assertTrue(request.contains("Host: metadata.example:65535\r\n"));
  assertEquals(HttpExchangeException.Kind.URI_REJECTED,assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.request(URI.create("https://metadata.example:65536/id"),false)).getKind());
 }
 @Test void ipv6HostnameDropsBothBracketsAndKeepsTheAddress() throws Exception {
  Method method=PinnedHttpsTransport.class.getDeclaredMethod("hostname",URI.class);method.setAccessible(true);
  assertEquals("2001:4860:4860::8888",method.invoke(null,URI.create("https://[2001:4860:4860::8888]/id")));
 }
 @Test void engineConfigurationUsesClientModeModernTlsExactAlpnAndDnsSni() {
  assertTimeoutPreemptively(BOUND,()->{
   RecordingEngine engine=new RecordingEngine("http/1.1");
   exchange(engine,"metadata.example.");
   assertTrue(engine.getUseClientMode());assertEquals("HTTPS",engine.getSSLParameters().getEndpointIdentificationAlgorithm());
   assertArrayEquals(new String[]{"TLSv1.3","TLSv1.2"},engine.getEnabledProtocols());
   assertArrayEquals(new String[]{"http/1.1"},engine.getSSLParameters().getApplicationProtocols());
   assertEquals(List.of(new SNIHostName("metadata.example")),engine.getSSLParameters().getServerNames());
   assertEquals("metadata.example.",engine.createdHost);assertTrue(engine.handshakeStarted);assertTrue(engine.requestWrapAttempted);
  });
 }
 @Test void literalAuthorityClearsPreviouslyConfiguredSni() {
  assertTimeoutPreemptively(BOUND,()->{
   RecordingEngine engine=new RecordingEngine("http/1.1");exchange(engine,"127.0.0.1");
   assertEquals(List.of(),engine.getSSLParameters().getServerNames());assertTrue(engine.requestWrapAttempted);
  });
 }
 @Test void unexpectedAlpnStopsBeforeAnyHttpRequestAndPermittedValuesReachTheWrite() {
  assertTimeoutPreemptively(BOUND,()->{
   RecordingEngine rejected=new RecordingEngine("h2");exchange(rejected,"metadata.example");assertTrue(rejected.handshakeStarted);assertFalse(rejected.requestWrapAttempted);
   for(String protocol:new String[]{"http/1.1",""}){RecordingEngine accepted=new RecordingEngine(protocol);exchange(accepted,"metadata.example");assertTrue(accepted.requestWrapAttempted,protocol);}
   RecordingEngine omitted=new RecordingEngine(null);exchange(omitted,"metadata.example");assertTrue(omitted.requestWrapAttempted);
  });
 }
 @Test void interruptionDuringTlsFailureKeepsTheInterruptedOutcome() {
  assertTimeoutPreemptively(BOUND,()->{
   RecordingEngine engine=new RecordingEngine("http/1.1");engine.interruptAtHandshake=true;
   try {assertEquals(HttpExchangeException.Kind.INTERRUPTED,exchange(engine,"metadata.example"));assertTrue(Thread.currentThread().isInterrupted());}
   finally {Thread.interrupted();}
  });
 }
 @Test void anExactNumericAnswerPassesLiteralBindingBeforeUnavailableTrustIsReported() throws Exception {
  Provider provider=new UnavailableTrustProvider();Security.insertProviderAt(provider,1);
  try {
   InetAddress exact=InetAddress.getByAddress(new byte[]{8,8,8,8});
   HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.fetch(URI.create("https://8.8.8.8/id"),(host,budget)->List.of(exact),16,5120,Duration.ofSeconds(1),Deadline.fromNow(Duration.ofSeconds(1))));
   assertEquals(HttpExchangeException.Kind.PINNED_TLS_UNAVAILABLE,failure.getKind());
  } finally {Security.removeProvider(provider.getName());}
 }
 @Test void interruptedResolverFailureRetainsInterruptionBeforeItBecomesIo() {
  try {
   HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.fetch(URI.create("https://metadata.revetsec.com/id"),(host,budget)->{Thread.currentThread().interrupt();throw new IllegalStateException("owned resolver failure");},16,5120,Duration.ofSeconds(1),Deadline.fromNow(Duration.ofSeconds(1))));
   assertEquals(HttpExchangeException.Kind.INTERRUPTED,failure.getKind());assertTrue(Thread.currentThread().isInterrupted());
  } finally {Thread.interrupted();}
 }
 @Test void expiredExchangeStopsBeforeConstructingAnInvalidPortEndpoint() throws Exception {
  RecordingEngine engine=new RecordingEngine("http/1.1");InetAddress loopback=InetAddress.getByAddress(new byte[]{127,0,0,1});
  HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.exchange(URI.create("https://metadata.example:65536/id"),loopback,new byte[0],5120,new RecordingContext(engine),Deadline.fromNow(Duration.ZERO),System.nanoTime()));
  assertEquals(HttpExchangeException.Kind.TIMEOUT,failure.getKind());assertEquals("",engine.createdHost);
 }
 private static HttpExchangeException.@NonNull Kind exchange(@NonNull RecordingEngine engine,@NonNull String host) throws Exception {
  InetAddress loopback=InetAddress.getByAddress(new byte[]{127,0,0,1});
  try(ServerSocket listener=new ServerSocket(0,1,loopback)){
   listener.setSoTimeout(1000);URI uri=URI.create("https://"+host+":"+listener.getLocalPort()+"/id");
   HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.exchange(uri,loopback,PinnedHttpsTransport.request(uri,false),5120,new RecordingContext(engine),Deadline.fromNow(Duration.ofSeconds(1)),System.nanoTime()));
   try(Socket accepted=listener.accept()){accepted.setSoTimeout(1000);assertEquals(-1,accepted.getInputStream().read());}
   return failure.getKind();
  }
 }
 private static final class RecordingContext extends SSLContext {
  private RecordingContext(@NonNull RecordingEngine engine){super(new ContextSpi(engine),new Provider("Rc1LocalTls", "1", "Owned TLS test context"){},"TLS");}
 }
 private static final class ContextSpi extends SSLContextSpi {
  private final @NonNull RecordingEngine engine;
  private ContextSpi(@NonNull RecordingEngine engine){this.engine=engine;}
  @Override protected void engineInit(@Nullable KeyManager @Nullable [] keyManagers,@Nullable TrustManager @Nullable [] trustManagers,@Nullable SecureRandom random){}
  @Override protected @NonNull SSLSocketFactory engineGetSocketFactory(){throw new UnsupportedOperationException();}
  @Override protected @NonNull SSLServerSocketFactory engineGetServerSocketFactory(){throw new UnsupportedOperationException();}
  @Override protected @NonNull SSLEngine engineCreateSSLEngine(){return this.engine;}
  @Override protected @NonNull SSLEngine engineCreateSSLEngine(@NonNull String host,int port){this.engine.createdHost=host;return this.engine;}
  @Override protected @NonNull SSLSessionContext engineGetServerSessionContext(){throw new UnsupportedOperationException();}
  @Override protected @NonNull SSLSessionContext engineGetClientSessionContext(){throw new UnsupportedOperationException();}
 }
 private static final class RecordingEngine extends SSLEngine {
  private final @NonNull SSLEngine delegate=SSLContext.getDefault().createSSLEngine();
  private final @Nullable String protocol;private @NonNull String createdHost="";private boolean handshakeStarted,requestWrapAttempted,interruptAtHandshake,closed;
  private RecordingEngine(@Nullable String protocol) throws Exception {
   this.protocol=protocol;SSLParameters initial=this.delegate.getSSLParameters();initial.setProtocols(new String[]{"TLSv1.1"});initial.setApplicationProtocols(new String[]{"h2"});initial.setServerNames(List.of(new SNIHostName("stale.example")));this.delegate.setSSLParameters(initial);
  }
  @Override public @NonNull SSLParameters getSSLParameters(){return this.delegate.getSSLParameters();}
  @Override public void setSSLParameters(@NonNull SSLParameters parameters){this.delegate.setSSLParameters(parameters);}
  @Override public @Nullable String getApplicationProtocol(){return this.protocol;}
  @Override public @NonNull SSLSession getSession(){return this.delegate.getSession();}
  @Override public SSLEngineResult.@NonNull HandshakeStatus getHandshakeStatus(){return SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;}
  @Override public @Nullable Runnable getDelegatedTask(){return null;}
  @Override public @NonNull SSLEngineResult wrap(@NonNull ByteBuffer @NonNull [] source,int offset,int length,@NonNull ByteBuffer target) throws SSLException {
   if(this.closed)return new SSLEngineResult(SSLEngineResult.Status.CLOSED,SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,0,0);
   this.requestWrapAttempted=source[offset].hasRemaining();throw new SSLException("Owned test stops before emitting TLS or HTTP bytes.");
  }
  @Override public @NonNull SSLEngineResult unwrap(@NonNull ByteBuffer source,@NonNull ByteBuffer @NonNull [] target,int offset,int length) throws SSLException {throw new SSLException("Owned test never reads response bytes.");}
  @Override public void beginHandshake() throws SSLException {this.handshakeStarted=true;if(this.interruptAtHandshake){Thread.currentThread().interrupt();throw new SSLException("Owned interrupted handshake.");}}
  @Override public void closeInbound() throws SSLException {this.delegate.closeInbound();}
  @Override public boolean isInboundDone(){return false;}
  @Override public void closeOutbound(){this.closed=true;}
  @Override public boolean isOutboundDone(){return this.closed;}
  @Override public @NonNull String @NonNull [] getSupportedCipherSuites(){return this.delegate.getSupportedCipherSuites();}
  @Override public @NonNull String @NonNull [] getEnabledCipherSuites(){return this.delegate.getEnabledCipherSuites();}
  @Override public void setEnabledCipherSuites(@NonNull String @NonNull [] values){this.delegate.setEnabledCipherSuites(values);}
  @Override public @NonNull String @NonNull [] getSupportedProtocols(){return this.delegate.getSupportedProtocols();}
  @Override public @NonNull String @NonNull [] getEnabledProtocols(){return this.delegate.getEnabledProtocols();}
  @Override public void setEnabledProtocols(@NonNull String @NonNull [] values){this.delegate.setEnabledProtocols(values);}
  @Override public void setUseClientMode(boolean value){this.delegate.setUseClientMode(value);}
  @Override public boolean getUseClientMode(){return this.delegate.getUseClientMode();}
  @Override public void setNeedClientAuth(boolean value){this.delegate.setNeedClientAuth(value);}
  @Override public boolean getNeedClientAuth(){return this.delegate.getNeedClientAuth();}
  @Override public void setWantClientAuth(boolean value){this.delegate.setWantClientAuth(value);}
  @Override public boolean getWantClientAuth(){return this.delegate.getWantClientAuth();}
  @Override public void setEnableSessionCreation(boolean value){this.delegate.setEnableSessionCreation(value);}
  @Override public boolean getEnableSessionCreation(){return this.delegate.getEnableSessionCreation();}
 }
 public static final class UnavailableTrustFactory extends TrustManagerFactorySpi {
  @Override protected void engineInit(@Nullable KeyStore store){}
  @Override protected void engineInit(@NonNull ManagerFactoryParameters parameters){}
  @Override protected @NonNull TrustManager @NonNull [] engineGetTrustManagers(){return new TrustManager[0];}
 }
 private static final class UnavailableTrustProvider extends Provider {
  private UnavailableTrustProvider(){super("Rc1UnavailableTrust","1","Owned unsupported trust provider");putService(new Service(this,"TrustManagerFactory","PKIX",UnavailableTrustFactory.class.getName(),List.of(),java.util.Map.of()));}
 }
}
