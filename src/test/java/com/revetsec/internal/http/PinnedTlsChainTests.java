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

import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import static java.util.Objects.requireNonNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.Timeout;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.util.concurrent.atomic.AtomicInteger;
import java.net.Socket;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Real certificates, real PKIX validation, and real TLS; reflection only supplies an observing delegate. */
final class PinnedTlsChainTests {
 private static PinnedTlsPki pki;
 private static X509Certificate leaf,issuer,root;
 private static Map<String,X509Certificate> variants;
 @BeforeAll static void certificates() throws Exception {
  if(pki==null)pki=new PinnedTlsPki(Files.createTempDirectory(Path.of("target"),"chain-pki-"),1);
  X509Certificate[] chain=pki.chain();leaf=chain[0];issuer=chain[1];root=chain[2];variants=pki.variants();
 }
 private static X509Certificate cert(String name){return requireNonNull(variants.get(name));}
 private static Map<String,X509Certificate[]> accepted() {
  return Map.ofEntries(
    Map.entry("ordered without root",new X509Certificate[]{leaf,issuer}),
    Map.entry("ordered with root",new X509Certificate[]{leaf,issuer,root}),
    Map.entry("root before intermediate",new X509Certificate[]{leaf,root,issuer}),
    Map.entry("cross-signed root",new X509Certificate[]{leaf,issuer,cert("cross")}),
    Map.entry("cross-signed root out of order",new X509Certificate[]{leaf,cert("cross"),issuer}),
    Map.entry("untrusted cross signer also supplied",new X509Certificate[]{leaf,issuer,cert("cross"),cert("other")}),
    Map.entry("unrelated certificate first in tail",new X509Certificate[]{leaf,cert("other"),issuer}),
    Map.entry("duplicate tail certificates",new X509Certificate[]{leaf,issuer,issuer,root}),
    Map.entry("alternate untrusted issuer before usable issuer",new X509Certificate[]{leaf,cert("untrusted-issuer"),issuer}),
    Map.entry("expired alternate issuer before usable issuer",new X509Certificate[]{leaf,cert("expired-issuer"),issuer}),
    Map.entry("non-CA alternate issuer before usable issuer",new X509Certificate[]{leaf,cert("non-ca"),issuer}),
    Map.entry("wrong key alternate issuer before usable issuer",new X509Certificate[]{leaf,cert("wrong-key"),issuer}),
    Map.entry("bad key usage alternate issuer before usable issuer",new X509Certificate[]{leaf,cert("bad-usage"),issuer}),
    Map.entry("critical extension alternate issuer before usable issuer",new X509Certificate[]{leaf,cert("critical"),issuer}),
    Map.entry("maximum bounded certificate bag",new X509Certificate[]{leaf,cert("other"),cert("untrusted-issuer"),cert("expired-issuer"),cert("non-ca"),cert("bad-usage"),cert("critical"),cert("cross"),root,issuer}));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> locallyConstructedPathsUseOnlySuppliedCertificatesAndConfiguredAnchor() {
  return accepted().entrySet().stream().map(entry->DynamicTest.dynamicTest(entry.getKey(),()->{
   RecordingTrust delegate=new RecordingTrust();X509ExtendedTrustManager manager=manager(delegate,root);
   X509Certificate[] supplied=entry.getValue(),original=supplied.clone();
   assertDoesNotThrow(()->manager.checkServerTrusted(supplied,"RSA",engine()));
   assertArrayEquals(original,supplied,"The peer's array must remain unchanged");
   assertEquals(1,delegate.chains.size());assertArrayEquals(new X509Certificate[]{leaf,issuer,root},delegate.chains.get(0));
  }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidOrIncompletePathsNeverReachTlsDelegate() {
  Map<String,X509Certificate[]> rejected=Map.ofEntries(
    Map.entry("missing intermediate",new X509Certificate[]{leaf,cert("cross"),cert("other")}),
    Map.entry("only untrusted issuer",new X509Certificate[]{leaf,cert("untrusted-issuer"),cert("other")}),
    Map.entry("expired issuer",new X509Certificate[]{leaf,cert("expired-issuer"),root}),
    Map.entry("non CA issuer",new X509Certificate[]{leaf,cert("non-ca"),root}),
    Map.entry("issuer with wrong key",new X509Certificate[]{leaf,cert("wrong-key"),root}),
    Map.entry("issuer without signing usage",new X509Certificate[]{leaf,cert("bad-usage"),root}),
    Map.entry("unknown critical extension",new X509Certificate[]{leaf,cert("critical"),root}),
    Map.entry("expired leaf",new X509Certificate[]{cert("expired-leaf"),issuer,root}),
    Map.entry("future leaf",new X509Certificate[]{cert("future-leaf"),issuer,root}),
    Map.entry("name constraints",new X509Certificate[]{leaf,cert("name-constraint"),root}),
    Map.entry("path length",new X509Certificate[]{cert("deep-leaf"),cert("sub-ca"),issuer,root}),
    Map.entry("null after trusted root",new X509Certificate[]{leaf,issuer,root,null}));
  return rejected.entrySet().stream().map(entry->DynamicTest.dynamicTest(entry.getKey(),()->{
   RecordingTrust delegate=new RecordingTrust();
   CertificateException failure=assertThrows(CertificateException.class,()->manager(delegate,root).checkServerTrusted(entry.getValue(),"RSA",engine()));
   assertEquals("The local TLS certificate checks failed.",failure.getMessage());assertNull(failure.getCause());assertTrue(delegate.chains.isEmpty());
  }));
 }
 @Test @Timeout(10) void cyclicSameSubjectBagIsBoundedAndCannotAcquireTrust() throws Exception {
  RecordingTrust delegate=new RecordingTrust();AtomicInteger encodings=new AtomicInteger();
  X509Certificate[] cyclic=Arrays.stream(pki.adversarial()).map(cert->new CountedCertificate(cert,encodings)).toArray(X509Certificate[]::new);
  assertEquals(10,Set.of(cyclic).size());
  assertThrows(CertificateException.class,()->manager(delegate,cert("other")).checkServerTrusted(cyclic,"RSA",engine()));
  assertTrue(delegate.chains.isEmpty());
 }
 @Test void oversizedCertificateAfterTrustedRootIsStillRejected() throws Exception {
  RecordingTrust delegate=new RecordingTrust();X509Certificate oversized=pki.oversized();assertTrue(oversized.getEncoded().length>32768);
  assertThrows(CertificateException.class,()->manager(delegate,root).checkServerTrusted(new X509Certificate[]{leaf,issuer,root,oversized},"RSA",engine()));
  assertTrue(delegate.chains.isEmpty());
 }
 @Test void suppliedSelfSignedRootDoesNotBecomeAnAnchor() throws Exception {
  RecordingTrust delegate=new RecordingTrust();
  assertThrows(CertificateException.class,()->manager(delegate,cert("other")).checkServerTrusted(new X509Certificate[]{leaf,issuer,root},"RSA",engine()));
  assertTrue(delegate.chains.isEmpty());
 }
 @Test void explicitlyTrustedLeafStillNeedsToBeCurrent() throws Exception {
  for(String name:List.of("expired-leaf","future-leaf")) {
   RecordingTrust delegate=new RecordingTrust();X509Certificate invalid=cert(name);
   assertThrows(CertificateException.class,()->manager(delegate,invalid).checkServerTrusted(new X509Certificate[]{invalid},"RSA",engine()));
   assertTrue(delegate.chains.isEmpty());
  }
 }
 @Test void explicitlyTrustedCurrentLeafIsStillPassedToTlsChecks() throws Exception {
  RecordingTrust delegate=new RecordingTrust();
  assertDoesNotThrow(()->manager(delegate,leaf).checkServerTrusted(new X509Certificate[]{leaf},"RSA",engine()));
  assertEquals(1,delegate.chains.size());assertArrayEquals(new X509Certificate[]{leaf},delegate.chains.get(0));
 }
 @Test void tlsRejectionCanBacktrackToAnotherLocallyValidPath() throws Exception {
  RecordingTrust delegate=new RecordingTrust();delegate.rejectIssuer=cert("untrusted-issuer");
  assertDoesNotThrow(()->manager(delegate,root,cert("other")).checkServerTrusted(new X509Certificate[]{leaf,cert("untrusted-issuer"),issuer},"RSA",engine()));
  assertEquals(2,delegate.chains.size());assertEquals(cert("untrusted-issuer"),delegate.chains.get(0)[1]);
  assertArrayEquals(new X509Certificate[]{leaf,issuer,root},delegate.chains.get(1));
 }
 @Test void tlsRejectionIsNeverTurnedIntoAcceptance() throws Exception {
  RecordingTrust delegate=new RecordingTrust();delegate.rejectAll=true;
  CertificateException failure=assertThrows(CertificateException.class,()->manager(delegate,root).checkServerTrusted(new X509Certificate[]{leaf,issuer},"RSA",engine()));
  assertNull(failure.getCause());assertFalse(requireNonNull(failure.getMessage()).contains("private TLS diagnostic"));assertFalse(delegate.chains.isEmpty());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> constructedPathsCompleteRealTlsWithHostnameAndOriginalRequest() {
  return Stream.of("TLSv1.2","TLSv1.3").flatMap(protocol->Stream.of("root before intermediate","cross-signed root","cross-signed root out of order","alternate untrusted issuer before usable issuer")
    .map(name->DynamicTest.dynamicTest(protocol+" "+name,()->{
     InetAddress loopback=InetAddress.getByAddress(new byte[]{127,0,0,1});
     try(PinnedTlsPeer peer=new PinnedTlsPeer(pki.server(requireNonNull(accepted().get(name))),loopback,protocol,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",false)) {
      URI uri=URI.create("https://localhost:"+peer.port()+"/id?x=%2B");
      RawResponse response=assertDoesNotThrow(()->PinnedHttpsTransport.exchange(uri,loopback,PinnedHttpsTransport.request(uri,false),5120,PinnedTlsContext.fromTrustStore(pki.trustStore()),Deadline.fromNow(Duration.ofSeconds(10)),System.nanoTime()));
      assertEquals(200,response.status());assertArrayEquals(new byte[]{'{','}'},response.body());
      assertTrue(peer.request().startsWith("GET /id?x=%2B HTTP/1.1\r\nHost: localhost:"+peer.port()+"\r\n"));
      assertEquals("localhost",peer.serverName());assertEquals(protocol,peer.negotiated());assertEquals("http/1.1",peer.applicationProtocol());
     }
    })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> realTlsRetainsLeafUsageAndHostnameChecks() {
  return Stream.of("client-only","wrong-host").map(name->DynamicTest.dynamicTest(name,()->{
   InetAddress loopback=InetAddress.getByAddress(new byte[]{127,0,0,1});X509Certificate selected=name.equals("client-only")?cert(name):leaf;
   try(PinnedTlsPeer peer=new PinnedTlsPeer(pki.server(selected,cert("cross"),issuer),loopback,"TLSv1.3","",false)) {
    URI uri=URI.create("https://"+(name.equals("wrong-host")?"wrong.invalid":"localhost")+":"+peer.port()+"/id");
    HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.exchange(uri,loopback,PinnedHttpsTransport.request(uri,false),5120,PinnedTlsContext.fromTrustStore(pki.trustStore()),Deadline.fromNow(Duration.ofSeconds(10)),System.nanoTime()));
    assertEquals(HttpExchangeException.Kind.IO,failure.getKind());assertNull(failure.getCause());
   }
  }));
 }
 @Test void realTlsAppliesEngineAlgorithmConstraintsToTheConstructedPath() throws Exception {
  InetAddress loopback=InetAddress.getByAddress(new byte[]{127,0,0,1});AtomicInteger denied=new AtomicInteger();
  try(PinnedTlsPeer peer=new PinnedTlsPeer(pki.server(leaf,cert("cross"),issuer),loopback,"TLSv1.3","",false)) {
   Deadline deadline=Deadline.fromNow(Duration.ofSeconds(10));
   SSLEngine engine=PinnedTlsContext.fromTrustStore(pki.trustStore()).createSSLEngine("localhost",peer.port());engine.setUseClientMode(true);
   var options=engine.getSSLParameters();options.setEndpointIdentificationAlgorithm("HTTPS");
   options.setAlgorithmConstraints(new AlgorithmConstraints(){
    private boolean permits(Key key){if(key.equals(issuer.getPublicKey())){denied.incrementAndGet();return false;}return true;}
    @Override public boolean permits(Set<CryptoPrimitive> primitives,String algorithm,@Nullable AlgorithmParameters parameters){return true;}
    @Override public boolean permits(Set<CryptoPrimitive> primitives,Key key){return permits(key);}
    @Override public boolean permits(Set<CryptoPrimitive> primitives,String algorithm,Key key,@Nullable AlgorithmParameters parameters){return permits(key);}
   });engine.setSSLParameters(options);
   // Reuse the actual numeric-only connector, without adding a production test hook or TLS-context bypass.
   var type=Class.forName("com.revetsec.internal.http.PinnedHttpsTransport$NioWire");
   var connect=type.getDeclaredMethod("connect",InetSocketAddress.class,Deadline.class);connect.setAccessible(true);
   try(PinnedTlsChannel.Wire wire=(PinnedTlsChannel.Wire)requireNonNull(connect.invoke(null,new InetSocketAddress(loopback,peer.port()),deadline));
     PinnedTlsChannel channel=new PinnedTlsChannel(wire,engine,deadline)) {
    Exception failure=assertThrows(Exception.class,channel::handshake);
    assertTrue(failure instanceof javax.net.ssl.SSLException || failure instanceof HttpExchangeException);
    assertTrue(denied.get()>0,"The certificate's actual issuer key must encounter the engine constraints");
   }
  }
 }
 private static X509ExtendedTrustManager manager(RecordingTrust delegate,X509Certificate... trusted) throws Exception {
  var type=Class.forName("com.revetsec.internal.http.PinnedTlsContext$LocalTrust");
  var constructor=type.getDeclaredConstructor(X509ExtendedTrustManager.class,Set.class);constructor.setAccessible(true);
  Set<TrustAnchor> anchors=Arrays.stream(trusted).map(cert->new TrustAnchor(cert,null)).collect(java.util.stream.Collectors.toSet());
  return (X509ExtendedTrustManager)constructor.newInstance(delegate,anchors);
 }
 private static SSLEngine engine() {
  SSLEngine engine=TestTls.clientSslContext().createSSLEngine("localhost",443);engine.setUseClientMode(true);
  var options=engine.getSSLParameters();options.setEndpointIdentificationAlgorithm("HTTPS");engine.setSSLParameters(options);return engine;
 }
 /** Count certificate work, so disabling the search bound fails an assertion rather than waiting for a timeout. */
 @SuppressWarnings("deprecation")
 private static final class CountedCertificate extends X509Certificate {
  private static final long serialVersionUID=1L;
  private final X509Certificate delegate;
  private final AtomicInteger encodings;
  private CountedCertificate(X509Certificate delegate,AtomicInteger encodings){this.delegate=delegate;this.encodings=encodings;}
  @Override public byte[] getEncoded() throws java.security.cert.CertificateEncodingException {
   // 128 prefixes over ten certificates have ample allowance, including PKIX's own encoding work.
   assertTrue(encodings.incrementAndGet()<=50000,"Certificate work exceeded the bounded local search allowance");
   return delegate.getEncoded();
  }
  @Override public void checkValidity() throws java.security.cert.CertificateExpiredException,java.security.cert.CertificateNotYetValidException {delegate.checkValidity();}
  @Override public void checkValidity(java.util.Date date) throws java.security.cert.CertificateExpiredException,java.security.cert.CertificateNotYetValidException {delegate.checkValidity(date);}
  @Override public int getVersion(){return delegate.getVersion();}
  @Override public java.math.BigInteger getSerialNumber(){return delegate.getSerialNumber();}
  @Override public java.security.Principal getIssuerDN(){return delegate.getIssuerDN();}
  @Override public java.security.Principal getSubjectDN(){return delegate.getSubjectDN();}
  @Override public java.util.Date getNotBefore(){return delegate.getNotBefore();}
  @Override public java.util.Date getNotAfter(){return delegate.getNotAfter();}
  @Override public byte[] getTBSCertificate() throws java.security.cert.CertificateEncodingException {return delegate.getTBSCertificate();}
  @Override public byte[] getSignature(){return delegate.getSignature();}
  @Override public String getSigAlgName(){return delegate.getSigAlgName();}
  @Override public String getSigAlgOID(){return delegate.getSigAlgOID();}
  @Override public byte @Nullable [] getSigAlgParams(){return delegate.getSigAlgParams();}
  @Override public boolean @Nullable [] getIssuerUniqueID(){return delegate.getIssuerUniqueID();}
  @Override public boolean @Nullable [] getSubjectUniqueID(){return delegate.getSubjectUniqueID();}
  @Override public boolean @Nullable [] getKeyUsage(){return delegate.getKeyUsage();}
  @Override public int getBasicConstraints(){return delegate.getBasicConstraints();}
  @Override public void verify(java.security.PublicKey key) throws java.security.cert.CertificateException,java.security.NoSuchAlgorithmException,java.security.InvalidKeyException,java.security.NoSuchProviderException,java.security.SignatureException {delegate.verify(key);}
  @Override public void verify(java.security.PublicKey key,String provider) throws java.security.cert.CertificateException,java.security.NoSuchAlgorithmException,java.security.InvalidKeyException,java.security.NoSuchProviderException,java.security.SignatureException {delegate.verify(key,provider);}
  @Override public String toString(){return "Counted TEST ONLY certificate";}
  @Override public java.security.PublicKey getPublicKey(){return delegate.getPublicKey();}
  @Override public Set<String> getCriticalExtensionOIDs(){return requireNonNull(delegate.getCriticalExtensionOIDs());}
  @Override public @Nullable Set<String> getNonCriticalExtensionOIDs(){return delegate.getNonCriticalExtensionOIDs();}
  @Override public byte @Nullable [] getExtensionValue(String oid){return delegate.getExtensionValue(oid);}
  @Override public boolean hasUnsupportedCriticalExtension(){return delegate.hasUnsupportedCriticalExtension();}
 }
 private static final class RecordingTrust extends X509ExtendedTrustManager {
  private final List<X509Certificate[]> chains=new ArrayList<>();
  private @Nullable X509Certificate rejectIssuer;
  private boolean rejectAll;
  @Override public void checkServerTrusted(X509Certificate[] chain,String authType,SSLEngine engine) throws CertificateException {
   assertEquals("RSA",authType);assertEquals("HTTPS",engine.getSSLParameters().getEndpointIdentificationAlgorithm());chains.add(chain.clone());
   if(rejectAll || chain.length>1 && chain[1].equals(rejectIssuer))throw new CertificateException("private TLS diagnostic");
  }
  @Override public X509Certificate[] getAcceptedIssuers(){return new X509Certificate[0];}
  @Override public void checkClientTrusted(X509Certificate[] chain,String authType){fail("client trust used");}
  @Override public void checkServerTrusted(X509Certificate[] chain,String authType){fail("legacy trust used");}
  @Override public void checkClientTrusted(X509Certificate[] chain,String authType,Socket socket){fail("client socket trust used");}
  @Override public void checkServerTrusted(X509Certificate[] chain,String authType,Socket socket){fail("server socket trust used");}
  @Override public void checkClientTrusted(X509Certificate[] chain,String authType,SSLEngine engine){fail("client engine trust used");}
 }
}
