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

import com.sun.net.httpserver.HttpServer;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static java.util.Objects.requireNonNull;

/** Child-only global-property/probe qualification. Emits fixed structural success facts, never runtime key bytes. */
public final class PinnedTlsIsolationCase {
 private PinnedTlsIsolationCase() {}
 public static void main(@NonNull String @NonNull [] arguments) throws Exception {
  if(arguments.length!=2)throw new IllegalArgumentException("Two isolated test arguments required.");
  if(arguments[0].equals("provider")){provider();System.out.println("PASS unsupported-provider-fails-closed");return;}
  boolean full=arguments[0].equals("namespace");
  Security.setProperty("ocsp.enable","true");
  require("true".equals(System.getProperty("com.sun.security.enableAIAcaIssuers")),"AIA switch missing");
  require("true".equals(System.getProperty("com.sun.net.ssl.checkRevocation")),"TLS revocation switch missing");
  require("true".equals(System.getProperty("com.sun.security.enableCRLDP")),"CRL switch missing");
  ProxySelector.setDefault(new ProxySelector(){
   @Override public @NonNull List<@NonNull Proxy> select(@NonNull URI uri){throw new AssertionError("Proxy selector was invoked.");}
   @Override public void connectFailed(@NonNull URI uri,@NonNull SocketAddress address,@NonNull IOException failure){throw new AssertionError("Proxy fallback was invoked.");}
  });
  AtomicInteger hits=new AtomicInteger();
  HttpServer probe=HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),0),0);
  Security.setProperty("com.sun.security.allowedAIALocations","http://127.0.0.1:"+probe.getAddress().getPort()+"/");
  Path runtime=Path.of(arguments[1]);Files.createDirectories(runtime);
  try {
   PinnedTlsPki pki=new PinnedTlsPki(runtime,probe.getAddress().getPort());byte[] issuer=pki.intermediateBytes();
   probe.createContext("/",exchange->{hits.incrementAndGet();byte[] body=exchange.getRequestURI().getPath().equals("/issuer")?issuer:new byte[0];
    exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);exchange.close();});probe.start();
   InetAddress address=InetAddress.getByAddress(full?new byte[]{8,8,8,8}:new byte[]{127,0,0,1});
   if(full){Path trust=runtime.resolve("trust.p12");pki.writeTrustStore(trust);System.setProperty("javax.net.ssl.trustStore",trust.toString());System.setProperty("javax.net.ssl.trustStorePassword","changeit");System.setProperty("javax.net.ssl.trustStoreType","PKCS12");}
   for(String protocol:List.of("TLSv1.2","TLSv1.3")) {
    try(PinnedTlsPeer peer=new PinnedTlsPeer(pki.server(true),address,protocol,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",false)) {
     URI uri=URI.create("https://"+(full?"metadata.revetsec.com":"localhost")+":"+peer.port()+"/id?x=%2B");
     RawResponse result;
     if(full)result=PinnedHttpsTransport.fetch(uri,(host,budget)->List.of(address),16,5120,Duration.ofSeconds(10),Deadline.fromNow(Duration.ofSeconds(10)));
     else result=local(uri,address,PinnedTlsContext.fromTrustStore(pki.trustStore()));
     require(result.status()==200 && new String(result.body(),StandardCharsets.US_ASCII).equals("{}"),"Pinned body failure");
     String request=peer.request();require(request.startsWith("GET /id?x=%2B HTTP/1.1\r\nHost: "+uri.getRawAuthority()+"\r\n"),"Host/target changed");
     require(peer.serverName().equals(full?"metadata.revetsec.com":"localhost"),"SNI changed");require(peer.negotiated().equals(protocol),"TLS version changed");require(peer.applicationProtocol().equals("http/1.1"),"HTTP ALPN changed");
    }
   }
   if(full) {
    InetAddress second=InetAddress.getByAddress(new byte[]{8,8,4,4});AtomicInteger resolutions=new AtomicInteger();int port;
    try(PinnedTlsPeer peer=new PinnedTlsPeer(pki.server(true),address,"TLSv1.3","HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",false)) {
     port=peer.port();URI uri=URI.create("https://metadata.revetsec.com:"+port+"/same-id");
     boolean refused=false;try{PinnedHttpsTransport.fetch(uri,(host,budget)->List.of(address,InetAddress.getLoopbackAddress()),16,5120,Duration.ofSeconds(10),Deadline.fromNow(Duration.ofSeconds(10)));}catch(HttpExchangeException failure){refused=failure.getKind()==HttpExchangeException.Kind.URI_REJECTED;}require(refused,"Mixed unsafe answers accepted");
     require(PinnedHttpsTransport.fetch(uri,(host,budget)->{resolutions.incrementAndGet();return List.of(address);},16,5120,Duration.ofSeconds(10),Deadline.fromNow(Duration.ofSeconds(10))).status()==200,"First answer failed");peer.request();
    }
    try(PinnedTlsPeer peer=new PinnedTlsPeer(pki.server(true),second,port,"TLSv1.3","HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n[]",false)) {
     URI uri=URI.create("https://metadata.revetsec.com:"+port+"/same-id");
     RawResponse result=PinnedHttpsTransport.fetch(uri,(host,budget)->{resolutions.incrementAndGet();return List.of(second);},16,5120,Duration.ofSeconds(10),Deadline.fromNow(Duration.ofSeconds(10)));
     require(new String(result.body(),StandardCharsets.US_ASCII).equals("[]"),"Old resolved peer reused");peer.request();require(peer.serverName().equals("metadata.revetsec.com"),"Changed peer lost SNI");
    }
    require(resolutions.get()==2,"Resolver repeated within a fetch or skipped on a new fetch");
   }
   require(hits.get()==0,"Pinned complete chain caused secondary retrieval");
   try(PinnedTlsPeer peer=new PinnedTlsPeer(pki.server(false),address,"TLSv1.3","",false)) {
    URI uri=URI.create("https://"+(full?"metadata.revetsec.com":"localhost")+":"+peer.port()+"/id");
    boolean failed=false;try {if(full)PinnedHttpsTransport.fetch(uri,(host,budget)->List.of(address),16,5120,Duration.ofSeconds(10),Deadline.fromNow(Duration.ofSeconds(10)));else local(uri,address,PinnedTlsContext.fromTrustStore(pki.trustStore()));}
    catch(HttpExchangeException failure){failed=failure.getKind()==HttpExchangeException.Kind.IO;require(failure.getCause()==null,"Remote certificate cause escaped");}
    require(failed,"Missing intermediate accepted");
   }
   require(hits.get()==0,"Pinned incomplete chain caused secondary retrieval");
   // Positive AIA control: ordinary PKIX with revocation disabled really fetches this missing intermediate.
   TrustManagerFactory ordinary=TrustManagerFactory.getInstance("PKIX");
   X509Certificate root=(X509Certificate)requireNonNull(pki.trustStore().getCertificate("root"));
   PKIXBuilderParameters parameters=new PKIXBuilderParameters(Set.of(new TrustAnchor(root,null)),null);parameters.setRevocationEnabled(false);
   ordinary.init(new CertPathTrustManagerParameters(parameters));SSLContext normal=SSLContext.getInstance("TLS");normal.init(null,ordinary.getTrustManagers(),null);
   // The positive stock control needs its URL connection; the specialized path above proved proxy exclusion.
   ProxySelector.setDefault(null);
   try(PinnedTlsPeer peer=new PinnedTlsPeer(pki.server(false),address,"TLSv1.3","HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",false)) {
    URI uri=URI.create("https://localhost:"+peer.port()+"/id");
    try(javax.net.ssl.SSLSocket socket=(javax.net.ssl.SSLSocket)normal.getSocketFactory().createSocket()) {
     var options=socket.getSSLParameters();options.setEndpointIdentificationAlgorithm("HTTPS");
     options.setServerNames(List.of(new javax.net.ssl.SNIHostName("localhost")));socket.setSSLParameters(options);
     socket.connect(new InetSocketAddress(address,peer.port()),5000);socket.setSoTimeout(5000);socket.startHandshake();
     socket.getOutputStream().write(PinnedHttpsTransport.request(uri,false));socket.getOutputStream().flush();
     require(new String(socket.getInputStream().readAllBytes(),StandardCharsets.US_ASCII).endsWith("{}"),"AIA positive control failed");
    }
    peer.request();
   }
   require(hits.get()>0,"AIA probe was not exercised by stock control");
   require("true".equals(Security.getProperty("ocsp.enable")) && "true".equals(System.getProperty("com.sun.net.ssl.checkRevocation")),"Global revocation properties changed");
   System.out.println("PASS pinned-complete-incomplete-no-secondary-fetch TLSv1.2 TLSv1.3 SNI Host proxy-exclusion AIA-positive-control"+(full?" fresh-resolution changed-numeric-peer mixed-answer-rejection":"")+"");
  } finally {probe.stop(0);}
 }
 private static @NonNull RawResponse local(@NonNull URI uri,@NonNull InetAddress address,@NonNull SSLContext context) throws Exception {
  return PinnedHttpsTransport.exchange(uri,address,PinnedHttpsTransport.request(uri,false),5120,context,Deadline.fromNow(Duration.ofSeconds(10)),System.nanoTime());
 }
 private static void require(boolean condition,@NonNull String message){if(!condition)throw new AssertionError(message);}
 private static void provider() throws Exception {
  Security.insertProviderAt(new Unsupported(),1);
  HttpExchangeException failure;
  try {PinnedTlsContext.fromTrustStore(TestTls.trustStore());throw new AssertionError("Unsupported TLS provider accepted.");}
  catch(HttpExchangeException expected){failure=expected;}
  require(failure.getKind()==HttpExchangeException.Kind.PINNED_TLS_UNAVAILABLE && failure.getCause()==null,"Wrong provider failure");
 }
 public static final class Unsupported extends Provider {
  private static final long serialVersionUID=1L;
  public Unsupported(){super("RevetsecTESTONLY", "1.0", "Isolated unsupported test provider");put("TrustManagerFactory.PKIX",Factory.class.getName());}
 }
 public static final class Factory extends TrustManagerFactorySpi {
  @Override protected void engineInit(@Nullable KeyStore store){throw new AssertionError("Unsupported provider initialized.");}
  @Override protected void engineInit(@NonNull ManagerFactoryParameters parameters){throw new AssertionError("Unsupported provider initialized.");}
  @Override protected @NonNull TrustManager @NonNull [] engineGetTrustManagers(){throw new AssertionError("Unsupported provider used.");}
 }
}
