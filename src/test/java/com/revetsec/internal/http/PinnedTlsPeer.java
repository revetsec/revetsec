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
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/** Exactly one test connection; closes the raw TCP socket to unblock all TLS fixture work. */
final class PinnedTlsPeer implements AutoCloseable {
 private final @NonNull ServerSocket server;
 private final @NonNull ExecutorService executor;
 private final @NonNull Future<@NonNull String> request;
 private volatile @Nullable Socket raw;
 private volatile @NonNull String serverName = "";
 private volatile @NonNull String negotiated = "";
 private volatile @NonNull String applicationProtocol = "";
 PinnedTlsPeer(@NonNull SSLContext context, @NonNull InetAddress address, @NonNull String protocol,
   @NonNull String response, boolean abrupt) throws IOException {
  this(context,address,0,protocol,response,abrupt);
 }
 PinnedTlsPeer(@NonNull SSLContext context, @NonNull InetAddress address, int port, @NonNull String protocol,
   @NonNull String response, boolean abrupt) throws IOException {
  this.server = new ServerSocket(port,1,address);
  this.executor = Executors.newSingleThreadExecutor();
  this.request = this.executor.submit(() -> {
   try (Socket accepted = this.server.accept()) {
    this.raw = accepted; accepted.setSoTimeout(5000);
    try (SSLSocket ssl = (SSLSocket)context.getSocketFactory().createSocket(accepted,(InputStream)null,true)) {
     ssl.setUseClientMode(false);ssl.setEnabledProtocols(new String[]{protocol});
     var options=ssl.getSSLParameters();options.setApplicationProtocols(new String[]{"http/1.1"});ssl.setSSLParameters(options);ssl.startHandshake();
     this.applicationProtocol=ssl.getApplicationProtocol();
     this.negotiated=ssl.getSession().getProtocol();
     if (ssl.getSession() instanceof ExtendedSSLSession extended) {
      for (var name:extended.getRequestedServerNames()) if(name instanceof SNIHostName host) this.serverName=host.getAsciiName();
     }
     ByteArrayOutputStream head=new ByteArrayOutputStream();int end=0;
     while(end<4) {
      int next=ssl.getInputStream().read();if(next<0 || head.size()>65536) throw new IOException("Test request incomplete.");
      head.write(next);end=next==(end%2==0?'\r':'\n')?end+1:0;
     }
     ssl.getOutputStream().write(response.getBytes(StandardCharsets.US_ASCII));ssl.getOutputStream().flush();
     if(abrupt) accepted.close();else {ssl.shutdownOutput();while(ssl.getInputStream().read()!=-1) {/* Drain client closure. */}}
     return head.toString(StandardCharsets.US_ASCII);
    }
   }
  });
 }
 int port() {return this.server.getLocalPort();}
 @NonNull String request() throws Exception {return this.request.get(10,TimeUnit.SECONDS);}
 @NonNull String serverName() {return this.serverName;}
 @NonNull String applicationProtocol() {return this.applicationProtocol;}
 @NonNull String negotiated() {return this.negotiated;}
 @Override public void close() throws Exception {
  @Nullable Socket accepted=this.raw;if(accepted!=null)accepted.close();this.server.close();
  this.executor.shutdownNow();if(!this.executor.awaitTermination(10,TimeUnit.SECONDS))throw new IOException("Owned TLS fixture did not stop.");
 }
}
