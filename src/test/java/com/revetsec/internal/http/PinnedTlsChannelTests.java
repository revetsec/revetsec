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

import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class PinnedTlsChannelTests {
 @TestFactory @NonNull Stream<@NonNull DynamicTest> realTlsHandlesSingleByteReadsWritesAndZeroReturns() {
  return Stream.of(1,7).flatMap(chunk->Stream.of("TLSv1.2","TLSv1.3").map(protocol->DynamicTest.dynamicTest(chunk+" "+protocol,()->{
   try(RawTlsServer server=RawTlsServer.start()) {
    server.script("/id",RawTlsServer.Script.fromString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"));
    SSLEngine engine=PinnedTlsContext.fromTrustStore(TestTls.trustStore()).createSSLEngine("localhost",server.getPort());
    engine.setUseClientMode(true);var parameters=engine.getSSLParameters();parameters.setEndpointIdentificationAlgorithm("HTTPS");parameters.setProtocols(new String[]{protocol});engine.setSSLParameters(parameters);
    Deadline deadline=Deadline.fromNow(Duration.ofSeconds(10));
    ChunkWire wire=new ChunkWire(server.getPort(),chunk,deadline);
    try(PinnedTlsChannel channel=new PinnedTlsChannel(wire,engine,deadline)) {
     channel.handshake();URI uri=server.uri("/id");channel.write(PinnedHttpsTransport.request(uri,false));
     assertEquals(200,PinnedHttpResponseReader.read(channel,5120,deadline,System.nanoTime()).status());
     assertTrue(wire.readCalls>100);assertTrue(wire.writeCalls>100);assertTrue(wire.readWaits>0);assertTrue(wire.writeWaits>0);
     channel.close();channel.close(); // Physical resources close once, including the enclosing resource block.
    }
    assertEquals(1,wire.closes);
    assertTrue(server.awaitConnectionCount(1,Duration.ofSeconds(10)));assertTrue(server.getConnections().get(0).awaitClientClose(Duration.ofSeconds(10)));
   }
  })));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> impossibleProviderStatesFailAndClose() {
  return Stream.of(Fault.values()).map(fault->DynamicTest.dynamicTest(fault.name(),()->{
   SSLEngine delegate=TestTls.clientSslContext().createSSLEngine("localhost",443);delegate.setUseClientMode(true);
   Deadline deadline=Deadline.fromNow(Duration.ofMillis(100));MemoryWire wire=new MemoryWire();wire.oversized=fault==Fault.EXCESSIVE_WIRE;wire.full=fault==Fault.FULL_UNDERFLOW;FaultEngine engine=new FaultEngine(delegate,fault,deadline);
   try {
    HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->{
     try(PinnedTlsChannel channel=new PinnedTlsChannel(wire,engine,deadline)){channel.handshake();}
    });
    assertEquals(fault==Fault.INTERRUPT_TASK?HttpExchangeException.Kind.INTERRUPTED:fault==Fault.EXPIRE_TASK?HttpExchangeException.Kind.TIMEOUT:HttpExchangeException.Kind.IO,failure.getKind());
    assertNull(failure.getCause());
    // Constructor rejection leaves ownership with the caller; every successfully constructed stream closes itself.
    if(fault==Fault.PACKET_CAP || fault==Fault.APPLICATION_CAP)wire.close();
    assertEquals(1,wire.closes);
    if(fault==Fault.WIRE_WRITE_CAP)assertEquals(PinnedTlsChannel.MAXIMUM_WIRE_BYTES,wire.written);
    if(fault==Fault.INTERRUPT_TASK)assertTrue(Thread.currentThread().isInterrupted());
   } finally {Thread.interrupted();}
  }));
 }
 @Test void rawTcpFinCannotSatisfyCloseDelimitedBody() throws Exception {
  try(PinnedTlsPeer peer=new PinnedTlsPeer(TestTls.serverSslContext(),InetAddress.getByAddress(new byte[]{127,0,0,1}),"TLSv1.3",
    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",true)) {
   URI uri=URI.create("https://localhost:"+peer.port()+"/id");
   HttpExchangeException failure=assertThrows(HttpExchangeException.class,()->PinnedHttpsTransport.exchange(uri,InetAddress.getByAddress(new byte[]{127,0,0,1}),PinnedHttpsTransport.request(uri,false),5120,PinnedTlsContext.fromTrustStore(TestTls.trustStore()),Deadline.fromNow(Duration.ofSeconds(10)),System.nanoTime()));
   assertEquals(HttpExchangeException.Kind.IO,failure.getKind());assertNull(failure.getCause());
  }
 }
 private enum Fault {PACKET_CAP,APPLICATION_CAP,WRAP_OVERFLOW,UNWRAP_OVERFLOW,WRAP_NO_PROGRESS,UNWRAP_NO_PROGRESS,NULL_TASK,LOOP_TASK,INTERRUPT_TASK,EXPIRE_TASK,RAW_EOF,EXCESSIVE_WIRE,WIRE_WRITE_CAP,HANDSHAKE_PLAINTEXT,HANDSHAKE_CLOSED,FULL_UNDERFLOW,WRAP_CLOSED,WRAP_LOOP,UNWRAP_LOOP}
 private static final class MemoryWire implements PinnedTlsChannel.Wire {
  private int closes,written;
  private boolean oversized,full;
  @Override public int read(@NonNull ByteBuffer target){if(this.full){int count=target.remaining();while(target.hasRemaining())target.put((byte)0);return count;}return this.oversized?PinnedTlsChannel.MAXIMUM_WIRE_BYTES+1:-1;}
  @Override public int write(@NonNull ByteBuffer source){int count=source.remaining();this.written+=count;source.position(source.limit());return count;}
  @Override public void await(int operation){throw new AssertionError("Unexpected synthetic wait.");}
  @Override public void close(){this.closes++;}
 }
 private static final class ChunkWire implements PinnedTlsChannel.Wire {
  private final @NonNull SocketChannel socket;
  private final @NonNull Selector selector;
  private final @NonNull SelectionKey key;
  private final int chunk;
  private final @NonNull Deadline deadline;
  private int readCalls,writeCalls,readWaits,writeWaits,closes;
  private ChunkWire(int port,int chunk,@NonNull Deadline deadline) throws Exception {
   this.chunk=chunk;this.deadline=deadline;this.socket=SocketChannel.open();
   this.socket.socket().connect(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}),port),5000);
   this.socket.configureBlocking(false);this.selector=Selector.open();this.key=this.socket.register(this.selector,0);
  }
  @Override public int read(@NonNull ByteBuffer target) throws IOException {
   if(++this.readCalls%3==1)return 0;ByteBuffer limited=target.duplicate();limited.limit(limited.position()+Math.min(this.chunk,limited.remaining()));
   int count=this.socket.read(limited);if(count>0)target.position(target.position()+count);return count;
  }
  @Override public int write(@NonNull ByteBuffer source) throws IOException {
   if(++this.writeCalls%3==1)return 0;ByteBuffer limited=source.duplicate();limited.limit(limited.position()+Math.min(this.chunk,limited.remaining()));
   int count=this.socket.write(limited);if(count>0)source.position(source.position()+count);return count;
  }
  @Override public void await(int operation) throws IOException,HttpExchangeException {
   if(operation==SelectionKey.OP_READ)this.readWaits++;else this.writeWaits++;
   PinnedHttpsTransport.checkBudget(this.deadline);this.key.interestOps(operation);this.selector.select(Math.max(1,this.deadline.remainingNanos()/1000000));
   this.selector.selectedKeys().clear();PinnedHttpsTransport.checkBudget(this.deadline);
  }
  @Override public void close() throws IOException {if(this.closes>0)return;this.closes++;try{this.socket.close();}finally{this.selector.close();}}
 }
 private static final class FaultEngine extends SSLEngine {
  private final @NonNull SSLEngine delegate;
  private final @NonNull Fault fault;
  private final @NonNull Deadline deadline;
  private boolean inboundDone;
  private FaultEngine(@NonNull SSLEngine delegate,@NonNull Fault fault,@NonNull Deadline deadline){this.delegate=delegate;this.fault=fault;this.deadline=deadline;}
  @Override public @NonNull SSLSession getSession(){
   if(this.fault==Fault.PACKET_CAP || this.fault==Fault.APPLICATION_CAP)
    return (SSLSession)Proxy.newProxyInstance(SSLSession.class.getClassLoader(),new Class<?>[]{SSLSession.class},(proxy,method,args)->{
     if(method.getName().equals(this.fault==Fault.PACKET_CAP?"getPacketBufferSize":"getApplicationBufferSize"))return PinnedTlsChannel.BUFFER_BYTES+1;
     return method.invoke(this.delegate.getSession(),args);
    });
   return this.delegate.getSession();
  }
  @Override public SSLEngineResult.@NonNull HandshakeStatus getHandshakeStatus(){
   return switch(this.fault){case NULL_TASK,LOOP_TASK,INTERRUPT_TASK,EXPIRE_TASK->SSLEngineResult.HandshakeStatus.NEED_TASK;
    case WRAP_OVERFLOW,WRAP_NO_PROGRESS,WIRE_WRITE_CAP,WRAP_CLOSED,WRAP_LOOP->SSLEngineResult.HandshakeStatus.NEED_WRAP;default->SSLEngineResult.HandshakeStatus.NEED_UNWRAP;};
  }
  @Override public @Nullable Runnable getDelegatedTask(){
   if(this.fault==Fault.NULL_TASK)return null;
   return ()->{if(this.fault==Fault.INTERRUPT_TASK)Thread.currentThread().interrupt();if(this.fault==Fault.EXPIRE_TASK)while(!this.deadline.isExpired())Thread.onSpinWait();};
  }
  @Override public @NonNull SSLEngineResult wrap(@NonNull ByteBuffer @NonNull [] src,int offset,int length,@NonNull ByteBuffer dst){
   if(this.fault==Fault.WRAP_CLOSED)return new SSLEngineResult(SSLEngineResult.Status.CLOSED,SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,0,0);
   if(this.fault==Fault.WRAP_LOOP)return new SSLEngineResult(SSLEngineResult.Status.OK,SSLEngineResult.HandshakeStatus.NEED_WRAP,0,0);
   if(this.fault==Fault.WIRE_WRITE_CAP){int n=dst.remaining();dst.position(dst.limit());return new SSLEngineResult(SSLEngineResult.Status.OK,SSLEngineResult.HandshakeStatus.NEED_WRAP,0,n);}
   return new SSLEngineResult(this.fault==Fault.WRAP_OVERFLOW?SSLEngineResult.Status.BUFFER_OVERFLOW:SSLEngineResult.Status.OK,SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,0,0);
  }
  @Override public @NonNull SSLEngineResult unwrap(@NonNull ByteBuffer src,@NonNull ByteBuffer @NonNull [] dst,int offset,int length){
   if(this.fault==Fault.HANDSHAKE_PLAINTEXT){dst[offset].put((byte)1);return new SSLEngineResult(SSLEngineResult.Status.OK,SSLEngineResult.HandshakeStatus.NEED_UNWRAP,0,1);}
   if(this.fault==Fault.HANDSHAKE_CLOSED){this.inboundDone=true;return new SSLEngineResult(SSLEngineResult.Status.CLOSED,SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,0,0);}
   if(this.fault==Fault.UNWRAP_LOOP)return new SSLEngineResult(SSLEngineResult.Status.OK,SSLEngineResult.HandshakeStatus.NEED_UNWRAP,0,0);
   return new SSLEngineResult(this.fault==Fault.UNWRAP_OVERFLOW?SSLEngineResult.Status.BUFFER_OVERFLOW:(this.fault==Fault.RAW_EOF || this.fault==Fault.EXCESSIVE_WIRE || this.fault==Fault.FULL_UNDERFLOW)?SSLEngineResult.Status.BUFFER_UNDERFLOW:SSLEngineResult.Status.OK,SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,0,0);
  }
  @Override public void beginHandshake(){}
  @Override public void closeInbound() throws SSLException{this.delegate.closeInbound();}
  @Override public boolean isInboundDone(){return this.inboundDone || this.delegate.isInboundDone();}
  @Override public void closeOutbound(){this.delegate.closeOutbound();}
  @Override public boolean isOutboundDone(){return this.delegate.isOutboundDone();}
  @Override public @NonNull String @NonNull [] getSupportedCipherSuites(){return this.delegate.getSupportedCipherSuites();}
  @Override public @NonNull String @NonNull [] getEnabledCipherSuites(){return this.delegate.getEnabledCipherSuites();}
  @Override public void setEnabledCipherSuites(@NonNull String @NonNull [] suites){this.delegate.setEnabledCipherSuites(suites);}
  @Override public @NonNull String @NonNull [] getSupportedProtocols(){return this.delegate.getSupportedProtocols();}
  @Override public @NonNull String @NonNull [] getEnabledProtocols(){return this.delegate.getEnabledProtocols();}
  @Override public void setEnabledProtocols(@NonNull String @NonNull [] protocols){this.delegate.setEnabledProtocols(protocols);}
  @Override public void setUseClientMode(boolean mode){this.delegate.setUseClientMode(mode);}
  @Override public boolean getUseClientMode(){return this.delegate.getUseClientMode();}
  @Override public void setNeedClientAuth(boolean value){this.delegate.setNeedClientAuth(value);}
  @Override public boolean getNeedClientAuth(){return this.delegate.getNeedClientAuth();}
  @Override public void setWantClientAuth(boolean value){this.delegate.setWantClientAuth(value);}
  @Override public boolean getWantClientAuth(){return this.delegate.getWantClientAuth();}
  @Override public void setEnableSessionCreation(boolean value){this.delegate.setEnableSessionCreation(value);}
  @Override public boolean getEnableSessionCreation(){return this.delegate.getEnableSessionCreation();}
 }
}
