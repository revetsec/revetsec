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

package com.revetsec.testing;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http2.DefaultHttp2DataFrame;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame;
import io.netty.handler.codec.http2.Http2Frame;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2HeadersFrame;
import io.netty.handler.codec.http2.Http2MultiplexHandler;
import io.netty.handler.codec.http2.Http2ResetFrame;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolNames;
import io.netty.handler.ssl.ApplicationProtocolNegotiationHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import org.jspecify.annotations.Nullable;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/** A loopback ALPN h2 server with direct frame control for transport regression tests. */
public final class OAuthHttp2Server implements AutoCloseable {
	private final NioEventLoopGroup boss = new NioEventLoopGroup(1);
	private final NioEventLoopGroup worker = new NioEventLoopGroup(1);
	private final AtomicInteger resets = new AtomicInteger();
	private final AtomicInteger requests = new AtomicInteger();
	private final AtomicInteger connections = new AtomicInteger();
	private final AtomicInteger openStreams = new AtomicInteger();
	private final ReentrantLock streamLock = new ReentrantLock();
	private final Condition streamChanged = this.streamLock.newCondition();
	private final int responseBytes;
	private final boolean malformedFirst;
	private final boolean stalledFirst;
	private @Nullable Channel channel;

	private OAuthHttp2Server(int responseBytes, boolean malformedFirst, boolean stalledFirst) {
		this.responseBytes = responseBytes;
		this.malformedFirst = malformedFirst;
		this.stalledFirst = stalledFirst;
	}

	public static OAuthHttp2Server start(int responseBytes) throws Exception {
		OAuthHttp2Server server = new OAuthHttp2Server(responseBytes, false, false);
		server.bind();
		return server;
	}

	public static OAuthHttp2Server startWithMalformedFirstStatus() throws Exception {
		OAuthHttp2Server server = new OAuthHttp2Server(0, true, false);
		server.bind();
		return server;
	}

	public static OAuthHttp2Server startWithStalledFirstBody() throws Exception {
		OAuthHttp2Server server = new OAuthHttp2Server(0, false, true);
		server.bind();
		return server;
	}

	private void bind() throws Exception {
		Path tls = Path.of("src/test/resources/tls");
		SslContext ssl = SslContextBuilder.forServer(tls.resolve("server.pem").toFile(),
				tls.resolve("server-key.pem").toFile())
				.sslProvider(SslProvider.JDK)
				.applicationProtocolConfig(new ApplicationProtocolConfig(ApplicationProtocolConfig.Protocol.ALPN,
						ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
						ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
						ApplicationProtocolNames.HTTP_2)).build();
		this.channel = new ServerBootstrap().group(this.boss, this.worker)
				.channel(NioServerSocketChannel.class)
				.childHandler(new ChannelInitializer<SocketChannel>() {
					@Override protected void initChannel(SocketChannel child) {
						connections.incrementAndGet();
						child.pipeline().addLast(ssl.newHandler(child.alloc()));
						child.pipeline().addLast(new ApplicationProtocolNegotiationHandler("") {
							@Override protected void configurePipeline(ChannelHandlerContext context, String protocol) {
								if (!ApplicationProtocolNames.HTTP_2.equals(protocol)) {
									context.close();
									return;
								}
								context.pipeline().addLast(Http2FrameCodecBuilder.forServer().build());
								context.pipeline().addLast(new Http2MultiplexHandler(new ChannelInitializer<Channel>() {
									@Override protected void initChannel(Channel stream) {
											streamCountChanged(1);
										stream.pipeline().addLast(new SimpleChannelInboundHandler<Http2Frame>() {
											@Override public void channelInactive(ChannelHandlerContext streamContext)
													throws Exception {
												streamCountChanged(-1);
												super.channelInactive(streamContext);
											}
											@Override protected void channelRead0(ChannelHandlerContext streamContext,
													Http2Frame frame) {
												if (frame instanceof Http2ResetFrame) {
													resets.incrementAndGet();
												} else if (frame instanceof Http2HeadersFrame) {
													respond(streamContext, requests.incrementAndGet());
												}
											}
										});
									}
								}));
							}
						});
					}
				}).bind("127.0.0.1", 0).sync().channel();
	}

	private void respond(ChannelHandlerContext context, int requestNumber) {
		if (this.malformedFirst && requestNumber == 1) {
			context.writeAndFlush(new DefaultHttp2HeadersFrame(new DefaultHttp2Headers()
					.status("not-a-status"), true));
			return;
		}
		byte[] chunk = "{\"access_token\":\"ok\",\"token_type\":\"Bearer\"}".getBytes(StandardCharsets.UTF_8);
		context.write(new DefaultHttp2HeadersFrame(new DefaultHttp2Headers()
				.status("200").set("content-type", "application/json"), false));
		if (this.stalledFirst && requestNumber == 1) {
			context.writeAndFlush(new DefaultHttp2DataFrame(Unpooled.wrappedBuffer(new byte[]{'{'}), false));
			return;
		}
		if (this.responseBytes == 0) {
			context.writeAndFlush(new DefaultHttp2DataFrame(Unpooled.wrappedBuffer(chunk), true));
			return;
		}
		byte[] largeChunk = new byte[16_384];
		int remaining = this.responseBytes;
		while (remaining > 0) {
			int size = Math.min(largeChunk.length, remaining);
			remaining -= size;
			context.write(new DefaultHttp2DataFrame(Unpooled.copiedBuffer(largeChunk, 0, size), remaining == 0));
		}
		context.flush();
	}

	public URI uri(String path) {
		return URI.create("https://localhost:" + ((InetSocketAddress) requireNonNull(this.channel)
				.localAddress()).getPort() + path);
	}

	public int getRequestCount() { return this.requests.get(); }
	public int getResetCount() { return this.resets.get(); }
	public int getConnectionCount() { return this.connections.get(); }
	public int getOpenStreamCount() { return this.openStreams.get(); }

	public boolean awaitNoOpenStreams(Duration timeout) throws InterruptedException {
		long remaining = timeout.toNanos();
		this.streamLock.lock();
		try {
			while (this.openStreams.get() != 0) {
				if (remaining <= 0) return false;
				remaining = this.streamChanged.awaitNanos(remaining);
			}
			return true;
		} finally {
			this.streamLock.unlock();
		}
	}

	private void streamCountChanged(int delta) {
		this.streamLock.lock();
		try {
			this.openStreams.addAndGet(delta);
			this.streamChanged.signalAll();
		} finally {
			this.streamLock.unlock();
		}
	}

	@Override public void close() {
		if (this.channel != null) this.channel.close().awaitUninterruptibly(5, TimeUnit.SECONDS);
		this.worker.shutdownGracefully().awaitUninterruptibly(5, TimeUnit.SECONDS);
		this.boss.shutdownGracefully().awaitUninterruptibly(5, TimeUnit.SECONDS);
	}
}
