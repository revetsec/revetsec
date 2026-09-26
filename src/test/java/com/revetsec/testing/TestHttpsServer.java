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

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * An in-process JDK {@link HttpsServer} on {@code 127.0.0.1} and an ephemeral port, presenting the TEST ONLY server
 * certificate ({@link TestTls}), for tests of Revetsec's outbound HTTP (plan 14.1; M1 plan, "Test helpers").
 * <p>
 * Each path answers with its {@link Script} ({@link #script(String, Script)}); a path without one answers 404 with
 * no body. Paths match {@link URI#getRawPath()} exactly. Every request is counted per path
 * ({@link #getHitCount(String)}, for plan 14.1's zero-hit assertions such as "the redirect target was never
 * requested") and recorded with its method, target, headers and body ({@link #getRequests()}). Each recorded
 * request also reports how its response ended ({@link RecordedRequest#awaitOutcome(Duration)}), so a test can check
 * that the server saw the client abort an oversized body.
 * <p>
 * Waits never sleep: {@link #awaitRequestCount(Integer, Duration)}, {@link Exchange#awaitServerClose()} and
 * {@link RecordedRequest#awaitOutcome(Duration)} all return when {@link #close()} runs.
 * <p>
 * {@link #close()} calls {@link ExecutorService#shutdownNow()} on the handler executor first and only then
 * {@link HttpsServer#stop(int) stop(0)}: stopping first hung for more than 10 s on JDK 25 and 27 (M1 plan). The JDK
 * server speaks only HTTP/1.1 and frames bodies itself; responses whose framing must be wrong on purpose belong on
 * {@link RawTlsServer}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class TestHttpsServer implements AutoCloseable {
	/**
	 * The most request-body bytes a {@link RecordedRequest} keeps; the rest is read and discarded.
	 */
	public static final int MAXIMUM_RECORDED_BODY_BYTES = 1024 * 1024;

	private static final Script NOT_FOUND = Script.fromResponse(Response.fromStatus(404));

	private final HttpsServer server;
	private final ExecutorService executor;
	private final URI baseUri;
	private final Map<String, Script> scripts = new ConcurrentHashMap<>();
	private final Map<String, AtomicInteger> hitCounts = new ConcurrentHashMap<>();
	private final List<RecordedRequest> requests = new CopyOnWriteArrayList<>();
	private final CountDownLatch closeLatch = new CountDownLatch(1);
	private final AtomicBoolean closed = new AtomicBoolean();
	private final ReentrantLock lock = new ReentrantLock();
	private final Condition requestRecordedOrClosed = this.lock.newCondition();

	private TestHttpsServer(HttpsServer server, ExecutorService executor) {
		this.server = server;
		this.executor = executor;
		this.baseUri = URI.create("https://127.0.0.1:" + server.getAddress().getPort());
	}

	/**
	 * Binds a new server to {@code 127.0.0.1} on an ephemeral port and starts it.
	 *
	 * @return the running server; close it when done
	 * @throws IOException if the server cannot bind
	 */
	public static TestHttpsServer start() throws IOException {
		InetSocketAddress address = new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), 0);
		HttpsServer server = HttpsServer.create(address, 0);
		ExecutorService executor = Executors.newCachedThreadPool(new DaemonThreadFactory("revetsec-test-https"));
		try {
			server.setHttpsConfigurator(new HttpsConfigurator(TestTls.serverSslContext()));
			server.setExecutor(executor);
			TestHttpsServer testServer = new TestHttpsServer(server, executor);
			server.createContext("/", testServer::handle);
			server.start();
			return testServer;
		} catch (RuntimeException e) {
			executor.shutdownNow();
			server.stop(0);
			throw e;
		}
	}

	/**
	 * Sets the script for {@code path}, replacing any earlier one. It applies to requests that arrive afterward.
	 *
	 * @param path the exact raw path, starting with {@code /}
	 * @param script how to answer
	 * @return this server
	 */
	public TestHttpsServer script(String path, Script script) {
		this.scripts.put(requirePath(path), requireNonNull(script));
		return this;
	}

	/**
	 * The server's origin, such as {@code https://127.0.0.1:50123}.
	 *
	 * @return the base URI, with no path
	 */
	public URI getBaseUri() {
		return this.baseUri;
	}

	/**
	 * The URI of {@code path} on this server.
	 *
	 * @param path a raw path starting with {@code /}, optionally with a query
	 * @return the absolute URI
	 */
	public URI uri(String path) {
		return URI.create(this.baseUri + requirePath(path));
	}

	/**
	 * The bound port.
	 *
	 * @return the port
	 */
	public Integer getPort() {
		return this.baseUri.getPort();
	}

	/**
	 * How many requests arrived for {@code path}, scripted or not.
	 *
	 * @param path the exact raw path
	 * @return the count, zero if none
	 */
	public Integer getHitCount(String path) {
		@Nullable AtomicInteger hitCount = this.hitCounts.get(requireNonNull(path));
		return hitCount == null ? 0 : hitCount.get();
	}

	/**
	 * Every recorded request, in arrival order.
	 *
	 * @return an immutable snapshot
	 */
	public List<RecordedRequest> getRequests() {
		return List.copyOf(this.requests);
	}

	/**
	 * The recorded requests for {@code path}, in arrival order.
	 *
	 * @param path the exact raw path
	 * @return an immutable snapshot
	 */
	public List<RecordedRequest> getRequests(String path) {
		requireNonNull(path);
		return this.requests.stream().filter(request -> request.getPath().equals(path)).toList();
	}

	/**
	 * Waits until at least {@code count} requests have been recorded, the timeout passes, or the server closes.
	 *
	 * @param count how many requests to wait for
	 * @param timeout the longest wait
	 * @return whether at least {@code count} requests were recorded
	 * @throws InterruptedException if interrupted while waiting
	 */
	public Boolean awaitRequestCount(Integer count, Duration timeout) throws InterruptedException {
		requireNonNull(count);
		long remaining = timeout.toNanos();
		this.lock.lock();
		try {
			while (this.requests.size() < count) {
				if (this.closed.get() || remaining <= 0)
					return false;
				remaining = this.requestRecordedOrClosed.awaitNanos(remaining);
			}
			return true;
		} finally {
			this.lock.unlock();
		}
	}

	/**
	 * Stops the server: the handler executor first ({@code shutdownNow}, which interrupts running scripts), then
	 * {@code stop(0)}. Every wait returns, and every request whose response had not finished reports
	 * {@link Outcome#SERVER_CLOSED}. Calling it again does nothing.
	 */
	@Override
	public void close() {
		if (!this.closed.compareAndSet(false, true))
			return;
		this.closeLatch.countDown();
		signalWaiters();
		this.executor.shutdownNow();
		this.server.stop(0);
		for (RecordedRequest request : this.requests)
			request.finish(Outcome.SERVER_CLOSED);
	}

	private void handle(HttpExchange httpExchange) {
		@Nullable RecordedRequest request = null;
		try {
			URI requestUri = httpExchange.getRequestURI();
			String path = requestUri.getRawPath() == null ? "" : requestUri.getRawPath();
			this.hitCounts.computeIfAbsent(path, ignored -> new AtomicInteger()).incrementAndGet();

			byte[] body;
			try (InputStream requestBody = httpExchange.getRequestBody()) {
				body = requestBody.readNBytes(MAXIMUM_RECORDED_BODY_BYTES);
				requestBody.transferTo(OutputStream.nullOutputStream());
			}
			request = new RecordedRequest(httpExchange.getRequestMethod(), requestUri, path,
					copyOf(httpExchange.getRequestHeaders()), body);
			this.requests.add(request);
			signalWaiters();

			this.scripts.getOrDefault(path, NOT_FOUND).run(new Exchange(this, httpExchange, request));
			// A script that returns because the server closed (Exchange#awaitServerClose) did not complete.
			request.finish(this.closed.get() ? Outcome.SERVER_CLOSED : Outcome.COMPLETED);
		} catch (IOException e) {
			if (request != null)
				request.finish(this.closed.get() ? Outcome.SERVER_CLOSED : Outcome.CLIENT_ABORTED);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			if (request != null)
				request.finish(Outcome.SERVER_CLOSED);
		} catch (RuntimeException | Error e) {
			// An Error is recorded too: a failed JUnit assertion inside a script is one, and losing it would leave the
			// request UNFINISHED and the failure invisible to the test.
			if (request != null) {
				request.recordScriptFailure(e);
				request.finish(Outcome.SCRIPT_FAILED);
			}
			sendServerErrorIfNothingWasSent(httpExchange);
			if (e instanceof VirtualMachineError)
				throw e;
		} finally {
			httpExchange.close();
		}
	}

	private static void sendServerErrorIfNothingWasSent(HttpExchange httpExchange) {
		if (httpExchange.getResponseCode() != -1)
			return;
		try {
			httpExchange.sendResponseHeaders(500, -1);
		} catch (IOException e) {
			// The client is gone, and the caller closes the exchange next either way.
			return;
		}
	}

	private void signalWaiters() {
		this.lock.lock();
		try {
			this.requestRecordedOrClosed.signalAll();
		} finally {
			this.lock.unlock();
		}
	}

	private static Map<String, List<String>> copyOf(Headers headers) {
		Map<String, List<String>> copy = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
		for (Map.Entry<String, List<String>> header : headers.entrySet())
			copy.computeIfAbsent(header.getKey(), ignored -> new ArrayList<>()).addAll(header.getValue());
		copy.replaceAll((name, values) -> List.copyOf(values));
		return Collections.unmodifiableMap(copy);
	}

	private static String requirePath(String path) {
		requireNonNull(path);
		if (!path.startsWith("/"))
			throw new IllegalArgumentException("A path starts with /: " + path);
		return path;
	}

	/**
	 * How a path answers. A script runs on a server thread, concurrently with itself when requests overlap, so an
	 * implementation must be thread-safe. It may block; {@link TestHttpsServer#close()} interrupts it and releases
	 * {@link Exchange#awaitServerClose()}. A script that throws a {@link RuntimeException} or an {@link Error} (a
	 * failed assertion included) is answered with {@code 500} if it had sent nothing, and its request reports
	 * {@link Outcome#SCRIPT_FAILED} with the throwable ({@link RecordedRequest#getScriptFailure()}).
	 */
	@ThreadSafe
	@FunctionalInterface
	public interface Script {
		/**
		 * Answers one request.
		 *
		 * @param exchange the request and the means to answer it
		 * @throws IOException if writing fails, which the server records as {@link Outcome#CLIENT_ABORTED} (or
		 * {@link Outcome#SERVER_CLOSED} while closing)
		 * @throws InterruptedException if interrupted, as {@link TestHttpsServer#close()} does
		 */
		void run(Exchange exchange) throws IOException, InterruptedException;

		/**
		 * Always sends {@code response}.
		 *
		 * @param response the response
		 * @return the script
		 */
		static Script fromResponse(Response response) {
			requireNonNull(response);
			return exchange -> exchange.send(response);
		}

		/**
		 * Sends a redirect with an empty body.
		 *
		 * @param status the 3xx status
		 * @param location the {@code Location} header value
		 * @return the script
		 */
		static Script fromRedirect(Integer status, String location) {
			return fromResponse(Response.withStatus(status).header("Location", location).build());
		}

		/**
		 * Sends {@code status} and {@code headers} declaring a 1 MiB {@code Content-Length} it never sends, then sends
		 * nothing more until the server closes: a response that stalls after its headers. Because the declared length
		 * is never met, the JDK server drops the connection when the server closes, so a client still reading the body
		 * always fails; a chunked body would instead end cleanly if the released script returned before
		 * {@code stop(0)}. The JDK server gives a script no way to notice the client
		 * closing a connection it is not writing to, so the request's outcome stays {@link Outcome#UNFINISHED} until
		 * the server closes. A test that must see the client close a stalled response uses
		 * {@link RawTlsServer.Script.Builder#stall()}.
		 *
		 * @param status the status
		 * @param headers header names and values
		 * @return the script
		 */
		static Script fromStalledResponse(Integer status, Map<String, List<String>> headers) {
			requireNonNull(status);
			Map<String, List<String>> headersCopy = Response.copyHeaders(headers);
			return exchange -> {
				HttpExchange httpExchange = exchange.getHttpExchange();
				Headers responseHeaders = httpExchange.getResponseHeaders();
				headersCopy.forEach((name, values) -> values.forEach(value -> responseHeaders.add(name, value)));
				httpExchange.sendResponseHeaders(status, 1_048_576);
				httpExchange.getResponseBody().flush();
				exchange.awaitServerClose();
			};
		}
	}

	/**
	 * One request being answered: the recorded request, the JDK exchange for full control, and helpers.
	 */
	@NotThreadSafe
	public static final class Exchange {
		private final TestHttpsServer server;
		private final HttpExchange httpExchange;
		private final RecordedRequest request;

		private Exchange(TestHttpsServer server, HttpExchange httpExchange, RecordedRequest request) {
			this.server = server;
			this.httpExchange = httpExchange;
			this.request = request;
		}

		/**
		 * The request, already recorded; its body has been read.
		 *
		 * @return the request
		 */
		public RecordedRequest getRequest() {
			return this.request;
		}

		/**
		 * The JDK exchange, for scripts that need to write their own headers and body.
		 *
		 * @return the exchange
		 */
		public HttpExchange getHttpExchange() {
			return this.httpExchange;
		}

		/**
		 * Sends {@code response}: its headers, then its body with the framing it names.
		 *
		 * @param response the response
		 * @throws IOException if writing fails
		 */
		public void send(Response response) throws IOException {
			requireNonNull(response);
			Headers headers = this.httpExchange.getResponseHeaders();
			response.getHeaders().forEach((name, values) -> values.forEach(value -> headers.add(name, value)));
			byte[] body = response.body;
			long length = response.getFraming() == Framing.CHUNKED ? 0 : body.length == 0 ? -1 : body.length;
			this.httpExchange.sendResponseHeaders(response.getStatus(), length);
			try (OutputStream responseBody = this.httpExchange.getResponseBody()) {
				if (body.length > 0)
					responseBody.write(body);
			}
		}

		/**
		 * Blocks until the server closes. Scripts use it to stall a response without sleeping.
		 *
		 * @throws InterruptedException if interrupted, as {@link TestHttpsServer#close()} does
		 */
		public void awaitServerClose() throws InterruptedException {
			this.server.closeLatch.await();
		}
	}

	/**
	 * How a response body is framed by the JDK server.
	 */
	@Immutable
	public enum Framing {
		/**
		 * {@code Content-Length} (zero, with no body, for an empty body).
		 */
		FIXED_LENGTH,
		/**
		 * {@code Transfer-Encoding: chunked}.
		 */
		CHUNKED
	}

	/**
	 * A canned response.
	 */
	@Immutable
	public static final class Response {
		private final Integer status;
		private final Map<String, List<String>> headers;
		private final byte[] body;
		private final Framing framing;

		private Response(Builder builder) {
			this.status = builder.status;
			this.headers = copyHeaders(builder.headers);
			this.body = builder.body.clone();
			this.framing = builder.framing;
		}

		/**
		 * Starts a response with {@code status}, no headers and an empty body.
		 *
		 * @param status the status, 100 to 999
		 * @return a new builder
		 */
		public static Builder withStatus(Integer status) {
			return new Builder(status);
		}

		/**
		 * A response with {@code status}, no extra headers and an empty body.
		 *
		 * @param status the status, 100 to 999
		 * @return the response
		 */
		public static Response fromStatus(Integer status) {
			return withStatus(status).build();
		}

		/**
		 * A response with {@code status}, {@code Content-Type: application/json} and {@code json} as its UTF-8 body.
		 *
		 * @param status the status, 100 to 999
		 * @param json the body
		 * @return the response
		 */
		public static Response fromJson(Integer status, String json) {
			return withStatus(status).header("Content-Type", "application/json").body(json).build();
		}

		/**
		 * The status.
		 *
		 * @return the status
		 */
		public Integer getStatus() {
			return this.status;
		}

		/**
		 * The headers the script adds; the JDK server adds {@code Date} and the framing headers itself.
		 *
		 * @return header names and values, in insertion order
		 */
		public Map<String, List<String>> getHeaders() {
			return this.headers;
		}

		/**
		 * The body.
		 *
		 * @return a copy of the body
		 */
		public byte[] getBody() {
			return this.body.clone();
		}

		/**
		 * The framing.
		 *
		 * @return the framing
		 */
		public Framing getFraming() {
			return this.framing;
		}

		private static Map<String, List<String>> copyHeaders(Map<String, List<String>> headers) {
			Map<String, List<String>> copy = new LinkedHashMap<>();
			headers.forEach((name, values) -> copy.put(requireNonNull(name), List.copyOf(values)));
			return Collections.unmodifiableMap(copy);
		}

		/**
		 * Builds a {@link Response}.
		 */
		@NotThreadSafe
		public static final class Builder {
			private final Integer status;
			private final Map<String, List<String>> headers = new LinkedHashMap<>();
			private byte[] body = new byte[0];
			private Framing framing = Framing.FIXED_LENGTH;

			private Builder(Integer status) {
				requireNonNull(status);
				if (status < 100 || status > 999)
					throw new IllegalArgumentException("Status out of range: " + status);
				this.status = status;
			}

			/**
			 * Adds a header value; calling it again with the same name adds another value.
			 *
			 * @param name the header name
			 * @param value the header value
			 * @return this builder
			 */
			public Builder header(String name, String value) {
				requireNonNull(name);
				requireNonNull(value);
				this.headers.computeIfAbsent(name, ignored -> new ArrayList<>()).add(value);
				return this;
			}

			/**
			 * The body bytes.
			 *
			 * @param body the body, or {@code null} for none
			 * @return this builder
			 */
			public Builder body(byte @Nullable [] body) {
				this.body = body == null ? new byte[0] : body.clone();
				return this;
			}

			/**
			 * The body, encoded as UTF-8.
			 *
			 * @param body the body, or {@code null} for none
			 * @return this builder
			 */
			public Builder body(@Nullable String body) {
				this.body = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
				return this;
			}

			/**
			 * The framing.
			 *
			 * @param framing the framing, or {@code null} for {@link Framing#FIXED_LENGTH}
			 * @return this builder
			 */
			public Builder framing(@Nullable Framing framing) {
				this.framing = framing == null ? Framing.FIXED_LENGTH : framing;
				return this;
			}

			/**
			 * Builds the response.
			 *
			 * @return the response
			 */
			public Response build() {
				return new Response(this);
			}
		}
	}

	/**
	 * How the response to a recorded request ended.
	 */
	@Immutable
	public enum Outcome {
		/**
		 * The script finished while the server was open.
		 */
		COMPLETED,
		/**
		 * Writing the response failed while the server was open: the client closed the connection.
		 */
		CLIENT_ABORTED,
		/**
		 * The server closed before the script finished, or the script ended because the server closed.
		 */
		SERVER_CLOSED,
		/**
		 * The script threw a runtime exception or an error, such as a failed assertion
		 * ({@link RecordedRequest#getScriptFailure()}).
		 */
		SCRIPT_FAILED,
		/**
		 * Returned by {@link RecordedRequest#awaitOutcome(Duration)} when the response had not ended in time.
		 */
		UNFINISHED
	}

	/**
	 * A request as the server received it, and how its response ended.
	 */
	@ThreadSafe
	public static final class RecordedRequest {
		private final String method;
		private final URI uri;
		private final String path;
		private final Map<String, List<String>> headers;
		private final byte[] body;
		private final CompletableFuture<Outcome> outcome = new CompletableFuture<>();
		private final AtomicReference<@Nullable Throwable> scriptFailure = new AtomicReference<>();

		private RecordedRequest(String method, URI uri, String path, Map<String, List<String>> headers, byte[] body) {
			this.method = method;
			this.uri = uri;
			this.path = path;
			this.headers = headers;
			this.body = body;
		}

		/**
		 * The request method.
		 *
		 * @return the method, such as {@code GET}
		 */
		public String getMethod() {
			return this.method;
		}

		/**
		 * The request target as received: raw path and query.
		 *
		 * @return the target
		 */
		public URI getUri() {
			return this.uri;
		}

		/**
		 * The raw path, which selected the script.
		 *
		 * @return the path
		 */
		public String getPath() {
			return this.path;
		}

		/**
		 * The request headers, looked up case-insensitively.
		 *
		 * @return header names and values
		 */
		public Map<String, List<String>> getHeaders() {
			return this.headers;
		}

		/**
		 * The first value of the header {@code name}.
		 *
		 * @param name the header name, in any case
		 * @return the value, or empty if the header is absent
		 */
		public Optional<String> getHeader(String name) {
			@Nullable List<String> values = this.headers.get(requireNonNull(name));
			return values == null || values.isEmpty() ? Optional.empty() : Optional.of(values.get(0));
		}

		/**
		 * The request body, up to {@value TestHttpsServer#MAXIMUM_RECORDED_BODY_BYTES} bytes.
		 *
		 * @return a copy of the body
		 */
		public byte[] getBody() {
			return this.body.clone();
		}

		/**
		 * The request body decoded as UTF-8.
		 *
		 * @return the body text
		 */
		public String getBodyAsString() {
			return new String(this.body, StandardCharsets.UTF_8);
		}

		/**
		 * Waits for the response to end.
		 *
		 * @param timeout the longest wait
		 * @return how it ended, or {@link Outcome#UNFINISHED} if it had not ended in time
		 * @throws InterruptedException if interrupted while waiting
		 */
		public Outcome awaitOutcome(Duration timeout) throws InterruptedException {
			try {
				return this.outcome.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
			} catch (TimeoutException e) {
				return Outcome.UNFINISHED;
			} catch (ExecutionException e) {
				throw new IllegalStateException("The outcome future never fails", e);
			}
		}

		/**
		 * What the script threw, if its outcome is {@link Outcome#SCRIPT_FAILED}.
		 *
		 * @return the runtime exception or error, or empty
		 */
		public Optional<Throwable> getScriptFailure() {
			return Optional.ofNullable(this.scriptFailure.get());
		}

		@Override
		public String toString() {
			return "RecordedRequest[" + this.method + " " + this.uri + "]";
		}

		private void finish(Outcome outcome) {
			this.outcome.complete(outcome);
		}

		private void recordScriptFailure(Throwable failure) {
			this.scriptFailure.compareAndSet(null, failure);
		}
	}
}
