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

import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;

/**
 * A TLS server on {@code 127.0.0.1} and an ephemeral port that answers each request with exact, scripted bytes, for
 * the responses the JDK {@code HttpsServer} will not send: framing anomalies, close-delimited bodies, HTTP/1.0,
 * headers of 384 KiB and more, and trickled or stalled bodies (M1 plan, "Test helpers"; G6-7; exit criteria 10 to
 * 12). It presents the TEST ONLY server certificate ({@link TestTls}).
 * <p>
 * <strong>Scripts.</strong> Each path answers with its {@link Script} ({@link #script(String, Script)}); a path
 * without one gets {@code 404} with {@code Connection: close}. A script is a list of steps: write bytes, trickle
 * bytes in timed chunks, stall, end the stream (TLS {@code close_notify}, then keep reading), or close the
 * connection. Trickled chunks are paced by the server's own {@link ScheduledExecutorService}, the one timed wait the
 * test policy allows (A-2); the test itself never sleeps.
 * <p>
 * <strong>Closure.</strong> After each response the server keeps reading the connection. Another request is served
 * the same way (keep-alive). End of stream, a reset, or a failed write while the server is open means the client
 * closed the connection, which is what every rejection case must show (exit criterion 12, and the plan's risk that a
 * callback which throws leaves the connection open). {@link Connection#awaitClientClose(Duration)} reports it.
 * Each request also reports whether its response was written in full or the client ended it early
 * ({@link RecordedRequest#awaitOutcome(Duration)}), which tells an aborted close-delimited body (exit criterion 10)
 * from one the client read to its end before closing. Every wait returns when the server closes.
 * <p>
 * Once a server took 3.1 s to notice an abort on JDK 25, so give server-side abort checks about 10 s (on 25 and 27
 * the JDK client closes an abandoned connection about 3 s after the body stream is closed). One JDK behavior to plan
 * around: when the JDK client refuses a response head it cannot parse with a {@code ProtocolException} (a header
 * section over {@code jdk.http.maxHeaderSize}, 384 KiB by default; a status line such as {@code HTTP/1.1 099 X}; a
 * header name that is not a token), it leaves the connection open for as long as the server keeps it, one connection
 * per call (observed on 17.0.20, 21.0.11 and 27 in September 2026). JDK 17 to 26 do the same for a 204 whose
 * {@code Content-Length} they cannot parse. Those cases cannot show a client close.
 * <p>
 * <strong>Sockets.</strong> The server accepts plain TCP connections on a {@link ServerSocket} and layers TLS on each
 * one in server mode ({@link SSLSocketFactory#createSocket(Socket, InputStream, boolean)}). Closing the server
 * closes those TCP sockets directly: {@code SSLSocket.close()} first sends {@code close_notify}, which waits
 * (without SO_LINGER, forever) for the TLS write lock that a writer blocked on a full send buffer holds.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class RawTlsServer implements AutoCloseable {
	/**
	 * The largest request head (request line and headers) the server reads before giving up on the connection.
	 */
	public static final int MAXIMUM_REQUEST_HEAD_BYTES = 1024 * 1024;

	/**
	 * The most request-body bytes a {@link RecordedRequest} keeps; the rest is read and discarded.
	 */
	public static final int MAXIMUM_RECORDED_BODY_BYTES = 1024 * 1024;

	/**
	 * How long a client may take to complete the TLS handshake before the server drops the connection
	 * ({@link ClosedBy#SERVER}).
	 */
	static final Duration HANDSHAKE_TIMEOUT = Duration.ofSeconds(10);

	private static final Script NOT_FOUND = Script.fromString(
			"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
	private static final Pattern CRLF = Pattern.compile("\r\n");
	private static final int MAXIMUM_LINE_BYTES = 8 * 1024;

	private final ServerSocket serverSocket;
	private final SSLSocketFactory socketFactory;
	private final ExecutorService executor;
	private final ScheduledExecutorService scheduler;
	private final Duration handshakeTimeout;
	private final URI baseUri;
	private final Map<String, Script> scripts = new ConcurrentHashMap<>();
	private final Map<String, AtomicInteger> hitCounts = new ConcurrentHashMap<>();
	private final List<Connection> connections = new CopyOnWriteArrayList<>();
	private final List<RecordedRequest> requests = new CopyOnWriteArrayList<>();
	private final AtomicBoolean closed = new AtomicBoolean();
	private final ReentrantLock lock = new ReentrantLock();
	private final Condition changed = this.lock.newCondition();

	private RawTlsServer(ServerSocket serverSocket, SSLSocketFactory socketFactory, ExecutorService executor,
			ScheduledExecutorService scheduler, Duration handshakeTimeout) {
		this.serverSocket = serverSocket;
		this.socketFactory = socketFactory;
		this.executor = executor;
		this.scheduler = scheduler;
		this.handshakeTimeout = handshakeTimeout;
		this.baseUri = URI.create("https://127.0.0.1:" + serverSocket.getLocalPort());
	}

	/**
	 * Binds a new server to {@code 127.0.0.1} on an ephemeral port and starts accepting connections.
	 *
	 * @return the running server; close it when done
	 * @throws IOException if the server cannot bind
	 */
	public static RawTlsServer start() throws IOException {
		return start(HANDSHAKE_TIMEOUT);
	}

	/**
	 * {@link #start()} with another handshake timeout, so a test can see a silent client dropped quickly.
	 */
	static RawTlsServer start(Duration handshakeTimeout) throws IOException {
		requireNonNull(handshakeTimeout);
		if (handshakeTimeout.isNegative() || handshakeTimeout.toMillis() < 1)
			throw new IllegalArgumentException("The handshake timeout must be at least 1 ms: " + handshakeTimeout);
		SSLSocketFactory socketFactory = TestTls.serverSslContext().getSocketFactory();
		ServerSocket serverSocket = new ServerSocket();
		ExecutorService executor = Executors.newCachedThreadPool(new DaemonThreadFactory("revetsec-raw-tls"));
		ScheduledExecutorService scheduler =
				Executors.newScheduledThreadPool(2, new DaemonThreadFactory("revetsec-raw-tls-pacer"));
		try {
			serverSocket.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), 0));
			RawTlsServer server = new RawTlsServer(serverSocket, socketFactory, executor, scheduler, handshakeTimeout);
			executor.execute(server::acceptConnections);
			return server;
		} catch (IOException | RuntimeException e) {
			executor.shutdownNow();
			scheduler.shutdownNow();
			serverSocket.close();
			throw e;
		}
	}

	/**
	 * Sets the script for {@code path}, replacing any earlier one. It applies to requests that arrive afterward.
	 *
	 * @param path the exact path of the request target (before any {@code ?}), starting with {@code /}
	 * @param script how to answer
	 * @return this server
	 */
	public RawTlsServer script(String path, Script script) {
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
	 * @param path a path starting with {@code /}, optionally with a query
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
	 * How many requests arrived for {@code path}, scripted or not. A request counts as soon as its request line has
	 * been read, so one whose headers the server rejects, or whose body the client never finishes, counts too (and is
	 * missing from {@link #getRequests()}); a zero-hit assertion therefore means no request line named the path.
	 *
	 * @param path the exact path
	 * @return the count, zero if none
	 */
	public Integer getHitCount(String path) {
		@Nullable AtomicInteger hitCount = this.hitCounts.get(requireNonNull(path));
		return hitCount == null ? 0 : hitCount.get();
	}

	/**
	 * Every accepted connection, in order.
	 *
	 * @return an immutable snapshot
	 */
	public List<Connection> getConnections() {
		return List.copyOf(this.connections);
	}

	/**
	 * Every recorded request on every connection, in arrival order.
	 *
	 * @return an immutable snapshot
	 */
	public List<RecordedRequest> getRequests() {
		return List.copyOf(this.requests);
	}

	/**
	 * Waits until at least {@code count} connections have been accepted, the timeout passes, or the server closes.
	 *
	 * @param count how many connections to wait for
	 * @param timeout the longest wait
	 * @return whether at least {@code count} connections were accepted
	 * @throws InterruptedException if interrupted while waiting
	 */
	public Boolean awaitConnectionCount(Integer count, Duration timeout) throws InterruptedException {
		return awaitSize(this.connections, count, timeout);
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
		return awaitSize(this.requests, count, timeout);
	}

	/**
	 * Stops the server: stops accepting, closes every connection's TCP socket (each still-open connection reports
	 * that the server closed it, and each unfinished response {@link Outcome#SERVER_CLOSED}), and stops its threads.
	 * Every wait returns. Calling it again does nothing.
	 */
	@Override
	public void close() {
		if (!this.closed.compareAndSet(false, true))
			return;
		closeQuietly(this.serverSocket);
		for (RecordedRequest request : this.requests)
			request.finish(Outcome.SERVER_CLOSED);
		for (Connection connection : this.connections)
			connection.closeByServer();
		this.executor.shutdownNow();
		this.scheduler.shutdownNow();
		signalWaiters();
	}

	private Boolean awaitSize(List<?> list, Integer count, Duration timeout) throws InterruptedException {
		requireNonNull(count);
		long remaining = timeout.toNanos();
		this.lock.lock();
		try {
			while (list.size() < count) {
				if (this.closed.get() || remaining <= 0)
					return false;
				remaining = this.changed.awaitNanos(remaining);
			}
			return true;
		} finally {
			this.lock.unlock();
		}
	}

	private void signalWaiters() {
		this.lock.lock();
		try {
			this.changed.signalAll();
		} finally {
			this.lock.unlock();
		}
	}

	private void acceptConnections() {
		while (!this.closed.get()) {
			Socket socket;
			try {
				socket = this.serverSocket.accept();
			} catch (IOException e) {
				// Closing the server socket ends the loop; any other accept failure ends it too, and the test that
				// expected a connection then fails on its own wait.
				return;
			}
			try {
				socket.setTcpNoDelay(true);
				SSLSocket sslSocket = (SSLSocket) this.socketFactory.createSocket(socket, null, true);
				sslSocket.setUseClientMode(false);
				Connection connection = new Connection(socket, sslSocket);
				this.connections.add(connection);
				signalWaiters();
				if (this.closed.get()) {
					connection.closeByServer();
					return;
				}
				this.executor.execute(() -> serve(connection));
			} catch (IOException | RejectedExecutionException e) {
				closeQuietly(socket);
			}
		}
	}

	private void serve(Connection connection) {
		@Nullable RecordedRequest request = null;
		try {
			SSLSocket sslSocket = connection.sslSocket;
			sslSocket.setSoTimeout(Math.toIntExact(this.handshakeTimeout.toMillis()));
			try {
				sslSocket.startHandshake();
			} catch (IOException e) {
				if (!isTimeout(e))
					throw e;
				// The client never completed the handshake, so the server gives up on it: not a client close.
				connection.finish(ClosedBy.SERVER);
				return;
			}
			sslSocket.setSoTimeout(0);
			InputStream inputStream = new BufferedInputStream(sslSocket.getInputStream());
			OutputStream outputStream = sslSocket.getOutputStream();

			while (true) {
				request = readRequest(inputStream);
				if (request == null) {
					connection.finish(ClosedBy.CLIENT);
					return;
				}
				connection.requests.add(request);
				this.requests.add(request);
				signalWaiters();

				Script script = this.scripts.getOrDefault(request.getPath(), NOT_FOUND);
				@Nullable ClosedBy closedBy = perform(script, request, sslSocket, inputStream, outputStream);
				if (closedBy != null) {
					connection.finish(closedBy);
					return;
				}
				request = null;
			}
		} catch (MalformedRequestException e) {
			connection.finish(ClosedBy.SERVER);
		} catch (IOException e) {
			boolean serverClosed = this.closed.get();
			if (request != null)
				request.finish(serverClosed ? Outcome.SERVER_CLOSED : Outcome.CLIENT_ABORTED);
			connection.finish(serverClosed ? ClosedBy.SERVER : ClosedBy.CLIENT);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			if (request != null)
				request.finish(Outcome.SERVER_CLOSED);
			connection.finish(ClosedBy.SERVER);
		} catch (RuntimeException e) {
			if (request != null)
				request.fail(e);
			connection.fail(e);
		} finally {
			// No other thread writes by now, so the TLS close cannot block; after close() only TCP is left to close.
			closeQuietly(this.closed.get() ? connection.socket : connection.sslSocket);
		}
	}

	/**
	 * Runs {@code script}'s steps and records the response's outcome; returns who closed the connection, or
	 * {@code null} if it stays open for another request. A failure propagates, and the caller records it.
	 */
	private @Nullable ClosedBy perform(Script script, RecordedRequest request, SSLSocket sslSocket,
			InputStream inputStream, OutputStream outputStream) throws IOException, InterruptedException {
		for (Step step : script.steps) {
			switch (step.kind) {
				case WRITE -> {
					outputStream.write(step.bytes);
					outputStream.flush();
				}
				case TRICKLE -> trickle(step, outputStream);
				case STALL -> {
					// A stalled response never finishes, so the client closing the connection ends it early.
					readToEnd(inputStream);
					request.finish(Outcome.CLIENT_ABORTED);
					return ClosedBy.CLIENT;
				}
				case END_OF_STREAM -> {
					sslSocket.shutdownOutput();
					request.finish(Outcome.COMPLETED);
					readToEnd(inputStream);
					return ClosedBy.CLIENT;
				}
				case CLOSE -> {
					request.finish(Outcome.COMPLETED);
					return ClosedBy.SERVER;
				}
			}
		}
		request.finish(Outcome.COMPLETED);
		return null;
	}

	/**
	 * Reads and discards until end of stream, which means the client closed the connection. A read failure
	 * propagates, and the caller decides who closed it.
	 */
	private static void readToEnd(InputStream inputStream) throws IOException {
		byte[] buffer = new byte[8 * 1024];
		int read;
		do {
			read = inputStream.read(buffer);
		} while (read >= 0);
	}

	private void trickle(Step step, OutputStream outputStream) throws IOException, InterruptedException {
		byte[] bytes = step.bytes;
		if (bytes.length == 0)
			return;
		CompletableFuture<@Nullable Void> done = new CompletableFuture<>();
		AtomicInteger offset = new AtomicInteger();
		Runnable writeNextChunk = () -> {
			if (done.isDone())
				return;
			try {
				int start = offset.get();
				int length = Math.min(step.chunkSize, bytes.length - start);
				outputStream.write(bytes, start, length);
				outputStream.flush();
				if (offset.addAndGet(length) >= bytes.length)
					done.complete(null);
			} catch (IOException | RuntimeException e) {
				done.completeExceptionally(e);
			}
		};

		ScheduledFuture<?> task;
		try {
			task = this.scheduler.scheduleWithFixedDelay(writeNextChunk, 0, step.interval.toNanos(),
					TimeUnit.NANOSECONDS);
		} catch (RejectedExecutionException e) {
			throw new InterruptedException("The server is closing");
		}
		try {
			done.get();
		} catch (ExecutionException e) {
			Throwable cause = e.getCause();
			if (cause instanceof IOException ioException)
				throw ioException;
			if (cause instanceof RuntimeException runtimeException)
				throw runtimeException;
			throw new IOException("Trickling failed", cause);
		} finally {
			task.cancel(false);
		}
	}

	/**
	 * Reads one request head and body, counting the hit as soon as the request line is known; {@code null} if the
	 * client closed the connection before sending a byte.
	 */
	private @Nullable RecordedRequest readRequest(InputStream inputStream) throws IOException {
		ByteArrayOutputStream head = new ByteArrayOutputStream();
		int matched = 0;
		while (matched < 4) {
			int value = inputStream.read();
			if (value < 0) {
				if (head.size() == 0)
					return null;
				throw new EOFException("The client closed the connection inside a request head");
			}
			head.write(value);
			if (head.size() > MAXIMUM_REQUEST_HEAD_BYTES)
				throw new MalformedRequestException("The request head is over " + MAXIMUM_REQUEST_HEAD_BYTES
						+ " bytes");
			if (value == '\r')
				matched = matched == 2 ? 3 : 1;
			else if (value == '\n' && (matched == 1 || matched == 3))
				++matched;
			else
				matched = 0;
		}

		String headText = head.toString(StandardCharsets.ISO_8859_1);
		String[] lines = CRLF.split(headText, -1);
		String requestLine = lines[0];
		String path = pathOf(targetOf(requestLine));
		this.hitCounts.computeIfAbsent(path, ignored -> new AtomicInteger()).incrementAndGet();
		Map<String, List<String>> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
		for (int index = 1; index < lines.length; ++index) {
			String line = lines[index];
			if (line.isEmpty())
				continue;
			int colon = line.indexOf(':');
			if (colon <= 0)
				throw new MalformedRequestException("Malformed request header line");
			headers.computeIfAbsent(line.substring(0, colon).strip(), ignored -> new ArrayList<>())
					.add(line.substring(colon + 1).strip());
		}
		headers.replaceAll((name, values) -> List.copyOf(values));

		byte[] body = readBody(inputStream, headers);
		return new RecordedRequest(headText, requestLine, Collections.unmodifiableMap(headers), body);
	}

	private static byte[] readBody(InputStream inputStream, Map<String, List<String>> headers) throws IOException {
		BoundedBody body = new BoundedBody();
		@Nullable List<String> transferEncoding = headers.get("Transfer-Encoding");
		if (transferEncoding != null
				&& String.join(",", transferEncoding).toLowerCase(Locale.ROOT).contains("chunked")) {
			while (true) {
				String sizeLine = readLine(inputStream);
				int semicolon = sizeLine.indexOf(';');
				String size = (semicolon < 0 ? sizeLine : sizeLine.substring(0, semicolon)).strip();
				long chunkSize;
				try {
					chunkSize = Long.parseLong(size, 16);
				} catch (NumberFormatException e) {
					throw new MalformedRequestException("Malformed chunk size");
				}
				if (chunkSize < 0)
					throw new MalformedRequestException("Negative chunk size");
				if (chunkSize == 0) {
					String trailer;
					do {
						trailer = readLine(inputStream);
					} while (!trailer.isEmpty());
					return body.toByteArray();
				}
				body.copyFrom(inputStream, chunkSize);
				if (!readLine(inputStream).isEmpty())
					throw new MalformedRequestException("A chunk is not followed by CRLF");
			}
		}

		@Nullable List<String> contentLength = headers.get("Content-Length");
		if (contentLength == null || contentLength.isEmpty())
			return body.toByteArray();
		long length;
		try {
			length = Long.parseLong(contentLength.get(0));
		} catch (NumberFormatException e) {
			throw new MalformedRequestException("Malformed Content-Length");
		}
		if (length < 0)
			throw new MalformedRequestException("Negative Content-Length");
		body.copyFrom(inputStream, length);
		return body.toByteArray();
	}

	private static String readLine(InputStream inputStream) throws IOException {
		ByteArrayOutputStream line = new ByteArrayOutputStream();
		while (true) {
			int value = inputStream.read();
			if (value < 0)
				throw new EOFException("The client closed the connection inside a line");
			if (value == '\n')
				break;
			line.write(value);
			if (line.size() > MAXIMUM_LINE_BYTES)
				throw new MalformedRequestException("A line is over " + MAXIMUM_LINE_BYTES + " bytes");
		}
		String text = line.toString(StandardCharsets.ISO_8859_1);
		return text.endsWith("\r") ? text.substring(0, text.length() - 1) : text;
	}

	/**
	 * Whether {@code failure} is, or was caused by, a socket read timing out (a JDK may wrap the timeout).
	 */
	private static boolean isTimeout(Throwable failure) {
		Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
		for (@Nullable Throwable current = failure; current != null && seen.add(current); current = current.getCause())
			if (current instanceof SocketTimeoutException)
				return true;
		return false;
	}

	/**
	 * The request target: the request line between its first and last spaces, or empty if it has no such part.
	 */
	private static String targetOf(String requestLine) {
		int first = requestLine.indexOf(' ');
		int last = requestLine.lastIndexOf(' ');
		return first < 0 || last <= first ? "" : requestLine.substring(first + 1, last);
	}

	/**
	 * The target's path: the target up to any {@code ?}.
	 */
	private static String pathOf(String target) {
		int query = target.indexOf('?');
		return query < 0 ? target : target.substring(0, query);
	}

	private static void closeQuietly(@Nullable AutoCloseable closeable) {
		if (closeable == null)
			return;
		try {
			closeable.close();
		} catch (Exception e) {
			// Closing is best effort: the socket is unusable either way.
			return;
		}
	}

	private static String requirePath(String path) {
		requireNonNull(path);
		if (!path.startsWith("/"))
			throw new IllegalArgumentException("A path starts with /: " + path);
		return path;
	}

	/**
	 * Who closed a connection.
	 */
	@Immutable
	public enum ClosedBy {
		/**
		 * The client: end of stream, a reset, or a failed write while the server was open.
		 */
		CLIENT,
		/**
		 * The server: a {@link Script.Builder#closeConnection()} step, a malformed request, a client that did not
		 * complete the TLS handshake in time, or {@link #close()}.
		 */
		SERVER
	}

	/**
	 * How the response to a recorded request ended.
	 */
	@Immutable
	public enum Outcome {
		/**
		 * Every step of the script ran: each byte was handed to the connection, and a final
		 * {@link Script.Builder#endOfStream()} or {@link Script.Builder#closeConnection()} ran too. Bytes still in
		 * socket buffers when the client closes do not make this an abort, so a body meant to show one must be larger
		 * than those buffers (a few MiB; exit criterion 10 uses 12 MiB).
		 */
		COMPLETED,
		/**
		 * The client ended the response early while the server was open: a write failed, or the client closed the
		 * connection during a {@link Script.Builder#stall()}.
		 */
		CLIENT_ABORTED,
		/**
		 * The server closed before the script finished.
		 */
		SERVER_CLOSED,
		/**
		 * Returned by {@link RecordedRequest#awaitOutcome(Duration)} when the response had not ended in time.
		 */
		UNFINISHED
	}

	/**
	 * One accepted connection and the requests it carried.
	 */
	@ThreadSafe
	public static final class Connection {
		private final Socket socket;
		private final SSLSocket sslSocket;
		private final List<RecordedRequest> requests = new CopyOnWriteArrayList<>();
		private final CompletableFuture<ClosedBy> closedBy = new CompletableFuture<>();

		private Connection(Socket socket, SSLSocket sslSocket) {
			this.socket = socket;
			this.sslSocket = sslSocket;
		}

		/**
		 * The requests this connection carried, in order.
		 *
		 * @return an immutable snapshot
		 */
		public List<RecordedRequest> getRequests() {
			return List.copyOf(this.requests);
		}

		/**
		 * Waits for the connection to close.
		 *
		 * @param timeout the longest wait
		 * @return who closed it, or empty if it was still open at the timeout
		 * @throws InterruptedException if interrupted while waiting
		 * @throws IllegalStateException if the connection handler failed
		 */
		public Optional<ClosedBy> awaitClose(Duration timeout) throws InterruptedException {
			try {
				return Optional.of(this.closedBy.get(timeout.toNanos(), TimeUnit.NANOSECONDS));
			} catch (TimeoutException e) {
				return Optional.empty();
			} catch (ExecutionException e) {
				Throwable cause = e.getCause();
				throw new IllegalStateException("The connection handler failed", cause);
			}
		}

		/**
		 * Waits for the client to close the connection: whether it did before the timeout and before the server
		 * closed it.
		 *
		 * @param timeout the longest wait; the server closing ends it early
		 * @return {@code true} if the client closed the connection
		 * @throws InterruptedException if interrupted while waiting
		 */
		public Boolean awaitClientClose(Duration timeout) throws InterruptedException {
			return awaitClose(timeout).filter(closedBy -> closedBy == ClosedBy.CLIENT).isPresent();
		}

		@Override
		public String toString() {
			String state = !this.closedBy.isDone() ? "open"
					: this.closedBy.isCompletedExceptionally() ? "failed" : "closed by " + this.closedBy.join();
			return "RawTlsServer.Connection[" + this.requests.size() + " request(s), " + state + "]";
		}

		private void finish(ClosedBy who) {
			this.closedBy.complete(who);
		}

		private void fail(RuntimeException failure) {
			this.closedBy.completeExceptionally(failure);
		}

		private void closeByServer() {
			finish(ClosedBy.SERVER);
			closeQuietly(this.socket);
		}
	}

	/**
	 * A request as the server read it, and how its response ended.
	 */
	@ThreadSafe
	public static final class RecordedRequest {
		private final String head;
		private final String requestLine;
		private final Map<String, List<String>> headers;
		private final byte[] body;
		private final CompletableFuture<Outcome> outcome = new CompletableFuture<>();

		private RecordedRequest(String head, String requestLine, Map<String, List<String>> headers, byte[] body) {
			this.head = head;
			this.requestLine = requestLine;
			this.headers = headers;
			this.body = body;
		}

		/**
		 * The request head exactly as received (ISO-8859-1), request line through the blank line.
		 *
		 * @return the head
		 */
		public String getHead() {
			return this.head;
		}

		/**
		 * The request line, such as {@code GET /jwks HTTP/1.1}.
		 *
		 * @return the request line
		 */
		public String getRequestLine() {
			return this.requestLine;
		}

		/**
		 * The method: the request line up to its first space.
		 *
		 * @return the method
		 */
		public String getMethod() {
			int space = this.requestLine.indexOf(' ');
			return space < 0 ? this.requestLine : this.requestLine.substring(0, space);
		}

		/**
		 * The request target: the request line between its first and last spaces.
		 *
		 * @return the target, such as {@code /token?x=1}
		 */
		public String getTarget() {
			return targetOf(this.requestLine);
		}

		/**
		 * The target's path: the target up to any {@code ?}.
		 *
		 * @return the path
		 */
		public String getPath() {
			return pathOf(getTarget());
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
		 * The body ({@code Content-Length} or chunked), up to {@value RawTlsServer#MAXIMUM_RECORDED_BODY_BYTES}
		 * bytes.
		 *
		 * @return a copy of the body
		 */
		public byte[] getBody() {
			return this.body.clone();
		}

		/**
		 * Waits for the response to end.
		 *
		 * @param timeout the longest wait
		 * @return how it ended, or {@link Outcome#UNFINISHED} if it had not ended in time
		 * @throws InterruptedException if interrupted while waiting
		 * @throws IllegalStateException if the connection handler failed
		 */
		public Outcome awaitOutcome(Duration timeout) throws InterruptedException {
			try {
				return this.outcome.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
			} catch (TimeoutException e) {
				return Outcome.UNFINISHED;
			} catch (ExecutionException e) {
				throw new IllegalStateException("The connection handler failed", e.getCause());
			}
		}

		@Override
		public String toString() {
			return "RawTlsServer.RecordedRequest[" + this.requestLine + "]";
		}

		private void finish(Outcome outcome) {
			this.outcome.complete(outcome);
		}

		private void fail(RuntimeException failure) {
			this.outcome.completeExceptionally(failure);
		}
	}

	/**
	 * The exact bytes and pacing of one response, as a list of steps. Build one with {@link #builder()}, or use
	 * {@link #fromBytes(byte[])} or {@link #fromString(String)} for a single write.
	 */
	@Immutable
	public static final class Script {
		private final List<Step> steps;

		private Script(List<Step> steps) {
			this.steps = List.copyOf(steps);
		}

		/**
		 * Starts an empty script.
		 *
		 * @return a new builder
		 */
		public static Builder builder() {
			return new Builder();
		}

		/**
		 * A script that writes {@code bytes} and then keeps the connection open for another request.
		 *
		 * @param bytes the whole response
		 * @return the script
		 */
		public static Script fromBytes(byte[] bytes) {
			return builder().write(bytes).build();
		}

		/**
		 * A script that writes {@code text} as ISO-8859-1 (one byte per character) and then keeps the connection open
		 * for another request.
		 *
		 * @param text the whole response, with explicit {@code \r\n} line ends
		 * @return the script
		 */
		public static Script fromString(String text) {
			return builder().write(text).build();
		}

		/**
		 * Builds a {@link Script}. {@link #stall()}, {@link #endOfStream()} and {@link #closeConnection()} end the
		 * connection, so each may only be the last step.
		 */
		@NotThreadSafe
		public static final class Builder {
			private final List<Step> steps = new ArrayList<>();

			private Builder() {
				// Starts empty.
			}

			/**
			 * Writes {@code bytes} at once.
			 *
			 * @param bytes the bytes
			 * @return this builder
			 */
			public Builder write(byte[] bytes) {
				return add(new Step(StepKind.WRITE, bytes.clone(), 0, Duration.ZERO));
			}

			/**
			 * Writes {@code text} as ISO-8859-1, one byte per character.
			 *
			 * @param text the text; every character must be at most U+00FF
			 * @return this builder
			 * @throws IllegalArgumentException if a character is above U+00FF
			 */
			public Builder write(String text) {
				requireNonNull(text);
				for (int index = 0; index < text.length(); ++index)
					if (text.charAt(index) > 0xFF)
						throw new IllegalArgumentException("Character at index " + index + " is not ISO-8859-1");
				return write(text.getBytes(StandardCharsets.ISO_8859_1));
			}

			/**
			 * Writes {@code bytes} in chunks of {@code chunkSize}, the first at once and each next one
			 * {@code interval} after the previous write finished, paced by the server's scheduled executor.
			 *
			 * @param bytes the bytes
			 * @param chunkSize bytes per write, at least 1
			 * @param interval the pause between writes, positive
			 * @return this builder
			 */
			public Builder trickle(byte[] bytes, Integer chunkSize, Duration interval) {
				requireNonNull(chunkSize);
				requireNonNull(interval);
				if (chunkSize < 1)
					throw new IllegalArgumentException("chunkSize must be at least 1");
				if (interval.isZero() || interval.isNegative())
					throw new IllegalArgumentException("interval must be positive");
				return add(new Step(StepKind.TRICKLE, bytes.clone(), chunkSize, interval));
			}

			/**
			 * Sends nothing more and reads until the client closes the connection or the server closes.
			 *
			 * @return this builder
			 */
			public Builder stall() {
				return add(new Step(StepKind.STALL, new byte[0], 0, Duration.ZERO));
			}

			/**
			 * Ends the response stream: sends TLS {@code close_notify} and shuts down output (a close-delimited body
			 * ends here), then reads until the client closes the connection.
			 *
			 * @return this builder
			 */
			public Builder endOfStream() {
				return add(new Step(StepKind.END_OF_STREAM, new byte[0], 0, Duration.ZERO));
			}

			/**
			 * Closes the connection from the server side; the connection reports {@link ClosedBy#SERVER}.
			 *
			 * @return this builder
			 */
			public Builder closeConnection() {
				return add(new Step(StepKind.CLOSE, new byte[0], 0, Duration.ZERO));
			}

			/**
			 * Builds the script.
			 *
			 * @return the script
			 */
			public Script build() {
				return new Script(this.steps);
			}

			private Builder add(Step step) {
				if (!this.steps.isEmpty() && this.steps.get(this.steps.size() - 1).kind.isTerminal())
					throw new IllegalStateException("No step may follow " + this.steps.get(this.steps.size() - 1).kind);
				this.steps.add(step);
				return this;
			}
		}
	}

	private enum StepKind {
		WRITE,
		TRICKLE,
		STALL,
		END_OF_STREAM,
		CLOSE;

		private boolean isTerminal() {
			return this == STALL || this == END_OF_STREAM || this == CLOSE;
		}
	}

	@Immutable
	private static final class Step {
		private final StepKind kind;
		private final byte[] bytes;
		private final int chunkSize;
		private final Duration interval;

		private Step(StepKind kind, byte[] bytes, int chunkSize, Duration interval) {
			this.kind = kind;
			this.bytes = bytes;
			this.chunkSize = chunkSize;
			this.interval = interval;
		}
	}

	/**
	 * Collects a request body, keeping at most {@link #MAXIMUM_RECORDED_BODY_BYTES} and discarding the rest.
	 */
	@NotThreadSafe
	private static final class BoundedBody {
		private final ByteArrayOutputStream kept = new ByteArrayOutputStream();

		private void copyFrom(InputStream inputStream, long length) throws IOException {
			byte[] buffer = new byte[8 * 1024];
			long remaining = length;
			while (remaining > 0) {
				int read = inputStream.read(buffer, 0, (int) Math.min(buffer.length, remaining));
				if (read < 0)
					throw new EOFException("The client closed the connection inside a request body");
				int keep = Math.min(read, MAXIMUM_RECORDED_BODY_BYTES - this.kept.size());
				if (keep > 0)
					this.kept.write(buffer, 0, keep);
				remaining -= read;
			}
		}

		private byte[] toByteArray() {
			return this.kept.toByteArray();
		}
	}

	/**
	 * A request the server cannot parse; the server closes the connection.
	 */
	private static final class MalformedRequestException extends IOException {
		private static final long serialVersionUID = 1L;

		private MalformedRequestException(String message) {
			super(message);
		}
	}
}
