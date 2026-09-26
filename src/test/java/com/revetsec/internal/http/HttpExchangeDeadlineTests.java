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
import com.revetsec.internal.http.HttpExchangeException.Kind;
import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * Deadlines (plan R12 and G5-5 as amended by G6-6; exit criterion 11): trickled, stalled and slow responses end in
 * {@link Kind#TIMEOUT} no later than the deadline plus 2 s on every JDK; an exchange with no time left fails before a
 * request is built; the per-request timeout bounds the body too; an interrupt gives {@link Kind#INTERRUPTED} with the
 * flag restored; and a saturated common pool neither delays a finished exchange nor holds a refused connection past
 * the deadline plus 2 s. Time is {@link System#nanoTime()}; nothing here sleeps.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class HttpExchangeDeadlineTests {
	/**
	 * The short deadline the paced cases run under.
	 */
	private static final Duration SHORT = Duration.ofMillis(1_500);

	/**
	 * Exit criterion 11's allowance past the deadline.
	 */
	private static final Duration SLACK = Duration.ofSeconds(2);

	/**
	 * Server-side checks allow about 10 s (M1 plan, "Test helpers").
	 */
	private static final Duration SERVER_WAIT = Duration.ofSeconds(10);

	private static final AtomicInteger NEXT_PATH = new AtomicInteger();

	private static @Nullable RawTlsServer rawServer;
	private static @Nullable TestHttpsServer jdkServer;
	private static @Nullable HttpExchange exchange;

	@BeforeAll
	static void startServers() throws IOException {
		rawServer = RawTlsServer.start();
		jdkServer = TestHttpsServer.start();
		exchange = HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false);
	}

	@AfterAll
	static void stopServers() {
		if (rawServer != null)
			rawServer.close();
		if (jdkServer != null)
			jdkServer.close();
	}

	// Exit criterion 11: a trickled body, a stalled chunked body, a stall after the headers, trickled headers and a
	// silent server each end in TIMEOUT within the total deadline plus 2 s, and the server sees the client leave.
	@TestFactory
	Stream<DynamicTest> everyPacedResponseTimesOutByTheTotalDeadline() {
		return HostileResponse.timeouts().stream()
				.map(hostileResponse -> DynamicTest.dynamicTest(hostileResponse.getName(), () -> {
					RawTlsServer server = required(rawServer);
					String path = nextPath();
					hostileResponse.installOn(server, path);
					// The request timeout is longer than the deadline, so the deadline alone must end the exchange.
					HttpExchangeRequest request = request(server.uri(path), hostileResponse.getProfile(),
							Duration.ofSeconds(30));

					long started = System.nanoTime();
					HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
							() -> required(exchange).execute(request, Deadline.fromNow(SHORT)));
					Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

					Assertions.assertEquals(Kind.TIMEOUT, exception.getKind());
					assertEndedWithin(elapsed, SHORT);
					Assertions.assertTrue(connectionFor(server, path).awaitClientClose(SERVER_WAIT),
							"the server saw the client close the connection");
				}));
	}

	// Exit criterion 11: the per-request timeout bounds the whole exchange, body included, on every JDK (the JDK's own
	// HttpRequest.timeout covers the body only from 26).
	@Test
	void theRequestTimeoutBoundsATrickledBodyOnEveryJdk() throws Exception {
		RawTlsServer server = required(rawServer);
		String path = nextPath();
		HostileResponse trickledBody = HostileResponse.timeouts().get(0);
		trickledBody.installOn(server, path);
		HttpExchangeRequest request = request(server.uri(path), trickledBody.getProfile(), SHORT);

		long started = System.nanoTime();
		HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
				() -> required(exchange).execute(request, Deadline.fromNow(Duration.ofSeconds(60))));
		Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

		Assertions.assertEquals(Kind.TIMEOUT, exception.getKind());
		assertEndedWithin(elapsed, SHORT);
		Assertions.assertTrue(connectionFor(server, path).awaitClientClose(SERVER_WAIT));
	}

	// M1 plan, algorithm step 2: every request carries timeout(min(requestTimeout, remaining)), so the JDK's own timer
	// never outlives the call's deadline, and the per-request timeout binds when it is the shorter.
	@TestFactory
	Stream<DynamicTest> everyRequestCarriesTheSmallerOfItsTimeoutAndTheTimeLeft() {
		return Stream.of(
				new Duration[]{Duration.ofSeconds(7), Duration.ofSeconds(60), Duration.ofSeconds(7)},
				new Duration[]{Duration.ofSeconds(30), Duration.ofSeconds(2), Duration.ofSeconds(2)}
		).map(testCase -> DynamicTest.dynamicTest("request timeout " + testCase[0] + ", deadline " + testCase[1], () -> {
			ScriptedHttpClient recording = ScriptedHttpClient.failingBeforeAnyResponse(
					ScriptedHttpClient.Behavior.THROW_FROM_SEND_ASYNC);
			HttpExchange recordingExchange = HttpExchange.fromHttpClient(recording, OutboundUriPolicy.defaultInstance(),
					false);

			HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
					() -> recordingExchange.execute(request(URI.create("https://example.com/jwks"), ResponseProfile.JWKS,
							testCase[0]), Deadline.fromNow(testCase[1])));

			Assertions.assertEquals(Kind.IO, exception.getKind());
			Duration timeout = recording.getLastRequest().timeout().orElseThrow();
			Assertions.assertTrue(timeout.compareTo(testCase[2]) <= 0, () -> "timeout " + timeout);
			Assertions.assertTrue(timeout.compareTo(testCase[2].minusSeconds(1)) > 0, () -> "timeout " + timeout);
		}));
	}

	// Exit criterion 11 and R12 text owed: an exchange started with no deadline left fails with TIMEOUT before any
	// request is built, so the server never sees a connection.
	@TestFactory
	Stream<DynamicTest> anExchangeWithNoTimeLeftFailsBeforeAnyRequestIsBuilt() {
		return Stream.of(Duration.ZERO, Duration.ofNanos(1)).map(total -> DynamicTest.dynamicTest("total " + total,
				() -> {
					TestHttpsServer server = required(jdkServer);
					String path = nextPath();
					server.script(path, TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, "{}")));
					Deadline deadline = Deadline.fromNow(total);
					// The expired deadline must win even with a client that would count any request it was given.
					StandInHttpClient countingHttpClient = new StandInHttpClient();
					HttpExchange countingExchange = HttpExchange.fromHttpClient(countingHttpClient,
							OutboundUriPolicy.defaultInstance(), false);

					HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
							() -> countingExchange.execute(HttpExchangeRequest.fromDefaults(server.uri(path),
									ResponseProfile.TOKEN), deadline));
					HttpExchangeException realClientException = Assertions.assertThrows(HttpExchangeException.class,
							() -> required(exchange).execute(HttpExchangeRequest.fromDefaults(server.uri(path),
									ResponseProfile.TOKEN), deadline));

					Assertions.assertEquals(Kind.TIMEOUT, exception.getKind());
					Assertions.assertEquals(Kind.TIMEOUT, realClientException.getKind());
					Assertions.assertEquals(0, countingHttpClient.getSendCount());
					Assertions.assertEquals(0, server.getHitCount(path));
				}));
	}

	// Exit criterion 11 and G6-6: with every common-pool worker blocked, a finished exchange still succeeds, because the
	// caller waits on the future Revetsec's subscriber completes, not on the sendAsync future the JDK completes on the
	// common pool. Then a refused connection, whose failure reaches Revetsec only through that pool, still ends by the
	// deadline plus 2 s, as TIMEOUT or IO (M1 plan, "Risks"), and a body cut short is IO at once.
	@Test
	void aSaturatedCommonPoolNeitherDelaysAFinishedExchangeNorHoldsARefusedOnePastTheDeadline() throws Exception {
		TestHttpsServer server = required(jdkServer);
		String path = nextPath();
		server.script(path, TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, "{\"ok\":true}")));
		URI refused = refusedUri();

		try (CommonPoolSaturation saturation = CommonPoolSaturation.start()) {
			Assertions.assertTrue(saturation.awaitAllWorkersBlocked(Duration.ofSeconds(10)),
					"every common-pool worker is blocked");

			long started = System.nanoTime();
			RawResponse response = required(exchange).execute(HttpExchangeRequest.fromDefaults(server.uri(path),
					ResponseProfile.TOKEN), Deadline.fromNow(Duration.ofSeconds(10)));
			Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

			Assertions.assertEquals(200, response.status());
			Assertions.assertEquals("{\"ok\":true}", new String(response.body(), StandardCharsets.UTF_8));
			Assertions.assertTrue(elapsed.compareTo(Duration.ofSeconds(5)) < 0, () -> "took " + elapsed);
			Assertions.assertTrue(saturation.isStillSaturated(), "the pool stayed saturated during the exchange");

			Duration deadline = Duration.ofSeconds(2);
			started = System.nanoTime();
			HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
					() -> required(exchange).execute(HttpExchangeRequest.fromDefaults(refused, ResponseProfile.TOKEN),
							Deadline.fromNow(deadline)));
			Duration refusedElapsed = Duration.ofNanos(System.nanoTime() - started);

			Assertions.assertTrue(exception.getKind() == Kind.TIMEOUT || exception.getKind() == Kind.IO,
					() -> "kind " + exception.getKind());
			Assertions.assertTrue(refusedElapsed.compareTo(deadline.plus(SLACK)) <= 0, () -> "took " + refusedElapsed);
			Assertions.assertTrue(saturation.isStillSaturated(), "the pool stayed saturated during the exchange");

			// A body cut short after the headers reaches Revetsec through the subscriber's onError, on the client's own
			// threads, so it is IO at once, not TIMEOUT at the deadline.
			RawTlsServer rawTlsServer = required(rawServer);
			String truncatedPath = nextPath();
			rawTlsServer.script(truncatedPath, RawTlsServer.Script.builder()
					.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"a\":")
					.closeConnection()
					.build());
			started = System.nanoTime();
			HttpExchangeException truncated = Assertions.assertThrows(HttpExchangeException.class,
					() -> required(exchange).execute(HttpExchangeRequest.fromDefaults(rawTlsServer.uri(truncatedPath),
							ResponseProfile.TOKEN), Deadline.fromNow(Duration.ofSeconds(10))));
			Duration truncatedElapsed = Duration.ofNanos(System.nanoTime() - started);

			Assertions.assertEquals(Kind.IO, truncated.getKind());
			Assertions.assertTrue(truncatedElapsed.compareTo(Duration.ofSeconds(5)) < 0, () -> "took " + truncatedElapsed);
			Assertions.assertTrue(saturation.isStillSaturated(), "the pool stayed saturated during the exchange");
		}
	}

	// Without a saturated pool, a refused connection is reported promptly as IO: the TIMEOUT above comes only from the
	// busy pool (control for the test above).
	@Test
	void aRefusedConnectionIsIoWellBeforeTheDeadline() throws Exception {
		URI refused = refusedUri();

		long started = System.nanoTime();
		HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
				() -> required(exchange).execute(HttpExchangeRequest.fromDefaults(refused, ResponseProfile.TOKEN),
						Deadline.fromNow(Duration.ofSeconds(30))));
		Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

		Assertions.assertEquals(Kind.IO, exception.getKind());
		Assertions.assertTrue(exception.getCause() instanceof IOException, () -> "cause " + exception.getCause());
		Assertions.assertTrue(elapsed.compareTo(Duration.ofSeconds(10)) < 0, () -> "took " + elapsed);
	}

	// G6-3: an interrupt while waiting gives INTERRUPTED, which is not transient, sets the interrupt flag again and
	// abandons the exchange, which the server sees as a client close.
	@Test
	void anInterruptWhileWaitingGivesInterruptedAndRestoresTheFlag() throws Exception {
		RawTlsServer server = required(rawServer);
		String path = nextPath();
		HostileResponse stalled = HostileResponse.timeouts().get(2);
		stalled.installOn(server, path);
		HttpExchangeRequest request = request(server.uri(path), stalled.getProfile(), Duration.ofSeconds(60));
		CompletableFuture<List<Object>> result = new CompletableFuture<>();

		Thread caller = new Thread(() -> {
			try {
				required(exchange).execute(request, Deadline.fromNow(Duration.ofSeconds(60)));
				result.complete(List.of("no exception"));
			} catch (HttpExchangeException e) {
				result.complete(List.of(e.getKind(), Thread.currentThread().isInterrupted()));
			} catch (RuntimeException | Error e) {
				result.completeExceptionally(e);
			}
		}, "revetsec-interrupt-test");
		caller.setDaemon(true);
		caller.start();

		waitForRequest(server, path);
		caller.interrupt();

		List<Object> outcome = result.get(SERVER_WAIT.toSeconds(), TimeUnit.SECONDS);
		Assertions.assertEquals(List.of(Kind.INTERRUPTED, true), outcome);
		Assertions.assertFalse(Kind.INTERRUPTED.isTransient());
		Assertions.assertTrue(connectionFor(server, path).awaitClientClose(SERVER_WAIT));
	}

	// M1 plan, "Risks" (callbacks and connection leaks): when the caller gives up on a body, the subscriber cancels its
	// own subscription, which is what makes the JDK close the connection. Cancelling the sendAsync future is not
	// enough: an injected client's future may not reach the exchange (a decorating client that copies the JDK's
	// result into a future of its own), and failing the body stage alone leaves the connection open and unread.
	@Test
	void aBodyTheCallerGaveUpOnCancelsItsSubscriptionEvenIfTheClientsFutureIgnoresCancel() {
		ScriptedHttpClient stalling = ScriptedHttpClient.respondingAndStalling(200, jsonHeaders());
		HttpExchange stallingExchange = HttpExchange.fromHttpClient(stalling, OutboundUriPolicy.defaultInstance(),
				false);

		HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
				() -> stallingExchange.execute(HttpExchangeRequest.fromDefaults(URI.create("https://example.com/token"),
						ResponseProfile.TOKEN), Deadline.fromNow(Duration.ofMillis(200))));

		Assertions.assertEquals(Kind.TIMEOUT, exception.getKind());
		Assertions.assertEquals(1, stalling.getSubscription().getRequested(), "the subscriber asked for one item");
		Assertions.assertTrue(stalling.getSubscription().isCancelled(), "the subscriber cancelled its subscription");
	}

	// The same on the wire: with a real JDK client behind a future that ignores cancel, a body stalled after its
	// headers still ends with the client closing the connection once the deadline passes (exit criterion 11).
	@Test
	void aStalledBodyBehindAFutureThatIgnoresCancelStillClosesItsConnection() throws Exception {
		RawTlsServer server = required(rawServer);
		String path = nextPath();
		HostileResponse stalled = HostileResponse.timeouts().get(2);
		stalled.installOn(server, path);
		HttpExchange detachedExchange = HttpExchange.fromHttpClient(new DetachedFutureHttpClient(TestTls.httpClient()),
				OutboundUriPolicy.defaultInstance(), false);
		HttpExchangeRequest request = request(server.uri(path), stalled.getProfile(), Duration.ofSeconds(30));

		long started = System.nanoTime();
		HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
				() -> detachedExchange.execute(request, Deadline.fromNow(SHORT)));
		Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

		Assertions.assertEquals(Kind.TIMEOUT, exception.getKind());
		assertEndedWithin(elapsed, SHORT);
		Assertions.assertTrue(connectionFor(server, path).awaitClientClose(SERVER_WAIT),
				"the server saw the client close the connection");
	}

	// G6-3: a thread that is already interrupted fails with INTERRUPTED before anything is sent, and keeps its flag.
	@Test
	void anAlreadyInterruptedThreadSendsNothing() throws Exception {
		StandInHttpClient countingHttpClient = new StandInHttpClient();
		HttpExchange countingExchange = HttpExchange.fromHttpClient(countingHttpClient,
				OutboundUriPolicy.defaultInstance(), false);
		Thread.currentThread().interrupt();
		try {
			HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
					() -> countingExchange.execute(HttpExchangeRequest.fromDefaults(URI.create("https://127.0.0.1:1/"),
							ResponseProfile.TOKEN), Deadline.fromNow(Duration.ofSeconds(5))));
			Assertions.assertEquals(Kind.INTERRUPTED, exception.getKind());
			Assertions.assertTrue(Thread.currentThread().isInterrupted());
			Assertions.assertEquals(0, countingHttpClient.getSendCount());
		} finally {
			// Clear the flag so it cannot leak into the next test.
			Assertions.assertTrue(Thread.interrupted());
		}
	}

	// R11 as amended: a deadline runs on System.nanoTime from its creation and accepts zero, never a negative total.
	@Test
	void aDeadlineCountsDownFromItsTotalAndRejectsNegativeTotals() {
		Deadline deadline = Deadline.fromNow(Duration.ofHours(1));
		Assertions.assertEquals(Duration.ofHours(1), deadline.getTotal());
		Assertions.assertTrue(deadline.remaining().compareTo(Duration.ofHours(1)) <= 0);
		Assertions.assertTrue(deadline.remaining().compareTo(Duration.ofMinutes(59)) > 0);
		Assertions.assertFalse(deadline.isExpired());

		Deadline expired = Deadline.fromNow(Duration.ZERO);
		Assertions.assertTrue(expired.isExpired());
		Assertions.assertTrue(expired.remainingNanos() <= 0);

		Assertions.assertEquals(Long.MAX_VALUE, Deadline.fromNow(Duration.ofSeconds(Long.MAX_VALUE)).getTotal().toNanos());
		Assertions.assertThrows(IllegalArgumentException.class, () -> Deadline.fromNow(Duration.ofNanos(-1)));
		Assertions.assertThrows(NullPointerException.class, () -> Deadline.fromNow(nullDuration()));
		Assertions.assertTrue(deadline.toString().startsWith("Deadline{total=PT1H, remaining="), deadline::toString);
	}

	private static void assertEndedWithin(Duration elapsed, Duration deadline) {
		Assertions.assertTrue(elapsed.compareTo(deadline.plus(SLACK)) <= 0, () -> "took " + elapsed);
		// Not early either: the exchange ran until its deadline (with a little room for timer granularity).
		Assertions.assertTrue(elapsed.compareTo(deadline.minus(Duration.ofMillis(50))) >= 0, () -> "took " + elapsed);
	}

	private static HttpExchangeRequest request(URI uri, ResponseProfile profile, Duration requestTimeout) {
		HttpExchangeRequest defaults = HttpExchangeRequest.fromDefaults(uri, profile);
		return new HttpExchangeRequest(uri, profile, null, Map.of(), defaults.maximumBodyBytes(),
				defaults.maximumErrorBodyBytes(), requestTimeout);
	}

	private static RawTlsServer.Connection connectionFor(RawTlsServer server, String path) throws InterruptedException {
		waitForRequest(server, path);
		for (RawTlsServer.Connection connection : server.getConnections())
			for (RawTlsServer.RecordedRequest request : connection.getRequests())
				if (request.getPath().equals(path))
					return connection;
		throw new AssertionError("No connection carried " + path);
	}

	private static void waitForRequest(RawTlsServer server, String path) throws InterruptedException {
		long deadline = System.nanoTime() + SERVER_WAIT.toNanos();
		while (!hasRequest(server, path)) {
			long remaining = deadline - System.nanoTime();
			if (remaining <= 0)
				throw new AssertionError("No request for " + path);
			server.awaitRequestCount(countRequests(server) + 1, Duration.ofNanos(remaining));
		}
	}

	private static boolean hasRequest(RawTlsServer server, String path) {
		return server.getRequests().stream().anyMatch(request -> request.getPath().equals(path));
	}

	private static int countRequests(RawTlsServer server) {
		return server.getRequests().size();
	}

	/**
	 * An {@code https} URI on {@code 127.0.0.1} whose port was just released, so connecting to it is refused.
	 */
	static URI refusedUri() throws IOException {
		int port;
		try (ServerSocket serverSocket = new ServerSocket()) {
			serverSocket.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), 0));
			port = serverSocket.getLocalPort();
		}
		return URI.create("https://127.0.0.1:" + port + "/refused");
	}

	private static String nextPath() {
		return "/deadline/" + NEXT_PATH.incrementAndGet();
	}

	private static <T> T required(@Nullable T value) {
		if (value == null)
			throw new IllegalStateException("The fixture did not start");
		return value;
	}

	@SuppressWarnings("NullAway")
	private static Duration nullDuration() {
		return null;
	}

	private static HttpHeaders jsonHeaders() {
		return HttpHeaders.of(Map.of("Content-Type", List.of("application/json"), "Content-Length", List.of("7")),
				(name, value) -> true);
	}

	/**
	 * An application's decorating {@link HttpClient}: it forwards everything to a real client, but {@code sendAsync}
	 * returns a future of its own, so cancelling that future does not reach the exchange underneath.
	 * {@link HttpExchangeHostileTests} uses it too.
	 */
	@ThreadSafe
	static final class DetachedFutureHttpClient extends HttpClient {
		private final HttpClient delegate;

		DetachedFutureHttpClient(HttpClient delegate) {
			this.delegate = delegate;
		}

		@Override
		public Optional<CookieHandler> cookieHandler() {
			return this.delegate.cookieHandler();
		}

		@Override
		public Optional<Duration> connectTimeout() {
			return this.delegate.connectTimeout();
		}

		@Override
		public Redirect followRedirects() {
			return this.delegate.followRedirects();
		}

		@Override
		public Optional<ProxySelector> proxy() {
			return this.delegate.proxy();
		}

		@Override
		public SSLContext sslContext() {
			return this.delegate.sslContext();
		}

		@Override
		public SSLParameters sslParameters() {
			return this.delegate.sslParameters();
		}

		@Override
		public Optional<Authenticator> authenticator() {
			return this.delegate.authenticator();
		}

		@Override
		public Version version() {
			return this.delegate.version();
		}

		@Override
		public Optional<Executor> executor() {
			return this.delegate.executor();
		}

		@Override
		public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
				throws IOException, InterruptedException {
			return this.delegate.send(request, responseBodyHandler);
		}

		@Override
		public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
				HttpResponse.BodyHandler<T> responseBodyHandler) {
			CompletableFuture<HttpResponse<T>> detached = new CompletableFuture<>();
			CompletableFuture<HttpResponse<T>> unused = this.delegate.sendAsync(request, responseBodyHandler)
					.whenComplete((response, failure) -> {
						if (failure != null)
							detached.completeExceptionally(failure);
						else
							detached.complete(response);
					});
			return detached;
		}

		@Override
		public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
				HttpResponse.BodyHandler<T> responseBodyHandler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
			return sendAsync(request, responseBodyHandler);
		}
	}

	/**
	 * Blocks every common-pool worker on a latch until closed, so nothing queued on the pool runs (G6-6's hazard). It
	 * waits for each blocker to start instead of sleeping, and the pool is left usable afterward.
	 */
	private static final class CommonPoolSaturation implements AutoCloseable {
		private final CountDownLatch release = new CountDownLatch(1);
		private final CountDownLatch started;
		private final List<Future<?>> blockers = new ArrayList<>();
		private final CompletableFuture<@Nullable Void> probe = new CompletableFuture<>();

		private CommonPoolSaturation(int parallelism) {
			this.started = new CountDownLatch(parallelism);
		}

		static CommonPoolSaturation start() {
			ForkJoinPool pool = ForkJoinPool.commonPool();
			int parallelism = Math.max(1, pool.getParallelism());
			CommonPoolSaturation saturation = new CommonPoolSaturation(parallelism);
			for (int i = 0; i < parallelism; ++i)
				saturation.blockers.add(pool.submit(() -> {
					saturation.started.countDown();
					saturation.release.await();
					return null;
				}));
			// Queued behind the blockers: it can only run once the pool is free again.
			pool.execute(() -> saturation.probe.complete(null));
			return saturation;
		}

		boolean awaitAllWorkersBlocked(Duration timeout) throws InterruptedException {
			return this.started.await(timeout.toNanos(), TimeUnit.NANOSECONDS) && !this.probe.isDone();
		}

		boolean isStillSaturated() {
			return !this.probe.isDone();
		}

		/**
		 * Releases the blockers and waits for the pool to run the queued probe, so the pool is usable again.
		 */
		@Override
		public void close() throws ExecutionException, TimeoutException {
			this.release.countDown();
			try {
				for (Future<?> blocker : this.blockers)
					blocker.get(SERVER_WAIT.toSeconds(), TimeUnit.SECONDS);
				this.probe.get(SERVER_WAIT.toSeconds(), TimeUnit.SECONDS);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new IllegalStateException("Interrupted while releasing the common pool", e);
			}
		}
	}
}
