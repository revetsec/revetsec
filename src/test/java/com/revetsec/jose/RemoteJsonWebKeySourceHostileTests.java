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

package com.revetsec.jose;

import com.revetsec.ErrorCategory;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HostileResponse;
import com.revetsec.internal.http.HttpExchangeException.Kind;
import com.revetsec.internal.jose.KeySelection;
import com.revetsec.jose.RemoteJsonWebKeySourceConcurrencyTests.Call;
import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.TestClock;
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
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static com.revetsec.jose.JwksCacheTests.START;
import static com.revetsec.jose.JwksCacheTests.WAIT;
import static com.revetsec.jose.JwksCacheTests.keySetJson;
import static com.revetsec.jose.JwksCacheTests.rs256;
import static com.revetsec.jose.JwksCacheTests.select;

/**
 * Hostile key-set endpoints (G8-8, M2-8; exit criteria 13 and 14): every JWKS case of the {@link HostileResponse}
 * catalog, for the leader and a waiter; the bound on attempts against an endpoint whose response head the JDK
 * refuses, and against one that answers a valid key set after each such failure; and a tarpit under a thousand
 * embedded calls with short deadlines. Every bound is asserted as attempt counts, never as the JDK's connection
 * behavior (M1 exit criterion 12's qualification).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RemoteJsonWebKeySourceHostileTests {
	private static final AtomicInteger NEXT_PATH = new AtomicInteger();
	/**
	 * The leader's deadline for the paced cases, M1 exit criterion 11's value.
	 */
	private static final Duration PACED_DEADLINE = Duration.ofMillis(1_500);
	private static final String INVALID_STATUS_LINE = "an invalid status line" + HostileResponse.JWKS_NAME_SUFFIX;
	private static @Nullable TestHttpsServer jdkServer;
	private static @Nullable RawTlsServer rawServer;
	private static @Nullable HttpClient client;

	@BeforeAll
	static void startServers() throws IOException {
		jdkServer = TestHttpsServer.start();
		rawServer = RawTlsServer.start();
		client = TestTls.httpClient();
	}

	@AfterAll
	static void stopServers() {
		if (jdkServer != null)
			jdkServer.close();
		if (rawServer != null)
			rawServer.close();
	}

	// Exit criterion 14 and the plan's category table: every JWKS case of the catalog gives the leader its category
	// and transience (the JDK's IOException as the cause, for IO only), and a waiter on the same flight the same
	// category and transience with no cause. A redirect's target is never requested.
	@TestFactory
	Stream<DynamicTest> everyHostileJwksResponseGivesItsCategoryToTheLeaderAndItsWaiters() {
		return HostileResponse.jwks().stream().map(hostileResponse -> DynamicTest.dynamicTest(hostileResponse.getName(),
				() -> {
					String path = path();
					URI uri;
					if (hostileResponse.getTransport() == HostileResponse.Transport.TEST_HTTPS_SERVER) {
						hostileResponse.installOn(jdkServer(), path);
						uri = jdkServer().uri(path);
					} else {
						hostileResponse.installOn(rawServer(), path);
						uri = rawServer().uri(path);
					}
					GatedClient gated = new GatedClient(client());
					RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
					RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(uri).httpClient(gated)
							.observer(observer.getObserver()).build();
					Duration leaderDeadline = hostileResponse.isPaced() ? PACED_DEADLINE : WAIT;

					Call<KeySelection> leader = Call.start("leader", () -> source.select(rs256("a"),
							Deadline.fromNow(leaderDeadline)));
					Assertions.assertTrue(gated.awaitEntered());
					Call<KeySelection> waiter = Call.start("waiter", () -> source.select(rs256("a"),
							Deadline.fromNow(WAIT)));
					Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(1, WAIT));
					gated.open();

					ErrorCategory category = expectedCategory(hostileResponse);
					boolean transientFailure = expectedTransience(hostileResponse);
					JsonWebKeySetUnavailableException leaderException = leader.awaitFailure(
							JsonWebKeySetUnavailableException.class);
					Assertions.assertEquals(category, leaderException.getCategory());
					Assertions.assertEquals(transientFailure, leaderException.isTransient());
					// An IO failure keeps the first IOException in the JDK's failure chain, when there is one: on some JDKs a
					// 204 whose Content-Length the JDK cannot parse fails with no IOException in the chain at all.
					@Nullable Throwable cause = leaderException.getCause();
					if (hostileResponse.getExpectedKind().equals(Optional.of(Kind.IO)))
						Assertions.assertTrue(cause == null || cause instanceof IOException, () -> String.valueOf(cause));
					else
						Assertions.assertNull(cause);
					Assertions.assertSame(leaderException, observer.getCalls("didFailToFetchJsonWebKeySet").get(0)
							.getArgument(1));

					JsonWebKeySetUnavailableException waiterException = waiter.awaitFailure(
							JsonWebKeySetUnavailableException.class);
					Assertions.assertEquals(category, waiterException.getCategory());
					Assertions.assertEquals(transientFailure, waiterException.isTransient());
					Assertions.assertNull(waiterException.getCause());
					Assertions.assertNotSame(leaderException, waiterException);
					Assertions.assertEquals(1, gated.getSendCount());

					if (hostileResponse.isRedirect()) {
						String target = HostileResponse.redirectTargetPath(path);
						Assertions.assertEquals(0, hostileResponse.getTransport()
								== HostileResponse.Transport.TEST_HTTPS_SERVER ? jdkServer().getHitCount(target)
								: rawServer().getHitCount(target));
					}
				}));
	}

	// Exit criterion 14 and G8-8: an endpoint whose status line the JDK refuses (IO, transient) gets at most 15 attempts
	// in one simulated hour at the defaults: at 0, 30, 90, 210 and 450 s, then every 300 s.
	@Test
	void anEndpointTheJdkRefusesGetsAtMostFifteenAttemptsAnHour() {
		String path = path();
		HostileResponse.jwks().stream().filter(hostileResponse -> hostileResponse.getName().equals(INVALID_STATUS_LINE))
				.findFirst().orElseThrow().installOn(rawServer(), path);
		TestClock clock = TestClock.fromInstant(START);
		AttemptObserver observer = new AttemptObserver(clock);
		RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(rawServer().uri(path)).httpClient(client())
				.clock(clock).observer(observer).build();

		for (int second = 0; second <= 3_600; second += 10) {
			clock.set(START.plusSeconds(second));
			JwksCacheTests.assertUnavailable(ErrorCategory.TRANSPORT, true, () -> select(source, "a"));
		}

		Assertions.assertEquals(List.of(0L, 30L, 90L, 210L, 450L, 750L, 1_050L, 1_350L, 1_650L, 1_950L, 2_250L, 2_550L,
				2_850L, 3_150L, 3_450L), observer.getAttemptSeconds());
		Assertions.assertEquals(15, rawServer().getHitCount(path));
	}

	// Exit criterion 14, G8-8 and M2-8 decay: an endpoint that answers a valid key set (no-store) after each refused
	// response gets no more failing attempts in the hour than one that always fails, because a success does not reset
	// the backoff; the key keeps verifying throughout, fresh or stale.
	@Test
	void anEndpointAlternatingWithValidKeySetsGetsNoMoreFailingAttempts() {
		String path = path();
		byte[] keySet = keySetJson("a").getBytes(StandardCharsets.UTF_8);
		rawServer().scriptCycle(path, List.of(
				RawTlsServer.Script.fromString("HTTP/1.1 099 Invalid\r\nContent-Length: 0\r\n\r\n"),
				RawTlsServer.Script.fromString("HTTP/1.1 200 OK\r\nContent-Type: application/jwk-set+json\r\n"
						+ "Cache-Control: no-store\r\nContent-Length: " + keySet.length + "\r\n\r\n"
						+ new String(keySet, StandardCharsets.UTF_8))));
		TestClock clock = TestClock.fromInstant(START);
		AttemptObserver observer = new AttemptObserver(clock);
		RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(rawServer().uri(path)).httpClient(client())
				.clock(clock).observer(observer).build();

		int verified = 0;
		for (int second = 0; second <= 3_600; second += 10) {
			clock.set(START.plusSeconds(second));
			try {
				Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
				++verified;
			} catch (JsonWebKeySetUnavailableException e) {
				Assertions.assertEquals(ErrorCategory.TRANSPORT, e.getCategory());
			}
		}

		// Failures at 0, 90, 210 and 390 s, then every 300 s (a 240 s step plus a 60 s key set): 14 in the hour, and
		// successes between them. The first three calls (0 to 20 s) have no key set at all.
		Assertions.assertEquals(14, observer.getFailures());
		Assertions.assertTrue(observer.getFailures() <= 15);
		Assertions.assertEquals(13, observer.getSuccesses());
		Assertions.assertEquals(27, rawServer().getHitCount(path));
		Assertions.assertEquals(361 - 3, verified);
	}

	// Exit criterion 13: a tarpit (it never answers) under 1,000 embedded unknown-key calls with 400 ms deadlines, over
	// one simulated hour, warm and cold: at most 15 requests, at most one unknown-key request per cooldown, and every
	// held-back call fails at once with TRANSPORT, transient, instead of waiting out its deadline.
	@TestFactory
	Stream<DynamicTest> aTarpitStaysWithinTheBackoffScheduleUnderEmbeddedDeadlines() {
		return Stream.of(false, true).map(warm -> DynamicTest.dynamicTest(warm ? "warm" : "cold", () -> {
			String path = path();
			TestClock clock = TestClock.fromInstant(START);
			AttemptObserver observer = new AttemptObserver(clock);
			RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(jdkServer().uri(path)).httpClient(client())
					.clock(clock).observer(observer).build();
			if (warm) {
				jdkServer().script(path, TestHttpsServer.Script.fromResponse(
						TestHttpsServer.Response.fromJsonWebKeySet(keySetJson("a"))));
				Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
			}
			jdkServer().script(path, TestHttpsServer.Script.fromTarpit());
			int warmFetches = warm ? 1 : 0;

			int heldBack = 0;
			for (int call = 0; call < 1_000; ++call) {
				clock.set(START.plusMillis(3_600L * call));
				int attemptsBefore = observer.getAttemptSeconds().size();
				Deadline deadline = Deadline.fromNow(Duration.ofMillis(400));
				String keyId = "unknown-" + call;
				JsonWebKeySetUnavailableException exception = JwksCacheTests.assertUnavailable(ErrorCategory.TRANSPORT,
						true, () -> source.select(rs256(keyId), deadline));
				Assertions.assertNull(exception.getCause());
				if (observer.getAttemptSeconds().size() == attemptsBefore) {
					++heldBack;
					Assertions.assertTrue(deadline.remainingNanos() > 0, "held back at once, not at its deadline");
				}
			}

			List<Long> attempts = observer.getAttemptSeconds().subList(warmFetches, observer.getAttemptSeconds().size());
			Assertions.assertTrue(attempts.size() <= 15, attempts::toString);
			Assertions.assertEquals(15, attempts.size(), attempts::toString);
			for (int index = 1; index < attempts.size(); ++index)
				Assertions.assertTrue(attempts.get(index) - attempts.get(index - 1) >= 30, attempts::toString);
			Assertions.assertEquals(1_000 - attempts.size(), heldBack);
			Assertions.assertTrue(jdkServer().getHitCount(path) <= warmFetches + attempts.size());
		}));
	}

	private static ErrorCategory expectedCategory(HostileResponse hostileResponse) {
		Optional<Kind> kind = hostileResponse.getExpectedKind();
		if (kind.isEmpty())
			return ErrorCategory.REMOTE_ERROR;
		return switch (kind.get()) {
			case TIMEOUT, IO, INTERRUPTED -> ErrorCategory.TRANSPORT;
			case REDIRECT -> ErrorCategory.REMOTE_ERROR;
			case TOO_LARGE, CONTENT_ENCODING, FRAMING, MEDIA_TYPE -> ErrorCategory.MALFORMED_INPUT;
			case URI_REJECTED, DEFAULT_CLIENT_UNAVAILABLE -> ErrorCategory.CONFIGURATION;
		};
	}

	private static boolean expectedTransience(HostileResponse hostileResponse) {
		Optional<Kind> kind = hostileResponse.getExpectedKind();
		if (kind.isPresent())
			return kind.get() == Kind.TIMEOUT || kind.get() == Kind.IO;
		int status = hostileResponse.getExpectedDroppedStatus().orElseThrow();
		return status == 429 || (status >= 500 && status <= 599);
	}

	private static String path() {
		return "/hostile-jwks/" + NEXT_PATH.incrementAndGet();
	}

	private static TestHttpsServer jdkServer() {
		TestHttpsServer server = jdkServer;
		if (server == null)
			throw new IllegalStateException("The server did not start");
		return server;
	}

	private static RawTlsServer rawServer() {
		RawTlsServer server = rawServer;
		if (server == null)
			throw new IllegalStateException("The server did not start");
		return server;
	}

	private static HttpClient client() {
		HttpClient current = client;
		if (current == null)
			throw new IllegalStateException("The client was not created");
		return current;
	}

	/**
	 * Records, on the clock, when each fetch was announced, and counts fetch outcomes.
	 */
	@ThreadSafe
	private static final class AttemptObserver implements JoseObserver {
		private final Clock clock;
		private final List<Long> attemptSeconds = new java.util.concurrent.CopyOnWriteArrayList<>();
		private final AtomicInteger successes = new AtomicInteger();
		private final AtomicInteger failures = new AtomicInteger();

		private AttemptObserver(Clock clock) {
			this.clock = clock;
		}

		List<Long> getAttemptSeconds() {
			return List.copyOf(this.attemptSeconds);
		}

		int getSuccesses() {
			return this.successes.get();
		}

		int getFailures() {
			return this.failures.get();
		}

		@Override
		public void willFetchJsonWebKeySet(URI jwksUri) {
			Instant now = this.clock.instant();
			this.attemptSeconds.add(Duration.between(START, now).toSeconds());
		}

		@Override
		public void didFetchJsonWebKeySet(URI jwksUri, Integer usableKeyCount, Integer skippedKeyCount,
				Duration timeToLive, Duration elapsed) {
			this.successes.incrementAndGet();
		}

		@Override
		public void didFailToFetchJsonWebKeySet(URI jwksUri, JsonWebKeySetUnavailableException exception,
				Boolean servingStaleKeys, Duration elapsed) {
			this.failures.incrementAndGet();
		}
	}

	/**
	 * Wraps a real client, holding the first {@code sendAsync} until the test opens the gate, so a waiter can join the
	 * leader's flight before the response arrives.
	 */
	@ThreadSafe
	private static final class GatedClient extends HttpClient {
		private final HttpClient delegate;
		private final CountDownLatch entered = new CountDownLatch(1);
		private final CountDownLatch gate = new CountDownLatch(1);
		private final AtomicInteger sendCount = new AtomicInteger();

		private GatedClient(HttpClient delegate) {
			this.delegate = delegate;
		}

		boolean awaitEntered() throws InterruptedException {
			return this.entered.await(WAIT.toNanos(), TimeUnit.NANOSECONDS);
		}

		void open() {
			this.gate.countDown();
		}

		int getSendCount() {
			return this.sendCount.get();
		}

		@Override
		public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
				HttpResponse.BodyHandler<T> responseBodyHandler) {
			this.sendCount.incrementAndGet();
			this.entered.countDown();
			try {
				if (!this.gate.await(WAIT.toNanos(), TimeUnit.NANOSECONDS))
					throw new IllegalStateException("The gate was never opened");
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new IllegalStateException("Interrupted at the gate", e);
			}
			return this.delegate.sendAsync(request, responseBodyHandler);
		}

		@Override
		public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
				HttpResponse.BodyHandler<T> responseBodyHandler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
			return sendAsync(request, responseBodyHandler);
		}

		@Override
		public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
				throws IOException, InterruptedException {
			return this.delegate.send(request, responseBodyHandler);
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
		public HttpClient.Redirect followRedirects() {
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
		public HttpClient.Version version() {
			return this.delegate.version();
		}

		@Override
		public Optional<Executor> executor() {
			return this.delegate.executor();
		}
	}
}
