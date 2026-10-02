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

import org.jspecify.annotations.NonNull;

import com.revetsec.ErrorCategory;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.jose.KeySelection;
import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestHttpsServer.Response;
import com.revetsec.testing.TestHttpsServer.Script;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static com.revetsec.jose.JwksCacheTests.START;
import static com.revetsec.jose.JwksCacheTests.assertUnavailable;
import static com.revetsec.jose.JwksCacheTests.keySetJson;
import static com.revetsec.jose.JwksCacheTests.rs256;
import static com.revetsec.jose.JwksCacheTests.select;

/**
 * {@link RemoteJsonWebKeySource} end to end over TLS, against the in-process {@link TestHttpsServer} and the JDK's
 * client (M2 plan, "RemoteJsonWebKeySource algorithm"): exit criteria 12, 13 (the unknown-key cooldown, stale keys and
 * timeouts), 15 and 18 (the fetch-time URI backstop). The server always sends a wall-clock
 * {@code Date}, so lifetimes here come from {@code max-age}, {@code no-store} or no header; the {@code Date},
 * {@code Expires} and {@code Age} cases are {@code CacheLifetimeTests}' table on {@code RawTlsServer}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RemoteJsonWebKeySourceTests {
	private static final AtomicInteger NEXT_PATH = new AtomicInteger();
	private static @Nullable TestHttpsServer server;
	private static @Nullable HttpClient client;

	@BeforeAll
	static void startServer() throws IOException {
		server = TestHttpsServer.start();
		client = TestTls.httpClient();
	}

	@AfterAll
	static void stopServer() {
		if (server != null)
			server.close();
	}

	// Plan "RemoteJsonWebKeySource algorithm": the first need fetches over TLS on the caller's thread with the JWKS
	// Accept header and identity encoding, and reports the fetch with its usable and skipped counts and lifetime.
	@Test
	void theFirstNeedFetchesTheKeySet() {
		String path = path();
		server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(keySetJson("a"))));
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(path, TestClock.fromInstant(START)).observer(observer.getObserver())
				.build();

		Assertions.assertEquals(0, server().getHitCount(path));
		KeySelection selection = select(source, "a");
		Assertions.assertEquals(KeySelection.Kind.FOUND, selection.getKind());
		Assertions.assertEquals(1, server().getHitCount(path));
		TestHttpsServer.RecordedRequest request = server().getRequests(path).get(0);
		Assertions.assertEquals("GET", request.getMethod());
		Assertions.assertEquals(Optional.of("application/jwk-set+json, application/json"), request.getHeader("Accept"));
		Assertions.assertEquals(Optional.of("identity"), request.getHeader("Accept-Encoding"));

		RecordingObserver.Call fetched = observer.getCalls("didFetchJsonWebKeySet").get(0);
		Assertions.assertEquals(List.of(server().uri(path), 1, 0, Duration.ofMinutes(10)),
				fetched.getArguments().subList(0, 4));
		Assertions.assertEquals(List.of(server().uri(path)), observer.getCalls("willFetchJsonWebKeySet").get(0)
				.getArguments());
	}

	// Exit criterion 15 (RFC 9111 section 5.2): max-age=5 gives the 1 min minimum, no-store the minimum,
	// max-age=999999999 the 6 h maximum, and no header the 10 min default. The key set is fresh one nanosecond before
	// that and refetched at it.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theTimeToLiveFollowsCacheControlWithinTheLimits() {
		return Stream.of(
				List.of("max-age=5", "PT1M"), List.of("no-store", "PT1M"), List.of("max-age=999999999", "PT6H"),
				List.of("", "PT10M"), List.of("max-age=3600, must-revalidate", "PT1H"), List.of("no-cache", "PT1M"))
				.map(row -> DynamicTest.dynamicTest(row.get(0).isEmpty() ? "no Cache-Control" : row.get(0), () -> {
					String path = path();
					Response response = row.get(0).isEmpty() ? Response.fromJsonWebKeySet(keySetJson("a"))
							: Response.fromJsonWebKeySet(keySetJson("a"), row.get(0));
					server().script(path, Script.fromResponse(response));
					TestClock clock = TestClock.fromInstant(START);
					RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
					RemoteJsonWebKeySource source = source(path, clock).observer(observer.getObserver()).build();
					Duration timeToLive = Duration.parse(row.get(1));

					Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
					Assertions.assertEquals(timeToLive, observer.getCalls("didFetchJsonWebKeySet").get(0).getArgument(3));
					clock.advance(timeToLive.minusNanos(1));
					Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
					Assertions.assertEquals(1, server().getHitCount(path));
					clock.advance(Duration.ofNanos(1));
					Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
					Assertions.assertEquals(2, server().getHitCount(path));
				}));
	}

	// Exit criterion 15 and M2-8's lifetime rules through the source, on RawTlsServer so Date, Expires and Age can be
	// scripted (RFC 9111 sections 4.2.1, 4.2.3 and 5.3): the source hands the response's headers and its own clock's
	// receipt time to the lifetime computation. Expires minus the server's Date ignores the skew between the two
	// clocks; Expires without a Date counts from receipt on the source's clock; Age is subtracted; and Entra's
	// max-age=86400, private is clamped to the 6 h maximum.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theLifetimeUsesTheServersDateOrTheSourcesClock() throws IOException {
		RawTlsServer rawServer = RawTlsServer.start();
		String body = keySetJson("a");
		return Stream.of(
				List.of("Expires two hours after a Date an hour behind this clock",
						"Date: Sat, 26 Sep 2026 23:00:00 GMT\r\nExpires: Sun, 27 Sep 2026 01:00:00 GMT\r\n", "PT2H"),
				List.of("Expires half an hour after receipt, with no Date",
						"Expires: Sun, 27 Sep 2026 00:30:00 GMT\r\n", "PT30M"),
				List.of("max-age=3600 with Age: 3500", "Cache-Control: max-age=3600\r\nAge: 3500\r\n", "PT1M40S"),
				List.of("Expires before Date",
						"Date: Sun, 27 Sep 2026 00:00:00 GMT\r\nExpires: Sat, 26 Sep 2026 23:00:00 GMT\r\n", "PT1M"),
				List.of("Expires: 0", "Expires: 0\r\n", "PT1M"),
				List.of("max-age=86400, private", "Cache-Control: max-age=86400, private\r\n", "PT6H"))
				.map(row -> DynamicTest.dynamicTest(row.get(0), () -> {
					String path = path();
					rawServer.script(path, RawTlsServer.Script.fromString("HTTP/1.1 200 OK\r\n"
							+ "Content-Type: application/jwk-set+json\r\n" + row.get(1) + "Content-Length: "
							+ body.getBytes(StandardCharsets.UTF_8).length + "\r\n\r\n" + body));
					TestClock clock = TestClock.fromInstant(START);
					RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
					RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(rawServer.uri(path)).httpClient(client())
							.clock(clock).observer(observer.getObserver()).build();
					Duration timeToLive = Duration.parse(row.get(2));

					Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
					Assertions.assertEquals(timeToLive, observer.getCalls("didFetchJsonWebKeySet").get(0).getArgument(3));
					clock.advance(timeToLive.minusNanos(1));
					Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
					Assertions.assertEquals(1, rawServer.getHitCount(path));
					clock.advance(Duration.ofNanos(1));
					Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
					Assertions.assertEquals(2, rawServer.getHitCount(path));
				})).onClose(rawServer::close);
	}

	// Exit criterion 15: a 300 KiB key set without a Content-Length is aborted at the
	// 256 KiB limit, and 101 keys is too many; both are MALFORMED_INPUT, not transient, and the previous key set
	// stays in use.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> anOversizedRefreshFailsAndThePreviousKeySetStaysInUse() {
		Response oversized = Response.withStatus(200).header("Content-Type", TestHttpsServer.JWK_SET_MEDIA_TYPE)
				.body(new byte[300 * 1024]).framing(TestHttpsServer.Framing.CHUNKED).build();
		Response tooManyKeys = Response.fromJsonWebKeySet(keySetJson(JwksCacheTests.keyIds(101)));
		return Stream.of(Map.entry("300 KiB with no Content-Length", oversized), Map.entry("101 keys", tooManyKeys))
				.map(row -> DynamicTest.dynamicTest(row.getKey(), () -> {
					String path = path();
					server().script(path, Script.fromSequence(List.of(Response.fromJsonWebKeySet(keySetJson("a")),
							row.getValue())));
					TestClock clock = TestClock.fromInstant(START);
					RemoteJsonWebKeySource source = source(path, clock).build();
					Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());

					clock.advance(Duration.ofSeconds(1));
					JsonWebKeySetUnavailableException exception = assertUnavailable(ErrorCategory.MALFORMED_INPUT, false,
							() -> select(source, "k-1"));
					Assertions.assertNull(exception.getCause());
					Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
					Assertions.assertEquals(2, server().getHitCount(path));

					// Past its expiry the previous key set still answers for its keys while refreshes fail.
					clock.advance(Duration.ofMinutes(10));
					Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
					Assertions.assertEquals(3, server().getHitCount(path));
				}));
	}

	// OpenID Connect Core section 10.1.1 over the wire: a rotated-in key is fetched at once and verifies; another
	// unknown key within the 30 s cooldown sends nothing and has no key; after it, one more fetch.
	@Test
	void anUnknownKeyRefetchesOncePerCooldown() {
		String path = path();
		server().script(path, Script.fromSequence(List.of(Response.fromJsonWebKeySet(keySetJson("a")),
				Response.fromJsonWebKeySet(keySetJson("a", "b")))));
		TestClock clock = TestClock.fromInstant(START);
		RemoteJsonWebKeySource source = source(path, clock).build();

		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		clock.advance(Duration.ofSeconds(1));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "b").getKind());
		Assertions.assertEquals(2, server().getHitCount(path));
		clock.advance(Duration.ofSeconds(29));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "c").getKind());
		Assertions.assertEquals(2, server().getHitCount(path));
		clock.advance(Duration.ofSeconds(1));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "c").getKind());
		Assertions.assertEquals(3, server().getHitCount(path));
	}

	// Exit criterion 12: a key removed from the key set stops verifying at the first
	// successful refresh after the time to live, and not before. The stored key set lacks it too, not only the refresh
	// leader's answer: a later call reads that set, finds no key and makes the one unknown-key refetch the expiry refresh
	// left it (that refresh took no cooldown mark), and a call inside that refetch's cooldown sends nothing.
	@Test
	void aRemovedKeyStopsVerifyingAtTheFirstRefreshAfterTheTimeToLive() {
		String path = path();
		server().script(path, Script.fromSequence(List.of(Response.fromJsonWebKeySet(keySetJson("a", "b"),
				"max-age=60"), Response.fromJsonWebKeySet(keySetJson("a"), "max-age=60"))));
		TestClock clock = TestClock.fromInstant(START);
		RemoteJsonWebKeySource source = source(path, clock).build();

		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "b").getKind());
		clock.advance(Duration.ofSeconds(60).minusNanos(1));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "b").getKind());
		clock.advance(Duration.ofNanos(1));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind());
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(2, server().getHitCount(path));

		clock.advance(Duration.ofSeconds(1));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind(), "a caller after the leader");
		Assertions.assertEquals(3, server().getHitCount(path));
		clock.advance(Duration.ofSeconds(1));
		Assertions.assertEquals(KeySelection.Kind.UNKNOWN, select(source, "b").getKind(), "inside the cooldown");
		Assertions.assertEquals(3, server().getHitCount(path));
	}

	// Exit criterion 13 (stale keys) over the wire: past the time to live, a 500 on refresh leaves the old key
	// verifying and reports the failure with servingStaleKeys; a key the old set lacks gets REMOTE_ERROR, transient.
	@Test
	void aFailedRefreshServesStaleKeys() {
		String path = path();
		server().script(path, Script.fromSequence(List.of(Response.fromJsonWebKeySet(keySetJson("a")),
				Response.fromStatus(500))));
		TestClock clock = TestClock.fromInstant(START);
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(path, clock).observer(observer.getObserver()).build();
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());

		clock.advance(Duration.ofMinutes(10));
		Assertions.assertEquals(KeySelection.Kind.FOUND, select(source, "a").getKind());
		Assertions.assertEquals(true, observer.getCalls("didFailToFetchJsonWebKeySet").get(0).getArgument(2));
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, () -> select(source, "b"));
		Assertions.assertEquals(2, server().getHitCount(path));
	}

	// G8-9 and exit criterion 18: the fetch-time backstop, at the package-private constructor with URIs build() would
	// refuse. Each is CONFIGURATION, not transient, with zero requests; the same server records one request for the
	// permitted URI.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aUriRefusedAtFetchTimeIsAConfigurationFailureWithNoRequest() {
		return Stream.of("#fragment", "#", "user info").map(variant -> DynamicTest.dynamicTest(variant, () -> {
			String path = path();
			server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(keySetJson("a"))));
			URI permitted = server().uri(path);
			URI unchecked = variant.equals("user info")
					? URI.create("https://user@127.0.0.1:" + server().getPort() + path) : URI.create(permitted + variant);
			RemoteJsonWebKeySource built = source(path, TestClock.fromInstant(START)).build();
			RemoteJsonWebKeySource source = new RemoteJsonWebKeySource(unchecked, built.httpExchangeForTests(),
					JwksCacheTests.settings(TestClock.fromInstant(START), JoseObserver.disabledInstance()));

			assertUnavailable(ErrorCategory.CONFIGURATION, false, () -> select(source, "a"));
			assertUnavailable(ErrorCategory.CONFIGURATION, false, source::warmUp);
			Assertions.assertEquals(0, server().getHitCount(path));

			Assertions.assertEquals(KeySelection.Kind.FOUND, select(built, "a").getKind());
			Assertions.assertEquals(1, server().getHitCount(path));
		}));
	}

	// The category table: a refused connection is an I/O failure, TRANSPORT and transient, and the leader keeps the
	// JDK's IOException as its cause.
	@Test
	void aRefusedConnectionIsATransientTransportFailureWithItsIoCause() throws IOException {
		int port;
		try (ServerSocket socket = new ServerSocket()) {
			socket.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), 0));
			port = socket.getLocalPort();
		}
		RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(URI.create("https://127.0.0.1:" + port + "/keys"))
				.httpClient(client()).build();

		JsonWebKeySetUnavailableException exception = assertUnavailable(ErrorCategory.TRANSPORT, true,
				() -> select(source, "a"));
		Assertions.assertInstanceOf(IOException.class, exception.getCause());
		JsonWebKeySetUnavailableException remembered = assertUnavailable(ErrorCategory.TRANSPORT, true,
				() -> select(source, "a"));
		Assertions.assertNull(remembered.getCause());
	}

	// M2-8 and exit criterion 13: a server that never answers ends in TIMEOUT at the caller's deadline, a failure like
	// any other, and the backoff then answers at once with TRANSPORT, transient, and no request.
	@Test
	void aTarpitTimesOutAndStartsTheBackoff() throws InterruptedException {
		String path = path();
		server().script(path, Script.fromTarpit());
		TestClock clock = TestClock.fromInstant(START);
		RemoteJsonWebKeySource source = source(path, clock).build();
		int requestsBefore = server().getRequests().size();

		long started = System.nanoTime();
		assertUnavailable(ErrorCategory.TRANSPORT, true, () -> source.select(rs256("a"),
				Deadline.fromNow(Duration.ofMillis(400))));
		Assertions.assertTrue(Duration.ofNanos(System.nanoTime() - started).compareTo(Duration.ofMillis(399)) > 0);
		Assertions.assertTrue(server().awaitRequestCount(requestsBefore + 1, Duration.ofSeconds(10)));
		Assertions.assertEquals(1, server().getHitCount(path));

		Deadline deadline = Deadline.fromNow(Duration.ofSeconds(10));
		assertUnavailable(ErrorCategory.TRANSPORT, true, () -> source.select(rs256("a"), deadline));
		Assertions.assertTrue(deadline.remainingNanos() > 0, "held back at once, not after waiting out the deadline");
		Assertions.assertEquals(1, server().getHitCount(path));
	}

	private static RemoteJsonWebKeySource.@NonNull Builder source(@NonNull String path, @NonNull TestClock clock) {
		return RemoteJsonWebKeySource.withUri(server().uri(path)).httpClient(client()).clock(clock);
	}

	private static @NonNull String path() {
		return "/jwks/" + NEXT_PATH.incrementAndGet();
	}

	private static @NonNull TestHttpsServer server() {
		TestHttpsServer current = server;
		if (current == null)
			throw new IllegalStateException("The server did not start");
		return current;
	}

	private static @NonNull HttpClient client() {
		HttpClient current = client;
		if (current == null)
			throw new IllegalStateException("The client was not created");
		return current;
	}
}
