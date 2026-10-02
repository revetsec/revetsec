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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.Limits;
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

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * Every {@link HostileResponse} rejection against {@link HttpExchange} (M1 plan G6-7; exit criteria 10 and 12): each
 * runs on the transport it names and again on {@link RawTlsServer}, which must see the client close the connection,
 * because a rejection that leaves the connection open and unread leaks it (M1 plan, "Risks"). The exceptions are the
 * responses the JDK refuses itself and leaves open, which Revetsec cannot reach
 * ({@link HostileResponse#isClientCloseObservable()}). Every redirect's
 * {@code Location} target keeps a hit count of zero, and the 12 MiB bodies are aborted, not read, which the server
 * observes.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class HttpExchangeHostileTests {
	/**
	 * Server-side checks allow about 10 s: once a server took 3.1 s to notice an abort on JDK 25 (M1 plan).
	 */
	private static final Duration SERVER_WAIT = Duration.ofSeconds(10);

	/**
	 * The deadline that ends a paced case, as in exit criterion 11's own test; each keeps its server busy for minutes
	 * otherwise. It leaves time for the connection and the request, which the server must record, on a loaded host.
	 */
	private static final Duration SHORT_DEADLINE = Duration.ofMillis(1_500);

	private static final AtomicInteger NEXT_PATH = new AtomicInteger();

	private static @Nullable TestHttpsServer jdkServer;
	private static @Nullable RawTlsServer rawServer;
	private static @Nullable HttpExchange exchange;

	@BeforeAll
	static void startServers() throws IOException {
		jdkServer = TestHttpsServer.start();
		rawServer = RawTlsServer.start();
		// One client for the class, as an application would inject; each rejection must close its own connection.
		exchange = HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false);
	}

	@AfterAll
	static void stopServers() {
		if (jdkServer != null)
			jdkServer.close();
		if (rawServer != null)
			rawServer.close();
	}

	// Exit criteria 10 and 12: each case on the server it was written for.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyRejectionEndsAsExpectedOnItsOwnTransport() {
		return HostileResponse.rejections().stream()
				.map(hostileResponse -> DynamicTest.dynamicTest(hostileResponse.getName(), () -> {
					if (hostileResponse.getTransport() == HostileResponse.Transport.TEST_HTTPS_SERVER)
						runOnJdkServer(hostileResponse);
					else
						runOnRawServer(hostileResponse);
				}));
	}

	// Exit criterion 12: every rejection case also runs on RawTlsServer, which sees the client close the connection.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyJdkServerRejectionAlsoEndsWithTheClientClosingARawConnection() {
		return HostileResponse.rejections().stream()
				.filter(hostileResponse -> hostileResponse.getTransport() == HostileResponse.Transport.TEST_HTTPS_SERVER)
				.map(hostileResponse -> DynamicTest.dynamicTest(hostileResponse.getName(),
						() -> runOnRawServer(hostileResponse)));
	}

	// The zero-hit assertions are meaningful only if a client that follows redirects would have hit the target: a
	// plain JDK client with Redirect.NORMAL does (plan 14.1; G6-5).
	@Test
	void aClientThatFollowsRedirectsWouldHaveRequestedTheRedirectTarget() throws Exception {
		TestHttpsServer server = requireNonNullServer(jdkServer);
		HostileResponse redirect = HostileResponse.rejections().stream()
				.filter(hostileResponse -> hostileResponse.isRedirect() && hostileResponse.getName().endsWith("302"))
				.findFirst()
				.orElseThrow();
		String path = nextPath();
		redirect.installOn(server, path);
		server.script(HostileResponse.redirectTargetPath(path), TestHttpsServer.Script.fromResponse(
				TestHttpsServer.Response.fromJson(200, "{}")));

		HttpClient following = TestTls.httpClientBuilder().followRedirects(HttpClient.Redirect.NORMAL).build();
		HttpResponse<String> response = following.send(HttpRequest.newBuilder(server.uri(path)).build(),
				HttpResponse.BodyHandlers.ofString());

		Assertions.assertEquals(200, response.statusCode());
		Assertions.assertEquals(1, server.getHitCount(HostileResponse.redirectTargetPath(path)));
	}

	// Plan 14.1: the catalog covers every kind a response can cause, on both transports.
	@Test
	void theCatalogCoversEveryResponseKindAndBothTransports() {
		List<HostileResponse> cases = HostileResponse.all();
		for (Kind kind : List.of(Kind.REDIRECT, Kind.FRAMING, Kind.CONTENT_ENCODING, Kind.TOO_LARGE, Kind.MEDIA_TYPE,
				Kind.TIMEOUT, Kind.IO))
			Assertions.assertTrue(cases.stream().anyMatch(hostileResponse -> hostileResponse.getExpectedKind()
					.filter(kind::equals).isPresent()), kind::name);
		Assertions.assertTrue(cases.stream().anyMatch(hostileResponse -> hostileResponse.getExpectedKind().isEmpty()));
		for (HostileResponse.Transport transport : HostileResponse.Transport.values())
			Assertions.assertTrue(cases.stream().anyMatch(hostileResponse -> hostileResponse.getTransport() == transport),
					transport::name);
		Assertions.assertEquals(cases.size(), cases.stream().map(HostileResponse::getName).distinct().count(),
				"case names are unique");
	}

	// M2 exit criterion 14: every case of the JWKS catalog ends as expected when it is requested the way a JSON Web Key
	// Set fetch requests it, under the JWKS profile and its 256 KiB default body limit, on the transport it names, with
	// the same client-close and redirect-target checks as above.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyJwksRejectionEndsAsExpectedUnderTheJwksProfile() {
		return HostileResponse.jwks().stream()
				.filter(hostileResponse -> !hostileResponse.isPaced())
				.map(hostileResponse -> DynamicTest.dynamicTest(hostileResponse.getName(), () -> {
					HttpExchangeRequest request = hostileResponse.requestFor(URI.create("https://example.com/jwks"));
					Assertions.assertEquals(ResponseProfile.JWKS, request.profile());
					Assertions.assertEquals(Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue(), request.maximumBodyBytes());

					if (hostileResponse.getTransport() == HostileResponse.Transport.TEST_HTTPS_SERVER)
						runOnJdkServer(hostileResponse);
					else
						runOnRawServer(hostileResponse);
				}));
	}

	// M2 exit criterion 14 (the tarpit) and M1 exit criterion 11: the paced cases end in TIMEOUT under the JWKS profile
	// too, by a short deadline, and the server sees the client leave.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyJwksTimeoutEndsInTimeoutByAShortDeadline() {
		return HostileResponse.jwks().stream()
				.filter(HostileResponse::isPaced)
				.map(hostileResponse -> DynamicTest.dynamicTest(hostileResponse.getName(), () -> {
					RawTlsServer server = requireNonNullServer(rawServer);
					String path = nextPath();
					hostileResponse.installOn(server, path);

					HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
							() -> requireNonNullExchange(exchange).execute(hostileResponse.requestFor(server.uri(path)),
									Deadline.fromNow(SHORT_DEADLINE)));

					Assertions.assertEquals(Kind.TIMEOUT, exception.getKind());
					Assertions.assertEquals(Optional.of(Kind.TIMEOUT), hostileResponse.getExpectedKind());
					RawTlsServer.Connection connection = connectionOf(server, awaitRecordedRequest(server, path));
					Assertions.assertTrue(connection.awaitClientClose(SERVER_WAIT), () -> "the client closed " + connection);
				}));
	}

	// M2 exit criterion 14: the JWKS catalog is every rejection that applies to JWKS, the JWKS-only cases and every
	// paced case, last; every case is requested under JWKS; the names are unique; and together they cover every kind
	// a response can cause, a dropped error body, a JDK-refused head (IO) and the JWKS body limit.
	@Test
	void theJwksCatalogCoversEveryResponseKindUnderTheJwksProfile() {
		List<HostileResponse> cases = HostileResponse.jwks();
		List<String> names = cases.stream().map(HostileResponse::getName).toList();

		Assertions.assertEquals(names.size(), names.stream().distinct().count(), "case names are unique");
		for (HostileResponse hostileResponse : cases)
			Assertions.assertEquals(ResponseProfile.JWKS, hostileResponse.getProfile(), hostileResponse::getName);

		for (HostileResponse rejection : HostileResponse.rejections()) {
			String expectedName = rejection.getProfile() == ResponseProfile.JWKS ? rejection.getName()
					: rejection.getName() + HostileResponse.JWKS_NAME_SUFFIX;
			Assertions.assertEquals(rejection.appliesTo(ResponseProfile.JWKS), names.contains(expectedName),
					rejection::getName);
		}
		for (HostileResponse timeout : HostileResponse.timeouts())
			Assertions.assertTrue(names.contains(timeout.getName() + HostileResponse.JWKS_NAME_SUFFIX), timeout::getName);

		long jwksOnly = names.stream().filter(name -> name.startsWith("JWKS: ")).count();
		Assertions.assertEquals(13, jwksOnly);
		Assertions.assertEquals(HostileResponse.rejections().stream()
				.filter(rejection -> rejection.appliesTo(ResponseProfile.JWKS)).count() + jwksOnly
				+ HostileResponse.timeouts().size(), cases.size());

		int firstPaced = names.size();
		for (int index = 0; index < cases.size(); ++index)
			if (cases.get(index).isPaced()) {
				firstPaced = index;
				break;
			}
		Assertions.assertEquals(HostileResponse.timeouts().size(), cases.size() - firstPaced, "the paced cases are last");
		for (HostileResponse paced : cases.subList(firstPaced, cases.size()))
			Assertions.assertTrue(paced.isPaced(), paced::getName);

		for (Kind kind : List.of(Kind.REDIRECT, Kind.FRAMING, Kind.CONTENT_ENCODING, Kind.TOO_LARGE, Kind.MEDIA_TYPE,
				Kind.TIMEOUT, Kind.IO))
			Assertions.assertTrue(cases.stream().anyMatch(hostileResponse -> hostileResponse.getExpectedKind()
					.filter(kind::equals).isPresent()), kind::name);
		Assertions.assertTrue(cases.stream().anyMatch(hostileResponse -> hostileResponse.getExpectedKind().isEmpty()));
		Assertions.assertEquals(Optional.of(Kind.IO), cases.stream()
				.filter(hostileResponse -> hostileResponse.getName().equals("an invalid status line"
						+ HostileResponse.JWKS_NAME_SUFFIX))
				.findFirst().orElseThrow().getExpectedKind());
		Assertions.assertTrue(names.contains("JWKS: fixed-length 2xx one byte over the JWKS body limit"));
	}

	// HostileResponse.appliesTo: every case that is not a media-type case keeps its expectation under every profile,
	// which is what lets M2 and M3 reuse the catalog for their own endpoints.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyProfileAgnosticCaseEndsTheSameUnderEveryProfile() {
		List<DynamicTest> tests = new ArrayList<>();
		for (HostileResponse hostileResponse : HostileResponse.rejections())
			for (ResponseProfile profile : ResponseProfile.values())
				if (hostileResponse.appliesTo(profile) && profile != hostileResponse.getProfile()
						&& !hostileResponse.isServerAbortObservable() && hostileResponse.isClientCloseObservable())
					tests.add(DynamicTest.dynamicTest(hostileResponse.getName() + " as " + profile, () -> {
						RawTlsServer server = requireNonNullServer(rawServer);
						String path = nextPath();
						hostileResponse.installOn(server, path);
						assertExpectedOutcome(hostileResponse, HttpExchangeRequest.fromDefaults(server.uri(path), profile));
					}));
		return tests.stream();
	}

	// An injected client that returns a future of its own (a decorating client) keeps every outcome. But for a
	// Content-Length the JDK cannot parse, the JDK fails the exchange without subscribing the early subscriber, and
	// cancelling the decorator's future does not reach it: JDK 27 closes the connection itself, while JDK 17 to 25
	// leave it open until the server closes it, and JDK 26 until the request timeout. So the close is asserted on 27
	// and later only (HttpExchange's class documentation).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aDecoratingClientKeepsEveryOutcomeForAContentLengthTheJdkCannotParse() {
		return HostileResponse.rejections().stream()
				.filter(hostileResponse -> hostileResponse.getTransport() == HostileResponse.Transport.RAW_TLS_SERVER
						&& !hostileResponse.getName().startsWith("204") && hasUnparseableContentLength(hostileResponse))
				.map(hostileResponse -> DynamicTest.dynamicTest(hostileResponse.getName(), () -> {
					RawTlsServer server = requireNonNullServer(rawServer);
					String path = nextPath();
					hostileResponse.installOn(server, path);
					HttpExchange decorated = HttpExchange.fromHttpClient(
							new HttpExchangeDeadlineTests.DetachedFutureHttpClient(TestTls.httpClient()),
							OutboundUriPolicy.defaultInstance(), false);

					assertExpectedOutcome(decorated, hostileResponse, hostileResponse.requestFor(server.uri(path)));

					if (Runtime.version().feature() >= 27) {
						RawTlsServer.Connection connection = connectionOf(server, recordedRequest(server, path));
						Assertions.assertTrue(connection.awaitClientClose(SERVER_WAIT), () -> "the client closed " + connection);
					}
				}));
	}

	private static boolean hasUnparseableContentLength(@NonNull HostileResponse hostileResponse) {
		return List.of("a Content-Length list", "a hexadecimal Content-Length", "a Content-Length too large for a long")
				.stream().anyMatch(hostileResponse.getName()::endsWith);
	}

	private static void runOnJdkServer(@NonNull HostileResponse hostileResponse) throws Exception {
		TestHttpsServer server = requireNonNullServer(jdkServer);
		String path = nextPath();
		hostileResponse.installOn(server, path);

		assertExpectedOutcome(hostileResponse, server.uri(path));

		if (hostileResponse.isRedirect())
			Assertions.assertEquals(0, server.getHitCount(HostileResponse.redirectTargetPath(path)));
		if (hostileResponse.isServerAbortObservable()) {
			List<TestHttpsServer.RecordedRequest> requests = server.getRequests(path);
			Assertions.assertEquals(1, requests.size());
			Assertions.assertEquals(TestHttpsServer.Outcome.CLIENT_ABORTED, requests.get(0).awaitOutcome(SERVER_WAIT),
					"the server saw the client abort the body");
		}
	}

	private static void runOnRawServer(@NonNull HostileResponse hostileResponse) throws Exception {
		RawTlsServer server = requireNonNullServer(rawServer);
		String path = nextPath();
		hostileResponse.installOn(server, path);

		assertExpectedOutcome(hostileResponse, server.uri(path));

		if (hostileResponse.isRedirect())
			Assertions.assertEquals(0, server.getHitCount(HostileResponse.redirectTargetPath(path)));
		Assertions.assertEquals(1, server.getHitCount(path));

		if (!hostileResponse.isClientCloseObservable())
			return;

		RawTlsServer.RecordedRequest request = recordedRequest(server, path);
		RawTlsServer.Connection connection = connectionOf(server, request);
		Assertions.assertTrue(connection.awaitClientClose(SERVER_WAIT), () -> "the client closed " + connection);
		if (hostileResponse.isServerAbortObservable())
			Assertions.assertEquals(RawTlsServer.Outcome.CLIENT_ABORTED, request.awaitOutcome(SERVER_WAIT),
					"the server saw the client abort the body");
	}

	private static void assertExpectedOutcome(@NonNull HostileResponse hostileResponse, @NonNull URI uri) {
		assertExpectedOutcome(hostileResponse, hostileResponse.requestFor(uri));
	}

	private static void assertExpectedOutcome(@NonNull HostileResponse hostileResponse, @NonNull HttpExchangeRequest request) {
		assertExpectedOutcome(requireNonNullExchange(exchange), hostileResponse, request);
	}

	private static void assertExpectedOutcome(@NonNull HttpExchange httpExchange, @NonNull HostileResponse hostileResponse,
			@NonNull HttpExchangeRequest request) {
		Deadline deadline = Deadline.fromNow(Duration.ofSeconds(30));

		if (hostileResponse.getExpectedKind().isPresent()) {
			HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
					() -> httpExchange.execute(request, deadline));
			Assertions.assertEquals(hostileResponse.getExpectedKind().orElseThrow(), exception.getKind());
			return;
		}

		RawResponse response = Assertions.assertDoesNotThrow(() -> httpExchange.execute(request, deadline));
		Assertions.assertEquals(hostileResponse.getExpectedDroppedStatus().orElseThrow(), response.status());
		Assertions.assertTrue(response.errorBodyDropped());
		Assertions.assertEquals(0, response.body().length);
	}

	private static RawTlsServer.@NonNull RecordedRequest recordedRequest(@NonNull RawTlsServer server, @NonNull String path) {
		for (RawTlsServer.RecordedRequest request : server.getRequests())
			if (request.getPath().equals(path))
				return request;
		throw new AssertionError("No recorded request for " + path + " among " + server.getRequests());
	}

	/**
	 * The request recorded at {@code path}, waiting up to {@link #SERVER_WAIT} for the server to record it.
	 */
	private static RawTlsServer.@NonNull RecordedRequest awaitRecordedRequest(@NonNull RawTlsServer server, @NonNull String path)
			throws InterruptedException {
		long deadline = System.nanoTime() + SERVER_WAIT.toNanos();
		while (server.getRequests().stream().noneMatch(request -> request.getPath().equals(path))) {
			long remaining = deadline - System.nanoTime();
			if (remaining <= 0)
				throw new AssertionError("No recorded request for " + path);
			server.awaitRequestCount(server.getRequests().size() + 1, Duration.ofNanos(remaining));
		}
		return recordedRequest(server, path);
	}

	private static RawTlsServer.@NonNull Connection connectionOf(@NonNull RawTlsServer server, RawTlsServer.@NonNull RecordedRequest request) {
		for (RawTlsServer.Connection connection : server.getConnections())
			for (RawTlsServer.RecordedRequest candidate : connection.getRequests())
				if (candidate == request)
					return connection;
		throw new AssertionError("No connection carried " + request);
	}

	private static @NonNull String nextPath() {
		return "/hostile/" + NEXT_PATH.incrementAndGet();
	}

	private static <T> @NonNull T requireNonNullServer(@Nullable T server) {
		if (server == null)
			throw new IllegalStateException("The servers did not start");
		return server;
	}

	private static @NonNull HttpExchange requireNonNullExchange(@Nullable HttpExchange httpExchange) {
		if (httpExchange == null)
			throw new IllegalStateException("The exchange was not created");
		return httpExchange;
	}
}
