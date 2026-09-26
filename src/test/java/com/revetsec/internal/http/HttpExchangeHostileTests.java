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

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
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
	Stream<DynamicTest> everyRejectionEndsAsExpectedOnItsOwnTransport() {
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
	Stream<DynamicTest> everyJdkServerRejectionAlsoEndsWithTheClientClosingARawConnection() {
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

	// HostileResponse.appliesTo: every case that is not a media-type case keeps its expectation under every profile,
	// which is what lets M2 and M3 reuse the catalog for their own endpoints.
	@TestFactory
	Stream<DynamicTest> everyProfileAgnosticCaseEndsTheSameUnderEveryProfile() {
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
	Stream<DynamicTest> aDecoratingClientKeepsEveryOutcomeForAContentLengthTheJdkCannotParse() {
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

	private static boolean hasUnparseableContentLength(HostileResponse hostileResponse) {
		return List.of("a Content-Length list", "a hexadecimal Content-Length", "a Content-Length too large for a long")
				.stream().anyMatch(hostileResponse.getName()::endsWith);
	}

	private static void runOnJdkServer(HostileResponse hostileResponse) throws Exception {
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

	private static void runOnRawServer(HostileResponse hostileResponse) throws Exception {
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

	private static void assertExpectedOutcome(HostileResponse hostileResponse, URI uri) {
		assertExpectedOutcome(hostileResponse, hostileResponse.requestFor(uri));
	}

	private static void assertExpectedOutcome(HostileResponse hostileResponse, HttpExchangeRequest request) {
		assertExpectedOutcome(requireNonNullExchange(exchange), hostileResponse, request);
	}

	private static void assertExpectedOutcome(HttpExchange httpExchange, HostileResponse hostileResponse,
			HttpExchangeRequest request) {
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

	private static RawTlsServer.RecordedRequest recordedRequest(RawTlsServer server, String path) {
		for (RawTlsServer.RecordedRequest request : server.getRequests())
			if (request.getPath().equals(path))
				return request;
		throw new AssertionError("No recorded request for " + path + " among " + server.getRequests());
	}

	private static RawTlsServer.Connection connectionOf(RawTlsServer server, RawTlsServer.RecordedRequest request) {
		for (RawTlsServer.Connection connection : server.getConnections())
			for (RawTlsServer.RecordedRequest candidate : connection.getRequests())
				if (candidate == request)
					return connection;
		throw new AssertionError("No connection carried " + request);
	}

	private static String nextPath() {
		return "/hostile/" + NEXT_PATH.incrementAndGet();
	}

	private static <T> T requireNonNullServer(@Nullable T server) {
		if (server == null)
			throw new IllegalStateException("The servers did not start");
		return server;
	}

	private static HttpExchange requireNonNullExchange(@Nullable HttpExchange httpExchange) {
		if (httpExchange == null)
			throw new IllegalStateException("The exchange was not created");
		return httpExchange;
	}
}
