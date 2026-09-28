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

import com.revetsec.ErrorCategory;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.Limits;
import com.revetsec.internal.http.HttpExchangeException.Kind;
import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.Sentinels;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import com.sun.net.httpserver.HttpServer;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * {@link HttpExchange}'s ordinary behavior (plan R12 as amended by G6-5 to G6-7; M1 plan, "HTTP helper"): what a
 * request sends, what a response returns, the media-type table on real responses, the size limits at their
 * boundaries, the URI checks, the {@link Kind} table and the redaction of every rendering. {@link HostileResponse}
 * cases are in {@link HttpExchangeHostileTests} and deadlines in {@link HttpExchangeDeadlineTests}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class HttpExchangeTests {
	private static final String JSON = "{\"issuer\":\"https://issuer.example\"}";
	private static final Duration LONG = Duration.ofSeconds(30);
	/**
	 * The deadline for {@link ScriptedHttpClient} exchanges: those that pass end at once, and a stalled one this soon.
	 */
	private static final Duration SCRIPTED = Duration.ofSeconds(3);
	private static final AtomicInteger NEXT_PATH = new AtomicInteger();

	private static @Nullable TestHttpsServer jdkServer;
	private static @Nullable RawTlsServer rawServer;
	private static @Nullable HttpExchange exchange;

	@BeforeAll
	static void startServers() throws IOException {
		jdkServer = TestHttpsServer.start();
		rawServer = RawTlsServer.start();
		exchange = HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false);
	}

	@AfterAll
	static void stopServers() {
		if (jdkServer != null)
			jdkServer.close();
		if (rawServer != null)
			rawServer.close();
	}

	// R12: a 2xx that meets its profile is returned whole, with its status, headers and parsed media type.
	@Test
	void returnsA2xxBodyWithItsStatusHeadersAndMediaType() throws Exception {
		String path = script(TestHttpsServer.Response.withStatus(200)
				.header("Content-Type", "application/json; charset=utf-8")
				.header("Cache-Control", "no-store")
				.body(JSON)
				.build());

		RawResponse response = execute(HttpExchangeRequest.fromDefaults(jdk().uri(path), ResponseProfile.METADATA));

		Assertions.assertEquals(200, response.status());
		Assertions.assertTrue(response.isSuccessful());
		Assertions.assertEquals(JSON, new String(response.body(), StandardCharsets.UTF_8));
		Assertions.assertEquals("application/json", requiredMediaType(response).getEssence());
		Assertions.assertEquals("utf-8", requiredMediaType(response).getCharset().orElseThrow());
		Assertions.assertEquals("no-store", response.headers().firstValue("Cache-Control").orElseThrow());
		Assertions.assertFalse(response.errorBodyDropped());
		Assertions.assertFalse(response.elapsed().isNegative());
	}

	// G6-7 and R12: every request sends its profile's Accept and Accept-Encoding: identity; a GET has no body.
	@TestFactory
	Stream<DynamicTest> sendsTheProfilesAcceptAndAcceptEncodingIdentity() {
		return Arrays.stream(ResponseProfile.values()).map(profile -> DynamicTest.dynamicTest(profile.name(), () -> {
			String path = script(TestHttpsServer.Response.withStatus(200)
					.header("Content-Type", profile == ResponseProfile.USERINFO ? "application/jwt" : "application/json")
					.body("{}")
					.build());

			execute(HttpExchangeRequest.fromDefaults(jdk().uri(path), profile));

			TestHttpsServer.RecordedRequest request = jdk().getRequests(path).get(0);
			Assertions.assertEquals("GET", request.getMethod());
			Assertions.assertEquals(List.of(profile.getAcceptHeaderValue()), request.getHeaders().get("Accept"));
			Assertions.assertEquals(List.of("identity"), request.getHeaders().get("Accept-Encoding"));
			Assertions.assertNull(request.getHeaders().get("Content-Type"));
			Assertions.assertEquals(0, request.getBody().length);
		}));
	}

	// RFC 6749 section 3.2 and Appendix B: a form POST carries its Content-Type, its exact bytes and the caller's
	// headers, such as client_secret_basic's Authorization.
	@Test
	void postsAFormBodyWithItsContentTypeAndTheCallersHeaders() throws Exception {
		String path = script(TestHttpsServer.Response.fromJson(200, "{\"access_token\":\"x\"}"));
		String form = "grant_type=client_credentials&scope=a+b%2Fc";
		HttpExchangeRequest request = new HttpExchangeRequest(jdk().uri(path), ResponseProfile.TOKEN, form,
				Map.of("Authorization", "Basic YTpi", "DPoP", "eyJ0eXAiOiJkcG9wK2p3dCJ9.e30.c2ln"),
				Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue(), Limits.HTTP_ERROR_BODY_SIZE.getDefaultIntValue(),
				LONG);

		execute(request);

		TestHttpsServer.RecordedRequest recorded = jdk().getRequests(path).get(0);
		Assertions.assertEquals("POST", recorded.getMethod());
		Assertions.assertEquals("POST", request.method());
		Assertions.assertEquals(List.of("application/x-www-form-urlencoded"), recorded.getHeaders().get("Content-Type"));
		Assertions.assertEquals(form, recorded.getBodyAsString());
		Assertions.assertEquals(List.of("Basic YTpi"), recorded.getHeaders().get("Authorization"));
		Assertions.assertEquals(List.of("eyJ0eXAiOiJkcG9wK2p3dCJ9.e30.c2ln"), recorded.getHeaders().get("DPoP"));
		Assertions.assertEquals(List.of("identity"), recorded.getHeaders().get("Accept-Encoding"));
	}

	// G6-7 frozen table, with the Content-Types Keycloak 26.7.4 and node-oidc-provider 9.12.2 actually sent (WP-5a
	// record): charset absent or utf-8 on every allowlisted type, compared case-insensitively (RFC 9110 section
	// 8.3.1).
	@TestFactory
	Stream<DynamicTest> acceptsEveryAllowlistedMediaTypeTheProvidersSend() {
		List<Object[]> cases = new ArrayList<>();
		for (ResponseProfile profile : List.of(ResponseProfile.METADATA, ResponseProfile.TOKEN,
				ResponseProfile.INTROSPECTION, ResponseProfile.JWKS, ResponseProfile.USERINFO))
			for (String contentType : List.of("application/json", "application/json; charset=utf-8",
					"Application/JSON; Charset=\"UTF-8\"", "application/json;charset=utf-8"))
				cases.add(new Object[]{profile, contentType, "application/json"});
		for (String contentType : List.of("application/jwk-set+json", "application/jwk-set+json; charset=utf-8"))
			cases.add(new Object[]{ResponseProfile.JWKS, contentType, "application/jwk-set+json"});
		for (String contentType : List.of("application/jwt", "application/jwt; charset=utf-8", "APPLICATION/JWT"))
			cases.add(new Object[]{ResponseProfile.USERINFO, contentType, "application/jwt"});

		return cases.stream().map(testCase -> DynamicTest.dynamicTest(testCase[0] + " " + testCase[1], () -> {
			ResponseProfile profile = (ResponseProfile) testCase[0];
			String path = script(TestHttpsServer.Response.withStatus(200).header("Content-Type", (String) testCase[1])
					.body("{}").build());

			RawResponse response = execute(HttpExchangeRequest.fromDefaults(jdk().uri(path), profile));

			Assertions.assertEquals(testCase[2], requiredMediaType(response).getEssence());
		}));
	}

	// Results > Phase 1: REVOCATION skips the whole media-type step (RFC 7009 section 2.2), count included; Keycloak
	// answers 200 with no Content-Type and node-oidc-provider text/plain.
	@TestFactory
	Stream<DynamicTest> revocationSkipsTheWholeMediaTypeStep() {
		return Stream.of(
				TestHttpsServer.Response.fromStatus(200),
				TestHttpsServer.Response.withStatus(200).header("Content-Type", "text/plain; charset=utf-8").body("OK")
						.build(),
				TestHttpsServer.Response.withStatus(200).header("Content-Type", "text/html")
						.header("Content-Type", "application/json").body("{}").build(),
				TestHttpsServer.Response.fromStatus(204)
		).map(scripted -> DynamicTest.dynamicTest(scripted.getStatus() + " " + scripted.getHeaders(), () -> {
			String path = script(scripted);

			RawResponse response = execute(HttpExchangeRequest.fromDefaults(jdk().uri(path), ResponseProfile.REVOCATION));

			Assertions.assertEquals(scripted.getStatus(), response.status());
			Assertions.assertArrayEquals(scripted.getBody(), response.body());
		}));
	}

	// G6-3 and G5-5: a non-2xx is not an exception: its status, headers and body (within the error limit) come back
	// unchecked for media type, so the protocol can read an OAuth error, WWW-Authenticate or Retry-After.
	@TestFactory
	Stream<DynamicTest> returnsNon2xxResponsesWithTheirStatusHeadersAndBody() {
		return Stream.of(
				TestHttpsServer.Response.withStatus(400).header("Content-Type", "application/json")
						.body("{\"error\":\"invalid_grant\"}").build(),
				TestHttpsServer.Response.withStatus(401).header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
						.header("Content-Type", "text/plain").build(),
				TestHttpsServer.Response.withStatus(429).header("Retry-After", "120").body("slow down").build(),
				TestHttpsServer.Response.withStatus(404).header("Content-Type", "text/html").body("<h1>no</h1>").build(),
				TestHttpsServer.Response.withStatus(500).header("Content-Type", "application/json")
						.header("Content-Type", "text/plain").body("{}").build(),
				TestHttpsServer.Response.fromStatus(503)
		).map(scripted -> DynamicTest.dynamicTest(scripted.getStatus() + " " + scripted.getHeaders(), () -> {
			String path = script(scripted);

			RawResponse response = execute(HttpExchangeRequest.fromDefaults(jdk().uri(path), ResponseProfile.TOKEN));

			Assertions.assertEquals(scripted.getStatus(), response.status());
			Assertions.assertFalse(response.isSuccessful());
			Assertions.assertFalse(response.errorBodyDropped());
			Assertions.assertArrayEquals(scripted.getBody(), response.body());
			for (Map.Entry<String, List<String>> header : scripted.getHeaders().entrySet())
				Assertions.assertEquals(header.getValue(), response.headers().allValues(header.getKey()));
		}));
	}

	// R8 and G5-5: a body exactly at its limit is read, one byte more is refused (TOO_LARGE on a 2xx, dropped with the
	// status kept otherwise), whether the length is declared or streamed.
	@TestFactory
	Stream<DynamicTest> readsABodyAtItsLimitAndRefusesOneByteMore() {
		int limit = 20_000;
		List<DynamicTest> tests = new ArrayList<>();
		for (TestHttpsServer.Framing framing : TestHttpsServer.Framing.values())
			for (int status : new int[]{200, 400}) {
				tests.add(DynamicTest.dynamicTest(status + " " + framing + " at the limit", () -> {
					byte[] body = randomBytes(limit, status);
					String path = script(TestHttpsServer.Response.withStatus(status).header("Content-Type", "application/json")
							.body(body).framing(framing).build());

					RawResponse response = execute(limited(jdk().uri(path), limit, limit));

					Assertions.assertEquals(status, response.status());
					Assertions.assertArrayEquals(body, response.body());
					Assertions.assertFalse(response.errorBodyDropped());
				}));
				tests.add(DynamicTest.dynamicTest(status + " " + framing + " one byte over the limit", () -> {
					String path = script(TestHttpsServer.Response.withStatus(status).header("Content-Type", "application/json")
							.body(randomBytes(limit + 1, status)).framing(framing).build());
					HttpExchangeRequest request = limited(jdk().uri(path), limit, limit);

					if (status == 200) {
						Assertions.assertEquals(Kind.TOO_LARGE, assertFails(request).getKind());
					} else {
						RawResponse response = execute(request);
						Assertions.assertEquals(status, response.status());
						Assertions.assertTrue(response.errorBodyDropped());
						Assertions.assertEquals(0, response.body().length);
					}
				}));
			}
		return tests.stream();
	}

	// R8: a limit of zero admits only an empty body.
	@Test
	void aZeroLimitAdmitsOnlyAnEmptyBody() throws Exception {
		String empty = script(TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json").build());
		String oneByte = script(TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
				.body("1").framing(TestHttpsServer.Framing.CHUNKED).build());

		Assertions.assertEquals(0, execute(limited(jdk().uri(empty), 0, 0)).body().length);
		Assertions.assertEquals(Kind.TOO_LARGE, assertFails(limited(jdk().uri(oneByte), 0, 0)).getKind());
	}

	// RFC 9112 section 6.3: a close-delimited HTTP/1.0 body within the limit is read to the end of the stream.
	@Test
	void readsACloseDelimitedHttp10Body() throws Exception {
		String path = "/exchange/" + NEXT_PATH.incrementAndGet();
		raw().script(path, RawTlsServer.Script.builder()
				.write("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + JSON)
				.endOfStream()
				.build());

		RawResponse response = execute(HttpExchangeRequest.fromDefaults(raw().uri(path), ResponseProfile.METADATA));

		Assertions.assertEquals(JSON, new String(response.body(), StandardCharsets.UTF_8));
	}

	// The bounded subscriber reassembles a body delivered in many pieces, growing its buffer as it goes.
	@Test
	void reassemblesALargeChunkedBodyExactly() throws Exception {
		byte[] body = randomBytes(Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue(), 7);
		String path = script(TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
				.body(body).framing(TestHttpsServer.Framing.CHUNKED).build());

		RawResponse response = execute(HttpExchangeRequest.fromDefaults(jdk().uri(path), ResponseProfile.TOKEN));

		Assertions.assertArrayEquals(body, response.body());
	}

	// A response read to its end leaves the connection clean, so the client reuses it: two exchanges, one connection.
	@Test
	void aResponseReadToItsEndLeavesTheConnectionReusable() throws Exception {
		String path = "/exchange/" + NEXT_PATH.incrementAndGet();
		raw().script(path, RawTlsServer.Script.fromString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
				+ "Content-Length: 2\r\n\r\n{}"));
		HttpExchange reusing = HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(),
				false);

		reusing.execute(HttpExchangeRequest.fromDefaults(raw().uri(path), ResponseProfile.TOKEN), Deadline.fromNow(LONG));
		reusing.execute(HttpExchangeRequest.fromDefaults(raw().uri(path), ResponseProfile.TOKEN), Deadline.fromNow(LONG));

		List<RawTlsServer.Connection> connections = raw().getConnections().stream()
				.filter(connection -> connection.getRequests().stream().anyMatch(request -> request.getPath().equals(path)))
				.toList();
		Assertions.assertEquals(1, connections.size());
		Assertions.assertEquals(2, connections.get(0).getRequests().size());
	}

	// RFC 9112 sections 6.3 and 7.1: a body that ends before its Content-Length, or a chunked body cut off before its
	// last chunk, is IO with the JDK's IOException kept as the cause (G6-2), never a short body returned as whole.
	@TestFactory
	Stream<DynamicTest> aBodyCutShortByTheServerIsIo() {
		return Stream.of(
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"a\":",
				"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"a\":\r\n",
				"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"error\":"
		).map(head -> DynamicTest.dynamicTest(head.substring(0, head.indexOf('\r')) + (head.contains("chunked")
				? " chunked" : " fixed-length"), () -> {
			String path = "/exchange/" + NEXT_PATH.incrementAndGet();
			raw().script(path, RawTlsServer.Script.builder().write(head).closeConnection().build());

			HttpExchangeException exception = assertFails(HttpExchangeRequest.fromDefaults(raw().uri(path),
					ResponseProfile.TOKEN));

			Assertions.assertEquals(Kind.IO, exception.getKind());
			Assertions.assertTrue(exception.getCause() instanceof IOException, () -> "cause " + exception.getCause());
		}));
	}

	// INV-G1 and M1 plan, "Risks": an injected client that throws from sendAsync, or returns null, gives IO; nothing
	// but HttpExchangeException leaves execute.
	@TestFactory
	Stream<DynamicTest> anInjectedClientThatFailsToSendGivesIo() {
		return Stream.of(ScriptedHttpClient.Behavior.THROW_FROM_SEND_ASYNC,
						ScriptedHttpClient.Behavior.RETURN_NULL_FROM_SEND_ASYNC)
				.map(behavior -> DynamicTest.dynamicTest(behavior.name(), () -> {
					HttpExchange broken = HttpExchange.fromHttpClient(ScriptedHttpClient.failingBeforeAnyResponse(behavior),
							OutboundUriPolicy.defaultInstance(), false);

					HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
							() -> broken.execute(HttpExchangeRequest.fromDefaults(URI.create("https://example.com/"),
									ResponseProfile.TOKEN), Deadline.fromNow(LONG)));

					Assertions.assertEquals(Kind.IO, exception.getKind());
				}));
	}

	// INV-G1: an injected client's future may throw from isDone or cancel, as CompletableFuture's minimal stage does.
	// execute contains that, so the caller still gets the exchange's own kind: a timeout, a transport failure, or a
	// rejection the server chose (a 302), and nothing but HttpExchangeException leaves execute.
	@TestFactory
	Stream<DynamicTest> aFutureThatThrowsFromIsDoneOrCancelStillGivesTheExchangesOwnKind() {
		HttpHeaders redirect = HttpHeaders.of(Map.of("Location", List.of("https://example.com/elsewhere")),
				(name, value) -> true);
		return Stream.of(
				new Object[]{ScriptedHttpClient.Behavior.NEVER_RESPOND, 200, Kind.TIMEOUT, Duration.ofMillis(300)},
				new Object[]{ScriptedHttpClient.Behavior.FAIL_WITH_IO, 200, Kind.IO, SCRIPTED},
				new Object[]{ScriptedHttpClient.Behavior.RESPOND_AND_STALL, 302, Kind.REDIRECT, SCRIPTED}
		).map(testCase -> DynamicTest.dynamicTest(testCase[0] + " gives " + testCase[2], () -> {
			ScriptedHttpClient scripted = ScriptedHttpClient.withAFutureThatThrows(
					(ScriptedHttpClient.Behavior) testCase[0], (Integer) testCase[1], redirect);
			HttpExchange httpExchange = HttpExchange.fromHttpClient(scripted, OutboundUriPolicy.defaultInstance(), false);

			HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
					() -> httpExchange.execute(HttpExchangeRequest.fromDefaults(URI.create("https://example.com/"),
							ResponseProfile.TOKEN), Deadline.fromNow((Duration) testCase[3])));

			Assertions.assertEquals(testCase[2], exception.getKind());
		}));
	}

	// M1 plan, "Checks in apply()": a status outside 100 to 999, which the JDK never passes on but an injected client
	// might, is FRAMING, and the body handler's subscriber cancels at once so nothing is read.
	@TestFactory
	Stream<DynamicTest> aStatusOutsideTheHttpRangeIsFramingAndReadsNothing() {
		return Stream.of(0, 42, 99, 1_000, -200).map(status -> DynamicTest.dynamicTest("status " + status, () -> {
			ScriptedHttpClient scripted = ScriptedHttpClient.respondingAndStalling(status, HttpHeaders.of(
					Map.of("Content-Type", List.of("application/json")), (name, value) -> true));

			HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
					() -> HttpExchange.fromHttpClient(scripted, OutboundUriPolicy.defaultInstance(), false)
							.execute(HttpExchangeRequest.fromDefaults(URI.create("https://example.com/"), ResponseProfile.TOKEN),
									Deadline.fromNow(SCRIPTED)));

			Assertions.assertEquals(Kind.FRAMING, exception.getKind());
			Assertions.assertTrue(scripted.getSubscription().isCancelled());
			Assertions.assertEquals(0, scripted.getSubscription().getRequested());
		}));
	}

	// M1 plan, "Checks in apply()": BodyHandler.apply never throws, because a throw leaves the connection open and
	// unread. Even when reading the response fails inside apply, it returns a subscriber that cancels, and the
	// exchange fails with IO.
	@Test
	void theBodyHandlerNeverThrowsAndStillCancelsWhenReadingTheResponseFails() {
		ScriptedHttpClient scripted = ScriptedHttpClient.respondingAndStalling(200, null);

		HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
				() -> HttpExchange.fromHttpClient(scripted, OutboundUriPolicy.defaultInstance(), false)
						.execute(HttpExchangeRequest.fromDefaults(URI.create("https://example.com/"), ResponseProfile.TOKEN),
								Deadline.fromNow(SCRIPTED)));

		Assertions.assertEquals(Kind.IO, exception.getKind());
		Assertions.assertTrue(scripted.getSubscription().isCancelled());
		Assertions.assertEquals(0, scripted.getSubscription().getRequested());
	}

	// R12, A-1 and G8-9: only https (or loopback http when allowed) to a URI the policy permits, with no user
	// information or fragment, is sent; everything else is URI_REJECTED before the client is asked to send anything.
	// The fragment rows are new in M2: the fetch runs the same UriChecks as a builder's build().
	@TestFactory
	Stream<DynamicTest> rejectsUrisBeforeSendingAnything() {
		return Stream.of("http://example.com/", "http://127.0.0.1:1/", "http://[::1]:1/", "http://localhost:1/",
						"ftp://example.com/", "ws://example.com/", "/relative", "mailto:someone@example.com",
						"https://user:secret@example.com/", "https://user@example.com/", "https://example.com:0/",
						"https://example.com:65536/", "https:///no-host", "https://169.254.169.254/latest/meta-data/",
						"https://[fe80::1]/", "https://[fd00:ec2::254]/", "https://0/", "https://0xa9fea9fe/",
						"https://127.1/", "https://example.com/#", "https://example.com/jwks#keys",
						"https://100.100.100.200/", "https://metadata.google.internal/", "https://[64:ff9b:1::a9fe:a9fe]/")
				.map(uri -> DynamicTest.dynamicTest(uri, () -> {
					StandInHttpClient standIn = new StandInHttpClient();
					HttpExchange strict = HttpExchange.fromHttpClient(standIn, OutboundUriPolicy.defaultInstance(), false);

					HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
							() -> strict.execute(HttpExchangeRequest.fromDefaults(URI.create(uri), ResponseProfile.TOKEN),
									Deadline.fromNow(LONG)));

					Assertions.assertEquals(Kind.URI_REJECTED, exception.getKind());
					Assertions.assertEquals(ErrorCategory.VALIDATION_FAILURE, exception.getKind().getCategory());
					Assertions.assertEquals(0, standIn.getSendCount());
				}));
	}

	// R12: https to any permitted host is sent (the scheme compares case-insensitively), and loopback http only when
	// the component allows it. The stand-in client fails every send with IO, which proves the URI passed.
	@TestFactory
	Stream<DynamicTest> sendsHttpsAndAllowedLoopbackHttp() {
		return Stream.of(
				new Object[]{"https://example.com/", false},
				new Object[]{"HTTPS://Example.COM:443/x?y=z", false},
				new Object[]{"https://127.0.0.1:1/", false},
				new Object[]{"https://10.0.0.1/", false},
				new Object[]{"http://127.0.0.1:1/", true},
				new Object[]{"http://127.3.4.5:1/", true},
				new Object[]{"http://[::1]:1/", true},
				new Object[]{"http://[::ffff:127.0.0.1]:1/", true},
				new Object[]{"http://localhost:1/", true},
				new Object[]{"HTTP://LOCALHOST:1/", true},
				new Object[]{"http://LocalHost:1/", true},
				new Object[]{"http://127.255.255.254:1/", true},
				new Object[]{"https://example.com/jwks?appid=x", false}
		).map(testCase -> DynamicTest.dynamicTest(testCase[0] + " loopback " + testCase[1], () -> {
			StandInHttpClient standIn = new StandInHttpClient();
			HttpExchange httpExchange = HttpExchange.fromHttpClient(standIn, OutboundUriPolicy.defaultInstance(),
					(Boolean) testCase[1]);

			HttpExchangeException exception = Assertions.assertThrows(HttpExchangeException.class,
					() -> httpExchange.execute(HttpExchangeRequest.fromDefaults(URI.create((String) testCase[0]),
							ResponseProfile.TOKEN), Deadline.fromNow(LONG)));

			Assertions.assertEquals(Kind.IO, exception.getKind());
			Assertions.assertEquals(1, standIn.getSendCount());
		}));
	}

	// R12 and plan v3 section 11: loopback http is allowed only to a host the JDK connects to as loopback. The
	// IPv4-compatible and NAT64 forms of 127.0.0.1 classify as loopback for the reject policy, but the JDK keeps them
	// as IPv6 and connects off the host, so plain http to them is refused even when loopback is allowed. https to them
	// stays permitted, as the policy decides.
	@TestFactory
	Stream<DynamicTest> refusesPlainHttpToEmbeddedLoopbackForms() {
		return Stream.of("http://[::127.0.0.1]:1/", "http://[::7f00:1]:1/", "http://[::127.1.2.3]:1/",
						"http://[64:ff9b::127.0.0.1]:1/", "http://[64:ff9b::7f00:1]:1/", "http://[::ffff:0:127.0.0.1]:1/")
				.map(uri -> DynamicTest.dynamicTest(uri, () -> {
					StandInHttpClient standIn = new StandInHttpClient();
					HttpExchange loopbackAllowed = HttpExchange.fromHttpClient(standIn, OutboundUriPolicy.defaultInstance(),
							true);

					HttpExchangeException refused = Assertions.assertThrows(HttpExchangeException.class,
							() -> loopbackAllowed.execute(HttpExchangeRequest.fromDefaults(URI.create(uri),
									ResponseProfile.TOKEN), Deadline.fromNow(LONG)));
					Assertions.assertEquals(Kind.URI_REJECTED, refused.getKind());
					Assertions.assertEquals(0, standIn.getSendCount());

					HttpExchangeException sent = Assertions.assertThrows(HttpExchangeException.class,
							() -> loopbackAllowed.execute(HttpExchangeRequest.fromDefaults(URI.create(uri.replace("http:",
									"https:")), ResponseProfile.TOKEN), Deadline.fromNow(LONG)));
					Assertions.assertEquals(Kind.IO, sent.getKind());
					Assertions.assertEquals(1, standIn.getSendCount());
				}));
	}

	// G8-7: plain http under insecure loopback goes to exactly localhost among names. The JDK hands names under
	// .localhost, and localhost. with its trailing dot, to the platform resolver, so they may leave the host; plain http
	// to them is refused, while https to them stays permitted, as the default policy decides.
	@TestFactory
	Stream<DynamicTest> refusesPlainHttpToLocalhostNamesOtherThanExactlyLocalhost() {
		return Stream.of("http://api.localhost:1/", "http://a.b.localhost:1/", "http://localhost.:1/",
						"http://LOCALHOST.:1/", "http://API.LOCALHOST:1/")
				.map(uri -> DynamicTest.dynamicTest(uri, () -> {
					StandInHttpClient standIn = new StandInHttpClient();
					HttpExchange loopbackAllowed = HttpExchange.fromHttpClient(standIn, OutboundUriPolicy.defaultInstance(),
							true);

					HttpExchangeException refused = Assertions.assertThrows(HttpExchangeException.class,
							() -> loopbackAllowed.execute(HttpExchangeRequest.fromDefaults(URI.create(uri),
									ResponseProfile.TOKEN), Deadline.fromNow(LONG)));
					Assertions.assertEquals(Kind.URI_REJECTED, refused.getKind());
					Assertions.assertEquals(0, standIn.getSendCount());

					HttpExchangeException sent = Assertions.assertThrows(HttpExchangeException.class,
							() -> loopbackAllowed.execute(HttpExchangeRequest.fromDefaults(URI.create(uri.replace("http:",
									"https:")), ResponseProfile.TOKEN), Deadline.fromNow(LONG)));
					Assertions.assertEquals(Kind.IO, sent.getKind());
					Assertions.assertEquals(1, standIn.getSendCount());
				}));
	}

	// R12: loopback http really reaches a plain server when allowed, and is refused before any connection otherwise.
	@Test
	void loopbackHttpReachesAPlainServerOnlyWhenAllowed() throws Exception {
		ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
			Thread thread = new Thread(runnable, "revetsec-plain-http-test");
			thread.setDaemon(true);
			return thread;
		});
		HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}),
				0), 0);
		AtomicInteger hits = new AtomicInteger();
		server.setExecutor(executor);
		server.createContext("/", httpExchange -> {
			hits.incrementAndGet();
			byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
			httpExchange.getResponseHeaders().add("Content-Type", "application/json");
			httpExchange.sendResponseHeaders(200, body.length);
			try (OutputStream responseBody = httpExchange.getResponseBody()) {
				responseBody.write(body);
			}
		});
		server.start();
		try {
			URI uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/metadata");
			HttpClient plainClient = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

			HttpExchangeException refused = Assertions.assertThrows(HttpExchangeException.class,
					() -> HttpExchange.fromHttpClient(plainClient, OutboundUriPolicy.defaultInstance(), false)
							.execute(HttpExchangeRequest.fromDefaults(uri, ResponseProfile.METADATA), Deadline.fromNow(LONG)));
			Assertions.assertEquals(Kind.URI_REJECTED, refused.getKind());
			Assertions.assertEquals(0, hits.get());

			RawResponse response = HttpExchange.fromHttpClient(plainClient, OutboundUriPolicy.defaultInstance(), true)
					.execute(HttpExchangeRequest.fromDefaults(uri, ResponseProfile.METADATA), Deadline.fromNow(LONG));
			Assertions.assertEquals(200, response.status());
			Assertions.assertEquals(1, hits.get());
		} finally {
			executor.shutdownNow();
			server.stop(0);
		}
	}

	// G6-5: an injected client that follows redirects is refused when the component is created.
	@TestFactory
	Stream<DynamicTest> refusesAnInjectedClientThatFollowsRedirects() {
		return Stream.of(HttpClient.Redirect.NORMAL, HttpClient.Redirect.ALWAYS)
				.map(redirect -> DynamicTest.dynamicTest(redirect.name(), () -> Assertions.assertThrows(
						IllegalArgumentException.class, () -> HttpExchange.fromHttpClient(new StandInHttpClient(redirect),
								OutboundUriPolicy.defaultInstance(), false))));
	}

	// M1 plan, Kind mapping (G6-3): each kind fixes its category and transience; only TIMEOUT and IO are transient.
	@Test
	void everyKindCarriesTheCategoryAndTransienceOfTheKindTable() {
		Map<Kind, List<Object>> table = new LinkedHashMap<>();
		table.put(Kind.TIMEOUT, List.of(ErrorCategory.TRANSPORT, true));
		table.put(Kind.IO, List.of(ErrorCategory.TRANSPORT, true));
		table.put(Kind.INTERRUPTED, List.of(ErrorCategory.TRANSPORT, false));
		table.put(Kind.REDIRECT, List.of(ErrorCategory.REMOTE_ERROR, false));
		table.put(Kind.TOO_LARGE, List.of(ErrorCategory.MALFORMED_INPUT, false));
		table.put(Kind.CONTENT_ENCODING, List.of(ErrorCategory.MALFORMED_INPUT, false));
		table.put(Kind.FRAMING, List.of(ErrorCategory.MALFORMED_INPUT, false));
		table.put(Kind.MEDIA_TYPE, List.of(ErrorCategory.MALFORMED_INPUT, false));
		table.put(Kind.URI_REJECTED, List.of(ErrorCategory.VALIDATION_FAILURE, false));
		table.put(Kind.DEFAULT_CLIENT_UNAVAILABLE, List.of(ErrorCategory.CONFIGURATION, false));

		Assertions.assertEquals(List.of(Kind.values()), List.copyOf(table.keySet()), "every kind is in the table");
		for (Map.Entry<Kind, List<Object>> row : table.entrySet()) {
			Assertions.assertEquals(row.getValue().get(0), row.getKey().getCategory(), row.getKey()::name);
			Assertions.assertEquals(row.getValue().get(1), row.getKey().isTransient(), row.getKey()::name);
		}
	}

	// G6-1 and G6-2: messages are the kind's fixed sentence, suppression is off, and only IO keeps a cause, which is
	// the JDK's IOException.
	@Test
	void onlyIoKeepsACauseAndEveryMessageIsFixed() {
		IOException cause = new ConnectException(Sentinels.secret("connect"));
		HttpExchangeException io = new HttpExchangeException(Kind.IO, cause);
		Assertions.assertSame(cause, io.getCause());
		Assertions.assertEquals(Kind.IO.getMessage(), io.getMessage());

		for (Kind kind : Kind.values()) {
			HttpExchangeException exception = new HttpExchangeException(kind);
			Assertions.assertEquals(kind.getMessage(), exception.getMessage());
			Assertions.assertNull(exception.getCause());
			exception.addSuppressed(new IllegalStateException());
			Assertions.assertEquals(0, exception.getSuppressed().length);
			Assertions.assertTrue(kind.getMessage().endsWith("."), kind::name);
			if (kind != Kind.IO)
				Assertions.assertThrows(IllegalArgumentException.class, () -> new HttpExchangeException(kind, cause));
		}
	}

	// M1 plan, algorithm step 4: HttpTimeoutException anywhere in the cause chain is TIMEOUT (JDK 26 wraps it in an
	// IOException); anything else is IO with the first IOException kept; a cyclic chain still ends.
	@Test
	void transportFailuresMapByTheirCauseChain() {
		Assertions.assertEquals(Kind.TIMEOUT, HttpExchange.fromTransportFailure(new HttpTimeoutException("t")).getKind());
		Assertions.assertEquals(Kind.TIMEOUT, HttpExchange.fromTransportFailure(
				new HttpConnectTimeoutException("t")).getKind());
		Assertions.assertEquals(Kind.TIMEOUT, HttpExchange.fromTransportFailure(
				new IOException("wrapped", new HttpTimeoutException("t"))).getKind());
		Assertions.assertEquals(Kind.TIMEOUT, HttpExchange.fromTransportFailure(
				new CompletionException(new IOException("wrapped", new HttpTimeoutException("t")))).getKind());

		ConnectException refused = new ConnectException("refused");
		HttpExchangeException io = HttpExchange.fromTransportFailure(new CompletionException(refused));
		Assertions.assertEquals(Kind.IO, io.getKind());
		Assertions.assertSame(refused, io.getCause());

		HttpExchangeException noIoException = HttpExchange.fromTransportFailure(new IllegalStateException("odd"));
		Assertions.assertEquals(Kind.IO, noIoException.getKind());
		Assertions.assertNull(noIoException.getCause());

		CyclicException cyclic = new CyclicException();
		Assertions.assertEquals(Kind.IO, HttpExchange.fromTransportFailure(cyclic).getKind());
	}

	// R9: no rendering of a request, a response or an exchange failure shows a header value, a query, a form body or a
	// body byte.
	@Test
	void noRenderingShowsCredentialsOrBodies() throws Exception {
		String secret = Sentinels.CLIENT_SECRET;
		HttpExchangeRequest request = new HttpExchangeRequest(URI.create("https://example.com/token?code=" + secret
				+ "#" + secret), ResponseProfile.TOKEN, "client_secret=" + secret, Map.of("Authorization", "Basic "
				+ secret), 1_000, 1_000, LONG);
		Sentinels.assertAbsent(request.toString());
		Assertions.assertTrue(request.toString().contains("https://example.com/token"), request::toString);
		Assertions.assertTrue(request.toString().contains("Authorization"), request::toString);

		String path = script(TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
				.header("X-Echo", secret).body("{\"access_token\":\"" + secret + "\"}").build());
		RawResponse response = execute(HttpExchangeRequest.fromDefaults(jdk().uri(path), ResponseProfile.TOKEN));
		Sentinels.assertPresent(response.body());
		Sentinels.assertAbsent(response.toString());
		Assertions.assertTrue(response.toString().contains("x-echo"), response::toString);

		for (Kind kind : Kind.values())
			Sentinels.assertAbsent(new HttpExchangeException(kind));
		Assertions.assertEquals("HttpExchange{httpClient=default, outboundUriPolicy=OutboundUriPolicy{name=default}, "
				+ "insecureLoopbackAllowed=false}", HttpExchange.fromHttpClient(null, OutboundUriPolicy.defaultInstance(),
				false).toString());
		Assertions.assertTrue(HttpExchange.fromHttpClient(new StandInHttpClient(), OutboundUriPolicy.defaultInstance(),
				true).toString().contains("httpClient=injected"));
	}

	// HttpExchangeRequest refuses headers Revetsec or the JDK owns, values the JDK would reject or that could split a
	// header, non-ASCII form bodies, negative limits and non-positive timeouts.
	@TestFactory
	Stream<DynamicTest> requestsRefuseMalformedComponents() {
		URI uri = URI.create("https://example.com/");
		List<Map<String, String>> badHeaders = new ArrayList<>();
		for (String reserved : List.of("Accept", "accept-encoding", "Alt-Used", "Connection", "Content-Length",
				"CONTENT-TYPE", "Expect", "Host", "TE", "Trailer", "Transfer-Encoding", "Upgrade"))
			badHeaders.add(Map.of(reserved, "x"));
		badHeaders.add(Map.of("", "x"));
		badHeaders.add(Map.of("Bad Name", "x"));
		badHeaders.add(Map.of("Bad:Name", "x"));
		badHeaders.add(Map.of("X-A", "line\r\nX-Injected: 1"));
		badHeaders.add(Map.of("X-A", "nul\u0000"));
		badHeaders.add(Map.of("X-A", "del\u007F"));
		badHeaders.add(Map.of("X-A", "caf\u00E9"));
		badHeaders.add(Map.of("X-\u00E9", "x"));

		List<DynamicTest> tests = new ArrayList<>();
		for (Map<String, String> headers : badHeaders)
			tests.add(DynamicTest.dynamicTest("headers " + headers.keySet(), () -> Assertions.assertThrows(
					IllegalArgumentException.class, () -> new HttpExchangeRequest(uri, ResponseProfile.TOKEN, null,
							headers, 1, 1, LONG))));
		tests.add(DynamicTest.dynamicTest("non-ASCII form body", () -> Assertions.assertThrows(
				IllegalArgumentException.class, () -> new HttpExchangeRequest(uri, ResponseProfile.TOKEN, "a=\u00E9",
						Map.of(), 1, 1, LONG))));
		tests.add(DynamicTest.dynamicTest("negative body limit", () -> Assertions.assertThrows(
				IllegalArgumentException.class, () -> new HttpExchangeRequest(uri, ResponseProfile.TOKEN, null, Map.of(),
						-1, 1, LONG))));
		tests.add(DynamicTest.dynamicTest("negative error-body limit", () -> Assertions.assertThrows(
				IllegalArgumentException.class, () -> new HttpExchangeRequest(uri, ResponseProfile.TOKEN, null, Map.of(),
						1, -1, LONG))));
		for (Duration timeout : List.of(Duration.ZERO, Duration.ofNanos(-1)))
			tests.add(DynamicTest.dynamicTest("timeout " + timeout, () -> Assertions.assertThrows(
					IllegalArgumentException.class, () -> new HttpExchangeRequest(uri, ResponseProfile.TOKEN, null,
							Map.of(), 1, 1, timeout))));
		tests.add(DynamicTest.dynamicTest("tab and visible ASCII are fine", () -> Assertions.assertEquals("a\tb ~",
				new HttpExchangeRequest(uri, ResponseProfile.TOKEN, null, Map.of("X-A", "a\tb ~"), 1, 1, LONG).headers()
						.get("X-A"))));
		return tests.stream();
	}

	// Every header name the running JDK's HttpRequest.Builder restricts is refused when the request is built, so it
	// never reaches execute, where the JDK's IllegalArgumentException would surface as URI_REJECTED. JDK 26 added
	// alt-used; on 17 to 25 it would go on the wire. Run on every JDK leg, this catches the next name a JDK adds.
	@TestFactory
	Stream<DynamicTest> requestsRefuseEveryHeaderNameTheJdkRestricts() {
		URI uri = URI.create("https://example.com/");
		List<String> candidates = List.of("Connection", "Content-Length", "Expect", "Host", "Upgrade", "Alt-Used",
				"Alt-Svc", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding",
				"HTTP2-Settings", "Priority", "Early-Data", "Date", "Via", "Origin", "Referer");
		List<String> restricted = candidates.stream().filter(name -> {
			try {
				HttpRequest.newBuilder(uri).header(name, "x");
				return false;
			} catch (IllegalArgumentException e) {
				return true;
			}
		}).toList();

		Assertions.assertTrue(restricted.containsAll(List.of("Connection", "Content-Length", "Expect", "Host",
				"Upgrade")), restricted::toString);

		return restricted.stream().map(name -> DynamicTest.dynamicTest(name, () -> Assertions.assertThrows(
				IllegalArgumentException.class, () -> new HttpExchangeRequest(uri, ResponseProfile.TOKEN, null,
						Map.of(name, "x"), 1, 1, LONG))));
	}

	// R8: the defaults are the profile's body row, the error-body row and the request-timeout row.
	@Test
	void defaultRequestsUseTheLimitsRegistry() {
		URI uri = URI.create("https://example.com/");
		HttpExchangeRequest jwks = HttpExchangeRequest.fromDefaults(uri, ResponseProfile.JWKS);
		HttpExchangeRequest token = HttpExchangeRequest.fromDefaults(uri, ResponseProfile.TOKEN);

		Assertions.assertEquals(Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue(), jwks.maximumBodyBytes());
		Assertions.assertEquals(Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue(), token.maximumBodyBytes());
		Assertions.assertEquals(Limits.HTTP_ERROR_BODY_SIZE.getDefaultIntValue(), token.maximumErrorBodyBytes());
		Assertions.assertEquals(Limits.REQUEST_TIMEOUT.getDefaultDuration(), token.requestTimeout());
		Assertions.assertEquals("GET", token.method());
		Assertions.assertNull(token.formBody());
		Assertions.assertEquals(Map.of(), token.headers());
	}

	// RawResponse keeps its invariants: a status from 100 to 999, a dropped body only on a non-2xx and always empty,
	// and equality by body content.
	@Test
	void rawResponsesKeepTheirInvariants() {
		HttpHeaders headers = HttpHeaders.of(Map.of("A", List.of("b")), (name, value) -> true);
		Duration elapsed = Duration.ofMillis(3);

		Assertions.assertThrows(IllegalArgumentException.class, () -> new RawResponse(99, headers, new byte[0], null,
				false, elapsed));
		Assertions.assertThrows(IllegalArgumentException.class, () -> new RawResponse(1_000, headers, new byte[0], null,
				false, elapsed));
		Assertions.assertThrows(IllegalArgumentException.class, () -> new RawResponse(200, headers, new byte[0], null,
				true, elapsed));
		Assertions.assertThrows(IllegalArgumentException.class, () -> new RawResponse(500, headers, new byte[1], null,
				true, elapsed));
		Assertions.assertThrows(IllegalArgumentException.class, () -> new RawResponse(200, headers, new byte[0], null,
				false, Duration.ofNanos(-1)));

		RawResponse first = new RawResponse(200, headers, new byte[]{1, 2}, null, false, elapsed);
		RawResponse second = new RawResponse(200, headers, new byte[]{1, 2}, null, false, elapsed);
		Assertions.assertEquals(first, second);
		Assertions.assertEquals(first.hashCode(), second.hashCode());
		Assertions.assertNotEquals(first, new RawResponse(200, headers, new byte[]{1, 3}, null, false, elapsed));
		Assertions.assertTrue(new RawResponse(999, headers, new byte[0], null, false, elapsed).status() == 999);

		// Copied in and out (R9): the caller may zero what it was given, or what it passed in, without changing the
		// response.
		byte[] given = {1, 2};
		RawResponse copied = new RawResponse(200, headers, given, null, false, elapsed);
		Arrays.fill(given, (byte) 0);
		byte[] body = copied.body();
		Arrays.fill(body, (byte) 0);
		Assertions.assertArrayEquals(new byte[]{1, 2}, copied.body());
		Assertions.assertEquals(first, copied);
	}

	private static RawResponse execute(HttpExchangeRequest request) throws HttpExchangeException {
		HttpExchange httpExchange = exchange;
		if (httpExchange == null)
			throw new IllegalStateException("The exchange was not created");
		return httpExchange.execute(request, Deadline.fromNow(LONG));
	}

	private static HttpExchangeException assertFails(HttpExchangeRequest request) {
		return Assertions.assertThrows(HttpExchangeException.class, () -> execute(request));
	}

	private static HttpExchangeRequest limited(URI uri, int bodyLimit, int errorBodyLimit) {
		return new HttpExchangeRequest(uri, ResponseProfile.TOKEN, null, Map.of(), bodyLimit, errorBodyLimit, LONG);
	}

	private static MediaType requiredMediaType(RawResponse response) {
		MediaType mediaType = response.mediaType();
		if (mediaType == null)
			throw new AssertionError("No media type on " + response);
		return mediaType;
	}

	private static String script(TestHttpsServer.Response response) {
		String path = "/exchange/" + NEXT_PATH.incrementAndGet();
		jdk().script(path, TestHttpsServer.Script.fromResponse(response));
		return path;
	}

	private static byte[] randomBytes(int length, long seed) {
		byte[] bytes = new byte[length];
		new Random(seed).nextBytes(bytes);
		return bytes;
	}

	private static TestHttpsServer jdk() {
		TestHttpsServer server = jdkServer;
		if (server == null)
			throw new IllegalStateException("The server did not start");
		return server;
	}

	private static RawTlsServer raw() {
		RawTlsServer server = rawServer;
		if (server == null)
			throw new IllegalStateException("The server did not start");
		return server;
	}

	/**
	 * An exception that is its own cause's cause, to prove the failure walk ends.
	 */
	private static final class CyclicException extends RuntimeException {
		private static final long serialVersionUID = 1L;

		private final RuntimeException partner = new RuntimeException("partner", this);

		@Override
		public Throwable getCause() {
			return this.partner;
		}
	}
}
