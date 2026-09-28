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

import com.revetsec.testing.TestHttpsServer.HeldScript;
import com.revetsec.testing.TestHttpsServer.Outcome;
import com.revetsec.testing.TestHttpsServer.RecordedRequest;
import com.revetsec.testing.TestHttpsServer.Response;
import com.revetsec.testing.TestHttpsServer.Script;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Tests {@link TestHttpsServer}: it binds to loopback on an ephemeral port, answers scripted paths over verified TLS,
 * counts hits (plan 14.1's zero-hit assertions) and records requests, sees a client abort an oversized body (exit
 * criterion 10), and closes promptly even with a stalled response in flight (M1 plan: {@code shutdownNow} before
 * {@code stop(0)}). Its key-set scripts (plan M2, "Test helpers") serve a JWK Set with {@code Cache-Control},
 * {@code Retry-After} failures, sequences and cycles, a response held until the test releases it, and a tarpit; a
 * scripted {@code Date} is always replaced by the server's own.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class TestHttpsServerTests {
	/**
	 * Server-side abort checks allow about 10 s (M1 plan: once a server took 3.1 s to notice an abort on 25).
	 */
	private static final Duration ABORT_SLACK = Duration.ofSeconds(10);
	private static final Duration WAIT = Duration.ofSeconds(30);
	private static final Duration PROMPT_CLOSE = Duration.ofSeconds(5);

	@Test
	void bindsToLoopbackOnAnEphemeralPort() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			URI baseUri = server.getBaseUri();
			Assertions.assertEquals("https", baseUri.getScheme());
			Assertions.assertEquals("127.0.0.1", baseUri.getHost());
			Assertions.assertTrue(server.getPort() > 0);
			Assertions.assertEquals(URI.create(baseUri + "/a?b=c"), server.uri("/a?b=c"));
			Assertions.assertThrows(IllegalArgumentException.class, () -> server.uri("relative"));
		}
	}

	@Test
	void answersScriptedPathsOverVerifiedTlsAndCountsEveryHit() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/json", Script.fromResponse(Response.fromJson(200, "{\"ok\":true}")));
			HttpClient client = TestTls.httpClient();

			HttpResponse<String> json = client.send(HttpRequest.newBuilder(server.uri("/json")).build(),
					HttpResponse.BodyHandlers.ofString());
			HttpResponse<String> missing = client.send(HttpRequest.newBuilder(server.uri("/missing")).build(),
					HttpResponse.BodyHandlers.ofString());

			Assertions.assertEquals(200, json.statusCode());
			Assertions.assertEquals("{\"ok\":true}", json.body());
			Assertions.assertEquals(List.of("application/json"), json.headers().allValues("content-type"));
			Assertions.assertEquals(404, missing.statusCode());
			Assertions.assertEquals(1, server.getHitCount("/json"));
			Assertions.assertEquals(1, server.getHitCount("/missing"));
			Assertions.assertEquals(0, server.getHitCount("/never"), "an unrequested path has zero hits");
		}
	}

	@Test
	void recordsTheMethodTargetHeadersAndBodyOfEachRequest() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/token", Script.fromResponse(Response.fromStatus(200)));
			HttpRequest request = HttpRequest.newBuilder(server.uri("/token?attempt=1"))
					.header("Content-Type", "application/x-www-form-urlencoded")
					.header("X-Repeated", "first")
					.header("X-Repeated", "second")
					.POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials"))
					.build();

			TestTls.httpClient().send(request, HttpResponse.BodyHandlers.discarding());

			RecordedRequest recorded = server.getRequests("/token").get(0);
			Assertions.assertEquals("POST", recorded.getMethod());
			Assertions.assertEquals(URI.create("/token?attempt=1"), recorded.getUri());
			Assertions.assertEquals("/token", recorded.getPath());
			Assertions.assertEquals("grant_type=client_credentials", recorded.getBodyAsString());
			Assertions.assertEquals("application/x-www-form-urlencoded",
					recorded.getHeader("content-type").orElseThrow());
			Assertions.assertEquals(List.of("first", "second"), recorded.getHeaders().get("x-repeated"));
			Assertions.assertTrue(recorded.getHeader("absent").isEmpty());
			Assertions.assertEquals(Outcome.COMPLETED, recorded.awaitOutcome(WAIT));
			Assertions.assertEquals(List.of(recorded), server.getRequests());
		}
	}

	@Test
	void answersARedirectWithoutTheTargetEverBeingRequested() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/start", Script.fromRedirect(307, server.uri("/target").toString()));

			HttpResponse<String> response = TestTls.httpClient().send(
					HttpRequest.newBuilder(server.uri("/start")).build(), HttpResponse.BodyHandlers.ofString());

			Assertions.assertEquals(307, response.statusCode());
			Assertions.assertEquals(server.uri("/target").toString(), response.headers().firstValue("location")
					.orElseThrow());
			Assertions.assertEquals(0, server.getHitCount("/target"));
		}
	}

	@Test
	void framesABodyAsChunkedWhenAsked() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/chunked", Script.fromResponse(Response.withStatus(200)
					.header("Content-Type", "text/plain")
					.body("chunked body")
					.framing(TestHttpsServer.Framing.CHUNKED)
					.build()));

			HttpResponse<String> response = TestTls.httpClient().send(
					HttpRequest.newBuilder(server.uri("/chunked")).build(), HttpResponse.BodyHandlers.ofString());

			Assertions.assertEquals("chunked body", response.body());
			Assertions.assertEquals("chunked", response.headers().firstValue("transfer-encoding").orElseThrow());
			Assertions.assertTrue(response.headers().firstValue("content-length").isEmpty());
		}
	}

	@Test
	void seesTheClientAbortAnOversizedBody() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/large", Script.fromResponse(Response.withStatus(200)
					.header("Content-Type", "application/json")
					.body(new byte[12 * 1024 * 1024])
					.build()));

			HttpResponse<InputStream> response = TestTls.httpClient().send(
					HttpRequest.newBuilder(server.uri("/large")).build(), HttpResponse.BodyHandlers.ofInputStream());
			try (InputStream body = response.body()) {
				Assertions.assertEquals(1024, body.readNBytes(1024).length);
			}

			Assertions.assertEquals(Outcome.CLIENT_ABORTED, server.getRequests("/large").get(0)
					.awaitOutcome(ABORT_SLACK));
		}
	}

	@Test
	void closesPromptlyWithAStalledResponseInFlightAndReleasesEveryWait() throws Exception {
		TestHttpsServer server = TestHttpsServer.start();
		CompletableFuture<HttpResponse<String>> inFlight;
		HttpResponse<InputStream> headersOnly;
		RecordedRequest stalled;
		Duration closing;
		try {
			server.script("/stall", Script.fromStalledResponse(200, Map.of("Content-Type", List.of("text/plain"))));
			HttpClient client = TestTls.httpClient();
			HttpRequest request = HttpRequest.newBuilder(server.uri("/stall")).build();
			inFlight = client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
			// The headers arrive although the body never does.
			headersOnly = client.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream())
					.get(WAIT.toSeconds(), TimeUnit.SECONDS);
			Assertions.assertEquals(200, headersOnly.statusCode());
			Assertions.assertTrue(server.awaitRequestCount(2, WAIT));
			stalled = server.getRequests().get(0);
			Assertions.assertEquals(Outcome.UNFINISHED, stalled.awaitOutcome(Duration.ofMillis(1)));
		} finally {
			long started = System.nanoTime();
			server.close();
			closing = Duration.ofNanos(System.nanoTime() - started);
		}

		Assertions.assertTrue(closing.compareTo(PROMPT_CLOSE) < 0, "close() took " + closing);
		Assertions.assertEquals(Outcome.SERVER_CLOSED, stalled.awaitOutcome(WAIT));
		Assertions.assertFalse(server.awaitRequestCount(3, WAIT), "a closed server releases waits at once");
		ExecutionException failure = Assertions.assertThrows(ExecutionException.class,
				() -> inFlight.get(WAIT.toSeconds(), TimeUnit.SECONDS));
		Assertions.assertTrue(failure.getCause() instanceof IOException, () -> String.valueOf(failure.getCause()));
		headersOnly.body().close();
		Assertions.assertThrows(IOException.class, () -> TestTls.httpClient().send(
				HttpRequest.newBuilder(server.uri("/stall")).build(), HttpResponse.BodyHandlers.discarding()));
		server.close();
	}

	@TestFactory
	Stream<DynamicTest> aScriptThatThrowsAnswers500AndIsRecordedAsFailed() {
		// A failed JUnit assertion inside a script is an Error; it must be recorded like a runtime exception, not lost.
		Map<String, Throwable> failures = new LinkedHashMap<>();
		failures.put("runtime exception", new IllegalStateException("script bug"));
		failures.put("failed assertion", new AssertionError("script assertion"));
		return failures.entrySet().stream().map(failure -> DynamicTest.dynamicTest(failure.getKey(), () -> {
			try (TestHttpsServer server = TestHttpsServer.start()) {
				server.script("/broken", exchange -> {
					if (failure.getValue() instanceof Error error)
						throw error;
					throw (RuntimeException) failure.getValue();
				});

				HttpResponse<String> response = TestTls.httpClient().send(
						HttpRequest.newBuilder(server.uri("/broken")).build(), HttpResponse.BodyHandlers.ofString());

				Assertions.assertEquals(500, response.statusCode());
				Assertions.assertEquals(1, server.getHitCount("/broken"), "the client had no reason to retry");
				RecordedRequest recorded = server.getRequests().get(0);
				Assertions.assertEquals(Outcome.SCRIPT_FAILED, recorded.awaitOutcome(WAIT));
				Assertions.assertSame(failure.getValue(), recorded.getScriptFailure().orElseThrow());
			}
		}));
	}

	@Test
	void aScriptCanWriteThroughTheJdkExchangeAndReadTheRecordedRequest() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/echo", exchange -> {
				byte[] body = ("you sent " + exchange.getRequest().getBodyAsString()).getBytes(StandardCharsets.UTF_8);
				exchange.getHttpExchange().sendResponseHeaders(201, body.length);
				exchange.getHttpExchange().getResponseBody().write(body);
			});

			HttpResponse<String> response = TestTls.httpClient().send(HttpRequest.newBuilder(server.uri("/echo"))
					.POST(HttpRequest.BodyPublishers.ofString("hello")).build(), HttpResponse.BodyHandlers.ofString());

			Assertions.assertEquals(201, response.statusCode());
			Assertions.assertEquals("you sent hello", response.body());
		}
	}

	@Test
	void servesAJsonWebKeySetWithItsMediaTypeAndAnyCacheControl() throws Exception {
		String keySet = "{\"keys\":[]}";
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/plain", Script.fromResponse(Response.fromJsonWebKeySet(keySet)));
			server.script("/cached", Script.fromResponse(Response.fromJsonWebKeySet(keySet, "max-age=300, public")));
			HttpClient client = TestTls.httpClient();

			HttpResponse<String> plain = get(client, server.uri("/plain"));
			HttpResponse<String> cached = get(client, server.uri("/cached"));

			Assertions.assertEquals(200, plain.statusCode());
			Assertions.assertEquals(keySet, plain.body());
			Assertions.assertEquals(List.of("application/jwk-set+json"), plain.headers().allValues("content-type"));
			Assertions.assertTrue(plain.headers().firstValue("cache-control").isEmpty());
			Assertions.assertEquals(List.of("max-age=300, public"), cached.headers().allValues("cache-control"));
			Assertions.assertEquals(TestHttpsServer.JWK_SET_MEDIA_TYPE,
					cached.headers().firstValue("content-type").orElseThrow());
		}
	}

	@Test
	void passesExpiresAndAgeThroughButAlwaysSendsItsOwnWallClockDate() throws Exception {
		// Plan M2, "Test helpers": the JDK server replaces a scripted Date, so Date-dependent lifetimes need
		// RawTlsServer.
		String scriptedDate = "Thu, 01 Jan 1970 00:00:00 GMT";
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/dated", Script.fromResponse(Response.withStatus(200)
					.header("Date", scriptedDate)
					.header("Expires", "Thu, 01 Jan 1970 00:10:00 GMT")
					.header("Age", "30")
					.build()));

			HttpResponse<String> response = get(TestTls.httpClient(), server.uri("/dated"));

			Assertions.assertEquals(List.of("Thu, 01 Jan 1970 00:10:00 GMT"), response.headers().allValues("expires"));
			Assertions.assertEquals(List.of("30"), response.headers().allValues("age"));
			List<String> dates = response.headers().allValues("date");
			Assertions.assertEquals(1, dates.size(), dates::toString);
			Assertions.assertNotEquals(scriptedDate, dates.get(0), "the server's own Date replaced the scripted one");
		}
	}

	@Test
	void retryAfterResponsesCarryTheirStatusAndHeader() throws Exception {
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/limited", Script.fromResponse(Response.fromRetryAfter(429, "120")));
			server.script("/down", Script.fromResponse(Response.fromRetryAfter(503, "Wed, 21 Oct 2015 07:28:00 GMT")));
			HttpClient client = TestTls.httpClient();

			HttpResponse<String> limited = get(client, server.uri("/limited"));
			HttpResponse<String> down = get(client, server.uri("/down"));

			Assertions.assertEquals(429, limited.statusCode());
			Assertions.assertEquals("120", limited.headers().firstValue("retry-after").orElseThrow());
			Assertions.assertEquals(503, down.statusCode());
			Assertions.assertEquals("Wed, 21 Oct 2015 07:28:00 GMT",
					down.headers().firstValue("retry-after").orElseThrow());
		}
	}

	@Test
	void aSequenceAnswersInOrderThenRepeatsItsLastResponse() throws Exception {
		// A key rotation scripted in advance: a failure, the old key set, then the new one for good.
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/jwks", Script.fromSequence(List.of(Response.fromRetryAfter(503, "1"),
					Response.fromJsonWebKeySet("{\"keys\":[\"old\"]}"),
					Response.fromJsonWebKeySet("{\"keys\":[\"new\"]}"))));
			HttpClient client = TestTls.httpClient();

			List<String> answers = new ArrayList<>();
			for (int request = 0; request < 5; ++request) {
				HttpResponse<String> response = get(client, server.uri("/jwks"));
				answers.add(response.statusCode() + " " + response.body());
			}

			Assertions.assertEquals(List.of("503 ", "200 {\"keys\":[\"old\"]}", "200 {\"keys\":[\"new\"]}",
					"200 {\"keys\":[\"new\"]}", "200 {\"keys\":[\"new\"]}"), answers);
			Assertions.assertEquals(5, server.getHitCount("/jwks"));
		}
	}

	@Test
	void aCycleStartsOverAfterItsLastResponse() throws Exception {
		// Plan M2-8 and G8-8: a server that answers a valid key set after each failure.
		try (TestHttpsServer server = TestHttpsServer.start()) {
			server.script("/jwks", Script.fromCycle(List.of(Response.fromStatus(500),
					Response.fromJsonWebKeySet("{\"keys\":[]}", "no-store"))));
			HttpClient client = TestTls.httpClient();

			List<Integer> statuses = new ArrayList<>();
			for (int request = 0; request < 5; ++request)
				statuses.add(get(client, server.uri("/jwks")).statusCode());

			Assertions.assertEquals(List.of(500, 200, 500, 200, 500), statuses);
		}
	}

	@Test
	void sequencesAndCyclesNeedAtLeastOneResponse() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> Script.fromSequence(List.of()));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Script.fromCycle(List.of()));
	}

	@Test
	void aHeldScriptHoldsEveryRequestUntilReleasedThenLetsLaterOnesThrough() throws Exception {
		// Plan M2 A-2 and exit criterion 11: hold the fetch until every caller has joined, with no sleeps.
		try (TestHttpsServer server = TestHttpsServer.start()) {
			HeldScript held = HeldScript.fromResponse(Response.fromJsonWebKeySet("{\"keys\":[]}"));
			server.script("/jwks", held);
			HttpClient client = TestTls.httpClient();
			HttpRequest request = HttpRequest.newBuilder(server.uri("/jwks")).build();

			List<CompletableFuture<HttpResponse<String>>> inFlight = new ArrayList<>();
			for (int caller = 0; caller < 3; ++caller)
				inFlight.add(client.sendAsync(request, HttpResponse.BodyHandlers.ofString()));
			Assertions.assertTrue(held.awaitHeldCount(3, WAIT));
			Assertions.assertEquals(3, held.getArrivalCount());
			Assertions.assertFalse(held.isReleased());
			for (CompletableFuture<HttpResponse<String>> future : inFlight)
				Assertions.assertFalse(future.isDone(), "held, so no response yet");
			Assertions.assertTrue(held.toString().contains("held=3"), held::toString);

			held.release();
			for (CompletableFuture<HttpResponse<String>> future : inFlight)
				Assertions.assertEquals(200, future.get(WAIT.toSeconds(), TimeUnit.SECONDS).statusCode());
			Assertions.assertEquals(200, get(client, server.uri("/jwks")).statusCode(), "later requests pass at once");
			Assertions.assertEquals(0, held.getHeldCount());
			Assertions.assertEquals(4, held.getArrivalCount());
			Assertions.assertTrue(held.isReleased());
			held.release();
			for (RecordedRequest recorded : server.getRequests())
				Assertions.assertEquals(Outcome.COMPLETED, recorded.awaitOutcome(WAIT));
		}
	}

	@Test
	void aHeldScriptTimesOutItsWaitAndClosingTheServerEndsItsHeldRequests() throws Exception {
		TestHttpsServer server = TestHttpsServer.start();
		HeldScript held = HeldScript.fromScript(Script.fromResponse(Response.fromStatus(204)));
		CompletableFuture<HttpResponse<String>> inFlight;
		Duration closing;
		try {
			server.script("/jwks", held);
			Assertions.assertFalse(held.awaitHeldCount(1, Duration.ZERO), "nothing held yet");
			inFlight = TestTls.httpClient().sendAsync(HttpRequest.newBuilder(server.uri("/jwks")).build(),
					HttpResponse.BodyHandlers.ofString());
			Assertions.assertTrue(held.awaitHeldCount(1, WAIT));
			Assertions.assertFalse(held.awaitHeldCount(2, Duration.ofMillis(1)), "only one is held");
		} finally {
			long started = System.nanoTime();
			server.close();
			closing = Duration.ofNanos(System.nanoTime() - started);
		}

		Assertions.assertTrue(closing.compareTo(PROMPT_CLOSE) < 0, "close() took " + closing);
		Assertions.assertEquals(Outcome.SERVER_CLOSED, server.getRequests().get(0).awaitOutcome(WAIT));
		ExecutionException failure = Assertions.assertThrows(ExecutionException.class,
				() -> inFlight.get(WAIT.toSeconds(), TimeUnit.SECONDS));
		Assertions.assertTrue(failure.getCause() instanceof IOException, () -> String.valueOf(failure.getCause()));
		Assertions.assertFalse(held.isReleased());
	}

	@Test
	void aTarpitNeverAnswersSoOnlyTheClientTimeoutEndsTheRequest() throws Exception {
		// Plan M2-8: a TIMEOUT is a failure, whoever's deadline ended it.
		TestHttpsServer server = TestHttpsServer.start();
		RecordedRequest tarpitted;
		Duration closing;
		try {
			server.script("/warm", Script.fromResponse(Response.fromJson(200, "{}")));
			server.script("/jwks", Script.fromTarpit());
			HttpClient client = TestTls.httpClient();
			// The first request leaves a pooled connection, so the second needs no handshake inside its timeout.
			Assertions.assertEquals(200, get(client, server.uri("/warm")).statusCode());
			CompletableFuture<HttpResponse<String>> inFlight = client.sendAsync(
					HttpRequest.newBuilder(server.uri("/jwks")).timeout(Duration.ofSeconds(1)).build(),
					HttpResponse.BodyHandlers.ofString());

			Assertions.assertTrue(server.awaitRequestCount(2, WAIT), "the tarpit saw the request");
			ExecutionException failure = Assertions.assertThrows(ExecutionException.class,
					() -> inFlight.get(WAIT.toSeconds(), TimeUnit.SECONDS));
			Assertions.assertTrue(failure.getCause() instanceof HttpTimeoutException,
					() -> String.valueOf(failure.getCause()));
			Assertions.assertEquals(1, server.getHitCount("/jwks"));
			tarpitted = server.getRequests("/jwks").get(0);
			Assertions.assertEquals(Outcome.UNFINISHED, tarpitted.awaitOutcome(Duration.ofMillis(1)),
					"the tarpit never answered");
		} finally {
			long started = System.nanoTime();
			server.close();
			closing = Duration.ofNanos(System.nanoTime() - started);
		}
		Assertions.assertTrue(closing.compareTo(PROMPT_CLOSE) < 0, "close() took " + closing);
		Assertions.assertEquals(Outcome.SERVER_CLOSED, tarpitted.awaitOutcome(WAIT));
	}

	private static HttpResponse<String> get(HttpClient client, URI uri) throws IOException, InterruptedException {
		return client.send(HttpRequest.newBuilder(uri).build(), HttpResponse.BodyHandlers.ofString());
	}

	@Test
	void validatesResponsesAndPaths() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class, () -> Response.withStatus(99));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Response.withStatus(1000));
		Response response = Response.withStatus(200).header("X-A", "1").header("X-A", "2").body("x").build();
		Assertions.assertEquals(Map.of("X-A", List.of("1", "2")), response.getHeaders());
		byte[] body = response.getBody();
		body[0] = 'y';
		Assertions.assertEquals("x", new String(response.getBody(), StandardCharsets.UTF_8), "getBody copies");
		try (TestHttpsServer server = TestHttpsServer.start()) {
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> server.script("no-slash", Script.fromResponse(response)));
		}
	}
}
