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

import org.jspecify.annotations.NonNull;

import com.revetsec.testing.RawTlsServer.ClosedBy;
import com.revetsec.testing.RawTlsServer.Connection;
import com.revetsec.testing.RawTlsServer.Outcome;
import com.revetsec.testing.RawTlsServer.RecordedRequest;
import com.revetsec.testing.RawTlsServer.Script;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Tests {@link RawTlsServer}: it writes exact bytes over verified TLS, serves keep-alive requests, trickles a body
 * on its own pacing executor (A-2), ends close-delimited HTTP/1.0 bodies, and reports whether the client closed
 * each connection: after {@code Connection: close}, on an abandoned oversized body, and during a stall (exit
 * criteria 10 to 12). Each response reports whether it was written in full or the client ended it early, hits count
 * from the request line, and a silent client is dropped as a server close. A path's cycle of scripts answers
 * successive requests in turn, a response head the JDK refuses included (plan M2-8, exit criterion 14). Closing the
 * server is prompt even with a writer blocked on a full send buffer or a trickle in progress, and releases every
 * wait.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RawTlsServerTests {
	/**
	 * Server-side abort checks allow about 10 s (M1 plan: once a server took 3.1 s to notice an abort on 25).
	 */
	private static final Duration ABORT_SLACK = Duration.ofSeconds(10);
	private static final Duration WAIT = Duration.ofSeconds(30);
	private static final Duration PROMPT_CLOSE = Duration.ofSeconds(5);

	@Test
	void writesExactBytesAndRecordsTheRequestAsReceived() throws Exception {
		try (RawTlsServer server = RawTlsServer.start()) {
			server.script("/exact", Script.fromString("HTTP/1.1 200 OK\r\nX-Exact: Value\r\nContent-Length: 5\r\n"
					+ "Connection: close\r\n\r\nhello"));

			HttpRequest request = HttpRequest.newBuilder(server.uri("/exact?x=1")).header("X-Probe", "probe").build();
			HttpResponse<String> response = TestTls.httpClient().send(request, HttpResponse.BodyHandlers.ofString());

			Assertions.assertEquals(200, response.statusCode());
			Assertions.assertEquals("hello", response.body());
			Assertions.assertEquals("Value", response.headers().firstValue("x-exact").orElseThrow());
			RecordedRequest recorded = server.getRequests().get(0);
			Assertions.assertEquals("GET /exact?x=1 HTTP/1.1", recorded.getRequestLine());
			Assertions.assertEquals("GET", recorded.getMethod());
			Assertions.assertEquals("/exact?x=1", recorded.getTarget());
			Assertions.assertEquals("/exact", recorded.getPath());
			Assertions.assertEquals("probe", recorded.getHeader("x-probe").orElseThrow());
			Assertions.assertTrue(recorded.getHead().startsWith("GET /exact?x=1 HTTP/1.1\r\n"), recorded::getHead);
			Assertions.assertTrue(recorded.getHead().endsWith("\r\n\r\n"), recorded::getHead);
			Assertions.assertEquals(1, server.getHitCount("/exact"));
			Assertions.assertEquals(0, server.getHitCount("/never"));
		}
	}

	@Test
	void aScriptCycleAnswersSuccessiveRequestsInTurnAndStartsOver() throws Exception {
		// Plan M2-8 and G8-8: a key-set endpoint that alternates a failure with a valid answer.
		try (RawTlsServer server = RawTlsServer.start()) {
			server.scriptCycle("/jwks", List.of(
					Script.fromString("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n"),
					Script.fromString("HTTP/1.1 200 OK\r\nContent-Type: application/jwk-set+json\r\n"
							+ "Cache-Control: no-store\r\nContent-Length: 11\r\n\r\n{\"keys\":[]}")));
			HttpClient client = TestTls.httpClient();

			List<Integer> statuses = new ArrayList<>();
			for (int request = 0; request < 5; ++request)
				statuses.add(client.send(HttpRequest.newBuilder(server.uri("/jwks")).build(),
						HttpResponse.BodyHandlers.ofString()).statusCode());

			Assertions.assertEquals(List.of(503, 200, 503, 200, 503), statuses);
			Assertions.assertEquals(5, server.getHitCount("/jwks"));
			server.script("/jwks", Script.fromString("HTTP/1.1 204 No Content\r\n\r\n"));
			Assertions.assertEquals(204, client.send(HttpRequest.newBuilder(server.uri("/jwks")).build(),
					HttpResponse.BodyHandlers.discarding()).statusCode(), "script() replaces a cycle");
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> server.scriptCycle("/jwks", List.of()));
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> server.scriptCycle("jwks", List.of(Script.fromString("x"))));
		}
	}

	@Test
	void aScriptCycleAlternatesAResponseHeadTheJdkRefusesWithAValidKeySet() throws Exception {
		// Plan M2 exit criterion 14: an invalid status line after each valid, no-store key set. The JDK refuses the
		// head with an IOException and does not retry it, so every call is one request on the server.
		try (RawTlsServer server = RawTlsServer.start()) {
			server.scriptCycle("/jwks", List.of(
					Script.fromString("HTTP/1.1 099 Invalid\r\nContent-Length: 0\r\n\r\n"),
					Script.fromString("HTTP/1.1 200 OK\r\nContent-Type: application/jwk-set+json\r\n"
							+ "Cache-Control: no-store\r\nContent-Length: 11\r\n\r\n{\"keys\":[]}")));
			HttpClient client = TestTls.httpClient();

			List<String> answers = new ArrayList<>();
			for (int request = 0; request < 4; ++request) {
				try {
					HttpResponse<String> response = client.send(HttpRequest.newBuilder(server.uri("/jwks")).build(),
							HttpResponse.BodyHandlers.ofString());
					answers.add(response.statusCode() + " " + response.body());
				} catch (IOException e) {
					answers.add("refused");
				}
			}

			Assertions.assertEquals(List.of("refused", "200 {\"keys\":[]}", "refused", "200 {\"keys\":[]}"), answers);
			Assertions.assertEquals(4, server.getHitCount("/jwks"));
		}
	}

	@Test
	void seesTheClientCloseAfterAConnectionCloseResponse() throws Exception {
		try (RawTlsServer server = RawTlsServer.start()) {
			HttpResponse<String> response = TestTls.httpClient().send(
					HttpRequest.newBuilder(server.uri("/unscripted")).build(), HttpResponse.BodyHandlers.ofString());

			Assertions.assertEquals(404, response.statusCode());
			Assertions.assertEquals(1, server.getHitCount("/unscripted"));
			Assertions.assertTrue(onlyConnection(server).awaitClientClose(ABORT_SLACK));
		}
	}

	@Test
	void seesTheClientCloseWhenItAbandonsAnOversizedBody() throws Exception {
		try (RawTlsServer server = RawTlsServer.start()) {
			server.script("/large", Script.builder()
					.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12582912\r\n\r\n")
					.write(new byte[12 * 1024 * 1024])
					.build());

			HttpResponse<InputStream> response = TestTls.httpClient().send(
					HttpRequest.newBuilder(server.uri("/large")).build(), HttpResponse.BodyHandlers.ofInputStream());
			try (InputStream body = response.body()) {
				Assertions.assertEquals(1024, body.readNBytes(1024).length);
			}

			Assertions.assertEquals(Optional.of(ClosedBy.CLIENT), onlyConnection(server).awaitClose(ABORT_SLACK));
			Assertions.assertEquals(Outcome.CLIENT_ABORTED, server.getRequests().get(0).awaitOutcome(WAIT));
		}
	}

	@Test
	void seesTheClientCloseWhileTheResponseStallsAfterItsHeaders() throws Exception {
		try (RawTlsServer server = RawTlsServer.start()) {
			server.script("/stall", Script.builder()
					.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
					.stall()
					.build());

			HttpResponse<InputStream> response = TestTls.httpClient().send(
					HttpRequest.newBuilder(server.uri("/stall")).build(), HttpResponse.BodyHandlers.ofInputStream());
			response.body().close();

			Assertions.assertTrue(onlyConnection(server).awaitClientClose(ABORT_SLACK));
			Assertions.assertEquals(Outcome.CLIENT_ABORTED, server.getRequests().get(0).awaitOutcome(WAIT),
					"a stalled response never finishes, so the client ended it early");
		}
	}

	@Test
	void endsACloseDelimitedHttp10BodyAndThenSeesTheClientClose() throws Exception {
		try (RawTlsServer server = RawTlsServer.start()) {
			server.script("/legacy", Script.builder()
					.write("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nclose-delimited body")
					.endOfStream()
					.build());

			HttpResponse<String> response = TestTls.httpClient().send(
					HttpRequest.newBuilder(server.uri("/legacy")).build(), HttpResponse.BodyHandlers.ofString());

			Assertions.assertEquals(200, response.statusCode());
			Assertions.assertEquals("close-delimited body", response.body());
			Assertions.assertTrue(onlyConnection(server).awaitClientClose(ABORT_SLACK));
			Assertions.assertEquals(Outcome.COMPLETED, server.getRequests().get(0).awaitOutcome(WAIT),
					"the client closed only after the whole body");
		}
	}

	@Test
	void tellsAnAbandonedCloseDelimitedBodyFromOneReadToItsEnd() throws Exception {
		// Exit criterion 10: a close-delimited body always ends with the client closing the connection, so only the
		// response outcome shows whether the client stopped reading early.
		try (RawTlsServer server = RawTlsServer.start()) {
			server.script("/large", Script.builder()
					.write("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n")
					.write(new byte[12 * 1024 * 1024])
					.endOfStream()
					.build());

			HttpResponse<InputStream> response = TestTls.httpClient().send(
					HttpRequest.newBuilder(server.uri("/large")).build(), HttpResponse.BodyHandlers.ofInputStream());
			try (InputStream body = response.body()) {
				Assertions.assertEquals(1024, body.readNBytes(1024).length);
			}

			Assertions.assertTrue(onlyConnection(server).awaitClientClose(ABORT_SLACK));
			Assertions.assertEquals(Outcome.CLIENT_ABORTED, server.getRequests().get(0).awaitOutcome(WAIT));
		}
	}

	@Test
	void tricklesABodyInChunksPacedByItsOwnExecutor() throws Exception {
		Duration interval = Duration.ofMillis(25);
		try (RawTlsServer server = RawTlsServer.start()) {
			server.script("/trickle", Script.builder()
					.write("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n")
					.trickle("0123456789".getBytes(StandardCharsets.US_ASCII), 2, interval)
					.build());

			long started = System.nanoTime();
			HttpResponse<String> response = TestTls.httpClient().send(
					HttpRequest.newBuilder(server.uri("/trickle")).build(), HttpResponse.BodyHandlers.ofString());
			Duration elapsed = Duration.ofNanos(System.nanoTime() - started);

			Assertions.assertEquals("0123456789", response.body());
			// Five chunks: the first at once, then four intervals.
			Assertions.assertTrue(elapsed.compareTo(interval.multipliedBy(4)) >= 0, () -> "took " + elapsed);
		}
	}

	@Test
	void writesAHeaderSectionOver384KiBByteForByte() throws Exception {
		// 384 KiB is the JDK client's default jdk.http.maxHeaderSize where that property exists (open question 7).
		byte[] response = ("HTTP/1.1 200 OK\r\nX-Padding: " + "a".repeat(400 * 1024)
				+ "\r\nContent-Length: 0\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
		try (RawTlsServer server = RawTlsServer.start()) {
			server.script("/huge-headers", Script.fromBytes(response));
			try (SSLSocket socket = (SSLSocket) TestTls.clientSslContext().getSocketFactory()
					.createSocket("127.0.0.1", server.getPort())) {
				OutputStream outputStream = socket.getOutputStream();
				outputStream.write("GET /huge-headers HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
						.getBytes(StandardCharsets.US_ASCII));
				outputStream.flush();

				Assertions.assertArrayEquals(response, socket.getInputStream().readNBytes(response.length));
			}

			Assertions.assertTrue(onlyConnection(server).awaitClientClose(ABORT_SLACK));
		}
	}

	@Test
	void servesAnotherRequestOnAKeptAliveConnectionAndReportsTheServerClosingIt() throws Exception {
		RawTlsServer server = RawTlsServer.start();
		Connection connection;
		Duration closing;
		try {
			server.script("/keep", Script.fromString("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
			HttpClient client = TestTls.httpClient();
			for (int attempt = 0; attempt < 2; ++attempt)
				Assertions.assertEquals("ok", client.send(HttpRequest.newBuilder(server.uri("/keep")).build(),
						HttpResponse.BodyHandlers.ofString()).body());

			connection = onlyConnection(server);
			Assertions.assertEquals(2, connection.getRequests().size());
			for (RecordedRequest request : connection.getRequests())
				Assertions.assertEquals(Outcome.COMPLETED, request.awaitOutcome(WAIT));
			Assertions.assertEquals(2, server.getHitCount("/keep"));
			Assertions.assertEquals(Optional.empty(), connection.awaitClose(Duration.ofMillis(1)), "still open");
		} finally {
			long started = System.nanoTime();
			server.close();
			closing = Duration.ofNanos(System.nanoTime() - started);
		}

		Assertions.assertTrue(closing.compareTo(PROMPT_CLOSE) < 0, "close() took " + closing);
		long started = System.nanoTime();
		Assertions.assertFalse(connection.awaitClientClose(WAIT), "the server, not the client, closed it");
		Assertions.assertEquals(Optional.of(ClosedBy.SERVER), connection.awaitClose(WAIT));
		Assertions.assertTrue(Duration.ofNanos(System.nanoTime() - started).compareTo(PROMPT_CLOSE) < 0,
				"waits return at once after close()");
		Assertions.assertFalse(server.awaitConnectionCount(2, WAIT));
		Assertions.assertFalse(server.awaitRequestCount(3, WAIT));
	}

	@Test
	void aCloseConnectionStepReportsThatTheServerClosedIt() throws Exception {
		try (RawTlsServer server = RawTlsServer.start()) {
			server.script("/bye", Script.builder()
					.write("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye")
					.closeConnection()
					.build());

			HttpResponse<String> response = TestTls.httpClient().send(
					HttpRequest.newBuilder(server.uri("/bye")).build(), HttpResponse.BodyHandlers.ofString());

			Assertions.assertEquals("bye", response.body());
			Assertions.assertEquals(Optional.of(ClosedBy.SERVER), onlyConnection(server).awaitClose(WAIT));
			Assertions.assertEquals(Outcome.COMPLETED, server.getRequests().get(0).awaitOutcome(WAIT));
		}
	}

	@Test
	void readsContentLengthAndChunkedRequestBodiesFromARawClient() throws Exception {
		try (RawTlsServer server = RawTlsServer.start()) {
			server.script("/form", Script.fromString("HTTP/1.1 204 No Content\r\n\r\n"));
			try (SSLSocket socket = (SSLSocket) TestTls.clientSslContext().getSocketFactory()
					.createSocket("127.0.0.1", server.getPort())) {
				OutputStream outputStream = socket.getOutputStream();
				outputStream.write(("POST /form HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 5\r\n\r\nfirst"
						+ "POST /form HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\n\r\n"
						+ "3;ext=1\r\nsec\r\n3\r\nond\r\n0\r\nTrailer: x\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
				outputStream.flush();
				Assertions.assertTrue(server.awaitRequestCount(2, WAIT));
			}

			Assertions.assertEquals("first", new String(server.getRequests().get(0).getBody(),
					StandardCharsets.US_ASCII));
			Assertions.assertEquals("second", new String(server.getRequests().get(1).getBody(),
					StandardCharsets.US_ASCII));
			Assertions.assertTrue(onlyConnection(server).awaitClientClose(ABORT_SLACK));
		}
	}

	@Test
	void closesTheConnectionOnAMalformedRequest() throws Exception {
		try (RawTlsServer server = RawTlsServer.start();
				SSLSocket socket = (SSLSocket) TestTls.clientSslContext().getSocketFactory()
						.createSocket("127.0.0.1", server.getPort())) {
			OutputStream outputStream = socket.getOutputStream();
			outputStream.write("GET /rejected HTTP/1.1\r\nno colon here\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
			outputStream.flush();

			Assertions.assertEquals(Optional.of(ClosedBy.SERVER), onlyConnection(server).awaitClose(WAIT));
			Assertions.assertEquals(0, server.getRequests().size());
			Assertions.assertEquals(1, server.getHitCount("/rejected"), "a rejected request line still counts");
		}
	}

	@Test
	void countsAHitAsSoonAsTheRequestLineArrivesEvenIfTheBodyNeverDoes() throws Exception {
		// Plan 14.1's zero-hit assertions must not pass because a request was cut short.
		try (RawTlsServer server = RawTlsServer.start()) {
			try (SSLSocket socket = (SSLSocket) TestTls.clientSslContext().getSocketFactory()
					.createSocket("127.0.0.1", server.getPort())) {
				OutputStream outputStream = socket.getOutputStream();
				outputStream.write("POST /partial HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 10\r\n\r\nabc"
						.getBytes(StandardCharsets.US_ASCII));
				outputStream.flush();
			}

			Assertions.assertTrue(onlyConnection(server).awaitClientClose(ABORT_SLACK));
			Assertions.assertEquals(1, server.getHitCount("/partial"));
			Assertions.assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void closesPromptlyWhileAWriterIsBlockedOnAFullSendBuffer() throws Exception {
		// The reason RawTlsServer closes TCP sockets itself: SSLSocket.close() would wait for the TLS write lock that
		// this blocked writer holds.
		byte[] head = "HTTP/1.1 200 OK\r\nContent-Length: 33554432\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
		RawTlsServer server = RawTlsServer.start();
		RecordedRequest request;
		Duration closing;
		try (SSLSocket socket = (SSLSocket) TestTls.clientSslContext().getSocketFactory()
				.createSocket("127.0.0.1", server.getPort())) {
			try {
				// 32 MiB is more than the socket buffers hold, so the write cannot finish while the client reads
				// nothing past the head.
				server.script("/blocked", Script.builder().write(head).write(new byte[32 * 1024 * 1024]).build());
				socket.getOutputStream().write("GET /blocked HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
						.getBytes(StandardCharsets.US_ASCII));
				socket.getOutputStream().flush();
				Assertions.assertArrayEquals(head, socket.getInputStream().readNBytes(head.length));
				request = server.getRequests().get(0);
				Assertions.assertEquals(Outcome.UNFINISHED, request.awaitOutcome(Duration.ofMillis(1)));
			} finally {
				long started = System.nanoTime();
				server.close();
				closing = Duration.ofNanos(System.nanoTime() - started);
			}
		}

		Assertions.assertTrue(closing.compareTo(PROMPT_CLOSE) < 0, "close() took " + closing);
		Assertions.assertEquals(Outcome.SERVER_CLOSED, request.awaitOutcome(WAIT));
		Assertions.assertEquals(Optional.of(ClosedBy.SERVER), onlyConnection(server).awaitClose(WAIT));
	}

	@Test
	void closesPromptlyWhileTricklingAndStopsThePacing() throws Exception {
		byte[] head = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
		RawTlsServer server = RawTlsServer.start();
		RecordedRequest request;
		Duration closing;
		try (SSLSocket socket = (SSLSocket) TestTls.clientSslContext().getSocketFactory()
				.createSocket("127.0.0.1", server.getPort())) {
			try {
				// 1,000 one-byte chunks a minute apart: only close() can end this response in a test's lifetime.
				server.script("/slow", Script.builder()
						.write(head)
						.trickle(new byte[1000], 1, Duration.ofMinutes(1))
						.build());
				socket.getOutputStream().write("GET /slow HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
						.getBytes(StandardCharsets.US_ASCII));
				socket.getOutputStream().flush();
				// The head, then the first chunk, which is written at once.
				Assertions.assertEquals(head.length + 1, socket.getInputStream().readNBytes(head.length + 1).length);
				request = server.getRequests().get(0);
			} finally {
				long started = System.nanoTime();
				server.close();
				closing = Duration.ofNanos(System.nanoTime() - started);
			}
		}

		Assertions.assertTrue(closing.compareTo(PROMPT_CLOSE) < 0, "close() took " + closing);
		Assertions.assertEquals(Outcome.SERVER_CLOSED, request.awaitOutcome(WAIT));
		Assertions.assertEquals(Optional.of(ClosedBy.SERVER), onlyConnection(server).awaitClose(WAIT));
	}

	@Test
	void dropsAClientThatNeverCompletesTheHandshakeAsAServerClose() throws Exception {
		// A silent client is not a client close: reporting CLIENT here would pass a "client closed" check falsely.
		try (RawTlsServer server = RawTlsServer.start(Duration.ofMillis(200));
				Socket socket = new Socket(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), server.getPort())) {
			Assertions.assertTrue(socket.isConnected());

			Assertions.assertEquals(Optional.of(ClosedBy.SERVER), onlyConnection(server).awaitClose(WAIT));
			Assertions.assertEquals(0, server.getRequests().size());
		}
	}

	@Test
	void scriptsRejectStepsAfterTheConnectionEndsAndNonLatin1Text() {
		Assertions.assertThrows(IllegalStateException.class, () -> Script.builder().stall().write("x"));
		Assertions.assertThrows(IllegalStateException.class, () -> Script.builder().endOfStream().stall());
		Assertions.assertThrows(IllegalStateException.class, () -> Script.builder().closeConnection().write("x"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Script.builder().write("\u2603"));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Script.builder().trickle(new byte[1], 0, Duration.ofMillis(1)));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Script.builder().trickle(new byte[1], 1, Duration.ZERO));
	}

	private static @NonNull Connection onlyConnection(@NonNull RawTlsServer server) throws InterruptedException {
		Assertions.assertTrue(server.awaitConnectionCount(1, WAIT), "no connection arrived");
		Assertions.assertEquals(1, server.getConnections().size(), () -> server.getConnections().toString());
		return server.getConnections().get(0);
	}
}
