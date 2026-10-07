/* Copyright 2026 Revetware LLC. Licensed under the Apache License, Version 2.0. */
package com.revetsec.internal.http;

import com.revetsec.M6FuzzOracle;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.jspecify.annotations.NonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Offline numeric-address, response-framing and freshness oracle for the CIMD target. */
public final class CimdTransportFuzzOracle {
	private CimdTransportFuzzOracle() { }
	public static void run(byte @NonNull [] input) throws Exception {
		addresses(M6FuzzOracle.choice(input, 2, 7));
		response(input, M6FuzzOracle.choice(input, 3, 10));
	}
	private static void addresses(int mode) throws Exception {
		List<InetAddress> answers = switch (mode) {
			case 0 -> List.of(address(8, 8, 8, 8), address(9, 9, 9, 9));
			case 1 -> List.of(address(127, 0, 0, 1));
			case 2 -> List.of(address(8, 8, 8, 8), address(10, 0, 0, 1));
			case 3 -> List.of(address(169, 254, 169, 254));
			case 4 -> List.of();
			case 5 -> List.of(address(192, 0, 0, 9));
			default -> List.of(address(8, 8, 8, 8), address(8, 8, 8, 8), address(9, 9, 9, 9));
		};
		try {
			List<InetAddress> checked = PinnedHttpsAddresses.checked(answers, 2, Deadline.fromNow(Duration.ofSeconds(2)));
			assertEquals(0, mode, "only the enumerated all-public bounded answer set is eligible");
			assertEquals(2, checked.size());
			assertNotSame(answers, checked);
		} catch (HttpExchangeException failure) {
			assertNotEquals(0, mode, "all-public bounded answers must remain eligible");
			assertEquals(HttpExchangeException.Kind.URI_REJECTED, failure.getKind());
		}
	}
	private static void response(byte @NonNull [] input, int mode) throws Exception {
		byte[] tail = Arrays.copyOfRange(input, Math.min(4, input.length), Math.min(input.length, 516));
		if (tail.length == 0) tail = new byte[]{'{', '}'};
		String body = new String(tail, StandardCharsets.ISO_8859_1);
		String wire = switch (mode) {
			case 0 -> "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: max-age=60\r\nAge: 5\r\nContent-Length: " + tail.length + "\r\n\r\n" + body;
			case 1 -> "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" + Integer.toHexString(tail.length) + "\r\n" + body + "\r\n0\r\n\r\n";
			case 2 -> "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}";
			case 3 -> "HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/\r\n\r\n";
			case 4 -> "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}";
			case 5 -> "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\n\r\n{}";
			case 6 -> "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}";
			case 7 -> "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + tail.length + "\r\n\r\n" + body;
			case 8 -> "HTTP/1.1 404 Missing\r\nContent-Length: 100\r\n\r\nsecret";
			default -> "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r\n0\r\nX-Trailer: value\r\n\r\n";
		};
		byte[] bytes = wire.getBytes(StandardCharsets.ISO_8859_1);
		int[] index = {0};
		try {
			RawResponse response = PinnedHttpResponseReader.read(() -> index[0] == bytes.length ? -1 : Byte.toUnsignedInt(bytes[index[0]++]), 1024, Deadline.fromNow(Duration.ofSeconds(2)), System.nanoTime());
			assertTrue(mode == 0 || mode == 1 || mode == 7 || mode == 8, "only enumerated unambiguous framing is accepted");
			if (mode == 8) { assertEquals(404, response.status()); assertEquals(0, response.body().length); assertTrue(response.errorBodyDropped()); }
			else {
				assertEquals(200, response.status()); assertArrayEquals(tail, response.body());
				if (mode == 0) {
					Duration remaining = ClientMetadataFreshness.remaining(response, Instant.parse("2026-10-07T12:00:00Z"), Duration.ofMinutes(5));
					assertTrue(remaining.compareTo(Duration.ofSeconds(54)) > 0 && remaining.compareTo(Duration.ofSeconds(55)) <= 0);
				}
			}
		} catch (HttpExchangeException failure) {
			assertFalse(mode == 0 || mode == 1 || mode == 7 || mode == 8, "valid response framing must remain accepted");
			assertNull(failure.getCause());
		}
	}
	private static @NonNull InetAddress address(int a, int b, int c, int d) throws Exception {
		return InetAddress.getByAddress(new byte[]{(byte) a, (byte) b, (byte) c, (byte) d});
	}
}
