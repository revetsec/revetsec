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

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.stream.Stream;

/**
 * Tests {@link Sentinels}: the walker behind RedactionTests and the no-echo tests (R9, R16; M1 exit criterion 17)
 * finds a planted sentinel wherever a rendering shows it (a nested cause, a suppressed exception, printed stack text,
 * a JSON value's {@code toJson()}, a log record, a recorded observer argument), and in base64url, standard base64 and
 * hex form, with positive controls at payload offsets 0, 1 and 2 (M2 exit criterion 20, "the sentinel blind spot");
 * it reports nothing for a clean graph or random base64 text.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class SentinelsTests {
	private static final Set<String> TEST_JSON_PACKAGES = Set.of(SentinelsTests.class.getPackageName());

	@Test
	void sentinelsCarryTheMarkerAtBothEndsAndAreDistinct() {
		Assertions.assertEquals(Sentinels.MARKER + "-client-secret-" + Sentinels.MARKER, Sentinels.CLIENT_SECRET);
		Assertions.assertEquals(Sentinels.NAMED_SENTINELS.size(), new HashSet<>(Sentinels.NAMED_SENTINELS).size());
		for (String sentinel : Sentinels.NAMED_SENTINELS) {
			Assertions.assertTrue(sentinel.startsWith(Sentinels.MARKER + "-"), sentinel);
			Assertions.assertTrue(sentinel.endsWith("-" + Sentinels.MARKER), sentinel);
		}
	}

	@Test
	void sentinelsSurviveJsonEscapingAndFormAndPercentEncodingUnchanged() {
		for (String sentinel : Sentinels.NAMED_SENTINELS) {
			Assertions.assertEquals(sentinel, URLEncoder.encode(sentinel, StandardCharsets.UTF_8));
			Assertions.assertTrue(sentinel.chars().allMatch(character -> character == '-'
					|| (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')), sentinel);
		}
	}

	@TestFactory
	Stream<DynamicTest> secretRejectsLabelsOutsideItsAlphabet() {
		return Stream.of("", "-leading", "trailing-", "double--hyphen", "Upper", "space here", "\u0131d",
						"x".repeat(65))
				.map(label -> DynamicTest.dynamicTest("rejects \"" + label + "\"", () ->
						Assertions.assertThrows(IllegalArgumentException.class, () -> Sentinels.secret(label))));
	}

	@Test
	void findsASentinelInTheMessageOfANestedCause() {
		RuntimeException innermost = new RuntimeException("upstream said " + Sentinels.CLIENT_SECRET);
		IllegalStateException root = new IllegalStateException("outer",
				new IllegalArgumentException("middle", innermost));

		List<String> locations = Sentinels.findIn(root);

		Assertions.assertTrue(locations.contains("$.getCause().getCause().getMessage()"), locations::toString);
		Assertions.assertTrue(locations.contains("$.getCause().getCause().toString()"), locations::toString);
		// The root's printed stack trace renders its "Caused by:" chain.
		Assertions.assertTrue(locations.contains("$ (printed stack trace)"), locations::toString);
		Assertions.assertFalse(locations.contains("$.getMessage()"), locations::toString);
	}

	@Test
	void findsASentinelInASuppressedException() {
		IllegalStateException root = new IllegalStateException("clean");
		root.addSuppressed(new IllegalArgumentException("while closing " + Sentinels.ACCESS_TOKEN));

		List<String> locations = Sentinels.findIn(root);

		Assertions.assertTrue(locations.contains("$.getSuppressed()[0].getMessage()"), locations::toString);
		Assertions.assertTrue(locations.contains("$ (printed stack trace)"), locations::toString);
		Assertions.assertFalse(locations.contains("$.getMessage()"), locations::toString);
	}

	@Test
	void findsASentinelThatOnlyThePrintedStackTraceShows() {
		RuntimeException exception = new RuntimeException("clean");
		exception.setStackTrace(new StackTraceElement[]{
				new StackTraceElement("com.example.Clean", Sentinels.secret("frame"), "Clean.java", 7)});

		Assertions.assertEquals(List.of("$ (printed stack trace)"), Sentinels.findIn(exception));
	}

	@Test
	void findsNothingInACleanExceptionGraph() {
		IllegalArgumentException cause =
				new IllegalArgumentException("SENTINEL-7F3A9C with a hyphen is not the marker");
		cause.addSuppressed(new UnsupportedOperationException("clean suppressed"));
		IllegalStateException root = new IllegalStateException("sentinel is a word, and so is 7f3a9c", cause);
		root.addSuppressed(new RuntimeException((String) null));

		Assertions.assertEquals(List.of(), Sentinels.findIn(root));
		Sentinels.assertAbsent(root);
		Sentinels.assertAbsent(null);
		Sentinels.assertAbsent(List.of("", "sentinel", "7f3a9c", Optional.empty()));
	}

	@Test
	void comparesTheMarkerCaseInsensitively() {
		Assertions.assertTrue(Sentinels.containsSentinel(Sentinels.PASSWORD.toUpperCase(Locale.ROOT)));
		Assertions.assertTrue(Sentinels.containsSentinel(CharBuffer.wrap("x" + Sentinels.MARKER)));
		Assertions.assertFalse(Sentinels.containsSentinel(null));
	}

	@Test
	void endsOnACausalCycle() {
		RuntimeException first = new RuntimeException("first");
		RuntimeException second = new RuntimeException("second " + Sentinels.REFRESH_TOKEN);
		first.initCause(second);
		second.initCause(first);

		List<String> locations = Sentinels.findIn(first);

		Assertions.assertTrue(locations.contains("$.getCause().getMessage()"), locations::toString);
		Assertions.assertFalse(locations.contains("$.getCause().getCause().getMessage()"), "each object once");
	}

	@Test
	void findsASentinelInToJsonThatToStringRedacts() {
		FakeJsonString value = new FakeJsonString(Sentinels.ID_TOKEN);

		List<String> locations = Sentinels.findIn(value, TEST_JSON_PACKAGES);

		Assertions.assertEquals(List.of("$.toJson()"), locations);
		Assertions.assertEquals(List.of(), Sentinels.findIn(new FakeJsonString("clean"), TEST_JSON_PACKAGES));
	}

	@Test
	void callsToJsonThroughAPublicInterfaceWhenTheValueClassIsNotPublic() {
		Object value = new HiddenJsonValue(Sentinels.CODE_VERIFIER);

		Assertions.assertEquals(List.of("$.toJson()"), Sentinels.findIn(value, TEST_JSON_PACKAGES));
		// Outside the JSON packages the walker reads only toString(), which is redacted.
		Assertions.assertEquals(List.of(), Sentinels.findIn(value, Set.of("com.example.none")));
	}

	@Test
	void treatsTheRevetsecJsonPackageAsJsonByDefault() {
		Assertions.assertEquals("com.revetsec.json", Sentinels.JSON_PACKAGE);
	}

	@TestFactory
	Stream<DynamicTest> findsASentinelInEveryKindOfContainerAndRendering() {
		String secret = Sentinels.AUTHORIZATION_CODE;
		RecordingObserver<Runnable> observer = RecordingObserver.fromInterface(Runnable.class);
		observer.getObserver().run();
		RecordingObserver<Comparable<Object>> comparing = comparingObserver();
		comparing.getObserver().compareTo(new IllegalStateException("hook saw " + secret));

		LogRecord messageRecord = new LogRecord(Level.FINE, "message " + secret);
		LogRecord parameterRecord = new LogRecord(Level.FINE, "value {0}");
		parameterRecord.setParameters(new Object[]{secret});
		LogRecord thrownRecord = new LogRecord(Level.FINE, "clean");
		thrownRecord.setThrown(new RuntimeException(secret));

		Map<String, Object> cases = new LinkedHashMap<>();
		cases.put("string", secret);
		cases.put("char sequence", CharBuffer.wrap(secret));
		cases.put("optional", Optional.of(secret));
		cases.put("map key", Map.of(secret, "value"));
		cases.put("map value", Map.of("key", secret));
		cases.put("list", List.of("clean", secret));
		cases.put("set", Set.of(secret));
		cases.put("path, rendered with toString()", Path.of("keys", secret + ".pem"));
		cases.put("object array", new Object[]{"clean", new Object[]{secret}});
		cases.put("UTF-8 bytes", ("caf\u00e9 " + secret).getBytes(StandardCharsets.UTF_8));
		cases.put("chars", secret.toCharArray());
		cases.put("arbitrary object's toString", new Object() {
			@Override
			public String toString() {
				return "rendered " + secret;
			}
		});
		cases.put("log record message", messageRecord);
		cases.put("log record parameter", parameterRecord);
		cases.put("log record thrown", thrownRecord);
		cases.put("recorded observer argument", comparing);
		cases.put("recorded call", comparing.getCalls().get(0));

		Assertions.assertEquals(List.of(), Sentinels.findIn(observer), "a hook call with no arguments is clean");
		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			Assertions.assertFalse(Sentinels.findIn(entry.getValue()).isEmpty(), entry::getKey);
			Sentinels.assertPresent(entry.getValue());
		}));
	}

	@Test
	void assertAbsentListsWhereTheSentinelWasFound() {
		AssertionError error = Assertions.assertThrows(AssertionError.class,
				() -> Sentinels.assertAbsent(List.of("clean", Sentinels.SEALED_PLAINTEXT)));
		Assertions.assertTrue(String.valueOf(error.getMessage()).contains("$[1]"), error::getMessage);
		Assertions.assertThrows(AssertionError.class, () -> Sentinels.assertPresent(List.of("clean")));
	}

	@Test
	void aRenderingThatThrowsFailsTheWalk() {
		Object broken = new Object() {
			@Override
			public String toString() {
				throw new UnsupportedOperationException("toString is broken");
			}
		};
		Assertions.assertThrows(UnsupportedOperationException.class, () -> Sentinels.findIn(broken));
	}

	@Test
	void joseSentinelsAreCanonicalBase64UrlAndTheHmacSecretIsLongEnoughForHs512() {
		// Plan M2, "Test helpers": planted literally as JWK members, whose private-member check rejects before
		// decoding.
		for (String sentinel : List.of(Sentinels.PRIVATE_KEY_MEMBER, Sentinels.SYMMETRIC_KEY, Sentinels.HMAC_SECRET)) {
			Assertions.assertTrue(Sentinels.NAMED_SENTINELS.contains(sentinel), sentinel);
			byte[] decoded = Base64.getUrlDecoder().decode(sentinel);
			Assertions.assertEquals(sentinel, TestJws.base64Url(decoded), "canonical base64url: " + sentinel);
		}
		Assertions.assertEquals(32, Base64.getUrlDecoder().decode(Sentinels.SYMMETRIC_KEY).length);
		// RFC 7518 section 3.2: an HS512 key is at least 64 octets.
		Assertions.assertTrue(Sentinels.HMAC_SECRET.getBytes(StandardCharsets.UTF_8).length >= 64);
	}

	@Test
	void theEncodedFormsAreTheMarkersBase64CoresAndItsHex() {
		// The marker is ASCII letters and digits, so its base64url and standard-base64 cores coincide.
		Assertions.assertEquals(List.of("c2VudGluZWw3ZjNhOW", "NlbnRpbmVsN2YzYTlj", "zZW50aW5lbDdmM2E5Y",
				"73656e74696e656c376633613963"), Sentinels.ENCODED_MARKERS);
		Assertions.assertEquals(Sentinels.ENCODED_MARKERS.subList(0, 3), Sentinels.BASE64_MARKER_CORES);
		Assertions.assertEquals(HexFormat.of().formatHex(Sentinels.MARKER.getBytes(StandardCharsets.US_ASCII)),
				Sentinels.ENCODED_MARKERS.get(3));
	}

	@TestFactory
	Stream<DynamicTest> findsTheMarkerBase64EncodedWhateverItsOffsetAndNeighbors() {
		// Each core depends on the marker's bits alone, so any prefix and suffix bytes leave it intact.
		byte[] marker = Sentinels.MARKER.getBytes(StandardCharsets.US_ASCII);
		Random random = new Random(20_260_927L);
		Map<String, Base64.Encoder> encoders = new LinkedHashMap<>();
		encoders.put("base64url", Base64.getUrlEncoder().withoutPadding());
		encoders.put("standard base64", Base64.getEncoder());
		encoders.put("MIME base64", Base64.getMimeEncoder());
		List<DynamicTest> tests = new ArrayList<>();
		for (int offset = 0; offset < 6; ++offset) {
			for (int neighbor : List.of(0x00, 0xff, -1)) {
				byte[] bytes = new byte[offset + marker.length + 5];
				for (int index = 0; index < bytes.length; ++index)
					bytes[index] = (byte) (neighbor >= 0 ? neighbor : random.nextInt(256));
				System.arraycopy(marker, 0, bytes, offset, marker.length);
				for (Map.Entry<String, Base64.Encoder> encoder : encoders.entrySet()) {
					String encoded = encoder.getValue().encodeToString(bytes);
					tests.add(DynamicTest.dynamicTest(encoder.getKey() + " at offset " + offset + ", neighbors "
							+ neighbor, () -> {
						Assertions.assertFalse(encoded.toLowerCase(Locale.ROOT).contains(Sentinels.MARKER),
								"only the encoded form is present");
						Assertions.assertTrue(Sentinels.containsSentinel(encoded), encoded);
						Assertions.assertTrue(encoded.contains(Sentinels.BASE64_MARKER_CORES.get(offsetMod3(encoded,
								bytes, marker))), encoded);
						Assertions.assertEquals(List.of("$"), Sentinels.findIn(encoded));
					}));
				}
			}
		}
		return tests.stream();
	}

	@TestFactory
	Stream<DynamicTest> positiveControlsFindASentinelClaimAtPayloadOffsetsZeroOneAndTwo() {
		// M2 exit criterion 20: a compact JWT that echoes a sentinel claim carries it only base64url-encoded.
		return Stream.of(0, 1, 2).map(alignment -> DynamicTest.dynamicTest("offset " + alignment + " mod 3", () -> {
			String claims = Sentinels.sentinelClaimsJson(alignment);
			byte[] claimBytes = claims.getBytes(StandardCharsets.UTF_8);
			String token = Sentinels.compactJwtWithSentinelClaim(alignment);
			String[] segments = token.split("\\.", -1);

			int offset = claims.indexOf(Sentinels.MARKER);
			Assertions.assertEquals(offset, claims.lastIndexOf(Sentinels.MARKER), "the marker appears exactly once");
			Assertions.assertEquals(alignment, offset % 3, "ASCII text, so the char offset is the byte offset");
			Assertions.assertEquals(claims.length(), claimBytes.length);
			Assertions.assertEquals(3, segments.length);
			Assertions.assertEquals(claims,
					new String(Base64.getUrlDecoder().decode(segments[1]), StandardCharsets.UTF_8));
			Assertions.assertFalse(token.toLowerCase(Locale.ROOT).contains(Sentinels.MARKER),
					"the plain marker never appears in the token");
			for (int core = 0; core < 3; ++core)
				Assertions.assertEquals(core == alignment, token.contains(Sentinels.BASE64_MARKER_CORES.get(core)),
						"exactly the core for this alignment: " + core);
			Assertions.assertTrue(Sentinels.containsSentinel(token));
			Assertions.assertEquals(List.of("$"), Sentinels.findIn(token));
			Assertions.assertEquals(List.of("$.getMessage()", "$.getLocalizedMessage()", "$.toString()",
					"$ (printed stack trace)"), Sentinels.findIn(new IllegalStateException("bad token " + token)));
			Sentinels.assertPresent(List.of("clean", token));
		}));
	}

	@TestFactory
	Stream<DynamicTest> aTokenWhoseClaimIsNotTheMarkerIsNotFlagged() {
		// The negative control for the positive controls above: one character off, at every alignment. A core covers
		// only part of the marker's first and last octets, so the change is in the middle.
		return Stream.of(0, 1, 2).map(alignment -> DynamicTest.dynamicTest("offset " + alignment + " mod 3", () -> {
			String claims = Sentinels.sentinelClaimsJson(alignment).replace(Sentinels.MARKER, "sentinel7e3a9c");
			String token = TestJws.builder().alg("RS256").typ("JWT").payload(claims).withSignature(new byte[256]);

			Assertions.assertFalse(Sentinels.containsSentinel(token), token);
			Sentinels.assertAbsent(token);
		}));
	}

	@Test
	void findsTheMarkerInALineWrappedPemBodyEvenWhereALineBreakSplitsTheCore() {
		byte[] marker = Sentinels.MARKER.getBytes(StandardCharsets.US_ASCII);
		Base64.Encoder pem = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII));
		int splitCores = 0;
		for (int offset = 0; offset < 64; ++offset) {
			byte[] bytes = new byte[offset + marker.length + 60];
			System.arraycopy(marker, 0, bytes, offset, marker.length);
			String body = "-----BEGIN CERTIFICATE-----\n" + pem.encodeToString(bytes) + "\n-----END CERTIFICATE-----\n";

			Assertions.assertTrue(Sentinels.containsSentinel(body), body);
			boolean anyLineHasACore = body.lines().anyMatch(line ->
					Sentinels.BASE64_MARKER_CORES.stream().anyMatch(line::contains));
			if (!anyLineHasACore)
				++splitCores;
		}
		Assertions.assertTrue(splitCores > 0,
				"some offsets split the core across lines, so whitespace removal matters");
	}

	@Test
	void findsTheMarkerHexEncodedInEitherCase() {
		String hex = HexFormat.of().formatHex(("key " + Sentinels.SYMMETRIC_KEY).getBytes(StandardCharsets.US_ASCII));
		Assertions.assertFalse(hex.contains(Sentinels.MARKER));
		Assertions.assertTrue(Sentinels.containsSentinel(hex));
		Assertions.assertTrue(Sentinels.containsSentinel(hex.toUpperCase(Locale.ROOT)));
		Assertions.assertFalse(Sentinels.containsSentinel(HexFormat.of().formatHex("sentinel7f3a9d"
				.getBytes(StandardCharsets.US_ASCII))));
	}

	@Test
	void findsNothingInLongRandomBase64OrHexText() {
		byte[] bytes = new byte[256 * 1024];
		new Random(7L).nextBytes(bytes);
		Assertions.assertFalse(Sentinels.containsSentinel(Base64.getUrlEncoder().encodeToString(bytes)));
		Assertions.assertFalse(Sentinels.containsSentinel(Base64.getMimeEncoder().encodeToString(bytes)));
		Assertions.assertFalse(Sentinels.containsSentinel(HexFormat.of().formatHex(bytes)));
	}

	@TestFactory
	Stream<DynamicTest> compactJwtCarriesSentinelsInTheKidAClaimAndTheSignatureSegment() {
		return Stream.of(11, 32, 48, 63, 64, 65, 96, 132, 256, 257, 512)
				.map(octets -> DynamicTest.dynamicTest(octets + " signature octets", () -> {
					String token = Sentinels.compactJwt("ES256", octets);
					String[] segments = token.split("\\.", -1);
					JsonObject header = parse(Base64.getUrlDecoder().decode(segments[0]));
					JsonObject claims = parse(Base64.getUrlDecoder().decode(segments[1]));
					byte[] signature = Base64.getUrlDecoder().decode(segments[2]);

					Assertions.assertEquals(3, segments.length);
					Assertions.assertEquals(List.of("alg", "typ", "kid"), List.copyOf(header.getMembers().keySet()));
					Assertions.assertEquals(JsonString.fromValue("ES256"), header.getMembers().get("alg"));
					Assertions.assertEquals(JsonString.fromValue(Sentinels.JWT_KEY_ID), header.getMembers().get("kid"));
					Assertions.assertEquals(JsonString.fromValue(Sentinels.COMPACT_JWT_ISSUER),
							claims.getMembers().get("iss"));
					Assertions.assertEquals(JsonString.fromValue(Sentinels.JWT_CLAIM), claims.getMembers().get("sub"));
					Assertions.assertEquals(JsonString.fromValue(Sentinels.COMPACT_JWT_AUDIENCE),
							claims.getMembers().get("aud"));
					Assertions.assertEquals(JsonNumber.fromValue(Sentinels.COMPACT_JWT_ISSUED_AT),
							claims.getMembers().get("iat"));
					Assertions.assertEquals(JsonNumber.fromValue(Sentinels.COMPACT_JWT_EXPIRES_AT),
							claims.getMembers().get("exp"));
					Assertions.assertEquals(octets, signature.length);
					Assertions.assertEquals(segments[2], TestJws.base64Url(signature), "canonical base64url");
					Assertions.assertTrue(segments[2].startsWith(Sentinels.MARKER), "the marker, literally");
					Assertions.assertEquals(segments[2], Sentinels.signatureSegment(octets));
					Assertions.assertTrue(Sentinels.containsSentinel(segments[0]), "the kid, encoded");
					Assertions.assertTrue(Sentinels.containsSentinel(segments[1]), "the claim, encoded");
				}));
	}

	@Test
	void sentinelSignaturesLieInEcdsaRangeExceptAtEs512() {
		// Plan M2, "JOSE semantics" step 5: 1 <= r, s <= n - 1, checked before key selection.
		for (TestJws.Algorithm algorithm : List.of(TestJws.Algorithm.ES256, TestJws.Algorithm.ES384,
				TestJws.Algorithm.ES512)) {
			byte[] signature = Base64.getUrlDecoder().decode(
					Sentinels.signatureSegment(algorithm.getSignatureLength().orElseThrow()));
			BigInteger n = TestJws.curveOrder(algorithm);
			BigInteger r = TestJws.ecdsaR(signature);
			BigInteger s = TestJws.ecdsaS(signature);
			boolean inRange = r.signum() > 0 && r.compareTo(n) < 0 && s.signum() > 0 && s.compareTo(n) < 0;
			Assertions.assertEquals(algorithm != TestJws.Algorithm.ES512, inRange, algorithm.name());
		}
		Assertions.assertEquals(0xb1, Base64.getUrlDecoder().decode(Sentinels.signatureSegment(132))[0] & 0xff);
	}

	@Test
	void sentinelTokenHelpersRejectArgumentsTheyCannotHonor() {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Sentinels.signatureSegment(Sentinels.MINIMUM_SIGNATURE_OCTETS - 1));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Sentinels.signatureSegment(Sentinels.MAXIMUM_SIGNATURE_OCTETS + 1));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Sentinels.sentinelClaimsJson(3));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Sentinels.sentinelClaimsJson(-1));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Sentinels.compactJwtWithSentinelClaim(3));
		Assertions.assertEquals(15, Sentinels.signatureSegment(Sentinels.MINIMUM_SIGNATURE_OCTETS).length());
	}

	private static int offsetMod3(String encoded, byte[] bytes, byte[] marker) {
		for (int offset = 0; offset + marker.length <= bytes.length; ++offset) {
			boolean match = true;
			for (int index = 0; index < marker.length && match; ++index)
				match = bytes[offset + index] == marker[index];
			if (match)
				return offset % 3;
		}
		throw new AssertionError("no marker in " + encoded);
	}

	private static JsonObject parse(byte[] json) throws Exception {
		return (JsonObject) JsonCodec.parse(json, JsonLimits.jose(65_536));
	}

	@SuppressWarnings("unchecked")
	private static RecordingObserver<Comparable<Object>> comparingObserver() {
		return RecordingObserver.fromInterface((Class<Comparable<Object>>) (Class<?>) Comparable.class);
	}

	/**
	 * Stands in for a {@code com.revetsec.json} value: {@code toString()} is redacted, {@code toJson()} is not.
	 */
	public static final class FakeJsonString {
		private final String value;

		FakeJsonString(String value) {
			this.value = value;
		}

		public String toJson() {
			return "\"" + this.value + "\"";
		}

		@Override
		public String toString() {
			return "FakeJsonString{value=<redacted>}";
		}
	}

	/**
	 * A public view of a JSON value, for {@link HiddenJsonValue}.
	 */
	public interface JsonRendering {
		String toJson();
	}

	/**
	 * A value class that reflection cannot call directly, as a package-private implementation would be.
	 */
	private static final class HiddenJsonValue implements JsonRendering {
		private final String value;

		private HiddenJsonValue(String value) {
			this.value = value;
		}

		@Override
		public String toJson() {
			return "{\"token\":\"" + this.value + "\"}";
		}

		@Override
		public String toString() {
			return "HiddenJsonValue{token=<redacted>}";
		}
	}
}
