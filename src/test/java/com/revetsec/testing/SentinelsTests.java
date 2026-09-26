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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.URLEncoder;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.stream.Stream;

/**
 * Tests {@link Sentinels}: the walker behind RedactionTests and the no-echo tests (R9, R16; exit criterion 17) finds
 * a planted sentinel wherever a rendering shows it (a nested cause, a suppressed exception, printed stack text, a
 * JSON value's {@code toJson()}, a log record, a recorded observer argument) and reports nothing for a clean graph.
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
