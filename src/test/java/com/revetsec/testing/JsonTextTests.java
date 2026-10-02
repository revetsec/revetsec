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

import org.jspecify.annotations.Nullable;

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonString;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Tests {@link JsonText}: string literals escape exactly what RFC 8259 section 7 requires, plus every unpaired
 * surrogate, so a fixture reaches the parser under test as written; objects keep member order and write duplicate
 * names; arrays join raw elements.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JsonTextTests {
	@Test
	void stringEscapesQuotesBackslashesAndControlCharactersOnly() {
		// RFC 8259 section 7: '"', '\' and U+0000 to U+001F must be escaped; everything else may be written as is.
		Assertions.assertEquals("\"a\\\"b\\\\c\"", JsonText.string("a\"b\\c"));
		Assertions.assertEquals("\"\\u0000\\u0009\\u000a\\u001f\"", JsonText.string("\u0000\t\n\u001f"));
		Assertions.assertEquals("\" /\u007f\u00e9\u2028\"", JsonText.string(" /\u007f\u00e9\u2028"));
		Assertions.assertEquals("\"\"", JsonText.string(""));
	}

	@Test
	void stringEscapesEveryUnpairedSurrogateAndKeepsPairs() {
		// A lone surrogate has no UTF-8 form, so written raw it would reach the parser as '?' after encoding.
		Assertions.assertEquals("\"\uD83D\uDE00\"", JsonText.string("\uD83D\uDE00"), "a pair is written as is");
		Assertions.assertEquals("\"x\\ud800\"", JsonText.string("x\uD800"), "a high surrogate at the end");
		Assertions.assertEquals("\"\\udc00x\"", JsonText.string("\uDC00x"), "a low surrogate first");
		Assertions.assertEquals("\"\\udc00\\ud800\"", JsonText.string("\uDC00\uD800"), "a reversed pair");
		Assertions.assertEquals("\"\\ud800\uD83D\uDE00\"", JsonText.string("\uD800\uD83D\uDE00"),
				"two high surrogates: the first is unpaired");
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> stringsWithoutUnpairedSurrogatesRoundTripThroughAStrictParser() {
		List<String> values = List.of("", "plain", "a\"b\\c", "\u0000\u001f\u007f", "\u00e9\u2028\u2029",
				"\uD83D\uDE00", Sentinels.CLIENT_SECRET);
		return values.stream().map(value -> DynamicTest.dynamicTest(Arrays.toString(value.toCharArray()), () -> {
			byte[] json = JsonText.string(value).getBytes(StandardCharsets.UTF_8);
			Assertions.assertEquals(JsonString.fromValue(value), JsonCodec.parse(json, JsonLimits.jose(65_536)));
		}));
	}

	@Test
	void objectKeepsMemberOrderWritesDuplicatesAndTakesRawValues() {
		List<Map.Entry<String, String>> members = new ArrayList<>();
		members.add(Map.entry("b", "1"));
		members.add(Map.entry("a\"", "null"));
		members.add(Map.entry("b", JsonText.string("x")));
		members.add(Map.entry("c", "[true,{}]"));

		Assertions.assertEquals("{\"b\":1,\"a\\\"\":null,\"b\":\"x\",\"c\":[true,{}]}", JsonText.object(members));
		Assertions.assertEquals("{}", JsonText.object(List.of()));
		Assertions.assertThrows(NullPointerException.class,
				() -> JsonText.object(List.of(new NullValueEntry("name"))));
	}

	@Test
	void arraysJoinRawElementsAndStringArraysQuoteEach() {
		Assertions.assertEquals("[]", JsonText.array(List.of()));
		Assertions.assertEquals("[1,\"a\",null]", JsonText.array(List.of("1", "\"a\"", "null")));
		Assertions.assertEquals("[\"verify\",\"a\\\"\"]", JsonText.stringArray(List.of("verify", "a\"")));
		Assertions.assertEquals("[]", JsonText.stringArray(List.of()));
	}

	/**
	 * A member whose value is {@code null}, which {@link Map#entry(Object, Object)} refuses to make.
	 */
	private static final class NullValueEntry implements Map.Entry<String, String> {
		private final String key;

		private NullValueEntry(@NonNull String key) {
			this.key = key;
		}

		@Override
		public @NonNull String getKey() {
			return this.key;
		}

		@Override
		@SuppressWarnings("NullAway")
		public @Nullable String getValue() {
			return null;
		}

		@Override
		public @NonNull String setValue(@Nullable String value) {
			throw new UnsupportedOperationException();
		}
	}
}
