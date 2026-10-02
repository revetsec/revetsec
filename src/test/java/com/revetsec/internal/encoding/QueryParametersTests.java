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

package com.revetsec.internal.encoding;

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Query and form parameters with multiplicity and order kept (R7; RFC 6749 section 3.1: parameters must not be
 * repeated, so the caller must be able to see a repetition; RFC 6749 Appendix B decoding).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class QueryParametersTests {
	// RFC 6749 section 4.1.2 example authorization response.
	@Test
	void parsesTheRfc6749AuthorizationResponseExample() throws EncodingException {
		QueryParameters parameters = QueryParameters.parse("code=SplxlOBeZQQYbYS6WxSbIA&state=xyz");
		Assertions.assertEquals(List.of("code=SplxlOBeZQQYbYS6WxSbIA", "state=xyz"), render(parameters));
		Assertions.assertEquals(List.of("SplxlOBeZQQYbYS6WxSbIA"), parameters.getValues("code"));
		Assertions.assertEquals(List.of("xyz"), parameters.getValues("state"));
	}

	// RFC 6749 section 3.1: a repeated parameter is kept, in place, so the caller can reject it; nothing is merged,
	// dropped or reordered.
	@Test
	void keepsEveryRepetitionInInputOrder() throws EncodingException {
		QueryParameters parameters = QueryParameters.parse("state=a&code=1&state=b&state=a");
		Assertions.assertEquals(List.of("state=a", "code=1", "state=b", "state=a"), render(parameters));
		Assertions.assertEquals(List.of("a", "b", "a"), parameters.getValues("state"));
		Assertions.assertEquals(List.of("state", "code"), List.copyOf(parameters.getValuesByName().keySet()));
		Assertions.assertEquals(Map.of("state", List.of("a", "b", "a"), "code", List.of("1")),
				parameters.getValuesByName());
	}

	// RFC 6749 Appendix B: names and values are decoded, '+' as a space.
	@Test
	void decodesNamesAndValues() throws EncodingException {
		QueryParameters parameters = QueryParameters.parse(
				"redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&scope=openid+profile&a+b=%C2%A3%E2%82%AC");
		Assertions.assertEquals(List.of("https://client.example.com/cb"), parameters.getValues("redirect_uri"));
		Assertions.assertEquals(List.of("openid profile"), parameters.getValues("scope"));
		Assertions.assertEquals(List.of("\u00A3\u20AC"), parameters.getValues("a b"));
	}

	// Splitting rules: '&' only; the first '=' separates; no '=' means the empty value; empty pieces are skipped.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> splitsPiecesAsSpecified() {
		return Stream.of(new Object[][]{
				{"", List.of()},
				{"&", List.of()},
				{"&&&", List.of()},
				{"a=1", List.of("a=1")},
				{"&a=1&&b=2&", List.of("a=1", "b=2")},
				{"a=b=c", List.of("a=b=c")},
				{"flag", List.of("flag=")},
				{"flag&a=", List.of("flag=", "a=")},
				{"=", List.of("=")},
				{"=x", List.of("=x")},
				{"a=1;b=2", List.of("a=1;b=2")},
				{"a=%26&b=%3D", List.of("a=&", "b==")},
				{"?a=1", List.of("?a=1")}
		}).map(vector -> DynamicTest.dynamicTest(EncodingFailures.describe((String) vector[0]), () ->
				Assertions.assertEquals(vector[1], render(QueryParameters.parse((String) vector[0])))));
	}

	// R18: parameter names are compared exactly; "State" is not "state".
	@Test
	void comparesNamesCaseSensitively() throws EncodingException {
		QueryParameters parameters = QueryParameters.parse("State=1&state=2&STATE=3");
		Assertions.assertEquals(List.of("2"), parameters.getValues("state"));
		Assertions.assertEquals(List.of("1"), parameters.getValues("State"));
		Assertions.assertEquals(List.of(), parameters.getValues("sTaTe"));
		Assertions.assertEquals(3, parameters.getValuesByName().size());
	}

	// One malformed name or value anywhere rejects the whole input; nothing is partially returned.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsTheWholeInputWhenAnyPieceIsMalformed() {
		return Stream.of(new Object[][]{
				{"code=abc&state=%", EncodingException.Kind.MALFORMED_PERCENT_ENCODING},
				{"code%G1=abc", EncodingException.Kind.MALFORMED_PERCENT_ENCODING},
				{"code=abc&state=%C3", EncodingException.Kind.INVALID_UTF8},
				{"%FF=1", EncodingException.Kind.INVALID_UTF8},
				{"code=\uD800", EncodingException.Kind.UNPAIRED_SURROGATE},
				{"code=" + EncodingFailures.SENTINEL + "&state=%ED%A0%80", EncodingException.Kind.INVALID_UTF8}
		}).map(vector -> DynamicTest.dynamicTest(EncodingFailures.describe((String) vector[0]), () ->
				EncodingFailures.assertRejected((EncodingException.Kind) vector[1], (String) vector[0],
						() -> QueryParameters.parse((String) vector[0]))));
	}

	@Test
	void returnsUnmodifiableViews() throws EncodingException {
		QueryParameters parameters = QueryParameters.parse("a=1&a=2&b=3");
		Assertions.assertThrows(UnsupportedOperationException.class, () -> parameters.getParameters().clear());
		Assertions.assertThrows(UnsupportedOperationException.class, () -> parameters.getValues("a").add("x"));
		Map<String, List<String>> byName = parameters.getValuesByName();
		Assertions.assertThrows(UnsupportedOperationException.class, () -> byName.remove("a"));
		List<String> values = byName.values().iterator().next();
		Assertions.assertThrows(UnsupportedOperationException.class, () -> values.add("x"));
	}

	// R9: parameters carry authorization codes and state, so neither rendering shows a name or value.
	@Test
	void rendersWithoutNamesOrValues() throws EncodingException {
		QueryParameters parameters = QueryParameters.parse("code=" + EncodingFailures.SENTINEL + "&"
				+ EncodingFailures.SENTINEL + "=1");
		Assertions.assertEquals("QueryParameters{parameters=<redacted>}", parameters.toString());
		for (QueryParameters.Parameter parameter : parameters.getParameters())
			Assertions.assertEquals("Parameter{name=<redacted>, value=<redacted>}", parameter.toString());
	}

	// R8: the parse is linear, because '=' is searched for only inside each piece. Searching the rest of the input
	// for every piece is quadratic: for these 1,000,000 pieces it took about 30 s on the machine where this test was
	// written, against about 0.2 s for the linear parse, so the 10 s budget catches that regression with wide margins
	// both ways. (At 200,000 pieces the quadratic search still finished in about 1.5 s, too fast to tell apart.)
	@Test
	void parsesManyPiecesWithoutAnEqualsSignInLinearTime() {
		String input = "a&".repeat(1_000_000);
		QueryParameters parameters = Assertions.assertTimeoutPreemptively(Duration.ofSeconds(10),
				() -> QueryParameters.parse(input));
		Assertions.assertEquals(1_000_000, parameters.getParameters().size());
		Assertions.assertEquals(1_000_000, parameters.getValues("a").size());
	}

	@Test
	@SuppressWarnings("NullAway")
	void rejectsNullArgumentsWithNullPointerException() throws EncodingException {
		Assertions.assertThrows(NullPointerException.class, () -> QueryParameters.parse(null));
		QueryParameters parameters = QueryParameters.parse("a=1");
		Assertions.assertThrows(NullPointerException.class, () -> parameters.getValues(null));
	}

	private static @NonNull List<@NonNull String> render(@NonNull QueryParameters parameters) {
		List<String> rendered = new ArrayList<>();
		for (QueryParameters.Parameter parameter : parameters.getParameters())
			rendered.add(parameter.getName() + "=" + parameter.getValue());
		Assertions.assertEquals(rendered.stream().map(piece -> piece.substring(0, piece.indexOf('=')))
				.distinct().collect(Collectors.toList()), List.copyOf(parameters.getValuesByName().keySet()));
		return rendered;
	}
}
