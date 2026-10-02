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

import com.revetsec.testing.Sentinels;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * {@code Content-Type} parsing (RFC 9110 section 8.3.1 and the grammar of sections 5.6.2 to 5.6.6) and the G6-7 media
 * type table as {@link ResponseProfile} enforces it, frozen after WP-5's record of the Content-Types that Keycloak
 * 26.7.4 and node-oidc-provider 9.12.2 send (M1 plan, "Results > Phase 1").
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class MediaTypeTests {
	// WP-5a record: every Content-Type the two providers sent, including the non-2xx and revocation ones, parses.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> parsesEveryContentTypeTheProvidersSent() {
		Map<String, List<String>> observed = new LinkedHashMap<>();
		observed.put("application/json", List.of("application/json", ""));
		observed.put("application/json; charset=utf-8", List.of("application/json", "utf-8"));
		observed.put("application/jwk-set+json", List.of("application/jwk-set+json", ""));
		observed.put("application/jwk-set+json; charset=utf-8", List.of("application/jwk-set+json", "utf-8"));
		observed.put("application/jwt", List.of("application/jwt", ""));
		observed.put("application/jwt; charset=utf-8", List.of("application/jwt", "utf-8"));
		observed.put("text/plain;charset=utf-8", List.of("text/plain", "utf-8"));
		observed.put("text/plain; charset=utf-8", List.of("text/plain", "utf-8"));

		return observed.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			MediaType mediaType = MediaType.parse(entry.getKey()).orElseThrow();
			Assertions.assertEquals(entry.getValue().get(0), mediaType.getEssence());
			Assertions.assertEquals(entry.getValue().get(1), mediaType.getCharset().orElse(""));
			Assertions.assertTrue(mediaType.hasUtf8OrNoCharset());
		}));
	}

	// RFC 9110 section 8.3.1: type, subtype, parameter names and (for charset) the value compare case-insensitively,
	// and a quoted-string value equals its token form.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> comparesCaseInsensitivelyAndUnquotes() {
		return Stream.of("application/json; charset=UTF-8", "Application/JSON; Charset=utf-8",
						"APPLICATION/JSON;CHARSET=\"UTF-8\"", "application/json;charset=\"utf-8\"",
						"application/json ; charset=utf-8", "\t application/json;\tcharset=Utf-8 \t",
						"application/json; charset=\"u\\tf-8\"")
				.map(value -> DynamicTest.dynamicTest(value, () -> {
					MediaType mediaType = MediaType.parse(value).orElseThrow();
					Assertions.assertEquals("application", mediaType.getType());
					Assertions.assertEquals("json", mediaType.getSubtype());
					Assertions.assertEquals("application/json", mediaType.getEssence());
					Assertions.assertTrue(mediaType.hasUtf8OrNoCharset(), value);
					Assertions.assertEquals(List.of("charset"), List.copyOf(mediaType.getParameters().keySet()));
				}));
	}

	// RFC 9110 sections 5.6.2 to 5.6.6: tokens, OWS only around ";", parameter = name "=" value, and quoted-string
	// escapes. Empty parameters are allowed by the grammar.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> parsesTheGrammar() {
		List<Object[]> cases = List.of(
				new Object[]{"a/b", "a/b", Map.of()},
				new Object[]{"a/b;", "a/b", Map.of()},
				new Object[]{"a/b; ;c=d", "a/b", Map.of("c", "d")},
				new Object[]{"a/b;c=d;e=f", "a/b", Map.of("c", "d", "e", "f")},
				new Object[]{"a/b; c=\"x;y=z\"", "a/b", Map.of("c", "x;y=z")},
				new Object[]{"a/b; c=\"a\\\"b\"", "a/b", Map.of("c", "a\"b")},
				new Object[]{"a/b; c=\"\"", "a/b", Map.of("c", "")},
				new Object[]{"a/b; c=\"caf\u00E9\"", "a/b", Map.of("c", "caf\u00E9")},
				new Object[]{"!#$%&'*+-.^_`|~0/x", "!#$%&'*+-.^_`|~0/x", Map.of()},
				new Object[]{"application/vnd.example+json; profile=\"https://example.com/p\"",
						"application/vnd.example+json", Map.of("profile", "https://example.com/p")});
		return cases.stream().map(testCase -> DynamicTest.dynamicTest((String) testCase[0], () -> {
			MediaType mediaType = MediaType.parse((String) testCase[0]).orElseThrow();
			Assertions.assertEquals(testCase[1], mediaType.getEssence());
			Assertions.assertEquals(testCase[2], mediaType.getParameters());
		}));
	}

	// RFC 9110 section 8.3.1: anything off the grammar is malformed, and so is a parameter repeated in any case (a
	// Revetsec rule: two charsets could be read two ways).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsValuesOffTheGrammar() {
		return Stream.of("", " ", "application", "application/", "/json", "application /json", "application/ json",
						"application/json json", "application/json, text/plain", "application/json;charset",
						"application/json;charset=", "application/json; charset = utf-8", "application/json;charset= utf-8",
						"application/json; =utf-8", "application/json; charset=\"utf-8", "application/json; charset=\"a\\\"",
						"application/json; charset=utf-8 x", "application/json; charset=utf-8; CHARSET=utf-8",
						"application/json; a=1; a=1", "application/json; c=\"x\u0001\"", "application/json; c=\"x\\\u0001\"",
						"application/json; c=\"\u0100\"", "appl\u00E9cation/json", "application/js\u0000on",
						"application/json;c=a\"b", "application/json\r\n", "text/\u212Aelvin")
				.map(value -> DynamicTest.dynamicTest("\"" + escaped(value) + "\"",
						() -> Assertions.assertEquals(Optional.empty(), MediaType.parse(value))));
	}

	// G6-7: only charset utf-8 (in any ASCII case), or no charset, is accepted; other parameters are ignored.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> acceptsOnlyAUtf8OrAbsentCharset() {
		Map<String, Boolean> cases = new LinkedHashMap<>();
		cases.put("application/json", true);
		cases.put("application/json; charset=utf-8", true);
		cases.put("application/json; charset=UTF-8", true);
		cases.put("application/json; profile=x", true);
		cases.put("application/json; charset=utf8", false);
		cases.put("application/json; charset=utf-16", false);
		cases.put("application/json; charset=iso-8859-1", false);
		cases.put("application/json; charset=us-ascii", false);
		cases.put("application/json; charset=\"\"", false);
		cases.put("application/json; charset=utf-8x", false);
		cases.put("application/json; charset=\"utf-8\"", true);
		return cases.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(),
				() -> Assertions.assertEquals(entry.getValue(),
						MediaType.parse(entry.getKey()).orElseThrow().hasUtf8OrNoCharset())));
	}

	// G6-7 frozen table: METADATA, TOKEN, INTROSPECTION application/json; JWKS adds application/jwk-set+json;
	// USERINFO adds application/jwt; REVOCATION is not checked. Every allowed type takes charset absent or utf-8.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> enforcesTheFrozenMediaTypeTable() {
		List<String> candidates = List.of("application/json", "application/jwk-set+json", "application/jwt",
				"application/jwk+json", "text/plain", "text/html", "application/token-introspection+jwt",
				"application/jose", "application/octet-stream");
		Map<ResponseProfile, List<String>> table = new LinkedHashMap<>();
		table.put(ResponseProfile.METADATA, List.of("application/json"));
		table.put(ResponseProfile.TOKEN, List.of("application/json"));
		table.put(ResponseProfile.INTROSPECTION, List.of("application/json"));
		table.put(ResponseProfile.JWKS, List.of("application/json", "application/jwk-set+json"));
		table.put(ResponseProfile.USERINFO, List.of("application/json", "application/jwt"));
		table.put(ResponseProfile.REVOCATION, List.of());
		Assertions.assertEquals(List.of(ResponseProfile.values()), List.copyOf(table.keySet()));

		List<DynamicTest> tests = new ArrayList<>();
		for (Map.Entry<ResponseProfile, List<String>> row : table.entrySet()) {
			ResponseProfile profile = row.getKey();
			tests.add(DynamicTest.dynamicTest(profile + " list", () -> {
				Assertions.assertEquals(row.getValue(), profile.getAcceptedMediaTypes());
				Assertions.assertEquals(!row.getValue().isEmpty(), profile.isMediaTypeChecked());
			}));
			for (String candidate : candidates)
				for (String parameters : List.of("", "; charset=utf-8", "; charset=UTF-8", "; charset=iso-8859-1")) {
					String value = candidate + parameters;
					boolean expected = !profile.isMediaTypeChecked()
							|| (row.getValue().contains(candidate) && !parameters.contains("iso"));
					tests.add(DynamicTest.dynamicTest(profile + " " + value, () -> Assertions.assertEquals(expected,
							profile.accepts(MediaType.parse(value).orElseThrow()))));
				}
		}
		return tests.stream();
	}

	// G6-7 and WP-5a: each profile's Accept header lists exactly what its table accepts (JWKS asks for the set type
	// first, so node-oidc-provider and Keycloak both answer with an accepted type), and REVOCATION asks for JSON.
	@Test
	void eachProfileAsksForWhatItAccepts() {
		Assertions.assertEquals("application/json", ResponseProfile.METADATA.getAcceptHeaderValue());
		Assertions.assertEquals("application/json", ResponseProfile.TOKEN.getAcceptHeaderValue());
		Assertions.assertEquals("application/json", ResponseProfile.INTROSPECTION.getAcceptHeaderValue());
		Assertions.assertEquals("application/jwk-set+json, application/json", ResponseProfile.JWKS.getAcceptHeaderValue());
		Assertions.assertEquals("application/json, application/jwt", ResponseProfile.USERINFO.getAcceptHeaderValue());
		Assertions.assertEquals("application/json", ResponseProfile.REVOCATION.getAcceptHeaderValue());
		for (ResponseProfile profile : ResponseProfile.values())
			for (String accepted : profile.getAcceptedMediaTypes())
				Assertions.assertTrue(profile.getAcceptHeaderValue().contains(accepted), profile::name);
	}

	// R8: each profile bounds its 2xx body with its own Limits row.
	@Test
	void eachProfileNamesItsBodySizeRow() {
		for (ResponseProfile profile : ResponseProfile.values())
			Assertions.assertEquals(profile == ResponseProfile.JWKS ? "JWKS response body size" : "HTTP response body size",
					profile.getBodySizeLimit().getName(), profile::name);
	}

	// R9: toString shows the essence and parameter names, never parameter values.
	@Test
	void toStringOmitsParameterValues() {
		MediaType mediaType = MediaType.parse("application/json; charset=utf-8; token=" + Sentinels.ACCESS_TOKEN)
				.orElseThrow();
		Assertions.assertEquals("MediaType{essence=application/json, parameterNames=[charset, token]}",
				mediaType.toString());
		Sentinels.assertAbsent(mediaType.toString());
		Assertions.assertThrows(NullPointerException.class, () -> MediaType.parse(nullString()));
		Assertions.assertThrows(NullPointerException.class, () -> ResponseProfile.TOKEN.accepts(nullMediaType()));
	}

	// MediaType is a value: parses that differ only in case, OWS or quoting are equal, and its parameters cannot be
	// changed.
	@Test
	void equalParsesAreEqualAndParametersAreUnmodifiable() {
		MediaType mediaType = MediaType.parse("a/b; c=d").orElseThrow();
		MediaType same = MediaType.parse("A/B ;C=\"d\"").orElseThrow();
		Assertions.assertEquals(mediaType, same);
		Assertions.assertEquals(mediaType.hashCode(), same.hashCode());
		Assertions.assertNotEquals(mediaType, MediaType.parse("a/b; c=D").orElseThrow());
		Assertions.assertNotEquals(mediaType, MediaType.parse("a/b").orElseThrow());
		Assertions.assertThrows(UnsupportedOperationException.class, () -> mediaType.getParameters().put("e", "f"));
	}

	private static @NonNull String escaped(@NonNull String value) {
		StringBuilder escaped = new StringBuilder();
		for (char c : value.toCharArray())
			escaped.append(c < 0x20 || c > 0x7E ? String.format(java.util.Locale.ROOT, "\\u%04X", (int) c)
					: String.valueOf(c));
		return escaped.toString();
	}

	@SuppressWarnings("NullAway")
	private static @NonNull String nullString() {
		return nullValue();
	}

	@SuppressWarnings("NullAway")
	private static @NonNull MediaType nullMediaType() {
		return nullValue();
	}

	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @NonNull T nullValue() {
		@Nullable T value = null;
		return value;
	}
}
