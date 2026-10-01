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

package com.revetsec.oauth;

import org.junit.jupiter.api.Test;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
final class BearerChallengeTests {
	private static final URI METADATA = URI.create("https://rs.example/.well-known/oauth-protected-resource/mcp");
	@Test void initialChallengesOmitErrorsAndContainTrustedParameters() {
		assertEquals("Bearer resource_metadata=\"" + METADATA + "\"",
				BearerChallenge.builder().resourceMetadata(METADATA).build().getHeaderValue());
		assertEquals("Bearer scope=\"read write\"", BearerChallenge.builder().scopes(List.of("read", "write", "read")).build().getHeaderValue());
		assertEquals("Bearer realm=\"\"", BearerChallenge.builder().realm("").build().getHeaderValue());
	}
	@Test void renderingEscapesRealmsAndOrdersParameters() {
		BearerChallenge challenge = BearerChallenge.builder().realm("a\"b\\c").error(BearerError.INSUFFICIENT_SCOPE)
				.errorDescription("A fixed denial.").scopes(List.of("read", "write")).resourceMetadata(METADATA).build();
		assertEquals("Bearer realm=\"a\\\"b\\\\c\", error=\"insufficient_scope\", error_description=\"A fixed denial.\", scope=\"read write\", resource_metadata=\"" + METADATA + "\"", challenge.getHeaderValue());
		assertFalse(challenge.toString().contains("fixed denial"));
	}
	@Test void injectionCharactersAndInvalidScopesNeverRender() {
		for (String value : List.of("a\r", "a\n", "a\t", "a\u0000", "a\u007F", "£")) {
			assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().realm(value));
			assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().errorDescription(value));
		}
		for (String value : List.of("a\"b", "a\\b"))
			assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().errorDescription(value));
		for (String value : List.of("", "a b", "a\"b", "a\\b", "a\n", "λ"))
			assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().scopes(List.of(value)));
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().errorDescription("fixed").build());
	}
	@Test void noRenderedConfigurationIsMissingAndAllSettersReset() {
		assertThrows(IllegalStateException.class, () -> BearerChallenge.builder().build());
		assertThrows(IllegalStateException.class, () -> BearerChallenge.builder().maximumHeaderLength(1024).build());
		assertThrows(IllegalStateException.class, () -> BearerChallenge.builder().scopes(List.of("read")).scopes(List.of()).build());
		assertThrows(IllegalStateException.class, () -> BearerChallenge.builder().realm("x").realm(null).build());
		assertThrows(IllegalStateException.class, () -> BearerChallenge.builder().error(BearerError.INVALID_TOKEN).error(null).build());
		assertThrows(IllegalStateException.class, () -> BearerChallenge.builder().resourceMetadata(METADATA).resourceMetadata(null).build());
		BearerChallenge.Builder builder = BearerChallenge.builder().realm("x").error(BearerError.INVALID_TOKEN)
				.errorDescription("fixed").scopes(List.of("read")).resourceMetadata(METADATA).maximumHeaderLength(1024).allowInsecureLoopback(true);
		String first = builder.build().getHeaderValue();
		builder = builder.error(null).errorDescription(null).scopes(null).resourceMetadata(null)
				.maximumHeaderLength(null).allowInsecureLoopback(null);
		assertEquals("Bearer realm=\"x\"", builder.build().getHeaderValue());
		assertTrue(first.contains("invalid_token"));
		assertTrue(builder.realm("x".repeat(2000)).build().getHeaderValue().length() > 1024);
	}
	@Test void headerCapsIncludeQuoteExpansionAndOverloadsStayBounded() {
		for (int maximum : List.of(1024, 8192, 65536)) {
			assertEquals(maximum, BearerChallenge.builder().maximumHeaderLength(maximum).realm("x".repeat(maximum - 15)).build().getHeaderValue().length());
			assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().maximumHeaderLength(maximum).realm("x".repeat(maximum - 14)).build());
		}
		assertEquals(1023, BearerChallenge.builder().maximumHeaderLength(1024).realm("\"".repeat(504)).build().getHeaderValue().length());
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().maximumHeaderLength(1024).realm("\"".repeat(505)).build());
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().realm("x".repeat(65537)));
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().errorDescription("x".repeat(65537)));
		for (int maximum : List.of(-1, 0, 1023, 65537)) assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().maximumHeaderLength(maximum));
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().realm("x".repeat(1000)).scopes(List.of("read")).maximumHeaderLength(1024).build());
	}
	@Test void metadataLocationsHaveARealUriBoundaryAndLoopbackIsExplicit() {
		for (String value : List.of("/metadata", "ftp://rs.example/meta", "https://user@rs.example/meta", "https://rs.example/meta#",
				"https://rs.example:0/meta", "http://rs.example/meta"))
			assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().resourceMetadata(URI.create(value)).build());
		URI local = URI.create("http://127.0.0.1:8080/metadata");
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().resourceMetadata(local).build());
		assertTrue(BearerChallenge.builder().allowInsecureLoopback(true).resourceMetadata(local).build().getHeaderValue().contains(local.toString()));
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().allowInsecureLoopback(true).allowInsecureLoopback(null).resourceMetadata(local).build());
		assertTrue(BearerChallenge.builder().resourceMetadata(URI.create("https://rs.example/λ")).build().getHeaderValue().contains("%CE%BB"));
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().resourceMetadata(URI.create("https://rs.example/" + "x".repeat(8192))).build());
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().resourceMetadata(URI.create("https://rs.example/" + "λ".repeat(2000))).build());
	}
	@Test void scopeSnapshotIsIndependentAndBounded() {
		List<String> scopes = new ArrayList<>(List.of("read"));
		BearerChallenge.Builder builder = BearerChallenge.builder().scopes(scopes);
		scopes.add("write"); assertEquals("Bearer scope=\"read\"", builder.build().getHeaderValue());
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().scopes(List.of("a".repeat(65536))));
		assertThrows(IllegalArgumentException.class, () -> BearerChallenge.builder().scopes(java.util.Collections.nCopies(30000, "read")));
	}
}
