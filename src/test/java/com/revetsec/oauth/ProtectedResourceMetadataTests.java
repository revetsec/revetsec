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
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;
final class ProtectedResourceMetadataTests {
	@Test void rawIdentifierAndDiscoveryDerivationRemainDistinct() {
		for (Map.Entry<String,String> pair : Map.ofEntries(
				Map.entry("https://rs.example", "https://rs.example/.well-known/oauth-protected-resource"),
				Map.entry("https://rs.example/", "https://rs.example/.well-known/oauth-protected-resource"),
				Map.entry("https://rs.example/?x=%2F", "https://rs.example/.well-known/oauth-protected-resource?x=%2F"),
				Map.entry("https://rs.example/path/", "https://rs.example/.well-known/oauth-protected-resource/path"),
				Map.entry("https://rs.example/path/?x=y", "https://rs.example/.well-known/oauth-protected-resource/path?x=y"),
				Map.entry("https://RS.example:443/a%2Fb/../c%2f?x=%252F&x=1", "https://RS.example:443/.well-known/oauth-protected-resource/a%2Fb/../c%2f?x=%252F&x=1"),
				Map.entry("https://rs.example/%2F?", "https://rs.example/.well-known/oauth-protected-resource/%2F?")).entrySet()) {
			ProtectedResourceMetadata metadata = ProtectedResourceMetadata.withResource(URI.create(pair.getKey())).build();
			assertEquals(pair.getKey(), metadata.getResource().toString());
			assertEquals(pair.getValue(), metadata.getWellKnownUri().toString());
			assertTrue(metadata.toJson().contains(pair.getKey()));
		}
	}
	@Test void jsonHasOnlyHeaderTransportAndOmittedEmptyArrays() {
		ProtectedResourceMetadata metadata = ProtectedResourceMetadata.withResource(URI.create("https://rs.example/mcp")).build();
		assertEquals("{\"resource\":\"https://rs.example/mcp\",\"bearer_methods_supported\":[\"header\"]}", metadata.toJson());
		assertTrue(metadata.getAuthorizationServers().isEmpty()); assertTrue(metadata.getScopesSupported().isEmpty());
		assertFalse(metadata.toString().contains("rs.example"));
	}
	@Test void listsAreOrderedExactSnapshotsAndResettable() {
		List<String> issuers = new ArrayList<>(List.of("https://AS.example", "https://as.example/", "https://AS.example"));
		List<String> scopes = new ArrayList<>(List.of("write", "read", "write"));
		ProtectedResourceMetadata.Builder builder = ProtectedResourceMetadata.withResource(URI.create("https://rs.example"))
				.authorizationServers(issuers).scopesSupported(scopes).allowInsecureLoopback(true);
		ProtectedResourceMetadata first = builder.build(); issuers.clear(); scopes.clear();
		assertEquals(List.of("https://AS.example", "https://as.example/"), first.getAuthorizationServers());
		assertEquals(List.of("write", "read"), first.getScopesSupported());
		assertTrue(first.toJson().contains("\"authorization_servers\":[\"https://AS.example\",\"https://as.example/\"]"));
		assertTrue(first.toJson().contains("\"scopes_supported\":[\"write\",\"read\"]"));
		assertThrows(UnsupportedOperationException.class, () -> first.getScopesSupported().add("admin"));
		assertThrows(UnsupportedOperationException.class, () -> first.getAuthorizationServers().clear());
		assertTrue(builder.authorizationServers(null).scopesSupported(null).allowInsecureLoopback(null).build().getAuthorizationServers().isEmpty());
		assertTrue(builder.authorizationServers(List.of()).scopesSupported(List.of()).build().getScopesSupported().isEmpty());
		assertEquals(2, first.getScopesSupported().size());
	}
	@Test void resourceAndIssuerPoliciesRejectUnsafeConfiguration() {
		for (String uri : List.of("relative", "mailto:rs@example.com", "ftp://rs.example", "https:/missing-host", "https://u@rs.example",
				"https://rs.example/#", "https://rs.example:0", "https://rs.example:65536", "http://rs.example"))
			assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(URI.create(uri)).build());
		for (String issuer : List.of("", "a b", "relative", "https://as.example?x=1", "https://as.example?", "https://as.example/#", "https://u@as.example", "http://as.example"))
			assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(URI.create("https://rs.example")).authorizationServers(List.of(issuer)).build());
		for (String host : List.of("localhost", "127.0.0.1", "[::1]")) {
			URI local = URI.create("http://"+host+":8080/resource");
			assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(local).build());
			assertEquals(local, ProtectedResourceMetadata.withResource(local).allowInsecureLoopback(true).authorizationServers(List.of("http://localhost:8081")).build().getResource());
			assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(local).allowInsecureLoopback(true).allowInsecureLoopback(null).build());
		}
		for (String host : List.of("localhost.", "a.localhost", "192.168.1.1", "0.0.0.0"))
			assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(URI.create("http://" + host)).allowInsecureLoopback(true).build());
	}
	@Test void jsonRenderingIsBoundedBeforeHugeExpansion() {
		URI base = URI.create("https://rs.example/");
		ProtectedResourceMetadata empty = ProtectedResourceMetadata.withResource(base).build();
		int padding = 262144 - empty.toJson().length();
		assertEquals(262144, ProtectedResourceMetadata.withResource(URI.create(base + "x".repeat(padding))).build().toJson().length());
		assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(URI.create(base + "x".repeat(padding+1))).build());
		assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(URI.create(base + "λ".repeat(150000))).build());
		assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(base).authorizationServers(List.of("https://as.example/"+"x".repeat(262144))));
		assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(base).authorizationServers(java.util.Collections.nCopies(100000, "https://as.example")));
		assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(base).authorizationServers(List.of("https://as.example/"+"x".repeat(150000),"https://bs.example/"+"x".repeat(150000))));
		assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(base).scopesSupported(List.of("x".repeat(262144))));
		assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(base).scopesSupported(List.of("")));
		assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(base).scopesSupported(List.of("a\nb")));
	}
	// Deliberate programmer misuse of the required factory seed.
	@SuppressWarnings("NullAway")
	@Test void nullResourceIsAProgrammingError() {
		assertThrows(NullPointerException.class, () -> ProtectedResourceMetadata.withResource(null));
	}

}
