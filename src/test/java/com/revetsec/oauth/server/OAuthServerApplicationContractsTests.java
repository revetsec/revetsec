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

package com.revetsec.oauth.server;

import com.revetsec.testing.Sentinels;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.util.stream.Stream;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Approved AS1-A1 app/configuration boundary; endpoint and store behavior are tested in later slices. */
final class OAuthServerApplicationContractsTests {
	private static final @NonNull String RESOURCE = "https://resource.example/mcp";
	private static final @NonNull URI REDIRECT = URI.create("https://client.example/callback?app=retained%2Fvalue");
	private static OAuthServerClientRegistration.@NonNull Builder registration() {
		return OAuthServerClientRegistration.withClientId("client").redirectUris(List.of(REDIRECT))
				.allowedScopesByResource(Map.of(RESOURCE, Set.of("read"))).configurationVersion("v1");
	}
	@Test void defaultsAndNullResetsAreExact() {
		var auth = OAuthServerClientAuthentication.fromClientSecretVerifier((id, secret, budget) -> true);
		var builder = registration().authentication(auth).refreshTokenPermitted(true).clientName("name")
				.introspectionResources(Set.of(RESOURCE));
		assertSame(builder, builder.authentication(null).refreshTokenPermitted(null).clientName(null).introspectionResources(null)
				.authorizationCodePermitted(null));
		var value = builder.build();
		assertSame(OAuthServerClientAuthentication.publicClientInstance(), value.getAuthentication());
		assertFalse(value.isRefreshTokenPermitted()); assertTrue(value.isAuthorizationCodePermitted());
		assertEquals(Optional.empty(), value.getClientName()); assertEquals(Set.of(), value.getIntrospectionResources());
		assertEquals("client", value.getClientId()); assertEquals("v1", value.getConfigurationVersion());
		assertEquals(List.of(REDIRECT), value.getRedirectUris());
		assertEquals(Map.of(RESOURCE, Set.of("read")), value.getAllowedScopesByResource());
	}
	@Test void requiredRegistrationResetsAndReplacementRecover() {
		assertThrows(IllegalStateException.class, () -> OAuthServerClientRegistration.withClientId("client").build());
		var builder = registration(); assertSame(builder, builder.configurationVersion(null));
		assertThrows(IllegalStateException.class, builder::build); assertSame(builder, builder.configurationVersion("v2"));
		assertSame(builder, builder.redirectUris(null)); assertThrows(IllegalStateException.class, builder::build);
		assertSame(builder, builder.redirectUris(List.of(REDIRECT)).allowedScopesByResource(null));
		assertThrows(IllegalStateException.class, builder::build);
		assertEquals("v2", builder.allowedScopesByResource(Map.of(RESOURCE, Set.of())).build().getConfigurationVersion());
	}
	@Test void resourceOnlyConfigurationNeedsNoFakeRedirectAndHasIndependentAuthority() {
		var auth = OAuthServerClientAuthentication.fromClientSecretVerifier((id, secret, budget) -> true);
		var builder = registration().authorizationCodePermitted(false).authentication(auth)
				.introspectionResources(Set.of("urn:resource:one"));
		var value = builder.build();
		assertFalse(value.isAuthorizationCodePermitted()); assertEquals(List.of(), value.getRedirectUris());
		assertEquals(Map.of(), value.getAllowedScopesByResource());
		assertEquals(Set.of("urn:resource:one"), value.getIntrospectionResources());
		assertSame(builder, builder.redirectUris(List.of(REDIRECT)));
		assertSame(builder, builder.allowedScopesByResource(Map.of(RESOURCE, Set.of("read"))));
		assertFalse(builder.build().isAuthorizationCodePermitted());
		assertEquals(List.of(), builder.build().getRedirectUris());
		assertEquals(Map.of(), builder.build().getAllowedScopesByResource());
		assertSame(builder, builder.authorizationCodePermitted(false).redirectUris(List.of()).allowedScopesByResource(Map.of()));
		assertSame(builder, builder.authorizationCodePermitted(null)); assertThrows(IllegalStateException.class, builder::build);
		assertTrue(builder.redirectUris(List.of(REDIRECT)).allowedScopesByResource(Map.of(RESOURCE, Set.of("read")))
				.build().isAuthorizationCodePermitted());
	}
	@Test void introspectionAuthorityRequiresBasicAndIsNeverInherited() {
		assertThrows(IllegalArgumentException.class, () -> registration().introspectionResources(Set.of(RESOURCE)).build());
		var auth = OAuthServerClientAuthentication.fromClientSecretVerifier((id, secret, budget) -> true);
		var value = registration().authentication(auth).build();
		assertEquals(Set.of(), value.getIntrospectionResources());
		assertThrows(IllegalArgumentException.class, () -> registration().authentication(auth)
				.introspectionResources(Set.of(RESOURCE)).authentication(null).build());
	}
	@Test void collectionsAreDeepSnapshotsAtSetterTimeAndBuildersRemainIndependent() {
		List<URI> redirects = new ArrayList<>(List.of(REDIRECT)); Set<String> scopes = new LinkedHashSet<>(Set.of("read"));
		Map<String, Set<String>> resources = new HashMap<>(); resources.put(RESOURCE, scopes);
		Set<String> introspection = new LinkedHashSet<>(Set.of(RESOURCE));
		var auth = OAuthServerClientAuthentication.fromClientSecretVerifier((id, secret, budget) -> true);
		var builder = registration().redirectUris(redirects).allowedScopesByResource(resources)
				.authentication(auth).introspectionResources(introspection);
		redirects.clear(); scopes.clear(); resources.clear(); introspection.clear();
		var first = builder.build(); assertSame(builder, builder.redirectUris(List.of(URI.create("https://other.example/callback")))
				.allowedScopesByResource(Map.of("urn:other", Set.of("write"))).introspectionResources(null));
		assertEquals(List.of(REDIRECT), first.getRedirectUris());
		assertEquals(Map.of(RESOURCE, Set.of("read")), first.getAllowedScopesByResource());
		assertEquals(Set.of(RESOURCE), first.getIntrospectionResources());
		assertThrows(UnsupportedOperationException.class, () -> first.getRedirectUris().clear());
		assertThrows(UnsupportedOperationException.class, () -> first.getAllowedScopesByResource().clear());
		assertThrows(UnsupportedOperationException.class, () -> first.getAllowedScopesByResource().getOrDefault(RESOURCE, Set.of()).clear());
		assertThrows(UnsupportedOperationException.class, () -> first.getIntrospectionResources().clear());
	}
	@Test void identitiesNeverNormalizeCaseEscapesOrWhitespace() {
		URI first = URI.create("https://CLIENT.example/%7Ecallback?x=%2f");
		URI second = URI.create("https://client.example/%7ecallback?x=%2F");
		assertEquals(first, second); // URI.equals would collapse distinct approved spellings.
		String a = "https://RESOURCE.example/%7E"; String b = "https://resource.example/%7e";
		var value = OAuthServerClientRegistration.withClientId(" exact client ").redirectUris(List.of(first, second))
				.allowedScopesByResource(Map.of(a, Set.of("READ"), b, Set.of("read")))
				.configurationVersion(" version ").build();
		assertEquals(" exact client ", value.getClientId()); assertEquals(" version ", value.getConfigurationVersion());
		assertEquals(List.of(first.toString(), second.toString()), value.getRedirectUris().stream().map(URI::toString).toList());
		assertEquals(2, value.getAllowedScopesByResource().size());
		assertThrows(IllegalArgumentException.class, () -> registration().redirectUris(List.of(first, first)));
	}
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> eligibleLoopbackConfigurationIsRepresentableButDoesNotEnableServerFlags() {
		return List.of("http://127.0.0.1:1234/callback", "http://[::1]:5432/callback", "http://localhost:1234/callback", "HTTPS://client.example/callback").stream().map(uri -> DynamicTest.dynamicTest("uri: " + uri, () -> {
		assertEquals(uri, registration().redirectUris(List.of(URI.create(uri))).build().getRedirectUris().get(0).toString());
		}));
	}
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> unsafeRedirectsAndEncodedResponseParameterCollisionsAreRejected() {
		return List.of("/relative", "urn:callback:one", "custom://client/callback", "http://client.example/callback",
			"http://127.0.0.2/callback", "http://127.1/callback", "http://127.000.000.001/callback",
			"http://localhost.example/callback", "http://localhost./callback", "http://LOCALHOST/callback",
			"http://192.168.1.2/callback", "http://[0:0:0:0:0:0:0:1]/callback", "https://user@client.example/callback",
			"https://client.example/callback#", "https://client.example:0/callback", "https://client.example:65536/callback",
			"https://client.example/*", "https://client.example/callback?code=x", "https://client.example/callback?%63ode=x",
			"https://client.example/callback?state", "https://client.example/callback?iss=x", "https://client.example/callback?error=x",
			"https://client.example/callback?error_description=x", "https://client.example/callback?error_uri=x",
			"https://client.example/callback?ok=1&st%61te=x&ok=2", "https://client.example/callback?%FF=x").stream().map(uri -> DynamicTest.dynamicTest("uri: " + uri, () -> {
		var failure = assertThrows(IllegalArgumentException.class, () -> registration().redirectUris(List.of(URI.create(uri))));
		assertEquals("Invalid authorization-server configuration value.", failure.getMessage()); assertNull(failure.getCause());
		}));
	}
	@Test void redirectListAndEncodedAggregateBoundsApplyBeforeSnapshot() {
		List<URI> redirects = new ArrayList<>();
		for (int i = 0; i < 64; i++) redirects.add(URI.create("https://client.example/callback/" + i));
		assertEquals(64, registration().redirectUris(redirects).build().getRedirectUris().size());
		redirects.add(URI.create("https://client.example/callback/64"));
		assertThrows(IllegalArgumentException.class, () -> registration().redirectUris(redirects));
		assertThrows(IllegalArgumentException.class, () -> registration().redirectUris(List.of()));
		assertThrows(IllegalArgumentException.class, () -> registration().redirectUris(List.of(URI.create("https://client.example/" + "a".repeat(65_536)))));
		List<URI> large = List.of(URI.create("https://client.example/1/" + "é".repeat(40_000)),
				URI.create("https://client.example/2/" + "é".repeat(40_000)));
		assertThrows(IllegalArgumentException.class, () -> registration().redirectUris(large));
	}
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> resourceIdentifiersHaveAbsoluteSyntaxAndNoFragment() {
		return List.of("", "relative", "https://resource.example/#fragment", "https://resource.example/#", "urn:bad value", "urn:bad\nvalue").stream().map(resource -> DynamicTest.dynamicTest("resource: " + resource, () -> {
		assertThrows(IllegalArgumentException.class, () -> registration().allowedScopesByResource(Map.of(resource, Set.of("read"))));
		assertThrows(IllegalArgumentException.class, () -> registration().introspectionResources(Set.of(resource)));
		}));
	}
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> scopeTokensHaveNonemptyAsciiOAuthGrammar() {
		return List.of("", "two scopes", "quote\"", "back\\slash", "line\nfeed", "read\t", "é", "read\u007F").stream().map(scope -> DynamicTest.dynamicTest("scope: " + scope, () -> {
		assertThrows(IllegalArgumentException.class, () -> registration().allowedScopesByResource(Map.of(RESOURCE, Set.of(scope))));
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationDecision.withSubject("subject")
				.authorizedScopesByResource(Map.of(RESOURCE, Set.of(scope))));
		}));
	}
	@Test void carrierCapacityCeilingsAdmitServerMaxima() {
		Map<String, Set<String>> resources = new LinkedHashMap<>();
		for (int i = 0; i < 1_024; i++) resources.put("urn:r:" + i, Set.of("read"));
		assertEquals(1_024, registration().allowedScopesByResource(resources).build().getAllowedScopesByResource().size());
		assertEquals(1_024, registration().introspectionResources(resources.keySet())
				.authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id, secret, budget) -> true))
				.build().getIntrospectionResources().size());
		resources.put("urn:r:1024", Set.of("read"));
		assertThrows(IllegalArgumentException.class, () -> registration().allowedScopesByResource(resources));
		assertThrows(IllegalArgumentException.class, () -> registration().introspectionResources(resources.keySet()));
		Set<String> scopes = new LinkedHashSet<>(); for (int i = 0; i < 128; i++) scopes.add("s" + i);
		assertEquals(128, registration().allowedScopesByResource(Map.of(RESOURCE, scopes)).build()
				.getAllowedScopesByResource().getOrDefault(RESOURCE, Set.of()).size());
		scopes.add("s128"); assertThrows(IllegalArgumentException.class, () -> registration().allowedScopesByResource(Map.of(RESOURCE, scopes)));
		assertEquals(128, registration().allowedScopesByResource(Map.of(RESOURCE, Set.of("a".repeat(128))))
				.build().getAllowedScopesByResource().getOrDefault(RESOURCE, Set.of()).iterator().next().length());
		assertThrows(IllegalArgumentException.class, () -> registration().allowedScopesByResource(Map.of(RESOURCE, Set.of("a".repeat(129)))));
	}
	@Test void aggregateResourceOctetsDoNotTreatUtf16LengthAsUtf8Length() {
		Map<String, Set<String>> resources = new LinkedHashMap<>();
		resources.put("urn:first:" + "é".repeat(40_000), Set.of("read"));
		resources.put("urn:second:" + "é".repeat(40_000), Set.of("read"));
		assertThrows(IllegalArgumentException.class, () -> registration().allowedScopesByResource(resources));
		assertThrows(IllegalArgumentException.class, () -> registration().introspectionResources(resources.keySet()));
		resources.clear(); resources.put("urn:exact:" + "a".repeat(65_536 - "urn:exact:".length()), Set.of());
		assertEquals(65_536, registration().allowedScopesByResource(resources).build().getAllowedScopesByResource().keySet().iterator().next().length());
		resources.put("urn:too-long:" + "a".repeat(65_536), Set.of());
		assertThrows(IllegalArgumentException.class, () -> registration().allowedScopesByResource(resources));
	}
	@Test
	@SuppressWarnings("NullAway") // Deliberately tests required-null boundary rejection.
	void primaryTextBoundsUnicodeAndNullsAreExplicit() {
		assertThrows(NullPointerException.class, () -> OAuthServerClientRegistration.withClientId(null));
		assertThrows(NullPointerException.class, () -> OAuthAuthorizationDecision.withSubject(null));
		assertThrows(NullPointerException.class, () -> OAuthServerClientAuthentication.fromClientSecretVerifier(null));
		assertEquals(4_096, OAuthServerClientRegistration.withClientId("x".repeat(4_096)).authorizationCodePermitted(false)
				.configurationVersion("v").build().getClientId().length());
		assertThrows(IllegalArgumentException.class, () -> OAuthServerClientRegistration.withClientId("x".repeat(4_097)));
		assertEquals(1_024, OAuthAuthorizationDecision.withSubject("x".repeat(1_024)).authorizedScopesByResource(Map.of(RESOURCE, Set.of("read")))
				.build().getSubject().orElseThrow().length());
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationDecision.withSubject("x".repeat(1_025)));
		assertEquals("用户😀", OAuthAuthorizationDecision.withSubject("用户😀").authorizedScopesByResource(Map.of(RESOURCE, Set.of("read")))
				.build().getSubject().orElseThrow());
		for (String invalid : List.of("", "bad\u0000value", "bad\uD800", "bad\uDC00", "bad\u0085")) {
			assertThrows(IllegalArgumentException.class, () -> OAuthServerClientRegistration.withClientId(invalid));
			assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationDecision.withSubject(invalid));
			assertThrows(IllegalArgumentException.class, () -> registration().clientName(invalid));
			assertThrows(IllegalArgumentException.class, () -> registration().configurationVersion(invalid));
		}
		assertEquals(4_096, registration().clientName("n".repeat(4_096)).configurationVersion("v".repeat(4_096))
				.build().getConfigurationVersion().length());
		assertThrows(IllegalArgumentException.class, () -> registration().clientName("n".repeat(4_097)));
		assertThrows(IllegalArgumentException.class, () -> registration().configurationVersion("v".repeat(4_097)));
	}
	@Test void nullCollectionElementsAreRejectedWithoutEcho() {
		List<URI> redirects = new ArrayList<>(); redirects.add(null);
		assertThrows(NullPointerException.class, () -> registration().redirectUris(redirects));
		Map<String, Set<String>> resources = new HashMap<>(); resources.put(null, Set.of("read"));
		assertThrows(NullPointerException.class, () -> registration().allowedScopesByResource(resources));
		resources.clear(); resources.put(RESOURCE, null);
		assertThrows(NullPointerException.class, () -> registration().allowedScopesByResource(resources));
		Set<String> scopes = new LinkedHashSet<>(); scopes.add(null); resources.put(RESOURCE, scopes);
		assertThrows(NullPointerException.class, () -> registration().allowedScopesByResource(resources));
		assertThrows(NullPointerException.class, () -> registration().introspectionResources(scopes));
	}
	@Test void deniedDecisionAndExplicitEmptyGrantRemainDistinct() {
		var denied = OAuthAuthorizationDecision.deniedInstance();
		assertTrue(denied.isDenied()); assertEquals(Optional.empty(), denied.getSubject());
		assertEquals(Map.of(), denied.getAuthorizedScopesByResource()); assertFalse(denied.isRefreshTokenPermitted());
		var empty = OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(RESOURCE, Set.of())).build();
		assertFalse(empty.isDenied()); assertEquals(Optional.of("subject"), empty.getSubject());
		assertEquals(Map.of(RESOURCE, Set.of()), empty.getAuthorizedScopesByResource());
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of()));
		assertThrows(IllegalArgumentException.class, () -> OAuthAuthorizationDecision.withSubject("subject")
				.authorizedScopesByResource(Map.of(RESOURCE, Set.of("read"), "urn:second", Set.of("write"))));
	}
	@Test void decisionRequiredResetAndDeepSnapshots() {
		Set<String> scopes = new LinkedHashSet<>(Set.of("read")); Map<String, Set<String>> map = new HashMap<>(); map.put(RESOURCE, scopes);
		var builder = OAuthAuthorizationDecision.withSubject("subject"); assertThrows(IllegalStateException.class, builder::build);
		assertSame(builder, builder.authorizedScopesByResource(map).refreshTokenPermitted(true)); map.clear(); scopes.clear();
		var value = builder.build(); assertTrue(value.isRefreshTokenPermitted());
		assertSame(builder, builder.authorizedScopesByResource(null).refreshTokenPermitted(null)); assertThrows(IllegalStateException.class, builder::build);
		assertFalse(builder.authorizedScopesByResource(Map.of(RESOURCE, Set.of())).build().isRefreshTokenPermitted());
		assertEquals(Map.of(RESOURCE, Set.of("read")), value.getAuthorizedScopesByResource());
		assertThrows(UnsupportedOperationException.class, () -> value.getAuthorizedScopesByResource().getOrDefault(RESOURCE, Set.of()).clear());
	}
	@Test void constructionNeverInvokesCallbacks() {
		AtomicInteger calls = new AtomicInteger();
		OAuthClientSecretVerifier verifier = (id, bytes, budget) -> { calls.incrementAndGet(); throw new AssertionError(); };
		var auth = OAuthServerClientAuthentication.fromClientSecretVerifier(verifier);
		var value = registration().authentication(auth).introspectionResources(Set.of(RESOURCE)).build();
		Sentinels.assertAbsent(value); Sentinels.assertAbsent(auth); assertEquals(0, calls.get());
		assertTrue(auth.isConfidential()); assertSame(verifier, auth.verifier());
		assertFalse(OAuthServerClientAuthentication.publicClientInstance().isConfidential());
		assertNull(OAuthServerClientAuthentication.publicClientInstance().verifier());
	}
	@Test void grantContextHasRestrictedConstructionAndDefensiveCheckedFacts() {
		Set<String> scopes = new LinkedHashSet<>(Set.of("read")); Map<String, Set<String>> map = new HashMap<>(); map.put(RESOURCE, scopes);
		var context = OAuthGrantContext.fromCheckedGrant("subject", "client", "authorization_code", "grant-handle", map, true);
		map.clear(); scopes.clear(); assertEquals("subject", context.getSubject()); assertEquals("client", context.getClientId());
		assertEquals("authorization_code", context.getGrantType()); assertEquals("grant-handle", context.getGrantValue());
		assertTrue(context.isRefreshTokenPermitted()); assertEquals(Map.of(RESOURCE, Set.of("read")), context.getAuthorizedScopesByResource());
		assertThrows(UnsupportedOperationException.class, () -> context.getAuthorizedScopesByResource().getOrDefault(RESOURCE, Set.of()).clear());
		assertTrue(java.util.Arrays.stream(OAuthGrantContext.class.getDeclaredConstructors()).allMatch(c -> Modifier.isPrivate(c.getModifiers())));
		assertTrue(java.util.Arrays.stream(OAuthGrantContext.class.getDeclaredMethods()).noneMatch(m -> Modifier.isPublic(m.getModifiers())
				&& Modifier.isStatic(m.getModifiers())));
		assertEquals(0, OAuthGrantContext.class.getClasses().length);
		assertThrows(IllegalArgumentException.class, () -> OAuthGrantContext.fromCheckedGrant("subject", "client", "client_credentials", "grant", Map.of(RESOURCE, Set.of("read")), false));
		assertEquals("refresh_token", OAuthGrantContext.fromCheckedGrant("subject", "client", "refresh_token", "grant", Map.of(RESOURCE, Set.of("read")), false).getGrantType());
	}
	@Test void appCallbacksReceiveTypedValuesWithoutBeingIdentityProofs() {
		var value = registration().build(); OAuthServerClientRepository repository = (id, budget) -> id.equals(value.getClientId()) ? Optional.of(value) : Optional.empty();
		assertSame(value, repository.findRegisteredClient("client", Duration.ofSeconds(1)).orElseThrow());
		assertTrue(repository.findRegisteredClient("unknown", Duration.ofSeconds(1)).isEmpty());
		OAuthGrantPolicy policy = (context, budget) -> OAuthAuthorizationDecision.withSubject(context.getSubject())
				.authorizedScopesByResource(context.getAuthorizedScopesByResource()).build();
		var context = OAuthGrantContext.fromCheckedGrant("subject", "client", "authorization_code", "grant", Map.of(RESOURCE, Set.of("read")), true);
		assertEquals(context.getSubject(), policy.authorizeGrant(context, Duration.ofSeconds(1)).getSubject().orElseThrow());
	}
	@Test void valuesBuildersCallbacksAndFailureChainsRedactSentinels() {
		String secret = Sentinels.CLIENT_SECRET; String resource = "urn:" + secret;
		OAuthClientSecretVerifier verifier = (id, bytes, budget) -> true;
		var auth = OAuthServerClientAuthentication.fromClientSecretVerifier(verifier);
		var builder = OAuthServerClientRegistration.withClientId(secret).redirectUris(List.of(URI.create("https://client.example/" + secret)))
				.authentication(auth).allowedScopesByResource(Map.of(resource, Set.of(secret))).introspectionResources(Set.of(resource))
				.clientName(secret).configurationVersion(secret);
		var decisionBuilder = OAuthAuthorizationDecision.withSubject(secret).authorizedScopesByResource(Map.of(resource, Set.of(secret)));
		var context = OAuthGrantContext.fromCheckedGrant(secret, secret, "authorization_code", secret, Map.of(resource, Set.of(secret)), true);
		for (Object value : List.of(builder, builder.build(), auth, decisionBuilder, decisionBuilder.build(), context,
				OAuthAuthorizationDecision.deniedInstance(), OAuthServerClientAuthentication.publicClientInstance())) Sentinels.assertAbsent(value);
		assertEquals(secret, context.getGrantValue()); // Privileged management release; never a diagnostic serialization.
		Sentinels.assertAbsent(assertThrows(IllegalArgumentException.class, () -> builder.clientName(secret + "\n")));
		Sentinels.assertAbsent(assertThrows(IllegalArgumentException.class, () -> builder.redirectUris(List.of(URI.create("https://client.example/?state=" + secret)))));
		Sentinels.assertAbsent(assertThrows(IllegalArgumentException.class, () -> decisionBuilder.authorizedScopesByResource(Map.of(resource, Set.of(secret + " ")))));
		assertSame(builder, builder.configurationVersion(null)); Sentinels.assertAbsent(assertThrows(IllegalStateException.class, builder::build));
	}
}
