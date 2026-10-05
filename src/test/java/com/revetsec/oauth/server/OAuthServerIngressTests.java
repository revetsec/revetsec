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

import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.http.Deadline;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static com.revetsec.oauth.server.OAuthServerAdmissionFailure.Reason.*;
import static com.revetsec.oauth.server.OAuthServerRequest.Endpoint.*;

/** Hostile wire and application callback boundary tests; no endpoint/store success is fabricated. */
final class OAuthServerIngressTests {
	private static final @NonNull OAuthServerIngressLimits LIMITS = OAuthServerIngressLimits.fromDefaults();
	private static final @NonNull String RESOURCE = "https://resource.example/mcp";
	private static final @NonNull String REDIRECT = "https://client.example/cb?x=%2f";
	private static final @NonNull String CHALLENGE = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	private static @NonNull String encode(@NonNull String value) {
		try { return FormUrlEncoding.encode(value); } catch (EncodingException failure) { throw new AssertionError(failure); }
	}
	private static @NonNull Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(5)); }
	private static @NonNull OAuthServerClientRegistration client(@NonNull String id, @Nullable OAuthClientSecretVerifier verifier) {
		return OAuthServerClientRegistration.withClientId(id).redirectUris(List.of(URI.create(REDIRECT)))
				.allowedScopesByResource(Map.of(RESOURCE, Set.of("read", "write"))).configurationVersion("v1")
				.authentication(verifier == null ? null : OAuthServerClientAuthentication.fromClientSecretVerifier(verifier)).build();
	}
	private static @NonNull OAuthServerClientRepository repository(@NonNull OAuthServerClientRegistration value) {
		return (id, budget) -> id.equals(value.getClientId()) ? Optional.of(value) : Optional.empty();
	}
	private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers(@Nullable String auth) {
		Map<String, List<String>> result = new HashMap<>(); result.put("Content-Type", List.of("application/x-www-form-urlencoded"));
		if (auth != null) result.put("Authorization", List.of(auth)); return result;
	}
	private static @NonNull OAuthServerRequest post(@NonNull String raw, @Nullable String auth) {
		return OAuthServerRequest.parse(TOKEN, "POST", null, raw.getBytes(StandardCharsets.UTF_8), headers(auth), LIMITS);
	}
	private static @NonNull OAuthServerRequest query(@NonNull String raw) {
		return OAuthServerRequest.parse(AUTHORIZATION, "GET", raw, new byte[0], Map.of(), LIMITS);
	}
	private static @NonNull String authorization() {
		return "client_id=client&response_type=code&redirect_uri=" + encode(REDIRECT)
				+ "&code_challenge_method=S256&code_challenge=" + CHALLENGE + "&resource=" + encode(RESOURCE);
	}
	private static @NonNull OAuthServerAuthorizationAdmission admit(@NonNull String raw) {
		return OAuthServerAuthorizationAdmission.admit(query(raw), repository(client("client", null)), deadline(),
				Map.of(RESOURCE, Set.of("read", "other")), LIMITS, false, false);
	}
	private static @NonNull String basic(@NonNull String components) {
		return "Basic " + Base64.getEncoder().encodeToString(components.getBytes(StandardCharsets.UTF_8));
	}
	private static void fails(OAuthServerAdmissionFailure.@NonNull Reason reason, @NonNull Runnable call) {
		var failure = assertThrows(OAuthServerAdmissionFailure.class, call::run);
		assertEquals(reason, failure.reason()); assertNull(failure.getCause());
		assertEquals("OAuth server admission failed.", failure.getMessage());
	}
	@Test void preservesExactDecodedValuesAndOnlyIgnoresOrdinaryExtensions() {
		var value = query("client_id=a%2Bb+%E2%9C%93&state=%20%2B%26%3D&x=one&x=two&empty=&=ignored&flag");
		assertEquals("a+b ✓", value.required("client_id")); assertEquals(" +&=", value.value("state"));
		assertNull(value.value("x")); assertNull(value.authorization()); assertEquals(AUTHORIZATION, value.endpoint());
		assertEquals("OAuthServerRequest{<redacted>}", value.toString());
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> duplicatesAreRejectedEvenWhenIdenticalOrEscaped() {
		return Stream.of("client_id", "redirect_uri", "state", "scope", "resource", "response_type", "code", "code_verifier",
				"code_challenge", "code_challenge_method", "grant_type", "refresh_token", "token", "token_type_hint", "response_mode")
				.map(name -> DynamicTest.dynamicTest(name, () -> fails(INVALID_REQUEST, () -> query(name + "=a&"
						+ "%" + Integer.toHexString(name.charAt(0)) + name.substring(1) + "=a"))));
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> unsupportedSecurityExtensionsCannotBeIgnored() {
		return Stream.of("client_secret", "client_assertion", "client_assertion_type", "request", "request_uri", "authorization_details", "username", "password")
				.map(name -> DynamicTest.dynamicTest(name, () -> fails(INVALID_REQUEST, () -> post(name + "=", null))));
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> malformedEncodingsAnywhereRejectWholeInput() {
		return Stream.of("%", "%1", "%GG", "%ＦＦ", "%FF", "%80", "%C0%AF", "%E0%80%80", "%ED%A0%80", "%F4%90%80%80", "%E2%82", "\uD800")
				.map(value -> DynamicTest.dynamicTest("encoding: " + value, () -> {
					fails(INVALID_REQUEST, () -> query("x=" + value)); fails(INVALID_REQUEST, () -> query(value + "=x"));
				}));
	}
	@Test void aggregateBoundsPrecedeDecodeAndEveryUnknownFieldCounts() {
		fails(INVALID_REQUEST, () -> query("x=" + "a".repeat(LIMITS.queryLength) + "%"));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(TOKEN, "POST", null, new byte[LIMITS.bodyBytes + 1], headers(null), LIMITS));
		assertNotNull(query("x=" + "a".repeat(LIMITS.queryLength - 2)));
		assertNotNull(query("x=1&".repeat(127) + "x=1")); fails(INVALID_REQUEST, () -> query("x=1&".repeat(128) + "x=1"));
		assertNotNull(OAuthServerRequest.parse(TOKEN, "POST", "x=1&".repeat(64), "x=1&".repeat(64).getBytes(StandardCharsets.UTF_8), headers(null), LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(TOKEN, "POST", "x=1&".repeat(65), "x=1&".repeat(64).getBytes(StandardCharsets.UTF_8), headers(null), LIMITS));
	}
	@Test void stateAndClientCapsApplyToRawSpellingBeforeDecode() {
		assertEquals("a".repeat(1024), query("state=" + "a".repeat(1024)).value("state"));
		fails(INVALID_REQUEST, () -> query("state=" + "a".repeat(1025)));
		fails(INVALID_REQUEST, () -> query("state=" + "%61".repeat(342)));
		assertEquals(2048, query("client_id=" + "a".repeat(2048)).required("client_id").length());
		fails(INVALID_REQUEST, () -> query("client_id=" + "a".repeat(2049)));
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> methodAndChannelAdmission() {
		return Stream.of("get", "POST", "PUT", "HEAD", "OPTIONS", "GET ", "GET\r\n")
				.map(method -> DynamicTest.dynamicTest("method: " + method, () -> fails(INVALID_REQUEST, () ->
						OAuthServerRequest.parse(AUTHORIZATION, method, null, new byte[0], Map.of(), LIMITS))));
	}
	@Test void bodyQueryAndEncodingChannelsAreStrict() {
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[]{1}, Map.of(), LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], headers(basic("client:secret")), LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(TOKEN, "GET", null, new byte[0], headers(null), LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(TOKEN, "POST", "client_id=client", new byte[0], headers(null), LIMITS));
		var encoded = headers(null); encoded.put("Content-Encoding", List.of("identity"));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(TOKEN, "POST", null, new byte[0], encoded, LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(TOKEN, "POST", null, new byte[]{(byte) 255}, headers(null), LIMITS));
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> unsupportedOrAmbiguousMime() {
		return Stream.of("application/json", "text/plain", "application/x-www-form-urlencoded; charset=latin1",
				"application/x-www-form-urlencoded; charset=utf-8; CHARSET=utf-8", "application/x-www-form-urlencoded, application/x-www-form-urlencoded", "application/x-www-form-urlencoded; charset =utf-8")
				.map(mime -> DynamicTest.dynamicTest(mime, () -> fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(TOKEN,
						"POST", null, new byte[0], Map.of("Content-Type", List.of(mime)), LIMITS))));
	}
	@Test void mimeQuotedUtf8CaseAndOwsAreAcceptedMissingMimeRejects() {
		assertNotNull(OAuthServerRequest.parse(TOKEN, "POST", null, new byte[0], Map.of("cOnTeNt-TyPe", List.of(" Application/X-Www-Form-Urlencoded; charset=\"UTF-8\" ")), LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(TOKEN, "POST", null, new byte[0], Map.of(), LIMITS));
	}
	@Test void headerOccurrencesIncludingIdenticalCaseVariantsAndFramingBytesAreBounded() {
		for (String name : List.of("Authorization", "Content-Type", "Content-Encoding")) {
			fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(TOKEN, "POST", null, new byte[0], Map.of(name, List.of("x", "x")), LIMITS));
			fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(TOKEN, "POST", null, new byte[0], Map.of(name, List.of("x"), name.toLowerCase(java.util.Locale.ROOT), List.of("x")), LIMITS));
		}
		List<String> sixtyFour = new ArrayList<>(); for (int i = 0; i < 64; i++) sixtyFour.add("x");
		assertNotNull(OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], Map.of("X", sixtyFour), LIMITS));
		sixtyFour.add("x"); fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], Map.of("X", sixtyFour), LIMITS));
		assertNotNull(OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], Map.of("X", List.of("a".repeat(16377))), LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], Map.of("X", List.of("a".repeat(16378))), LIMITS));
		for (String bad : List.of("x\r\nInjected: 1", "x\0", "x\u007f", "x✓"))
			fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], Map.of("X", List.of(bad)), LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], Map.of("Bad Name", List.of("x")), LIMITS));
	}
	@Test void basicPercentDecodingUsesExactIdAndZeroesSecretAfterSuccess() {
		String id = "id:+ ✓"; byte[] expected = "s:+ ✓".getBytes(StandardCharsets.UTF_8);
		AtomicReference<byte[]> retained = new AtomicReference<>(); AtomicInteger called = new AtomicInteger();
		var value = client(id, (actual, secret, budget) -> {
			assertEquals(id, actual); assertArrayEquals(expected, secret); assertTrue(!budget.isNegative() && !budget.isZero());
			retained.set(secret); called.incrementAndGet(); return true;
		});
		assertSame(value, OAuthServerClientAdmission.authenticate(post("grant_type=authorization_code", basic("id%3A%2B+%E2%9C%93:s%3A%2B+%E2%9C%93")), repository(value), deadline(), LIMITS));
		assertEquals(1, called.get()); assertArrayEquals(new byte[expected.length], retained.get());
	}
	@Test void basicFalseAndCallbackFaultsRemainDistinctAndAlwaysClearSecret() {
		for (int mode = 0; mode < 5; mode++) {
			int selected = mode; AtomicReference<byte[]> retained = new AtomicReference<>();
			@SuppressWarnings("NullAway") // Deliberate broken trusted SPI is the input under test.
			OAuthClientSecretVerifier verifier = (id, secret, budget) -> {
				retained.set(secret); if (selected == 0) return false; if (selected == 1) return null;
				if (selected == 2) throw new IllegalArgumentException("SENTINEL-SECRET"); if (selected == 3) throw new AssertionError("provider failure"); throw new InternalError("fatal VM failure");
			};
			var value = client("client", verifier); Runnable call = () -> OAuthServerClientAdmission.authenticate(post("", basic("client:secret")), repository(value), deadline(), LIMITS);
			if (mode == 4) assertThrows(InternalError.class, call::run); else fails(mode == 0 ? INVALID_CLIENT : INFRASTRUCTURE, call);
			assertArrayEquals(new byte[6], retained.get());
		}
	}
	@Test void callbackTimeoutCannotPublishSuccessAndDoesNotInvokeWithExpiredBudget() {
		var expired = Deadline.fromNow(Duration.ZERO); AtomicInteger called = new AtomicInteger();
		fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", (id, budget) -> { called.incrementAndGet(); return Optional.empty(); }, expired, LIMITS));
		assertEquals(0, called.get());
		var shortDeadline = Deadline.fromNow(Duration.ofSeconds(1)); AtomicReference<byte[]> retained = new AtomicReference<>();
		var value = client("client", (id, secret, budget) -> { retained.set(secret); while (!shortDeadline.isExpired()) Thread.onSpinWait(); return true; });
		fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.authenticate(post("", basic("client:secret")), repository(value), shortDeadline, LIMITS));
		assertArrayEquals(new byte[6], retained.get());
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> invalidBasicNeverReachesVerifier() {
		return Stream.of("Bearer abc", "Basic ", "Basic YTpi,", "Basic YTpi ", "Basic YTpi=", "Basic YTphYh==",
				basic("no-colon"), basic("client:%"), basic("client:%FF"), basic("client:%ED%A0%80"), basic("client:✓"), basic(":secret"))
				.map(header -> DynamicTest.dynamicTest("Basic: " + header, () -> {
					AtomicInteger called = new AtomicInteger(); var value = client("client", (id, secret, budget) -> { called.incrementAndGet(); return true; });
					fails(INVALID_CLIENT, () -> OAuthServerClientAdmission.authenticate(post("", header), repository(value), deadline(), LIMITS)); assertEquals(0, called.get());
				}));
	}
	@Test void publicAndConfidentialProfilesNeverDowngradeOrCombineChannels() {
		var confidential = client("client", (id, secret, budget) -> true); var publicClient = client("client", null);
		assertSame(publicClient, OAuthServerClientAdmission.authenticate(post("client_id=client", null), repository(publicClient), deadline(), LIMITS));
		fails(INVALID_CLIENT, () -> OAuthServerClientAdmission.authenticate(post("client_id=client", null), repository(confidential), deadline(), LIMITS));
		fails(INVALID_CLIENT, () -> OAuthServerClientAdmission.authenticate(post("", basic("client:secret")), repository(publicClient), deadline(), LIMITS));
		fails(INVALID_CLIENT, () -> OAuthServerClientAdmission.authenticate(post("client_id=client", basic("client:secret")), repository(confidential), deadline(), LIMITS));
		fails(INVALID_CLIENT, () -> OAuthServerClientAdmission.authenticate(post("", null), repository(publicClient), deadline(), LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerClientAdmission.authenticate(query(""), repository(publicClient), deadline(), LIMITS));
		var introspection = OAuthServerRequest.parse(INTROSPECTION, "POST", null, "client_id=client".getBytes(StandardCharsets.UTF_8), headers(null), LIMITS);
		fails(INVALID_CLIENT, () -> OAuthServerClientAdmission.authenticate(introspection, repository(publicClient), deadline(), LIMITS));
	}
	@Test void repositoryAbsenceBrokenSpiWrongIdentityAndTimeoutHaveFixedClassifications() {
		fails(INVALID_CLIENT, () -> OAuthServerClientAdmission.registered("absent", (id, budget) -> Optional.empty(), deadline(), LIMITS));
		fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", (id, budget) -> { throw new IllegalStateException("SENTINEL"); }, deadline(), LIMITS));
		@SuppressWarnings("NullAway") // Deliberate broken trusted SPI.
		OAuthServerClientRepository broken = (id, budget) -> null;
		fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", broken, deadline(), LIMITS));
		fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", (id, budget) -> Optional.of(client("different", null)), deadline(), LIMITS));
		fails(INVALID_CLIENT, () -> OAuthServerClientAdmission.registered("bad\n", repository(client("client", null)), deadline(), LIMITS));
		var shortDeadline = Deadline.fromNow(Duration.ofSeconds(1));
		fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", (id, budget) -> { while (!shortDeadline.isExpired()) Thread.onSpinWait(); return Optional.of(client("client", null)); }, shortDeadline, LIMITS));
	}
	@Test void authorizationSelectsExactResourceIntersectionPkceAndRetainsState() {
		var value = admit(authorization() + "&state=%20exact%2B");
		assertEquals("client", value.client().getClientId()); assertEquals(REDIRECT, value.redirect()); assertEquals(RESOURCE, value.resource());
		assertEquals(Set.of("read"), value.scopes()); assertEquals(" exact+", value.state()); assertEquals(CHALLENGE, value.challenge());
		assertEquals("OAuthServerAuthorizationAdmission{<redacted>}", value.toString());
		assertEquals(Set.of("read"), admit(authorization() + "&scope=read&response_mode=query").scopes());
		assertNull(admit(authorization()).state()); assertThrows(UnsupportedOperationException.class, () -> value.scopes().clear());
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> exactRedirectSpellingIsNotNormalized() {
		return Stream.of("https://CLIENT.example/cb?x=%2f", "https://client.example:443/cb?x=%2f", "https://client.example/cb?x=%2F",
				"https://client.example/a/../cb?x=%2f", "https://client.example/cb?x=%2f&code=injected", "https://attacker.example/cb", "https://client.example/cb?x=%2f#fragment")
				.map(redirect -> DynamicTest.dynamicTest(redirect, () -> assertFalse(OAuthServerAuthorizationAdmission.matchesRedirect(client("client", null), redirect, true, true))));
	}
	@Test void loopbackPortsVaryOnlyForExplicitlyEnabledExactIpNativePolicy() {
		for (String host : List.of("127.0.0.1", "[::1]", "localhost")) {
			String registered = "http://" + host + ":1234/cb?x=%2f";
			var value = OAuthServerClientRegistration.withClientId("native").redirectUris(List.of(URI.create(registered)))
					.allowedScopesByResource(Map.of(RESOURCE, Set.of("read"))).configurationVersion("v1").build();
			assertFalse(OAuthServerAuthorizationAdmission.matchesRedirect(value, registered, false, false));
			assertTrue(OAuthServerAuthorizationAdmission.matchesRedirect(value, registered, !host.equals("localhost"), host.equals("localhost")));
			assertEquals(!host.equals("localhost"), OAuthServerAuthorizationAdmission.matchesRedirect(value, registered.replace(":1234", ":4321"), true, true));
			for (String wrong : List.of(registered.replace("%2f", "%2F"), registered.replace("/cb", "/a/../cb"), registered.replace(":1234", ":0"), registered + "#x"))
				assertFalse(OAuthServerAuthorizationAdmission.matchesRedirect(value, wrong, true, true));
		}
		var ip = OAuthServerClientRegistration.withClientId("native").redirectUris(List.of(URI.create("http://127.0.0.1/cb")))
				.allowedScopesByResource(Map.of(RESOURCE, Set.of("read"))).configurationVersion("v1").build();
		assertTrue(OAuthServerAuthorizationAdmission.matchesRedirect(ip, "http://127.0.0.1:4321/cb", true, false));
		for (String host : List.of("127.1", "127.0.0.2", "2130706433", "localhost", "localhost.example", "192.168.1.1"))
			assertFalse(OAuthServerAuthorizationAdmission.matchesRedirect(ip, "http://" + host + ":4321/cb", true, true));
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> invalidScopesNeverBecomeEmptyIssuableAuthority() {
		return Stream.of("", "write", "other", "read write", " read", "read ", "read  read", "read\t", "✓", "r\"", "r\\")
				.map(scope -> DynamicTest.dynamicTest("scope: " + scope, () -> fails(INVALID_SCOPE, () -> admit(authorization() + "&scope=" + encode(scope)))));
	}
	@Test void unknownClientResourceEmptyIntersectionAndUnsupportedResponsesReject() {
		fails(INVALID_CLIENT, () -> admit(authorization().replace("client_id=client", "client_id=absent")));
		fails(INVALID_TARGET, () -> admit(authorization().replace(encode(RESOURCE), encode("https://RESOURCE.example/mcp"))));
		fails(INVALID_SCOPE, () -> OAuthServerAuthorizationAdmission.admit(query(authorization()), repository(client("client", null)), deadline(), Map.of(RESOURCE, Set.of("other")), LIMITS, false, false));
		fails(UNSUPPORTED_RESPONSE_TYPE, () -> admit(authorization().replace("response_type=code", "response_type=token")));
		fails(INVALID_REQUEST, () -> admit(authorization() + "&response_mode=form_post"));
		fails(INVALID_REQUEST, () -> admit(authorization().replace("code_challenge_method=S256", "code_challenge_method=plain")));
		var disabled = OAuthServerClientRegistration.withClientId("client").configurationVersion("v1").authorizationCodePermitted(false).build();
		fails(UNAUTHORIZED_CLIENT, () -> OAuthServerAuthorizationAdmission.admit(query(authorization()), repository(disabled), deadline(), Map.of(RESOURCE, Set.of("read")), LIMITS, false, false));
	}
	@Test void canonicalChallengeAndVerifierGrammarAndSupportedGrants() {
		assertTrue(OAuthServerAuthorizationAdmission.challenge(CHALLENGE));
		for (String bad : List.of("", CHALLENGE + "=", CHALLENGE.substring(1), CHALLENGE.substring(0, 42) + "B", CHALLENGE.substring(0, 42) + "+"))
			assertFalse(OAuthServerAuthorizationAdmission.challenge(bad));
		OAuthServerAuthorizationAdmission.requireTokenGrant(post("grant_type=authorization_code&code=x&code_verifier=" + "a".repeat(43) + "&resource=r", null));
		OAuthServerAuthorizationAdmission.requireTokenGrant(post("grant_type=authorization_code&code=x&code_verifier=" + "-._~".repeat(32) + "&resource=r", null));
		OAuthServerAuthorizationAdmission.requireTokenGrant(post("grant_type=refresh_token&refresh_token=x&resource=r", null));
		for (String bad : List.of("a".repeat(42), "a".repeat(129), "a".repeat(42) + "+", "a".repeat(42) + "✓"))
			fails(INVALID_REQUEST, () -> OAuthServerAuthorizationAdmission.requireTokenGrant(post("grant_type=authorization_code&code=x&code_verifier=" + encode(bad) + "&resource=r", null)));
		fails(UNSUPPORTED_GRANT_TYPE, () -> OAuthServerAuthorizationAdmission.requireTokenGrant(post("grant_type=client_credentials", null)));
		fails(INVALID_REQUEST, () -> OAuthServerAuthorizationAdmission.requireTokenGrant(post("grant_type=refresh_token&refresh_token=x", null)));
		fails(INVALID_REQUEST, () -> OAuthServerAuthorizationAdmission.requireTokenGrant(query("")));
	}
	private static @NonNull OAuthServerIngressLimits limits(int @NonNull [] values) {
		return new OAuthServerIngressLimits(values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8]);
	}
	@Test void allInternalLimitsUseTheApprovedInclusiveRanges() {
		int[] minimum = {1024, 1024, 1024, 128, 256, 1, 1, 1, 1};
		int[] maximum = {65536, 65536, 65536, 4096, 4096, 1024, 64, 128, 128};
		assertNotNull(limits(minimum)); assertNotNull(limits(maximum));
		for (int i = 0; i < minimum.length; i++) {
			int[] below = minimum.clone(); below[i]--; assertThrows(IllegalArgumentException.class, () -> limits(below));
			int[] above = maximum.clone(); above[i]++; assertThrows(IllegalArgumentException.class, () -> limits(above));
		}
		assertEquals(16384, LIMITS.bodyBytes); assertEquals(16384, LIMITS.queryLength); assertEquals(16384, LIMITS.headerBytes);
		assertEquals(1024, LIMITS.stateLength); assertEquals(2048, LIMITS.clientIdLength); assertEquals(64, LIMITS.resources);
		assertEquals(32, LIMITS.redirects); assertEquals(32, LIMITS.scopes); assertEquals(128, LIMITS.scopeLength);
	}
	@Test void configuredNarrowLimitsRejectTrustedOversizedRegistrationsAndResourceSets() {
		var narrow = new OAuthServerIngressLimits(1024, 1024, 1024, 128, 256, 1, 1, 1, 3);
		fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", repository(client("client", null)), deadline(), narrow));
		var value = OAuthServerClientRegistration.withClientId("client").redirectUris(List.of(URI.create(REDIRECT)))
				.allowedScopesByResource(Map.of(RESOURCE, Set.of("r"))).configurationVersion("v1").build();
		assertSame(value, OAuthServerClientAdmission.registered("client", repository(value), deadline(), narrow));
		for (Map<String, Set<String>> bad : List.of(Map.of(RESOURCE, Set.of("r", "s")), Map.of(RESOURCE, Set.of("long")),
				Map.of(RESOURCE, Set.of("r"), "urn:second", Set.of("r"))))
			assertThrows(IllegalArgumentException.class, () -> OAuthServerAuthorizationAdmission.admit(query(authorization()), repository(value), deadline(), bad, narrow, false, false));
		fails(INVALID_SCOPE, () -> OAuthServerAuthorizationAdmission.selectScopes(RESOURCE, "rrrr", value, Map.of(RESOURCE, Set.of("r")), narrow));
		fails(INVALID_SCOPE, () -> OAuthServerAuthorizationAdmission.selectScopes(RESOURCE, "r r", value, Map.of(RESOURCE, Set.of("r")), narrow));
		var longScope = OAuthServerClientRegistration.withClientId("client").redirectUris(List.of(URI.create(REDIRECT)))
				.allowedScopesByResource(Map.of(RESOURCE, Set.of("long"))).configurationVersion("v1").build();
		fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", repository(longScope), deadline(), narrow));
	}
	@Test void parsedRequestIsIndependentOfMutableEdgeContainers() {
		byte[] body = "client_id=client".getBytes(StandardCharsets.UTF_8); var rawHeaders = headers(basic("client:secret"));
		var parsed = OAuthServerRequest.parse(TOKEN, "POST", "ignored=ordinary", body, rawHeaders, LIMITS);
		java.util.Arrays.fill(body, (byte) 0); rawHeaders.clear();
		assertEquals("client", parsed.required("client_id")); assertEquals(basic("client:secret"), parsed.authorization());
		fails(INVALID_REQUEST, () -> parsed.required("missing"));
		fails(INVALID_REQUEST, () -> query("client_id=").required("client_id"));
	}
	@Test void emptyPiecesCaseSensitiveNamesAndSingleDecodeArePreserved() {
		var value = query("&&client_id=a%252Bb&Client_Id=extension&state&");
		assertEquals("a%2Bb", value.required("client_id")); assertEquals("", value.value("state"));
		assertNull(value.value("Client_Id")); assertEquals("a;b", query("client_id=a;b").required("client_id"));
		assertEquals("�", query("state=%EF%BF%BD").value("state"));
	}
	@Test void allPostEndpointShapesRetainTokenAndHintWithoutAuthenticatingTheToken() {
		for (var endpoint : List.of(REVOCATION, INTROSPECTION)) {
			var value = OAuthServerRequest.parse(endpoint, "POST", null, "token=untrusted&token_type_hint=extension".getBytes(StandardCharsets.UTF_8), headers(null), LIMITS);
			assertEquals(endpoint, value.endpoint()); assertEquals("untrusted", value.required("token")); assertEquals("extension", value.value("token_type_hint"));
		}
	}

	@Test void registrationRedirectResourceAndIntrospectionCapsAreAppliedAtLookup() {
		var narrow = new OAuthServerIngressLimits(1024, 1024, 1024, 128, 256, 1, 1, 32, 128);
		var twoRedirects = OAuthServerClientRegistration.withClientId("client").redirectUris(List.of(URI.create(REDIRECT), URI.create("https://client.example/second")))
				.allowedScopesByResource(Map.of(RESOURCE, Set.of("read"))).configurationVersion("v1").build();
		var twoResources = OAuthServerClientRegistration.withClientId("client").redirectUris(List.of(URI.create(REDIRECT)))
				.allowedScopesByResource(Map.of(RESOURCE, Set.of("read"), "urn:second", Set.of("read"))).configurationVersion("v1").build();
		var twoIntrospection = OAuthServerClientRegistration.withClientId("client").authorizationCodePermitted(false)
				.authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((id, secret, budget) -> true))
				.introspectionResources(Set.of(RESOURCE, "urn:second")).configurationVersion("v1").build();
		for (var value : List.of(twoRedirects, twoResources, twoIntrospection))
			fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", repository(value), deadline(), narrow));
	}
	@Test void basicClientIdRawCapAndLowercaseEscapesAreChecked() {
		var narrow = new OAuthServerIngressLimits(1024, 1024, 1024, 128, 256, 64, 32, 32, 128);
		fails(INVALID_CLIENT, () -> OAuthServerClientAdmission.authenticate(post("", basic("a".repeat(257) + ":secret")), repository(client("client", null)), deadline(), narrow));
		AtomicReference<byte[]> retained = new AtomicReference<>(); var value = client("client", (id, secret, budget) -> {
			assertArrayEquals(new byte[]{':', '+'}, secret); retained.set(secret); return true;
		});
		assertSame(value, OAuthServerClientAdmission.authenticate(post("", basic("client:%3a%2b")), repository(value), deadline(), LIMITS));
		assertArrayEquals(new byte[2], retained.get());
	}
	@Test void headerMapAndNameCapsRejectBeforeNormalization() {
		Map<String, List<String>> raw = new HashMap<>(); for (int i = 0; i < 65; i++) raw.put("X" + i, List.of("x"));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], raw, LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], Map.of("", List.of("x")), LIMITS));
		fails(INVALID_REQUEST, () -> OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], Map.of("X".repeat(16385), List.of("x")), LIMITS));
		assertNotNull(OAuthServerRequest.parse(AUTHORIZATION, "GET", null, new byte[0], Map.of("X", List.of("\tÿ")), LIMITS));
	}
	@Test void wrongEndpointMissingGrantFieldsAndInvalidAuthorizationChallengeReject() {
		fails(INVALID_REQUEST, () -> OAuthServerAuthorizationAdmission.admit(post("", null), repository(client("client", null)), deadline(), Map.of(RESOURCE, Set.of("read")), LIMITS, false, false));
		fails(INVALID_REQUEST, () -> admit(authorization().replace(CHALLENGE, "bad")));
		fails(INVALID_REQUEST, () -> OAuthServerAuthorizationAdmission.requireTokenGrant(post("grant_type=authorization_code&code=x&resource=r", null)));
		fails(INVALID_REQUEST, () -> OAuthServerAuthorizationAdmission.requireTokenGrant(post("grant_type=refresh_token&resource=r", null)));
		var nativeClient = OAuthServerClientRegistration.withClientId("native").redirectUris(List.of(URI.create("http://[::1]/cb")))
				.allowedScopesByResource(Map.of(RESOURCE, Set.of("read"))).configurationVersion("v1").build();
		assertTrue(OAuthServerAuthorizationAdmission.matchesRedirect(nativeClient, "http://[::1]:4321/cb", true, false));
		assertFalse(OAuthServerAuthorizationAdmission.matchesRedirect(nativeClient, "https://[::1]:4321/cb", true, false));
	}

	@SuppressWarnings("unchecked") // Exercise checked callback interruption without changing the SPI signature.
	private static <E extends @NonNull Throwable> void unchecked(@NonNull Throwable exception) throws E { throw (E) exception; }
	@Test void repositoryNonfatalErrorsAreContainedAndVmErrorsKeepRuntimeSemantics() {
		fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", (id, budget) -> { throw new AssertionError("SECRET-SENTINEL"); }, deadline(), LIMITS));
		assertThrows(InternalError.class, () -> OAuthServerClientAdmission.registered("client", (id, budget) -> { throw new InternalError("fatal"); }, deadline(), LIMITS));
	}
	@Test void callbackAndCallerInterruptionFailClosedAndPreserveTheInterruptFlag() {
		try {
			Thread.currentThread().interrupt();
			fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", repository(client("client", null)), deadline(), LIMITS));
			assertTrue(Thread.currentThread().isInterrupted());
		} finally { assertTrue(Thread.interrupted()); }
		try {
			fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.registered("client", (id, budget) -> { unchecked(new InterruptedException("SECRET-SENTINEL")); return Optional.empty(); }, deadline(), LIMITS));
			assertTrue(Thread.currentThread().isInterrupted());
		} finally { assertTrue(Thread.interrupted()); }
		AtomicReference<byte[]> retained = new AtomicReference<>();
		var value = client("client", (id, secret, budget) -> { retained.set(secret); unchecked(new InterruptedException("SECRET-SENTINEL")); return true; });
		try {
			fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.authenticate(post("", basic("client:secret")), repository(value), deadline(), LIMITS));
			assertTrue(Thread.currentThread().isInterrupted()); assertArrayEquals(new byte[6], retained.get());
		} finally { assertTrue(Thread.interrupted()); }
		var interruptedReturn = client("client", (id, secret, budget) -> { Thread.currentThread().interrupt(); return true; });
		try {
			fails(INFRASTRUCTURE, () -> OAuthServerClientAdmission.authenticate(post("", basic("client:secret")), repository(interruptedReturn), deadline(), LIMITS));
			assertTrue(Thread.currentThread().isInterrupted());
		} finally { assertTrue(Thread.interrupted()); }
	}

}
