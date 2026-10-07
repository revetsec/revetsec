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

import com.revetsec.M6FuzzOracle;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.oauth.BearerToken;
import java.math.BigInteger;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Public-engine model with independent JCA verification and exact fixed-profile assertions. */
final class IssuerSigningFuzzModel {
	private static final @NonNull String ISSUER = "https://issuer.example/tenant";
	private static final @NonNull String REDIRECT = "https://client.example/cb?original=%2f";
	private static final @NonNull String BROWSER = "A".repeat(43);
	private static final @NonNull String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	private static final @NonNull String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private static final @NonNull Instant NOW = Instant.parse("2026-10-07T12:00:00Z");
	private static final @NonNull List<@NonNull String> CLIENTS = List.of("client-a", "client-\"b\\snowman-☃");
	private static final @NonNull List<@NonNull String> RESOURCES = List.of("https://resource.example/mcp?tenant=a%22b", "urn:revetsec:resource:%CE%B2");
	private static final @NonNull List<@NonNull Set<@NonNull String>> SCOPE_CHOICES = List.of(
		Set.of("read"), Set.of("write"), Set.of("read", "write"), Set.of("audit:all", "read", "write"));
	private static final @NonNull List<@NonNull String> SUBJECTS = List.of("subject", "subject\"quoted", "subject\\slash",
		"subject-ø", "subject-😀", "subject- separator", "subject <tag> &", " subject with spaces ");
	private static final @NonNull List<@NonNull Duration> LIFETIMES = List.of(Duration.ofSeconds(30), Duration.ofSeconds(60),
		Duration.ofMinutes(5), Duration.ofMinutes(15));
	private static final char @NonNull [] SUBJECT_ALPHABET = "abCD09 -_\"\\<>&/ø☃".toCharArray();

	private IssuerSigningFuzzModel() { }

	static void run(byte @NonNull [] input) throws Exception {
		Fixture fixture = new Fixture(input);
		Issued initial = fixture.issue();
		fixture.assertToken(initial.access(), null);
		if (fixture.refreshFlow) {
			Issued rotated = fixture.rotate(initial.refresh());
			fixture.assertToken(rotated.access(), initial.access());
			fixture.assertToken(initial.access(), rotated.access());
		}
		fixture.assertPublishedKeys();
	}

	private record Issued(@NonNull String access, @NonNull String refresh) { }

	private static @NonNull String form(@NonNull Map<@NonNull String, @NonNull String> values) {
		return String.join("&", values.entrySet().stream().map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8)
			+ "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8)).toList());
	}

	private static @NonNull JsonObject parseObject(byte @NonNull [] bytes) throws Exception {
		return (JsonObject) JsonCodec.parse(bytes, JsonLimits.protocolDocument(131072));
	}

	private static @NonNull String strictUtf8(byte @NonNull [] bytes) throws CharacterCodingException {
		return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
			.decode(ByteBuffer.wrap(bytes)).toString();
	}

	private static @NonNull String unsigned(@NonNull BigInteger value) {
		byte[] bytes = value.toByteArray();
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes[0] == 0 && bytes.length > 1
			? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);
	}

	private static boolean verifies(@NonNull String compact, @NonNull PublicKey key) throws Exception {
		String[] parts = compact.split("\\.", -1); assertEquals(3, parts.length);
		Signature signature = Signature.getInstance("SHA256withRSA"); signature.initVerify(key);
		signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
		return signature.verify(Base64.getUrlDecoder().decode(parts[2]));
	}

	private static final class Fixture {
		private final @NonNull Store store = new Store();
		private final @NonNull ModelClock clock = new ModelClock();
		private final @NonNull String clientId, resource, subject, activeKeyId, retainedKeyId;
		private final @NonNull Set<@NonNull String> scopes;
		private final @NonNull Duration lifetime;
		private final @NonNull PublicKey activePublicKey, retainedPublicKey;
		private final boolean refreshFlow;
		private final @NonNull OAuthAuthorizationServer server;

		private Fixture(byte @NonNull [] input) throws Exception {
			int active = M6FuzzOracle.choice(input, 0, 2);
			this.clientId = CLIENTS.get(M6FuzzOracle.choice(input, 1, CLIENTS.size()));
			this.resource = RESOURCES.get(M6FuzzOracle.choice(input, 2, RESOURCES.size()));
			this.scopes = SCOPE_CHOICES.get(M6FuzzOracle.choice(input, 3, SCOPE_CHOICES.size()));
			this.subject = subject(input, M6FuzzOracle.choice(input, 4, SUBJECTS.size()));
			this.refreshFlow = M6FuzzOracle.choice(input, 5, 2) == 1;
			this.lifetime = LIFETIMES.get(M6FuzzOracle.choice(input, 6, LIFETIMES.size()));
			KeyPair activePair = active == 0 ? M6FuzzOracle.KEY : M6FuzzOracle.OTHER;
			KeyPair retainedPair = active == 0 ? M6FuzzOracle.OTHER : M6FuzzOracle.KEY;
			this.activeKeyId = active == 0 ? "active-key-a" : "active-key-b";
			this.retainedKeyId = active == 0 ? "retained-key-b" : "retained-key-a";
			this.activePublicKey = activePair.getPublic(); this.retainedPublicKey = retainedPair.getPublic();
			OAuthIssuerSigningKey signing = OAuthIssuerSigningKey.fromKeyPair(this.activeKeyId, activePair.getPrivate(), activePair.getPublic());
			OAuthIssuerKeySnapshot snapshot = OAuthIssuerKeySnapshot.withActiveKey(signing)
				.verificationKeys(Map.of(this.retainedKeyId, this.retainedPublicKey)).generation("signing-generation")
				.publishedAt(NOW.minusSeconds(120)).build();
			byte[] material = new byte[32]; for (int index = 0; index < material.length; index++) material[index] = (byte) (index + 1);
			StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("test", Base64.getEncoder().encodeToString(material))).build();
			this.server = OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER + "/authorize"))
				.tokenEndpoint(URI.create(ISSUER + "/token")).jsonWebKeySetEndpoint(URI.create(ISSUER + "/jwks"))
				.revocationEndpoint(URI.create(ISSUER + "/revoke")).introspectionEndpoint(URI.create(ISSUER + "/introspect"))
				.clientRepository((id, budget) -> id.equals(this.clientId) ? Optional.of(client()) : Optional.empty())
				.store(this.store).stateSealer(sealer).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(snapshot))
				.resources(Map.of(this.resource, Set.of("audit:all", "read", "write"))).clock(this.clock)
				.accessTokenLifetime(this.lifetime).clockSkew(Duration.ofSeconds(5)).refreshTokenIdleLifetime(Duration.ofMinutes(15))
				.refreshTokenAbsoluteLifetime(Duration.ofHours(1)).refreshTokensEnabled(true)
				.grantPolicy((context, budget) -> decision(context.getAuthorizedScopesByResource().get(this.resource))).build();
			assertEquals(OAuthStoreCommitStatus.COMMITTED, this.server.initializeFreshIssuer());
			this.server.establishNewSubject(this.subject);
		}

		private static @NonNull String subject(byte @NonNull [] input, int mode) {
			StringBuilder value = new StringBuilder(SUBJECTS.get(mode));
			for (int index = 7; index < Math.min(input.length, 39); index++)
				value.append(SUBJECT_ALPHABET[Byte.toUnsignedInt(input[index]) % SUBJECT_ALPHABET.length]);
			return value.toString();
		}

		private @NonNull OAuthServerClientRegistration client() {
			return OAuthServerClientRegistration.withClientId(this.clientId).configurationVersion("v1")
				.redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(Map.of(this.resource, Set.of("audit:all", "read", "write")))
				.refreshTokenPermitted(true).build();
		}

		private @NonNull OAuthAuthorizationDecision decision(@NonNull Set<@NonNull String> selected) {
			return OAuthAuthorizationDecision.withSubject(this.subject).authorizedScopesByResource(Map.of(this.resource, selected))
				.refreshTokenPermitted(true).build();
		}

		private @NonNull Issued issue() throws Exception {
			String query = form(Map.of("client_id", this.clientId, "response_type", "code", "redirect_uri", REDIRECT,
				"resource", this.resource, "scope", String.join(" ", this.scopes), "code_challenge", CHALLENGE,
				"code_challenge_method", "S256", "state", "state"));
			OAuthServerInteraction interaction = assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,
				this.server.beginAuthorizationResult("GET", query, new byte[0], Map.of(), BROWSER)).getInteraction();
			OAuthServerResponse authorization = assertInstanceOf(OAuthAuthorizationResult.Completed.class,
				this.server.completeAuthorizationResult(interaction.getInteractionValue(), BROWSER, decision(this.scopes))).getResponse();
			String location = authorization.getLocationWithCredentials().orElseThrow().toString();
			String code = location.substring(location.indexOf("code=") + 5, location.indexOf("&state="));
			Map<String, String> fields = Map.of("grant_type", "authorization_code", "client_id", this.clientId,
				"resource", this.resource, "code", code, "code_verifier", VERIFIER, "redirect_uri", REDIRECT);
			OAuthTokenResult result = this.server.tokenResult("POST", null, form(fields).getBytes(StandardCharsets.UTF_8), headers());
			return issued(assertInstanceOf(OAuthTokenResult.Succeeded.class, result).getResponse());
		}

		private @NonNull Issued rotate(@NonNull String refresh) throws Exception {
			Map<String, String> fields = Map.of("grant_type", "refresh_token", "client_id", this.clientId,
				"resource", this.resource, "refresh_token", refresh);
			OAuthTokenResult result = this.server.tokenResult("POST", null, form(fields).getBytes(StandardCharsets.UTF_8), headers());
			return issued(assertInstanceOf(OAuthTokenResult.Succeeded.class, result).getResponse());
		}

		private @NonNull Issued issued(@NonNull OAuthServerResponse response) throws Exception {
			assertEquals(200, response.getStatusCode()); JsonObject body = parseObject(response.toHttpBodyWithCredentials());
			assertEquals(Set.of("access_token", "token_type", "expires_in", "scope", "refresh_token"), body.getMembers().keySet());
			assertEquals("Bearer", body.findString("token_type").orElseThrow());
			assertEquals(this.lifetime.getSeconds(), body.findLong("expires_in").orElseThrow());
			assertEquals(String.join(" ", this.scopes.stream().sorted().toList()), body.findString("scope").orElseThrow());
			return new Issued(body.findString("access_token").orElseThrow(), body.findString("refresh_token").orElseThrow());
		}

		private void assertToken(@NonNull String compact, @org.jspecify.annotations.Nullable String different) throws Exception {
			String[] parts = compact.split("\\.", -1); assertEquals(3, parts.length); assertTrue(compact.length() <= 65536);
			byte[] headerBytes = Base64.getUrlDecoder().decode(parts[0]), payloadBytes = Base64.getUrlDecoder().decode(parts[1]);
			strictUtf8(headerBytes); strictUtf8(payloadBytes);
			JsonObject header = parseObject(headerBytes), claims = parseObject(payloadBytes);
			assertEquals(Set.of("alg", "kid", "typ"), header.getMembers().keySet());
			assertEquals("RS256", header.findString("alg").orElseThrow()); assertEquals("at+jwt", header.findString("typ").orElseThrow());
			assertEquals(this.activeKeyId, header.findString("kid").orElseThrow());
			assertEquals(Set.of("iss", "sub", "aud", "client_id", "iat", "exp", "jti", "scope"), claims.getMembers().keySet());
			assertEquals(ISSUER, claims.findString("iss").orElseThrow()); assertEquals(this.subject, claims.findString("sub").orElseThrow());
			assertEquals(this.resource, claims.findString("aud").orElseThrow()); assertEquals(this.clientId, claims.findString("client_id").orElseThrow());
			assertEquals(NOW.getEpochSecond(), claims.findLong("iat").orElseThrow());
			assertEquals(NOW.plus(this.lifetime).getEpochSecond(), claims.findLong("exp").orElseThrow());
			String jti = claims.findString("jti").orElseThrow(); OAuthStoreFormat.nonce(jti);
			assertEquals(String.join(" ", this.scopes.stream().sorted().toList()), claims.findString("scope").orElseThrow());
			assertTrue(verifies(compact, this.activePublicKey)); assertFalse(verifies(compact, this.retainedPublicKey));
			if (different != null) {
				JsonObject other = parseObject(Base64.getUrlDecoder().decode(different.split("\\.", -1)[1]));
				assertNotEquals(other.findString("jti").orElseThrow(), jti);
			}
			BearerToken bearer = BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + compact)).orElseThrow();
			OAuthIssuerAccessTokenResult.Succeeded checked = assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,
				this.server.validateAccessTokenResult(bearer, this.resource));
			assertEquals(this.scopes, checked.getAccessToken().getScopes()); assertEquals(Optional.of(this.subject), checked.getAccessToken().getSubject());
		}

		private void assertPublishedKeys() throws Exception {
			JsonObject jwks = parseObject(this.server.jsonWebKeySetResponse("GET").toHttpBodyWithCredentials());
			assertEquals(Set.of("keys"), jwks.getMembers().keySet()); JsonArray keys = assertInstanceOf(JsonArray.class, jwks.find("keys").orElseThrow());
			assertEquals(2, keys.getElements().size()); Map<String, JsonObject> byId = new LinkedHashMap<>();
			for (JsonValue value : keys.getElements()) {
				JsonObject key = assertInstanceOf(JsonObject.class, value);
				assertEquals(Set.of("kty", "alg", "use", "key_ops", "kid", "n", "e"), key.getMembers().keySet());
				assertEquals("RSA", key.findString("kty").orElseThrow()); assertEquals("RS256", key.findString("alg").orElseThrow());
				assertEquals("sig", key.findString("use").orElseThrow());
				JsonArray operations = assertInstanceOf(JsonArray.class, key.find("key_ops").orElseThrow());
				assertEquals(List.of(JsonString.fromValue("verify")), operations.getElements());
				assertNull(byId.put(key.findString("kid").orElseThrow(), key));
			}
			assertEquals(Set.of(this.activeKeyId, this.retainedKeyId), byId.keySet());
			assertKey(requireNonNull(byId.get(this.activeKeyId)), this.activePublicKey);
			assertKey(requireNonNull(byId.get(this.retainedKeyId)), this.retainedPublicKey);
		}

		private static void assertKey(@NonNull JsonObject key, @NonNull PublicKey expected) {
			RSAPublicKey rsa = assertInstanceOf(RSAPublicKey.class, expected);
			assertEquals(unsigned(rsa.getModulus()), key.findString("n").orElseThrow());
			assertEquals(unsigned(rsa.getPublicExponent()), key.findString("e").orElseThrow());
		}

		private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers() {
			return Map.of("Content-Type", List.of("application/x-www-form-urlencoded"));
		}
	}

	/** Complete atomic conditions and mutations, no eviction, no durable/shared-backend claim. */
	private static final class Store implements OAuthAuthorizationServerStore {
		private final @NonNull Map<@NonNull OAuthStoreKey, @NonNull OAuthStoreEntry> rows = new LinkedHashMap<>();
		private Store() { }
		@Override public synchronized @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key, @NonNull Duration budget) {
			assertFalse(budget.isNegative() || budget.isZero()); return Optional.ofNullable(this.rows.get(key));
		}
		@Override public synchronized @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction, @NonNull Duration budget) {
			assertFalse(budget.isNegative() || budget.isZero());
			for (OAuthStoreTransaction.Condition condition : transaction.getConditions()) {
				OAuthStoreEntry row = this.rows.get(condition.getKey());
				if (!condition.getExpectedVersion().equals(row == null ? Optional.empty() : Optional.of(row.getVersion()))) return OAuthStoreCommitStatus.CONFLICT;
			}
			assertTrue(this.rows.size() + transaction.getMutations().size() < 64, "bounded fixture capacity");
			for (OAuthStoreTransaction.Mutation mutation : transaction.getMutations()) {
				if (mutation.getKind() == OAuthStoreTransaction.Mutation.Kind.REMOVE) this.rows.remove(mutation.getKey());
				else this.rows.put(mutation.getKey(), mutation.getEntry().orElseThrow());
			}
			return OAuthStoreCommitStatus.COMMITTED;
		}
	}

	private static final class ModelClock extends Clock {
		private @NonNull Instant now = NOW;
		private ModelClock() { }
		@Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
		@Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return Clock.fixed(this.now, zone); }
		@Override public @NonNull Instant instant() { return this.now; }
	}

	private static <T> @NonNull T requireNonNull(@org.jspecify.annotations.Nullable T value) { return java.util.Objects.requireNonNull(value); }
}
