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
import com.revetsec.oauth.BearerToken;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonObject;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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

/** Bounded single-process model. The application owns its users, decisions and atomic test store. */
final class IssuerCodeFuzzModel {
	private static final @NonNull String ISSUER = "https://issuer.example/tenant", REDIRECT = "https://client.example/cb?original=%2f", BROWSER = "A".repeat(43);
	private static final @NonNull List<@NonNull String> RESOURCES = List.of("https://resource.example/mcp", "https://resource.example/second");
	private static final @NonNull Instant NOW = Instant.parse("2026-10-06T12:00:00Z");
	private IssuerCodeFuzzModel() { }
	static void consumedCodeRecordCannotBeConsumedAgain() throws Exception {
		Fixture fixture = new Fixture(new byte[]{0, 0, 0, 0});
		fixture.issue();
		OAuthStoreEntry entry = fixture.store.rows.values().stream()
			.filter(value -> value.getKey().getKind() == OAuthStoreKey.Kind.CODE).findFirst().orElseThrow();
		JsonObject payload = fixture.codec.open(entry, fixture.clock);
		String id = payload.findString("id").orElseThrow();
		OAuthAuthorizationRecord unused = OAuthAuthorizationRecord.decode(OAuthStoreKey.Kind.CODE, id, payload,
			OAuthServerIngressLimits.fromDefaults(), 255);
		OAuthAuthorizationRecord used = unused.consumed(NOW.plusSeconds(3600), OAuthServerIngressLimits.fromDefaults(), 255);
		assertThrows(IllegalArgumentException.class,
			() -> used.consumed(NOW.plusSeconds(3600), OAuthServerIngressLimits.fromDefaults(), 255),
			"a consumed record cannot be reused as an unused authorization code");
	}
	static void run(byte @NonNull [] input) throws Exception {
		Fixture fixture = new Fixture(input);
		String code = fixture.issue();
		int mode = M6FuzzOracle.choice(input, 3, 11);
		if (mode == 5) fixture.version = "v2";
		if (mode == 6) fixture.clock.now = NOW.plusSeconds(121);
		if (mode == 7) fixture.deny = true;
		if (mode == 8) fixture.narrow = true;
		if (mode == 10) fixture.store.conflicts = 1;
		Map<OAuthStoreKey, OAuthStoreEntry> before = Map.copyOf(fixture.store.rows);
		int accesses = fixture.store.accesses();
		OAuthTokenResult result = fixture.redeem(code, mode);
		if (mode >= 1 && mode <= 7 || mode == 9) {
			assertInstanceOf(OAuthTokenResult.Rejected.class, result, "bound code must reject changed verifier/resource/client/return/version/expiry/policy");
			assertEquals(accesses, fixture.store.accesses(), "failed redemption cannot mint an access row");
			if (mode != 7) assertEquals(before, fixture.store.rows, "binding/expiry rejection cannot consume or alter the code");
			if (mode == 6 || mode == 7) {
				assertInstanceOf(OAuthTokenResult.Rejected.class, fixture.redeem(code, 0));
				return;
			}
			fixture.version = "v1";
			result = fixture.redeem(code, 0);
		}
		OAuthServerResponse response = assertInstanceOf(OAuthTokenResult.Succeeded.class, result, "correct unused code must succeed").getResponse();
		assertEquals(200, response.getStatusCode());
		assertEquals(accesses + 1, fixture.store.accesses(), "one credential response requires one new access row");
		JsonObject json = (JsonObject) JsonCodec.parse(response.toHttpBodyWithCredentials(), JsonLimits.protocolDocument(65536));
		String compact = json.findString("access_token").orElseThrow();
		M6FuzzOracle.verify(compact, M6FuzzOracle.KEY.getPublic(), com.revetsec.jose.JwsAlgorithm.RS256);
		JsonObject claims = M6FuzzOracle.object(new String(M6FuzzOracle.decode(compact.split("\\.")[1]), StandardCharsets.UTF_8));
		assertEquals(ISSUER, claims.findString("iss").orElseThrow());
		assertEquals(fixture.resource, claims.findString("aud").orElseThrow());
		assertEquals(fixture.clientId, claims.findString("client_id").orElseThrow());
		assertEquals("subject", claims.findString("sub").orElseThrow());
		Set<String> scopes = Set.copyOf(Arrays.asList(claims.findString("scope").orElseThrow().split(" ")));
		assertEquals(fixture.narrow ? Set.of("read") : fixture.scopes, scopes, "policy may narrow but never widen scopes");
		assertFalse(json.getMembers().containsKey("refresh_token"), "refresh is outside this code-only model");
		BearerToken bearer = BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + compact)).orElseThrow();
		assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class, fixture.server.validateAccessTokenResult(bearer, fixture.resource));
		assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class, fixture.server.validateAccessTokenResult(bearer, fixture.otherResource));
		before = Map.copyOf(fixture.store.rows);
		assertInstanceOf(OAuthTokenResult.Rejected.class, fixture.redeem(code, 1), "wrongly bound replay must reject");
		assertEquals(before, fixture.store.rows, "wrong verifier cannot invalidate the winning grant");
		assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class, fixture.server.validateAccessTokenResult(bearer, fixture.resource));
		assertInstanceOf(OAuthTokenResult.Rejected.class, fixture.redeem(code, 0), "a consumed code must never issue a second credential response");
		assertEquals(accesses + 1, fixture.store.accesses(), "a consumed code must never mint a second access row");
		assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class, fixture.server.validateAccessTokenResult(bearer, fixture.resource), "valid replay must invalidate the winning grant");
		assertInstanceOf(OAuthTokenResult.Rejected.class, fixture.redeem(code, 0), "subsequent replay stays rejected");
	}
	private static @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources() { return Map.of(RESOURCES.get(0), Set.of("read", "write"), RESOURCES.get(1), Set.of("read", "write")); }
	private static @NonNull String form(@NonNull Map<@NonNull String, @NonNull String> values) {
		return String.join("&", values.entrySet().stream().map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8)).toList());
	}
	private static final class Fixture {
		private final @NonNull Store store = new Store();
		private final @NonNull ModelClock clock = new ModelClock();
		private final @NonNull String resource, otherResource, clientId, verifier;
		private final @NonNull Set<@NonNull String> scopes;
		private final @NonNull OAuthStoreRecordCodec codec;
		private final boolean confidential;
		private final @NonNull OAuthAuthorizationServer server;
		private @NonNull String version = "v1";
		private boolean deny, narrow;
		private Fixture(byte @NonNull [] input) throws Exception {
			this.confidential = M6FuzzOracle.choice(input, 0, 2) == 1;
			this.clientId = this.confidential ? "confidential" : "public";
			int resourceIndex = M6FuzzOracle.choice(input, 1, 2);
			this.resource = RESOURCES.get(resourceIndex); this.otherResource = RESOURCES.get(1 - resourceIndex);
			this.scopes = M6FuzzOracle.choice(input, 2, 2) == 0 ? Set.of("read") : Set.of("read", "write");
			byte[] entropy = Arrays.copyOfRange(input, Math.min(4, input.length), Math.min(260, input.length));
			this.verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(entropy));
			byte[] material = new byte[32]; for (int i = 0; i < material.length; i++) material[i] = (byte) (i + 1);
			StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("test", Base64.getEncoder().encodeToString(material))).build();
			this.codec = new OAuthStoreRecordCodec(ISSUER, sealer, 3800);
			OAuthIssuerKeySnapshot keys = OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key", M6FuzzOracle.KEY.getPrivate(), M6FuzzOracle.KEY.getPublic())).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
			this.server = OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER + "/authorize"))
				.tokenEndpoint(URI.create(ISSUER + "/token")).jsonWebKeySetEndpoint(URI.create(ISSUER + "/jwks"))
				.clientRepository((id, budget) -> id.equals(this.clientId) || id.equals("other") ? Optional.of(client(id)) : Optional.empty())
				.store(this.store).stateSealer(sealer).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys)).resources(resources()).clock(this.clock)
				.grantPolicy((context, budget) -> this.deny ? OAuthAuthorizationDecision.deniedInstance() : decision(this.narrow ? Set.of("read") : context.getAuthorizedScopesByResource().get(this.resource))).build();
			assertEquals(OAuthStoreCommitStatus.COMMITTED, this.server.initializeFreshIssuer());
			this.server.establishNewSubject("subject");
		}
		private @NonNull OAuthServerClientRegistration client(@NonNull String id) {
			var builder = OAuthServerClientRegistration.withClientId(id).configurationVersion(this.version).redirectUris(List.of(URI.create(REDIRECT))).allowedScopesByResource(resources());
			if (this.confidential) builder.authentication(OAuthServerClientAuthentication.fromClientSecretVerifier((client, secret, budget) -> Arrays.equals(secret, "test-secret".getBytes(StandardCharsets.UTF_8))));
			return builder.build();
		}
		private @NonNull OAuthAuthorizationDecision decision(@NonNull Set<@NonNull String> selected) {
			return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(this.resource, selected)).build();
		}
		private @NonNull String issue() throws Exception {
			String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(this.verifier.getBytes(StandardCharsets.US_ASCII)));
			String query = form(Map.of("client_id", this.clientId, "response_type", "code", "redirect_uri", REDIRECT,
				"resource", this.resource, "scope", String.join(" ", this.scopes), "code_challenge", challenge, "code_challenge_method", "S256", "state", "state"));
			OAuthServerInteraction interaction = assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,
				this.server.beginAuthorizationResult("GET", query, new byte[0], Map.of(), BROWSER)).getInteraction();
			OAuthServerResponse response = assertInstanceOf(OAuthAuthorizationResult.Completed.class,
				this.server.completeAuthorizationResult(interaction.getInteractionValue(), BROWSER, decision(this.scopes))).getResponse();
			assertEquals(303, response.getStatusCode());
			String location = response.getLocationWithCredentials().orElseThrow().toString();
			assertTrue(location.startsWith(REDIRECT + "&code=rsc1_"));
			assertTrue(location.contains("&state=state&iss=" + URLEncoder.encode(ISSUER, StandardCharsets.UTF_8)));
			return location.substring(location.indexOf("code=") + 5, location.indexOf("&state="));
		}
		private @NonNull OAuthTokenResult redeem(@NonNull String code, int mode) {
			Map<String, String> fields = new LinkedHashMap<>(Map.of("grant_type", "authorization_code", "code", code,
				"code_verifier", mode == 1 ? "A".repeat(43) : mode == 9 ? "short" : this.verifier,
				"resource", mode == 2 ? this.otherResource : this.resource, "redirect_uri", mode == 4 ? REDIRECT + "x" : REDIRECT));
			String id = mode == 3 ? "other" : this.clientId;
			Map<String, List<String>> headers = new LinkedHashMap<>(Map.of("Content-Type", List.of("application/x-www-form-urlencoded")));
			if (this.confidential) headers.put("Authorization", List.of("Basic " + Base64.getEncoder().encodeToString((id + ":test-secret").getBytes(StandardCharsets.UTF_8))));
			else fields.put("client_id", id);
			return this.server.tokenResult("POST", null, form(fields).getBytes(StandardCharsets.UTF_8), headers);
		}
	}
	/** Complete atomic conditions and mutations, no eviction, no durable/shared-backend claim. */
	private static final class Store implements OAuthAuthorizationServerStore {
		private final @NonNull Map<@NonNull OAuthStoreKey, @NonNull OAuthStoreEntry> rows = new LinkedHashMap<>();
		private int conflicts;
		private Store() { }
		@Override public synchronized @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key, @NonNull Duration budget) {
			assertFalse(budget.isNegative() || budget.isZero()); return Optional.ofNullable(this.rows.get(key));
		}
		@Override public synchronized @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction, @NonNull Duration budget) {
			assertFalse(budget.isNegative() || budget.isZero());
			if (this.conflicts > 0) { this.conflicts--; return OAuthStoreCommitStatus.CONFLICT; }
			for (var condition : transaction.getConditions()) {
				OAuthStoreEntry row = this.rows.get(condition.getKey());
				if (!condition.getExpectedVersion().equals(row == null ? Optional.empty() : Optional.of(row.getVersion()))) return OAuthStoreCommitStatus.CONFLICT;
			}
			assertTrue(this.rows.size() + transaction.getMutations().size() < 64, "bounded fixture capacity");
			for (var mutation : transaction.getMutations()) {
				if (mutation.getKind() == OAuthStoreTransaction.Mutation.Kind.REMOVE) this.rows.remove(mutation.getKey());
				else this.rows.put(mutation.getKey(), mutation.getEntry().orElseThrow());
			}
			return OAuthStoreCommitStatus.COMMITTED;
		}
		private int accesses() { return (int) this.rows.keySet().stream().filter(k -> k.getKind() == OAuthStoreKey.Kind.ACCESS_TOKEN).count(); }
	}
	private static final class ModelClock extends Clock {
		private @NonNull Instant now = NOW;
		private ModelClock() { }
		@Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
		@Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return Clock.fixed(this.now, zone); }
		@Override public @NonNull Instant instant() { return this.now; }
	}
}
