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
import com.revetsec.json.JsonObject;
import com.revetsec.oauth.BearerToken;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Bounded single-process model. The application owns its users, policy and atomic test store. */
final class IssuerRefreshFuzzModel {
	private static final @NonNull String ISSUER = "https://issuer.example/tenant";
	private static final @NonNull String REDIRECT = "https://client.example/cb?original=%2f";
	private static final @NonNull String BROWSER = "A".repeat(43);
	private static final @NonNull String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
	private static final @NonNull String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
	private static final @NonNull List<@NonNull String> CLIENTS = List.of("client-a", "client-b");
	private static final @NonNull List<@NonNull String> RESOURCES = List.of("https://resource.example/mcp", "https://resource.example/second");
	private static final @NonNull Instant NOW = Instant.parse("2026-10-07T12:00:00Z");

	private IssuerRefreshFuzzModel() { }

	static void run(byte @NonNull [] input) throws Exception {
		Fixture fixture = new Fixture(input);
		Tokens first = fixture.issue();
		fixture.assertActive(first.access(), fixture.scopes);
		int scenario = M6FuzzOracle.choice(input, 2, 16);
		switch (scenario) {
			case 0 -> {
				Tokens second = fixture.rotateSucceeded(first.refresh(), RequestMode.EXACT);
				fixture.assertActive(first.access(), fixture.scopes);
				fixture.assertActive(second.access(), fixture.scopes);
			}
			case 1 -> fixture.assertUsedReplayInvalidatesFamily(first);
			case 2 -> {
				fixture.server.revokeGrant(fixture.grant());
				fixture.assertInactive(first.access()); fixture.assertRejected(first.refresh(), RequestMode.EXACT);
			}
			case 3 -> {
				fixture.server.revokeSubject("subject");
				fixture.assertInactive(first.access()); fixture.assertRejected(first.refresh(), RequestMode.EXACT);
			}
			case 4 -> {
				fixture.server.revokeAllGrants();
				fixture.assertInactive(first.access()); fixture.assertRejected(first.refresh(), RequestMode.EXACT);
			}
			case 5 -> {
				fixture.assertRejected(first.refresh(), RequestMode.WRONG_CLIENT);
				fixture.assertActive(first.access(), fixture.scopes);
				fixture.assertActive(fixture.rotateSucceeded(first.refresh(), RequestMode.EXACT).access(), fixture.scopes);
			}
			case 6 -> {
				fixture.assertRejected(first.refresh(), RequestMode.WRONG_RESOURCE);
				fixture.assertActive(first.access(), fixture.scopes);
				fixture.assertActive(fixture.rotateSucceeded(first.refresh(), RequestMode.EXACT).access(), fixture.scopes);
			}
			case 7 -> {
				Tokens second = fixture.rotateSucceeded(first.refresh(), RequestMode.NARROW_REQUEST);
				fixture.assertActive(second.access(), Set.of("read"));
				Tokens third = fixture.rotateSucceeded(second.refresh(), RequestMode.EXACT);
				fixture.assertActive(third.access(), fixture.scopes);
			}
			case 8 -> {
				fixture.policy = PolicyMode.DENY;
				fixture.assertRejected(first.refresh(), RequestMode.EXACT);
				fixture.assertInactive(first.access());
			}
			case 9 -> {
				fixture.policy = PolicyMode.NARROW;
				fixture.assertRejected(first.refresh(), RequestMode.EXACT);
				fixture.assertInactive(first.access());
			}
			case 10 -> {
				fixture.store.conflicts = 1 + M6FuzzOracle.choice(input, 3, 2);
				fixture.assertActive(fixture.rotateSucceeded(first.refresh(), RequestMode.EXACT).access(), fixture.scopes);
			}
			case 11 -> {
				fixture.clock.now = NOW.plusSeconds(301);
				fixture.assertRejected(first.refresh(), RequestMode.EXACT);
				fixture.assertInactive(first.access());
			}
			case 12 -> {
				Tokens second = fixture.rotateSucceeded(first.refresh(), RequestMode.EXACT);
				Tokens third = fixture.rotateSucceeded(second.refresh(), RequestMode.EXACT);
				fixture.assertActive(third.access(), fixture.scopes);
				fixture.assertRejected(first.refresh(), RequestMode.EXACT);
				fixture.assertInactive(third.access());
			}
			case 13 -> {
				assertInstanceOf(OAuthRevocationResult.Succeeded.class, fixture.revoke(first.refresh()));
				fixture.assertInactive(first.access()); fixture.assertRejected(first.refresh(), RequestMode.EXACT);
			}
			case 14 -> {
				assertInstanceOf(OAuthRevocationResult.Succeeded.class, fixture.revoke(first.access()));
				fixture.assertInactive(first.access()); fixture.assertRejected(first.refresh(), RequestMode.EXACT);
			}
			default -> {
				Tokens second = fixture.rotateSucceeded(first.refresh(), RequestMode.EXACT);
				fixture.assertRejected(first.refresh(), RequestMode.WRONG_CLIENT);
				fixture.assertActive(second.access(), fixture.scopes);
				fixture.assertRejected(first.refresh(), RequestMode.EXACT);
				fixture.assertInactive(second.access());
			}
		}
	}

	static void usedRefreshReplayCalibration() throws Exception {
		Fixture fixture = new Fixture(new byte[]{0, 0, 1, 0});
		fixture.assertUsedReplayInvalidatesFamily(fixture.issue());
	}

	static void subjectStatusCalibration() throws Exception {
		Fixture fixture = new Fixture(new byte[]{0, 0, 3, 0}); Tokens first = fixture.issue();
		fixture.assertActive(first.access(), fixture.scopes); fixture.server.revokeSubject("subject"); fixture.assertInactive(first.access());
	}

	static void grantStatusCalibration() throws Exception {
		Fixture fixture = new Fixture(new byte[]{0, 0, 2, 0}); Tokens first = fixture.issue();
		fixture.assertActive(first.access(), fixture.scopes); fixture.server.revokeGrant(fixture.grant()); fixture.assertInactive(first.access());
	}

	private enum RequestMode { EXACT, WRONG_CLIENT, WRONG_RESOURCE, NARROW_REQUEST }
	private enum PolicyMode { EXACT, DENY, NARROW }
	private record Tokens(@NonNull String access, @NonNull String refresh) { }

	private static @NonNull Map<@NonNull String, @NonNull Set<@NonNull String>> resources() {
		return Map.of(RESOURCES.get(0), Set.of("read", "write"), RESOURCES.get(1), Set.of("read", "write"));
	}

	private static @NonNull String form(@NonNull Map<@NonNull String, @NonNull String> values) {
		return String.join("&", values.entrySet().stream().map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8)
			+ "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8)).toList());
	}

	private static @NonNull JsonObject json(@NonNull OAuthServerResponse response) throws Exception {
		return (JsonObject) JsonCodec.parse(response.toHttpBodyWithCredentials(), JsonLimits.protocolDocument(65536));
	}

	private static final class Fixture {
		private final @NonNull Store store = new Store();
		private final @NonNull ModelClock clock = new ModelClock();
		private final @NonNull String clientId, otherClient, resource, otherResource;
		private final @NonNull Set<@NonNull String> scopes;
		private final @NonNull OAuthAuthorizationServer server;
		private final @NonNull ArrayList<@NonNull OAuthGrantContext> contexts = new ArrayList<>();
		private @NonNull PolicyMode policy = PolicyMode.EXACT;

		private Fixture(byte @NonNull [] input) throws Exception {
			int clientIndex = M6FuzzOracle.choice(input, 0, 2), resourceIndex = M6FuzzOracle.choice(input, 1, 2);
			this.clientId = CLIENTS.get(clientIndex); this.otherClient = CLIENTS.get(1 - clientIndex);
			this.resource = RESOURCES.get(resourceIndex); this.otherResource = RESOURCES.get(1 - resourceIndex);
			this.scopes = M6FuzzOracle.choice(input, 3, 2) == 0 ? Set.of("read") : Set.of("read", "write");
			byte[] material = new byte[32]; for (int index = 0; index < material.length; index++) material[index] = (byte) (index + 1);
			StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("test", Base64.getEncoder().encodeToString(material))).build();
			OAuthIssuerKeySnapshot keys = OAuthIssuerKeySnapshot.withActiveKey(OAuthIssuerSigningKey.fromKeyPair("key",
				M6FuzzOracle.KEY.getPrivate(), M6FuzzOracle.KEY.getPublic())).generation("g1").publishedAt(NOW.minusSeconds(120)).build();
			this.server = OAuthAuthorizationServer.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER + "/authorize"))
				.tokenEndpoint(URI.create(ISSUER + "/token")).jsonWebKeySetEndpoint(URI.create(ISSUER + "/jwks"))
				.revocationEndpoint(URI.create(ISSUER + "/revoke")).introspectionEndpoint(URI.create(ISSUER + "/introspect"))
				.clientRepository((id, budget) -> CLIENTS.contains(id) ? Optional.of(client(id)) : Optional.empty())
				.store(this.store).stateSealer(sealer).signingKeys(OAuthIssuerKeyProvider.fromSnapshot(keys)).resources(resources()).clock(this.clock)
				.accessTokenLifetime(Duration.ofSeconds(60)).refreshTokenIdleLifetime(Duration.ofSeconds(300))
				.refreshTokenAbsoluteLifetime(Duration.ofHours(1)).refreshTokensEnabled(true)
				.grantPolicy((context, budget) -> {
					this.contexts.add(context);
					if (this.policy == PolicyMode.DENY && context.getGrantType().equals("refresh_token")) return OAuthAuthorizationDecision.deniedInstance();
					Set<String> selected = this.policy == PolicyMode.NARROW && context.getGrantType().equals("refresh_token") ? Set.of() : context.getAuthorizedScopesByResource().get(this.resource);
					return decision(selected == null ? Set.of() : selected, true);
				}).build();
			assertEquals(OAuthStoreCommitStatus.COMMITTED, this.server.initializeFreshIssuer());
			this.server.establishNewSubject("subject");
		}

		private @NonNull OAuthServerClientRegistration client(@NonNull String id) {
			return OAuthServerClientRegistration.withClientId(id).configurationVersion("v1").redirectUris(List.of(URI.create(REDIRECT)))
				.allowedScopesByResource(resources()).refreshTokenPermitted(true).build();
		}

		private @NonNull OAuthAuthorizationDecision decision(@NonNull Set<@NonNull String> selected, boolean refresh) {
			return OAuthAuthorizationDecision.withSubject("subject").authorizedScopesByResource(Map.of(this.resource, selected))
				.refreshTokenPermitted(refresh).build();
		}

		private @NonNull Tokens issue() throws Exception {
			String query = form(Map.of("client_id", this.clientId, "response_type", "code", "redirect_uri", REDIRECT,
				"resource", this.resource, "scope", String.join(" ", this.scopes), "code_challenge", CHALLENGE,
				"code_challenge_method", "S256", "state", "state"));
			OAuthServerInteraction interaction = assertInstanceOf(OAuthAuthorizationResult.InteractionRequired.class,
				this.server.beginAuthorizationResult("GET", query, new byte[0], Map.of(), BROWSER)).getInteraction();
			OAuthServerResponse authorization = assertInstanceOf(OAuthAuthorizationResult.Completed.class,
				this.server.completeAuthorizationResult(interaction.getInteractionValue(), BROWSER, decision(this.scopes, true))).getResponse();
			String location = authorization.getLocationWithCredentials().orElseThrow().toString();
			String code = location.substring(location.indexOf("code=") + 5, location.indexOf("&state="));
			Map<String, String> fields = Map.of("grant_type", "authorization_code", "client_id", this.clientId,
				"resource", this.resource, "code", code, "code_verifier", VERIFIER, "redirect_uri", REDIRECT);
			OAuthTokenResult result = this.server.tokenResult("POST", null, form(fields).getBytes(StandardCharsets.UTF_8), headers());
			return tokens(assertInstanceOf(OAuthTokenResult.Succeeded.class, result).getResponse());
		}

		private @NonNull Tokens rotateSucceeded(@NonNull String refresh, @NonNull RequestMode mode) throws Exception {
			return tokens(assertInstanceOf(OAuthTokenResult.Succeeded.class, rotate(refresh, mode)).getResponse());
		}

		private @NonNull OAuthTokenResult rotate(@NonNull String refresh, @NonNull RequestMode mode) {
			Map<String, String> fields = new LinkedHashMap<>();
			fields.put("grant_type", "refresh_token"); fields.put("client_id", mode == RequestMode.WRONG_CLIENT ? this.otherClient : this.clientId);
			fields.put("resource", mode == RequestMode.WRONG_RESOURCE ? this.otherResource : this.resource); fields.put("refresh_token", refresh);
			if (mode == RequestMode.NARROW_REQUEST) fields.put("scope", "read");
			return this.server.tokenResult("POST", null, form(fields).getBytes(StandardCharsets.UTF_8), headers());
		}

		private @NonNull OAuthRevocationResult revoke(@NonNull String token) {
			Map<String, String> fields = Map.of("client_id", this.clientId, "token", token);
			return this.server.revokeResult("POST", null, form(fields).getBytes(StandardCharsets.UTF_8), headers());
		}

		private @NonNull Tokens tokens(@NonNull OAuthServerResponse response) throws Exception {
			JsonObject body = json(response); String access = body.findString("access_token").orElseThrow();
			String refresh = body.findString("refresh_token").orElseThrow();
			M6FuzzOracle.verify(access, M6FuzzOracle.KEY.getPublic(), com.revetsec.jose.JwsAlgorithm.RS256);
			return new Tokens(access, refresh);
		}

		private void assertActive(@NonNull String access, @NonNull Set<@NonNull String> expectedScopes) {
			BearerToken bearer = BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + access)).orElseThrow();
			OAuthIssuerAccessTokenResult.Succeeded result = assertInstanceOf(OAuthIssuerAccessTokenResult.Succeeded.class,
				this.server.validateAccessTokenResult(bearer, this.resource));
			assertEquals(expectedScopes, result.getAccessToken().getScopes());
			assertEquals(Optional.of("subject"), result.getAccessToken().getSubject());
		}

		private void assertInactive(@NonNull String access) {
			BearerToken bearer = BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + access)).orElseThrow();
			assertInstanceOf(OAuthIssuerAccessTokenResult.Rejected.class, this.server.validateAccessTokenResult(bearer, this.resource));
		}

		private void assertRejected(@NonNull String refresh, @NonNull RequestMode mode) {
			assertInstanceOf(OAuthTokenResult.Rejected.class, rotate(refresh, mode));
		}

		private void assertUsedReplayInvalidatesFamily(@NonNull Tokens first) throws Exception {
			Tokens second = rotateSucceeded(first.refresh(), RequestMode.EXACT);
			assertActive(second.access(), this.scopes);
			assertRejected(first.refresh(), RequestMode.EXACT);
			assertInactive(first.access()); assertInactive(second.access());
			assertRejected(second.refresh(), RequestMode.EXACT);
		}

		private @NonNull String grant() { return this.contexts.get(0).getGrantValue(); }

		private static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers() {
			return Map.of("Content-Type", List.of("application/x-www-form-urlencoded"));
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
}
