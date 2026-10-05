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

package com.revetsec.oidc;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.M6FuzzOracle;
import com.revetsec.oauth.OAuthException;
import com.revetsec.internal.http.Deadline;
import com.revetsec.jose.*;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonArray;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import static org.junit.jupiter.api.Assertions.*;

/** Independent finite model across metadata, signature, verifying-key issuer, tenant and session continuity. */
@ThreadSafe
public class EntraIssuerFuzzTests {
	private static final @NonNull String TENANT = "11111111-2222-3333-4444-555555555555", OTHER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0";
	private static final @NonNull Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
	/** Control bytes combine trust roots, metadata shape, token/key binding and independently signed refreshes. */
	@FuzzTest(maxDuration = "5m")
	public void entraMatchesMetadataKeyTenantAndSessionModel(byte @NonNull [] input) throws Exception {
		String trust = "https://login.microsoftonline.com/" + (M6FuzzOracle.choice(input, 0, 2) == 0 ? "common" : "organizations") + "/v2.0";
		int metadataCase = M6FuzzOracle.choice(input, 1, 3), keyCase = M6FuzzOracle.choice(input, 2, 5), claimCase = M6FuzzOracle.choice(input, 3, 5), refreshCase = M6FuzzOracle.choice(input, 6, 5);
		boolean forged = M6FuzzOracle.choice(input, 4, 2) == 1, allowed = M6FuzzOracle.choice(input, 5, 2) == 0;
		JwsAlgorithm algorithm = List.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384).get(M6FuzzOracle.choice(input, 7, 3));
		AtomicInteger calls = new AtomicInteger();
		OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> { calls.incrementAndGet(); assertTrue(tenant.equals(TENANT) || tenant.equals(OTHER)); return allowed; });
		String advertised = metadataCase == 0 ? TEMPLATE : metadataCase == 1 ? issuer(TENANT) : TEMPLATE + "/";
		String metadata = JsonObject.builder().put("issuer", advertised).put("authorization_endpoint", trust + "/authorize").put("token_endpoint", trust + "/token").put("jwks_uri", trust + "/jwks").put("subject_types_supported", JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("public")))).put("response_types_supported", JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("code")))).put("id_token_signing_alg_values_supported", JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue("RS256")))).build().toJson();
		if (metadataCase != 0) { assertThrows(OAuthException.class, () -> OidcProviderMetadata.fromJson(trust, metadata, policy)); assertEquals(0, calls.get()); return; }
		OidcProviderMetadata parsed = OidcProviderMetadata.fromJson(trust, metadata, policy); assertEquals(trust, parsed.getIssuer()); assertEquals(0, calls.get());
		@Nullable String keyIssuer = switch (keyCase) { case 0 -> TEMPLATE; case 1 -> issuer(TENANT); case 2 -> null; case 3 -> issuer(OTHER); default -> TEMPLATE + "/"; };
		IdTokenValidator validator = validator(trust, keyIssuer, algorithm, policy);
		String compact = M6FuzzOracle.sign(claims(TENANT, claimCase, false), algorithm, forged);
		boolean profile = !forged && keyCase < 2 && claimCase == 0;
		try {
			IdToken initial = validator.validate(compact, "nonce", "TEST-ONLY-access", "TEST-ONLY-code", null, Set.of());
			assertTrue(profile && allowed); assertEquals(1, calls.get()); assertEquals(issuer(TENANT), initial.getClaims().getIssuer().orElseThrow());
			OidcSessionReference reference = new OidcSessionReference(initial, "client");
			OidcSessionReference restored = OidcSessionReference.fromSerializedForm(reference.toSerializedForm()); assertTrue(reference.matchesOriginalReference(restored));
			// A template key can validate both tenants, so original-issuer continuity has a separate oracle.
			IdTokenValidator refreshValidator = validator(trust, TEMPLATE, algorithm, policy);
			String refreshed = M6FuzzOracle.sign(claims(refreshCase == 1 ? OTHER : TENANT, refreshCase == 2 ? 1 : 0, refreshCase == 3), algorithm, refreshCase == 4);
			if (refreshCase == 0) assertEquals(issuer(TENANT), refreshValidator.validateRefresh(refreshed, restored, "TEST-ONLY-access", Set.of(), Deadline.fromNow(Duration.ofSeconds(10))).getClaims().getIssuer().orElseThrow());
			else assertThrows(OidcValidationException.class, () -> refreshValidator.validateRefresh(refreshed, restored, "TEST-ONLY-access", Set.of(), Deadline.fromNow(Duration.ofSeconds(10))));
			assertEquals(refreshCase == 0 ? 2 : 1, calls.get());
		} catch (OidcValidationException rejected) {
			assertFalse(profile && allowed); assertNull(rejected.getCause()); assertEquals(profile ? 1 : 0, calls.get());
		}
	}
	private static @NonNull String issuer(@NonNull String tenant) { return "https://login.microsoftonline.com/" + tenant + "/v2.0"; }
	private static @NonNull JsonObject claims(@NonNull String tenant, int mode, boolean changedSubject) {
		JsonObject.Builder claims = JsonObject.builder().put("iss", issuer(mode == 1 ? OTHER : tenant)).put("tid", mode == 2 ? OTHER.toUpperCase(Locale.ROOT) : tenant).put("sub", changedSubject ? "other" : "subject").put("aud", mode == 3 ? "other" : "client").put("nonce", "nonce").put("iat", NOW.getEpochSecond()).put("exp", NOW.plusSeconds(mode == 4 ? 0 : 300).getEpochSecond());
		return claims.build();
	}
	private static @NonNull IdTokenValidator validator(@NonNull String trust, @Nullable String keyIssuer, @NonNull JwsAlgorithm algorithm, @NonNull OidcIssuerPolicy policy) {
		return new IdTokenValidator(trust, "client", StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(M6FuzzOracle.jwks(keyIssuer, algorithm))), Set.of(algorithm), Set.of(), Set.of(), Duration.ZERO, Duration.ofMinutes(5), Clock.fixed(NOW, ZoneOffset.UTC), OidcObserver.disabledInstance(), false, policy);
	}
}
