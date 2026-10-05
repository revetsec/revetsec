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

import com.revetsec.M6FuzzOracle;
import com.revetsec.internal.http.Deadline;
import com.revetsec.jose.*;
import com.revetsec.json.JsonObject;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import static org.junit.jupiter.api.Assertions.*;

/** State model for original budgets, role audiences, clocks and one rotating key snapshot per assertion. */
@ThreadSafe
public final class ClientAssertionFuzzModel {
	private static final @NonNull Instant NOW = Instant.parse("2026-10-03T12:00:00Z");
	/** Control bytes select role/audience, metadata rejection, key state, budget and post-sign clock movement. */
	public static void run(byte @NonNull [] input) throws Exception {
		int roleCase = M6FuzzOracle.choice(input, 0, 3), audienceCase = M6FuzzOracle.choice(input, 1, 2), metadataCase = M6FuzzOracle.choice(input, 2, 5), keyCase = M6FuzzOracle.choice(input, 3, 3), clockCase = M6FuzzOracle.choice(input, 4, 4);
		boolean expired = M6FuzzOracle.choice(input, 5, 2) == 1;
		JwsAlgorithm algorithm = List.of(JwsAlgorithm.PS256, JwsAlgorithm.RS256, JwsAlgorithm.RS384).get(M6FuzzOracle.choice(input, 6, 3));
		OAuthEndpoint role = List.of(OAuthEndpoint.TOKEN, OAuthEndpoint.REVOCATION, OAuthEndpoint.INTROSPECTION).get(roleCase);
		String issuer = "https://issuer.example", path = List.of("/token", "/revoke", "/inspect").get(roleCase);
		URI endpoint = URI.create((metadataCase == 1 ? "https://foreign.example" : issuer) + path + "?q=%2F&x=a%20b");
		ResourceServerMetadata target = new ResourceServerMetadata(issuer, endpoint, metadataCase == 2 ? Set.of("client_secret_basic") : Set.of("private_key_jwt"), metadataCase == 3 ? Set.of() : Set.of(algorithm.getWireValue()), URI.create(metadataCase == 4 ? "https://foreign.example/token" : issuer + "/token"));
		Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
		OAuthClient client = OAuthClient.withIssuer(issuer).clientId("client").clientAuthentication(ClientAuthentication.noneInstance()).clock(clock).build();
		AtomicInteger reads = new AtomicInteger(); List<String> selected = new ArrayList<>();
		ClientAuthentication authentication = ClientAuthentication.withPrivateKeyJwt(budget -> {
			assertTrue(budget.toNanos() > 0 && budget.compareTo(Duration.ofSeconds(10)) <= 0);
			int index = reads.incrementAndGet(); if (keyCase == 1) throw new IllegalStateException("TEST-ONLY-unavailable");
			String kid = "key-" + index; selected.add(kid);
			return ClientAssertionSigningKey.withSigner(JwsSigner.fromRsaKeyPair(M6FuzzOracle.KEY.getPrivate(), (keyCase == 2 ? M6FuzzOracle.OTHER : M6FuzzOracle.KEY).getPublic(), algorithm)).keyId(kid).build();
		}).audience(audienceCase == 0 ? ClientAssertionAudience.ISSUER : ClientAssertionAudience.TOKEN_ENDPOINT).build();
		Deadline deadline = Deadline.fromNow(expired ? Duration.ZERO : Duration.ofSeconds(10));
		boolean permitted = !expired && metadataCase == 0 && keyCase == 0;
		try {
			ClientAssertionPreparation.Prepared first = ClientAssertionPreparation.prepare(authentication, "client", target, role, client.resourceSettings(), new SecureRandom(), deadline);
			assertTrue(permitted); assertEquals(1, reads.get()); verify(first, selected.get(0), audienceCase == 0 ? issuer : endpoint.toString(), audienceCase, algorithm);
			Clock moved = Clock.fixed(NOW.plusSeconds(clockCase == 0 ? 0 : clockCase == 1 ? -1 : clockCase == 2 ? 59 : 60), ZoneOffset.UTC);
			if (clockCase == 1 || clockCase == 3) assertEquals(OAuthException.Reason.CLIENT_ASSERTION_SIGNING_FAILED, assertThrows(OAuthException.class, () -> ClientAssertionPreparation.checkReady(first, moved, deadline)).getReason());
			else ClientAssertionPreparation.checkReady(first, moved, deadline);
			assertThrows(OAuthTransportException.class, () -> ClientAssertionPreparation.checkReady(first, clock, Deadline.fromNow(Duration.ZERO)));
			ClientAssertionPreparation.Prepared second = ClientAssertionPreparation.prepare(authentication, "client", target, role, client.resourceSettings(), new SecureRandom(), deadline);
			assertEquals(2, reads.get()); verify(second, selected.get(1), audienceCase == 0 ? issuer : endpoint.toString(), audienceCase, algorithm);
			assertNotEquals(claims(first.value()).findString("jti"), claims(second.value()).findString("jti"));
		} catch (OAuthException rejected) {
			assertFalse(permitted); assertNull(rejected.getCause());
			assertEquals(expired ? OAuthException.Reason.NETWORK_FAILURE : metadataCase != 0 ? OAuthException.Reason.CLIENT_ASSERTION_ENDPOINT_MISMATCH : keyCase == 1 ? OAuthException.Reason.CLIENT_ASSERTION_KEY_UNAVAILABLE : OAuthException.Reason.CLIENT_ASSERTION_KEY_PAIR_MISMATCH, rejected.getReason());
		}
		assertEquals(expired || metadataCase != 0 ? 0 : keyCase != 0 ? 1 : 2, reads.get());
	}
	private static @NonNull JsonObject claims(@NonNull String compact) throws Exception { return M6FuzzOracle.object(new String(M6FuzzOracle.decode(compact.split("\\.")[1]), StandardCharsets.UTF_8)); }
	private static void verify(ClientAssertionPreparation.@NonNull Prepared prepared, @NonNull String kid, @NonNull String audience, int mode, @NonNull JwsAlgorithm algorithm) throws Exception {
		M6FuzzOracle.verify(prepared.value(), M6FuzzOracle.KEY.getPublic(), algorithm);
		JsonObject claims = claims(prepared.value()), header = M6FuzzOracle.object(new String(M6FuzzOracle.decode(prepared.value().split("\\.")[0]), StandardCharsets.UTF_8));
		assertEquals("client", claims.findString("iss").orElseThrow()); assertEquals("client", claims.findString("sub").orElseThrow()); assertEquals(audience, claims.findString("aud").orElseThrow());
		assertEquals(NOW.getEpochSecond(), claims.findLong("iat").orElseThrow()); assertEquals(NOW.getEpochSecond(), claims.findLong("nbf").orElseThrow()); assertEquals(NOW.plusSeconds(60).getEpochSecond(), claims.findLong("exp").orElseThrow());
		assertEquals(32, M6FuzzOracle.decode(claims.findString("jti").orElseThrow()).length); assertEquals(kid, header.findString("kid").orElseThrow()); assertEquals(mode == 0 ? "client-authentication+jwt" : "JWT", header.findString("typ").orElseThrow());
		assertEquals(NOW, prepared.issued()); assertEquals(NOW.plusSeconds(60), prepared.expires());
	}
}
