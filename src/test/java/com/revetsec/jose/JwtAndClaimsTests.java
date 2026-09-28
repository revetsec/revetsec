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

package com.revetsec.jose;

import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * {@link Jwt} and {@link JwtClaims}, the verified types (R17; M2-5): only a successful validation makes one, every
 * getter is total, claims read as the token sent them, both compare by reference, and neither shows its token or
 * claims in {@code toString}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtAndClaimsTests {
	private static final JwtValidator VALIDATOR = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);

	// Jwt gives the header's alg, kid and raw typ, the claims, and the token exactly as received.
	@Test
	void aJwtGivesItsHeaderFactsAndTheReceivedToken() {
		String token = JwtFixtures.token(Algorithm.RS256).typ("application/JWT").sign(
				Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
		Jwt jwt = JwtFixtures.assertAccepted(VALIDATOR, token);

		Assertions.assertEquals(JwsAlgorithm.RS256, jwt.getAlgorithm());
		Assertions.assertEquals(Optional.of(JwtFixtures.KID), jwt.getKeyId());
		Assertions.assertEquals(Optional.of("application/JWT"), jwt.getType());
		Assertions.assertSame(token, jwt.toCompactSerialization());
		Assertions.assertSame(jwt.getClaims(), jwt.getClaims());

		Jwt bare = JwtFixtures.assertAccepted(JwtFixtures.validator(JwtFixtures.source(JwtFixtures.jwk(
				Fixture.IDP_SIGNING_RSA_2048).kid(null).toJson())).build(), TestJws.withAlgorithm(
				Algorithm.RS256).payload(JwtFixtures.claims().toJson()).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
		Assertions.assertEquals(Optional.empty(), bare.getKeyId());
		Assertions.assertEquals(Optional.empty(), bare.getType());
	}

	// RFC 7519 section 4.1: the registered claims are typed, and every getter is total, giving empty for an absent
	// claim; aud as a string is a list of one; and the claim names keep the token's member order.
	@Test
	void theClaimGettersAreTotal() {
		JwtClaims full = JwtFixtures.assertAccepted(VALIDATOR, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048,
				Algorithm.RS256, JwtFixtures.claims().put("nbf", JwtFixtures.at(Duration.ofMinutes(-1)))
						.put("jti", "id-1").raw("aud", "[\"" + JwtFixtures.AUDIENCE + "\",\"b\"]").raw("n", "1.50"))).getClaims();

		Assertions.assertEquals(Optional.of(JwtFixtures.ISSUER), full.getIssuer());
		Assertions.assertEquals(Optional.of("subject-1"), full.getSubject());
		Assertions.assertEquals(List.of(JwtFixtures.AUDIENCE, "b"), full.getAudiences());
		Assertions.assertEquals(Optional.of(JwtFixtures.NOW.plusSeconds(300)), full.getExpiresAt());
		Assertions.assertEquals(Optional.of(JwtFixtures.NOW), full.getIssuedAt());
		Assertions.assertEquals(Optional.of(JwtFixtures.NOW.minusSeconds(60)), full.getNotBefore());
		Assertions.assertEquals(Optional.of("id-1"), full.getJwtId());
		Assertions.assertEquals(Optional.of(JsonNumber.fromValue(new BigDecimal("1.50"))), full.getClaim("n"));
		Assertions.assertEquals(Optional.of(JsonString.fromValue("id-1")), full.getClaim("jti"));
		Assertions.assertEquals(Optional.empty(), full.getClaim("absent"));
		Assertions.assertEquals(List.of("iss", "sub", "aud", "iat", "exp", "nbf", "jti", "n"),
				List.copyOf(full.getClaimNames()), "in the order the claims appear in the token");
		Assertions.assertThrows(UnsupportedOperationException.class, () -> full.getAudiences().add("x"));
		Assertions.assertThrows(UnsupportedOperationException.class, () -> full.getClaimNames().add("x"));

		JwtClaims sparse = JwtFixtures.assertAccepted(JwtValidator.withIssuer(JwtFixtures.ISSUER).jsonWebKeySource(
				JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048)).acceptAnyAudience(true).clock(JwtFixtures.clock()).build(),
				JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256, JwtFixtures.claims().remove("sub")
						.remove("aud").remove("iat"))).getClaims();
		Assertions.assertEquals(Optional.empty(), sparse.getSubject());
		Assertions.assertEquals(List.of(), sparse.getAudiences());
		Assertions.assertEquals(Optional.empty(), sparse.getIssuedAt());
		Assertions.assertEquals(Optional.empty(), sparse.getNotBefore());
		Assertions.assertEquals(Optional.empty(), sparse.getJwtId());

		JwtClaims single = JwtFixtures.assertAccepted(VALIDATOR, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048,
				Algorithm.RS256)).getClaims();
		Assertions.assertEquals(List.of(JwtFixtures.AUDIENCE), single.getAudiences());
	}

	// A claim name is required.
	@Test
	@SuppressWarnings("NullAway")
	void aNullClaimNameIsRefused() {
		JwtClaims claims = JwtFixtures.assertAccepted(VALIDATOR, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048,
				Algorithm.RS256)).getClaims();
		Assertions.assertThrows(NullPointerException.class, () -> claims.getClaim(null));
	}

	// toJsonObject gives the whole claims set as sent, other members and their order included.
	@Test
	void toJsonObjectGivesTheWholeClaimsSet() {
		JwtClaims claims = JwtFixtures.assertAccepted(VALIDATOR, JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048,
				Algorithm.RS256, JwtFixtures.claims().raw("nested", "{\"a\":[1,true,null]}"))).getClaims();
		JsonObject json = claims.toJsonObject();

		Assertions.assertEquals(JwtFixtures.claims().raw("nested", "{\"a\":[1,true,null]}").toJson(), json.toJson());
		Assertions.assertEquals(json.find("nested"), claims.getClaim("nested"));
	}

	// M2-5: Jwt and JwtClaims compare by reference, so the same token validated twice gives two unequal objects, and
	// toString is redacted.
	@Test
	void verifiedTypesCompareByReferenceAndAreRedacted() {
		String token = JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256);
		Jwt first = JwtFixtures.assertAccepted(VALIDATOR, token);
		Jwt second = JwtFixtures.assertAccepted(VALIDATOR, token);

		Assertions.assertNotEquals(first, second);
		Assertions.assertNotEquals(first.getClaims(), second.getClaims());
		Assertions.assertEquals(first, first);
		Assertions.assertEquals(System.identityHashCode(first), first.hashCode());
		Assertions.assertEquals(System.identityHashCode(first.getClaims()), first.getClaims().hashCode());
		Assertions.assertEquals("Jwt{algorithm=RS256}", first.toString());
		Assertions.assertEquals("JwtClaims{<redacted>}", first.getClaims().toString());
	}

	// R17: there is no public way to make a Jwt or JwtClaims except validation: no public constructor, and no public
	// static method.
	@Test
	void onlyValidationMakesAVerifiedType() {
		for (Class<?> type : List.of(Jwt.class, JwtClaims.class)) {
			Assertions.assertTrue(Modifier.isFinal(type.getModifiers()));
			for (Constructor<?> constructor : type.getDeclaredConstructors())
				Assertions.assertFalse(Modifier.isPublic(constructor.getModifiers()), constructor.toString());
			for (Method method : type.getDeclaredMethods())
				Assertions.assertFalse(Modifier.isPublic(method.getModifiers()) && Modifier.isStatic(method.getModifiers()),
						method.toString());
		}
	}
}
