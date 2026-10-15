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

import com.revetsec.internal.json.JsonFields;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/**
 * Outbound claims preserve their typed meaning without applying a validation profile, cannot bypass registered
 * setters through custom claims, and remain immutable and redacted when builders and input collections change.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwtClaimsSetTests {
	@Test
	void registeredAndCustomClaimsKeepTheirJsonTypes() throws Exception {
		Instant issuedAt = Instant.parse("2026-10-15T14:00:00.123456789Z");
		Instant expiresAt = issuedAt.plusSeconds(300);
		Instant notBefore = issuedAt.minusSeconds(30);
		JsonObject nested = JsonObject.builder().put("enabled", true).build();
		JsonArray array = JsonArray.fromElements(List.of(JsonString.fromValue("read"), JsonString.fromValue("write")));
		JwtClaimsSet claims = JwtClaimsSet.builder().issuer("https://issuer.example.com").subject("user-123")
				.audiences(List.of("https://api.example.com", "https://other.example.com"))
				.issuedAt(issuedAt).expiresAt(expiresAt).notBefore(notBefore).jwtId("token-123")
				.claim("role", "reader").claim("attempt", 42L).claim("ratio", new BigDecimal("0.125"))
				.claim("active", true).claim("context", nested).claim("permissions", array).claimNull("absent")
				.build();

		Assertions.assertEquals("https://issuer.example.com", claims.getIssuer().orElseThrow());
		Assertions.assertEquals("user-123", claims.getSubject().orElseThrow());
		Assertions.assertEquals(List.of("https://api.example.com", "https://other.example.com"), claims.getAudiences());
		Assertions.assertEquals(issuedAt, claims.getIssuedAt().orElseThrow());
		Assertions.assertEquals(expiresAt, claims.getExpiresAt().orElseThrow());
		Assertions.assertEquals(notBefore, claims.getNotBefore().orElseThrow());
		Assertions.assertEquals("token-123", claims.getJwtId().orElseThrow());
		Assertions.assertEquals(issuedAt, JsonFields.numericDate(claims.toJsonObject(), "iat").orElseThrow());
		Assertions.assertEquals(expiresAt, JsonFields.numericDate(claims.toJsonObject(), "exp").orElseThrow());
		Assertions.assertEquals(notBefore, JsonFields.numericDate(claims.toJsonObject(), "nbf").orElseThrow());
		JsonObject expectedCustomClaims = JsonObject.builder().put("role", "reader").put("attempt", 42L)
				.put("ratio", new BigDecimal("0.125")).put("active", true).put("context", nested)
				.put("permissions", array).putNull("absent").build();
		expectedCustomClaims.getMembers().forEach((name, value) -> Assertions.assertEquals(value,
				claims.getClaim(name).orElseThrow()));
		Assertions.assertInstanceOf(JsonArray.class, claims.getClaim("aud").orElseThrow());
		Assertions.assertSame(JsonNull.defaultInstance(), claims.getClaim("absent").orElseThrow());
		Assertions.assertTrue(claims.getClaim("missing").isEmpty());
		Assertions.assertEquals(Set.of("iss", "sub", "aud", "iat", "exp", "nbf", "jti", "role", "attempt", "ratio",
				"active", "context", "permissions", "absent"), claims.getClaimNames());
	}

	@Test
	void everyRegisteredClaimIsOptionalAndNullClearsIt() {
		JwtClaimsSet empty = JwtClaimsSet.builder().build();
		Assertions.assertSame(JsonObject.emptyInstance(), empty.toJsonObject());
		Assertions.assertTrue(empty.getIssuer().isEmpty());
		Assertions.assertTrue(empty.getSubject().isEmpty());
		Assertions.assertTrue(empty.getAudiences().isEmpty());
		Assertions.assertTrue(empty.getIssuedAt().isEmpty());
		Assertions.assertTrue(empty.getExpiresAt().isEmpty());
		Assertions.assertTrue(empty.getNotBefore().isEmpty());
		Assertions.assertTrue(empty.getJwtId().isEmpty());

		JwtClaimsSet cleared = JwtClaimsSet.builder().issuer("issuer").subject("subject").audiences(List.of("audience"))
				.issuedAt(Instant.EPOCH).expiresAt(Instant.EPOCH).notBefore(Instant.EPOCH).jwtId("id")
				.issuer(null).subject(null).audiences(null).issuedAt(null).expiresAt(null).notBefore(null).jwtId(null)
				.build();
		Assertions.assertSame(JsonObject.emptyInstance(), cleared.toJsonObject());
		Assertions.assertTrue(cleared.getIssuer().isEmpty());
		Assertions.assertTrue(cleared.getSubject().isEmpty());
		Assertions.assertTrue(cleared.getAudiences().isEmpty());
		Assertions.assertTrue(cleared.getIssuedAt().isEmpty());
		Assertions.assertTrue(cleared.getExpiresAt().isEmpty());
		Assertions.assertTrue(cleared.getNotBefore().isEmpty());
		Assertions.assertTrue(cleared.getJwtId().isEmpty());
	}

	@Test
	void settersReplaceAndBuildsAndAudienceInputsAreIndependentSnapshots() {
		List<String> audiences = new ArrayList<>(List.of("first"));
		JwtClaimsSet.Builder builder = JwtClaimsSet.builder().issuer("original").subject("original")
				.audiences(audiences).issuedAt(Instant.EPOCH).expiresAt(Instant.EPOCH).notBefore(Instant.EPOCH)
				.jwtId("original").claim("original", true);
		audiences.clear();
		JwtClaimsSet first = builder.build();
		JwtClaimsSet second = builder.issuer("replacement").subject("replacement").audiences(List.of("second"))
				.issuedAt(Instant.EPOCH.plusSeconds(1)).expiresAt(Instant.EPOCH.plusSeconds(2))
				.notBefore(Instant.EPOCH.plusSeconds(3)).jwtId("replacement").claim("later", true).build();

		Assertions.assertEquals("original", first.getIssuer().orElseThrow());
		Assertions.assertEquals("original", first.getSubject().orElseThrow());
		Assertions.assertEquals(List.of("first"), first.getAudiences());
		Assertions.assertEquals(Instant.EPOCH, first.getIssuedAt().orElseThrow());
		Assertions.assertEquals(Instant.EPOCH, first.getExpiresAt().orElseThrow());
		Assertions.assertEquals(Instant.EPOCH, first.getNotBefore().orElseThrow());
		Assertions.assertEquals("original", first.getJwtId().orElseThrow());
		Assertions.assertTrue(first.getClaim("later").isEmpty());
		Assertions.assertEquals("replacement", second.getIssuer().orElseThrow());
		Assertions.assertEquals("replacement", second.getSubject().orElseThrow());
		Assertions.assertEquals(List.of("second"), second.getAudiences());
		Assertions.assertEquals(Instant.EPOCH.plusSeconds(1), second.getIssuedAt().orElseThrow());
		Assertions.assertEquals(Instant.EPOCH.plusSeconds(2), second.getExpiresAt().orElseThrow());
		Assertions.assertEquals(Instant.EPOCH.plusSeconds(3), second.getNotBefore().orElseThrow());
		Assertions.assertEquals("replacement", second.getJwtId().orElseThrow());
		Assertions.assertTrue(second.getClaim("later").isPresent());
		Assertions.assertThrows(UnsupportedOperationException.class, () -> first.getAudiences().add("another"));
		Assertions.assertThrows(UnsupportedOperationException.class, () -> first.getClaimNames().remove("original"));
		Assertions.assertThrows(UnsupportedOperationException.class,
				() -> first.toJsonObject().getMembers().put("new", JsonNull.defaultInstance()));
		Assertions.assertInstanceOf(JsonArray.class, first.getClaim("aud").orElseThrow());
	}

	@Test
	void numericDatesRoundTripExactlyAcrossTheEpochAndAtSupportedLimits() throws Exception {
		for (Instant instant : List.of(Instant.EPOCH, Instant.ofEpochSecond(0, 1), Instant.ofEpochSecond(-1, 999_999_999),
				Instant.parse("-9999-01-01T00:00:00Z"), Instant.parse("9999-12-31T23:59:59.999999999Z"))) {
			JwtClaimsSet claims = JwtClaimsSet.builder().issuedAt(instant).expiresAt(instant).notBefore(instant).build();
			for (String name : List.of("iat", "exp", "nbf"))
				Assertions.assertEquals(instant, JsonFields.numericDate(claims.toJsonObject(), name).orElseThrow());
		}
		JsonNumber negativeFraction = (JsonNumber) JwtClaimsSet.builder().issuedAt(Instant.ofEpochSecond(-1, 750_000_000))
				.build().getClaim("iat").orElseThrow();
		Assertions.assertEquals(new BigDecimal("-0.25"), negativeFraction.getValue());
		Assertions.assertEquals("0", JwtClaimsSet.builder().issuedAt(Instant.EPOCH).build().getClaim("iat")
				.orElseThrow().toJson());
	}

	@Test
	void datesOutsideTheSupportedRangeAreRejectedBeforeReplacingValues() {
		JwtClaimsSet.Builder builder = JwtClaimsSet.builder().issuedAt(Instant.EPOCH).expiresAt(Instant.EPOCH)
				.notBefore(Instant.EPOCH);
		for (Instant instant : List.of(Instant.MIN, Instant.MAX, Instant.parse("-9999-01-01T00:00:00Z").minusNanos(1),
				Instant.parse("+10000-01-01T00:00:00Z"))) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.issuedAt(instant));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.expiresAt(instant));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.notBefore(instant));
		}
		Assertions.assertEquals(Instant.EPOCH, builder.build().getIssuedAt().orElseThrow());
		Assertions.assertEquals(Instant.EPOCH, builder.build().getExpiresAt().orElseThrow());
		Assertions.assertEquals(Instant.EPOCH, builder.build().getNotBefore().orElseThrow());
	}

	@Test
	void customClaimsCannotBypassRegisteredSettersOrDuplicateAnyCustomName() {
		JwtClaimsSet.Builder builder = JwtClaimsSet.builder();
		for (String name : List.of("iss", "sub", "aud", "exp", "iat", "nbf", "jti")) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim(name, JsonNull.defaultInstance()));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim(name, "wrong"));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim(name, 1L));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim(name, BigDecimal.ONE));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim(name, true));
			Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claimNull(name));
		}
		builder.claimNull("custom");
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim("custom", "replacement"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claimNull("custom"));
		Assertions.assertSame(JsonNull.defaultInstance(), builder.build().getClaim("custom").orElseThrow());
		Assertions.assertEquals(JsonString.fromValue("case-sensitive"), builder.claim("ISS", "case-sensitive")
				.build().getClaim("ISS").orElseThrow());
	}

	@Test
	void malformedJsonAndEmptyAudiencesAreRejectedBeforeChangingTheBuilder() {
		JwtClaimsSet.Builder builder = JwtClaimsSet.builder().issuer("valid").subject("valid").jwtId("valid")
				.audiences(List.of("valid"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.issuer("\uD800"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.subject("\uDFFF"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.jwtId("\uD800"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.audiences(List.of("\uD800")));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.audiences(List.of()));
		Assertions.assertThrows(NullPointerException.class, () -> builder.audiences(Arrays.asList("valid", null)));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim("\uD800", "value"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim("name", "\uD800"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim("number", BigDecimal.ONE.scaleByPowerOfTen(100_001)));
		Assertions.assertEquals("valid", builder.build().getIssuer().orElseThrow());
		Assertions.assertEquals("valid", builder.build().getSubject().orElseThrow());
		Assertions.assertEquals("valid", builder.build().getJwtId().orElseThrow());
		Assertions.assertEquals(List.of("valid"), builder.build().getAudiences());
		Assertions.assertEquals(4, builder.build().getClaimNames().size());
	}

	@Test
	@SuppressWarnings("NullAway")
	void nullCustomInputsRequireExplicitJsonNull() {
		JwtClaimsSet.Builder builder = JwtClaimsSet.builder();
		Assertions.assertThrows(NullPointerException.class, () -> builder.claim(null, "value"));
		Assertions.assertThrows(NullPointerException.class, () -> builder.claim("name", (JsonValue) null));
		Assertions.assertThrows(NullPointerException.class, () -> builder.claim("name", (String) null));
		Assertions.assertThrows(NullPointerException.class, () -> builder.claim("name", (Long) null));
		Assertions.assertThrows(NullPointerException.class, () -> builder.claim("name", (BigDecimal) null));
		Assertions.assertThrows(NullPointerException.class, () -> builder.claim("name", (Boolean) null));
		Assertions.assertThrows(NullPointerException.class, () -> builder.claimNull(null));
		Assertions.assertThrows(NullPointerException.class, () -> builder.build().getClaim(null));
		Assertions.assertTrue(builder.build().getClaimNames().isEmpty());
	}

	@Test
	void claimsCanHoldLargeSharedJsonTreesWithoutExpandingThemAndStillEnforceDepth() {
		JsonValue value = JsonString.fromValue("leaf");
		for (int depth = 1; depth < 63; depth++)
			value = JsonArray.fromElements(List.of(value, value));
		JsonValue allowed = value;
		JwtClaimsSet claims = JwtClaimsSet.builder().claim("shared", allowed).build();
		Assertions.assertSame(allowed, claims.getClaim("shared").orElseThrow());
		JsonValue tooDeep = JsonArray.fromElements(List.of(allowed));
		JwtClaimsSet.Builder builder = JwtClaimsSet.builder();
		Assertions.assertThrows(IllegalArgumentException.class, () -> builder.claim("too-deep", tooDeep));
		Assertions.assertTrue(builder.build().getClaimNames().isEmpty());
	}

	@Test
	void claimsAndBuildersDoNotRenderNamesOrValues() {
		JwtClaimsSet.Builder builder = JwtClaimsSet.builder().issuer("private-issuer").subject("private-subject")
				.audiences(List.of("private-audience")).issuedAt(Instant.parse("2026-10-15T14:00:00Z"))
				.jwtId("private-id").claim("private-name", "private-value");
		Assertions.assertEquals("JwtClaimsSet.Builder{<redacted>}", builder.toString());
		Assertions.assertEquals("JwtClaimsSet{<redacted>}", builder.build().toString());
	}
}
