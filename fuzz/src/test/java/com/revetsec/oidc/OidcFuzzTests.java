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
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.jose.JoseObserver;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.oauth.OAuthException;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** M4 input boundaries. No network, core test helpers or production credentials. */
@ThreadSafe
public class OidcFuzzTests {
	private static final String ISSUER = "https://issuer.example";
	private static final String CLIENT = "client";
	private static final String SUBJECT = "subject";
	private static final String NONCE = "test-only-nonce";
	private static final String SECRET = "TEST-ONLY-HMAC-SECRET-0123456789abcdef";
	private static final Instant NOW = Instant.parse("2026-09-30T12:00:00Z");
	private static final long ORIGINAL_IAT = NOW.getEpochSecond() - 30;
	private static final IdTokenValidator VALIDATOR = validator();
	private static final OidcSessionReference ORIGINAL = original();

	/** Signs arbitrary claim bytes with JDK HMAC so mutation reaches the post-signature OIDC checks. */
	@FuzzTest(maxDuration = "5m")
	public void signedClaimsRespectInitialAndRefreshProfiles(byte[] input) {
		String token = sign(input);
		JsonObject claims = object(input, JsonLimits.jose(65_536));
		for (boolean refresh : List.of(false, true)) {
			boolean expected = token.length() <= 65_536 && acceptsClaims(claims, refresh);
			try {
				IdToken accepted = refresh
						? VALIDATOR.validateRefresh(token, ORIGINAL, "access", Set.of("urn:mfa"), null, SECRET)
						: VALIDATOR.validate(token, NONCE, "access", "code", Duration.ofSeconds(120),
								Set.of("urn:mfa"), null, SECRET);
				Assertions.assertTrue(expected, "accepted claims outside the independently evaluated profile");
				Assertions.assertEquals(claims, accepted.getClaims().toJsonObject());
			} catch (OidcValidationException rejected) {
				Assertions.assertFalse(expected, "rejected independently valid claims: " + rejected.getReason());
				fixedFailure(rejected);
			}
		}
	}

	/** Remote metadata must retain the exact issuer and required capabilities, without explicit defaults. */
	@FuzzTest(maxDuration = "5m")
	public void metadataRequiresExactIssuerAndCapabilities(byte[] input) {
		String text = new String(input, StandardCharsets.ISO_8859_1);
		try {
			OidcProviderMetadata accepted = OidcProviderMetadata.fromJson(ISSUER, text);
			Assertions.assertEquals(ISSUER, accepted.getIssuer());
			Assertions.assertTrue(accepted.getResponseTypesSupported().contains("code"));
			Assertions.assertTrue(accepted.getIdTokenSigningAlgValuesSupported().contains("RS256"));
			Assertions.assertFalse(accepted.getSubjectTypesSupported().isEmpty());
			Assertions.assertTrue(Set.of("public", "pairwise").containsAll(accepted.getSubjectTypesSupported()));
			Assertions.assertNotNull(accepted.getJwksUri());
			Assertions.assertEquals("OidcProviderMetadata{configuration=<redacted>}", accepted.toString());
		} catch (OAuthException rejected) {
			Assertions.assertNull(rejected.getCause());
			Assertions.assertEquals(0, rejected.getSuppressed().length);
		}
	}

	/** JSON UserInfo accepts exactly objects with an ASCII subject equal to the verified subject. */
	@FuzzTest(maxDuration = "5m")
	public void userInfoRequiresTheVerifiedSubject(byte[] input) {
		JsonObject claims = object(input, JsonLimits.protocolDocument(256 * 1_024));
		boolean expected = claims != null && SUBJECT.equals(text(claims.getMembers().get("sub")));
		try {
			Assertions.assertEquals(claims, UserInfoValidator.json(input.clone(), SUBJECT));
			Assertions.assertTrue(expected);
		} catch (OidcValidationException rejected) {
			Assertions.assertFalse(expected);
			Assertions.assertTrue(Set.of(OidcValidationException.Reason.USERINFO_MALFORMED,
					OidcValidationException.Reason.USERINFO_SUBJECT_MISMATCH).contains(rejected.getReason()));
			fixedFailure(rejected);
		}
	}

	/** A trusted-storage reference stays bounded, canonical and redacted, and retains no credentials. */
	@FuzzTest(maxDuration = "5m")
	public void sessionReferencesRoundTripWithoutCredentials(byte[] input) {
		try {
			OidcSessionReference reference = OidcSessionReference.fromSerializedForm(
					new String(input, StandardCharsets.ISO_8859_1));
			String serialized = reference.toSerializedForm();
			Assertions.assertTrue(serialized.getBytes(StandardCharsets.UTF_8).length <= 65_536);
			OidcSessionReference restored = OidcSessionReference.fromSerializedForm(serialized);
			Assertions.assertEquals(serialized, restored.toSerializedForm());
			Assertions.assertEquals(reference.getSessionId(), restored.getSessionId());
			Assertions.assertEquals("OidcSessionReference{session=<redacted>}", reference.toString());
			JsonObject envelope = object(serialized.getBytes(StandardCharsets.UTF_8), JsonLimits.protocolDocument(65_536));
			Assertions.assertNotNull(envelope);
			Assertions.assertEquals(Set.of("v", "client_id", "claims", "nonce_digest"), envelope.getMembers().keySet());
			Assertions.assertTrue(Set.of("iss", "sub", "aud", "iat", "azp", "auth_time", "sid")
					.containsAll(reference.continuityClaims().getMembers().keySet()));
		} catch (OidcValidationException rejected) {
			Assertions.assertEquals(OidcValidationException.Reason.SESSION_REFERENCE_INVALID, rejected.getReason());
			fixedFailure(rejected);
		}
	}

	// Uses the separately fuzzed JSON codec for syntax only. All profile rules below are evaluated here.
	private static JsonObject object(byte[] input, JsonLimits limits) {
		try { return JsonCodec.parse(input, limits) instanceof JsonObject value ? value : null; }
		catch (JsonParseException rejected) { return null; }
	}

	private static boolean acceptsClaims(JsonObject object, boolean refresh) {
		if (object == null) return false;
		Map<String, JsonValue> c = object.getMembers();
		if (!ISSUER.equals(text(c.get("iss"))) || !asciiSubject(text(c.get("sub")))) return false;
		for (String name : List.of("iss", "sub", "jti", "nonce", "acr", "sid", "azp"))
			if (c.containsKey(name) && !(c.get(name) instanceof JsonString)) return false;
		JsonValue aud = c.get("aud");
		if (!(aud instanceof JsonString s && CLIENT.equals(s.getValue()))
				&& !(aud instanceof JsonArray a && a.getElements().size() == 1
				&& CLIENT.equals(text(a.getElements().get(0))))) return false;
		if (c.containsKey("azp") && !CLIENT.equals(text(c.get("azp")))) return false;
		if (c.containsKey("cnf") || !"urn:mfa".equals(text(c.get("acr")))) return false;
		if (c.containsKey("amr") && (!(c.get("amr") instanceof JsonArray a)
				|| a.getElements().stream().anyMatch(v -> !(v instanceof JsonString)))) return false;
		Instant exp = date(c.get("exp")), iat = date(c.get("iat"));
		if (exp == null || iat == null || !NOW.isBefore(exp.plusSeconds(60)) || iat.isAfter(NOW.plusSeconds(60))) return false;
		if (c.containsKey("nbf")) {
			Instant nbf = date(c.get("nbf"));
			if (nbf == null || nbf.isAfter(NOW.plusSeconds(60))) return false;
		}
		Instant auth = date(c.get("auth_time"));
		if (c.containsKey("auth_time") && auth == null) return false;
		if (auth != null && auth.isAfter(NOW.plusSeconds(60))) return false;
		if (!hashMatches(c, "at_hash", "access")) return false;
		if (refresh) {
			return SUBJECT.equals(text(c.get("sub"))) && !c.containsKey("azp")
					&& !iat.isBefore(Instant.ofEpochSecond(ORIGINAL_IAT))
					&& (!c.containsKey("auth_time") || Instant.ofEpochSecond(ORIGINAL_IAT).equals(auth))
					&& (!c.containsKey("nonce") || NONCE.equals(text(c.get("nonce")))) && !c.containsKey("c_hash");
		}
		return NONCE.equals(text(c.get("nonce"))) && !iat.isBefore(NOW.minusSeconds(360))
				&& auth != null && !auth.isBefore(NOW.minusSeconds(180)) && hashMatches(c, "c_hash", "code");
	}

	private static String text(JsonValue value) { return value instanceof JsonString s ? s.getValue() : null; }
	private static boolean asciiSubject(String subject) {
		return subject != null && !subject.isEmpty() && subject.length() <= 255
				&& subject.chars().allMatch(c -> c <= 127);
	}

	// NumericDate range and nanosecond floor, written with decimal arithmetic rather than JsonFields.
	private static Instant date(JsonValue value) {
		if (!(value instanceof JsonNumber n)) return null;
		BigDecimal seconds = n.getValue();
		if (seconds.compareTo(BigDecimal.valueOf(-377_705_116_800L)) < 0
				|| seconds.compareTo(BigDecimal.valueOf(253_402_300_800L)) >= 0) return null;
		if (seconds.abs().compareTo(new BigDecimal("0.000000001")) < 0)
			return seconds.signum() < 0 ? Instant.ofEpochSecond(0, -1) : Instant.EPOCH;
		BigDecimal nanos = seconds.movePointRight(9).setScale(0, RoundingMode.FLOOR);
		BigDecimal whole = nanos.divideToIntegralValue(BigDecimal.valueOf(1_000_000_000));
		return Instant.ofEpochSecond(whole.longValueExact(), nanos.remainder(BigDecimal.valueOf(1_000_000_000)).longValueExact());
	}

	private static boolean hashMatches(Map<String, JsonValue> c, String name, String credential) {
		if (!c.containsKey(name)) return true;
		try {
			byte[] hash = MessageDigest.getInstance("SHA-256").digest(credential.getBytes(StandardCharsets.US_ASCII));
			return Base64.getUrlEncoder().withoutPadding().encodeToString(Arrays.copyOf(hash, 16)).equals(text(c.get(name)));
		} catch (GeneralSecurityException impossible) { throw new AssertionError(impossible); }
	}

	private static void fixedFailure(OidcValidationException rejected) {
		Assertions.assertNull(rejected.getCause());
		Assertions.assertEquals(0, rejected.getSuppressed().length);
		Assertions.assertEquals(OidcValidationException.fromReason(rejected.getReason()).getMessage(), rejected.getMessage());
	}

	private static String sign(byte[] claims) {
		String header = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.US_ASCII));
		String input = header + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(claims);
		try {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
			return input + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(input.getBytes(StandardCharsets.US_ASCII)));
		} catch (GeneralSecurityException impossible) { throw new AssertionError(impossible); }
	}

	private static IdTokenValidator validator() {
		try {
			// HMAC never reads this source. The template still requires a valid public-key source.
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
			RSAPublicKey key = (RSAPublicKey) generator.generateKeyPair().getPublic();
			byte[] modulus = key.getModulus().toByteArray();
			if (modulus[0] == 0) modulus = Arrays.copyOfRange(modulus, 1, modulus.length);
			String n = Base64.getUrlEncoder().withoutPadding().encodeToString(modulus);
			StaticJsonWebKeySource source = StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(
					"{\"keys\":[{\"kty\":\"RSA\",\"n\":\"" + n + "\",\"e\":\"AQAB\"}]}"));
			return new IdTokenValidator(ISSUER, CLIENT, source, Set.of(JwsAlgorithm.HS256), Set.of(), Set.of(),
					Duration.ofSeconds(60), Duration.ofSeconds(300), Clock.fixed(NOW, ZoneOffset.UTC), JoseObserver.disabledInstance(), true);
		} catch (GeneralSecurityException impossible) { throw new AssertionError(impossible); }
	}

	private static OidcSessionReference original() {
		String claims = "{\"iss\":\"" + ISSUER + "\",\"sub\":\"subject\",\"aud\":\"client\",\"iat\":" + ORIGINAL_IAT
				+ ",\"exp\":" + (NOW.getEpochSecond() + 300) + ",\"auth_time\":" + ORIGINAL_IAT
				+ ",\"nonce\":\"" + NONCE + "\",\"acr\":\"urn:mfa\"}";
		IdToken token = VALIDATOR.validate(sign(claims.getBytes(StandardCharsets.UTF_8)), NONCE, "access", "code",
				Duration.ofSeconds(120), Set.of("urn:mfa"), null, SECRET);
		return new OidcSessionReference(token, CLIENT);
	}
}
