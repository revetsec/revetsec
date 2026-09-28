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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.RevetsecException;
import com.revetsec.internal.Limits;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.jose.JwtValidatorFuzzSupport.KeySlot;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import static com.revetsec.jose.JwtValidatorFuzzSupport.AUDIENCE;
import static com.revetsec.jose.JwtValidatorFuzzSupport.ENTRA_ISSUER;
import static com.revetsec.jose.JwtValidatorFuzzSupport.ENTRA_TEMPLATE;
import static com.revetsec.jose.JwtValidatorFuzzSupport.ENTRA_TENANT;
import static com.revetsec.jose.JwtValidatorFuzzSupport.FIXTURE_KEY_SET_RESOURCE;
import static com.revetsec.jose.JwtValidatorFuzzSupport.ISSUER;
import static com.revetsec.jose.JwtValidatorFuzzSupport.KEY_SLOTS;
import static com.revetsec.jose.JwtValidatorFuzzSupport.NOW;
import static com.revetsec.jose.JwtValidatorFuzzSupport.REQUIRED_CLAIMS;
import static com.revetsec.jose.JwtValidatorFuzzSupport.UPPERCASE_ENTRA_ISSUER;
import static com.revetsec.jose.JwtValidatorFuzzSupport.encodeBase64Url;

/**
 * Coverage-guided checks for {@link JwtValidator} end to end over a {@link StaticJsonWebKeySource} (M2 plan, "JOSE
 * semantics" steps 1 to 15, "Key selection" and M2-11; exit criteria 1, 4 to 6, 9 and 10; INV-J1 to INV-J7, INV-G1,
 * INV-G6, INV-C6).
 * <p>
 * The central property: a token is accepted only if the JDK's own verifier for its algorithm accepts its signature
 * with the one key the selection rules pick: {@code SHAxxxwithRSA}, {@code RSASSA-PSS} with RFC 7518 section 3.5's
 * fixed parameters, the fixed-length {@code SHAxxxwithECDSAinP1363Format} (after RFC 7518 section 3.4's exact length
 * and range, because that engine accepts short signatures), or {@code Ed25519} (after RFC 8032's 64 octets, because
 * JDK 17 accepts 65). The oracle goes further and predicts every outcome: it runs the plan's fifteen steps in order,
 * with its own compact splitter and base64url decoder, header rules, key selection (kid, family, curve, the key's
 * {@code alg} with the {@code EdDSA}/{@code Ed25519} alias, one RSA algorithm for a key without {@code alg}), JDK
 * verification, registered-claim typing with its own NumericDate conversion, and the claim rules, the Entra
 * {@code {tenantid}} template included. It parses JSON text with {@link JsonCodec} under the JOSE profile, which has
 * its own fuzz target. An accepted token must carry exactly the oracle's claims, and a rejected one the oracle's
 * reason, in the reason's exception class, with its fixed message, no cause, and the same instance reported to the
 * observer.
 * <p>
 * Every token is checked by three validators over the same keys. The first is for
 * {@value JwtValidatorFuzzSupport#ISSUER}: it allows the eleven asymmetric algorithms, expects
 * {@value JwtValidatorFuzzSupport#AUDIENCE}, requires {@code sub} and {@code client_id}, and allows 60 seconds of skew.
 * The second is for an Entra tenant ({@link JwtValidatorFuzzSupport#ENTRA_ISSUER}): it allows {@code RS256},
 * {@code ES256} and {@code EdDSA}, accepts any audience, requires {@code typ}, allows no skew and caps tokens at 8,192
 * characters. The third is for the same tenant spelled in upper case
 * ({@link JwtValidatorFuzzSupport#UPPERCASE_ENTRA_ISSUER}), with the defaults and any audience; the Entra template must
 * never serve it. All three read the time from a clock fixed at {@link JwtValidatorFuzzSupport#NOW}.
 * <p>
 * The first target reads raw tokens and verifies with the TEST ONLY fixture keys' public halves
 * ({@link #FIXTURE_KEY_SET}); its seeds are tokens signed with those keys, Wycheproof's JWS strings and hand-written
 * negatives. The second signs what its input describes with fuzz-only keys generated when the class loads, so that
 * fuzzed headers and claims reach the steps after the signature.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class JwtValidatorFuzzTests {
	/**
	 * {@link JwtValidatorFuzzSupport#KEY_SLOTS} over the TEST ONLY fixture keys' public halves (and, where a slot says
	 * so, their certificates), as {@code com.revetsec.FuzzSeedGenerator} writes it from
	 * {@code src/test/resources/fixtures/} into {@link JwtValidatorFuzzSupport#FIXTURE_KEY_SET_RESOURCE}.
	 * {@code FuzzSeedProvenanceTests} checks that the resource is still what the generator makes from the fixtures.
	 */
	public static final String FIXTURE_KEY_SET = resource(FIXTURE_KEY_SET_RESOURCE);

	private static final String BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	private static final Pattern MEDIA_TYPE = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+");
	private static final Pattern LOWERCASE_GUID = Pattern.compile(
			"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
	private static final BigDecimal EARLIEST_NUMERIC_DATE = BigDecimal.valueOf(
			LocalDateTime.of(-9_999, 1, 1, 0, 0).toEpochSecond(ZoneOffset.UTC));
	private static final BigDecimal END_NUMERIC_DATE = BigDecimal.valueOf(
			LocalDateTime.of(10_000, 1, 1, 0, 0).toEpochSecond(ZoneOffset.UTC));
	private static final BigInteger NANOSECONDS_PER_SECOND = BigInteger.valueOf(1_000_000_000L);

	/**
	 * RFC 7518 section 3.1, RFC 8037 section 3.1 and RFC 9864: every {@code alg} Revetsec knows, spelled exactly.
	 */
	private static final Map<String, JwsAlgorithm> WIRE_VALUES = Map.ofEntries(Map.entry("RS256", JwsAlgorithm.RS256),
			Map.entry("RS384", JwsAlgorithm.RS384), Map.entry("RS512", JwsAlgorithm.RS512),
			Map.entry("PS256", JwsAlgorithm.PS256), Map.entry("PS384", JwsAlgorithm.PS384),
			Map.entry("PS512", JwsAlgorithm.PS512), Map.entry("ES256", JwsAlgorithm.ES256),
			Map.entry("ES384", JwsAlgorithm.ES384), Map.entry("ES512", JwsAlgorithm.ES512),
			Map.entry("Ed25519", JwsAlgorithm.ED25519), Map.entry("EdDSA", JwsAlgorithm.EDDSA),
			Map.entry("HS256", JwsAlgorithm.HS256), Map.entry("HS384", JwsAlgorithm.HS384),
			Map.entry("HS512", JwsAlgorithm.HS512));
	private static final Map<String, ECParameterSpec> CURVES = Map.of("P-256", curve("secp256r1"), "P-384",
			curve("secp384r1"), "P-521", curve("secp521r1"));

	private static final List<ValidatorCase> FIXTURE_VALIDATORS = validators(FIXTURE_KEY_SET);
	private static final Signers SIGNERS = new Signers();
	private static final List<ValidatorCase> SIGNED_VALIDATORS = validators(SIGNERS.keySet);

	/**
	 * Every token, under the three validators over the fixture keys, gets the oracle's outcome: accepted only when the
	 * JDK's verifier accepts its signature with the selected key and every header and claim rule passes, with exactly
	 * the oracle's claims; otherwise the reason of the first failed step (M2 plan, "JOSE semantics").
	 *
	 * @param input the fuzzed token, read as ISO-8859-1 so that every byte is one character
	 */
	@FuzzTest(maxDuration = "5m")
	public void validateAcceptsOnlyWhatTheJdkVerifiersAccept(byte[] input) {
		String token = new String(input, StandardCharsets.ISO_8859_1);

		for (ValidatorCase validator : FIXTURE_VALIDATORS)
			requireAgreement(validator, token);
	}

	/**
	 * Tokens whose header and claims the input spells out, signed here with fuzz-only keys and then optionally damaged,
	 * get the oracle's outcome under the three validators. The input is the header's JSON text, a NUL, the payload, a
	 * NUL, then control octets: the signing key's slot, the signing algorithm among those the key can make, a damage
	 * kind and its parameter (see {@link Signers#token(byte[])}). Without a NUL, the payload is a set of claims the Entra
	 * validator accepts; without control octets, the header's {@code kid} and {@code alg} choose the key and the
	 * algorithm, so the signature verifies whatever the fuzzer does to the header and payload.
	 *
	 * @param input the fuzzed signing program
	 */
	@FuzzTest(maxDuration = "5m")
	public void signedTokensAreJudgedLikeTheOracleWhateverTheirHeaderAndClaims(byte[] input) {
		String token = SIGNERS.token(input);

		for (ValidatorCase validator : SIGNED_VALIDATORS)
			requireAgreement(validator, token);
	}

	private static void requireAgreement(ValidatorCase validator, String token) {
		Outcome expected = expected(validator, token);
		RecordingObserver.reset();
		Jwt jwt;

		try {
			jwt = validator.validator.validate(token);
		} catch (JoseException exception) {
			Assertions.assertEquals(expected.failure, exception.getReason(), () -> validator.name
					+ " rejected the token with the wrong reason (the oracle expects " + expected.failure + ")");
			requireFixedShape(exception);
			Assertions.assertSame(exception, RecordingObserver.failure(), "the observer got another failure instance");
			Assertions.assertEquals(0, RecordingObserver.validations(), "a failed validation was reported as valid");
			Assertions.assertEquals(validator.config.audiences == null ? 1 : 0, RecordingObserver.anyAudience(),
					"didAcceptAnyAudience did not fire exactly when any audience is accepted");
			return;
		}

		Assertions.assertNull(expected.failure, () -> validator.name + " accepted a token the oracle rejects with "
				+ expected.failure);
		Assertions.assertEquals(1, RecordingObserver.validations(), "a validation was not reported exactly once");
		Assertions.assertNull(RecordingObserver.failure(), "a valid token was reported as a failure");
		Assertions.assertEquals(validator.config.audiences == null ? 1 : 0, RecordingObserver.anyAudience(),
				"didAcceptAnyAudience did not fire exactly when any audience is accepted");

		Assertions.assertEquals(expected.algorithm, jwt.getAlgorithm(), "getAlgorithm");
		Assertions.assertEquals(Optional.ofNullable(expected.keyId), jwt.getKeyId(), "getKeyId");
		Assertions.assertEquals(Optional.ofNullable(expected.type), jwt.getType(), "getType");
		Assertions.assertEquals(token, jwt.toCompactSerialization(), "toCompactSerialization");
		Assertions.assertEquals("Jwt{algorithm=" + expected.algorithm.getWireValue() + "}", jwt.toString(),
				"Jwt.toString shows more than the algorithm");

		JwtClaims claims = jwt.getClaims();
		Claims registered = expected.claims;
		Assertions.assertEquals(Optional.ofNullable(registered.issuer), claims.getIssuer(), "getIssuer");
		Assertions.assertEquals(Optional.ofNullable(registered.subject), claims.getSubject(), "getSubject");
		Assertions.assertEquals(registered.audiences, claims.getAudiences(), "getAudiences");
		Assertions.assertEquals(Optional.ofNullable(registered.expiresAt), claims.getExpiresAt(), "getExpiresAt");
		Assertions.assertEquals(Optional.ofNullable(registered.issuedAt), claims.getIssuedAt(), "getIssuedAt");
		Assertions.assertEquals(Optional.ofNullable(registered.notBefore), claims.getNotBefore(), "getNotBefore");
		Assertions.assertEquals(Optional.ofNullable(registered.jwtId), claims.getJwtId(), "getJwtId");
		Assertions.assertEquals(registered.object.getMembers().keySet(), claims.getClaimNames(), "getClaimNames");
		Assertions.assertEquals(registered.object, claims.toJsonObject(), "toJsonObject");

		for (Map.Entry<String, JsonValue> member : registered.object.getMembers().entrySet())
			Assertions.assertEquals(Optional.of(member.getValue()), claims.getClaim(member.getKey()), "getClaim");

		Assertions.assertEquals("JwtClaims{<redacted>}", claims.toString(), "JwtClaims.toString is not redacted");
	}

	/**
	 * Each rejection is the class its reason belongs to, with the reason's category and fixed message, no cause, and
	 * never transient (M2-2).
	 */
	private static void requireFixedShape(JoseException exception) {
		JoseException.Reason reason = exception.getReason();
		Class<? extends JoseException> expectedClass = switch (reason.category()) {
			case MALFORMED_INPUT -> MalformedJoseInputException.class;
			case UNSUPPORTED -> UnsupportedJoseFeatureException.class;
			default -> JwtValidationException.class;
		};

		Assertions.assertEquals(expectedClass, exception.getClass(), "the reason's exception class");
		Assertions.assertEquals(reason.category(), exception.getCategory(), "the reason's category");
		Assertions.assertEquals(reason.message(), exception.getMessage(), "the reason's fixed message");
		Assertions.assertNull(exception.getCause(), "a JOSE exception has a cause");
		Assertions.assertFalse(exception.isTransient(), "a JOSE exception is transient");
	}

	/**
	 * The oracle: the plan's steps 1 to 15, in order.
	 */
	private static Outcome expected(ValidatorCase validator, String token) {
		Config config = validator.config;

		// Steps 1 to 3.
		if (token.length() > config.maximumLength)
			return Outcome.failing(JoseException.Reason.TOKEN_TOO_LARGE);

		if (!token.isEmpty() && token.charAt(0) == '{')
			return Outcome.failing(JoseException.Reason.JSON_SERIALIZATION);

		for (int index = 0; index < token.length(); ++index)
			if (token.charAt(index) != '.' && BASE64URL_ALPHABET.indexOf(token.charAt(index)) < 0)
				return Outcome.failing(JoseException.Reason.TOKEN_SYNTAX);

		String[] segments = token.split("\\.", -1);

		if (segments.length == 5)
			return Outcome.failing(JoseException.Reason.ENCRYPTED_TOKEN);

		if (segments.length != 3 || segments[0].isEmpty())
			return Outcome.failing(JoseException.Reason.TOKEN_SYNTAX);

		byte[] header = decodeBase64Url(segments[0]);
		byte[] payload = decodeBase64Url(segments[1]);
		byte[] signature = decodeBase64Url(segments[2]);

		if (header == null || payload == null || signature == null)
			return Outcome.failing(JoseException.Reason.TOKEN_SYNTAX);

		// Step 4.
		JsonObject headerObject = jsonObject(header, config.maximumLength);

		if (headerObject == null)
			return Outcome.failing(JoseException.Reason.HEADER);

		Map<String, JsonValue> members = headerObject.getMembers();

		if (!(members.get("alg") instanceof JsonString alg))
			return Outcome.failing(JoseException.Reason.HEADER);

		JwsAlgorithm algorithm = WIRE_VALUES.get(alg.getValue());

		if (algorithm == null || !config.algorithms.contains(algorithm))
			return Outcome.failing(JoseException.Reason.ALGORITHM_NOT_ALLOWED);

		if (members.containsKey("crit"))
			return Outcome.failing(JoseException.Reason.CRITICAL_HEADER);

		if (members.containsKey("b64"))
			return Outcome.failing(JoseException.Reason.UNENCODED_PAYLOAD);

		if (members.containsKey("zip"))
			return Outcome.failing(JoseException.Reason.COMPRESSED_PAYLOAD);

		if (members.containsKey("jwk") || members.containsKey("jku") || members.containsKey("x5u"))
			return Outcome.failing(JoseException.Reason.UNTRUSTED_KEY_REFERENCE);

		JsonValue typ = members.get("typ");
		String type = null;

		if (typ == null) {
			if (config.typeRequired)
				return Outcome.failing(JoseException.Reason.INVALID_TYPE);
		} else if (typ instanceof JsonString typString
				&& normalizedType(typString.getValue()).map(config.types::contains).orElse(false)) {
			type = typString.getValue();
		} else {
			return Outcome.failing(JoseException.Reason.INVALID_TYPE);
		}

		if (members.containsKey("cty"))
			return Outcome.failing(JoseException.Reason.NESTED_TOKEN);

		JsonValue kid = members.get("kid");
		String keyId = null;

		if (kid != null) {
			if (!(kid instanceof JsonString kidString) || kidString.getValue().isEmpty()
					|| kidString.getValue().length() > 256)
				return Outcome.failing(JoseException.Reason.HEADER);

			keyId = kidString.getValue();
		}

		// Step 5.
		if (!hasKeyFreeShape(algorithm, signature))
			return Outcome.failing(JoseException.Reason.SIGNATURE_MALFORMED);

		// Step 6.
		List<OracleKey> candidates = new ArrayList<>();
		boolean keyIdMatched = false;

		for (OracleKey key : validator.keys) {
			if (keyId != null) {
				if (!keyId.equals(key.keyId))
					continue;

				keyIdMatched = true;
			}

			if (fits(key, algorithm, config.algorithms))
				candidates.add(key);
		}

		if (candidates.size() > 1)
			return Outcome.failing(JoseException.Reason.AMBIGUOUS_KEY);

		if (candidates.isEmpty())
			return Outcome.failing(keyIdMatched ? JoseException.Reason.KEY_ALGORITHM_MISMATCH
					: JoseException.Reason.UNKNOWN_KEY);

		OracleKey key = candidates.get(0);

		// Step 7.
		if (key.publicKey instanceof RSAPublicKey rsa && signature.length != (rsa.getModulus().bitLength() + 7) / 8)
			return Outcome.failing(JoseException.Reason.SIGNATURE_MALFORMED);

		if (!jdkVerifies(algorithm, key.publicKey, (segments[0] + "." + segments[1]).getBytes(StandardCharsets.US_ASCII),
				signature))
			return Outcome.failing(JoseException.Reason.SIGNATURE_MISMATCH);

		// Steps 8 and 9.
		Claims claims = Claims.read(payload, config.maximumLength);

		if (claims == null)
			return Outcome.failing(JoseException.Reason.CLAIMS);

		// Step 10.
		if (claims.issuer == null)
			return Outcome.failing(JoseException.Reason.MISSING_CLAIM);

		if (!claims.issuer.equals(config.issuer))
			return Outcome.failing(JoseException.Reason.ISSUER_MISMATCH);

		// M2-11: a key whose issuer member is the template is bound only through a tenant ID, never literally.
		if (key.issuer != null && !(key.issuer.equals(ENTRA_TEMPLATE) ? isEntraTemplateMatch(claims)
				: key.issuer.equals(claims.issuer)))
			return Outcome.failing(JoseException.Reason.KEY_ISSUER_MISMATCH);

		// Step 11.
		if (config.audiences != null) {
			if (claims.audiences.isEmpty())
				return Outcome.failing(JoseException.Reason.MISSING_CLAIM);

			if (claims.audiences.stream().noneMatch(config.audiences::contains))
				return Outcome.failing(JoseException.Reason.AUDIENCE_MISMATCH);
		}

		// Step 12.
		if (claims.expiresAt == null)
			return Outcome.failing(JoseException.Reason.MISSING_CLAIM);

		if (!NOW.isBefore(claims.expiresAt.plus(config.skew)))
			return Outcome.failing(JoseException.Reason.EXPIRED);

		if (claims.issuedAt != null && claims.issuedAt.isAfter(NOW.plus(config.skew)))
			return Outcome.failing(JoseException.Reason.ISSUED_IN_FUTURE);

		if (claims.notBefore != null && NOW.isBefore(claims.notBefore.minus(config.skew)))
			return Outcome.failing(JoseException.Reason.NOT_YET_VALID);

		// Step 13.
		for (String name : config.requiredClaims) {
			JsonValue value = claims.object.getMembers().get(name);

			if (value == null || value instanceof JsonNull)
				return Outcome.failing(JoseException.Reason.MISSING_CLAIM);
		}

		// Step 14.
		if (claims.object.getMembers().containsKey("cnf"))
			return Outcome.failing(JoseException.Reason.CONFIRMATION_NOT_VERIFIED);

		return new Outcome(null, algorithm, keyId, type, claims);
	}

	/**
	 * "Key selection": the key type and curve fit the algorithm; a key's {@code alg} must be the token's, except the
	 * {@code EdDSA}/{@code Ed25519} alias on an Ed25519 key, Revetsec's own, where both name EdDSA with the Ed25519
	 * parameter set (RFC 9864 sections 2.2 and 5, read 2026-09-28); an RSA key without {@code alg} fits only while the
	 * allowed set holds exactly one RSA algorithm, the token's (RFC 8725 section 3.1, read 2026-09-28).
	 */
	private static boolean fits(OracleKey key, JwsAlgorithm algorithm, Set<JwsAlgorithm> allowed) {
		String keyType = switch (algorithm) {
			case RS256, RS384, RS512, PS256, PS384, PS512 -> "RSA";
			case ES256, ES384, ES512 -> "EC";
			case ED25519, EDDSA -> "OKP";
			default -> null;
		};

		if (keyType == null || !keyType.equals(key.keyType))
			return false;

		String curve = switch (algorithm) {
			case ES256 -> "P-256";
			case ES384 -> "P-384";
			case ES512 -> "P-521";
			case ED25519, EDDSA -> "Ed25519";
			default -> null;
		};

		if (curve != null && !curve.equals(key.curve))
			return false;

		if (key.algorithm != null)
			return key.algorithm == algorithm || (EnumSet.of(JwsAlgorithm.EDDSA, JwsAlgorithm.ED25519).contains(algorithm)
					&& EnumSet.of(JwsAlgorithm.EDDSA, JwsAlgorithm.ED25519).contains(key.algorithm));

		if (!keyType.equals("RSA"))
			return true;

		return allowed.stream().filter(allowedAlgorithm -> allowedAlgorithm.name().startsWith("RS")
				|| allowedAlgorithm.name().startsWith("PS")).toList().equals(List.of(algorithm));
	}

	/**
	 * Step 5: RSA signatures of 256 to 2,048 octets; ECDSA's of twice the coordinate length with {@code r} and
	 * {@code s} in {@code [1, n - 1]}; Ed25519's of 64 octets. The validators allow no HMAC algorithm.
	 */
	private static boolean hasKeyFreeShape(JwsAlgorithm algorithm, byte[] signature) {
		return switch (algorithm) {
			case RS256, RS384, RS512, PS256, PS384, PS512 -> signature.length >= 256 && signature.length <= 2_048;
			case ES256 -> hasEcdsaShape(signature, CURVES.get("P-256"));
			case ES384 -> hasEcdsaShape(signature, CURVES.get("P-384"));
			case ES512 -> hasEcdsaShape(signature, CURVES.get("P-521"));
			case ED25519, EDDSA -> signature.length == 64;
			default -> false;
		};
	}

	private static boolean hasEcdsaShape(byte[] signature, ECParameterSpec curve) {
		int length = (((ECFieldFp) curve.getCurve().getField()).getP().bitLength() + 7) / 8;

		if (signature.length != 2 * length)
			return false;

		BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, length));
		BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, length, 2 * length));
		return r.signum() > 0 && r.compareTo(curve.getOrder()) < 0 && s.signum() > 0 && s.compareTo(curve.getOrder()) < 0;
	}

	/**
	 * The JDK's own verifier for {@code algorithm}; any exception is a refusal.
	 */
	private static boolean jdkVerifies(JwsAlgorithm algorithm, PublicKey key, byte[] signingInput, byte[] signature) {
		try {
			Signature verifier = switch (algorithm) {
				case RS256 -> Signature.getInstance("SHA256withRSA");
				case RS384 -> Signature.getInstance("SHA384withRSA");
				case RS512 -> Signature.getInstance("SHA512withRSA");
				case PS256, PS384, PS512 -> Signature.getInstance("RSASSA-PSS");
				case ES256 -> Signature.getInstance("SHA256withECDSAinP1363Format");
				case ES384 -> Signature.getInstance("SHA384withECDSAinP1363Format");
				case ES512 -> Signature.getInstance("SHA512withECDSAinP1363Format");
				default -> Signature.getInstance("Ed25519");
			};

			verifier.initVerify(key);

			switch (algorithm) {
				case PS256 -> verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
				case PS384 -> verifier.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1));
				case PS512 -> verifier.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
				default -> {
					// No parameters.
				}
			}

			verifier.update(signingInput);
			return verifier.verify(signature);
		} catch (GeneralSecurityException | RuntimeException e) {
			return false;
		}
	}

	/**
	 * M2-11, for a key whose issuer member is Entra's exact template: a lowercase GUID {@code tid}, and {@code iss}
	 * equal to the template with it.
	 */
	private static boolean isEntraTemplateMatch(Claims claims) {
		return claims.object.getMembers().get("tid") instanceof JsonString tid
				&& LOWERCASE_GUID.matcher(tid.getValue()).matches()
				&& claims.issuer.equals("https://login.microsoftonline.com/" + tid.getValue() + "/v2.0");
	}

	/**
	 * RFC 7515 section 4.1.9 (read 2026-09-28): {@code application/} implied without a {@code /}; a
	 * {@code type/subtype} pair of RFC 9110 tokens, compared with ASCII letters folded.
	 */
	private static Optional<String> normalizedType(String type) {
		String mediaType = type.contains("/") ? type : "application/" + type;

		if (!MEDIA_TYPE.matcher(mediaType).matches())
			return Optional.empty();

		StringBuilder folded = new StringBuilder();

		for (int index = 0; index < mediaType.length(); ++index) {
			char c = mediaType.charAt(index);
			folded.append(c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c);
		}

		return Optional.of(folded.toString());
	}

	private static JsonObject jsonObject(byte[] text, int maximumLength) {
		try {
			return JsonCodec.parse(text, JsonLimits.jose(maximumLength)) instanceof JsonObject object ? object : null;
		} catch (JsonParseException e) {
			return null;
		}
	}

	/**
	 * RFC 4648 section 5 without padding, canonical; {@code null} for anything else.
	 */
	private static byte[] decodeBase64Url(String segment) {
		if (segment.length() % 4 == 1)
			return null;

		ByteArrayOutputStream octets = new ByteArrayOutputStream();
		int buffer = 0;
		int bits = 0;

		for (int index = 0; index < segment.length(); ++index) {
			int value = BASE64URL_ALPHABET.indexOf(segment.charAt(index));

			if (value < 0)
				return null;

			buffer = (buffer << 6) | value;
			bits += 6;

			if (bits >= 8) {
				bits -= 8;
				octets.write((buffer >> bits) & 0xFF);
				buffer &= (1 << bits) - 1;
			}
		}

		return buffer == 0 ? octets.toByteArray() : null;
	}

	private static String resource(String name) {
		try (InputStream stream = JwtValidatorFuzzTests.class.getResourceAsStream(name)) {
			if (stream == null)
				throw new IllegalStateException("No resource " + name + " next to " + JwtValidatorFuzzTests.class.getName());

			return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	private static ECParameterSpec curve(String name) {
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec(name));
			return parameters.getParameterSpec(ECParameterSpec.class);
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("The JDK does not name " + name, e);
		}
	}

	/**
	 * The three validators over a key set, with the oracle's own reading of its keys.
	 */
	private static List<ValidatorCase> validators(String keySet) {
		JsonWebKeySet set = JsonWebKeySet.fromJson(keySet);

		if (set.getKeys().size() != KEY_SLOTS.size())
			throw new IllegalStateException("The fuzz key set has " + set.getKeys().size() + " usable keys, not "
					+ KEY_SLOTS.size());

		StaticJsonWebKeySource source = StaticJsonWebKeySource.fromJsonWebKeySet(set);
		List<OracleKey> keys = OracleKey.readAll(keySet);
		Set<JwsAlgorithm> asymmetric = EnumSet.complementOf(EnumSet.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384,
				JwsAlgorithm.HS512));
		Set<JwsAlgorithm> entraAlgorithms = EnumSet.of(JwsAlgorithm.RS256, JwsAlgorithm.ES256, JwsAlgorithm.EDDSA);

		JwtValidator issuerValidator = JwtValidator.withIssuer(ISSUER).jsonWebKeySource(source)
				.expectedAudiences(Set.of(AUDIENCE)).allowedAlgorithms(asymmetric).requiredClaims(REQUIRED_CLAIMS)
				.clock(Clock.fixed(NOW, ZoneOffset.UTC)).observer(new RecordingObserver()).build();
		JwtValidator entraValidator = JwtValidator.withIssuer(ENTRA_ISSUER).jsonWebKeySource(source)
				.acceptAnyAudience(true).allowedAlgorithms(entraAlgorithms).allowedTypes(Set.of("JWT", "at+jwt"))
				.typeRequired(true).clockSkew(Duration.ZERO).maximumTokenLength(8_192).clock(Clock.fixed(NOW, ZoneOffset.UTC))
				.observer(new RecordingObserver()).build();
		JwtValidator uppercaseEntraValidator = JwtValidator.withIssuer(UPPERCASE_ENTRA_ISSUER).jsonWebKeySource(source)
				.acceptAnyAudience(true).clock(Clock.fixed(NOW, ZoneOffset.UTC)).observer(new RecordingObserver()).build();

		return List.of(
				new ValidatorCase("the issuer validator", issuerValidator, new Config(ISSUER, Set.of(AUDIENCE), asymmetric,
						Set.of("application/jwt"), false, REQUIRED_CLAIMS, Limits.JOSE_CLOCK_SKEW.getDefaultDuration(),
						Limits.COMPACT_JWT_SIZE.getDefaultIntValue()), keys),
				new ValidatorCase("the Entra validator", entraValidator, new Config(ENTRA_ISSUER, null, entraAlgorithms,
						Set.of("application/jwt", "application/at+jwt"), true, Set.of(), Duration.ZERO, 8_192), keys),
				new ValidatorCase("the uppercase-tenant validator", uppercaseEntraValidator, new Config(UPPERCASE_ENTRA_ISSUER,
						null, EnumSet.of(JwsAlgorithm.RS256), Set.of("application/jwt"), false, Set.of(),
						Limits.JOSE_CLOCK_SKEW.getDefaultDuration(), Limits.COMPACT_JWT_SIZE.getDefaultIntValue()), keys));
	}

	/**
	 * A validator's settings, as the oracle reads them.
	 */
	@Immutable
	private static final class Config {
		private final String issuer;
		private final Set<String> audiences;
		private final Set<JwsAlgorithm> algorithms;
		private final Set<String> types;
		private final boolean typeRequired;
		private final Set<String> requiredClaims;
		private final Duration skew;
		private final int maximumLength;

		private Config(String issuer, Set<String> audiences, Set<JwsAlgorithm> algorithms, Set<String> types,
									 boolean typeRequired, Set<String> requiredClaims, Duration skew, int maximumLength) {
			this.issuer = issuer;
			this.audiences = audiences;
			this.algorithms = Set.copyOf(algorithms);
			this.types = Set.copyOf(types);
			this.typeRequired = typeRequired;
			this.requiredClaims = Set.copyOf(requiredClaims);
			this.skew = skew;
			this.maximumLength = maximumLength;
		}
	}

	/**
	 * A validator under test, its settings and the oracle's keys.
	 */
	@Immutable
	private static final class ValidatorCase {
		private final String name;
		private final JwtValidator validator;
		private final Config config;
		private final List<OracleKey> keys;

		private ValidatorCase(String name, JwtValidator validator, Config config, List<OracleKey> keys) {
			this.name = name;
			this.validator = validator;
			this.config = config;
			this.keys = List.copyOf(keys);
		}
	}

	/**
	 * A key as the oracle reads it from the key set's JSON, with its JCA key built directly from the members.
	 */
	@Immutable
	private static final class OracleKey {
		private final String keyId;
		private final String keyType;
		private final String curve;
		private final JwsAlgorithm algorithm;
		private final String issuer;
		private final PublicKey publicKey;

		private OracleKey(String keyId, String keyType, String curve, JwsAlgorithm algorithm, String issuer,
											PublicKey publicKey) {
			this.keyId = keyId;
			this.keyType = keyType;
			this.curve = curve;
			this.algorithm = algorithm;
			this.issuer = issuer;
			this.publicKey = publicKey;
		}

		private static List<OracleKey> readAll(String keySet) {
			try {
				JsonObject document = (JsonObject) JsonCodec.parse(keySet.getBytes(StandardCharsets.UTF_8),
						JsonLimits.protocolDocument((int) Limits.JWKS_RESPONSE_BODY_SIZE.getCap()));
				List<OracleKey> keys = new ArrayList<>();

				for (JsonValue element : ((JsonArray) document.getMembers().get("keys")).getElements())
					keys.add(read(((JsonObject) element).getMembers()));

				return List.copyOf(keys);
			} catch (JsonParseException | GeneralSecurityException e) {
				throw new IllegalStateException("The fuzz key set does not parse", e);
			}
		}

		private static OracleKey read(Map<String, JsonValue> members) throws GeneralSecurityException {
			String keyType = string(members, "kty");
			String curve = members.containsKey("crv") ? string(members, "crv") : null;
			PublicKey key = switch (keyType) {
				case "RSA" -> KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(integer(members, "n"),
						integer(members, "e")));
				case "EC" -> KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(integer(members, "x"),
						integer(members, "y")), CURVES.get(curve)));
				default -> {
					byte[] encoded = decodeBase64Url(string(members, "x"));
					boolean xOdd = (encoded[31] & 0x80) != 0;
					byte[] bigEndian = new byte[32];

					for (int index = 0; index < 32; ++index)
						bigEndian[index] = encoded[31 - index];

					bigEndian[0] &= 0x7F;
					yield KeyFactory.getInstance("Ed25519").generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519,
							new EdECPoint(xOdd, new BigInteger(1, bigEndian))));
				}
			};

			return new OracleKey(members.containsKey("kid") ? string(members, "kid") : null, keyType, curve,
					members.containsKey("alg") ? WIRE_VALUES.get(string(members, "alg")) : null,
					members.containsKey("issuer") ? string(members, "issuer") : null, key);
		}

		private static String string(Map<String, JsonValue> members, String name) {
			return ((JsonString) members.get(name)).getValue();
		}

		private static BigInteger integer(Map<String, JsonValue> members, String name) {
			return new BigInteger(1, decodeBase64Url(string(members, name)));
		}
	}

	/**
	 * RFC 7519 section 4.1's registered claims, typed: {@code iss}, {@code sub} and {@code jti} strings; {@code aud} a
	 * string or a non-empty array of strings; {@code exp}, {@code iat} and {@code nbf} NumericDates (numbers from year
	 * -9999 to 9999, fractions rounded down to the nanosecond). JSON {@code null} or any other type is malformed.
	 */
	@Immutable
	private static final class Claims {
		private final JsonObject object;
		private final String issuer;
		private final String subject;
		private final List<String> audiences;
		private final Instant expiresAt;
		private final Instant issuedAt;
		private final Instant notBefore;
		private final String jwtId;

		private Claims(JsonObject object, String issuer, String subject, List<String> audiences, Instant expiresAt,
									 Instant issuedAt, Instant notBefore, String jwtId) {
			this.object = object;
			this.issuer = issuer;
			this.subject = subject;
			this.audiences = List.copyOf(audiences);
			this.expiresAt = expiresAt;
			this.issuedAt = issuedAt;
			this.notBefore = notBefore;
			this.jwtId = jwtId;
		}

		/**
		 * The claims, or {@code null} if the payload is not a claims set with well-typed registered claims.
		 */
		private static Claims read(byte[] payload, int maximumLength) {
			JsonObject object = jsonObject(payload, maximumLength);

			if (object == null)
				return null;

			Map<String, JsonValue> members = object.getMembers();
			List<String> audiences = new ArrayList<>();
			JsonValue audience = members.get("aud");

			if (audience instanceof JsonString string) {
				audiences.add(string.getValue());
			} else if (audience instanceof JsonArray array && !array.getElements().isEmpty()) {
				for (JsonValue element : array.getElements()) {
					if (!(element instanceof JsonString string))
						return null;

					audiences.add(string.getValue());
				}
			} else if (audience != null) {
				return null;
			}

			for (String name : List.of("iss", "sub", "jti"))
				if (members.containsKey(name) && !(members.get(name) instanceof JsonString))
					return null;

			for (String name : List.of("exp", "iat", "nbf"))
				if (members.containsKey(name) && numericDate(members.get(name)) == null)
					return null;

			return new Claims(object, stringOrNull(members, "iss"), stringOrNull(members, "sub"), audiences,
					numericDate(members.get("exp")), numericDate(members.get("iat")), numericDate(members.get("nbf")),
					stringOrNull(members, "jti"));
		}

		private static String stringOrNull(Map<String, JsonValue> members, String name) {
			return members.get(name) instanceof JsonString string ? string.getValue() : null;
		}

		/**
		 * RFC 7519 section 2: seconds since the epoch, here from -9999-01-01 to before 10000-01-01, rounded down to a
		 * nanosecond; {@code null} if absent or not such a number.
		 */
		private static Instant numericDate(JsonValue value) {
			if (!(value instanceof JsonNumber number))
				return null;

			BigDecimal seconds = number.getValue();

			if (seconds.compareTo(EARLIEST_NUMERIC_DATE) < 0 || seconds.compareTo(END_NUMERIC_DATE) >= 0)
				return null;

			BigInteger nanoseconds = seconds.movePointRight(9).setScale(0, RoundingMode.FLOOR).toBigIntegerExact();
			BigInteger[] parts = nanoseconds.divideAndRemainder(NANOSECONDS_PER_SECOND);

			if (parts[1].signum() < 0) {
				parts[0] = parts[0].subtract(BigInteger.ONE);
				parts[1] = parts[1].add(NANOSECONDS_PER_SECOND);
			}

			return Instant.ofEpochSecond(parts[0].longValueExact(), parts[1].longValueExact());
		}
	}

	/**
	 * The oracle's verdict.
	 */
	@Immutable
	private static final class Outcome {
		private final JoseException.Reason failure;
		private final JwsAlgorithm algorithm;
		private final String keyId;
		private final String type;
		private final Claims claims;

		private Outcome(JoseException.Reason failure, JwsAlgorithm algorithm, String keyId, String type, Claims claims) {
			this.failure = failure;
			this.algorithm = algorithm;
			this.keyId = keyId;
			this.type = type;
			this.claims = claims;
		}

		private static Outcome failing(JoseException.Reason failure) {
			return new Outcome(failure, null, null, null, null);
		}
	}

	/**
	 * Records the validator's hooks for the current thread's validation.
	 */
	@ThreadSafe
	private static final class RecordingObserver implements JoseObserver {
		private static final ThreadLocal<Events> EVENTS = ThreadLocal.withInitial(Events::new);

		private static void reset() {
			EVENTS.set(new Events());
		}

		private static int validations() {
			return EVENTS.get().validations;
		}

		private static RevetsecException failure() {
			return EVENTS.get().failure;
		}

		private static int anyAudience() {
			return EVENTS.get().anyAudience;
		}

		@Override
		public void didValidateJwt(JwsAlgorithm algorithm, Duration elapsed) {
			++EVENTS.get().validations;
		}

		@Override
		public void didFailToValidateJwt(RevetsecException exception, Duration elapsed) {
			Events events = EVENTS.get();
			Assertions.assertNull(events.failure, "a failure was reported twice");
			events.failure = exception;
		}

		@Override
		public void didAcceptAnyAudience(String issuer) {
			++EVENTS.get().anyAudience;
		}

		/**
		 * One thread's events.
		 */
		@NotThreadSafe
		private static final class Events {
			private int validations;
			private RevetsecException failure;
			private int anyAudience;
		}
	}

	/**
	 * The second target's signer: fuzz-only keys for every fixture name in {@link #KEY_SLOTS}, generated from fixed
	 * seeds, and the key set of those slots over them.
	 */
	@Immutable
	private static final class Signers {
		private static final List<String> RSA_ALGORITHMS = List.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
				"PS256", "PS384", "PS512");
		private static final List<String> ECDSA_ENGINES = List.of("SHA256withECDSAinP1363Format",
				"SHA384withECDSAinP1363Format", "SHA512withECDSAinP1363Format");
		private static final int DAMAGES = 14;

		private final Map<String, KeyPair> keyPairs;
		private final String keySet;
		private final byte[] defaultPayload;

		private Signers() {
			Map<String, KeyPair> generated = new LinkedHashMap<>();

			for (KeySlot slot : KEY_SLOTS)
				generated.computeIfAbsent(slot.getFixture(), fixture -> generate(fixture, 1_000 + generated.size()));

			// Insertion order, so that a choice among the keys is the same in every run.
			this.keyPairs = Collections.unmodifiableMap(generated);
			this.keySet = JwtValidatorFuzzSupport.keySetJson(KEY_SLOTS, fixture -> this.keyPairs.get(fixture).getPublic(),
					fixture -> null);
			this.defaultPayload = ("{\"iss\":\"" + ENTRA_ISSUER + "\",\"sub\":\"s\",\"client_id\":\"c\",\"aud\":\"" + AUDIENCE
					+ "\",\"exp\":" + (NOW.getEpochSecond() + 3_600) + ",\"tid\":\"" + ENTRA_TENANT + "\"}")
					.getBytes(StandardCharsets.UTF_8);
		}

		/**
		 * Builds the token an input describes: the header's JSON text, a NUL, the payload, a NUL, then the control
		 * octets: the signing slot, the signing algorithm among those its key can make, a damage kind and the damage's
		 * parameter octets.
		 */
		private String token(byte[] input) {
			int firstNul = indexOf(input, 0);
			byte[] header = firstNul < 0 ? input : Arrays.copyOfRange(input, 0, firstNul);
			int secondNul = firstNul < 0 ? -1 : indexOf(input, firstNul + 1);
			byte[] payload = firstNul < 0 ? this.defaultPayload
					: Arrays.copyOfRange(input, firstNul + 1, secondNul < 0 ? input.length : secondNul);
			byte[] controls = secondNul < 0 ? new byte[0] : Arrays.copyOfRange(input, secondNul + 1, input.length);

			// Without control octets, the header's kid (or else its alg) picks the slot and its alg the algorithm, so a
			// mutated header or payload still carries a signature that verifies.
			String[] named = namedKeyAndAlgorithm(header);
			KeySlot slot = controls.length > 0 ? KEY_SLOTS.get(control(controls, 0) % KEY_SLOTS.size()) : slotFor(named);
			int algorithm = controls.length > 1 ? control(controls, 1) : algorithmChoice(named[1]);
			KeyPair keyPair = this.keyPairs.get(slot.getFixture());
			String headerSegment = encodeBase64Url(header);
			String payloadSegment = encodeBase64Url(payload);
			byte[] signingInput = (headerSegment + "." + payloadSegment).getBytes(StandardCharsets.US_ASCII);
			byte[] signature = sign(keyPair.getPrivate(), algorithm, signingInput);
			int damage = control(controls, 2) % DAMAGES;
			byte[] parameter = controls.length > 3 ? Arrays.copyOfRange(controls, 3, controls.length) : new byte[0];

			switch (damage) {
				case 1 -> {
					if (signature.length > 0) {
						int bit = (parameter.length > 0 ? (parameter[0] & 0xFF) << 8 : 0)
								| (parameter.length > 1 ? parameter[1] & 0xFF : 0);
						signature[(bit / 8) % signature.length] ^= (byte) (1 << (bit % 8));
					}
				}
				case 2 -> signature = Arrays.copyOf(signature, Math.max(0, signature.length - 1));
				case 3 -> signature = Arrays.copyOf(signature, signature.length + 1);
				case 4 -> signature = new byte[0];
				case 5 -> signature = new byte[signature.length];
				case 6 -> signature = ecdsaHighS(keyPair.getPublic(), signature);
				case 7 -> signature = ecdsaR(keyPair.getPublic(), signature, BigInteger.ZERO);
				case 8 -> signature = ecdsaR(keyPair.getPublic(), signature, null);
				case 9 -> payloadSegment = encodeBase64Url(Arrays.copyOf(payload, payload.length + 1));
				case 10 -> signature = parameter;
				case 11 -> headerSegment = headerSegment + "=";
				case 12 -> signature = sign(otherKeyOfTheSameType(slot).getPrivate(), algorithm, signingInput);
				case 13 -> {
					return headerSegment + "." + payloadSegment;
				}
				default -> {
					// Undamaged.
				}
			}

			return headerSegment + "." + payloadSegment + "." + encodeBase64Url(signature);
		}

		/**
		 * The header's {@code kid} and {@code alg} strings, either {@code null} when absent or the header is not a JSON
		 * object.
		 */
		private static String[] namedKeyAndAlgorithm(byte[] header) {
			try {
				if (JsonCodec.parse(header, JsonLimits.jose(Limits.COMPACT_JWT_SIZE.getDefaultIntValue()))
						instanceof JsonObject object)
					return new String[]{object.getMembers().get("kid") instanceof JsonString kid ? kid.getValue() : null,
							object.getMembers().get("alg") instanceof JsonString alg ? alg.getValue() : null};
			} catch (JsonParseException e) {
				// Not JSON: no names.
			}

			return new String[2];
		}

		/**
		 * The slot {@code kid} names, or else the first whose key can make {@code alg}, or else the first slot.
		 */
		private KeySlot slotFor(String[] named) {
			for (KeySlot slot : KEY_SLOTS)
				if (named[0] != null && named[0].equals(slot.getKeyId()))
					return slot;

			String algorithm = named[1] == null ? "" : named[1];

			for (KeySlot slot : KEY_SLOTS) {
				PublicKey key = this.keyPairs.get(slot.getFixture()).getPublic();
				boolean fits = (key instanceof RSAPublicKey && (algorithm.startsWith("RS") || algorithm.startsWith("PS")))
						|| (key instanceof ECPublicKey ec && algorithm.startsWith("ES")
						&& algorithm.endsWith(String.valueOf(Math.min(ec.getParams().getOrder().bitLength(), 512))))
						|| (key instanceof EdECPublicKey && algorithm.startsWith("Ed"));

				if (fits)
					return slot;
			}

			return KEY_SLOTS.get(0);
		}

		/**
		 * The signing choice {@code alg} asks for: its position in {@link #RSA_ALGORITHMS}, or its hash for ECDSA.
		 */
		private static int algorithmChoice(String algorithm) {
			return switch (algorithm == null ? "" : algorithm) {
				case "RS384", "ES384" -> 1;
				case "RS512", "ES512" -> 2;
				case "PS256" -> 3;
				case "PS384" -> 4;
				case "PS512" -> 5;
				default -> 0;
			};
		}

		/**
		 * Another key of the same type as {@code slot}'s, of the same size where there is one, so that its signature has
		 * the right length and fails only on its value.
		 */
		private KeyPair otherKeyOfTheSameType(KeySlot slot) {
			PublicKey own = this.keyPairs.get(slot.getFixture()).getPublic();
			KeyPair sameType = null;

			for (KeyPair other : this.keyPairs.values()) {
				if (other.getPublic().equals(own) || !other.getPublic().getAlgorithm().equals(own.getAlgorithm()))
					continue;

				if (other.getPublic().getEncoded().length == own.getEncoded().length)
					return other;

				sameType = sameType == null ? other : sameType;
			}

			return sameType == null ? this.keyPairs.get(slot.getFixture()) : sameType;
		}

		private static int control(byte[] controls, int index) {
			return index < controls.length ? controls[index] & 0xFF : 0;
		}

		private static int indexOf(byte[] input, int from) {
			for (int index = from; index < input.length; ++index)
				if (input[index] == 0)
					return index;

			return -1;
		}

		private static byte[] sign(PrivateKey key, int choice, byte[] signingInput) {
			try {
				Signature signer;

				if (key.getAlgorithm().equals("RSA")) {
					String name = RSA_ALGORITHMS.get(choice % RSA_ALGORITHMS.size());
					signer = Signature.getInstance(name.startsWith("PS") ? "RSASSA-PSS" : name);
					signer.initSign(key, seededRandom());

					switch (name) {
						case "PS256" -> signer.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32,
								1));
						case "PS384" -> signer.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48,
								1));
						case "PS512" -> signer.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64,
								1));
						default -> {
							// PKCS #1 v1.5 has no parameters.
						}
					}
				} else if (key.getAlgorithm().equals("EC")) {
					signer = Signature.getInstance(ECDSA_ENGINES.get(choice % ECDSA_ENGINES.size()));
					signer.initSign(key, seededRandom());
				} else {
					signer = Signature.getInstance("Ed25519");
					signer.initSign(key);
				}

				signer.update(signingInput);
				return signer.sign();
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException("A fuzz-only key could not sign", e);
			}
		}

		/**
		 * {@code s} replaced by {@code n - s}, which verifies too (ECDSA is malleable); other keys' signatures unchanged.
		 */
		private static byte[] ecdsaHighS(PublicKey key, byte[] signature) {
			if (!(key instanceof ECPublicKey ec))
				return signature;

			int length = signature.length / 2;
			BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, length, signature.length));
			byte[] damaged = signature.clone();
			System.arraycopy(JwtValidatorFuzzSupport.fixedLength(ec.getParams().getOrder().subtract(s), length), 0, damaged,
					length, length);
			return damaged;
		}

		/**
		 * {@code r} replaced by {@code value}, or by the curve order when {@code value} is {@code null}.
		 */
		private static byte[] ecdsaR(PublicKey key, byte[] signature, BigInteger value) {
			if (!(key instanceof ECPublicKey ec))
				return signature;

			int length = signature.length / 2;
			byte[] damaged = signature.clone();
			System.arraycopy(JwtValidatorFuzzSupport.fixedLength(value == null ? ec.getParams().getOrder() : value, length),
					0, damaged, 0, length);
			return damaged;
		}

		private static KeyPair generate(String fixture, long seed) {
			try {
				KeyPairGenerator generator;

				if (fixture.contains("rsa")) {
					generator = KeyPairGenerator.getInstance("RSA");
					generator.initialize(fixture.endsWith("3072") ? 3_072 : 2_048, seededRandom(seed));
				} else if (fixture.contains("-ec-")) {
					generator = KeyPairGenerator.getInstance("EC");
					generator.initialize(new ECGenParameterSpec(fixture.endsWith("p256") ? "secp256r1" : fixture.endsWith("p384")
							? "secp384r1" : "secp521r1"), seededRandom(seed));
				} else {
					generator = KeyPairGenerator.getInstance("Ed25519");
					generator.initialize(NamedParameterSpec.ED25519, seededRandom(seed));
				}

				return generator.generateKeyPair();
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException("The JDK could not generate a fuzz-only key", e);
			}
		}

		private static SecureRandom seededRandom() {
			return seededRandom(0);
		}

		private static SecureRandom seededRandom(long seed) {
			try {
				SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
				random.setSeed(seed);
				return random;
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException("The JDK has no SHA1PRNG", e);
			}
		}
	}
}
