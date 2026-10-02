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

package com.revetsec.internal.jose;

import org.jspecify.annotations.Nullable;

import org.jspecify.annotations.NonNull;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.ErrorCategory;
import com.revetsec.internal.Limits;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.pem.PemException;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JsonWebKey;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JsonWebKeySkipReason;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.MalformedJoseInputException;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Coverage-guided checks for JSON Web Key and JWK Set parsing (M2 plan, M2-7 and "Keys"; exit criterion 7; INV-J3,
 * INV-J5, INV-C6): {@link JwkSetParser}, {@link JwkParser} and the public {@link JsonWebKeySet} over them.
 * <p>
 * The oracle is written here from RFC 7517 (sections 4 and 5), RFC 7518 (section 6), RFC 8037 (section 2), RFC 7638
 * (section 3) and the plan's twelve key rules, in their order. It has its own canonical base64url and padded Base64
 * decoders (RFC 4648 sections 4 and 5), and decides the key rules in {@link BigInteger} arithmetic of its own:
 * <ul>
 *   <li>RSA: minimal unsigned integers, an odd modulus of 2,048 to 16,384 bits, an odd exponent from 65,537 to below
 *   2<sup>32</sup>, and the ROCA fingerprint, tested as membership of {@code n mod p} in the subgroup that 65,537
 *   generates for each odd prime {@code p} from 3 to 167, through that subgroup's order;</li>
 *   <li>EC: coordinates of exactly the curve's length, below the field prime, and on {@code y^2 = x^3 + ax + b} over
 *   the parameters the JDK names for {@code secp256r1}, {@code secp384r1} and {@code secp521r1};</li>
 *   <li>Ed25519: the RFC 8032 section 5.1.3 decoding, with the square root taken by Atkin's method for primes
 *   {@code 5 mod 8} and quadratic residuosity by Euler's criterion, then the small-order test as
 *   {@code [8]P = (0, 1)} in twisted Edwards arithmetic;</li>
 *   <li>the RFC 7638 thumbprint from the required members in lexicographic order, hashed with the JDK's SHA-256.</li>
 * </ul>
 * The document's JSON text is parsed with {@link JsonCodec}, and an {@code x5c} certificate with {@link Pem}, which
 * have their own fuzz targets; every decision after those parses comes from the oracle.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class JsonWebKeyFuzzTests {
	private static final String BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	private static final String BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	private static final List<String> PRIVATE_MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k");
	private static final int MAXIMUM_KEY_ID_LENGTH = 256;
	private static final BigInteger MINIMUM_EXPONENT = BigInteger.valueOf(65_537);
	private static final BigInteger EXPONENT_LIMIT = BigInteger.ONE.shiftLeft(32);
	private static final List<Integer> ROCA_PRIMES = oddPrimesThrough(167);
	private static final List<BigInteger> ROCA_SUBGROUP_ORDERS = subgroupOrders(65_537, ROCA_PRIMES);
	private static final int JWKS_BYTES_CAP = (int) Limits.JWKS_RESPONSE_BODY_SIZE.getCap();
	private static final BigInteger ED25519_P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
	private static final BigInteger ED25519_D = ED25519_P.subtract(BigInteger.valueOf(121_665))
			.multiply(BigInteger.valueOf(121_666).modInverse(ED25519_P)).mod(ED25519_P);
	private static final Map<String, NamedCurve> EC_CURVES = Map.of("P-256", NamedCurve.fromJdkName("secp256r1"),
			"P-384", NamedCurve.fromJdkName("secp384r1"), "P-521", NamedCurve.fromJdkName("secp521r1"));
	private static final List<String> EC_CURVE_NAMES = List.of("P-256", "P-384", "P-521");
	private static final List<BigInteger> ED25519_SMALL_ORDER_Y = smallOrderYCoordinates();

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

	/**
	 * The default JWKS limits (256 KiB, 100 keys), which {@link JsonWebKeySet#fromJson} uses too, and tight ones.
	 */
	private static final List<SetLimits> SET_LIMITS = List.of(
			new SetLimits(Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue(), Limits.JWKS_KEY_COUNT.getDefaultIntValue()),
			new SetLimits(2_048, 3));

	private static final List<String> ALG_VALUES = List.of("RS256", "PS384", "ES256", "ES384", "ES512", "EdDSA",
			"Ed25519", "HS256", "ES521", "none", "RSA-OAEP", "rs256", "");

	/**
	 * {@link JwkSetParser#parse(byte[], int, int)} rejects exactly the documents the oracle rejects (too large, not
	 * strict JSON, no {@code keys} array, too many elements, an element that is not an object) with {@code KEY_SET},
	 * and otherwise keeps every key the twelve rules accept, in order, and skips each other key with the reason of the
	 * first rule it breaks, at its index. Every object anywhere in the document, taken as a JWK, gets the oracle's
	 * verdict from {@link JwkParser#parse}. The public {@link JsonWebKeySet#fromJson} agrees on the same text, its keys
	 * escape the {@code kid} in {@code toString}, and a {@link StaticJsonWebKeySource} needs one usable key.
	 *
	 * @param document the fuzzed JWK Set document: JSON text
	 */
	@FuzzTest(maxDuration = "5m")
	public void keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses(byte @NonNull [] document) {
		byte[] original = document.clone();

		for (SetLimits limits : SET_LIMITS) {
			SetOutcome expected = expectedSet(document, limits);

			try {
				ParsedKeySet parsed = JwkSetParser.parse(document, limits.bytes, limits.keys);
				Assertions.assertFalse(expected.failed, "accepted a key set document the oracle rejects");
				requireSameSet(expected, parsed);
			} catch (JoseFailure failure) {
				Assertions.assertEquals("A JOSE check failed: KEY_SET.", failure.getMessage(), "a failure's message");
				Assertions.assertNull(failure.getCause(), "a key set failure has a cause");
				Assertions.assertEquals(JoseException.Reason.KEY_SET, failure.getReason(), "the wrong document reason");
				Assertions.assertTrue(expected.failed, "rejected a key set document the oracle accepts");
			}
		}

		Assertions.assertArrayEquals(original, document, "the document was modified");

		try {
			List<JsonObject> objects = new ArrayList<>();
			collectObjects(JsonCodec.parse(document, JsonLimits.protocolDocument(JWKS_BYTES_CAP)), objects);

			for (JsonObject object : objects)
				requireKeyAgreement(object);
		} catch (JsonParseException e) {
			// Not JSON: the document checks above cover it.
		}

		String text = strictUtf8(document);

		if (text != null)
			requirePublicApiAgreement(text, expectedSet(document, SET_LIMITS.get(0)));
	}

	/**
	 * {@link JwkParser#parse} agrees with the oracle on keys built from fuzzed integers, where a byte-level mutation
	 * would almost never reach the key arithmetic: RSA moduli of chosen sizes and parity, some built by the Chinese
	 * remainder theorem to carry the ROCA fingerprint for every prime or for all but one; exponents at and around their
	 * bounds; EC points computed on the curve, pushed off it by one, or given coordinates at or past the field prime;
	 * Ed25519 encodings of the small-order points, of {@code y} at or past the field prime, and of {@code x = 0} with the
	 * sign bit set; encodings that are not minimal or not the curve's length; and every optional member in valid and
	 * invalid forms. The same key in a one-key set gets the same verdict from {@link JwkSetParser}.
	 *
	 * @param data the fuzzed choices
	 */
	@FuzzTest(maxDuration = "5m")
	public void keysBuiltFromFuzzedIntegersAgreeWithTheCurveAndThumbprintOracle(@NonNull FuzzedDataProvider data) {
		Map<String, JsonValue> members = new LinkedHashMap<>();

		switch (data.consumeInt(0, 4)) {
			case 0 -> rsaMembers(data, members);
			case 1, 2, 3 -> ecMembers(data, members, EC_CURVE_NAMES.get(data.consumeInt(0, 2)));
			default -> ed25519Members(data, members);
		}

		optionalMembers(data, members);
		JsonObject jwk;

		try {
			jwk = JsonObject.fromMembers(members);
		} catch (IllegalArgumentException e) {
			// A fuzzed string outside the JSON model (an unpaired surrogate); not a key.
			return;
		}

		requireKeyAgreement(jwk);

		byte[] document = JsonCodec.toUtf8Bytes(JsonObject.fromMembers(Map.of("keys", JsonArray.fromElements(
				List.of(jwk)))));

		try {
			ParsedKeySet parsed = JwkSetParser.parse(document, JWKS_BYTES_CAP, 1);
			requireSameSet(expectedSet(document, new SetLimits(JWKS_BYTES_CAP, 1)), parsed);
		} catch (JoseFailure failure) {
			Assertions.fail("a one-key set document was rejected: " + failure.getReason());
		}
	}

	private static void requireKeyAgreement(@NonNull JsonObject jwk) {
		KeyOutcome expected = expectedKey(jwk);

		try {
			VerificationKey actual = JwkParser.parse(jwk);
			Assertions.assertNull(expected.skip, () -> "accepted a key the oracle skips as " + expected.skip);
			requireSameKey(expected, actual);
		} catch (SkippedKeyException e) {
			Assertions.assertEquals("A JSON Web Key was skipped: " + e.getReason().name() + ".", e.getMessage(),
					"a skip's message is not its fixed text");
			Assertions.assertNull(e.getCause(), "a skip has a cause");
			Assertions.assertEquals(0, e.getStackTrace().length, "a skip records a stack trace");
			Assertions.assertEquals(expected.skip, e.getReason(), "the key was skipped for the wrong reason");
		}
	}

	/**
	 * Compares a parsed set with the oracle's. The parameter is {@link Object}, not {@link ParsedKeySet}: Jazzer finds
	 * a target by reflecting over its class's declared methods, which loads every type their signatures name before
	 * fuzzing starts, and the Jazzer and JDK of ClusterFuzzLite's base image then fail on a record loaded that early
	 * ({@code NoSuchFieldError} on one of its own fields). So no method here names a main-code record in its signature.
	 */
	private static void requireSameSet(@NonNull SetOutcome expected, @NonNull Object parsedKeySet) {
		ParsedKeySet parsed = (ParsedKeySet) parsedKeySet;
		Assertions.assertEquals(expected.keys.size(), parsed.keys().size(), "the usable key count differs");
		Assertions.assertEquals(expected.skips, parsed.skips(), "the skipped keys or their reasons differ");
		Assertions.assertEquals(expected.keys.size() + expected.skips.size(), parsed.elementCount(), "the element count");

		for (int index = 0; index < expected.keys.size(); ++index)
			requireSameKey(expected.keys.get(index), parsed.keys().get(index));
	}

	/**
	 * Compares a key with the oracle's. The parameter is {@link Object}, not {@link VerificationKey}, for the reason
	 * {@link #requireSameSet} gives.
	 */
	private static void requireSameKey(@NonNull KeyOutcome expected, @NonNull Object verificationKey) {
		VerificationKey actual = (VerificationKey) verificationKey;
		Assertions.assertEquals(expected.keyId, actual.keyId(), "kid");
		Assertions.assertEquals(expected.keyType, actual.keyType(), "kty");
		Assertions.assertEquals(expected.curve, actual.curve(), "crv");
		Assertions.assertEquals(expected.algorithm, actual.algorithm(), "alg");
		Assertions.assertEquals(expected.use, actual.use(), "use");
		Assertions.assertEquals(expected.issuer, actual.issuer(), "the JWK issuer member");
		Assertions.assertEquals(expected.thumbprint, actual.thumbprintSha256(), "the RFC 7638 thumbprint");
		Assertions.assertTrue(expected.material.isSameKey(actual.publicKey()), "the JCA key is not the JWK's key");
		Assertions.assertEquals("VerificationKey{kty=" + expected.keyType + (expected.curve == null ? ""
						: ", crv=" + expected.curve) + (expected.algorithm == null ? ""
						: ", alg=" + expected.algorithm.getWireValue()) + ", thumbprint=" + expected.thumbprint + "}",
				actual.toString(),
				"toString shows more than the key's public facts");
	}

	private static void requirePublicApiAgreement(@NonNull String text, @NonNull SetOutcome expected) {
		JsonWebKeySet set;

		try {
			set = JsonWebKeySet.fromJson(text);
		} catch (MalformedJoseInputException e) {
			Assertions.assertTrue(expected.failed, "fromJson rejected a document the oracle accepts");
			Assertions.assertEquals(JoseException.Reason.KEY_SET, e.getReason(), "fromJson's reason");
			Assertions.assertEquals(ErrorCategory.MALFORMED_INPUT, e.getCategory(), "fromJson's category");
			Assertions.assertFalse(e.isTransient(), "a malformed key set is transient");
			Assertions.assertNull(e.getCause(), "fromJson's exception has a cause");
			Assertions.assertEquals("The JSON Web Key Set document is malformed.", e.getMessage(), "fromJson's message");
			return;
		}

		Assertions.assertFalse(expected.failed, "fromJson accepted a document the oracle rejects");
		List<JsonWebKey> keys = set.getKeys();
		Assertions.assertEquals(expected.keys.size(), keys.size(), "fromJson's usable key count");

		for (int index = 0; index < keys.size(); ++index) {
			KeyOutcome key = expected.keys.get(index);
			JsonWebKey actual = keys.get(index);
			Assertions.assertEquals(Optional.ofNullable(key.keyId), actual.getKeyId(), "getKeyId");
			Assertions.assertEquals(key.keyType, actual.getKeyType(), "getKeyType");
			Assertions.assertEquals(Optional.ofNullable(key.curve), actual.getCurve(), "getCurve");
			Assertions.assertEquals(Optional.ofNullable(key.algorithm), actual.getAlgorithm(), "getAlgorithm");
			Assertions.assertEquals(Optional.ofNullable(key.use), actual.getUse(), "getUse");
			Assertions.assertEquals(key.thumbprint, actual.getThumbprintSha256(), "getThumbprintSha256");
			Assertions.assertEquals("JsonWebKey{" + (key.keyId == null ? "" : "kid=\"" + escapedKeyId(key.keyId) + "\", ")
					+ "kty=" + key.keyType + (key.curve == null ? "" : ", crv=" + key.curve) + (key.algorithm == null ? ""
					: ", alg=" + key.algorithm.getWireValue()) + ", thumbprint=" + key.thumbprint + "}", actual.toString(),
					"toString does not escape the kid, or shows more than the key's public facts");
		}

		JsonWebKeySet again = JsonWebKeySet.fromJson(text);
		Assertions.assertEquals(set, again, "a key set does not equal its own reparse");
		Assertions.assertEquals(set.hashCode(), again.hashCode(), "equal key sets hash differently");

		if (keys.isEmpty()) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> StaticJsonWebKeySource.fromJsonWebKeySet(set),
					"a static source accepted a key set with no usable key");
		} else {
			Assertions.assertSame(set, StaticJsonWebKeySource.fromJsonWebKeySet(set).getJsonWebKeySet(),
					"a static source does not hold its key set");
		}
	}

	/**
	 * RFC 7517 section 5 and the plan's document failures, then each element through the key oracle.
	 */
	private static @NonNull SetOutcome expectedSet(byte @NonNull [] document, @NonNull SetLimits limits) {
		if (document.length > limits.bytes)
			return SetOutcome.FAILED;

		JsonValue root;

		try {
			root = JsonCodec.parse(document, JsonLimits.protocolDocument(limits.bytes));
		} catch (JsonParseException e) {
			return SetOutcome.FAILED;
		}

		if (!(root instanceof JsonObject object) || !(object.getMembers().get("keys") instanceof JsonArray keys)
				|| keys.getElements().size() > limits.keys)
			return SetOutcome.FAILED;

		for (JsonValue element : keys.getElements())
			if (!(element instanceof JsonObject))
				return SetOutcome.FAILED;

		List<KeyOutcome> usable = new ArrayList<>();
		List<ParsedKeySet.Skip> skips = new ArrayList<>();

		for (int index = 0; index < keys.getElements().size(); ++index) {
			KeyOutcome key = expectedKey((JsonObject) keys.getElements().get(index));

			if (key.skip == null)
				usable.add(key);
			else
				skips.add(new ParsedKeySet.Skip(index, key.skip));
		}

		return new SetOutcome(false, usable, skips);
	}

	/**
	 * The twelve key rules, in order (plan "Keys").
	 */
	private static @NonNull KeyOutcome expectedKey(@NonNull JsonObject jwk) {
		Map<String, JsonValue> members = jwk.getMembers();

		// 1 and 2.
		if (!(members.get("kty") instanceof JsonString keyTypeString))
			return KeyOutcome.skipped(JsonWebKeySkipReason.MALFORMED_KEY);

		String keyType = keyTypeString.getValue();

		if (keyType.equals("oct"))
			return KeyOutcome.skipped(JsonWebKeySkipReason.SYMMETRIC_KEY);

		if (!keyType.equals("RSA") && !keyType.equals("EC") && !keyType.equals("OKP"))
			return KeyOutcome.skipped(JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE);

		// 3.
		for (String name : PRIVATE_MEMBERS)
			if (members.containsKey(name))
				return KeyOutcome.skipped(JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS);

		// 4: RFC 7517 sections 4.2 and 4.3.
		JsonValue use = members.get("use");

		if (use != null && !(use instanceof JsonString useString && useString.getValue().equals("sig")))
			return KeyOutcome.skipped(JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY);

		JsonValue keyOperations = members.get("key_ops");

		if (keyOperations != null) {
			if (!(keyOperations instanceof JsonArray operations))
				return KeyOutcome.skipped(JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY);

			boolean verify = false;

			for (JsonValue operation : operations.getElements()) {
				if (!(operation instanceof JsonString operationString))
					return KeyOutcome.skipped(JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY);

				if (operationString.getValue().equals("verify"))
					verify = true;
				else if (use != null && !operationString.getValue().equals("sign"))
					return KeyOutcome.skipped(JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY);
			}

			if (!verify)
				return KeyOutcome.skipped(JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY);
		}

		// 5.
		JwsAlgorithm algorithm = null;
		JsonValue alg = members.get("alg");

		if (alg != null) {
			algorithm = alg instanceof JsonString algString ? WIRE_VALUES.get(algString.getValue()) : null;

			if (algorithm == null)
				return KeyOutcome.skipped(JsonWebKeySkipReason.UNSUPPORTED_ALGORITHM);

			if (!keyTypeOf(algorithm).equals(keyType))
				return KeyOutcome.skipped(JsonWebKeySkipReason.ALGORITHM_MISMATCH);

			if (members.get("crv") instanceof JsonString curve && isSupportedCurve(keyType, curve.getValue())
					&& !curve.getValue().equals(curveOf(algorithm)))
				return KeyOutcome.skipped(JsonWebKeySkipReason.ALGORITHM_MISMATCH);
		}

		// 6.
		if (!keyType.equals("RSA") && members.get("crv") instanceof JsonString curve
				&& !isSupportedCurve(keyType, curve.getValue()))
			return KeyOutcome.skipped(JsonWebKeySkipReason.UNSUPPORTED_CURVE);

		// 7, for the members that are not key material.
		JsonValue kid = members.get("kid");

		if (kid != null && !(kid instanceof JsonString kidString && !kidString.getValue().isEmpty()
				&& kidString.getValue().length() <= MAXIMUM_KEY_ID_LENGTH))
			return KeyOutcome.skipped(JsonWebKeySkipReason.MALFORMED_KEY);

		JsonValue issuer = members.get("issuer");

		if (issuer != null && !(issuer instanceof JsonString issuerString && !issuerString.getValue().isEmpty()))
			return KeyOutcome.skipped(JsonWebKeySkipReason.MALFORMED_KEY);

		// 7 to 11, for the key material.
		Object material = switch (keyType) {
			case "RSA" -> rsaMaterial(members);
			case "EC" -> ecMaterial(members);
			default -> ed25519Material(members);
		};

		if (material instanceof JsonWebKeySkipReason reason)
			return KeyOutcome.skipped(reason);

		KeyMaterial key = (KeyMaterial) material;

		// 12.
		JsonValue chain = members.get("x5c");

		if (chain != null && !certificateHoldsKey(chain, key))
			return KeyOutcome.skipped(JsonWebKeySkipReason.CERTIFICATE_MISMATCH);

		return new KeyOutcome(null, kid == null ? null : ((JsonString) kid).getValue(), keyType, key.curve, algorithm,
				use == null ? null : "sig", issuer == null ? null : ((JsonString) issuer).getValue(), thumbprint(members,
				keyType), key);
	}

	/**
	 * Rules 7 to 11 for RSA (RFC 7518 section 6.3.1): minimal {@code n} and {@code e}, then the key policy.
	 */
	private static @NonNull Object rsaMaterial(@NonNull Map<@NonNull String, @NonNull JsonValue> members) {
		byte[] modulus = base64UrlMember(members, "n");
		byte[] exponent = base64UrlMember(members, "e");

		if (modulus == null || exponent == null || !isMinimal(modulus) || !isMinimal(exponent))
			return JsonWebKeySkipReason.MALFORMED_KEY;

		BigInteger n = new BigInteger(1, modulus);
		BigInteger e = new BigInteger(1, exponent);

		if (n.signum() == 0 || !n.testBit(0))
			return JsonWebKeySkipReason.MALFORMED_KEY;

		if (n.bitLength() < 2_048 || n.bitLength() > 16_384)
			return JsonWebKeySkipReason.RSA_KEY_SIZE;

		if (!e.testBit(0) || e.compareTo(MINIMUM_EXPONENT) < 0 || e.compareTo(EXPONENT_LIMIT) >= 0)
			return JsonWebKeySkipReason.RSA_EXPONENT;

		if (hasRocaFingerprint(n))
			return JsonWebKeySkipReason.WEAK_KEY;

		return KeyMaterial.rsa(n, e);
	}

	/**
	 * Rules 7 and 10 for EC (RFC 7518 section 6.2.1): the curve's exact coordinate length, then coordinates below
	 * the field prime and on the curve.
	 */
	private static @NonNull Object ecMaterial(@NonNull Map<@NonNull String, @NonNull JsonValue> members) {
		if (!(members.get("crv") instanceof JsonString curveName))
			return JsonWebKeySkipReason.MALFORMED_KEY;

		NamedCurve curve = EC_CURVES.get(curveName.getValue());
		byte[] x = base64UrlMember(members, "x");
		byte[] y = base64UrlMember(members, "y");

		if (x == null || y == null || x.length != curve.coordinateLength || y.length != curve.coordinateLength)
			return JsonWebKeySkipReason.MALFORMED_KEY;

		BigInteger px = new BigInteger(1, x);
		BigInteger py = new BigInteger(1, y);

		if (!curve.isOnCurve(px, py))
			return JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE;

		return KeyMaterial.ec(curveName.getValue(), curve, px, py);
	}

	/**
	 * Rules 7 and 11 for Ed25519 (RFC 8037 section 2, RFC 8032 section 5.1.3).
	 */
	private static @NonNull Object ed25519Material(@NonNull Map<@NonNull String, @NonNull JsonValue> members) {
		if (!(members.get("crv") instanceof JsonString))
			return JsonWebKeySkipReason.MALFORMED_KEY;

		byte[] encoded = base64UrlMember(members, "x");

		if (encoded == null || encoded.length != 32)
			return JsonWebKeySkipReason.MALFORMED_KEY;

		boolean xOdd = (encoded[31] & 0x80) != 0;
		byte[] bigEndian = new byte[32];

		for (int index = 0; index < 32; ++index)
			bigEndian[index] = encoded[31 - index];

		bigEndian[0] &= 0x7F;
		BigInteger y = new BigInteger(1, bigEndian);
		BigInteger x = recoverX(y, xOdd);

		if (x == null)
			return JsonWebKeySkipReason.MALFORMED_KEY;

		if (hasSmallOrder(x, y))
			return JsonWebKeySkipReason.WEAK_KEY;

		return KeyMaterial.ed25519(y, xOdd);
	}

	/**
	 * RFC 8032 section 5.1.3: the {@code x} of the point with this {@code y} and sign, or {@code null} if there is
	 * none. The square root comes from Atkin's method, not from the RFC's candidate formula.
	 */
	private static @Nullable BigInteger recoverX(@NonNull BigInteger y, boolean xOdd) {
		BigInteger p = ED25519_P;

		if (y.compareTo(p) >= 0)
			return null;

		BigInteger ySquared = y.multiply(y).mod(p);
		BigInteger numerator = ySquared.subtract(BigInteger.ONE).mod(p);
		BigInteger denominator = ED25519_D.multiply(ySquared).add(BigInteger.ONE).mod(p);
		BigInteger xSquared = numerator.multiply(denominator.modInverse(p)).mod(p);
		BigInteger x;

		if (xSquared.signum() == 0) {
			x = BigInteger.ZERO;
		} else {
			// Euler's criterion.
			if (!xSquared.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p).equals(BigInteger.ONE))
				return null;

			// Atkin's square root for p = 5 mod 8.
			BigInteger twiceA = xSquared.shiftLeft(1).mod(p);
			BigInteger v = twiceA.modPow(p.subtract(BigInteger.valueOf(5)).shiftRight(3), p);
			BigInteger i = twiceA.multiply(v).multiply(v).mod(p);
			x = xSquared.multiply(v).multiply(i.subtract(BigInteger.ONE)).mod(p);
			Assertions.assertEquals(xSquared, x.multiply(x).mod(p), "the oracle's square root is wrong");
		}

		if (x.signum() == 0 && xOdd)
			return null;

		return x.testBit(0) == xOdd ? x : p.subtract(x);
	}

	/**
	 * Whether {@code [8](x, y)} is the neutral element {@code (0, 1)}, by three doublings with the twisted Edwards
	 * addition law for {@code a = -1} (RFC 8032 section 5.1.4), which is complete on this curve.
	 */
	private static boolean hasSmallOrder(@NonNull BigInteger x, @NonNull BigInteger y) {
		BigInteger[] point = {x, y};

		for (int doubling = 0; doubling < 3; ++doubling)
			point = edwardsAdd(point, point);

		return point[0].signum() == 0 && point[1].equals(BigInteger.ONE);
	}

	private static @NonNull BigInteger @NonNull [] edwardsAdd(@NonNull BigInteger @NonNull [] first, @NonNull BigInteger @NonNull [] second) {
		BigInteger p = ED25519_P;
		BigInteger x1y2 = first[0].multiply(second[1]);
		BigInteger y1x2 = first[1].multiply(second[0]);
		BigInteger y1y2 = first[1].multiply(second[1]);
		BigInteger x1x2 = first[0].multiply(second[0]);
		BigInteger dxy = ED25519_D.multiply(x1x2).multiply(y1y2).mod(p);
		BigInteger x = x1y2.add(y1x2).multiply(BigInteger.ONE.add(dxy).modInverse(p)).mod(p);
		BigInteger y = y1y2.add(x1x2).multiply(BigInteger.ONE.subtract(dxy).mod(p).modInverse(p)).mod(p);
		return new BigInteger[]{x, y};
	}

	/**
	 * The ROCA fingerprint: for every odd prime {@code p} from 3 to 167, {@code n mod p} is a unit whose power by the
	 * order of 65,537 mod {@code p} is 1, so it lies in the subgroup 65,537 generates.
	 */
	private static boolean hasRocaFingerprint(@NonNull BigInteger n) {
		for (int index = 0; index < ROCA_PRIMES.size(); ++index) {
			BigInteger p = BigInteger.valueOf(ROCA_PRIMES.get(index));
			BigInteger residue = n.mod(p);

			if (residue.signum() == 0 || !residue.modPow(ROCA_SUBGROUP_ORDERS.get(index), p).equals(BigInteger.ONE))
				return false;
		}

		return true;
	}

	/**
	 * For each prime, the multiplicative order of {@code generator} modulo it: the size of the subgroup it generates.
	 */
	private static @NonNull List<@NonNull BigInteger> subgroupOrders(int generator, @NonNull List<@NonNull Integer> primes) {
		List<BigInteger> orders = new ArrayList<>();

		for (int prime : primes) {
			int order = 1;

			for (long power = generator % prime; power != 1; power = power * generator % prime)
				++order;

			orders.add(BigInteger.valueOf(order));
		}

		return List.copyOf(orders);
	}

	/**
	 * Rule 12: {@code x5c}'s first element is padded Base64 of a certificate that {@link Pem#parseCertificateDer}
	 * accepts, and whose key is this key by value.
	 */
	private static boolean certificateHoldsKey(@NonNull JsonValue chain, @NonNull KeyMaterial key) {
		if (!(chain instanceof JsonArray certificates) || certificates.getElements().isEmpty()
				|| !(certificates.getElements().get(0) instanceof JsonString first))
			return false;

		byte[] der = decodeBase64(first.getValue());

		if (der == null)
			return false;

		try {
			X509Certificate certificate = Pem.parseCertificateDer(der);
			return key.isSameKey(certificate.getPublicKey());
		} catch (PemException | RuntimeException e) {
			return false;
		}
	}

	/**
	 * RFC 7638 section 3: the required members of the key type, in lexicographic order, with no whitespace, hashed with
	 * SHA-256 and written as unpadded base64url. The values are canonical base64url and curve names, so none needs
	 * escaping.
	 */
	private static @NonNull String thumbprint(@NonNull Map<@NonNull String, @NonNull JsonValue> members, @NonNull String keyType) {
		String canonical = switch (keyType) {
			case "RSA" -> "{\"e\":\"" + string(members, "e") + "\",\"kty\":\"RSA\",\"n\":\"" + string(members, "n") + "\"}";
			case "EC" -> "{\"crv\":\"" + string(members, "crv") + "\",\"kty\":\"EC\",\"x\":\"" + string(members, "x")
					+ "\",\"y\":\"" + string(members, "y") + "\"}";
			default -> "{\"crv\":\"" + string(members, "crv") + "\",\"kty\":\"OKP\",\"x\":\"" + string(members, "x") + "\"}";
		};

		try {
			return encodeBase64Url(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("The JDK has no SHA-256", e);
		}
	}

	private static @NonNull String string(@NonNull Map<@NonNull String, @NonNull JsonValue> members, @NonNull String name) {
		return ((JsonString) members.get(name)).getValue();
	}

	private static byte @Nullable [] base64UrlMember(@NonNull Map<@NonNull String, @NonNull JsonValue> members, @NonNull String name) {
		return members.get(name) instanceof JsonString string ? decodeBase64Url(string.getValue()) : null;
	}

	private static boolean isMinimal(byte @NonNull [] value) {
		return value.length == 1 || (value.length > 1 && value[0] != 0);
	}

	private static @NonNull String keyTypeOf(@NonNull JwsAlgorithm algorithm) {
		return switch (algorithm) {
			case RS256, RS384, RS512, PS256, PS384, PS512 -> "RSA";
			case ES256, ES384, ES512 -> "EC";
			case ED25519, EDDSA -> "OKP";
			case HS256, HS384, HS512 -> "oct";
		};
	}

	private static @NonNull String curveOf(@NonNull JwsAlgorithm algorithm) {
		return switch (algorithm) {
			case ES256 -> "P-256";
			case ES384 -> "P-384";
			case ES512 -> "P-521";
			case ED25519, EDDSA -> "Ed25519";
			default -> "";
		};
	}

	private static boolean isSupportedCurve(@NonNull String keyType, @NonNull String curve) {
		return (keyType.equals("EC") && EC_CURVES.containsKey(curve)) || (keyType.equals("OKP") && curve.equals("Ed25519"));
	}

	/**
	 * RFC 4648 section 5 without padding, canonical; {@code null} for anything else.
	 */
	private static byte @Nullable [] decodeBase64Url(@NonNull String text) {
		if (text.length() % 4 == 1)
			return null;

		return decodeBits(text, BASE64URL_ALPHABET);
	}

	/**
	 * RFC 4648 section 4 with its padding required, canonical; {@code null} for anything else.
	 */
	private static byte @Nullable [] decodeBase64(@NonNull String text) {
		if (text.length() % 4 != 0)
			return null;

		int padding = text.endsWith("==") ? 2 : text.endsWith("=") ? 1 : 0;
		String significant = text.substring(0, text.length() - padding);

		if (significant.indexOf('=') >= 0 || significant.length() % 4 == 1)
			return null;

		return decodeBits(significant, BASE64_ALPHABET);
	}

	private static byte @Nullable [] decodeBits(@NonNull String text, @NonNull String alphabet) {
		ByteArrayOutputStream octets = new ByteArrayOutputStream();
		int buffer = 0;
		int bits = 0;

		for (int index = 0; index < text.length(); ++index) {
			int value = alphabet.indexOf(text.charAt(index));

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

	private static @NonNull String encodeBase64Url(byte @NonNull [] bytes) {
		StringBuilder encoded = new StringBuilder();
		int buffer = 0;
		int bits = 0;

		for (byte b : bytes) {
			buffer = (buffer << 8) | (b & 0xFF);
			bits += 8;

			while (bits >= 6) {
				bits -= 6;
				encoded.append(BASE64URL_ALPHABET.charAt((buffer >> bits) & 0x3F));
			}
		}

		if (bits > 0)
			encoded.append(BASE64URL_ALPHABET.charAt((buffer << (6 - bits)) & 0x3F));

		return encoded.toString();
	}

	/**
	 * The documented {@code toString} escape: C0 and C1 controls, DEL, the quotation mark, the backslash, the line and
	 * paragraph separators, the bidirectional formatting characters and unpaired surrogates, as {@code \}{@code uXXXX}.
	 */
	private static @NonNull String escapedKeyId(@NonNull String keyId) {
		StringBuilder escaped = new StringBuilder();

		for (int index = 0; index < keyId.length(); ++index) {
			char c = keyId.charAt(index);
			boolean pairedHigh = Character.isHighSurrogate(c) && index + 1 < keyId.length()
					&& Character.isLowSurrogate(keyId.charAt(index + 1));
			boolean pairedLow = Character.isLowSurrogate(c) && index > 0
					&& Character.isHighSurrogate(keyId.charAt(index - 1));
			boolean unpaired = Character.isSurrogate(c) && !pairedHigh && !pairedLow;
			boolean escape = c < 0x20 || (c >= 0x7F && c <= 0x9F) || c == '"' || c == '\\' || c == 0x2028 || c == 0x2029
					|| (c >= 0x202A && c <= 0x202E) || (c >= 0x2066 && c <= 0x2069) || c == 0x200E || c == 0x200F
					|| c == 0x061C || unpaired;

			if (escape)
				escaped.append("\\u").append(String.format(Locale.ROOT, "%04X", (int) c));
			else
				escaped.append(c);
		}

		return escaped.toString();
	}

	private static @Nullable String strictUtf8(byte @NonNull [] bytes) {
		try {
			return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
		} catch (CharacterCodingException e) {
			return null;
		}
	}

	private static void collectObjects(@NonNull JsonValue value, @NonNull List<@NonNull JsonObject> objects) {
		if (value instanceof JsonObject object) {
			objects.add(object);

			for (JsonValue member : object.getMembers().values())
				collectObjects(member, objects);
		} else if (value instanceof JsonArray array) {
			for (JsonValue element : array.getElements())
				collectObjects(element, objects);
		}
	}

	private static @NonNull List<@NonNull Integer> oddPrimesThrough(int limit) {
		List<Integer> primes = new ArrayList<>();

		for (int candidate = 3; candidate <= limit; candidate += 2) {
			boolean prime = true;

			for (int divisor = 3; divisor * divisor <= candidate && prime; divisor += 2)
				prime = candidate % divisor != 0;

			if (prime)
				primes.add(candidate);
		}

		return List.copyOf(primes);
	}

	/**
	 * The {@code y} coordinates of Ed25519's eight small-order points, found as the curve points whose double has a
	 * smaller order: {@code y = 1} and {@code y = -1} (orders 1 and 2), {@code y = 0} (order 4), and the roots of
	 * {@code d y^4 + 2 y^2 - 1 = 0} (order 8).
	 */
	private static @NonNull List<@NonNull BigInteger> smallOrderYCoordinates() {
		BigInteger p = ED25519_P;
		List<BigInteger> ys = new ArrayList<>(List.of(BigInteger.ONE, p.subtract(BigInteger.ONE), BigInteger.ZERO));
		BigInteger root = squareRoot(BigInteger.ONE.add(ED25519_D).mod(p));

		for (BigInteger sign : List.of(BigInteger.ONE, p.subtract(BigInteger.ONE))) {
			BigInteger ySquared = p.subtract(BigInteger.ONE).add(sign.multiply(root)).multiply(ED25519_D.modInverse(p))
					.mod(p);
			BigInteger y = squareRoot(ySquared);

			if (y != null) {
				ys.add(y);
				ys.add(p.subtract(y));
			}
		}

		// Orders 1, 2, 4 and two for order 8: five y coordinates carry the eight points.
		if (ys.size() != 5)
			throw new IllegalStateException("The oracle found " + ys.size() + " small-order y coordinates, not 5");

		return List.copyOf(ys);
	}

	private static @Nullable BigInteger squareRoot(@NonNull BigInteger a) {
		BigInteger p = ED25519_P;

		if (a.signum() == 0)
			return BigInteger.ZERO;

		if (!a.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p).equals(BigInteger.ONE))
			return null;

		BigInteger twiceA = a.shiftLeft(1).mod(p);
		BigInteger v = twiceA.modPow(p.subtract(BigInteger.valueOf(5)).shiftRight(3), p);
		BigInteger i = twiceA.multiply(v).multiply(v).mod(p);
		return a.multiply(v).multiply(i.subtract(BigInteger.ONE)).mod(p);
	}

	// Structure-aware builders for the second target.

	private static void rsaMembers(@NonNull FuzzedDataProvider data, @NonNull Map<@NonNull String, @NonNull JsonValue> members) {
		members.put("kty", JsonString.fromValue("RSA"));
		// Choice 0, which an exhausted input gives, is always the ordinary case: here, an odd 2,048-bit modulus and 65537.
		BigInteger n = switch (data.consumeInt(0, 3)) {
			case 1 -> rocaModulus(data);
			case 2 -> new BigInteger(1, data.consumeBytes(data.consumeInt(0, 300)));
			case 3 -> randomModulus(data, data.consumeInt(1, 4_200));
			default -> randomModulus(data, List.of(2_048, 2_047, 2_049, 3_072, 4_096, 16_384, 16_385)
					.get(data.consumeInt(0, 6)));
		};
		BigInteger e = switch (data.consumeInt(0, 9)) {
			case 1 -> BigInteger.valueOf(65_535);
			case 2 -> BigInteger.valueOf(65_536);
			case 3 -> BigInteger.valueOf(65_539);
			case 4 -> EXPONENT_LIMIT.subtract(BigInteger.ONE);
			case 5 -> EXPONENT_LIMIT.add(BigInteger.ONE);
			case 6 -> BigInteger.ONE;
			case 7 -> BigInteger.ZERO;
			case 8 -> new BigInteger(1, data.consumeBytes(data.consumeInt(0, 9)));
			case 9 -> BigInteger.valueOf(3);
			default -> MINIMUM_EXPONENT;
		};
		members.put("n", JsonString.fromValue(encodeInteger(data, n)));
		members.put("e", JsonString.fromValue(encodeInteger(data, e)));
	}

	/**
	 * A modulus of about {@code bits} bits whose residues modulo every ROCA prime lie in the subgroup 65,537 generates,
	 * built by the Chinese remainder theorem; optionally one prime gets a residue outside it.
	 */
	private static @NonNull BigInteger rocaModulus(@NonNull FuzzedDataProvider data) {
		int bits = List.of(2_047, 2_048, 3_072, 4_096).get(data.consumeInt(0, 3));
		int broken = data.consumeBoolean() ? data.consumeInt(0, ROCA_PRIMES.size() - 1) : -1;
		BigInteger product = BigInteger.ONE;

		for (int prime : ROCA_PRIMES)
			product = product.multiply(BigInteger.valueOf(prime));

		BigInteger residue = BigInteger.ZERO;

		for (int index = 0; index < ROCA_PRIMES.size(); ++index) {
			BigInteger p = BigInteger.valueOf(ROCA_PRIMES.get(index));
			BigInteger r = index == broken ? BigInteger.ZERO
					: BigInteger.valueOf(65_537).modPow(BigInteger.valueOf(data.consumeInt(0, 1_000)), p);
			BigInteger cofactor = product.divide(p);
			residue = residue.add(r.multiply(cofactor).multiply(cofactor.modInverse(p)));
		}

		residue = residue.mod(product);
		BigInteger multiplier = new BigInteger(1, data.consumeBytes((bits - product.bitLength()) / 8 + 1))
				.setBit(bits - product.bitLength() - 1);
		BigInteger n = residue.add(product.multiply(multiplier));

		// The product is odd, so adding it once more flips the parity and keeps every residue.
		return n.testBit(0) ? n : n.add(product);
	}

	private static @NonNull BigInteger randomModulus(@NonNull FuzzedDataProvider data, int bits) {
		BigInteger n = new BigInteger(1, data.consumeBytes((bits + 7) / 8));
		n = n.mod(BigInteger.ONE.shiftLeft(bits)).setBit(bits - 1);
		return data.consumeBoolean() ? n.clearBit(0) : n.setBit(0);
	}

	private static void ecMembers(@NonNull FuzzedDataProvider data, @NonNull Map<@NonNull String, @NonNull JsonValue> members, @NonNull String curveName) {
		NamedCurve curve = EC_CURVES.get(curveName);
		BigInteger x = new BigInteger(1, data.consumeBytes(curve.coordinateLength)).mod(curve.fieldPrime);
		BigInteger y = data.consumeBoolean() ? curve.yFor(x) : null;

		// No point has that x (or the generator was chosen): use the generator.
		if (y == null) {
			x = curve.generatorX();
			y = curve.generatorY();
		}

		if (data.consumeBoolean())
			y = curve.fieldPrime.subtract(y);

		int length = curve.coordinateLength;
		byte[] xBytes;
		byte[] yBytes;

		switch (data.consumeInt(0, 7)) {
			case 1 -> {
				xBytes = fixedLength(x, length);
				yBytes = fixedLength(y.add(BigInteger.ONE).mod(curve.fieldPrime), length);
			}
			case 2 -> {
				xBytes = fixedLength(x.add(curve.fieldPrime), length);
				yBytes = fixedLength(y, length);
			}
			case 3 -> {
				xBytes = fixedLength(x, length);
				yBytes = fixedLength(y.add(curve.fieldPrime), length);
			}
			case 4 -> {
				xBytes = fixedLength(x, length - 1);
				yBytes = fixedLength(y, length);
			}
			case 5 -> {
				xBytes = fixedLength(x, length);
				yBytes = fixedLength(y, length + 1);
			}
			case 6 -> {
				xBytes = data.consumeBytes(data.consumeInt(0, length + 2));
				yBytes = data.consumeBytes(data.consumeInt(0, length + 2));
			}
			default -> {
				xBytes = fixedLength(x, length);
				yBytes = fixedLength(y, length);
			}
		}

		members.put("kty", JsonString.fromValue("EC"));
		members.put("crv", JsonString.fromValue(curveName));
		members.put("x", JsonString.fromValue(encodeBase64Url(xBytes)));
		members.put("y", JsonString.fromValue(encodeBase64Url(yBytes)));
	}

	private static void ed25519Members(@NonNull FuzzedDataProvider data, @NonNull Map<@NonNull String, @NonNull JsonValue> members) {
		BigInteger y = switch (data.consumeInt(0, 4)) {
			case 1 -> ED25519_SMALL_ORDER_Y.get(data.consumeInt(0, ED25519_SMALL_ORDER_Y.size() - 1));
			case 2 -> ED25519_P.add(BigInteger.valueOf(data.consumeInt(0, 18)));
			case 3 -> data.consumeBoolean() ? BigInteger.ONE : ED25519_P.subtract(BigInteger.ONE);
			default -> new BigInteger(1, data.consumeBytes(32)).mod(BigInteger.ONE.shiftLeft(255));
		};
		boolean xOdd = data.consumeBoolean();
		byte[] bigEndian = fixedLength(y, 32);
		byte[] encoded = new byte[32];

		for (int index = 0; index < 32; ++index)
			encoded[index] = bigEndian[31 - index];

		if (xOdd)
			encoded[31] |= (byte) 0x80;

		int length = data.consumeInt(0, 9) == 9 ? data.consumeInt(30, 34) : 32;
		members.put("kty", JsonString.fromValue("OKP"));
		members.put("crv", JsonString.fromValue("Ed25519"));
		members.put("x", JsonString.fromValue(encodeBase64Url(Arrays.copyOf(encoded, length))));
	}

	private static void optionalMembers(@NonNull FuzzedDataProvider data, @NonNull Map<@NonNull String, @NonNull JsonValue> members) {
		int choices = data.consumeInt(0, 255);

		if ((choices & 1) != 0)
			members.put("kid", pick(data, JsonString.fromValue(""), JsonString.fromValue("k"),
					JsonString.fromValue("a".repeat(256)), JsonString.fromValue("a".repeat(257)),
					JsonNumber.fromValue(5L), JsonNull.defaultInstance(), fuzzedString(data)));

		if ((choices & 2) != 0)
			members.put("issuer", pick(data, JsonString.fromValue(""), JsonString.fromValue("https://issuer.example.com"),
					JsonNull.defaultInstance(), JsonNumber.fromValue(123L), JsonArray.emptyInstance(), fuzzedString(data)));

		if ((choices & 4) != 0)
			members.put("alg", data.consumeInt(0, 9) == 9 ? JsonNumber.fromValue(1L)
					: JsonString.fromValue(ALG_VALUES.get(data.consumeInt(0, ALG_VALUES.size() - 1))));

		if ((choices & 8) != 0)
			members.put("use", pick(data, JsonString.fromValue("sig"), JsonString.fromValue("enc"), JsonString.fromValue(""),
					JsonNumber.fromValue(1L)));

		if ((choices & 16) != 0)
			members.put("key_ops", pick(data, strings("verify"), strings("sign", "verify"), strings("verify", "encrypt"),
					strings("encrypt"), JsonArray.emptyInstance(), JsonString.fromValue("verify"),
					JsonArray.fromElements(List.of(JsonNumber.fromValue(1L)))));

		if ((choices & 32) != 0) {
			JsonValue curve = pick(data, JsonString.fromValue("P-256"), JsonString.fromValue("P-384"),
					JsonString.fromValue("P-521"), JsonString.fromValue("Ed25519"), JsonString.fromValue("Ed448"),
					JsonString.fromValue("X25519"), JsonString.fromValue("secp256k1"), JsonNumber.fromValue(5L), null);

			if (curve == null)
				members.remove("crv");
			else
				members.put("crv", curve);
		}

		if ((choices & 64) != 0)
			members.put(PRIVATE_MEMBERS.get(data.consumeInt(0, PRIVATE_MEMBERS.size() - 1)), JsonString.fromValue("AQAB"));

		if ((choices & 128) != 0)
			members.put("x5c", pick(data, JsonArray.emptyInstance(), strings("!!"), strings("AAAA"), strings("MIIB"),
					JsonString.fromValue("MIIB"), JsonArray.fromElements(List.of(JsonNumber.fromValue(1L))),
					strings(encodeBase64Url(data.consumeBytes(data.consumeInt(0, 64))))));

		if (data.consumeInt(0, 15) == 15)
			members.put("kty", pick(data, JsonString.fromValue("oct"), JsonString.fromValue("rsa"),
					JsonString.fromValue("OKP"), JsonNumber.fromValue(1L)));
	}

	@SafeVarargs
	private static <T> @NonNull T pick(@NonNull FuzzedDataProvider data, @NonNull T @NonNull ... values) {
		return values[data.consumeInt(0, values.length - 1)];
	}

	private static @NonNull JsonValue fuzzedString(@NonNull FuzzedDataProvider data) {
		try {
			return JsonString.fromValue(data.consumeString(300));
		} catch (IllegalArgumentException e) {
			// An unpaired surrogate, which the JSON model refuses.
			return JsonString.fromValue("unpaired");
		}
	}

	private static @NonNull JsonArray strings(@NonNull String @NonNull ... values) {
		List<JsonValue> elements = new ArrayList<>();

		for (String value : values)
			elements.add(JsonString.fromValue(value));

		return JsonArray.fromElements(elements);
	}

	/**
	 * An unsigned integer as base64url: minimal, with a leading zero octet, or empty.
	 */
	private static @NonNull String encodeInteger(@NonNull FuzzedDataProvider data, @NonNull BigInteger value) {
		byte[] minimal = value.toByteArray();

		if (minimal.length > 1 && minimal[0] == 0)
			minimal = Arrays.copyOfRange(minimal, 1, minimal.length);

		return switch (data.consumeInt(0, 15)) {
			case 14 -> encodeBase64Url(concat(new byte[1], minimal));
			case 15 -> "";
			default -> encodeBase64Url(minimal);
		};
	}

	private static byte @NonNull [] concat(byte @NonNull [] first, byte @NonNull [] second) {
		byte[] joined = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, joined, first.length, second.length);
		return joined;
	}

	/**
	 * {@code value} big-endian in exactly {@code length} octets, keeping the low octets of a larger value.
	 */
	private static byte @NonNull [] fixedLength(@NonNull BigInteger value, int length) {
		byte[] bytes = value.toByteArray();
		byte[] fixed = new byte[Math.max(length, 0)];

		for (int index = 0; index < fixed.length && index < bytes.length; ++index)
			fixed[fixed.length - 1 - index] = bytes[bytes.length - 1 - index];

		return fixed;
	}

	/**
	 * The limits one parse runs under.
	 */
	@Immutable
	private static final class SetLimits {
		private final int bytes;
		private final int keys;

		private SetLimits(int bytes, int keys) {
			this.bytes = bytes;
			this.keys = keys;
		}
	}

	/**
	 * The set oracle's verdict.
	 */
	@Immutable
	private static final class SetOutcome {
		private static final SetOutcome FAILED = new SetOutcome(true, List.of(), List.of());

		private final boolean failed;
		private final List<KeyOutcome> keys;
		private final List<ParsedKeySet.Skip> skips;

		private SetOutcome(boolean failed, @NonNull List<@NonNull KeyOutcome> keys, @NonNull List<ParsedKeySet.@NonNull Skip> skips) {
			this.failed = failed;
			this.keys = List.copyOf(keys);
			this.skips = List.copyOf(skips);
		}
	}

	/**
	 * The key oracle's verdict: a skip reason, or every fact of the usable key.
	 */
	@Immutable
	private static final class KeyOutcome {
		private final JsonWebKeySkipReason skip;
		private final String keyId;
		private final String keyType;
		private final String curve;
		private final JwsAlgorithm algorithm;
		private final String use;
		private final String issuer;
		private final String thumbprint;
		private final KeyMaterial material;

		private KeyOutcome(@Nullable JsonWebKeySkipReason skip, @Nullable String keyId, @Nullable String keyType, @Nullable String curve, @Nullable JwsAlgorithm algorithm,
											 @Nullable String use, @Nullable String issuer, @Nullable String thumbprint, @Nullable KeyMaterial material) {
			this.skip = skip;
			this.keyId = keyId;
			this.keyType = keyType;
			this.curve = curve;
			this.algorithm = algorithm;
			this.use = use;
			this.issuer = issuer;
			this.thumbprint = thumbprint;
			this.material = material;
		}

		private static @NonNull KeyOutcome skipped(@NonNull JsonWebKeySkipReason skip) {
			return new KeyOutcome(skip, null, null, null, null, null, null, null, null);
		}
	}

	/**
	 * A key's public values, compared with a JCA key by value.
	 */
	@Immutable
	private static final class KeyMaterial {
		private final String curve;
		private final NamedCurve ecCurve;
		private final BigInteger first;
		private final BigInteger second;
		private final boolean xOdd;

		private KeyMaterial(@Nullable String curve, @Nullable NamedCurve ecCurve, @NonNull BigInteger first, @Nullable BigInteger second, boolean xOdd) {
			this.curve = curve;
			this.ecCurve = ecCurve;
			this.first = first;
			this.second = second;
			this.xOdd = xOdd;
		}

		private static @NonNull KeyMaterial rsa(@NonNull BigInteger n, @NonNull BigInteger e) {
			return new KeyMaterial(null, null, n, e, false);
		}

		private static @NonNull KeyMaterial ec(@NonNull String curve, @NonNull NamedCurve ecCurve, @NonNull BigInteger x, @NonNull BigInteger y) {
			return new KeyMaterial(curve, ecCurve, x, y, false);
		}

		private static @NonNull KeyMaterial ed25519(@NonNull BigInteger y, boolean xOdd) {
			return new KeyMaterial("Ed25519", null, y, null, xOdd);
		}

		private boolean isSameKey(@NonNull PublicKey key) {
			try {
				if (this.curve == null)
					return key instanceof RSAPublicKey rsa && rsa.getModulus().equals(this.first)
							&& rsa.getPublicExponent().equals(this.second);

				if (this.ecCurve != null)
					return key instanceof ECPublicKey ec && this.ecCurve.describes(ec.getParams())
							&& ec.getW().getAffineX().equals(this.first) && ec.getW().getAffineY().equals(this.second);

				return key instanceof EdECPublicKey ed && ed.getParams().getName().equals("Ed25519")
						&& ed.getPoint().getY().equals(this.first) && ed.getPoint().isXOdd() == this.xOdd;
			} catch (RuntimeException e) {
				return false;
			}
		}
	}

	/**
	 * A NIST prime curve as the JDK names it.
	 */
	@Immutable
	private static final class NamedCurve {
		private final ECParameterSpec parameters;
		private final BigInteger fieldPrime;
		private final int coordinateLength;

		private NamedCurve(@NonNull ECParameterSpec parameters) {
			this.parameters = parameters;
			this.fieldPrime = ((ECFieldFp) parameters.getCurve().getField()).getP();
			this.coordinateLength = (this.fieldPrime.bitLength() + 7) / 8;
		}

		private static @NonNull NamedCurve fromJdkName(@NonNull String name) {
			try {
				AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
				parameters.init(new ECGenParameterSpec(name));
				return new NamedCurve(parameters.getParameterSpec(ECParameterSpec.class));
			} catch (GeneralSecurityException e) {
				throw new IllegalStateException("The JDK does not name " + name, e);
			}
		}

		/**
		 * SEC 1 section 3.2.2.1's point check for an affine point: both coordinates in {@code [0, p)} and
		 * {@code y^2 = x^3 + ax + b}.
		 */
		private boolean isOnCurve(@NonNull BigInteger x, @NonNull BigInteger y) {
			BigInteger p = this.fieldPrime;

			if (x.compareTo(p) >= 0 || y.compareTo(p) >= 0)
				return false;

			BigInteger left = y.multiply(y).mod(p);
			BigInteger right = x.pow(3).add(this.parameters.getCurve().getA().multiply(x))
					.add(this.parameters.getCurve().getB()).mod(p);
			return left.equals(right);
		}

		/**
		 * A {@code y} with {@code (x, y)} on the curve, or {@code null}; every curve here has {@code p = 3 mod 4}.
		 */
		private @Nullable BigInteger yFor(@NonNull BigInteger x) {
			BigInteger p = this.fieldPrime;
			BigInteger right = x.pow(3).add(this.parameters.getCurve().getA().multiply(x))
					.add(this.parameters.getCurve().getB()).mod(p);
			BigInteger y = right.modPow(p.add(BigInteger.ONE).shiftRight(2), p);
			return y.multiply(y).mod(p).equals(right) ? y : null;
		}

		private @NonNull BigInteger generatorX() {
			return this.parameters.getGenerator().getAffineX();
		}

		private @NonNull BigInteger generatorY() {
			return this.parameters.getGenerator().getAffineY();
		}

		private boolean describes(@Nullable ECParameterSpec other) {
			return other != null && other.getCurve().equals(this.parameters.getCurve())
					&& other.getGenerator().equals(this.parameters.getGenerator())
					&& other.getOrder().equals(this.parameters.getOrder())
					&& other.getCofactor() == this.parameters.getCofactor();
		}
	}

}
