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

import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.EcPublicKeys;
import com.revetsec.internal.crypto.Ed25519PublicKeys;
import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.internal.crypto.KeyRejectedException;
import com.revetsec.internal.crypto.RsaPublicKeys;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StandardBase64;
import com.revetsec.internal.json.JsonFieldException;
import com.revetsec.internal.json.Rfc7638;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.pem.PemException;
import com.revetsec.jose.JsonWebKeySkipReason;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Turns one JSON Web Key (RFC 7517 section 4) into a {@link VerificationKey}, or refuses it with the
 * {@link JsonWebKeySkipReason} of the first rule it breaks (plan M2-7, "Keys"). A refused key is skipped, never used
 * for its public half, and never fails its key set.
 * <p>
 * <strong>The rules, in order:</strong>
 * <ol>
 *   <li>{@code kty} is present and a string, else {@code MALFORMED_KEY};</li>
 *   <li>{@code kty} is {@code RSA}, {@code EC} or {@code OKP}; {@code oct} is {@code SYMMETRIC_KEY}, and anything
 *   else {@code UNSUPPORTED_KEY_TYPE};</li>
 *   <li>none of {@code d}, {@code p}, {@code q}, {@code dp}, {@code dq}, {@code qi}, {@code oth} and {@code k} is
 *   present, whatever its value, else {@code PRIVATE_KEY_MEMBERS};</li>
 *   <li>{@code use}, when present, is exactly the string {@code sig}; {@code key_ops}, when present, is an array of
 *   strings that contains {@code verify}, and, when {@code use} is present too, holds only {@code sign} and
 *   {@code verify} (RFC 7517 section 4.3: the two must agree). Otherwise {@code NOT_A_VERIFICATION_KEY};</li>
 *   <li>{@code alg}, when present, is a string that names a {@link JwsAlgorithm}, else {@code UNSUPPORTED_ALGORITHM};
 *   and that algorithm is for this key type and, when {@code crv} names another supported curve, for that curve:
 *   {@code ES384} on a P-256 key and any {@code HS*} are {@code ALGORITHM_MISMATCH}. A curve Revetsec does not
 *   support is left to the next rule;</li>
 *   <li>a string {@code crv} is P-256, P-384 or P-521 for {@code EC}, and Ed25519 for {@code OKP}, else
 *   {@code UNSUPPORTED_CURVE};</li>
 *   <li>{@code kid}, when present, is a string of 1 to {@value #MAXIMUM_KEY_ID_LENGTH} characters; {@code issuer},
 *   when present, is a non-empty string (JSON {@code null} included, so an unusable issuer never counts as absent:
 *   INV-C6); the key members are present, strings and canonical unpadded base64url: {@code n} and {@code e} minimal
 *   with an odd {@code n}, EC coordinates exactly the curve's length, and an Ed25519 {@code x} of 32 octets that
 *   decodes to a curve point (RFC 8032 section 5.1.3). Otherwise {@code MALFORMED_KEY};</li>
 *   <li>the RSA modulus has 2048 to 16384 bits, else {@code RSA_KEY_SIZE};</li>
 *   <li>the RSA public exponent is odd, from 65537 to below 2<sup>32</sup>, else {@code RSA_EXPONENT};</li>
 *   <li>the EC point is on its curve, with coordinates below the field prime, else {@code EC_POINT_NOT_ON_CURVE};</li>
 *   <li>the RSA modulus has no ROCA fingerprint and the Ed25519 point does not have small order, else
 *   {@code WEAK_KEY};</li>
 *   <li>{@code x5c}, when present, is an array whose first element is standard padded base64 of a certificate that
 *   {@code Pem.parseCertificateDer} accepts, and that certificate holds exactly this key; else
 *   {@code CERTIFICATE_MISMATCH}. Nothing else about the certificate is checked, and the rest of the chain is
 *   ignored.</li>
 * </ol>
 * Other members, such as {@code x5t}, {@code x5u} and {@code cloud_instance_name}, are ignored. Rules 8 to 11 are
 * {@code internal.crypto}'s key policy, in its own order, and every check of rule 7 runs before them, so a malformed
 * member always wins over a weak key. The RFC 7638 thumbprint is computed
 * last, over members that are then known to be canonical, because a leading zero octet or a short EC coordinate would
 * give the same key another thumbprint.
 * <p>
 * An unexpected {@link RuntimeException} while parsing refuses the key as {@code MALFORMED_KEY} (INV-G1); the JCA's
 * own unchecked exceptions are already contained by {@code internal.crypto}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JwkParser {
	/**
	 * The longest {@code kid} accepted, in characters.
	 */
	public static final int MAXIMUM_KEY_ID_LENGTH = 256;

	/**
	 * The members that hold private or symmetric key material (RFC 7518 sections 6.2.2, 6.3.2 and 6.4.1; RFC 8037
	 * section 2).
	 */
	@NonNull
	private static final List<@NonNull String> PRIVATE_MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k");
	private static final String SIGNATURE_USE = "sig";
	private static final String VERIFY_OPERATION = "verify";
	private static final String SIGN_OPERATION = "sign";

	private JwkParser() {
		// Static helpers only.
	}

	/**
	 * Parses one JWK under the rules in the class documentation.
	 *
	 * @param jwk the JWK
	 * @return the usable key
	 * @throws NullPointerException if {@code jwk} is {@code null}
	 * @throws SkippedKeyException  if a rule refuses the key; its reason names the first rule that did
	 */
	@NonNull
	public static VerificationKey parse(@NonNull JsonObject jwk) throws SkippedKeyException {
		requireNonNull(jwk);

		try {
			return parseMembers(jwk);
		} catch (RuntimeException e) {
			throw skip(JsonWebKeySkipReason.MALFORMED_KEY);
		}
	}

	@NonNull
	private static VerificationKey parseMembers(@NonNull JsonObject jwk) throws SkippedKeyException {
		Map<@NonNull String, @NonNull JsonValue> members = jwk.getMembers();

		// Rules 1 and 2.
		String keyType = requiredString(members, "kty");
		switch (keyType) {
			case Algorithms.RSA_KEY_TYPE, Algorithms.EC_KEY_TYPE, Algorithms.OKP_KEY_TYPE -> {
				// Supported.
			}
			case Algorithms.OCT_KEY_TYPE -> throw skip(JsonWebKeySkipReason.SYMMETRIC_KEY);
			default -> throw skip(JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE);
		}

		// Rule 3.
		for (String name : PRIVATE_MEMBERS)
			if (members.containsKey(name))
				throw skip(JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS);

		// Rules 4 to 6.
		String use = checkUse(members);
		JwsAlgorithm algorithm = checkAlgorithm(members, keyType);
		checkCurve(members, keyType);

		// Rule 7, for the members that are not key material, then rules 7 to 11 for the key.
		String keyId = optionalKeyId(members);
		String issuer = optionalIssuer(members);
		String curve;
		PublicKey publicKey;

		try {
			if (keyType.equals(Algorithms.RSA_KEY_TYPE)) {
				curve = null;
				publicKey = RsaPublicKeys.fromComponents(requiredBase64Url(members, "n"), requiredBase64Url(members, "e"));
			} else if (keyType.equals(Algorithms.EC_KEY_TYPE)) {
				String curveName = requiredString(members, "crv");
				// Rule 6 has already refused a string crv that names no supported curve.
				EcCurve ecCurve = EcCurve.findByName(curveName)
						.orElseThrow(() -> skip(JsonWebKeySkipReason.UNSUPPORTED_CURVE));
				curve = curveName;
				publicKey = EcPublicKeys.fromCoordinates(ecCurve, requiredBase64Url(members, "x"),
						requiredBase64Url(members, "y"));
			} else {
				String curveName = requiredString(members, "crv");
				if (!isSupportedCurve(Algorithms.OKP_KEY_TYPE, curveName))
					throw skip(JsonWebKeySkipReason.UNSUPPORTED_CURVE);
				curve = curveName;
				publicKey = Ed25519PublicKeys.fromEncoded(requiredBase64Url(members, "x"));
			}
		} catch (KeyRejectedException e) {
			throw skip(reasonFor(e.getKind()));
		}

		// Rule 12, then the thumbprint over members now known to be canonical.
		checkCertificate(members, publicKey);

		return new VerificationKey(keyId, keyType, curve, algorithm, use, issuer, thumbprint(jwk), publicKey);
	}

	/**
	 * Rule 4. Returns {@code sig} if {@code use} is present, else {@code null}.
	 */
	@Nullable
	private static String checkUse(@NonNull Map<@NonNull String, @NonNull JsonValue> members)
			throws SkippedKeyException {
		JsonValue use = members.get("use");
		if (use != null && !(use instanceof JsonString string && string.getValue().equals(SIGNATURE_USE)))
			throw skip(JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY);

		JsonValue keyOperations = members.get("key_ops");
		if (keyOperations != null) {
			if (!(keyOperations instanceof JsonArray operations))
				throw skip(JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY);

			boolean verify = false;
			for (JsonValue element : operations.getElements()) {
				if (!(element instanceof JsonString operation))
					throw skip(JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY);
				if (operation.getValue().equals(VERIFY_OPERATION))
					verify = true;
				else if (use != null && !operation.getValue().equals(SIGN_OPERATION))
					throw skip(JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY);
			}

			if (!verify)
				throw skip(JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY);
		}

		return use == null ? null : SIGNATURE_USE;
	}

	/**
	 * Rule 5. Returns the key's algorithm, or {@code null} if {@code alg} is absent.
	 */
	@Nullable
	private static JwsAlgorithm checkAlgorithm(@NonNull Map<@NonNull String, @NonNull JsonValue> members,
																						 @NonNull String keyType) throws SkippedKeyException {
		JsonValue value = members.get("alg");
		if (value == null)
			return null;
		if (!(value instanceof JsonString string))
			throw skip(JsonWebKeySkipReason.UNSUPPORTED_ALGORITHM);

		JwsAlgorithm algorithm = JwsAlgorithm.findByWireValue(string.getValue())
				.orElseThrow(() -> skip(JsonWebKeySkipReason.UNSUPPORTED_ALGORITHM));

		// A key set never supplies an HMAC key, so an HS* alg is for another key type whatever kty says.
		if (Algorithms.familyOf(algorithm) == Algorithms.Family.HMAC || !Algorithms.keyTypeOf(algorithm).equals(keyType))
			throw skip(JsonWebKeySkipReason.ALGORITHM_MISMATCH);

		// Another supported curve than the algorithm's is a mismatch; a curve Revetsec does not support is rule 6's.
		if (members.get("crv") instanceof JsonString curve && isSupportedCurve(keyType, curve.getValue())
				&& !Algorithms.findCurveName(algorithm).orElse("").equals(curve.getValue()))
			throw skip(JsonWebKeySkipReason.ALGORITHM_MISMATCH);

		return algorithm;
	}

	/**
	 * Rule 6. A {@code crv} that is absent or not a string is rule 7's.
	 */
	private static void checkCurve(@NonNull Map<@NonNull String, @NonNull JsonValue> members,
																 @NonNull String keyType) throws SkippedKeyException {
		if (!keyType.equals(Algorithms.RSA_KEY_TYPE) && members.get("crv") instanceof JsonString curve
				&& !isSupportedCurve(keyType, curve.getValue()))
			throw skip(JsonWebKeySkipReason.UNSUPPORTED_CURVE);
	}

	/**
	 * Whether {@code curve} is a curve Revetsec supports for {@code keyType}: P-256, P-384 and P-521 for {@code EC},
	 * Ed25519 for {@code OKP}, and none for {@code RSA}.
	 */
	private static boolean isSupportedCurve(@NonNull String keyType,
																					@NonNull String curve) {
		return switch (keyType) {
			case Algorithms.EC_KEY_TYPE -> EcCurve.findByName(curve).isPresent();
			case Algorithms.OKP_KEY_TYPE -> curve.equals(Algorithms.ED25519_CURVE);
			default -> false;
		};
	}

	/**
	 * Rule 7 for {@code kid}.
	 */
	@Nullable
	private static String optionalKeyId(@NonNull Map<@NonNull String, @NonNull JsonValue> members)
			throws SkippedKeyException {
		JsonValue value = members.get("kid");
		if (value == null)
			return null;
		if (!(value instanceof JsonString string) || string.getValue().isEmpty()
				|| string.getValue().length() > MAXIMUM_KEY_ID_LENGTH)
			throw skip(JsonWebKeySkipReason.MALFORMED_KEY);
		return string.getValue();
	}

	/**
	 * Rule 7 for the JWK {@code issuer} member: a member that is present but unusable refuses the key, so it can never
	 * count as absent and make the key usable for every issuer (INV-C6).
	 */
	@Nullable
	private static String optionalIssuer(@NonNull Map<@NonNull String, @NonNull JsonValue> members)
			throws SkippedKeyException {
		JsonValue value = members.get("issuer");
		if (value == null)
			return null;
		if (!(value instanceof JsonString string) || string.getValue().isEmpty())
			throw skip(JsonWebKeySkipReason.MALFORMED_KEY);
		return string.getValue();
	}

	@NonNull
	private static String requiredString(@NonNull Map<@NonNull String, @NonNull JsonValue> members,
																			 @NonNull String name) throws SkippedKeyException {
		if (!(members.get(name) instanceof JsonString string))
			throw skip(JsonWebKeySkipReason.MALFORMED_KEY);
		return string.getValue();
	}

	private static byte @NonNull [] requiredBase64Url(@NonNull Map<@NonNull String, @NonNull JsonValue> members,
																										@NonNull String name) throws SkippedKeyException {
		try {
			return Base64Url.decode(requiredString(members, name));
		} catch (EncodingException e) {
			throw skip(JsonWebKeySkipReason.MALFORMED_KEY);
		}
	}

	/**
	 * Rule 12.
	 */
	private static void checkCertificate(@NonNull Map<@NonNull String, @NonNull JsonValue> members,
																			 @NonNull PublicKey publicKey) throws SkippedKeyException {
		JsonValue value = members.get("x5c");
		if (value == null)
			return;
		if (!(value instanceof JsonArray chain) || chain.getElements().isEmpty()
				|| !(chain.getElements().get(0) instanceof JsonString first))
			throw skip(JsonWebKeySkipReason.CERTIFICATE_MISMATCH);

		PublicKey certificateKey;

		try {
			// RFC 7517 section 4.7: standard base64 of the DER, not base64url.
			certificateKey = Pem.parseCertificateDer(StandardBase64.decode(first.getValue())).getPublicKey();
		} catch (EncodingException | PemException | RuntimeException e) {
			throw skip(JsonWebKeySkipReason.CERTIFICATE_MISMATCH);
		}

		if (!isSameKey(publicKey, certificateKey))
			throw skip(JsonWebKeySkipReason.CERTIFICATE_MISMATCH);
	}

	/**
	 * Whether {@code certificateKey} is the same key as {@code publicKey}, by value: the RSA modulus and exponent, the
	 * EC curve and point, or the Ed25519 point. The certificate's key need not come from the same provider.
	 */
	static boolean isSameKey(@NonNull PublicKey publicKey,
													 @Nullable PublicKey certificateKey) {
		try {
			if (publicKey instanceof RSAPublicKey rsa)
				return certificateKey instanceof RSAPublicKey other && rsa.getModulus().equals(other.getModulus())
						&& rsa.getPublicExponent().equals(other.getPublicExponent());

			if (publicKey instanceof ECPublicKey ec) {
				Optional<EcCurve> curve = EcCurve.findByParameterSpec(ec.getParams());
				return certificateKey instanceof ECPublicKey other && curve.isPresent()
						&& curve.get().isDescribedBy(other.getParams()) && ec.getW().equals(other.getW());
			}

			if (publicKey instanceof EdECPublicKey ed && certificateKey instanceof EdECPublicKey other) {
				EdECPoint point = ed.getPoint();
				EdECPoint otherPoint = other.getPoint();
				return other.getParams().getName().equals(NamedParameterSpec.ED25519.getName())
						&& point.isXOdd() == otherPoint.isXOdd() && point.getY().equals(otherPoint.getY());
			}

			return false;
		} catch (RuntimeException e) {
			// A key implementation outside the JDK may throw from its accessors.
			return false;
		}
	}

	/**
	 * The RFC 7638 SHA-256 thumbprint, in unpadded base64url.
	 */
	@NonNull
	private static String thumbprint(@NonNull JsonObject jwk) throws SkippedKeyException {
		try {
			byte[] canonical = Rfc7638.canonicalJwk(jwk);
			return Base64Url.encode(MessageDigest.getInstance(HashAlgorithm.SHA_256.getDigestName()).digest(canonical));
		} catch (JsonFieldException | GeneralSecurityException e) {
			// Unreachable once every member is canonical base64url; SHA-256 is in every JDK.
			throw skip(JsonWebKeySkipReason.MALFORMED_KEY);
		}
	}

	@NonNull
	private static JsonWebKeySkipReason reasonFor(KeyRejectedException.@NonNull Kind kind) {
		return switch (kind) {
			case MALFORMED, SECRET_TOO_SHORT -> JsonWebKeySkipReason.MALFORMED_KEY;
			case RSA_KEY_SIZE -> JsonWebKeySkipReason.RSA_KEY_SIZE;
			case RSA_EXPONENT -> JsonWebKeySkipReason.RSA_EXPONENT;
			case NOT_ON_CURVE -> JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE;
			case WEAK -> JsonWebKeySkipReason.WEAK_KEY;
		};
	}

	@NonNull
	private static SkippedKeyException skip(@NonNull JsonWebKeySkipReason reason) {
		return new SkippedKeyException(reason);
	}
}
