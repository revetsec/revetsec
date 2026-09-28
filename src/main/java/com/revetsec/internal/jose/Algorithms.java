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
import com.revetsec.internal.crypto.Ed25519PublicKeys;
import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.jose.JwsAlgorithm;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * What each {@link JwsAlgorithm} means to the verifier (RFC 7518 section 3.1, RFC 8037 section 3.1, RFC 9864): its
 * family, the key type and curve it needs, its hash, and the fixed length of its signatures where it has one.
 * <p>
 * Everything is decided by {@code switch}, never by comparing names. The one alias is between {@code EdDSA} and
 * {@code Ed25519}, and only on an Ed25519 key ({@link #isAlias(JwsAlgorithm, JwsAlgorithm)}); the allowlist never
 * applies it.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class Algorithms {
	/**
	 * The JWK {@code kty} of RSA keys (RFC 7518 section 6.3).
	 */
	public static final String RSA_KEY_TYPE = "RSA";
	/**
	 * The JWK {@code kty} of EC keys (RFC 7518 section 6.2).
	 */
	public static final String EC_KEY_TYPE = "EC";
	/**
	 * The JWK {@code kty} of octet key pairs, Ed25519 among them (RFC 8037 section 2).
	 */
	public static final String OKP_KEY_TYPE = "OKP";
	/**
	 * The JWK {@code kty} of symmetric keys (RFC 7518 section 6.4).
	 */
	public static final String OCT_KEY_TYPE = "oct";
	/**
	 * The JWK {@code crv} of Ed25519 keys (RFC 8037 section 2).
	 */
	public static final String ED25519_CURVE = "Ed25519";

	private Algorithms() {
		// Static helpers only.
	}

	/**
	 * Returns the family of {@code algorithm}.
	 *
	 * @param algorithm the algorithm
	 * @return its family
	 */
	@NonNull
	public static Family familyOf(@NonNull JwsAlgorithm algorithm) {
		return switch (requireNonNull(algorithm)) {
			case RS256, RS384, RS512 -> Family.RSA_PKCS1;
			case PS256, PS384, PS512 -> Family.RSA_PSS;
			case ES256, ES384, ES512 -> Family.ECDSA;
			case ED25519, EDDSA -> Family.EDDSA;
			case HS256, HS384, HS512 -> Family.HMAC;
		};
	}

	/**
	 * Returns whether {@code algorithm} is an RSA algorithm, PKCS #1 v1.5 or PSS.
	 *
	 * @param algorithm the algorithm
	 * @return {@code true} for {@code RS*} and {@code PS*}
	 */
	public static boolean isRsa(@NonNull JwsAlgorithm algorithm) {
		Family family = familyOf(algorithm);
		return family == Family.RSA_PKCS1 || family == Family.RSA_PSS;
	}

	/**
	 * Returns the one RSA algorithm in {@code algorithms}, if it holds exactly one. An RSA key without {@code alg} is
	 * usable only for that algorithm (RFC 8725 section 3.1, read 2026-09-28: one algorithm per key; gate 8, G8-2).
	 *
	 * @param algorithms the effective algorithm set
	 * @return the sole RSA algorithm, or empty if the set holds none or more than one
	 */
	@NonNull
	public static Optional<@NonNull JwsAlgorithm> findSoleRsaAlgorithm(@NonNull Set<@NonNull JwsAlgorithm> algorithms) {
		requireNonNull(algorithms);
		JwsAlgorithm sole = null;

		for (JwsAlgorithm algorithm : algorithms) {
			if (!isRsa(algorithm))
				continue;
			if (sole != null)
				return Optional.empty();
			sole = algorithm;
		}

		return Optional.ofNullable(sole);
	}

	/**
	 * Returns the JWK {@code kty} of the keys {@code algorithm} verifies with.
	 *
	 * @param algorithm the algorithm
	 * @return {@code RSA}, {@code EC}, {@code OKP} or {@code oct}
	 */
	@NonNull
	public static String keyTypeOf(@NonNull JwsAlgorithm algorithm) {
		return switch (familyOf(algorithm)) {
			case RSA_PKCS1, RSA_PSS -> RSA_KEY_TYPE;
			case ECDSA -> EC_KEY_TYPE;
			case EDDSA -> OKP_KEY_TYPE;
			case HMAC -> OCT_KEY_TYPE;
		};
	}

	/**
	 * Returns the JWK {@code crv} of the keys {@code algorithm} verifies with: {@code P-256}, {@code P-384} or
	 * {@code P-521} for ECDSA, and {@code Ed25519} for EdDSA.
	 *
	 * @param algorithm the algorithm
	 * @return the curve name, or empty for RSA and HMAC algorithms
	 */
	@NonNull
	public static Optional<@NonNull String> findCurveName(@NonNull JwsAlgorithm algorithm) {
		return switch (requireNonNull(algorithm)) {
			case ES256 -> Optional.of(EcCurve.P_256.getName());
			case ES384 -> Optional.of(EcCurve.P_384.getName());
			case ES512 -> Optional.of(EcCurve.P_521.getName());
			case ED25519, EDDSA -> Optional.of(ED25519_CURVE);
			default -> Optional.empty();
		};
	}

	/**
	 * Returns the curve of an ECDSA algorithm.
	 *
	 * @param algorithm the algorithm
	 * @return the curve, or empty for every algorithm but {@code ES256}, {@code ES384} and {@code ES512}
	 */
	@NonNull
	public static Optional<@NonNull EcCurve> findEcCurve(@NonNull JwsAlgorithm algorithm) {
		return switch (requireNonNull(algorithm)) {
			case ES256 -> Optional.of(EcCurve.P_256);
			case ES384 -> Optional.of(EcCurve.P_384);
			case ES512 -> Optional.of(EcCurve.P_521);
			default -> Optional.empty();
		};
	}

	/**
	 * Returns the hash of {@code algorithm}.
	 *
	 * @param algorithm the algorithm
	 * @return the hash, or empty for EdDSA, whose hash is part of the signature scheme
	 */
	@NonNull
	public static Optional<@NonNull HashAlgorithm> findHash(@NonNull JwsAlgorithm algorithm) {
		return switch (requireNonNull(algorithm)) {
			case RS256, PS256, ES256, HS256 -> Optional.of(HashAlgorithm.SHA_256);
			case RS384, PS384, ES384, HS384 -> Optional.of(HashAlgorithm.SHA_384);
			case RS512, PS512, ES512, HS512 -> Optional.of(HashAlgorithm.SHA_512);
			case ED25519, EDDSA -> Optional.empty();
		};
	}

	/**
	 * Returns the fixed signature length of {@code algorithm}, in octets: 64, 96 or 132 for ECDSA (R and S, each the
	 * curve's coordinate length), 64 for EdDSA, and the hash length for HMAC.
	 *
	 * @param algorithm the algorithm
	 * @return the length, or empty for RSA algorithms, whose signatures are as long as the key's modulus
	 */
	@NonNull
	public static Optional<@NonNull Integer> findSignatureLength(@NonNull JwsAlgorithm algorithm) {
		return switch (familyOf(algorithm)) {
			case ECDSA -> findEcCurve(algorithm).map(EcCurve::getSignatureLength);
			case EDDSA -> Optional.of(Ed25519PublicKeys.SIGNATURE_LENGTH);
			case HMAC -> findHash(algorithm).map(HashAlgorithm::getLength);
			case RSA_PKCS1, RSA_PSS -> Optional.empty();
		};
	}

	/**
	 * Returns whether a key whose JWK {@code alg} is {@code keyAlgorithm} verifies a token whose {@code alg} is
	 * {@code tokenAlgorithm} although they differ: only {@code EdDSA} and {@code Ed25519}, in either order. The caller
	 * has already required an Ed25519 key, on which both name EdDSA with the Ed25519 parameter set (RFC 9864 sections 2.2
	 * and 5, read 2026-09-28; the RFC itself defines no alias).
	 *
	 * @param keyAlgorithm   the key's {@code alg}
	 * @param tokenAlgorithm the token's {@code alg}
	 * @return {@code true} if the two are {@code EdDSA} and {@code Ed25519}
	 */
	public static boolean isAlias(@NonNull JwsAlgorithm keyAlgorithm,
																@NonNull JwsAlgorithm tokenAlgorithm) {
		requireNonNull(keyAlgorithm);
		requireNonNull(tokenAlgorithm);
		return (keyAlgorithm == JwsAlgorithm.EDDSA && tokenAlgorithm == JwsAlgorithm.ED25519)
				|| (keyAlgorithm == JwsAlgorithm.ED25519 && tokenAlgorithm == JwsAlgorithm.EDDSA);
	}

	/**
	 * The signature scheme behind a {@link JwsAlgorithm}.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum Family {
		/**
		 * RSASSA-PKCS1-v1_5 ({@code RS*}).
		 */
		RSA_PKCS1,
		/**
		 * RSASSA-PSS ({@code PS*}).
		 */
		RSA_PSS,
		/**
		 * ECDSA on a NIST prime curve ({@code ES*}).
		 */
		ECDSA,
		/**
		 * EdDSA over Ed25519 ({@code Ed25519} and {@code EdDSA}).
		 */
		EDDSA,
		/**
		 * HMAC ({@code HS*}), only ever over a configured secret.
		 */
		HMAC
	}
}
