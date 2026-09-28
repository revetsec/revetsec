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

import com.revetsec.jose.JwsAlgorithm;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.security.PublicKey;

import static java.util.Objects.requireNonNull;

/**
 * One usable public verification key from a JSON Web Key Set: every rule in {@link JwkParser} passed, and the JCA
 * key has been built.
 * <p>
 * The JWK {@code issuer} member is kept here, never in public API: when present, it must match the token's
 * {@code iss} (INV-C6, and M2-11's one template). Equality compares every component, the JCA key by its encoding.
 *
 * @param keyId            the {@code kid}, 1 to 256 characters, or {@code null} if absent
 * @param keyType          the {@code kty}: {@code RSA}, {@code EC} or {@code OKP}
 * @param curve            the {@code crv} ({@code P-256}, {@code P-384}, {@code P-521} or {@code Ed25519}), or
 *                         {@code null} for an RSA key
 * @param algorithm        the {@code alg}, or {@code null} if absent
 * @param use              the {@code use} ({@code sig}), or {@code null} if absent
 * @param issuer           the JWK {@code issuer} member, a non-empty string, or {@code null} if absent
 * @param thumbprintSha256 the RFC 7638 SHA-256 thumbprint, in unpadded base64url
 * @param publicKey        the JCA public key
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public record VerificationKey(@Nullable String keyId,
															@NonNull String keyType,
															@Nullable String curve,
															@Nullable JwsAlgorithm algorithm,
															@Nullable String use,
															@Nullable String issuer,
															@NonNull String thumbprintSha256,
															@NonNull PublicKey publicKey) {
	/**
	 * Checks the required components.
	 *
	 * @throws NullPointerException if {@code keyType}, {@code thumbprintSha256} or {@code publicKey} is {@code null}
	 */
	public VerificationKey {
		requireNonNull(keyType);
		requireNonNull(thumbprintSha256);
		requireNonNull(publicKey);
	}

	/**
	 * Describes the key by its public facts, without the key ID or the issuer member, which come from the key set's
	 * author.
	 *
	 * @return the description
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{kty=" + this.keyType + (this.curve == null ? "" : ", crv=" + this.curve)
				+ (this.algorithm == null ? "" : ", alg=" + this.algorithm.getWireValue()) + ", thumbprint="
				+ this.thumbprintSha256 + "}";
	}
}
