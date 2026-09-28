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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * A JWS signature algorithm, named by its {@code alg} header value (RFC 7515 section 4.1.1, RFC 7518 section 3.1,
 * RFC 8037 section 3.1 and RFC 9864).
 * <p>
 * Revetsec verifies RSASSA-PKCS1-v1_5 ({@code RS*}), RSASSA-PSS ({@code PS*}), ECDSA on P-256, P-384 and P-521
 * ({@code ES*}) and EdDSA over Ed25519, which RFC 9864 names {@code Ed25519} and the older RFC 8037 names
 * {@code EdDSA}. {@code EdDSA} is accepted for Ed25519 keys only. The HMAC algorithms ({@code HS*}) can be named here,
 * but {@link JwtValidator} refuses them: it verifies only with public keys. There is no constant for {@code none}.
 * <p>
 * Wire values are compared exactly and case-sensitively, so {@code rs256} and {@code NONE} name no algorithm here.
 * <p>
 * This enum is not switch-stable: a later release may add constants, so a {@code switch} over it needs a default
 * branch.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public enum JwsAlgorithm {
	/**
	 * RSASSA-PKCS1-v1_5 with SHA-256 ({@code RS256}, RFC 7518 section 3.3).
	 */
	RS256("RS256"),
	/**
	 * RSASSA-PKCS1-v1_5 with SHA-384 ({@code RS384}, RFC 7518 section 3.3).
	 */
	RS384("RS384"),
	/**
	 * RSASSA-PKCS1-v1_5 with SHA-512 ({@code RS512}, RFC 7518 section 3.3).
	 */
	RS512("RS512"),
	/**
	 * RSASSA-PSS with SHA-256, MGF1 with SHA-256 and a 32-byte salt ({@code PS256}, RFC 7518 section 3.5).
	 */
	PS256("PS256"),
	/**
	 * RSASSA-PSS with SHA-384, MGF1 with SHA-384 and a 48-byte salt ({@code PS384}, RFC 7518 section 3.5).
	 */
	PS384("PS384"),
	/**
	 * RSASSA-PSS with SHA-512, MGF1 with SHA-512 and a 64-byte salt ({@code PS512}, RFC 7518 section 3.5).
	 */
	PS512("PS512"),
	/**
	 * ECDSA on P-256 with SHA-256 ({@code ES256}, RFC 7518 section 3.4).
	 */
	ES256("ES256"),
	/**
	 * ECDSA on P-384 with SHA-384 ({@code ES384}, RFC 7518 section 3.4).
	 */
	ES384("ES384"),
	/**
	 * ECDSA on P-521 with SHA-512 ({@code ES512}, RFC 7518 section 3.4).
	 */
	ES512("ES512"),
	/**
	 * EdDSA over Ed25519, by its fully specified name ({@code Ed25519}, RFC 9864).
	 */
	ED25519("Ed25519"),
	/**
	 * EdDSA ({@code EdDSA}, RFC 8037 section 3.1), accepted for Ed25519 keys only. RFC 9864 deprecates this name
	 * (section 4.1.2) in favor of fully specified ones, {@link #ED25519} for Ed25519 keys (section 2.2). On an Ed25519
	 * key both name the same operation, so a key whose {@code alg} is one of the two verifies tokens that name the
	 * other; that alias is Revetsec's, not the RFC's.
	 */
	EDDSA("EdDSA"),
	/**
	 * HMAC with SHA-256 ({@code HS256}, RFC 7518 section 3.2). {@link JwtValidator} refuses it.
	 */
	HS256("HS256"),
	/**
	 * HMAC with SHA-384 ({@code HS384}, RFC 7518 section 3.2). {@link JwtValidator} refuses it.
	 */
	HS384("HS384"),
	/**
	 * HMAC with SHA-512 ({@code HS512}, RFC 7518 section 3.2). {@link JwtValidator} refuses it.
	 */
	HS512("HS512");

	@NonNull
	private final String wireValue;

	JwsAlgorithm(@NonNull String wireValue) {
		this.wireValue = wireValue;
	}

	/**
	 * Returns the algorithm named by an {@code alg} value, compared exactly and case-sensitively.
	 *
	 * @param wireValue the {@code alg} value, such as {@code RS256} or {@code Ed25519}
	 * @return the algorithm, or empty if {@code wireValue} names none of these algorithms
	 * @throws NullPointerException if {@code wireValue} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public static Optional<@NonNull JwsAlgorithm> findByWireValue(@NonNull String wireValue) {
		requireNonNull(wireValue);

		return switch (wireValue) {
			case "RS256" -> Optional.of(RS256);
			case "RS384" -> Optional.of(RS384);
			case "RS512" -> Optional.of(RS512);
			case "PS256" -> Optional.of(PS256);
			case "PS384" -> Optional.of(PS384);
			case "PS512" -> Optional.of(PS512);
			case "ES256" -> Optional.of(ES256);
			case "ES384" -> Optional.of(ES384);
			case "ES512" -> Optional.of(ES512);
			case "Ed25519" -> Optional.of(ED25519);
			case "EdDSA" -> Optional.of(EDDSA);
			case "HS256" -> Optional.of(HS256);
			case "HS384" -> Optional.of(HS384);
			case "HS512" -> Optional.of(HS512);
			default -> Optional.empty();
		};
	}

	/**
	 * Returns this algorithm's {@code alg} value.
	 *
	 * @return the {@code alg} value, such as {@code RS256} or {@code Ed25519}
	 * @since 1.0.0
	 */
	@NonNull
	public String getWireValue() {
		return this.wireValue;
	}
}
