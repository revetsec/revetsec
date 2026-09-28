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
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * What a token asks of a key set: its algorithm, its {@code kid} if it has one, and the effective algorithm set the
 * token was checked against, which decides whether an RSA key without {@code alg} may verify it (INV-J3, G8-2).
 * {@link KeySelector} answers it against a list of keys, and a remote key source against its cached key set.
 * <p>
 * The effective set is Revetsec's algorithms intersected with the configured ones, and with the provider's advertised
 * ones where a specification defines them; the token's algorithm is in it, compared exactly.
 *
 * @param algorithm         the token's {@code alg}
 * @param keyId             the token's {@code kid}, already checked to be 1 to 256 characters, or {@code null} if the
 *                          header has none
 * @param allowedAlgorithms the effective algorithm set; copied
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public record KeyQuery(@NonNull JwsAlgorithm algorithm,
											 @Nullable String keyId,
											 @NonNull Set<@NonNull JwsAlgorithm> allowedAlgorithms) {
	/**
	 * Checks and copies the components.
	 *
	 * @throws NullPointerException     if {@code algorithm} or {@code allowedAlgorithms} (or an element) is
	 *                                  {@code null}
	 * @throws IllegalArgumentException if {@code algorithm} is not in {@code allowedAlgorithms}
	 */
	public KeyQuery {
		requireNonNull(algorithm);
		allowedAlgorithms = Set.copyOf(allowedAlgorithms);

		if (!allowedAlgorithms.contains(algorithm))
			throw new IllegalArgumentException("A key query's algorithm must be in its effective algorithm set.");
	}

	/**
	 * Returns whether an RSA key without {@code alg} may verify this token: only when the effective set holds exactly
	 * one RSA algorithm, which is then the token's (RFC 8725 section 3.1, read 2026-09-28: one algorithm per key;
	 * G8-2).
	 *
	 * @return {@code true} if the token's algorithm is the effective set's only RSA algorithm
	 */
	public boolean allowsRsaKeyWithoutAlgorithm() {
		return Algorithms.findSoleRsaAlgorithm(this.allowedAlgorithms).equals(Optional.of(this.algorithm));
	}

	/**
	 * Describes this query without the {@code kid}, which the token's sender chose.
	 *
	 * @return the description
	 */
	@Override
	@NonNull
	public String toString() {
		Set<JwsAlgorithm> sorted = EnumSet.noneOf(JwsAlgorithm.class);
		sorted.addAll(this.allowedAlgorithms);
		return getClass().getSimpleName() + "{algorithm=" + this.algorithm.getWireValue() + ", keyIdPresent="
				+ (this.keyId != null) + ", allowedAlgorithms=" + sorted + "}";
	}
}
