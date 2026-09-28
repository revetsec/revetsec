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

import static java.util.Objects.requireNonNull;

/**
 * The members of a JOSE header that passed {@link JoseHeaderPolicy#check(byte[])}. Every other member was either
 * refused by the policy or is ignored (RFC 7515 section 4).
 *
 * @param algorithm the {@code alg}, in the effective algorithm set
 * @param keyId     the {@code kid}, 1 to {@value JwkParser#MAXIMUM_KEY_ID_LENGTH} characters, or {@code null} if
 *                  absent
 * @param type      the {@code typ} as received, which the policy allowed, or {@code null} if absent
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public record JoseHeader(@NonNull JwsAlgorithm algorithm,
												 @Nullable String keyId,
												 @Nullable String type) {
	/**
	 * Checks the required component.
	 *
	 * @throws NullPointerException if {@code algorithm} is {@code null}
	 */
	public JoseHeader {
		requireNonNull(algorithm);
	}

	/**
	 * Describes the header by its algorithm, and whether it has a {@code kid} and a {@code typ}; their values come from
	 * the token.
	 *
	 * @return the description
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{algorithm=" + this.algorithm.getWireValue() + ", keyIdPresent="
				+ (this.keyId != null) + ", typePresent=" + (this.type != null) + "}";
	}
}
