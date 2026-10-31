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

package com.revetsec;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * Immutable identities of an authority and its active data/recovery admission.
 * <p>
 * This carrier validates identifier syntax only. It does not authenticate an authority, establish admission,
 * generate an identity or reinterpret an engine's existing recovery-epoch address.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class StoreAdmission {
	private final @NonNull String authorityId;
	private final @NonNull String recoveryGeneration;

	private StoreAdmission(@NonNull String authorityId, @NonNull String recoveryGeneration) {
		validateIdentifier(authorityId);
		validateIdentifier(recoveryGeneration);
		this.authorityId = authorityId;
		this.recoveryGeneration = recoveryGeneration;
	}

	/**
	 * Validates and retains the two separately provisioned identifiers.
	 *
	 * @param authorityId canonical unpadded Base64URL encoding of exactly 32 bytes
	 * @param recoveryGeneration canonical unpadded Base64URL encoding of exactly 32 bytes
	 * @return the immutable identities, without any admission or authenticity assertion
	 * @throws NullPointerException if an argument is {@code null}
	 * @throws IllegalArgumentException if an identifier is not in the exact canonical form
	 * @since 1.0.0
	 */
	public static @NonNull StoreAdmission fromIdentifiers(@NonNull String authorityId,
			@NonNull String recoveryGeneration) {
		return new StoreAdmission(authorityId, recoveryGeneration);
	}

	/**
	 * Returns the authority identity.
	 * @return the canonical authority identifier
	 * @since 1.0.0
	 */
	public @NonNull String getAuthorityId() {
		return this.authorityId;
	}

	/**
	 * Returns the active data/recovery generation.
	 * @return the canonical recovery-generation identifier
	 * @since 1.0.0
	 */
	public @NonNull String getRecoveryGeneration() {
		return this.recoveryGeneration;
	}

	/**
	 * Returns a fixed description that discloses neither identifier.
	 * @return the redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() {
		return "StoreAdmission{admission=<redacted>}";
	}

	static void validateIdentifier(@NonNull String value) {
		requireNonNull(value);
		if (value.length() != 43)
			throw new IllegalArgumentException("Invalid store-time identifier.");
		try {
			if (Base64Url.decode(value).length != 32)
				throw new IllegalArgumentException("Invalid store-time identifier.");
		} catch (EncodingException exception) {
			throw new IllegalArgumentException("Invalid store-time identifier.");
		}
	}
}
