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
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * A compact JWS whose signature verified, at the JWS layer only: its payload is returned as bytes and is not parsed as
 * JWT claims, so a JWS with any payload, such as the RFC examples' text payloads, can be checked.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class VerifiedJws {
	@NonNull
	private final JwsAlgorithm algorithm;
	@Nullable
	private final String keyId;
	@Nullable
	private final String type;
	private final byte @NonNull [] payload;
	@Nullable
	private final VerificationKey key;

	/**
	 * Holds the verified parts; the payload is copied.
	 *
	 * @param algorithm the header's {@code alg}
	 * @param keyId     the header's {@code kid}, or {@code null} if absent
	 * @param type      the header's {@code typ} as received, or {@code null} if absent
	 * @param payload   the decoded payload
	 * @param key       the key that verified it, or {@code null} for a configured HMAC secret
	 */
	VerifiedJws(@NonNull JwsAlgorithm algorithm,
							@Nullable String keyId,
							@Nullable String type,
							byte @NonNull [] payload,
							@Nullable VerificationKey key) {
		this.algorithm = requireNonNull(algorithm);
		this.keyId = keyId;
		this.type = type;
		this.payload = payload.clone();
		this.key = key;
	}

	/**
	 * Returns the header's algorithm.
	 *
	 * @return the algorithm
	 */
	@NonNull
	public JwsAlgorithm getAlgorithm() {
		return this.algorithm;
	}

	/**
	 * Returns the header's {@code kid}.
	 *
	 * @return the key ID, or empty if absent
	 */
	@NonNull
	public Optional<@NonNull String> findKeyId() {
		return Optional.ofNullable(this.keyId);
	}

	/**
	 * Returns the header's {@code typ} as received.
	 *
	 * @return the type, or empty if absent
	 */
	@NonNull
	public Optional<@NonNull String> findType() {
		return Optional.ofNullable(this.type);
	}

	/**
	 * Returns a copy of the decoded payload.
	 *
	 * @return the payload, possibly empty
	 */
	public byte @NonNull [] getPayload() {
		return this.payload.clone();
	}

	/**
	 * Returns the key that verified the signature.
	 *
	 * @return the key, or empty when a configured HMAC secret verified it
	 */
	@NonNull
	public Optional<@NonNull VerificationKey> findKey() {
		return Optional.ofNullable(this.key);
	}

	/**
	 * Describes the JWS by its algorithm and payload length, never the payload.
	 *
	 * @return the description
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{algorithm=" + this.algorithm.getWireValue() + ", payloadLength="
				+ this.payload.length + "}";
	}
}
