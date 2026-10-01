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

import com.revetsec.internal.json.JsonLimits;
import com.revetsec.jose.JwsAlgorithm;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * A compact JWS that passed every check that needs no key (plan "JOSE semantics", steps 1 to 5): its size, its
 * serialization, the canonical base64url of every segment, the header policy, and the key-independent signature
 * shape. What is left is to select a key ({@link #getKeyQuery()}), verify the signature, and check the payload.
 * <p>
 * It holds the token, so {@link #toString()} shows only its algorithm. The payload has been decoded to check its
 * encoding but not yet parsed: nothing reads it before the signature verifies.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class PreparedJws {
	@NonNull
	private final String compactSerialization;
	@NonNull
	private final JwsAlgorithm algorithm;
	@Nullable
	private final String keyId;
	@Nullable
	private final String type;
	private final byte @NonNull [] signingInput;
	private final byte @NonNull [] payload;
	private final byte @NonNull [] signature;
	@NonNull
	private final KeyQuery keyQuery;
	@NonNull
	private final JsonLimits jsonLimits;

	/**
	 * Holds the parts of a checked compact JWS; the arrays are copied.
	 *
	 * @param compactSerialization the token as received
	 * @param algorithm            the header's {@code alg}, in the effective set
	 * @param keyId                the header's {@code kid}, or {@code null} if absent
	 * @param type                 the header's {@code typ} as received, or {@code null} if absent
	 * @param signingInput         the ASCII bytes of {@code header.payload}, as received
	 * @param payload              the decoded payload, possibly empty
	 * @param signature            the decoded signature
	 * @param keyQuery             the query for the key that verifies it
	 * @param jsonLimits           the JOSE profile the claims are parsed under, the header's own
	 */
	PreparedJws(@NonNull String compactSerialization,
							@NonNull JwsAlgorithm algorithm,
							@Nullable String keyId,
							@Nullable String type,
							byte @NonNull [] signingInput,
							byte @NonNull [] payload,
							byte @NonNull [] signature,
							@NonNull KeyQuery keyQuery,
							@NonNull JsonLimits jsonLimits) {
		this.compactSerialization = requireNonNull(compactSerialization);
		this.algorithm = requireNonNull(algorithm);
		this.keyId = keyId;
		this.type = type;
		this.signingInput = signingInput.clone();
		this.payload = payload.clone();
		this.signature = signature.clone();
		this.keyQuery = requireNonNull(keyQuery);
		this.jsonLimits = requireNonNull(jsonLimits);
	}

	/** Returns the compact input length without releasing its credential. */
	public int getCompactLength() { return this.compactSerialization.length(); }

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
	 * Returns the query that selects the key for this token.
	 *
	 * @return the key query
	 */
	@NonNull
	public KeyQuery getKeyQuery() {
		return this.keyQuery;
	}

	/**
	 * The JOSE profile the claims are parsed under.
	 */
	@NonNull
	JsonLimits jsonLimits() {
		return this.jsonLimits;
	}

	/**
	 * The token as received.
	 */
	@NonNull
	String compactSerialization() {
		return this.compactSerialization;
	}

	/**
	 * A copy of the signing input.
	 */
	byte @NonNull [] signingInput() {
		return this.signingInput.clone();
	}

	/**
	 * A copy of the decoded payload.
	 */
	byte @NonNull [] payload() {
		return this.payload.clone();
	}

	/**
	 * A copy of the decoded signature.
	 */
	byte @NonNull [] signature() {
		return this.signature.clone();
	}

	/**
	 * Describes the token by its algorithm only.
	 *
	 * @return the description
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{algorithm=" + this.algorithm.getWireValue() + "}";
	}
}
