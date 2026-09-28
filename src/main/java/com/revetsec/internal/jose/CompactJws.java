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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * A JWS compact serialization split into its three segments and decoded (RFC 7515 sections 3.1 and 7.1), as
 * {@link CompactJwsParser} returns it: nothing in it has been interpreted yet.
 * <p>
 * Every accessor returns a new array. It holds the token, so {@link #toString()} shows only the segment lengths.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class CompactJws {
	@NonNull
	private final String compactSerialization;
	private final byte @NonNull [] header;
	private final byte @NonNull [] payload;
	private final byte @NonNull [] signature;
	private final byte @NonNull [] signingInput;

	/**
	 * Holds the decoded segments; the arrays are copied.
	 *
	 * @param compactSerialization the token as received
	 * @param header               the decoded header segment, not empty
	 * @param payload              the decoded payload segment, possibly empty
	 * @param signature            the decoded signature segment, possibly empty
	 * @param signingInput         the ASCII bytes of {@code header.payload}, exactly as received
	 */
	CompactJws(@NonNull String compactSerialization,
						 byte @NonNull [] header,
						 byte @NonNull [] payload,
						 byte @NonNull [] signature,
						 byte @NonNull [] signingInput) {
		this.compactSerialization = requireNonNull(compactSerialization);
		this.header = header.clone();
		this.payload = payload.clone();
		this.signature = signature.clone();
		this.signingInput = signingInput.clone();
	}

	/**
	 * Returns the token as received.
	 *
	 * @return the compact serialization
	 */
	@NonNull
	public String getCompactSerialization() {
		return this.compactSerialization;
	}

	/**
	 * Returns the decoded header: the bytes of the JOSE header, not yet parsed.
	 *
	 * @return a new array
	 */
	public byte @NonNull [] getHeader() {
		return this.header.clone();
	}

	/**
	 * Returns the decoded payload, not yet parsed; it may be empty (RFC 7515 section 7.1).
	 *
	 * @return a new array
	 */
	public byte @NonNull [] getPayload() {
		return this.payload.clone();
	}

	/**
	 * Returns the decoded signature; it may be empty.
	 *
	 * @return a new array
	 */
	public byte @NonNull [] getSignature() {
		return this.signature.clone();
	}

	/**
	 * Returns the JWS signing input: the ASCII bytes of the header and payload segments and the dot between them, as
	 * received (RFC 7515 section 5.2, step 8). A signature is verified over these bytes, never over a re-encoding.
	 *
	 * @return a new array
	 */
	public byte @NonNull [] getSigningInput() {
		return this.signingInput.clone();
	}

	/**
	 * Describes the token by its decoded segment lengths only.
	 *
	 * @return the description
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{headerLength=" + this.header.length + ", payloadLength="
				+ this.payload.length + ", signatureLength=" + this.signature.length + "}";
	}
}
