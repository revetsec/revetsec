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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.jose.JwkParser;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.util.Arrays;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Immutable protected-header metadata for signing a JWT: its required {@link JwtType type} and optional key
 * identifier and SHA-256 certificate thumbprint. The {@code alg} header comes from the {@link JwsSigner}; callers
 * cannot configure a conflicting algorithm here.
 * <p>
 * Arrays are defensively copied. String rendering never exposes configured identifiers or certificate digests.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class JwtSigningHeader {
	private static final int CERTIFICATE_DIGEST_LENGTH = 32;

	private final @NonNull JwtType type;
	private final @Nullable String keyId;
	private final byte @Nullable [] certificateSha256Thumbprint;

	private JwtSigningHeader(@NonNull Builder builder) {
		this.type = builder.type;
		this.keyId = builder.keyId;
		this.certificateSha256Thumbprint = builder.certificateSha256Thumbprint == null
				? null : builder.certificateSha256Thumbprint.clone();
	}

	/**
	 * Starts a header builder with the required token type.
	 *
	 * @param type the protected-header token type
	 * @return the builder
	 * @throws NullPointerException if {@code type} is {@code null}
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull Builder withType(@NonNull JwtType type) {
		return new Builder(type);
	}

	/**
	 * Returns a header with the required token type and no key identifier or certificate thumbprint.
	 * Equivalent to {@code withType(type).build()}.
	 *
	 * @param type the protected-header token type
	 * @return the immutable header
	 * @throws NullPointerException if {@code type} is {@code null}
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull JwtSigningHeader fromType(@NonNull JwtType type) {
		return withType(type).build();
	}

	/**
	 * Returns the required protected-header {@code typ} selection.
	 *
	 * @return the token type
	 * @since 1.0.0
	 */
	public @NonNull JwtType getType() {
		return this.type;
	}

	/**
	 * Returns the optional protected-header {@code kid} value.
	 *
	 * @return the key identifier when configured
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getKeyId() {
		return Optional.ofNullable(this.keyId);
	}

	/**
	 * Returns a copy of the optional SHA-256 digest of a DER certificate, serialized as {@code x5t#S256} when signing.
	 *
	 * @return a copy of the certificate digest when configured
	 * @since 1.0.0
	 */
	public @NonNull Optional<byte @NonNull []> getCertificateSha256Thumbprint() {
		return this.certificateSha256Thumbprint == null
				? Optional.empty() : Optional.of(this.certificateSha256Thumbprint.clone());
	}

	/**
	 * Returns a description without configured identifiers or certificate digests.
	 *
	 * @return the redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() {
		return "JwtSigningHeader{header=<redacted>}";
	}

	/**
	 * Configures an immutable JWT signing header without signing or I/O. Optional setters replace their previous
	 * value, and {@code null} clears the value. Each {@link #build()} call takes an independent snapshot.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private final @NonNull JwtType type;
		private @Nullable String keyId;
		private byte @Nullable [] certificateSha256Thumbprint;

		private Builder(@NonNull JwtType type) {
			this.type = requireNonNull(type);
		}

		/**
		 * Replaces the optional protected-header key identifier. Text must contain 1–256 UTF-16 code units and valid
		 * Unicode.
		 *
		 * @param keyId the key identifier, or {@code null} to clear it
		 * @return this builder
		 * @throws IllegalArgumentException if the supplied identifier is empty, too long or invalid Unicode
		 * @since 1.0.0
		 */
		public @NonNull Builder keyId(@Nullable String keyId) {
			if (keyId != null) {
				if (keyId.isEmpty() || keyId.length() > JwkParser.MAXIMUM_KEY_ID_LENGTH)
					throw new IllegalArgumentException("The JWT signing key identifier is invalid.");
				try {
					Arrays.fill(StrictUtf8.encode(keyId), (byte) 0);
				} catch (EncodingException invalid) {
					throw new IllegalArgumentException("The JWT signing key identifier is invalid.");
				}
			}
			this.keyId = keyId;
			return this;
		}

		/**
		 * Replaces the optional SHA-256 digest of a DER certificate with a defensive copy.
		 *
		 * @param certificateSha256Thumbprint exactly 32 digest bytes, or {@code null} to clear it
		 * @return this builder
		 * @throws IllegalArgumentException if the supplied digest does not contain exactly 32 bytes
		 * @since 1.0.0
		 */
		public @NonNull Builder certificateSha256Thumbprint(byte @Nullable [] certificateSha256Thumbprint) {
			if (certificateSha256Thumbprint != null && certificateSha256Thumbprint.length != CERTIFICATE_DIGEST_LENGTH)
				throw new IllegalArgumentException("The JWT signing certificate digest must contain 32 bytes.");
			this.certificateSha256Thumbprint = certificateSha256Thumbprint == null
					? null : certificateSha256Thumbprint.clone();
			return this;
		}

		/**
		 * Builds an immutable header snapshot without signing or I/O.
		 *
		 * @return the header
		 * @since 1.0.0
		 */
		public @NonNull JwtSigningHeader build() {
			return new JwtSigningHeader(this);
		}

		/**
		 * Returns a description without configured identifiers or certificate digests.
		 *
		 * @return the redacted description
		 * @since 1.0.0
		 */
		@Override
		public @NonNull String toString() {
			return "JwtSigningHeader.Builder{header=<redacted>}";
		}
	}
}
