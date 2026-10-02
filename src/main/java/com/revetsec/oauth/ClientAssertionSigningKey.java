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

package com.revetsec.oauth;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.jose.JwsSigner;
import java.util.Arrays;
import java.util.Optional;
import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.NotThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import static java.util.Objects.requireNonNull;

/**
 * Immutable signer and protected-header identifiers selected together for one assertion. At least one identifier
 * is required. The private key and identifiers never appear in string rendering; arrays are defensively copied.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class ClientAssertionSigningKey {
	private final @NonNull JwsSigner signer;
	private final @Nullable String keyId;
	private final byte @Nullable [] thumbprint;

	private ClientAssertionSigningKey(@NonNull Builder builder) {
		this.signer = builder.signer;
		this.keyId = builder.keyId;
		this.thumbprint = builder.thumbprint == null ? null : builder.thumbprint.clone();
	}
	/**
	 * Starts a snapshot builder. A key ID or certificate digest must also be supplied.
	 * @param signer the required signer
	 * @return the builder
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull Builder withSigner(@NonNull JwsSigner signer) { return new Builder(signer); }
	/**
	 * Returns the optional key identifier.
	 * @return identifier when configured
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getKeyId() { return Optional.ofNullable(this.keyId); }
	/**
	 * Returns a copy of the optional SHA-256 certificate digest.
	 * @return digest when configured
	 * @since 1.0.0
	 */
	public @NonNull Optional<byte @NonNull []> getCertificateSha256Thumbprint() {
		return this.thumbprint == null ? Optional.empty() : Optional.of(this.thumbprint.clone());
	}
	@NonNull JwsSigner signer() { return this.signer; }
	/**
	 * Redacts the key and identifiers.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "ClientAssertionSigningKey{key=<redacted>}"; }

	/**
	 * Configures one immutable signing snapshot without provider or signing calls.
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe @CheckReturnValue
	public static final class Builder {
		private final @NonNull JwsSigner signer;
		private @Nullable String keyId;
		private byte @Nullable [] thumbprint;
		private Builder(@NonNull JwsSigner signer) { this.signer = requireNonNull(signer); }
		/**
		 * Replaces the optional key identifier. Text must contain 1–256 UTF-16 code units and valid Unicode.
		 * @param value identifier, or null to clear
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder keyId(@Nullable String value) {
			if (value != null) {
				if (value.isEmpty() || value.length() > 256) throw new IllegalArgumentException("The assertion key identifier is invalid.");
				try { Arrays.fill(StrictUtf8.encode(value), (byte) 0); }
				catch (EncodingException invalid) { throw new IllegalArgumentException("The assertion key identifier is invalid."); }
			}
			this.keyId = value; return this;
		}
		/**
		 * Replaces the optional SHA-256 certificate digest with a defensive copy.
		 * @param value exactly 32 bytes, or null to clear
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder certificateSha256Thumbprint(byte @Nullable [] value) {
			if (value != null && value.length != 32) throw new IllegalArgumentException("The assertion certificate digest must contain 32 bytes.");
			this.thumbprint = value == null ? null : value.clone(); return this;
		}
		/**
		 * Builds an immutable snapshot without signing or I/O.
		 * @return the snapshot
		 * @since 1.0.0
		 */
		public @NonNull ClientAssertionSigningKey build() {
			if (this.keyId == null && this.thumbprint == null) throw new IllegalStateException("An assertion key identifier or certificate digest is required.");
			return new ClientAssertionSigningKey(this);
		}
		/**
		 * Redacts configured keys and identifiers.
		 * @return redacted description
		 * @since 1.0.0
		 */
		@Override public @NonNull String toString() { return "ClientAssertionSigningKey.Builder{key=<redacted>}"; }
	}
}
