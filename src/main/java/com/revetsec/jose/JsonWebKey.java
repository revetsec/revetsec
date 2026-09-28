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

import com.revetsec.internal.jose.VerificationKey;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * One usable public key from a {@link JsonWebKeySet}: an RSA, EC (P-256, P-384 or P-521) or Ed25519 key that passed
 * every rule for verifying JWS signatures (see {@link JsonWebKeySkipReason}).
 * <p>
 * Instances exist only for such keys, so there is no public factory: they come from
 * {@link JsonWebKeySet#getKeys()}. This class describes the key; it holds no private key material and exposes no
 * JCA key.
 * <p>
 * <strong>Equality</strong> is by value: the RFC 7638 thumbprint, which identifies the key material, and the
 * {@code kid}, {@code alg} and {@code use} members, and also the key's JWK {@code issuer} member, which this class does
 * not expose but which decides the tokens the key may verify. {@link #toString()} shows the key ID with its control
 * characters escaped, the key type, curve and algorithm, and the thumbprint.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class JsonWebKey {
	@NonNull
	private final VerificationKey verificationKey;

	private JsonWebKey(@NonNull VerificationKey verificationKey) {
		this.verificationKey = verificationKey;
	}

	/**
	 * Returns the public view of a key that {@code internal.jose} has parsed and checked.
	 *
	 * @param verificationKey the parsed key
	 * @return the public view
	 */
	@NonNull
	static JsonWebKey fromVerificationKey(@NonNull VerificationKey verificationKey) {
		return new JsonWebKey(requireNonNull(verificationKey));
	}

	/**
	 * The parsed key behind this view.
	 */
	@NonNull
	VerificationKey verificationKey() {
		return this.verificationKey;
	}

	/**
	 * Returns the key ID ({@code kid}, RFC 7517 section 4.5).
	 *
	 * @return the key ID, 1 to 256 characters, or empty if the key has none
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getKeyId() {
		return Optional.ofNullable(this.verificationKey.keyId());
	}

	/**
	 * Returns the key type ({@code kty}, RFC 7517 section 4.1).
	 *
	 * @return {@code RSA}, {@code EC} or {@code OKP}
	 * @since 1.0.0
	 */
	@NonNull
	public String getKeyType() {
		return this.verificationKey.keyType();
	}

	/**
	 * Returns the curve ({@code crv}; RFC 7518 section 6.2.1.1, RFC 8037 section 2).
	 *
	 * @return {@code P-256}, {@code P-384}, {@code P-521} or {@code Ed25519}, or empty for an RSA key
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getCurve() {
		return Optional.ofNullable(this.verificationKey.curve());
	}

	/**
	 * Returns the algorithm the key is restricted to ({@code alg}, RFC 7517 section 4.4). A key with an algorithm
	 * verifies only that algorithm, except that {@link JwsAlgorithm#EDDSA} and {@link JwsAlgorithm#ED25519} verify
	 * each other; an RSA key without one verifies only while exactly one RSA algorithm is allowed.
	 *
	 * @return the algorithm, or empty if the key has none
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull JwsAlgorithm> getAlgorithm() {
		return Optional.ofNullable(this.verificationKey.algorithm());
	}

	/**
	 * Returns the key's intended use ({@code use}, RFC 7517 section 4.2).
	 *
	 * @return {@code sig}, or empty if the key has no {@code use} member
	 * @since 1.0.0
	 */
	@NonNull
	public Optional<@NonNull String> getUse() {
		return Optional.ofNullable(this.verificationKey.use());
	}

	/**
	 * Returns the key's RFC 7638 JWK thumbprint with SHA-256, which identifies the key material whatever its other
	 * members say.
	 *
	 * @return the thumbprint, in unpadded base64url (43 characters)
	 * @since 1.0.0
	 */
	@NonNull
	public String getThumbprintSha256() {
		return this.verificationKey.thumbprintSha256();
	}

	/**
	 * Compares by value: the thumbprint, key ID, algorithm, use and the JWK {@code issuer} member.
	 *
	 * @param object the other object
	 * @return whether {@code object} is an equal key
	 * @since 1.0.0
	 */
	@Override
	public boolean equals(@Nullable Object object) {
		if (this == object)
			return true;
		if (!(object instanceof JsonWebKey other))
			return false;

		VerificationKey mine = this.verificationKey;
		VerificationKey theirs = other.verificationKey;
		return mine.thumbprintSha256().equals(theirs.thumbprintSha256()) && Objects.equals(mine.keyId(), theirs.keyId())
				&& mine.algorithm() == theirs.algorithm() && Objects.equals(mine.use(), theirs.use())
				&& Objects.equals(mine.issuer(), theirs.issuer());
	}

	/**
	 * Returns a hash of the thumbprint.
	 *
	 * @return the hash code
	 * @since 1.0.0
	 */
	@Override
	public int hashCode() {
		return this.verificationKey.thumbprintSha256().hashCode();
	}

	/**
	 * Describes the key by its public facts. The key ID comes from the key set's author, so its control characters,
	 * quotation marks, backslashes and bidirectional formatting characters are escaped.
	 *
	 * @return the description
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		VerificationKey key = this.verificationKey;
		String keyId = key.keyId();
		String curve = key.curve();
		JwsAlgorithm algorithm = key.algorithm();

		return getClass().getSimpleName() + "{" + (keyId == null ? "" : "kid=\"" + escape(keyId) + "\", ") + "kty="
				+ key.keyType() + (curve == null ? "" : ", crv=" + curve)
				+ (algorithm == null ? "" : ", alg=" + algorithm.getWireValue()) + ", thumbprint="
				+ key.thumbprintSha256() + "}";
	}

	/**
	 * Escapes the characters that could forge or hide text in a log line as {@code \}{@code uXXXX}: C0 and C1
	 * controls, DEL, {@code "}, {@code \}, the line and paragraph separators, the bidirectional formatting characters
	 * and unpaired surrogates.
	 */
	@NonNull
	static String escape(@NonNull String value) {
		StringBuilder escaped = new StringBuilder(value.length());

		for (int index = 0; index < value.length(); ++index) {
			char character = value.charAt(index);
			boolean unpaired = (Character.isHighSurrogate(character) && (index + 1 >= value.length()
					|| !Character.isLowSurrogate(value.charAt(index + 1))))
					|| (Character.isLowSurrogate(character) && (index == 0
					|| !Character.isHighSurrogate(value.charAt(index - 1))));

			if (character < 0x20 || (character >= 0x7F && character <= 0x9F) || character == '"' || character == '\\'
					|| character == 0x2028 || character == 0x2029 || (character >= 0x202A && character <= 0x202E)
					|| (character >= 0x2066 && character <= 0x2069) || character == 0x200E || character == 0x200F
					|| character == 0x061C || unpaired)
				escaped.append(String.format(Locale.ROOT, "\\u%04X", (int) character));
			else
				escaped.append(character);
		}

		return escaped.toString();
	}
}
