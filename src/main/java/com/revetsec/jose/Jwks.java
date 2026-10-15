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

import com.revetsec.internal.Limits;
import com.revetsec.internal.jose.JoseFailure;
import com.revetsec.internal.jose.JwksParser;
import com.revetsec.internal.jose.ParsedJwks;
import com.revetsec.internal.jose.VerificationKey;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import com.google.errorprone.annotations.CheckReturnValue;

import javax.annotation.concurrent.Immutable;
import java.util.ArrayList;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * A JSON Web Key Set (RFC 7517 section 5): the usable public verification keys of a key set document, in document
 * order.
 * <p>
 * <strong>Keys that are not usable are skipped</strong>, never used in part, and never fail the set: a symmetric or
 * private key, a key for encryption, a curve or key type Revetsec does not support, a weak or malformed key, and the
 * rest of the cases {@link JwkSkipReason} lists. Only the document itself can fail: text that is not strict
 * JSON, not an object, without a {@code keys} array of objects, or over the size and key-count limits.
 * <p>
 * The {@link #fromJsonResult(String)} operation applies the default limits of {@link RemoteJwksSource}: 256 KiB and 100 keys, every
 * element of {@code keys} counted. So at the default limits a document is accepted the same way from a string as from
 * the network.
 * <p>
 * Two key sets are equal when they hold equal keys in the same order.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class Jwks {
	@NonNull
	private final List<@NonNull Jwk> keys;
	@NonNull
	private final List<@NonNull VerificationKey> verificationKeys;

	private Jwks(@NonNull List<@NonNull Jwk> keys,
												@NonNull List<@NonNull VerificationKey> verificationKeys) {
		this.keys = List.copyOf(keys);
		this.verificationKeys = List.copyOf(verificationKeys);
	}

	/**
	 * Parses a JSON Web Key Set document and returns the usable keys or a fixed structural rejection.
	 * Malformed or unusable individual keys are skipped; only the document structure and limits reject the set.
	 *
	 * @param json untrusted document, at most 256 KiB as UTF-8 and 100 elements in its keys array
	 * @return the parsing outcome; a successful key set may have no usable keys
	 * @throws NullPointerException if the document is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull JwksParseResult fromJsonResult(@NonNull String json) {
		requireNonNull(json);
		try {
			return JwksParseResult.fromJwks(fromParsedJwks(JwksParser.parse(json,
					Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue(), Limits.JWKS_KEY_COUNT.getDefaultIntValue())));
		} catch (JoseFailure failure) {
			return JwksParseResult.fromReason(failure.getReason());
		}
	}

	/**
	 * Returns the public view of a parsed key set document.
	 *
	 * @param parsedJwks the parsed document
	 * @return the key set of its usable keys
	 */
	@NonNull
	static Jwks fromParsedJwks(@NonNull ParsedJwks parsedJwks) {
		requireNonNull(parsedJwks);
		List<Jwk> keys = new ArrayList<>(parsedJwks.keys().size());
		for (VerificationKey key : parsedJwks.keys())
			keys.add(Jwk.fromVerificationKey(key));
		return new Jwks(keys, parsedJwks.keys());
	}

	/**
	 * Returns the usable keys.
	 *
	 * @return an unmodifiable list, in document order; empty if every key was skipped
	 * @since 1.0.0
	 */
	@NonNull
	public List<@NonNull Jwk> getKeys() {
		return this.keys;
	}

	/**
	 * The parsed keys, in the same order as {@link #getKeys()}.
	 */
	@NonNull
	List<@NonNull VerificationKey> verificationKeys() {
		return this.verificationKeys;
	}

	/**
	 * Compares the keys, in order.
	 *
	 * @param object the other object
	 * @return whether {@code object} is a key set with equal keys in the same order
	 * @since 1.0.0
	 */
	@Override
	public boolean equals(@Nullable Object object) {
		if (this == object)
			return true;
		return object instanceof Jwks other && this.keys.equals(other.keys);
	}

	/**
	 * Returns a hash of the keys, in order.
	 *
	 * @return the hash code
	 * @since 1.0.0
	 */
	@Override
	public int hashCode() {
		return this.keys.hashCode();
	}

	/**
	 * Describes the key set by its keys' public facts.
	 *
	 * @return the description
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{keys=" + this.keys + "}";
	}
}
