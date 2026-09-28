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

import com.revetsec.jose.JoseException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Objects;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * The answer to a {@link KeyQuery}: the one key to verify with, or why there is none.
 * <p>
 * Only {@link Kind#UNKNOWN} may lead a remote key source to refresh its key set; every other kind is final for the
 * key set it came from (plan "Key selection"). {@link JwtProcessor} turns a kind without a key into its
 * {@link JoseException.Reason}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class KeySelection {
	@NonNull
	private static final KeySelection UNKNOWN = new KeySelection(Kind.UNKNOWN, null);
	@NonNull
	private static final KeySelection AMBIGUOUS = new KeySelection(Kind.AMBIGUOUS, null);
	@NonNull
	private static final KeySelection ALGORITHM_MISMATCH = new KeySelection(Kind.ALGORITHM_MISMATCH, null);

	@NonNull
	private final Kind kind;
	@Nullable
	private final VerificationKey key;

	private KeySelection(@NonNull Kind kind,
											 @Nullable VerificationKey key) {
		this.kind = kind;
		this.key = key;
	}

	/**
	 * Returns the selection of {@code key}.
	 *
	 * @param key the one key that fits the query
	 * @return a {@link Kind#FOUND} selection
	 */
	@NonNull
	public static KeySelection fromKey(@NonNull VerificationKey key) {
		return new KeySelection(Kind.FOUND, requireNonNull(key));
	}

	/**
	 * Returns the shared selection of a kind that has no key.
	 *
	 * @param kind {@link Kind#UNKNOWN}, {@link Kind#AMBIGUOUS} or {@link Kind#ALGORITHM_MISMATCH}
	 * @return the selection
	 * @throws IllegalArgumentException for {@link Kind#FOUND}, which needs a key
	 */
	@NonNull
	public static KeySelection fromKind(@NonNull Kind kind) {
		return switch (requireNonNull(kind)) {
			case UNKNOWN -> UNKNOWN;
			case AMBIGUOUS -> AMBIGUOUS;
			case ALGORITHM_MISMATCH -> ALGORITHM_MISMATCH;
			case FOUND -> throw new IllegalArgumentException("A FOUND selection needs its key.");
		};
	}

	/**
	 * Returns the kind of answer.
	 *
	 * @return the kind
	 */
	@NonNull
	public Kind getKind() {
		return this.kind;
	}

	/**
	 * Returns the selected key.
	 *
	 * @return the key for {@link Kind#FOUND}, otherwise empty
	 */
	@NonNull
	public Optional<@NonNull VerificationKey> findKey() {
		return Optional.ofNullable(this.key);
	}

	/**
	 * Compares the kind and the key.
	 *
	 * @param object the other object
	 * @return whether {@code object} is an equal selection
	 */
	@Override
	public boolean equals(@Nullable Object object) {
		if (this == object)
			return true;
		return object instanceof KeySelection other && this.kind == other.kind && Objects.equals(this.key, other.key);
	}

	/**
	 * A hash of the kind and the key.
	 *
	 * @return the hash code
	 */
	@Override
	public int hashCode() {
		return Objects.hash(this.kind, this.key);
	}

	/**
	 * Describes the selection.
	 *
	 * @return the kind, and the key's public facts for {@link Kind#FOUND}
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{kind=" + this.kind + (this.key == null ? "" : ", key=" + this.key) + "}";
	}

	/**
	 * The kinds of answer.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum Kind {
		/**
		 * Exactly one key fits the query.
		 */
		FOUND,
		/**
		 * No key has the token's {@code kid}, or, for a token without one, no key fits its algorithm. A remote source
		 * may refresh and select again ({@link JoseException.Reason#UNKNOWN_KEY} if it still finds none).
		 */
		UNKNOWN,
		/**
		 * More than one key fits: two keys with the token's {@code kid}, or, for a token without one, more than one key
		 * that fits its algorithm ({@link JoseException.Reason#AMBIGUOUS_KEY}; never a refresh).
		 */
		AMBIGUOUS,
		/**
		 * Keys with the token's {@code kid} exist, but none fits its algorithm
		 * ({@link JoseException.Reason#KEY_ALGORITHM_MISMATCH}; never a refresh).
		 */
		ALGORITHM_MISMATCH
	}
}
