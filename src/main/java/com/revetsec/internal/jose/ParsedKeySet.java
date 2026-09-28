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

import com.revetsec.jose.JsonWebKeySkipReason;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * What {@link JwkSetParser} made of one JSON Web Key Set document: the usable keys in document order, and each
 * skipped key's position in the {@code keys} array with the reason it was skipped.
 * <p>
 * A document in which every key was skipped is a valid, empty key set (plan M2-8): an identity provider may revoke
 * every key.
 *
 * @param keys  the usable keys, in document order
 * @param skips the skipped keys, in document order
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public record ParsedKeySet(@NonNull List<@NonNull VerificationKey> keys,
													 @NonNull List<@NonNull Skip> skips) {
	/**
	 * Copies the lists.
	 *
	 * @throws NullPointerException if a list or an element is {@code null}
	 */
	public ParsedKeySet {
		keys = List.copyOf(keys);
		skips = List.copyOf(skips);
	}

	/**
	 * How many elements the document's {@code keys} array held: the usable keys plus the skipped ones.
	 *
	 * @return the element count
	 */
	public int elementCount() {
		return this.keys.size() + this.skips.size();
	}

	/**
	 * One skipped key.
	 *
	 * @param index  the key's zero-based position in the document's {@code keys} array
	 * @param reason why it was skipped
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public record Skip(int index,
										 @NonNull JsonWebKeySkipReason reason) {
		/**
		 * Checks the components.
		 *
		 * @throws NullPointerException     if {@code reason} is {@code null}
		 * @throws IllegalArgumentException if {@code index} is negative
		 */
		public Skip {
			requireNonNull(reason);
			if (index < 0)
				throw new IllegalArgumentException("A key's index must not be negative.");
		}
	}
}
