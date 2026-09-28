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

import javax.annotation.concurrent.Immutable;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * A fixed set of verification keys, which never changes and is never fetched.
 * <p>
 * Use it for keys the application already holds, such as a key set configured with the application or fetched out of
 * band. It does no I/O and needs no network settings. A token whose key is not in the set is rejected as
 * {@link JoseException.Reason#UNKNOWN_KEY UNKNOWN_KEY}; nothing is refreshed.
 * <p>
 * A source holds no issuer: share one only among validators that expect the same issuer. Sources compare by
 * reference.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class StaticJsonWebKeySource implements JsonWebKeySource {
	@NonNull
	private final JsonWebKeySet jsonWebKeySet;

	private StaticJsonWebKeySource(@NonNull JsonWebKeySet jsonWebKeySet) {
		this.jsonWebKeySet = jsonWebKeySet;
	}

	/**
	 * Returns a source that holds exactly the usable keys of {@code jsonWebKeySet}.
	 *
	 * @param jsonWebKeySet the key set
	 * @return the source
	 * @throws NullPointerException     if {@code jsonWebKeySet} is {@code null}
	 * @throws IllegalArgumentException if the key set holds no usable key, because such a source could verify
	 *                                  nothing
	 * @since 1.0.0
	 */
	@NonNull
	public static StaticJsonWebKeySource fromJsonWebKeySet(@NonNull JsonWebKeySet jsonWebKeySet) {
		requireNonNull(jsonWebKeySet);

		if (jsonWebKeySet.getKeys().isEmpty())
			throw new IllegalArgumentException("A static JSON Web Key source needs at least one usable key.");

		return new StaticJsonWebKeySource(jsonWebKeySet);
	}

	/**
	 * Returns the key set this source holds.
	 *
	 * @return the key set
	 * @since 1.0.0
	 */
	@NonNull
	public JsonWebKeySet getJsonWebKeySet() {
		return this.jsonWebKeySet;
	}

	/**
	 * The parsed keys, for key selection.
	 */
	@NonNull
	List<@NonNull VerificationKey> verificationKeys() {
		return this.jsonWebKeySet.verificationKeys();
	}

	/**
	 * Describes the source by its keys' public facts.
	 *
	 * @return the description
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{jsonWebKeySet=" + this.jsonWebKeySet + "}";
	}
}
