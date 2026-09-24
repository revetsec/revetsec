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

package com.revetsec.oidc;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;

/**
 * A validator listed in ContractMetaTests' VERIFIED_TYPE_SOURCES, with one nested result listed by its binary name and
 * one by its canonical name. The list exempts instance members only: validate() and Completion#getIdToken() are
 * allowed, but the static factory and the static field are seeded violations. The canonical entry matches nothing, so
 * Refresh#getIdToken() is a seeded violation too.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class IdTokenValidatorFixture {
	/**
	 * Seeded violation: a static field that hands out a "verified" token.
	 *
	 * @since 1.0.0
	 */
	public static final @Nullable IdToken LAST_VALIDATED = null;

	private IdTokenValidatorFixture() {
	}

	/**
	 * Seeded violation: a forged static factory on a listed source, which mints a token without validating it.
	 *
	 * @param compactSerialization a JWS
	 * @return never
	 * @since 1.0.0
	 */
	public static @NonNull IdToken fromTrustedStorage(@NonNull String compactSerialization) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Control: the validating instance method a listed source exists for.
	 *
	 * @param compactSerialization a JWS
	 * @return never
	 * @since 1.0.0
	 */
	public @NonNull IdToken validate(@NonNull String compactSerialization) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Control: a nested result, listed by its binary name, whose accessor hands out the validated token.
	 *
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Completion {
		private Completion() {
		}

		/**
		 * The validated token.
		 *
		 * @return never
		 * @since 1.0.0
		 */
		public @NonNull IdToken getIdToken() {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * Seeded violation: listed only by its canonical name (Outer.Nested), which exempts nothing.
	 *
	 * @since 1.0.0
	 */
	@Immutable
	public static final class Refresh {
		private Refresh() {
		}

		/**
		 * The refreshed token.
		 *
		 * @return never
		 * @since 1.0.0
		 */
		public @NonNull IdToken getIdToken() {
			throw new UnsupportedOperationException();
		}
	}
}
