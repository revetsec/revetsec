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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

/**
 * A verified (R17) type since M2 (M2-5): claims exist only after a validator checked the token that carried them.
 * Seeded violation: a public static factory, which would give any caller claims that nothing checked. Controls: the
 * private constructor and an accessor that returns no verified type.
 *
 * @since 1.0.0
 */
@Immutable
public final class JwtClaims {
	private JwtClaims() {
	}

	/**
	 * Seeded violation: claims from a JSON object that no validator checked.
	 *
	 * @param json a JSON object
	 * @return never
	 * @since 1.0.0
	 */
	public static @NonNull JwtClaims fromJson(@NonNull String json) {
		throw new UnsupportedOperationException();
	}

	/**
	 * Control: an accessor that returns no verified type.
	 *
	 * @return the issuer
	 * @since 1.0.0
	 */
	public @NonNull String getIssuer() {
		return "";
	}
}
