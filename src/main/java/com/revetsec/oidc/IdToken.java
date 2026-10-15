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

import com.revetsec.jose.Jwt;
import com.revetsec.jose.JwtClaims;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * An ID token whose signature, registered claims and OIDC checks have all passed. There is no parse-only factory.
 * The exact issuer and subject identify the account; email is a mutable attribute, including when verified.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class IdToken {
	private final @NonNull Jwt jwt;

	IdToken(@NonNull Jwt jwt) {
		this.jwt = requireNonNull(jwt);
	}

	/**
	 * Returns the authenticated claims. Their explicit JSON representation may contain personal data.
	 *
	 * @return the claims
	 * @since 1.0.0
	 */
	public @NonNull JwtClaims getClaims() {
		return this.jwt.getClaims();
	}

	/**
	 * Returns the complete signed token. This deliberately emits a credential; do not log it.
	 *
	 * @return the compact serialization
	 * @since 1.0.0
	 */
	public @NonNull String toCompactSerialization() {
		return this.jwt.toCompactSerialization();
	}

	@Override
	public @NonNull String toString() {
		return "IdToken{claims=<redacted>, token=<redacted>}";
	}
}
