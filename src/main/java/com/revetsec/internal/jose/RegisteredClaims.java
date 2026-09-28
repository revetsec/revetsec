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

import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * A JWT claims set whose registered claims (RFC 7519 section 4.1) were read with their types checked: {@code iss},
 * {@code sub} and {@code jti} strings; {@code aud} a string or a non-empty array of strings; {@code exp}, {@code nbf}
 * and {@code iat} NumericDates. A claim of the wrong type never gets this far, so each component is either the claim's
 * value or absent.
 *
 * @param claims     the whole claims set, every member included
 * @param issuer     {@code iss}, or {@code null} if absent
 * @param subject    {@code sub}, or {@code null} if absent
 * @param audiences  {@code aud}: one element for a string, the array's elements in order, or empty if absent; copied
 * @param expiresAt  {@code exp}, or {@code null} if absent
 * @param issuedAt   {@code iat}, or {@code null} if absent
 * @param notBefore  {@code nbf}, or {@code null} if absent
 * @param jwtId      {@code jti}, or {@code null} if absent
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public record RegisteredClaims(@NonNull JsonObject claims,
															 @Nullable String issuer,
															 @Nullable String subject,
															 @NonNull List<@NonNull String> audiences,
															 @Nullable Instant expiresAt,
															 @Nullable Instant issuedAt,
															 @Nullable Instant notBefore,
															 @Nullable String jwtId) {
	/**
	 * Checks and copies the components.
	 *
	 * @throws NullPointerException if {@code claims} or {@code audiences} (or an element) is {@code null}
	 */
	public RegisteredClaims {
		requireNonNull(claims);
		audiences = List.copyOf(audiences);
	}

	/**
	 * Describes the claims set without any claim, because claims can carry personal data and tokens' secrets.
	 *
	 * @return a redacted description
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{<redacted>}";
	}
}
