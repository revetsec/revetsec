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

import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonBoolean;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/**
 * UserInfo whose subject exactly matches a verified authentication. JSON responses rely on the provider's TLS
 * endpoint; signed responses additionally pass JOSE issuer, audience, signature and profile checks. Claims can
 * contain personal data. The exact issuer/subject pair is the account key; email is a mutable attribute.
 * No public constructor or parse-only factory exists.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OidcUserInfo {
	private final String issuer;
	private final JsonObject claims;
	private final boolean signed;
	OidcUserInfo(String issuer, JsonObject claims, boolean signed) {
		this.issuer = requireNonNull(issuer); this.claims = requireNonNull(claims); this.signed = signed;
	}
	/**
	 * Returns the exact provider issuer to which this result is bound.
	 * @return issuer
	 * @since 1.0.0
	 */
	public @NonNull String getIssuer() { return this.issuer; }
	/**
	 * Returns the subject already matched against the validated ID token.
	 * @return subject
	 * @since 1.0.0
	 */
	public @NonNull String getSubject() { return ((JsonString) requireNonNull(this.claims.getMembers().get("sub"))).getValue(); }
	/**
	 * Explicitly returns the checked claims. JSON serialization deliberately emits personal data; do not log it.
	 * Aggregated/distributed claim references remain data and are never followed by Revetsec.
	 * @return immutable claims object
	 * @since 1.0.0
	 */
	public @NonNull JsonObject getClaims() { return this.claims; }
	/**
	 * Returns whether the response was authenticated with the configured signing algorithm.
	 * @return whether signed
	 * @since 1.0.0
	 */
	public boolean isSigned() { return this.signed; }
	/**
	 * Returns a string email claim, never an account key.
	 * @return optional email
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getEmail() {
		return this.claims.getMembers().get("email") instanceof JsonString text ? Optional.of(text.getValue()) : Optional.empty();
	}
	/**
	 * Returns a JSON-boolean email-verification claim; strings are never coerced. This does not establish the
	 * provider's authority over an email domain.
	 * @return optional boolean
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull Boolean> getEmailVerified() {
		return this.claims.getMembers().get("email_verified") instanceof JsonBoolean value ? Optional.of(value.getValue()) : Optional.empty();
	}
	/**
	 * Redacts claims and identity.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OidcUserInfo{claims=<redacted>}"; }
}
