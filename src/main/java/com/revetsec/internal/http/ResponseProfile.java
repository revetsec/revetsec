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

package com.revetsec.internal.http;

import com.revetsec.internal.Limit;
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * What an endpoint's successful response must look like: its body-size row in {@link Limits}, the {@code Accept}
 * header Revetsec sends, and the media types a 2xx may carry (M1 plan, G6-7, frozen after the WP-5 Content-Type
 * record of Keycloak 26.7.4 and node-oidc-provider 9.12.2).
 * <p>
 * A 2xx under a checked profile needs exactly one {@code Content-Type} field whose type and subtype are in the
 * profile's list and whose charset is absent or {@code utf-8}, compared case-insensitively
 * ({@link MediaType#hasUtf8OrNoCharset()}); other parameters are ignored. {@link #REVOCATION} skips the whole
 * media-type step, count included, because under RFC 7009 section 2.2 the client ignores a success body (Keycloak
 * sends no {@code Content-Type} and node-oidc-provider sends {@code text/plain}). The step never applies to a non-2xx
 * response.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public enum ResponseProfile {
	/**
	 * An OpenID Provider or authorization server metadata (discovery) document.
	 */
	METADATA("application/json"),
	/**
	 * A token endpoint response (RFC 6749 section 5.1).
	 */
	TOKEN("application/json"),
	/**
	 * A token introspection response (RFC 7662 section 2.2).
	 */
	INTROSPECTION("application/json"),
	/**
	 * A JSON Web Key Set (RFC 7517 section 5). Keycloak answers {@code application/json} whenever the {@code Accept}
	 * header lists it, and node-oidc-provider always answers {@code application/jwk-set+json}, so both are accepted.
	 */
	JWKS("application/jwk-set+json, application/json"),
	/**
	 * A UserInfo response (OpenID Connect Core section 5.3.2): JSON, or a signed JWT when the client is registered for
	 * one. The client's registration, not {@code Accept}, selects the form, so callers branch on the received type.
	 */
	USERINFO("application/json, application/jwt"),
	/**
	 * A token revocation response (RFC 7009 section 2.2), whose success body the client ignores. A 2xx's media type is
	 * not checked.
	 */
	REVOCATION("application/json");

	private static final List<String> JSON = List.of("application/json");
	private static final List<String> JSON_OR_JWK_SET = List.of("application/json", "application/jwk-set+json");
	private static final List<String> JSON_OR_JWT = List.of("application/json", "application/jwt");

	@NonNull
	private final String acceptHeaderValue;

	ResponseProfile(@NonNull String acceptHeaderValue) {
		this.acceptHeaderValue = requireNonNull(acceptHeaderValue);
	}

	/**
	 * The {@link Limits} row that bounds a 2xx body for this profile; its default is the default limit.
	 *
	 * @return the row
	 */
	@NonNull
	public Limit getBodySizeLimit() {
		return this == JWKS ? Limits.JWKS_RESPONSE_BODY_SIZE : Limits.HTTP_RESPONSE_BODY_SIZE;
	}

	/**
	 * The {@code Accept} header value Revetsec sends.
	 *
	 * @return the header value
	 */
	@NonNull
	public String getAcceptHeaderValue() {
		return this.acceptHeaderValue;
	}

	/**
	 * The media types a 2xx may carry, as lower-case {@code type/subtype}; empty when the media type is not checked.
	 *
	 * @return an unmodifiable list
	 */
	@NonNull
	public List<@NonNull String> getAcceptedMediaTypes() {
		return switch (this) {
			case METADATA, TOKEN, INTROSPECTION -> JSON;
			case JWKS -> JSON_OR_JWK_SET;
			case USERINFO -> JSON_OR_JWT;
			case REVOCATION -> List.of();
		};
	}

	/**
	 * Whether a 2xx's {@code Content-Type} is checked at all.
	 *
	 * @return {@code false} only for {@link #REVOCATION}
	 */
	public boolean isMediaTypeChecked() {
		return this != REVOCATION;
	}

	/**
	 * Whether a 2xx with this media type passes the profile's check.
	 *
	 * @param mediaType the response's one parsed media type
	 * @return {@code true} if the type and subtype are accepted and the charset is absent or {@code utf-8}, or if the
	 * profile does not check media types
	 * @throws NullPointerException if {@code mediaType} is {@code null}
	 */
	public boolean accepts(@NonNull MediaType mediaType) {
		requireNonNull(mediaType);

		if (!isMediaTypeChecked())
			return true;

		return getAcceptedMediaTypes().contains(mediaType.getEssence()) && mediaType.hasUtf8OrNoCharset();
	}
}
