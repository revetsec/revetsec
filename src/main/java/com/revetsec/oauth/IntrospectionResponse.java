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
package com.revetsec.oauth;

import com.revetsec.internal.Limits;
import com.revetsec.internal.http.*;
import com.revetsec.internal.jose.*;
import com.revetsec.jose.*;
import com.revetsec.json.*;
import java.time.*;
import java.util.*;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Strict typed RFC7662 response. Only an active checked profile can release public proof.
 */
@ThreadSafe
final class IntrospectionResponse {

	private final JsonObject claims;

	private final boolean active;

	private final List<String> audiences;

	@Nullable
	private final String issuer;

	@Nullable
	private final String subject;

	@Nullable
	private final String clientId;

	@Nullable
	private final Instant expires;

	@Nullable
	private final Instant issued;

	@Nullable
	private final Instant notBefore;

	private IntrospectionResponse(@NonNull JsonObject claims, boolean active, @NonNull List<@NonNull String> audiences, @Nullable String issuer, @Nullable String subject, @Nullable String clientId, @Nullable Instant expires, @Nullable Instant issued, @Nullable Instant notBefore) {
		this.claims = claims;
		this.active = active;
		this.audiences = audiences;
		this.issuer = issuer;
		this.subject = subject;
		this.clientId = clientId;
		this.expires = expires;
		this.issued = issued;
		this.notBefore = notBefore;
	}

	static @NonNull IntrospectionResponse parse(@NonNull RawResponse response, @NonNull Instant requestStart) {
		if (response.status() != 200)
			throw TokenResponseParser.error(response, requestStart);
		byte[] body = response.body();
		try {
			JsonValue value = com.revetsec.internal.json.JsonCodec.parse(body, com.revetsec.internal.json.JsonLimits.protocolDocument(Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue()));
			if (!(value instanceof JsonObject claims) || !(claims.getMembers().get("active") instanceof JsonBoolean active))
				throw malformed();
			if (!active.getValue())
				return new IntrospectionResponse(JsonObject.fromMembers(Map.of()), false, List.of(), null, null, null, null, null, null);
			List<String> audience = audiences(claims.getMembers().get("aud"));
			String issuer = text(claims, "iss"), subject = text(claims, "sub"), client = text(claims, "client_id");
			text(claims, "token_type");
			if (claims.getMembers().containsKey("scope") && !(claims.getMembers().get("scope") instanceof JsonString))
				throw malformed();
			return new IntrospectionResponse(claims, true, audience, issuer, subject, client, date(claims, "exp"), date(claims, "iat"), date(claims, "nbf"));
		} catch (com.revetsec.internal.json.JsonParseException failure) {
			throw malformed();
		} finally {
			Arrays.fill(body, (byte) 0);
		}
	}

	private static @NonNull List<@NonNull String> audiences(@Nullable JsonValue value) {
		if (value == null)
			return List.of();
		if (value instanceof JsonString text) {
			if (text.getValue().isEmpty())
				throw malformed();
			return List.of(text.getValue());
		}
		if (!(value instanceof JsonArray array))
			throw malformed();
		List<String> result = new ArrayList<>();
		for (JsonValue element : array.getElements()) {
			if (!(element instanceof JsonString text) || text.getValue().isEmpty())
				throw malformed();
			result.add(text.getValue());
		}
		return List.copyOf(result);
	}

	@Nullable
	private static String text(@NonNull JsonObject claims, @NonNull String name) {
		JsonValue value = claims.getMembers().get(name);
		if (value == null)
			return null;
		if (!(value instanceof JsonString text) || text.getValue().isEmpty())
			throw malformed();
		return text.getValue();
	}

	@Nullable
	private static Instant date(@NonNull JsonObject claims, @NonNull String name) {
		JsonValue value = claims.getMembers().get(name);
		if (value == null)
			return null;
		if (!(value instanceof JsonNumber number))
			throw malformed();
		Long seconds = number.getLongValueExact().orElse(null);
		if (seconds == null)
			throw malformed();
		try {
			return Instant.ofEpochSecond(seconds);
		} catch (DateTimeException failure) {
			throw malformed();
		}
	}

	@NonNull VerifiedAccessToken validate(@NonNull String issuer, @NonNull Set<@NonNull String> expected, @NonNull Set<@NonNull String> required, @NonNull Instant now, @NonNull Duration skew) {
		if (!this.active)
			throw rejected(AccessTokenValidationException.Reason.INACTIVE);
		if (this.audiences.isEmpty())
			throw rejected(AccessTokenValidationException.Reason.AUDIENCE_MISSING);
		if (this.audiences.stream().noneMatch(expected::contains))
			throw rejected(AccessTokenValidationException.Reason.AUDIENCE_MISMATCH);
		if (this.issuer != null && !issuer.equals(this.issuer))
			throw rejected(AccessTokenValidationException.Reason.ISSUER_MISMATCH);
		if (this.expires != null && !now.isBefore(this.expires) && Duration.between(this.expires, now).compareTo(skew) >= 0)
			throw rejected(AccessTokenValidationException.Reason.EXPIRED);
		if (this.issued != null && this.issued.isAfter(now) && Duration.between(now, this.issued).compareTo(skew) > 0)
			throw rejected(AccessTokenValidationException.Reason.ISSUED_IN_FUTURE);
		if (this.notBefore != null && this.notBefore.isAfter(now) && Duration.between(now, this.notBefore).compareTo(skew) > 0)
			throw rejected(AccessTokenValidationException.Reason.NOT_YET_VALID);
		AccessTokenClaims.required(this.claims, required);
		if (this.claims.getMembers().containsKey("cnf"))
			throw rejected(AccessTokenValidationException.Reason.CONFIRMATION_NOT_VERIFIED);
		String type = text(this.claims, "token_type");
		if (type != null && !type.equalsIgnoreCase("Bearer"))
			throw rejected(AccessTokenValidationException.Reason.TOKEN_TYPE_INVALID);
		Set<String> scopes = AccessTokenClaims.scopes(this.claims.getMembers().get("scope"), false);
		return new VerifiedAccessToken(issuer, this.subject, this.clientId, scopes, this.audiences, this.expires, this.claims);
	}

	private static @NonNull AccessTokenValidationException rejected(AccessTokenValidationException.@NonNull Reason reason) {
		return AccessTokenValidationException.fromReason(reason);
	}

	private static @NonNull OAuthResponseException malformed() {
		return OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
	}

	@Override
	public @NonNull String toString() {
		return "IntrospectionResponse{data=<redacted>}";
	}
}
