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
import com.revetsec.internal.http.RawResponse;
import com.revetsec.internal.http.RetryAfter;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Strict token JSON interpretation. Response bytes are cleared after parsing. */
@ThreadSafe
final class TokenResponseParser {
	private static final Set<String> SENSITIVE = Set.of("access_token", "token_type", "expires_in",
			"refresh_token", "scope", "id_token", "error", "error_description", "error_uri");

	private TokenResponseParser() {
	}

	static TokenResponse parse(RawResponse response, Instant requestStart, @Nullable Set<String> requestedScopes) {
		int status = response.status();
		if (status != 200) throw error(response, requestStart);
		byte[] body = response.body();
		try {
			JsonObject object = null;
			if (body.length > 0) {
				try {
					JsonValue parsed = JsonCodec.parse(body, JsonLimits.protocolDocument(
							Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue()));
					if (parsed instanceof JsonObject parsedObject)
						object = parsedObject;
				} catch (JsonParseException ignored) {
					// An unsuccessful endpoint may send arbitrary error text; its status remains available.
				}
			}
			if (object == null)
				throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
			Map<String, JsonValue> members = object.getMembers();
			if (members.containsKey("error")) {
				String error = safeErrorString(object);
				throw OAuthErrorResponseException.fromResponse(status, error,
						RetryAfter.parse(response.headers(), requestStart));
			}
			String value = requiredString(members, "access_token");
			if (!isVisibleAscii(value))
				throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
			String tokenType = requiredString(members, "token_type");
			Instant expiresAt = members.containsKey("expires_in")
					? expiry(requestStart, members.get("expires_in")) : null;
			AccessToken accessToken = new AccessToken(value, tokenType, expiresAt);
			RefreshToken refreshToken = members.containsKey("refresh_token")
					? RefreshToken.fromValue(requiredString(members, "refresh_token")) : null;
			String scope = members.containsKey("scope") ? requiredString(members, "scope") : null;
			Set<String> scopes = scope == null ? requestedScopes : scopeSet(scope);
			Map<String, JsonValue> safe = new LinkedHashMap<>();
			members.forEach((name, member) -> {
				if (!SENSITIVE.contains(name)) safe.put(name, member);
			});
			return new TokenResponse(accessToken, refreshToken, scope, scopes, requestStart,
					JsonObject.fromMembers(safe));
		} finally {
			Arrays.fill(body, (byte) 0);
		}
	}

	static OAuthErrorResponseException error(RawResponse response, Instant requestStart) {
		if (response.status() == 200)
			throw new IllegalArgumentException("An endpoint error requires a non-200 status.");
		byte[] body = response.body();
		try {
			String code = "";
			if (body.length > 0) {
				try {
					JsonValue parsed = JsonCodec.parse(body,
							JsonLimits.protocolDocument(Limits.HTTP_ERROR_BODY_SIZE.getDefaultIntValue()));
					if (parsed instanceof JsonObject object) code = safeErrorString(object);
				} catch (JsonParseException ignored) {
					// A failed endpoint may return arbitrary error text.
				}
			}
			return OAuthErrorResponseException.fromResponse(response.status(), code,
					RetryAfter.parse(response.headers(), requestStart));
		} finally {
			Arrays.fill(body, (byte) 0);
		}
	}

	private static String safeErrorString(JsonObject object) {
		JsonValue error = object.getMembers().get("error");
		return error instanceof JsonString text ? text.getValue() : "";
	}

	private static String requiredString(Map<String, JsonValue> members, String name) {
		JsonValue value = members.get(name);
		if (!(value instanceof JsonString text) || text.getValue().isEmpty())
			throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
		return text.getValue();
	}

	private static boolean isVisibleAscii(String value) {
		for (int index = 0; index < value.length(); index++) {
			char character = value.charAt(index);
			if (character < 0x20 || character > 0x7E) return false;
		}
		return true;
	}

	private static Instant expiry(Instant start, JsonValue value) {
		String digits;
		if (value instanceof JsonString text) {
			digits = text.getValue();
		} else if (value instanceof JsonNumber number) {
			if (number.getValue().scale() != 0)
				throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
			digits = number.toJson();
		} else {
			throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
		}
		if (digits.isEmpty() || digits.length() > 19)
			throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
		for (int i = 0; i < digits.length(); i++)
			if (digits.charAt(i) < '0' || digits.charAt(i) > '9')
				throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
		try {
			return start.plusSeconds(Long.parseLong(digits));
		} catch (NumberFormatException | ArithmeticException | DateTimeException exception) {
			throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
		}
	}

	private static Set<String> scopeSet(String scope) {
		Set<String> result = new LinkedHashSet<>();
		for (String token : scope.split(" ", -1)) {
			if (token.isEmpty() || token.chars().anyMatch(c -> c <= 0x20 || c == 0x22 || c == 0x5C || c >= 0x7F)
					|| !result.add(token))
				throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
		}
		return Set.copyOf(result);
	}
}
