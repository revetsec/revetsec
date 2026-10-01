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

import com.revetsec.jose.*;
import com.revetsec.json.*;
import java.time.*;
import java.util.*;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Shared post-verification claim interpretation; never reads an incoming credential. RFC9068/RFC7662.
 */
@ThreadSafe
final class AccessTokenClaims {

	private AccessTokenClaims() {
	}

	static @NonNull Set<@NonNull String> names(@NonNull Set<@NonNull String> values, boolean audiences) {
		Set<String> copied = Set.copyOf(values);
		if ((audiences && copied.isEmpty()) || copied.contains(""))
			throw new IllegalArgumentException("Claim names and audiences must not be empty.");
		return copied;
	}

	static void required(@NonNull JsonObject claims, @NonNull Set<@NonNull String> names) {
		for (String name : names) if (!claims.getMembers().containsKey(name) || claims.getMembers().get(name) instanceof JsonNull)
			throw AccessTokenValidationException.fromReason(AccessTokenValidationException.Reason.REQUIRED_CLAIM_MISSING);
	}

	static @NonNull String requiredString(@NonNull JsonObject claims, @NonNull String name) {
		JsonValue value = claims.getMembers().get(name);
		if (value == null)
			throw AccessTokenValidationException.fromReason(AccessTokenValidationException.Reason.REQUIRED_CLAIM_MISSING);
		if (!(value instanceof JsonString text) || text.getValue().isEmpty())
			throw AccessTokenValidationException.fromReason(AccessTokenValidationException.Reason.INVALID_CLAIM);
		return text.getValue();
	}

	static @NonNull Set<@NonNull String> scopes(@Nullable JsonValue value, boolean arrayAllowed) {
		if (value == null)
			return Set.of();
		Set<String> result = new LinkedHashSet<>();
		if (value instanceof JsonString text) {
			if (text.getValue().isEmpty())
				return Set.of();
			for (String scope : text.getValue().split(" ", -1)) addScope(result, scope);
		} else if (arrayAllowed && value instanceof JsonArray array) {
			for (JsonValue element : array.getElements()) {
				if (!(element instanceof JsonString text))
					throw scopeFailure();
				addScope(result, text.getValue());
			}
		} else
			throw scopeFailure();
		return Set.copyOf(result);
	}

	private static void addScope(@NonNull Set<@NonNull String> scopes, @NonNull String value) {
		if (value.isEmpty())
			throw scopeFailure();
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c <= 0x20 || c == 0x22 || c == 0x5c || c >= 0x7f)
				throw scopeFailure();
		}
		scopes.add(value);
	}

	private static @NonNull AccessTokenValidationException scopeFailure() {
		return AccessTokenValidationException.fromReason(AccessTokenValidationException.Reason.SCOPE_INVALID);
	}
}
