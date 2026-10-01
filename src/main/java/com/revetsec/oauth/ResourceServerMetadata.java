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
import com.revetsec.internal.json.*;
import com.revetsec.json.*;
import java.net.URI;
import java.util.*;
import javax.annotation.concurrent.Immutable;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * RFC8414 role projection. No unrelated browser/token endpoints or ID-token algorithms are required.
 */
@Immutable
final class ResourceServerMetadata {

	enum Role {

		JWT, INTROSPECTION
	}

	private final String issuer;

	private final URI endpoint;

	@Nullable
	private final Set<String> authenticationMethods;

	ResourceServerMetadata(@NonNull String issuer, @NonNull URI endpoint, @Nullable Set<@NonNull String> methods) {
		this.issuer = issuer;
		this.endpoint = endpoint;
		this.authenticationMethods = methods;
	}

	@NonNull String issuer() {
		return this.issuer;
	}

	@NonNull URI endpoint() {
		return this.endpoint;
	}

	@Nullable
	Set<@NonNull String> authenticationMethods() {
		return this.authenticationMethods;
	}

	static @NonNull ResourceServerMetadata parse(@NonNull String issuer, byte @NonNull [] bytes, @NonNull Role role) {
		try {
			JsonValue value = JsonCodec.parse(bytes, JsonLimits.protocolDocument(Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue()));
			if (!(value instanceof JsonObject object))
				throw malformed();
			String actual = text(object, "issuer");
			if (!issuer.equals(actual))
				throw OAuthValidationException.fromReason(OAuthException.Reason.ISSUER_MISMATCH);
			URI endpoint = URI.create(text(object, role == Role.JWT ? "jwks_uri" : "introspection_endpoint"));
			Set<String> methods = null;
			if (object.getMembers().containsKey("introspection_endpoint_auth_methods_supported")) {
				if (!(object.getMembers().get("introspection_endpoint_auth_methods_supported") instanceof JsonArray array))
					throw malformed();
				Set<String> parsed = new LinkedHashSet<>();
				for (JsonValue element : array.getElements()) {
					if (!(element instanceof JsonString string) || string.getValue().isEmpty() || !parsed.add(string.getValue()))
						throw malformed();
				}
				methods = Set.copyOf(parsed);
			}
			return new ResourceServerMetadata(issuer, endpoint, methods);
		} catch (JsonParseException | IllegalArgumentException failure) {
			throw malformed();
		}
	}

	private static @NonNull String text(@NonNull JsonObject claims, @NonNull String name) {
		if (!(claims.getMembers().get(name) instanceof JsonString text) || text.getValue().isEmpty())
			throw malformed();
		return text.getValue();
	}

	private static @NonNull OAuthResponseException malformed() {
		return OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
	}

	@Override
	public @NonNull String toString() {
		return "ResourceServerMetadata{data=<redacted>}";
	}
}
