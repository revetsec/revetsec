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

import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Versioned, bounded pending-state record codec. No public serialization entry point exists. */
@ThreadSafe
final class PendingAuthorizationCodec {
	private static final int MAXIMUM_BYTES = 64 * 1_024;

	private PendingAuthorizationCodec() {
	}

	static String encode(PendingAuthorization pending, @Nullable String bindingDigest) {
		JsonObject.Builder builder = JsonObject.builder()
				.put("v", pending.kind().equals("oidc") ? 2L : 1L).put("kind", pending.kind()).put("issuer", pending.getIssuer())
				.put("client_id", pending.getClientId()).put("redirect_uri", pending.getRedirectUri().toString())
				.put("state", pending.state()).put("verifier", pending.verifier())
				.put("response_mode", pending.responseMode().name())
				.put("created_at", pending.getCreatedAt().toString())
				.put("expires_at", pending.getExpiresAt().toString())
				.put("issuer_required", pending.issuerRequired())
				.put("authorization_endpoint", pending.authorizationEndpoint().toString())
				.put("token_endpoint", pending.tokenEndpoint().toString());
		String nonce = pending.nonce();
		if (nonce != null)
			builder.put("nonce", nonce);
		if (pending.kind().equals("oidc")) {
			Duration maxAge = pending.maxAge();
			if (maxAge != null) builder.put("max_age", maxAge.getSeconds());
			builder.put("acr_values", JsonArray.fromElements(pending.acrValues().stream().sorted()
					.map(JsonString::fromValue).toList()));
			String prompt = pending.prompt();
			if (prompt != null) builder.put("prompt", prompt);
		}
		if (bindingDigest != null)
			builder.put("binding_digest", bindingDigest);
		builder.put("scopes", JsonArray.fromElements(pending.getRequestedScopes().stream()
				.map(JsonString::fromValue).toList()));
		builder.put("resources", JsonArray.fromElements(pending.resources().stream()
				.map(uri -> JsonString.fromValue(uri.toString())).toList()));
		JsonObject.Builder data = JsonObject.builder();
		pending.getApplicationData().forEach(data::put);
		builder.put("application_data", data.build());
		String encoded = builder.build().toJson();
		byte[] bytes;
		try {
			bytes = StrictUtf8.encode(encoded);
		} catch (EncodingException invalidText) {
			throw new IllegalArgumentException("The pending record contains invalid text.");
		}
		try {
			if (bytes.length > MAXIMUM_BYTES)
				throw new IllegalArgumentException("The pending record exceeds its byte limit.");
		} finally {
			Arrays.fill(bytes, (byte) 0);
		}
		return encoded;
	}

	static Decoded decode(String encoded) {
		try {
			byte[] bytes = StrictUtf8.encode(encoded);
			JsonValue parsed;
			try {
				if (bytes.length > MAXIMUM_BYTES)
					throw new IllegalArgumentException();
				parsed = JsonCodec.parse(bytes, JsonLimits.protocolDocument(MAXIMUM_BYTES));
			} finally {
				Arrays.fill(bytes, (byte) 0);
			}
			if (!(parsed instanceof JsonObject object))
				throw new IllegalArgumentException();
			Map<String, JsonValue> values = object.getMembers();
			if (!(values.get("v") instanceof com.revetsec.json.JsonNumber number)
					|| !number.getLongValueExact().filter(n -> n == 1 || n == 2).isPresent())
				throw new IllegalArgumentException();
			Instant createdAt = Instant.parse(text(values, "created_at"));
			Instant expiresAt = Instant.parse(text(values, "expires_at"));
			Duration lifetime = Duration.between(createdAt, expiresAt);
			if (lifetime.isNegative() || lifetime.isZero() || lifetime.compareTo(Duration.ofMinutes(60)) > 0)
				throw new IllegalArgumentException();
			Set<String> scopes = new HashSet<>(strings(values, "scopes"));
			List<URI> resources = new ArrayList<>();
			for (String resource : strings(values, "resources")) resources.add(URI.create(resource));
			JsonValue applicationData = values.get("application_data");
			if (!(applicationData instanceof JsonObject data)) throw new IllegalArgumentException();
			Map<String, String> app = new HashMap<>();
			for (Map.Entry<String, JsonValue> entry : data.getMembers().entrySet()) {
				if (!(entry.getValue() instanceof JsonString value)) throw new IllegalArgumentException();
				app.put(entry.getKey(), value.getValue());
			}
			JsonValue required = values.get("issuer_required");
			if (!(required instanceof JsonBoolean requiredBoolean)) throw new IllegalArgumentException();
			String kind = text(values, "kind");
			if (!kind.equals("oauth") && !kind.equals("oidc")) throw new IllegalArgumentException();
			long version = number.getLongValueExact().orElseThrow();
			String nonce = optionalText(values, "nonce");
			Duration maxAge = null;
			Set<String> acrValues = Set.of();
			String prompt = null;
			if (kind.equals("oidc")) {
				if (version != 2 || nonce == null || !scopes.contains("openid")) throw new IllegalArgumentException();
				if (values.containsKey("max_age")) {
					if (!(values.get("max_age") instanceof com.revetsec.json.JsonNumber age)) throw new IllegalArgumentException();
					long seconds = age.getLongValueExact().orElseThrow();
					if (seconds < 0) throw new IllegalArgumentException();
					maxAge = Duration.ofSeconds(seconds);
				}
				List<String> acrList = strings(values, "acr_values");
				acrValues = Set.copyOf(acrList);
				if (acrValues.size() != acrList.size() || acrValues.stream().anyMatch(value -> value.isEmpty()
						|| value.chars().anyMatch(c -> c <= 0x20 || c >= 0x7F))) throw new IllegalArgumentException();
				prompt = optionalText(values, "prompt");
				if (prompt != null) {
					List<String> prompts = List.of(prompt.split(" ", -1));
					if (prompts.stream().anyMatch(value -> !Set.of("none", "login", "consent", "select_account").contains(value))
							|| Set.copyOf(prompts).size() != prompts.size() || (prompts.contains("none") && prompts.size() != 1))
						throw new IllegalArgumentException();
				}
			} else if (version != 1 || values.containsKey("max_age") || values.containsKey("acr_values")
					|| values.containsKey("prompt")) throw new IllegalArgumentException();
			PendingAuthorization pending = new PendingAuthorization(kind, text(values, "issuer"),
					text(values, "client_id"), URI.create(text(values, "redirect_uri")), text(values, "state"),
					text(values, "verifier"), nonce, scopes, resources,
					AuthorizationRequestOptions.ResponseMode.valueOf(text(values, "response_mode")),
					createdAt, expiresAt, app, requiredBoolean.getValue(),
					URI.create(text(values, "authorization_endpoint")), URI.create(text(values, "token_endpoint")), maxAge, acrValues, prompt);
			return new Decoded(pending, optionalText(values, "binding_digest"));
		} catch (RuntimeException | EncodingException | com.revetsec.internal.json.JsonParseException exception) {
			throw OAuthValidationException.fromReason(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID);
		}
	}

	private static String text(Map<String, JsonValue> values, String name) {
		JsonValue value = values.get(name);
		if (!(value instanceof JsonString text) || text.getValue().isEmpty()) throw new IllegalArgumentException();
		return text.getValue();
	}

	@Nullable
	private static String optionalText(Map<String, JsonValue> values, String name) {
		return values.containsKey(name) ? text(values, name) : null;
	}

	private static List<String> strings(Map<String, JsonValue> values, String name) {
		JsonValue value = values.get(name);
		if (!(value instanceof JsonArray array)) throw new IllegalArgumentException();
		List<String> strings = new ArrayList<>();
		for (JsonValue element : array.getElements()) {
			if (!(element instanceof JsonString text)) throw new IllegalArgumentException();
			strings.add(text.getValue());
		}
		return strings;
	}

	static String bindingDigest(String binding) {
		if (binding.isEmpty()) throw new IllegalArgumentException("A browser binding must not be empty.");
		try {
			byte[] bindingBytes = StrictUtf8.encode(binding);
			try {
				byte[] digest = MessageDigest.getInstance("SHA-256").digest(bindingBytes);
				try {
					return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
				} finally {
					Arrays.fill(digest, (byte) 0);
				}
			} finally {
				Arrays.fill(bindingBytes, (byte) 0);
			}
		} catch (NoSuchAlgorithmException impossible) {
			throw new IllegalStateException("SHA-256 is unavailable.");
		} catch (EncodingException invalidText) {
			throw new IllegalArgumentException("A browser binding contains invalid text.");
		}
	}

	record Decoded(PendingAuthorization pending, @Nullable String bindingDigest) {
	}
}
