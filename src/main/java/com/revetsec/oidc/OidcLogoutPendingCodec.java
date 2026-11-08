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
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Closed logout-only pending grammar. No credential, nonce, verifier or free-standing serializer is exposed. */
final class OidcLogoutPendingCodec {
	private static final Set<String> REQUIRED = Set.of("v", "purpose", "issuer", "client_id", "callback_uri", "state", "created_at", "expires_at");
	private OidcLogoutPendingCodec() { }
	record Decoded(@NonNull PendingOidcLogout pending, @Nullable String bindingDigest) {
		@Override public @NonNull String toString() { return "OidcLogoutPendingCodec.Decoded{correlation=<redacted>}"; }
	}
	static @NonNull String encode(@NonNull PendingOidcLogout pending, @Nullable String bindingDigest) {
		Map<String, String> fields = new LinkedHashMap<>(); fields.put("purpose", "oidc-logout"); fields.put("issuer", pending.getIssuer()); fields.put("client_id", pending.getClientId());
		fields.put("callback_uri", pending.getCallbackUri().toString()); fields.put("state", pending.state()); fields.put("created_at", pending.getCreatedAt().toString()); fields.put("expires_at", pending.getExpiresAt().toString());
		if (bindingDigest != null) { OidcLogoutSupport.state(bindingDigest); fields.put("binding_digest", bindingDigest); }
		long bytes = 7;
		for (Map.Entry<String, String> field : fields.entrySet()) bytes += 2L + jsonBytes(field.getKey()) + jsonBytes(field.getValue());
		if (bytes > OidcLogoutSupport.PENDING_LIMIT) throw OidcLogoutSupport.invalid();
		JsonObject.Builder object = JsonObject.builder().put("v", 1L); fields.forEach(object::put); String encoded = object.build().toJson();
		if (OidcLogoutSupport.text(encoded, OidcLogoutSupport.PENDING_LIMIT) != bytes) throw new IllegalStateException("OIDC logout pending size prediction failed.");
		return encoded;
	}
	private static long jsonBytes(@NonNull String value) {
		long bytes = 2L + OidcLogoutSupport.text(value, OidcLogoutSupport.PENDING_LIMIT);
		for (int i = 0; i < value.length(); ++i) {
			char c = value.charAt(i);
			if (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') ++bytes;
			else if (c < 0x20) bytes += 5;
		}
		return bytes;
	}
	static @NonNull Decoded decode(@NonNull String encoded) {
		JsonObject object = OidcLogoutSupport.object(encoded, OidcLogoutSupport.PENDING_LIMIT); OidcLogoutSupport.version(object);
		Set<String> keys = object.getMembers().keySet();
		if (!(keys.equals(REQUIRED) || keys.size() == REQUIRED.size() + 1 && keys.containsAll(REQUIRED) && keys.contains("binding_digest"))
				|| !OidcLogoutSupport.field(object, "purpose", 32).equals("oidc-logout")) throw OidcLogoutSupport.invalid();
		String issuer = OidcLogoutSupport.field(object, "issuer", OidcLogoutSupport.FIELD_LIMIT), client = OidcLogoutSupport.field(object, "client_id", OidcLogoutSupport.FIELD_LIMIT);
		URI callback; Instant created, expires;
		try {
			callback = URI.create(OidcLogoutSupport.field(object, "callback_uri", OidcLogoutSupport.FIELD_LIMIT));
			created = Instant.parse(OidcLogoutSupport.field(object, "created_at", 64)); expires = Instant.parse(OidcLogoutSupport.field(object, "expires_at", 64));
		} catch (IllegalArgumentException | java.time.DateTimeException invalid) { throw OidcLogoutSupport.invalid(); }
		String state = OidcLogoutSupport.field(object, "state", 43);
		PendingOidcLogout pending = new PendingOidcLogout(issuer, client, callback, state, created, expires);
		String binding = keys.contains("binding_digest") ? OidcLogoutSupport.field(object, "binding_digest", 43) : null;
		if (binding != null) OidcLogoutSupport.state(binding);
		return new Decoded(pending, binding);
	}
	static void interval(@NonNull Instant created, @NonNull Instant expires) {
		Duration lifetime = Duration.between(created, expires);
		if (lifetime.compareTo(Duration.ofMinutes(1)) < 0 || lifetime.compareTo(Duration.ofMinutes(60)) > 0) throw OidcLogoutSupport.invalid();
	}
	static @NonNull String digest(@NonNull String browserBinding) {
		OidcLogoutSupport.binding(browserBinding);
		try { return OidcSessionReference.digest(browserBinding); }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (RuntimeException | Error unavailable) { OidcLogoutSupport.interrupted(); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE); }
	}
}
