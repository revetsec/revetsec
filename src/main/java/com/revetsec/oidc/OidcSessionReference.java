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

import com.revetsec.internal.crypto.ConstantTime;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

/**
 * Continuity reference for refresh and future logout. It holds original continuity claims and a SHA-256 nonce
 * digest. It is not proof of identity and contains no access, refresh or compact ID token.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OidcSessionReference {
	private final com.revetsec.json.JsonObject continuityClaims;
	private final String nonceDigest;
	private final @Nullable String sessionId;
	OidcSessionReference(IdToken token) {
		// Keep only continuity fields; email and other identity attributes do not enter the reference.
		com.revetsec.json.JsonObject.Builder fields = com.revetsec.json.JsonObject.builder();
		for (String name : java.util.List.of("iss", "sub", "aud", "azp", "auth_time", "sid"))
			token.getClaims().getClaim(name).ifPresent(value -> fields.put(name, value));
		this.continuityClaims = fields.build();
		this.nonceDigest = digest(((JsonString) token.getClaims().getClaim("nonce").orElseThrow()).getValue());
		this.sessionId = token.getClaims().getClaim("sid").map(value -> ((JsonString) value).getValue()).orElse(null);
	}
	static String digest(String nonce) {
		byte[] input = nonce.getBytes(StandardCharsets.UTF_8);
		try {
			byte[] result = MessageDigest.getInstance("SHA-256").digest(input);
			try { return Base64.getUrlEncoder().withoutPadding().encodeToString(result); }
			finally { Arrays.fill(result, (byte) 0); }
		} catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 is unavailable."); }
		finally { Arrays.fill(input, (byte) 0); }
	}
	com.revetsec.json.JsonObject continuityClaims() { return this.continuityClaims; }
	boolean matchesNonce(String nonce) { return ConstantTime.isEqual(this.nonceDigest, digest(nonce)); }
	/**
	 * Returns the original validated session ID, if present. This reference is not proof of identity.
	 *
	 * @return session ID
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getSessionId() { return Optional.ofNullable(this.sessionId); }
	/**
	 * Redacts all session continuity fields.
	 *
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OidcSessionReference{session=<redacted>}"; }
}
