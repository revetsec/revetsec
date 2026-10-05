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

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.ConstantTime;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.json.*;
import com.revetsec.jose.JwtClaims;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import static java.util.Objects.requireNonNull;

/**
 * Continuity reference for refresh and future logout. It holds original continuity claims, client binding and a
 * SHA-256 nonce digest. It is not proof of identity and contains no access, refresh or compact ID token. Persist
 * it in trusted application storage or seal it; parsing a serialized reference does not authenticate its fields.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OidcSessionReference {
	private static final int MAXIMUM_BYTES = 64 * 1_024;
	private static final Set<String> CLAIM_NAMES = Set.of("iss", "sub", "aud", "iat", "azp", "auth_time", "sid");
	private final JsonObject continuityClaims;
	private final String clientId;
	private final String nonceDigest;
	private final @Nullable String sessionId;
	OidcSessionReference(@NonNull IdToken token, @NonNull String clientId) {
		JsonObject.Builder fields = JsonObject.builder();
		for (String name : CLAIM_NAMES) token.getClaims().getClaim(name).ifPresent(value -> fields.put(name, value));
		this.continuityClaims = fields.build(); this.clientId = requireNonNull(clientId);
		this.nonceDigest = digest(((JsonString) token.getClaims().getClaim("nonce").orElseThrow()).getValue());
		this.sessionId = token.getClaims().getClaim("sid").map(value -> ((JsonString) value).getValue()).orElse(null);
	}
	private OidcSessionReference(@NonNull JsonObject claims, @NonNull String clientId, @NonNull String nonceDigest) {
		this.continuityClaims = claims; this.clientId = clientId; this.nonceDigest = nonceDigest;
		this.sessionId = claims.findString("sid").orElse(null);
	}
	static @NonNull String digest(@NonNull String nonce) {
		byte[] input = nonce.getBytes(StandardCharsets.UTF_8);
		try {
			byte[] result = MessageDigest.getInstance("SHA-256").digest(input);
			try { return Base64.getUrlEncoder().withoutPadding().encodeToString(result); }
			finally { Arrays.fill(result, (byte) 0); }
		} catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 is unavailable."); }
		finally { Arrays.fill(input, (byte) 0); }
	}
	@NonNull JsonObject continuityClaims() { return this.continuityClaims; }
	boolean matchesNonce(@NonNull String nonce) { return ConstantTime.isEqual(this.nonceDigest, digest(nonce)); }
	boolean matchesOriginalReference(@NonNull OidcSessionReference other) {
		if (!this.clientId.equals(other.clientId) || !ConstantTime.isEqual(this.nonceDigest, other.nonceDigest)
				|| !audiences(this.continuityClaims).equals(audiences(other.continuityClaims))) return false;
		Map<String, JsonValue> original = new HashMap<>(this.continuityClaims.getMembers());
		Map<String, JsonValue> restored = new HashMap<>(other.continuityClaims.getMembers());
		original.remove("aud"); restored.remove("aud");
		return original.equals(restored);
	}
	void checkMicrosoftEntraClient(@NonNull String clientId) {
		if (!this.clientId.equals(clientId) || OidcIssuerPolicy.tenantFromIssuer(this.continuityClaims.findString("iss").orElseThrow()) == null) throw mismatch();
	}
	void checkClient(@NonNull String issuer, @NonNull String clientId) {
		if (!this.continuityClaims.findString("iss").orElseThrow().equals(issuer) || !this.clientId.equals(clientId)) throw mismatch();
	}
	void checkContinuity(@NonNull JwtClaims claims) {
		try {
			JsonObject current = claims.toJsonObject();
			if (!Objects.equals(current.getMembers().get("iss"), this.continuityClaims.getMembers().get("iss"))
					|| !Objects.equals(current.getMembers().get("sub"), this.continuityClaims.getMembers().get("sub"))
					|| !Set.copyOf(claims.getAudiences()).equals(audiences(this.continuityClaims))
					|| !Objects.equals(current.getMembers().get("azp"), this.continuityClaims.getMembers().get("azp"))) throw mismatch();
			Instant issuedAt = claims.getIssuedAt().orElseThrow();
			if (issuedAt.isBefore(JsonFields.numericDate(this.continuityClaims, "iat").orElseThrow())) throw mismatch();
			if (current.getMembers().containsKey("auth_time") && !JsonFields.numericDate(current, "auth_time")
					.equals(JsonFields.numericDate(this.continuityClaims, "auth_time"))) throw mismatch();
			if (current.getMembers().get("nonce") instanceof JsonString nonce && !matchesNonce(nonce.getValue())) throw mismatch();
		} catch (JsonFieldException invalid) { throw mismatch(); }
	}
	private static @NonNull OidcValidationException mismatch() { return OidcValidationException.fromReason(OidcValidationException.Reason.REFRESHED_ID_TOKEN_MISMATCH); }
	private static @NonNull Set<@NonNull String> audiences(@NonNull JsonObject claims) {
		JsonValue value = claims.getMembers().get("aud"); Set<String> result = new HashSet<>();
		if (value instanceof JsonString text && !text.getValue().isEmpty()) result.add(text.getValue());
		else if (value instanceof JsonArray array && !array.getElements().isEmpty()) {
			for (JsonValue item : array.getElements()) {
				if (!(item instanceof JsonString text) || text.getValue().isEmpty()) throw new IllegalArgumentException();
				result.add(text.getValue());
			}
		} else throw new IllegalArgumentException();
		return Set.copyOf(result);
	}
	/**
	 * Explicitly serializes the original continuity fields and nonce digest for trusted storage. This discloses
	 * issuer, subject and session data; do not log it. It neither authenticates fields nor creates an identity.
	 * @return versioned, bounded JSON storage form
	 * @since 1.0.0
	 */
	public @NonNull String toSerializedForm() {
		String value = JsonObject.builder().put("v", 1L).put("client_id", this.clientId).put("claims", this.continuityClaims).put("nonce_digest", this.nonceDigest).build().toJson();
		if (value.length() > MAXIMUM_BYTES) throw invalid();
		byte[] bytes;
		try { bytes = StrictUtf8.encode(value); } catch (EncodingException malformed) { throw invalid(); }
		try { if (bytes.length > MAXIMUM_BYTES) throw invalid(); return value; } finally { Arrays.fill(bytes, (byte) 0); }
	}
	/**
	 * Parses a bounded reference from trusted application storage. This factory checks structure only, supplies no
	 * identity and accepts no credentials. Untrusted browser storage must use {@link #fromSealedForm(String, StateSealer, String)}.
	 * @param serializedForm versioned storage form
	 * @return continuity reference, not authenticated identity
	 * @throws OidcValidationException if the structure is invalid
	 * @since 1.0.0
	 */
	public static @NonNull OidcSessionReference fromSerializedForm(@NonNull String serializedForm) {
		requireNonNull(serializedForm); byte @Nullable [] bytes = null;
		try {
			if (serializedForm.length() > MAXIMUM_BYTES) throw new IllegalArgumentException();
			bytes = StrictUtf8.encode(serializedForm); JsonValue value = JsonCodec.parse(bytes, JsonLimits.protocolDocument(MAXIMUM_BYTES));
			if (!(value instanceof JsonObject envelope) || !envelope.getMembers().keySet().equals(Set.of("v", "client_id", "claims", "nonce_digest"))
					|| !envelope.findLong("v").filter(v -> v == 1).isPresent() || !(envelope.getMembers().get("claims") instanceof JsonObject claims)) throw new IllegalArgumentException();
			String client = envelope.findString("client_id").filter(v -> !v.isEmpty()).orElseThrow(IllegalArgumentException::new);
			String digest = envelope.findString("nonce_digest").orElseThrow(IllegalArgumentException::new);
			if (digest.length() != 43) throw new IllegalArgumentException();
			byte[] decoded = Base64Url.decode(digest);
			try { if (decoded.length != 32) throw new IllegalArgumentException(); }
			finally { Arrays.fill(decoded, (byte) 0); }
			if (!CLAIM_NAMES.containsAll(claims.getMembers().keySet()) || !claims.findString("iss").filter(v -> !v.isEmpty()).isPresent()) throw new IllegalArgumentException();
			String subject = claims.findString("sub").orElseThrow(IllegalArgumentException::new);
			if (subject.isEmpty() || subject.length() > 255 || subject.chars().anyMatch(c -> c > 0x7f)) throw new IllegalArgumentException();
			if (!audiences(claims).contains(client) || JsonFields.numericDate(claims, "iat").isEmpty()) throw new IllegalArgumentException();
			JsonFields.numericDate(claims, "auth_time");
			for (String name : List.of("azp", "sid")) if (claims.getMembers().containsKey(name) && !(claims.getMembers().get(name) instanceof JsonString)) throw new IllegalArgumentException();
			return new OidcSessionReference(claims, client, digest);
		} catch (JsonParseException | JsonFieldException | EncodingException | IllegalArgumentException invalid) { throw invalid(); }
		finally { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
	}
	/**
	 * Seals a reference under an application-specific context and explicit lifetime. The sealer's lifetime and size
	 * bounds apply. The application owns session lifetime and refresh-token storage.
	 * @param sealer application sealer
	 * @param context application-specific OIDC session context
	 * @param lifetime how long the sealed reference opens
	 * @return sealed storage form
	 * @since 1.0.0
	 */
	public @NonNull String toSealedForm(@NonNull StateSealer sealer, @NonNull String context, @NonNull Duration lifetime) {
		return requireNonNull(sealer).seal(toSerializedForm(), requireNonNull(context), requireNonNull(lifetime));
	}
	/**
	 * Opens a sealed reference under the same application-specific context. Sealer failures retain its fixed
	 * exception; invalid reference structure uses a fixed OIDC reason. No identity is created by opening it.
	 * @param sealedForm sealed storage form
	 * @param sealer application sealer
	 * @param context original OIDC session context
	 * @return continuity reference
	 * @since 1.0.0
	 */
	public static @NonNull OidcSessionReference fromSealedForm(@NonNull String sealedForm, @NonNull StateSealer sealer, @NonNull String context) {
		return fromSerializedForm(requireNonNull(sealer).unseal(requireNonNull(sealedForm), requireNonNull(context)));
	}
	private static @NonNull OidcValidationException invalid() { return OidcValidationException.fromReason(OidcValidationException.Reason.SESSION_REFERENCE_INVALID); }
	/**
	 * Returns the original session ID, if present. This reference is not proof of identity.
	 * @return session ID
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getSessionId() { return Optional.ofNullable(this.sessionId); }
	/**
	 * Redacts all session continuity fields.
	 * @return a redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OidcSessionReference{session=<redacted>}"; }
}
