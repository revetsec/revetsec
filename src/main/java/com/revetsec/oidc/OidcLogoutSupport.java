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
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.HostClassifier;
import com.revetsec.internal.jose.CompactJws;
import com.revetsec.internal.jose.CompactJwsParser;
import com.revetsec.internal.jose.JoseFailure;
import com.revetsec.internal.jose.JoseHeaderPolicy;
import com.revetsec.internal.jose.JwtClaimsReader;
import com.revetsec.internal.jose.RegisteredClaims;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonFieldException;
import com.revetsec.internal.json.JsonFields;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** Pure bounded logout framing and structural comparisons; no identity or signature validation. */
final class OidcLogoutSupport {
	static final int TOKEN_LIMIT = 65_536, REFERENCE_LIMIT = 65_536, HINT_LIMIT = 131_200;
	static final int FIELD_LIMIT = 2_048, BINDING_LIMIT = 512, PENDING_LIMIT = 16_384, QUERY_LIMIT = 4_096, REQUEST_LIMIT = 131_072;
	private static final Set<String> RESERVED = Set.of("id_token_hint", "logout_hint", "client_id", "post_logout_redirect_uri", "state", "ui_locales");
	private OidcLogoutSupport() { }

	/** Counts exactly before encoding/copy, rejecting malformed UTF16 and excessive character/byte counts. */
	static int text(@NonNull String value, int maximum) {
		requireNonNull(value);
		if (value.length() > maximum) throw invalid();
		int bytes = 0;
		for (int i = 0; i < value.length(); ++i) {
			char c = value.charAt(i);
			if (Character.isHighSurrogate(c)) {
				if (++i >= value.length() || !Character.isLowSurrogate(value.charAt(i))) throw invalid();
				bytes += 4;
			} else if (Character.isLowSurrogate(c)) throw invalid();
			else bytes += c < 0x80 ? 1 : c < 0x800 ? 2 : 3;
			if (bytes > maximum) throw invalid();
		}
		return bytes;
	}
	static void client(@NonNull String value) {
		if (text(value, FIELD_LIMIT) == 0 || value.chars().anyMatch(Character::isISOControl)) throw invalid();
	}
	static void binding(@NonNull String value) { if (text(value, BINDING_LIMIT) == 0) throw invalid(); }
	static @NonNull URI callback(@NonNull URI uri, boolean loopback) {
		text(uri.toString(), FIELD_LIMIT);
		String scheme = uri.getScheme(), host = uri.getHost();
		if (!uri.isAbsolute() || uri.isOpaque() || scheme == null || host == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null
				|| uri.getRawQuery() != null || uri.getPort() == 0 || uri.getPort() > 65_535 || !(scheme.equalsIgnoreCase("https") || (scheme.equalsIgnoreCase("http") && loopback && HostClassifier.isPlainHttpLoopbackHost(host)))) throw invalid();
		return uri;
	}
	static void endpoint(@NonNull URI uri) {
		text(uri.toString(), FIELD_LIMIT);
		String query = uri.getRawQuery();
		if (query == null || query.isEmpty()) return;
		Set<String> seen = new HashSet<>();
		for (String pair : query.split("&", -1)) {
			int equals = pair.indexOf('='); if (pair.isEmpty() || equals == 0) throw invalid();
			try {
				String name = FormUrlEncoding.decode(equals < 0 ? pair : pair.substring(0, equals));
				if (equals >= 0) FormUrlEncoding.decode(pair.substring(equals + 1));
				if (RESERVED.contains(name) || !seen.add(name)) throw invalid();
			} catch (EncodingException failure) { throw invalid(); }
		}
	}
	static @NonNull String returnedState(@NonNull String rawQuery) {
		if (rawQuery.length() > QUERY_LIMIT || !rawQuery.startsWith("state=") || rawQuery.indexOf('&') >= 0 || rawQuery.indexOf(';') >= 0) throw invalid();
		try { String state = FormUrlEncoding.decode(rawQuery.substring(6)); state(state); return state; }
		catch (EncodingException failure) { throw invalid(); }
	}
	static void state(@NonNull String state) {
		if (state.length() != 43) throw invalid();
		try { byte[] decoded = Base64Url.decode(state); try { if (decoded.length != 32) throw invalid(); } finally { clear(decoded); } }
		catch (EncodingException failure) { throw invalid(); }
	}
	static @NonNull JsonObject object(@NonNull String encoded, int maximum) {
		text(encoded, maximum); byte @Nullable [] bytes = null;
		try { bytes = StrictUtf8.encode(encoded); if (!(JsonCodec.parse(bytes, JsonLimits.protocolDocument(maximum)) instanceof JsonObject object)) throw invalid(); return object; }
		catch (EncodingException | JsonParseException failure) { throw invalid(); }
		finally { clear(bytes); }
	}
	static @NonNull String field(@NonNull JsonObject object, @NonNull String name, int maximum) {
		try { String value = JsonFields.string(object, name).orElseThrow(OidcLogoutSupport::invalid); text(value, maximum); return value; }
		catch (JsonFieldException failure) { throw invalid(); }
	}
	static void version(@NonNull JsonObject object) {
		if (!(object.getMembers().get("v") instanceof JsonNumber number) || !number.getLongValueExact().filter(v -> v == 1).isPresent()) throw invalid();
	}
	static @NonNull RegisteredClaims token(@NonNull String compact) {
		byte @Nullable [] header = null, payload = null, signature = null;
		try {
			CompactJws parsed = CompactJwsParser.parse(compact, TOKEN_LIMIT);
			header = parsed.getHeader(); payload = parsed.getPayload(); signature = parsed.getSignature();
			JoseHeaderPolicy.fromSettings(TOKEN_LIMIT, EnumSet.allOf(JwsAlgorithm.class), Set.of("JWT"), false).check(header);
			if (signature.length == 0) throw invalid();
			RegisteredClaims claims = JwtClaimsReader.read(payload, JsonLimits.jose(TOKEN_LIMIT));
			if (claims.expiresAt() == null || claims.issuedAt() == null || claims.issuer() == null || claims.subject() == null || claims.audiences().isEmpty()) throw invalid();
			return claims;
		} catch (JoseFailure failure) { throw invalid(); }
		finally { clear(header); clear(payload); clear(signature); }
	}
	/** Equivalent structural comparisons to reference.checkContinuity; creates no validated JwtClaims or IdToken. */
	static void continuity(@NonNull OidcSessionReference reference, @NonNull RegisteredClaims claims) {
		JsonObject current = claims.claims(), original = reference.continuityClaims();
		try {
			if (!Objects.equals(current.getMembers().get("iss"), original.getMembers().get("iss"))
					|| !Objects.equals(current.getMembers().get("sub"), original.getMembers().get("sub"))
					|| !Set.copyOf(claims.audiences()).equals(Set.copyOf(JsonFields.stringOrStringArray(original, "aud").orElseThrow(OidcLogoutSupport::invalid)))
					|| !Objects.equals(current.getMembers().get("azp"), original.getMembers().get("azp"))
					|| requireNonNull(claims.issuedAt()).isBefore(JsonFields.numericDate(original, "iat").orElseThrow(OidcLogoutSupport::invalid))) throw invalid();
			if (current.getMembers().containsKey("auth_time") && !JsonFields.numericDate(current, "auth_time").equals(JsonFields.numericDate(original, "auth_time"))) throw invalid();
			if (current.getMembers().containsKey("nonce") && !nonceMatches(reference, JsonFields.string(current, "nonce").orElseThrow(OidcLogoutSupport::invalid))) throw invalid();
			if (current.getMembers().containsKey("sid")) JsonFields.string(current, "sid");
		} catch (JsonFieldException failure) { throw invalid(); }
	}
	private static boolean nonceMatches(@NonNull OidcSessionReference reference, @NonNull String nonce) {
		try { return reference.matchesNonce(nonce); }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (RuntimeException | Error unavailable) { interrupted(); throw failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE); }
	}
	static boolean same(@NonNull String one, @NonNull String two) { return ConstantTime.isEqual(one, two); }
	static java.time.@NonNull Duration remaining(@NonNull Deadline deadline) {
		active(deadline); java.time.Duration allowance = deadline.remaining();
		if (allowance.isZero() || allowance.isNegative()) throw failure(OidcLogoutException.Reason.BUDGET_EXHAUSTED);
		return allowance;
	}
	static void active(@NonNull Deadline deadline) { interrupted(); if (deadline.isExpired()) throw failure(OidcLogoutException.Reason.BUDGET_EXHAUSTED); }
	static void interrupted() { if (Thread.currentThread().isInterrupted()) throw failure(OidcLogoutException.Reason.INTERRUPTED); }
	static @NonNull OidcLogoutException failure(OidcLogoutException.@NonNull Reason reason) { return OidcLogoutException.fromReason(reason); }
	static @NonNull IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid OIDC logout value."); }
	static void clear(byte @Nullable [] bytes) { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
}
