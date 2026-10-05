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

import org.jspecify.annotations.NonNull;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.internal.jose.JwtValidationAccess;
import com.revetsec.json.*;
import com.revetsec.jose.*;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.Duration;
import java.util.Set;

/** Profile checks run before construction of a public UserInfo result. */
@ThreadSafe
final class UserInfoValidator {
	private UserInfoValidator() { }
	static @NonNull JsonObject json(byte @NonNull [] body, @NonNull String subject) {
		try {
			JsonValue parsed = JsonCodec.parse(body, JsonLimits.protocolDocument(256 * 1_024));
			if (!(parsed instanceof JsonObject object)) throw OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_MALFORMED);
			checkSubject(object, subject); return object;
		} catch (JsonParseException invalid) { throw OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_MALFORMED); }
	}
	static @NonNull JsonObject signed(@NonNull String compact, @NonNull String issuer, @NonNull String clientId, @NonNull String subject, @NonNull JwsAlgorithm algorithm,
			@NonNull JsonWebKeySource keys, @NonNull Duration skew, @NonNull Clock clock, @NonNull OidcObserver observer, @NonNull Set<@NonNull String> trustedAudiences, @NonNull Deadline deadline) {
		return signed(compact, issuer, clientId, subject, algorithm, keys, skew, clock, observer, trustedAudiences, deadline, false);
	}
	static @NonNull JsonObject signed(@NonNull String compact, @NonNull String issuer, @NonNull String clientId, @NonNull String subject, @NonNull JwsAlgorithm algorithm,
			@NonNull JsonWebKeySource keys, @NonNull Duration skew, @NonNull Clock clock, @NonNull OidcObserver observer, @NonNull Set<@NonNull String> trustedAudiences, @NonNull Deadline deadline, boolean microsoftEntra) {
		Jwt token;
		try {
			JwtValidator validator = JwtValidator.withIssuer(issuer).expectedAudiences(Set.of(clientId))
					.jsonWebKeySource(keys).allowedAlgorithms(Set.of(algorithm)).requiredClaims(Set.of("sub"))
					.clockSkew(skew).clock(clock).observer(observer).build();
			token = microsoftEntra ? JwtValidationAccess.get().validateMicrosoftEntraUserInfo(validator, compact, issuer, deadline::remainingNanos)
					: JwtValidationAccess.get().validateUserInfo(validator, compact, deadline::remainingNanos);
		} catch (JoseException invalid) { throw OidcValidationException.fromUserInfoJoseReason(invalid.getReason()); }
		for (String audience : token.getClaims().getAudiences())
			if (!audience.equals(clientId) && !trustedAudiences.contains(audience))
				throw OidcValidationException.fromReason(OidcValidationException.Reason.UNTRUSTED_AUDIENCE);
		JsonObject claims = token.getClaims().toJsonObject(); checkSubject(claims, subject); return claims;
	}
	private static void checkSubject(@NonNull JsonObject claims, @NonNull String expected) {
		if (!(claims.getMembers().get("sub") instanceof JsonString text) || text.getValue().isEmpty()
				|| text.getValue().length() > 255 || text.getValue().chars().anyMatch(c -> c > 0x7F))
			throw OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_MALFORMED);
		if (!text.getValue().equals(expected))
			throw OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_SUBJECT_MISMATCH);
	}
}
