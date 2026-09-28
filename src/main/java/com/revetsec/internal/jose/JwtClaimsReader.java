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

package com.revetsec.internal.jose;

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonFieldException;
import com.revetsec.internal.json.JsonFields;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.jose.JoseException;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Parses a verified JWS payload as a JWT claims set and reads its registered claims with their types checked (RFC 7519
 * sections 4.1 and 7.2; plan "JOSE semantics", steps 8 and 9). It runs only after the signature verified, so nothing
 * reads a forged payload.
 * <ul>
 *   <li>The payload is a strict UTF-8 JSON object under the token's JOSE profile: no byte-order mark, no ill-formed
 *   UTF-8, no duplicate member (RFC 7519 section 4), within the depth and size limits. An empty payload is not.</li>
 *   <li>{@code iss}, {@code sub} and {@code jti} are strings; {@code aud} is a string or a non-empty array of strings;
 *   {@code exp}, {@code nbf} and {@code iat} are NumericDates from year -9999 to 9999, with fractions allowed.</li>
 *   <li>A registered claim of the wrong type, out of range, or JSON {@code null} is malformed, never treated as
 *   absent.</li>
 * </ul>
 * Every failure is {@link JoseException.Reason#CLAIMS}, an unexpected {@link RuntimeException} included (INV-G1).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JwtClaimsReader {
	private JwtClaimsReader() {
		// Static helpers only.
	}

	/**
	 * Parses and reads a claims set.
	 *
	 * @param payload the verified payload; not modified
	 * @param limits  the JOSE profile it is parsed under
	 * @return the claims, with their registered claims read
	 * @throws NullPointerException if an argument is {@code null}
	 * @throws JoseFailure          {@link JoseException.Reason#CLAIMS} if the payload is not a claims set, or a
	 *                              registered claim is malformed
	 */
	@NonNull
	public static RegisteredClaims read(byte @NonNull [] payload,
																			@NonNull JsonLimits limits) throws JoseFailure {
		requireNonNull(payload);
		requireNonNull(limits);

		try {
			return readClaims(payload, limits);
		} catch (JsonParseException | JsonFieldException | RuntimeException e) {
			throw new JoseFailure(JoseException.Reason.CLAIMS);
		}
	}

	@NonNull
	private static RegisteredClaims readClaims(byte @NonNull [] payload,
																						 @NonNull JsonLimits limits) throws JsonParseException, JsonFieldException,
			JoseFailure {
		JsonValue parsed = JsonCodec.parse(payload, limits);

		if (!(parsed instanceof JsonObject claims))
			throw new JoseFailure(JoseException.Reason.CLAIMS);

		List<String> audiences = JsonFields.stringOrStringArray(claims, "aud").orElse(List.of());
		if (audiences.isEmpty() && claims.getMembers().containsKey("aud"))
			throw new JoseFailure(JoseException.Reason.CLAIMS);

		return new RegisteredClaims(claims, JsonFields.string(claims, "iss").orElse(null),
				JsonFields.string(claims, "sub").orElse(null), audiences, JsonFields.numericDate(claims, "exp").orElse(null),
				JsonFields.numericDate(claims, "iat").orElse(null), JsonFields.numericDate(claims, "nbf").orElse(null),
				JsonFields.string(claims, "jti").orElse(null));
	}
}
