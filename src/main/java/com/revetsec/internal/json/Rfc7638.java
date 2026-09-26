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

package com.revetsec.internal.json;

import com.revetsec.internal.json.JsonFieldException.Kind;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * The canonical JSON form of a JWK that RFC 7638 hashes into a JWK thumbprint.
 * <p>
 * The form holds only the required members of the key type (RFC 7638 section 3.2), in lexicographic order, with no
 * whitespace, each value a JSON string:
 * <ul>
 *   <li>{@code RSA}: {@code e}, {@code kty}, {@code n} (RFC 7518 section 6.3.1);</li>
 *   <li>{@code EC}: {@code crv}, {@code kty}, {@code x}, {@code y} (RFC 7518 section 6.2.1);</li>
 *   <li>{@code OKP}: {@code crv}, {@code kty}, {@code x} (RFC 8037 section 2);</li>
 *   <li>{@code oct}: {@code k}, {@code kty} (RFC 7518 section 6.4.1).</li>
 * </ul>
 * Every other member ({@code alg}, {@code kid}, {@code use}, private members and so on) is ignored. The key type is
 * matched exactly, so {@code rsa} is not {@code RSA}. Values are copied as they are, not decoded or validated: that
 * is the key parser's job. The result is the UTF-8 encoding; the caller hashes it (SHA-256 for the usual thumbprint).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class Rfc7638 {
	@NonNull
	private static final List<@NonNull String> RSA_MEMBERS = List.of("e", "kty", "n");
	@NonNull
	private static final List<@NonNull String> EC_MEMBERS = List.of("crv", "kty", "x", "y");
	@NonNull
	private static final List<@NonNull String> OKP_MEMBERS = List.of("crv", "kty", "x");
	@NonNull
	private static final List<@NonNull String> OCT_MEMBERS = List.of("k", "kty");

	private Rfc7638() {
	}

	/**
	 * Returns the canonical form of a JWK's required members.
	 *
	 * @param jwk the JWK
	 * @return the UTF-8 bytes of the canonical JSON object
	 * @throws NullPointerException if {@code jwk} is {@code null}
	 * @throws JsonFieldException   {@link Kind#MISSING} if {@code kty} or a required member is absent;
	 *                              {@link Kind#WRONG_TYPE} if one is not a string; {@link Kind#UNSUPPORTED} if
	 *                              {@code kty} is not {@code RSA}, {@code EC}, {@code OKP} or {@code oct}, or a
	 *                              required value contains a character JSON must escape ({@code "}, {@code \} or a
	 *                              control character), for which RFC 7638 section 3.3 defines no thumbprint
	 */
	public static byte @NonNull [] canonicalJwk(@NonNull JsonObject jwk) throws JsonFieldException {
		requireNonNull(jwk);
		String keyType = requiredString(jwk, "kty");

		List<@NonNull String> members = switch (keyType) {
			case "RSA" -> RSA_MEMBERS;
			case "EC" -> EC_MEMBERS;
			case "OKP" -> OKP_MEMBERS;
			case "oct" -> OCT_MEMBERS;
			default -> throw new JsonFieldException(Kind.UNSUPPORTED);
		};

		StringBuilder output = new StringBuilder().append('{');

		for (int index = 0; index < members.size(); ++index) {
			String name = members.get(index);
			String value = requiredString(jwk, name);

			for (int character = 0; character < value.length(); ++character)
				if (value.charAt(character) < 0x20 || value.charAt(character) == '"' || value.charAt(character) == '\\')
					throw new JsonFieldException(Kind.UNSUPPORTED);

			if (index > 0)
				output.append(',');

			JsonWriter.writeString(output, name);
			output.append(':');
			JsonWriter.writeString(output, value);
		}

		// Every value came from a JsonString, which is well-formed UTF-16, so the encoder never substitutes.
		return output.append('}').toString().getBytes(StandardCharsets.UTF_8);
	}

	private static @NonNull String requiredString(@NonNull JsonObject jwk, @NonNull String name)
			throws JsonFieldException {
		@Nullable JsonValue value = jwk.getMembers().get(name);

		if (value == null)
			throw new JsonFieldException(Kind.MISSING);

		if (!(value instanceof JsonString string))
			throw new JsonFieldException(Kind.WRONG_TYPE);

		return string.getValue();
	}
}
