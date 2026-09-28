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

import com.revetsec.internal.json.AsciiCase;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import static java.util.Objects.requireNonNull;

/**
 * The JWS-layer settings a token is checked against before any key is looked up: the maximum token length, the
 * effective algorithm set, and the allowed {@code typ} values (plan P1 to P8, M2-4).
 * <p>
 * <strong>{@code typ}</strong> is a media type (RFC 7515 section 4.1.9, read 2026-09-28; RFC 2045). A value without a
 * {@code /} has {@code application/} implied, and values are compared after folding ASCII letters only
 * ({@link AsciiCase}), so {@code JWT}, {@code jwt} and {@code application/JWT} are one type. Allowed types are media
 * types without parameters: a {@code type/subtype} pair of RFC 9110 tokens. A header {@code typ} that is not of that
 * form is never allowed.
 * <p>
 * {@link #check(byte[])} applies the header checks (plan "JOSE semantics", step 4) in a fixed order, and the first
 * failure names the reason:
 * <ol>
 *   <li>the header is a strict UTF-8 JSON object under {@link #getJsonLimits()}: no byte-order mark, no ill-formed
 *   UTF-8 or unpaired surrogate, no duplicate member, within the depth and size limits (RFC 7515 section 5.2, RFC 8725
 *   section 3.7); else {@link JoseException.Reason#HEADER};</li>
 *   <li>P4: {@code alg} is a string, else {@link JoseException.Reason#HEADER}, that names an algorithm in the effective
 *   set exactly, else {@link JoseException.Reason#ALGORITHM_NOT_ALLOWED}. There is no {@code none} algorithm, and no
 *   case folding, so every spelling of {@code none} fails here (RFC 8725 section 3.2);</li>
 *   <li>P5: {@code crit} with any value is {@link JoseException.Reason#CRITICAL_HEADER}, because no extension is
 *   understood (RFC 7515 section 4.1.11); then {@code b64} is {@link JoseException.Reason#UNENCODED_PAYLOAD} (RFC 7797)
 *   and {@code zip} is {@link JoseException.Reason#COMPRESSED_PAYLOAD};</li>
 *   <li>P6: {@code jwk}, {@code jku} or {@code x5u} is {@link JoseException.Reason#UNTRUSTED_KEY_REFERENCE}; nothing
 *   is ever fetched or trusted from a token (RFC 8725 section 3.10). {@code x5c}, {@code x5t} and {@code x5t#S256} are
 *   ignored;</li>
 *   <li>P7: {@code typ} as above, else {@link JoseException.Reason#INVALID_TYPE};</li>
 *   <li>P8: {@code cty} is {@link JoseException.Reason#NESTED_TOKEN}, because nested tokens are not processed (RFC 7519
 *   section 7.2, step 8);</li>
 *   <li>{@code kid}, when present, is a string of 1 to {@value JwkParser#MAXIMUM_KEY_ID_LENGTH} characters, else
 *   {@link JoseException.Reason#HEADER}.</li>
 * </ol>
 * Every other member is ignored (RFC 7515 section 4). An unexpected {@link RuntimeException} is
 * {@link JoseException.Reason#HEADER} (INV-G1).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class JoseHeaderPolicy {
	private static final String IMPLIED_TYPE_PREFIX = "application/";

	/**
	 * The header members that point at a key or a key location outside the trusted key source (P6).
	 */
	@NonNull
	private static final List<@NonNull String> KEY_REFERENCE_MEMBERS = List.of("jwk", "jku", "x5u");

	private final int maximumTokenLength;
	@NonNull
	private final JsonLimits jsonLimits;
	@NonNull
	private final Set<@NonNull JwsAlgorithm> allowedAlgorithms;
	@NonNull
	private final Set<@NonNull String> allowedTypes;
	private final boolean typeRequired;

	private JoseHeaderPolicy(int maximumTokenLength,
													 @NonNull JsonLimits jsonLimits,
													 @NonNull Set<@NonNull JwsAlgorithm> allowedAlgorithms,
													 @NonNull Set<@NonNull String> allowedTypes,
													 boolean typeRequired) {
		this.maximumTokenLength = maximumTokenLength;
		this.jsonLimits = jsonLimits;
		this.allowedAlgorithms = Set.copyOf(allowedAlgorithms);
		this.allowedTypes = Set.copyOf(allowedTypes);
		this.typeRequired = typeRequired;
	}

	/**
	 * Returns a policy from settings the caller has already range-checked against its own limits.
	 *
	 * @param maximumTokenLength the longest token accepted, in characters, from 1 to 1 MiB
	 * @param allowedAlgorithms  the effective algorithm set, not empty; HMAC algorithms are allowed here, for the
	 *                           internal HMAC engine
	 * @param allowedTypes       the allowed {@code typ} media types, each normalized here; may be empty when a type is
	 *                           not required, which then allows only tokens without {@code typ}
	 * @param typeRequired       whether a token without {@code typ} is rejected
	 * @return the policy
	 * @throws NullPointerException     if a set or an element is {@code null}
	 * @throws IllegalArgumentException if the length is out of range, the algorithm set is empty, an allowed type is
	 *                                  not a media type without parameters, or a type is required but none is allowed
	 */
	@NonNull
	public static JoseHeaderPolicy fromSettings(int maximumTokenLength,
																							@NonNull Set<@NonNull JwsAlgorithm> allowedAlgorithms,
																							@NonNull Set<@NonNull String> allowedTypes,
																							boolean typeRequired) {
		JsonLimits jsonLimits = JsonLimits.jose(maximumTokenLength);
		Set<JwsAlgorithm> algorithms = Set.copyOf(allowedAlgorithms);
		if (algorithms.isEmpty())
			throw new IllegalArgumentException("At least one algorithm must be allowed.");

		Set<String> types = new LinkedHashSet<>();
		for (String type : Set.copyOf(allowedTypes))
			types.add(normalizeType(type).orElseThrow(() -> new IllegalArgumentException("An allowed type must be a "
					+ "media type without parameters, such as JWT or application/jwt.")));

		if (typeRequired && types.isEmpty())
			throw new IllegalArgumentException("A type cannot be required when no type is allowed.");

		return new JoseHeaderPolicy(maximumTokenLength, jsonLimits, algorithms, types, typeRequired);
	}

	/**
	 * Normalizes a {@code typ} value: {@code application/} is prepended when it has no {@code /} (RFC 7515
	 * section 4.1.9), and ASCII letters are folded to lower case.
	 *
	 * @param type the value
	 * @return the normalized media type, or empty if {@code type} is not a {@code type/subtype} pair of RFC 9110 tokens
	 * with no parameters
	 * @throws NullPointerException if {@code type} is {@code null}
	 */
	@NonNull
	public static Optional<@NonNull String> normalizeType(@NonNull String type) {
		requireNonNull(type);
		String mediaType = type.indexOf('/') < 0 ? IMPLIED_TYPE_PREFIX + type : type;
		int slash = mediaType.indexOf('/');

		if (!isToken(mediaType, 0, slash) || !isToken(mediaType, slash + 1, mediaType.length()))
			return Optional.empty();

		return Optional.of(AsciiCase.fold(mediaType));
	}

	/**
	 * Whether {@code value} holds a non-empty run of RFC 9110 {@code tchar} from {@code start} to {@code end}, so it
	 * holds no {@code /}, {@code ;}, whitespace or non-ASCII character.
	 */
	private static boolean isToken(@NonNull String value,
																 int start,
																 int end) {
		if (start >= end)
			return false;

		for (int index = start; index < end; ++index) {
			char character = value.charAt(index);
			boolean alphanumeric = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z')
					|| (character >= '0' && character <= '9');
			if (!alphanumeric && "!#$%&'*+-.^_`|~".indexOf(character) < 0)
				return false;
		}

		return true;
	}

	/**
	 * Parses a decoded JOSE header and applies the checks in the class documentation, in order.
	 *
	 * @param header the decoded header segment, untrusted; not modified
	 * @return the header's algorithm, {@code kid} and {@code typ}
	 * @throws NullPointerException if {@code header} is {@code null}
	 * @throws JoseFailure          with the reason of the first check that failed
	 */
	@NonNull
	public JoseHeader check(byte @NonNull [] header) throws JoseFailure {
		requireNonNull(header);

		try {
			return checkMembers(header);
		} catch (RuntimeException e) {
			throw new JoseFailure(JoseException.Reason.HEADER);
		}
	}

	@NonNull
	private JoseHeader checkMembers(byte @NonNull [] header) throws JoseFailure {
		JsonValue parsed;

		try {
			parsed = JsonCodec.parse(header, this.jsonLimits);
		} catch (JsonParseException e) {
			throw new JoseFailure(JoseException.Reason.HEADER);
		}

		if (!(parsed instanceof JsonObject object))
			throw new JoseFailure(JoseException.Reason.HEADER);

		Map<@NonNull String, @NonNull JsonValue> members = object.getMembers();

		// P4.
		if (!(members.get("alg") instanceof JsonString alg))
			throw new JoseFailure(JoseException.Reason.HEADER);
		JwsAlgorithm algorithm = JwsAlgorithm.findByWireValue(alg.getValue()).filter(this.allowedAlgorithms::contains)
				.orElseThrow(() -> new JoseFailure(JoseException.Reason.ALGORITHM_NOT_ALLOWED));

		// P5.
		if (members.containsKey("crit"))
			throw new JoseFailure(JoseException.Reason.CRITICAL_HEADER);
		if (members.containsKey("b64"))
			throw new JoseFailure(JoseException.Reason.UNENCODED_PAYLOAD);
		if (members.containsKey("zip"))
			throw new JoseFailure(JoseException.Reason.COMPRESSED_PAYLOAD);

		// P6.
		for (String name : KEY_REFERENCE_MEMBERS)
			if (members.containsKey(name))
				throw new JoseFailure(JoseException.Reason.UNTRUSTED_KEY_REFERENCE);

		// P7.
		JsonValue typ = members.get("typ");
		String type = null;
		if (typ == null) {
			if (this.typeRequired)
				throw new JoseFailure(JoseException.Reason.INVALID_TYPE);
		} else if (typ instanceof JsonString typString && allowsType(typString.getValue())) {
			type = typString.getValue();
		} else {
			throw new JoseFailure(JoseException.Reason.INVALID_TYPE);
		}

		// P8.
		if (members.containsKey("cty"))
			throw new JoseFailure(JoseException.Reason.NESTED_TOKEN);

		// kid.
		JsonValue kid = members.get("kid");
		String keyId = null;
		if (kid != null) {
			if (!(kid instanceof JsonString kidString) || kidString.getValue().isEmpty()
					|| kidString.getValue().length() > JwkParser.MAXIMUM_KEY_ID_LENGTH)
				throw new JoseFailure(JoseException.Reason.HEADER);
			keyId = kidString.getValue();
		}

		return new JoseHeader(algorithm, keyId, type);
	}

	/**
	 * Returns whether a header {@code typ} passes P7: an absent one when no type is required, or one that normalizes
	 * into the allowed set.
	 *
	 * @param type the header's {@code typ}, or {@code null} if absent
	 * @return {@code true} if the type is allowed
	 */
	public boolean allowsType(@Nullable String type) {
		if (type == null)
			return !this.typeRequired;
		return normalizeType(type).map(this.allowedTypes::contains).orElse(false);
	}

	/**
	 * Returns the longest token accepted, in characters.
	 *
	 * @return the maximum token length
	 */
	public int getMaximumTokenLength() {
		return this.maximumTokenLength;
	}

	/**
	 * Returns the JSON profile the header and the claims are parsed under, bounded by the maximum token length.
	 *
	 * @return the JOSE profile
	 */
	@NonNull
	public JsonLimits getJsonLimits() {
		return this.jsonLimits;
	}

	/**
	 * Returns the effective algorithm set.
	 *
	 * @return an unmodifiable set
	 */
	@NonNull
	public Set<@NonNull JwsAlgorithm> getAllowedAlgorithms() {
		return this.allowedAlgorithms;
	}

	/**
	 * Returns the allowed {@code typ} media types, normalized.
	 *
	 * @return an unmodifiable set
	 */
	@NonNull
	public Set<@NonNull String> getAllowedTypes() {
		return this.allowedTypes;
	}

	/**
	 * Returns whether a token without {@code typ} is rejected.
	 *
	 * @return {@code true} if a type is required
	 */
	public boolean isTypeRequired() {
		return this.typeRequired;
	}

	/**
	 * Describes the policy.
	 *
	 * @return the settings
	 */
	@Override
	@NonNull
	public String toString() {
		Set<JwsAlgorithm> sorted = EnumSet.noneOf(JwsAlgorithm.class);
		sorted.addAll(this.allowedAlgorithms);
		return getClass().getSimpleName() + "{maximumTokenLength=" + this.maximumTokenLength + ", allowedAlgorithms="
				+ sorted + ", allowedTypes=" + new TreeSet<>(this.allowedTypes) + ", typeRequired=" + this.typeRequired
				+ "}";
	}
}
