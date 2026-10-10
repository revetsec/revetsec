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

import com.revetsec.internal.Limit;
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * The resource bounds of one {@link JsonCodec#parse(byte[], JsonLimits)} call: a profile (M1 plan, gates 5 and 7).
 * <p>
 * <strong>Profiles.</strong> The protocol, JOSE and SCIM structural values come from JSON rows of {@link Limits},
 * which R8 keeps internal in 1.0.0; SCIM's node count uses the caller's setting of the one public JSON row,
 * {@link Limits#SCIM_JSON_NODES} (G5-4 and G5-5). WebAuthn client data uses its separately selected tight profile.
 * <table>
 *   <caption>Profiles</caption>
 *   <tr><th>Profile</th><th>Input bytes</th><th>Depth</th><th>Nodes</th><th>String</th><th>Number</th>
 *   <th>Exponent</th><th>Names</th></tr>
 *   <tr><td>{@link #protocolDocument(Integer)}</td><td>caller, 1 B to 4 MiB</td><td>32</td><td>100,000</td>
 *   <td>1 Mi</td><td>1,024</td><td>10,000</td><td>exact</td></tr>
 *   <tr><td>{@link #jose(Integer)}</td><td>caller, 1 B to 1 MiB</td><td>32</td><td>100,000</td><td>1 Mi</td>
 *   <td>1,024</td><td>10,000</td><td>exact</td></tr>
 *   <tr><td>{@link #webauthnClientData(Integer)}</td><td>caller, 1 B to 16 KiB</td><td>16</td><td>256</td>
 *   <td>16 Ki</td><td>128</td><td>1,000</td><td>exact</td></tr>
 *   <tr><td>{@link #webauthnResponse(Integer)}</td><td>caller, 1 B to 256 KiB</td><td>16</td><td>512</td>
 *   <td>256 Ki</td><td>128</td><td>1,000</td><td>exact</td></tr>
 *   <tr><td>{@link #scim(Integer, Integer)}</td><td>caller, 1 B to 10 MiB</td><td>64</td>
 *   <td>caller, 1,000 to 1,000,000</td><td>1 Mi</td><td>1,024</td><td>10,000</td><td>ASCII case folded</td></tr>
 *   <tr><td>maximum caps (tests only)</td><td>unbounded</td><td>64</td><td>1,000,000</td><td>4 Mi</td><td>4,096</td>
 *   <td>100,000</td><td>exact</td></tr>
 * </table>
 * <ul>
 *   <li><strong>Input bytes</strong> is the body or JWT limit that owns the document (G5-5): the caller passes that
 *   row's validated setting. The profile accepts any setting from 1 byte up to the largest cap of the rows it serves
 *   (the HTTP response, JWKS and error-body rows for protocol documents, the compact-JWT row for JOSE, the SCIM body
 *   row for SCIM, or the WebAuthn client-data and raw-response caps) and rejects the rest. A smaller value only
 *   makes the parse stricter.</li>
 *   <li><strong>Depth</strong> uses the G7-6 convention: a scalar or an empty container is 1, and any other container
 *   is 1 more than its deepest child. Member names add nothing.</li>
 *   <li><strong>Nodes</strong> counts every value, the root and containers included; member names do not count.</li>
 *   <li><strong>String</strong> bounds each string and each member name after unescaping, in UTF-16 code
 *   units.</li>
 *   <li><strong>Number</strong> bounds a number's text and its canonical form ({@code BigDecimal.toString()}), in
 *   characters, so a parsed number always serializes within the same profile.</li>
 *   <li><strong>Exponent</strong> bounds both the written exponent and the adjusted decimal exponent
 *   (precision &minus; scale &minus; 1) in magnitude.</li>
 *   <li><strong>Names</strong>: every profile rejects a repeated member name; the SCIM profile also rejects names that
 *   differ only in ASCII case, at every level, through {@link AsciiCase} (G7-7).</li>
 * </ul>
 * <strong>Model caps.</strong> No profile limit exceeds a cap of the public model (G7-6): depth
 * {@value #MODEL_MAXIMUM_DEPTH}, {@value #MODEL_MAXIMUM_NUMBER_DIGITS} digits per number, and an adjusted exponent of
 * magnitude {@value #MODEL_MAXIMUM_EXPONENT_MAGNITUDE}. A number's text is at least as long as its digit count, so
 * the number limit bounds digits too. The constructor enforces this, so a value the codec accepts always satisfies
 * the model's invariants and {@link IllegalArgumentException} never escapes a parse.
 * <p>
 * The package-private {@link #maximumCaps()} profile sets every JSON row at its cap and does not bound the input
 * size. Tests use it to check that a {@code toJson()} &rarr; parse round trip is stable: whatever any profile
 * accepted serializes to text that this profile parses back to an equal value. The input size is unbounded because
 * the canonical form of a number can be longer than its text ({@code 1e-6} becomes {@code 0.000001}). The default
 * profiles are tighter than the model, so a round trip through them is not total, and neither is a round trip of an
 * arbitrary model value through this one: the model caps a number's digits, not its canonical length, and has no
 * node or string cap (G7-6).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class JsonLimits {
	/**
	 * The public model's depth cap (G7-6): {@code com.revetsec.json} factories reject deeper values.
	 */
	public static final int MODEL_MAXIMUM_DEPTH = 64;

	/**
	 * The public model's cap on a number's precision, in decimal digits (G7-6).
	 */
	public static final int MODEL_MAXIMUM_NUMBER_DIGITS = 4_096;

	/**
	 * The public model's cap on the magnitude of a number's adjusted decimal exponent (G7-6).
	 */
	public static final int MODEL_MAXIMUM_EXPONENT_MAGNITUDE = 100_000;

	/**
	 * The largest input a protocol document can be: the largest cap of the HTTP response, JWKS and error-body rows.
	 */
	static final int PROTOCOL_DOCUMENT_INPUT_BYTES_CAP = cap(Math.max(Limits.HTTP_RESPONSE_BODY_SIZE.getCap(),
			Math.max(Limits.JWKS_RESPONSE_BODY_SIZE.getCap(), Limits.HTTP_ERROR_BODY_SIZE.getCap())));

	/**
	 * The largest input a JOSE document can be: the compact-JWT row's cap.
	 */
	static final int JOSE_INPUT_BYTES_CAP = cap(Limits.COMPACT_JWT_SIZE.getCap());

	/**
	 * The largest input a SCIM document can be: the SCIM body row's cap.
	 */
	static final int SCIM_INPUT_BYTES_CAP = cap(Limits.SCIM_BODY_SIZE.getCap());

	/** The WebAuthn client-data ceiling selected for the initial relying-party profile. */
	static final int WEBAUTHN_CLIENT_DATA_INPUT_BYTES_CAP = 16 * 1_024;
	/** The WebAuthn raw response-body ceiling selected for the initial relying-party profile. */
	static final int WEBAUTHN_RESPONSE_INPUT_BYTES_CAP = 256 * 1_024;

	private final int maxInputBytes;
	private final int maxDepth;
	private final int maxNodes;
	private final int maxStringLength;
	private final int maxNumberLength;
	private final int maxExponentMagnitude;
	private final boolean asciiCaseVariantNamesRejected;

	/**
	 * The profile for protocol documents: discovery metadata, JWKS, token, UserInfo, introspection and error responses.
	 *
	 * @param maxInputBytes the owning body limit's setting, from 1 byte to 4 MiB
	 * @return the profile
	 * @throws NullPointerException     if {@code maxInputBytes} is {@code null}
	 * @throws IllegalArgumentException if {@code maxInputBytes} is out of range
	 */
	public static @NonNull JsonLimits protocolDocument(@NonNull Integer maxInputBytes) {
		return new JsonLimits(requireInputBytes(maxInputBytes, PROTOCOL_DOCUMENT_INPUT_BYTES_CAP),
				Limits.JSON_DEPTH_PROTOCOL.getDefaultIntValue(), Limits.JSON_NODES.getDefaultIntValue(),
				Limits.JSON_STRING_LENGTH.getDefaultIntValue(), Limits.JSON_NUMBER_LENGTH.getDefaultIntValue(),
				Limits.JSON_NUMBER_EXPONENT_MAGNITUDE.getDefaultIntValue(), false);
	}

	/**
	 * The profile for JOSE headers, JWT claims sets and single JWKs.
	 *
	 * @param maxInputBytes the owning JWT limit's setting, from 1 byte to 1 MiB
	 * @return the profile
	 * @throws NullPointerException     if {@code maxInputBytes} is {@code null}
	 * @throws IllegalArgumentException if {@code maxInputBytes} is out of range
	 */
	public static @NonNull JsonLimits jose(@NonNull Integer maxInputBytes) {
		return new JsonLimits(requireInputBytes(maxInputBytes, JOSE_INPUT_BYTES_CAP),
				Limits.JSON_DEPTH_PROTOCOL.getDefaultIntValue(), Limits.JSON_NODES.getDefaultIntValue(),
				Limits.JSON_STRING_LENGTH.getDefaultIntValue(), Limits.JSON_NUMBER_LENGTH.getDefaultIntValue(),
				Limits.JSON_NUMBER_EXPONENT_MAGNITUDE.getDefaultIntValue(), false);
	}

	/**
	 * The bounded profile for WebAuthn {@code clientDataJSON}. Unknown members remain parseable within these bounds.
	 *
	 * @param maxInputBytes the configured client-data limit, from 1 byte to 16 KiB
	 * @return the profile
	 * @throws NullPointerException if {@code maxInputBytes} is {@code null}
	 * @throws IllegalArgumentException if {@code maxInputBytes} is out of range
	 * @since 1.0.0
	 */
	public static @NonNull JsonLimits webauthnClientData(@NonNull Integer maxInputBytes) {
		return new JsonLimits(requireInputBytes(maxInputBytes, WEBAUTHN_CLIENT_DATA_INPUT_BYTES_CAP),
				16, 256, WEBAUTHN_CLIENT_DATA_INPUT_BYTES_CAP, 128, 1_000, false);
	}

	/**
	 * The bounded profile for a WebAuthn browser {@code credential.toJSON()} response body.
	 *
	 * @param maxInputBytes the configured raw response-body limit, from 1 byte to 256 KiB
	 * @return the profile
	 * @throws NullPointerException if {@code maxInputBytes} is {@code null}
	 * @throws IllegalArgumentException if {@code maxInputBytes} is out of range
	 * @since 1.0.0
	 */
	public static @NonNull JsonLimits webauthnResponse(@NonNull Integer maxInputBytes) {
		return new JsonLimits(requireInputBytes(maxInputBytes, WEBAUTHN_RESPONSE_INPUT_BYTES_CAP),
				16, 512, WEBAUTHN_RESPONSE_INPUT_BYTES_CAP, 128, 1_000, false);
	}

	/**
	 * The profile for SCIM request bodies. It also rejects member names that differ only in ASCII case (G7-7).
	 *
	 * @param maxInputBytes the SCIM body limit's setting, from 1 byte to 10 MiB
	 * @param maxNodes      the SCIM JSON node limit's setting, checked against {@link Limits#SCIM_JSON_NODES}
	 * @return the profile
	 * @throws NullPointerException     if an argument is {@code null}
	 * @throws IllegalArgumentException if an argument is out of range
	 */
	public static @NonNull JsonLimits scim(@NonNull Integer maxInputBytes, @NonNull Integer maxNodes) {
		requireNonNull(maxNodes);
		return new JsonLimits(requireInputBytes(maxInputBytes, SCIM_INPUT_BYTES_CAP),
				Limits.JSON_DEPTH_SCIM.getDefaultIntValue(), Limits.SCIM_JSON_NODES.require(maxNodes.intValue()),
				Limits.JSON_STRING_LENGTH.getDefaultIntValue(), Limits.JSON_NUMBER_LENGTH.getDefaultIntValue(),
				Limits.JSON_NUMBER_EXPONENT_MAGNITUDE.getDefaultIntValue(), true);
	}

	/**
	 * Every JSON row at its cap, no input-size bound, and exact name comparison. For round-trip tests only; no
	 * production path uses it.
	 */
	static @NonNull JsonLimits maximumCaps() {
		return new JsonLimits(Integer.MAX_VALUE,
				Math.max(capOf(Limits.JSON_DEPTH_PROTOCOL), capOf(Limits.JSON_DEPTH_SCIM)),
				Math.max(capOf(Limits.JSON_NODES), capOf(Limits.SCIM_JSON_NODES)), capOf(Limits.JSON_STRING_LENGTH),
				capOf(Limits.JSON_NUMBER_LENGTH), capOf(Limits.JSON_NUMBER_EXPONENT_MAGNITUDE), false);
	}

	/**
	 * Only the factories above call this, and tests. Every argument of the factories comes from the registry or has
	 * been range-checked, so a failure here is a programming error, never input.
	 *
	 * @throws IllegalArgumentException if a limit is not positive, or exceeds a cap of the public model
	 */
	JsonLimits(int maxInputBytes,
						 int maxDepth,
						 int maxNodes,
						 int maxStringLength,
						 int maxNumberLength,
						 int maxExponentMagnitude,
						 boolean asciiCaseVariantNamesRejected) {
		if (maxInputBytes < 1 || maxNodes < 1 || maxStringLength < 1 || maxNumberLength < 1 || maxDepth < 1
				|| maxExponentMagnitude < 1)
			throw new IllegalArgumentException("Every JSON limit must be positive.");
		if (maxDepth > MODEL_MAXIMUM_DEPTH || maxNumberLength > MODEL_MAXIMUM_NUMBER_DIGITS
				|| maxExponentMagnitude > MODEL_MAXIMUM_EXPONENT_MAGNITUDE)
			throw new IllegalArgumentException("A JSON profile limit exceeds a cap of the public model.");

		this.maxInputBytes = maxInputBytes;
		this.maxDepth = maxDepth;
		this.maxNodes = maxNodes;
		this.maxStringLength = maxStringLength;
		this.maxNumberLength = maxNumberLength;
		this.maxExponentMagnitude = maxExponentMagnitude;
		this.asciiCaseVariantNamesRejected = asciiCaseVariantNamesRejected;
	}

	/**
	 * The largest input accepted, in bytes.
	 *
	 * @return the input-size limit
	 */
	public int getMaxInputBytes() {
		return this.maxInputBytes;
	}

	/**
	 * The deepest value accepted, by the G7-6 convention.
	 *
	 * @return the depth limit
	 */
	public int getMaxDepth() {
		return this.maxDepth;
	}

	/**
	 * The most values accepted in one document, the root and containers included.
	 *
	 * @return the node limit
	 */
	public int getMaxNodes() {
		return this.maxNodes;
	}

	/**
	 * The longest string accepted after unescaping, in UTF-16 code units.
	 *
	 * @return the string-length limit
	 */
	public int getMaxStringLength() {
		return this.maxStringLength;
	}

	/**
	 * The longest number accepted, in characters of its text and of its canonical form.
	 *
	 * @return the number-length limit
	 */
	public int getMaxNumberLength() {
		return this.maxNumberLength;
	}

	/**
	 * The largest magnitude accepted for a number's written exponent and its adjusted decimal exponent.
	 *
	 * @return the exponent limit
	 */
	public int getMaxExponentMagnitude() {
		return this.maxExponentMagnitude;
	}

	/**
	 * Whether an object may not hold two member names that differ only in ASCII case (the SCIM profile, G7-7).
	 *
	 * @return {@code true} for the SCIM profile
	 */
	public boolean isAsciiCaseVariantNamesRejected() {
		return this.asciiCaseVariantNamesRejected;
	}

	@Override
	public @NonNull String toString() {
		return getClass().getSimpleName() + "{maxInputBytes=" + this.maxInputBytes + ", maxDepth=" + this.maxDepth
				+ ", maxNodes=" + this.maxNodes + ", maxStringLength=" + this.maxStringLength + ", maxNumberLength="
				+ this.maxNumberLength + ", maxExponentMagnitude=" + this.maxExponentMagnitude
				+ ", asciiCaseVariantNamesRejected=" + this.asciiCaseVariantNamesRejected + "}";
	}

	private static int requireInputBytes(@NonNull Integer maxInputBytes, int cap) {
		requireNonNull(maxInputBytes);
		int value = maxInputBytes.intValue();

		if (value < 1 || value > cap)
			throw new IllegalArgumentException("A JSON input-size limit must be from 1 to " + cap + " bytes; got "
					+ value + ".");

		return value;
	}

	private static int capOf(@NonNull Limit limit) {
		return cap(limit.getCap());
	}

	private static int cap(long value) {
		return Math.toIntExact(value);
	}
}
