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

import org.jspecify.annotations.Nullable;

import org.jspecify.annotations.NonNull;

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.internal.Limits;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.jose.JoseException.Reason;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Coverage-guided checks for the JWS layer's key-free steps (M2 plan, "JOSE semantics" steps 1 to 5, P1 to P8, M2-6;
 * exit criteria 4 to 6 and 10; INV-J7): {@link CompactJwsParser}, {@link JoseHeaderPolicy} and
 * {@link JwtProcessor#prepare(String, JoseHeaderPolicy)}.
 * <p>
 * The oracles are written here from RFC 7515 (sections 3.1, 4.1, 5.2 and 7.1), RFC 4648 section 5, RFC 7519
 * section 7.2, RFC 8725 and the plan's step order: a splitter over the compact serialization, a canonical base64url
 * decoder, a P3 to P8 header oracle over the header's JSON members with its own table of {@code alg} wire values and
 * its own {@code typ} media-type normalization (RFC 7515 section 4.1.9, RFC 9110 section 5.6.2), and the key-free
 * signature shape of RFC 7518 sections 3.3 to 3.5 and RFC 8037 section 3.1 over the curve orders the JDK names. The
 * header's JSON text is parsed with {@link JsonCodec} under the JOSE profile, which has its own fuzz target; the
 * decisions after that parse come from the oracle.
 * <p>
 * Each check runs under several header policies: the validator's defaults ({@code RS256}, {@code JWT}, 64 KiB), one
 * that allows every algorithm (the internal HMAC engine's view), four media types, requires {@code typ} and caps
 * tokens at 512 characters, and one that allows no {@code typ} at all.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class CompactJwsFuzzTests {
	private static final String BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	private static final Pattern MEDIA_TYPE = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+/[!#$%&'*+.^_`|~0-9A-Za-z-]+");
	private static final int MAXIMUM_KEY_ID_LENGTH = 256;

	/**
	 * RFC 7518 section 3.1, RFC 8037 section 3.1 and RFC 9864: every {@code alg} Revetsec knows, spelled exactly.
	 */
	private static final Map<String, JwsAlgorithm> WIRE_VALUES = Map.ofEntries(Map.entry("RS256", JwsAlgorithm.RS256),
			Map.entry("RS384", JwsAlgorithm.RS384), Map.entry("RS512", JwsAlgorithm.RS512),
			Map.entry("PS256", JwsAlgorithm.PS256), Map.entry("PS384", JwsAlgorithm.PS384),
			Map.entry("PS512", JwsAlgorithm.PS512), Map.entry("ES256", JwsAlgorithm.ES256),
			Map.entry("ES384", JwsAlgorithm.ES384), Map.entry("ES512", JwsAlgorithm.ES512),
			Map.entry("Ed25519", JwsAlgorithm.ED25519), Map.entry("EdDSA", JwsAlgorithm.EDDSA),
			Map.entry("HS256", JwsAlgorithm.HS256), Map.entry("HS384", JwsAlgorithm.HS384),
			Map.entry("HS512", JwsAlgorithm.HS512));

	private static final Map<JwsAlgorithm, BigInteger> CURVE_ORDERS = Map.of(JwsAlgorithm.ES256, order("secp256r1"),
			JwsAlgorithm.ES384, order("secp384r1"), JwsAlgorithm.ES512, order("secp521r1"));

	private static final List<Integer> MAXIMUM_LENGTHS = List.of(Limits.COMPACT_JWT_SIZE.getDefaultIntValue(), 64);

	private static final List<PolicyCase> POLICIES = List.of(
			new PolicyCase(Limits.COMPACT_JWT_SIZE.getDefaultIntValue(), EnumSet.of(JwsAlgorithm.RS256), Set.of("JWT"),
					false),
			new PolicyCase(512, EnumSet.allOf(JwsAlgorithm.class), Set.of("JWT", "at+jwt", "application/secevent+jwt",
					"DPoP+JWT"), true),
			new PolicyCase(Limits.COMPACT_JWT_SIZE.getDefaultIntValue(), EnumSet.of(JwsAlgorithm.ES256, JwsAlgorithm.ES384,
					JwsAlgorithm.ES512, JwsAlgorithm.ED25519, JwsAlgorithm.EDDSA, JwsAlgorithm.PS256), Set.of(), false));

	/**
	 * {@link CompactJwsParser#parse} splits exactly what RFC 7515 section 7.1 allows and fails with the reason of the
	 * first failed step: {@code TOKEN_TOO_LARGE} on length alone; {@code JSON_SERIALIZATION} for a leading left
	 * brace; {@code TOKEN_SYNTAX} for a character outside the base64url alphabet and the dot, for any dot count but 2
	 * and 4, for an empty header, or for a segment that is not canonical unpadded base64url (INV-J7); and
	 * {@code ENCRYPTED_TOKEN} for four dots. An empty payload or signature is allowed (M2-6). An accepted token's
	 * segments are the oracle's decoding and its signing input is the received ASCII text before the second dot.
	 * {@link JwtProcessor#prepare} then adds the header policy and the key-free signature shape in that order, and
	 * its result carries exactly the header's algorithm, {@code kid} and {@code typ}. Every failure is a
	 * {@link JoseFailure} that names only its reason, with no cause and no stack trace.
	 *
	 * @param input the fuzzed token, read as ISO-8859-1 so that every byte is one character
	 */
	@FuzzTest(maxDuration = "5m")
	public void compactSerializationsSplitIntoThreeCanonicalSegmentsOrFailInStepOrder(byte @NonNull [] input) {
		String token = new String(input, StandardCharsets.ISO_8859_1);

		for (int maximumLength : MAXIMUM_LENGTHS) {
			Split expected = expectedSplit(token, maximumLength);

			try {
				CompactJws jws = CompactJwsParser.parse(token, maximumLength);
				Assertions.assertNull(expected.failure, () -> "split a token the oracle rejects with " + expected.failure);
				Assertions.assertEquals(token, jws.getCompactSerialization(), "the token was not kept as received");
				Assertions.assertArrayEquals(expected.header, jws.getHeader(), "the header segment decodes differently");
				Assertions.assertArrayEquals(expected.payload, jws.getPayload(), "the payload segment decodes differently");
				Assertions.assertArrayEquals(expected.signature, jws.getSignature(),
						"the signature segment decodes differently");
				Assertions.assertArrayEquals(expected.signingInput, jws.getSigningInput(),
						"the signing input is not the received header.payload");
				Assertions.assertEquals("CompactJws{headerLength=" + expected.header.length + ", payloadLength="
						+ expected.payload.length + ", signatureLength=" + expected.signature.length + "}", jws.toString(),
						"toString shows more than the segment lengths");
			} catch (JoseFailure failure) {
				requireFixedShape(failure);
				Assertions.assertEquals(expected.failure, failure.getReason(), "the split failed with the wrong reason");
			}
		}

		for (PolicyCase policy : POLICIES) {
			Prepared expected = expectedPrepared(token, policy);

			try {
				PreparedJws prepared = JwtProcessor.prepare(token, policy.policy);
				Assertions.assertNull(expected.failure, () -> "prepared a token the oracle rejects with " + expected.failure);
				Assertions.assertEquals(expected.header.algorithm, prepared.getAlgorithm(), "the algorithm differs");
				Assertions.assertEquals(Optional.ofNullable(expected.header.keyId), prepared.findKeyId(), "the kid differs");
				Assertions.assertEquals(Optional.ofNullable(expected.header.type), prepared.findType(), "the typ differs");
				Assertions.assertEquals(new KeyQuery(expected.header.algorithm, expected.header.keyId, policy.algorithms),
						prepared.getKeyQuery(), "the key query differs");
				Assertions.assertArrayEquals(expected.split.signingInput, prepared.signingInput(), "the signing input differs");
				Assertions.assertArrayEquals(expected.split.payload, prepared.payload(), "the payload differs");
				Assertions.assertArrayEquals(expected.split.signature, prepared.signature(), "the signature differs");
				Assertions.assertEquals(token, prepared.compactSerialization(), "the token was not kept as received");
				Assertions.assertEquals(policy.maximumLength, prepared.jsonLimits().getMaxInputBytes(),
						"the claims are not bounded by the maximum token length");
				Assertions.assertEquals("PreparedJws{algorithm=" + expected.header.algorithm.getWireValue() + "}",
						prepared.toString(), "toString shows more than the algorithm");
			} catch (JoseFailure failure) {
				requireFixedShape(failure);
				Assertions.assertEquals(expected.failure, failure.getReason(), "prepare failed with the wrong reason");
			}
		}
	}

	/**
	 * {@link JoseHeaderPolicy#check(byte[])} agrees with the P3 to P8 oracle under every policy: {@code HEADER} for a
	 * header that is not a strict JSON object under the JOSE profile, or whose {@code alg} is not a string, or whose
	 * {@code kid} is not a string of 1 to 256 characters; {@code ALGORITHM_NOT_ALLOWED} for an {@code alg} outside the
	 * policy's set by exact match, so {@code none} in every spelling (RFC 8725 section 3.2); then {@code crit},
	 * {@code b64}, {@code zip}, a key or key location ({@code jwk}, {@code jku}, {@code x5u}; RFC 8725 section 3.10),
	 * a {@code typ} outside the allowed media types (or absent when required), and {@code cty}, in that order. An
	 * accepted header yields its algorithm, {@code kid} and raw {@code typ}. For every string in the header,
	 * {@link JoseHeaderPolicy#normalizeType}, {@link JoseHeaderPolicy#allowsType} and
	 * {@link JwsAlgorithm#findByWireValue} agree with the oracle, and the input array is never modified.
	 *
	 * @param header the fuzzed decoded header: JSON text
	 */
	@FuzzTest(maxDuration = "5m")
	public void headerChecksAgreeWithAnIndependentOracleForP3ToP8(byte @NonNull [] header) {
		byte[] original = header.clone();

		for (PolicyCase policy : POLICIES) {
			HeaderOutcome expected = expectedHeader(header, policy);

			try {
				JoseHeader actual = policy.policy.check(header);
				Assertions.assertNull(expected.failure, () -> "accepted a header the oracle rejects with " + expected.failure);
				Assertions.assertEquals(new JoseHeader(expected.algorithm, expected.keyId, expected.type), actual,
						"the accepted header differs");
			} catch (JoseFailure failure) {
				requireFixedShape(failure);
				Assertions.assertEquals(expected.failure, failure.getReason(), "the header failed with the wrong reason");
			}
		}

		Assertions.assertArrayEquals(original, header, "the header was modified");

		JsonValue parsed;

		try {
			parsed = JsonCodec.parse(header, JsonLimits.jose(Limits.COMPACT_JWT_SIZE.getDefaultIntValue()));
		} catch (JsonParseException e) {
			return;
		}

		List<String> strings = new ArrayList<>();
		collectStrings(parsed, strings);

		for (String string : strings) {
			Assertions.assertEquals(expectedType(string), JoseHeaderPolicy.normalizeType(string),
					"typ normalization disagrees with the oracle");
			Assertions.assertEquals(Optional.ofNullable(WIRE_VALUES.get(string)), JwsAlgorithm.findByWireValue(string),
					"the alg lookup disagrees with the wire-value table");

			for (PolicyCase policy : POLICIES)
				Assertions.assertEquals(expectedType(string).map(policy.types::contains).orElse(false),
						policy.policy.allowsType(string), "allowsType disagrees with the oracle");
		}

		for (PolicyCase policy : POLICIES)
			Assertions.assertEquals(!policy.typeRequired, policy.policy.allowsType(null), "allowsType(null) is wrong");
	}

	/**
	 * Steps 1 to 3: size, serialization and canonical base64url.
	 */
	private static @NonNull Split expectedSplit(@NonNull String token, int maximumLength) {
		if (token.length() > maximumLength)
			return Split.failing(Reason.TOKEN_TOO_LARGE);

		if (!token.isEmpty() && token.charAt(0) == '{')
			return Split.failing(Reason.JSON_SERIALIZATION);

		for (int index = 0; index < token.length(); ++index)
			if (token.charAt(index) != '.' && BASE64URL_ALPHABET.indexOf(token.charAt(index)) < 0)
				return Split.failing(Reason.TOKEN_SYNTAX);

		String[] segments = token.split("\\.", -1);

		if (segments.length == 5)
			return Split.failing(Reason.ENCRYPTED_TOKEN);

		if (segments.length != 3 || segments[0].isEmpty())
			return Split.failing(Reason.TOKEN_SYNTAX);

		byte[] header = decodeBase64Url(segments[0]);
		byte[] payload = decodeBase64Url(segments[1]);
		byte[] signature = decodeBase64Url(segments[2]);

		if (header == null || payload == null || signature == null)
			return Split.failing(Reason.TOKEN_SYNTAX);

		return new Split(null, header, payload, signature,
				(segments[0] + "." + segments[1]).getBytes(StandardCharsets.US_ASCII));
	}

	/**
	 * Steps 1 to 5 under {@code policy}.
	 */
	private static @NonNull Prepared expectedPrepared(@NonNull String token, @NonNull PolicyCase policy) {
		Split split = expectedSplit(token, policy.maximumLength);

		if (split.failure != null)
			return Prepared.failing(split.failure);

		HeaderOutcome header = expectedHeader(split.header, policy);

		if (header.failure != null)
			return Prepared.failing(header.failure);

		if (!hasKeyFreeShape(header.algorithm, split.signature))
			return Prepared.failing(Reason.SIGNATURE_MALFORMED);

		return new Prepared(null, split, header);
	}

	/**
	 * Step 5: what a signature's shape decides without a key. RSA signatures are as long as a 2,048- to 16,384-bit
	 * modulus (256 to 2,048 octets); ECDSA's are twice the coordinate length with {@code r} and {@code s} in
	 * {@code [1, n - 1]}; Ed25519's are 64 octets; an HMAC tag is the hash length.
	 */
	private static boolean hasKeyFreeShape(@NonNull JwsAlgorithm algorithm, byte @NonNull [] signature) {
		return switch (algorithm) {
			case RS256, RS384, RS512, PS256, PS384, PS512 -> signature.length >= 256 && signature.length <= 2_048;
			case ES256 -> hasEcdsaShape(signature, 32, CURVE_ORDERS.get(JwsAlgorithm.ES256));
			case ES384 -> hasEcdsaShape(signature, 48, CURVE_ORDERS.get(JwsAlgorithm.ES384));
			case ES512 -> hasEcdsaShape(signature, 66, CURVE_ORDERS.get(JwsAlgorithm.ES512));
			case ED25519, EDDSA -> signature.length == 64;
			case HS256 -> signature.length == 32;
			case HS384 -> signature.length == 48;
			case HS512 -> signature.length == 64;
		};
	}

	private static boolean hasEcdsaShape(byte @NonNull [] signature, int coordinateLength, @NonNull BigInteger order) {
		if (signature.length != 2 * coordinateLength)
			return false;

		BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, coordinateLength));
		BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, coordinateLength, signature.length));
		return r.signum() > 0 && r.compareTo(order) < 0 && s.signum() > 0 && s.compareTo(order) < 0;
	}

	/**
	 * Step 4, P3 to P8, in the plan's order.
	 */
	private static @NonNull HeaderOutcome expectedHeader(byte @NonNull [] header, @NonNull PolicyCase policy) {
		JsonValue parsed;

		try {
			parsed = JsonCodec.parse(header, JsonLimits.jose(policy.maximumLength));
		} catch (JsonParseException e) {
			return HeaderOutcome.failing(Reason.HEADER);
		}

		if (!(parsed instanceof JsonObject object))
			return HeaderOutcome.failing(Reason.HEADER);

		Map<String, JsonValue> members = object.getMembers();

		if (!(members.get("alg") instanceof JsonString alg))
			return HeaderOutcome.failing(Reason.HEADER);

		JwsAlgorithm algorithm = WIRE_VALUES.get(alg.getValue());

		if (algorithm == null || !policy.algorithms.contains(algorithm))
			return HeaderOutcome.failing(Reason.ALGORITHM_NOT_ALLOWED);

		if (members.containsKey("crit"))
			return HeaderOutcome.failing(Reason.CRITICAL_HEADER);

		if (members.containsKey("b64"))
			return HeaderOutcome.failing(Reason.UNENCODED_PAYLOAD);

		if (members.containsKey("zip"))
			return HeaderOutcome.failing(Reason.COMPRESSED_PAYLOAD);

		if (members.containsKey("jwk") || members.containsKey("jku") || members.containsKey("x5u"))
			return HeaderOutcome.failing(Reason.UNTRUSTED_KEY_REFERENCE);

		JsonValue typ = members.get("typ");
		String type = null;

		if (typ == null) {
			if (policy.typeRequired)
				return HeaderOutcome.failing(Reason.INVALID_TYPE);
		} else if (typ instanceof JsonString typString
				&& expectedType(typString.getValue()).map(policy.types::contains).orElse(false)) {
			type = typString.getValue();
		} else {
			return HeaderOutcome.failing(Reason.INVALID_TYPE);
		}

		if (members.containsKey("cty"))
			return HeaderOutcome.failing(Reason.NESTED_TOKEN);

		JsonValue kid = members.get("kid");
		String keyId = null;

		if (kid != null) {
			if (!(kid instanceof JsonString kidString) || kidString.getValue().isEmpty()
					|| kidString.getValue().length() > MAXIMUM_KEY_ID_LENGTH)
				return HeaderOutcome.failing(Reason.HEADER);

			keyId = kidString.getValue();
		}

		return new HeaderOutcome(null, algorithm, keyId, type);
	}

	/**
	 * RFC 7515 section 4.1.9 (read 2026-09-28): {@code application/} is implied without a {@code /}; the result must be
	 * a {@code type/subtype} pair of RFC 9110 tokens, compared with ASCII letters folded.
	 */
	private static @NonNull Optional<@NonNull String> expectedType(@NonNull String type) {
		String mediaType = type.contains("/") ? type : "application/" + type;

		if (!MEDIA_TYPE.matcher(mediaType).matches())
			return Optional.empty();

		StringBuilder folded = new StringBuilder(mediaType.length());

		for (int index = 0; index < mediaType.length(); ++index) {
			char c = mediaType.charAt(index);
			folded.append(c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c);
		}

		return Optional.of(folded.toString());
	}

	/**
	 * RFC 4648 section 5 without padding, canonical: no length of the form 4n + 1, and zero bits after the last whole
	 * octet. Returns {@code null} for anything else.
	 */
	private static byte @Nullable [] decodeBase64Url(@NonNull String segment) {
		if (segment.length() % 4 == 1)
			return null;

		ByteArrayOutputStream octets = new ByteArrayOutputStream();
		int buffer = 0;
		int bits = 0;

		for (int index = 0; index < segment.length(); ++index) {
			int value = BASE64URL_ALPHABET.indexOf(segment.charAt(index));

			if (value < 0)
				return null;

			buffer = (buffer << 6) | value;
			bits += 6;

			if (bits >= 8) {
				bits -= 8;
				octets.write((buffer >> bits) & 0xFF);
				buffer &= (1 << bits) - 1;
			}
		}

		return buffer == 0 ? octets.toByteArray() : null;
	}

	private static void requireFixedShape(@NonNull JoseFailure failure) {
		Assertions.assertEquals("A JOSE check failed: " + failure.getReason().name() + ".", failure.getMessage(),
				"a JoseFailure message is not its fixed text");
		Assertions.assertNull(failure.getCause(), "a JoseFailure has a cause");
		Assertions.assertEquals(0, failure.getSuppressed().length, "a JoseFailure has suppressed exceptions");
		Assertions.assertEquals(0, failure.getStackTrace().length, "a JoseFailure records a stack trace");
	}

	private static void collectStrings(@NonNull JsonValue value, @NonNull List<@NonNull String> strings) {
		if (value instanceof JsonString string) {
			strings.add(string.getValue());
		} else if (value instanceof JsonObject object) {
			for (Map.Entry<String, JsonValue> member : object.getMembers().entrySet()) {
				strings.add(member.getKey());
				collectStrings(member.getValue(), strings);
			}
		} else if (value instanceof JsonArray array) {
			for (JsonValue element : array.getElements())
				collectStrings(element, strings);
		}
	}

	private static @NonNull BigInteger order(@NonNull String curveName) {
		try {
			AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
			parameters.init(new ECGenParameterSpec(curveName));
			return parameters.getParameterSpec(ECParameterSpec.class).getOrder();
		} catch (GeneralSecurityException e) {
			throw new IllegalStateException("The JDK does not name " + curveName, e);
		}
	}

	/**
	 * One header policy, with the oracle's own copy of its settings.
	 */
	@Immutable
	private static final class PolicyCase {
		private final int maximumLength;
		private final Set<JwsAlgorithm> algorithms;
		private final Set<String> types;
		private final boolean typeRequired;
		private final JoseHeaderPolicy policy;

		private PolicyCase(int maximumLength, @NonNull Set<@NonNull JwsAlgorithm> algorithms, @NonNull Set<@NonNull String> allowedTypes,
											 boolean typeRequired) {
			this.maximumLength = maximumLength;
			this.algorithms = Set.copyOf(algorithms);
			Set<String> types = new LinkedHashSet<>();

			for (String type : allowedTypes)
				types.add(expectedType(type).orElseThrow());

			this.types = Set.copyOf(types);
			this.typeRequired = typeRequired;
			this.policy = JoseHeaderPolicy.fromSettings(maximumLength, algorithms, allowedTypes, typeRequired);
		}
	}

	/**
	 * The split oracle's verdict: a reason, or the decoded segments and the signing input.
	 */
	@Immutable
	private static final class Split {
		private final Reason failure;
		private final byte[] header;
		private final byte[] payload;
		private final byte[] signature;
		private final byte[] signingInput;

		private Split(@Nullable Reason failure, byte @NonNull [] header, byte @NonNull [] payload, byte @NonNull [] signature, byte @NonNull [] signingInput) {
			this.failure = failure;
			this.header = header;
			this.payload = payload;
			this.signature = signature;
			this.signingInput = signingInput;
		}

		private static @NonNull Split failing(@NonNull Reason failure) {
			return new Split(failure, new byte[0], new byte[0], new byte[0], new byte[0]);
		}
	}

	/**
	 * The header oracle's verdict: a reason, or the algorithm, {@code kid} and raw {@code typ}.
	 */
	@Immutable
	private static final class HeaderOutcome {
		private final Reason failure;
		private final JwsAlgorithm algorithm;
		private final String keyId;
		private final String type;

		private HeaderOutcome(@Nullable Reason failure, @Nullable JwsAlgorithm algorithm, @Nullable String keyId, @Nullable String type) {
			this.failure = failure;
			this.algorithm = algorithm;
			this.keyId = keyId;
			this.type = type;
		}

		private static @NonNull HeaderOutcome failing(@NonNull Reason failure) {
			return new HeaderOutcome(failure, null, null, null);
		}
	}

	/**
	 * The verdict for steps 1 to 5.
	 */
	@Immutable
	private static final class Prepared {
		private final Reason failure;
		private final Split split;
		private final HeaderOutcome header;

		private Prepared(@Nullable Reason failure, @Nullable Split split, @Nullable HeaderOutcome header) {
			this.failure = failure;
			this.split = split;
			this.header = header;
		}

		private static @NonNull Prepared failing(@NonNull Reason failure) {
			return new Prepared(failure, null, null);
		}
	}
}
