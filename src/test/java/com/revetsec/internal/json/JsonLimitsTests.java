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

import com.revetsec.internal.Limits;
import com.revetsec.testing.Sentinels;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.List;
import java.util.function.IntFunction;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * The codec's profiles (M1 plan gates 5 and 7: "Limits registry", G5-4, G5-5 and G7-6). The values come from the JSON
 * rows of {@code internal.Limits}, each profile's input size is the caller's setting of the body or JWT row that owns
 * it, and no profile exceeds a cap of the public model.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JsonLimitsTests {
	private static final int KIB = 1_024;
	private static final int MIB = 1_024 * KIB;

	// Gate 5 table: protocol documents use the protocol depth (32) and the default node, string, number and exponent
	// rows; the input size is the caller's.
	@Test
	void protocolDocumentsUseTheProtocolRowDefaults() {
		JsonLimits limits = JsonLimits.protocolDocument(256 * KIB);

		assertProfile(limits, 256 * KIB, 32, 100_000, MIB, 1_024, 10_000, false);
		assertProfile(JsonLimits.jose(64 * KIB), 64 * KIB, 32, 100_000, MIB, 1_024, 10_000, false);
		Assertions.assertEquals(Limits.JSON_DEPTH_PROTOCOL.getDefaultIntValue(), limits.getMaxDepth());
		Assertions.assertEquals(Limits.JSON_NODES.getDefaultIntValue(), limits.getMaxNodes());
		Assertions.assertEquals(Limits.JSON_STRING_LENGTH.getDefaultIntValue(), limits.getMaxStringLength());
		Assertions.assertEquals(Limits.JSON_NUMBER_LENGTH.getDefaultIntValue(), limits.getMaxNumberLength());
		Assertions.assertEquals(Limits.JSON_NUMBER_EXPONENT_MAGNITUDE.getDefaultIntValue(),
				limits.getMaxExponentMagnitude());
	}

	// Gate 5 (G5-4) and G7-7: SCIM documents nest 64 deep, take the public SCIM node setting, and fold ASCII case
	// when comparing member names.
	@Test
	void scimDocumentsUseTheScimRowsAndFoldAsciiCase() {
		JsonLimits limits = JsonLimits.scim(MIB, 100_000);

		assertProfile(limits, MIB, 64, 100_000, MIB, 1_024, 10_000, true);
		assertProfile(JsonLimits.scim(10 * MIB, 1_000_000), 10 * MIB, 64, 1_000_000, MIB, 1_024, 10_000, true);
		assertProfile(JsonLimits.scim(16 * KIB, 1_000), 16 * KIB, 64, 1_000, MIB, 1_024, 10_000, true);
		Assertions.assertEquals(Limits.JSON_DEPTH_SCIM.getDefaultIntValue(), limits.getMaxDepth());
	}

	// G5-5: each profile's input size is the body or JWT limit that owns it, from 1 byte up to the largest cap of the
	// rows it serves: HTTP response, JWKS and error bodies for protocol documents (4 MiB), compact JWTs for JOSE
	// (1 MiB) and SCIM bodies for SCIM (10 MiB).
	@TestFactory
	Stream<DynamicTest> acceptsInputSizesUpToTheOwningRowsCap() {
		return Stream.of(
				new Object[]{"protocolDocument", (IntFunction<JsonLimits>) JsonLimits::protocolDocument,
						Math.max(Limits.HTTP_RESPONSE_BODY_SIZE.getCap(), Limits.JWKS_RESPONSE_BODY_SIZE.getCap())},
				new Object[]{"jose", (IntFunction<JsonLimits>) JsonLimits::jose, Limits.COMPACT_JWT_SIZE.getCap()},
				new Object[]{"scim", (IntFunction<JsonLimits>) size -> JsonLimits.scim(size, 100_000),
						Limits.SCIM_BODY_SIZE.getCap()})
				.map(row -> DynamicTest.dynamicTest((String) row[0], () -> {
					@SuppressWarnings("unchecked")
					IntFunction<JsonLimits> profile = (IntFunction<JsonLimits>) row[1];
					int cap = Math.toIntExact((Long) row[2]);

					Assertions.assertEquals(1, profile.apply(1).getMaxInputBytes());
					Assertions.assertEquals(cap, profile.apply(cap).getMaxInputBytes());
					assertRangeFailure(() -> profile.apply(0));
					assertRangeFailure(() -> profile.apply(-1));
					assertRangeFailure(() -> profile.apply(cap + 1));
					assertRangeFailure(() -> profile.apply(Integer.MAX_VALUE));
				}));
	}

	// G5-4: the SCIM node count is the public row [1,000, 1,000,000], checked by the row itself.
	@Test
	void scimNodeCountMustBeWithinThePublicRow() {
		Assertions.assertEquals(1_000, JsonLimits.scim(MIB, 1_000).getMaxNodes());
		Assertions.assertEquals(1_000_000, JsonLimits.scim(MIB, 1_000_000).getMaxNodes());
		assertRangeFailure(() -> JsonLimits.scim(MIB, 999));
		assertRangeFailure(() -> JsonLimits.scim(MIB, 1_000_001));
		assertRangeFailure(() -> JsonLimits.scim(MIB, 0));
	}

	// R15: null arguments throw NullPointerException before any range check.
	@Test
	void rejectsNullArguments() {
		Integer noInteger = JsonFailures.nullValue();
		byte[] noBytes = JsonFailures.nullValue();
		JsonLimits noLimits = JsonFailures.nullValue();

		Assertions.assertThrows(NullPointerException.class, () -> JsonLimits.protocolDocument(noInteger));
		Assertions.assertThrows(NullPointerException.class, () -> JsonLimits.jose(noInteger));
		Assertions.assertThrows(NullPointerException.class, () -> JsonLimits.scim(noInteger, 100_000));
		Assertions.assertThrows(NullPointerException.class, () -> JsonLimits.scim(MIB, noInteger));
		Assertions.assertThrows(NullPointerException.class, () -> JsonCodec.parse(noBytes, JsonLimits.jose(1)));
		Assertions.assertThrows(NullPointerException.class, () -> JsonCodec.parse(new byte[0], noLimits));
	}

	// G7-6: the maximum-cap test profile sets every JSON row at its cap (depth 64, 1,000,000 nodes, 4 Mi characters,
	// 4,096-character numbers, exponent 100,000), leaves the input size unbounded, and compares names exactly.
	@Test
	void theMaximumCapProfileSetsEveryJsonRowAtItsCap() {
		JsonLimits limits = JsonLimits.maximumCaps();

		assertProfile(limits, Integer.MAX_VALUE, 64, 1_000_000, 4 * MIB, 4_096, 100_000, false);
		Assertions.assertEquals(Limits.JSON_DEPTH_SCIM.getCap(), limits.getMaxDepth());
		Assertions.assertEquals(Limits.JSON_NODES.getCap(), limits.getMaxNodes());
		Assertions.assertEquals(Limits.SCIM_JSON_NODES.getCap(), limits.getMaxNodes());
		Assertions.assertEquals(Limits.JSON_STRING_LENGTH.getCap(), limits.getMaxStringLength());
		Assertions.assertEquals(Limits.JSON_NUMBER_LENGTH.getCap(), limits.getMaxNumberLength());
		Assertions.assertEquals(Limits.JSON_NUMBER_EXPONENT_MAGNITUDE.getCap(), limits.getMaxExponentMagnitude());
	}

	// G7-6 and M1 plan "JSON model and codec": no profile limit exceeds a model cap (depth 64, 4,096 digits, adjusted
	// exponent 100,000), so a value the codec accepts always satisfies the model's invariants.
	@Test
	void noProfileExceedsAModelCap() {
		Assertions.assertEquals(64, JsonLimits.MODEL_MAXIMUM_DEPTH);
		Assertions.assertEquals(4_096, JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS);
		Assertions.assertEquals(100_000, JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE);

		for (JsonLimits limits : List.of(JsonLimits.protocolDocument(4 * MIB), JsonLimits.jose(MIB),
				JsonLimits.scim(10 * MIB, 1_000_000), JsonLimits.maximumCaps())) {
			Assertions.assertTrue(limits.getMaxDepth() <= JsonLimits.MODEL_MAXIMUM_DEPTH, limits::toString);
			Assertions.assertTrue(limits.getMaxNumberLength() <= JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS,
					limits::toString);
			Assertions.assertTrue(limits.getMaxExponentMagnitude() <= JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE,
					limits::toString);
		}
	}

	// Soklet: jsonLimitsRejectUnsafeOrNonPositiveConfigurations. Every limit must be positive.
	@TestFactory
	Stream<DynamicTest> rejectsNonPositiveLimits() {
		return Stream.of(
				(Runnable) () -> new JsonLimits(0, 1, 1, 1, 1, 1, false),
				() -> new JsonLimits(1, 0, 1, 1, 1, 1, false),
				() -> new JsonLimits(1, 1, 0, 1, 1, 1, false),
				() -> new JsonLimits(1, 1, 1, 0, 1, 1, false),
				() -> new JsonLimits(1, 1, 1, 1, 0, 1, false),
				() -> new JsonLimits(1, 1, 1, 1, 1, 0, false),
				() -> new JsonLimits(1, 1, 1, 1, 1, -1, false))
				.map(construction -> DynamicTest.dynamicTest("non-positive limit", () -> {
					IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
							construction::run);
					Assertions.assertEquals("Every JSON limit must be positive.", exception.getMessage());
				}));
	}

	// Soklet: productionJsonLimitsAndHardCeilingsAreFrozen. Revetsec's hard ceilings are the model caps: the maximum
	// value of each capped field is accepted, and one more is rejected.
	@Test
	void acceptsEachModelCapAndRejectsOneMore() {
		Assertions.assertDoesNotThrow(() -> new JsonLimits(Integer.MAX_VALUE, 64, Integer.MAX_VALUE, Integer.MAX_VALUE,
				4_096, 100_000, true));

		for (Runnable oneOver : List.<Runnable>of(
				() -> new JsonLimits(1, 65, 1, 1, 1, 1, false),
				() -> new JsonLimits(1, 1, 1, 1, 4_097, 1, false),
				() -> new JsonLimits(1, 1, 1, 1, 1, 100_001, false))) {
			IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, oneOver::run);
			Assertions.assertEquals("A JSON profile limit exceeds a cap of the public model.", exception.getMessage());
		}
	}

	// R9: a profile's description shows its numbers, and a range failure names the range, never a secret.
	@Test
	void describesItselfWithoutSecrets() {
		String description = JsonLimits.scim(MIB, 100_000).toString();

		Assertions.assertEquals("JsonLimits{maxInputBytes=1048576, maxDepth=64, maxNodes=100000, maxStringLength="
				+ "1048576, maxNumberLength=1024, maxExponentMagnitude=10000, asciiCaseVariantNamesRejected=true}",
				description);
		Assertions.assertFalse(Sentinels.containsSentinel(description));
	}

	private static void assertProfile(JsonLimits limits, int inputBytes, int depth, int nodes, int stringLength,
																		int numberLength, int exponent, boolean asciiCaseVariantNamesRejected) {
		Assertions.assertEquals(inputBytes, limits.getMaxInputBytes());
		Assertions.assertEquals(depth, limits.getMaxDepth());
		Assertions.assertEquals(nodes, limits.getMaxNodes());
		Assertions.assertEquals(stringLength, limits.getMaxStringLength());
		Assertions.assertEquals(numberLength, limits.getMaxNumberLength());
		Assertions.assertEquals(exponent, limits.getMaxExponentMagnitude());
		Assertions.assertEquals(asciiCaseVariantNamesRejected, limits.isAsciiCaseVariantNamesRejected());
	}

	private static void assertRangeFailure(Supplier<JsonLimits> construction) {
		Assertions.assertThrows(IllegalArgumentException.class, construction::get);
	}
}
