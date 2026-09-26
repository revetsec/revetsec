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

package com.revetsec;

import com.revetsec.internal.Limit;
import com.revetsec.internal.Limit.Unit;
import com.revetsec.internal.Limits;
import com.revetsec.internal.http.HttpExchangeRequest;
import com.revetsec.internal.http.ResponseProfile;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.IntFunction;
import java.util.stream.Stream;

/**
 * Freezes the R8 limits registry as approved at gate 5 (M1 plan, "Limits registry", G5-1 to G5-6, and the
 * cross-field rule added under "Results"; exit criterion 16).
 * <p>
 * {@link #APPROVED_ROWS} is a literal transcription of the plan's table, row by row, in {@link Limits#all()} order
 * (which lists the two StateSealer rows before the JWKS rows, where the plan lists them last): the constant, the name
 * rejection messages print, the unit, the default, the floor, the cap and whether zero is permitted. Every
 * test here reads its numbers from that table, never from {@link Limit}'s own getters, so a change to any row, an
 * added or removed row, or a consumer that stops enforcing a row fails loudly. Changing a value is a change to an
 * approved gate item: update the plan first, then this table.
 * <p>
 * The tests also pin what the M1 consumers do with the rows: the JSON profiles stay within the public model's caps
 * (G7-6) and take the registry's defaults, {@link JsonLimits}, {@link StateSealer.Builder#maximumSealedLength(Integer)}
 * and {@link StateSealer#seal(String, String, Duration)} reject every out-of-range setting, the HTTP helper's defaults
 * come from the registry, and the four cross-field rules and the G5-3 runtime rule hold at their boundaries.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class FrozenLimitsTests {
	private static final long KIB = 1_024L;
	private static final long MIB = 1_024L * KIB;
	private static final boolean ZERO_ALLOWED = true;
	private static final boolean ZERO_REJECTED = false;

	/**
	 * The approved registry (M1 plan, "Limits registry"), in {@link Limits#all()} order. Changes from plan v3 made at
	 * gate 5 are marked with their gate item.
	 */
	private static final List<Row> APPROVED_ROWS = List.of(
			// HTTP body: token, metadata, UserInfo, introspection (G5-1: floor 4 -> 16 KiB).
			amounts("HTTP_RESPONSE_BODY_SIZE", "HTTP response body size", Unit.BYTES, 256 * KIB, 16 * KIB, 4 * MIB),
			// HTTP body: JWKS / key count (G5-1: floor 4 -> 16 KiB).
			amounts("JWKS_RESPONSE_BODY_SIZE", "JWKS response body size", Unit.BYTES, 256 * KIB, 16 * KIB, 4 * MIB),
			amounts("JWKS_KEY_COUNT", "JWKS key count", Unit.COUNT, 100, 1, 1_000),
			// HTTP error body (overflow or encoding keeps the status).
			amounts("HTTP_ERROR_BODY_SIZE", "HTTP error body size", Unit.BYTES, 16 * KIB, KIB, 64 * KIB),
			// Per-request timeout / total deadline (G5-5: per public call; timeout <= deadline).
			durations("REQUEST_TIMEOUT", "Request timeout", Duration.ofSeconds(10), Duration.ofSeconds(1),
					Duration.ofSeconds(60), ZERO_REJECTED),
			durations("TOTAL_DEADLINE", "Total deadline", Duration.ofSeconds(15), Duration.ofSeconds(1),
					Duration.ofSeconds(120), ZERO_REJECTED),
			// Compact JWT (G5-1: floor 1 -> 8 KiB).
			amounts("COMPACT_JWT_SIZE", "Compact JWT size", Unit.BYTES, 64 * KIB, 8 * KIB, MIB),
			// JSON depth, protocol / SCIM; internal (G5-2: cap 256 -> 64).
			amounts("JSON_DEPTH_PROTOCOL", "JSON depth for protocol documents", Unit.COUNT, 32, 8, 64),
			amounts("JSON_DEPTH_SCIM", "JSON depth for SCIM documents", Unit.COUNT, 64, 8, 64),
			// JSON nodes / string length / number length; internal (G5-1: string floor 1 -> 16 KiB).
			amounts("JSON_NODES", "JSON node count", Unit.COUNT, 100_000, 1_000, 1_000_000),
			amounts("JSON_STRING_LENGTH", "JSON string length", Unit.CHARACTERS, MIB, 16 * KIB, 4 * MIB),
			amounts("JSON_NUMBER_LENGTH", "JSON number length", Unit.CHARACTERS, 1_024, 32, 4_096),
			// JSON number magnitude, adjusted decimal exponent; internal (new row; G5-1: floor 32).
			amounts("JSON_NUMBER_EXPONENT_MAGNITUDE", "JSON number exponent magnitude", Unit.COUNT, 10_000, 32,
					100_000),
			// Authorization-response parameter / query (G5-1: floors 256 B / 1 KiB -> 2 / 4 KiB).
			amounts("AUTHORIZATION_RESPONSE_PARAMETER_SIZE", "Authorization-response parameter size", Unit.BYTES,
					8 * KIB, 2 * KIB, 32 * KIB),
			amounts("AUTHORIZATION_RESPONSE_QUERY_SIZE", "Authorization-response query size", Unit.BYTES, 32 * KIB,
					4 * KIB, 128 * KIB),
			// SAMLResponse decoded.
			amounts("SAML_RESPONSE_DECODED_SIZE", "Decoded SAMLResponse size", Unit.BYTES, 256 * KIB, 16 * KIB,
					4 * MIB),
			// XML depth / attributes / elements / name length (G5-1: attribute and element floors raised).
			amounts("XML_DEPTH", "XML depth", Unit.COUNT, 64, 16, 256),
			amounts("XML_ATTRIBUTES_PER_ELEMENT", "XML attributes per element", Unit.COUNT, 64, 16, 256),
			amounts("XML_ELEMENTS", "XML element count", Unit.COUNT, 10_000, 1_000, 100_000),
			amounts("XML_NAME_LENGTH", "XML name length", Unit.CHARACTERS, 1_000, 64, 10_000),
			// SAML metadata (G5-1: floor 16 -> 64 KiB; G5-2: cap 32 -> 8 MiB).
			amounts("SAML_METADATA_SIZE", "SAML metadata size", Unit.BYTES, MIB, 64 * KIB, 8 * MIB),
			// Redirect inflate / Redirect parameter (M8b, gate 15).
			amounts("SAML_REDIRECT_INFLATED_SIZE", "Inflated Redirect-binding payload size", Unit.BYTES, 64 * KIB,
					4 * KIB, 256 * KIB),
			amounts("SAML_REDIRECT_PARAMETER_SIZE", "Redirect-binding parameter size", Unit.BYTES, 16 * KIB, 2 * KIB,
					64 * KIB),
			// SCIM body / PATCH operations / JSON nodes, public (G5-4: new node row).
			amounts("SCIM_BODY_SIZE", "SCIM body size", Unit.BYTES, MIB, 16 * KIB, 10 * MIB),
			amounts("SCIM_PATCH_OPERATIONS", "SCIM PATCH operation count", Unit.COUNT, 1_000, 1, 10_000),
			amounts("SCIM_JSON_NODES", "SCIM JSON node count", Unit.COUNT, 100_000, 1_000, 1_000_000),
			// SCIM filter length / AST depth / nodes (G5-1: floors 64 / 2 / 4 -> 256 / 4 / 8).
			amounts("SCIM_FILTER_LENGTH", "SCIM filter length", Unit.CHARACTERS, 4_096, 256, 65_536),
			amounts("SCIM_FILTER_DEPTH", "SCIM filter depth", Unit.COUNT, 16, 4, 64),
			amounts("SCIM_FILTER_NODES", "SCIM filter node count", Unit.COUNT, 128, 8, 4_096),
			// Pending-state lifetime (G5-6: default 10 -> 15 min).
			durations("PENDING_STATE_LIFETIME", "Pending-state lifetime", Duration.ofMinutes(15), Duration.ofMinutes(1),
					Duration.ofMinutes(60), ZERO_REJECTED),
			// StateSealer maximum sealed length, in characters (G5-4: new row).
			amounts("STATE_SEALER_MAXIMUM_SEALED_LENGTH", "StateSealer maximum sealed length", Unit.CHARACTERS, 3_800,
					1_024, 16_384),
			// Seal lifetime, a per-call argument with no default (G5-4: new row).
			durations("SEAL_LIFETIME", "Seal lifetime", null, Duration.ofSeconds(1), Duration.ofDays(400),
					ZERO_REJECTED),
			// JWKS cooldown / min TTL / default TTL / max TTL / max staleness (G5-4: new default-TTL row).
			durations("JWKS_UNKNOWN_KEY_ID_COOLDOWN", "JWKS unknown-kid cooldown", Duration.ofSeconds(30),
					Duration.ofSeconds(1), Duration.ofMinutes(10), ZERO_REJECTED),
			durations("JWKS_MINIMUM_TIME_TO_LIVE", "JWKS minimum time to live", Duration.ofMinutes(1),
					Duration.ofSeconds(30), Duration.ofHours(1), ZERO_REJECTED),
			durations("JWKS_DEFAULT_TIME_TO_LIVE", "JWKS default time to live", Duration.ofMinutes(10),
					Duration.ofSeconds(30), Duration.ofHours(24), ZERO_REJECTED),
			durations("JWKS_MAXIMUM_TIME_TO_LIVE", "JWKS maximum time to live", Duration.ofHours(6),
					Duration.ofMinutes(1), Duration.ofHours(24), ZERO_REJECTED),
			durations("JWKS_MAXIMUM_STALENESS", "JWKS maximum staleness", Duration.ofHours(12), Duration.ZERO,
					Duration.ofHours(24), ZERO_ALLOWED),
			// Client credentials fallback / maximum cache duration / renewBefore (G5-3: new rows).
			durations("CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION", "Client-credentials fallback cache duration",
					Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1), ZERO_REJECTED),
			durations("CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION", "Client-credentials maximum cache duration",
					Duration.ofHours(24), Duration.ofMinutes(1), Duration.ofHours(24), ZERO_REJECTED),
			durations("CLIENT_CREDENTIALS_RENEW_BEFORE", "Client-credentials renewBefore", Duration.ofSeconds(60),
					Duration.ZERO, Duration.ofMinutes(10), ZERO_ALLOWED));

	/**
	 * The rows that permit zero (M1 plan, "Limits registry": "Zero is allowed only for maximum staleness and
	 * renewBefore").
	 */
	private static final Set<String> ZERO_ROWS = Set.of("JWKS_MAXIMUM_STALENESS", "CLIENT_CREDENTIALS_RENEW_BEFORE");

	// Gate 5: the registry holds exactly the approved rows, as public constants, in the transcribed order.
	@Test
	void theRegistryHoldsExactlyTheFortyApprovedRowsInOrder() throws IllegalAccessException {
		List<String> approved = APPROVED_ROWS.stream().map(Row::getConstant).toList();
		Assertions.assertEquals(40, approved.size(), "the plan's table has 40 rows");

		Map<String, Limit> constants = constants();
		IdentityHashMap<Limit, String> names = new IdentityHashMap<>();
		constants.forEach((name, limit) -> names.put(limit, name));
		Assertions.assertEquals(approved, Limits.all().stream().map(names::get).toList(),
				"Limits.all() holds every approved row, in order, and nothing else");
		Assertions.assertEquals(approved.stream().sorted().toList(), constants.keySet().stream().sorted().toList(),
				"every Limit constant is an approved row");
		for (Field field : Limits.class.getDeclaredFields())
			if (field.getType() == Limit.class)
				Assertions.assertTrue(Modifier.isPublic(field.getModifiers()) && Modifier.isStatic(field.getModifiers())
						&& Modifier.isFinal(field.getModifiers()), field::getName);

		Assertions.assertThrows(UnsupportedOperationException.class,
				() -> Limits.all().add(Limits.HTTP_RESPONSE_BODY_SIZE));
	}

	// Gate 5 and exit criterion 16: every row keeps its approved name, unit, default, floor, cap and zero rule.
	@TestFactory
	Stream<DynamicTest> everyApprovedRowIsPinned() {
		return APPROVED_ROWS.stream().map(row -> DynamicTest.dynamicTest(row.getConstant(), () -> {
			Limit limit = limit(row);

			Assertions.assertEquals(row.getName(), limit.getName());
			Assertions.assertEquals(row.getUnit(), limit.getUnit());
			Assertions.assertEquals(row.isZeroAllowed(), limit.isZeroAllowed());
			Assertions.assertEquals(row.isZeroAllowed(), ZERO_ROWS.contains(row.getConstant()));

			if (row.getUnit() == Unit.DURATION) {
				Assertions.assertEquals(row.getFloorDuration(), limit.getFloorDuration());
				Assertions.assertEquals(row.getCapDuration(), limit.getCapDuration());
				@Nullable Duration defaultDuration = row.getDefaultDuration();
				Assertions.assertEquals(defaultDuration != null, limit.hasDefault());
				if (defaultDuration == null)
					Assertions.assertThrows(IllegalStateException.class, limit::getDefaultDuration);
				else
					Assertions.assertEquals(defaultDuration, limit.getDefaultDuration());
			} else {
				Assertions.assertTrue(limit.hasDefault());
				Assertions.assertEquals(row.getDefaultAmount(), limit.getDefaultValue());
				Assertions.assertEquals(row.getFloorAmount(), limit.getFloor());
				Assertions.assertEquals(row.getCapAmount(), limit.getCap());
			}
		}));
	}

	// Plan R8 and exit criterion 16: Limit.require rejects zero outside the two zero rows, and every value outside the
	// approved [floor, cap], through each overload; it accepts the approved floor, default and cap.
	@TestFactory
	Stream<DynamicTest> requireRejectsZeroAndEveryValueOutsideTheApprovedRange() {
		return APPROVED_ROWS.stream().map(row -> DynamicTest.dynamicTest(row.getConstant(), () -> {
			Limit limit = limit(row);

			if (row.getUnit() == Unit.DURATION) {
				Duration floor = row.getFloorDuration();
				Duration cap = row.getCapDuration();

				Assertions.assertEquals(floor, limit.require(floor));
				Assertions.assertEquals(cap, limit.require(cap));
				@Nullable Duration defaultDuration = row.getDefaultDuration();
				if (defaultDuration != null)
					Assertions.assertEquals(defaultDuration, limit.require(defaultDuration));

				if (row.isZeroAllowed())
					Assertions.assertEquals(Duration.ZERO, limit.require(Duration.ZERO));
				else
					assertRejected(() -> limit.require(Duration.ZERO));

				for (Duration outside : List.of(floor.minusNanos(1), cap.plusNanos(1), Duration.ofNanos(-1),
						Duration.ofSeconds(Long.MIN_VALUE), Duration.ofSeconds(Long.MAX_VALUE, 999_999_999)))
					assertRejected(() -> limit.require(outside));

				// A duration row is never read as a count.
				Assertions.assertThrows(IllegalStateException.class, () -> limit.require(1L));
			} else {
				long floor = row.getFloorAmount();
				long cap = row.getCapAmount();

				Assertions.assertEquals(floor, limit.require(floor));
				Assertions.assertEquals(cap, limit.require(cap));
				Assertions.assertEquals(row.getDefaultAmount(), limit.require(row.getDefaultAmount()));
				Assertions.assertEquals((int) cap, limit.require((int) cap));
				Assertions.assertEquals((int) floor, limit.require((int) floor));

				// No amount row permits zero: every floor is positive.
				assertRejected(() -> limit.require(0));
				assertRejected(() -> limit.require(0L));

				for (long outside : new long[]{floor - 1, cap + 1, -1, Long.MIN_VALUE, Long.MAX_VALUE,
						Integer.MAX_VALUE + 1L})
					assertRejected(() -> limit.require(outside));
				for (int outside : new int[]{(int) floor - 1, (int) cap + 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE})
					assertRejected(() -> limit.require(outside));

				// A count row is never read as a duration.
				Assertions.assertThrows(IllegalStateException.class, () -> limit.require(Duration.ofSeconds(1)));
			}
		}));
	}

	// G7-6 and exit criterion 16: the public model's caps are 64 levels, 4,096 digits and an adjusted exponent of
	// 100,000, and no JSON row's cap, and so no profile, exceeds them.
	@Test
	void noJsonProfileExceedsAModelCap() throws ReflectiveOperationException {
		Assertions.assertEquals(64, JsonLimits.MODEL_MAXIMUM_DEPTH);
		Assertions.assertEquals(4_096, JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS);
		Assertions.assertEquals(100_000, JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE);

		Assertions.assertTrue(row("JSON_DEPTH_PROTOCOL").getCapAmount() <= JsonLimits.MODEL_MAXIMUM_DEPTH);
		Assertions.assertTrue(row("JSON_DEPTH_SCIM").getCapAmount() <= JsonLimits.MODEL_MAXIMUM_DEPTH);
		Assertions.assertTrue(row("JSON_NUMBER_LENGTH").getCapAmount() <= JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS);
		Assertions.assertTrue(row("JSON_NUMBER_EXPONENT_MAGNITUDE").getCapAmount()
				<= JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE);

		List<JsonLimits> profiles = new ArrayList<>(List.of(
				JsonLimits.protocolDocument(1), JsonLimits.protocolDocument((int) (4 * MIB)),
				JsonLimits.jose(1), JsonLimits.jose((int) MIB),
				JsonLimits.scim(1, 1_000), JsonLimits.scim((int) (10 * MIB), 1_000_000)));
		profiles.add(maximumCaps());

		for (JsonLimits profile : profiles) {
			Assertions.assertTrue(profile.getMaxDepth() <= JsonLimits.MODEL_MAXIMUM_DEPTH, profile::toString);
			Assertions.assertTrue(profile.getMaxNumberLength() <= JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS,
					profile::toString);
			Assertions.assertTrue(profile.getMaxExponentMagnitude() <= JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE,
					profile::toString);
		}
	}

	// G5-5 and G7-6: the JSON structural rows are internal in 1.0.0, so each profile uses their approved defaults,
	// except SCIM's node count, the one public JSON row; the test-only maximum-cap profile uses every cap.
	@Test
	void theJsonProfilesUseTheApprovedRows() throws ReflectiveOperationException {
		for (JsonLimits profile : List.of(JsonLimits.protocolDocument(1_000), JsonLimits.jose(1_000))) {
			assertJsonProfile(profile, 1_000, row("JSON_DEPTH_PROTOCOL").getDefaultAmount(),
					row("JSON_NODES").getDefaultAmount(), false);
		}
		assertJsonProfile(JsonLimits.scim(1_000, 2_000), 1_000, row("JSON_DEPTH_SCIM").getDefaultAmount(), 2_000,
				true);

		JsonLimits maximumCaps = maximumCaps();
		Assertions.assertEquals(Integer.MAX_VALUE, maximumCaps.getMaxInputBytes());
		Assertions.assertEquals(row("JSON_DEPTH_SCIM").getCapAmount(), maximumCaps.getMaxDepth());
		Assertions.assertEquals(row("SCIM_JSON_NODES").getCapAmount(), maximumCaps.getMaxNodes());
		Assertions.assertEquals(row("JSON_STRING_LENGTH").getCapAmount(), maximumCaps.getMaxStringLength());
		Assertions.assertEquals(row("JSON_NUMBER_LENGTH").getCapAmount(), maximumCaps.getMaxNumberLength());
		Assertions.assertEquals(row("JSON_NUMBER_EXPONENT_MAGNITUDE").getCapAmount(),
				maximumCaps.getMaxExponentMagnitude());
		Assertions.assertFalse(maximumCaps.isAsciiCaseVariantNamesRejected());
	}

	// G5-5 and exit criterion 16: each JSON profile's input size is the owning row's setting, from 1 byte to the
	// largest cap of the rows it serves, and SCIM's node count is the SCIM_JSON_NODES row.
	@TestFactory
	Stream<DynamicTest> theJsonProfilesRejectOutOfRangeSettings() {
		int protocolDocumentCap = (int) Math.max(row("HTTP_RESPONSE_BODY_SIZE").getCapAmount(),
				Math.max(row("JWKS_RESPONSE_BODY_SIZE").getCapAmount(), row("HTTP_ERROR_BODY_SIZE").getCapAmount()));
		int joseCap = (int) row("COMPACT_JWT_SIZE").getCapAmount();
		int scimCap = (int) row("SCIM_BODY_SIZE").getCapAmount();
		Row scimNodes = row("SCIM_JSON_NODES");

		return Stream.of(
				DynamicTest.dynamicTest("protocolDocument input bytes", () -> {
					Assertions.assertEquals((int) (4 * MIB), protocolDocumentCap);
					assertIntRange(value -> JsonLimits.protocolDocument(value).getMaxInputBytes(), 1,
							protocolDocumentCap);
				}),
				DynamicTest.dynamicTest("jose input bytes", () -> {
					Assertions.assertEquals((int) MIB, joseCap);
					assertIntRange(value -> JsonLimits.jose(value).getMaxInputBytes(), 1, joseCap);
				}),
				DynamicTest.dynamicTest("scim input bytes", () -> {
					Assertions.assertEquals((int) (10 * MIB), scimCap);
					assertIntRange(value -> JsonLimits.scim(value, 1_000).getMaxInputBytes(), 1, scimCap);
				}),
				DynamicTest.dynamicTest("scim nodes", () -> assertIntRange(
						value -> JsonLimits.scim(1_000, value).getMaxNodes(), (int) scimNodes.getFloorAmount(),
						(int) scimNodes.getCapAmount())));
	}

	// G5-4 and exit criterion 16: build() rejects a maximumSealedLength outside [1,024, 16,384], and null means
	// 3,800. The sealed length is ceil(4 * (54 + keyIdLength + plaintextBytes) / 3) (M1 plan, "StateSealer v1"), so
	// with the 4-character key ID "test" a plaintext of 2,792 bytes seals to exactly 3,800 characters.
	@Test
	void theSealerRejectsAMaximumSealedLengthOutsideTheApprovedRange() {
		Row row = row("STATE_SEALER_MAXIMUM_SEALED_LENGTH");
		assertIntRange(value -> sealerWithMaximum(value).toString(), (int) row.getFloorAmount(),
				(int) row.getCapAmount());

		assertSealsExactlyUpTo(sealerWithMaximum(null), (int) row.getDefaultAmount());
		assertSealsExactlyUpTo(StateSealer.withActiveKey(TestSealers.fixedKey(TestSealers.FIXED_KEY_ID)).build(),
				(int) row.getDefaultAmount());
		assertSealsExactlyUpTo(sealerWithMaximum((int) row.getFloorAmount()), (int) row.getFloorAmount());
		assertSealsExactlyUpTo(sealerWithMaximum((int) row.getCapAmount()), (int) row.getCapAmount());
	}

	// G5-4 and exit criterion 16: seal rejects a lifetime outside [1 s, 400 days].
	@Test
	void theSealerRejectsALifetimeOutsideTheApprovedRange() {
		Row row = row("SEAL_LIFETIME");
		StateSealer sealer = TestSealers.fromFixedKey();

		Assertions.assertFalse(sealer.seal("x", "context", row.getFloorDuration()).isEmpty());
		Assertions.assertFalse(sealer.seal("x", "context", row.getCapDuration()).isEmpty());
		for (Duration outside : List.of(row.getFloorDuration().minusNanos(1), row.getCapDuration().plusNanos(1),
				Duration.ZERO, Duration.ofSeconds(-1), Duration.ofSeconds(Long.MAX_VALUE)))
			assertRejected(() -> sealer.seal("x", "context", outside));
	}

	// Plan R8 and R12: the HTTP helper's defaults are the registry's, and a JWKS body is bounded by its own row.
	@Test
	void theHttpDefaultsComeFromTheApprovedRows() throws IllegalAccessException {
		URI uri = URI.create("https://example.com/");
		for (ResponseProfile profile : ResponseProfile.values()) {
			String bodyRow = profile == ResponseProfile.JWKS ? "JWKS_RESPONSE_BODY_SIZE" : "HTTP_RESPONSE_BODY_SIZE";
			Assertions.assertSame(limit(row(bodyRow)), profile.getBodySizeLimit(), profile::name);

			HttpExchangeRequest request = HttpExchangeRequest.fromDefaults(uri, profile);
			Assertions.assertEquals(row(bodyRow).getDefaultAmount(), request.maximumBodyBytes(), profile::name);
			Assertions.assertEquals(row("HTTP_ERROR_BODY_SIZE").getDefaultAmount(), request.maximumErrorBodyBytes(),
					profile::name);
			Assertions.assertEquals(row("REQUEST_TIMEOUT").getDefaultDuration(), request.requestTimeout(),
					profile::name);
		}
	}

	// G5-5: requestTimeout <= totalDeadline; equal passes, one nanosecond more fails, whatever the rows allow.
	@Test
	void theRequestTimeoutMayNotExceedTheTotalDeadline() {
		Limits.requireRequestTimeoutWithinTotalDeadline(Duration.ofSeconds(10), Duration.ofSeconds(15));
		Limits.requireRequestTimeoutWithinTotalDeadline(Duration.ofSeconds(15), Duration.ofSeconds(15));
		assertRejected(() -> Limits.requireRequestTimeoutWithinTotalDeadline(Duration.ofSeconds(15).plusNanos(1),
				Duration.ofSeconds(15)));
		assertRejected(() -> Limits.requireRequestTimeoutWithinTotalDeadline(Duration.ofSeconds(60),
				Duration.ofSeconds(1)));
	}

	// G5-4: JWKS minimum TTL <= default TTL <= maximum TTL; equal passes.
	@Test
	void theJwksTimesToLiveMustBeOrdered() {
		Limits.requireJwksTimeToLiveOrder(Duration.ofMinutes(1), Duration.ofMinutes(10), Duration.ofHours(6));
		Limits.requireJwksTimeToLiveOrder(Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ofMinutes(1));
		assertRejected(() -> Limits.requireJwksTimeToLiveOrder(Duration.ofMinutes(10).plusNanos(1),
				Duration.ofMinutes(10), Duration.ofHours(6)));
		assertRejected(() -> Limits.requireJwksTimeToLiveOrder(Duration.ofMinutes(1), Duration.ofHours(6).plusNanos(1),
				Duration.ofHours(6)));
		assertRejected(() -> Limits.requireJwksTimeToLiveOrder(Duration.ofHours(1), Duration.ofSeconds(30),
				Duration.ofMinutes(1)));
	}

	// G5-3: renewBefore < maximumCacheDuration, strictly; zero renewBefore passes with the smallest maximum.
	@Test
	void renewBeforeMustBeShorterThanTheMaximumCacheDuration() {
		Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ofSeconds(60), Duration.ofHours(24));
		Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ZERO, Duration.ofMinutes(1));
		Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ofMinutes(1).minusNanos(1), Duration.ofMinutes(1));
		assertRejected(() -> Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ofMinutes(1),
				Duration.ofMinutes(1)));
		assertRejected(() -> Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ofMinutes(10),
				Duration.ofMinutes(1)));
	}

	// M1 plan, Results (phase 1, "Calls made within approved scope"): fallbackCacheDuration <= maximumCacheDuration;
	// equal passes, one nanosecond more fails.
	@Test
	void theFallbackCacheDurationMayNotExceedTheMaximumCacheDuration() {
		Limits.requireFallbackWithinMaximumCacheDuration(Duration.ofMinutes(5), Duration.ofHours(24));
		Limits.requireFallbackWithinMaximumCacheDuration(Duration.ofMinutes(1), Duration.ofMinutes(1));
		Limits.requireFallbackWithinMaximumCacheDuration(Duration.ofHours(1), Duration.ofHours(1));
		assertRejected(() -> Limits.requireFallbackWithinMaximumCacheDuration(Duration.ofMinutes(1).plusNanos(1),
				Duration.ofMinutes(1)));
		assertRejected(() -> Limits.requireFallbackWithinMaximumCacheDuration(Duration.ofHours(1),
				Duration.ofMinutes(1)));
	}

	// G5-3 runtime rule: a token's lifetime is expires_in capped at maximumCacheDuration, or the fallback without one,
	// and it is renewed min(renewBefore, lifetime / 2) before expiry, so a 30 s token under the 60 s default is renewed
	// after 15 s.
	@Test
	void clientCredentialsTokensFollowTheApprovedRuntimeRule() {
		Assertions.assertEquals(Duration.ofMinutes(5),
				Limits.clientCredentialsCacheLifetime(null, Duration.ofMinutes(5), Duration.ofHours(24)));
		Assertions.assertEquals(Duration.ofHours(24),
				Limits.clientCredentialsCacheLifetime(Duration.ofHours(48), Duration.ofMinutes(5), Duration.ofHours(24)));
		Assertions.assertEquals(Duration.ofHours(1),
				Limits.clientCredentialsCacheLifetime(Duration.ofHours(1), Duration.ofMinutes(5), Duration.ofHours(24)));

		Assertions.assertEquals(Duration.ofSeconds(15),
				Limits.clientCredentialsRenewalLeadTime(Duration.ofSeconds(60), Duration.ofSeconds(30)));
		Assertions.assertEquals(Duration.ofSeconds(60),
				Limits.clientCredentialsRenewalLeadTime(Duration.ofSeconds(60), Duration.ofHours(24)));
		Assertions.assertEquals(Duration.ZERO,
				Limits.clientCredentialsRenewalLeadTime(Duration.ZERO, Duration.ofHours(1)));
	}

	private static void assertJsonProfile(JsonLimits profile, int maxInputBytes, long depth, long nodes,
			boolean asciiCaseVariantNamesRejected) {
		Assertions.assertEquals(maxInputBytes, profile.getMaxInputBytes(), profile::toString);
		Assertions.assertEquals(depth, profile.getMaxDepth(), profile::toString);
		Assertions.assertEquals(nodes, profile.getMaxNodes(), profile::toString);
		Assertions.assertEquals(row("JSON_STRING_LENGTH").getDefaultAmount(), profile.getMaxStringLength(),
				profile::toString);
		Assertions.assertEquals(row("JSON_NUMBER_LENGTH").getDefaultAmount(), profile.getMaxNumberLength(),
				profile::toString);
		Assertions.assertEquals(row("JSON_NUMBER_EXPONENT_MAGNITUDE").getDefaultAmount(),
				profile.getMaxExponentMagnitude(), profile::toString);
		Assertions.assertEquals(asciiCaseVariantNamesRejected, profile.isAsciiCaseVariantNamesRejected(),
				profile::toString);
	}

	/**
	 * {@code consumer} accepts {@code floor} and {@code cap} and rejects, with {@link IllegalArgumentException}, the
	 * values just outside them, zero, a negative value and both {@code int} extremes.
	 */
	private static void assertIntRange(IntFunction<Object> consumer, int floor, int cap) {
		Assertions.assertNotNull(consumer.apply(floor));
		Assertions.assertNotNull(consumer.apply(cap));
		for (int outside : new int[]{floor - 1, cap + 1, 0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE})
			assertRejected(() -> consumer.apply(outside));
	}

	/**
	 * {@code sealer} seals a value of exactly {@code maximumSealedLength} characters and refuses one byte more.
	 */
	private static void assertSealsExactlyUpTo(StateSealer sealer, int maximumSealedLength) {
		int overhead = 54 + TestSealers.FIXED_KEY_ID.length();
		Assertions.assertEquals(0, maximumSealedLength % 4, "the boundary is exact only for multiples of 4");
		int largestPlaintext = maximumSealedLength / 4 * 3 - overhead;

		Assertions.assertEquals(maximumSealedLength,
				sealer.seal("a".repeat(largestPlaintext), "context", Duration.ofMinutes(1)).length());
		assertRejected(() -> sealer.seal("a".repeat(largestPlaintext + 1), "context", Duration.ofMinutes(1)));
	}

	private static StateSealer sealerWithMaximum(@Nullable Integer maximumSealedLength) {
		return StateSealer.withActiveKey(TestSealers.fixedKey(TestSealers.FIXED_KEY_ID))
				.maximumSealedLength(maximumSealedLength)
				.build();
	}

	private static void assertRejected(Executable executable) {
		Assertions.assertThrows(IllegalArgumentException.class, executable);
	}

	/**
	 * The package-private, test-only profile that sets every JSON row at its cap, read reflectively because it is
	 * deliberately not part of the internal API.
	 */
	private static JsonLimits maximumCaps() throws ReflectiveOperationException {
		Method maximumCaps = JsonLimits.class.getDeclaredMethod("maximumCaps");
		maximumCaps.setAccessible(true);
		return (JsonLimits) maximumCaps.invoke(null);
	}

	/**
	 * Every public {@link Limit} constant of {@link Limits}, by name, in declaration order.
	 */
	private static Map<String, Limit> constants() throws IllegalAccessException {
		Map<String, Limit> constants = new LinkedHashMap<>();
		for (Field field : Limits.class.getFields())
			if (field.getType() == Limit.class)
				constants.put(field.getName(), (Limit) field.get(null));
		return constants;
	}

	private static Limit limit(Row row) throws IllegalAccessException {
		return Objects.requireNonNull(constants().get(row.getConstant()),
				() -> "Limits has no public constant " + row.getConstant());
	}

	private static Row row(String constant) {
		return APPROVED_ROWS.stream()
				.filter(row -> row.getConstant().equals(constant))
				.findFirst()
				.orElseThrow(() -> new AssertionError("No approved row " + constant));
	}

	private static Row amounts(String constant, String name, Unit unit, long defaultValue, long floor, long cap) {
		return new Row(constant, name, unit, defaultValue, floor, cap, null, Duration.ZERO, Duration.ZERO,
				ZERO_REJECTED);
	}

	private static Row durations(String constant, String name, @Nullable Duration defaultValue, Duration floor,
			Duration cap, boolean zeroAllowed) {
		return new Row(constant, name, Unit.DURATION, 0, 0, 0, defaultValue, floor, cap, zeroAllowed);
	}

	/**
	 * One transcribed row: a count, size or length row uses the amounts, and a duration row the durations.
	 */
	private static final class Row {
		private final String constant;
		private final String name;
		private final Unit unit;
		private final long defaultAmount;
		private final long floorAmount;
		private final long capAmount;
		private final @Nullable Duration defaultDuration;
		private final Duration floorDuration;
		private final Duration capDuration;
		private final boolean zeroAllowed;

		private Row(String constant, String name, Unit unit, long defaultAmount, long floorAmount, long capAmount,
				@Nullable Duration defaultDuration, Duration floorDuration, Duration capDuration, boolean zeroAllowed) {
			this.constant = constant;
			this.name = name;
			this.unit = unit;
			this.defaultAmount = defaultAmount;
			this.floorAmount = floorAmount;
			this.capAmount = capAmount;
			this.defaultDuration = defaultDuration;
			this.floorDuration = floorDuration;
			this.capDuration = capDuration;
			this.zeroAllowed = zeroAllowed;
		}

		String getConstant() {
			return this.constant;
		}

		String getName() {
			return this.name;
		}

		Unit getUnit() {
			return this.unit;
		}

		long getDefaultAmount() {
			return this.defaultAmount;
		}

		long getFloorAmount() {
			return this.floorAmount;
		}

		long getCapAmount() {
			return this.capAmount;
		}

		@Nullable Duration getDefaultDuration() {
			return this.defaultDuration;
		}

		Duration getFloorDuration() {
			return this.floorDuration;
		}

		Duration getCapDuration() {
			return this.capDuration;
		}

		boolean isZeroAllowed() {
			return this.zeroAllowed;
		}
	}
}
