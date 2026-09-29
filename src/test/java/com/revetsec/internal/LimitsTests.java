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

package com.revetsec.internal;

import com.revetsec.internal.Limit.Unit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * The limits registry as a whole (plan R8; M1 plan gate 5, "Limits registry"; gate 8, G8-10).
 * {@code FrozenLimitsTests} pins every value; these tests check that each row enforces its own range and that the
 * registry is complete.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class LimitsTests {
	private static final long KIB = 1_024;
	private static final long MIB = 1_024 * KIB;

	@TestFactory
	Stream<DynamicTest> everyRowAcceptsItsFloorAndCapAndRejectsZeroAndOutOfRangeValues() {
		// Plan R8: values outside [floor, cap] throw IllegalArgumentException; zero only where the floor is zero.
		return Limits.all().stream().map(limit -> DynamicTest.dynamicTest(limit.getName(), () -> {
			if (limit.getUnit() == Unit.DURATION) {
				Duration floor = limit.getFloorDuration();
				Duration cap = limit.getCapDuration();

				Assertions.assertEquals(floor, limit.require(floor));
				Assertions.assertEquals(cap, limit.require(cap));
				Assertions.assertThrows(IllegalArgumentException.class, () -> limit.require(floor.minusNanos(1)));
				Assertions.assertThrows(IllegalArgumentException.class, () -> limit.require(cap.plusNanos(1)));
				Assertions.assertThrows(IllegalArgumentException.class, () -> limit.require(Duration.ofSeconds(-1)));
				Assertions.assertThrows(IllegalArgumentException.class,
						() -> limit.require(Duration.ofSeconds(Long.MAX_VALUE, 999_999_999)));

				if (limit.isZeroAllowed())
					Assertions.assertEquals(Duration.ZERO, limit.require(Duration.ZERO));
				else
					Assertions.assertThrows(IllegalArgumentException.class, () -> limit.require(Duration.ZERO));

				if (limit.hasDefault()) {
					Duration defaultValue = limit.getDefaultDuration();
					Assertions.assertEquals(defaultValue, limit.require(defaultValue));
				}
			} else {
				long floor = limit.getFloor();
				long cap = limit.getCap();

				Assertions.assertTrue(cap <= Integer.MAX_VALUE, "every size row fits an int");
				Assertions.assertEquals(floor, limit.require(floor));
				Assertions.assertEquals((int) cap, limit.require((int) cap));
				Assertions.assertThrows(IllegalArgumentException.class, () -> limit.require(floor - 1));
				Assertions.assertThrows(IllegalArgumentException.class, () -> limit.require(cap + 1));
				Assertions.assertThrows(IllegalArgumentException.class, () -> limit.require(-1));
				Assertions.assertThrows(IllegalArgumentException.class, () -> limit.require(Long.MAX_VALUE));
				Assertions.assertThrows(IllegalArgumentException.class, () -> limit.require(0));
				Assertions.assertFalse(limit.isZeroAllowed());
				Assertions.assertTrue(limit.hasDefault());
				Assertions.assertEquals(limit.getDefaultValue(), limit.require(limit.getDefaultIntValue()));
			}

			// The message names the row and repeats nothing but the number.
			IllegalArgumentException rejection = Assertions.assertThrows(IllegalArgumentException.class,
					() -> requireOutOfRange(limit));
			String message = String.valueOf(rejection.getMessage());
			Assertions.assertTrue(message.startsWith(limit.getName() + " must be from "), message);
		}));
	}

	@Test
	void zeroIsAllowedOnlyForTheJoseClockSkewMaximumStalenessAndRenewBefore() {
		// M1 plan, Limits registry: "Zero is allowed only for maximum staleness and renewBefore." G8-10 adds the JOSE
		// clock skew (R11: "configurable 0-5 min") as the third zero row, in registry order.
		List<Limit> zeroAllowed = Limits.all().stream().filter(Limit::isZeroAllowed).toList();

		Assertions.assertEquals(List.of(Limits.JOSE_CLOCK_SKEW, Limits.JWKS_MAXIMUM_STALENESS,
				Limits.CLIENT_CREDENTIALS_RENEW_BEFORE), zeroAllowed);
	}

	@Test
	void theRegistryListsEveryConstantOnceWithAUniqueName() throws IllegalAccessException {
		// One constant per row: every public Limit constant is in all(), and nothing else is.
		List<Limit> constants = new ArrayList<>();

		for (Field field : Limits.class.getDeclaredFields()) {
			int modifiers = field.getModifiers();
			if (field.getType() == Limit.class) {
				Assertions.assertTrue(Modifier.isPublic(modifiers) && Modifier.isStatic(modifiers)
						&& Modifier.isFinal(modifiers), field::getName);
				constants.add((Limit) field.get(null));
			}
		}

		Assertions.assertEquals(constants, Limits.all());
		Assertions.assertEquals(49, Limits.all().size());

		Set<String> names = new HashSet<>();
		for (Limit limit : Limits.all())
			Assertions.assertTrue(names.add(limit.getName()), limit::getName);

		Assertions.assertThrows(UnsupportedOperationException.class, () -> Limits.all().add(Limits.XML_DEPTH));
	}

	@Test
	void discoveryLifetimeAndCooldownMustBeOrdered() {
		Duration minimum = Duration.ofMinutes(1);
		Duration fallback = Duration.ofMinutes(10);
		Duration maximum = Duration.ofHours(6);
		Limits.requireDiscoveryTimeToLiveOrder(minimum, fallback, maximum, Duration.ofSeconds(30));
		Assertions.assertThrows(IllegalArgumentException.class, () ->
				Limits.requireDiscoveryTimeToLiveOrder(fallback, minimum, maximum, Duration.ofSeconds(30)));
		Assertions.assertThrows(IllegalArgumentException.class, () ->
				Limits.requireDiscoveryTimeToLiveOrder(minimum, maximum, fallback, Duration.ofSeconds(30)));
		Assertions.assertThrows(IllegalArgumentException.class, () ->
				Limits.requireDiscoveryTimeToLiveOrder(minimum, fallback, maximum, Duration.ofMinutes(2)));
	}

	@Test
	void onlyTheSealLifetimeHasNoDefault() {
		// M1 plan, Limits registry: the seal lifetime is a per-call argument (a dash in the default column).
		Assertions.assertEquals(List.of(Limits.SEAL_LIFETIME),
				Limits.all().stream().filter(limit -> !limit.hasDefault()).toList());
	}

	@Test
	void gateFiveChangesAreInPlace() {
		// The rows gate 5 changed (G5-1 to G5-6), spot-checked; FrozenLimitsTests pins every value.
		Assertions.assertEquals(16 * KIB, Limits.HTTP_RESPONSE_BODY_SIZE.getFloor());
		Assertions.assertEquals(16 * KIB, Limits.JWKS_RESPONSE_BODY_SIZE.getFloor());
		Assertions.assertEquals(8 * KIB, Limits.COMPACT_JWT_SIZE.getFloor());
		Assertions.assertEquals(2 * KIB, Limits.AUTHORIZATION_RESPONSE_PARAMETER_SIZE.getFloor());
		Assertions.assertEquals(4 * KIB, Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getFloor());
		Assertions.assertEquals(16, Limits.XML_ATTRIBUTES_PER_ELEMENT.getFloor());
		Assertions.assertEquals(1_000, Limits.XML_ELEMENTS.getFloor());
		Assertions.assertEquals(64 * KIB, Limits.SAML_METADATA_SIZE.getFloor());
		Assertions.assertEquals(8 * MIB, Limits.SAML_METADATA_SIZE.getCap());
		Assertions.assertEquals(256, Limits.SCIM_FILTER_LENGTH.getFloor());
		Assertions.assertEquals(4, Limits.SCIM_FILTER_DEPTH.getFloor());
		Assertions.assertEquals(8, Limits.SCIM_FILTER_NODES.getFloor());
		Assertions.assertEquals(16 * KIB, Limits.JSON_STRING_LENGTH.getFloor());
		Assertions.assertEquals(32, Limits.JSON_NUMBER_EXPONENT_MAGNITUDE.getFloor());
		Assertions.assertEquals(64, Limits.JSON_DEPTH_PROTOCOL.getCap());
		Assertions.assertEquals(64, Limits.JSON_DEPTH_SCIM.getCap());
		Assertions.assertEquals(Duration.ofMinutes(15), Limits.PENDING_STATE_LIFETIME.getDefaultDuration());
		Assertions.assertEquals(3_800, Limits.STATE_SEALER_MAXIMUM_SEALED_LENGTH.getDefaultValue());
		Assertions.assertEquals(Duration.ofDays(400), Limits.SEAL_LIFETIME.getCapDuration());
		Assertions.assertEquals(Duration.ofMinutes(10), Limits.JWKS_DEFAULT_TIME_TO_LIVE.getDefaultDuration());
		Assertions.assertEquals(100_000, Limits.SCIM_JSON_NODES.getDefaultValue());
		Assertions.assertEquals(Duration.ofSeconds(60), Limits.CLIENT_CREDENTIALS_RENEW_BEFORE.getDefaultDuration());
	}

	@Test
	void gateEightRowsAreInPlace() {
		// G8-10: the JOSE clock skew is 60 s [0, 5 min] and zero compares times exactly; the ID token maximum age,
		// for M4, is 5 min [1 min, 1 h]. FrozenLimitsTests pins every value.
		Assertions.assertEquals(Duration.ofSeconds(60), Limits.JOSE_CLOCK_SKEW.getDefaultDuration());
		Assertions.assertEquals(Duration.ZERO, Limits.JOSE_CLOCK_SKEW.require(Duration.ZERO));
		Assertions.assertEquals(Duration.ofMinutes(5), Limits.JOSE_CLOCK_SKEW.require(Duration.ofMinutes(5)));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Limits.JOSE_CLOCK_SKEW.require(Duration.ofMinutes(5).plusNanos(1)));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Limits.JOSE_CLOCK_SKEW.require(Duration.ofNanos(-1)));

		Assertions.assertEquals(Duration.ofMinutes(5), Limits.ID_TOKEN_MAXIMUM_AGE.getDefaultDuration());
		Assertions.assertEquals(Duration.ofMinutes(1), Limits.ID_TOKEN_MAXIMUM_AGE.getFloorDuration());
		Assertions.assertEquals(Duration.ofHours(1), Limits.ID_TOKEN_MAXIMUM_AGE.getCapDuration());
		Assertions.assertFalse(Limits.ID_TOKEN_MAXIMUM_AGE.isZeroAllowed());
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Limits.ID_TOKEN_MAXIMUM_AGE.require(Duration.ofMinutes(1).minusNanos(1)));

		// Both sit with the other JOSE row, after the compact JWT size.
		int compactJwtSize = Limits.all().indexOf(Limits.COMPACT_JWT_SIZE);
		Assertions.assertEquals(List.of(Limits.COMPACT_JWT_SIZE, Limits.JOSE_CLOCK_SKEW, Limits.ID_TOKEN_MAXIMUM_AGE),
				Limits.all().subList(compactJwtSize, compactJwtSize + 3));
	}

	@Test
	void requestTimeoutMustNotExceedTheTotalDeadline() {
		// M1 plan G5-5: build() rejects requestTimeout > totalDeadline.
		Limits.requireRequestTimeoutWithinTotalDeadline(Duration.ofSeconds(10), Duration.ofSeconds(15));
		Limits.requireRequestTimeoutWithinTotalDeadline(Duration.ofSeconds(15), Duration.ofSeconds(15));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limits.requireRequestTimeoutWithinTotalDeadline(
				Duration.ofSeconds(15).plusNanos(1), Duration.ofSeconds(15)));
		Limits.requireRequestTimeoutWithinTotalDeadline(Limits.REQUEST_TIMEOUT.getDefaultDuration(),
				Limits.TOTAL_DEADLINE.getDefaultDuration());
	}

	@Test
	void jwksTimeToLiveSettingsMustBeOrdered() {
		// M1 plan, Limits registry: min TTL <= default TTL <= max TTL.
		Limits.requireJwksTimeToLiveOrder(Limits.JWKS_MINIMUM_TIME_TO_LIVE.getDefaultDuration(),
				Limits.JWKS_DEFAULT_TIME_TO_LIVE.getDefaultDuration(), Limits.JWKS_MAXIMUM_TIME_TO_LIVE.getDefaultDuration());
		Limits.requireJwksTimeToLiveOrder(Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ofMinutes(1));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limits.requireJwksTimeToLiveOrder(
				Duration.ofMinutes(2), Duration.ofMinutes(1), Duration.ofHours(1)));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limits.requireJwksTimeToLiveOrder(
				Duration.ofMinutes(1), Duration.ofHours(2), Duration.ofHours(1)));
	}

	@Test
	void jwksCooldownMustNotExceedTheMinimumTimeToLive() {
		// M2-8, the owner's decision of 2026-09-28: unknown-kid cooldown <= minimum TTL; equal passes.
		Limits.requireJwksCooldownWithinMinimumTimeToLive(Limits.JWKS_UNKNOWN_KEY_ID_COOLDOWN.getDefaultDuration(),
				Limits.JWKS_MINIMUM_TIME_TO_LIVE.getDefaultDuration());
		Limits.requireJwksCooldownWithinMinimumTimeToLive(Duration.ofMinutes(1), Duration.ofMinutes(1));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limits.requireJwksCooldownWithinMinimumTimeToLive(
				Duration.ofMinutes(1).plusNanos(1), Duration.ofMinutes(1)));
		// The rows' floors pass together, and the cooldown's cap passes only with a minimum TTL as long.
		Limits.requireJwksCooldownWithinMinimumTimeToLive(Limits.JWKS_UNKNOWN_KEY_ID_COOLDOWN.getFloorDuration(),
				Limits.JWKS_MINIMUM_TIME_TO_LIVE.getFloorDuration());
		Limits.requireJwksCooldownWithinMinimumTimeToLive(Limits.JWKS_UNKNOWN_KEY_ID_COOLDOWN.getCapDuration(),
				Limits.JWKS_UNKNOWN_KEY_ID_COOLDOWN.getCapDuration());
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limits.requireJwksCooldownWithinMinimumTimeToLive(
				Limits.JWKS_UNKNOWN_KEY_ID_COOLDOWN.getCapDuration(), Limits.JWKS_MINIMUM_TIME_TO_LIVE.getDefaultDuration()));
	}

	@Test
	void renewBeforeMustBeShorterThanTheMaximumCacheDuration() {
		// M1 plan, Limits registry: renewBefore < maximumCacheDuration.
		Limits.requireRenewBeforeBelowMaximumCacheDuration(Limits.CLIENT_CREDENTIALS_RENEW_BEFORE.getDefaultDuration(),
				Limits.CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION.getDefaultDuration());
		Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ZERO, Duration.ofMinutes(1));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limits.requireRenewBeforeBelowMaximumCacheDuration(
				Duration.ofMinutes(1), Duration.ofMinutes(1)));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Limits.requireRenewBeforeBelowMaximumCacheDuration(
				Duration.ofMinutes(10), Duration.ofMinutes(5)));
	}

	@Test
	void aCachedTokenIsRenewedAtMinOfRenewBeforeAndHalfItsLifetime() {
		// M1 plan G5-3: a 30 s token under the 60 s default is renewed after 15 s, not re-fetched on every call.
		Duration renewBefore = Limits.CLIENT_CREDENTIALS_RENEW_BEFORE.getDefaultDuration();

		Assertions.assertEquals(Duration.ofSeconds(15),
				Limits.clientCredentialsRenewalLeadTime(renewBefore, Duration.ofSeconds(30)));
		Assertions.assertEquals(Duration.ofSeconds(60),
				Limits.clientCredentialsRenewalLeadTime(renewBefore, Duration.ofHours(24)));
		Assertions.assertEquals(Duration.ZERO, Limits.clientCredentialsRenewalLeadTime(Duration.ZERO,
				Duration.ofHours(1)));
		Assertions.assertEquals(Duration.ZERO, Limits.clientCredentialsRenewalLeadTime(renewBefore, Duration.ZERO));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Limits.clientCredentialsRenewalLeadTime(Duration.ofSeconds(-1), Duration.ofHours(1)));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Limits.clientCredentialsRenewalLeadTime(renewBefore, Duration.ofSeconds(-1)));
	}

	@Test
	void aCachedTokensLifetimeIsExpiresInCappedOrTheFallback() {
		// M1 plan G5-3: expires_in capped at maximumCacheDuration, or fallbackCacheDuration when it is absent.
		Duration fallback = Limits.CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION.getDefaultDuration();
		Duration maximum = Limits.CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION.getDefaultDuration();

		Assertions.assertEquals(Duration.ofMinutes(5), Limits.clientCredentialsCacheLifetime(null, fallback, maximum));
		Assertions.assertEquals(Duration.ofHours(1),
				Limits.clientCredentialsCacheLifetime(Duration.ofHours(1), fallback, maximum));
		Assertions.assertEquals(Duration.ofHours(24),
				Limits.clientCredentialsCacheLifetime(Duration.ofDays(30), fallback, maximum));
		Assertions.assertEquals(Duration.ZERO, Limits.clientCredentialsCacheLifetime(Duration.ZERO, fallback, maximum));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Limits.clientCredentialsCacheLifetime(Duration.ofSeconds(-1), fallback, maximum));

		// With the fallback at the largest value build() accepts for the smallest maximum, neither path exceeds it.
		Duration shortMaximum = Limits.CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION.getFloorDuration();
		Limits.requireFallbackWithinMaximumCacheDuration(shortMaximum, shortMaximum);
		Assertions.assertEquals(shortMaximum, Limits.clientCredentialsCacheLifetime(null, shortMaximum, shortMaximum));
		Assertions.assertEquals(shortMaximum,
				Limits.clientCredentialsCacheLifetime(Duration.ofHours(1), shortMaximum, shortMaximum));
	}

	@Test
	void theFallbackCacheDurationMustNotExceedTheMaximumCacheDuration() {
		// M1 plan, Results > Phase 1: build() rejects fallbackCacheDuration > maximumCacheDuration, so that "maximum"
		// bounds a token without expires_in too.
		Duration fallbackCap = Limits.CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION.getCapDuration();
		Duration maximumFloor = Limits.CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION.getFloorDuration();

		Limits.requireFallbackWithinMaximumCacheDuration(
				Limits.CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION.getDefaultDuration(),
				Limits.CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION.getDefaultDuration());
		Limits.requireFallbackWithinMaximumCacheDuration(maximumFloor, maximumFloor);
		Limits.requireFallbackWithinMaximumCacheDuration(fallbackCap, fallbackCap);
		Limits.requireFallbackWithinMaximumCacheDuration(
				Limits.CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION.getFloorDuration(), maximumFloor);

		IllegalArgumentException rejection = Assertions.assertThrows(IllegalArgumentException.class,
				() -> Limits.requireFallbackWithinMaximumCacheDuration(maximumFloor.plusNanos(1), maximumFloor));
		Assertions.assertEquals("Client-credentials fallback cache duration must not exceed the maximum cache "
				+ "duration.", rejection.getMessage());
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Limits.requireFallbackWithinMaximumCacheDuration(fallbackCap, maximumFloor));
	}

	private static void requireOutOfRange(Limit limit) {
		if (limit.getUnit() == Unit.DURATION)
			limit.require(limit.getCapDuration().plusSeconds(1));
		else
			limit.require(limit.getCap() + 1);
	}
}
