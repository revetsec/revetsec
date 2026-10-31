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

import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.testing.ChildJvm;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * SCP-02's additive carrier/bridge subset of SC-API-02/05/08 and restricted-construction contracts.
 * These tests make no backend admission, trusted UTC, commit-outcome or family-engine claim.
 */
final class StoreTimeContractTests {
	private static final String AUTHORITY = identifier(1);
	private static final String RECOVERY = identifier(2);
	private static final String GENERATION = identifier(3);
	private static final String OTHER = identifier(4);
	private static final Instant START = Instant.parse("2026-10-29T12:34:56.123456789Z");
	private static final Instant MAXIMUM = Instant.ofEpochSecond(253_402_300_799L, 999_999_999);
	private static final Duration MAXIMUM_ERROR = Duration.ofMillis(250);
	private static final String CHILD_SUCCESS = "store-time-access-initialized-once";

	@Test
	void allThreeIdentifierDomainsAcceptCanonical32ByteEncodingsWithoutGeneratingIdentifiers() {
		for (int value = 0; value < 256; value++) {
			String encoded = identifier(value);
			StoreAdmission admission = StoreAdmission.fromIdentifiers(encoded, encoded);
			StoreTimeObservation.Healthy observation = StoreTimeObservation.Healthy.fromObservation(
					admission, encoded, START, Duration.ZERO);
			Assertions.assertEquals(encoded, admission.getAuthorityId());
			Assertions.assertEquals(encoded, admission.getRecoveryGeneration());
			Assertions.assertEquals(encoded, observation.getClockGeneration());
		}
		// The domains are separate facts, not a constraint that their encoded strings must differ.
		byte[] bytes = new byte[32];
		Arrays.fill(bytes, (byte) 0xff);
		String alphabetEdge = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
		Assertions.assertTrue(alphabetEdge.contains("_"));
		Assertions.assertEquals(alphabetEdge,
				StoreAdmission.fromIdentifiers(alphabetEdge, RECOVERY).getAuthorityId());
	}

	@Test
	void identifiersRejectWrongLengthPaddingNonAsciiNonUrlAlphabetAndNonCanonicalSpareBits() {
		String nonCanonical = "A".repeat(42) + "B";
		Assertions.assertEquals(32, Base64.getUrlDecoder().decode(nonCanonical).length);
		Assertions.assertNotEquals(nonCanonical,
				Base64.getUrlEncoder().withoutPadding().encodeToString(Base64.getUrlDecoder().decode(nonCanonical)));
		List<String> invalid = List.of("", "A".repeat(42), "A".repeat(44), "A".repeat(43) + "=",
				"A".repeat(42) + "+", "A".repeat(42) + "/", "A".repeat(42) + " ",
				"A".repeat(21) + "." + "A".repeat(21), "A".repeat(42) + "\u00e9",
				"\uff21".repeat(43), "\ud800".repeat(43), nonCanonical);
		StoreAdmission valid = admission();
		for (String input : invalid) {
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> StoreAdmission.fromIdentifiers(input, RECOVERY), "authority input");
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> StoreAdmission.fromIdentifiers(AUTHORITY, input), "recovery input");
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> StoreTimeObservation.Healthy.fromObservation(valid, input, START, Duration.ZERO),
					"clock-generation input");
		}
	}

	@Test
	void healthyTimePreservesBothUtcEndpointsAndEveryNanosecondWithoutRounding() {
		for (Instant value : List.of(Instant.EPOCH, Instant.ofEpochSecond(0, 1),
				Instant.ofEpochSecond(253_402_300_799L), MAXIMUM, START)) {
			Assertions.assertEquals(value, healthy(value, Duration.ZERO).getObservedAt());
		}
		for (Instant value : List.of(Instant.ofEpochSecond(-1, 999_999_999),
				Instant.ofEpochSecond(253_402_300_800L), Instant.MIN, Instant.MAX)) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> healthy(value, Duration.ZERO));
		}
	}

	@Test
	void authorityErrorBoundsAreInclusiveAndProfileValuesStayFixed() {
		for (Duration error : List.of(Duration.ZERO, Duration.ofNanos(1),
				MAXIMUM_ERROR.minusNanos(1), MAXIMUM_ERROR)) {
			StoreTimeObservation.Healthy value = healthy(START, error);
			Assertions.assertEquals(error, value.getMaximumUtcError());
			Assertions.assertEquals(Integer.valueOf(2), value.getMaximumUtcAdvanceRate());
			Assertions.assertEquals(Duration.ofSeconds(5), value.getMaximumWorkerClockOffset());
		}
		for (Duration error : List.of(Duration.ofNanos(-1), Duration.ofSeconds(-1),
				MAXIMUM_ERROR.plusNanos(1), Duration.ofSeconds(Long.MAX_VALUE))) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> healthy(START, error));
		}
	}

	@Test
	void timeUnavailableRetainsOnlyTheActiveDataAdmission() {
		StoreAdmission admission = admission();
		StoreTimeObservation unavailable = StoreTimeObservation.Unavailable.fromAdmission(admission);
		Assertions.assertSame(admission, unavailable.getAdmission());
		Assertions.assertEquals(Set.of("fromAdmission(com.revetsec.StoreAdmission)", "getAdmission()", "toString()"),
				publicMethods(StoreTimeObservation.Unavailable.class));
	}

	@Test
	void temporalConditionsCopyTheObservationTupleAndPreserveExactBounds() {
		StoreTimeObservation.Healthy observation = healthy(START, MAXIMUM_ERROR);
		StoreTemporalCondition condition = StoreTimeAccess.get().fromObservation(
				observation, START.plusNanos(1), START.plusNanos(2));
		Assertions.assertSame(observation.getAdmission(), condition.getAdmission());
		Assertions.assertEquals(observation.getClockGeneration(), condition.getClockGeneration());
		Assertions.assertEquals(START.plusNanos(1), condition.getNotBeforeInclusive());
		Assertions.assertEquals(START.plusNanos(2), condition.getValidBeforeExclusive().orElseThrow());
		StoreTemporalCondition equality = StoreTimeAccess.get().fromObservation(observation, START, null);
		Assertions.assertEquals(START, equality.getNotBeforeInclusive());
		Assertions.assertTrue(equality.getValidBeforeExclusive().isEmpty());
	}

	@Test
	void temporalConditionsRejectEarlierFloorNonIncreasingUpperBoundAndUnsupportedInstants() {
		StoreTimeObservation.Healthy observation = healthy(START, Duration.ZERO);
		StoreTimeAccess.Operations operations = StoreTimeAccess.get();
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> operations.fromObservation(observation, START.minusNanos(1), START.plusSeconds(1)));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> operations.fromObservation(observation, START, START));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> operations.fromObservation(observation, START, START.minusNanos(1)));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> operations.fromObservation(observation, Instant.ofEpochSecond(-1), null));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> operations.fromObservation(observation, START, MAXIMUM.plusNanos(1)));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> operations.fromObservation(observation, MAXIMUM.plusNanos(1), null));
		StoreTemporalCondition lastInstant = operations.fromObservation(healthy(MAXIMUM, Duration.ZERO), MAXIMUM, null);
		Assertions.assertEquals(MAXIMUM, lastInstant.getNotBeforeInclusive());
		Assertions.assertTrue(lastInstant.getValidBeforeExclusive().isEmpty());
		Assertions.assertEquals(MAXIMUM, operations.fromObservation(healthy(Instant.EPOCH, Duration.ZERO),
				MAXIMUM.minusNanos(1), MAXIMUM).getValidBeforeExclusive().orElseThrow());
	}

	@Test
	void completionIsOptionalAndMayEqualOrFollowValidationAtNanosecondPrecision() {
		StoreTimeObservation.Healthy validated = healthy(START, MAXIMUM_ERROR);
		StoreCommitTiming missing = StoreCommitTiming.fromTimes(validated, null);
		Assertions.assertSame(validated, missing.getValidatedTime());
		Assertions.assertTrue(missing.getCompletedTime().isEmpty());
		for (Instant time : List.of(START, START.plusNanos(1), MAXIMUM)) {
			StoreTimeObservation.Healthy completed = healthy(time, MAXIMUM_ERROR);
			StoreCommitTiming timing = StoreCommitTiming.fromTimes(validated, completed);
			Assertions.assertSame(validated, timing.getValidatedTime());
			Assertions.assertSame(completed, timing.getCompletedTime().orElseThrow());
		}
	}

	@Test
	void completionMatchesIdentifierValuesRatherThanAdmissionObjectIdentity() {
		StoreTimeObservation.Healthy validated = healthy(START, MAXIMUM_ERROR);
		StoreAdmission separateButEqualAdmission = StoreAdmission.fromIdentifiers(
				new String(AUTHORITY), new String(RECOVERY));
		StoreTimeObservation.Healthy completed = StoreTimeObservation.Healthy.fromObservation(
				separateButEqualAdmission, new String(GENERATION), START.plusNanos(1), MAXIMUM_ERROR);
		Assertions.assertNotSame(validated.getAdmission(), completed.getAdmission());
		Assertions.assertSame(completed, StoreCommitTiming.fromTimes(validated, completed).getCompletedTime().orElseThrow());
	}

	@Test
	void suppliedCompletionCannotRegressOrMixAnyAdmissionGenerationOrProfileFact() {
		StoreTimeObservation.Healthy validated = healthy(START, MAXIMUM_ERROR);
		List<StoreTimeObservation.Healthy> invalid = List.of(
				healthy(START.minusNanos(1), MAXIMUM_ERROR),
				StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(OTHER, RECOVERY),
						GENERATION, START, MAXIMUM_ERROR),
				StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(AUTHORITY, OTHER),
						GENERATION, START, MAXIMUM_ERROR),
				StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(RECOVERY, AUTHORITY),
						GENERATION, START, MAXIMUM_ERROR),
				StoreTimeObservation.Healthy.fromObservation(admission(), OTHER, START, MAXIMUM_ERROR),
				healthy(START, Duration.ZERO),
				healthy(START, MAXIMUM_ERROR.minusNanos(1)));
		for (StoreTimeObservation.Healthy completed : invalid) {
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> StoreCommitTiming.fromTimes(validated, completed));
		}
		// Invalid supplied completion must be rejected; absence is a deliberate backend choice, not silent rescue.
		Assertions.assertTrue(StoreCommitTiming.fromTimes(validated, null).getCompletedTime().isEmpty());
	}

	@SuppressWarnings("NullAway")
	@Test
	void everyRequiredFactoryAndBridgeArgumentRejectsNullBeforeCreatingAValue() {
		StoreAdmission admission = admission();
		StoreTimeObservation.Healthy observation = healthy(START, Duration.ZERO);
		StoreTimeAccess.Operations operations = StoreTimeAccess.get();
		Assertions.assertThrows(NullPointerException.class,
				() -> StoreAdmission.fromIdentifiers(nullValue(), RECOVERY));
		Assertions.assertThrows(NullPointerException.class,
				() -> StoreAdmission.fromIdentifiers(AUTHORITY, nullValue()));
		Assertions.assertThrows(NullPointerException.class,
				() -> StoreTimeObservation.Healthy.fromObservation(nullValue(), GENERATION, START, Duration.ZERO));
		Assertions.assertThrows(NullPointerException.class,
				() -> StoreTimeObservation.Healthy.fromObservation(admission, nullValue(), START, Duration.ZERO));
		Assertions.assertThrows(NullPointerException.class,
				() -> StoreTimeObservation.Healthy.fromObservation(admission, GENERATION, nullValue(), Duration.ZERO));
		Assertions.assertThrows(NullPointerException.class,
				() -> StoreTimeObservation.Healthy.fromObservation(admission, GENERATION, START, nullValue()));
		Assertions.assertThrows(NullPointerException.class,
				() -> StoreTimeObservation.Unavailable.fromAdmission(nullValue()));
		Assertions.assertThrows(NullPointerException.class,
				() -> operations.fromObservation(nullValue(), START, null));
		Assertions.assertThrows(NullPointerException.class,
				() -> operations.fromObservation(observation, nullValue(), null));
		Assertions.assertThrows(NullPointerException.class,
				() -> StoreCommitTiming.fromTimes(nullValue(), null));
		Assertions.assertThrows(NullPointerException.class, () -> StoreTimeAccess.set(nullValue()));
	}

	@Test
	void allCarrierConstructorsArePrivateAndEveryInstanceFieldIsFinal() {
		for (Class<?> type : carrierClasses()) {
			Assertions.assertFalse(type.isRecord(), type.getName());
			Assertions.assertTrue(Modifier.isFinal(type.getModifiers()), type.getName());
			Assertions.assertTrue(type.getDeclaredConstructors().length > 0, type.getName());
			for (Constructor<?> constructor : type.getDeclaredConstructors())
				Assertions.assertTrue(Modifier.isPrivate(constructor.getModifiers()), constructor.toString());
			for (Field field : type.getDeclaredFields()) {
				if (!Modifier.isStatic(field.getModifiers()))
					Assertions.assertTrue(Modifier.isPrivate(field.getModifiers()) && Modifier.isFinal(field.getModifiers()),
							field.toString());
			}
		}
		Assertions.assertTrue(StoreTimeObservation.class.isSealed());
		Assertions.assertEquals(Set.of(StoreTimeObservation.Healthy.class, StoreTimeObservation.Unavailable.class),
				Set.of(StoreTimeObservation.class.getPermittedSubclasses()));
	}

	@Test
	void exportedCarrierAndInternalBridgeSurfacesMatchTheSelectedAdditiveInventory() {
		Assertions.assertEquals(Set.of("fromIdentifiers(java.lang.String,java.lang.String)",
						"getAuthorityId()", "getRecoveryGeneration()", "toString()"),
				publicMethods(StoreAdmission.class));
		Assertions.assertEquals(Set.of("getAdmission()"), publicMethods(StoreTimeObservation.class));
		Assertions.assertEquals(Set.of("fromObservation(com.revetsec.StoreAdmission,java.lang.String,java.time.Instant,java.time.Duration)",
						"getAdmission()", "getClockGeneration()", "getObservedAt()", "getMaximumUtcError()",
						"getMaximumUtcAdvanceRate()", "getMaximumWorkerClockOffset()", "toString()"),
				publicMethods(StoreTimeObservation.Healthy.class));
		Assertions.assertEquals(Set.of("getAdmission()", "getClockGeneration()", "getNotBeforeInclusive()",
						"getValidBeforeExclusive()", "toString()"), publicMethods(StoreTemporalCondition.class));
		Assertions.assertEquals(Set.of("fromTimes(com.revetsec.StoreTimeObservation$Healthy,com.revetsec.StoreTimeObservation$Healthy)",
						"getValidatedTime()", "getCompletedTime()", "toString()"), publicMethods(StoreCommitTiming.class));
		Assertions.assertEquals(Set.of("set(com.revetsec.internal.StoreTimeAccess$Operations)", "get()"),
				publicMethods(StoreTimeAccess.class));
		Assertions.assertEquals(Set.of("fromObservation(com.revetsec.StoreTimeObservation$Healthy,java.time.Instant,java.time.Instant)"),
				publicMethods(StoreTimeAccess.Operations.class));
		for (Class<?> type : carrierClasses()) {
			for (Method method : type.getDeclaredMethods()) {
				if (Modifier.isPublic(method.getModifiers()))
					Assertions.assertFalse(method.getReturnType().isPrimitive(), method.toString());
			}
			Assertions.assertEquals(0, type.getFields().length, "No public carrier fields: " + type.getName());
		}
	}

	@Test
	void diagnosticsAreFixedAcrossDifferentFactsAndExposeNoIdentifiersOrTimes() {
		StoreAdmission firstAdmission = admission();
		StoreAdmission secondAdmission = StoreAdmission.fromIdentifiers(OTHER, AUTHORITY);
		StoreTimeObservation.Healthy first = healthy(START, Duration.ZERO);
		StoreTimeObservation.Healthy second = StoreTimeObservation.Healthy.fromObservation(
				secondAdmission, RECOVERY, MAXIMUM, MAXIMUM_ERROR);
		StoreTemporalCondition firstCondition = StoreTimeAccess.get().fromObservation(first, START, START.plusSeconds(1));
		StoreTemporalCondition secondCondition = StoreTimeAccess.get().fromObservation(second, MAXIMUM, null);
		List<List<Object>> pairs = List.of(List.of(firstAdmission, secondAdmission), List.of(first, second),
				List.of(StoreTimeObservation.Unavailable.fromAdmission(firstAdmission),
						StoreTimeObservation.Unavailable.fromAdmission(secondAdmission)),
				List.of(firstCondition, secondCondition),
				List.of(StoreCommitTiming.fromTimes(first, null), StoreCommitTiming.fromTimes(second, second)));
		for (List<Object> pair : pairs) {
			String diagnostic = pair.get(0).toString();
			Assertions.assertFalse(diagnostic.isEmpty());
			Assertions.assertEquals(diagnostic, pair.get(1).toString());
			for (String value : List.of(AUTHORITY, RECOVERY, GENERATION, OTHER, START.toString(), MAXIMUM.toString()))
				Assertions.assertFalse(diagnostic.contains(value), "Diagnostic disclosed a carrier fact");
		}
	}

	@Test
	void bridgeRejectsForeignAndDuplicateInstallationsWithoutChangingItsOperations() {
		StoreTimeAccess.Operations installed = StoreTimeAccess.get();
		Assertions.assertThrows(IllegalArgumentException.class, () -> StoreTimeAccess.set(new ForeignOperations()));
		Assertions.assertThrows(IllegalStateException.class, () -> StoreTimeAccess.set(installed));
		Assertions.assertSame(installed, StoreTimeAccess.get());
		Assertions.assertEquals(StoreTemporalCondition.class, installed.getClass().getNestHost());
	}

	@Test
	void getBeforeAnyConditionInitializationIsSafeUnderConcurrentFirstUseInAFreshJvm() throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(FreshJvmMain.class).build().run();
		Assertions.assertFalse(result.isTimedOut(), result::toString);
		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		Assertions.assertTrue(result.getStandardOutput().contains(CHILD_SUCCESS), result::toString);
	}

	private static @NonNull Set<@NonNull String> publicMethods(@NonNull Class<?> type) {
		return Arrays.stream(type.getDeclaredMethods())
				.filter(method -> Modifier.isPublic(method.getModifiers()))
				.map(method -> method.getName() + "(" + Arrays.stream(method.getParameterTypes())
						.map(Class::getName).collect(Collectors.joining(",")) + ")")
				.collect(Collectors.toUnmodifiableSet());
	}

	private static @NonNull List<@NonNull Class<?>> carrierClasses() {
		return List.of(StoreAdmission.class, StoreTimeObservation.Healthy.class, StoreTimeObservation.Unavailable.class,
				StoreTemporalCondition.class, StoreCommitTiming.class);
	}

	private static @NonNull StoreAdmission admission() {
		return StoreAdmission.fromIdentifiers(AUTHORITY, RECOVERY);
	}

	private static StoreTimeObservation.@NonNull Healthy healthy(@NonNull Instant time, @NonNull Duration error) {
		return StoreTimeObservation.Healthy.fromObservation(admission(), GENERATION, time, error);
	}

	private static @NonNull String identifier(int value) {
		byte[] bytes = new byte[32];
		for (int index = 0; index < bytes.length; index++)
			bytes[index] = (byte) (value + index);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}

	private static final class ForeignOperations implements StoreTimeAccess.Operations {
		@Override
		public @NonNull StoreTemporalCondition fromObservation(StoreTimeObservation.@NonNull Healthy observation,
				@NonNull Instant notBeforeInclusive, @Nullable Instant validBeforeExclusive) {
			throw new UnsupportedOperationException("Foreign operations must never be installed");
		}
	}

	/** Fresh-process probe; reflection reads the registration field but never changes or forges operations. */
	public static final class FreshJvmMain {
		private FreshJvmMain() { }

		public static void main(@NonNull String @NonNull [] arguments) throws Exception {
			Field registration = StoreTimeAccess.class.getDeclaredField("operations");
			registration.setAccessible(true);
			Assertions.assertNull(registration.get(null), "condition initialized before first bridge use");
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> StoreTimeAccess.set(new ForeignOperations()));
			Assertions.assertNull(registration.get(null), "foreign registration initialized or installed operations");
			int readers = 16;
			ExecutorService executor = Executors.newFixedThreadPool(readers);
			CountDownLatch ready = new CountDownLatch(readers);
			CountDownLatch start = new CountDownLatch(1);
			List<Future<StoreTimeAccess.Operations>> results = new ArrayList<>();
			try {
				for (int index = 0; index < readers; index++) {
					results.add(executor.submit(() -> {
						ready.countDown();
						Assertions.assertTrue(start.await(10, TimeUnit.SECONDS));
						return StoreTimeAccess.get();
					}));
				}
				Assertions.assertTrue(ready.await(10, TimeUnit.SECONDS));
				start.countDown();
				StoreTimeAccess.Operations installed = results.get(0).get(10, TimeUnit.SECONDS);
				for (Future<StoreTimeAccess.Operations> result : results)
					Assertions.assertSame(installed, result.get(10, TimeUnit.SECONDS));
				Assertions.assertEquals(StoreTemporalCondition.class, installed.getClass().getNestHost());
				Assertions.assertThrows(IllegalStateException.class, () -> StoreTimeAccess.set(installed));
				StoreTimeObservation.Healthy observation = healthy(START, Duration.ZERO);
				StoreTemporalCondition condition = installed.fromObservation(observation, START, null);
				Assertions.assertEquals(START, condition.getNotBeforeInclusive());
				Assertions.assertTrue(condition.getValidBeforeExclusive().isEmpty());
				Assertions.assertSame(installed, StoreTimeAccess.get());
			} finally {
				start.countDown();
				executor.shutdownNow();
				Assertions.assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
			}
			System.out.println(CHILD_SUCCESS);
		}
	}
}
