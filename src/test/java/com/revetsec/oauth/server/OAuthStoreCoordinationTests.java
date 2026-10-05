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

package com.revetsec.oauth.server;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.http.Deadline;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.LockSupport;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthStoreFailure.Reason.*;

/** Two-coordinator controlled interleavings; no durable multi-node/process-crash backend proof. */
class OAuthStoreCoordinationTests {
	private static final @NonNull Instant NOW = Instant.parse("2026-10-04T00:00:00.123456789Z");
	private static final @NonNull String NONCE = "A".repeat(43);
	private static final @NonNull String ISSUER = "https://issuer.example/tenant";
	private final @NonNull OAuthAtomicStoreFixture store = new OAuthAtomicStoreFixture();
	private final @NonNull MutableClock clock = new MutableClock(NOW);
	private final @NonNull OAuthStoreRecordCodec codec = codec(ISSUER);
	private final @NonNull OAuthStoreCoordinator first = coordinator(3);
	private final @NonNull OAuthStoreCoordinator second = coordinator(3);
	OAuthStoreCoordinationTests() { }
	private static @NonNull OAuthStoreRecordCodec codec(@NonNull String issuer) {
		byte[] bytes = new byte[32]; for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (i + 1);
		StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("k", Base64.getEncoder().encodeToString(bytes)))
			.clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
		return new OAuthStoreRecordCodec(issuer, sealer, 3800);
	}
	private @NonNull OAuthStoreCoordinator coordinator(int attempts) {
		return new OAuthStoreCoordinator(this.store, this.codec, this.clock, attempts, 255);
	}
	private static @NonNull Deadline deadline() { return Deadline.fromNow(Duration.ofSeconds(10)); }
	private void initialized() { assertEquals(OAuthStoreCommitStatus.COMMITTED, this.first.initializeFreshIssuer(deadline())); }
	private @NonNull OAuthStoreFence issuer() { return this.second.begin(deadline()).issuer(); }
	private void putIssuer(@NonNull String payload) {
		this.store.rows.put(this.codec.issuerKey(), this.codec.seal(this.codec.issuerKey(), OAuthStoreFormat.PERMANENT, payload));
	}
	private static void failed(OAuthStoreFailure.@NonNull Reason reason, @NonNull Executable operation) {
		OAuthStoreFailure failure = assertThrows(OAuthStoreFailure.class, operation);
		assertEquals(reason, failure.reason()); assertEquals("OAuth server store operation failed.", failure.getMessage());
		assertNull(failure.getCause()); assertEquals(0, failure.getSuppressed().length);
		failure.addSuppressed(new IllegalStateException("secret")); assertEquals(0, failure.getSuppressed().length);
	}
	private static @NonNull OAuthStoreEntry required(@NonNull Optional<@NonNull OAuthStoreEntry> entry) { return entry.orElseThrow(); }
	private @NonNull OAuthStoreKey key(int number) {
		return this.codec.key(OAuthStoreKey.Kind.CODE, "A".repeat(41) + "ABCDEFGHIJKLMNOPQRSTUVWXYZ".charAt(number) + "A");
	}
	private @NonNull OAuthStoreEntry finite(@NonNull OAuthStoreKey key) {
		return this.codec.seal(key, NOW.plusSeconds(100).minusNanos(123456789), "{}");
	}

	@Test void missingIssuerFailsClosedWithoutInitializing() {
		failed(CORRUPT_STATE, () -> this.first.begin(deadline())); assertEquals(0, this.store.commits); assertTrue(this.store.rows.isEmpty());
	}
	@Test void explicitFreshInitializationAndWarmReconstruction() {
		initialized(); OAuthStoreFence fence = issuer(); assertEquals(0, fence.epoch()); assertEquals(NOW, fence.highWater());
		assertEquals(OAuthStoreFormat.PERMANENT, requireNonNull(this.store.rows.get(this.codec.issuerKey())).getRetainUntil());
		OAuthStoreCoordinator restarted = coordinator(3); assertEquals(fence.incarnation(), restarted.begin(deadline()).issuer().incarnation());
		assertEquals(OAuthStoreCommitStatus.CONFLICT, restarted.initializeFreshIssuer(deadline())); assertEquals(1, this.store.commits);
	}
	@Test void competingFreshInitializationCannotOverwriteWinner() {
		this.store.beforeCommit = () -> assertEquals(OAuthStoreCommitStatus.COMMITTED, this.second.initializeFreshIssuer(deadline()));
		assertEquals(OAuthStoreCommitStatus.CONFLICT, this.first.initializeFreshIssuer(deadline())); assertEquals(1, this.store.rows.size());
	}
	@Test void deletedEstablishedIssuerCannotBeRecreatedByNormalTraffic() {
		initialized(); this.store.rows.clear(); failed(CORRUPT_STATE, () -> this.second.revokeAll(deadline()));
		failed(CORRUPT_STATE, () -> this.second.establishNewSubject("subject", deadline())); assertTrue(this.store.rows.isEmpty());
	}
	@Test void subjectCreationRequiresIssuerAndIsStableAcrossInstances() {
		initialized(); OAuthStoreFence original = this.first.establishNewSubject("subject", deadline());
		OAuthStoreFence copy = this.second.establishNewSubject("subject", deadline());
		assertEquals(original.incarnation(), copy.incarnation()); assertEquals(0, copy.epoch());
		assertEquals(original.incarnation(), this.first.begin(deadline()).subject("subject").incarnation());
		assertEquals(OAuthStoreFormat.PERMANENT, requireNonNull(this.store.rows.get(this.codec.subjectKey("subject"))).getRetainUntil());
		assertEquals(List.of(), requireNonNull(this.store.lastTransaction).getMutations());
	}
	@Test void simultaneousSubjectCreationReloadsTheWinningIncarnation() {
		initialized(); this.store.beforeCommit = () -> this.second.establishNewSubject("subject", deadline());
		OAuthStoreFence result = this.first.establishNewSubject("subject", deadline());
		assertEquals(result.incarnation(), this.second.begin(deadline()).subject("subject").incarnation());
		assertEquals(0, result.epoch()); assertEquals(2, this.store.rows.size());
	}
	@Test void missingEstablishedSubjectNeverBecomesEpochZero() {
		initialized(); failed(CORRUPT_STATE, () -> this.first.begin(deadline()).subject("subject"));
		failed(CORRUPT_STATE, () -> this.first.revokeSubject("subject", deadline())); assertEquals(1, this.store.rows.size());
		this.first.establishNewSubject("subject", deadline()); this.store.rows.remove(this.codec.subjectKey("subject"));
		failed(CORRUPT_STATE, () -> this.second.revokeSubject("subject", deadline()));
	}
	@Test void issuerRevocationAdvancesEpochAndClockWithoutChangingIncarnation() {
		initialized(); String incarnation = issuer().incarnation(); this.clock.time = NOW.plusNanos(1);
		assertEquals(1, this.first.revokeAll(deadline()).epoch()); assertEquals(2, this.second.revokeAll(deadline()).epoch());
		assertEquals(incarnation, issuer().incarnation()); assertEquals(this.clock.time, issuer().highWater());
	}
	@Test void racingIssuerRevocationsReloadAndBothAdvanceExactlyOnce() {
		initialized(); this.store.beforeCommit = () -> assertEquals(1, this.second.revokeAll(deadline()).epoch());
		assertEquals(2, this.first.revokeAll(deadline()).epoch()); assertEquals(2, issuer().epoch());
	}
	@Test void subjectRevocationAdvancesOnlySelectedSubjectWithClockFence() {
		initialized(); OAuthStoreFence a = this.first.establishNewSubject("a", deadline());
		this.first.establishNewSubject("b", deadline()); this.clock.time = NOW.plusSeconds(10);
		assertEquals(1, this.first.revokeSubject("a", deadline()).epoch());
		assertEquals(a.incarnation(), this.second.begin(deadline()).subject("a").incarnation());
		assertEquals(0, this.second.begin(deadline()).subject("b").epoch()); assertEquals(0, issuer().epoch());
		assertEquals(this.clock.time, issuer().highWater()); assertEquals(2, requireNonNull(this.store.lastTransaction).getConditions().size());
	}
	@Test void racingSubjectRevocationsAdvanceTwiceWithoutLosingWrites() {
		initialized(); this.first.establishNewSubject("a", deadline());
		this.store.beforeCommit = () -> assertEquals(1, this.second.revokeSubject("a", deadline()).epoch());
		assertEquals(2, this.first.revokeSubject("a", deadline()).epoch());
		assertEquals(2, this.second.begin(deadline()).subject("a").epoch());
	}
	@Test void issuerRevocationConflictsWithPendingSubjectTransition() {
		initialized(); this.first.establishNewSubject("a", deadline());
		this.store.beforeCommit = () -> this.second.revokeAll(deadline());
		assertEquals(1, this.first.revokeSubject("a", deadline()).epoch()); assertEquals(1, issuer().epoch());
	}
	@Test void statusBarrierIncludesIssuerSubjectLedgerAndAbsence() {
		initialized(); this.first.establishNewSubject("a", deadline()); OAuthStoreKey present = key(0), absent = key(1);
		this.store.rows.put(present, finite(present)); OAuthStoreCoordinator.Session status = this.first.begin(deadline());
		status.subject("a"); status.read(present); status.read(absent);
		OAuthStoreEntry issuerBefore = requireNonNull(this.store.rows.get(this.codec.issuerKey()));
		assertEquals(OAuthStoreCommitStatus.COMMITTED, status.barrier());
		assertEquals(4, requireNonNull(this.store.lastTransaction).getConditions().size()); assertTrue(requireNonNull(this.store.lastTransaction).getMutations().isEmpty());
		assertSame(issuerBefore, requireNonNull(this.store.rows.get(this.codec.issuerKey())));
		assertEquals(Optional.empty(), requireNonNull(this.store.lastTransaction).getConditions().stream().filter(c -> c.getKey().equals(absent)).findFirst().orElseThrow().getExpectedVersion());
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> changesToEveryObservedRowConflictWithStatusAdmission() {
		return Stream.of("issuer", "subject", "present", "absent").map(which -> DynamicTest.dynamicTest(which, () -> {
			initialized(); this.first.establishNewSubject("a", deadline()); OAuthStoreKey present = key(0), absent = key(1);
			this.store.rows.put(present, finite(present)); OAuthStoreCoordinator.Session pending = this.first.begin(deadline());
			pending.subject("a"); pending.read(present); pending.read(absent);
			this.store.beforeCommit = () -> { switch (which) {
				case "issuer" -> this.second.revokeAll(deadline());
				case "subject" -> this.second.revokeSubject("a", deadline());
				case "present" -> this.store.rows.put(present, finite(present));
				default -> this.store.rows.put(absent, finite(absent));
			} };
			assertEquals(OAuthStoreCommitStatus.CONFLICT, pending.barrier());
			assertThrows(IllegalStateException.class, pending::barrier);
			// Dynamic cases share one instance: reset only the fixture after verifying this case.
			this.store.rows.clear(); this.store.commits = 0;
		}));
	}
	@Test void alreadyAdmittedWorkIsNotRolledBackByLaterRevocation() {
		initialized(); this.first.establishNewSubject("a", deadline()); OAuthStoreCoordinator.Session admitted = this.first.begin(deadline());
		admitted.subject("a"); assertEquals(OAuthStoreCommitStatus.COMMITTED, admitted.barrier());
		this.second.revokeSubject("a", deadline()); assertEquals(1, this.first.begin(deadline()).subject("a").epoch());
	}
	@Test void transactionConflictRejectsAllWritesIncludingClockUpdate() {
		initialized(); OAuthStoreKey a = key(0), b = key(1); OAuthStoreCoordinator.Session attempt = this.first.begin(deadline());
		attempt.read(a); attempt.read(b); OAuthStoreEntry issuerBefore = requireNonNull(this.store.rows.get(this.codec.issuerKey()));
		this.store.rows.put(b, finite(b)); this.clock.time = NOW.plusSeconds(10);
		assertEquals(OAuthStoreCommitStatus.CONFLICT, attempt.commit(List.of(
			OAuthStoreTransaction.Mutation.fromPut(finite(a)), OAuthStoreTransaction.Mutation.fromPut(finite(b)))));
		assertFalse(this.store.rows.containsKey(a)); assertSame(issuerBefore, requireNonNull(this.store.rows.get(this.codec.issuerKey())));
	}
	@Test void multiRowCommitIncludesCompleteConditionsAndChangesClockAtomically() {
		initialized(); OAuthStoreKey a = key(0), b = key(1); this.store.rows.put(b, finite(b));
		OAuthStoreCoordinator.Session attempt = this.first.begin(deadline()); attempt.read(a); attempt.read(b);
		this.clock.time = NOW.plusSeconds(1);
		assertEquals(OAuthStoreCommitStatus.COMMITTED, attempt.commit(List.of(
			OAuthStoreTransaction.Mutation.fromPut(finite(a)), OAuthStoreTransaction.Mutation.fromRemove(b))));
		assertTrue(this.store.rows.containsKey(a)); assertFalse(this.store.rows.containsKey(b));
		assertEquals(3, requireNonNull(this.store.lastTransaction).getConditions().size()); assertEquals(3, requireNonNull(this.store.lastTransaction).getMutations().size());
		assertEquals(this.clock.time, issuer().highWater());
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> unknownStopsWithoutRetryRegardlessOfBackendEffects() {
		return Stream.of("before", "after").map(when -> DynamicTest.dynamicTest(when, () -> {
			initialized(); int commits = this.store.commits;
			this.store.unknownBefore = when.equals("before"); this.store.unknownAfter = when.equals("after");
			failed(COMMIT_OUTCOME_UNKNOWN, () -> this.first.revokeAll(deadline())); assertEquals(commits + 1, this.store.commits);
			this.store.unknownBefore = false; this.store.unknownAfter = false;
			assertEquals(when.equals("after") ? 1 : 0, issuer().epoch());
			OAuthStoreCoordinator.Session attempt = this.first.begin(deadline());
			this.store.unknownAfter = true; failed(COMMIT_OUTCOME_UNKNOWN, attempt::barrier);
			assertThrows(IllegalStateException.class, attempt::barrier);
			this.store.unknownAfter = false; this.store.rows.clear(); this.store.commits = 0;
		}));
	}
	@Test void unknownSubjectRevocationIsNonIdempotentAndRequiresReconciliation() {
		initialized(); this.first.establishNewSubject("a", deadline()); int before = this.store.commits;
		this.store.unknownAfter = true; failed(COMMIT_OUTCOME_UNKNOWN, () -> this.first.revokeSubject("a", deadline()));
		assertEquals(before + 1, this.store.commits); this.store.unknownAfter = false;
		assertEquals(1, this.second.begin(deadline()).subject("a").epoch());
	}
	@Test void unknownFreshInitializationNeverRetries() {
		this.store.unknownAfter = true; failed(COMMIT_OUTCOME_UNKNOWN, () -> this.first.initializeFreshIssuer(deadline()));
		assertEquals(1, this.store.commits); this.store.unknownAfter = false; assertEquals(0, issuer().epoch());
	}
	@Test void conflictAttemptsAreBoundedAndBudgetsNeverReset() {
		initialized(); this.store.budgets.clear(); this.store.conflicts = 10; int before = this.store.commits;
		failed(UNAVAILABLE, () -> this.first.revokeAll(deadline())); assertEquals(before + 3, this.store.commits);
		for (int i = 1; i < this.store.budgets.size(); i++)
			assertTrue(this.store.budgets.get(i).compareTo(this.store.budgets.get(i - 1)) <= 0);
		assertEquals(0, issuer().epoch());
	}
	@Test void exhaustionAfterConflictCannotStartAnotherAttempt() {
		initialized(); Deadline shortBudget = Deadline.fromNow(Duration.ofMillis(100)); this.store.conflicts = 1;
		this.store.beforeCommit = () -> { while (!shortBudget.isExpired()) LockSupport.parkNanos(100000); };
		int reads = this.store.reads, commits = this.store.commits;
		failed(UNAVAILABLE, () -> this.first.revokeAll(shortBudget)); assertEquals(commits + 1, this.store.commits);
		assertEquals(reads + 1, this.store.reads);
	}
	@Test void expiredBudgetPreventsReadAndInitialization() {
		failed(UNAVAILABLE, () -> this.first.initializeFreshIssuer(Deadline.fromNow(Duration.ZERO)));
		failed(UNAVAILABLE, () -> this.first.begin(Deadline.fromNow(Duration.ZERO))); assertEquals(0, this.store.reads);
	}
	@Test void callbackExhaustionIsCheckedOnReturn() {
		Deadline shortBudget = Deadline.fromNow(Duration.ofMillis(100));
		this.store.beforeRead = () -> { while (!shortBudget.isExpired()) LockSupport.parkNanos(100000); };
		failed(UNAVAILABLE, () -> this.first.initializeFreshIssuer(shortBudget)); assertEquals(0, this.store.commits);
	}
	@Test void committedButOverBudgetNeverReportsSuccessOrRetries() {
		initialized(); Deadline shortBudget = Deadline.fromNow(Duration.ofMillis(100));
		this.store.afterCommit = () -> { while (!shortBudget.isExpired()) LockSupport.parkNanos(100000); };
		int commits = this.store.commits; failed(UNAVAILABLE, () -> this.first.revokeAll(shortBudget));
		assertEquals(commits + 1, this.store.commits); assertEquals(1, issuer().epoch());
	}
	@Test void unknownRetainsClassificationAfterBudgetExhaustion() {
		initialized(); Deadline shortBudget = Deadline.fromNow(Duration.ofMillis(100)); this.store.unknownAfter = true;
		this.store.afterCommit = () -> { while (!shortBudget.isExpired()) LockSupport.parkNanos(100000); };
		failed(COMMIT_OUTCOME_UNKNOWN, () -> this.first.revokeAll(shortBudget));
	}
	@Test void clocksBehindPersistedHighWaterFailIncludingWithinOneSecond() {
		initialized(); this.clock.time = NOW.minusNanos(1); failed(UNAVAILABLE, () -> this.second.begin(deadline()));
		this.clock.time = NOW; assertEquals(OAuthStoreCommitStatus.COMMITTED, this.second.begin(deadline()).barrier());
	}
	@Test void clockRollbackDuringPreparationOrCallbackNeverReleasesSuccess() {
		initialized(); OAuthStoreCoordinator.Session attempt = this.first.begin(deadline()); this.clock.time = NOW.minusSeconds(1);
		int commits = this.store.commits; failed(UNAVAILABLE, attempt::barrier); assertEquals(commits, this.store.commits);
		this.clock.time = NOW; this.store.afterCommit = () -> this.clock.time = NOW.minusNanos(1);
		failed(UNAVAILABLE, () -> this.second.revokeAll(deadline())); this.clock.time = NOW; assertEquals(1, issuer().epoch());
	}
	@Test void repeatedReadsRemainOneObservedVersionAndOneBackendRead() {
		initialized(); OAuthStoreKey key = key(0); this.store.rows.put(key, finite(key)); OAuthStoreCoordinator.Session attempt = this.first.begin(deadline());
		OAuthStoreEntry old = required(attempt.read(key)); int reads = this.store.reads; this.store.rows.put(key, finite(key));
		assertSame(old, required(attempt.read(key))); assertEquals(reads, this.store.reads);
		assertEquals(OAuthStoreCommitStatus.CONFLICT, attempt.barrier());
	}
	@Test void sessionCannotBeReusedAfterCommitOrConflict() {
		initialized(); OAuthStoreCoordinator.Session attempt = this.first.begin(deadline());
		assertEquals(OAuthStoreCommitStatus.COMMITTED, attempt.commit(List.of()));
		assertThrows(IllegalStateException.class, () -> attempt.read(key(0))); assertThrows(IllegalStateException.class, attempt::issuer);
		assertThrows(IllegalStateException.class, attempt::effectiveNow);
	}
	@Test void conditionAndMutationBoundsReserveIssuerFenceSlot() {
		initialized(); OAuthStoreCoordinator.Session attempt = this.first.begin(deadline());
		for (int i = 0; i < 15; i++) attempt.read(key(i)); int reads = this.store.reads;
		assertThrows(IllegalArgumentException.class, () -> attempt.read(key(15))); assertEquals(reads, this.store.reads);
		List<OAuthStoreTransaction.Mutation> seven = java.util.stream.IntStream.range(0, 7)
			.mapToObj(i -> OAuthStoreTransaction.Mutation.fromPut(finite(key(i)))).toList();
		assertEquals(OAuthStoreCommitStatus.COMMITTED, attempt.commit(seven)); assertEquals(8, requireNonNull(this.store.lastTransaction).getMutations().size());
		OAuthStoreCoordinator.Session bad = this.first.begin(deadline());
		assertThrows(IllegalArgumentException.class, () -> bad.commit(Stream.concat(seven.stream(), seven.stream().limit(1)).toList()));
		assertThrows(IllegalArgumentException.class, () -> bad.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(requireNonNull(this.store.rows.get(this.codec.issuerKey()))))));
	}
	@Test void foreignNamespaceRejectedBeforeBackendLookup() {
		initialized(); OAuthStoreCoordinator.Session attempt = this.first.begin(deadline()); int reads = this.store.reads;
		assertThrows(IllegalArgumentException.class, () -> attempt.read(codec("https://other.example").issuerKey()));
		assertEquals(reads, this.store.reads);
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> subjectInputBoundsAreCheckedBeforeStorage() {
		return Stream.of("", "a".repeat(256), "bad\nsubject", "\ud800").map(value -> DynamicTest.dynamicTest("invalid-subject-" + value.length(), () -> {
			assertThrows(IllegalArgumentException.class, () -> this.first.establishNewSubject(value, deadline())); assertEquals(0, this.store.reads);
		}));
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> coordinatorSettingsHaveExactBounds() {
		return Stream.of(0, 9, -1).map(value -> DynamicTest.dynamicTest("attempts-" + value, () ->
			assertThrows(IllegalArgumentException.class, () -> coordinator(value))));
	}
	@Test void subjectSettingAndInclusiveValidSettings() {
		assertThrows(IllegalArgumentException.class, () -> new OAuthStoreCoordinator(this.store, this.codec, this.clock, 1, 15));
		assertThrows(IllegalArgumentException.class, () -> new OAuthStoreCoordinator(this.store, this.codec, this.clock, 8, 1025));
		initialized(); new OAuthStoreCoordinator(this.store, this.codec, this.clock, 8, 1024).establishNewSubject("a".repeat(1024), deadline());
		assertEquals(NOW, coordinator(1).begin(deadline()).effectiveNow());
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> authenticatedMalformedIssuerPayloadsAreConfigurationFaults() {
		String good = OAuthStoreFence.initialIssuer(NONCE, NOW).toPayload();
		return Stream.of("{}", good.replace("\"schema\":1", "\"schema\":2"), good.replace("\"schema\":1", "\"schema\":null"),
			good.replace("\"epoch\":0", "\"epoch\":-1"), good.replace("\"epoch\":0", "\"epoch\":1.5"),
			good.replace("\"epoch\":0", "\"epoch\":\"0\""), good.replace("\"epoch\":0", "\"epoch\":9223372036854775808"),
			good.replace(NONCE, "bad"), good.replace(NONCE, "A".repeat(42) + "B"),
			good.replace("123456789", "1000000000"), good.replace("123456789", "-1"),
			good.replace("123456789", "null"), good.replace("1791072000", "9223372036854775807"),
			good.replace("\"epoch\":0", "\"extra\":true,\"epoch\":0"),
			OAuthStoreFence.initialSubject(NONCE).toPayload()).distinct().map(payload -> DynamicTest.dynamicTest("invalid-issuer-" + payload.hashCode(), () -> {
				putIssuer(payload); failed(CORRUPT_STATE, () -> this.first.begin(deadline())); assertEquals(0, this.store.commits);
			}));
	}
	@Test void epochOverflowFailsBeforeAnyCommit() {
		putIssuer(OAuthStoreFence.initialIssuer(NONCE, NOW).toPayload().replace("\"epoch\":0", "\"epoch\":" + Long.MAX_VALUE));
		failed(CORRUPT_STATE, () -> this.first.revokeAll(deadline())); assertEquals(0, this.store.commits);
		this.store.rows.put(this.codec.subjectKey("a"), this.codec.seal(this.codec.subjectKey("a"), OAuthStoreFormat.PERMANENT,
			OAuthStoreFence.initialSubject(NONCE).toPayload().replace("\"epoch\":0", "\"epoch\":" + Long.MAX_VALUE)));
		failed(CORRUPT_STATE, () -> this.first.revokeSubject("a", deadline())); assertEquals(0, this.store.commits);
	}
	@Test void subjectSchemaDoesNotAcceptIssuerFieldsOrUnknownKind() {
		initialized(); this.store.rows.put(this.codec.subjectKey("a"), this.codec.seal(this.codec.subjectKey("a"), OAuthStoreFormat.PERMANENT,
			OAuthStoreFence.initialIssuer(NONCE, NOW).toPayload()));
		failed(CORRUPT_STATE, () -> this.first.begin(deadline()).subject("a"));
		assertThrows(IllegalArgumentException.class, () -> OAuthStoreFence.initialSubject(NONCE).atTime(NOW));
	}
	@Test void envelopeCorruptionOrBackendKeySubstitutionNeverBecomesAbsence() {
		initialized(); OAuthStoreEntry old = requireNonNull(this.store.rows.get(this.codec.issuerKey()));
		this.store.rows.put(old.getKey(), OAuthStoreEntry.fromStoredForm(old.getKey(), old.getVersion(), old.getRetainUntil(), "broken"));
		failed(CORRUPT_STATE, () -> this.second.begin(deadline()));
		this.store.substitute = finite(key(0)); failed(CORRUPT_STATE, () -> this.second.begin(deadline()));
		assertEquals(1, this.store.commits);
	}
	@TestFactory @NonNull Stream<@NonNull DynamicTest> nonfatalInfrastructureFailuresAreFixedAndNeverRetried() {
		return Stream.of(new IllegalStateException("secret-row"), new AssertionError("secret-row"), new LinkageError("secret-row"))
			.map(fault -> DynamicTest.dynamicTest(fault.getClass().getSimpleName(), () -> {
				this.store.fault = fault; failed(UNAVAILABLE, () -> this.first.initializeFreshIssuer(deadline())); assertEquals(0, this.store.commits);
			}));
	}
	@Test void commitFailureNeverAutomaticallyRepeatsAnOperation() {
		initialized(); this.store.beforeCommit = () -> this.store.fault = new IllegalStateException("secret"); int commits = this.store.commits;
		failed(UNAVAILABLE, () -> this.first.revokeAll(deadline())); assertEquals(commits + 1, this.store.commits);
	}
	@Test void nullSpiReturnsAreUnavailable() {
		this.store.nullRead = true; failed(UNAVAILABLE, () -> this.first.initializeFreshIssuer(deadline()));
		this.store.nullRead = false; initialized(); this.store.nullCommit = true;
		failed(UNAVAILABLE, () -> this.first.revokeAll(deadline()));
	}
	@Test void interruptedCallbackRestoresFlagAndExistingInterruptionPreventsWork() {
		try {
			this.store.fault = new InterruptedException("secret"); failed(UNAVAILABLE, () -> this.first.initializeFreshIssuer(deadline()));
			assertTrue(Thread.currentThread().isInterrupted()); int reads = this.store.reads; this.store.fault = null;
			failed(UNAVAILABLE, () -> this.first.initializeFreshIssuer(deadline())); assertEquals(reads, this.store.reads);
		} finally { Thread.interrupted(); }
	}
	@Test void interruptionDuringCommitPreventsSuccessAndKeepsFlag() {
		initialized(); this.store.afterCommit = () -> Thread.currentThread().interrupt();
		try { failed(UNAVAILABLE, () -> this.first.revokeAll(deadline())); assertTrue(Thread.currentThread().isInterrupted()); }
		finally { Thread.interrupted(); }
		assertEquals(1, issuer().epoch());
	}
	@Test void fatalVmErrorsPropagateAsTheSameInstance() {
		VirtualMachineError fatal = new OutOfMemoryError("synthetic"); this.store.fault = fatal;
		assertSame(fatal, assertThrows(VirtualMachineError.class, () -> this.first.initializeFreshIssuer(deadline())));
		this.store.fault = null; initialized(); this.store.beforeCommit = () -> this.store.fault = fatal;
		assertSame(fatal, assertThrows(VirtualMachineError.class, () -> this.first.revokeAll(deadline())));
	}
	@Test void subjectConflictExhaustionDoesNotPretendInitializationOrRevocationSucceeded() {
		initialized(); this.store.conflicts = 8; failed(UNAVAILABLE, () -> this.first.establishNewSubject("a", deadline()));
		assertFalse(this.store.rows.containsKey(this.codec.subjectKey("a"))); this.store.conflicts = 0;
		this.first.establishNewSubject("a", deadline()); this.store.conflicts = 8;
		failed(UNAVAILABLE, () -> this.first.revokeSubject("a", deadline()));
		assertEquals(0, this.second.begin(deadline()).subject("a").epoch());
	}
	@Test void invalidClockAndClockCallbackFaultsFailClosed() {
		initialized(); this.clock.time = OAuthStoreFormat.PERMANENT; failed(UNAVAILABLE, () -> this.first.begin(deadline()));
		this.clock.time = NOW; this.clock.fault = new IllegalStateException("secret");
		failed(UNAVAILABLE, () -> this.first.begin(deadline())); this.clock.fault = new InterruptedException("secret");
		try { failed(UNAVAILABLE, () -> this.first.begin(deadline())); assertTrue(Thread.currentThread().isInterrupted()); }
		finally { Thread.interrupted(); }
		this.clock.fault = new OutOfMemoryError("synthetic");
		assertSame(this.clock.fault, assertThrows(VirtualMachineError.class, () -> this.first.begin(deadline())));
		this.clock.fault = null; this.clock.nullResult = true; failed(UNAVAILABLE, () -> this.first.begin(deadline()));
	}
	@Test void fenceKindTimeAndPermanentBoundaryChecks() {
		assertThrows(IllegalArgumentException.class, () -> OAuthStoreFence.initialIssuer(NONCE, OAuthStoreFormat.PERMANENT));
		assertThrows(IllegalArgumentException.class, () -> OAuthStoreFence.initialIssuer(NONCE, NOW).atTime(NOW.minusNanos(1)));
		OAuthStoreEntry row = finite(key(0));
		assertThrows(IllegalArgumentException.class, () -> OAuthStoreFence.decode(this.codec.open(row, this.clock), OAuthStoreKey.Kind.CODE));
	}
	@Test void unobservedMutationsCannotBeSubmitted() {
		initialized(); OAuthStoreCoordinator.Session attempt = this.first.begin(deadline()); int commits = this.store.commits;
		assertThrows(IllegalArgumentException.class, () -> attempt.commit(List.of(OAuthStoreTransaction.Mutation.fromPut(finite(key(0))))));
		assertEquals(commits, this.store.commits); assertThrows(IllegalStateException.class, attempt::barrier);
	}
	@Test void stateDiagnosticsAreFixed() {
		initialized(); assertEquals("OAuthStoreFence{state=<redacted>}", issuer().toString());
	}
	private static final class MutableClock extends Clock {
		private @NonNull Instant time;
		private @Nullable Throwable fault;
		private boolean nullResult;
		private MutableClock(@NonNull Instant time) { this.time = time; }
		@Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
		@Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return Clock.fixed(this.time, zone); }
		@Override @SuppressWarnings("NullAway") // Intentionally invalid Clock to exercise trusted callback checks.
		public @NonNull Instant instant() {
			if (this.fault != null) raise(this.fault);
			return this.nullResult ? null : this.time;
		}
		@SuppressWarnings("unchecked")
		private static <T extends Throwable> void raise(@NonNull Throwable failure) throws T { throw (T) failure; }
	}
}
