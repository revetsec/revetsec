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

package com.revetsec.totp;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.crypto.TotpPrimitives;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** Contextual acknowledgements and retry identity over actual engine-generated transactions. */
final class TotpSharedClockReceiptTests {
	private static final @NonNull Instant BASE = Instant.ofEpochSecond(1700000010);
	private static final @NonNull String NAMESPACE = "receipt-tests", EPOCH = "epoch-one", ACCOUNT = "account-a";

	@Test void missingRequiredTimingPreservesKnownCommitWithoutReadRescue() {
		F f = new F();
		f.store.after = (number, write, receipt) -> {
			// Public factories forbid this shape; deliberately simulate a malformed backend reply.
			corrupt(receipt, "timing", null);
			return receipt;
		};
		assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class, f.begin());
		assertEquals(1, f.store.writes.size());
		assertEquals(1, f.store.reads);
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertNotNull(Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending)); }
	}

	@Test void regressedRequiredValidationPreservesKnownCommit() {
		F f = new F();
		f.store.after = (number, write, receipt) -> committed(at(write, BASE.minusNanos(1)), null);
		assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class, f.begin());
		assertEquals(1, f.store.writes.size());
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertNotNull(Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending)); }
	}

	@Test void foreignRequiredValidationProfilePreservesKnownCommit() {
		F f = new F();
		f.store.after = (number, write, receipt) -> {
			StoreTimeObservation.Healthy prior = healthy(write);
			return committed(StoreTimeObservation.Healthy.fromObservation(prior.getAdmission(), prior.getClockGeneration(),
					prior.getObservedAt(), Duration.ofMillis(1)), null);
		};
		assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class, f.begin());
		assertEquals(1, f.store.writes.size());
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertNotNull(Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending)); }
	}

	@Test void malformedRegressedCompletionPreservesKnownCommit() {
		F f = new F();
		f.store.after = (number, write, receipt) -> {
			StoreCommitTiming timing = receipt.getTiming().orElseThrow();
			// StoreCommitTiming rejects this through its public factory.
			corrupt(timing, "completedTime", at(write, BASE.minusNanos(1)));
			return receipt;
		};
		assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class, f.begin());
		assertEquals(1, f.store.writes.size());
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertNotNull(Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending)); }
	}

	@Test void absentOptionalCompletionIsRescuedByFreshFinalRead() {
		F f = new F();
		f.store.after = (number, write, receipt) -> {
			assertTrue(receipt.getTiming().orElseThrow().getCompletedTime().isEmpty());
			return receipt;
		};
		assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class, f.begin());
		assertEquals(1, f.store.writes.size());
		assertEquals(2, f.store.reads);
		assertEquals(Set.of(f.root()), f.store.lastRead);
	}

	@Test void finalReadCannotRegressBelowUsableCompletion() {
		F f = new F();
		f.store.after = (number, write, receipt) -> committed(healthy(write), at(write, BASE.plusMillis(1)));
		assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class, f.begin());
		assertEquals(2, f.store.reads);
		assertEquals(1, f.store.writes.size());
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertNotNull(Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending)); }
	}

	@Test void finalReadAtUsableCompletionAllowsRelease() {
		F f = new F();
		f.store.after = (number, write, receipt) -> {
			f.advance(Duration.ofMillis(1));
			return committed(healthy(write), at(write, f.source.authorityTime()));
		};
		assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class, f.begin());
		assertEquals(2, f.store.reads);
		assertEquals(1, f.store.writes.size());
	}

	@Test void conflictsKeepOneChargeIdentityAndOriginalMatchedStep() {
		F f = new F(); f.enroll(); f.advance(Duration.ofSeconds(60)); f.reset();
		String code = f.code(0);
		long matched = f.source.authorityTime().getEpochSecond() / 30;
		List<String> chargeIds = new ArrayList<>(); List<Instant> upperBounds = new ArrayList<>();
		f.store.before = (number, write) -> {
			upperBounds.add(write.getTemporalCondition().getValidBeforeExclusive().orElseThrow());
			try (TotpRecordsV3.Decoded decoded = f.open(write.getMutations().get(0).getRecord())) {
				if (number <= 2) {
					assertEquals(1, Objects.requireNonNull(decoded.account).charges.size()); assertEquals(1, Objects.requireNonNull(decoded.account).totpCharges.size());
					String id = Objects.requireNonNull(decoded.account).charges.get(0).id;
					assertEquals(id, Objects.requireNonNull(decoded.account).totpCharges.get(0).id); chargeIds.add(id);
				} else { assertEquals(0, Objects.requireNonNull(decoded.account).charges.size()); assertEquals(matched, Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).usedStep); }
			}
			if (number == 1 || number == 3) { f.advance(Duration.ofSeconds(1)); return refusal(TotpStoreCommitResult.CONFLICT); }
			return null;
		};
		assertInstanceOf(TotpVerificationResult.Succeeded.class, f.totp.verifyResult(ACCOUNT, code, "login"));
		assertEquals(4, f.store.writes.size()); assertEquals(2, chargeIds.size()); assertEquals(chargeIds.get(0), chargeIds.get(1));
		assertTrue(upperBounds.stream().allMatch(upperBounds.get(0)::equals));
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertEquals(0, Objects.requireNonNull(decoded.account).charges.size()); assertEquals(matched, Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).usedStep); }
	}

	@Test void enrollmentConflictRetainsOriginalPendingIdentitySecretAndExpiry() {
		F f = new F();
		List<TotpStoreRecord> candidates = new ArrayList<>();
		f.store.before = (number, write) -> {
			candidates.add(write.getMutations().get(0).getRecord());
			if (number == 1) { f.advance(Duration.ofSeconds(10)); return refusal(TotpStoreCommitResult.CONFLICT); }
			return null;
		};
		TotpEnrollment enrollment = assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class, f.begin()).getEnrollment();
		assertEquals(2, candidates.size());
		try (TotpRecordsV3.Decoded first = f.open(candidates.get(0)); TotpRecordsV3.Decoded second = f.open(candidates.get(1))) {
			assertEquals(Objects.requireNonNull(Objects.requireNonNull(first.account).pending).enrollmentId, Objects.requireNonNull(Objects.requireNonNull(second.account).pending).enrollmentId);
			assertEquals(Objects.requireNonNull(Objects.requireNonNull(first.account).pending).factorId, Objects.requireNonNull(Objects.requireNonNull(second.account).pending).factorId);
			assertArrayEquals(Objects.requireNonNull(Objects.requireNonNull(first.account).pending).secret, Objects.requireNonNull(Objects.requireNonNull(second.account).pending).secret);
			assertEquals(BASE.plusSeconds(300), Objects.requireNonNull(Objects.requireNonNull(first.account).pending).expiresAt);
			assertEquals(Objects.requireNonNull(Objects.requireNonNull(first.account).pending).expiresAt, Objects.requireNonNull(Objects.requireNonNull(second.account).pending).expiresAt);
			assertEquals(Objects.requireNonNull(Objects.requireNonNull(first.account).pending).expiresAt, enrollment.getExpiresAt());
			assertEquals(BASE.plusSeconds(10), Objects.requireNonNull(second.account).observedAt);
		}
		assertEquals(f.store.writes.get(0).getTemporalCondition().getValidBeforeExclusive(), f.store.writes.get(1).getTemporalCondition().getValidBeforeExclusive());
	}

	@Test void intentionalInvalidCodeUsesNoEffectSettlementBarrierAndRetainsCharge() {
		F f = new F(); f.enroll(); f.advance(Duration.ofSeconds(60)); f.reset();
		AtomicReference<TotpStoreRecord> charged = new AtomicReference<>();
		f.store.after = (number, write, receipt) -> { if (number == 1) charged.set(f.record(f.key())); return receipt; };
		assertEquals(TotpRejectionReason.INVALID_CODE, assertInstanceOf(TotpVerificationResult.Rejected.class,
				f.totp.verifyResult(ACCOUNT, f.invalidCode(), "login")).getReason());
		assertEquals(2, f.store.writes.size()); assertEquals(1, f.store.writes.get(0).getMutations().size());
		assertTrue(f.store.writes.get(1).getMutations().isEmpty());
		assertEquals(Objects.requireNonNull(charged.get()).getVersion(), f.record(f.key()).getVersion());
		try (TotpRecordsV3.Decoded decoded = f.account()) {
			assertEquals(1, Objects.requireNonNull(decoded.account).charges.size()); assertEquals(1, Objects.requireNonNull(decoded.account).totpCharges.size());
			assertEquals(Objects.requireNonNull(decoded.account).charges.get(0).id, Objects.requireNonNull(decoded.account).totpCharges.get(0).id);
		}
	}

	@Test void genericPostEntryThrowNeverInfersRollbackOrRetries() {
		for (boolean effect : List.of(false, true)) {
			F f = new F();
			if (effect) f.store.after = (number, write, receipt) -> { throw new IllegalStateException("Scripted lost acknowledgement"); };
			else f.store.before = (number, write) -> { throw new IllegalStateException("Scripted uncertain callback"); };
			assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class, f.begin());
			assertEquals(1, f.store.writes.size()); assertEquals(1, f.store.reads);
			assertEquals(effect, f.entry(f.key()) instanceof TotpStoreEntry.Present);
		}
	}

	@Test void emptyBarrierUnknownIsUnavailableWithoutMutationUncertainty() {
		F f = new F(); f.store.before = (number, write) -> TotpStoreCommitReceipt.unknownInstance();
		assertEquals(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE, assertInstanceOf(TotpNamespaceInitializationResult.Unavailable.class,
				f.totp.initializeNamespaceResult()).getReason());
		assertEquals(1, f.store.writes.size()); assertTrue(f.store.writes.get(0).getMutations().isEmpty());
	}

	@Test void emptySettlementUnknownKeepsConfirmedChargeIncomplete() {
		F f = new F(); f.enroll(); f.advance(Duration.ofSeconds(60)); f.reset();
		f.store.before = (number, write) -> number == 2 ? TotpStoreCommitReceipt.unknownInstance() : null;
		assertEquals(TotpUnavailableReason.ATTEMPT_INCOMPLETE, assertInstanceOf(TotpVerificationResult.Unavailable.class,
				f.totp.verifyResult(ACCOUNT, f.invalidCode(), "login")).getReason());
		assertEquals(2, f.store.writes.size()); assertTrue(f.store.writes.get(1).getMutations().isEmpty());
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertEquals(1, Objects.requireNonNull(decoded.account).charges.size()); }
	}

	@Test void prechargeTimeExpiredIsDefiniteRejectionWithFreshFinalAdmission() {
		F f = new F(); f.enroll(); f.advance(Duration.ofSeconds(70)); f.reset();
		TotpStoreRecord before = f.record(f.key());
		String code = f.code(-1);
		f.store.before = (number, write) -> {
			f.advance(Duration.between(f.source.authorityTime(), write.getTemporalCondition().getValidBeforeExclusive().orElseThrow()));
			return null;
		};
		assertEquals(TotpRejectionReason.INVALID_CODE, assertInstanceOf(TotpVerificationResult.Rejected.class,
				f.totp.verifyResult(ACCOUNT, code, "login")).getReason());
		assertEquals(1, f.store.writes.size()); assertEquals(2, f.store.reads);
		assertEquals(before.getVersion(), f.record(f.key()).getVersion());
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertTrue(Objects.requireNonNull(decoded.account).charges.isEmpty()); }
	}

	@Test void confirmationStepExpiryDoesNotBecomePendingEnrollmentExpiry() {
		F f = new F();
		TotpEnrollment pending = assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class, f.begin()).getEnrollment();
		f.advance(Duration.ofSeconds(70)); f.reset();
		String code = f.pendingCode(-1);
		f.expireAtValidation();
		assertEquals(TotpRejectionReason.INVALID_CODE, assertInstanceOf(TotpEnrollmentResult.Rejected.class,
				f.totp.confirmEnrollmentResult(ACCOUNT, pending.getEnrollmentId(), code, "browser")).getReason());
		assertEquals(1, f.store.writes.size()); assertEquals(2, f.store.reads);
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertNotNull(Objects.requireNonNull(decoded.account).pending); assertTrue(Objects.requireNonNull(decoded.account).charges.isEmpty()); }
	}

	@Test void confirmationPendingExpiryKeepsItsDistinctReason() {
		F f = new F();
		TotpEnrollment pending = assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class, f.begin()).getEnrollment();
		f.advance(Duration.ofSeconds(295)); f.reset();
		String code = f.pendingCode(0);
		f.expireAtValidation();
		assertEquals(TotpRejectionReason.ENROLLMENT_NOT_FOUND, assertInstanceOf(TotpEnrollmentResult.Rejected.class,
				f.totp.confirmEnrollmentResult(ACCOUNT, pending.getEnrollmentId(), code, "browser")).getReason());
		assertEquals(1, f.store.writes.size()); assertEquals(2, f.store.reads);
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertNotNull(Objects.requireNonNull(decoded.account).pending); assertTrue(Objects.requireNonNull(decoded.account).charges.isEmpty()); }
	}

	@Test void recoveryActionExpiryIsRejectedWithoutAChargeOrCodeConsumption() {
		F f = new F(); RecoveryCodes codes = f.enroll(); f.reset();
		TotpStoreRecord before = f.record(f.key()); f.expireAtValidation();
		assertEquals(TotpRejectionReason.REJECTED, assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
				f.totp.consumeRecoveryCodeResult(ACCOUNT, codes.getCodes().get(0), "recover")).getReason());
		assertEquals(1, f.store.writes.size()); assertEquals(2, f.store.reads);
		assertEquals(before.getVersion(), f.record(f.key()).getVersion());
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertEquals(10, Objects.requireNonNull(decoded.account).recoveryHashes.size()); assertTrue(Objects.requireNonNull(decoded.account).charges.isEmpty()); }
	}

	@Test void lateKnownAcknowledgementRetainsCommitAndWithholdsArtifact() {
		F f = new F();
		TotpAuthenticator shortBudget = f.auth(Duration.ofMillis(100));
		f.store.after = (number, write, receipt) -> {
			try { assertFalse(new CountDownLatch(1).await(200, TimeUnit.MILLISECONDS)); }
			catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
			return receipt;
		};
		assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,
				shortBudget.beginEnrollmentResult(options(), "browser"));
		assertEquals(1, f.store.writes.size()); assertEquals(1, f.store.reads);
		try (TotpRecordsV3.Decoded decoded = f.account()) { assertNotNull(Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending)); }
	}

	private static @NonNull TotpEnrollmentOptions options() { return TotpEnrollmentOptions.withAccountId(ACCOUNT).accountName("person@example.test").build(); }
	private static StoreTimeObservation.@NonNull Healthy healthy(@NonNull TotpStoreWrite write) { return (StoreTimeObservation.Healthy) write.getSnapshot().getTimeObservation(); }
	private static StoreTimeObservation.@NonNull Healthy at(@NonNull TotpStoreWrite write, @NonNull Instant time) {
		StoreTimeObservation.Healthy sample = healthy(write);
		return StoreTimeObservation.Healthy.fromObservation(sample.getAdmission(), sample.getClockGeneration(), time, sample.getMaximumUtcError());
	}
	private static @NonNull TotpStoreCommitReceipt committed(StoreTimeObservation.@NonNull Healthy validated, StoreTimeObservation.@Nullable Healthy completed) {
		return TotpStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(validated, completed));
	}
	private static @NonNull TotpStoreCommitReceipt refusal(@NonNull TotpStoreCommitResult status) { return TotpStoreCommitReceipt.fromRefusal(status); }
	private static @NonNull String hotp(byte @NonNull [] secret, long step) {
		try { return TotpPrimitives.hotp(secret, step, "HmacSHA1", 6); }
		catch (GeneralSecurityException failure) { throw new AssertionError(failure); }
	}
	private static long matching(byte @NonNull [] secret, @NonNull String code, long step, long used) {
		try { return TotpPrimitives.matchingStep(secret, code, step, used); }
		catch (GeneralSecurityException failure) { throw new AssertionError(failure); }
	}
	private static void corrupt(@NonNull Object target, @NonNull String name, @Nullable Object value) {
		try { Field field = target.getClass().getDeclaredField(name); field.setAccessible(true); field.set(target, value); }
		catch (ReflectiveOperationException failure) { throw new AssertionError(failure); }
	}

	@FunctionalInterface private interface Before { @Nullable TotpStoreCommitReceipt apply(int number, @NonNull TotpStoreWrite write); }
	@FunctionalInterface private interface After { @NonNull TotpStoreCommitReceipt apply(int number, @NonNull TotpStoreWrite write, @NonNull TotpStoreCommitReceipt receipt); }
	@NotThreadSafe private static final class RecordingStore implements TotpStore {
		final @NonNull ScriptedTotpStore source;
		final @NonNull List<@NonNull TotpStoreWrite> writes = new ArrayList<>();
		int reads;
		@NonNull Set<@NonNull TotpStoreKey> lastRead = Set.of();
		@Nullable Before before;
		@Nullable After after;
		RecordingStore(@NonNull ScriptedTotpStore source) { this.source = source; }
		@Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys, @NonNull Duration budget) {
			this.reads++; this.lastRead = Set.copyOf(keys); return this.source.read(keys, budget);
		}
		@Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write, @NonNull Duration budget) {
			this.writes.add(write); int number = this.writes.size();
			TotpStoreCommitReceipt receipt = this.before == null ? null : this.before.apply(number, write);
			if (receipt == null) receipt = this.source.compareAndCommit(write, budget);
			return this.after == null ? receipt : this.after.apply(number, write, receipt);
		}
	}
	@ThreadSafe private static final class WorkerClock extends Clock {
		private final @NonNull AtomicReference<@NonNull Instant> time = new AtomicReference<>(BASE);
		@Override public @NonNull Instant instant() { return Objects.requireNonNull(this.time.get()); }
		@Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
		@Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return Clock.fixed(instant(), zone); }
	}
	@ThreadSafe private static final class Gate implements TotpRecoveryGate {
		@Override public @NonNull Permit acquire(@NonNull TotpRecoveryContext context, @NonNull Duration budget) {
			return new Permit() {
				@Override public @NonNull Boolean isCurrent() { return Boolean.TRUE; }
				@Override public void close() { }
			};
		}
	}
	@NotThreadSafe private static final class F {
		final @NonNull ScriptedTotpStore source = new ScriptedTotpStore(NAMESPACE, EPOCH, BASE);
		final @NonNull RecordingStore store = new RecordingStore(this.source);
		final @NonNull WorkerClock worker = new WorkerClock();
		final @NonNull StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("key", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).maximumSealedLength(16384).build();
		final @NonNull TotpRecordsV3 codec = new TotpRecordsV3(this.sealer);
		final @NonNull TotpAuthenticator totp = auth(Duration.ofSeconds(30));
		F() { assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class, this.totp.initializeNamespaceResult()); reset(); }
		@NonNull TotpAuthenticator auth(@NonNull Duration timeout) {
			return TotpAuthenticator.withIssuer("Receipt tests").credentialNamespace(NAMESPACE).recoveryEpoch(EPOCH).store(this.store)
					.clock(this.worker).stateSealer(this.sealer).recoveryGate(new Gate()).operationTimeout(timeout).build();
		}
		void reset() { this.store.writes.clear(); this.store.reads = 0; this.store.lastRead = Set.of(); this.store.before = null; this.store.after = null; }
		void advance(@NonNull Duration duration) { this.source.advance(duration); this.worker.time.set(this.worker.instant().plus(duration)); }
		void expireAtValidation() {
			this.store.before = (number, write) -> {
				advance(Duration.between(this.source.authorityTime(), write.getTemporalCondition().getValidBeforeExclusive().orElseThrow()));
				return null;
			};
		}
		@NonNull TotpStoreKey root() { return TotpStoreKey.forNamespace(NAMESPACE, EPOCH); }
		@NonNull TotpStoreKey key() { return TotpStoreKey.forAccount(NAMESPACE, EPOCH, ACCOUNT); }
		@NonNull TotpStoreEntry entry(@NonNull TotpStoreKey key) { return assertInstanceOf(TotpStoreReadResult.Available.class, this.source.read(Set.of(key), Duration.ofSeconds(2))).getSnapshot().getEntry(key); }
		@NonNull TotpStoreRecord record(@NonNull TotpStoreKey key) { return assertInstanceOf(TotpStoreEntry.Present.class, entry(key)).getRecord(); }
		TotpRecordsV3.@NonNull Decoded open(@NonNull TotpStoreRecord record) { try { return this.codec.open(record); } catch (IOException failure) { throw new AssertionError(failure); } }
		TotpRecordsV3.@NonNull Decoded account() { return open(record(key())); }
		@NonNull TotpEnrollmentRequestResult begin() { return this.totp.beginEnrollmentResult(options(), "browser"); }
		@NonNull RecoveryCodes enroll() {
			TotpEnrollment enrollment = assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class, begin()).getEnrollment();
			String code = null;
			for (int i = 0; i < 8 && code == null; i++) {
				try (TotpRecordsV3.Decoded decoded = account()) {
					long step = this.source.authorityTime().getEpochSecond() / 30; byte[] secret = Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending).secret;
					String candidate = hotp(secret, step);
					if (matching(secret, candidate, step, -1) == step) code = candidate;
				}
				if (code == null) advance(Duration.ofSeconds(30));
			}
			assertNotNull(code); return assertInstanceOf(TotpEnrollmentResult.Succeeded.class, this.totp.confirmEnrollmentResult(ACCOUNT, enrollment.getEnrollmentId(), code, "browser")).getRecoveryCodes();
		}
		@NonNull String pendingCode(int offset) {
			try (TotpRecordsV3.Decoded decoded = account()) {
				long current = this.source.authorityTime().getEpochSecond() / 30, step = current + offset;
				byte[] secret = Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending).secret;
				String code = hotp(secret, step); assertEquals(step, matching(secret, code, current, -1)); return code;
			}
		}
		@NonNull String code(int offset) {
			try (TotpRecordsV3.Decoded decoded = account()) {
				long current = this.source.authorityTime().getEpochSecond() / 30, step = current + offset;
				String code = hotp(Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).secret, step);
				assertEquals(step, matching(Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).secret, code, current, Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).usedStep)); return code;
			}
		}
		@NonNull String invalidCode() {
			try (TotpRecordsV3.Decoded decoded = account()) {
				long step = this.source.authorityTime().getEpochSecond() / 30;
				for (int i = 0; i < 100; i++) {
					String code = String.format(java.util.Locale.ROOT, "%06d", i);
					if (matching(Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).secret, code, step, Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).usedStep) < 0) return code;
				}
			}
			throw new AssertionError("No invalid code found");
		}
	}
}
