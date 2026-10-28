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
import com.revetsec.internal.crypto.TotpPrimitives;
import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Public-operation regressions exercising the opaque store and recovery-admission boundary. */
final class TotpAuthenticatorTests {
    private static final @NonNull String NAMESPACE = "totp-tests";
    private static final @NonNull String EPOCH = "epoch-one";
    private static final @NonNull String ACCOUNT = "account-1";
    private static final @NonNull String BROWSER = "application-owned-browser-binding";
    private static final @NonNull String LOGIN = "application-owned-pending-login";

    @Test void constructionPerformsNoStoreOrGateIoAndInitializationIsExplicit() {
        Fixture fixture = new Fixture(false);
        assertEquals(0, fixture.store.reads.get());
        assertEquals(0, fixture.store.commits.get());
        assertTrue(fixture.gate.contexts.isEmpty());
        assertInstanceOf(TotpStatusResult.Unavailable.class, fixture.totp.getStatusResult(ACCOUNT));
        assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,
                fixture.totp.initializeNamespaceResult());
        assertInstanceOf(TotpNamespaceInitializationResult.AlreadyInitialized.class,
                fixture.totp.initializeNamespaceResult());
        assertInstanceOf(TotpStatusResult.Absent.class, fixture.totp.getStatusResult(ACCOUNT));
        TotpRecoveryContext context = fixture.gate.contexts.get(0);
        assertEquals(NAMESPACE, context.getCredentialNamespace());
        assertEquals(EPOCH, context.getRecoveryEpoch());
        assertEquals("old", context.getActiveSealingKeyId());
        assertEquals(Set.of("old"), context.getOpeningSealingKeyIds());
    }

    @Test void anInitiallyStalePermitIsAlwaysClosedWithoutCallingStorage() {
        Fixture fixture = new Fixture(false);
        fixture.gate.initiallyStale.set(true);
        assertInstanceOf(TotpNamespaceInitializationResult.Unavailable.class,
                fixture.totp.initializeNamespaceResult());
        assertEquals(1, fixture.gate.closedPermits.get());
        assertEquals(0, fixture.store.reads.get());
        assertEquals(0, fixture.store.commits.get());
    }

    @Test void oversizedSubmittedCodesAreRejectedBeforeAdmissionOrStorage() {
        Fixture fixture = new Fixture();
        String oversized = "x".repeat(129);
        int admissions = fixture.gate.contexts.size();
        int reads = fixture.store.reads.get();
        int commits = fixture.store.commits.get();

        assertEquals(TotpRejectionReason.INVALID_CODE, assertInstanceOf(TotpEnrollmentResult.Rejected.class,
                fixture.totp.confirmEnrollmentResult(ACCOUNT, "enrollment", oversized, BROWSER)).getReason());
        assertEquals(TotpRejectionReason.INVALID_CODE, assertInstanceOf(TotpEnrollmentResult.Rejected.class,
                fixture.totp.confirmEnrollmentResult(ACCOUNT, oversized, "123456", BROWSER)).getReason());
        assertEquals(TotpRejectionReason.INVALID_CODE, assertInstanceOf(TotpVerificationResult.Rejected.class,
                fixture.totp.verifyResult(ACCOUNT, oversized, LOGIN)).getReason());
        assertEquals(TotpRejectionReason.INVALID_CODE, assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, oversized, LOGIN)).getReason());

        assertEquals(admissions, fixture.gate.contexts.size());
        assertEquals(reads, fixture.store.reads.get());
        assertEquals(commits, fixture.store.commits.get());
    }

    @Test void confirmationCommitsFactorRecoveryBatchAndUsedStepTogether() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        assertEquals(enrolled.pending.getFactorId(), enrolled.factor.getFactorId());
        assertEquals(10, enrolled.codes.getCodes().size());
        assertEquals(EPOCH, enrolled.factor.getRecoveryEpoch());
        assertTrue(enrolled.pending.getProvisioningUri().startsWith("otpauth://totp/"));
        assertTrue(enrolled.pending.getProvisioningUri().contains("algorithm=SHA1"));
        assertTrue(enrolled.pending.getProvisioningUri().contains("digits=6"));
        assertTrue(enrolled.pending.getProvisioningUri().contains("period=30"));
        assertInstanceOf(TotpVerificationResult.Rejected.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        fixture.clock.advance(Duration.ofSeconds(30));
        TotpVerification proof = assertInstanceOf(TotpVerificationResult.Succeeded.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN)).getVerification();
        assertEquals(TotpAuthenticationMethod.TOTP, proof.getMethod());
        assertEquals(ACCOUNT, proof.getAccountId());
        assertEquals(LOGIN, proof.getOperationBinding());
        assertEquals(enrolled.factor.getFactorId(), proof.getFactorId());
        assertEquals(EPOCH, proof.getRecoveryEpoch());
        assertInstanceOf(TotpVerificationResult.Rejected.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        TotpStatus status = fixture.status();
        assertEquals(enrolled.factor.getFactorId(), status.getActiveFactor().orElseThrow().getFactorId());
        assertTrue(status.getPendingEnrollment().isEmpty());
        assertEquals(enrolled.codes.getBatchId(), status.getRecoveryBatchId().orElseThrow());
        assertEquals(10, status.getRemainingRecoveryCodeCount());
    }

    @Test void anExpiredReservationPersistsObservedExpiryBeforeRejecting() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        TotpEnrollment pending = fixture.begin(null);
        String code = fixture.code(pending);
        fixture.store.afterNextCommit.set(() -> fixture.clock.advance(Duration.ofMinutes(6)));
        assertInstanceOf(TotpEnrollmentResult.Rejected.class,
                fixture.totp.confirmEnrollmentResult(ACCOUNT, pending.getEnrollmentId(), code, BROWSER));
        fixture.clock.advance(Duration.ofMinutes(-6));
        assertInstanceOf(TotpEnrollmentResult.Unavailable.class,
                fixture.totp.confirmEnrollmentResult(ACCOUNT, pending.getEnrollmentId(), code, BROWSER));
        fixture.clock.advance(Duration.ofMinutes(6));
        assertTrue(fixture.status().getPendingEnrollment().isEmpty());
        assertTrue(fixture.status().getActiveFactor().isEmpty());
    }

    @Test void previousCurrentAndNextStepsShareAnIncreasingHighWaterMark() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        fixture.clock.advance(Duration.ofSeconds(60));
        String future = fixture.code(enrolled.pending, 1);
        assertInstanceOf(TotpVerificationResult.Succeeded.class,
                fixture.totp.verifyResult(ACCOUNT, future, LOGIN));
        assertInstanceOf(TotpVerificationResult.Rejected.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        fixture.clock.advance(Duration.ofSeconds(30));
        assertInstanceOf(TotpVerificationResult.Rejected.class,
                fixture.totp.verifyResult(ACCOUNT, future, LOGIN));
    }

    @Test void fiveFailuresAreSharedAcrossConfirmationTotpAndRecovery() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        TotpEnrollment replacement = fixture.begin(enrolled.factor.getFactorId());
        assertInstanceOf(TotpEnrollmentResult.Rejected.class, fixture.totp.confirmEnrollmentResult(
                ACCOUNT, replacement.getEnrollmentId(), "bad", BROWSER));
        assertInstanceOf(TotpVerificationResult.Rejected.class,
                fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, "bad", LOGIN));
        assertInstanceOf(TotpVerificationResult.Rejected.class,
                fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, "bad", LOGIN));
        assertInstanceOf(TotpVerificationResult.Throttled.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending, 1), LOGIN));
        assertInstanceOf(RecoveryCodeUseResult.Throttled.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, enrolled.codes.getCodes().get(0), LOGIN));
        assertInstanceOf(TotpEnrollmentResult.Throttled.class, fixture.totp.confirmEnrollmentResult(
                ACCOUNT, replacement.getEnrollmentId(), fixture.code(replacement), BROWSER));
        fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        assertInstanceOf(TotpVerificationResult.Succeeded.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
    }

    @Test void tenFailedSixDigitAttemptsAreChargedForRollingDayAcrossAuthenticatorRestart()
            throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        for (int window = 0; window < 2; window++) {
            for (int attempt = 0; attempt < 5; attempt++)
                assertInstanceOf(TotpVerificationResult.Rejected.class,
                        fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
            if (window == 1) {
                TotpVerificationResult.Throttled bothLimits = assertInstanceOf(TotpVerificationResult.Throttled.class,
                        fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
                assertEquals(Duration.ofDays(1).minusSeconds(301), bothLimits.getRetryAfter());
            }
            fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        }
        TotpAuthenticator restarted = authenticator(fixture.store, fixture.clock, fixture.gate,
                fixture.sealer, EPOCH);
        TotpVerificationResult.Throttled throttled = assertInstanceOf(TotpVerificationResult.Throttled.class,
                restarted.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        assertEquals(Duration.ofDays(1).minusSeconds(602), throttled.getRetryAfter());
        assertInstanceOf(RecoveryCodeUseResult.Succeeded.class,
                restarted.consumeRecoveryCodeResult(ACCOUNT, enrolled.codes.getCodes().get(0), LOGIN));
        assertInstanceOf(TotpVerificationResult.Throttled.class,
                restarted.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        fixture.clock.advance(Duration.ofDays(1).minusSeconds(602));
        assertInstanceOf(TotpVerificationResult.Succeeded.class,
                restarted.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
    }

    @Test void confirmationAndVerificationShareTheDailyLimit() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        TotpEnrollment replacement = fixture.begin(enrolled.factor.getFactorId());
        for (int window = 0; window < 2; window++) {
            for (int attempt = 0; attempt < 5; attempt++) {
                if (window == 0 && attempt == 0)
                    assertInstanceOf(TotpEnrollmentResult.Rejected.class,
                            fixture.totp.confirmEnrollmentResult(ACCOUNT, replacement.getEnrollmentId(), "bad", BROWSER));
                else assertInstanceOf(TotpVerificationResult.Rejected.class,
                        fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
            }
            fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        }
        assertInstanceOf(TotpVerificationResult.Throttled.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
    }

    @Test void successfulVerificationClearsOnlyItsOwnDailyReservation() throws Exception {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        assertInstanceOf(TotpVerificationResult.Rejected.class,
                fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        fixture.clock.advance(Duration.ofSeconds(30));
        assertInstanceOf(TotpVerificationResult.Succeeded.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        TotpStoreRecord record = assertInstanceOf(TotpStoreEntry.Present.class,
                fixture.accountRecordEntry()).getRecord();
        try (TotpRecords.Decoded decoded = new TotpRecords(fixture.sealer).open(record)) {
            TotpRecords.Account account = java.util.Objects.requireNonNull(decoded.account);
            assertEquals(1, account.charges.size());
            assertEquals(1, account.totpCharges.size());
            assertEquals(account.charges.get(0).id, account.totpCharges.get(0).id);
        }
    }

    @Test void uncertainReservationIsChargedToTheDailyLimit() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        fixture.store.unknownAfterCommit.set(true);
        assertInstanceOf(TotpVerificationResult.Indeterminate.class,
                fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        for (int attempt = 0; attempt < 4; attempt++)
            assertInstanceOf(TotpVerificationResult.Rejected.class,
                    fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        for (int attempt = 0; attempt < 5; attempt++)
            assertInstanceOf(TotpVerificationResult.Rejected.class,
                    fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        assertInstanceOf(TotpVerificationResult.Throttled.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
    }

    @Test void concurrentReservationsCannotExceedTheDailyLimit() throws Exception {
        Fixture fixture = new Fixture();
        fixture.enroll();
        for (int attempt = 0; attempt < 9; attempt++) {
            if (attempt == 5) fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
            assertInstanceOf(TotpVerificationResult.Rejected.class,
                    fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        }
        fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        List<TotpVerificationResult> results = race(
                () -> fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN),
                () -> fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        assertEquals(1L, results.stream().filter(TotpVerificationResult.Rejected.class::isInstance).count());
        assertEquals(1L, results.stream().filter(TotpVerificationResult.Throttled.class::isInstance).count());
    }

    @Test void clockRollbackCannotClearTheDailyLimit() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        for (int window = 0; window < 2; window++) {
            for (int attempt = 0; attempt < 5; attempt++)
                assertInstanceOf(TotpVerificationResult.Rejected.class,
                        fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
            fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        }
        assertInstanceOf(TotpVerificationResult.Throttled.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        fixture.clock.advance(Duration.ofSeconds(-20));
        assertInstanceOf(TotpVerificationResult.Throttled.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        fixture.clock.advance(Duration.ofMinutes(-1));
        assertInstanceOf(TotpVerificationResult.Unavailable.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
    }

    @Test void recoveryCodesAreSingleUseAndCarryRecoveryMethodProvenance() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        String code = enrolled.codes.getCodes().get(0);
        RecoveryCodeUse use = assertInstanceOf(RecoveryCodeUseResult.Succeeded.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, code, LOGIN)).getUse();
        assertEquals(TotpAuthenticationMethod.RECOVERY_CODE, use.getMethod());
        assertEquals(EPOCH, use.getRecoveryEpoch());
        assertEquals(LOGIN, use.getOperationBinding());
        assertEquals(9, use.getRemainingRecoveryCodeCount());
        assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, code, LOGIN));
        assertEquals(9, fixture.status().getRemainingRecoveryCodeCount());
    }

    @Test void concurrentRecoveryRedemptionsCannotBothSucceed() throws Exception {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        String code = enrolled.codes.getCodes().get(0);
        List<RecoveryCodeUseResult> results = race(
                () -> fixture.totp.consumeRecoveryCodeResult(ACCOUNT, code, LOGIN),
                () -> fixture.totp.consumeRecoveryCodeResult(ACCOUNT, code, LOGIN));
        assertEquals(1L, results.stream().filter(RecoveryCodeUseResult.Succeeded.class::isInstance).count());
        assertEquals(9, fixture.status().getRemainingRecoveryCodeCount());
    }

    @Test void concurrentIdenticalTotpAttemptsCannotBothSucceed() throws Exception {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        fixture.clock.advance(Duration.ofSeconds(30));
        String code = fixture.code(enrolled.pending);
        List<TotpVerificationResult> results = race(
                () -> fixture.totp.verifyResult(ACCOUNT, code, LOGIN),
                () -> fixture.totp.verifyResult(ACCOUNT, code, LOGIN));
        assertEquals(1L, results.stream().filter(TotpVerificationResult.Succeeded.class::isInstance).count());
    }

    @Test void rotationInvalidatesEveryOldCodeAndRequiresCurrentFactorAndBatch() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        RecoveryCodes rotated = assertInstanceOf(RecoveryCodeRotationResult.Succeeded.class,
                fixture.totp.rotateRecoveryCodesResult(ACCOUNT, enrolled.factor.getFactorId(),
                        enrolled.codes.getBatchId())).getRecoveryCodes();
        assertNotEquals(enrolled.codes.getBatchId(), rotated.getBatchId());
        assertEquals(10, rotated.getCodes().size());
        assertInstanceOf(RecoveryCodeUseResult.Rejected.class, fixture.totp.consumeRecoveryCodeResult(
                ACCOUNT, enrolled.codes.getCodes().get(0), LOGIN));
        assertInstanceOf(RecoveryCodeRotationResult.Rejected.class, fixture.totp.rotateRecoveryCodesResult(
                ACCOUNT, enrolled.factor.getFactorId(), enrolled.codes.getBatchId()));
        assertInstanceOf(RecoveryCodeRotationResult.Rejected.class, fixture.totp.rotateRecoveryCodesResult(
                ACCOUNT, "stale-factor", rotated.getBatchId()));
        assertInstanceOf(RecoveryCodeUseResult.Succeeded.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, rotated.getCodes().get(0), LOGIN));
    }

    @Test void replacementPreservesCurrentFactorAndCodesUntilConfirmation() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        TotpEnrollment replacement = fixture.begin(enrolled.factor.getFactorId());
        assertEquals(enrolled.factor.getFactorId(), fixture.status().getActiveFactor().orElseThrow().getFactorId());
        assertInstanceOf(RecoveryCodeUseResult.Succeeded.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, enrolled.codes.getCodes().get(0), LOGIN));
        fixture.clock.advance(Duration.ofSeconds(30));
        assertInstanceOf(TotpVerificationResult.Succeeded.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        TotpEnrollmentResult.Succeeded confirmed = assertInstanceOf(TotpEnrollmentResult.Succeeded.class,
                fixture.totp.confirmEnrollmentResult(ACCOUNT, replacement.getEnrollmentId(),
                        fixture.code(replacement), BROWSER));
        assertEquals(replacement.getFactorId(), confirmed.getFactor().getFactorId());
        assertNotEquals(enrolled.codes.getBatchId(), confirmed.getRecoveryCodes().getBatchId());
        assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, enrolled.codes.getCodes().get(1), LOGIN));
        assertInstanceOf(TotpFactorRemovalResult.Rejected.class,
                fixture.totp.removeFactorResult(ACCOUNT, enrolled.factor.getFactorId()));
    }

    @Test void confirmationIsBoundToAccountBrowserEnrollmentAndExpiry() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        TotpEnrollment pending = fixture.begin(null);
        assertInstanceOf(TotpEnrollmentResult.Rejected.class, fixture.totp.confirmEnrollmentResult(
                ACCOUNT, pending.getEnrollmentId(), fixture.code(pending), "different-browser"));
        assertInstanceOf(TotpEnrollmentResult.Rejected.class, fixture.totp.confirmEnrollmentResult(
                "different-account", pending.getEnrollmentId(), fixture.code(pending), BROWSER));
        assertInstanceOf(TotpEnrollmentResult.Rejected.class, fixture.totp.confirmEnrollmentResult(
                ACCOUNT, "stale-enrollment", fixture.code(pending), BROWSER));
        fixture.clock.advance(Duration.ofMinutes(5));
        assertInstanceOf(TotpEnrollmentResult.Rejected.class, fixture.totp.confirmEnrollmentResult(
                ACCOUNT, pending.getEnrollmentId(), fixture.code(pending), BROWSER));
        assertTrue(fixture.status().getActiveFactor().isEmpty());
    }

    @Test void cancellationRequiresTheBrowserBindingAndPreservesTheActiveGeneration() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        TotpEnrollment replacement = fixture.begin(enrolled.factor.getFactorId());
        assertInstanceOf(TotpEnrollmentCancellationResult.Rejected.class,
                fixture.totp.cancelEnrollmentResult(ACCOUNT, replacement.getEnrollmentId(), "wrong-browser"));
        assertTrue(fixture.status().getPendingEnrollment().isPresent());
        assertInstanceOf(TotpEnrollmentCancellationResult.Succeeded.class,
                fixture.totp.cancelEnrollmentResult(ACCOUNT, replacement.getEnrollmentId(), BROWSER));
        assertTrue(fixture.status().getPendingEnrollment().isEmpty());
        assertEquals(enrolled.factor.getFactorId(), fixture.status().getActiveFactor().orElseThrow().getFactorId());
    }

    @Test void observingEnrollmentExpiryThroughStatusSurvivesASmallClockRollback()
            throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        TotpEnrollment pending = fixture.begin(null);
        fixture.clock.advance(Duration.ofSeconds(301));
        assertTrue(fixture.status().getPendingEnrollment().isEmpty());
        fixture.clock.advance(Duration.ofSeconds(-2));
        assertInstanceOf(TotpEnrollmentResult.Rejected.class, fixture.totp.confirmEnrollmentResult(
                ACCOUNT, pending.getEnrollmentId(), fixture.code(pending), BROWSER));
    }

    @Test void observingEnrollmentExpiryThroughCancellationSurvivesASmallClockRollback()
            throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        TotpEnrollment pending = fixture.begin(null);
        fixture.clock.advance(Duration.ofSeconds(301));
        assertInstanceOf(TotpEnrollmentCancellationResult.Rejected.class,
                fixture.totp.cancelEnrollmentResult(ACCOUNT, pending.getEnrollmentId(), BROWSER));
        fixture.clock.advance(Duration.ofSeconds(-2));
        assertInstanceOf(TotpEnrollmentResult.Rejected.class, fixture.totp.confirmEnrollmentResult(
                ACCOUNT, pending.getEnrollmentId(), fixture.code(pending), BROWSER));
    }

    @Test void removalRevokesActivePendingAndRecoveryButRetainsATombstone() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        TotpEnrollment replacement = fixture.begin(enrolled.factor.getFactorId());
        assertInstanceOf(TotpFactorRemovalResult.Succeeded.class,
                fixture.totp.removeFactorResult(ACCOUNT, enrolled.factor.getFactorId()));
        TotpStatus status = fixture.status();
        assertTrue(status.getActiveFactor().isEmpty());
        assertTrue(status.getPendingEnrollment().isEmpty());
        assertTrue(status.getRecoveryBatchId().isEmpty());
        assertEquals(0, status.getRemainingRecoveryCodeCount());
        assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, enrolled.codes.getCodes().get(0), LOGIN));
        assertInstanceOf(TotpEnrollmentResult.Rejected.class, fixture.totp.confirmEnrollmentResult(
                ACCOUNT, replacement.getEnrollmentId(), fixture.code(replacement), BROWSER));
        assertInstanceOf(TotpStoreEntry.Present.class, fixture.accountRecordEntry());
        TotpEnrollment fresh = fixture.begin(null);
        assertNotEquals(enrolled.factor.getFactorId(), fresh.getFactorId());
        assertInstanceOf(TotpFactorRemovalResult.Rejected.class,
                fixture.totp.removeFactorResult(ACCOUNT, enrolled.factor.getFactorId()));
    }

    @Test void factorRemovalDoesNotEraseTheSharedFailureBudget() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        for (int attempt = 0; attempt < 5; attempt++)
            assertInstanceOf(TotpVerificationResult.Rejected.class,
                    fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        assertInstanceOf(TotpFactorRemovalResult.Succeeded.class,
                fixture.totp.removeFactorResult(ACCOUNT, enrolled.factor.getFactorId()));
        assertInstanceOf(TotpEnrollmentRequestResult.Throttled.class,
                fixture.totp.beginEnrollmentResult(options(null), BROWSER));
        fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,
                fixture.totp.beginEnrollmentResult(options(null), BROWSER));
    }

    @Test void factorRemovalAndReenrollmentDoNotEraseDailyFailures() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        for (int attempt = 0; attempt < 5; attempt++)
            assertInstanceOf(TotpVerificationResult.Rejected.class,
                    fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        assertInstanceOf(TotpFactorRemovalResult.Succeeded.class,
                fixture.totp.removeFactorResult(ACCOUNT, enrolled.factor.getFactorId()));
        fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        TotpEnrollment fresh = fixture.begin(null);
        assertInstanceOf(TotpEnrollmentResult.Succeeded.class,
                fixture.totp.confirmEnrollmentResult(ACCOUNT, fresh.getEnrollmentId(), fixture.code(fresh), BROWSER));
        for (int attempt = 0; attempt < 5; attempt++)
            assertInstanceOf(TotpVerificationResult.Rejected.class,
                    fixture.totp.verifyResult(ACCOUNT, "bad", LOGIN));
        fixture.clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        assertInstanceOf(TotpVerificationResult.Throttled.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(fresh), LOGIN));
    }

    @Test void racingRemovalCannotBeIgnoredByVerification() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        fixture.clock.advance(Duration.ofSeconds(30));
        fixture.store.beforeNextCommit.set(() -> assertInstanceOf(TotpFactorRemovalResult.Succeeded.class,
                fixture.totp.removeFactorResult(ACCOUNT, enrolled.factor.getFactorId())));
        TotpVerificationResult result = fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN);
        assertFalse(result instanceof TotpVerificationResult.Succeeded);
        assertTrue(fixture.status().getActiveFactor().isEmpty());
    }

    @Test void unknownBeginReleasesNoProvisioningMaterialAndDoesNotRetry() {
        Fixture fixture = new Fixture();
        fixture.store.unknownAfterCommit.set(true);
        int before = fixture.store.commits.get();
        TotpEnrollmentRequestResult result = fixture.totp.beginEnrollmentResult(options(null), BROWSER);
        assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class, result);
        assertEquals(before + 1, fixture.store.commits.get());
        assertFalse(result.toString().contains("otpauth"));
        TotpPendingEnrollment committed = fixture.status().getPendingEnrollment().orElseThrow();
        assertInstanceOf(TotpEnrollmentCancellationResult.Succeeded.class,
                fixture.totp.cancelEnrollmentResult(ACCOUNT, committed.getEnrollmentId(), BROWSER));
    }

    @Test void unknownWithoutAnAppliedMutationStillCannotBeRetriedAutomatically() {
        Fixture fixture = new Fixture();
        fixture.store.unknownWithoutMutation.set(true);
        int before = fixture.store.commits.get();
        assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,
                fixture.totp.beginEnrollmentResult(options(null), BROWSER));
        assertEquals(before + 1, fixture.store.commits.get());
        assertInstanceOf(TotpStatusResult.Absent.class, fixture.totp.getStatusResult(ACCOUNT));
    }

    @Test void callbackExceptionAfterAnAppliedWriteIsIndeterminateAndNotRetried() {
        Fixture fixture = new Fixture();
        fixture.store.afterNextCommit.set(() -> { throw new IllegalStateException("Lost acknowledgement"); });
        int before = fixture.store.commits.get();
        assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,
                fixture.totp.beginEnrollmentResult(options(null), BROWSER));
        assertEquals(before + 1, fixture.store.commits.get());
        assertTrue(fixture.status().getPendingEnrollment().isPresent());
    }

    @Test void unknownRotationReleasesNoCodesAndStatusReconcilesTheNewBatch() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        fixture.store.unknownAfterCommit.set(true);
        int before = fixture.store.commits.get();
        RecoveryCodeRotationResult result = fixture.totp.rotateRecoveryCodesResult(
                ACCOUNT, enrolled.factor.getFactorId(), enrolled.codes.getBatchId());
        assertInstanceOf(RecoveryCodeRotationResult.Indeterminate.class, result);
        assertEquals(before + 1, fixture.store.commits.get());
        String newBatch = fixture.status().getRecoveryBatchId().orElseThrow();
        assertNotEquals(enrolled.codes.getBatchId(), newBatch);
        assertInstanceOf(RecoveryCodeRotationResult.Succeeded.class, fixture.totp.rotateRecoveryCodesResult(
                ACCOUNT, enrolled.factor.getFactorId(), newBatch));
    }

    @Test void unknownCodeUseNeverReleasesProofOrAutomaticallyRetries() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        fixture.store.unknownAfterCommit.set(true);
        int before = fixture.store.commits.get();
        RecoveryCodeUseResult result = fixture.totp.consumeRecoveryCodeResult(
                ACCOUNT, enrolled.codes.getCodes().get(0), LOGIN);
        assertInstanceOf(RecoveryCodeUseResult.Indeterminate.class, result);
        assertEquals(before + 1, fixture.store.commits.get());
        assertFalse(result.toString().contains(LOGIN));
    }

    @Test void unknownConfirmationSettlementCanActivateTheFactorWithoutReleasingRecoveryPlaintext()
            throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        TotpEnrollment pending = fixture.begin(null);
        fixture.store.unknownCommitCountdown.set(2);
        int before = fixture.store.commits.get();
        assertInstanceOf(TotpEnrollmentResult.Indeterminate.class,
                fixture.totp.confirmEnrollmentResult(ACCOUNT, pending.getEnrollmentId(), fixture.code(pending), BROWSER));
        assertEquals(before + 2, fixture.store.commits.get());
        TotpStatus status = fixture.status();
        assertEquals(pending.getFactorId(), status.getActiveFactor().orElseThrow().getFactorId());
        assertEquals(10, status.getRemainingRecoveryCodeCount());
        assertInstanceOf(TotpEnrollmentResult.Rejected.class,
                fixture.totp.confirmEnrollmentResult(ACCOUNT, pending.getEnrollmentId(), fixture.code(pending), BROWSER));
    }

    @Test void unknownTotpSettlementConsumesTheStepWithoutReleasingProof() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        fixture.clock.advance(Duration.ofSeconds(30));
        fixture.store.unknownCommitCountdown.set(2);
        String code = fixture.code(enrolled.pending);
        int before = fixture.store.commits.get();
        assertInstanceOf(TotpVerificationResult.Indeterminate.class, fixture.totp.verifyResult(ACCOUNT, code, LOGIN));
        assertEquals(before + 2, fixture.store.commits.get());
        assertInstanceOf(TotpVerificationResult.Rejected.class, fixture.totp.verifyResult(ACCOUNT, code, LOGIN));
    }

    @Test void unknownRecoverySettlementConsumesTheCodeWithoutReleasingProof() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        fixture.store.unknownCommitCountdown.set(2);
        String code = enrolled.codes.getCodes().get(0);
        int before = fixture.store.commits.get();
        assertInstanceOf(RecoveryCodeUseResult.Indeterminate.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, code, LOGIN));
        assertEquals(before + 2, fixture.store.commits.get());
        assertEquals(9, fixture.status().getRemainingRecoveryCodeCount());
        assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, code, LOGIN));
    }

    @Test void lossOfRecoveryAdmissionAfterAWritePreventsProvisioningRelease() {
        Fixture fixture = new Fixture();
        fixture.store.afterNextCommit.set(() -> fixture.gate.open.set(false));
        assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,
                fixture.totp.beginEnrollmentResult(options(null), BROWSER));
        assertInstanceOf(TotpStatusResult.Unavailable.class, fixture.totp.getStatusResult(ACCOUNT));
        fixture.gate.open.set(true);
        assertTrue(fixture.status().getPendingEnrollment().isPresent());
        assertTrue(fixture.gate.closedPermits.get() > 0);
    }

    @Test void aPermitCloseFailureBeforeAnyWriteIsUnavailable() {
        Fixture fixture = new Fixture(false);
        fixture.gate.initiallyStale.set(true);
        fixture.gate.onNextClose.set(() -> { throw new IllegalStateException("Close failed"); });
        assertInstanceOf(TotpNamespaceInitializationResult.Unavailable.class,
                fixture.totp.initializeNamespaceResult());
        assertEquals(1, fixture.gate.closedPermits.get());
        assertEquals(0, fixture.store.reads.get());
        assertEquals(0, fixture.store.commits.get());
    }

    @Test void aPermitCloseFailureAfterCommitPreventsProvisioningRelease() {
        Fixture fixture = new Fixture();
        fixture.gate.onNextClose.set(() -> { throw new IllegalStateException("Close failed"); });
        int before = fixture.store.commits.get();
        assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,
                fixture.totp.beginEnrollmentResult(options(null), BROWSER));
        assertEquals(before + 1, fixture.store.commits.get());
        assertTrue(fixture.status().getPendingEnrollment().isPresent());
    }

    @Test void permitCloseCannotExtendTheDeadlineForReleasingProvisioningMaterial() {
        Fixture fixture = new Fixture();
        TotpAuthenticator shortBudget = TotpAuthenticator.withIssuer("Example Security")
                .credentialNamespace(NAMESPACE).recoveryEpoch(EPOCH).store(fixture.store)
                .clock(fixture.clock).stateSealer(fixture.sealer).recoveryGate(fixture.gate)
                .operationTimeout(Duration.ofMillis(100)).build();
        fixture.gate.onNextClose.set(TotpAuthenticatorTests::delayPastShortDeadline);
        int before = fixture.store.commits.get();
        assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,
                shortBudget.beginEnrollmentResult(options(null), BROWSER));
        assertEquals(before + 1, fixture.store.commits.get());
        assertTrue(fixture.status().getPendingEnrollment().isPresent());
    }

    @Test void aLateStoreAcknowledgementCannotReleaseProvisioningMaterial() {
        Fixture fixture = new Fixture();
        TotpAuthenticator shortBudget = TotpAuthenticator.withIssuer("Example Security")
                .credentialNamespace(NAMESPACE).recoveryEpoch(EPOCH).store(fixture.store)
                .clock(fixture.clock).stateSealer(fixture.sealer).recoveryGate(fixture.gate)
                .operationTimeout(Duration.ofMillis(100)).build();
        fixture.store.afterNextCommit.set(TotpAuthenticatorTests::delayPastShortDeadline);
        assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,
                shortBudget.beginEnrollmentResult(options(null), BROWSER));
        assertTrue(fixture.status().getPendingEnrollment().isPresent());
    }

    @Test void interruptionIsPreservedAndPreventsAdmissionOrStorageCalls() {
        Fixture fixture = new Fixture();
        int reads = fixture.store.reads.get();
        int commits = fixture.store.commits.get();
        int admissions = fixture.gate.contexts.size();
        try {
            Thread.currentThread().interrupt();
            assertInstanceOf(TotpVerificationResult.Unavailable.class,
                    fixture.totp.verifyResult(ACCOUNT, "123456", LOGIN));
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(reads, fixture.store.reads.get());
            assertEquals(commits, fixture.store.commits.get());
            assertEquals(admissions, fixture.gate.contexts.size());
        } finally { Thread.interrupted(); }
    }

    @Test void wrappedInterruptionFromGateAcquisitionIsPreservedWithoutStorageOrRetry() {
        Fixture fixture = new Fixture();
        fixture.gate.onNextAcquire.set(() -> {
            throw new IllegalStateException("Wrapped gate interruption", new InterruptedException());
        });
        int beforeAdmissions = fixture.gate.contexts.size();
        int beforeReads = fixture.store.reads.get();
        int beforeCommits = fixture.store.commits.get();
        try {
            assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,
                    fixture.totp.beginEnrollmentResult(options(null), BROWSER));
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(beforeAdmissions + 1, fixture.gate.contexts.size());
            assertEquals(beforeReads, fixture.store.reads.get());
            assertEquals(beforeCommits, fixture.store.commits.get());
        } finally { Thread.interrupted(); }
    }

    @Test void wrappedInterruptionFromStoreReadIsPreservedWithoutMutationOrRetry() {
        Fixture fixture = new Fixture();
        fixture.store.beforeNextRead.set(() -> {
            throw new IllegalStateException("Wrapped read interruption", new InterruptedException());
        });
        int beforeReads = fixture.store.reads.get();
        int beforeCommits = fixture.store.commits.get();
        try {
            assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,
                    fixture.totp.beginEnrollmentResult(options(null), BROWSER));
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(beforeReads + 1, fixture.store.reads.get());
            assertEquals(beforeCommits, fixture.store.commits.get());
        } finally { Thread.interrupted(); }
    }

    @Test void wrappedInterruptionAfterStoreCommitIsPreservedWithoutProofOrRetry() {
        Fixture fixture = new Fixture();
        fixture.store.afterNextCommit.set(() -> {
            throw new IllegalStateException("Wrapped commit interruption", new InterruptedException());
        });
        int before = fixture.store.commits.get();
        try {
            assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,
                    fixture.totp.beginEnrollmentResult(options(null), BROWSER));
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(before + 1, fixture.store.commits.get());
        } finally { Thread.interrupted(); }
        assertTrue(fixture.status().getPendingEnrollment().isPresent());
    }

    @Test void wrappedInterruptionFromPermitCloseIsPreservedWithoutProofOrRetry() {
        Fixture fixture = new Fixture();
        fixture.gate.onNextClose.set(() -> {
            throw new IllegalStateException("Wrapped close interruption", new InterruptedException());
        });
        int before = fixture.store.commits.get();
        try {
            assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,
                    fixture.totp.beginEnrollmentResult(options(null), BROWSER));
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(before + 1, fixture.store.commits.get());
        } finally { Thread.interrupted(); }
        assertTrue(fixture.status().getPendingEnrollment().isPresent());
    }

    @Test void recoveryEpochAdvanceFencesOldWritersAndRequiresFreshInitialization() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        assertEquals(TotpStoreCommitResult.COMMITTED,
                fixture.delegate.provisionRecoveryEpoch("epoch-two", Duration.ofSeconds(1)));
        // The test gate deliberately still admits the stale epoch: backend fencing must suffice.
        assertInstanceOf(TotpVerificationResult.Unavailable.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending, 1), LOGIN));
        Gate freshGate = new Gate("epoch-two");
        TotpAuthenticator fresh = authenticator(fixture.store, fixture.clock, freshGate,
                fixture.sealer, "epoch-two");
        assertInstanceOf(TotpStatusResult.Unavailable.class, fresh.getStatusResult(ACCOUNT));
        assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class, fresh.initializeNamespaceResult());
        assertInstanceOf(TotpStatusResult.Absent.class, fresh.getStatusResult(ACCOUNT));
        assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                fresh.consumeRecoveryCodeResult(ACCOUNT, enrolled.codes.getCodes().get(0), LOGIN));
        assertThrows(IllegalArgumentException.class,
                () -> fixture.delegate.provisionRecoveryEpoch(EPOCH, Duration.ofSeconds(1)));
    }

    @Test void tamperedEnvelopeAndUnauthenticatedOuterVersionAreUnavailable() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        fixture.enroll();
        TotpStoreRecord record = assertInstanceOf(TotpStoreEntry.Present.class,
                fixture.accountRecordEntry()).getRecord();
        byte[] corrupt = record.getSealedBytes();
        corrupt[corrupt.length / 2] = corrupt[corrupt.length / 2] == 'A' ? (byte) 'B' : (byte) 'A';
        fixture.store.readReplacement.set(TotpStoreRecord.fromStoredForm(
                record.getKey(), record.getVersion(), corrupt));
        assertInstanceOf(TotpStatusResult.Unavailable.class, fixture.totp.getStatusResult(ACCOUNT));
        fixture.store.readReplacement.set(TotpStoreRecord.fromStoredForm(
                record.getKey(), Base64Url.encode(new byte[32]), record.getSealedBytes()));
        assertInstanceOf(TotpStatusResult.Unavailable.class, fixture.totp.getStatusResult(ACCOUNT));
        fixture.store.readReplacement.set(null);
        assertTrue(fixture.status().getActiveFactor().isPresent());
    }

    @Test void recordAddressCannotBeTransplantedToAnotherAccount() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        fixture.enroll();
        TotpStoreRecord record = assertInstanceOf(TotpStoreEntry.Present.class,
                fixture.accountRecordEntry()).getRecord();
        TotpStoreKey other = TotpStoreKey.forAccount(NAMESPACE, EPOCH, "other-account");
        fixture.store.readReplacement.set(TotpStoreRecord.fromStoredForm(
                other, record.getVersion(), record.getSealedBytes()));
        assertInstanceOf(TotpStatusResult.Unavailable.class, fixture.totp.getStatusResult("other-account"));
    }

    @Test void clockRollbackDoesNotReviveEnrollmentOrPermitAuthentication() throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        fixture.clock.advance(Duration.ofSeconds(60));
        assertInstanceOf(TotpVerificationResult.Succeeded.class,
                fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        fixture.clock.advance(Duration.ofMinutes(-1));
        assertFalse(fixture.totp.verifyResult(ACCOUNT, fixture.code(enrolled.pending, 1), LOGIN)
                instanceof TotpVerificationResult.Succeeded);
        assertFalse(fixture.totp.consumeRecoveryCodeResult(ACCOUNT, enrolled.codes.getCodes().get(0), LOGIN)
                instanceof RecoveryCodeUseResult.Succeeded);
    }

    @Test void permanentFactorsSurviveTimeAndAuthenticatedResealingPreservesReplayAndRecoveryState()
            throws GeneralSecurityException {
        Fixture fixture = new Fixture();
        Enrollment enrolled = fixture.enroll();
        assertInstanceOf(RecoveryCodeUseResult.Succeeded.class,
                fixture.totp.consumeRecoveryCodeResult(ACCOUNT, enrolled.codes.getCodes().get(0), LOGIN));
        StateSealer rotatedSealer = StateSealer.withActiveKey(key("new", 43))
                .verificationKeys(List.of(key("old", 11))).build();
        TotpAuthenticator prematureRetirement = authenticator(fixture.store, fixture.clock, fixture.gate,
                StateSealer.withActiveKey(key("new", 43)).build(), EPOCH);
        assertInstanceOf(TotpStatusResult.Unavailable.class, prematureRetirement.getStatusResult(ACCOUNT));
        TotpAuthenticator rotated = authenticator(fixture.store, fixture.clock, fixture.gate, rotatedSealer, EPOCH);
        TotpStoreKey namespaceKey = TotpStoreKey.forNamespace(NAMESPACE, EPOCH);
        TotpStoreKey accountKey = TotpStoreKey.forAccount(NAMESPACE, EPOCH, ACCOUNT);
        assertInstanceOf(TotpStoreResealResult.Resealed.class, rotated.resealStoreEntryResult(namespaceKey));
        assertInstanceOf(TotpStoreResealResult.Resealed.class, rotated.resealStoreEntryResult(accountKey));
        assertInstanceOf(TotpStoreResealResult.AlreadyCurrent.class, rotated.resealStoreEntryResult(accountKey));
        assertInstanceOf(TotpStatusResult.Unavailable.class, fixture.totp.getStatusResult(ACCOUNT));
        TotpAuthenticator newKeyOnly = authenticator(fixture.store, fixture.clock, fixture.gate,
                StateSealer.withActiveKey(key("new", 43)).build(), EPOCH);
        TotpStatus status = assertInstanceOf(TotpStatusResult.Present.class,
                newKeyOnly.getStatusResult(ACCOUNT)).getStatus();
        assertEquals(enrolled.factor.getFactorId(), status.getActiveFactor().orElseThrow().getFactorId());
        assertEquals(enrolled.codes.getBatchId(), status.getRecoveryBatchId().orElseThrow());
        assertEquals(9, status.getRemainingRecoveryCodeCount());
        assertInstanceOf(TotpVerificationResult.Rejected.class,
                newKeyOnly.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        assertInstanceOf(RecoveryCodeUseResult.Rejected.class,
                newKeyOnly.consumeRecoveryCodeResult(ACCOUNT, enrolled.codes.getCodes().get(0), LOGIN));
        fixture.clock.advance(Duration.ofDays(3650));
        assertInstanceOf(TotpVerificationResult.Succeeded.class,
                newKeyOnly.verifyResult(ACCOUNT, fixture.code(enrolled.pending), LOGIN));
        assertInstanceOf(RecoveryCodeUseResult.Succeeded.class,
                newKeyOnly.consumeRecoveryCodeResult(ACCOUNT, enrolled.codes.getCodes().get(1), LOGIN));
    }

    @Test void capacityRefusalDoesNotEvictPermanentStateOrFallBack() {
        InMemoryTotpStore store = InMemoryTotpStore.withNamespace(NAMESPACE, EPOCH).maximumEntries(1).build();
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(1700000010));
        TotpAuthenticator totp = authenticator(store, clock, new Gate(EPOCH),
                StateSealer.withActiveKey(key("old", 11)).build(), EPOCH);
        assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class, totp.initializeNamespaceResult());
        TotpEnrollmentRequestResult.Unavailable failure = assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,
                totp.beginEnrollmentResult(options(null), BROWSER));
        assertEquals(TotpUnavailableReason.CAPACITY_REFUSED, failure.getReason());
        assertInstanceOf(TotpStatusResult.Absent.class, totp.getStatusResult(ACCOUNT));
    }

    private static @NonNull TotpAuthenticator authenticator(@NonNull TotpStore store,
            @NonNull Clock clock, @NonNull TotpRecoveryGate gate, @NonNull StateSealer sealer,
            @NonNull String epoch) {
        return TotpAuthenticator.withIssuer("Example Security").credentialNamespace(NAMESPACE)
                .recoveryEpoch(epoch).store(store).clock(clock).recoveryGate(gate).stateSealer(sealer).build();
    }

    private static @NonNull TotpEnrollmentOptions options(@Nullable String replacingFactorId) {
        return TotpEnrollmentOptions.withAccountId(ACCOUNT).accountName("person@example.com")
                .replacingFactorId(replacingFactorId).build();
    }

    private static @NonNull SealingKey key(@NonNull String id, int offset) {
        byte[] bytes = new byte[32];
        for (int index = 0; index < bytes.length; index++) bytes[index] = (byte) (index + offset);
        return SealingKey.fromBase64(id, Base64.getEncoder().encodeToString(bytes));
    }

    private static byte @NonNull [] decodeBase32(@NonNull String encoded) {
        byte[] result = new byte[encoded.length() * 5 / 8];
        int bits = 0;
        int buffer = 0;
        int position = 0;
        for (int index = 0; index < encoded.length(); index++) {
            int value = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(encoded.charAt(index));
            assertTrue(value >= 0);
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) { bits -= 8; result[position++] = (byte) (buffer >>> bits); }
        }
        return result;
    }

    private static <T extends @NonNull Object> @NonNull List<@NonNull T> race(
            @NonNull Callable<@NonNull T> first, @NonNull Callable<@NonNull T> second) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<T> left = executor.submit(() -> { assertTrue(start.await(5, TimeUnit.SECONDS)); return first.call(); });
            Future<T> right = executor.submit(() -> { assertTrue(start.await(5, TimeUnit.SECONDS)); return second.call(); });
            start.countDown();
            return List.of(left.get(10, TimeUnit.SECONDS), right.get(10, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    @NotThreadSafe
    private static final class Fixture {
        final @NonNull MutableClock clock = new MutableClock(Instant.ofEpochSecond(1700000010));
        final @NonNull InMemoryTotpStore delegate = InMemoryTotpStore.withNamespace(NAMESPACE, EPOCH).build();
        final @NonNull FaultStore store = new FaultStore(this.delegate);
        final @NonNull Gate gate = new Gate(EPOCH);
        final @NonNull StateSealer sealer = StateSealer.withActiveKey(key("old", 11)).build();
        final @NonNull TotpAuthenticator totp = authenticator(this.store, this.clock, this.gate, this.sealer, EPOCH);
        Fixture() { this(true); }
        Fixture(boolean initialize) {
            if (initialize) assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,
                    this.totp.initializeNamespaceResult());
        }
        @NonNull TotpEnrollment begin(@Nullable String replacingFactorId) {
            return assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,
                    this.totp.beginEnrollmentResult(options(replacingFactorId), BROWSER)).getEnrollment();
        }
        @NonNull Enrollment enroll() throws GeneralSecurityException {
            TotpEnrollment pending = begin(null);
            TotpEnrollmentResult.Succeeded result = assertInstanceOf(TotpEnrollmentResult.Succeeded.class,
                    this.totp.confirmEnrollmentResult(ACCOUNT, pending.getEnrollmentId(), code(pending), BROWSER));
            return new Enrollment(pending, result.getFactor(), result.getRecoveryCodes());
        }
        @NonNull TotpStatus status() {
            return assertInstanceOf(TotpStatusResult.Present.class, this.totp.getStatusResult(ACCOUNT)).getStatus();
        }
        @NonNull String code(@NonNull TotpEnrollment enrollment) throws GeneralSecurityException {
            return code(enrollment, 0);
        }
        @NonNull String code(@NonNull TotpEnrollment enrollment, int delta) throws GeneralSecurityException {
            byte[] secret = decodeBase32(enrollment.getManualEntryKey());
            try { return TotpPrimitives.hotp(secret, this.clock.instant().getEpochSecond() / 30 + delta, "HmacSHA1", 6); }
            finally { Arrays.fill(secret, (byte) 0); }
        }
        @NonNull TotpStoreEntry accountRecordEntry() {
            TotpStoreKey key = TotpStoreKey.forAccount(NAMESPACE, EPOCH, ACCOUNT);
            return assertInstanceOf(TotpStoreReadResult.Available.class,
                    this.delegate.read(Set.of(key), Duration.ofSeconds(1))).getSnapshot().getEntry(key);
        }
    }

    @Immutable
    private static final class Enrollment {
        final @NonNull TotpEnrollment pending;
        final @NonNull TotpFactor factor;
        final @NonNull RecoveryCodes codes;
        Enrollment(@NonNull TotpEnrollment pending, @NonNull TotpFactor factor, @NonNull RecoveryCodes codes) {
            this.pending = pending; this.factor = factor; this.codes = codes;
        }
    }

    private static void delayPastShortDeadline() {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(150);
        long remaining;
        while ((remaining = deadline - System.nanoTime()) > 0) LockSupport.parkNanos(remaining);
    }

    @ThreadSafe
    private static final class MutableClock extends Clock {
        private final @NonNull AtomicReference<@NonNull Instant> now;
        MutableClock(@NonNull Instant initial) { this.now = new AtomicReference<>(initial); }
        void advance(@NonNull Duration duration) { this.now.updateAndGet(value -> value.plus(duration)); }
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) throw new IllegalArgumentException("Test clock requires UTC");
            return this;
        }
        @Override public @NonNull Instant instant() { return java.util.Objects.requireNonNull(this.now.get()); }
    }

    /** Test-only epoch admission; production implementations need independent durable state. */
    @ThreadSafe
    private static final class Gate implements TotpRecoveryGate {
        private final @NonNull String epoch;
        final @NonNull AtomicBoolean open = new AtomicBoolean(true);
        final @NonNull AtomicBoolean initiallyStale = new AtomicBoolean();
        final @NonNull AtomicInteger closedPermits = new AtomicInteger();
        final @NonNull AtomicReference<@Nullable Runnable> onNextAcquire = new AtomicReference<>();
        final @NonNull AtomicReference<@Nullable Runnable> onNextClose = new AtomicReference<>();
        final @NonNull List<@NonNull TotpRecoveryContext> contexts = new CopyOnWriteArrayList<>();
        Gate(@NonNull String epoch) { this.epoch = epoch; }
        @Override public TotpRecoveryGate.@Nullable Permit acquire(@NonNull TotpRecoveryContext context,
                @NonNull Duration remainingBudget) {
            this.contexts.add(context);
            Runnable before = this.onNextAcquire.getAndSet(null);
            if (before != null) before.run();
            if (!this.open.get() || !this.epoch.equals(context.getRecoveryEpoch())
                    || !NAMESPACE.equals(context.getCredentialNamespace()) || remainingBudget.isNegative()
                    || remainingBudget.isZero()) return null;
            return new TestPermit(this, System.nanoTime() + remainingBudget.toNanos());
        }
    }

    @NotThreadSafe
    private static final class TestPermit implements TotpRecoveryGate.Permit {
        private final @NonNull Gate gate;
        private final long deadline;
        private boolean closed;
        TestPermit(@NonNull Gate gate, long deadline) { this.gate = gate; this.deadline = deadline; }
        @Override public @NonNull Boolean isCurrent() {
            return !this.closed && !this.gate.initiallyStale.get() && this.gate.open.get()
                    && this.deadline - System.nanoTime() > 0;
        }
        @Override public void close() {
            if (!this.closed) {
                this.closed = true;
                this.gate.closedPermits.incrementAndGet();
                Runnable callback = this.gate.onNextClose.getAndSet(null);
                if (callback != null) callback.run();
            }
        }
    }

    @ThreadSafe
    private static final class FaultStore implements TotpStore {
        private final @NonNull TotpStore delegate;
        final @NonNull AtomicInteger reads = new AtomicInteger();
        final @NonNull AtomicInteger commits = new AtomicInteger();
        final @NonNull AtomicBoolean unknownAfterCommit = new AtomicBoolean();
        final @NonNull AtomicBoolean unknownWithoutMutation = new AtomicBoolean();
        final @NonNull AtomicInteger unknownCommitCountdown = new AtomicInteger();
        final @NonNull AtomicReference<@Nullable Runnable> beforeNextRead = new AtomicReference<>();
        final @NonNull AtomicReference<@Nullable Runnable> beforeNextCommit = new AtomicReference<>();
        final @NonNull AtomicReference<@Nullable Runnable> afterNextCommit = new AtomicReference<>();
        final @NonNull AtomicReference<@Nullable TotpStoreRecord> readReplacement = new AtomicReference<>();
        FaultStore(@NonNull TotpStore delegate) { this.delegate = delegate; }
        @Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,
                @NonNull Duration remainingBudget) {
            this.reads.incrementAndGet();
            Runnable before = this.beforeNextRead.getAndSet(null);
            if (before != null) before.run();
            TotpStoreReadResult result = this.delegate.read(keys, remainingBudget);
            TotpStoreRecord replacement = this.readReplacement.get();
            if (replacement != null && keys.contains(replacement.getKey())
                    && result instanceof TotpStoreReadResult.Available available) {
                Map<TotpStoreKey, TotpStoreEntry> entries = new HashMap<>(available.getSnapshot().getEntries());
                entries.put(replacement.getKey(), TotpStoreEntry.Present.fromRecord(replacement));
                return TotpStoreReadResult.Available.fromSnapshot(TotpStoreSnapshot.fromEntries(keys, entries));
            }
            return result;
        }
        @Override public @NonNull TotpStoreCommitResult compareAndCommit(@NonNull TotpStoreWrite write,
                @NonNull Duration remainingBudget) {
            this.commits.incrementAndGet();
            if (this.unknownWithoutMutation.getAndSet(false)) return TotpStoreCommitResult.UNKNOWN;
            Runnable before = this.beforeNextCommit.getAndSet(null);
            if (before != null) before.run();
            TotpStoreCommitResult result = this.delegate.compareAndCommit(write, remainingBudget);
            Runnable after = this.afterNextCommit.getAndSet(null);
            if (after != null) after.run();
            boolean unknown = this.unknownAfterCommit.getAndSet(false);
            boolean countedUnknown = this.unknownCommitCountdown.getAndUpdate(value -> value > 0 ? value - 1 : 0) == 1;
            return (unknown || countedUnknown) && result == TotpStoreCommitResult.COMMITTED
                    ? TotpStoreCommitResult.UNKNOWN : result;
        }
    }
}
