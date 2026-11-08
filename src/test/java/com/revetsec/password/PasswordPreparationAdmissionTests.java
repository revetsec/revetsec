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
package com.revetsec.password;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

final class PasswordPreparationAdmissionTests {
    private static final int MEMORY = 19_456;
    private static final Argon2idParameters PARAMETERS = Argon2idParameters.fromCosts(MEMORY, 2, 1);
    private static final String STORED = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAA";
    private static final String BCRYPT = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    private enum Operation { HASH, VERIFY, BCRYPT, PBKDF2 }

    @Test void fullHashGatePrecedesPasswordPreparation() { fullGate(Operation.HASH); }
    @Test void fullNativeVerifyGatePrecedesPasswordPreparation() { fullGate(Operation.VERIFY); }
    @Test void fullBcryptGatePrecedesPasswordPreparation() { fullGate(Operation.BCRYPT); }
    @Test void fullPbkdf2GatePrecedesPasswordPreparation() { fullGate(Operation.PBKDF2); }

    private static void fullGate(@NonNull Operation operation) {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        PasswordHasher hasher = hasher(gate);
        char[][] inputs = {new char[]{'a', '\uD800'}, new char[1025], ("a" + "\u0315\u0300".repeat(500)).toCharArray()};
        try (PasswordWorkGate.Permit held = requireNonNull(gate.tryAcquire(MEMORY))) {
            for (char[] input : inputs) {
                char[] copy = input.clone();
                unavailable(operation, invoke(operation, hasher, input), PasswordUnavailableReason.WORK_CAPACITY);
                assertArrayEquals(copy, input, "caller retains ownership");
            }
        } finally { for (char[] input : inputs) Arrays.fill(input, '\0'); }
        available(gate);
    }

    @Test void deniedHashCannotInvokePepperSource() {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        AtomicInteger calls = new AtomicInteger();
        PasswordHasher hasher = PasswordHasher.withArgon2id(PARAMETERS).workGate(gate)
            .pepperSource(() -> { calls.incrementAndGet(); return PasswordPepperSnapshotResult.unavailable(); }).build();
        try (PasswordWorkGate.Permit held = requireNonNull(gate.tryAcquire(MEMORY))) {
            unavailable(Operation.HASH, hasher.hashResult("pw".toCharArray()), PasswordUnavailableReason.WORK_CAPACITY);
            assertEquals(0, calls.get());
        }
        available(gate);
    }

    @Test void deniedNativeVerificationCannotInvokePepperSource() {
        PasswordPepperSnapshot snapshot = snapshot();
        PasswordHasher producer = PasswordHasher.withArgon2id(PARAMETERS)
            .workGate(PasswordWorkGate.fromInMemoryLimits(1, MEMORY))
            .pepperSource(PasswordPepperSource.fromSnapshot(snapshot)).build();
        String stored = assertInstanceOf(PasswordHashResult.Succeeded.class, producer.hashResult("pw".toCharArray()))
            .getPasswordHash().getStoredForm();
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        AtomicInteger calls = new AtomicInteger();
        PasswordHasher hasher = PasswordHasher.withArgon2id(PARAMETERS).workGate(gate)
            .pepperSource(() -> { calls.incrementAndGet(); return PasswordPepperSnapshotResult.unavailable(); }).build();
        try (PasswordWorkGate.Permit held = requireNonNull(gate.tryAcquire(MEMORY))) {
            unavailable(Operation.VERIFY, hasher.verifyResult("pw".toCharArray(), stored), PasswordUnavailableReason.WORK_CAPACITY);
            assertEquals(0, calls.get());
        }
        available(gate);
    }

    @Test void pepperCallbackRunsUnderSameWorkReservationOutsideAccountingLock() {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        AtomicBoolean reserved = new AtomicBoolean();
        PasswordPepperSnapshot snapshot = snapshot();
        PasswordHasher hasher = PasswordHasher.withArgon2id(PARAMETERS).workGate(gate).pepperSource(() -> {
            PasswordWorkGate.Permit second = gate.tryAcquire(0);
            reserved.set(second == null);
            if (second != null) second.close();
            return PasswordPepperSnapshotResult.available(snapshot);
        }).build();
        assertInstanceOf(PasswordHashResult.Succeeded.class, hasher.hashResult("pw".toCharArray()));
        assertTrue(reserved.get(), "preparation, callback and KDF share one permit");
        available(gate);
    }

    @Test void rejectedPreparationReturnsEveryReservationAndPreservesCallerInput() {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        PasswordHasher hasher = hasher(gate);
        for (Operation operation : Operation.values()) {
            char[] input = {'a', '\uD800'}; char[] original = input.clone();
            Object result = invoke(operation, hasher, input);
            if (operation == Operation.HASH) assertEquals(PasswordRejectionReason.INVALID_PASSWORD,
                assertInstanceOf(PasswordHashResult.Rejected.class, result).getReason());
            else assertEquals(PasswordRejectionReason.INVALID_PASSWORD,
                assertInstanceOf(PasswordVerificationResult.Rejected.class, result).getReason());
            assertArrayEquals(original, input); available(gate); Arrays.fill(input, '\0'); Arrays.fill(original, '\0');
        }
    }

    @Test void unavailablePepperAndCancellationReturnReservation() {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        PasswordHasher failing = PasswordHasher.withArgon2id(PARAMETERS).workGate(gate)
            .pepperSource(() -> { throw new IllegalStateException("scripted"); }).build();
        unavailable(Operation.HASH, failing.hashResult("pw".toCharArray()), PasswordUnavailableReason.PEPPER_UNAVAILABLE);
        available(gate);
        PasswordPepperSnapshot current = snapshot();
        PasswordHasher interrupted = PasswordHasher.withArgon2id(PARAMETERS).workGate(gate)
            .pepperSource(() -> { Thread.currentThread().interrupt(); return PasswordPepperSnapshotResult.available(current); }).build();
        try {
            unavailable(Operation.HASH, interrupted.hashResult("pw".toCharArray()), PasswordUnavailableReason.INTERRUPTED);
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); }
        available(gate);
    }

    @Test void validStoredCostAboveGateTotalIsIntentionallyUnavailableEvenWhenIdle() {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        PasswordHasher hasher = hasher(gate);
        unavailable(Operation.VERIFY, hasher.verifyResult("pw".toCharArray(), STORED.replace("m=19456", "m=32768")), PasswordUnavailableReason.WORK_CAPACITY);
        available(gate);
    }

    @Test void malformedStoredRecordStillRejectsBeforeGateAdmission() {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        try (PasswordWorkGate.Permit held = requireNonNull(gate.tryAcquire(MEMORY))) {
            assertEquals(PasswordRejectionReason.INVALID_STORED_HASH,
                assertInstanceOf(PasswordVerificationResult.Rejected.class, hasher(gate).verifyResult("pw".toCharArray(), STORED.replace("m=19456", "m=999999999"))).getReason());
        }
        available(gate);
    }

    @Test void establishedNfcCohortExamplesRetainMatchingAndExactLegacyBehavior() {
        PasswordHasher hasher = hasher(PasswordWorkGate.fromInMemoryLimits(1, MEMORY));
        String[][] pairs = {{"caf\u00e9", "cafe\u0301"}, {"\uac01", "\u1100\u1161\u11a8"}, {"\u00c5", "A\u030a"}, {"a\u0300\u0315", "a\u0315\u0300"}};
        for (String[] pair : pairs) {
            String stored = assertInstanceOf(PasswordHashResult.Succeeded.class, hasher.hashResult(pair[0].toCharArray())).getPasswordHash().getStoredForm();
            assertInstanceOf(PasswordVerificationResult.Matched.class, hasher.verifyResult(pair[1].toCharArray(), stored));
            assertInstanceOf(PasswordVerificationResult.NotMatched.class, hasher.verifyResult((pair[1]+"x").toCharArray(), stored));
        }
        assertInstanceOf(PasswordVerificationResult.Matched.class, hasher.verifyLegacyBcryptResult("U*U".toCharArray(), BCRYPT));
    }

    private static @NonNull PasswordPepperSnapshot snapshot() {
        byte[] bytes = new byte[32]; for (int i=0;i<bytes.length;i++) bytes[i]=(byte)(i+7);
        try { return PasswordPepperSnapshot.withActiveKey(PasswordPepperKey.fromBytes("preparation", bytes)).build(); }
        finally { Arrays.fill(bytes, (byte) 0); }
    }
    private static @NonNull PasswordHasher hasher(@NonNull PasswordWorkGate gate) {
        return PasswordHasher.withArgon2id(PARAMETERS).workGate(gate)
            .legacyBcrypt(LegacyPasswordPreparation.NFC_UTF8, 5)
            .legacyPbkdf2(LegacyPasswordPreparation.NFC_UTF8, 100).build();
    }
    private static @NonNull Object invoke(@NonNull Operation operation, @NonNull PasswordHasher hasher, char @NonNull [] input) {
        return switch (operation) {
            case HASH -> hasher.hashResult(input);
            case VERIFY -> hasher.verifyResult(input, STORED);
            case BCRYPT -> hasher.verifyLegacyBcryptResult(input, BCRYPT);
            case PBKDF2 -> hasher.verifyLegacyPbkdf2Result(input, Pbkdf2Hmac.SHA256, 1, new byte[16], new byte[32]);
        };
    }
    private static void unavailable(@NonNull Operation operation, @NonNull Object result, @NonNull PasswordUnavailableReason reason) {
        if (operation == Operation.HASH) assertEquals(reason, assertInstanceOf(PasswordHashResult.Unavailable.class, result).getReason());
        else assertEquals(reason, assertInstanceOf(PasswordVerificationResult.Unavailable.class, result).getReason());
    }
    private static void available(@NonNull PasswordWorkGate gate) {
        try (PasswordWorkGate.Permit permit = requireNonNull(gate.tryAcquire(MEMORY))) { assertNotNull(permit); }
    }
}
