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
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class PasswordHasherTests {
    private static final Argon2idParameters PARAMETERS = Argon2idParameters.withCosts(19_456, 2, 1);
    private static final String BCRYPT_2A = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";

    @Test void nativeRoundTripUsesCanonicalStoredFormAndFullNfcPassword() {
        PasswordHasher hasher = hasher();
        PasswordHashResult.Succeeded first = assertInstanceOf(PasswordHashResult.Succeeded.class,
                hasher.hashResult("café🔒".toCharArray()));
        PasswordHashResult.Succeeded second = assertInstanceOf(PasswordHashResult.Succeeded.class,
                hasher.hashResult("café🔒".toCharArray()));
        String stored = first.getPasswordHash().getStoredForm();
        assertTrue(stored.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));
        assertNotEquals(stored, second.getPasswordHash().getStoredForm());
        PasswordVerificationResult.Matched matched = assertInstanceOf(PasswordVerificationResult.Matched.class,
                hasher.verifyResult("cafe\u0301🔒".toCharArray(), stored));
        assertFalse(matched.isRehashRecommended());
        assertInstanceOf(PasswordVerificationResult.NotMatched.class,
                hasher.verifyResult("cafe\u0301🔓".toCharArray(), stored));
        assertFalse(first.toString().contains(stored));
        assertFalse(first.getPasswordHash().toString().contains(stored));
    }

    @Test void invalidInputsAndStoredCostsAreRejectedBeforeKdfAdmission() {
        PasswordWorkGate gate = PasswordWorkGate.withLimits(1, 19_456);
        PasswordHasher hasher = PasswordHasher.withArgon2id(PARAMETERS).workGate(gate).build();
        assertEquals(PasswordRejectionReason.INVALID_PASSWORD,
                assertInstanceOf(PasswordHashResult.Rejected.class,
                        hasher.hashResult(new char[]{'a', '\uD800'})).getReason());
        assertEquals(PasswordRejectionReason.PASSWORD_TOO_LONG,
                assertInstanceOf(PasswordHashResult.Rejected.class,
                        hasher.hashResult(new char[1_025])).getReason());
        String excessiveCost = "$argon2id$v=19$m=999999999,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$"
                + "AAAAAAAAAAAAAAAAAAAAAA";
        try (PasswordWorkGate.Permit ignored = gate.tryAcquire(19_456)) {
            assertEquals(PasswordRejectionReason.INVALID_STORED_HASH,
                    assertInstanceOf(PasswordVerificationResult.Rejected.class,
                            hasher.verifyResult("pw".toCharArray(), excessiveCost)).getReason());
        }
        assertEquals(PasswordRejectionReason.UNSUPPORTED_STORED_HASH,
                assertInstanceOf(PasswordVerificationResult.Rejected.class,
                        hasher.verifyResult("pw".toCharArray(), "$2a$05$...")).getReason());
    }

    @Test void sharedGateLimitsMemoryAndConcurrentCallsWithoutBlocking() {
        PasswordWorkGate gate = PasswordWorkGate.withLimits(1, 19_456);
        PasswordHasher hasher = PasswordHasher.withArgon2id(PARAMETERS).workGate(gate).build();
        PasswordWorkGate.Permit reservation = Objects.requireNonNull(gate.tryAcquire(19_456));
        assertEquals(PasswordUnavailableReason.WORK_CAPACITY,
                assertInstanceOf(PasswordHashResult.Unavailable.class,
                        hasher.hashResult("pw".toCharArray())).getReason());
        reservation.close();
        reservation.close();
        assertInstanceOf(PasswordHashResult.Succeeded.class, hasher.hashResult("pw".toCharArray()));
    }

    @Test void sharedGateAccountsForOverlappingThreadsAndReleasesEveryReservation() throws InterruptedException {
        PasswordWorkGate gate = PasswordWorkGate.withLimits(2, 38_912);
        CountDownLatch firstHolding = new CountDownLatch(1);
        CountDownLatch secondHolding = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch releaseSecond = new CountDownLatch(1);
        AtomicReference<@Nullable Throwable> failure = new AtomicReference<>();
        Thread first = holdingThread(gate, firstHolding, releaseFirst, failure);
        Thread second = holdingThread(gate, secondHolding, releaseSecond, failure);
        try {
            first.start();
            assertTrue(firstHolding.await(5, TimeUnit.SECONDS));
            second.start();
            assertTrue(secondHolding.await(5, TimeUnit.SECONDS));
            assertNull(gate.tryAcquire(0), "Both concurrent-call slots must be reserved");

            releaseSecond.countDown();
            second.join(5_000);
            assertFalse(second.isAlive());
            assertNull(gate.tryAcquire(19_457), "The first thread still reserves 19,456 KiB");
            try (PasswordWorkGate.Permit permit = Objects.requireNonNull(gate.tryAcquire(19_456))) {
                assertNull(gate.tryAcquire(0));
            }

            releaseFirst.countDown();
            first.join(5_000);
            assertFalse(first.isAlive());
            assertNull(failure.get());
            try (PasswordWorkGate.Permit ignored = Objects.requireNonNull(gate.tryAcquire(38_912))) {
                assertNull(gate.tryAcquire(1), "The entire memory budget is reserved");
            }
        } finally {
            releaseFirst.countDown();
            releaseSecond.countDown();
            first.interrupt();
            second.interrupt();
            first.join(5_000);
            second.join(5_000);
        }
    }

    @Test void dynamicPepperSnapshotIsCoherentAcrossConcurrentRotationAndOutage() throws InterruptedException {
        PasswordPepperKey oldKey = key("old-dynamic", 5);
        PasswordPepperKey newKey = key("new-dynamic", 6);
        PasswordPepperSnapshot oldSnapshot = PasswordPepperSnapshot.withActiveKey(oldKey).build();
        PasswordPepperSnapshot rotatedSnapshot = PasswordPepperSnapshot.withActiveKey(newKey)
                .retainedKeys(List.of(oldKey)).build();
        String oldStored = assertInstanceOf(PasswordHashResult.Succeeded.class,
                peppered(oldSnapshot).hashResult("pw".toCharArray())).getPasswordHash().getStoredForm();

        AtomicReference<PasswordPepperSnapshotResult> current = new AtomicReference<>(
                PasswordPepperSnapshotResult.available(oldSnapshot));
        AtomicInteger snapshotCalls = new AtomicInteger();
        CountDownLatch snapshotRead = new CountDownLatch(1);
        CountDownLatch releaseSnapshot = new CountDownLatch(1);
        PasswordPepperSource dynamicSource = () -> {
            PasswordPepperSnapshotResult observed = Objects.requireNonNull(current.get());
            snapshotCalls.incrementAndGet();
            snapshotRead.countDown();
            try {
                if (!releaseSnapshot.await(5, TimeUnit.SECONDS))
                    return PasswordPepperSnapshotResult.unavailable();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return PasswordPepperSnapshotResult.unavailable();
            }
            return observed;
        };
        PasswordHasher dynamic = PasswordHasher.withArgon2id(PARAMETERS)
                .workGate(PasswordWorkGate.withLimits(1, 19_456))
                .pepperSource(dynamicSource).build();
        AtomicReference<PasswordVerificationResult> result = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread verifying = new Thread(() -> {
            try {
                result.set(dynamic.verifyResult("pw".toCharArray(), oldStored));
            } catch (Throwable t) {
                failure.set(t);
            }
        }, "password-pepper-rotation-test");
        verifying.setDaemon(true);
        try {
            verifying.start();
            assertTrue(snapshotRead.await(5, TimeUnit.SECONDS));
            current.set(PasswordPepperSnapshotResult.unavailable());
            releaseSnapshot.countDown();
            verifying.join(10_000);
            assertFalse(verifying.isAlive());
            assertNull(failure.get());
            assertFalse(assertInstanceOf(PasswordVerificationResult.Matched.class,
                    result.get()).isRehashRecommended());
            assertEquals(1, snapshotCalls.get(), "One operation must use one coherent snapshot");

            assertEquals(PasswordUnavailableReason.PEPPER_UNAVAILABLE,
                    assertInstanceOf(PasswordVerificationResult.Unavailable.class,
                            dynamic.verifyResult("pw".toCharArray(), oldStored)).getReason());
            current.set(PasswordPepperSnapshotResult.available(rotatedSnapshot));
            assertTrue(assertInstanceOf(PasswordVerificationResult.Matched.class,
                    dynamic.verifyResult("pw".toCharArray(), oldStored)).isRehashRecommended());
            String newStored = assertInstanceOf(PasswordHashResult.Succeeded.class,
                    dynamic.hashResult("pw".toCharArray())).getPasswordHash().getStoredForm();
            assertTrue(newStored.startsWith("$revetsec-pw$v=1$kid=new-dynamic$"));
            assertFalse(assertInstanceOf(PasswordVerificationResult.Matched.class,
                    dynamic.verifyResult("pw".toCharArray(), newStored)).isRehashRecommended());
        } finally {
            releaseSnapshot.countDown();
            verifying.interrupt();
            verifying.join(10_000);
        }
    }

    @Test void interruptedInFlightNativeHashReleasesGatePermit() throws InterruptedException {
        PasswordWorkGate gate = PasswordWorkGate.withLimits(1, 65_536);
        PasswordHasher hasher = PasswordHasher.withArgon2id(Argon2idParameters.withCosts(65_536, 10, 1))
                .workGate(gate)
                .verificationLimits(PasswordVerificationLimits.builder().maximumArgon2idPasses(10).build())
                .build();
        AtomicReference<PasswordHashResult> result = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<Boolean> interruptedFlag = new AtomicReference<>();
        Thread hashing = new Thread(() -> {
            try {
                result.set(hasher.hashResult("pw".toCharArray()));
            } catch (Throwable t) {
                failure.set(t);
            } finally {
                interruptedFlag.set(Thread.currentThread().isInterrupted());
            }
        }, "password-mid-argon2-interruption-test");
        hashing.setDaemon(true);
        try {
            hashing.start();
            assertTrue(awaitStackFrame(hashing, "com.revetsec.internal.password.Argon2id", "fill_segment"),
                    "The worker must enter the Argon2 memory fill before cancellation");
            hashing.interrupt();
            hashing.join(10_000);
            assertFalse(hashing.isAlive());
            assertNull(failure.get());
            assertEquals(PasswordUnavailableReason.INTERRUPTED,
                    assertInstanceOf(PasswordHashResult.Unavailable.class, result.get()).getReason());
            assertEquals(Boolean.TRUE, interruptedFlag.get());
            try (PasswordWorkGate.Permit ignored = Objects.requireNonNull(gate.tryAcquire(65_536))) {
                assertNull(gate.tryAcquire(0));
            }
        } finally {
            hashing.interrupt();
            hashing.join(10_000);
        }
    }

    @Test void pepperRotationRetainsOldKeysAndMissingKeysFailClosed() {
        PasswordPepperKey oldKey = key("old", 1);
        PasswordPepperKey newKey = key("new", 2);
        PasswordHasher oldHasher = peppered(PasswordPepperSnapshot.withActiveKey(oldKey).build());
        String oldStored = assertInstanceOf(PasswordHashResult.Succeeded.class,
                oldHasher.hashResult("pw".toCharArray())).getPasswordHash().getStoredForm();
        assertTrue(oldStored.startsWith("$revetsec-pw$v=1$kid=old$argon2id$"));

        PasswordHasher rotated = peppered(PasswordPepperSnapshot.withActiveKey(newKey).retainedKeys(List.of(oldKey)).build());
        assertTrue(assertInstanceOf(PasswordVerificationResult.Matched.class,
                rotated.verifyResult("pw".toCharArray(), oldStored)).isRehashRecommended());
        String newStored = assertInstanceOf(PasswordHashResult.Succeeded.class,
                rotated.hashResult("pw".toCharArray())).getPasswordHash().getStoredForm();
        assertTrue(newStored.startsWith("$revetsec-pw$v=1$kid=new$argon2id$"));
        assertFalse(assertInstanceOf(PasswordVerificationResult.Matched.class,
                rotated.verifyResult("pw".toCharArray(), newStored)).isRehashRecommended());

        PasswordHasher withoutOldKey = peppered(PasswordPepperSnapshot.withActiveKey(newKey).build());
        assertEquals(PasswordUnavailableReason.PEPPER_UNAVAILABLE,
                assertInstanceOf(PasswordVerificationResult.Unavailable.class,
                        withoutOldKey.verifyResult("pw".toCharArray(), oldStored)).getReason());
        assertEquals(PasswordUnavailableReason.PEPPER_UNAVAILABLE,
                assertInstanceOf(PasswordVerificationResult.Unavailable.class,
                        hasher().verifyResult("pw".toCharArray(), oldStored)).getReason());
        String raw = assertInstanceOf(PasswordHashResult.Succeeded.class,
                hasher().hashResult("pw".toCharArray())).getPasswordHash().getStoredForm();
        assertEquals(PasswordRejectionReason.UNSUPPORTED_STORED_HASH,
                assertInstanceOf(PasswordVerificationResult.Rejected.class,
                        rotated.verifyResult("pw".toCharArray(), raw)).getReason());
    }

    @Test void pepperSnapshotsDefensivelyCopyKeyMaterial() {
        byte[] original = new byte[32];
        for (int i = 0; i < original.length; i++) original[i] = (byte) i;
        PasswordPepperKey key = PasswordPepperKey.fromBytes("v1", original);
        Arrays.fill(original, (byte) 0);
        assertNotEquals(0, key.copyKeyBytes()[31]);
        assertFalse(key.toString().contains("v1"));
        assertThrows(IllegalArgumentException.class,
                () -> PasswordPepperSnapshot.withActiveKey(key).retainedKeys(List.of(key)));
    }

    @Test void retainedKeySetReplacesAtomicallyAndNullRestoresOnlyTheActiveKey() {
        PasswordPepperKey active = key("active", 1);
        PasswordPepperKey first = key("first", 2);
        PasswordPepperKey second = key("second", 3);
        PasswordPepperSnapshot.Builder builder = PasswordPepperSnapshot.withActiveKey(active)
                .retainedKeys(List.of(first));
        assertThrows(IllegalArgumentException.class,
                () -> builder.retainedKeys(List.of(second, second)));
        assertNotNull(builder.build().keyForId("first"));
        assertNull(builder.build().keyForId("second"));
        assertSame(builder, builder.retainedKeys(List.of(second)));
        assertNull(builder.build().keyForId("first"));
        assertNotNull(builder.build().keyForId("second"));
        assertSame(builder, builder.retainedKeys(null));
        assertNull(builder.build().keyForId("second"));
        assertNotNull(builder.build().keyForId("active"));
    }

    @Test void nullableBuilderPropertiesRestoreDefaultsWithoutRemovingRequiredWorkAdmission() {
        PasswordWorkGate gate = PasswordWorkGate.withLimits(1, 19_456);
        PasswordHasher.Builder builder = PasswordHasher.withArgon2id(PARAMETERS).workGate(gate);
        assertThrows(IllegalStateException.class, () -> builder.workGate(null).build());
        assertSame(builder, builder.workGate(gate)
                .verificationLimits(PasswordVerificationLimits.builder().maximumPasswordChars(16_384).build())
                .verificationLimits(null)
                .pepperSource(PasswordPepperSnapshotResult::unavailable));
        assertEquals(PasswordUnavailableReason.PEPPER_UNAVAILABLE,
                assertInstanceOf(PasswordHashResult.Unavailable.class,
                        builder.build().hashResult("pw".toCharArray())).getReason());
        assertSame(builder, builder.pepperSource(null));
        assertEquals(PasswordRejectionReason.PASSWORD_TOO_LONG,
                assertInstanceOf(PasswordHashResult.Rejected.class,
                        builder.build().hashResult("x".repeat(1_025).toCharArray())).getReason());
        assertInstanceOf(PasswordHashResult.Succeeded.class, builder.build().hashResult("pw".toCharArray()));
    }

    @Test void nullableVerificationLimitPropertiesRestoreEveryDefault() {
        PasswordVerificationLimits defaults = PasswordVerificationLimits.fromDefaults();
        PasswordVerificationLimits reset = PasswordVerificationLimits.builder()
                .maximumStoredFormChars(192).maximumStoredFormChars(null)
                .maximumPasswordChars(64).maximumPasswordChars(null)
                .maximumPasswordUtf8Bytes(256).maximumPasswordUtf8Bytes(null)
                .maximumArgon2idMemoryKiB(19_456).maximumArgon2idMemoryKiB(null)
                .maximumArgon2idPasses(2).maximumArgon2idPasses(null)
                .maximumArgon2idLanes(1).maximumArgon2idLanes(null)
                .build();
        assertEquals(defaults.getMaximumStoredFormChars(), reset.getMaximumStoredFormChars());
        assertEquals(defaults.getMaximumPasswordChars(), reset.getMaximumPasswordChars());
        assertEquals(defaults.getMaximumPasswordUtf8Bytes(), reset.getMaximumPasswordUtf8Bytes());
        assertEquals(defaults.getMaximumArgon2idMemoryKiB(), reset.getMaximumArgon2idMemoryKiB());
        assertEquals(defaults.getMaximumArgon2idPasses(), reset.getMaximumArgon2idPasses());
        assertEquals(defaults.getMaximumArgon2idLanes(), reset.getMaximumArgon2idLanes());
    }

    @Test void rehashRecommendationRespectsCostFloorAndLanePolicy() {
        PasswordPepperKey oldKey = key("older", 3);
        PasswordPepperKey currentKey = key("current", 4);
        PasswordHasher strongerHistorical = PasswordHasher
                .withArgon2id(Argon2idParameters.withCosts(47_104, 2, 1))
                .workGate(PasswordWorkGate.withLimits(1, 47_104))
                .pepperSource(PasswordPepperSource.fromSnapshot(
                        PasswordPepperSnapshot.withActiveKey(oldKey).build()))
                .build();
        String strongerStored = assertInstanceOf(PasswordHashResult.Succeeded.class,
                strongerHistorical.hashResult("pw".toCharArray())).getPasswordHash().getStoredForm();
        PasswordHasher lowerCurrent = PasswordHasher.withArgon2id(PARAMETERS)
                .workGate(PasswordWorkGate.withLimits(1, 47_104))
                .pepperSource(PasswordPepperSource.fromSnapshot(PasswordPepperSnapshot
                        .withActiveKey(currentKey).retainedKeys(List.of(oldKey)).build()))
                .build();
        assertFalse(assertInstanceOf(PasswordVerificationResult.Matched.class,
                lowerCurrent.verifyResult("pw".toCharArray(), strongerStored)).isRehashRecommended());

        PasswordHasher differentLanes = PasswordHasher
                .withArgon2id(Argon2idParameters.withCosts(19_456, 2, 2))
                .workGate(PasswordWorkGate.withLimits(1, 19_456)).build();
        String otherLanes = assertInstanceOf(PasswordHashResult.Succeeded.class,
                differentLanes.hashResult("pw".toCharArray())).getPasswordHash().getStoredForm();
        assertTrue(assertInstanceOf(PasswordVerificationResult.Matched.class,
                hasher().verifyResult("pw".toCharArray(), otherLanes)).isRehashRecommended());
    }

    @Test void legacyVerificationIsExplicitAndOnlyMatchesRecommendRehash() {
        PasswordHasher legacy = PasswordHasher.withArgon2id(PARAMETERS)
                .workGate(PasswordWorkGate.withLimits(1, 19_456))
                .legacyBcrypt(LegacyPasswordPreparation.EXACT_UTF8, 5)
                .legacyPbkdf2(LegacyPasswordPreparation.EXACT_UTF8, 10_000)
                .build();
        assertTrue(assertInstanceOf(PasswordVerificationResult.Matched.class,
                legacy.verifyLegacyBcryptResult("U*U".toCharArray(), BCRYPT_2A)).isRehashRecommended());
        assertInstanceOf(PasswordVerificationResult.NotMatched.class,
                legacy.verifyLegacyBcryptResult("wrong".toCharArray(), BCRYPT_2A));
        assertEquals(PasswordRejectionReason.LEGACY_BCRYPT_INPUT_TOO_LONG,
                assertInstanceOf(PasswordVerificationResult.Rejected.class,
                        legacy.verifyLegacyBcryptResult("x".repeat(73).toCharArray(), BCRYPT_2A)).getReason());
        assertEquals(PasswordRejectionReason.INVALID_STORED_HASH,
                assertInstanceOf(PasswordVerificationResult.Rejected.class,
                        legacy.verifyLegacyBcryptResult("U*U".toCharArray(), BCRYPT_2A.replace("$05$", "$16$"))).getReason());

        byte[] salt = "0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] tag = HexFormat.of().parseHex("ef9d5f6add4a5d19f4a7fc92b48f2351ea95bb977642c0071ed4e4010a42cb6c");
        PasswordVerificationResult pbkdf2 = legacy.verifyLegacyPbkdf2Result("password".toCharArray(),
                Pbkdf2Hmac.SHA256, 1, salt, tag);
        assertTrue(assertInstanceOf(PasswordVerificationResult.Matched.class, pbkdf2).isRehashRecommended());
        assertInstanceOf(PasswordVerificationResult.NotMatched.class,
                legacy.verifyLegacyPbkdf2Result("wrong".toCharArray(), Pbkdf2Hmac.SHA256, 1, salt, tag));
        assertTrue(assertInstanceOf(PasswordVerificationResult.Matched.class,
                legacy.verifyLegacyPbkdf2Result("password".toCharArray(), Pbkdf2Hmac.SHA256, 1,
                        "saltysalt".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                        HexFormat.of().parseHex("08d487f3999f74aa4e1a56d250f885f3e3e241d223daa47ac9e715e484f1342f")))
                .isRehashRecommended());
    }

    @Test void widenedPasswordByteLimitWorksForNativeAndPbkdf2Verification() {
        PasswordVerificationLimits limits = PasswordVerificationLimits.builder()
                .maximumPasswordChars(16_384)
                .maximumPasswordUtf8Bytes(65_536)
                .build();
        PasswordHasher passwords = PasswordHasher.withArgon2id(PARAMETERS)
                .workGate(PasswordWorkGate.withLimits(1, 19_456))
                .verificationLimits(limits)
                .legacyPbkdf2(LegacyPasswordPreparation.EXACT_UTF8, 10_000)
                .build();
        char[] longPassword = new char[4_097];
        Arrays.fill(longPassword, 'x');
        try {
            String stored = assertInstanceOf(PasswordHashResult.Succeeded.class,
                    passwords.hashResult(longPassword)).getPasswordHash().getStoredForm();
            assertInstanceOf(PasswordVerificationResult.Matched.class,
                    passwords.verifyResult(longPassword, stored));
            assertInstanceOf(PasswordVerificationResult.Matched.class,
                    passwords.verifyLegacyPbkdf2Result(longPassword, Pbkdf2Hmac.SHA256, 1,
                            "saltysalt".getBytes(java.nio.charset.StandardCharsets.US_ASCII),
                            HexFormat.of().parseHex("77e4af2002cae811f113b3d7b8e7342f"
                                    + "9490ef19c911bb8b8a6808b3c3018a24")));
        } finally {
            Arrays.fill(longPassword, '\0');
        }
    }

    @Test void minimumStoredFormLimitAcceptsMaximumPepperKeyId() {
        PasswordVerificationLimits limits = PasswordVerificationLimits.builder()
                .maximumStoredFormChars(192).build();
        PasswordHasher passwords = PasswordHasher.withArgon2id(PARAMETERS)
                .workGate(PasswordWorkGate.withLimits(1, 19_456))
                .verificationLimits(limits)
                .pepperSource(PasswordPepperSource.fromSnapshot(
                        PasswordPepperSnapshot.withActiveKey(key("k".repeat(64), 1)).build()))
                .build();
        String stored = assertInstanceOf(PasswordHashResult.Succeeded.class,
                passwords.hashResult("pw".toCharArray())).getPasswordHash().getStoredForm();
        assertTrue(stored.length() <= limits.getMaximumStoredFormChars());
        assertInstanceOf(PasswordVerificationResult.Matched.class,
                passwords.verifyResult("pw".toCharArray(), stored));
        assertThrows(IllegalArgumentException.class,
                () -> PasswordVerificationLimits.builder().maximumStoredFormChars(191).build());
    }

    private static @NonNull PasswordHasher hasher() {
        return PasswordHasher.withArgon2id(PARAMETERS)
                .workGate(PasswordWorkGate.withLimits(1, 19_456)).build();
    }

    private static @NonNull PasswordHasher peppered(@NonNull PasswordPepperSnapshot snapshot) {
        return PasswordHasher.withArgon2id(PARAMETERS)
                .workGate(PasswordWorkGate.withLimits(1, 19_456))
                .pepperSource(PasswordPepperSource.fromSnapshot(snapshot)).build();
    }

    private static @NonNull PasswordPepperKey key(@NonNull String id, int offset) {
        byte[] bytes = new byte[32];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (i + offset);
        return PasswordPepperKey.fromBytes(id, bytes);
    }

    private static @NonNull Thread holdingThread(@NonNull PasswordWorkGate gate,
            @NonNull CountDownLatch holding, @NonNull CountDownLatch release,
            @NonNull AtomicReference<@Nullable Throwable> failure) {
        Thread thread = new Thread(() -> {
            try (PasswordWorkGate.Permit ignored = Objects.requireNonNull(gate.tryAcquire(19_456))) {
                holding.countDown();
                if (!release.await(5, TimeUnit.SECONDS))
                    throw new AssertionError("Timed out waiting to release gate permit");
            } catch (Throwable t) {
                failure.compareAndSet(null, t);
            }
        }, "password-work-gate-test");
        thread.setDaemon(true);
        return thread;
    }

    private static boolean awaitStackFrame(@NonNull Thread worker, @NonNull String className,
            @NonNull String methodName) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (worker.isAlive() && System.nanoTime() < deadline) {
            for (StackTraceElement frame : worker.getStackTrace()) {
                if (className.equals(frame.getClassName()) && methodName.equals(frame.getMethodName()))
                    return true;
            }
            Thread.onSpinWait();
        }
        return false;
    }
}
