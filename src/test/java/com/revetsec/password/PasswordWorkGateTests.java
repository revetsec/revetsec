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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

final class PasswordWorkGateTests {
    private static final int MEMORY = 19_456;
    private static final Argon2idParameters PARAMETERS = Argon2idParameters.fromCosts(MEMORY, 2, 1);
    private static final String BCRYPT = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";

    private enum Operation { HASH, VERIFY, BCRYPT, PBKDF2 }

    @Test void counterContentionDoesNotRejectAvailableCapacityForHash() throws Exception {
        assertAvailableCapacity(Operation.HASH);
    }
    @Test void counterContentionDoesNotRejectAvailableCapacityForVerification() throws Exception {
        assertAvailableCapacity(Operation.VERIFY);
    }
    @Test void counterContentionDoesNotRejectAvailableCapacityForBcrypt() throws Exception {
        assertAvailableCapacity(Operation.BCRYPT);
    }
    @Test void counterContentionDoesNotRejectAvailableCapacityForPbkdf2() throws Exception {
        assertAvailableCapacity(Operation.PBKDF2);
    }

    private static void assertAvailableCapacity(@NonNull Operation operation) throws Exception {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(2, 2 * MEMORY);
        Supplier<Object> call = operation(operation, gate);
        // One operation already owns capacity; another complete reservation still fits.
        try (PasswordWorkGate.Permit existing = requireNonNull(gate.tryAcquire(MEMORY))) {
            Attempt attempt = contend(gate, call, false);
            Object result = attempt.result();
            if (operation == Operation.HASH) assertInstanceOf(PasswordHashResult.Succeeded.class, result);
            else assertInstanceOf(PasswordVerificationResult.Matched.class, result);
        }
        assertEntireBudgetAvailable(gate, 2 * MEMORY);
    }

    @Test void interruptedCounterWaitReportsInterruptionForHash() throws Exception {
        assertInterruptedCounterWait(Operation.HASH);
    }
    @Test void interruptedCounterWaitReportsInterruptionForVerification() throws Exception {
        assertInterruptedCounterWait(Operation.VERIFY);
    }
    @Test void interruptedCounterWaitReportsInterruptionForBcrypt() throws Exception {
        assertInterruptedCounterWait(Operation.BCRYPT);
    }
    @Test void interruptedCounterWaitReportsInterruptionForPbkdf2() throws Exception {
        assertInterruptedCounterWait(Operation.PBKDF2);
    }

    private static void assertInterruptedCounterWait(@NonNull Operation operation) throws Exception {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        Attempt attempt = contend(gate, operation(operation, gate), true);
        assertUnavailable(operation, attempt.result(), PasswordUnavailableReason.INTERRUPTED);
        assertTrue(attempt.interrupted.get(), "Cancellation must preserve the worker's interrupt flag");
        assertEntireBudgetAvailable(gate, MEMORY);
    }

    @Test void exhaustedCapacityDoesNotWaitForAnExistingPermitForHash() throws Exception {
        assertExhaustedCapacity(Operation.HASH);
    }
    @Test void exhaustedCapacityDoesNotWaitForAnExistingPermitForVerification() throws Exception {
        assertExhaustedCapacity(Operation.VERIFY);
    }
    @Test void exhaustedCapacityDoesNotWaitForAnExistingPermitForBcrypt() throws Exception {
        assertExhaustedCapacity(Operation.BCRYPT);
    }
    @Test void exhaustedCapacityDoesNotWaitForAnExistingPermitForPbkdf2() throws Exception {
        assertExhaustedCapacity(Operation.PBKDF2);
    }

    private static void assertExhaustedCapacity(@NonNull Operation operation) throws Exception {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        Supplier<Object> call = operation(operation, gate);
        try (PasswordWorkGate.Permit existing = requireNonNull(gate.tryAcquire(MEMORY))) {
            Attempt attempt = contend(gate, call, false);
            assertUnavailable(operation, attempt.result(), PasswordUnavailableReason.WORK_CAPACITY);
            assertFalse(attempt.interrupted.get());
        }
        assertEntireBudgetAvailable(gate, MEMORY);
    }

    @Test void rejectedReservationsDoNotConsumeCapacityAndZeroMemoryWorkStillUsesACallSlot() {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(2, 2 * MEMORY);
        assertNull(gate.tryAcquire(-1));
        assertNull(gate.tryAcquire(2 * MEMORY + 1));
        assertNull(gate.tryAcquire(Integer.MAX_VALUE));
        try (PasswordWorkGate.Permit full = requireNonNull(gate.tryAcquire(2 * MEMORY))) {
            assertNull(gate.tryAcquire(1), "An available call slot cannot exceed the memory budget");
            try (PasswordWorkGate.Permit zero = requireNonNull(gate.tryAcquire(0))) {
                assertNull(gate.tryAcquire(0), "Zero-memory legacy work still consumes a call slot");
            }
        }
        assertEntireBudgetAvailable(gate, 2 * MEMORY);
    }

    @Test void simultaneousAdmissionsUseAllAvailableMemoryWithoutExceedingIt() throws InterruptedException {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(8, 4 * MEMORY);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch admitted = new CountDownLatch(8);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger successes = new AtomicInteger();
        AtomicReference<@Nullable Throwable> failure = new AtomicReference<>();
        List<Thread> workers = new ArrayList<>();
        for (int n = 0; n < 8; n++) {
            Thread worker = new Thread(() -> {
                try {
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    try (PasswordWorkGate.Permit permit = gate.tryAcquire(MEMORY)) {
                        if (permit != null) successes.incrementAndGet();
                        admitted.countDown();
                        assertTrue(release.await(5, TimeUnit.SECONDS));
                    }
                } catch (Throwable t) {
                    failure.compareAndSet(null, t);
                    admitted.countDown();
                }
            }, "password-gate-admission-" + n);
            worker.setDaemon(true);
            workers.add(worker);
        }
        try {
            workers.forEach(Thread::start);
            start.countDown();
            assertTrue(admitted.await(5, TimeUnit.SECONDS));
            assertNull(failure.get());
            assertEquals(4, successes.get(), "Exactly four reservations fit while all remain outstanding");
            assertNull(gate.tryAcquire(1));
            try (PasswordWorkGate.Permit zero = requireNonNull(gate.tryAcquire(0))) {
                assertNotNull(zero);
            }
        } finally {
            release.countDown();
            stop(workers);
        }
        assertNull(failure.get());
        assertEntireBudgetAvailable(gate, 4 * MEMORY);
    }

    @Test void concurrentRepeatedCloseReturnsOnlyItsOwnReservation() throws InterruptedException {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(2, 2 * MEMORY);
        PasswordWorkGate.Permit closing = requireNonNull(gate.tryAcquire(MEMORY));
        CountDownLatch start = new CountDownLatch(1);
        List<Thread> workers = new ArrayList<>();
        AtomicReference<@Nullable Throwable> failure = new AtomicReference<>();
        try (PasswordWorkGate.Permit remaining = requireNonNull(gate.tryAcquire(MEMORY)); closing) {
            for (int n = 0; n < 8; n++) {
                Thread worker = new Thread(() -> {
                    try {
                        assertTrue(start.await(5, TimeUnit.SECONDS));
                        closing.close();
                    } catch (Throwable t) {
                        failure.compareAndSet(null, t);
                    }
                }, "password-gate-close-" + n);
                worker.setDaemon(true);
                workers.add(worker);
            }
            try {
                workers.forEach(Thread::start);
                start.countDown();
                for (Thread worker : workers) {
                    worker.join(5_000);
                    assertFalse(worker.isAlive());
                }
                assertNull(failure.get());
                assertNull(gate.tryAcquire(MEMORY + 1), "The other permit's memory remains reserved");
                try (PasswordWorkGate.Permit replacement = requireNonNull(gate.tryAcquire(MEMORY))) {
                    assertNull(gate.tryAcquire(0), "Closing one permit cannot return multiple call slots");
                }
            } finally {
                start.countDown();
                stop(workers);
            }
        }
        assertEntireBudgetAvailable(gate, 2 * MEMORY);
    }

    @Test void interruptedPermitCloseStillReturnsItsReservation() throws Exception {
        PasswordWorkGate gate = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        try (PasswordWorkGate.Permit permit = requireNonNull(gate.tryAcquire(MEMORY))) {
            Attempt attempt = contend(gate, () -> {
                Thread.currentThread().interrupt();
                permit.close();
                return Boolean.TRUE;
            }, false);
            assertEquals(Boolean.TRUE, attempt.result());
            assertTrue(attempt.interrupted.get());
        }
        assertEntireBudgetAvailable(gate, MEMORY);
    }

    @Test void configuredLimitsAreInspectableAtBothSupportedBoundaries() {
        PasswordWorkGate minimum = PasswordWorkGate.fromInMemoryLimits(1, MEMORY);
        assertEquals(1, minimum.getMaximumConcurrentCalls());
        assertEquals(MEMORY, minimum.getMaximumMemoryKiB());
        PasswordWorkGate maximum = PasswordWorkGate.fromInMemoryLimits(256, 4_194_304);
        assertEquals(256, maximum.getMaximumConcurrentCalls());
        assertEquals(4_194_304, maximum.getMaximumMemoryKiB());
        assertThrows(IllegalArgumentException.class, () -> PasswordWorkGate.fromInMemoryLimits(0, MEMORY));
        assertThrows(IllegalArgumentException.class, () -> PasswordWorkGate.fromInMemoryLimits(257, MEMORY));
        assertThrows(IllegalArgumentException.class, () -> PasswordWorkGate.fromInMemoryLimits(1, MEMORY - 1));
        assertThrows(IllegalArgumentException.class, () -> PasswordWorkGate.fromInMemoryLimits(1, 4_194_305));
    }

    private static @NonNull Supplier<@NonNull Object> operation(@NonNull Operation operation,
            @NonNull PasswordWorkGate gate) {
        PasswordHasher hasher = PasswordHasher.withArgon2id(PARAMETERS).workGate(gate)
                .legacyBcrypt(LegacyPasswordPreparation.EXACT_UTF8, 5)
                .legacyPbkdf2(LegacyPasswordPreparation.EXACT_UTF8, 10_000).build();
        return switch (operation) {
            case HASH -> () -> hasher.hashResult("pw".toCharArray());
            case VERIFY -> {
                PasswordHasher producer = PasswordHasher.withArgon2id(PARAMETERS)
                        .workGate(PasswordWorkGate.fromInMemoryLimits(1, MEMORY)).build();
                String stored = assertInstanceOf(PasswordHashResult.Succeeded.class,
                        producer.hashResult("pw".toCharArray())).getPasswordHash().getStoredForm();
                yield () -> hasher.verifyResult("pw".toCharArray(), stored);
            }
            case BCRYPT -> () -> hasher.verifyLegacyBcryptResult("U*U".toCharArray(), BCRYPT);
            case PBKDF2 -> () -> hasher.verifyLegacyPbkdf2Result("password".toCharArray(), Pbkdf2Hmac.SHA256,
                    1, "0123456789abcdef".getBytes(StandardCharsets.US_ASCII), HexFormat.of().parseHex(
                            "ef9d5f6add4a5d19f4a7fc92b48f2351ea95bb977642c0071ed4e4010a42cb6c"));
        };
    }

    private static void assertUnavailable(@NonNull Operation operation, @NonNull Object result,
            @NonNull PasswordUnavailableReason reason) {
        if (operation == Operation.HASH)
            assertEquals(reason, assertInstanceOf(PasswordHashResult.Unavailable.class, result).getReason());
        else assertEquals(reason, assertInstanceOf(PasswordVerificationResult.Unavailable.class, result).getReason());
    }

    private static void assertEntireBudgetAvailable(@NonNull PasswordWorkGate gate, int memory) {
        try (PasswordWorkGate.Permit permit = requireNonNull(gate.tryAcquire(memory))) {
            assertNotNull(permit);
        }
    }

    private static @NonNull Attempt contend(@NonNull PasswordWorkGate gate,
            @NonNull Supplier<@NonNull Object> operation, boolean interrupt) throws Exception {
        // Hold the actual bookkeeping mutex to force the schedule, without a production test hook.
        var field = PasswordWorkGate.class.getDeclaredField("lock");
        field.setAccessible(true);
        ReentrantLock counterLock = (ReentrantLock) requireNonNull(field.get(gate));
        Attempt attempt = new Attempt(operation);
        counterLock.lock();
        try {
            attempt.worker.start();
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (!counterLock.hasQueuedThread(attempt.worker) && attempt.done.getCount() != 0
                    && System.nanoTime() < deadline) LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
            assertTrue(counterLock.hasQueuedThread(attempt.worker) || attempt.done.getCount() == 0,
                    "The worker must reach bookkeeping contention or complete before the mutex is released");
            if (interrupt) {
                attempt.worker.interrupt();
                assertTrue(attempt.done.await(5, TimeUnit.SECONDS),
                        "A cancelled counter wait must finish while the mutex remains held");
            }
        } finally {
            counterLock.unlock();
            attempt.worker.join(10_000);
            if (attempt.worker.isAlive()) {
                attempt.worker.interrupt();
                attempt.worker.join(5_000);
            }
            assertFalse(attempt.worker.isAlive());
        }
        return attempt;
    }

    private static void stop(@NonNull List<@NonNull Thread> workers) throws InterruptedException {
        for (Thread worker : workers) {
            worker.join(5_000);
            if (worker.isAlive()) {
                worker.interrupt();
                worker.join(5_000);
            }
            assertFalse(worker.isAlive());
        }
    }

    private static final class Attempt {
        private final @NonNull AtomicReference<@Nullable Object> value = new AtomicReference<>();
        private final @NonNull AtomicReference<@Nullable Throwable> failure = new AtomicReference<>();
        private final @NonNull AtomicBoolean interrupted = new AtomicBoolean();
        private final @NonNull CountDownLatch done = new CountDownLatch(1);
        private final @NonNull Thread worker;

        Attempt(@NonNull Supplier<@NonNull Object> operation) {
            this.worker = new Thread(() -> {
                try {
                    this.value.set(operation.get());
                } catch (Throwable t) {
                    this.failure.set(t);
                } finally {
                    this.interrupted.set(Thread.currentThread().isInterrupted());
                    this.done.countDown();
                }
            }, "password-gate-counter-contention");
            this.worker.setDaemon(true);
        }

        @NonNull Object result() {
            assertNull(this.failure.get());
            return requireNonNull(this.value.get());
        }
    }
}
