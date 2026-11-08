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

import javax.annotation.concurrent.ThreadSafe;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

/** Explicit in-memory, process-local admission for expensive password work. Share one instance
 * across every hasher in a process; each JVM needs its own gate to bound that JVM's CPU and memory.
 * Its temporary counters are discarded on restart and are never shared across nodes.
 * Admission waits interruptibly for short reservation-counter updates. The gate never queues
 * for KDF capacity or starts worker threads; exhausted capacity yields an operation result.
 * Password preparation, hashing and application callbacks run outside the accounting lock.
 * One permit covers normalization/encoding, pepper lookup and KDF cleanup; it is not released
 * between those phases. Input length caps do not guarantee a normalization wall-time bound.
 * Applications separately own shared per-account/edge attempt admission and durable credential storage.
 * @since 1.0.0 */
@ThreadSafe
public final class PasswordWorkGate {
    private final int maximumConcurrentCalls;
    private final int maximumMemoryKiB;
    private final @NonNull ReentrantLock lock = new ReentrantLock();
    private int activeCalls;
    private int reservedMemoryKiB;

    private PasswordWorkGate(int maximumConcurrentCalls, int maximumMemoryKiB) {
        this.maximumConcurrentCalls = maximumConcurrentCalls;
        this.maximumMemoryKiB = maximumMemoryKiB;
    }

    /** Creates a bounded in-memory work gate for one JVM. Reuse the returned instance across all
     * hashers in that JVM. Separate calls create independent gates; this factory supplies no
     * default concurrency or memory budget and performs no distributed attempt throttling.
     * @param maximumConcurrentCalls maximum simultaneous password operations, from 1 through 256
     * @param maximumMemoryKiB aggregate Argon2id memory reservation in KiB, from 19,456 through 4,194,304
     * @return the gate
     * @throws IllegalArgumentException if either limit is outside its supported range
     * @since 1.0.0 */
    public static @NonNull PasswordWorkGate fromInMemoryLimits(int maximumConcurrentCalls, int maximumMemoryKiB) {
        if (maximumConcurrentCalls < 1 || maximumConcurrentCalls > 256
                || maximumMemoryKiB < 19_456 || maximumMemoryKiB > 4_194_304) {
            throw new IllegalArgumentException("Invalid password work limits");
        }
        return new PasswordWorkGate(maximumConcurrentCalls, maximumMemoryKiB);
    }

    /** Returns the concurrency limit for admitted password operations.
     * @return the maximum simultaneous password operations
     * @since 1.0.0 */
    public @NonNull Integer getMaximumConcurrentCalls() { return maximumConcurrentCalls; }

    /** Returns the shared memory reservation limit.
     * @return the aggregate Argon2id memory reservation in KiB
     * @since 1.0.0 */
    public @NonNull Integer getMaximumMemoryKiB() { return maximumMemoryKiB; }

    @Nullable Permit tryAcquire(int memoryKiB) {
        try {
            lock.lockInterruptibly();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
        try {
            if (memoryKiB < 0 || memoryKiB > maximumMemoryKiB || activeCalls >= maximumConcurrentCalls
                    || reservedMemoryKiB > maximumMemoryKiB - memoryKiB) return null;
            activeCalls++;
            reservedMemoryKiB += memoryKiB;
            return new Permit(this, memoryKiB);
        } finally {
            lock.unlock();
        }
    }

    private void release(int memoryKiB) {
        lock.lock();
        try {
            activeCalls--;
            reservedMemoryKiB -= memoryKiB;
        } finally {
            lock.unlock();
        }
    }

    @ThreadSafe
    static final class Permit implements AutoCloseable {
        private final @NonNull PasswordWorkGate gate;
        private final int memoryKiB;
        private final @NonNull AtomicBoolean closed = new AtomicBoolean();

        private Permit(@NonNull PasswordWorkGate gate, int memoryKiB) {
            this.gate = gate;
            this.memoryKiB = memoryKiB;
        }

        @Override public void close() {
            if (closed.compareAndSet(false, true)) gate.release(memoryKiB);
        }
    }
}
