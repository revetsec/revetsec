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

/** Process-local admission for expensive password work. Share one instance across every hasher in
 * a process. The gate never waits or starts worker threads; exhausted capacity yields an operation
 * result. Applications still own distributed and per-account login throttling.
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

    /** Creates a shared bounded work gate.
     * @param maximumConcurrentCalls maximum simultaneous KDF operations
     * @param maximumMemoryKiB aggregate Argon2id memory reservation in KiB
     * @return the gate
     * @since 1.0.0 */
    public static @NonNull PasswordWorkGate withLimits(int maximumConcurrentCalls, int maximumMemoryKiB) {
        if (maximumConcurrentCalls < 1 || maximumConcurrentCalls > 256
                || maximumMemoryKiB < 19_456 || maximumMemoryKiB > 4_194_304) {
            throw new IllegalArgumentException("Invalid password work limits");
        }
        return new PasswordWorkGate(maximumConcurrentCalls, maximumMemoryKiB);
    }

    /** Returns the concurrency limit for KDF operations.
     * @return the maximum simultaneous KDF operations
     * @since 1.0.0 */
    public @NonNull Integer getMaximumConcurrentCalls() { return maximumConcurrentCalls; }

    /** Returns the shared memory reservation limit.
     * @return the aggregate Argon2id memory reservation in KiB
     * @since 1.0.0 */
    public @NonNull Integer getMaximumMemoryKiB() { return maximumMemoryKiB; }

    @Nullable Permit tryAcquire(int memoryKiB) {
        if (!lock.tryLock()) return null;
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
