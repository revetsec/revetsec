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

package com.revetsec.internal.webauthn;

import com.revetsec.webauthn.WebAuthnStore;
import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.function.LongSupplier;

import static java.util.Objects.requireNonNull;

/**
 * One caller-thread, bounded authoritative read, optional expanded read, and at most one compare-and-commit. This
 * coordinator validates callback shapes and withholds success after a late or uncertain write;
 * the provider remains responsible for linearizability, durable commits and capacity fences.
 * No result here is a WebAuthn authentication or registration proof.
 */
final class WebAuthnStoreCoordinator {
    private final @NonNull WebAuthnStore store;
    private final long timeoutNanos;
    private final @NonNull LongSupplier nanoTime;

    WebAuthnStoreCoordinator(@NonNull WebAuthnStore store, @NonNull Duration timeout) {
        this(store, timeout, System::nanoTime);
    }

    /** Clock injection is test-only; production uses the JVM's monotonic clock. */
    WebAuthnStoreCoordinator(@NonNull WebAuthnStore store, @NonNull Duration timeout,
            @NonNull LongSupplier nanoTime) {
        this.store = requireNonNull(store);
        requireNonNull(timeout);
        if (timeout.compareTo(Duration.ofMillis(100)) < 0 || timeout.compareTo(Duration.ofSeconds(30)) > 0)
            throw new IllegalArgumentException("Invalid WebAuthn operation timeout");
        this.timeoutNanos = timeout.toNanos();
        this.nanoTime = requireNonNull(nanoTime);
    }

    @NonNull Attempt begin() {
        return new Attempt(this.nanoTime.getAsLong());
    }

    /** One thread-confined operation. A failed or uncertain attempt cannot be reused. */
    final class Attempt {
        private final @NonNull Thread owner;
        private final long startNanos;
        private long lastRemainingNanos;
        private int readCount;
        private boolean finished;
        private @Nullable WebAuthnStoreSnapshot snapshot;
        private @Nullable Set<@NonNull WebAuthnStoreKey> firstKeys;

        private Attempt(long startNanos) {
            this.owner = Thread.currentThread();
            this.startNanos = startNanos;
            this.lastRemainingNanos = timeoutNanos;
        }

        @NonNull Read read(@NonNull Set<@NonNull WebAuthnStoreKey> keys) {
            checkOwner();
            if (this.readCount != 0 || this.finished) throw new IllegalStateException("Read already attempted");
            Set<WebAuthnStoreKey> requested = Set.copyOf(keys);
            if (requested.isEmpty() || requested.size() > 16)
                throw new IllegalArgumentException("Invalid WebAuthn read set");
            this.readCount = 1;
            this.firstKeys = requested;
            return performRead(requested);
        }

        /** One expanded read after the ceremony supplies the account and credential keys. */
        @NonNull Read readExpanded(@NonNull Set<@NonNull WebAuthnStoreKey> keys) {
            checkOwner();
            if (this.readCount != 1 || this.finished || this.snapshot == null || this.firstKeys == null)
                throw new IllegalStateException("No usable first read or expansion already attempted");
            Set<WebAuthnStoreKey> requested = Set.copyOf(keys);
            if (requested.size() <= this.firstKeys.size() || requested.size() > 16
                    || !requested.containsAll(this.firstKeys))
                throw new IllegalArgumentException("Invalid expanded WebAuthn read set");
            this.readCount = 2;
            this.snapshot = null;
            return performRead(requested);
        }

        private @NonNull Read performRead(@NonNull Set<@NonNull WebAuthnStoreKey> requested) {
            Duration budget = remaining();
            if (budget == null) { this.finished = true; return Read.unavailable(); }

            WebAuthnStoreReadResult result;
            try {
                result = store.read(requested, budget);
            } catch (VirtualMachineError fatal) {
                throw fatal;
            } catch (Throwable failure) {
                preserveInterrupt(failure);
                this.finished = true;
                return Read.unavailable();
            }

            if (remaining() == null || !(result instanceof WebAuthnStoreReadResult.Available available)
                    || !available.getSnapshot().getEntries().keySet().equals(requested)) {
                this.finished = true;
                return Read.unavailable();
            }
            this.snapshot = available.getSnapshot();
            return Read.available(this.snapshot);
        }

        @NonNull Commit commit(@NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations) {
            checkOwner();
            if (this.readCount == 0 || this.finished || this.snapshot == null)
                throw new IllegalStateException("No usable read or write already attempted");
            WebAuthnStoreWrite write = WebAuthnStoreWrite.fromSnapshotAndMutations(this.snapshot, mutations);
            Duration budget = remaining();
            this.finished = true;
            if (budget == null) return Commit.UNAVAILABLE;

            WebAuthnStoreCommitResult result;
            try {
                result = store.compareAndCommit(write, budget);
            } catch (VirtualMachineError fatal) {
                throw fatal;
            } catch (Throwable failure) {
                preserveInterrupt(failure);
                return Commit.INDETERMINATE;
            }

            if (result == null || result == WebAuthnStoreCommitResult.UNKNOWN)
                return Commit.INDETERMINATE;
            // A confirmed late commit still occurred; the operation must withhold proof.
            if (result == WebAuthnStoreCommitResult.COMMITTED)
                return remaining() == null ? Commit.INDETERMINATE : Commit.COMMITTED;
            if (remaining() == null) return Commit.UNAVAILABLE;
            return switch (result) {
                case CONFLICT -> Commit.CONFLICT;
                case CAPACITY -> Commit.CAPACITY;
                case UNAVAILABLE -> Commit.UNAVAILABLE;
                case COMMITTED, UNKNOWN -> throw new IllegalStateException("Handled commit result");
            };
        }

        /** Shares the same shrinking monotonic deadline with an external admission callback. */
        @Nullable Duration remainingBudget() {
            checkOwner();
            return remaining();
        }

        private @Nullable Duration remaining() {
            if (Thread.currentThread().isInterrupted()) return null;
            long elapsed = nanoTime.getAsLong() - this.startNanos;
            if (elapsed < 0 || elapsed >= timeoutNanos) return null;
            long remaining = Math.min(this.lastRemainingNanos, timeoutNanos - elapsed);
            this.lastRemainingNanos = remaining;
            return remaining > 0 ? Duration.ofNanos(remaining) : null;
        }

        private void checkOwner() {
            if (!Thread.currentThread().equals(this.owner))
                throw new IllegalStateException("WebAuthn store attempt used on another thread");
        }
    }

    @SuppressWarnings("ReferenceEquality") // Detect an adversarial self-cause without calling overridable equals().
    static void preserveInterrupt(@NonNull Throwable failure) {
        Throwable current = failure;
        for (int depth = 0; depth < 8 && current != null; depth++) {
            if (current instanceof InterruptedException) {
                Thread.currentThread().interrupt();
                return;
            }
            Throwable cause;
            try { cause = current.getCause(); }
            catch (VirtualMachineError fatal) { throw fatal; }
            catch (Throwable malformedCause) { return; }
            if (cause == current) return;
            current = cause;
        }
    }

    /** An authoritative read or a fixed unavailable outcome. */
    @javax.annotation.concurrent.Immutable
    static final class Read {
        private static final @NonNull Read UNAVAILABLE = new Read(null);
        private final @Nullable WebAuthnStoreSnapshot snapshot;

        private Read(@Nullable WebAuthnStoreSnapshot snapshot) { this.snapshot = snapshot; }
        private static @NonNull Read available(@NonNull WebAuthnStoreSnapshot snapshot) {
            return new Read(requireNonNull(snapshot));
        }
        private static @NonNull Read unavailable() { return UNAVAILABLE; }
        boolean isAvailable() { return this.snapshot != null; }
        @NonNull WebAuthnStoreSnapshot getSnapshot() {
            if (this.snapshot == null) throw new IllegalStateException("No authoritative snapshot");
            return this.snapshot;
        }
        @Override public @NonNull String toString() {
            return this.snapshot == null ? "Read{UNAVAILABLE}" : "Read{AVAILABLE, <redacted>}";
        }
    }

    /** A commit outcome; only COMMITTED can support a later engine-created proof. */
    enum Commit { COMMITTED, CONFLICT, CAPACITY, UNAVAILABLE, INDETERMINATE }
}
