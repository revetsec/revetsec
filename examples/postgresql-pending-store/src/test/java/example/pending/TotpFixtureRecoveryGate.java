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
package example.pending;

import com.revetsec.totp.TotpRecoveryContext;
import com.revetsec.totp.TotpRecoveryGate;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static java.util.Objects.requireNonNull;

/**
 * Test-only one-host TOTP admission. A process-wide shared OS lock spans each outer operation;
 * per-thread nested permits retain it through the caller's session transaction. The external
 * marker binds the exact namespace, epoch, key IDs and key-material digests. A production gate
 * needs cross-host coordination and a separately durable controller.
 */
@ThreadSafe
final class TotpFixtureRecoveryGate implements TotpRecoveryGate {
    private static final @NonNull ConcurrentMap<@NonNull Path, @NonNull SharedLock> SHARED_LOCKS =
            new ConcurrentHashMap<>();

    private final @NonNull Path markerFile;
    private final @NonNull Path lockFile;
    private final @NonNull Map<@NonNull String, @NonNull String> expectedKeyDigests;
    private final @NonNull SharedLock sharedLock;
    private final @NonNull ThreadLocal<@Nullable Admission> active = new ThreadLocal<>();

    TotpFixtureRecoveryGate(@NonNull Path markerFile, @NonNull Path lockFile,
            @NonNull Map<@NonNull String, @NonNull String> sealingKeysBase64) {
        this.markerFile = requireNonNull(markerFile).toAbsolutePath().normalize();
        this.lockFile = requireNonNull(lockFile).toAbsolutePath().normalize();
        if (this.markerFile.equals(this.lockFile)) throw new IllegalArgumentException("Fixture paths overlap");
        this.expectedKeyDigests = TotpFixtureRecoveryController.digestKeys(sealingKeysBase64);
        this.sharedLock = SHARED_LOCKS.computeIfAbsent(this.lockFile, ignored -> new SharedLock());
    }

    @Override public @Nullable Permit acquire(@NonNull TotpRecoveryContext context,
            @NonNull Duration remainingBudget) {
        requireNonNull(context);
        requireNonNull(remainingBudget);
        long budget = budgetNanos(remainingBudget);
        if (budget <= 0 || Thread.currentThread().isInterrupted()) return null;
        long deadline = System.nanoTime() + budget;
        Admission existing = this.active.get();
        if (existing != null) {
            if (!existing.matches(context) || !existing.isCurrent(deadline)) return null;
            existing.retain();
            return new NestedPermit(existing, deadline);
        }
        if (!this.sharedLock.acquire(this.lockFile)) return null;
        boolean admitted = false;
        try {
            if (!markerMatches(context, deadline)) return null;
            Admission root = new Admission(context, deadline);
            this.active.set(root);
            admitted = true;
            return new NestedPermit(root, deadline);
        } finally {
            if (!admitted) this.sharedLock.release();
        }
    }

    /**
     * Test-only outer application admission. It nests core's operation permit on the same thread
     * and stays held through the application's PostgreSQL session transaction and result decision.
     */
    @Nullable Permit acquireApplicationOperation(@NonNull String namespace, @NonNull String epoch,
            @NonNull String activeKeyId, @NonNull Set<@NonNull String> openingKeyIds,
            @NonNull Duration remainingBudget) {
        requireNonNull(namespace);
        requireNonNull(epoch);
        requireNonNull(activeKeyId);
        requireNonNull(openingKeyIds);
        requireNonNull(remainingBudget);
        long budget = budgetNanos(remainingBudget);
        if (budget <= 0 || Thread.currentThread().isInterrupted()) return null;
        long deadline = System.nanoTime() + budget;
        Admission existing = this.active.get();
        if (existing != null) {
            if (!existing.matchesApplication(namespace, epoch, activeKeyId, openingKeyIds)
                    || !existing.isCurrent(deadline)) return null;
            existing.retain();
            return new NestedPermit(existing, deadline);
        }
        if (!this.sharedLock.acquire(this.lockFile)) return null;
        boolean admitted = false;
        try {
            if (!markerMatchesApplication(namespace, epoch, activeKeyId, openingKeyIds, deadline))
                return null;
            Admission root = new Admission(namespace, epoch, activeKeyId, openingKeyIds, deadline);
            this.active.set(root);
            admitted = true;
            return new NestedPermit(root, deadline);
        } finally {
            if (!admitted) this.sharedLock.release();
        }
    }

    private boolean markerMatches(@NonNull TotpRecoveryContext context, long deadline) {
        if (deadline - System.nanoTime() <= 0 || Thread.currentThread().isInterrupted()
                || !this.sharedLock.valid()) return false;
        try {
            TotpFixtureRecoveryController.Marker marker =
                    TotpFixtureRecoveryController.readMarker(this.markerFile);
            return deadline - System.nanoTime() > 0 && marker.matches(context, this.expectedKeyDigests);
        } catch (IOException | RuntimeException failure) {
            return false;
        }
    }

    private boolean markerMatchesApplication(@NonNull String namespace, @NonNull String epoch,
            @NonNull String activeKeyId, @NonNull Set<@NonNull String> openingKeyIds,
            long deadline) {
        if (deadline - System.nanoTime() <= 0 || Thread.currentThread().isInterrupted()
                || !this.sharedLock.valid()) return false;
        try {
            TotpFixtureRecoveryController.Marker marker =
                    TotpFixtureRecoveryController.readMarker(this.markerFile);
            return deadline - System.nanoTime() > 0
                    && marker.matchesApplicationOperation(namespace, epoch, activeKeyId,
                            openingKeyIds, this.expectedKeyDigests);
        } catch (IOException | RuntimeException failure) {
            return false;
        }
    }

    private static long budgetNanos(@NonNull Duration budget) {
        if (budget.isNegative() || budget.isZero()) return 0;
        try { return Math.min(budget.toNanos(), Duration.ofMinutes(5).toNanos()); }
        catch (ArithmeticException tooLarge) { return Duration.ofMinutes(5).toNanos(); }
    }

    /** One process-wide shared lock, ref-counted across caller threads in this JVM. */
    @ThreadSafe
    private static final class SharedLock {
        private @Nullable FileChannel channel;
        private @Nullable FileLock lock;
        private int users;

        private synchronized boolean acquire(@NonNull Path lockFile) {
            if (this.users > 0) {
                if (!valid()) return false;
                this.users++;
                return true;
            }
            FileChannel opened = null;
            FileLock acquired = null;
            try {
                opened = FileChannel.open(lockFile, StandardOpenOption.CREATE,
                        StandardOpenOption.READ, StandardOpenOption.WRITE);
                acquired = opened.tryLock(1L, Long.MAX_VALUE - 1L, true);
                if (acquired == null) return false;
                this.channel = opened;
                this.lock = acquired;
                this.users = 1;
                opened = null;
                acquired = null;
                return true;
            } catch (IOException | OverlappingFileLockException failure) {
                return false;
            } finally {
                if (acquired != null) {
                    try { acquired.release(); } catch (IOException ignored) { }
                }
                if (opened != null) {
                    try { opened.close(); } catch (IOException ignored) { }
                }
            }
        }

        private synchronized boolean valid() {
            return this.users > 0 && this.lock != null && this.lock.isValid();
        }

        private synchronized void release() {
            if (--this.users > 0) return;
            FileLock held = this.lock;
            FileChannel opened = this.channel;
            this.lock = null;
            this.channel = null;
            try {
                if (held != null) held.release();
            } catch (IOException failure) {
                throw new IllegalStateException("Could not release TOTP fixture admission", failure);
            } finally {
                if (opened != null) {
                    try { opened.close(); }
                    catch (IOException failure) {
                        throw new IllegalStateException("Could not close TOTP fixture admission", failure);
                    }
                }
            }
        }
    }

    @NotThreadSafe
    private final class Admission {
        private final @Nullable TotpRecoveryContext context;
        private final @NonNull String namespace;
        private final @NonNull String epoch;
        private final @NonNull String activeKeyId;
        private final @NonNull Set<@NonNull String> openingKeyIds;
        private final @NonNull Thread owner = Thread.currentThread();
        private final long outerDeadline;
        private int depth = 1;
        private boolean closed;

        private Admission(@NonNull TotpRecoveryContext context, long deadline) {
            this.context = context;
            this.namespace = context.getCredentialNamespace();
            this.epoch = context.getRecoveryEpoch();
            this.activeKeyId = context.getActiveSealingKeyId();
            this.openingKeyIds = context.getOpeningSealingKeyIds();
            this.outerDeadline = deadline;
        }

        private Admission(@NonNull String namespace, @NonNull String epoch,
                @NonNull String activeKeyId, @NonNull Set<@NonNull String> openingKeyIds,
                long deadline) {
            this.context = null;
            this.namespace = namespace;
            this.epoch = epoch;
            this.activeKeyId = activeKeyId;
            this.openingKeyIds = Set.copyOf(openingKeyIds);
            this.outerDeadline = deadline;
        }

        private boolean matches(@NonNull TotpRecoveryContext other) {
            return this.namespace.equals(other.getCredentialNamespace())
                    && this.epoch.equals(other.getRecoveryEpoch())
                    && this.activeKeyId.equals(other.getActiveSealingKeyId())
                    && this.openingKeyIds.equals(other.getOpeningSealingKeyIds())
                    && (this.context == null
                            ? other.getPurpose() == TotpRecoveryContext.Purpose.OPERATION
                            : this.context.getPurpose() == other.getPurpose());
        }

        private boolean matchesApplication(@NonNull String expectedNamespace,
                @NonNull String expectedEpoch, @NonNull String expectedActiveKeyId,
                @NonNull Set<@NonNull String> expectedOpeningKeyIds) {
            return this.namespace.equals(expectedNamespace) && this.epoch.equals(expectedEpoch)
                    && this.activeKeyId.equals(expectedActiveKeyId)
                    && this.openingKeyIds.equals(expectedOpeningKeyIds)
                    && (this.context == null
                            || this.context.getPurpose() == TotpRecoveryContext.Purpose.OPERATION);
        }

        private boolean isCurrent(long nestedDeadline) {
            return Thread.currentThread() == this.owner && !this.closed
                    && this.outerDeadline - System.nanoTime() > 0
                    && (this.context == null
                            ? markerMatchesApplication(this.namespace, this.epoch,
                                    this.activeKeyId, this.openingKeyIds,
                                    Math.min(this.outerDeadline, nestedDeadline))
                            : markerMatches(this.context, Math.min(this.outerDeadline, nestedDeadline)));
        }

        private void retain() { this.depth++; }

        private void requireOwner() {
            if (Thread.currentThread() != this.owner)
                throw new IllegalStateException("TOTP fixture permit belongs to another thread");
        }

        private void release() {
            requireOwner();
            if (--this.depth > 0) return;
            this.closed = true;
            active.remove();
            sharedLock.release();
        }
    }

    @NotThreadSafe
    private final class NestedPermit implements Permit {
        private final @NonNull Admission admission;
        private final long deadline;
        private boolean closed;

        private NestedPermit(@NonNull Admission admission, long deadline) {
            this.admission = admission;
            this.deadline = deadline;
        }

        @Override public @NonNull Boolean isCurrent() {
            return !this.closed && this.admission.isCurrent(this.deadline);
        }

        @Override public void close() {
            if (this.closed) return;
            this.admission.requireOwner();
            this.closed = true;
            this.admission.release();
        }
    }
}
