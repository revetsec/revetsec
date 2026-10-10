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
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnStoreCoordinatorTests {
    private static final WebAuthnStoreKey CEREMONY = WebAuthnStoreKey.forCeremony("tenant", "login.example.com", new byte[32]);
    private static final WebAuthnStoreKey CREDENTIAL = WebAuthnStoreKey.forCredential("tenant", "login.example.com", new byte[] {1});
    private static final Set<WebAuthnStoreKey> KEYS = Set.of(CEREMONY, CREDENTIAL);

    @Test void passesOneShrinkingBudgetAndCompleteSnapshotToCommit() {
        AtomicLong clock = new AtomicLong();
        WebAuthnStoreSnapshot snapshot = snapshot(KEYS);
        AtomicInteger reads = new AtomicInteger();
        AtomicInteger writes = new AtomicInteger();
        WebAuthnStore store = store((keys, budget) -> {
            reads.incrementAndGet();
            assertEquals(KEYS, keys);
            assertEquals(Duration.ofSeconds(1), budget);
            clock.addAndGet(Duration.ofMillis(125).toNanos());
            return WebAuthnStoreReadResult.Available.fromSnapshot(snapshot);
        }, (write, budget) -> {
            writes.incrementAndGet();
            assertEquals(Duration.ofMillis(875), budget);
            assertSame(snapshot, write.getSnapshot());
            assertEquals(KEYS, write.getSnapshot().getEntries().keySet());
            assertTrue(write.getSnapshot().getEntry(CEREMONY) instanceof WebAuthnStoreEntry.Absent);
            assertTrue(write.getSnapshot().getEntry(CREDENTIAL) instanceof WebAuthnStoreEntry.Present);
            assertEquals(List.of(WebAuthnStoreWrite.Mutation.Kind.INSERT,
                    WebAuthnStoreWrite.Mutation.Kind.REPLACE),
                    write.getMutations().stream().map(WebAuthnStoreWrite.Mutation::getKind).toList());
            clock.addAndGet(Duration.ofMillis(100).toNanos());
            return WebAuthnStoreCommitResult.COMMITTED;
        });
        var attempt = new WebAuthnStoreCoordinator(store, Duration.ofSeconds(1), clock::get).begin();
        assertSame(snapshot, attempt.read(KEYS).getSnapshot());
        assertEquals(WebAuthnStoreCoordinator.Commit.COMMITTED, attempt.commit(List.of(
                WebAuthnStoreWrite.Mutation.insert(CEREMONY, new byte[] {3}),
                WebAuthnStoreWrite.Mutation.replace(CREDENTIAL, new byte[] {4}))));
        assertEquals(1, reads.get());
        assertEquals(1, writes.get());
        assertThrows(IllegalStateException.class, () -> attempt.commit(List.of()));
        assertThrows(IllegalStateException.class, () -> attempt.read(KEYS));
    }

    @Test void expandedReadUsesSameDeadlineAndOnlyItsCompleteSnapshotForCommit() {
        AtomicLong clock = new AtomicLong();
        AtomicInteger reads = new AtomicInteger();
        WebAuthnStoreSnapshot first = snapshot(Set.of(CEREMONY));
        WebAuthnStoreSnapshot expanded = snapshot(KEYS);
        var attempt = new WebAuthnStoreCoordinator(store((keys, budget) -> {
            int call = reads.incrementAndGet();
            assertEquals(call == 1 ? Set.of(CEREMONY) : KEYS, keys);
            assertEquals(call == 1 ? Duration.ofSeconds(1) : Duration.ofMillis(750), budget);
            clock.addAndGet(Duration.ofMillis(250).toNanos());
            return WebAuthnStoreReadResult.Available.fromSnapshot(call == 1 ? first : expanded);
        }, (write, budget) -> {
            assertEquals(Duration.ofMillis(500), budget);
            assertSame(expanded, write.getSnapshot());
            return WebAuthnStoreCommitResult.COMMITTED;
        }), Duration.ofSeconds(1), clock::get).begin();
        assertSame(first, attempt.read(Set.of(CEREMONY)).getSnapshot());
        assertThrows(IllegalArgumentException.class, () -> attempt.readExpanded(Set.of(CREDENTIAL)));
        assertSame(expanded, attempt.readExpanded(KEYS).getSnapshot());
        assertEquals(WebAuthnStoreCoordinator.Commit.COMMITTED, attempt.commit(List.of()));
        assertEquals(2, reads.get());
        assertThrows(IllegalStateException.class, () -> attempt.readExpanded(KEYS));
    }

    @Test void failedExpandedReadInvalidatesFirstSnapshotAndPreventsCommit() {
        for (WebAuthnStoreReadResult second : List.of(
                WebAuthnStoreReadResult.Unavailable.get(),
                WebAuthnStoreReadResult.Available.fromSnapshot(snapshot(Set.of(CEREMONY))))) {
            AtomicInteger reads = new AtomicInteger();
            var attempt = new WebAuthnStoreCoordinator(store((keys, budget) ->
                    reads.incrementAndGet() == 1
                            ? WebAuthnStoreReadResult.Available.fromSnapshot(snapshot(Set.of(CEREMONY)))
                            : second,
                    (write, budget) -> { throw new AssertionError("unexpected write"); }),
                    Duration.ofSeconds(1), () -> 0).begin();
            assertTrue(attempt.read(Set.of(CEREMONY)).isAvailable());
            assertFalse(attempt.readExpanded(KEYS).isAvailable());
            assertEquals(2, reads.get());
            assertThrows(IllegalStateException.class, () -> attempt.commit(List.of()));
        }
    }

    @Test void rejectsIncompleteUnavailableAndFaultingReadsWithoutWriting() {
        WebAuthnStoreSnapshot incomplete = snapshot(Set.of(CEREMONY));
        for (WebAuthnStoreReadResult result : List.of(
                WebAuthnStoreReadResult.Available.fromSnapshot(incomplete),
                WebAuthnStoreReadResult.Unavailable.get())) {
            var attempt = new WebAuthnStoreCoordinator(store((keys, budget) -> result,
                    (write, budget) -> { throw new AssertionError("unexpected write"); }),
                    Duration.ofSeconds(1), () -> 0).begin();
            var read = attempt.read(KEYS);
            assertFalse(read.isAvailable());
            assertThrows(IllegalStateException.class, read::getSnapshot);
            assertThrows(IllegalStateException.class, () -> attempt.commit(List.of()));
        }
        var fault = new WebAuthnStoreCoordinator(store((keys, budget) -> {
            throw new IllegalStateException("backend fault with sensitive details");
        }, (write, budget) -> { throw new AssertionError("unexpected write"); }),
                Duration.ofSeconds(1), () -> 0).begin();
        var read = fault.read(KEYS);
        assertFalse(read.isAvailable());
        assertFalse(read.toString().contains("sensitive"));
    }

    @Test void explicitZeroEffectAndUnknownCommitOutcomesRemainDistinct() {
        for (WebAuthnStoreCommitResult status : WebAuthnStoreCommitResult.values()) {
            var attempt = new WebAuthnStoreCoordinator(store((keys, budget) ->
                    WebAuthnStoreReadResult.Available.fromSnapshot(snapshot(KEYS)),
                    (write, budget) -> status), Duration.ofSeconds(1), () -> 0).begin();
            assertTrue(attempt.read(KEYS).isAvailable());
            var outcome = attempt.commit(List.of());
            assertEquals(switch (status) {
                case COMMITTED -> WebAuthnStoreCoordinator.Commit.COMMITTED;
                case CONFLICT -> WebAuthnStoreCoordinator.Commit.CONFLICT;
                case CAPACITY -> WebAuthnStoreCoordinator.Commit.CAPACITY;
                case UNAVAILABLE -> WebAuthnStoreCoordinator.Commit.UNAVAILABLE;
                case UNKNOWN -> WebAuthnStoreCoordinator.Commit.INDETERMINATE;
            }, outcome);
        }
    }

    @Test void faultsAfterEnteringCommitAreIndeterminateAndNeverRetried() {
        AtomicInteger calls = new AtomicInteger();
        var attempt = new WebAuthnStoreCoordinator(store((keys, budget) ->
                WebAuthnStoreReadResult.Available.fromSnapshot(snapshot(KEYS)), (write, budget) -> {
            calls.incrementAndGet();
            throw new IllegalStateException("lost acknowledgement");
        }), Duration.ofSeconds(1), () -> 0).begin();
        attempt.read(KEYS);
        assertEquals(WebAuthnStoreCoordinator.Commit.INDETERMINATE, attempt.commit(List.of()));
        assertThrows(IllegalStateException.class, () -> attempt.commit(List.of()));
        assertEquals(1, calls.get());
    }

    @Test void lateCommitWithholdsSuccessAndZeroEffectLateReplyIsUnavailable() {
        for (WebAuthnStoreCommitResult status : List.of(WebAuthnStoreCommitResult.COMMITTED,
                WebAuthnStoreCommitResult.CONFLICT, WebAuthnStoreCommitResult.UNKNOWN)) {
            AtomicLong clock = new AtomicLong();
            var attempt = new WebAuthnStoreCoordinator(store((keys, budget) ->
                    WebAuthnStoreReadResult.Available.fromSnapshot(snapshot(KEYS)), (write, budget) -> {
                clock.addAndGet(Duration.ofSeconds(1).toNanos());
                return status;
            }), Duration.ofSeconds(1), clock::get).begin();
            attempt.read(KEYS);
            assertEquals(status == WebAuthnStoreCommitResult.CONFLICT
                    ? WebAuthnStoreCoordinator.Commit.UNAVAILABLE : WebAuthnStoreCoordinator.Commit.INDETERMINATE,
                    attempt.commit(List.of()));
        }
    }

    @Test @SuppressWarnings("NullAway") // Deliberate broken provider replies.
    void lateReadAndNullCallbacksWithholdAnySnapshotOrProof() {
        AtomicLong clock = new AtomicLong();
        var late = new WebAuthnStoreCoordinator(store((keys, budget) -> {
            clock.addAndGet(Duration.ofSeconds(1).toNanos());
            return WebAuthnStoreReadResult.Available.fromSnapshot(snapshot(KEYS));
        }, (write, budget) -> { throw new AssertionError("unexpected write"); }),
                Duration.ofSeconds(1), clock::get).begin();
        assertFalse(late.read(KEYS).isAvailable());

        var nullRead = new WebAuthnStoreCoordinator(store((keys, budget) -> null,
                (write, budget) -> { throw new AssertionError("unexpected write"); }),
                Duration.ofSeconds(1), () -> 0).begin();
        assertFalse(nullRead.read(KEYS).isAvailable());

        var nullCommit = new WebAuthnStoreCoordinator(store((keys, budget) ->
                WebAuthnStoreReadResult.Available.fromSnapshot(snapshot(KEYS)),
                (write, budget) -> null), Duration.ofSeconds(1), () -> 0).begin();
        assertTrue(nullCommit.read(KEYS).isAvailable());
        assertEquals(WebAuthnStoreCoordinator.Commit.INDETERMINATE, nullCommit.commit(List.of()));
    }

    @Test void expiredOrInterruptedBudgetSkipsCallbacksAndPreservesInterrupt() {
        AtomicLong clock = new AtomicLong();
        AtomicInteger calls = new AtomicInteger();
        WebAuthnStore store = store((keys, budget) -> {
            calls.incrementAndGet();
            return WebAuthnStoreReadResult.Available.fromSnapshot(snapshot(KEYS));
        }, (write, budget) -> {
            calls.incrementAndGet();
            return WebAuthnStoreCommitResult.COMMITTED;
        });
        var expired = new WebAuthnStoreCoordinator(store, Duration.ofMillis(100), clock::get).begin();
        clock.addAndGet(Duration.ofMillis(100).toNanos());
        assertFalse(expired.read(KEYS).isAvailable());
        assertEquals(0, calls.get());

        clock.set(0);
        var expiredBeforeCommit = new WebAuthnStoreCoordinator(store, Duration.ofMillis(100), clock::get).begin();
        assertTrue(expiredBeforeCommit.read(KEYS).isAvailable());
        clock.addAndGet(Duration.ofMillis(100).toNanos());
        assertEquals(WebAuthnStoreCoordinator.Commit.UNAVAILABLE, expiredBeforeCommit.commit(List.of()));
        assertEquals(1, calls.get());

        var interrupted = new WebAuthnStoreCoordinator(store, Duration.ofMillis(100), clock::get).begin();
        Thread.currentThread().interrupt();
        try {
            assertFalse(interrupted.read(KEYS).isAvailable());
            assertTrue(Thread.currentThread().isInterrupted());
            assertEquals(1, calls.get());
        } finally {
            Thread.interrupted();
        }
    }

    @Test void callbackInterruptAfterPossibleWriteIsIndeterminate() {
        var attempt = new WebAuthnStoreCoordinator(store((keys, budget) ->
                WebAuthnStoreReadResult.Available.fromSnapshot(snapshot(KEYS)), (write, budget) -> {
            throw new IllegalStateException(new InterruptedException("interrupted backend"));
        }), Duration.ofSeconds(1), () -> 0).begin();
        try {
            attempt.read(KEYS);
            assertEquals(WebAuthnStoreCoordinator.Commit.INDETERMINATE, attempt.commit(List.of()));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    private static @NonNull WebAuthnStoreSnapshot snapshot(@NonNull Set<@NonNull WebAuthnStoreKey> keys) {
        Map<WebAuthnStoreKey, WebAuthnStoreEntry> entries = new java.util.HashMap<>();
        for (WebAuthnStoreKey key : keys) entries.put(key, key.equals(CREDENTIAL)
                ? WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[] {1}, new byte[] {2})
                : WebAuthnStoreEntry.Absent.confirmed());
        return WebAuthnStoreSnapshot.fromEntries(keys, entries);
    }

    private static @NonNull WebAuthnStore store(@NonNull ReadCall reader, @NonNull CommitCall writer) {
        return new WebAuthnStore() {
            @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,
                    @NonNull Duration budget) { return reader.call(keys, budget); }
            @Override public @NonNull WebAuthnStoreCommitResult compareAndCommit(@NonNull WebAuthnStoreWrite write,
                    @NonNull Duration budget) { return writer.call(write, budget); }
        };
    }

    private interface ReadCall {
        @NonNull WebAuthnStoreReadResult call(@NonNull Set<@NonNull WebAuthnStoreKey> keys,
                @NonNull Duration budget);
    }

    private interface CommitCall {
        @NonNull WebAuthnStoreCommitResult call(@NonNull WebAuthnStoreWrite write, @NonNull Duration budget);
    }
}
