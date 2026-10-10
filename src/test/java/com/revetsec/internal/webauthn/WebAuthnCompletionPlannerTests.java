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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnStore;
import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnCompletionPlannerTests {
    private static final String NAMESPACE = "tenant";
    private static final String RP = "login.example.com";
    private static final byte[] CEREMONY_ID = filled(1);
    private static final byte[] CHALLENGE = filled(33);
    private static final byte[] BINDING = filled(65);
    private static final byte[] ID = {1, 2, 3};
    private static final byte[] HANDLE = {4, 5, 6};
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final WebAuthnRecoveryGate ALLOW = remaining -> new WebAuthnRecoveryGate.Permit() {
        @Override public boolean isCurrent() { return true; }
        @Override public void close() { }
    };

    @Test void registrationPlansAtomicCeremonyCredentialIndexAndClockTransition() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var planner = planner();
        var pending = registration();
        var first = first(pending);
        var inspected = planner.inspectRegistration(first, CEREMONY_ID, BINDING,
                registrationJson(pair), CLOCK).orElseThrow();
        var keys = inspected.expandedKeys();
        var expanded = expanded(first, keys, Map.of(
                credentialKey(), WebAuthnStoreEntry.Absent.confirmed(),
                indexKey(), WebAuthnStoreEntry.Absent.confirmed(),
                fenceKey(), present(new byte[] {2}, fence(true))));
        var prepared = planner.prepareRegistration(inspected, expanded, CLOCK);
        assertEquals(WebAuthnCompletionPlanner.Preparation.Status.CANDIDATE, prepared.status());
        WebAuthnStoreWrite write = prepared.write().orElseThrow();
        assertEquals(keys, write.getSnapshot().getEntries().keySet());
        assertEquals(4, write.getMutations().size());
        assertTrue(write.getMutations().stream().noneMatch(mutation -> mutation.getKey().equals(fenceKey())));
        assertTrue(new WebAuthnCeremonyRecordCodec(NAMESPACE, RP, records()).decode(
                ceremonyKey(), changed(write, ceremonyKey()), CLOCK).isConsumed());
        assertArrayEquals(HANDLE, new WebAuthnCredentialRecordCodec(NAMESPACE, RP, records())
                .decode(credentialKey(), changed(write, credentialKey()), CLOCK).userHandle());
        assertTrue(new WebAuthnCredentialIndex(NAMESPACE, RP, records())
                .decode(indexKey(), changed(write, indexKey()), CLOCK).contains(ID));
        assertEquals(NOW, new WebAuthnNamespaceClock(NAMESPACE, RP, records())
                .decode(clockKey(), changed(write, clockKey()), CLOCK));
        assertFalse(prepared.toString().contains(credentialKey().getStorageKey()));

        var duplicate = expanded(first, keys, Map.of(
                credentialKey(), present(new byte[] {3}, changed(write, credentialKey())),
                indexKey(), WebAuthnStoreEntry.Absent.confirmed(),
                fenceKey(), present(new byte[] {2}, fence(true))));
        assertEquals(WebAuthnCompletionPlanner.Preparation.Status.REJECTED,
                planner.prepareRegistration(inspected, duplicate, CLOCK).status());
    }

    @Test void registrationRejectsChallengeSwapAndDisabledAccountAfterExpandedRead() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var planner = planner();
        var first = first(registration());
        var inspected = planner.inspectRegistration(first, CEREMONY_ID, BINDING,
                registrationJson(pair), CLOCK).orElseThrow();
        var keys = inspected.expandedKeys();
        var base = Map.<WebAuthnStoreKey, WebAuthnStoreEntry>of(
                credentialKey(), WebAuthnStoreEntry.Absent.confirmed(),
                indexKey(), WebAuthnStoreEntry.Absent.confirmed(),
                fenceKey(), present(new byte[] {2}, fence(false)));
        assertEquals(WebAuthnCompletionPlanner.Preparation.Status.REJECTED,
                planner.prepareRegistration(inspected, expanded(first, keys, base), CLOCK).status());

        byte[] changedChallenge = CHALLENGE.clone(); changedChallenge[0] ^= 1;
        var swapped = WebAuthnCeremonyState.registration(CEREMONY_ID, changedChallenge, BINDING,
                Set.of("https://" + RP), HANDLE, NOW, NOW.plusSeconds(300));
        Map<WebAuthnStoreKey, WebAuthnStoreEntry> switched = new HashMap<>(base);
        switched.put(fenceKey(), present(new byte[] {2}, fence(true)));
        switched.put(ceremonyKey(), present(new byte[] {4}, new WebAuthnCeremonyRecordCodec(
                NAMESPACE, RP, records()).encode(swapped).sealedBytes()));
        assertEquals(WebAuthnCompletionPlanner.Preparation.Status.REJECTED,
                planner.prepareRegistration(inspected, expanded(first, keys, switched), CLOCK).status());
    }

    @Test void authenticationPlansSignedCounterUpdateAndRejectsRevocationRiskAndWrongKey()
            throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var planner = planner();
        var first = first(authentication());
        var inspected = planner.inspectAuthentication(first, CEREMONY_ID, BINDING,
                assertionJson(pair.getPrivate(), 8), CLOCK).orElseThrow();
        var keys = inspected.expandedKeys();
        var stored = WebAuthnCredentialState.checked(ID, HANDLE, edKey(pair), -8, 7, false, false);
        var credential = new WebAuthnCredentialRecordCodec(NAMESPACE, RP, records()).encode(stored);
        var expanded = expanded(first, keys, Map.of(
                credentialKey(), present(new byte[] {5}, credential.sealedBytes()),
                indexKey(), present(new byte[] {6}, index(ID)),
                fenceKey(), present(new byte[] {7}, fence(true))));
        var prepared = planner.prepareAuthentication(inspected, expanded, CLOCK);
        assertEquals(WebAuthnCompletionPlanner.Preparation.Status.CANDIDATE, prepared.status());
        WebAuthnStoreWrite write = prepared.write().orElseThrow();
        assertEquals(3, write.getMutations().size());
        assertTrue(write.getMutations().stream().noneMatch(mutation -> mutation.getKey().equals(indexKey())));
        assertEquals(8, new WebAuthnCredentialRecordCodec(NAMESPACE, RP, records())
                .decode(credentialKey(), changed(write, credentialKey()), CLOCK).counter());

        var revoked = expanded(first, keys, Map.of(
                credentialKey(), present(new byte[] {8}, new WebAuthnCredentialRecordCodec(
                        NAMESPACE, RP, records()).encodeRevoked(ID, HANDLE).sealedBytes()),
                indexKey(), present(new byte[] {6}, index(ID)),
                fenceKey(), present(new byte[] {7}, fence(true))));
        assertEquals(WebAuthnCompletionPlanner.Preparation.Status.REJECTED,
                planner.prepareAuthentication(inspected, revoked, CLOCK).status());

        var stale = planner.inspectAuthentication(first, CEREMONY_ID, BINDING,
                assertionJson(pair.getPrivate(), 7), CLOCK).orElseThrow();
        assertEquals(WebAuthnCompletionPlanner.Preparation.Status.COUNTER_RISK,
                planner.prepareAuthentication(stale, expanded, CLOCK).status());
        KeyPair attacker = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var invalidSignature = planner.inspectAuthentication(first, CEREMONY_ID, BINDING,
                assertionJson(attacker.getPrivate(), 8), CLOCK).orElseThrow();
        assertEquals(WebAuthnCompletionPlanner.Preparation.Status.REJECTED,
                planner.prepareAuthentication(invalidSignature, expanded, CLOCK).status());
    }

    @Test void accountPinnedReauthenticationRejectsAnotherClaimedHandleBeforeExpandedRead()
            throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var pinned = WebAuthnCeremonyState.accountReauthentication(CEREMONY_ID, CHALLENGE,
                BINDING, Set.of("https://" + RP), new byte[] {9}, "transfer", NOW,
                NOW.plusSeconds(300));
        assertTrue(planner().inspectAuthentication(first(pinned), CEREMONY_ID, BINDING,
                assertionJson(pair.getPrivate(), 8), CLOCK).isEmpty());
    }

    @Test void runnerCommitsVerifiedRegistrationOnlyAfterBothReadsAndWithholdsProofOnUnknown()
            throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var planner = planner();
        var first = first(registration());
        var inspected = planner.inspectRegistration(first, CEREMONY_ID, BINDING,
                registrationJson(pair), CLOCK).orElseThrow();
        var expanded = expanded(first, inspected.expandedKeys(), Map.of(
                credentialKey(), WebAuthnStoreEntry.Absent.confirmed(),
                indexKey(), WebAuthnStoreEntry.Absent.confirmed(),
                fenceKey(), present(new byte[] {2}, fence(true))));
        for (WebAuthnStoreCommitResult status : new WebAuthnStoreCommitResult[] {
                WebAuthnStoreCommitResult.COMMITTED, WebAuthnStoreCommitResult.UNKNOWN,
                WebAuthnStoreCommitResult.CONFLICT}) {
            AtomicInteger reads = new AtomicInteger();
            AtomicInteger writes = new AtomicInteger();
            var runner = runner(first, expanded, status, reads, writes, new AtomicLong());
            var completion = runner.completeRegistrationFact(CEREMONY_ID, BINDING, registrationJson(pair));
            assertEquals(switch (status) {
                case COMMITTED -> WebAuthnCompletionRunner.Outcome.COMMITTED_NO_PROOF;
                case UNKNOWN -> WebAuthnCompletionRunner.Outcome.INDETERMINATE;
                case CONFLICT -> WebAuthnCompletionRunner.Outcome.UNAVAILABLE;
                default -> throw new AssertionError(status);
            }, completion.outcome());
            assertEquals(status == WebAuthnStoreCommitResult.COMMITTED, completion.fact().isPresent());
            if (status == WebAuthnStoreCommitResult.COMMITTED) {
                var fact = completion.fact().orElseThrow();
                assertEquals(WebAuthnCeremonyState.Kind.REGISTRATION, fact.kind());
                assertArrayEquals(HANDLE, fact.userHandle());
                assertArrayEquals(ID, fact.credentialId());
                assertFalse(fact.toString().contains(Base64Url.encode(HANDLE)));
                byte[] copy = fact.userHandle(); copy[0] ^= 1;
                assertArrayEquals(HANDLE, fact.userHandle());
            }
            assertEquals(2, reads.get());
            assertEquals(1, writes.get());
        }
    }

    @Test void runnerPersistsObservedTimeForRejectedInputAndWithholdsLateCommit() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var planner = planner();
        var first = first(registration());
        AtomicInteger reads = new AtomicInteger();
        AtomicInteger writes = new AtomicInteger();
        var rejected = runner(first, first, WebAuthnStoreCommitResult.COMMITTED,
                reads, writes, new AtomicLong());
        byte[] malformed = registrationJson(pair);
        malformed[0] = '<';
        assertEquals(WebAuthnCompletionRunner.Outcome.REJECTED,
                rejected.completeRegistration(CEREMONY_ID, BINDING, malformed));
        assertEquals(1, reads.get());
        assertEquals(1, writes.get());

        reads.set(0); writes.set(0);
        AtomicLong nanos = new AtomicLong();
        WebAuthnStore store = new WebAuthnStore() {
            @Override public @NonNull WebAuthnStoreReadResult read(
                    @NonNull Set<@NonNull WebAuthnStoreKey> keys, @NonNull Duration remaining) {
                reads.incrementAndGet();
                return WebAuthnStoreReadResult.Available.fromSnapshot(first);
            }
            @Override public @NonNull WebAuthnStoreCommitResult compareAndCommit(
                    @NonNull WebAuthnStoreWrite write, @NonNull Duration remaining) {
                writes.incrementAndGet();
                nanos.addAndGet(Duration.ofSeconds(1).toNanos());
                return WebAuthnStoreCommitResult.COMMITTED;
            }
        };
        var late = new WebAuthnCompletionRunner(new WebAuthnStoreCoordinator(
                store, Duration.ofSeconds(1), nanos::get), planner, CLOCK, ALLOW);
        assertEquals(WebAuthnCompletionRunner.Outcome.INDETERMINATE,
                late.completeRegistration(CEREMONY_ID, BINDING, malformed));
        assertEquals(1, reads.get());
        assertEquals(1, writes.get());
    }

    @Test void runnerChecksRealSignedAssertionBeforeConfirmedCredentialUpdate() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var planner = planner();
        var first = first(authentication());
        var inspected = planner.inspectAuthentication(first, CEREMONY_ID, BINDING,
                assertionJson(pair.getPrivate(), 8), CLOCK).orElseThrow();
        var stored = WebAuthnCredentialState.checked(ID, HANDLE, edKey(pair), -8, 7, false, false);
        var expanded = expanded(first, inspected.expandedKeys(), Map.of(
                credentialKey(), present(new byte[] {5}, new WebAuthnCredentialRecordCodec(
                        NAMESPACE, RP, records()).encode(stored).sealedBytes()),
                indexKey(), present(new byte[] {6}, index(ID)),
                fenceKey(), present(new byte[] {7}, fence(true))));
        AtomicInteger reads = new AtomicInteger();
        AtomicInteger writes = new AtomicInteger();
        var runner = runner(first, expanded, WebAuthnStoreCommitResult.COMMITTED,
                reads, writes, new AtomicLong());
        var completion = runner.completeAuthenticationFact(CEREMONY_ID, BINDING,
                assertionJson(pair.getPrivate(), 8));
        assertEquals(WebAuthnCompletionRunner.Outcome.COMMITTED_NO_PROOF, completion.outcome());
        assertEquals(WebAuthnCeremonyState.Kind.DISCOVERABLE_AUTHENTICATION,
                completion.fact().orElseThrow().kind());
        assertArrayEquals(HANDLE, completion.fact().orElseThrow().userHandle());
        assertEquals(2, reads.get());
        assertEquals(1, writes.get());
    }

    @Test void confirmedAccountPinnedReauthenticationRetainsPurposeOnlyInVerifiedFact()
            throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var pending = WebAuthnCeremonyState.accountReauthentication(CEREMONY_ID, CHALLENGE,
                BINDING, Set.of("https://" + RP), HANDLE, "transfer", NOW, NOW.plusSeconds(300));
        var first = first(pending);
        var inspected = planner().inspectAuthentication(first, CEREMONY_ID, BINDING,
                assertionJson(pair.getPrivate(), 8), CLOCK).orElseThrow();
        var stored = WebAuthnCredentialState.checked(ID, HANDLE, edKey(pair), -8, 7, false, false);
        var expanded = expanded(first, inspected.expandedKeys(), Map.of(
                credentialKey(), present(new byte[] {5}, new WebAuthnCredentialRecordCodec(
                        NAMESPACE, RP, records()).encode(stored).sealedBytes()),
                indexKey(), present(new byte[] {6}, index(ID)),
                fenceKey(), present(new byte[] {7}, fence(true))));
        var completion = runner(first, expanded, WebAuthnStoreCommitResult.COMMITTED,
                new AtomicInteger(), new AtomicInteger(), new AtomicLong())
                .completeAuthenticationFact(CEREMONY_ID, BINDING, assertionJson(pair.getPrivate(), 8));
        assertEquals(WebAuthnCompletionRunner.Outcome.COMMITTED_NO_PROOF, completion.outcome());
        assertEquals(WebAuthnCeremonyState.Kind.ACCOUNT_REAUTHENTICATION,
                completion.fact().orElseThrow().kind());
        assertEquals("transfer", completion.fact().orElseThrow().actionPurpose());
        assertFalse(completion.toString().contains("transfer"));
    }

    @Test void runnerWithholdsProofIfCeremonyExpiresDuringConfirmedCommit() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var first = first(registration());
        var inspected = planner().inspectRegistration(first, CEREMONY_ID, BINDING,
                registrationJson(pair), CLOCK).orElseThrow();
        var expanded = expanded(first, inspected.expandedKeys(), Map.of(
                credentialKey(), WebAuthnStoreEntry.Absent.confirmed(),
                indexKey(), WebAuthnStoreEntry.Absent.confirmed(),
                fenceKey(), present(new byte[] {2}, fence(true))));
        AtomicReference<Instant> wallTime = new AtomicReference<>(NOW);
        Clock changingClock = new Clock() {
            @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone) {
                return Clock.fixed(instant(), zone);
            }
            @Override public @NonNull Instant instant() { return java.util.Objects.requireNonNull(wallTime.get()); }
        };
        AtomicInteger reads = new AtomicInteger();
        WebAuthnStore store = new WebAuthnStore() {
            @Override public @NonNull WebAuthnStoreReadResult read(
                    @NonNull Set<@NonNull WebAuthnStoreKey> keys, @NonNull Duration remaining) {
                WebAuthnStoreSnapshot snapshot = reads.incrementAndGet() == 1 ? first : expanded;
                assertEquals(keys, snapshot.getEntries().keySet());
                return WebAuthnStoreReadResult.Available.fromSnapshot(snapshot);
            }
            @Override public @NonNull WebAuthnStoreCommitResult compareAndCommit(
                    @NonNull WebAuthnStoreWrite write, @NonNull Duration remaining) {
                assertEquals(expanded, write.getSnapshot());
                wallTime.set(NOW.plusSeconds(301));
                return WebAuthnStoreCommitResult.COMMITTED;
            }
        };
        var runner = new WebAuthnCompletionRunner(new WebAuthnStoreCoordinator(store,
                Duration.ofSeconds(1), () -> 0), planner(), changingClock, ALLOW);
        assertEquals(WebAuthnCompletionRunner.Outcome.INDETERMINATE,
                runner.completeRegistration(CEREMONY_ID, BINDING, registrationJson(pair)));
        assertEquals(2, reads.get());
    }

    @Test void recoveryGateDenialPreventsReadsAndRevocationWithholdsConfirmedCommit()
            throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var first = first(registration());
        var inspected = planner().inspectRegistration(first, CEREMONY_ID, BINDING,
                registrationJson(pair), CLOCK).orElseThrow();
        var expanded = expanded(first, inspected.expandedKeys(), Map.of(
                credentialKey(), WebAuthnStoreEntry.Absent.confirmed(),
                indexKey(), WebAuthnStoreEntry.Absent.confirmed(),
                fenceKey(), present(new byte[] {2}, fence(true))));
        AtomicInteger reads = new AtomicInteger();
        AtomicInteger writes = new AtomicInteger();
        var denied = runner(first, expanded, WebAuthnStoreCommitResult.COMMITTED,
                reads, writes, new AtomicLong(), remaining -> null);
        var deniedCompletion = denied.completeRegistrationFact(CEREMONY_ID, BINDING,
                registrationJson(pair));
        assertEquals(WebAuthnCompletionRunner.Outcome.UNAVAILABLE, deniedCompletion.outcome());
        assertTrue(deniedCompletion.fact().isEmpty());
        assertEquals(0, reads.get());
        assertEquals(0, writes.get());

        AtomicInteger checks = new AtomicInteger();
        AtomicInteger closes = new AtomicInteger();
        WebAuthnRecoveryGate revoked = remaining -> new WebAuthnRecoveryGate.Permit() {
            @Override public boolean isCurrent() { return checks.incrementAndGet() == 1; }
            @Override public void close() { closes.incrementAndGet(); }
        };
        var runner = runner(first, expanded, WebAuthnStoreCommitResult.COMMITTED,
                reads, writes, new AtomicLong(), revoked);
        var revokedCompletion = runner.completeRegistrationFact(CEREMONY_ID, BINDING,
                registrationJson(pair));
        assertEquals(WebAuthnCompletionRunner.Outcome.INDETERMINATE, revokedCompletion.outcome());
        assertTrue(revokedCompletion.fact().isEmpty());
        assertEquals(2, checks.get());
        assertEquals(2, reads.get());
        assertEquals(1, writes.get());
        assertEquals(1, closes.get());
    }

    @Test void recoveryGateSharesDeadlineAndCloseFaultWithholdsResult() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var first = first(registration());
        AtomicLong nanos = new AtomicLong();
        AtomicInteger reads = new AtomicInteger();
        AtomicInteger writes = new AtomicInteger();
        AtomicInteger closes = new AtomicInteger();
        WebAuthnRecoveryGate slow = remaining -> {
            assertEquals(Duration.ofSeconds(1), remaining);
            nanos.addAndGet(Duration.ofSeconds(1).toNanos());
            return new WebAuthnRecoveryGate.Permit() {
                @Override public boolean isCurrent() { return true; }
                @Override public void close() { closes.incrementAndGet(); }
            };
        };
        var timedOut = runner(first, first, WebAuthnStoreCommitResult.COMMITTED,
                reads, writes, nanos, slow);
        assertEquals(WebAuthnCompletionRunner.Outcome.UNAVAILABLE,
                timedOut.completeRegistration(CEREMONY_ID, BINDING, registrationJson(pair)));
        assertEquals(0, reads.get());
        assertEquals(0, writes.get());
        assertEquals(1, closes.get());

        WebAuthnRecoveryGate brokenRelease = remaining -> new WebAuthnRecoveryGate.Permit() {
            @Override public boolean isCurrent() { return true; }
            @Override public void close() { throw new IllegalStateException("private marker"); }
        };
        var afterClockOnlyWrite = runner(first, first, WebAuthnStoreCommitResult.COMMITTED,
                reads, writes, new AtomicLong(), brokenRelease);
        byte[] malformed = registrationJson(pair);
        malformed[0] = '<';
        assertEquals(WebAuthnCompletionRunner.Outcome.INDETERMINATE,
                afterClockOnlyWrite.completeRegistration(CEREMONY_ID, BINDING, malformed));
        assertEquals(1, reads.get());
        assertEquals(1, writes.get());
    }

    private static @NonNull WebAuthnCompletionRunner runner(@NonNull WebAuthnStoreSnapshot first,
            @NonNull WebAuthnStoreSnapshot expanded, @NonNull WebAuthnStoreCommitResult status,
            @NonNull AtomicInteger reads, @NonNull AtomicInteger writes, @NonNull AtomicLong nanos) {
        return runner(first, expanded, status, reads, writes, nanos, ALLOW);
    }

    private static @NonNull WebAuthnCompletionRunner runner(@NonNull WebAuthnStoreSnapshot first,
            @NonNull WebAuthnStoreSnapshot expanded, @NonNull WebAuthnStoreCommitResult status,
            @NonNull AtomicInteger reads, @NonNull AtomicInteger writes, @NonNull AtomicLong nanos,
            @NonNull WebAuthnRecoveryGate gate) {
        WebAuthnStore store = new WebAuthnStore() {
            @Override public @NonNull WebAuthnStoreReadResult read(
                    @NonNull Set<@NonNull WebAuthnStoreKey> keys, @NonNull Duration remaining) {
                int call = reads.incrementAndGet();
                WebAuthnStoreSnapshot snapshot = call == 1 ? first : expanded;
                assertEquals(keys, snapshot.getEntries().keySet());
                return WebAuthnStoreReadResult.Available.fromSnapshot(snapshot);
            }
            @Override public @NonNull WebAuthnStoreCommitResult compareAndCommit(
                    @NonNull WebAuthnStoreWrite write, @NonNull Duration remaining) {
                writes.incrementAndGet();
                assertEquals(reads.get() == 1 ? first : expanded, write.getSnapshot());
                return status;
            }
        };
        return new WebAuthnCompletionRunner(new WebAuthnStoreCoordinator(
                store, Duration.ofSeconds(1), nanos::get), planner(), CLOCK, gate);
    }

    private static @NonNull WebAuthnCompletionPlanner planner() {
        return new WebAuthnCompletionPlanner(NAMESPACE, RP, records());
    }
    private static @NonNull WebAuthnCeremonyState registration() {
        return WebAuthnCeremonyState.registration(CEREMONY_ID, CHALLENGE, BINDING,
                Set.of("https://" + RP), HANDLE, NOW, NOW.plusSeconds(300));
    }
    private static @NonNull WebAuthnCeremonyState authentication() {
        return WebAuthnCeremonyState.discoverableAuthentication(CEREMONY_ID, CHALLENGE, BINDING,
                Set.of("https://" + RP), NOW, NOW.plusSeconds(300));
    }
    private static @NonNull WebAuthnStoreSnapshot first(@NonNull WebAuthnCeremonyState pending) {
        var ceremony = new WebAuthnCeremonyRecordCodec(NAMESPACE, RP, records()).encode(pending);
        return WebAuthnStoreSnapshot.fromEntries(Set.of(ceremony.key(), clockKey()), Map.of(
                ceremony.key(), present(new byte[] {1}, ceremony.sealedBytes()),
                clockKey(), WebAuthnStoreEntry.Absent.confirmed()));
    }
    private static @NonNull WebAuthnStoreSnapshot expanded(@NonNull WebAuthnStoreSnapshot first,
            @NonNull Set<@NonNull WebAuthnStoreKey> keys,
            @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull WebAuthnStoreEntry> changes) {
        Map<WebAuthnStoreKey, WebAuthnStoreEntry> entries = new HashMap<>(first.getEntries());
        entries.putAll(changes);
        return WebAuthnStoreSnapshot.fromEntries(keys, entries);
    }
    private static WebAuthnStoreEntry.@NonNull Present present(byte @NonNull [] version,
            byte @NonNull [] sealed) {
        return WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(version, sealed);
    }
    private static @NonNull WebAuthnStoreKey ceremonyKey() {
        return WebAuthnStoreKey.forCeremony(NAMESPACE, RP, CEREMONY_ID);
    }
    private static @NonNull WebAuthnStoreKey credentialKey() {
        return WebAuthnStoreKey.forCredential(NAMESPACE, RP, ID);
    }
    private static @NonNull WebAuthnStoreKey indexKey() {
        return WebAuthnStoreKey.forAccountCredentialIndex(NAMESPACE, RP, HANDLE);
    }
    private static @NonNull WebAuthnStoreKey fenceKey() {
        return WebAuthnStoreKey.forAccountFence(NAMESPACE, RP, HANDLE);
    }
    private static @NonNull WebAuthnStoreKey clockKey() {
        return WebAuthnStoreKey.forNamespaceClock(NAMESPACE, RP);
    }
    private static byte @NonNull [] fence(boolean active) {
        return new WebAuthnAccountFence(NAMESPACE, RP, records()).encode(HANDLE, active).sealedBytes();
    }
    private static byte @NonNull [] index(byte @NonNull [] id) {
        var indexes = new WebAuthnCredentialIndex(NAMESPACE, RP, records());
        return indexes.encode(indexes.empty(HANDLE).withAdded(id)).sealedBytes();
    }
    private static byte @NonNull [] changed(@NonNull WebAuthnStoreWrite write,
            @NonNull WebAuthnStoreKey key) {
        return write.getMutations().stream().filter(mutation -> mutation.getKey().equals(key))
                .findFirst().orElseThrow().getSealedBytes().orElseThrow();
    }
    private static byte @NonNull [] registrationJson(@NonNull KeyPair pair) {
        byte[] auth = registrationAuth(pair);
        String encodedId = Base64Url.encode(ID);
        return json("{\"id\":\"" + encodedId + "\",\"rawId\":\"" + encodedId
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.create")) + "\",\"authenticatorData\":\""
                + Base64Url.encode(auth) + "\",\"attestationObject\":\""
                + Base64Url.encode(attestation(auth))
                + "\",\"publicKeyAlgorithm\":-8,\"transports\":[\"usb\"]},"
                + "\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}");
    }
    private static byte @NonNull [] assertionJson(@NonNull PrivateKey key, long counter) throws Exception {
        byte[] auth = assertionAuth(counter);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(auth);
        signer.update(hash(clientJson("webauthn.get")));
        byte[] signature = signer.sign();
        String encodedId = Base64Url.encode(ID);
        return json("{\"id\":\"" + encodedId + "\",\"rawId\":\"" + encodedId
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.get")) + "\",\"authenticatorData\":\""
                + Base64Url.encode(auth) + "\",\"signature\":\"" + Base64Url.encode(signature)
                + "\",\"userHandle\":\"" + Base64Url.encode(HANDLE)
                + "\"},\"clientExtensionResults\":{}}");
    }
    private static byte @NonNull [] clientJson(@NonNull String type) {
        return json("{\"type\":\"" + type + "\",\"challenge\":\"" + Base64Url.encode(CHALLENGE)
                + "\",\"origin\":\"https://" + RP + "\",\"crossOrigin\":false}");
    }
    private static byte @NonNull [] registrationAuth(@NonNull KeyPair pair) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII)));
        out.write(0x45); out.writeBytes(new byte[4]); out.writeBytes(new byte[16]);
        out.write(0); out.write(ID.length); out.writeBytes(ID); out.writeBytes(edKey(pair));
        return out.toByteArray();
    }
    private static byte @NonNull [] assertionAuth(long counter) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII))); out.write(0x05);
        out.write((int) (counter >>> 24)); out.write((int) (counter >>> 16));
        out.write((int) (counter >>> 8)); out.write((int) counter);
        return out.toByteArray();
    }
    private static byte @NonNull [] attestation(byte @NonNull [] auth) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa3); text(out, "fmt"); text(out, "none");
        text(out, "authData"); bytes(out, auth); text(out, "attStmt"); out.write(0xa0);
        return out.toByteArray();
    }
    private static byte @NonNull [] edKey(@NonNull KeyPair pair) {
        byte[] spki = pair.getPublic().getEncoded();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(1); out.write(3); out.write(0x27);
        out.write(0x20); out.write(6); out.write(0x21); out.write(0x58); out.write(32);
        out.writeBytes(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        return out.toByteArray();
    }
    private static void text(@NonNull ByteArrayOutputStream out, @NonNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        out.write(0x60 | bytes.length); out.writeBytes(bytes);
    }
    private static void bytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] value) {
        if (value.length < 24) out.write(0x40 | value.length);
        else if (value.length < 256) { out.write(0x58); out.write(value.length); }
        else { out.write(0x59); out.write(value.length >>> 8); out.write(value.length); }
        out.writeBytes(value);
    }
    private static byte @NonNull [] hash(byte @NonNull [] input) {
        try { return MessageDigest.getInstance("SHA-256").digest(input); }
        catch (java.security.NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }
    private static byte @NonNull [] json(@NonNull String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
    private static byte @NonNull [] filled(int first) {
        byte[] result = new byte[32];
        for (int index = 0; index < result.length; index++) result[index] = (byte) (first + index);
        return result;
    }
    private static @NonNull WebAuthnRecordCodec records() {
        byte[] material = filled(1);
        StateSealer sealer = StateSealer.withActiveKey(
                SealingKey.fromBase64("k", Base64.getEncoder().encodeToString(material)))
                .clock(CLOCK).build();
        return new WebAuthnRecordCodec(sealer);
    }
}
