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
package com.revetsec.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Public trusted-configuration and storage-failure contracts, with synthetic local callbacks. */
final class WebAuthnCloseoutContractTests {
    private static final String RP = "login.example.com";
    private static final String ORIGIN = "https://" + RP;
    private static final String BINDING = Base64Url.encode(new byte[32]);
    private static final byte[] HANDLE = {4, 5, 6};

    @Test void namespaceAndDnsLabelsRejectEveryIndependentGrammarBoundary() {
        for (String namespace : List.of("", "x".repeat(129), " bad", "bad\u007f", "é"))
            assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreKey.forNamespaceClock(namespace, RP));
        for (String id : List.of("a", "a".repeat(254), "abc", "a..example", "a".repeat(64)+".example",
                "-a.example", "a-.example", "a_.example", "a/.example", "1.2"))
            assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreKey.forNamespaceClock("tenant", id));
        assertEquals(WebAuthnStoreKey.Kind.NAMESPACE_CLOCK, WebAuthnStoreKey.forNamespaceClock("x~", "a-0.example").getKind());
        var key = WebAuthnStoreKey.forCredential("tenant", RP, new byte[] {1});
        assertFalse(key.equals("address")); assertFalse(key.equals(null));
    }

    @Test void originPortsAndNamesEnforceCanonicalTrustedConfiguration() {
        for (String origin : List.of("https://user@"+RP, ORIGIN+"?q=v", ORIGIN+"#fragment", ORIGIN+":0", ORIGIN+":65536",
                ORIGIN+":0443", ORIGIN+":-1", "https://[", ORIGIN+"/"))
            assertThrows(IllegalArgumentException.class, () -> WebAuthnRelyingParty.withRelyingPartyId(RP).allowedOrigins(Set.of(origin)));
        assertThrows(IllegalArgumentException.class, () -> WebAuthnRelyingParty.withRelyingPartyId(RP).allowedOrigins(Set.of()));
        assertThrows(IllegalArgumentException.class, () -> WebAuthnRelyingParty.withRelyingPartyId(RP).allowedOrigins(Set.of("1","2","3","4","5","6","7","8","9")));
        for (String name : List.of("", "x".repeat(65), "bad\nname")) {
            assertThrows(IllegalArgumentException.class, () -> WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName(name));
            assertThrows(IllegalArgumentException.class, () -> WebAuthnRegistrationOptions.withUserHandle(HANDLE).userName(name));
            assertThrows(IllegalArgumentException.class, () -> WebAuthnRegistrationOptions.withUserHandle(HANDLE).userDisplayName(name));
        }
        var display = "😀".repeat(64);
        assertEquals(display, WebAuthnRegistrationOptions.withUserHandle(HANDLE).userName(display).userDisplayName(display).build().getUserDisplayName());
        for (byte[] handle : new byte[][] {new byte[0],new byte[65]})
            assertThrows(IllegalArgumentException.class, () -> WebAuthnRegistrationOptions.withUserHandle(handle));
        assertThrows(NullPointerException.class, () -> WebAuthnRegistrationOptions.withUserHandle(HANDLE).userName("a").build());
        assertThrows(NullPointerException.class, () -> WebAuthnRegistrationOptions.withUserHandle(HANDLE).userDisplayName("a").build());
    }

    @Test void malformedBrowserHandlesAndActionLabelsNeverReachApplicationStorage() {
        var store = new OutcomeStore(WebAuthnStoreCommitResult.COMMITTED); var rp = relyingParty(store, budget -> null);
        for (String binding : List.of("", "A".repeat(42), "!".repeat(43)))
            assertThrows(IllegalArgumentException.class, () -> rp.beginAuthenticationResult(binding));
        for (String purpose : List.of("", "x".repeat(129), "\u001f", "\u007f"))
            assertThrows(IllegalArgumentException.class, () -> rp.beginReauthenticationResult(HANDLE, purpose, BINDING));
        for (String ceremony : List.of("", "x".repeat(44), "!".repeat(43))) {
            assertInstanceOf(WebAuthnRegistrationResult.Rejected.class, rp.completeRegistrationResult(ceremony, new byte[] {1}, BINDING));
            assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class, rp.completeAuthenticationResult(ceremony, new byte[] {1}, BINDING));
        }
        for (byte[] body : new byte[][] {new byte[0], new byte[65537]}) {
            assertInstanceOf(WebAuthnRegistrationResult.Rejected.class, rp.completeRegistrationResult(BINDING, body, BINDING));
            assertInstanceOf(WebAuthnAuthenticationResult.Rejected.class, rp.completeAuthenticationResult(BINDING, body, BINDING));
        }
        assertEquals(0, store.reads); assertEquals(0, store.writes);
    }

    @Test void allWriteFailureKindsWithholdEnrollmentAndAccountPinnedRequests() {
        var options = WebAuthnRegistrationOptions.withUserHandle(HANDLE).userName("a").userDisplayName("A").build();
        for (WebAuthnStoreCommitResult outcome : WebAuthnStoreCommitResult.values()) {
            var store = new OutcomeStore(outcome); var rp = relyingParty(store, budget -> permit(true, false));
            var registration = rp.beginRegistrationResult(options, BINDING);
            var authentication = rp.beginAuthenticationResult(BINDING);
            var reauth = rp.beginReauthenticationResult(HANDLE, "transfer", BINDING);
            if (outcome == WebAuthnStoreCommitResult.COMMITTED) {
                assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class, registration);
                assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class, authentication);
            } else if (outcome == WebAuthnStoreCommitResult.UNKNOWN) {
                assertInstanceOf(WebAuthnRegistrationRequestResult.Indeterminate.class, registration);
                assertInstanceOf(WebAuthnAuthenticationRequestResult.Indeterminate.class, authentication);
            } else {
                assertInstanceOf(WebAuthnRegistrationRequestResult.Unavailable.class, registration);
                assertInstanceOf(WebAuthnAuthenticationRequestResult.Unavailable.class, authentication);
            }
            assertInstanceOf(WebAuthnAuthenticationRequestResult.Rejected.class, reauth);
            assertEquals(outcome == WebAuthnStoreCommitResult.CONFLICT ? 18 : 2, store.writes);
        }
    }

    @Test void revokedAndUnclosableRecoveryPermitsWithholdRequestsAndManagementSuccess() {
        var store = new OutcomeStore(WebAuthnStoreCommitResult.COMMITTED);
        var revoked = relyingParty(store, budget -> permit(false, false));
        assertInstanceOf(WebAuthnAuthenticationRequestResult.Unavailable.class, revoked.beginAuthenticationResult(BINDING));
        assertInstanceOf(WebAuthnCredentialListResult.Unavailable.class, revoked.listCredentialsResult(HANDLE));
        assertInstanceOf(WebAuthnCredentialRemovalResult.Unavailable.class, revoked.removeCredentialResult(HANDLE, new byte[] {1}));
        assertInstanceOf(WebAuthnAccountDisableResult.Unavailable.class, revoked.disableAccountResult(HANDLE));
        assertEquals(0, store.reads);
        var unclosable = relyingParty(store, budget -> permit(true, true));
        assertInstanceOf(WebAuthnAuthenticationRequestResult.Indeterminate.class, unclosable.beginAuthenticationResult(BINDING));
        assertInstanceOf(WebAuthnCredentialListResult.Unavailable.class, unclosable.listCredentialsResult(HANDLE));
        assertInstanceOf(WebAuthnAccountDisableResult.Indeterminate.class, unclosable.disableAccountResult(HANDLE));
        assertInstanceOf(WebAuthnCredentialRemovalResult.Indeterminate.class, unclosable.removeCredentialResult(HANDLE, new byte[] {1}));
    }

    @Test void boundedStoreRequestsRejectEmptyAndOverLimitPredicatesAndMutations() {
        assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreSnapshot.fromEntries(Set.of(),Map.of()));
        Map<WebAuthnStoreKey, WebAuthnStoreEntry> entries = new HashMap<>();
        for (int i=0;i<17;i++) entries.put(WebAuthnStoreKey.forCredential("tenant",RP,new byte[] {(byte)i}),WebAuthnStoreEntry.Absent.confirmed());
        assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreSnapshot.fromEntries(entries.keySet(),entries));
        var keys = new ArrayList<>(entries.keySet()).subList(0,9);
        Map<WebAuthnStoreKey,WebAuthnStoreEntry> nine = new HashMap<>();
        List<WebAuthnStoreWrite.Mutation> mutations = new ArrayList<>();
        for (WebAuthnStoreKey key : keys) { nine.put(key,WebAuthnStoreEntry.Absent.confirmed()); mutations.add(WebAuthnStoreWrite.Mutation.insert(key,new byte[] {1})); }
        var snapshot = WebAuthnStoreSnapshot.fromEntries(nine.keySet(),nine);
        assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,mutations));
        for (byte[] invalid : new byte[][] {new byte[0],new byte[262145]}) {
            assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.Mutation.insert(keys.get(0),invalid));
            assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.Mutation.replace(keys.get(0),invalid));
        }
        assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[129],new byte[] {1}));
        assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[] {1},new byte[0]));
        assertTrue(WebAuthnStoreWrite.Mutation.delete(keys.get(0)).getSealedBytes().isEmpty());
    }

    @Test void storeLimitsAndInterruptedCallsLeaveAuthoritativeStateUntouched() {
        for (int[] limits : new int[][] {{0,1},{65537,1},{1,0},{1,268435457}})
            assertThrows(IllegalArgumentException.class, () -> InMemoryWebAuthnStore.withLimits(limits[0],limits[1]));
        var store = InMemoryWebAuthnStore.withLimits(1,1); var key = WebAuthnStoreKey.forCredential("tenant",RP,new byte[] {1});
        var absent = WebAuthnStoreSnapshot.fromEntries(Set.of(key),Map.of(key,WebAuthnStoreEntry.Absent.confirmed()));
        var insertion=WebAuthnStoreWrite.fromSnapshotAndMutations(absent,List.of(WebAuthnStoreWrite.Mutation.insert(key,new byte[] {1})));
        assertEquals(WebAuthnStoreCommitResult.UNAVAILABLE,store.compareAndCommit(insertion,Duration.ofNanos(-1)));
        assertInstanceOf(WebAuthnStoreReadResult.Unavailable.class,store.read(Set.of(key),Duration.ZERO));
        Thread.currentThread().interrupt();
        try {
            assertEquals(WebAuthnStoreCommitResult.UNAVAILABLE,store.compareAndCommit(insertion,Duration.ofSeconds(30)));
            assertInstanceOf(WebAuthnStoreReadResult.Unavailable.class,store.read(Set.of(key),Duration.ofSeconds(31)));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); }
        assertEquals(WebAuthnStoreCommitResult.COMMITTED,store.compareAndCommit(insertion,Duration.ofSeconds(30)));
        assertEquals(WebAuthnStoreCommitResult.CONFLICT,store.compareAndCommit(insertion,Duration.ofSeconds(1)));
    }

    private static @NonNull WebAuthnRelyingParty relyingParty(@NonNull WebAuthnStore store,@NonNull WebAuthnRecoveryGate gate) {
        byte[] material = new byte[32]; for(int i=0;i<32;i++)material[i]=(byte)(i+1);
        return WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Name").allowedOrigins(Set.of(ORIGIN))
                .credentialNamespace("tenant").store(store).stateSealer(StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(material))).build())
                .recoveryGate(gate).build();
    }
    private static WebAuthnRecoveryGate.@NonNull Permit permit(boolean current,boolean closeFails) {
        return new WebAuthnRecoveryGate.Permit() {
            @Override public @NonNull Boolean isCurrent(){return current;}
            @Override public void close(){if(closeFails)throw new IllegalStateException("synthetic close failure");}
        };
    }
    private static final class OutcomeStore implements WebAuthnStore {
        private final @NonNull WebAuthnStoreCommitResult outcome;
        private int reads,writes;
        private OutcomeStore(@NonNull WebAuthnStoreCommitResult outcome){this.outcome=outcome;}
        @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget) {
            reads++; Map<WebAuthnStoreKey,WebAuthnStoreEntry> absent=new HashMap<>();
            for(WebAuthnStoreKey key:keys)absent.put(key,WebAuthnStoreEntry.Absent.confirmed());
            return WebAuthnStoreReadResult.Available.fromSnapshot(WebAuthnStoreSnapshot.fromEntries(keys,absent));
        }
        @Override public @NonNull WebAuthnStoreCommitResult compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){writes++;return outcome;}
    }
}
