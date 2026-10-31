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

import com.revetsec.testing.ScriptedWebAuthnStore;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnAuthoritativeAccountRecordsTests {
    private static final String NAMESPACE = "tenant";
    private static final String RP = "login.example.com";
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00.123456789Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final byte[] HANDLE = {1, 2, 3};

    @Test void namespaceRootStaysImmutableAndTimeComesOnlyFromTheObservation() throws Exception {
        var codec=new WebAuthnNamespaceClock(NAMESPACE,RP,records());
        WebAuthnStoreKey key=codec.key();
        assertEquals(WebAuthnStoreKey.Kind.NAMESPACE_CLOCK,key.getKind());
        assertFalse(key.equals(WebAuthnStoreKey.forNamespaceClock("other",RP)));
        var absent=ScriptedWebAuthnStore.snapshot(Set.of(key),Map.of(key,WebAuthnStoreEntry.Absent.confirmed()),NOW);
        var initial=codec.prepare(absent,NOW.minusSeconds(31),CLOCK);
        assertEquals(NOW,initial.effectiveAt());
        var inserted=requireNonNull(initial.mutation());
        assertEquals(WebAuthnStoreWrite.Mutation.Kind.INSERT,inserted.getKind());
        byte[] sealed=inserted.getSealedBytes().orElseThrow();
        assertEquals(NOW,codec.decode(key,sealed,CLOCK));
        for(Instant later:List.of(NOW,NOW.plusNanos(1),NOW.plusSeconds(1))){
            var present=ScriptedWebAuthnStore.snapshot(Set.of(key),Map.of(key,
                    WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{1},sealed)),later);
            var prepared=codec.prepare(present,NOW.minusSeconds(31),CLOCK);
            assertEquals(later,prepared.effectiveAt());assertNull(prepared.mutation());
            assertFalse(prepared.toString().contains(key.getStorageKey()));
        }
        var ceremony=WebAuthnCeremonyState.discoverableAuthentication(new byte[32],new byte[32],new byte[32],
                Set.of("https://login.example.com"),NOW.minusSeconds(300),NOW);
        assertFalse(ceremony.isPendingAt(initial.effectiveAt()));
    }

    @Test void namespaceClockRejectsAuthenticatedMalformedOrReboundPayload() throws Exception {
        var codec = new WebAuthnNamespaceClock(NAMESPACE, RP, records());
        WebAuthnStoreKey key = codec.key();
        byte[] valid = ByteBuffer.allocate(13).put((byte) 1)
                .putLong(NOW.getEpochSecond()).putInt(NOW.getNano()).array();
        for (byte[] invalid : new byte[][] {
                Arrays.copyOf(valid, 12), change(valid, 0, 2), change(valid, 9, 127)
        }) {
            byte[] sealed = malformed(key, invalid, NOW.plusSeconds(300));
            assertRedacted(() -> codec.decode(key, sealed, CLOCK));
        }
        assertRedacted(() -> codec.decode(WebAuthnStoreKey.forNamespaceClock("other", RP),
                codec.encode(ScriptedWebAuthnStore.observation(NOW).getAdmission().getAuthorityId(), NOW), CLOCK));
    }

    @Test void futureAndUnrepresentableHealthyMinimaNeverClampTheObservation() throws Exception {
        var codec=new WebAuthnNamespaceClock(NAMESPACE,RP,records());WebAuthnStoreKey key=codec.key();
        for(Instant minimum:List.of(NOW.plusNanos(1),Instant.MAX,Instant.MAX.minusNanos(1))){
            byte[] sealed=codec.encode(ScriptedWebAuthnStore.observation(NOW).getAdmission().getAuthorityId(),minimum);
            var snapshot=ScriptedWebAuthnStore.snapshot(Set.of(key),Map.of(key,
                    WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{1},sealed)),NOW);
            assertThrows(WebAuthnRecordException.class,()->codec.prepare(snapshot,minimum,CLOCK));
        }
    }

    @Test void accountFenceActiveAndDisabledAreKeyBoundAndDoNotInferActiveFromAbsence() throws Exception {
        var codec = new WebAuthnAccountFence(NAMESPACE, RP, records());
        var active = codec.encode(HANDLE, true, NOW);
        assertTrue(codec.decode(active.key(), active.sealedBytes(), CLOCK).isActive());
        assertArrayEquals(HANDLE, codec.decode(active.key(), active.sealedBytes(), CLOCK).userHandle());
        var disabled = codec.encode(HANDLE, false, NOW);
        assertFalse(codec.decode(disabled.key(), disabled.sealedBytes(), CLOCK).isActive());
        assertFalse(active.toString().contains(active.key().getStorageKey()));
        assertRedacted(() -> codec.decode(WebAuthnStoreKey.forAccountFence(NAMESPACE, RP,
                new byte[] {1, 2, 4}), active.sealedBytes(), CLOCK));
        byte[] invalid = {1, 2, 3, 1, 2, 3};
        assertRedacted(() -> codec.decode(active.key(), malformed(active.key(), invalid,
                NOW.plusSeconds(300)), CLOCK));
        var snapshot = WebAuthnStoreSnapshot.fromEntries(Set.of(active.key()), Map.of(
                active.key(), WebAuthnStoreEntry.Absent.confirmed()), ScriptedWebAuthnStore.observation(NOW));
        assertTrue(snapshot.getEntry(active.key()) instanceof WebAuthnStoreEntry.Absent);
    }

    @Test void indexRoundTripsCanonicalIdsAndRejectsReassignmentOrMalformedStoredLists() throws Exception {
        var codec = new WebAuthnCredentialIndex(NAMESPACE, RP, records());
        var index = codec.empty(HANDLE).withAdded(new byte[] {(byte) 0xff})
                .withAdded(new byte[] {0}).withAdded(new byte[] {1, 2});
        assertEquals(3, index.size());
        assertTrue(index.contains(new byte[] {(byte) 0xff}));
        assertArrayEquals(new byte[] {0}, index.credentialIds().get(0));
        assertArrayEquals(new byte[] {(byte) 0xff}, index.credentialIds().get(2));
        index.credentialIds().get(0)[0] = 42;
        assertArrayEquals(new byte[] {0}, index.credentialIds().get(0));
        assertThrows(IllegalArgumentException.class, () -> index.withAdded(new byte[] {0}));
        assertEquals(2, index.without(new byte[] {0}).size());
        assertThrows(IllegalArgumentException.class, () -> index.without(new byte[] {5}));
        var full = codec.empty(HANDLE);
        for (int value = 0; value < WebAuthnCredentialIndex.MAXIMUM_CREDENTIALS; value++)
            full = full.withAdded(new byte[] {(byte) value});
        var capped = full;
        assertThrows(IllegalArgumentException.class, () -> capped.withAdded(new byte[] {64}));

        var encoded = codec.encode(index, NOW);
        var decoded = codec.decode(encoded.key(), encoded.sealedBytes(), CLOCK);
        assertEquals(3, decoded.size());
        assertArrayEquals(HANDLE, decoded.userHandle());
        assertFalse(encoded.toString().contains(encoded.key().getStorageKey()));
        assertRedacted(() -> codec.decode(WebAuthnStoreKey.forAccountCredentialIndex(
                "other", RP, HANDLE), encoded.sealedBytes(), CLOCK));

        WebAuthnStoreKey key = encoded.key();
        for (byte[] invalid : new byte[][] {
                {2, 3, 0, 1, 2, 3}, // version
                {1, 3, 2, 1, 2, 3, 0, 1, 9}, // truncated second ID
                {1, 3, 2, 1, 2, 3, 0, 1, 9, 0, 1, 9}, // duplicate
                {1, 3, 1, 1, 2, 4, 0, 1, 9}, // wrong account
                {1, 3, 2, 1, 2, 3, 0, 1, 9, 0, 1, 8} // out of order
        }) {
            byte[] sealed = malformed(key, invalid, NOW.plusSeconds(300));
            assertRedacted(() -> codec.decode(key, sealed, CLOCK));
        }
    }

    private static void assertRedacted(@NonNull ThrowingAction action) {
        WebAuthnRecordException failure = assertThrows(WebAuthnRecordException.class, action::run);
        assertEquals("Invalid WebAuthn store record.", failure.getMessage());
    }

    private interface ThrowingAction { void run() throws Exception; }

    private static byte @NonNull [] change(byte @NonNull [] bytes, int offset, int replacement) {
        byte[] changed = bytes.clone();
        changed[offset] = (byte) replacement;
        return changed;
    }

    private static @NonNull WebAuthnRecordCodec records() {
        byte[] material = new byte[32];
        for (int index = 0; index < material.length; index++) material[index] = (byte) (index + 1);
        StateSealer sealer = StateSealer.withActiveKey(
                SealingKey.fromBase64("k", Base64.getEncoder().encodeToString(material)))
                .clock(CLOCK).build();
        return new WebAuthnRecordCodec(sealer);
    }



    private static byte @NonNull [] malformed(@NonNull WebAuthnStoreKey key,byte @NonNull [] inner,@NonNull Instant expires){
        return WebAuthnTestPayloads.seal(key,inner,expires,NOW);
    }

}
