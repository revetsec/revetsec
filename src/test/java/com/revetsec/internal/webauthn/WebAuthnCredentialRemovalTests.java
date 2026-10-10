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
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnCredentialRemovalTests {
    private static final String NAMESPACE = "tenant";
    private static final String RP = "login.example.com";
    private static final byte[] HANDLE = {4, 5, 6};
    private static final byte[] ID = {1, 2, 3};
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test void removalAtomicallyReplacesCredentialWithPermanentTombstoneAndUpdatesIndex()
            throws Exception {
        var fixture = fixture(HANDLE, true, true);
        var prepared = fixture.planner.prepare(fixture.snapshot, HANDLE, ID, CLOCK).orElseThrow();
        WebAuthnStoreWrite write = prepared.write();
        var keys = fixture.planner.keys(HANDLE, ID);
        assertEquals(keys.all(), write.getSnapshot().getEntries().keySet());
        assertEquals(3, write.getMutations().size());
        assertTrue(write.getMutations().stream().noneMatch(
                mutation -> mutation.getKey().equals(keys.fence())));

        byte[] tombstone = changedBytes(write, keys.credential());
        var revoked = new WebAuthnCredentialRecordCodec(NAMESPACE, RP, records())
                .decodeRecord(keys.credential(), tombstone, CLOCK);
        assertTrue(revoked.isRevoked());
        assertArrayEquals(ID, revoked.credentialId());
        assertArrayEquals(HANDLE, revoked.userHandle());
        assertEquals(0, new WebAuthnCredentialIndex(NAMESPACE, RP, records())
                .decode(keys.index(), changedBytes(write, keys.index()), CLOCK).size());
        assertEquals(NOW, new WebAuthnNamespaceClock(NAMESPACE, RP, records())
                .decode(keys.clock(), changedBytes(write, keys.clock()), CLOCK));
        assertFalse(prepared.toString().contains(keys.credential().getStorageKey()));

        // A later read sees a retained Present credential, so registration cannot insert this ID.
        var later = WebAuthnStoreSnapshot.fromEntries(keys.all(), Map.of(
                keys.credential(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {9}, tombstone),
                keys.index(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {10}, changedBytes(write, keys.index())),
                keys.fence(), fixture.snapshot.getEntry(keys.fence()),
                keys.clock(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {11}, changedBytes(write, keys.clock()))));
        assertThrows(IllegalArgumentException.class, () -> WebAuthnStoreWrite.fromSnapshotAndMutations(
                later, java.util.List.of(WebAuthnStoreWrite.Mutation.insert(keys.credential(),
                        new byte[] {1}))));
        assertTrue(fixture.planner.prepare(later, HANDLE, ID, CLOCK).isEmpty());
    }

    @Test void disabledAccountCanRemoveButInconsistentStateCannotPrepareRemoval() throws Exception {
        var fixture = fixture(HANDLE, true, true);
        var keys = fixture.planner.keys(HANDLE, ID);
        Map<WebAuthnStoreKey, WebAuthnStoreEntry> entries = new HashMap<>(fixture.snapshot.getEntries());
        entries.put(keys.fence(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                new byte[] {7}, new WebAuthnAccountFence(NAMESPACE, RP, records())
                        .encode(HANDLE, false).sealedBytes()));
        assertTrue(fixture.planner.prepare(snapshot(keys, entries), HANDLE, ID, CLOCK).isPresent());

        entries = new HashMap<>(fixture.snapshot.getEntries());
        entries.put(keys.fence(), WebAuthnStoreEntry.Absent.confirmed());
        var missingFence = snapshot(keys, entries);
        assertThrows(WebAuthnRecordException.class,
                () -> fixture.planner.prepare(missingFence, HANDLE, ID, CLOCK));

        entries = new HashMap<>(fixture.snapshot.getEntries());
        entries.put(keys.credential(), WebAuthnStoreEntry.Absent.confirmed());
        var missingCredential = snapshot(keys, entries);
        WebAuthnRecordException missing = assertThrows(WebAuthnRecordException.class,
                () -> fixture.planner.prepare(missingCredential, HANDLE, ID, CLOCK));
        assertEquals("Invalid WebAuthn store record.", missing.getMessage());

        entries = new HashMap<>(fixture.snapshot.getEntries());
        entries.put(keys.index(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                new byte[] {8}, new WebAuthnCredentialIndex(NAMESPACE, RP, records())
                        .encode(new WebAuthnCredentialIndex(NAMESPACE, RP, records())
                                .empty(HANDLE)).sealedBytes()));
        var missingIndexMembership = snapshot(keys, entries);
        assertThrows(WebAuthnRecordException.class,
                () -> fixture.planner.prepare(missingIndexMembership, HANDLE, ID, CLOCK));

        entries = new HashMap<>(fixture.snapshot.getEntries());
        entries.put(keys.credential(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                new byte[] {9}, new WebAuthnCredentialRecordCodec(NAMESPACE, RP, records())
                        .encodeRevoked(ID, HANDLE).sealedBytes()));
        var stillListedRevoked = snapshot(keys, entries);
        assertThrows(WebAuthnRecordException.class,
                () -> fixture.planner.prepare(stillListedRevoked, HANDLE, ID, CLOCK));

        byte[] otherHandle = {9};
        byte[] otherCredential = new WebAuthnCredentialRecordCodec(NAMESPACE, RP, records())
                .encode(WebAuthnCredentialState.checked(ID, otherHandle,
                        edKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair()),
                        -8, 0, false, false)).sealedBytes();
        entries = new HashMap<>(fixture.snapshot.getEntries());
        entries.put(keys.credential(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                new byte[] {10}, otherCredential));
        var conflictingOwner = snapshot(keys, entries);
        assertThrows(WebAuthnRecordException.class,
                () -> fixture.planner.prepare(conflictingOwner, HANDLE, ID, CLOCK));
        entries.put(keys.index(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                new byte[] {11}, new WebAuthnCredentialIndex(NAMESPACE, RP, records())
                        .encode(new WebAuthnCredentialIndex(NAMESPACE, RP, records())
                                .empty(HANDLE)).sealedBytes()));
        assertTrue(fixture.planner.prepare(snapshot(keys, entries), HANDLE, ID, CLOCK).isEmpty());
    }

    private static @NonNull Fixture fixture(byte @NonNull [] handle, boolean active,
            boolean listed) throws Exception {
        WebAuthnRecordCodec records = records();
        var planner = new WebAuthnCredentialRemoval(NAMESPACE, RP, records);
        var keys = planner.keys(handle, ID);
        byte[] publicKey = edKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
        var credential = new WebAuthnCredentialRecordCodec(NAMESPACE, RP, records)
                .encode(WebAuthnCredentialState.checked(ID, handle, publicKey, -8, 0, false, false));
        var indexes = new WebAuthnCredentialIndex(NAMESPACE, RP, records);
        var index = indexes.encode(listed ? indexes.empty(handle).withAdded(ID) : indexes.empty(handle));
        var fence = new WebAuthnAccountFence(NAMESPACE, RP, records).encode(handle, active);
        var snapshot = WebAuthnStoreSnapshot.fromEntries(keys.all(), Map.of(
                keys.credential(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {1}, credential.sealedBytes()),
                keys.index(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {2}, index.sealedBytes()),
                keys.fence(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {3}, fence.sealedBytes()),
                keys.clock(), WebAuthnStoreEntry.Absent.confirmed()));
        return new Fixture(planner, snapshot);
    }

    private static @NonNull WebAuthnStoreSnapshot snapshot(
            WebAuthnCredentialRemoval.@NonNull SetOfKeys keys,
            @NonNull Map<@NonNull WebAuthnStoreKey, @NonNull WebAuthnStoreEntry> entries) {
        return WebAuthnStoreSnapshot.fromEntries(keys.all(), entries);
    }

    private static byte @NonNull [] changedBytes(@NonNull WebAuthnStoreWrite write,
            @NonNull WebAuthnStoreKey key) {
        return write.getMutations().stream().filter(mutation -> mutation.getKey().equals(key))
                .findFirst().orElseThrow().getSealedBytes().orElseThrow();
    }

    private static byte @NonNull [] edKey(@NonNull KeyPair pair) {
        byte[] spki = pair.getPublic().getEncoded();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(1); out.write(3); out.write(0x27);
        out.write(0x20); out.write(6); out.write(0x21); out.write(0x58); out.write(32);
        out.writeBytes(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        return out.toByteArray();
    }

    private static @NonNull WebAuthnRecordCodec records() {
        byte[] material = new byte[32];
        for (int index = 0; index < material.length; index++) material[index] = (byte) (index + 1);
        StateSealer sealer = StateSealer.withActiveKey(
                SealingKey.fromBase64("k", Base64.getEncoder().encodeToString(material)))
                .clock(CLOCK).build();
        return new WebAuthnRecordCodec(sealer);
    }

    private static final class Fixture {
        private final @NonNull WebAuthnCredentialRemoval planner;
        private final @NonNull WebAuthnStoreSnapshot snapshot;
        private Fixture(@NonNull WebAuthnCredentialRemoval planner,
                @NonNull WebAuthnStoreSnapshot snapshot) {
            this.planner = planner;
            this.snapshot = snapshot;
        }
    }
}
