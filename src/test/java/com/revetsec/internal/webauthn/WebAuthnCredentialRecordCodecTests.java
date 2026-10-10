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
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnCredentialRecordCodecTests {
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final byte[] ID = {1, 2, 3};
    private static final byte[] HANDLE = {4, 5, 6};
    private static final String NAMESPACE = "tenant";
    private static final String RP = "login.example.com";

    @Test void roundTripsCheckedCredentialStateWithUnsignedCounterAndCopies() throws Exception {
        byte[] key = edKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
        var state = WebAuthnCredentialState.checked(ID, HANDLE, key, -8, 0xffff_ffffL, true, true);
        WebAuthnCredentialRecordCodec codec = credentialCodec();
        var encoded = codec.encode(state);
        assertEquals(WebAuthnStoreKey.forCredential(NAMESPACE, RP, ID), encoded.key());
        byte[] frame = encoded.sealedBytes();
        frame[0] = 0;
        assertFalse(Arrays.equals(frame, encoded.sealedBytes()));
        var restored = codec.decode(encoded.key(), encoded.sealedBytes(), CLOCK);
        assertArrayEquals(ID, restored.credentialId());
        assertArrayEquals(HANDLE, restored.userHandle());
        assertArrayEquals(key, restored.keyCbor());
        assertEquals(-8, restored.algorithm());
        assertEquals(0xffff_ffffL, restored.counter());
        assertTrue(restored.backupEligible());
        assertTrue(restored.backedUp());
        assertFalse(encoded.toString().contains(encoded.key().getStorageKey()));
        assertFalse(encoded.toString().contains("AQID"));
    }

    @Test void rejectsReboundCredentialKeysAndWrongKinds() throws Exception {
        byte[] key = edKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
        var codec = credentialCodec();
        var encoded = codec.encode(WebAuthnCredentialState.checked(ID, HANDLE, key, -8, 1, false, false));
        assertThrows(WebAuthnRecordException.class, () -> codec.decode(
                WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {1, 2, 4}),
                encoded.sealedBytes(), CLOCK));
        assertThrows(WebAuthnRecordException.class, () -> codec.decode(
                WebAuthnStoreKey.forAccountFence(NAMESPACE, RP, HANDLE), encoded.sealedBytes(), CLOCK));

        WebAuthnStoreKey wrongAddress = WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {1, 2, 4});
        byte[] rebound = recordCodec().seal(wrongAddress, rawPayload(ID, HANDLE, key, -8, 1, 0),
                NOW.plusSeconds(300));
        assertThrows(WebAuthnRecordException.class, () -> codec.decode(wrongAddress, rebound, CLOCK));
    }

    @Test void rejectsAuthenticatedButInvalidCredentialPayloads() throws Exception {
        byte[] key = edKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair());
        WebAuthnStoreKey address = WebAuthnStoreKey.forCredential(NAMESPACE, RP, ID);
        WebAuthnRecordCodec envelopes = recordCodec();
        WebAuthnCredentialRecordCodec codec = new WebAuthnCredentialRecordCodec(NAMESPACE, RP, envelopes);
        byte[] valid = rawPayload(ID, HANDLE, key, -8, 7, 0);
        int[] tamperedOffsets = {0, 1, 7, 8, 10, 11, 12, 13 + ID.length + HANDLE.length};
        for (int offset : tamperedOffsets) {
            byte[] invalid = valid.clone();
            invalid[offset] ^= 0x40;
            byte[] sealed = envelopes.seal(address, invalid, NOW.plusSeconds(300));
            assertThrows(WebAuthnRecordException.class, () -> codec.decode(address, sealed, CLOCK));
        }
        for (byte[] invalid : new byte[][] {Arrays.copyOf(valid, 12), Arrays.copyOf(valid, valid.length - 1),
                Arrays.copyOf(valid, valid.length + 1), rawPayload(ID, HANDLE, key, -7, 7, 0),
                rawPayload(ID, HANDLE, key, -8, 7, 2)}) {
            byte[] sealed = envelopes.seal(address, invalid, NOW.plusSeconds(300));
            assertThrows(WebAuthnRecordException.class, () -> codec.decode(address, sealed, CLOCK));
        }
    }

    @Test void revokedCredentialRetainsIdOwnershipWithoutAnActiveVerificationKey() throws Exception {
        var codec = credentialCodec();
        var tombstone = codec.encodeRevoked(ID, HANDLE);
        var decoded = codec.decodeRecord(tombstone.key(), tombstone.sealedBytes(), CLOCK);
        assertTrue(decoded.isRevoked());
        assertArrayEquals(ID, decoded.credentialId());
        assertArrayEquals(HANDLE, decoded.userHandle());
        assertThrows(WebAuthnRecordException.class,
                () -> codec.decode(tombstone.key(), tombstone.sealedBytes(), CLOCK));
        assertTrue(tombstone.sealedBytes().length < codec.encode(WebAuthnCredentialState.checked(
                ID, HANDLE, edKey(KeyPairGenerator.getInstance("Ed25519").generateKeyPair()),
                -8, 0, false, false)).sealedBytes().length);

        WebAuthnStoreKey address = tombstone.key();
        byte[] valid = {2, 0, 3, 3, 1, 2, 3, 4, 5, 6};
        for (byte[] invalid : new byte[][] {
                Arrays.copyOf(valid, valid.length - 1), Arrays.copyOf(valid, valid.length + 1),
                {2, 0, 3, 3, 1, 2, 4, 4, 5, 6}, {2, 0, 3, 3, 1, 2, 3, 4, 5, 6, 7}
        }) {
            byte[] sealed = recordCodec().seal(address, invalid, NOW.plusSeconds(300));
            assertThrows(WebAuthnRecordException.class, () -> codec.decodeRecord(address, sealed, CLOCK));
        }
        assertThrows(WebAuthnRecordException.class, () -> codec.decodeRecord(
                WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {1, 2, 4}),
                tombstone.sealedBytes(), CLOCK));
    }

    private static @NonNull WebAuthnCredentialRecordCodec credentialCodec() {
        return new WebAuthnCredentialRecordCodec(NAMESPACE, RP, recordCodec());
    }

    private static @NonNull WebAuthnRecordCodec recordCodec() {
        byte[] material = new byte[32];
        for (int index = 0; index < material.length; index++) material[index] = (byte) (index + 1);
        StateSealer sealer = StateSealer.withActiveKey(
                SealingKey.fromBase64("k", Base64.getEncoder().encodeToString(material)))
                .clock(CLOCK).build();
        return new WebAuthnRecordCodec(sealer);
    }

    private static byte @NonNull [] rawPayload(byte @NonNull [] id, byte @NonNull [] handle,
            byte @NonNull [] key, int algorithm, long counter, int flags) {
        ByteBuffer writer = ByteBuffer.allocate(13 + id.length + handle.length + key.length);
        writer.put((byte) 1).putShort((short) algorithm).putInt((int) counter).put((byte) flags);
        writer.putShort((short) id.length).put((byte) handle.length).putShort((short) key.length);
        writer.put(id).put(handle).put(key);
        return writer.array();
    }

    private static byte @NonNull [] edKey(@NonNull KeyPair pair) {
        byte[] spki = pair.getPublic().getEncoded();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(1); out.write(3); out.write(0x27);
        out.write(0x20); out.write(6); out.write(0x21); out.write(0x58); out.write(32);
        out.writeBytes(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        return out.toByteArray();
    }
}
