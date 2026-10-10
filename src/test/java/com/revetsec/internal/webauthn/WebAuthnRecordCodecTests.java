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

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnRecordCodecTests {
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final WebAuthnStoreKey CREDENTIAL = WebAuthnStoreKey.forCredential(
            "tenant", "login.example.com", new byte[] {1, 2, 3});
    private static final WebAuthnStoreKey OTHER_CREDENTIAL = WebAuthnStoreKey.forCredential(
            "tenant", "login.example.com", new byte[] {1, 2, 4});

    @Test void allSupportedSealerCapsRoundTripLargeBinaryState() throws Exception {
        for (int cap : List.of(1_024, 3_800, 16_384)) {
            WebAuthnRecordCodec codec = new WebAuthnRecordCodec(sealer("k".repeat(64), cap));
            byte[] payload = pattern(90_000);
            byte[] original = payload.clone();
            byte[] record = codec.seal(CREDENTIAL, payload, NOW.plusSeconds(300));
            assertArrayEquals(original, payload);
            assertTrue(record.length > 16_384);
            assertTrue(record.length <= WebAuthnRecordCodec.MAXIMUM_RECORD_BYTES);
            assertArrayEquals(payload, codec.open(CREDENTIAL, record, CLOCK));
            assertArrayEquals(payload, codec.open(CREDENTIAL, record, CLOCK));
            assertThrows(WebAuthnRecordException.class,
                    () -> codec.open(CREDENTIAL, record, Clock.fixed(NOW.plusSeconds(300), ZoneOffset.UTC)));
        }
    }

    @Test void smallestAndLargestSupportedPayloadsRemainBounded() throws Exception {
        WebAuthnRecordCodec codec = new WebAuthnRecordCodec(sealer("k", 1_024));
        assertArrayEquals(new byte[] {7}, codec.open(CREDENTIAL,
                codec.seal(CREDENTIAL, new byte[] {7}, NOW.plusSeconds(300)), CLOCK));
        byte[] largest = pattern(WebAuthnRecordCodec.MAXIMUM_PLAINTEXT_BYTES);
        byte[] record = codec.seal(CREDENTIAL, largest, NOW.plusSeconds(300));
        assertTrue(record.length <= WebAuthnRecordCodec.MAXIMUM_RECORD_BYTES);
        assertArrayEquals(largest, codec.open(CREDENTIAL, record, CLOCK));
        assertThrows(IllegalArgumentException.class,
                () -> codec.seal(CREDENTIAL, new byte[WebAuthnRecordCodec.MAXIMUM_PLAINTEXT_BYTES + 1],
                        NOW.plusSeconds(300)));
        assertThrows(IllegalArgumentException.class, () -> codec.seal(CREDENTIAL, new byte[0], NOW.plusSeconds(300)));
    }

    @Test void keyKindNamespaceAndSealingKeyBindEveryChunk() throws Exception {
        StateSealer sealer = sealer("k", 3_800);
        WebAuthnRecordCodec codec = new WebAuthnRecordCodec(sealer);
        byte[] record = codec.seal(CREDENTIAL, pattern(5_000), NOW.plusSeconds(300));
        for (WebAuthnStoreKey other : List.of(OTHER_CREDENTIAL,
                WebAuthnStoreKey.forCredential("other-tenant", "login.example.com", new byte[] {1, 2, 3}),
                WebAuthnStoreKey.forCredential("tenant", "other.example.com", new byte[] {1, 2, 3}),
                WebAuthnStoreKey.forAccountFence("tenant", "login.example.com", new byte[] {1, 2, 3})))
            assertThrows(WebAuthnRecordException.class, () -> codec.open(other, record, CLOCK));
        assertThrows(WebAuthnRecordException.class,
                () -> new WebAuthnRecordCodec(sealer("other", 3_800)).open(CREDENTIAL, record, CLOCK));

        byte[] second = codec.seal(CREDENTIAL, pattern(5_000), NOW.plusSeconds(300));
        assertFalse(Arrays.equals(record, second));
        assertArrayEquals(codec.open(CREDENTIAL, record, CLOCK), codec.open(CREDENTIAL, second, CLOCK));
    }

    @Test void framingRejectsTruncationExtensionTamperingAndReordering() throws Exception {
        WebAuthnRecordCodec codec = new WebAuthnRecordCodec(sealer("k", 3_800));
        byte[] payload = pattern(5_000);
        byte[] record = codec.seal(CREDENTIAL, payload, NOW.plusSeconds(300));
        byte[] unchanged = record.clone();
        for (int index : new int[] {0, 4, 6, 8, 25, record.length - 1}) {
            byte[] altered = record.clone();
            altered[index] ^= 1;
            assertThrows(WebAuthnRecordException.class, () -> codec.open(CREDENTIAL, altered, CLOCK));
        }
        assertThrows(WebAuthnRecordException.class,
                () -> codec.open(CREDENTIAL, Arrays.copyOf(record, record.length - 1), CLOCK));
        assertThrows(WebAuthnRecordException.class,
                () -> codec.open(CREDENTIAL, Arrays.copyOf(record, record.length + 1), CLOCK));
        assertThrows(WebAuthnRecordException.class,
                () -> codec.open(CREDENTIAL, new byte[WebAuthnRecordCodec.MAXIMUM_RECORD_BYTES + 1], CLOCK));
        assertArrayEquals(unchanged, record);

        int firstLength = unsignedShort(record, 24);
        int secondOffset = 26 + firstLength;
        int secondLength = unsignedShort(record, secondOffset);
        assertEquals(firstLength, secondLength);
        byte[] reordered = record.clone();
        System.arraycopy(record, secondOffset + 2, reordered, 26, firstLength);
        System.arraycopy(record, 26, reordered, secondOffset + 2, secondLength);
        assertThrows(WebAuthnRecordException.class, () -> codec.open(CREDENTIAL, reordered, CLOCK));

        byte[] differentEnvelope = codec.seal(CREDENTIAL, payload, NOW.plusSeconds(300));
        assertEquals(firstLength, unsignedShort(differentEnvelope, 24));
        byte[] spliced = record.clone();
        System.arraycopy(differentEnvelope, 26, spliced, 26, firstLength);
        assertThrows(WebAuthnRecordException.class, () -> codec.open(CREDENTIAL, spliced, CLOCK));
    }

    @Test void keyRotationOpensExistingRecordWithVerificationKey() throws Exception {
        SealingKey oldKey = key("old");
        SealingKey newKey = key("new");
        WebAuthnRecordCodec oldCodec = new WebAuthnRecordCodec(StateSealer.withActiveKey(oldKey)
                .maximumSealedLength(3_800).clock(CLOCK).build());
        byte[] payload = pattern(8_000);
        byte[] record = oldCodec.seal(CREDENTIAL, payload, NOW.plusSeconds(300));
        StateSealer rotated = StateSealer.withActiveKey(newKey).verificationKeys(List.of(oldKey))
                .maximumSealedLength(3_800).clock(CLOCK).build();
        assertArrayEquals(payload, new WebAuthnRecordCodec(rotated).open(CREDENTIAL, record, CLOCK));
    }

    private static @NonNull StateSealer sealer(@NonNull String id, int cap) {
        return StateSealer.withActiveKey(key(id)).maximumSealedLength(cap).clock(CLOCK).build();
    }

    private static @NonNull SealingKey key(@NonNull String id) {
        byte[] bytes = new byte[32];
        for (int index = 0; index < bytes.length; index++) bytes[index] = (byte) (index + 1);
        if (id.equals("other") || id.equals("new")) bytes[0] = 42;
        return SealingKey.fromBase64(id, Base64.getEncoder().encodeToString(bytes));
    }

    private static byte @NonNull [] pattern(int length) {
        byte[] bytes = new byte[length];
        for (int index = 0; index < length; index++) bytes[index] = (byte) (index * 37 + 11);
        return bytes;
    }

    private static int unsignedShort(byte @NonNull [] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }
}
