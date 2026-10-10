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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnCeremonyRecordCodecTests {
    private static final Instant NOW = Instant.parse("2026-10-09T12:00:00.123456789Z");
    private static final Instant EXPIRY = NOW.plusSeconds(300);
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final byte[] ID = bytes(1);
    private static final byte[] CHALLENGE = bytes(33);
    private static final byte[] BINDING = bytes(65);
    private static final byte[] HANDLE = {1, 2, 3};
    private static final Set<String> ORIGINS = Set.of("https://login.example.com",
            "https://login.example.com:8443");
    private static final String NAMESPACE = "tenant";
    private static final String RP = "login.example.com";

    @Test void roundTripsAllKindsAndConsumedMarkerWithoutReleasingAProof() throws Exception {
        WebAuthnCeremonyRecordCodec codec = ceremonyCodec();
        WebAuthnCeremonyState[] states = {
                WebAuthnCeremonyState.registration(ID, CHALLENGE, BINDING, ORIGINS, HANDLE, NOW, EXPIRY),
                WebAuthnCeremonyState.discoverableAuthentication(ID, CHALLENGE, BINDING, ORIGINS, NOW, EXPIRY),
                WebAuthnCeremonyState.accountReauthentication(ID, CHALLENGE, BINDING, ORIGINS,
                        HANDLE, "transfer 123", NOW, EXPIRY)
        };
        for (WebAuthnCeremonyState original : states) {
            var encoded = codec.encode(original);
            assertEquals(WebAuthnStoreKey.forCeremony(NAMESPACE, RP, ID), encoded.key());
            var restored = codec.decode(encoded.key(), encoded.sealedBytes(), CLOCK);
            assertEquals(original.kind(), restored.kind());
            assertArrayEquals(CHALLENGE, restored.challenge());
            assertArrayEquals(BINDING, restored.browserBinding());
            assertEquals(ORIGINS, restored.allowedOrigins());
            assertEquals(NOW, restored.issuedAt());
            assertEquals(EXPIRY, restored.expiresAt());
            assertTrue(restored.matchesBrowserBinding(BINDING));
            assertFalse(restored.matchesBrowserBinding(bytes(66)));
            assertTrue(restored.isPendingAt(NOW));
            assertFalse(restored.isPendingAt(EXPIRY));
            assertFalse(restored.isPendingAt(NOW.minusNanos(1)));
            assertEquals(original.actionPurpose(), restored.actionPurpose());
            assertArrayEquals(original.expectedHandle(), restored.expectedHandle());

            byte[] mutable = restored.challenge();
            mutable[0] ^= 1;
            assertArrayEquals(CHALLENGE, restored.challenge());
            byte[] sealed = encoded.sealedBytes();
            sealed[0] ^= 1;
            assertFalse(Arrays.equals(sealed, encoded.sealedBytes()));
            assertFalse(encoded.toString().contains(encoded.key().getStorageKey()));

            var consumed = codec.decode(encoded.key(), codec.encode(restored.consume()).sealedBytes(), CLOCK);
            assertTrue(consumed.isConsumed());
            assertFalse(consumed.isPendingAt(NOW));
            assertThrows(IllegalStateException.class, consumed::consume);
        }
    }

    @Test void rejectsWrongAddressNamespaceOriginAndExpiry() throws Exception {
        var codec = ceremonyCodec();
        var pending = WebAuthnCeremonyState.registration(ID, CHALLENGE, BINDING, ORIGINS, HANDLE, NOW, EXPIRY);
        var encoded = codec.encode(pending);
        assertThrows(WebAuthnRecordException.class, () -> codec.decode(
                WebAuthnStoreKey.forCeremony(NAMESPACE, RP, bytes(2)), encoded.sealedBytes(), CLOCK));
        assertThrows(WebAuthnRecordException.class, () -> new WebAuthnCeremonyRecordCodec(
                "other", RP, recordCodec()).decode(encoded.key(), encoded.sealedBytes(), CLOCK));
        assertThrows(WebAuthnRecordException.class, () -> codec.decode(encoded.key(), encoded.sealedBytes(),
                Clock.fixed(EXPIRY.plusNanos(1), ZoneOffset.UTC)));
        assertThrows(IllegalArgumentException.class, () -> codec.encode(WebAuthnCeremonyState.registration(
                ID, CHALLENGE, BINDING, Set.of("https://attacker.example.com"), HANDLE, NOW, EXPIRY)));
    }

    @Test void rejectsAuthenticatedPayloadWithInvalidKindStatusTimeOriginOrAccountBinding() throws Exception {
        WebAuthnStoreKey address = WebAuthnStoreKey.forCeremony(NAMESPACE, RP, ID);
        WebAuthnRecordCodec envelopes = recordCodec();
        var codec = new WebAuthnCeremonyRecordCodec(NAMESPACE, RP, envelopes);
        byte[] valid = rawPayload(1, 0, 1, ID, CHALLENGE, BINDING, NOW, EXPIRY,
                HANDLE, new byte[0], "https://login.example.com");
        byte[][] invalid = {
                change(valid, 0, 2), // version
                change(valid, 1, 2), // status
                change(valid, 2, 0), // kind
                change(valid, 2, 2), // discoverable may not carry an account handle
                change(valid, 2, 3), // reauth requires a purpose
                change(valid, 107, 127), // issued nanoseconds out of range
                Arrays.copyOf(valid, valid.length - 1),
                Arrays.copyOf(valid, valid.length + 1),
                rawPayload(1, 0, 1, bytes(2), CHALLENGE, BINDING, NOW, EXPIRY,
                        HANDLE, new byte[0], "https://login.example.com"),
                rawPayload(1, 0, 1, ID, CHALLENGE, BINDING, NOW, NOW.plusSeconds(29),
                        HANDLE, new byte[0], "https://login.example.com"),
                rawPayload(1, 0, 1, ID, CHALLENGE, BINDING, NOW, EXPIRY,
                        HANDLE, new byte[0], "https://other.example.com"),
                rawPayload(1, 0, 1, ID, CHALLENGE, BINDING, NOW, EXPIRY,
                        HANDLE, new byte[0], "https://login.example.com/"),
                rawPayload(1, 0, 3, ID, CHALLENGE, BINDING, NOW, EXPIRY,
                        HANDLE, new byte[] {(byte) 0xff}, "https://login.example.com")
        };
        for (byte[] payload : invalid) {
            byte[] sealed = envelopes.seal(address, payload, EXPIRY);
            WebAuthnRecordException failure = assertThrows(WebAuthnRecordException.class,
                    () -> codec.decode(address, sealed, CLOCK));
            assertEquals("Invalid WebAuthn store record.", failure.getMessage());
        }
    }

    @Test void preparesSingleUseConsumptionForSameAtomicWriteAsCredentialAndFencePredicates()
            throws Exception {
        var codec = ceremonyCodec();
        var encoded = codec.encode(WebAuthnCeremonyState.registration(
                ID, CHALLENGE, BINDING, ORIGINS, HANDLE, NOW, EXPIRY));
        WebAuthnStoreKey credential = WebAuthnStoreKey.forCredential(NAMESPACE, RP, new byte[] {9});
        WebAuthnStoreKey fence = WebAuthnStoreKey.forAccountFence(NAMESPACE, RP, HANDLE);
        var namespaceClock = new WebAuthnNamespaceClock(NAMESPACE, RP, recordCodec());
        var snapshot = WebAuthnStoreSnapshot.fromEntries(
                Set.of(encoded.key(), credential, fence, namespaceClock.key()), Map.of(
                encoded.key(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {1}, encoded.sealedBytes()),
                credential, WebAuthnStoreEntry.Absent.confirmed(),
                fence, WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {2}, new byte[] {1}),
                namespaceClock.key(), WebAuthnStoreEntry.Absent.confirmed()));
        var namespaceTime = namespaceClock.prepare(snapshot, NOW, CLOCK);
        var prepared = WebAuthnCeremonyConsumption.prepare(snapshot, codec, encoded.key(), ID,
                BINDING, WebAuthnCeremonyState.Kind.REGISTRATION, namespaceTime, CLOCK).orElseThrow();
        var write = WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, List.of(prepared.mutation(),
                WebAuthnStoreWrite.Mutation.insert(credential, new byte[] {7}),
                requireNonNull(namespaceTime.mutation())));
        assertEquals(Set.of(encoded.key(), credential, fence, namespaceClock.key()),
                write.getSnapshot().getEntries().keySet());
        assertEquals(WebAuthnStoreWrite.Mutation.Kind.REPLACE, prepared.mutation().getKind());
        assertTrue(codec.decode(encoded.key(), prepared.mutation().getSealedBytes().orElseThrow(), CLOCK)
                .isConsumed());
        assertFalse(prepared.toString().contains(encoded.key().getStorageKey()));

        assertTrue(WebAuthnCeremonyConsumption.prepare(snapshot, codec, encoded.key(), ID,
                bytes(66), WebAuthnCeremonyState.Kind.REGISTRATION, namespaceTime, CLOCK).isEmpty());
        assertTrue(WebAuthnCeremonyConsumption.prepare(snapshot, codec, encoded.key(), ID,
                BINDING, WebAuthnCeremonyState.Kind.ACCOUNT_REAUTHENTICATION,
                namespaceTime, CLOCK).isEmpty());
        assertTrue(WebAuthnCeremonyConsumption.prepare(snapshot, codec, encoded.key(), bytes(2),
                BINDING, WebAuthnCeremonyState.Kind.REGISTRATION, namespaceTime, CLOCK).isEmpty());
        var consumedSnapshot = WebAuthnStoreSnapshot.fromEntries(
                Set.of(encoded.key(), namespaceClock.key()), Map.of(
                encoded.key(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {3}, prepared.mutation().getSealedBytes().orElseThrow()),
                namespaceClock.key(), WebAuthnStoreEntry.Absent.confirmed()));
        var consumedTime = namespaceClock.prepare(consumedSnapshot, NOW, CLOCK);
        assertTrue(WebAuthnCeremonyConsumption.prepare(consumedSnapshot, codec, encoded.key(), ID,
                BINDING, WebAuthnCeremonyState.Kind.REGISTRATION, consumedTime, CLOCK).isEmpty());
        assertThrows(IllegalArgumentException.class, () -> WebAuthnCeremonyConsumption.prepare(
                consumedSnapshot, codec, encoded.key(), ID, BINDING,
                WebAuthnCeremonyState.Kind.REGISTRATION, namespaceTime, CLOCK));

        var rolledBackSnapshot = WebAuthnStoreSnapshot.fromEntries(
                Set.of(encoded.key(), namespaceClock.key()), Map.of(
                encoded.key(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {4}, encoded.sealedBytes()),
                namespaceClock.key(), WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                        new byte[] {5}, namespaceClock.encode(EXPIRY))));
        var rolledBackTime = namespaceClock.prepare(rolledBackSnapshot, NOW, CLOCK);
        assertEquals(EXPIRY, rolledBackTime.effectiveAt());
        assertTrue(WebAuthnCeremonyConsumption.prepare(rolledBackSnapshot, codec, encoded.key(), ID,
                BINDING, WebAuthnCeremonyState.Kind.REGISTRATION, rolledBackTime, CLOCK).isEmpty());
    }

    private static @NonNull WebAuthnCeremonyRecordCodec ceremonyCodec() {
        return new WebAuthnCeremonyRecordCodec(NAMESPACE, RP, recordCodec());
    }

    private static @NonNull WebAuthnRecordCodec recordCodec() {
        byte[] material = new byte[32];
        for (int index = 0; index < material.length; index++) material[index] = (byte) (index + 1);
        StateSealer sealer = StateSealer.withActiveKey(
                SealingKey.fromBase64("k", Base64.getEncoder().encodeToString(material)))
                .clock(CLOCK).build();
        return new WebAuthnRecordCodec(sealer);
    }

    private static byte @NonNull [] bytes(int first) {
        byte[] result = new byte[32];
        for (int index = 0; index < result.length; index++) result[index] = (byte) (first + index);
        return result;
    }

    private static byte @NonNull [] change(byte @NonNull [] bytes, int offset, int replacement) {
        byte[] changed = bytes.clone();
        changed[offset] = (byte) replacement;
        return changed;
    }

    private static byte @NonNull [] rawPayload(int version, int status, int kind, byte @NonNull [] id,
            byte @NonNull [] challenge, byte @NonNull [] binding, @NonNull Instant issued,
            @NonNull Instant expires, byte @NonNull [] handle, byte @NonNull [] purpose,
            @NonNull String origin) {
        byte[] ascii = origin.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer writer = ByteBuffer.allocate(126 + handle.length + purpose.length + 2 + ascii.length);
        writer.put((byte) version).put((byte) status).put((byte) kind);
        writer.put(id).put(challenge).put(binding);
        writer.putLong(issued.getEpochSecond()).putInt(issued.getNano());
        writer.putLong(expires.getEpochSecond()).putInt(expires.getNano());
        writer.put((byte) handle.length).put((byte) purpose.length).put((byte) 1);
        writer.put(handle).put(purpose).putShort((short) ascii.length).put(ascii);
        return writer.array();
    }
}
