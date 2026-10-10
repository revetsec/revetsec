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

import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Version-one pending/consumed ceremony payload inside an authenticated, key-bound store record.
 * The payload fixes the configured origin set at preparation; restoration checks its RP profile,
 * key address, lengths, canonical ordering and kind-specific fields. It grants no proof.
 */
@Immutable
final class WebAuthnCeremonyRecordCodec {
    private static final int VERSION = 1;
    private static final int FIXED_BYTES = 3 + 32 + 32 + 32 + 8 + 4 + 8 + 4 + 1 + 1 + 1;
    private static final int MAXIMUM_PAYLOAD_BYTES = 2_400;

    private final @NonNull String namespace;
    private final @NonNull String relyingPartyId;
    private final @NonNull WebAuthnRecordCodec records;

    WebAuthnCeremonyRecordCodec(@NonNull String namespace, @NonNull String relyingPartyId,
            @NonNull WebAuthnRecordCodec records) {
        WebAuthnStoreKey.forCeremony(requireNonNull(namespace), requireNonNull(relyingPartyId), new byte[32]);
        this.namespace = namespace;
        this.relyingPartyId = relyingPartyId;
        this.records = requireNonNull(records);
    }

    @NonNull Encoded encode(@NonNull WebAuthnCeremonyState state) {
        requireNonNull(state);
        validateOrigins(state.allowedOrigins());
        List<String> origins = state.allowedOrigins().stream().sorted().toList();
        byte[] id = state.ceremonyId();
        byte[] challenge = state.challenge();
        byte[] binding = state.browserBinding();
        byte[] handle = state.expectedHandle();
        String actionPurpose = state.actionPurpose();
        byte[] purpose = actionPurpose == null ? new byte[0]
                : actionPurpose.getBytes(StandardCharsets.US_ASCII);
        int length = FIXED_BYTES + (handle == null ? 0 : handle.length) + purpose.length;
        for (String origin : origins) length += 2 + origin.length();
        if (length > MAXIMUM_PAYLOAD_BYTES) throw new IllegalArgumentException("Invalid ceremony size");
        byte[] payload = new byte[length];
        try {
            ByteBuffer writer = ByteBuffer.wrap(payload);
            writer.put((byte) VERSION).put((byte) (state.isConsumed() ? 1 : 0))
                    .put((byte) (state.kind().ordinal() + 1));
            writer.put(id).put(challenge).put(binding);
            putInstant(writer, state.issuedAt());
            putInstant(writer, state.expiresAt());
            writer.put((byte) (handle == null ? 0 : handle.length));
            writer.put((byte) purpose.length).put((byte) origins.size());
            if (handle != null) writer.put(handle);
            writer.put(purpose);
            for (String origin : origins) {
                byte[] ascii = origin.getBytes(StandardCharsets.US_ASCII);
                writer.putShort((short) ascii.length).put(ascii);
            }
            WebAuthnStoreKey key = WebAuthnStoreKey.forCeremony(this.namespace, this.relyingPartyId, id);
            return new Encoded(key, this.records.seal(key, payload, state.expiresAt()));
        } finally {
            Arrays.fill(id, (byte) 0);
            Arrays.fill(challenge, (byte) 0);
            Arrays.fill(binding, (byte) 0);
            if (handle != null) Arrays.fill(handle, (byte) 0);
            Arrays.fill(purpose, (byte) 0);
            Arrays.fill(payload, (byte) 0);
        }
    }

    @NonNull WebAuthnCeremonyState decode(@NonNull WebAuthnStoreKey key,
            byte @NonNull [] sealedBytes, @NonNull Clock clock) throws WebAuthnRecordException {
        requireNonNull(key);
        requireNonNull(sealedBytes);
        requireNonNull(clock);
        if (key.getKind() != WebAuthnStoreKey.Kind.CEREMONY) throw new WebAuthnRecordException();
        byte[] payload = this.records.open(key, sealedBytes, clock);
        try {
            if (payload.length < FIXED_BYTES || payload.length > MAXIMUM_PAYLOAD_BYTES)
                throw new WebAuthnRecordException();
            ByteBuffer reader = ByteBuffer.wrap(payload);
            int version = reader.get() & 0xff;
            int status = reader.get() & 0xff;
            int kind = reader.get() & 0xff;
            if (version != VERSION || status > 1 || kind < 1 || kind > 3)
                throw new WebAuthnRecordException();
            byte[] id = new byte[32];
            byte[] challenge = new byte[32];
            byte[] binding = new byte[32];
            byte[] handle = null;
            byte[] purpose = null;
            try {
                reader.get(id).get(challenge).get(binding);
                Instant issuedAt = readInstant(reader);
                Instant expiresAt = readInstant(reader);
                // StateSealer transports expiry at second precision; the ceremony keeps the
                // exact instant so a subsecond deadline cannot be rounded into acceptance.
                if (!clock.instant().isBefore(expiresAt)) throw new WebAuthnRecordException();
                int handleLength = reader.get() & 0xff;
                int purposeLength = reader.get() & 0xff;
                int originCount = reader.get() & 0xff;
                if (handleLength > 64 || purposeLength > 128 || originCount < 1 || originCount > 8
                        || reader.remaining() < handleLength + purposeLength + originCount * 3)
                    throw new WebAuthnRecordException();
                handle = new byte[handleLength];
                purpose = new byte[purposeLength];
                reader.get(handle).get(purpose);
                List<String> origins = new ArrayList<>(originCount);
                String previous = null;
                for (int index = 0; index < originCount; index++) {
                    if (reader.remaining() < 2) throw new WebAuthnRecordException();
                    int length = Short.toUnsignedInt(reader.getShort());
                    if (length < 1 || length > 267 || reader.remaining() < length)
                        throw new WebAuthnRecordException();
                    byte[] ascii = new byte[length];
                    reader.get(ascii);
                    for (byte value : ascii)
                        if (value < 0x21 || value > 0x7e) throw new WebAuthnRecordException();
                    String origin = new String(ascii, StandardCharsets.US_ASCII);
                    if (previous != null && previous.compareTo(origin) >= 0)
                        throw new WebAuthnRecordException();
                    origins.add(origin);
                    previous = origin;
                }
                if (reader.hasRemaining() || !key.equals(WebAuthnStoreKey.forCeremony(
                        this.namespace, this.relyingPartyId, id))) throw new WebAuthnRecordException();
                Set<String> originSet = Set.copyOf(origins);
                validateOrigins(originSet);
                String actionPurpose = purposeLength == 0 ? null : new String(purpose, StandardCharsets.US_ASCII);
                for (byte value : purpose)
                    if (value < 0x20 || value > 0x7e) throw new WebAuthnRecordException();
                return WebAuthnCeremonyState.restored(WebAuthnCeremonyState.Kind.values()[kind - 1],
                        id, challenge, binding, originSet, handleLength == 0 ? null : handle,
                        actionPurpose, issuedAt, expiresAt, status == 1);
            } finally {
                Arrays.fill(id, (byte) 0);
                Arrays.fill(challenge, (byte) 0);
                Arrays.fill(binding, (byte) 0);
                if (handle != null) Arrays.fill(handle, (byte) 0);
                if (purpose != null) Arrays.fill(purpose, (byte) 0);
            }
        } catch (IllegalArgumentException | DateTimeException failure) {
            throw new WebAuthnRecordException();
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
    }

    private void validateOrigins(@NonNull Set<@NonNull String> origins) {
        new WebAuthnClientData(this.relyingPartyId, origins, WebAuthnClientData.DEFAULT_MAXIMUM_BYTES);
    }

    private static void putInstant(@NonNull ByteBuffer writer, @NonNull Instant instant) {
        writer.putLong(instant.getEpochSecond()).putInt(instant.getNano());
    }

    private static @NonNull Instant readInstant(@NonNull ByteBuffer reader) {
        long seconds = reader.getLong();
        int nanos = reader.getInt();
        if (nanos < 0 || nanos > 999_999_999) throw new IllegalArgumentException("Invalid instant");
        return Instant.ofEpochSecond(seconds, nanos);
    }

    /** Key and sealed bytes for a conditional insert or replacement; no proof. */
    @Immutable
    static final class Encoded {
        private final @NonNull WebAuthnStoreKey key;
        private final byte @NonNull [] sealedBytes;

        private Encoded(@NonNull WebAuthnStoreKey key, byte @NonNull [] sealedBytes) {
            this.key = key;
            this.sealedBytes = sealedBytes.clone();
        }

        @NonNull WebAuthnStoreKey key() { return this.key; }
        byte @NonNull [] sealedBytes() { return this.sealedBytes.clone(); }
        @Override public @NonNull String toString() { return "Encoded{ceremony=<redacted>, no proof}"; }
    }
}
