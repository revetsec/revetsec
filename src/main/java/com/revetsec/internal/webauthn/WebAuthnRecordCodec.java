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

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.EntropySource;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.SealerV1;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Bounded authenticated binary envelope for one authoritative WebAuthn record. Each chunk uses
 * {@link StateSealer} under a dedicated type label and a context binding the exact store key,
 * random envelope ID, chunk count, chunk size and position. Framing is checked before any crypto.
 * The codec authenticates bytes but does not validate a ceremony, credential or account fence.
 * Store versions and external recovery fencing still protect against live races and rollback.
 */
@ThreadSafe
final class WebAuthnRecordCodec {
    static final int MAXIMUM_RECORD_BYTES = 262_144;
    static final int MAXIMUM_PLAINTEXT_BYTES = 110_000;
    private static final int MAXIMUM_CHUNKS = 256;
    private static final int RECORD_ID_BYTES = 16;
    private static final int HEADER_BYTES = 4 + 2 + 2 + RECORD_ID_BYTES;
    private static final String MAGIC = "WAR1";

    private final @NonNull StateSealer sealer;
    private final @NonNull EntropySource entropy;
    private final int rawChunkSize;

    WebAuthnRecordCodec(@NonNull StateSealer sealer) {
        this(sealer, EntropySource.fromDefaults());
    }

    WebAuthnRecordCodec(@NonNull StateSealer sealer, @NonNull EntropySource entropy) {
        this.sealer = requireNonNull(sealer);
        this.entropy = requireNonNull(entropy);
        int sealedLimit = SealedStateAccess.get().getMaximumSealedLength(sealer);
        // Two base64url expansions: raw bytes to StateSealer plaintext, then its authenticated wire value.
        // Reserve the full 64-byte key ID and extra room for length rounding on both encodings.
        int plaintextLimit = sealedLimit * 3 / 4 - SealerV1.FIXED_OVERHEAD
                - SealerV1.MAXIMUM_KEY_ID_LENGTH - 16;
        this.rawChunkSize = plaintextLimit * 3 / 4 - 8;
        if (this.rawChunkSize < 1 || this.rawChunkSize > 16_384)
            throw new IllegalArgumentException("Invalid WebAuthn sealer capacity");
    }

    byte @NonNull [] seal(@NonNull WebAuthnStoreKey key, byte @NonNull [] plaintext,
            @NonNull Instant expiresAt) {
        requireNonNull(key);
        requireNonNull(plaintext);
        requireNonNull(expiresAt);
        if (plaintext.length == 0 || plaintext.length > MAXIMUM_PLAINTEXT_BYTES)
            throw new IllegalArgumentException("Invalid WebAuthn record size");
        int count = (plaintext.length + this.rawChunkSize - 1) / this.rawChunkSize;
        if (count > MAXIMUM_CHUNKS) throw new IllegalArgumentException("Too many WebAuthn record chunks");
        byte[] recordId = this.entropy.nextBytes(RECORD_ID_BYTES);
        String addressDigest = addressDigest(key);
        List<String> sealed = new ArrayList<>(count);
        int total = HEADER_BYTES;
        for (int index = 0; index < count; index++) {
            int start = index * this.rawChunkSize;
            int end = Math.min(start + this.rawChunkSize, plaintext.length);
            byte[] chunk = Arrays.copyOfRange(plaintext, start, end);
            String encoded;
            try { encoded = Base64Url.encode(chunk); }
            finally { Arrays.fill(chunk, (byte) 0); }
            String value = SealedStateAccess.get().seal(this.sealer, SealedStateType.WEBAUTHN_RECORD,
                    encoded, context(addressDigest, recordId, count, this.rawChunkSize, index), expiresAt);
            if (value.length() == 0 || value.length() > 16_384
                    || total > MAXIMUM_RECORD_BYTES - 2 - value.length())
                throw new IllegalArgumentException("Invalid WebAuthn sealed record size");
            sealed.add(value);
            total += 2 + value.length();
        }
        byte[] frame = new byte[total];
        byte[] magic = MAGIC.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(magic, 0, frame, 0, magic.length);
        putUnsignedShort(frame, 4, count);
        putUnsignedShort(frame, 6, this.rawChunkSize);
        System.arraycopy(recordId, 0, frame, 8, RECORD_ID_BYTES);
        int position = HEADER_BYTES;
        for (String value : sealed) {
            putUnsignedShort(frame, position, value.length());
            position += 2;
            byte[] ascii = value.getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(ascii, 0, frame, position, ascii.length);
            position += ascii.length;
        }
        return frame;
    }

    byte @NonNull [] open(@NonNull WebAuthnStoreKey key, byte @NonNull [] untrusted,
            @NonNull Clock clock) throws WebAuthnRecordException {
        requireNonNull(key);
        requireNonNull(untrusted);
        requireNonNull(clock);
        if (untrusted.length < HEADER_BYTES + 3 || untrusted.length > MAXIMUM_RECORD_BYTES)
            throw new WebAuthnRecordException();
        byte[] frame = untrusted.clone();
        try {
            for (int index = 0; index < MAGIC.length(); index++)
                if (frame[index] != MAGIC.charAt(index)) throw new WebAuthnRecordException();
            int count = unsignedShort(frame, 4);
            int chunkSize = unsignedShort(frame, 6);
            if (count < 1 || count > MAXIMUM_CHUNKS || chunkSize < 1 || chunkSize > 16_384)
                throw new WebAuthnRecordException();
            byte[] recordId = Arrays.copyOfRange(frame, 8, HEADER_BYTES);
            int[] offsets = new int[count];
            int[] lengths = new int[count];
            int position = HEADER_BYTES;
            for (int index = 0; index < count; index++) {
                if (position > frame.length - 2) throw new WebAuthnRecordException();
                int length = unsignedShort(frame, position);
                position += 2;
                if (length < 1 || length > 16_384 || position > frame.length - length)
                    throw new WebAuthnRecordException();
                offsets[index] = position;
                lengths[index] = length;
                position += length;
            }
            if (position != frame.length) throw new WebAuthnRecordException();

            String addressDigest = addressDigest(key);
            byte[] plaintext = new byte[MAXIMUM_PLAINTEXT_BYTES];
            int size = 0;
            try {
                for (int index = 0; index < count; index++) {
                    for (int offset = offsets[index]; offset < offsets[index] + lengths[index]; offset++)
                        if (!Base64Url.isAlphabet((char) (frame[offset] & 0xff)))
                            throw new WebAuthnRecordException();
                    String value = new String(frame, offsets[index], lengths[index], StandardCharsets.US_ASCII);
                    String encoded = SealedStateAccess.get().unseal(this.sealer, SealedStateType.WEBAUTHN_RECORD,
                            value, context(addressDigest, recordId, count, chunkSize, index), clock);
                    byte[] chunk = Base64Url.decode(encoded);
                    try {
                        if (chunk.length == 0 || chunk.length > chunkSize
                                || index + 1 < count && chunk.length != chunkSize
                                || size > MAXIMUM_PLAINTEXT_BYTES - chunk.length)
                            throw new WebAuthnRecordException();
                        System.arraycopy(chunk, 0, plaintext, size, chunk.length);
                        size += chunk.length;
                    } finally {
                        Arrays.fill(chunk, (byte) 0);
                    }
                }
                return Arrays.copyOf(plaintext, size);
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        } catch (UnsealException | EncodingException | IllegalArgumentException failure) {
            throw new WebAuthnRecordException();
        } finally {
            Arrays.fill(frame, (byte) 0);
        }
    }

    private static @NonNull String addressDigest(@NonNull WebAuthnStoreKey key) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(key.getStorageKey().getBytes(StandardCharsets.US_ASCII));
            try { return Base64Url.encode(hash); }
            finally { Arrays.fill(hash, (byte) 0); }
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 unavailable", failure);
        }
    }

    private static @NonNull String context(@NonNull String addressDigest, byte @NonNull [] recordId,
            int count, int chunkSize, int index) {
        return "revetsec/wa-record/v1:" + addressDigest + ':' + Base64Url.encode(recordId)
                + ':' + count + ':' + chunkSize + ':' + index;
    }

    private static int unsignedShort(byte @NonNull [] bytes, int offset) {
        return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
    }

    private static void putUnsignedShort(byte @NonNull [] bytes, int offset, int value) {
        bytes[offset] = (byte) (value >>> 8);
        bytes[offset + 1] = (byte) value;
    }
}
