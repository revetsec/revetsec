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

import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/** Authenticated namespace-wide observed time, advanced with the accepting store transaction. */
@Immutable
final class WebAuthnNamespaceClock {
    private static final int VERSION = 1;
    private static final int PAYLOAD_BYTES = 13;
    private static final @NonNull Instant PERMANENT = Instant.ofEpochSecond(Instant.MAX.getEpochSecond());

    private final @NonNull WebAuthnStoreKey key;
    private final @NonNull WebAuthnRecordCodec records;

    WebAuthnNamespaceClock(@NonNull String namespace, @NonNull String relyingPartyId,
            @NonNull WebAuthnRecordCodec records) {
        this.key = WebAuthnStoreKey.forNamespaceClock(namespace, relyingPartyId);
        this.records = requireNonNull(records);
    }

    @NonNull WebAuthnStoreKey key() { return this.key; }

    byte @NonNull [] encode(@NonNull Instant observedAt) {
        requireNonNull(observedAt);
        byte[] payload = ByteBuffer.allocate(PAYLOAD_BYTES).put((byte) VERSION)
                .putLong(observedAt.getEpochSecond()).putInt(observedAt.getNano()).array();
        try { return this.records.seal(this.key, payload, PERMANENT); }
        finally { Arrays.fill(payload, (byte) 0); }
    }

    @NonNull Instant decode(@NonNull WebAuthnStoreKey addressedKey, byte @NonNull [] sealedBytes,
            @NonNull Clock clock) throws WebAuthnRecordException {
        requireNonNull(addressedKey);
        requireNonNull(sealedBytes);
        requireNonNull(clock);
        if (!this.key.equals(addressedKey)) throw new WebAuthnRecordException();
        byte[] payload = this.records.open(addressedKey, sealedBytes, clock);
        try {
            if (payload.length != PAYLOAD_BYTES || payload[0] != VERSION)
                throw new WebAuthnRecordException();
            ByteBuffer reader = ByteBuffer.wrap(payload);
            reader.get();
            long seconds = reader.getLong();
            int nanos = reader.getInt();
            if (nanos < 0 || nanos > 999_999_999) throw new WebAuthnRecordException();
            return Instant.ofEpochSecond(seconds, nanos);
        } catch (DateTimeException failure) {
            throw new WebAuthnRecordException();
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
    }

    /**
     * The returned mutation must share the accepting transaction's complete snapshot. If the
     * wall clock moved backward, the stored observation remains the effective time. This does
     * not replace the separate external durable recovery marker after a database restore.
     */
    @NonNull Advance prepare(@NonNull WebAuthnStoreSnapshot snapshot, @NonNull Instant wallTime,
            @NonNull Clock clock) throws WebAuthnRecordException {
        requireNonNull(snapshot);
        requireNonNull(wallTime);
        requireNonNull(clock);
        WebAuthnStoreEntry entry = snapshot.getEntry(this.key);
        if (entry instanceof WebAuthnStoreEntry.Absent)
            return new Advance(snapshot, wallTime,
                    WebAuthnStoreWrite.Mutation.insert(this.key, encode(wallTime)));
        WebAuthnStoreEntry.Present present = (WebAuthnStoreEntry.Present) entry;
        Instant stored = decode(this.key, present.getSealedBytes(), clock);
        if (!wallTime.isAfter(stored)) return new Advance(snapshot, stored, null);
        return new Advance(snapshot, wallTime,
                WebAuthnStoreWrite.Mutation.replace(this.key, encode(wallTime)));
    }

    /** Effective monotonic time and an optional version-conditioned advance; no proof. */
    @Immutable
    static final class Advance {
        private final @NonNull WebAuthnStoreSnapshot snapshot;
        private final @NonNull Instant effectiveAt;
        private final WebAuthnStoreWrite.@Nullable Mutation mutation;

        private Advance(@NonNull WebAuthnStoreSnapshot snapshot, @NonNull Instant effectiveAt,
                WebAuthnStoreWrite.@Nullable Mutation mutation) {
            this.snapshot = snapshot;
            this.effectiveAt = effectiveAt;
            this.mutation = mutation;
        }

        boolean belongsTo(@NonNull WebAuthnStoreSnapshot candidate) { return this.snapshot.equals(candidate); }
        @NonNull Instant effectiveAt() { return this.effectiveAt; }
        WebAuthnStoreWrite.@Nullable Mutation mutation() { return this.mutation; }
        @Override public @NonNull String toString() { return "Advance{clock=<redacted>, no proof}"; }
    }
}
