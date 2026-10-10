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
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * Key-bound active/disabled account fence. Absence does not mean active. The application must
 * coordinate account disable and reopening with this authoritative versioned record; the store
 * version is the race predicate, and the external recovery marker handles authentic rollback.
 */
@Immutable
final class WebAuthnAccountFence {
    private static final int VERSION = 1;
    private static final @NonNull Instant PERMANENT = Instant.ofEpochSecond(Instant.MAX.getEpochSecond());

    private final @NonNull String namespace;
    private final @NonNull String relyingPartyId;
    private final @NonNull WebAuthnRecordCodec records;

    WebAuthnAccountFence(@NonNull String namespace, @NonNull String relyingPartyId,
            @NonNull WebAuthnRecordCodec records) {
        WebAuthnStoreKey.forAccountFence(requireNonNull(namespace), requireNonNull(relyingPartyId),
                new byte[] {1});
        this.namespace = namespace;
        this.relyingPartyId = relyingPartyId;
        this.records = requireNonNull(records);
    }

    @NonNull Encoded encode(byte @NonNull [] userHandle, boolean active) {
        requireNonNull(userHandle);
        byte[] handle = userHandle.clone();
        try {
            WebAuthnStoreKey key = WebAuthnStoreKey.forAccountFence(
                    this.namespace, this.relyingPartyId, handle);
            byte[] payload = ByteBuffer.allocate(3 + handle.length)
                    .put((byte) VERSION).put((byte) (active ? 1 : 0))
                    .put((byte) handle.length).put(handle).array();
            try { return new Encoded(key, this.records.seal(key, payload, PERMANENT)); }
            finally { Arrays.fill(payload, (byte) 0); }
        } finally { Arrays.fill(handle, (byte) 0); }
    }

    @NonNull State decode(@NonNull WebAuthnStoreKey key, byte @NonNull [] sealedBytes,
            @NonNull Clock clock) throws WebAuthnRecordException {
        requireNonNull(key);
        requireNonNull(sealedBytes);
        requireNonNull(clock);
        if (key.getKind() != WebAuthnStoreKey.Kind.ACCOUNT_FENCE)
            throw new WebAuthnRecordException();
        byte[] payload = this.records.open(key, sealedBytes, clock);
        try {
            if (payload.length < 4 || payload.length > 67 || payload[0] != VERSION
                    || payload[1] < 0 || payload[1] > 1 || (payload[2] & 0xff) != payload.length - 3)
                throw new WebAuthnRecordException();
            byte[] handle = Arrays.copyOfRange(payload, 3, payload.length);
            try {
                if (!key.equals(WebAuthnStoreKey.forAccountFence(this.namespace, this.relyingPartyId, handle)))
                    throw new WebAuthnRecordException();
                return new State(handle, payload[1] == 1);
            } finally { Arrays.fill(handle, (byte) 0); }
        } catch (IllegalArgumentException failure) {
            throw new WebAuthnRecordException();
        } finally { Arrays.fill(payload, (byte) 0); }
    }

    @Immutable
    static final class State {
        private final byte @NonNull [] userHandle;
        private final boolean active;
        private State(byte @NonNull [] userHandle, boolean active) {
            this.userHandle = userHandle.clone();
            this.active = active;
        }
        byte @NonNull [] userHandle() { return this.userHandle.clone(); }
        boolean isActive() { return this.active; }
        @Override public @NonNull String toString() { return "AccountFence{state=<redacted>}"; }
    }

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
        @Override public @NonNull String toString() { return "Encoded{account=<redacted>, no proof}"; }
    }
}
