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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * Key-bound credential payload. Active version-one records recheck their COSE key and state;
 * compact version-two tombstones retain ID ownership indefinitely without the public key.
 * Neither authentic bytes nor a reconstructed active record are an assertion proof.
 */
@Immutable
final class WebAuthnCredentialRecordCodec {
    private static final int ACTIVE_VERSION = 1;
    private static final int ACTIVE_HEADER_BYTES = 13;
    private static final int REVOKED_VERSION = 2;
    private static final int REVOKED_HEADER_BYTES = 4;
    private static final @NonNull Instant PERMANENT = Instant.ofEpochSecond(Instant.MAX.getEpochSecond());

    private final @NonNull String namespace;
    private final @NonNull String relyingPartyId;
    private final @NonNull WebAuthnRecordCodec records;

    WebAuthnCredentialRecordCodec(@NonNull String namespace, @NonNull String relyingPartyId,
            @NonNull WebAuthnRecordCodec records) {
        requireNonNull(namespace);
        requireNonNull(relyingPartyId);
        WebAuthnStoreKey.forCredential(namespace, relyingPartyId, new byte[] {1});
        this.namespace = namespace;
        this.relyingPartyId = relyingPartyId;
        this.records = requireNonNull(records);
    }

    @NonNull Encoded encode(@NonNull WebAuthnCredentialState state) {
        requireNonNull(state);
        byte[] id = state.credentialId();
        byte[] handle = state.userHandle();
        byte[] publicKey = state.keyCbor();
        byte[] payload = new byte[ACTIVE_HEADER_BYTES + id.length + handle.length + publicKey.length];
        try {
            ByteBuffer writer = ByteBuffer.wrap(payload);
            writer.put((byte) ACTIVE_VERSION);
            writer.putShort((short) state.algorithm());
            writer.putInt((int) state.counter());
            int flags = (state.backupEligible() ? 1 : 0) | (state.backedUp() ? 2 : 0);
            writer.put((byte) flags);
            writer.putShort((short) id.length);
            writer.put((byte) handle.length);
            writer.putShort((short) publicKey.length);
            writer.put(id).put(handle).put(publicKey);
            WebAuthnStoreKey key = WebAuthnStoreKey.forCredential(this.namespace, this.relyingPartyId, id);
            return new Encoded(key, this.records.seal(key, payload, PERMANENT));
        } finally {
            Arrays.fill(id, (byte) 0);
            Arrays.fill(handle, (byte) 0);
            Arrays.fill(publicKey, (byte) 0);
            Arrays.fill(payload, (byte) 0);
        }
    }

    @NonNull Encoded encodeRevoked(byte @NonNull [] credentialId, byte @NonNull [] userHandle) {
        requireNonNull(credentialId);
        requireNonNull(userHandle);
        byte[] id = credentialId.clone();
        byte[] handle = userHandle.clone();
        try {
            WebAuthnStoreKey key = WebAuthnStoreKey.forCredential(this.namespace, this.relyingPartyId, id);
            if (handle.length < 1 || handle.length > 64)
                throw new IllegalArgumentException("Invalid WebAuthn account handle");
            byte[] payload = ByteBuffer.allocate(REVOKED_HEADER_BYTES + id.length + handle.length)
                    .put((byte) REVOKED_VERSION).putShort((short) id.length)
                    .put((byte) handle.length).put(id).put(handle).array();
            try { return new Encoded(key, this.records.seal(key, payload, PERMANENT)); }
            finally { Arrays.fill(payload, (byte) 0); }
        } finally {
            Arrays.fill(id, (byte) 0);
            Arrays.fill(handle, (byte) 0);
        }
    }

    @NonNull WebAuthnCredentialState decode(@NonNull WebAuthnStoreKey key,
            byte @NonNull [] sealedBytes, @NonNull Clock clock) throws WebAuthnRecordException {
        Decoded decoded = decodeRecord(key, sealedBytes, clock);
        WebAuthnCredentialState active = decoded.activeState();
        if (active == null) throw new WebAuthnRecordException();
        return active;
    }

    @NonNull Decoded decodeRecord(@NonNull WebAuthnStoreKey key,
            byte @NonNull [] sealedBytes, @NonNull Clock clock) throws WebAuthnRecordException {
        requireNonNull(key);
        requireNonNull(sealedBytes);
        requireNonNull(clock);
        if (key.getKind() != WebAuthnStoreKey.Kind.CREDENTIAL)
            throw new WebAuthnRecordException();
        byte[] payload = this.records.open(key, sealedBytes, clock);
        try {
            if (payload.length < 1) throw new WebAuthnRecordException();
            if ((payload[0] & 0xff) == REVOKED_VERSION) return decodeRevoked(key, payload);
            if (payload.length < ACTIVE_HEADER_BYTES) throw new WebAuthnRecordException();
            ByteBuffer reader = ByteBuffer.wrap(payload);
            int version = reader.get() & 0xff;
            int algorithm = reader.getShort();
            long counter = Integer.toUnsignedLong(reader.getInt());
            int flags = reader.get() & 0xff;
            int idLength = Short.toUnsignedInt(reader.getShort());
            int handleLength = reader.get() & 0xff;
            int keyLength = Short.toUnsignedInt(reader.getShort());
            if (version != ACTIVE_VERSION || (flags & ~3) != 0 || idLength < 1 || idLength > 1_023
                    || handleLength < 1 || handleLength > 64 || keyLength < 1 || keyLength > 1_024
                    || idLength + handleLength + keyLength != reader.remaining())
                throw new WebAuthnRecordException();
            byte[] id = new byte[idLength];
            byte[] handle = new byte[handleLength];
            byte[] publicKey = new byte[keyLength];
            try {
                reader.get(id).get(handle).get(publicKey);
                WebAuthnStoreKey encodedKey = WebAuthnStoreKey.forCredential(this.namespace, this.relyingPartyId, id);
                if (!key.equals(encodedKey)) throw new WebAuthnRecordException();
                return Decoded.active(WebAuthnCredentialState.checked(id, handle, publicKey,
                        algorithm, counter, (flags & 1) != 0, (flags & 2) != 0));
            } finally {
                Arrays.fill(id, (byte) 0);
                Arrays.fill(handle, (byte) 0);
                Arrays.fill(publicKey, (byte) 0);
            }
        } catch (WebAuthnCborException | IllegalArgumentException failure) {
            throw new WebAuthnRecordException();
        } finally {
            Arrays.fill(payload, (byte) 0);
        }
    }

    private @NonNull Decoded decodeRevoked(@NonNull WebAuthnStoreKey key,
            byte @NonNull [] payload) throws WebAuthnRecordException {
        if (payload.length < REVOKED_HEADER_BYTES + 2) throw new WebAuthnRecordException();
        ByteBuffer reader = ByteBuffer.wrap(payload);
        reader.get();
        int idLength = Short.toUnsignedInt(reader.getShort());
        int handleLength = reader.get() & 0xff;
        if (idLength < 1 || idLength > 1_023 || handleLength < 1 || handleLength > 64
                || idLength + handleLength != reader.remaining()) throw new WebAuthnRecordException();
        byte[] id = new byte[idLength];
        byte[] handle = new byte[handleLength];
        try {
            reader.get(id).get(handle);
            if (!key.equals(WebAuthnStoreKey.forCredential(this.namespace, this.relyingPartyId, id)))
                throw new WebAuthnRecordException();
            return Decoded.revoked(id, handle);
        } finally {
            Arrays.fill(id, (byte) 0);
            Arrays.fill(handle, (byte) 0);
        }
    }

    /** Checked active state or a permanent revoked-ID ownership marker; no proof. */
    @Immutable
    static final class Decoded {
        private final byte @NonNull [] credentialId;
        private final byte @NonNull [] userHandle;
        private final @Nullable WebAuthnCredentialState activeState;

        private Decoded(byte @NonNull [] credentialId, byte @NonNull [] userHandle,
                @Nullable WebAuthnCredentialState activeState) {
            this.credentialId = credentialId.clone();
            this.userHandle = userHandle.clone();
            this.activeState = activeState;
        }

        private static @NonNull Decoded active(@NonNull WebAuthnCredentialState state) {
            return new Decoded(state.credentialId(), state.userHandle(), state);
        }
        private static @NonNull Decoded revoked(byte @NonNull [] id, byte @NonNull [] handle) {
            return new Decoded(id, handle, null);
        }
        byte @NonNull [] credentialId() { return this.credentialId.clone(); }
        byte @NonNull [] userHandle() { return this.userHandle.clone(); }
        boolean isRevoked() { return this.activeState == null; }
        @Nullable WebAuthnCredentialState activeState() { return this.activeState; }
        @Override public @NonNull String toString() { return "Decoded{credential=<redacted>, no proof}"; }
    }

    /** A key and sealed bytes prepared for one version-conditioned store mutation; no proof. */
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

        @Override public @NonNull String toString() { return "Encoded{credential=<redacted>, no proof}"; }
    }
}
