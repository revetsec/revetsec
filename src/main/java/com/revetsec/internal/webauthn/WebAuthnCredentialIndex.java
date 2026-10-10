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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Bounded account credential index for enrollment exclusion and listing. This lists active IDs;
 * removal must leave a revoked credential tombstone at the credential key so an ID is never
 * reassigned. Index changes, credential changes and account fence predicates share one commit.
 */
@Immutable
final class WebAuthnCredentialIndex {
    static final int MAXIMUM_CREDENTIALS = 64;
    private static final int VERSION = 1;
    private static final int MAXIMUM_PAYLOAD_BYTES = 3 + 64 + MAXIMUM_CREDENTIALS * (2 + 1_023);
    private static final @NonNull Instant PERMANENT = Instant.ofEpochSecond(Instant.MAX.getEpochSecond());

    private final @NonNull String namespace;
    private final @NonNull String relyingPartyId;
    private final @NonNull WebAuthnRecordCodec records;

    WebAuthnCredentialIndex(@NonNull String namespace, @NonNull String relyingPartyId,
            @NonNull WebAuthnRecordCodec records) {
        WebAuthnStoreKey.forAccountCredentialIndex(requireNonNull(namespace),
                requireNonNull(relyingPartyId), new byte[] {1});
        this.namespace = namespace;
        this.relyingPartyId = relyingPartyId;
        this.records = requireNonNull(records);
    }

    @NonNull State empty(byte @NonNull [] userHandle) {
        return new State(userHandle, List.of());
    }

    @NonNull Encoded encode(@NonNull State state) {
        requireNonNull(state);
        byte[] handle = state.userHandle();
        WebAuthnStoreKey key = WebAuthnStoreKey.forAccountCredentialIndex(
                this.namespace, this.relyingPartyId, handle);
        List<byte[]> ids = state.credentialIds();
        int length = 3 + handle.length;
        for (byte[] id : ids) length += 2 + id.length;
        byte[] payload = new byte[length];
        try {
            ByteBuffer writer = ByteBuffer.wrap(payload);
            writer.put((byte) VERSION).put((byte) handle.length).put((byte) ids.size()).put(handle);
            for (byte[] id : ids) writer.putShort((short) id.length).put(id);
            return new Encoded(key, this.records.seal(key, payload, PERMANENT));
        } finally {
            Arrays.fill(handle, (byte) 0);
            for (byte[] id : ids) Arrays.fill(id, (byte) 0);
            Arrays.fill(payload, (byte) 0);
        }
    }

    @NonNull State decode(@NonNull WebAuthnStoreKey key, byte @NonNull [] sealedBytes,
            @NonNull Clock clock) throws WebAuthnRecordException {
        requireNonNull(key);
        requireNonNull(sealedBytes);
        requireNonNull(clock);
        if (key.getKind() != WebAuthnStoreKey.Kind.ACCOUNT_CREDENTIAL_INDEX)
            throw new WebAuthnRecordException();
        byte[] payload = this.records.open(key, sealedBytes, clock);
        try {
            if (payload.length < 4 || payload.length > MAXIMUM_PAYLOAD_BYTES || payload[0] != VERSION)
                throw new WebAuthnRecordException();
            ByteBuffer reader = ByteBuffer.wrap(payload);
            reader.get();
            int handleLength = reader.get() & 0xff;
            int count = reader.get() & 0xff;
            if (handleLength < 1 || handleLength > 64 || count > MAXIMUM_CREDENTIALS
                    || reader.remaining() < handleLength + count * 3)
                throw new WebAuthnRecordException();
            byte[] handle = new byte[handleLength];
            reader.get(handle);
            List<byte[]> ids = new ArrayList<>(count);
            try {
                byte[] previous = null;
                for (int index = 0; index < count; index++) {
                    if (reader.remaining() < 2) throw new WebAuthnRecordException();
                    int idLength = Short.toUnsignedInt(reader.getShort());
                    if (idLength < 1 || idLength > 1_023 || reader.remaining() < idLength)
                        throw new WebAuthnRecordException();
                    byte[] id = new byte[idLength];
                    reader.get(id);
                    if (previous != null && Arrays.compareUnsigned(previous, id) >= 0)
                        throw new WebAuthnRecordException();
                    ids.add(id);
                    previous = id;
                }
                if (reader.hasRemaining() || !key.equals(WebAuthnStoreKey.forAccountCredentialIndex(
                        this.namespace, this.relyingPartyId, handle)))
                    throw new WebAuthnRecordException();
                return new State(handle, ids);
            } finally {
                Arrays.fill(handle, (byte) 0);
                for (byte[] id : ids) Arrays.fill(id, (byte) 0);
            }
        } catch (IllegalArgumentException failure) {
            throw new WebAuthnRecordException();
        } finally { Arrays.fill(payload, (byte) 0); }
    }

    @Immutable
    static final class State {
        private final byte @NonNull [] userHandle;
        private final byte @NonNull [][] credentialIds;

        private State(byte @NonNull [] userHandle, @NonNull List<byte @NonNull []> ids) {
            requireNonNull(userHandle);
            if (userHandle.length < 1 || userHandle.length > 64 || ids.size() > MAXIMUM_CREDENTIALS)
                throw new IllegalArgumentException("Invalid WebAuthn credential index");
            this.userHandle = userHandle.clone();
            this.credentialIds = new byte[ids.size()][];
            byte[] previous = null;
            for (int index = 0; index < ids.size(); index++) {
                byte[] id = requireNonNull(ids.get(index));
                if (id.length < 1 || id.length > 1_023
                        || previous != null && Arrays.compareUnsigned(previous, id) >= 0)
                    throw new IllegalArgumentException("Invalid WebAuthn credential index");
                this.credentialIds[index] = id.clone();
                previous = id;
            }
        }

        byte @NonNull [] userHandle() { return this.userHandle.clone(); }
        @NonNull List<byte @NonNull []> credentialIds() {
            List<byte[]> copy = new ArrayList<>(this.credentialIds.length);
            for (byte[] id : this.credentialIds) copy.add(id.clone());
            return List.copyOf(copy);
        }
        int size() { return this.credentialIds.length; }
        boolean contains(byte @NonNull [] id) {
            requireNonNull(id);
            for (byte[] candidate : this.credentialIds)
                if (Arrays.equals(candidate, id)) return true;
            return false;
        }
        @NonNull State withAdded(byte @NonNull [] id) {
            requireNonNull(id);
            if (this.credentialIds.length == MAXIMUM_CREDENTIALS || id.length < 1 || id.length > 1_023
                    || contains(id)) throw new IllegalArgumentException("Cannot add credential ID");
            List<byte[]> ids = credentialIds();
            ids = new ArrayList<>(ids);
            ids.add(id.clone());
            ids.sort(Arrays::compareUnsigned);
            return new State(this.userHandle, ids);
        }
        @NonNull State without(byte @NonNull [] id) {
            requireNonNull(id);
            if (!contains(id)) throw new IllegalArgumentException("Credential ID absent");
            List<byte[]> ids = new ArrayList<>(credentialIds());
            ids.removeIf(candidate -> Arrays.equals(candidate, id));
            return new State(this.userHandle, ids);
        }
        @Override public @NonNull String toString() { return "CredentialIndex{ids=<redacted>}"; }
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
        @Override public @NonNull String toString() { return "Encoded{index=<redacted>, no proof}"; }
    }
}
