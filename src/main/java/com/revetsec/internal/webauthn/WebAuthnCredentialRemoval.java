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

import javax.annotation.concurrent.Immutable;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Prepares one authorized credential removal against a complete authoritative read. The caller
 * has already approved the account and must still commit this entire mutation set with the
 * snapshot predicates. A revoked credential remains at its unique ID key indefinitely.
 */
final class WebAuthnCredentialRemoval {
    private final @NonNull String namespace;
    private final @NonNull String relyingPartyId;
    private final @NonNull WebAuthnCredentialRecordCodec credentials;
    private final @NonNull WebAuthnCredentialIndex indexes;
    private final @NonNull WebAuthnAccountFence fences;
    private final @NonNull WebAuthnNamespaceClock namespaceClock;

    WebAuthnCredentialRemoval(@NonNull String namespace, @NonNull String relyingPartyId,
            @NonNull WebAuthnRecordCodec records) {
        this.namespace = requireNonNull(namespace);
        this.relyingPartyId = requireNonNull(relyingPartyId);
        requireNonNull(records);
        this.credentials = new WebAuthnCredentialRecordCodec(namespace, relyingPartyId, records);
        this.indexes = new WebAuthnCredentialIndex(namespace, relyingPartyId, records);
        this.fences = new WebAuthnAccountFence(namespace, relyingPartyId, records);
        this.namespaceClock = new WebAuthnNamespaceClock(namespace, relyingPartyId, records);
    }

    @NonNull SetOfKeys keys(byte @NonNull [] approvedUserHandle,
            byte @NonNull [] credentialId) {
        requireNonNull(approvedUserHandle);
        requireNonNull(credentialId);
        WebAuthnStoreKey credential = WebAuthnStoreKey.forCredential(
                this.namespace, this.relyingPartyId, credentialId);
        WebAuthnStoreKey index = WebAuthnStoreKey.forAccountCredentialIndex(
                this.namespace, this.relyingPartyId, approvedUserHandle);
        WebAuthnStoreKey fence = WebAuthnStoreKey.forAccountFence(
                this.namespace, this.relyingPartyId, approvedUserHandle);
        return new SetOfKeys(credential, index, fence, this.namespaceClock.key());
    }

    @NonNull Optional<@NonNull Prepared> prepare(@NonNull WebAuthnStoreSnapshot snapshot,
            byte @NonNull [] approvedUserHandle, byte @NonNull [] credentialId,
            @NonNull Clock clock) throws WebAuthnRecordException {
        requireNonNull(snapshot);
        requireNonNull(clock);
        SetOfKeys keys = keys(approvedUserHandle, credentialId);
        WebAuthnStoreEntry credentialEntry = snapshot.getEntry(keys.credential());
        WebAuthnStoreEntry indexEntry = snapshot.getEntry(keys.index());
        WebAuthnStoreEntry fenceEntry = snapshot.getEntry(keys.fence());
        WebAuthnNamespaceClock.Advance time = this.namespaceClock.prepare(snapshot, clock.instant(), clock);
        if (!(fenceEntry instanceof WebAuthnStoreEntry.Present presentFence)) {
            if (!(indexEntry instanceof WebAuthnStoreEntry.Absent)) throw new WebAuthnRecordException();
            return Optional.empty();
        }
        // Removal remains available after disabling an account so the app can retire its keys.
        this.fences.decode(keys.fence(), presentFence.getSealedBytes(), clock);

        WebAuthnCredentialIndex.State index = indexEntry instanceof WebAuthnStoreEntry.Present presentIndex
                ? this.indexes.decode(keys.index(), presentIndex.getSealedBytes(), clock) : null;
        WebAuthnCredentialRecordCodec.Decoded credential =
                credentialEntry instanceof WebAuthnStoreEntry.Present presentCredential
                ? this.credentials.decodeRecord(keys.credential(), presentCredential.getSealedBytes(), clock) : null;
        boolean owned = credential != null && MessageDigest.isEqual(
                credential.userHandle(), approvedUserHandle);
        if (index == null || !index.contains(credentialId)) {
            if (credential != null && !credential.isRevoked() && owned)
                throw new WebAuthnRecordException();
            return Optional.empty();
        }
        if (credential == null || credential.isRevoked() || !owned)
            throw new WebAuthnRecordException();

        var revoked = this.credentials.encodeRevoked(credentialId, approvedUserHandle);
        var updatedIndex = this.indexes.encode(index.without(credentialId));
        List<WebAuthnStoreWrite.Mutation> mutations = new ArrayList<>(3);
        mutations.add(WebAuthnStoreWrite.Mutation.replace(revoked.key(), revoked.sealedBytes()));
        mutations.add(WebAuthnStoreWrite.Mutation.replace(updatedIndex.key(), updatedIndex.sealedBytes()));
        if (time.mutation() != null) mutations.add(time.mutation());
        WebAuthnStoreWrite write = WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, mutations);
        return Optional.of(new Prepared(write));
    }

    /** The four keys whose exact observations must participate in the removal transaction. */
    @Immutable
    static final class SetOfKeys {
        private final @NonNull WebAuthnStoreKey credential;
        private final @NonNull WebAuthnStoreKey index;
        private final @NonNull WebAuthnStoreKey fence;
        private final @NonNull WebAuthnStoreKey clock;
        private SetOfKeys(@NonNull WebAuthnStoreKey credential, @NonNull WebAuthnStoreKey index,
                @NonNull WebAuthnStoreKey fence, @NonNull WebAuthnStoreKey clock) {
            this.credential = credential;
            this.index = index;
            this.fence = fence;
            this.clock = clock;
        }
        @NonNull WebAuthnStoreKey credential() { return this.credential; }
        @NonNull WebAuthnStoreKey index() { return this.index; }
        @NonNull WebAuthnStoreKey fence() { return this.fence; }
        @NonNull WebAuthnStoreKey clock() { return this.clock; }
        @NonNull Set<@NonNull WebAuthnStoreKey> all() {
            return Set.of(this.credential, this.index, this.fence, this.clock);
        }
    }

    /** Candidate atomic write only; the application must reconcile unknown commit outcomes. */
    @Immutable
    static final class Prepared {
        private final @NonNull WebAuthnStoreWrite write;
        private Prepared(@NonNull WebAuthnStoreWrite write) { this.write = write; }
        @NonNull WebAuthnStoreWrite write() { return this.write; }
        @Override public @NonNull String toString() { return "Prepared{removal=<redacted>, no proof}"; }
    }
}
