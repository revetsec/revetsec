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
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Prepares a version-conditioned ceremony consumption from an authoritative snapshot. The caller
 * must add the credential and account mutations/predicates to the same store write and receive a
 * timely confirmed commit. This helper never commits and never creates verification proof.
 */
final class WebAuthnCeremonyConsumption {
    private WebAuthnCeremonyConsumption() { }

    static @NonNull Optional<@NonNull Prepared> prepare(@NonNull WebAuthnStoreSnapshot snapshot,
            @NonNull WebAuthnCeremonyRecordCodec codec, @NonNull WebAuthnStoreKey ceremonyKey,
            byte @NonNull [] expectedCeremonyId, byte @NonNull [] browserBinding,
            WebAuthnCeremonyState.@NonNull Kind expectedKind,
            WebAuthnNamespaceClock.@NonNull Advance namespaceTime, @NonNull Clock clock)
            throws WebAuthnRecordException {
        requireNonNull(snapshot);
        requireNonNull(codec);
        requireNonNull(ceremonyKey);
        requireNonNull(expectedCeremonyId);
        requireNonNull(browserBinding);
        requireNonNull(expectedKind);
        requireNonNull(namespaceTime);
        requireNonNull(clock);
        if (!namespaceTime.belongsTo(snapshot))
            throw new IllegalArgumentException("Namespace time belongs to another read");
        if (expectedCeremonyId.length != 32 || browserBinding.length != 32)
            throw new IllegalArgumentException("Invalid WebAuthn ceremony or browser binding");
        WebAuthnStoreEntry entry = snapshot.getEntry(ceremonyKey);
        if (!(entry instanceof WebAuthnStoreEntry.Present present)) return Optional.empty();
        Instant observedAt = namespaceTime.effectiveAt();
        WebAuthnCeremonyState pending = codec.decode(ceremonyKey, present.getSealedBytes(), clock);
        if (pending.kind() != expectedKind || !pending.isPendingAt(observedAt)
                || !pending.matchesBrowserBinding(browserBinding)
                || !java.security.MessageDigest.isEqual(pending.ceremonyId(), expectedCeremonyId))
            return Optional.empty();
        var consumed = codec.encode(pending.consume());
        return Optional.of(new Prepared(pending,
                WebAuthnStoreWrite.Mutation.replace(consumed.key(), consumed.sealedBytes())));
    }

    /** Candidate input and the required ceremony mutation, never a verified result. */
    @Immutable
    static final class Prepared {
        private final @NonNull WebAuthnCeremonyState pending;
        private final WebAuthnStoreWrite.@NonNull Mutation mutation;

        private Prepared(@NonNull WebAuthnCeremonyState pending,
                WebAuthnStoreWrite.@NonNull Mutation mutation) {
            this.pending = pending;
            this.mutation = mutation;
        }

        @NonNull WebAuthnCeremonyState pending() { return this.pending; }
        WebAuthnStoreWrite.@NonNull Mutation mutation() { return this.mutation; }
        @Override public @NonNull String toString() { return "Prepared{ceremony=<redacted>, no proof}"; }
    }
}
