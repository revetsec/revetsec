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

import com.revetsec.StoreTimeObservation;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static java.util.Objects.requireNonNull;

/** Authenticated immutable authority binding and minimum; ordinary work never advances the root. */
@Immutable
final class WebAuthnNamespaceClock {
    private final @NonNull WebAuthnStoreKey key;
    private final @NonNull WebAuthnRecordCodec records;

    WebAuthnNamespaceClock(@NonNull String namespace, @NonNull String relyingPartyId,
            @NonNull WebAuthnRecordCodec records) {
        this.key = WebAuthnStoreKey.forNamespaceClock(namespace, relyingPartyId);
        this.records = requireNonNull(records);
    }

    @NonNull WebAuthnStoreKey key() { return this.key; }

    byte @NonNull [] encode(@NonNull String authorityId, @NonNull Instant minimum) {
        return this.records.sealNamespace(this.key, authorityId, minimum);
    }

    @NonNull Instant decode(@NonNull WebAuthnStoreKey addressedKey, byte @NonNull [] sealedBytes,
            @NonNull Clock authorityClock) throws WebAuthnRecordException {
        if (!this.key.equals(requireNonNull(addressedKey))) throw new WebAuthnRecordException();
        try (var decoded = this.records.openAdmittedRecord(addressedKey, sealedBytes, authorityClock)) {
            return decoded.floor();
        }
    }

    /** The retained arguments are internal fixture inputs; healthy snapshot time is authoritative. */
    @NonNull Advance prepare(@NonNull WebAuthnStoreSnapshot snapshot, @NonNull Instant ignoredWorkerTime,
            @NonNull Clock ignoredWorkerClock) throws WebAuthnRecordException {
        requireNonNull(snapshot); requireNonNull(ignoredWorkerTime); requireNonNull(ignoredWorkerClock);
        if (!(snapshot.getTimeObservation() instanceof StoreTimeObservation.Healthy observation))
            throw new WebAuthnRecordException();
        Instant now = observation.getObservedAt();
        String authority = observation.getAdmission().getAuthorityId();
        WebAuthnStoreEntry entry = snapshot.getEntry(this.key);
        if (entry instanceof WebAuthnStoreEntry.Absent)
            return new Advance(snapshot, now, now, false,
                    WebAuthnStoreWrite.Mutation.insert(this.key, encode(authority, now)));
        if (!(entry instanceof WebAuthnStoreEntry.Present present)) throw new WebAuthnRecordException();
        try (var decoded = this.records.openAdmittedRecord(this.key, present.getSealedBytes(),
                Clock.fixed(now, ZoneOffset.UTC))) {
            if (!decoded.authorityId().orElseThrow().equals(authority)) throw new WebAuthnRecordException();
            return new Advance(snapshot, now, decoded.floor(), true, null);
        }
    }

    @Immutable
    static final class Advance {
        private final @NonNull WebAuthnStoreSnapshot snapshot;
        private final @NonNull Instant effectiveAt;
        private final @NonNull Instant minimum;
        private final boolean present;
        private final WebAuthnStoreWrite.@Nullable Mutation mutation;
        private Advance(@NonNull WebAuthnStoreSnapshot snapshot, @NonNull Instant effectiveAt,
                @NonNull Instant minimum, boolean present, WebAuthnStoreWrite.@Nullable Mutation mutation) {
            this.snapshot=snapshot;this.effectiveAt=effectiveAt;this.minimum=minimum;this.present=present;this.mutation=mutation;
        }
        boolean belongsTo(@NonNull WebAuthnStoreSnapshot candidate) { return this.snapshot.equals(candidate); }
        @NonNull Instant effectiveAt() { return this.effectiveAt; }
        @NonNull Instant minimum() { return this.minimum; }
        boolean present() { return this.present; }
        WebAuthnStoreWrite.@Nullable Mutation mutation() { return this.mutation; }
        @Override public @NonNull String toString() { return "Advance{clock=<redacted>, no proof}"; }
    }
}
