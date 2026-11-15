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
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * Explicit admitted WAR2 normal-record operations over {@link WebAuthnRecordCodecV2}. Each chunk uses
 * {@link StateSealer} under a dedicated type label and a context binding the exact store key,
 * random envelope ID, chunk count, chunk size and position. Framing is checked before any crypto.
 * The codec authenticates bytes but does not validate a ceremony, credential or account fence.
 * Store versions and external recovery fencing still protect against live races and rollback.
 */
@ThreadSafe
final class WebAuthnRecordCodec {
    private final @NonNull WebAuthnRecordCodecV2 records;

    WebAuthnRecordCodec(@NonNull StateSealer sealer) {
        this(sealer, EntropySource.fromDefaults());
    }

    WebAuthnRecordCodec(@NonNull StateSealer sealer, @NonNull EntropySource entropy) {
        // The WAR2 codec refuses an unsupported sealer chunk capacity here, before any record operation.
        this.records = new WebAuthnRecordCodecV2(requireNonNull(sealer), requireNonNull(entropy));
    }

    /** Active normal WAR2 path; the caller supplies admitted entity time explicitly. */
    byte @NonNull [] sealEntity(@NonNull WebAuthnStoreKey key, byte @NonNull [] inner,
            @NonNull Instant expiresAt, @NonNull Instant floor) {
        byte[] payload;
        try { payload = WebAuthnRecordPayloadV2.entity(key, floor, inner); }
        catch (WebAuthnRecordException failure) { throw new IllegalArgumentException("Invalid WebAuthn payload"); }
        try { return this.records.seal(key, payload, expiresAt); }
        finally { Arrays.fill(payload, (byte) 0); }
    }

    byte @NonNull [] sealNamespace(@NonNull WebAuthnStoreKey key, @NonNull String authorityId,
            @NonNull Instant minimum) {
        byte[] payload = WebAuthnRecordPayloadV2.namespace(key, authorityId, minimum);
        try { return this.records.seal(key, payload, WebAuthnRecordPayloadV2.PERMANENT); }
        finally { Arrays.fill(payload, (byte) 0); }
    }

    WebAuthnRecordPayloadV2.@NonNull Decoded openAdmittedRecord(@NonNull WebAuthnStoreKey key,
            byte @NonNull [] sealedBytes, @NonNull Clock authorityClock) throws WebAuthnRecordException {
        Instant admitted = authorityClock.instant();
        if (admitted.getEpochSecond() < 0 || admitted.getEpochSecond() > 253402300799L)
            throw new WebAuthnRecordException();
        var decoded = this.records.openRecord(key, sealedBytes, authorityClock);
        if (decoded.floor().getEpochSecond() < 0 || decoded.floor().getEpochSecond() > 253402300799L
                || decoded.floor().isAfter(admitted)) { decoded.close(); throw new WebAuthnRecordException(); }
        return decoded;
    }

    byte @NonNull [] openAdmitted(@NonNull WebAuthnStoreKey key, byte @NonNull [] sealedBytes,
            @NonNull Clock authorityClock) throws WebAuthnRecordException {
        try (var decoded = openAdmittedRecord(key, sealedBytes, authorityClock)) { return decoded.innerPayload(); }
    }

    byte @NonNull [] resealAdmitted(@NonNull WebAuthnStoreKey key, byte @NonNull [] sealedBytes,
            @NonNull Clock authorityClock) throws WebAuthnRecordException {
        try (var decoded = openAdmittedRecord(key, sealedBytes, authorityClock)) {
            if (key.getKind() == WebAuthnStoreKey.Kind.NAMESPACE_CLOCK)
                return sealNamespace(key, decoded.authorityId().orElseThrow(), decoded.floor());
            byte[] inner = decoded.innerPayload();
            try { return sealEntity(key, inner, decoded.expiresAt(), decoded.floor()); }
            finally { Arrays.fill(inner, (byte) 0); }
        }
    }
}
