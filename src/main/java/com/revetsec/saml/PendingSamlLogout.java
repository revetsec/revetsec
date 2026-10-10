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
package com.revetsec.saml;

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Engine-created pending SP logout. Its separate seal type cannot be replayed as login state.
 *
 * @since 1.0.0
 */
@Immutable
public final class PendingSamlLogout {
    private final @NonNull PendingSamlAuthentication record;

    PendingSamlLogout(@NonNull PendingSamlAuthentication record) { this.record = record; }

    /**
     * Seals logout pending state for a browser-bound secure cookie.
     *
     * @param sealer active and verification keys
     * @param context application cookie namespace
     * @return sealed value
     * @since 1.0.0
     */
    public @NonNull String toSealedForm(@NonNull StateSealer sealer, @NonNull String context) {
        return SealedStateAccess.get().seal(Objects.requireNonNull(sealer),
                SealedStateType.PENDING_SAML_LOGOUT, PendingSamlAuthenticationCodec.encode(record),
                Objects.requireNonNull(context), record.expiresAt());
    }

    /**
     * Seals and saves logout pending state in an atomic browser-bound store.
     *
     * @param store atomic pending store
     * @param sealer active and verification keys
     * @param context application store namespace
     * @param browserBinding browser-specific secret
     * @param remaining positive operation budget
     * @return save outcome
     * @since 1.0.0
     */
    public @NonNull SamlPendingSaveResult saveToResult(@NonNull PendingSamlAuthenticationStore store,
            @NonNull StateSealer sealer, @NonNull String context, @NonNull String browserBinding,
            @NonNull Duration remaining) {
        Objects.requireNonNull(store);
        Objects.requireNonNull(sealer);
        Objects.requireNonNull(remaining);
        if (remaining.isZero() || remaining.isNegative()) return SamlPendingSaveResult.UNAVAILABLE;
        String bound = SamlPendingBinding.context(Objects.requireNonNull(context) + "|logout",
                Objects.requireNonNull(browserBinding));
        String sealed = toSealedForm(sealer, bound);
        long started = System.nanoTime();
        try {
            SamlPendingSaveResult result = store.save(browserBinding, record.relayState(), sealed,
                    record.expiresAt(), remaining);
            return result == null || System.nanoTime() - started >= remaining.toNanos()
                    ? SamlPendingSaveResult.INDETERMINATE : result;
        } catch (RuntimeException exception) { return SamlPendingSaveResult.INDETERMINATE; }
    }

    /**
     * Returns the generated logout request ID.
     *
     * @return request ID
     * @since 1.0.0
     */
    public @NonNull String getRequestId() { return record.requestId(); }
    /**
     * Returns the generated RelayState handle.
     *
     * @return handle
     * @since 1.0.0
     */
    public @NonNull String getRelayStateHandle() { return record.relayState(); }
    /**
     * Returns pending expiry.
     *
     * @return expiry
     * @since 1.0.0
     */
    public @NonNull Instant getExpiresAt() { return record.expiresAt(); }
    @NonNull PendingSamlAuthentication record() { return record; }
    /**
     * Redacts pending state.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "PendingSamlLogout{<redacted>}"; }
}
