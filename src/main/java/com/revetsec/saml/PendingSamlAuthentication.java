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
import java.time.Instant;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * An engine-created pending SAML login. Place its sealed form in a Secure, HttpOnly, SameSite=None
 * browser cookie for a cross-site POST ACS. A sealed cookie can be replayed in concurrent callbacks;
 * the assertion replay cache still prevents releasing the same assertion twice. An atomic pending
 * store is required when the application needs authoritative single consumption of the login itself.
 *
 * @since 1.0.0
 */
@Immutable
public final class PendingSamlAuthentication {
    private final @NonNull String spEntityId;
    private final @NonNull String requestId;
    private final @NonNull String relayState;
    private final @NonNull String connectionId;
    private final @NonNull String idpEntityId;
    private final @NonNull String acs;
    private final @NonNull Instant issuedAt;
    private final @NonNull Instant expiresAt;
    private final @NonNull SamlAuthenticationRequestOptions options;

    PendingSamlAuthentication(@NonNull String spEntityId, @NonNull String requestId,
            @NonNull String relayState, @NonNull String connectionId, @NonNull String idpEntityId,
            @NonNull String acs, @NonNull Instant issuedAt, @NonNull Instant expiresAt) {
        this(spEntityId, requestId, relayState, connectionId, idpEntityId, acs,
                issuedAt, expiresAt, SamlAuthenticationRequestOptions.builder().build());
    }

    PendingSamlAuthentication(@NonNull String spEntityId, @NonNull String requestId,
            @NonNull String relayState, @NonNull String connectionId, @NonNull String idpEntityId,
            @NonNull String acs, @NonNull Instant issuedAt, @NonNull Instant expiresAt,
            @NonNull SamlAuthenticationRequestOptions options) {
        this.spEntityId = Objects.requireNonNull(spEntityId);
        this.requestId = Objects.requireNonNull(requestId);
        this.relayState = Objects.requireNonNull(relayState);
        this.connectionId = Objects.requireNonNull(connectionId);
        this.idpEntityId = Objects.requireNonNull(idpEntityId);
        this.acs = Objects.requireNonNull(acs);
        this.issuedAt = Objects.requireNonNull(issuedAt);
        this.expiresAt = Objects.requireNonNull(expiresAt);
        this.options = Objects.requireNonNull(options);
    }

    /**
     * Seals this pending login under the SAML-specific type and exact application context.
     *
     * @param sealer active and verification sealing keys
     * @param context fixed application-selected cookie context
     * @return the sealed value for a browser-bound cookie
     * @since 1.0.0
     */
    public @NonNull String toSealedForm(@NonNull StateSealer sealer, @NonNull String context) {
        return SealedStateAccess.get().seal(Objects.requireNonNull(sealer), SealedStateType.PENDING_SAML,
                PendingSamlAuthenticationCodec.encode(this), Objects.requireNonNull(context), expiresAt);
    }

    /**
     * Seals and saves this login under a browser-bound context. A possibly completed save returns
     * INDETERMINATE; callers must not assume that retrying is safe.
     *
     * @param store atomic pending store
     * @param sealer active and verification sealing keys
     * @param context application-selected store namespace
     * @param browserBinding browser-specific secret
     * @param remaining positive operation budget
     * @return the storage outcome
     * @since 1.0.0
     */
    public @NonNull SamlPendingSaveResult saveToResult(@NonNull PendingSamlAuthenticationStore store,
            @NonNull StateSealer sealer, @NonNull String context, @NonNull String browserBinding,
            @NonNull Duration remaining) {
        Objects.requireNonNull(store);
        Objects.requireNonNull(sealer);
        Objects.requireNonNull(remaining);
        if (remaining.isZero() || remaining.isNegative()) return SamlPendingSaveResult.UNAVAILABLE;
        String bindingContext = SamlPendingBinding.context(Objects.requireNonNull(context),
                Objects.requireNonNull(browserBinding));
        String record = toSealedForm(sealer, bindingContext);
        long started = System.nanoTime();
        try {
            SamlPendingSaveResult result = store.save(browserBinding, relayState, record, expiresAt, remaining);
            if (result == null || System.nanoTime() - started >= remaining.toNanos())
                return SamlPendingSaveResult.INDETERMINATE;
            return result;
        } catch (RuntimeException exception) { return SamlPendingSaveResult.INDETERMINATE; }
    }

    /**
     * Returns the generated request ID.
     *
     * @return request ID
     * @since 1.0.0
     */
    public @NonNull String getRequestId() { return requestId; }
    /**
     * Returns the opaque RelayState handle.
     *
     * @return handle
     * @since 1.0.0
     */
    public @NonNull String getRelayStateHandle() { return relayState; }
    /**
     * Returns the expiration of this login attempt.
     *
     * @return expiry
     * @since 1.0.0
     */
    public @NonNull Instant getExpiresAt() { return expiresAt; }
    /**
     * Returns the app-owned hint sealed into this request, when supplied.
     * @return optional application data
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getApplicationData() { return options.getApplicationData(); }
    /**
     * Redacts the pending identifiers.
     *
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "PendingSamlAuthentication{<redacted>}"; }

    @NonNull String spEntityId() { return spEntityId; }
    @NonNull String requestId() { return requestId; }
    @NonNull String relayState() { return relayState; }
    @NonNull String connectionId() { return connectionId; }
    @NonNull String idpEntityId() { return idpEntityId; }
    @NonNull String acs() { return acs; }
    @NonNull Instant issuedAt() { return issuedAt; }
    @NonNull Instant expiresAt() { return expiresAt; }
    @NonNull SamlAuthenticationRequestOptions options() { return options; }
}
