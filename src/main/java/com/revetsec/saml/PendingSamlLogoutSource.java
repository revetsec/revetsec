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
import com.revetsec.internal.crypto.UnsealException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * Browser-bound source of one SP-initiated pending logout. The caller clears the cookie on
 * completion; an atomic store supplies single use across callbacks and nodes.
 *
 * @since 1.0.0
 */
@Immutable
public final class PendingSamlLogoutSource {
    private final @Nullable String sealedForm;
    private final @Nullable PendingSamlAuthenticationStore store;
    private final @Nullable String browserBinding;
    private final @NonNull StateSealer sealer;
    private final @NonNull String context;

    private PendingSamlLogoutSource(@Nullable String sealedForm,
            @Nullable PendingSamlAuthenticationStore store, @Nullable String browserBinding,
            @NonNull StateSealer sealer, @NonNull String context) {
        this.sealedForm = sealedForm;
        this.store = store;
        this.browserBinding = browserBinding;
        this.sealer = sealer;
        this.context = context;
    }

    /**
     * Selects a sealed browser cookie.
     *
     * @param sealedForm received cookie value
     * @param sealer active and verification keys
     * @param context exact cookie namespace
     * @return pending source
     * @since 1.0.0
     */
    public static @NonNull PendingSamlLogoutSource fromSealedForm(@NonNull String sealedForm,
            @NonNull StateSealer sealer, @NonNull String context) {
        return new PendingSamlLogoutSource(Objects.requireNonNull(sealedForm), null, null,
                Objects.requireNonNull(sealer), Objects.requireNonNull(context));
    }

    /**
     * Selects an atomic pending store and browser binding.
     *
     * @param store atomic store
     * @param browserBinding browser-specific secret
     * @param sealer active and verification keys
     * @param context same namespace used when saving
     * @return pending source
     * @since 1.0.0
     */
    public static @NonNull PendingSamlLogoutSource fromStore(@NonNull PendingSamlAuthenticationStore store,
            @NonNull String browserBinding, @NonNull StateSealer sealer, @NonNull String context) {
        SamlPendingBinding.context(Objects.requireNonNull(context) + "|logout",
                Objects.requireNonNull(browserBinding));
        return new PendingSamlLogoutSource(null, Objects.requireNonNull(store), browserBinding,
                Objects.requireNonNull(sealer), context);
    }

    @NonNull Resolution resolve(@NonNull Clock clock, @Nullable String relay, @NonNull Duration budget) {
        String record = sealedForm;
        String sealContext = context;
        if (store != null) {
            if (relay == null || relay.isEmpty()) return Rejected.INSTANCE;
            SamlPendingConsumeResult consumed;
            long started = System.nanoTime();
            try { consumed = store.consume(Objects.requireNonNull(browserBinding), relay, budget); }
            catch (RuntimeException exception) { return Indeterminate.INSTANCE; }
            if (consumed == null || System.nanoTime() - started >= budget.toNanos())
                return Indeterminate.INSTANCE;
            if (consumed instanceof SamlPendingConsumeResult.Missing) return Rejected.INSTANCE;
            if (consumed instanceof SamlPendingConsumeResult.Unavailable) return Unavailable.INSTANCE;
            if (consumed instanceof SamlPendingConsumeResult.Indeterminate) return Indeterminate.INSTANCE;
            record = ((SamlPendingConsumeResult.Consumed) consumed).getSealedRecord();
            sealContext = SamlPendingBinding.context(context + "|logout",
                    Objects.requireNonNull(browserBinding));
        }
        try {
            String opened = SealedStateAccess.get().unseal(sealer, SealedStateType.PENDING_SAML_LOGOUT,
                    Objects.requireNonNull(record), sealContext, clock);
            PendingSamlAuthentication pending = PendingSamlAuthenticationCodec.decode(opened);
            return pending == null ? Rejected.INSTANCE : new Resolved(pending);
        } catch (UnsealException exception) { return Rejected.INSTANCE; }
        catch (RuntimeException exception) { return Unavailable.INSTANCE; }
    }

    /**
     * Redacts state and store details.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "PendingSamlLogoutSource{<redacted>}"; }
    sealed interface Resolution permits Resolved, Rejected, Unavailable, Indeterminate { }
    record Resolved(@NonNull PendingSamlAuthentication pending) implements Resolution { }
    enum Rejected implements Resolution { INSTANCE }
    enum Unavailable implements Resolution { INSTANCE }
    enum Indeterminate implements Resolution { INSTANCE }
}
