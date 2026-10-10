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
 * A sealed pending login obtained from the initiating browser's cookie. The application must bind
 * the cookie to that browser and clear it after completion. A backend with atomic single-use
 * consumption can be supplied through the separate pending-store source.
 *
 * @since 1.0.0
 */
@Immutable
public final class PendingSamlAuthenticationSource {
    private final @Nullable String sealedForm;
    private final @NonNull StateSealer sealer;
    private final @NonNull String context;
    private final @Nullable PendingSamlAuthenticationStore store;
    private final @Nullable String browserBinding;

    private PendingSamlAuthenticationSource(@Nullable String sealedForm, @NonNull StateSealer sealer,
            @NonNull String context, @Nullable PendingSamlAuthenticationStore store,
            @Nullable String browserBinding) {
        this.sealedForm = sealedForm;
        this.sealer = sealer;
        this.context = context;
        this.store = store;
        this.browserBinding = browserBinding;
    }

    /**
     * Selects the sealed state received from the initiating browser.
     *
     * @param sealedForm value read from that browser's secure cookie
     * @param sealer active and verification sealing keys
     * @param context exact application-selected cookie context
     * @return the pending source
     * @since 1.0.0
     */
    public static @NonNull PendingSamlAuthenticationSource fromSealedForm(@NonNull String sealedForm,
            @NonNull StateSealer sealer, @NonNull String context) {
        return new PendingSamlAuthenticationSource(Objects.requireNonNull(sealedForm),
                Objects.requireNonNull(sealer), Objects.requireNonNull(context), null, null);
    }

    /**
     * Selects an atomic pending store for this browser. Completion consumes using the received
     * RelayState handle before parsing XML.
     *
     * @param store atomic pending store
     * @param browserBinding browser-specific secret
     * @param sealer active and verification sealing keys
     * @param context same application-selected namespace used when saving
     * @return the pending source
     * @since 1.0.0
     */
    public static @NonNull PendingSamlAuthenticationSource fromStore(@NonNull PendingSamlAuthenticationStore store,
            @NonNull String browserBinding, @NonNull StateSealer sealer, @NonNull String context) {
        SamlPendingBinding.context(Objects.requireNonNull(context), Objects.requireNonNull(browserBinding));
        return new PendingSamlAuthenticationSource(null, Objects.requireNonNull(sealer), context,
                Objects.requireNonNull(store), browserBinding);
    }

    @NonNull Resolution resolve(@NonNull Clock clock, @Nullable String relayState, @NonNull Duration budget) {
        String record = sealedForm;
        String sealContext = context;
        if (store != null) {
            if (relayState == null || relayState.isEmpty()) return Rejected.INSTANCE;
            SamlPendingConsumeResult consumed;
            long started = System.nanoTime();
            try { consumed = store.consume(Objects.requireNonNull(browserBinding), relayState, budget); }
            catch (RuntimeException exception) { return Indeterminate.INSTANCE; }
            if (consumed == null || System.nanoTime() - started >= budget.toNanos()) return Indeterminate.INSTANCE;
            if (consumed instanceof SamlPendingConsumeResult.Missing) return Rejected.INSTANCE;
            if (consumed instanceof SamlPendingConsumeResult.Unavailable) return Unavailable.INSTANCE;
            if (consumed instanceof SamlPendingConsumeResult.Indeterminate) return Indeterminate.INSTANCE;
            record = ((SamlPendingConsumeResult.Consumed) consumed).getSealedRecord();
            sealContext = SamlPendingBinding.context(context, Objects.requireNonNull(browserBinding));
        }
        try {
            String opened = SealedStateAccess.get().unseal(sealer, SealedStateType.PENDING_SAML,
                    Objects.requireNonNull(record), sealContext, clock);
            PendingSamlAuthentication pending = PendingSamlAuthenticationCodec.decode(opened);
            return pending == null ? Rejected.INSTANCE : new Resolved(pending);
        } catch (UnsealException exception) {
            return Rejected.INSTANCE;
        } catch (RuntimeException exception) {
            return Unavailable.INSTANCE;
        }
    }

    /** Redacts the sealed state. @since 1.0.0 */
    @Override public @NonNull String toString() { return "PendingSamlAuthenticationSource{<redacted>}"; }

    sealed interface Resolution permits Resolved, Rejected, Unavailable, Indeterminate { }
    record Resolved(@NonNull PendingSamlAuthentication pending) implements Resolution { }
    enum Rejected implements Resolution { INSTANCE }
    enum Unavailable implements Resolution { INSTANCE }
    enum Indeterminate implements Resolution { INSTANCE }
}
