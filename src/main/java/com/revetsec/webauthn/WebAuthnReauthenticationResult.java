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

package com.revetsec.webauthn;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/** Library-created reauthentication completion; only Succeeded carries a verified identity.
 * @since 1.0.0 */
@Immutable
public abstract sealed class WebAuthnReauthenticationResult permits WebAuthnReauthenticationResult.Succeeded,
        WebAuthnReauthenticationResult.Rejected, WebAuthnReauthenticationResult.Unavailable,
        WebAuthnReauthenticationResult.Indeterminate, WebAuthnReauthenticationResult.ReconciliationRequired {
    private static final @NonNull Unavailable UNAVAILABLE = new Unavailable();
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();
    private static final @NonNull ReconciliationRequired RECONCILIATION_REQUIRED = new ReconciliationRequired();
    WebAuthnReauthenticationResult() { }
    static @NonNull WebAuthnReauthenticationResult succeeded(@NonNull WebAuthnReauthentication reauthentication) {
        return new Succeeded(reauthentication);
    }
    static @NonNull WebAuthnReauthenticationResult rejected(@NonNull WebAuthnRejectionReason reason) {
        return new Rejected(reason);
    }
    static @NonNull WebAuthnReauthenticationResult unavailable() { return UNAVAILABLE; }
    static @NonNull WebAuthnReauthenticationResult indeterminate() { return INDETERMINATE; }
    static @NonNull WebAuthnReauthenticationResult reconciliationRequired() { return RECONCILIATION_REQUIRED; }
    /** Redacts all identity and browser data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "WebAuthnReauthenticationResult{<redacted>}"; }

    /** Confirmed stored-key reauthentication.
     * @since 1.0.0 */
    @Immutable public static final class Succeeded extends WebAuthnReauthenticationResult {
        private final @NonNull WebAuthnReauthentication reauthentication;
        private Succeeded(@NonNull WebAuthnReauthentication reauthentication) {
            this.reauthentication = requireNonNull(reauthentication);
        }
        /** Returns the verified reauthentication.
         * @return reauthentication
         * @since 1.0.0 */
        public @NonNull WebAuthnReauthentication getReauthentication() { return this.reauthentication; }
    }
    /** Fixed validation or policy rejection without an identity.
     * @since 1.0.0 */
    @Immutable public static final class Rejected extends WebAuthnReauthenticationResult {
        private final @NonNull WebAuthnRejectionReason reason;
        private Rejected(@NonNull WebAuthnRejectionReason reason) { this.reason = requireNonNull(reason); }
        /** Returns a fixed reason.
         * @return rejection reason
         * @since 1.0.0 */
        public @NonNull WebAuthnRejectionReason getReason() { return this.reason; }
    }
    /** Storage or admission was unavailable.
     * @since 1.0.0 */
    @Immutable public static final class Unavailable extends WebAuthnReauthenticationResult {
        private Unavailable() { }
    }
    /** A write may have occurred; reconcile before retry.
     * @since 1.0.0 */
    @Immutable public static final class Indeterminate extends WebAuthnReauthenticationResult {
        private Indeterminate() { }
    }
    /** The requested transition committed, but normal output could not be admitted.
     * Reconcile through an authorized fresh operation before deciding what to do next.
     * @since 1.0.0 */
    @Immutable public static final class ReconciliationRequired extends WebAuthnReauthenticationResult {
        private ReconciliationRequired() { }
    }

}
