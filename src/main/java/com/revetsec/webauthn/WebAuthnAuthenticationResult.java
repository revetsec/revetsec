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

/** Library-created authentication completion; only Succeeded carries a verified identity.
 * @since 1.0.0 */
@Immutable
public abstract sealed class WebAuthnAuthenticationResult permits WebAuthnAuthenticationResult.Succeeded,
        WebAuthnAuthenticationResult.Rejected, WebAuthnAuthenticationResult.Unavailable,
        WebAuthnAuthenticationResult.Indeterminate {
    private static final @NonNull Unavailable UNAVAILABLE = new Unavailable();
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();
    WebAuthnAuthenticationResult() { }
    static @NonNull WebAuthnAuthenticationResult succeeded(@NonNull WebAuthnAuthentication authentication) {
        return new Succeeded(authentication);
    }
    static @NonNull WebAuthnAuthenticationResult rejected(@NonNull WebAuthnRejectionReason reason) {
        return new Rejected(reason);
    }
    static @NonNull WebAuthnAuthenticationResult unavailable() { return UNAVAILABLE; }
    static @NonNull WebAuthnAuthenticationResult indeterminate() { return INDETERMINATE; }
    /** Redacts all identity and browser data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "WebAuthnAuthenticationResult{<redacted>}"; }

    /** Confirmed stored-key authentication.
     * @since 1.0.0 */
    @Immutable public static final class Succeeded extends WebAuthnAuthenticationResult {
        private final @NonNull WebAuthnAuthentication authentication;
        private Succeeded(@NonNull WebAuthnAuthentication authentication) {
            this.authentication = requireNonNull(authentication);
        }
        /** Returns the verified authentication.
         * @return authentication
         * @since 1.0.0 */
        public @NonNull WebAuthnAuthentication getAuthentication() { return this.authentication; }
    }
    /** Fixed validation or policy rejection without an identity.
     * @since 1.0.0 */
    @Immutable public static final class Rejected extends WebAuthnAuthenticationResult {
        private final @NonNull WebAuthnRejectionReason reason;
        private Rejected(@NonNull WebAuthnRejectionReason reason) { this.reason = requireNonNull(reason); }
        /** Returns a fixed reason.
         * @return rejection reason
         * @since 1.0.0 */
        public @NonNull WebAuthnRejectionReason getReason() { return this.reason; }
    }
    /** Storage or admission was unavailable.
     * @since 1.0.0 */
    @Immutable public static final class Unavailable extends WebAuthnAuthenticationResult {
        private Unavailable() { }
    }
    /** A write may have occurred; reconcile before retry.
     * @since 1.0.0 */
    @Immutable public static final class Indeterminate extends WebAuthnAuthenticationResult {
        private Indeterminate() { }
    }
}
