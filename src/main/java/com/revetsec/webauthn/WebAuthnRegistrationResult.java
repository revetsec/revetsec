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

/** Library-created enrollment completion; only Succeeded carries a verified registration.
 * @since 1.0.0 */
@Immutable
public abstract sealed class WebAuthnRegistrationResult permits WebAuthnRegistrationResult.Succeeded,
        WebAuthnRegistrationResult.Rejected, WebAuthnRegistrationResult.Unavailable,
        WebAuthnRegistrationResult.Indeterminate {
    private static final @NonNull Unavailable UNAVAILABLE = new Unavailable();
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();
    WebAuthnRegistrationResult() { }
    static @NonNull WebAuthnRegistrationResult succeeded(@NonNull WebAuthnRegistration registration) {
        return new Succeeded(registration);
    }
    static @NonNull WebAuthnRegistrationResult rejected(@NonNull WebAuthnRejectionReason reason) {
        return new Rejected(reason);
    }
    static @NonNull WebAuthnRegistrationResult unavailable() { return UNAVAILABLE; }
    static @NonNull WebAuthnRegistrationResult indeterminate() { return INDETERMINATE; }
    /** Redacts all identity and browser data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "WebAuthnRegistrationResult{<redacted>}"; }

    /** Confirmed enrollment of a new credential.
     * @since 1.0.0 */
    @Immutable public static final class Succeeded extends WebAuthnRegistrationResult {
        private final @NonNull WebAuthnRegistration registration;
        private Succeeded(@NonNull WebAuthnRegistration registration) {
            this.registration = requireNonNull(registration);
        }
        /** Returns the verified registration.
         * @return registration
         * @since 1.0.0 */
        public @NonNull WebAuthnRegistration getRegistration() { return this.registration; }
    }
    /** Fixed validation or policy rejection without an identity.
     * @since 1.0.0 */
    @Immutable public static final class Rejected extends WebAuthnRegistrationResult {
        private final @NonNull WebAuthnRejectionReason reason;
        private Rejected(@NonNull WebAuthnRejectionReason reason) { this.reason = requireNonNull(reason); }
        /** Returns a fixed reason.
         * @return rejection reason
         * @since 1.0.0 */
        public @NonNull WebAuthnRejectionReason getReason() { return this.reason; }
    }
    /** Storage or admission was unavailable.
     * @since 1.0.0 */
    @Immutable public static final class Unavailable extends WebAuthnRegistrationResult {
        private Unavailable() { }
    }
    /** A write may have occurred; reconcile before retry.
     * @since 1.0.0 */
    @Immutable public static final class Indeterminate extends WebAuthnRegistrationResult {
        private Indeterminate() { }
    }
}
