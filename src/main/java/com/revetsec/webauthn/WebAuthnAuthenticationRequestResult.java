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

/** Library-created sign-in or reauthentication preparation outcome.
 * @since 1.0.0 */
@Immutable
public abstract sealed class WebAuthnAuthenticationRequestResult permits
        WebAuthnAuthenticationRequestResult.Prepared, WebAuthnAuthenticationRequestResult.Rejected,
        WebAuthnAuthenticationRequestResult.Unavailable, WebAuthnAuthenticationRequestResult.Indeterminate {
    private static final @NonNull Unavailable UNAVAILABLE = new Unavailable();
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();
    WebAuthnAuthenticationRequestResult() { }
    static @NonNull WebAuthnAuthenticationRequestResult prepared(@NonNull WebAuthnBrowserRequest request) {
        return new Prepared(request);
    }
    static @NonNull WebAuthnAuthenticationRequestResult rejected() { return new Rejected(); }
    static @NonNull WebAuthnAuthenticationRequestResult unavailable() { return UNAVAILABLE; }
    static @NonNull WebAuthnAuthenticationRequestResult indeterminate() { return INDETERMINATE; }
    /** Redacts browser and account fields.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "WebAuthnAuthenticationRequestResult{<redacted>}"; }

    /** A committed, single-use browser request.
     * @since 1.0.0 */
    @Immutable public static final class Prepared extends WebAuthnAuthenticationRequestResult {
        private final @NonNull WebAuthnBrowserRequest request;
        private Prepared(@NonNull WebAuthnBrowserRequest request) { this.request = requireNonNull(request); }
        /** Returns the browser request.
         * @return request
         * @since 1.0.0 */
        public @NonNull WebAuthnBrowserRequest getRequest() { return this.request; }
    }
    /** The approved account was not admitted for reauthentication.
     * @since 1.0.0 */
    @Immutable public static final class Rejected extends WebAuthnAuthenticationRequestResult {
        private Rejected() { }
        /** Returns a fixed reason.
         * @return rejection reason
         * @since 1.0.0 */
        public @NonNull WebAuthnRejectionReason getReason() { return WebAuthnRejectionReason.REJECTED; }
    }
    /** Storage or admission was unavailable.
     * @since 1.0.0 */
    @Immutable public static final class Unavailable extends WebAuthnAuthenticationRequestResult {
        private Unavailable() { }
    }
    /** A write may have occurred; reconcile before retry.
     * @since 1.0.0 */
    @Immutable public static final class Indeterminate extends WebAuthnAuthenticationRequestResult {
        private Indeterminate() { }
    }
}
