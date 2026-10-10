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

/** App-authorized account fence transition that stops future passkey acceptance.
 * @since 1.0.0 */
@Immutable
public abstract sealed class WebAuthnAccountDisableResult permits
        WebAuthnAccountDisableResult.Disabled,
        WebAuthnAccountDisableResult.Unavailable, WebAuthnAccountDisableResult.Indeterminate {
    private static final @NonNull Disabled DISABLED = new Disabled();
    private static final @NonNull Unavailable UNAVAILABLE = new Unavailable();
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();
    WebAuthnAccountDisableResult() { }
    static @NonNull WebAuthnAccountDisableResult disabled() { return DISABLED; }
    static @NonNull WebAuthnAccountDisableResult unavailable() { return UNAVAILABLE; }
    static @NonNull WebAuthnAccountDisableResult indeterminate() { return INDETERMINATE; }
    /** Redacts account identity.
     * @return fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "WebAuthnAccountDisableResult{<redacted>}"; }
    /** The fence is confirmed disabled; new and pending ceremonies cannot authenticate.
     * @since 1.0.0 */
    @Immutable public static final class Disabled extends WebAuthnAccountDisableResult {
        private Disabled() { }
    }
    /** Storage, recovery admission or a concurrent change prevented a confirmed result.
     * @since 1.0.0 */
    @Immutable public static final class Unavailable extends WebAuthnAccountDisableResult {
        private Unavailable() { }
    }
    /** A write may have occurred; reconcile the account before reopening it.
     * @since 1.0.0 */
    @Immutable public static final class Indeterminate extends WebAuthnAccountDisableResult {
        private Indeterminate() { }
    }
}
