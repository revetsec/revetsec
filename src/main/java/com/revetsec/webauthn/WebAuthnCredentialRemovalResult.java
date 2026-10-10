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

/** App-authorized credential removal; the app supplies session, CSRF and policy checks.
 * @since 1.0.0 */
@Immutable
public abstract sealed class WebAuthnCredentialRemovalResult permits
        WebAuthnCredentialRemovalResult.Removed, WebAuthnCredentialRemovalResult.Absent,
        WebAuthnCredentialRemovalResult.Unavailable, WebAuthnCredentialRemovalResult.Indeterminate {
    private static final @NonNull Removed REMOVED = new Removed();
    private static final @NonNull Absent ABSENT = new Absent();
    private static final @NonNull Unavailable UNAVAILABLE = new Unavailable();
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();
    WebAuthnCredentialRemovalResult() { }
    static @NonNull WebAuthnCredentialRemovalResult removed() { return REMOVED; }
    static @NonNull WebAuthnCredentialRemovalResult absent() { return ABSENT; }
    static @NonNull WebAuthnCredentialRemovalResult unavailable() { return UNAVAILABLE; }
    static @NonNull WebAuthnCredentialRemovalResult indeterminate() { return INDETERMINATE; }
    /** Redacts account and credential identifiers.
     * @return fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "WebAuthnCredentialRemovalResult{<redacted>}"; }
    /** The credential was atomically revoked and removed from the active index.
     * @since 1.0.0 */
    @Immutable public static final class Removed extends WebAuthnCredentialRemovalResult {
        private Removed() { }
    }
    /** No active credential with this ID belongs to the approved account.
     * @since 1.0.0 */
    @Immutable public static final class Absent extends WebAuthnCredentialRemovalResult {
        private Absent() { }
    }
    /** Storage, recovery admission or a concurrent change prevented a confirmed result.
     * @since 1.0.0 */
    @Immutable public static final class Unavailable extends WebAuthnCredentialRemovalResult {
        private Unavailable() { }
    }
    /** A write may have occurred; reconcile authoritative state before another action.
     * @since 1.0.0 */
    @Immutable public static final class Indeterminate extends WebAuthnCredentialRemovalResult {
        private Indeterminate() { }
    }
}
