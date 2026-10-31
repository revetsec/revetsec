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

package com.revetsec.totp;

import org.jspecify.annotations.NonNull;
import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/** Explicit namespace initialization under provisioning admission.
 * @since 1.0.0 */
@Immutable
public abstract sealed class TotpNamespaceInitializationResult permits
        TotpNamespaceInitializationResult.Initialized, TotpNamespaceInitializationResult.AlreadyInitialized, TotpNamespaceInitializationResult.Unavailable, TotpNamespaceInitializationResult.Indeterminate, TotpNamespaceInitializationResult.ReconciliationRequired {
    private static final @NonNull Initialized INITIALIZED = new Initialized();
    private static final @NonNull AlreadyInitialized ALREADY_INITIALIZED = new AlreadyInitialized();
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();
    private static final @NonNull ReconciliationRequired RECONCILIATION_REQUIRED = new ReconciliationRequired();

    TotpNamespaceInitializationResult() { }
    static @NonNull TotpNamespaceInitializationResult initialized() {
        return INITIALIZED;
    }
    static @NonNull TotpNamespaceInitializationResult alreadyInitialized() {
        return ALREADY_INITIALIZED;
    }
    static @NonNull TotpNamespaceInitializationResult unavailable(@NonNull TotpUnavailableReason reason) {
        return new Unavailable(reason);
    }
    static @NonNull TotpNamespaceInitializationResult indeterminate() {
        return INDETERMINATE;
    }
    @CheckReturnValue
    static @NonNull TotpNamespaceInitializationResult reconciliationRequired() {
        return RECONCILIATION_REQUIRED;
    }
    static @NonNull TotpNamespaceInitializationResult unavailable() {
        return unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);
    }

    /** Redacts all account, binding and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "TotpNamespaceInitializationResult{<redacted>}"; }

    /** The new namespace record and activation state were atomically initialized.
     * @since 1.0.0 */
    @Immutable
    public static final class Initialized extends TotpNamespaceInitializationResult {
        private Initialized() { }
    }

    /** The current namespace was already validly initialized.
     * @since 1.0.0 */
    @Immutable
    public static final class AlreadyInitialized extends TotpNamespaceInitializationResult {
        private AlreadyInitialized() { }
    }

    /** Infrastructure or recovery admission was unavailable; no success is established.
     * @since 1.0.0 */
    @Immutable
    public static final class Unavailable extends TotpNamespaceInitializationResult {
        private final @NonNull TotpUnavailableReason reason;
        private Unavailable(@NonNull TotpUnavailableReason reason) {
            this.reason = requireNonNull(reason);
        }
        /** Returns the reason.
         * @return reason
         * @since 1.0.0 */
        public @NonNull TotpUnavailableReason getReason() { return this.reason; }
    }

    /** A write may have occurred; reconcile management state and never infer authentication success.
     * @since 1.0.0 */
    @Immutable
    public static final class Indeterminate extends TotpNamespaceInitializationResult {
        private Indeterminate() { }
    }

    /** The requested transition is known committed, but normal output could not be admitted.
     * No proof, secret or operation detail is released.
     * @since 1.0.0 */
    @Immutable
    public static final class ReconciliationRequired extends TotpNamespaceInitializationResult {
        private ReconciliationRequired() { }
    }
}
