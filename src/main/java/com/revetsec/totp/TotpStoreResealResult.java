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
import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/** Maintenance resealing of an exact authenticated durable record without changing semantic state.
 * @since 1.0.0 */
@Immutable
public abstract sealed class TotpStoreResealResult permits
        TotpStoreResealResult.Resealed, TotpStoreResealResult.AlreadyCurrent, TotpStoreResealResult.Absent, TotpStoreResealResult.Unavailable, TotpStoreResealResult.Indeterminate {
    private static final @NonNull Resealed RESEALED = new Resealed();
    private static final @NonNull AlreadyCurrent ALREADY_CURRENT = new AlreadyCurrent();
    private static final @NonNull Absent ABSENT = new Absent();
    private static final @NonNull Indeterminate INDETERMINATE = new Indeterminate();

    TotpStoreResealResult() { }
    static @NonNull TotpStoreResealResult resealed() {
        return RESEALED;
    }
    static @NonNull TotpStoreResealResult alreadyCurrent() {
        return ALREADY_CURRENT;
    }
    static @NonNull TotpStoreResealResult absent() {
        return ABSENT;
    }
    static @NonNull TotpStoreResealResult unavailable(@NonNull TotpUnavailableReason reason) {
        return new Unavailable(reason);
    }
    static @NonNull TotpStoreResealResult indeterminate() {
        return INDETERMINATE;
    }
    static @NonNull TotpStoreResealResult unavailable() {
        return unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);
    }

    /** Redacts all account, binding and secret data.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "TotpStoreResealResult{<redacted>}"; }

    /** The authenticated record was resealed and the replacement definitely committed.
     * @since 1.0.0 */
    @Immutable
    public static final class Resealed extends TotpStoreResealResult {
        private Resealed() { }
    }

    /** The authenticated record already uses the configured active sealing key and current format.
     * @since 1.0.0 */
    @Immutable
    public static final class AlreadyCurrent extends TotpStoreResealResult {
        private AlreadyCurrent() { }
    }

    /** The requested record was authoritatively absent in this recovery epoch.
     * @since 1.0.0 */
    @Immutable
    public static final class Absent extends TotpStoreResealResult {
        private Absent() { }
    }

    /** Infrastructure or recovery admission was unavailable; no success is established.
     * @since 1.0.0 */
    @Immutable
    public static final class Unavailable extends TotpStoreResealResult {
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
    public static final class Indeterminate extends TotpStoreResealResult {
        private Indeterminate() { }
    }
}
