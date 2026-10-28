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
package com.revetsec.password;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/** Application pepper-source outcome. Never place key material in a result's diagnostics.
 * @since 1.0.0 */
@Immutable
public abstract sealed class PasswordPepperSnapshotResult permits PasswordPepperSnapshotResult.Available,
        PasswordPepperSnapshotResult.Unavailable {
    private static final @NonNull Unavailable UNAVAILABLE = new Unavailable();
    PasswordPepperSnapshotResult() { }

    /** Reports an available pepper snapshot.
     * @param snapshot coherent current and retained keys
     * @return an available result
     * @since 1.0.0 */
    public static @NonNull PasswordPepperSnapshotResult available(@NonNull PasswordPepperSnapshot snapshot) {
        return new Available(snapshot);
    }

    /** Reports that the pepper source is unavailable.
     * @return a provider-unavailable result
     * @since 1.0.0 */
    public static @NonNull PasswordPepperSnapshotResult unavailable() { return UNAVAILABLE; }

    /** @return a fixed redacted description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "PasswordPepperSnapshotResult{<redacted>}"; }

    /** Coherent key snapshot is available.
     * @since 1.0.0 */
    @Immutable
    public static final class Available extends PasswordPepperSnapshotResult {
        private final @NonNull PasswordPepperSnapshot snapshot;
        private Available(@NonNull PasswordPepperSnapshot snapshot) { this.snapshot = requireNonNull(snapshot); }
        /** Returns the available pepper snapshot.
         * @return the snapshot
         * @since 1.0.0 */
        public @NonNull PasswordPepperSnapshot getSnapshot() { return snapshot; }
    }

    /** The provider could not supply its current snapshot.
     * @since 1.0.0 */
    @Immutable
    public static final class Unavailable extends PasswordPepperSnapshotResult {
        private Unavailable() { }
    }
}
