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

import javax.annotation.concurrent.ThreadSafe;

import static java.util.Objects.requireNonNull;

/** Thread-safe application source of coherent pepper-key snapshots. Implementations must be
 * bounded and must not log key material. The hasher calls this on the caller thread, never from
 * its builder or a library worker thread.
 * @since 1.0.0 */
@FunctionalInterface
@ThreadSafe
public interface PasswordPepperSource {
    /** Supplies the complete snapshot for one operation.
     * @return available or unavailable, never {@code null}
     * @since 1.0.0 */
    @NonNull PasswordPepperSnapshotResult snapshotResult();

    /** Supplies a constant snapshot until the application replaces its hasher configuration.
     * @param snapshot immutable keys
     * @return fixed source
     * @since 1.0.0 */
    static @NonNull PasswordPepperSource fromSnapshot(@NonNull PasswordPepperSnapshot snapshot) {
        PasswordPepperSnapshot accepted = requireNonNull(snapshot);
        return () -> PasswordPepperSnapshotResult.available(accepted);
    }
}
