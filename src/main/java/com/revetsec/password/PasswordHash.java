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

/** A generated password verifier. Treat its stored form as sensitive credential data even though
 * it contains no plaintext password. Logging and {@link #toString()} redact it.
 * @since 1.0.0 */
@Immutable
public final class PasswordHash {
    private final @NonNull String storedForm;

    PasswordHash(@NonNull String storedForm) { this.storedForm = requireNonNull(storedForm); }

    /** Returns the complete durable representation, including any non-secret pepper key ID.
     * Store it atomically with the account's credential version. Access to this value is deliberate.
     * @return durable stored form
     * @since 1.0.0 */
    public @NonNull String getStoredForm() { return storedForm; }

    /** @return a fixed redacted description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "PasswordHash{<redacted>}"; }
}
