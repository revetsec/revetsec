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

package com.revetsec;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.crypto.EntropySource;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.Arrays;
import java.util.Base64;

import static java.util.Objects.requireNonNull;

/**
 * Bounded application-held correlation secret for selected WebAuthn and TOTP operations.
 * <p>
 * The binding is not identity, permission, freshness, uniqueness or a one-use authorization grant. Applications
 * still authorize the current session/action and atomically consume their own pending state. WebAuthn retains its
 * canonical 43-character boundary; TOTP retains its historical nonempty, well-formed 1,024-code-unit boundary.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class OperationBinding {
    /**
     * Maximum trusted-persistence spelling retained for the TOTP compatibility profile.
     *
     * @since 1.0.0
     */
    public static final @NonNull Integer MAXIMUM_CODE_UNITS = 1_024;

    private final @NonNull String value;

    private OperationBinding(@NonNull String value) { this.value = value; }

    /**
     * Generates a fresh 32-byte correlation secret in canonical unpadded Base64URL form.
     *
     * @return a fresh 43-character binding
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull OperationBinding fresh() {
        byte[] bytes = EntropySource.fromDefaults().nextBytes(32);
        try {
            return new OperationBinding(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Restores an exact TOTP-compatible value from application-controlled trusted persistence.
     * This is not a parser for untrusted browser or request input.
     *
     * @param value exact persisted correlation secret
     * @return the bounded exact value
     * @throws IllegalArgumentException if empty, longer than 1,024 Java UTF-16 code units or not well-formed UTF-16
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull OperationBinding fromTrustedPersistence(@NonNull String value) {
        requireNonNull(value);
        if (value.isEmpty() || value.length() > MAXIMUM_CODE_UNITS || !StrictUtf8.isWellFormed(value))
            throw new IllegalArgumentException("Invalid operation binding");
        return new OperationBinding(value);
    }

    /**
     * Emits the correlation secret for protected persistence, an affected Revetsec operation or exact comparison.
     * Never log, diagnose or expose this value to a browser response.
     *
     * @return the exact secret spelling
     * @since 1.0.0
     */
    public @NonNull String toSecretString() { return this.value; }

    /** @return a fixed redacted description */
    @Override public @NonNull String toString() { return "OperationBinding{<redacted>}"; }
}
