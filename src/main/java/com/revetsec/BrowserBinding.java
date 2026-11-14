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
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.Arrays;
import java.util.Base64;

import static java.util.Objects.requireNonNull;

/**
 * Bounded application-held correlation secret for browser pending workflows.
 * <p>
 * This value is not an authenticated browser, user, session, permission or recovery admission. A value restored
 * from trusted persistence retains only its exact spelling; syntactic validity does not establish randomness,
 * provenance or ownership. Untrusted request input must remain an untrusted comparison candidate and must not be
 * passed to {@link #fromTrustedPersistence(String)} merely to obtain this type.
 * <p>
 * The restoration ceiling is 65,536 Java UTF-16 code units. Individual protocols and stores retain every narrower
 * rule, including strict UTF-8 where already required. The broad carrier deliberately preserves unmatched-surrogate
 * spellings used by retained SAML pending state; it does not normalize text.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class BrowserBinding {
    /**
     * Maximum restored Java UTF-16 code units.
     *
     * @since 1.0.0
     */
    public static final @NonNull Integer MAXIMUM_CODE_UNITS = 65_536;

    private final @NonNull String value;

    private BrowserBinding(@NonNull String value) { this.value = value; }

    /**
     * Generates a fresh 32-byte application correlation secret in canonical unpadded Base64URL form.
     *
     * @return a fresh 43-character binding
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull BrowserBinding fresh() {
        byte[] bytes = EntropySource.fromDefaults().nextBytes(32);
        try {
            return new BrowserBinding(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /**
     * Restores the exact value from application-controlled trusted persistence.
     * This is not a parser for cookies, form fields, query parameters or other request input.
     *
     * @param value exact persisted correlation secret
     * @return the bounded exact value
     * @throws IllegalArgumentException if empty or longer than 65,536 Java UTF-16 code units
     * @since 1.0.0
     */
    @CheckReturnValue
    public static @NonNull BrowserBinding fromTrustedPersistence(@NonNull String value) {
        requireNonNull(value);
        if (value.isEmpty() || value.length() > MAXIMUM_CODE_UNITS)
            throw new IllegalArgumentException("Invalid browser binding");
        return new BrowserBinding(value);
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
    @Override public @NonNull String toString() { return "BrowserBinding{<redacted>}"; }
}
