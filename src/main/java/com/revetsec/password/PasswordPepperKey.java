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

/** An application-owned, 32-byte Argon2id secret-input key identified by a non-secret ID. Keep the
 * key outside the password-hash database. The supplied array is copied and remains caller-owned.
 * @since 1.0.0 */
@Immutable
public final class PasswordPepperKey {
    private final @NonNull String keyId;
    private final byte @NonNull [] key;

    private PasswordPepperKey(@NonNull String keyId, byte @NonNull [] key) {
        this.keyId = keyId;
        this.key = key;
    }

    /** Constructs a pepper key from 32 cryptographically random bytes.
     * @param keyId stable 1–64 character ASCII key ID
     * @param keyBytes 32 secret bytes; borrowed only for this call and not modified
     * @return a retained defensive copy
     * @since 1.0.0 */
    public static @NonNull PasswordPepperKey fromBytes(@NonNull String keyId, byte @NonNull [] keyBytes) {
        requireNonNull(keyId); requireNonNull(keyBytes);
        if (keyId.length() < 1 || keyId.length() > 64 || !keyId.chars().allMatch(ch ->
                (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                        || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '~' || ch == '-')) {
            throw new IllegalArgumentException("Invalid pepper key ID");
        }
        if (keyBytes.length != 32) throw new IllegalArgumentException("Pepper key must be 32 bytes");
        int difference = 0;
        for (int i = 1; i < keyBytes.length; i++) difference |= keyBytes[0] ^ keyBytes[i];
        if (difference == 0) throw new IllegalArgumentException("Uniform pepper key is not allowed");
        return new PasswordPepperKey(keyId, keyBytes.clone());
    }

    /** Returns the identifier used to select this pepper key.
     * @return non-secret key ID
     * @since 1.0.0 */
    public @NonNull String getKeyId() { return keyId; }

    byte @NonNull [] copyKeyBytes() { return key.clone(); }

    /** @return a fixed redacted description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "PasswordPepperKey{<redacted>}"; }

    // Intentionally identity-based: comparing key bytes is not a supported operation.
}
