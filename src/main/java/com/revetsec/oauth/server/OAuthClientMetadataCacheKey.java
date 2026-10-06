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

package com.revetsec.oauth.server;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.CheckReturnValue;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;

/**
 * Bounded opaque address for optional client-metadata storage. Reconstructing an address grants no
 * authority. The core binds stable issuer/configuration and exact client identities; providers
 * preserve the string exactly.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class OAuthClientMetadataCacheKey {
    private static final @NonNull String PREFIX = "revetsec:cimd-cache:1:";
    private final @NonNull String storageKey;

    private OAuthClientMetadataCacheKey(@NonNull String value) {
        this.storageKey = value;
    }

    /**
     * Reconstructs the current address format: fixed prefix, two canonical 32-byte base64url
     * digests separated by a colon. This checks bounded syntax only; it does not verify namespace
     * or record authenticity.
     *
     * @param value the exact persisted string
     * @return the bounded address
     * @throws NullPointerException if value is null
     * @throws IllegalArgumentException if the format is invalid
     * @since 1.0.0
     */
    public static @NonNull OAuthClientMetadataCacheKey fromStoredForm(@NonNull String value) {
        requireNonNull(value);
        int offset = PREFIX.length();
        if (value.length() != offset + 87
                || !value.startsWith(PREFIX)
                || value.charAt(offset + 43) != ':')
            throw new IllegalArgumentException("Invalid client metadata cache address.");
        OAuthStoreFormat.nonce(value.substring(offset, offset + 43));
        OAuthStoreFormat.nonce(value.substring(offset + 44));
        return new OAuthClientMetadataCacheKey(value);
    }

    /**
     * Releases the opaque storage string; keep it out of logs and responses.
     *
     * @return the exact address
     * @since 1.0.0
     */
    public @NonNull String getStorageKey() {
        return this.storageKey;
    }

    /**
     * Compares exact addresses.
     *
     * @param other the possible address
     * @return whether they match
     * @since 1.0.0
     */
    @Override
    public boolean equals(@Nullable Object other) {
        return other instanceof OAuthClientMetadataCacheKey key
                && this.storageKey.equals(key.storageKey);
    }

    /**
     * Returns the address hash.
     *
     * @return the hash
     * @since 1.0.0
     */
    @Override
    public int hashCode() {
        return this.storageKey.hashCode();
    }

    /**
     * Redacts the address.
     *
     * @return a fixed description
     * @since 1.0.0
     */
    @Override
    public @NonNull String toString() {
        return "OAuthClientMetadataCacheKey{address=<redacted>}";
    }
}
