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

import java.time.Instant;

import javax.annotation.concurrent.Immutable;

/**
 * Immutable bounded encrypted cache carrier. This is storage data, never authenticated metadata or
 * a fresh-fetch proof. Core authentication and current policy/time checks are required before use.
 * Providers preserve all fields exactly. The expiry is a storage cleanup hint, not permission to
 * use a document; provider TTL may only shorten retention.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class OAuthClientMetadataCacheEntry {
    private final @NonNull OAuthClientMetadataCacheKey key;
    private final @NonNull String version;
    private final @NonNull Instant expiresAt;
    private final @NonNull String sealedForm;

    private OAuthClientMetadataCacheEntry(
            @NonNull OAuthClientMetadataCacheKey key,
            @NonNull String version,
            @NonNull Instant expiresAt,
            @NonNull String sealedForm) {
        this.key = key;
        this.version = version;
        this.expiresAt = expiresAt;
        this.sealedForm = sealedForm;
    }

    /**
     * Reconstructs syntax-bounded storage fields without authenticating their contents.
     *
     * @param key the exact address
     * @param version a canonical base64url 32-byte nonce; core writes use a fresh version on every
     *     replacement
     * @param expiresAt a finite whole-second UTC expiry hint, distinct from authenticated freshness
     * @param sealedForm the exact nonempty ASCII encrypted envelope, at most 16384 characters
     * @return the bounded carrier
     * @throws NullPointerException if an argument is null
     * @throws IllegalArgumentException if a field is invalid
     * @since 1.0.0
     */
    public static @NonNull OAuthClientMetadataCacheEntry fromStoredForm(
            @NonNull OAuthClientMetadataCacheKey key,
            @NonNull String version,
            @NonNull Instant expiresAt,
            @NonNull String sealedForm) {
        requireNonNull(key);
        OAuthStoreFormat.nonce(version);
        OAuthStoreFormat.retention(OAuthStoreKey.Kind.GRANT, expiresAt);
        OAuthStoreFormat.sealed(sealedForm, 16384);
        return new OAuthClientMetadataCacheEntry(key, version, expiresAt, sealedForm);
    }

    /**
     * Returns the exact address.
     *
     * @return the address
     * @since 1.0.0
     */
    public @NonNull OAuthClientMetadataCacheKey getKey() {
        return this.key;
    }

    /**
     * Returns the exact comparison nonce, not a freshness ordering value.
     *
     * @return the opaque version
     * @since 1.0.0
     */
    public @NonNull String getVersion() {
        return this.version;
    }

    /**
     * Returns the unauthenticated storage expiry hint.
     *
     * @return the expiry hint
     * @since 1.0.0
     */
    public @NonNull Instant getExpiresAt() {
        return this.expiresAt;
    }

    /**
     * Releases the encrypted envelope for persistence; never log it or render it in a browser
     * response.
     *
     * @return the exact envelope
     * @since 1.0.0
     */
    public @NonNull String toSealedForm() {
        return this.sealedForm;
    }

    /**
     * Redacts every field.
     *
     * @return a fixed description
     * @since 1.0.0
     */
    @Override
    public @NonNull String toString() {
        return "OAuthClientMetadataCacheEntry{record=<redacted>}";
    }
}
