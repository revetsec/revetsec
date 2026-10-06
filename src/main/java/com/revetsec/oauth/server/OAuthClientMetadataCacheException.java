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

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * Fixed-diagnostic optional-cache failure, distinct from a miss or comparison conflict. Providers
 * may throw this type without retaining backend messages or causes. A failed write may already have
 * happened; cached data still requires core validation. This type supplies no authoritative-store
 * outcome.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public final class OAuthClientMetadataCacheException extends RevetsecException {
    private static final long serialVersionUID = 1L;

    /** Fixed reason retained by this exception. */
    private final OAuthClientMetadataCacheException.@NonNull Reason reason;

    private OAuthClientMetadataCacheException(
            OAuthClientMetadataCacheException.@NonNull Reason reason) {
        super(
                ErrorCategory.TRANSPORT,
                requireNonNull(reason) != Reason.INTERRUPTED,
                "Client metadata cache operation failed.",
                null);
        this.reason = reason;
    }

    /**
     * Creates a fixed failure for an application cache provider; raw diagnostics and causes are not
     * accepted.
     *
     * @param reason the fixed reason
     * @return the provider failure
     * @throws NullPointerException if reason is null
     * @since 1.0.0
     */
    public static @NonNull OAuthClientMetadataCacheException fromReason(
            OAuthClientMetadataCacheException.@NonNull Reason reason) {
        return new OAuthClientMetadataCacheException(reason);
    }

    /**
     * Returns the fixed failure reason.
     *
     * @return the reason
     * @since 1.0.0
     */
    public OAuthClientMetadataCacheException.@NonNull Reason getReason() {
        return this.reason;
    }

    /**
     * The optional-cache failure reasons. Interrupted calls preserve the thread flag and are never
     * transient.
     *
     * @author <a href="https://www.revetkn.com">Mark Allen</a>
     * @since 1.0.0
     */
    @Immutable
    public enum Reason {
        /** The provider could not complete the operation.
         * @since 1.0.0
         */
        UNAVAILABLE,
        /** The remaining operation budget elapsed.
         * @since 1.0.0
         */
        TIMEOUT,
        /** The calling thread was interrupted.
         * @since 1.0.0
         */
        INTERRUPTED
    }
}
