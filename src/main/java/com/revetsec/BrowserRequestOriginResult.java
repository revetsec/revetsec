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
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * Closed outcome of a browser request-origin check.
 * <p>
 * An allowed result says which input admitted the request. A rejected result carries only a fixed reason; it never
 * exposes a submitted origin. This policy result is one layer of request admission, not a complete CSRF defense.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public abstract sealed class BrowserRequestOriginResult permits BrowserRequestOriginResult.Allowed,
        BrowserRequestOriginResult.Rejected {
    BrowserRequestOriginResult() { }

    static @NonNull BrowserRequestOriginResult allowed(@NonNull Basis basis) {
        return new Allowed(basis);
    }

    static @NonNull BrowserRequestOriginResult rejected(@NonNull Reason reason) {
        return new Rejected(reason);
    }

    /**
     * Redacts all request metadata.
     *
     * @return a fixed description
     * @since 1.0.0
     */
    @Override
    public final @NonNull String toString() {
        return "BrowserRequestOriginResult{<redacted>}";
    }

    /**
     * The input that admitted a request.
     *
     * @since 1.0.0
     */
    @Immutable
    public enum Basis {
        /** A safe HTTP method. */
        SAFE_METHOD,
        /** {@code Sec-Fetch-Site: same-origin}. */
        SAME_ORIGIN,
        /** {@code Sec-Fetch-Site: none}, normally a user-initiated navigation. */
        USER_INITIATED,
        /** An exact configured {@code Origin}. */
        CONFIGURED_ORIGIN,
        /** The explicit compatibility option for a request with neither metadata header. */
        MISSING_METADATA_COMPATIBILITY
    }

    /**
     * A fixed rejection reason.
     *
     * @since 1.0.0
     */
    @Immutable
    public enum Reason {
        /** Cross-site metadata had no exact configured origin. */
        CROSS_SITE,
        /** Same-site metadata had no exact configured origin. */
        SAME_SITE,
        /** An unrecognized {@code Sec-Fetch-Site} value had no exact configured origin. */
        UNRECOGNIZED_FETCH_SITE,
        /** A syntactically valid origin was not configured. */
        UNTRUSTED_ORIGIN,
        /** An opaque {@code Origin: null} could not be admitted. */
        NULL_ORIGIN,
        /** Neither request metadata header was present. */
        MISSING_METADATA,
        /** A header was duplicated or malformed. */
        MALFORMED
    }

    /**
     * An admitted request.
     *
     * @since 1.0.0
     */
    @Immutable
    public static final class Allowed extends BrowserRequestOriginResult {
        private final @NonNull Basis basis;

        private Allowed(@NonNull Basis basis) {
            this.basis = requireNonNull(basis);
        }

        /**
         * Returns the input that admitted the request. This makes use of the missing-metadata compatibility option
         * observable without logging submitted headers.
         *
         * @return admission basis
         * @since 1.0.0
         */
        public @NonNull Basis getBasis() {
            return this.basis;
        }
    }

    /**
     * A request rejected before application state changes.
     *
     * @since 1.0.0
     */
    @Immutable
    public static final class Rejected extends BrowserRequestOriginResult {
        private final @NonNull Reason reason;

        private Rejected(@NonNull Reason reason) {
            this.reason = requireNonNull(reason);
        }

        /**
         * Returns the fixed rejection reason.
         *
         * @return rejection reason
         * @since 1.0.0
         */
        public @NonNull Reason getReason() {
            return this.reason;
        }
    }
}
