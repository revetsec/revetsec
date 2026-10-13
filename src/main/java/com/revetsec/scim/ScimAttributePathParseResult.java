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

package com.revetsec.scim;

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.Objects;

/**
 * The outcome of parsing attribute-path syntax. Success does not establish a registered attribute or
 * grant query permission.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public sealed interface ScimAttributePathParseResult permits ScimAttributePathParseResult.Succeeded,
        ScimAttributePathParseResult.Rejected {
    /**
     * A syntactically valid, immutable attribute path.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Succeeded implements ScimAttributePathParseResult {
        private final @NonNull ScimAttributePath attributePath;

        Succeeded(@NonNull ScimAttributePath attributePath) {
            this.attributePath = Objects.requireNonNull(attributePath);
        }

        /**
         * Returns the syntactically valid path.
         *
         * @return the path
         * @since 1.0.0
         */
        public @NonNull ScimAttributePath getAttributePath() {
            return attributePath;
        }

        /**
     * Returns a redacted description.
     *
     * @return a redacted description
     * @since 1.0.0
     */
        @Override public @NonNull String toString() {
            return "ScimAttributePathParseResult.Succeeded{<redacted>}";
        }
    }

    /**
     * A fixed rejection without retained input or an exception cause.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Rejected implements ScimAttributePathParseResult {
        private final @NonNull ScimError error;

        Rejected(@NonNull ScimError error) {
            this.error = Objects.requireNonNull(error);
        }

        /**
         * Returns the fixed error and its optional expression offset.
         *
         * @return the error
         * @since 1.0.0
         */
        public @NonNull ScimError getError() {
            return error;
        }

        /**
     * Returns a redacted description.
     *
     * @return a redacted description
     * @since 1.0.0
     */
        @Override public @NonNull String toString() {
            return "ScimAttributePathParseResult.Rejected{<redacted>}";
        }
    }
}
