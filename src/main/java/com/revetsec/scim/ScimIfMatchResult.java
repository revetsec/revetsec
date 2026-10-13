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

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.CheckReturnValue;

import org.jspecify.annotations.NonNull;

import java.util.*;

import javax.annotation.concurrent.Immutable;

/** Closed SCIM operation outcome with redacted diagnostics.
 * @since 1.0.0
 */
@Immutable
public sealed interface ScimIfMatchResult
        permits ScimIfMatchResult.Satisfied, ScimIfMatchResult.Rejected {
    /** Satisfied outcome.
     * @since 1.0.0
     */
    @Immutable
    final class Satisfied implements ScimIfMatchResult {
        static final @NonNull Satisfied INSTANCE = new Satisfied();

        private Satisfied() {}

        /** Returns a fixed diagnostic.
         * @return redacted description
         * @since 1.0.0
         */
        @Override
        public @NonNull String toString() {
            return "ScimIfMatchResult.Satisfied{<redacted>}";
        }
    }

    /** Rejected outcome.
     * @since 1.0.0
     */
    @Immutable
    final class Rejected implements ScimIfMatchResult {
        private final @NonNull ScimError error;

        Rejected(@NonNull ScimError value) {
            error = requireNonNull(value);
        }

        /** Returns the outcome payload.
         * @return payload
         * @since 1.0.0
         */
        @CheckReturnValue
        public @NonNull ScimError getError() {
            return error;
        }

        /** Returns a fixed diagnostic.
         * @return redacted description
         * @since 1.0.0
         */
        @Override
        public @NonNull String toString() {
            return "ScimIfMatchResult.Rejected{<redacted>}";
        }
    }
}
