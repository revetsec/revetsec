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

/** Provider-constructible match outcome, without arbitrary failure data.
 * @since 1.0.0
 */
@Immutable
public sealed interface ScimStringMatchResult
        permits ScimStringMatchResult.Matched, ScimStringMatchResult.Unsupported {
    /** Creates a matching verdict.
     * @param value verdict
     * @return outcome
     * @since 1.0.0
     */
    @CheckReturnValue
    static @NonNull ScimStringMatchResult fromMatched(@NonNull Boolean value) {
        return new Matched(requireNonNull(value));
    }

    /** Reports unsupported matching.
     * @return fixed outcome
     * @since 1.0.0
     */
    @CheckReturnValue
    static @NonNull ScimStringMatchResult unsupportedInstance() {
        return Unsupported.INSTANCE;
    }

    /** A matching verdict.
     * @since 1.0.0
     */
    @Immutable
    final class Matched implements ScimStringMatchResult {
        private final boolean matched;

        private Matched(boolean value) {
            matched = value;
        }

        /** Returns the verdict.
         * @return matching state
         * @since 1.0.0
         */
        public @NonNull Boolean isMatched() {
            return matched;
        }

        /** Returns a fixed diagnostic.
         * @return description
         * @since 1.0.0
         */
        @Override
        public @NonNull String toString() {
            return "ScimStringMatchResult.Matched";
        }
    }

    /** Matching is unsupported.
     * @since 1.0.0
     */
    @Immutable
    final class Unsupported implements ScimStringMatchResult {
        private static final @NonNull Unsupported INSTANCE = new Unsupported();

        private Unsupported() {}

        /** Returns a fixed diagnostic.
         * @return description
         * @since 1.0.0
         */
        @Override
        public @NonNull String toString() {
            return "ScimStringMatchResult.Unsupported";
        }
    }
}
