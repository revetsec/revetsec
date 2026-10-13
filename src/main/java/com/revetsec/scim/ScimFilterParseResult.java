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

import org.jspecify.annotations.NonNull;

import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/**
 * The result of bounded SCIM filter syntax parsing. Syntax success does not bind
 * attributes to a schema, approve a filter policy, or authorize query execution.
 * Results have identity equality and redacted diagnostics.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface ScimFilterParseResult permits ScimFilterParseResult.Succeeded,
        ScimFilterParseResult.Rejected {
    /**
     * A syntactically valid immutable filter awaiting schema binding and policy approval.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Succeeded implements ScimFilterParseResult {
        private final @NonNull ScimFilter filter;

        Succeeded(@NonNull ScimFilter filter) { this.filter = requireNonNull(filter); }

        /**
         * Returns the parsed syntax tree, without query permission.
         *
         * @return the filter
         * @since 1.0.0
         */
        @CheckReturnValue
        public @NonNull ScimFilter getFilter() { return this.filter; }

        /**
         * Returns a fixed description without filter content.
         *
         * @return redacted description
         * @since 1.0.0
         */
        @Override
        public @NonNull String toString() { return "ScimFilterParseResult.Succeeded{filter=<redacted>}"; }
    }

    /**
     * Invalid syntax or a configured bound was exceeded; no partial tree is released.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Rejected implements ScimFilterParseResult {
        private final @NonNull ScimError error;

        Rejected(@NonNull ScimError error) { this.error = requireNonNull(error); }

        /**
         * Returns the fixed error and an optional expression offset.
         *
         * @return the error
         * @since 1.0.0
         */
        @CheckReturnValue
        public @NonNull ScimError getError() { return this.error; }

        /**
         * Returns a fixed description without filter content.
         *
         * @return redacted description
         * @since 1.0.0
         */
        @Override
        public @NonNull String toString() { return "ScimFilterParseResult.Rejected{error=<redacted>}"; }
    }
}
