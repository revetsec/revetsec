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
import static java.util.Objects.requireNonNull;

/** A complete filter evaluation, or a fixed rejection without a partial verdict.
 * @since 1.0.0
 */
@Immutable
public sealed interface ScimFilterEvaluationResult permits ScimFilterEvaluationResult.Succeeded,
        ScimFilterEvaluationResult.Rejected {
    /** A verdict after every filter clause was checked and evaluated.
     * @since 1.0.0
     */
    @Immutable
    final class Succeeded implements ScimFilterEvaluationResult {
        private final boolean matched;
        Succeeded(boolean matched) { this.matched = matched; }
        /** Returns whether the complete filter matched the resource.
         * @return the complete verdict
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Boolean isMatched() { return matched; }
        /** Returns a fixed redacted description.
         * @return the description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilterEvaluationResult.Succeeded{<redacted>}"; }
    }
    /** A fixed rejection; no partial verdict or application failure is exposed.
     * @since 1.0.0
     */
    @Immutable
    final class Rejected implements ScimFilterEvaluationResult {
        private final @NonNull ScimError error;
        Rejected(@NonNull ScimError error) { this.error = requireNonNull(error); }
        /** Returns the fixed rejection.
         * @return the error
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimError getError() { return error; }
        /** Returns a fixed redacted description.
         * @return the description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimFilterEvaluationResult.Rejected{<redacted>}"; }
    }
}
