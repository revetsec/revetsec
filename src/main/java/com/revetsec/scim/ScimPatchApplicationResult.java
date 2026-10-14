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

/** A complete PATCH outcome with fixed rejection diagnostics and no partial success.
 * @since 1.0.0
 */
@Immutable
public sealed interface ScimPatchApplicationResult permits ScimPatchApplicationResult.Succeeded, ScimPatchApplicationResult.Rejected {
    /** The complete accepted payload.
     * @since 1.0.0 */
    @Immutable final class Succeeded implements ScimPatchApplicationResult {
        private final @NonNull ScimPatchResult patchResult;
        Succeeded(@NonNull ScimPatchResult value) { patchResult=requireNonNull(value); }
        /** Returns the complete accepted payload.
         * @return the payload
     * @since 1.0.0 */
        @CheckReturnValue public @NonNull ScimPatchResult getPatchResult() { return patchResult; }
        /** Returns a fixed redacted description.
         * @return the description
     * @since 1.0.0 */
        @Override public @NonNull String toString() { return "ScimPatchApplicationResult.Succeeded{<redacted>}"; }
    }
    /** A fixed rejection with no partial payload.
     * @since 1.0.0 */
    @Immutable final class Rejected implements ScimPatchApplicationResult {
        private final @NonNull ScimError error;
        Rejected(@NonNull ScimError value) { error=requireNonNull(value); }
        /** Returns the fixed rejection.
         * @return the error
     * @since 1.0.0 */
        @CheckReturnValue public @NonNull ScimError getError() { return error; }
        /** Returns a fixed redacted description.
         * @return the description
     * @since 1.0.0 */
        @Override public @NonNull String toString() { return "ScimPatchApplicationResult.Rejected{<redacted>}"; }
    }
}
