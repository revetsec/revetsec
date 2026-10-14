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

import javax.annotation.concurrent.Immutable;

/** Conservative membership reduction, full-evaluation fallback, or a fixed rejection.
 * @since 1.0.0
 */
@Immutable
public sealed interface ScimMembershipPatchResult permits ScimMembershipPatchResult.Reduced,
        ScimMembershipPatchResult.RequiresFullEvaluation, ScimMembershipPatchResult.Rejected {
    /** Ordered ID instructions; success does not establish modification or authorization.
     * @since 1.0.0
     */
    @Immutable
    final class Reduced implements ScimMembershipPatchResult {
        private final @NonNull ScimMembershipPatch membershipPatch;
        Reduced(@NonNull ScimMembershipPatch membershipPatch) { this.membershipPatch = requireNonNull(membershipPatch); }

        /** Returns the ordered membership instructions and remaining operations.
         * @return membership patch
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimMembershipPatch getMembershipPatch() { return membershipPatch; }

        /** Returns a fixed redacted diagnostic.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimMembershipPatchResult.Reduced{<redacted>}"; }
    }

    /** Valid operations whose semantics cannot be represented as the conservative ID-only instructions.
     * @since 1.0.0
     */
    @Immutable
    final class RequiresFullEvaluation implements ScimMembershipPatchResult {
        static final @NonNull RequiresFullEvaluation INSTANCE = new RequiresFullEvaluation();
        private RequiresFullEvaluation() {}

        /** Returns a fixed redacted diagnostic.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimMembershipPatchResult.RequiresFullEvaluation"; }
    }

    /** A fixed error without partial executable instructions.
     * @since 1.0.0
     */
    @Immutable
    final class Rejected implements ScimMembershipPatchResult {
        private final @NonNull ScimError error;
        Rejected(@NonNull ScimError error) { this.error = requireNonNull(error); }

        /** Returns the fixed error.
         * @return fixed error
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull ScimError getError() { return error; }

        /** Returns a fixed redacted diagnostic.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimMembershipPatchResult.Rejected{<redacted>}"; }
    }
}
