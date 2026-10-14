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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Ordered, ID-only Group membership instructions and the remaining resource operations.
 * Applications execute both parts in original operation-index order under one authorization
 * decision, transaction and version predicate. Existing member metadata and represented order
 * must be retained when adding an existing ID or retaining an ID during replacement; removing
 * then adding an ID creates a new member without the removed metadata.
 * <p>
 * Reduction does not inspect current membership and cannot establish whether anything changed.
 * Applications require assigned, unique member IDs in their keyed storage snapshot and preserve
 * whether the optional members attribute is absent or holds an empty array. Duplicate IDs in a
 * whole-array replacement require full evaluation.
 * Explicit value getters may disclose personal data; diagnostics redact them.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimMembershipPatch {
    private final @NonNull ScimResourceType resourceType;
    private final @NonNull List<@NonNull Step> steps;
    private final @Nullable ScimPatchRequest remainingPatchRequest;
    private final @NonNull Set<@NonNull ScimAttributePath> requestedAttributePaths;
    private final @NonNull Set<@NonNull ScimAttributePath> suppliedAttributePaths;

    ScimMembershipPatch(@NonNull ScimResourceType resourceType,
            @NonNull List<@NonNull Step> steps, @Nullable ScimPatchRequest remainingPatchRequest,
            @NonNull Set<@NonNull ScimAttributePath> requestedAttributePaths,
            @NonNull Set<@NonNull ScimAttributePath> suppliedAttributePaths) {
        this.resourceType = requireNonNull(resourceType);
        this.steps = List.copyOf(steps);
        this.remainingPatchRequest = remainingPatchRequest;
        this.requestedAttributePaths = Collections.unmodifiableSet(new LinkedHashSet<>(requestedAttributePaths));
        this.suppliedAttributePaths = Collections.unmodifiableSet(new LinkedHashSet<>(suppliedAttributePaths));
    }

    /** Returns the original resource-type registration.
     * @return resource type
     * @since 1.0.0
     */
    public @NonNull ScimResourceType getResourceType() { return resourceType; }

    /** Returns membership steps in original request order.
     * @return immutable ordered steps
     * @since 1.0.0
     */
    public @NonNull List<@NonNull Step> getSteps() { return steps; }

    /** Returns remaining nonmember operations with their original indexes and private provenance.
     * @return the remaining request, or empty when every operation was reduced
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull ScimPatchRequest> getRemainingPatchRequest() {
        return Optional.ofNullable(remainingPatchRequest);
    }

    /** Returns attempted canonical paths from the complete original request, including no-op attempts.
     * @return immutable requested paths
     * @since 1.0.0
     */
    public @NonNull Set<@NonNull ScimAttributePath> getRequestedAttributePaths() { return requestedAttributePaths; }

    /** Returns canonical paths actually supplied by the complete original request.
     * @return immutable supplied paths
     * @since 1.0.0
     */
    public @NonNull Set<@NonNull ScimAttributePath> getSuppliedAttributePaths() { return suppliedAttributePaths; }

    /** Returns a fixed redacted diagnostic.
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimMembershipPatch{<redacted>}"; }

    /** One executable membership instruction at its original zero-based operation position.
     * @since 1.0.0
     */
    @Immutable
    @CheckReturnValue
    public static final class Step {
        private final int operationIndex;
        private final @NonNull Kind kind;
        private final @NonNull List<@NonNull String> values;

        Step(int operationIndex, @NonNull Kind kind, @NonNull List<@NonNull String> values) {
            this.operationIndex = operationIndex;
            this.kind = requireNonNull(kind);
            this.values = List.copyOf(values);
        }

        /** Returns the original zero-based operation index.
         * @return original index
         * @since 1.0.0
         */
        public @NonNull Integer getOperationIndex() { return operationIndex; }

        /** Returns the instruction kind.
         * @return kind
         * @since 1.0.0
         */
        public @NonNull Kind getKind() { return kind; }

        /** Returns exact IDs in input order; CLEAR has an empty list.
         * @return immutable ID values, which may contain personal data
         * @since 1.0.0
         */
        public @NonNull List<@NonNull String> getValues() { return values; }

        /** Returns a fixed redacted diagnostic.
         * @return redacted description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "ScimMembershipPatch.Step{<redacted>}"; }
    }

    /** Ordered instruction kinds; compare member IDs exactly, regardless of text collation.
     * @since 1.0.0
     */
    @Immutable
    public enum Kind {
        /** Append IDs absent from current membership, preserving existing metadata and order.
         * An empty values list is a no-op that preserves absent, empty or assigned membership.
         * @since 1.0.0
         */
        ADD_IDS,
        /** Remove the exact IDs if present; absent IDs are no-ops.
         * Removing the last value from an existing members array leaves it present and empty.
         * @since 1.0.0
         */
        REMOVE_IDS,
        /** Remove the optional members attribute, yielding absence rather than a present empty array.
         * This differs from REPLACE_IDS with an empty list.
         * @since 1.0.0
         */
        CLEAR,
        /** Replace represented sequence, retaining metadata for surviving exact IDs; an empty list represents an empty array.
         * @since 1.0.0
         */
        REPLACE_IDS
    }
}
