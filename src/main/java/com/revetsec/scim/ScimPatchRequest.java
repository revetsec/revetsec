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
import java.util.List;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** An immutable ordered, schema-bound PATCH request. Parsing does not authorize a mutation.
 * The private registration proof prevents applying permissively parsed input under a different policy.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimPatchRequest {
    private final @NonNull ScimResourceType resourceType;
    private final @NonNull List<@NonNull ScimPatchOperation> operations;
    private final @NonNull Set<@NonNull ScimAttributePath> requestedAttributePaths;
    private final @NonNull Set<@NonNull ScimAttributePath> suppliedAttributePaths;
    private final @NonNull Object semanticContext;
    ScimPatchRequest(@NonNull ScimResourceType type, @NonNull List<@NonNull ScimPatchOperation> operations,
            @NonNull Set<@NonNull ScimAttributePath> requested, @NonNull Set<@NonNull ScimAttributePath> supplied,
            @NonNull Object context) {
        resourceType=requireNonNull(type); this.operations=List.copyOf(operations);
        requestedAttributePaths=Set.copyOf(requested); suppliedAttributePaths=Set.copyOf(supplied);
        semanticContext=requireNonNull(context);
    }
    /** Returns the registered target resource type.
     * @return the type
     * @since 1.0.0 */
    public @NonNull ScimResourceType getResourceType() { return resourceType; }
    /** Returns ordered operations with their original request indexes.
     * @return the immutable operations
     * @since 1.0.0 */
    public @NonNull List<@NonNull ScimPatchOperation> getOperations() { return operations; }
    /** Returns conservative canonical attempted targets and selector paths for application authorization.
     * @return the immutable requested paths
     * @since 1.0.0 */
    public @NonNull Set<@NonNull ScimAttributePath> getRequestedAttributePaths() { return requestedAttributePaths; }
    /** Returns only canonical leaf paths actually supplied, including explicit nulls and empty containers.
     * @return the immutable supplied paths
     * @since 1.0.0 */
    public @NonNull Set<@NonNull ScimAttributePath> getSuppliedAttributePaths() { return suppliedAttributePaths; }
    @NonNull Object getSemanticContext() { return semanticContext; }
    /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "ScimPatchRequest{<redacted>}"; }
}
