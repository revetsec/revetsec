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
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** An atomic candidate published only after every PATCH operation and final schema check succeeds.
 * This value is neither authorization nor proof of persistence. Applications own version/timestamp updates.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimPatchResult {
    private final @NonNull ScimResource resource;
    private final boolean modified;
    private final @NonNull Set<@NonNull ScimAttributePath> requestedAttributePaths;
    private final @NonNull Set<@NonNull ScimAttributePath> modifiedAttributePaths;
    private final @NonNull Set<@NonNull ScimAttributePath> suppliedAttributePaths;
    private final @NonNull Object semanticContext;
    ScimPatchResult(@NonNull ScimResource resource, boolean modified,
            @NonNull Set<@NonNull ScimAttributePath> requested, @NonNull Set<@NonNull ScimAttributePath> changed,
            @NonNull Set<@NonNull ScimAttributePath> supplied, @NonNull Object context) {
        this.resource=requireNonNull(resource); this.modified=modified; requestedAttributePaths=Set.copyOf(requested);
        modifiedAttributePaths=Set.copyOf(changed); suppliedAttributePaths=Set.copyOf(supplied); semanticContext=requireNonNull(context);
    }
    /** Returns the complete candidate resource.
     * @return the resource
     * @since 1.0.0 */
    public @NonNull ScimResource getResource() { return resource; }
    /** Returns whether the final resource differs from the original after all ordered operations.
     * @return the final difference flag
     * @since 1.0.0 */
    public @NonNull Boolean isModified() { return modified; }
    /** Returns all conservative attempted and selector paths, including no-op attempts.
     * @return the immutable requested paths
     * @since 1.0.0 */
    public @NonNull Set<@NonNull ScimAttributePath> getRequestedAttributePaths() { return requestedAttributePaths; }
    /** Returns conservative effective paths, including induced primary/container/schema changes.
     * @return the immutable modified paths
     * @since 1.0.0 */
    public @NonNull Set<@NonNull ScimAttributePath> getModifiedAttributePaths() { return modifiedAttributePaths; }
    /** Returns canonical paths actually supplied by the request, for write-response projection.
     * @return the immutable supplied paths
     * @since 1.0.0 */
    public @NonNull Set<@NonNull ScimAttributePath> getSuppliedAttributePaths() { return suppliedAttributePaths; }
    @NonNull Object getSemanticContext() { return semanticContext; }
    /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "ScimPatchResult{<redacted>}"; }
}
