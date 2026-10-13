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
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** A bounded create or replacement candidate; success is not authorization or persistence.
 *
     * @since 1.0.0
 */
@Immutable
public sealed interface ScimResourceParseResult permits ScimResourceParseResult.Succeeded, ScimResourceParseResult.Rejected {
    /** A normalized candidate and the canonical paths actually supplied by the accepted request.
     *
     * @since 1.0.0
     */
    @Immutable final class Succeeded implements ScimResourceParseResult {
        private final @NonNull ScimResource resource;
        private final @NonNull Set<@NonNull ScimAttributePath> suppliedAttributePaths;
        private final @NonNull Object semanticContext;
        Succeeded(@NonNull ScimResource resource, @NonNull Set<@NonNull ScimAttributePath> paths, @NonNull Object context) {
            this.resource = requireNonNull(resource);
            this.suppliedAttributePaths = Collections.unmodifiableSet(new LinkedHashSet<>(paths));
            this.semanticContext = requireNonNull(context);
        }
        /** Returns the candidate resource.
     * @return the resource
     * @since 1.0.0 */
        @CheckReturnValue public @NonNull ScimResource getResource() { return resource; }
        /** Returns canonical nested leaf paths actually supplied, distinct from the final resource contents.
         *
     * @return the immutable paths
     * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Set<@NonNull ScimAttributePath> getSuppliedAttributePaths() { return suppliedAttributePaths; }
        @NonNull Object getSemanticContext() { return semanticContext; }
        /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0 */
        @Override public @NonNull String toString() { return "ScimResourceParseResult.Succeeded{resource=<redacted>, paths=<redacted>}"; }
    }
    /** A fixed rejection with no partial candidate.
     * @since 1.0.0 */
    @Immutable final class Rejected implements ScimResourceParseResult {
        private final @NonNull ScimError error;
        Rejected(@NonNull ScimError error) { this.error = requireNonNull(error); }
        /** Returns the fixed error.
     * @return the error
     * @since 1.0.0 */
        @CheckReturnValue public @NonNull ScimError getError() { return error; }
        /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0 */
        @Override public @NonNull String toString() { return "ScimResourceParseResult.Rejected{error=<redacted>}"; }
    }
}
