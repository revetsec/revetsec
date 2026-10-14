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
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/** A schema-bound operation created only by the PATCH parser. Its value may contain personal data.
 * Filtered paths expose the outer attribute, a same-element predicate, and an optional suffix.
 * An unfiltered subattribute remains part of the attribute path.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimPatchOperation {
    private final int operationIndex;
    private final @NonNull ScimPatchOperationType operationType;
    private final @Nullable ScimAttributePath attributePath;
    private final @Nullable ScimFilter valueFilter;
    private final @Nullable String subAttributeName;
    private final @Nullable JsonValue value;
    ScimPatchOperation(int index, @NonNull ScimPatchOperationType type,
            @Nullable ScimAttributePath path, @Nullable ScimFilter filter,
            @Nullable String suffix, @Nullable JsonValue value) {
        this.operationIndex=index; this.operationType=requireNonNull(type); this.attributePath=path;
        this.valueFilter=filter; this.subAttributeName=suffix; this.value=value;
    }
    /** Returns the zero-based original request index, preserved through reduction.
     * @return the original index
     * @since 1.0.0 */
    public @NonNull Integer getOperationIndex() { return operationIndex; }
    /** Returns the operation kind.
     * @return the kind
     * @since 1.0.0 */
    public @NonNull ScimPatchOperationType getOperationType() { return operationType; }
    /** Returns the canonical path, absent for a resource-object operation.
     * @return the path
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull ScimAttributePath> getAttributePath() { return Optional.ofNullable(attributePath); }
    /** Returns the bound same-element selector, when present.
     * @return the predicate
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull ScimFilter> getValueFilter() { return Optional.ofNullable(valueFilter); }
    /** Returns the canonical suffix following a filtered path.
     * @return the suffix
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull String> getSubAttributeName() { return Optional.ofNullable(subAttributeName); }
    /** Returns the normalized value. Explicit JSON null is present; an absent remove value is empty.
     * @return the value, which may contain personal data
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull JsonValue> getValue() { return Optional.ofNullable(value); }
    /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "ScimPatchOperation{<redacted>}"; }
}
