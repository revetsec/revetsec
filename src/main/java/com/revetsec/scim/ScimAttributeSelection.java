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

/** Bound projection with private registration provenance; never grants access.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimAttributeSelection {
    private final @NonNull ScimResourceType resourceType;
    private final @NonNull Set<@NonNull ScimAttributePath> includedAttributes;
    private final @NonNull Set<@NonNull ScimAttributePath> excludedAttributes;
    private final boolean explicit;
    private final @NonNull Object semanticContext;

    ScimAttributeSelection(
            @NonNull ScimResourceType type,
            @NonNull Set<@NonNull ScimAttributePath> included,
            @NonNull Set<@NonNull ScimAttributePath> excluded,
            boolean explicit,
            @NonNull Object context) {
        resourceType = requireNonNull(type);
        includedAttributes = Set.copyOf(included);
        excludedAttributes = Set.copyOf(excluded);
        this.explicit = explicit;
        semanticContext = requireNonNull(context);
    }

    /** Returns the registered resource type.
     * @return type
     * @since 1.0.0
     */
    public @NonNull ScimResourceType getResourceType() {
        return resourceType;
    }

    /** Returns complete inclusion paths.
     * @return immutable paths
     * @since 1.0.0
     */
    public @NonNull Set<@NonNull ScimAttributePath> getIncludedAttributes() {
        return includedAttributes;
    }

    /** Returns complete exclusion paths.
     * @return immutable paths
     * @since 1.0.0
     */
    public @NonNull Set<@NonNull ScimAttributePath> getExcludedAttributes() {
        return excludedAttributes;
    }

    /** Reports whether projection was supplied.
     * @return explicit state
     * @since 1.0.0
     */
    public @NonNull Boolean isExplicit() {
        return explicit;
    }

    /** Checks raw projection membership with parent/child expansion.
     * Returned characteristics and caller authorization are separate checks.
     * @param path canonical path
     * @return whether the path participates in the selection
     * @since 1.0.0
     */
    public @NonNull Boolean includes(@NonNull ScimAttributePath path) {
        requireNonNull(path);
        for (ScimAttributePath excluded : excludedAttributes)
            if (covers(excluded, path)) return false;
        if (includedAttributes.isEmpty()) return true;
        for (ScimAttributePath included : includedAttributes)
            if (covers(included, path) || covers(path, included)) return true;
        return false;
    }

    static boolean covers(@NonNull ScimAttributePath parent, @NonNull ScimAttributePath child) {
        return parent.getSchemaId().equals(child.getSchemaId())
                && com.revetsec.internal.json.AsciiCase.fold(parent.getAttributeName())
                        .equals(com.revetsec.internal.json.AsciiCase.fold(child.getAttributeName()))
                && (parent.getSubAttributeName().isEmpty() || parent.equals(child));
    }

    @NonNull Object getSemanticContext() {
        return semanticContext;
    }

    /** Returns a fixed diagnostic.
     * @return description
     * @since 1.0.0
     */
    @Override
    public @NonNull String toString() {
        return "ScimAttributeSelection{<redacted>}";
    }
}
