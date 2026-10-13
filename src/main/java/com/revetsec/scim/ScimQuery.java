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

import java.util.*;

import javax.annotation.concurrent.Immutable;

/** Immutable approved query; applications own tenant-scoped execution and stable ordering.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimQuery {
    private final @NonNull ScimResourceType resourceType;
    private final @Nullable ScimFilter filter;
    private final @NonNull ScimAttributeSelection attributeSelection;
    private final @Nullable ScimAttributePath sortBy;
    private final @Nullable ScimSortOrder sortOrder;
    private final @NonNull ScimPaginationMethod paginationMethod;
    private final @Nullable Long startIndex;
    private final @NonNull Integer count;
    private final @Nullable Long requestedCount;
    private final @Nullable String cursor;
    private final boolean firstCursorPage;
    private final @NonNull Object semanticContext;
    private final int maximumCursorCharacters;

    ScimQuery(
            @NonNull ScimResourceType resourceType,
            @Nullable ScimFilter filter,
            @NonNull ScimAttributeSelection attributeSelection,
            @Nullable ScimAttributePath sortBy,
            @Nullable ScimSortOrder sortOrder,
            @NonNull ScimPaginationMethod paginationMethod,
            @Nullable Long startIndex,
            @NonNull Integer count,
            @Nullable Long requestedCount,
            @Nullable String cursor,
            boolean firstCursorPage,
            @NonNull Object context,
            int maximumCursorCharacters) {
        this.resourceType = resourceType;
        this.filter = filter;
        this.attributeSelection = attributeSelection;
        this.sortBy = sortBy;
        this.sortOrder = sortOrder;
        this.paginationMethod = paginationMethod;
        this.startIndex = startIndex;
        this.count = count;
        this.requestedCount = requestedCount;
        this.cursor = cursor;
        this.firstCursorPage = firstCursorPage;
        semanticContext = requireNonNull(context);
        this.maximumCursorCharacters = maximumCursorCharacters;
    }

    /** Returns the query resourceType.
     * @return resourceType
     * @since 1.0.0
     */
    public @NonNull ScimResourceType getResourceType() {
        return resourceType;
    }

    /** Returns the query filter.
     * @return filter
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull ScimFilter> getFilter() {
        return Optional.ofNullable(filter);
    }

    /** Returns the query attributeSelection.
     * @return attributeSelection
     * @since 1.0.0
     */
    public @NonNull ScimAttributeSelection getAttributeSelection() {
        return attributeSelection;
    }

    /** Returns the query sortBy.
     * @return sortBy
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull ScimAttributePath> getSortBy() {
        return Optional.ofNullable(sortBy);
    }

    /** Returns the query sortOrder.
     * @return sortOrder
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull ScimSortOrder> getSortOrder() {
        return Optional.ofNullable(sortOrder);
    }

    /** Returns the query paginationMethod.
     * @return paginationMethod
     * @since 1.0.0
     */
    public @NonNull ScimPaginationMethod getPaginationMethod() {
        return paginationMethod;
    }

    /** Returns the query startIndex.
     * @return startIndex
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Long> getStartIndex() {
        return Optional.ofNullable(startIndex);
    }

    /** Returns the query count.
     * @return count
     * @since 1.0.0
     */
    public @NonNull Integer getCount() {
        return count;
    }

    /** Returns the query requestedCount.
     * @return requestedCount
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Long> getRequestedCount() {
        return Optional.ofNullable(requestedCount);
    }

    /** Returns the query cursor.
     * @return cursor
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getCursor() {
        return Optional.ofNullable(cursor);
    }

    /** Reports first cursor-page framing.
     * @return first-page state
     * @since 1.0.0
     */
    public @NonNull Boolean isFirstCursorPage() {
        return firstCursorPage;
    }

    @NonNull Object getSemanticContext() {
        return semanticContext;
    }

    int maximumCursorCharacters() {
        return maximumCursorCharacters;
    }

    /** Returns a redacted diagnostic.
     * @return description
     * @since 1.0.0
     */
    @Override
    public @NonNull String toString() {
        return "ScimQuery{<redacted>}";
    }
}
