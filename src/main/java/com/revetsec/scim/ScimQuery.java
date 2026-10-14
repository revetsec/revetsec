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

/** Immutable engine-created query bound to its originating provider's schema and semantic registration.
 * Filter-policy approval and projection do not authorize a caller. Applications authenticate callers,
 * select tenants, authorize access and execute the returned normalized filter with stable ordering.
 * A page built from this query must be rendered by the originating provider or a base-URI-only copy.
 * Applications own cursor authenticity, context binding and expiry; core checks only bounded framing.
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

    /** Returns the exact registered resource-type object targeted by this query.
     * @return the originating registration
     * @since 1.0.0
     */
    public @NonNull ScimResourceType getResourceType() {
        return resourceType;
    }

    /** Returns the complete normalized, schema-bound, policy-approved filter, when supplied.
     * Applications execute this returned tree rather than the original request text; policy approval
     * does not establish caller authorization.
     * @return the approved filter, or empty when no filter was supplied
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull ScimFilter> getFilter() {
        return Optional.ofNullable(filter);
    }

    /** Returns this query's bound projection, separately from attribute authorization.
     * The selection retains the originating provider's semantic registration.
     * @return the bound projection
     * @since 1.0.0
     */
    public @NonNull ScimAttributeSelection getAttributeSelection() {
        return attributeSelection;
    }

    /** Returns the canonical schema-bound sort path, when requested.
     * Applications own appropriate string collation, primary-or-first multivalue selection,
     * absent-value ordering and a stable authoritative-ID tie-break.
     * @return the sort path, or empty when sorting was not requested
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull ScimAttributePath> getSortBy() {
        return Optional.ofNullable(sortBy);
    }

    /** Returns the selected direction when sortBy is present; otherwise returns empty.
     * A supplied sortBy with no sortOrder selects {@link ScimSortOrder#ASCENDING}.
     * @return the bound direction, or empty when sorting was not requested
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull ScimSortOrder> getSortOrder() {
        return Optional.ofNullable(sortOrder);
    }

    /** Returns the selected page-framing method.
     * An explicit cursor selects CURSOR, an explicit startIndex selects INDEX, and otherwise the
     * provider's configured default applies. Cursor and startIndex cannot both be supplied.
     * @return the selected pagination method
     * @since 1.0.0
     */
    public @NonNull ScimPaginationMethod getPaginationMethod() {
        return paginationMethod;
    }

    /** Returns the normalized one-based start index for INDEX framing, and empty for CURSOR.
     * The index defaults to one; explicitly supplied values below one become one.
     * @return the effective index, or empty for cursor pagination
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Long> getStartIndex() {
        return Optional.ofNullable(startIndex);
    }

    /** Returns the effective nonnegative page-size bound after defaults and configured caps.
     * INDEX requests are clamped to those caps; oversized CURSOR requests reject during parsing.
     * Zero denotes a count-only operation with no resources or traversal cursors and an accurate
     * totalResults value in the application-authored page.
     * @return the effective count
     * @since 1.0.0
     */
    public @NonNull Integer getCount() {
        return count;
    }

    /** Returns the original explicitly supplied signed count, before normalization or clamping.
     * Negative values remain visible here even though the effective count becomes zero. Empty means
     * the count field was absent. Applications can retain both this presence/original value and
     * {@link #getCount()} when checking a cursor's page-size context.
     * @return the original requested count, or empty when the field was absent
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Long> getRequestedCount() {
        return Optional.ofNullable(requestedCount);
    }

    /** Returns the original decoded opaque cursor when explicitly supplied.
     * An explicit empty string remains present and denotes the first cursor page. An absent cursor
     * also denotes the first page when CURSOR is the configured default. Core validates grammar and
     * framing; applications authenticate the token and bind tenant, caller, permissions, resource
     * type, approved query, sort, projection, page size and expiry.
     * @return the supplied cursor, including an explicit empty string, or empty when absent
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getCursor() {
        return Optional.ofNullable(cursor);
    }

    /** Reports first-page framing: true exactly for CURSOR with an absent or empty cursor.
     * This is always false for INDEX and establishes neither cursor authenticity nor storage state.
     * @return whether this is the first cursor page
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
