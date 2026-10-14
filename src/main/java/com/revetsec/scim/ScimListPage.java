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
import javax.annotation.concurrent.NotThreadSafe;

/** Application-authored page framing for one approved query; storage and count accuracy are app-owned.
 * INDEX pages require a nonnegative accurate totalResults and a consistent result window. CURSOR
 * pages declare more results exactly when a nextCursor is present; the first page has no
 * previousCursor. A short page alone does not prove exhaustion. For either method, a zero count
 * requires accurate totalResults, empty resources and no traversal cursors or more-results flag.
 * Construction checks framing and resource-type identity, not the truth of storage metadata or
 * cursor authenticity. The originating provider checks private query/resource associations before
 * rendering the page.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimListPage {
    private final @NonNull ScimQuery query;
    private final @NonNull List<@NonNull ScimResource> resources;
    private final @Nullable Long totalResults;
    private final @Nullable String nextCursor;
    private final @Nullable String previousCursor;
    private final boolean moreResultsAvailable;

    @SuppressWarnings(
            "ReferenceEquality") // Pages require the originating registration object, not
                                 // equivalent definitions.
    private ScimListPage(@NonNull Builder b) {
        query = b.query;
        resources = b.resources;
        totalResults = b.totalResults;
        nextCursor = b.nextCursor;
        previousCursor = b.previousCursor;
        moreResultsAvailable = b.moreResultsAvailable != null && b.moreResultsAvailable;
        if (resources.size() > query.getCount() || totalResults != null && totalResults < 0)
            throw new IllegalArgumentException("Inconsistent SCIM page counts.");
        if (query.getPaginationMethod() == ScimPaginationMethod.INDEX) {
            if (totalResults == null
                    || nextCursor != null
                    || previousCursor != null
                    || moreResultsAvailable)
                throw new IllegalArgumentException("Invalid index page framing.");
            long start = query.getStartIndex().orElseThrow();
            if (!resources.isEmpty()
                    && (start > totalResults || resources.size() > totalResults - start + 1))
                throw new IllegalArgumentException("Page exceeds total results.");
        } else {
            if (moreResultsAvailable != (nextCursor != null)
                    || query.isFirstCursorPage() && previousCursor != null)
                throw new IllegalArgumentException("Invalid cursor page framing.");
        }
        if (query.getCount() == 0
                && (totalResults == null
                        || nextCursor != null
                        || previousCursor != null
                        || moreResultsAvailable
                        || !resources.isEmpty()))
            throw new IllegalArgumentException("Invalid count-only page framing.");
        for (ScimResource r : resources)
            if (r.getResourceType() != query.getResourceType())
                throw new IllegalArgumentException("Foreign SCIM page resource type.");
        if (nextCursor != null && !cursor(nextCursor, query.maximumCursorCharacters())
                || previousCursor != null
                        && !cursor(previousCursor, query.maximumCursorCharacters()))
            throw new IllegalArgumentException("Invalid SCIM cursor.");
    }

    /** Returns the originating approved query whose bounds and projection frame this page.
     * @return the original query
     * @since 1.0.0
     */
    public @NonNull ScimQuery getQuery() {
        return query;
    }

    /** Returns the immutable application-supplied resource snapshot in represented page order.
     * Every resource uses the query's exact resource-type registration and the list is no larger
     * than the query's effective count.
     * @return the resources
     * @since 1.0.0
     */
    public @NonNull List<@NonNull ScimResource> getResources() {
        return resources;
    }

    /** Returns the application's declared accurate nonnegative matching-resource total, when present.
     * It is required for INDEX and every count-only page; ordinary CURSOR pages may omit it.
     * @return the declared total, or empty when omitted
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Long> getTotalResults() {
        return Optional.ofNullable(totalResults);
    }

    /** Returns the application's next-page token, present exactly when more results are declared.
     * The token's authenticity, context and validity remain application responsibilities.
     * @return the next cursor, or empty when no next page is declared
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getNextCursor() {
        return Optional.ofNullable(nextCursor);
    }

    /** Returns the application's previous-page token, when available.
     * The first cursor page, INDEX pages and count-only pages cannot have a previous token.
     * @return the previous cursor, or empty when unavailable
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getPreviousCursor() {
        return Optional.ofNullable(previousCursor);
    }

    /** Reports the application's more-results declaration, true exactly when nextCursor is present.
     * A short page does not itself imply false; INDEX and count-only pages require false.
     * @return whether a next cursor page is declared
     * @since 1.0.0
     */
    public @NonNull Boolean isMoreResultsAvailable() {
        return moreResultsAvailable;
    }

    static boolean cursor(@NonNull String value, int maximum) {
        if (value.isEmpty() || value.length() > maximum) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(c >= 'A' && c <= 'Z'
                    || c >= 'a' && c <= 'z'
                    || c >= '0' && c <= '9'
                    || c == '-'
                    || c == '_'
                    || c == '.'
                    || c == '~')) return false;
        }
        return true;
    }

    /** Starts page framing for an approved query with empty resources, absent total/cursors and
     * moreResultsAvailable false. Supply the metadata required by the query's framing before build.
     * @param query the originating approved query
     * @return builder
     * @since 1.0.0
     */
    public static @NonNull Builder withQuery(@NonNull ScimQuery query) {
        return new Builder(requireNonNull(query));
    }

    /** Returns a redacted diagnostic.
     * @return description
     * @since 1.0.0
     */
    @Override
    public @NonNull String toString() {
        return "ScimListPage{<redacted>}";
    }

    /** Mutable complete page configuration. Defaults are empty resources, absent total/cursors and
     * moreResultsAvailable false. Setters replace complete values; build checks the combined framing.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull ScimQuery query;
        private @NonNull List<@NonNull ScimResource> resources = List.of();
        private @Nullable Long totalResults;
        private @Nullable String nextCursor;
        private @Nullable String previousCursor;
        private @Nullable Boolean moreResultsAvailable;

        private Builder(@NonNull ScimQuery query) {
            this.query = query;
        }

        /** Replaces the complete resource snapshot.
         * @param value resources or null for empty
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder resources(@Nullable List<@NonNull ScimResource> value) {
            if (value != null && value.size() > query.getCount())
                throw new IllegalArgumentException("Too many page resources.");
            resources = value == null ? List.of() : List.copyOf(value);
            return this;
        }

        /** Replaces the application's accurate nonnegative matching-resource total; null restores absence.
         * INDEX and count-only framing require a total even when no resources are returned.
         * @param value the declared total, or null to omit it
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder totalResults(@Nullable Long value) {
            totalResults = value;
            return this;
        }

        /** Replaces the next-page token; null restores absence.
         * A token must be nonempty unreserved ASCII within the query's cursor bound. The application
         * owns its authenticity, context and validity. Presence must agree with moreResultsAvailable.
         * @param value the complete next token, or null for absence
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder nextCursor(@Nullable String value) {
            nextCursor = value;
            return this;
        }

        /** Replaces the previous-page token; null restores absence.
         * A token must be nonempty unreserved ASCII within the query's cursor bound. The application
         * owns its authenticity, context and validity; first, INDEX and count-only pages forbid it.
         * @param value the complete previous token, or null for absence
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder previousCursor(@Nullable String value) {
            previousCursor = value;
            return this;
        }

        /** Replaces the more-results declaration; null restores false.
         * CURSOR framing requires true exactly when nextCursor is present. INDEX and count-only
         * pages require false.
         * @param value the complete declaration, or null for false
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder moreResultsAvailable(@Nullable Boolean value) {
            moreResultsAvailable = value;
            return this;
        }

        /** Checks combined counts, cursors, resource-type identity and page framing, then creates the page.
         * This does not verify storage/count accuracy or token authenticity. INDEX requires totalResults
         * and a consistent window; CURSOR requires nextCursor iff moreResultsAvailable and no previous
         * cursor on the first page. Count-only pages require an accurate total, empty resources and no
         * traversal cursors or more-results declaration.
         * @return the immutable page
         * @throws IllegalArgumentException if trusted page values violate the query's bounds or framing
         * @since 1.0.0
         */
        public @NonNull ScimListPage build() {
            return new ScimListPage(this);
        }
    }
}
