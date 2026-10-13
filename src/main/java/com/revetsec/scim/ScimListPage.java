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

/** Application-authored page framing for one approved query; storage/count accuracy is app-owned.
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

    /** Returns the page query.
     * @return query
     * @since 1.0.0
     */
    public @NonNull ScimQuery getQuery() {
        return query;
    }

    /** Returns the page resources.
     * @return resources
     * @since 1.0.0
     */
    public @NonNull List<@NonNull ScimResource> getResources() {
        return resources;
    }

    /** Returns the page totalResults.
     * @return totalResults
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Long> getTotalResults() {
        return Optional.ofNullable(totalResults);
    }

    /** Returns the page nextCursor.
     * @return nextCursor
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getNextCursor() {
        return Optional.ofNullable(nextCursor);
    }

    /** Returns the page previousCursor.
     * @return previousCursor
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getPreviousCursor() {
        return Optional.ofNullable(previousCursor);
    }

    /** Returns the page moreResultsAvailable.
     * @return moreResultsAvailable
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

    /** Starts page framing for an approved query.
     * @param query original query
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

    /** Mutable complete page configuration.
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

        /** Replaces totalResults; null restores absence or false.
         * @param value complete value or null
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder totalResults(@Nullable Long value) {
            totalResults = value;
            return this;
        }

        /** Replaces nextCursor; null restores absence or false.
         * @param value complete value or null
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder nextCursor(@Nullable String value) {
            nextCursor = value;
            return this;
        }

        /** Replaces previousCursor; null restores absence or false.
         * @param value complete value or null
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder previousCursor(@Nullable String value) {
            previousCursor = value;
            return this;
        }

        /** Replaces moreResultsAvailable; null restores absence or false.
         * @param value complete value or null
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder moreResultsAvailable(@Nullable Boolean value) {
            moreResultsAvailable = value;
            return this;
        }

        /** Creates checked page framing.
         * @return page
         * @since 1.0.0
         */
        public @NonNull ScimListPage build() {
            return new ScimListPage(this);
        }
    }
}
