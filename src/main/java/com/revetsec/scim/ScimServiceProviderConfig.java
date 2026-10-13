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
import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable SCIM capability advertisement. The application must implement every enabled
 * operation; the facade checks registered filtering policies and configured processing bounds.
 * Bulk is always unsupported. Builders and copying perform no application callbacks.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimServiceProviderConfig {
    private final boolean patchSupported;
    private final boolean filterSupported;
    private final boolean sortSupported;
    private final boolean changePasswordSupported;
    private final boolean etagSupported;
    private final int filterMaximumResults;
    private final @NonNull ScimPaginationConfig pagination;
    private final @NonNull List<@NonNull ScimAuthenticationScheme> authenticationSchemes;
    private final @Nullable URI documentationUri;

    private ScimServiceProviderConfig(@NonNull Builder builder) {
        patchSupported = Boolean.TRUE.equals(builder.patchSupported);
        filterSupported = Boolean.TRUE.equals(builder.filterSupported);
        sortSupported = Boolean.TRUE.equals(builder.sortSupported);
        changePasswordSupported = Boolean.TRUE.equals(builder.changePasswordSupported);
        etagSupported = builder.etagSupported == null || builder.etagSupported;
        filterMaximumResults = Limits.SCIM_PAGE_SIZE.require(builder.filterMaximumResults == null
                ? Limits.SCIM_PAGE_SIZE.getDefaultIntValue() : builder.filterMaximumResults);
        pagination = builder.pagination == null ? ScimPaginationConfig.builder().build() : builder.pagination;
        authenticationSchemes = builder.authenticationSchemes;
        documentationUri = builder.documentationUri;
        int primaryCount = 0;
        for (ScimAuthenticationScheme scheme : authenticationSchemes)
            if (scheme.isPrimary()) primaryCount++;
        if (primaryCount > 1)
            throw new IllegalArgumentException("SCIM authentication schemes may have only one primary value.");
    }

    /**
     * Starts with PATCH/filter/sort/password disabled, ETags enabled and default pagination.
     * @return a new builder
     * @since 1.0.0
     */
    public static @NonNull Builder builder() { return new Builder(); }

    /**
     * Returns whether PATCH is advertised.
     * @return whether PATCH is advertised
     * @since 1.0.0
     */
    public @NonNull Boolean isPatchSupported() { return patchSupported; }

    /**
     * Returns whether filtering is advertised.
     * @return whether filtering is advertised
     * @since 1.0.0
     */
    public @NonNull Boolean isFilterSupported() { return filterSupported; }

    /**
     * Returns whether sorting is advertised.
     * @return whether sorting is advertised
     * @since 1.0.0
     */
    public @NonNull Boolean isSortSupported() { return sortSupported; }

    /**
     * Returns whether password changes are advertised.
     * @return whether password changes are advertised
     * @since 1.0.0
     */
    public @NonNull Boolean isChangePasswordSupported() { return changePasswordSupported; }

    /**
     * Returns whether entity tags are advertised.
     * @return whether entity tags are advertised
     * @since 1.0.0
     */
    public @NonNull Boolean isEtagSupported() { return etagSupported; }

    /**
     * Returns the maximum advertised filtered result count.
     * @return the maximum advertised filtered result count
     * @since 1.0.0
     */
    public @NonNull Integer getFilterMaximumResults() { return filterMaximumResults; }

    /**
     * Returns the immutable pagination advertisement.
     * @return the immutable pagination advertisement
     * @since 1.0.0
     */
    public @NonNull ScimPaginationConfig getPagination() { return pagination; }

    /**
     * Returns the immutable authentication-scheme descriptions.
     * @return the immutable authentication-scheme descriptions
     * @since 1.0.0
     */
    public @NonNull List<@NonNull ScimAuthenticationScheme> getAuthenticationSchemes() { return authenticationSchemes; }

    /**
     * Returns the optional documentation URI.
     * @return the optional documentation URI
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull URI> getDocumentationUri() { return Optional.ofNullable(documentationUri); }

    /**
     * Compares all advertised capability characteristics.
     * @param other the comparison value
     * @return whether advertisements are equal
     * @since 1.0.0
     */
    @Override public boolean equals(@Nullable Object other) {
        return this == other || other instanceof ScimServiceProviderConfig value
                && patchSupported == value.patchSupported && filterSupported == value.filterSupported
                && sortSupported == value.sortSupported && changePasswordSupported == value.changePasswordSupported
                && etagSupported == value.etagSupported && filterMaximumResults == value.filterMaximumResults
                && pagination.equals(value.pagination) && authenticationSchemes.equals(value.authenticationSchemes)
                && Objects.equals(documentationUri, value.documentationUri);
    }

    /**
     * Returns the advertisement hash.
     * @return the advertisement hash
     * @since 1.0.0
     */
    @Override public int hashCode() {
        return Objects.hash(patchSupported, filterSupported, sortSupported, changePasswordSupported,
                etagSupported, filterMaximumResults, pagination, authenticationSchemes, documentationUri);
    }

    /**
     * Returns a fixed redacted description.
     * @return a fixed redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimServiceProviderConfig{<redacted>}"; }

    /**
     * Mutable, non-thread-safe capability configuration; null restores the stated default.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private @Nullable Boolean patchSupported;
        private @Nullable Boolean filterSupported;
        private @Nullable Boolean sortSupported;
        private @Nullable Boolean changePasswordSupported;
        private @Nullable Boolean etagSupported;
        private @Nullable Integer filterMaximumResults;
        private @Nullable ScimPaginationConfig pagination;
        private @NonNull List<@NonNull ScimAuthenticationScheme> authenticationSchemes = List.of();
        private @Nullable URI documentationUri;
        private Builder() {}

        /**
         * Sets patchSupported; null restores false.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder patchSupported(@Nullable Boolean value) { patchSupported = value; return this; }

        /**
         * Sets filterSupported; null restores false.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder filterSupported(@Nullable Boolean value) { filterSupported = value; return this; }

        /**
         * Sets sortSupported; null restores false.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder sortSupported(@Nullable Boolean value) { sortSupported = value; return this; }

        /**
         * Sets changePasswordSupported; null restores false.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder changePasswordSupported(@Nullable Boolean value) { changePasswordSupported = value; return this; }

        /**
         * Sets etagSupported; null restores true.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder etagSupported(@Nullable Boolean value) { etagSupported = value; return this; }

        /**
         * Sets filterMaximumResults; null restores 1000.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder filterMaximumResults(@Nullable Integer value) { filterMaximumResults = value; return this; }

        /**
         * Sets pagination; null restores fresh defaults.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder pagination(@Nullable ScimPaginationConfig value) { pagination = value; return this; }

        /**
         * Sets authenticationSchemes; null restores empty.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder authenticationSchemes(@Nullable List<@NonNull ScimAuthenticationScheme> value) { if (value == null) authenticationSchemes = List.of();
            else {
                ScimSchemas.requireDefinitionCount(value.size());
                for (ScimAuthenticationScheme scheme : value) Objects.requireNonNull(scheme);
                authenticationSchemes = List.copyOf(value);
            }; return this; }

        /**
         * Sets documentationUri; null restores absent.
         * @param value the replacement, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder documentationUri(@Nullable URI value) { documentationUri = value == null ? null : ScimSchemas.requireDocumentationUri(value); return this; }

        /**
         * Checks bounded advertisement characteristics and creates an immutable snapshot.
         * @return the capability advertisement
         * @since 1.0.0
         */
        public @NonNull ScimServiceProviderConfig build() { return new ScimServiceProviderConfig(this); }
    }
}
