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
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable advertised pagination capabilities. A cursor timeout is a minimum validity
 * commitment the application must honor, rather than a core cursor-expiry implementation.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimPaginationConfig {
    private final boolean indexSupported;
    private final boolean cursorSupported;
    private final @NonNull ScimPaginationMethod defaultMethod;
    private final int defaultPageSize;
    private final int maximumPageSize;
    private final @Nullable Duration cursorTimeout;

    private ScimPaginationConfig(@NonNull Builder builder) {
        indexSupported = builder.indexSupported == null || builder.indexSupported;
        cursorSupported = Boolean.TRUE.equals(builder.cursorSupported);
        defaultMethod = builder.defaultMethod == null ? ScimPaginationMethod.INDEX : builder.defaultMethod;
        defaultPageSize = Limits.SCIM_DEFAULT_PAGE_SIZE.require(builder.defaultPageSize == null
                ? Limits.SCIM_DEFAULT_PAGE_SIZE.getDefaultIntValue() : builder.defaultPageSize);
        maximumPageSize = Limits.SCIM_PAGE_SIZE.require(builder.maximumPageSize == null
                ? Limits.SCIM_PAGE_SIZE.getDefaultIntValue() : builder.maximumPageSize);
        cursorTimeout = builder.cursorTimeout;
        if (cursorTimeout != null) Limits.SCIM_CURSOR_TIMEOUT.require(cursorTimeout);
        if (!indexSupported && !cursorSupported)
            throw new IllegalArgumentException("At least one SCIM pagination method must be supported.");
        if (defaultMethod == ScimPaginationMethod.INDEX && !indexSupported
                || defaultMethod == ScimPaginationMethod.CURSOR && !cursorSupported)
            throw new IllegalArgumentException("The default SCIM pagination method must be supported.");
        if (defaultPageSize > maximumPageSize)
            throw new IllegalArgumentException("SCIM default page size must not exceed maximum page size.");
        if (cursorSupported && cursorTimeout == null)
            throw new IllegalStateException("SCIM cursor support requires an explicit validity commitment.");
    }

    /**
     * Starts pagination configuration with index enabled, cursor disabled and page size 100/1000.
     * @return a new builder
     * @since 1.0.0
     */
    public static @NonNull Builder builder() { return new Builder(); }

    /**
     * Returns whether index pagination is supported.
     * @return whether index pagination is supported
     * @since 1.0.0
     */
    public @NonNull Boolean isIndexSupported() { return indexSupported; }

    /**
     * Returns whether cursor pagination is supported.
     * @return whether cursor pagination is supported
     * @since 1.0.0
     */
    public @NonNull Boolean isCursorSupported() { return cursorSupported; }

    /**
     * Returns the default pagination method.
     * @return the default pagination method
     * @since 1.0.0
     */
    public @NonNull ScimPaginationMethod getDefaultMethod() { return defaultMethod; }

    /**
     * Returns the default page size.
     * @return the default page size
     * @since 1.0.0
     */
    public @NonNull Integer getDefaultPageSize() { return defaultPageSize; }

    /**
     * Returns the maximum accepted page size.
     * @return the maximum accepted page size
     * @since 1.0.0
     */
    public @NonNull Integer getMaximumPageSize() { return maximumPageSize; }

    /**
     * Returns the optional minimum cursor-validity commitment.
     * @return the optional minimum cursor-validity commitment
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Duration> getCursorTimeout() { return Optional.ofNullable(cursorTimeout); }

    /**
     * Compares all advertised pagination characteristics.
     * @param other the comparison value
     * @return whether configurations are equal
     * @since 1.0.0
     */
    @Override public boolean equals(@Nullable Object other) {
        return this == other || other instanceof ScimPaginationConfig value
                && indexSupported == value.indexSupported && cursorSupported == value.cursorSupported
                && defaultMethod == value.defaultMethod && defaultPageSize == value.defaultPageSize
                && maximumPageSize == value.maximumPageSize && Objects.equals(cursorTimeout, value.cursorTimeout);
    }

    /**
     * Returns the configuration hash.
     * @return the configuration hash
     * @since 1.0.0
     */
    @Override public int hashCode() {
        return Objects.hash(indexSupported, cursorSupported, defaultMethod, defaultPageSize, maximumPageSize, cursorTimeout);
    }

    /**
     * Returns a fixed configuration description.
     * @return a fixed description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimPaginationConfig{<redacted>}"; }

    /**
     * Mutable, non-thread-safe pagination configuration; null restores the stated default.
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private @Nullable Boolean indexSupported;
        private @Nullable Boolean cursorSupported;
        private @Nullable ScimPaginationMethod defaultMethod;
        private @Nullable Integer defaultPageSize;
        private @Nullable Integer maximumPageSize;
        private @Nullable Duration cursorTimeout;
        private Builder() {}

        /**
         * Sets indexSupported; null restores true.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder indexSupported(@Nullable Boolean value) { indexSupported = value; return this; }

        /**
         * Sets cursorSupported; null restores false.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder cursorSupported(@Nullable Boolean value) { cursorSupported = value; return this; }

        /**
         * Sets defaultMethod; null restores INDEX.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder defaultMethod(@Nullable ScimPaginationMethod value) { defaultMethod = value; return this; }

        /**
         * Sets defaultPageSize; null restores 100.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder defaultPageSize(@Nullable Integer value) { defaultPageSize = value; return this; }

        /**
         * Sets maximumPageSize; null restores 1000.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder maximumPageSize(@Nullable Integer value) { maximumPageSize = value; return this; }

        /**
         * Sets cursorTimeout; null restores absent.
         * @param value the setting, or null to restore its default
         * @return this builder
         * @since 1.0.0
         */
        public @NonNull Builder cursorTimeout(@Nullable Duration value) { cursorTimeout = value; return this; }

        /**
         * Checks bounds and advertised method/timeout consistency and creates an immutable snapshot.
         * @return pagination capabilities
         * @since 1.0.0
         */
        public @NonNull ScimPaginationConfig build() { return new ScimPaginationConfig(this); }
    }
}
