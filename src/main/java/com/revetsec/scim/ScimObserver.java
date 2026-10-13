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
import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.Immutable;

/**
 * Fixed redacted events for SCIM operations. Hooks must be fast, deterministic and thread-safe.
 * The facade contains ordinary hook failures and restores interruption; fatal VM errors escape.
 * Events never carry request bodies, filters, identifiers, credentials or arbitrary exceptions.
 * @since 1.0.0
 */
@ThreadSafe
public interface ScimObserver {
    /**
     * Returns the shared observer whose hooks do nothing.
     * @return the disabled observer
     * @since 1.0.0
     */
    @CheckReturnValue
    static @NonNull ScimObserver disabledInstance() { return DisabledScimObserver.INSTANCE; }

    /**
     * Called once before a public processing operation.
     * @param operation the fixed operation kind
     * @since 1.0.0
     */
    default void willProcess(@NonNull Operation operation) {}

    /**
     * Called once when a public processing operation returns its direct result.
     * @param operation the fixed operation kind
     * @param outcome the fixed result classification
     * @since 1.0.0
     */
    default void didProcess(@NonNull Operation operation, @NonNull Outcome outcome) {}

    /**
     * Called once when an ordinary unexpected processing failure prevents a direct result.
     * @param operation the fixed operation kind
     * @since 1.0.0
     */
    default void didFailToProcess(@NonNull Operation operation) {}

    /**
     * Called once per feature actually used during a public operation.
     * @param feature the explicitly configured fixed feature
     * @since 1.0.0
     */
    default void didUseCompatibilityFeature(@NonNull ScimCompatibilityFeature feature) {}

    /**
     * Fixed public processing operation kinds, including separately sequenced PATCH operations.
     * @since 1.0.0
     */
    @Immutable
    enum Operation {
        /** Parse and approve a filter. */
        FILTER,
        /** Parse a collection query. */
        QUERY,
        /** Parse a SearchRequest. */
        SEARCH,
        /** Parse a projection. */
        ATTRIBUTE_SELECTION,
        /** Parse a create candidate. */
        RESOURCE_CREATE,
        /** Parse a replacement candidate. */
        RESOURCE_REPLACE,
        /** Parse a PATCH request. */
        PATCH_PARSE,
        /** Apply a PATCH request. */
        PATCH_APPLY,
        /** Reduce reviewed membership steps. */
        MEMBERSHIP_REDUCE,
        /** Validate a request media type. */
        CONTENT_TYPE,
        /** Check If-Match. */
        IF_MATCH,
        /** Check If-None-Match. */
        IF_NONE_MATCH,
        /** Prepare a bounded response. */
        RESPONSE_PREPARE,
        /** Evaluate an approved filter. */
        FILTER_EVALUATE
    }

    /**
     * Fixed direct-result classifications, without data or exception payloads.
     * @since 1.0.0
     */
    @Immutable
    enum Outcome {
        /** A checked candidate or query was produced. */
        SUCCEEDED,
        /** A bounded response was prepared. */
        PREPARED,
        /** Processing rejected input. */
        REJECTED,
        /** A precondition was satisfied. */
        SATISFIED,
        /** A request may proceed. */
        PROCEED,
        /** The existing resource matched a conditional read. */
        NOT_MODIFIED,
        /** A valid membership request requires full evaluation. */
        REQUIRES_FULL_EVALUATION
    }
}

final class DisabledScimObserver implements ScimObserver {
    static final @NonNull ScimObserver INSTANCE = new DisabledScimObserver();
    private DisabledScimObserver() {}
}
