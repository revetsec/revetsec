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

import org.jspecify.annotations.NonNull;

import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.NotThreadSafe;

/**
 * Visits each closed SCIM filter node kind on Java 17. A visitor controls its own
 * traversal and is responsible for binding and policy approval before execution.
 * Implementations can keep traversal state; callers control their concurrent use.
 *
 * @param <R> the nonnull result type
 * @since 1.0.0
 */
@NotThreadSafe
public interface ScimFilterVisitor<R extends @NonNull Object> {
    /** Visits a conjunction.
     * @param filter node
     * @return result
     * @since 1.0.0
     */
    @CheckReturnValue @NonNull R visitAnd(ScimFilter.@NonNull And filter);
    /** Visits a disjunction.
     * @param filter node
     * @return result
     * @since 1.0.0
     */
    @CheckReturnValue @NonNull R visitOr(ScimFilter.@NonNull Or filter);
    /** Visits a negation.
     * @param filter node
     * @return result
     * @since 1.0.0
     */
    @CheckReturnValue @NonNull R visitNot(ScimFilter.@NonNull Not filter);
    /** Visits a comparison.
     * @param filter node
     * @return result
     * @since 1.0.0
     */
    @CheckReturnValue @NonNull R visitComparison(ScimFilter.@NonNull Comparison filter);
    /** Visits a presence test.
     * @param filter node
     * @return result
     * @since 1.0.0
     */
    @CheckReturnValue @NonNull R visitPresent(ScimFilter.@NonNull Present filter);
    /** Visits a same-element value path.
     * @param filter node
     * @return result
     * @since 1.0.0
     */
    @CheckReturnValue @NonNull R visitValuePath(ScimFilter.@NonNull ValuePath filter);
}
