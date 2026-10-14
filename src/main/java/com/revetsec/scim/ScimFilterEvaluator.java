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
import javax.annotation.concurrent.Immutable;
import static java.util.Objects.requireNonNull;

/** Optional bounded evaluation of schema-bound, policy-approved filters against application data.
 * Each evaluation rechecks the entire filter under this evaluator's provider. All clauses and
 * matching array elements are visited, including clauses whose truth value cannot change the
 * verdict, so unsupported application matching cannot become a successful non-match.
 * <p>String matching uses the provider's explicitly configured strategy, shared with PATCH.
 * Missing/null values and empty multi-values are unassigned; empty strings are assigned for null
 * comparisons but fail presence. For assigned multi-values, comparisons use any-element semantics,
 * including {@code ne}; {@code not} negates the complete predicate. An unassigned attribute is
 * unequal to a nonnull literal. This evaluator does not authorize a resource, execute storage
 * queries, or establish authoritative identity uniqueness.
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimFilterEvaluator {
    private final @NonNull ScimServiceProvider provider;
    private ScimFilterEvaluator(@NonNull ScimServiceProvider provider) { this.provider = provider; }

    /** Creates an evaluator using this provider's matching strategy, policies and limits.
     * @param provider the registered semantic context
     * @return an immutable evaluator
     * @throws IllegalArgumentException if the provider has no application string matching strategy
     * @since 1.0.0
     */
    public static @NonNull ScimFilterEvaluator fromServiceProvider(@NonNull ScimServiceProvider provider) {
        requireNonNull(provider);
        if (provider.getStringMatching().isEmpty())
            throw new IllegalArgumentException("SCIM filter evaluation requires an application matching strategy.");
        return new ScimFilterEvaluator(provider);
    }

    /** Rebinds, approves and evaluates a complete filter with one shared work budget.
     * A foreign registered resource context rejects; a syntax-only or foreign filter is rechecked.
     * Unsupported matching rejects with invalidFilter. Ordinary application faults are contained
     * as fixed internalError results and redacted observer events; interruption is preserved and
     * fatal VM errors escape.
     * @param resource the immutable application resource
     * @param filter the bounded filter tree to recheck
     * @return the complete verdict or fixed rejection
     * @since 1.0.0
     */
    public @NonNull ScimFilterEvaluationResult evaluateResult(@NonNull ScimResource resource,
            @NonNull ScimFilter filter) {
        return provider.evaluateFilterResult(requireNonNull(resource), requireNonNull(filter));
    }

    /** Returns a fixed redacted description.
     * @return the description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimFilterEvaluator{<redacted>}"; }
}
