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
import org.jspecify.annotations.Nullable;

/** Bounded original syntax retained privately on a root; never an approval capability. */
final class ScimFilterSource {
    private ScimFilterSource() { }

    static @Nullable String expression(@NonNull ScimFilter filter) {
        if (filter instanceof ScimFilter.And node) return node.sourceExpression();
        if (filter instanceof ScimFilter.Or node) return node.sourceExpression();
        if (filter instanceof ScimFilter.Not node) return node.sourceExpression();
        if (filter instanceof ScimFilter.Comparison node) return node.sourceExpression();
        if (filter instanceof ScimFilter.Present node) return node.sourceExpression();
        return ((ScimFilter.ValuePath) filter).sourceExpression();
    }

    static @NonNull ScimFilter retain(@NonNull ScimFilter filter, @NonNull String expression) {
        if (filter instanceof ScimFilter.And node) return new ScimFilter.And(node.getOperands(), expression);
        if (filter instanceof ScimFilter.Or node) return new ScimFilter.Or(node.getOperands(), expression);
        if (filter instanceof ScimFilter.Not node) return new ScimFilter.Not(node.getOperand(), expression);
        if (filter instanceof ScimFilter.Comparison node)
            return new ScimFilter.Comparison(node.getAttributePath(), node.getOperator(), node.getValue(), expression);
        if (filter instanceof ScimFilter.Present node) return new ScimFilter.Present(node.getAttributePath(), expression);
        ScimFilter.ValuePath node = (ScimFilter.ValuePath) filter;
        return new ScimFilter.ValuePath(node.getAttributePath(), node.getFilter(), expression);
    }
}
