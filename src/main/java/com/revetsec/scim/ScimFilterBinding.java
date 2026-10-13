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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Schema binding and whole-tree policy checking; never executes a query. */
final class ScimFilterBinding {
    private final @NonNull ScimResourceType type;
    private final @NonNull ScimFilterLimits limits;
    private final @NonNull ScimCompatibility compatibility;
    private final @NonNull Policy policy;
    private final boolean supported;

    ScimFilterBinding(
            @NonNull ScimResourceType type,
            @NonNull ScimFilterLimits limits,
            @NonNull ScimCompatibility compatibility,
            @NonNull ScimFilterPolicy policy,
            boolean supported) {
        this.type = type;
        this.limits = limits;
        this.compatibility = compatibility;
        this.supported = supported;
        this.policy = compile(policy, null);
    }

    @NonNull ScimFilterParseResult bind(
            @NonNull String expression,
            @NonNull Set<@NonNull ScimCompatibilityFeature> used,
            @NonNull ScimWork work) {
        if (!supported) return new ScimFilterParseResult.Rejected(ScimError.forbiddenInstance());
        if (!work.spend(expression.length())) return rejected();
        ScimFilterParser parser =
                new ScimFilterParser(
                        expression,
                        limits,
                        compatibility
                                .getFeatures()
                                .contains(
                                        ScimCompatibilityFeature
                                                .FILTER_VALUE_PATH_SUB_ATTRIBUTE_COMPARISON));
        ScimFilterParseResult syntax = parser.parse();
        if (parser.usedValuePathComparison())
            used.add(ScimCompatibilityFeature.FILTER_VALUE_PATH_SUB_ATTRIBUTE_COMPARISON);
        if (!(syntax instanceof ScimFilterParseResult.Succeeded success)) return syntax;
        State state = new State(work, used);
        ScimFilter result = bindNode(success.getFilter(), policy, null, state);
        return result == null ? rejected() : new ScimFilterParseResult.Succeeded(result);
    }

    @NonNull Optional<@NonNull ScimAttributePath> sort(@NonNull ScimAttributePath path) {
        Target target = resolve(path, null, true);
        return Optional.ofNullable(target == null ? null : target.path);
    }

    private static @NonNull ScimFilterParseResult rejected() {
        return new ScimFilterParseResult.Rejected(ScimError.invalidFilterInstance());
    }

    private @NonNull Policy compile(
            @NonNull ScimFilterPolicy source, @Nullable ScimAttributeDefinition parent) {
        Map<ScimAttributePath, Set<ScimComparisonOperator>> comparisons = new LinkedHashMap<>();
        Set<ScimAttributePath> presence = new LinkedHashSet<>();
        Map<ScimAttributePath, Policy> children = new LinkedHashMap<>();
        for (Map.Entry<String, Set<ScimComparisonOperator>> entry :
                source.getAllowedComparisons().entrySet()) {
            Target target = configTarget(entry.getKey(), parent, true);
            for (ScimComparisonOperator operator : entry.getValue())
                if (!operator(target.definition.getType(), operator))
                    throw new IllegalArgumentException(
                            "SCIM policy contains an unsupported typed operator.");
            if (comparisons.put(target.path, entry.getValue()) != null)
                throw new IllegalArgumentException(
                        "SCIM policy contains equivalent bound comparison paths.");
        }
        for (String expression : source.getAllowedPresence()) {
            Target target = configTarget(expression, parent, false);
            if (!presence.add(target.path))
                throw new IllegalArgumentException(
                        "SCIM policy contains equivalent bound presence paths.");
        }
        for (Map.Entry<String, ScimFilterPolicy> entry : source.getAllowedValuePaths().entrySet()) {
            Target target = configTarget(entry.getKey(), parent, false);
            if (parent != null
                    || target.path.getSubAttributeName().isPresent()
                    || target.definition.getType() != ScimAttributeType.COMPLEX
                    || !target.definition.isMultiValued())
                throw new IllegalArgumentException(
                        "SCIM ValuePath policy requires a multi-valued complex attribute.");
            if (children.put(target.path, compile(entry.getValue(), target.definition)) != null)
                throw new IllegalArgumentException(
                        "SCIM policy contains equivalent bound ValuePath paths.");
        }
        return new Policy(
                comparisons,
                presence,
                children,
                source.getAllowedLogicalOperators(),
                source.getMaximumComparisons());
    }

    private @NonNull Target configTarget(
            @NonNull String expression, @Nullable ScimAttributeDefinition parent, boolean scalar) {
        ScimAttributePathParseResult parsed = ScimAttributePath.fromExpressionResult(expression);
        Target target =
                parsed instanceof ScimAttributePathParseResult.Succeeded success
                        ? resolve(success.getAttributePath(), parent, scalar)
                        : null;
        if (target == null)
            throw new IllegalArgumentException(
                    "SCIM policy contains an unknown, hidden or unsupported bound path.");
        return target;
    }

    private @Nullable Target resolve(
            @NonNull ScimAttributePath path,
            @Nullable ScimAttributeDefinition parent,
            boolean scalar) {
        ScimAttributeDefinition definition;
        ScimAttributePath canonical;
        if (parent == null) {
            ScimAttributePath top =
                    path(path.getSchemaId().orElse(null), path.getAttributeName(), null);
            ScimAttributeDefinition outer = ScimSchemas.find(type, top).orElse(null);
            if (outer == null || outer.getReturned() == ScimReturned.NEVER) return null;
            definition = ScimSchemas.find(type, path).orElse(null);
            canonical = ScimSchemas.canonicalPath(type, path).orElse(null);
        } else {
            if (path.getSchemaId().isPresent()) return null;
            ScimAttributeDefinition outer =
                    ScimSchemas.attribute(parent.getSubAttributes(), path.getAttributeName())
                            .orElse(null);
            if (outer == null || outer.getReturned() == ScimReturned.NEVER) return null;
            definition =
                    path.getSubAttributeName().isPresent()
                            ? ScimSchemas.attribute(
                                            outer.getSubAttributes(),
                                            path.getSubAttributeName().get())
                                    .orElse(null)
                            : outer;
            canonical =
                    definition == null
                            ? null
                            : path(
                                    null,
                                    outer.getName(),
                                    path.getSubAttributeName().isPresent()
                                            ? definition.getName()
                                            : null);
        }
        if (definition == null
                || canonical == null
                || definition.getReturned() == ScimReturned.NEVER) return null;
        if (scalar && definition.getType() == ScimAttributeType.COMPLEX) {
            if (canonical.getSubAttributeName().isPresent()) return null;
            ScimAttributeDefinition value =
                    ScimSchemas.attribute(definition.getSubAttributes(), "value").orElse(null);
            if (value == null
                    || value.getType() == ScimAttributeType.COMPLEX
                    || value.getReturned() == ScimReturned.NEVER) return null;
            definition = value;
            canonical =
                    path(
                            canonical.getSchemaId().orElse(null),
                            canonical.getAttributeName(),
                            value.getName());
        }
        return new Target(canonical, definition);
    }

    static @NonNull ScimAttributePath path(
            @Nullable String schema, @NonNull String attribute, @Nullable String sub) {
        String expression =
                (schema == null ? "" : schema + ":") + attribute + (sub == null ? "" : "." + sub);
        ScimAttributePathParseResult result = ScimAttributePath.fromExpressionResult(expression);
        if (!(result instanceof ScimAttributePathParseResult.Succeeded success))
            throw new IllegalStateException("SCIM canonical schema path is invalid.");
        return success.getAttributePath();
    }

    private @Nullable ScimFilter bindNode(
            @NonNull ScimFilter node,
            @NonNull Policy active,
            @Nullable ScimAttributeDefinition parent,
            @NonNull State state) {
        if (!state.work.spend(
                1L + 4L * (parent == null ? type.definitionCount() : parent.definitionCount())))
            return null;
        int before = state.comparisons;
        ScimFilter result;
        if (node instanceof ScimFilter.And and) {
            if (!active.logical.contains(ScimLogicalOperator.AND)) return null;
            List<ScimFilter> children = new ArrayList<>();
            for (ScimFilter child : and.getOperands()) {
                ScimFilter bound = bindNode(child, active, parent, state);
                if (bound == null) return null;
                children.add(bound);
            }
            result = new ScimFilter.And(children);
        } else if (node instanceof ScimFilter.Or or) {
            if (!active.logical.contains(ScimLogicalOperator.OR)) return null;
            List<ScimFilter> children = new ArrayList<>();
            for (ScimFilter child : or.getOperands()) {
                ScimFilter bound = bindNode(child, active, parent, state);
                if (bound == null) return null;
                children.add(bound);
            }
            result = new ScimFilter.Or(children);
        } else if (node instanceof ScimFilter.Not not) {
            if (!active.logical.contains(ScimLogicalOperator.NOT)) return null;
            ScimFilter bound = bindNode(not.getOperand(), active, parent, state);
            if (bound == null) return null;
            result = new ScimFilter.Not(bound);
        } else if (node instanceof ScimFilter.ValuePath valuePath) {
            Target target = resolve(valuePath.getAttributePath(), parent, false);
            if (target == null || target.path.getSubAttributeName().isPresent()) return null;
            Policy childPolicy = active.children.get(target.path);
            if (childPolicy == null) return null;
            ScimFilter child =
                    bindNode(valuePath.getFilter(), childPolicy, target.definition, state);
            if (child == null) return null;
            result = new ScimFilter.ValuePath(target.path, child);
        } else if (node instanceof ScimFilter.Present present) {
            Target target = resolve(present.getAttributePath(), parent, false);
            if (target == null || !active.presence.contains(target.path)) return null;
            state.comparisons++;
            result = new ScimFilter.Present(target.path);
        } else {
            ScimFilter.Comparison comparison = (ScimFilter.Comparison) node;
            Target target = resolve(comparison.getAttributePath(), parent, true);
            if (target == null) return null;
            Set<ScimComparisonOperator> allowed = active.comparisons.get(target.path);
            if (allowed == null
                    || !allowed.contains(comparison.getOperator())
                    || !operator(target.definition.getType(), comparison.getOperator()))
                return null;
            ScimFilterValue value =
                    literal(
                            target.definition,
                            comparison.getOperator(),
                            comparison.getValue(),
                            state);
            if (value == null) return null;
            state.comparisons++;
            result = new ScimFilter.Comparison(target.path, comparison.getOperator(), value);
        }
        // Each nested policy bounds its entire subtree, while the root bounds the complete filter.
        return state.comparisons - before > active.maximum ? null : result;
    }

    private @Nullable ScimFilterValue literal(
            @NonNull ScimAttributeDefinition definition,
            @NonNull ScimComparisonOperator operator,
            @NonNull ScimFilterValue value,
            @NonNull State state) {
        if (value instanceof ScimFilterValue.NullValue)
            return operator == ScimComparisonOperator.EQ || operator == ScimComparisonOperator.NE
                    ? value
                    : null;
        if (value instanceof ScimFilterValue.StringValue string
                && !state.work.spend(string.getValue().length())) return null;
        ScimAttributeType kind = definition.getType();
        if (kind == ScimAttributeType.BOOLEAN
                && value instanceof ScimFilterValue.StringValue string
                && compatibility.getFeatures().contains(ScimCompatibilityFeature.BOOLEAN_STRINGS)) {
            String folded = string.getValue();
            if (folded.equals("true") || folded.equals("false")) {
                state.used.add(ScimCompatibilityFeature.BOOLEAN_STRINGS);
                return new ScimFilterValue.BooleanValue(folded.equals("true"));
            }
        }
        return switch (kind) {
            case BOOLEAN -> value instanceof ScimFilterValue.BooleanValue ? value : null;
            case INTEGER ->
                    value instanceof ScimFilterValue.NumberValue number
                                    && number.getValue().stripTrailingZeros().scale() <= 0
                            ? value
                            : null;
            case DECIMAL -> value instanceof ScimFilterValue.NumberValue ? value : null;
            case STRING -> value instanceof ScimFilterValue.StringValue ? value : null;
            case DATE_TIME ->
                    value instanceof ScimFilterValue.StringValue string
                                    && ScimResourceValidation.dateTime(string.getValue())
                            ? value
                            : null;
            case BINARY ->
                    value instanceof ScimFilterValue.StringValue string
                                    && ScimResourceValidation.binary(string.getValue())
                            ? value
                            : null;
            case REFERENCE ->
                    value instanceof ScimFilterValue.StringValue string
                                    && ScimResourceValidation.reference(string.getValue())
                            ? value
                            : null;
            case COMPLEX -> null;
        };
    }

    private static boolean operator(
            @NonNull ScimAttributeType type, @NonNull ScimComparisonOperator operator) {
        if (type == ScimAttributeType.COMPLEX) return false;
        if (operator == ScimComparisonOperator.EQ || operator == ScimComparisonOperator.NE)
            return true;
        if (type == ScimAttributeType.BOOLEAN || type == ScimAttributeType.BINARY) return false;
        if (operator == ScimComparisonOperator.CO
                || operator == ScimComparisonOperator.SW
                || operator == ScimComparisonOperator.EW)
            return type == ScimAttributeType.STRING || type == ScimAttributeType.REFERENCE;
        return true;
    }

    private static final class Target {
        final @NonNull ScimAttributePath path;
        final @NonNull ScimAttributeDefinition definition;

        Target(@NonNull ScimAttributePath path, @NonNull ScimAttributeDefinition definition) {
            this.path = path;
            this.definition = definition;
        }
    }

    private static final class Policy {
        final @NonNull
                Map<@NonNull ScimAttributePath, @NonNull Set<@NonNull ScimComparisonOperator>>
                comparisons;
        final @NonNull Set<@NonNull ScimAttributePath> presence;
        final @NonNull Map<@NonNull ScimAttributePath, @NonNull Policy> children;
        final @NonNull Set<@NonNull ScimLogicalOperator> logical;
        final int maximum;

        Policy(
                @NonNull
                        Map<
                                @NonNull ScimAttributePath,
                                @NonNull Set<@NonNull ScimComparisonOperator>>
                        comparisons,
                @NonNull Set<@NonNull ScimAttributePath> presence,
                @NonNull Map<@NonNull ScimAttributePath, @NonNull Policy> children,
                @NonNull Set<@NonNull ScimLogicalOperator> logical,
                int maximum) {
            this.comparisons = Map.copyOf(comparisons);
            this.presence = Set.copyOf(presence);
            this.children = Map.copyOf(children);
            this.logical = logical;
            this.maximum = maximum;
        }
    }

    private static final class State {
        final @NonNull ScimWork work;
        final @NonNull Set<@NonNull ScimCompatibilityFeature> used;
        int comparisons;

        State(@NonNull ScimWork work, @NonNull Set<@NonNull ScimCompatibilityFeature> used) {
            this.work = work;
            this.used = used;
        }
    }
}
