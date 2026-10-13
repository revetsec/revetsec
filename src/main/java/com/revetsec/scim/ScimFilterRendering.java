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

import java.util.List;

/** SCIM-owned bounded syntax rendering; no schema binding or execution. */
final class ScimFilterRendering {
    private ScimFilterRendering() {}

    static @NonNull String render(@NonNull ScimFilter filter) {
        @NonNull StringBuilder output = new StringBuilder();
        append(output, filter, 0);
        return output.toString();
    }

    private static void append(@NonNull StringBuilder output, @NonNull ScimFilter filter, int parentPrecedence) {
        int precedence = filter instanceof ScimFilter.Or ? 1 : filter instanceof ScimFilter.And ? 2 : 3;
        boolean group = precedence < parentPrecedence;
        if (group) output.append('(');
        if (filter instanceof ScimFilter.And and) {
            appendOperands(output, and.getOperands(), " and ", 2);
        } else if (filter instanceof ScimFilter.Or or) {
            appendOperands(output, or.getOperands(), " or ", 1);
        } else if (filter instanceof ScimFilter.Not not) {
            output.append("not(");
            append(output, not.getOperand(), 0);
            output.append(')');
        } else if (filter instanceof ScimFilter.Comparison comparison) {
            output.append(comparison.getAttributePath().toScimString()).append(' ')
                    .append(operatorText(comparison.getOperator())).append(' ');
            appendValue(output, comparison.getValue());
        } else if (filter instanceof ScimFilter.Present present) {
            output.append(present.getAttributePath().toScimString()).append(" pr");
        } else if (filter instanceof ScimFilter.ValuePath valuePath) {
            output.append(valuePath.getAttributePath().toScimString()).append('[');
            append(output, valuePath.getFilter(), 0);
            output.append(']');
        }
        if (group) output.append(')');
    }

    private static void appendOperands(@NonNull StringBuilder output,
            @NonNull List<@NonNull ScimFilter> operands, @NonNull String separator, int precedence) {
        for (int index = 0; index < operands.size(); ++index) {
            if (index != 0) output.append(separator);
            append(output, operands.get(index), precedence);
        }
    }

    private static @NonNull String operatorText(@NonNull ScimComparisonOperator operator) {
        return switch (operator) {
            case EQ -> "eq"; case NE -> "ne"; case CO -> "co";
            case SW -> "sw"; case EW -> "ew"; case GT -> "gt";
            case LT -> "lt"; case GE -> "ge"; case LE -> "le";
        };
    }

    private static void appendValue(@NonNull StringBuilder output, @NonNull ScimFilterValue value) {
        if (value instanceof ScimFilterValue.StringValue string) {
            output.append('"');
            @NonNull String text = string.getValue();
            for (int index = 0; index < text.length(); ++index) {
                char character = text.charAt(index);
                switch (character) {
                    case '"' -> output.append("\\\"");
                    case '\\' -> output.append("\\\\");
                    case '\b' -> output.append("\\b");
                    case '\f' -> output.append("\\f");
                    case '\n' -> output.append("\\n");
                    case '\r' -> output.append("\\r");
                    case '\t' -> output.append("\\t");
                    default -> {
                        if (character < 0x20) {
                            output.append("\\u00")
                                    .append("0123456789abcdef".charAt(character >>> 4))
                                    .append("0123456789abcdef".charAt(character & 15));
                        } else output.append(character);
                    }
                }
            }
            output.append('"');
        } else if (value instanceof ScimFilterValue.NumberValue number) {
            output.append(number.expression());
        } else if (value instanceof ScimFilterValue.BooleanValue bool) {
            output.append(bool.getValue().booleanValue() ? "true" : "false");
        } else output.append("null");
    }
}
