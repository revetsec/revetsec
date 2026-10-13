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

import javax.annotation.concurrent.NotThreadSafe;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;

/** SCIM-owned result-first bounded grammar, separate from query execution. */
@NotThreadSafe
final class ScimFilterParser {
    private final @NonNull String expression;
    private final int maximumDepth;
    private final int maximumNodes;
    private final int maximumLength;
    private final int maximumLiteral;
    private final int maximumNumber;
    private final int maximumExponent;
    private final boolean allowValuePathComparison;
    private boolean usedValuePathComparison;
    private int position;
    private int errorOffset = -1;

    ScimFilterParser(@NonNull String expression, @NonNull ScimFilterLimits limits) {
        this(expression, limits, false);
    }

    ScimFilterParser(@NonNull String expression, @NonNull ScimFilterLimits limits, boolean allowValuePathComparison) {
        this.allowValuePathComparison = allowValuePathComparison;
        this.expression = expression;
        this.maximumDepth = limits.getMaximumDepth();
        this.maximumNodes = limits.getMaximumNodes();
        this.maximumLength = limits.getMaximumExpressionCharacters();
        this.maximumLiteral = limits.getMaximumLiteralCharacters();
        this.maximumNumber = limits.getMaximumNumberCharacters();
        this.maximumExponent = limits.getMaximumNumberExponentMagnitude();
    }

    boolean usedValuePathComparison() { return this.usedValuePathComparison; }

    @NonNull ScimFilterParseResult parse() {
        if (this.expression.length() > this.maximumLength)
            return new ScimFilterParseResult.Rejected(ScimError.invalidFilterAt(this.maximumLength));
        @Nullable Node filter = parseOr(false, 0);
        skipWhitespace();
        if (filter != null && this.position != this.expression.length()) reject(this.position);
        if (filter == null || this.errorOffset >= 0)
            return new ScimFilterParseResult.Rejected(ScimError.invalidFilterAt(
                    this.errorOffset >= 0 ? this.errorOffset : this.position));
        return new ScimFilterParseResult.Succeeded(filter.filter);
    }

    private @Nullable Node parseOr(boolean inValuePath, int nesting) {
        return parseLogical(false, inValuePath, nesting);
    }

    private @Nullable Node parseAnd(boolean inValuePath, int nesting) {
        return parseLogical(true, inValuePath, nesting);
    }

    private @Nullable Node parseLogical(boolean conjunction, boolean inValuePath, int nesting) {
        @Nullable Node first = conjunction ? parsePrimary(inValuePath, nesting) : parseAnd(inValuePath, nesting);
        if (first == null) return null;
        @Nullable List<@NonNull Node> operands = null;
        int nodeCount = 0;
        int depth = 0;
        while (true) {
            int beforeWhitespace = this.position;
            skipWhitespace();
            int operatorOffset = this.position;
            @NonNull String word = conjunction ? "and" : "or";
            if (beforeWhitespace == this.position || !keywordAt(this.position, word)) {
                this.position = beforeWhitespace;
                break;
            }
            this.position += word.length();
            if (!skipWhitespace()) { reject(this.position); return null; }
            @Nullable Node next = conjunction ? parsePrimary(inValuePath, nesting) : parseAnd(inValuePath, nesting);
            if (next == null) return null;
            if (operands == null) {
                operands = new ArrayList<>();
                appendFlattened(operands, first, conjunction);
                nodeCount = first.nodes - (sameLogical(first.filter, conjunction) ? 1 : 0);
                depth = flattenedDepth(first, conjunction);
            }
            int nextNodes = next.nodes - (sameLogical(next.filter, conjunction) ? 1 : 0);
            if (nodeCount + nextNodes + 1 > this.maximumNodes) { reject(operatorOffset); return null; }
            depth = Math.max(depth, flattenedDepth(next, conjunction));
            if (depth + 1 > this.maximumDepth) { reject(operatorOffset); return null; }
            nodeCount += nextNodes;
            appendFlattened(operands, next, conjunction);
        }
        if (operands == null) return first;
        @NonNull List<@NonNull ScimFilter> filters = new ArrayList<>(operands.size());
        for (@NonNull Node operand : operands) filters.add(operand.filter);
        @NonNull ScimFilter result = conjunction ? new ScimFilter.And(filters) : new ScimFilter.Or(filters);
        return new Node(result, depth + 1, nodeCount + 1, List.copyOf(operands));
    }

    private static boolean sameLogical(@NonNull ScimFilter filter, boolean conjunction) {
        return conjunction ? filter instanceof ScimFilter.And : filter instanceof ScimFilter.Or;
    }

    private static int flattenedDepth(@NonNull Node node, boolean conjunction) {
        return node.depth - (sameLogical(node.filter, conjunction) ? 1 : 0);
    }

    private static void appendFlattened(@NonNull List<@NonNull Node> output,
            @NonNull Node node, boolean conjunction) {
        if (sameLogical(node.filter, conjunction) && node.operands != null) output.addAll(node.operands);
        else output.add(node);
    }

    private @Nullable Node parsePrimary(boolean inValuePath, int nesting) {
        skipWhitespace();
        int start = this.position;
        if (start >= this.expression.length()) { reject(start); return null; }
        char character = this.expression.charAt(start);
        if (character == '(') {
            if (!enter(nesting, start)) return null;
            ++this.position;
            @Nullable Node grouped = parseOr(inValuePath, nesting + 1);
            if (grouped == null || !close(')')) return null;
            return grouped;
        }
        if (keywordAt(start, "not")) {
            int afterNot = start + 3;
            while (afterNot < this.expression.length() && whitespace(this.expression.charAt(afterNot))) ++afterNot;
            if (afterNot < this.expression.length() && this.expression.charAt(afterNot) == '(') {
                if (!enter(nesting, start)) return null;
                this.position = afterNot + 1;
                @Nullable Node operand = parseOr(inValuePath, nesting + 1);
                if (operand == null || !close(')')) return null;
                if (operand.depth + 1 > this.maximumDepth || operand.nodes + 1 > this.maximumNodes) {
                    reject(start); return null;
                }
                return new Node(new ScimFilter.Not(operand.filter), operand.depth + 1, operand.nodes + 1, null);
            }
        }
        int pathEnd = pathEnd(start);
        if (pathEnd == start) { reject(start); return null; }
        @NonNull ScimAttributePathParseResult pathResult = ScimAttributePath.parseRange(this.expression, start, pathEnd);
        if (!(pathResult instanceof ScimAttributePathParseResult.Succeeded succeeded)) {
            @NonNull ScimError error = ((ScimAttributePathParseResult.Rejected) pathResult).getError();
            reject(error.getExpressionOffset().orElse(start)); return null;
        }
        @NonNull ScimAttributePath path = succeeded.getAttributePath();
        if (inValuePath && path.getSchemaId().isPresent()) { reject(start); return null; }
        this.position = pathEnd;
        if (this.position < this.expression.length() && this.expression.charAt(this.position) == '[') {
            int bracket = this.position;
            if (inValuePath || !enter(nesting, bracket)) { reject(bracket); return null; }
            ++this.position;
            @Nullable Node filter = parseOr(true, nesting + 1);
            if (filter == null || !close(']')) return null;
            if (this.allowValuePathComparison && this.position < this.expression.length()
                    && this.expression.charAt(this.position) == '.') {
                ++this.position;
                int relativeStart = this.position;
                int relativeEnd = pathEnd(relativeStart);
                ScimAttributePathParseResult relative = ScimAttributePath.parseRange(this.expression, relativeStart, relativeEnd);
                if (!(relative instanceof ScimAttributePathParseResult.Succeeded child)
                        || child.getAttributePath().getSchemaId().isPresent()
                        || child.getAttributePath().getSubAttributeName().isPresent()) { reject(relativeStart); return null; }
                this.position = relativeEnd;
                if (!skipWhitespace()) { reject(this.position); return null; }
                int opStart = this.position;
                while (this.position < this.expression.length() && asciiLetter(this.expression.charAt(this.position))) ++this.position;
                ScimComparisonOperator op = comparison(opStart, this.position);
                if (op == null || !skipWhitespace()) { reject(opStart); return null; }
                ScimFilterValue value = parseValue();
                if (value == null) return null;
                List<Node> nodes = new ArrayList<>();
                appendFlattened(nodes, filter, true);
                Node comparison = new Node(new ScimFilter.Comparison(child.getAttributePath(), op, value), 1, 1, null);
                nodes.add(comparison);
                int count = filter.nodes + (filter.filter instanceof ScimFilter.And ? 1 : 2);
                int depth = Math.max(flattenedDepth(filter, true), 1) + 1;
                if (depth + 1 > this.maximumDepth || count + 1 > this.maximumNodes) { reject(bracket); return null; }
                List<ScimFilter> operands = new ArrayList<>(nodes.size());
                for (Node operand : nodes) operands.add(operand.filter);
                filter = new Node(new ScimFilter.And(operands), depth, count, List.copyOf(nodes));
                this.usedValuePathComparison = true;
            }
            if (filter.depth + 1 > this.maximumDepth || filter.nodes + 1 > this.maximumNodes) {
                reject(bracket); return null;
            }
            return new Node(new ScimFilter.ValuePath(path, filter.filter), filter.depth + 1, filter.nodes + 1, null);
        }
        if (!skipWhitespace()) { reject(this.position); return null; }
        int operatorStart = this.position;
        while (this.position < this.expression.length() && asciiLetter(this.expression.charAt(this.position))) ++this.position;
        int operatorEnd = this.position;
        if (matches(operatorStart, operatorEnd, "pr"))
            return new Node(new ScimFilter.Present(path), 1, 1, null);
        @Nullable ScimComparisonOperator operator = comparison(operatorStart, operatorEnd);
        if (operator == null) { reject(operatorStart); return null; }
        if (!skipWhitespace()) { reject(this.position); return null; }
        @Nullable ScimFilterValue value = parseValue();
        return value == null ? null : new Node(new ScimFilter.Comparison(path, operator, value), 1, 1, null);
    }

    private boolean enter(int nesting, int offset) {
        if (nesting >= this.maximumDepth) { reject(offset); return false; }
        return true;
    }

    private boolean close(char expected) {
        skipWhitespace();
        if (this.position >= this.expression.length() || this.expression.charAt(this.position) != expected) {
            reject(this.position); return false;
        }
        ++this.position;
        return true;
    }

    private int pathEnd(int start) {
        int index = start;
        int authorityStart = -1;
        // URI authorities can contain bracketed IPv6 addresses. Those brackets
        // belong to the schema URI, rather than beginning a valuePath.
        int schemeEnd = start;
        while (schemeEnd < this.expression.length()) {
            char character = this.expression.charAt(schemeEnd);
            if (!asciiLetter(character) && !digit(character) && character != '+' && character != '-' && character != '.') break;
            ++schemeEnd;
        }
        boolean qualified = schemeEnd > start && asciiLetter(this.expression.charAt(start))
                && schemeEnd < this.expression.length() && this.expression.charAt(schemeEnd) == ':';
        if (schemeEnd + 2 < this.expression.length() && this.expression.charAt(schemeEnd) == ':'
                && this.expression.charAt(schemeEnd + 1) == '/' && this.expression.charAt(schemeEnd + 2) == '/')
            authorityStart = schemeEnd + 3;
        boolean inAuthority = authorityStart >= 0;
        while (index < this.expression.length()) {
            char character = this.expression.charAt(index);
            if (inAuthority && index >= authorityStart && (character == '/' || character == '?' || character == '#'))
                inAuthority = false;
            if (character == '[' && inAuthority
                    && (index == authorityStart || index > authorityStart && this.expression.charAt(index - 1) == '@')) {
                ++index;
                while (index < this.expression.length() && this.expression.charAt(index) != ']'
                        && !whitespace(this.expression.charAt(index))) ++index;
                if (index < this.expression.length() && this.expression.charAt(index) == ']') { ++index; continue; }
                return index;
            }
            if (whitespace(character) || character == '[' || character == ']'
                    || !qualified && (character == '(' || character == ')')) break;
            ++index;
        }
        if (qualified) {
            // Parentheses are RFC 3986 URI sub-delimiters. Only delimiters after
            // the final schema/attribute colon are filter grouping syntax.
            int delimiter = index - 1;
            while (delimiter > start && this.expression.charAt(delimiter) != ':') --delimiter;
            int attributeEnd = delimiter + 1;
            while (attributeEnd < index) {
                char character = this.expression.charAt(attributeEnd);
                if (character == '(' || character == ')') break;
                ++attributeEnd;
            }
            return attributeEnd;
        }
        return index;
    }

    private @Nullable ScimFilterValue parseValue() {
        int start = this.position;
        if (start >= this.expression.length()) { reject(start); return null; }
        if (this.expression.charAt(start) == '"') return parseString();
        while (this.position < this.expression.length()) {
            char character = this.expression.charAt(this.position);
            if (whitespace(character) || character == ')' || character == ']') break;
            ++this.position;
        }
        int end = this.position;
        if (this.expression.regionMatches(start, "true", 0, 4) && end - start == 4)
            return new ScimFilterValue.BooleanValue(true);
        if (this.expression.regionMatches(start, "false", 0, 5) && end - start == 5)
            return new ScimFilterValue.BooleanValue(false);
        if (this.expression.regionMatches(start, "null", 0, 4) && end - start == 4)
            return new ScimFilterValue.NullValue();
        return parseNumber(start, end);
    }

    private @Nullable ScimFilterValue parseString() {
        ++this.position;
        @NonNull StringBuilder decoded = new StringBuilder();
        int pendingHighOffset = -1;
        while (this.position < this.expression.length()) {
            int unitOffset = this.position;
            char character = this.expression.charAt(this.position++);
            if (character == '"') {
                if (pendingHighOffset >= 0) { reject(pendingHighOffset); return null; }
                return new ScimFilterValue.StringValue(decoded.toString());
            }
            if (character < 0x20) { reject(unitOffset); return null; }
            if (character == '\\') {
                if (this.position >= this.expression.length()) { reject(this.position); return null; }
                int escapeOffset = this.position;
                char escape = this.expression.charAt(this.position++);
                switch (escape) {
                    case '"', '\\', '/' -> character = escape;
                    case 'b' -> character = '\b'; case 'f' -> character = '\f';
                    case 'n' -> character = '\n'; case 'r' -> character = '\r'; case 't' -> character = '\t';
                    case 'u' -> {
                        int value = 0;
                        for (int index = 0; index < 4; ++index) {
                            if (this.position >= this.expression.length()) { reject(this.position); return null; }
                            int hex = hex(this.expression.charAt(this.position));
                            if (hex < 0) { reject(this.position); return null; }
                            ++this.position;
                            value = (value << 4) | hex;
                        }
                        character = (char) value;
                    }
                    default -> { reject(escapeOffset); return null; }
                }
            }
            if (pendingHighOffset >= 0) {
                if (character < 0xdc00 || character > 0xdfff) { reject(unitOffset); return null; }
                pendingHighOffset = -1;
            } else if (character >= 0xd800 && character <= 0xdbff) pendingHighOffset = unitOffset;
            else if (character >= 0xdc00 && character <= 0xdfff) { reject(unitOffset); return null; }
            if (decoded.length() >= this.maximumLiteral) { reject(unitOffset); return null; }
            decoded.append(character);
        }
        reject(this.position); return null;
    }

    private @Nullable ScimFilterValue parseNumber(int start, int end) {
        if (end - start > this.maximumNumber) { reject(start + this.maximumNumber); return null; }
        int index = start;
        if (index < end && this.expression.charAt(index) == '-') ++index;
        if (index >= end || !digit(this.expression.charAt(index))) { reject(index); return null; }
        if (this.expression.charAt(index) == '0') ++index;
        else while (index < end && digit(this.expression.charAt(index))) ++index;
        if (index < end && this.expression.charAt(index) == '.') {
            ++index;
            int digitsStart = index;
            while (index < end && digit(this.expression.charAt(index))) ++index;
            if (index == digitsStart) { reject(index); return null; }
        }
        int exponentStart = -1;
        int exponentDigits = -1;
        boolean negativeExponent = false;
        int magnitude = 0;
        if (index < end && (this.expression.charAt(index) == 'e' || this.expression.charAt(index) == 'E')) {
            exponentStart = index++;
            if (index < end && (this.expression.charAt(index) == '+' || this.expression.charAt(index) == '-')) {
                negativeExponent = this.expression.charAt(index) == '-'; ++index;
            }
            exponentDigits = index;
            while (index < end && digit(this.expression.charAt(index))) {
                int nextDigit = this.expression.charAt(index) - '0';
                if (magnitude > this.maximumExponent / 10
                        || magnitude == this.maximumExponent / 10 && nextDigit > this.maximumExponent % 10) {
                    reject(index); return null;
                }
                magnitude = magnitude * 10 + nextDigit;
                ++index;
            }
            if (index == exponentDigits) { reject(index); return null; }
        }
        if (index != end) { reject(index); return null; }
        @NonNull String token = this.expression.substring(start, end);
        @NonNull BigDecimal value = new BigDecimal(token);
        @NonNull String canonical = token;
        if (exponentStart >= 0) {
            int firstDigit = exponentDigits;
            while (firstDigit < end - 1 && this.expression.charAt(firstDigit) == '0') ++firstDigit;
            canonical = this.expression.substring(start, exponentStart) + "E"
                    + (negativeExponent && magnitude != 0 ? "-" : "") + this.expression.substring(firstDigit, end);
        }
        return new ScimFilterValue.NumberValue(value, canonical);
    }

    private @Nullable ScimComparisonOperator comparison(int start, int end) {
        if (matches(start, end, "eq")) return ScimComparisonOperator.EQ;
        if (matches(start, end, "ne")) return ScimComparisonOperator.NE;
        if (matches(start, end, "co")) return ScimComparisonOperator.CO;
        if (matches(start, end, "sw")) return ScimComparisonOperator.SW;
        if (matches(start, end, "ew")) return ScimComparisonOperator.EW;
        if (matches(start, end, "gt")) return ScimComparisonOperator.GT;
        if (matches(start, end, "lt")) return ScimComparisonOperator.LT;
        if (matches(start, end, "ge")) return ScimComparisonOperator.GE;
        if (matches(start, end, "le")) return ScimComparisonOperator.LE;
        return null;
    }

    private boolean keywordAt(int start, @NonNull String keyword) {
        int end = start + keyword.length();
        return end <= this.expression.length() && matches(start, end, keyword)
                && (end == this.expression.length() || !nameCharacter(this.expression.charAt(end)));
    }

    private boolean matches(int start, int end, @NonNull String text) {
        if (end - start != text.length()) return false;
        for (int index = 0; index < text.length(); ++index) {
            char actual = this.expression.charAt(start + index);
            if (actual >= 'A' && actual <= 'Z') actual = (char) (actual + ('a' - 'A'));
            if (actual != text.charAt(index)) return false;
        }
        return true;
    }

    private boolean skipWhitespace() {
        int start = this.position;
        while (this.position < this.expression.length() && whitespace(this.expression.charAt(this.position))) ++this.position;
        return this.position != start;
    }

    private static boolean whitespace(char value) {
        return value == ' ' || value == '\t' || value == '\r' || value == '\n' || value == '\f';
    }

    private static boolean asciiLetter(char value) { return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'; }
    private static boolean digit(char value) { return value >= '0' && value <= '9'; }
    private static boolean nameCharacter(char value) { return asciiLetter(value) || digit(value) || value == '_' || value == '-'; }
    private static int hex(char value) {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    }

    private void reject(int offset) { if (this.errorOffset < 0) this.errorOffset = offset; }

    private static final class Node {
        private final @NonNull ScimFilter filter;
        private final int depth;
        private final int nodes;
        private final @Nullable List<@NonNull Node> operands;

        private Node(@NonNull ScimFilter filter, int depth, int nodes, @Nullable List<@NonNull Node> operands) {
            this.filter = filter; this.depth = depth; this.nodes = nodes; this.operands = operands;
        }
    }
}
