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
import com.revetsec.internal.HostClassifier;
import com.revetsec.internal.Limits;
import com.revetsec.internal.json.AsciiCase;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable SCIM attribute-path syntax with an optional absolute schema URI and one optional
 * subattribute. Equality folds ASCII letters throughout the structural path. Syntax success does
 * not establish a registered schema or grant filtering permission. URI text is never fetched.
 *
 * @since 1.0.0
 */
@Immutable
@CheckReturnValue
public final class ScimAttributePath {
    private final @Nullable String schemaId;
    private final @NonNull String attributeName;
    private final @Nullable String subAttributeName;
    private final @Nullable String foldedSchemaId;
    private final @NonNull String foldedAttributeName;
    private final @Nullable String foldedSubAttributeName;

    private ScimAttributePath(@Nullable String schemaId, @NonNull String attributeName,
            @Nullable String subAttributeName) {
        this.schemaId = schemaId;
        this.attributeName = attributeName;
        this.subAttributeName = subAttributeName;
        foldedSchemaId = schemaId == null ? null : AsciiCase.fold(schemaId);
        foldedAttributeName = AsciiCase.fold(attributeName);
        foldedSubAttributeName = subAttributeName == null ? null : AsciiCase.fold(subAttributeName);
    }

    /**
     * Parses a complete bounded attribute path without surrounding whitespace. Names start with an
     * ASCII letter and then contain ASCII letters, digits, underscore or hyphen. The narrowly
     * supported {@code $ref} name can also represent a relative subattribute inside a ValuePath;
     * declaring it as a top-level resource attribute still requires later schema binding. Schema
     * IDs use bounded absolute URI syntax.
     *
     * @param expression the complete path expression
     * @return syntactic success or a fixed invalidPath error
     * @since 1.0.0
     */
    public static @NonNull ScimAttributePathParseResult fromExpressionResult(@NonNull String expression) {
        Objects.requireNonNull(expression);
        return parseRange(expression, 0, expression.length());
    }

    /**
     * Returns the original schema ID spelling, when qualified.
     *
     * @return the original schema ID spelling, when qualified
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getSchemaId() { return Optional.ofNullable(schemaId); }
    /**
     * Returns the original attribute-name spelling.
     *
     * @return the original attribute-name spelling
     * @since 1.0.0
     */
    public @NonNull String getAttributeName() { return attributeName; }
    /**
     * Returns the original subattribute-name spelling, when supplied.
     *
     * @return the original subattribute-name spelling, when supplied
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getSubAttributeName() { return Optional.ofNullable(subAttributeName); }

    /**
     * Explicitly emits this path as SCIM data, preserving the component spellings supplied during
     * parsing. This operation can disclose application attribute and schema names.
     * @return the SCIM attribute-path expression
     * @since 1.0.0
     */
    public @NonNull String toScimString() {
        return (schemaId == null ? "" : schemaId + ":") + attributeName
                + (subAttributeName == null ? "" : "." + subAttributeName);
    }

    /**
     * Returns whether the structural paths have equal ASCII-folded components.
     *
     * @return whether the structural paths have equal ASCII-folded components
     * @since 1.0.0
     */
    @Override public boolean equals(@Nullable Object other) {
        return this == other || other instanceof ScimAttributePath path
                && Objects.equals(foldedSchemaId, path.foldedSchemaId)
                && foldedAttributeName.equals(path.foldedAttributeName)
                && Objects.equals(foldedSubAttributeName, path.foldedSubAttributeName);
    }

    /**
     * Returns a hash of the same ASCII-folded components used by equality.
     *
     * @return a hash of the same ASCII-folded components used by equality
     * @since 1.0.0
     */
    @Override public int hashCode() {
        int hash = Objects.hashCode(foldedSchemaId);
        hash = 31 * hash + foldedAttributeName.hashCode();
        return 31 * hash + Objects.hashCode(foldedSubAttributeName);
    }

    /**
     * Returns a fixed redacted description.
     *
     * @return a fixed redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "ScimAttributePath{<redacted>}"; }

    // Syntax-only engine helper. Its offsets remain relative to the complete supplied expression.
    static @NonNull ScimAttributePathParseResult parseRange(@NonNull String expression, int start, int end) {
        Objects.requireNonNull(expression);
        if (start < 0 || end < start || end > expression.length())
            throw new IllegalArgumentException("Invalid SCIM attribute-path input range.");
        int maximumName = Limits.SCIM_ATTRIBUTE_NAME_LENGTH.getDefaultIntValue();
        int maximumSchema = Limits.SCIM_SCHEMA_ID_LENGTH.getDefaultIntValue();
        int maximumPath = maximumSchema + 2 * maximumName + 2;
        if (end - start > maximumPath || end > Limits.SCIM_FILTER_LENGTH.getCap())
            return rejected(0);
        if (start == end) return rejected(start);

        int separator = -1;
        for (int index = end - 1; index >= start; --index) {
            if (expression.charAt(index) == ':') { separator = index; break; }
        }
        int nameStart = separator < 0 ? start : separator + 1;
        @Nullable String schema = null;
        if (separator >= 0) {
            if (separator - start > maximumSchema) return rejected(start + maximumSchema);
            int failure = uriFailure(expression, start, separator);
            if (failure >= 0) return rejected(failure);
            schema = expression.substring(start, separator);
        }

        int dot = -1;
        for (int index = nameStart; index < end; ++index) {
            if (expression.charAt(index) == '.') { dot = index; break; }
        }
        int nameEnd = dot < 0 ? end : dot;
        int failure = nameFailure(expression, nameStart, nameEnd, maximumName);
        if (failure >= 0) return rejected(failure);
        @Nullable String subAttribute = null;
        if (dot >= 0) {
            failure = nameFailure(expression, dot + 1, end, maximumName);
            if (failure >= 0) return rejected(failure);
            subAttribute = expression.substring(dot + 1, end);
        }
        return new ScimAttributePathParseResult.Succeeded(
                new ScimAttributePath(schema, expression.substring(nameStart, nameEnd), subAttribute));
    }

    private static @NonNull ScimAttributePathParseResult rejected(int offset) {
        return new ScimAttributePathParseResult.Rejected(ScimError.invalidPathAt(offset));
    }

    private static int nameFailure(@NonNull String text, int start, int end, int maximum) {
        if (start == end) return start;
        if (end - start > maximum) return start + maximum;
        if (end - start == 4 && text.charAt(start) == '$'
                && AsciiCase.fold(text.charAt(start + 1)) == 'r'
                && AsciiCase.fold(text.charAt(start + 2)) == 'e'
                && AsciiCase.fold(text.charAt(start + 3)) == 'f') return -1;
        if (!alpha(text.charAt(start))) return start;
        for (int index = start + 1; index < end; ++index) {
            char character = text.charAt(index);
            if (!alpha(character) && !digit(character) && character != '_' && character != '-') return index;
        }
        return -1;
    }

    static boolean isAbsoluteUriSyntax(@NonNull String value) {
        return uriFailure(value, 0, value.length()) < 0;
    }

    // Bounded RFC 3986 URI syntax recognition, without exception-driven input rejection. Scheme-
    // specific semantics and registered-prefix resolution belong to later schema binding.
    private static int uriFailure(@NonNull String text, int start, int end) {
        if (start == end || !alpha(text.charAt(start))) return start;
        int schemeEnd = start + 1;
        while (schemeEnd < end && text.charAt(schemeEnd) != ':') {
            char character = text.charAt(schemeEnd);
            if (!alpha(character) && !digit(character) && character != '+' && character != '-' && character != '.')
                return schemeEnd;
            ++schemeEnd;
        }
        if (schemeEnd == end) return schemeEnd;
        int contentStart = schemeEnd + 1;
        int fragment = end;
        int query = end;
        for (int index = contentStart; index < end; ++index) {
            char character = text.charAt(index);
            if (character == '#') { fragment = index; break; }
            if (character == '?' && query == end) query = index;
        }
        int hierarchyEnd = Math.min(query, fragment);
        int pathStart = contentStart;
        if (contentStart + 1 < hierarchyEnd && text.charAt(contentStart) == '/'
                && text.charAt(contentStart + 1) == '/') {
            int authorityStart = contentStart + 2;
            int authorityEnd = authorityStart;
            while (authorityEnd < hierarchyEnd && text.charAt(authorityEnd) != '/') ++authorityEnd;
            int failure = authorityFailure(text, authorityStart, authorityEnd);
            if (failure >= 0) return failure;
            pathStart = authorityEnd;
        }
        int failure = componentFailure(text, pathStart, hierarchyEnd, true, false, false);
        if (failure >= 0) return failure;
        if (query < fragment) {
            failure = componentFailure(text, query + 1, fragment, true, true, false);
            if (failure >= 0) return failure;
        }
        return fragment < end ? componentFailure(text, fragment + 1, end, true, true, false) : -1;
    }

    private static int authorityFailure(@NonNull String text, int start, int end) {
        int hostStart = start;
        for (int index = start; index < end; ++index) {
            if (text.charAt(index) == '@') {
                if (hostStart != start) return index;
                int failure = componentFailure(text, start, index, false, false, true);
                if (failure >= 0) return failure;
                hostStart = index + 1;
            }
        }
        if (hostStart < end && text.charAt(hostStart) == '[') {
            int close = hostStart + 1;
            while (close < end && text.charAt(close) != ']') ++close;
            if (close == end) return hostStart;
            if (!validIpLiteral(text, hostStart, close + 1)) return hostStart;
            if (close + 1 == end) return -1;
            if (text.charAt(close + 1) != ':') return close + 1;
            return portFailure(text, close + 2, end);
        }
        int hostEnd = hostStart;
        while (hostEnd < end && text.charAt(hostEnd) != ':') ++hostEnd;
        int failure = registeredNameFailure(text, hostStart, hostEnd);
        if (failure >= 0) return failure;
        return hostEnd < end ? portFailure(text, hostEnd + 1, end) : -1;
    }

    private static boolean validIpLiteral(@NonNull String text, int start, int end) {
        if (end - start < 3) return false;
        char first = text.charAt(start + 1);
        if (first != 'v' && first != 'V')
            return HostClassifier.parseLiteral(text.substring(start, end)) != null;
        int index = start + 2;
        int versionStart = index;
        while (index < end - 1 && hex(text.charAt(index))) ++index;
        if (index == versionStart || index >= end - 2 || text.charAt(index++) != '.') return false;
        while (index < end - 1) {
            char character = text.charAt(index++);
            if (!unreserved(character) && !subDelimiter(character) && character != ':') return false;
        }
        return true;
    }

    private static int portFailure(@NonNull String text, int start, int end) {
        for (int index = start; index < end; ++index) if (!digit(text.charAt(index))) return index;
        return -1;
    }

    private static int registeredNameFailure(@NonNull String text, int start, int end) {
        for (int index = start; index < end; ++index) {
            char character = text.charAt(index);
            if (character == '%') {
                if (index + 2 >= end || !hex(text.charAt(index + 1)) || !hex(text.charAt(index + 2))) return index;
                index += 2;
            } else if (!unreserved(character) && !subDelimiter(character)) return index;
        }
        return -1;
    }

    private static int componentFailure(@NonNull String text, int start, int end,
            boolean slash, boolean question, boolean userInfo) {
        for (int index = start; index < end; ++index) {
            char character = text.charAt(index);
            if (character == '%') {
                if (index + 2 >= end || !hex(text.charAt(index + 1)) || !hex(text.charAt(index + 2))) return index;
                index += 2;
            } else if (!unreserved(character) && !subDelimiter(character) && character != ':'
                    && !(character == '@' && !userInfo) && !(character == '/' && slash)
                    && !(character == '?' && question)) return index;
        }
        return -1;
    }

    private static boolean alpha(char character) {
        return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z';
    }

    private static boolean digit(char character) { return character >= '0' && character <= '9'; }

    private static boolean hex(char character) {
        return digit(character) || character >= 'A' && character <= 'F' || character >= 'a' && character <= 'f';
    }

    private static boolean unreserved(char character) {
        return alpha(character) || digit(character) || character == '-' || character == '.'
                || character == '_' || character == '~';
    }

    private static boolean subDelimiter(char character) {
        return character == '!' || character == '$' || character == '&' || character == '\''
                || character == '(' || character == ')' || character == '*' || character == '+'
                || character == ',' || character == ';' || character == '=';
    }
}
