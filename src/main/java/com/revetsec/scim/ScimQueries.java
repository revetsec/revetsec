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

import com.revetsec.internal.json.AsciiCase;
import com.revetsec.internal.json.JsonDocument;
import com.revetsec.internal.json.JsonNumberSyntax;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** SCIM-owned direct-result query, SearchRequest and projection processing. */
final class ScimQueries {
    private static final @NonNull String SEARCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";
    private static final @NonNull BigDecimal LONG_MINIMUM = BigDecimal.valueOf(Long.MIN_VALUE);
    private static final @NonNull BigDecimal LONG_MAXIMUM = BigDecimal.valueOf(Long.MAX_VALUE);
    private ScimQueries() {}

    static @NonNull ScimQueryParseResult query(@NonNull ScimResourceType type, @NonNull String raw,
            @NonNull ScimServiceProviderConfig config, @NonNull ScimLimits limits,
            @NonNull ScimCompatibility compatibility, @NonNull Object context, @NonNull ScimFilterBinding binding,
            @NonNull Set<@NonNull ScimCompatibilityFeature> used, @NonNull ScimWork work) {
        Fields fields = raw(raw, limits, work);
        if (fields.error != null) return rejected(fields.error);
        return finish(type, fields, config, limits, context, binding, used, work);
    }

    static @NonNull ScimAttributeSelectionResult selection(@NonNull ScimResourceType type, @NonNull String raw,
            @NonNull ScimLimits limits, @NonNull Object context, @NonNull ScimWork work) {
        Fields fields = raw(raw, limits, work);
        if (fields.error != null) return new ScimAttributeSelectionResult.Rejected(fields.error);
        return select(type, fields, limits, context, work);
    }

    static @NonNull ScimAttributeSelectionResult discoverySelection(@NonNull ScimResourceType type,
            @NonNull String raw, @NonNull ScimLimits limits, @NonNull Object context, @NonNull ScimWork work) {
        Fields fields = raw(raw, limits, work);
        if (fields.error != null) return new ScimAttributeSelectionResult.Rejected(fields.error);
        if (fields.values.containsKey("filter"))
            return new ScimAttributeSelectionResult.Rejected(ScimError.forbiddenInstance());
        return select(type, fields, limits, context, work);
    }

    static @NonNull ScimQueryParseResult search(@NonNull ScimResourceType type, @NonNull JsonDocument document,
            @NonNull ScimServiceProviderConfig config, @NonNull ScimLimits limits,
            @NonNull ScimCompatibility compatibility, @NonNull Object context, @NonNull ScimFilterBinding binding,
            @NonNull Set<@NonNull ScimCompatibilityFeature> used, @NonNull ScimWork work) {
        Objects.requireNonNull(document);
        if (!(document.getValue() instanceof JsonObject object)) return rejected(ScimError.invalidSyntaxInstance());
        Fields fields = new Fields();
        boolean schema = false;
        if (object.getMembers().size() > limits.getMaximumQueryParameters()
                || !work.spend(object.getMembers().size())) return rejected(ScimError.invalidSyntaxInstance());
        for (Map.Entry<String, JsonValue> entry : object.getMembers().entrySet()) {
            if (entry.getKey().length() > limits.getMaximumParameterCharacters() || !work.spend(entry.getKey().length()))
                return rejected(ScimError.invalidSyntaxInstance());
            String name = AsciiCase.fold(entry.getKey());
            JsonValue value = entry.getValue();
            if (name.equals("schemas")) {
                if (schema || !(value instanceof JsonArray array) || array.getElements().size() != 1
                        || !(array.getElements().get(0) instanceof JsonString string)
                        || string.getValue().length() > limits.getMaximumParameterCharacters()
                        || !work.spend(string.getValue().length())
                        || !AsciiCase.fold(string.getValue()).equals(AsciiCase.fold(SEARCH_SCHEMA)))
                    return rejected(ScimError.invalidValueInstance());
                schema = true;
            } else if (!recognized(name)) return rejected(ScimError.invalidSyntaxInstance());
            else if (fields.values.containsKey(name)) return rejected(ScimError.invalidSyntaxInstance());
            else if (name.equals("attributes") || name.equals("excludedattributes")) {
                if (!(value instanceof JsonArray array) || array.getElements().isEmpty()
                        || array.getElements().size() > limits.getMaximumProjectionPaths())
                    return rejected(ScimError.invalidPathInstance());
                List<@NonNull String> paths = new ArrayList<>(array.getElements().size());
                for (JsonValue element : array.getElements()) {
                    if (!(element instanceof JsonString string) || string.getValue().length() > limits.getMaximumParameterCharacters()
                            || !work.spend(string.getValue().length())) return rejected(ScimError.invalidPathInstance());
                    paths.add(string.getValue());
                }
                fields.values.put(name, "");
                if (name.equals("attributes")) fields.included = paths;
                else fields.excluded = paths;
            } else if (name.equals("startindex") || name.equals("count")) {
                if (!(value instanceof JsonNumber number)) return rejected(ScimError.invalidValueInstance());
                Optional<JsonNumberSyntax> syntax = document.numberSyntax(number);
                if (syntax.isEmpty() || syntax.get().hadFraction() || syntax.get().hadExponent()
                        || !work.spend(number.getValue().precision())
                        || number.getValue().compareTo(LONG_MINIMUM) < 0 || number.getValue().compareTo(LONG_MAXIMUM) > 0)
                    return rejected(ScimError.invalidValueInstance());
                fields.values.put(name, Long.toString(number.getValue().longValue()));
            } else {
                if (!(value instanceof JsonString string) || string.getValue().length() > limits.getMaximumParameterCharacters()
                        || !work.spend(string.getValue().length())) return rejected(ScimError.invalidValueInstance());
                fields.values.put(name, string.getValue());
            }
        }
        if (!schema) return rejected(ScimError.invalidValueInstance());
        return finish(type, fields, config, limits, context, binding, used, work);
    }

    private static @NonNull ScimQueryParseResult finish(@NonNull ScimResourceType type, @NonNull Fields fields,
            @NonNull ScimServiceProviderConfig config, @NonNull ScimLimits limits, @NonNull Object context,
            @NonNull ScimFilterBinding binding, @NonNull Set<@NonNull ScimCompatibilityFeature> used,
            @NonNull ScimWork work) {
        ScimAttributeSelectionResult selected = select(type, fields, limits, context, work);
        if (selected instanceof ScimAttributeSelectionResult.Rejected error) return rejected(error.getError());
        ScimAttributeSelection selection = ((ScimAttributeSelectionResult.Succeeded) selected).getAttributeSelection();
        ScimFilter filter = null;
        if (fields.values.containsKey("filter")) {
            ScimFilterParseResult result = binding.bind(fields.values.get("filter"), used, work);
            if (result instanceof ScimFilterParseResult.Rejected error) return rejected(error.getError());
            filter = ((ScimFilterParseResult.Succeeded) result).getFilter();
        }
        ScimAttributePath sortBy = null;
        ScimSortOrder sortOrder = null;
        if (fields.values.containsKey("sortby")) {
            if (!config.isSortSupported()) return rejected(ScimError.forbiddenInstance());
            String expression = fields.values.get("sortby");
            if (!work.spend(expression.length() + 4L * type.definitionCount())) return rejected(ScimError.invalidPathInstance());
            ScimAttributePathParseResult path = ScimAttributePath.fromExpressionResult(expression);
            if (!(path instanceof ScimAttributePathParseResult.Succeeded parsed))
                return rejected(ScimError.invalidPathInstance());
            Optional<ScimAttributePath> bound = binding.sort(parsed.getAttributePath());
            if (bound.isEmpty()) return rejected(ScimError.invalidPathInstance());
            sortBy = bound.get();
            sortOrder = ScimSortOrder.ASCENDING;
            if (fields.values.containsKey("sortorder")) {
                String order = AsciiCase.fold(fields.values.get("sortorder"));
                if (order.equals("descending")) sortOrder = ScimSortOrder.DESCENDING;
                else if (!order.equals("ascending")) return rejected(ScimError.invalidValueInstance());
            }
        } else if (fields.values.containsKey("sortorder")) return rejected(ScimError.invalidValueInstance());
        boolean cursorPresent = fields.values.containsKey("cursor");
        boolean indexPresent = fields.values.containsKey("startindex");
        if (cursorPresent && indexPresent) return rejected(ScimError.invalidValueInstance());
        ScimPaginationConfig paging = config.getPagination();
        ScimPaginationMethod method = cursorPresent ? ScimPaginationMethod.CURSOR
                : indexPresent ? ScimPaginationMethod.INDEX : paging.getDefaultMethod();
        if (method == ScimPaginationMethod.CURSOR && !paging.isCursorSupported())
            return rejected(ScimError.invalidCursorInstance());
        if (method == ScimPaginationMethod.INDEX && !paging.isIndexSupported())
            return rejected(ScimError.invalidValueInstance());
        String cursor = cursorPresent ? fields.values.get("cursor") : null;
        if (cursor != null && !validCursor(cursor, limits.getMaximumCursorCharacters()))
            return rejected(ScimError.invalidCursorInstance());
        Long startIndex = method == ScimPaginationMethod.INDEX ? 1L : null;
        if (indexPresent) {
            Long requested = signedInteger(Objects.requireNonNull(fields.values.get("startindex")));
            if (requested == null) return rejected(ScimError.invalidValueInstance());
            startIndex = Math.max(1, requested);
        }
        Long requestedCount = null;
        if (fields.values.containsKey("count")) {
            requestedCount = signedInteger(fields.values.get("count"));
            if (requestedCount == null) return rejected(ScimError.invalidValueInstance());
        }
        int maximum = Math.min(limits.getMaximumPageSize(), paging.getMaximumPageSize());
        if (filter != null) maximum = Math.min(maximum, config.getFilterMaximumResults());
        long normalizedCount = requestedCount == null ? paging.getDefaultPageSize() : Math.max(0, requestedCount);
        if (method == ScimPaginationMethod.CURSOR && requestedCount != null && normalizedCount > maximum)
            return rejected(ScimError.invalidCountInstance());
        int count = (int) Math.min(maximum, normalizedCount);
        return new ScimQueryParseResult.Succeeded(new ScimQuery(type, filter, selection, sortBy, sortOrder,
                method, startIndex, count, requestedCount, cursor,
                method == ScimPaginationMethod.CURSOR && (cursor == null || cursor.isEmpty()), context,
                limits.getMaximumCursorCharacters()));
    }

    private static @NonNull ScimAttributeSelectionResult select(@NonNull ScimResourceType type,
            @NonNull Fields fields, @NonNull ScimLimits limits, @NonNull Object context, @NonNull ScimWork work) {
        boolean included = fields.values.containsKey("attributes");
        boolean excluded = fields.values.containsKey("excludedattributes");
        if (included && excluded) return new ScimAttributeSelectionResult.Rejected(ScimError.invalidValueInstance());
        Set<@NonNull ScimAttributePath> includePaths = new LinkedHashSet<>();
        Set<@NonNull ScimAttributePath> excludePaths = new LinkedHashSet<>();
        if (included || excluded) {
            List<String> paths = included ? fields.included : fields.excluded;
            if (paths == null) paths = commaPaths(Objects.requireNonNull(fields.values.get(included ? "attributes" : "excludedattributes")),
                    limits.getMaximumProjectionPaths());
            if (paths == null || paths.isEmpty())
                return new ScimAttributeSelectionResult.Rejected(ScimError.invalidPathInstance());
            for (String expression : paths) {
                if (!work.spend(expression.length() + 1L + 4L * type.definitionCount()))
                    return new ScimAttributeSelectionResult.Rejected(ScimError.invalidPathInstance());
                String trimmed = trimWhitespace(expression);
                ScimAttributePathParseResult parsed = ScimAttributePath.fromExpressionResult(trimmed);
                if (!(parsed instanceof ScimAttributePathParseResult.Succeeded path))
                    return new ScimAttributeSelectionResult.Rejected(ScimError.invalidPathInstance());
                Optional<ScimAttributePath> canonical = ScimSchemas.canonicalPath(type, path.getAttributePath());
                if (canonical.isEmpty()) return new ScimAttributeSelectionResult.Rejected(ScimError.invalidPathInstance());
                if (included) includePaths.add(canonical.get()); else excludePaths.add(canonical.get());
            }
        }
        return new ScimAttributeSelectionResult.Succeeded(new ScimAttributeSelection(type, includePaths, excludePaths,
                included || excluded, context));
    }

    private static @Nullable List<@NonNull String> commaPaths(@NonNull String value, int maximum) {
        List<@NonNull String> paths = new ArrayList<>();
        int start = 0;
        while (true) {
            if (paths.size() == maximum) return null;
            int end = value.indexOf(',', start);
            if (end < 0) end = value.length();
            paths.add(value.substring(start, end));
            if (end == value.length()) return paths;
            start = end + 1;
        }
    }

    private static @NonNull String trimWhitespace(@NonNull String value) {
        int first = 0;
        int last = value.length();
        while (first < last && whitespace(value.charAt(first))) first++;
        while (last > first && whitespace(value.charAt(last - 1))) last--;
        return value.substring(first, last);
    }
    private static boolean whitespace(char unit) { return unit == ' ' || unit == '\t' || unit == '\r' || unit == '\n' || unit == '\f'; }

    private static boolean validCursor(@NonNull String value, int maximum) {
        if (value.length() > maximum) return false;
        for (int index = 0; index < value.length(); index++) {
            char unit = value.charAt(index);
            if (!(unit >= 'A' && unit <= 'Z' || unit >= 'a' && unit <= 'z' || unit >= '0' && unit <= '9'
                    || unit == '-' || unit == '.' || unit == '_' || unit == '~')) return false;
        }
        return true;
    }

    private static @Nullable Long signedInteger(@NonNull String value) {
        if (value.isEmpty()) return null;
        boolean negative = value.charAt(0) == '-';
        int index = negative ? 1 : 0;
        if (index == value.length()) return null;
        long limit = negative ? Long.MIN_VALUE : -Long.MAX_VALUE;
        long multiplyLimit = limit / 10;
        long result = 0;
        for (; index < value.length(); index++) {
            char unit = value.charAt(index);
            if (unit < '0' || unit > '9' || result < multiplyLimit) return null;
            int digit = unit - '0';
            result *= 10;
            if (result < limit + digit) return null;
            result -= digit;
        }
        return negative ? result : -result;
    }

    private static boolean recognized(@NonNull String name) {
        return name.equals("filter") || name.equals("sortby") || name.equals("sortorder") || name.equals("startindex")
                || name.equals("count") || name.equals("cursor") || name.equals("attributes") || name.equals("excludedattributes");
    }

    private static @NonNull Fields raw(@NonNull String raw, @NonNull ScimLimits limits, @NonNull ScimWork work) {
        Objects.requireNonNull(raw);
        Fields fields = new Fields();
        if (raw.length() > limits.getMaximumRawQueryBytes() || !work.spend(raw.length())) {
            fields.error = ScimError.invalidSyntaxInstance(); return fields;
        }
        int octets = utf8Length(raw, 0, raw.length(), false);
        if (octets < 0 || octets > limits.getMaximumRawQueryBytes() || !work.spend(2L * octets)) {
            fields.error = ScimError.invalidSyntaxInstance(); return fields;
        }
        if (raw.isEmpty()) return fields;
        int start = 0;
        int parameters = 0;
        while (true) {
            if (++parameters > limits.getMaximumQueryParameters()) {
                fields.error = ScimError.invalidSyntaxInstance(); return fields;
            }
            int end = raw.indexOf('&', start);
            if (end < 0) end = raw.length();
            int separator = start;
            while (separator < end && raw.charAt(separator) != '=') separator++;
            String name = decode(raw, start, separator, limits.getMaximumParameterCharacters());
            String value = decode(raw, separator < end ? separator + 1 : end, end, limits.getMaximumParameterCharacters());
            if (name == null || value == null) { fields.error = ScimError.invalidSyntaxInstance(); return fields; }
            String folded = AsciiCase.fold(name);
            if (recognized(folded)) {
                if (fields.values.putIfAbsent(folded, value) != null) {
                    fields.error = ScimError.invalidSyntaxInstance(); return fields;
                }
            }
            if (end == raw.length()) return fields;
            start = end + 1;
        }
    }

    private static int utf8Length(@NonNull String value, int start, int end, boolean decodeEscapes) {
        int bytes = 0;
        for (int index = start; index < end; index++) {
            char unit = value.charAt(index);
            if (unit == '%' && decodeEscapes) {
                if (index + 2 >= end || hex(value.charAt(index + 1)) < 0 || hex(value.charAt(index + 2)) < 0) return -1;
                index += 2; bytes++;
            } else if (Character.isHighSurrogate(unit)) {
                if (++index >= end || !Character.isLowSurrogate(value.charAt(index))) return -1;
                bytes += 4;
            } else if (Character.isLowSurrogate(unit)) return -1;
            else bytes += unit < 0x80 ? 1 : unit < 0x800 ? 2 : 3;
        }
        return bytes;
    }

    private static @Nullable String decode(@NonNull String raw, int start, int end, int maximumCharacters) {
        int length = utf8Length(raw, start, end, true);
        if (length < 0) return null;
        byte[] octets = new byte[length];
        char[] characters = new char[Math.min(length, maximumCharacters)];
        try {
            int position = 0;
            for (int index = start; index < end; index++) {
                char unit = raw.charAt(index);
                if (unit == '%') {
                    octets[position++] = (byte) ((hex(raw.charAt(index + 1)) << 4) | hex(raw.charAt(index + 2)));
                    index += 2;
                } else if (unit == '+') octets[position++] = ' ';
                else {
                    int codePoint = Character.isHighSurrogate(unit) ? Character.toCodePoint(unit, raw.charAt(++index)) : unit;
                    if (codePoint < 0x80) octets[position++] = (byte) codePoint;
                    else if (codePoint < 0x800) {
                        octets[position++] = (byte) (0xc0 | codePoint >> 6);
                        octets[position++] = (byte) (0x80 | codePoint & 0x3f);
                    } else if (codePoint < 0x10000) {
                        octets[position++] = (byte) (0xe0 | codePoint >> 12);
                        octets[position++] = (byte) (0x80 | codePoint >> 6 & 0x3f);
                        octets[position++] = (byte) (0x80 | codePoint & 0x3f);
                    } else {
                        octets[position++] = (byte) (0xf0 | codePoint >> 18);
                        octets[position++] = (byte) (0x80 | codePoint >> 12 & 0x3f);
                        octets[position++] = (byte) (0x80 | codePoint >> 6 & 0x3f);
                        octets[position++] = (byte) (0x80 | codePoint & 0x3f);
                    }
                }
            }
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            CharBuffer output = CharBuffer.wrap(characters);
            CoderResult result = decoder.decode(ByteBuffer.wrap(octets), output, true);
            if (!result.isUnderflow()) return null;
            if (!decoder.flush(output).isUnderflow()) return null;
            return new String(characters, 0, output.position());
        } finally {
            Arrays.fill(octets, (byte) 0);
            Arrays.fill(characters, '\0');
        }
    }
    private static int hex(char unit) {
        return unit >= '0' && unit <= '9' ? unit - '0' : unit >= 'a' && unit <= 'f' ? unit - 'a' + 10
                : unit >= 'A' && unit <= 'F' ? unit - 'A' + 10 : -1;
    }

    private static @NonNull ScimQueryParseResult rejected(@NonNull ScimError error) {
        return new ScimQueryParseResult.Rejected(error);
    }
    private static final class Fields {
        private final @NonNull Map<@NonNull String, @NonNull String> values = new LinkedHashMap<>();
        private @Nullable List<@NonNull String> included;
        private @Nullable List<@NonNull String> excluded;
        private @Nullable ScimError error;
        private Fields() {}
    }
}
