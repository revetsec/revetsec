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
import com.revetsec.internal.Limits;
import com.revetsec.internal.HostClassifier;
import com.revetsec.internal.json.JsonDocument;
import com.revetsec.internal.json.JsonNumberSyntax;
import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.math.BigDecimal;
import javax.annotation.concurrent.NotThreadSafe;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Pure schema validation and canonical normalization; no input exceptions are used as control flow. */
@NotThreadSafe
final class ScimResourceValidation {
    private final @NonNull ScimResourceType type;
    private final @Nullable JsonDocument parsed;
    private final @NonNull ScimCompatibility compatibility;
    private final @NonNull ScimWork work;
    private final boolean create;
    private final @NonNull Set<@NonNull ScimCompatibilityFeature> usedFeatures;
    private final @NonNull Set<@NonNull ScimAttributePath> supplied = new LinkedHashSet<>();
    private final @NonNull Map<@NonNull JsonObject,@NonNull Map<@NonNull String,@NonNull Set<@NonNull String>>> explicitNulls=new IdentityHashMap<>();
    private @Nullable ScimError error;
    private boolean preservePatchNulls;
    ScimResourceValidation(@NonNull ScimResourceType type, @Nullable JsonDocument parsed,
            @NonNull ScimCompatibility compatibility, @NonNull ScimWork work, boolean create) {
        this(type,parsed,compatibility,work,create,new LinkedHashSet<>());
    }
    ScimResourceValidation(@NonNull ScimResourceType type, @Nullable JsonDocument parsed,
            @NonNull ScimCompatibility compatibility, @NonNull ScimWork work, boolean create,
            @NonNull Set<@NonNull ScimCompatibilityFeature> usedFeatures) {
        this.type = type; this.parsed = parsed; this.compatibility = compatibility; this.work = work; this.create = create; this.usedFeatures=usedFeatures;
    }
    boolean explicitlyCleared(@NonNull JsonObject object,@NonNull String name,@NonNull String prefix) { return explicitNulls.getOrDefault(object,Map.of()).getOrDefault(prefix,Set.of()).contains(AsciiCase.fold(name)); }
    @NonNull Set<@NonNull ScimAttributePath> supplied() { return supplied; }
    @NonNull ScimError error() { return error == null ? ScimError.invalidValueInstance() : error; }
    boolean failed() { return error != null; }
    private boolean spend(long amount) {
        if (work.spend(amount)) return true;
        error = ScimError.requestTooLargeInstance(); return false;
    }
    private boolean enabled(@NonNull ScimCompatibilityFeature feature) { return compatibility.getFeatures().contains(feature); }
    @Nullable JsonObject normalize(@NonNull JsonObject input) { return normalize(input,true); }
    @Nullable JsonObject normalize(@NonNull JsonObject input, boolean enforceRequired) {
        Map<String, JsonValue> source = folded(input);
        if (source == null) return null;
        Set<String> declarations = declarations(source.get("schemas"));
        if (declarations == null) return null;
        LinkedHashMap<String, JsonValue> normalized = new LinkedHashMap<>();
        List<ScimAttributeDefinition> attributes = ScimResources.definitions(type);
        Set<String> recognized = new HashSet<>(); recognized.add("schemas");
        for (ScimAttributeDefinition definition : attributes) {
            if (!spend(1)) return null;
            String name = definition.getName();
            String folded = AsciiCase.fold(name);
            if (!recognized.add(folded)) continue;
            JsonValue value = source.get(folded);
            if (value != null) {
                if (create && definition.getMutability() == ScimMutability.READ_ONLY) { if (!scan(value)) return null; continue; }
                JsonValue canonical = value(definition, value, name, enforceRequired);
                if (failed()) return null;
                if (canonical != null) normalized.put(name, canonical);
            }
        }
        for (ScimSchemaExtension extension : type.getSchemaExtensions()) {
            ScimSchema schema = extension.getSchema(); String id = schema.getId(); String key = AsciiCase.fold(id);
            recognized.add(key);
            JsonValue value = source.get(key);
            if (value == null || value instanceof JsonNull) {
                if (enforceRequired && extension.isRequired()) { error = ScimError.invalidValueInstance(); return null; }
                continue;
            }
            if (!declarations.contains(key)) {
                if (!enabled(ScimCompatibilityFeature.INFER_MISSING_EXTENSION_SCHEMAS)) { error = ScimError.invalidValueInstance(); return null; }
                usedFeatures.add(ScimCompatibilityFeature.INFER_MISSING_EXTENSION_SCHEMAS);
                declarations.add(key);
            }
            if (!(value instanceof JsonObject object)) { error = ScimError.invalidValueInstance(); return null; }
            JsonObject canonical = object(schema.getAttributes(), object, id + ":", enforceRequired);
            if (canonical == null) return null;
            normalized.put(id, canonical);
        }
        for (Map.Entry<String,JsonValue> member : source.entrySet()) if (!recognized.contains(member.getKey())) {
            if (!scan(member.getValue())) return null;
            if (!enabled(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES)) { error = ScimError.invalidValueInstance(); return null; }
            usedFeatures.add(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES);
        }
        List<JsonValue> schemaIds = new ArrayList<>();
        schemaIds.add(JsonString.fromValue(type.getSchema().getId()));
        for (ScimSchemaExtension extension : type.getSchemaExtensions()) {
            String id = extension.getSchema().getId();
            if (declarations.contains(AsciiCase.fold(id))) schemaIds.add(JsonString.fromValue(id));
        }
        normalized.put("schemas", JsonArray.fromElements(schemaIds));
        JsonObject result = JsonObject.fromMembers(normalized);
        if (enforceRequired && !required(attributes, result)) return null;
        return result;
    }
    private @Nullable Set<@NonNull String> declarations(@Nullable JsonValue raw) {
        if (!(raw instanceof JsonArray array) || array.getElements().isEmpty()) { error = ScimError.invalidValueInstance(); return null; }
        Set<String> declared = new LinkedHashSet<>();
        for (JsonValue value : array.getElements()) {
            if (!spend(1)) return null;
            if (!(value instanceof JsonString string)) { error = ScimError.invalidValueInstance(); return null; }
            if (!ScimSchemas.absoluteUri(string.getValue())) { error = ScimError.invalidValueInstance(); return null; }
            String key = AsciiCase.fold(string.getValue());
            if (!declared.add(key)) { error = ScimError.invalidValueInstance(); return null; }
            boolean registered = false;
            for (ScimSchema schema : ScimSchemas.allSchemas(type)) {
                if (!spend(1)) return null;
                if (AsciiCase.fold(schema.getId()).equals(key)) registered = true;
            }
            if (!registered) {
                if (!enabled(ScimCompatibilityFeature.IGNORE_UNDECLARED_SCHEMA_URIS)) { error = ScimError.invalidValueInstance(); return null; }
                usedFeatures.add(ScimCompatibilityFeature.IGNORE_UNDECLARED_SCHEMA_URIS);
            }
        }
        if (!declared.contains(AsciiCase.fold(type.getSchema().getId()))) { error = ScimError.invalidValueInstance(); return null; }
        return declared;
    }
    private @Nullable Map<@NonNull String, @NonNull JsonValue> folded(@NonNull JsonObject input) {
        LinkedHashMap<String, JsonValue> folded = new LinkedHashMap<>();
        for (Map.Entry<String, JsonValue> entry : input.getMembers().entrySet()) {
            if (!spend(1L + entry.getKey().length())) return null;
            String key = AsciiCase.fold(entry.getKey());
            if (folded.putIfAbsent(key, entry.getValue()) != null) { error = ScimError.invalidValueInstance(); return null; }
        }
        return folded;
    }
    private @Nullable JsonObject object(@NonNull List<@NonNull ScimAttributeDefinition> definitions,
            @NonNull JsonObject input, @NonNull String prefix, boolean enforceRequired) {
        Map<String, JsonValue> source = folded(input);
        if (source == null) return null;
        LinkedHashMap<String, JsonValue> normalized = new LinkedHashMap<>();
        Set<String> recognized = new HashSet<>();
        for (ScimAttributeDefinition definition : definitions) {
            if (!spend(1)) return null;
            String name = definition.getName(); String folded = AsciiCase.fold(name); recognized.add(folded);
            JsonValue value = source.get(folded);
            if (value != null && create && definition.getMutability() == ScimMutability.READ_ONLY) { if (!scan(value)) return null; }
            if (value != null && !(create && definition.getMutability() == ScimMutability.READ_ONLY)) {
                JsonValue canonical = value(definition, value, prefix + name, enforceRequired);
                if (failed()) return null;
                if (canonical != null) normalized.put(name, canonical);
            }
        }
        for (Map.Entry<String,JsonValue> member : source.entrySet()) if (!recognized.contains(member.getKey())) {
            if (!scan(member.getValue())) return null;
            if (!enabled(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES)) { error = ScimError.invalidValueInstance(); return null; }
            usedFeatures.add(ScimCompatibilityFeature.IGNORE_UNKNOWN_ATTRIBUTES);
        }
        JsonObject result = JsonObject.fromMembers(normalized);
        Set<String> nullNames=new HashSet<>();
        for (Map.Entry<String,JsonValue> member : source.entrySet()) {
            if (!spend(1)) return null;
            if (member.getValue() instanceof JsonNull) nullNames.add(member.getKey());
        }
        if (!nullNames.isEmpty()) explicitNulls.computeIfAbsent(result,ignored -> new LinkedHashMap<>()).put(prefix,Set.copyOf(nullNames));
        return !enforceRequired || required(definitions, result) ? result : null;
    }
    /** Normalizes one partial PATCH attribute, preserving explicit-null instructions and wire-number evidence. */
    @Nullable JsonValue patchValue(@NonNull ScimAttributeDefinition definition, @NonNull JsonValue input,
            @NonNull String path, boolean scalarElement) {
        preservePatchNulls=true;
        if (!spend(1)) return null;
        if (input instanceof JsonNull) { record(path); return input; }
        return scalarElement ? scalar(definition,input,path,false) : value(definition,input,path,false);
    }
    private @Nullable JsonValue value(@NonNull ScimAttributeDefinition definition, @NonNull JsonValue input,
            @NonNull String path, boolean enforceRequired) {
        if (!spend(1)) return null;
        if (input instanceof JsonNull) { record(path); return preservePatchNulls ? input : null; }
        if (definition.isMultiValued()) {
            if (!(input instanceof JsonArray array)) { error = ScimError.invalidValueInstance(); return null; }
            if (!spend(definition.getSubAttributes().size())) return null;
            ScimAttributeDefinition primary = ScimSchemas.attribute(definition.getSubAttributes(), "primary").orElse(null);
            List<JsonValue> normalized = new ArrayList<>(); int primaries = 0;
            Set<String> groupMemberIds = new HashSet<>();
            for (JsonValue element : array.getElements()) {
                if (element instanceof JsonNull) { error = ScimError.invalidValueInstance(); return null; }
                JsonValue canonical = scalar(definition, element, path, enforceRequired);
                if (canonical == null) return null;
                normalized.add(canonical);
                if (path.equals("members") && type.hasStandardGroupSchema()
                        && canonical instanceof JsonObject member) {
                    String id = member.find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElse(null);
                    if (id != null && !id.isEmpty() && !groupMemberIds.add(id)) {
                        error = ScimError.invalidValueInstance(); return null;
                    }
                }
                if (primary != null && primary.getType() == ScimAttributeType.BOOLEAN
                        && canonical instanceof JsonObject object && object.find(primary.getName()).filter(JsonBoolean.class::isInstance).map(JsonBoolean.class::cast).map(JsonBoolean::getValue).orElse(false) && ++primaries > 1) {
                    error = ScimError.invalidValueInstance(); return null;
                }
            }
            if (array.getElements().isEmpty()) record(path);
            return JsonArray.fromElements(normalized);
        }
        if (input instanceof JsonArray) { error = ScimError.invalidValueInstance(); return null; }
        return scalar(definition, input, path, enforceRequired);
    }
    private @Nullable JsonValue scalar(@NonNull ScimAttributeDefinition definition, @NonNull JsonValue input,
            @NonNull String path, boolean enforceRequired) {
        if (!spend(1)) return null;
        if (definition.getType() == ScimAttributeType.COMPLEX) {
            JsonValue complex = input;
            if (input instanceof JsonString string && type.isStandardEnterpriseManagerPath(path)
                    && enabled(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR))
                {
                usedFeatures.add(ScimCompatibilityFeature.COMPLEX_VALUE_AS_SCALAR);
                complex = JsonObject.builder().put("value", string).build();
            }
            if (!(complex instanceof JsonObject object)) { error = ScimError.invalidValueInstance(); return null; }
            if (object.getMembers().isEmpty()) record(path);
            return object(definition.getSubAttributes(), object, path + ".", enforceRequired);
        }
        JsonValue normalized = input;
        if (input instanceof JsonString string && !spend(string.getValue().length())) return null;
        boolean valid = switch (definition.getType()) {
            case STRING -> input instanceof JsonString;
            case BOOLEAN -> input instanceof JsonBoolean;
            case DECIMAL -> input instanceof JsonNumber;
            case INTEGER -> integer(input);
            case DATE_TIME -> input instanceof JsonString string && dateTime(string.getValue());
            case BINARY -> input instanceof JsonString string && binary(string.getValue());
            case REFERENCE -> input instanceof JsonString string && reference(string.getValue());
            case COMPLEX -> false;
        };
        if (!valid && definition.getType() == ScimAttributeType.BOOLEAN && input instanceof JsonString string
                && enabled(ScimCompatibilityFeature.BOOLEAN_STRINGS)
                && (string.getValue().equals("true") || string.getValue().equals("false"))) {
            usedFeatures.add(ScimCompatibilityFeature.BOOLEAN_STRINGS);
            normalized = JsonBoolean.fromValue(string.getValue().equals("true")); valid = true;
        }
        if (!valid) { error = ScimError.invalidValueInstance(); return null; }
        if (definition.getType() == ScimAttributeType.INTEGER && input instanceof JsonNumber number) {
            BigDecimal numeric = number.getValue();
            normalized = JsonNumber.fromValue(numeric.signum() == 0 ? BigDecimal.ZERO : new BigDecimal(numeric.toBigInteger()));
        }
        if ((path.equals("id") || path.equals("members.value") && type.hasStandardGroupSchema()
                || path.equals("groups.value") && type.hasStandardUserSchema()
                || type.isStandardEnterpriseManagerValuePath(path)) && normalized instanceof JsonString string && !validResourceId(string.getValue())) {
            error = ScimError.invalidValueInstance(); return null;
        }
        if (path.equals("meta.resourceType") && normalized instanceof JsonString string && !string.getValue().equals(type.getName())) {
            error = ScimError.invalidValueInstance(); return null;
        }
        if ((path.equals("meta.created") || path.equals("meta.lastModified")) && normalized instanceof JsonString string) {
            DateParts parts = dateParts(string.getValue());
            if (parts == null || !parts.hasOffset || !parts.inInstantRange) { error = ScimError.invalidValueInstance(); return null; }
        }
        if (path.equals("meta.version") && normalized instanceof JsonString string && !entityTag(string.getValue())) {
            error = ScimError.invalidValueInstance(); return null;
        }
        if (path.equals("meta.location") && normalized instanceof JsonString string && !location(string.getValue())) {
            error = ScimError.invalidValueInstance(); return null;
        }
        record(path);
        return normalized;
    }
    private boolean integer(@NonNull JsonValue input) {
        if (!(input instanceof JsonNumber number)) return false;
        if (parsed != null) {
            java.util.Optional<JsonNumberSyntax> syntax = parsed.numberSyntax(number);
            if (syntax.isEmpty() || syntax.orElseThrow().hadFraction() || syntax.orElseThrow().hadExponent()) return false;
        }
        BigDecimal value = number.getValue();
        long integerDigits = (long)value.precision() - value.scale();
        return value.signum() == 0 || value.stripTrailingZeros().scale() <= 0
                && integerDigits <= com.revetsec.internal.json.JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS;
    }
    private boolean required(@NonNull List<@NonNull ScimAttributeDefinition> definitions, @NonNull JsonObject object) {
        for (ScimAttributeDefinition definition : definitions) {
            if (!spend(1)) return false;
            if (definition.isRequired() && !(create && definition.getMutability() == ScimMutability.READ_ONLY)
                    && !assigned(object.getMembers().get(definition.getName()))) {
                error = ScimError.invalidValueInstance(); return false;
            }
        }
        return true;
    }
    private boolean scan(@Nullable JsonValue value) {
        if (!spend(1)) return false;
        if (value instanceof JsonString string) return spend(string.getValue().length());
        if (value instanceof JsonNumber number) return spend(number.getValue().precision());
        if (value instanceof JsonObject object) {
            Map<String,JsonValue> members = folded(object);
            if (members == null) return false;
            for (JsonValue child : members.values()) if (!scan(child)) return false;
        }
        if (value instanceof JsonArray array) for (JsonValue child : array.getElements()) if (!scan(child)) return false;
        return true;
    }
    private void record(@NonNull String path) {
        ScimAttributePathParseResult result = ScimAttributePath.fromExpressionResult(type.getSchema().isDiscovery() ? ScimResources.descriptorPath(path) : path);
        if (result instanceof ScimAttributePathParseResult.Succeeded success) supplied.add(success.getAttributePath());
        else error = ScimError.invalidValueInstance();
    }
    static boolean assigned(@Nullable JsonValue value) {
        return value != null && !(value instanceof JsonNull) && !(value instanceof JsonArray array && array.getElements().isEmpty())
                && !(value instanceof JsonString string && string.getValue().isEmpty());
    }
    static boolean validResourceId(@NonNull String value) {
        if (value.isEmpty() || value.equals(".") || value.equals("..")
                || value.length() > Limits.SCIM_IDENTIFIER_LENGTH.getCap()
                || AsciiCase.fold(value).contains("bulkid")) return false;
        for (int index = 0; index < value.length(); index++) if (value.charAt(index) < 0x20 || value.charAt(index) == 0x7f) return false;
        return true;
    }
    private static boolean entityTag(@NonNull String value) {
        if (value.length() > Limits.SCIM_IDENTIFIER_LENGTH.getCap()) return false;
        int index = value.startsWith("W/") ? 2 : 0;
        if (value.length() - index < 2 || value.charAt(index++) != '"' || value.charAt(value.length()-1) != '"') return false;
        for (; index < value.length()-1; index++) {
            char ch = value.charAt(index);
            if (!(ch == 0x21 || ch >= 0x23 && ch <= 0x7e || ch >= 0x80 && ch <= 0xff)) return false;
        }
        return true;
    }
    private static boolean location(@NonNull String value) {
        // Absolute hierarchical HTTP(S) references are also safe for the intentional URI getter.
        if (!(AsciiCase.fold(value).startsWith("https://") || AsciiCase.fold(value).startsWith("http://"))) return false;
        if (!reference(value)) return false;
        int authorityStart = value.indexOf("//") + 2;
        int authorityEnd = value.length();
        for (int index = authorityStart; index < value.length(); index++) if (value.charAt(index) == '/' || value.charAt(index) == '?' || value.charAt(index) == '#') { authorityEnd = index; break; }
        String authority = value.substring(authorityStart, authorityEnd);
        if (authority.isEmpty() || authority.indexOf('@') >= 0) return false;
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            return close > 0 && com.revetsec.internal.HostClassifier.parseLiteral(authority.substring(0, close + 1)) != null;
        }
        for (int index = 0; index < authority.length(); index++) if (authority.charAt(index) == '[' || authority.charAt(index) == ']') return false;
        return true;
    }
    static boolean reference(@NonNull String value) {
        String absolute = value;
        int firstColon = value.indexOf(':'), firstSlash = value.indexOf('/');
        if (value.startsWith("//")) absolute = "https:" + value;
        else if (firstColon < 0 || firstSlash >= 0 && firstSlash < firstColon || value.startsWith("?") || value.startsWith("#"))
            absolute = "https://example.invalid/" + value;
        return ScimAttributePath.isAbsoluteUriSyntax(absolute);
    }
    private static boolean digit(char character) { return character >= '0' && character <= '9'; }

    static boolean binary(@NonNull String value) {
        if (value.isEmpty()) return true;
        int padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
        int content = value.length() - padding;
        if (content == 0 || content % 4 == 1 || padding > 0 && value.length() % 4 != 0) return false;
        for (int index = 0; index < content; index++) {
            char ch = value.charAt(index);
            if (!(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '+' || ch == '/')) return false;
        }
        char last = value.charAt(content - 1);
        int bits = last >= 'A' && last <= 'Z' ? last - 'A' : last >= 'a' && last <= 'z' ? last - 'a' + 26
                : last >= '0' && last <= '9' ? last - '0' + 52 : last == '+' ? 62 : 63;
        int remainder = content % 4;
        return remainder == 0 && padding == 0 || remainder == 2 && (padding == 0 || padding == 2) && (bits & 15) == 0
                || remainder == 3 && (padding == 0 || padding == 1) && (bits & 3) == 0;
    }
    static boolean dateTime(@NonNull String value) { return dateParts(value) != null; }
    private static @Nullable DateParts dateParts(@NonNull String value) {
        int yearStart = value.startsWith("-") ? 1 : 0;
        int yearEnd = yearStart;
        long yearMagnitude = 0; int yearMod = 0; boolean nonzero = false;
        while (yearEnd < value.length() && digit(value.charAt(yearEnd))) {
            int digit = value.charAt(yearEnd++) - '0';
            yearMod = (yearMod * 10 + digit) % 400; nonzero |= digit != 0;
            yearMagnitude = Math.min(1_000_000_000L,yearMagnitude*10 + digit);
        }
        int count = yearEnd - yearStart;
        if (count < 4 || !nonzero || count > 4 && value.charAt(yearStart) == '0' || value.length()-yearEnd < 15) return null;
        int month = digits(value,yearEnd+1,yearEnd+3), day = digits(value,yearEnd+4,yearEnd+6);
        int hour = digits(value,yearEnd+7,yearEnd+9), minute = digits(value,yearEnd+10,yearEnd+12), second = digits(value,yearEnd+13,yearEnd+15);
        if (value.charAt(yearEnd) != '-' || value.charAt(yearEnd+3) != '-' || value.charAt(yearEnd+6) != 'T'
                || value.charAt(yearEnd+9) != ':' || value.charAt(yearEnd+12) != ':' || month < 1 || month > 12
                || hour < 0 || hour > 24 || minute < 0 || minute > 59 || second < 0 || second > 59) return null;
        int calendarMod = yearStart == 0 ? yearMod : (401-yearMod)%400;
        int maximum = switch (month) { case 2 -> calendarMod % 4 == 0 && (calendarMod % 100 != 0 || calendarMod == 0) ? 29 : 28; case 4,6,9,11 -> 30; default -> 31; };
        if (day < 1 || day > maximum || hour == 24 && (minute != 0 || second != 0)) return null;
        int index = yearEnd+15, nanos = 0; boolean fractionNonzero = false;
        if (index < value.length() && value.charAt(index) == '.') {
            int start = ++index;
            while (index < value.length() && digit(value.charAt(index))) {
                int digit = value.charAt(index) - '0'; fractionNonzero |= digit != 0;
                if (index - start < 9) nanos = nanos*10+digit;
                index++;
            }
            if (index == start || hour == 24 && fractionNonzero) return null;
            for (int scale = Math.min(9,index-start); scale < 9; scale++) nanos *= 10;
        }
        boolean hasOffset = index < value.length(); int offsetSeconds = 0;
        if (hasOffset) {
            if (value.charAt(index) == 'Z') { if (index+1 != value.length()) return null; }
            else {
                if (value.length()-index != 6 || value.charAt(index) != '+' && value.charAt(index) != '-' || value.charAt(index+3) != ':') return null;
                int hours = digits(value,index+1,index+3), minutes = digits(value,index+4,index+6);
                if (hours < 0 || hours > 14 || minutes < 0 || minutes > 59 || hours == 14 && minutes != 0) return null;
                offsetSeconds = (hours*60+minutes)*60*(value.charAt(index) == '-' ? -1 : 1);
            }
        }
        int year = (int)(yearStart == 0 ? yearMagnitude : 1-yearMagnitude);
        return new DateParts(year,month,day,hour,minute,second,nanos,offsetSeconds,hasOffset,yearMagnitude<1_000_000_000L);
    }
    private static int digits(@NonNull String value, int start, int end) {
        int result = 0;
        for (int index = start; index < end; index++) { char ch = value.charAt(index); if (!digit(ch)) return -1; result = result * 10 + ch - '0'; }
        return result;
    }
    static @NonNull Instant instant(@NonNull String value) {
        DateParts parts = java.util.Objects.requireNonNull(dateParts(value));
        LocalDateTime date = LocalDateTime.of(parts.year,parts.month,parts.day,parts.hour == 24 ? 0 : parts.hour,parts.minute,parts.second,parts.nanos);
        long seconds = date.toEpochSecond(ZoneOffset.UTC)-parts.offsetSeconds + (parts.hour == 24 ? 86400 : 0);
        return Instant.ofEpochSecond(seconds,parts.nanos);
    }
    private static final class DateParts {
        final int year,month,day,hour,minute,second,nanos,offsetSeconds;
        final boolean hasOffset,inInstantRange;
        DateParts(int year,int month,int day,int hour,int minute,int second,int nanos,int offsetSeconds,boolean hasOffset,boolean inInstantRange) {
            this.year=year; this.month=month; this.day=day; this.hour=hour; this.minute=minute; this.second=second; this.nanos=nanos;
            this.offsetSeconds=offsetSeconds; this.hasOffset=hasOffset; this.inInstantRange=inInstantRange;
        }
    }
}
