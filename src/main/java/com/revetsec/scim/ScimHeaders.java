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

import com.revetsec.internal.Limits;
import com.revetsec.internal.json.AsciiCase;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.util.List;

import static java.util.Objects.requireNonNull;

/** Bounded raw-header parsers. Expected wire errors return fixed outcomes without exceptions. */
@ThreadSafe
final class ScimHeaders {
    private ScimHeaders() { }

    static @NonNull ScimContentTypeResult contentType(@NonNull List<@NonNull String> values) {
        requireNonNull(values);
        if (values.size() != 1) return mediaRejected();
        String value = requireNonNull(values.get(0));
        if (value.length() > Limits.SCIM_CONTENT_TYPE_HEADER_BYTES.getCap()) return mediaRejected();
        for (int index = 0; index < value.length(); ++index) {
            char ch = value.charAt(index);
            if (ch > 0x7e || (ch < 0x20 && ch != '\t')) return mediaRejected();
        }
        int index = whitespace(value, 0);
        int start = index;
        while (index < value.length() && token(value.charAt(index))) ++index;
        if (start == index || index >= value.length() || value.charAt(index++) != '/') return mediaRejected();
        String type = AsciiCase.fold(value.substring(start, index - 1));
        start = index;
        while (index < value.length() && token(value.charAt(index))) ++index;
        if (start == index) return mediaRejected();
        String subtype = AsciiCase.fold(value.substring(start, index));
        if (!type.equals("application") || (!subtype.equals("scim+json") && !subtype.equals("json"))) return mediaRejected();
        index = whitespace(value, index);
        if (index == value.length()) return ScimContentTypeResult.Accepted.INSTANCE;
        if (value.charAt(index++) != ';') return mediaRejected();
        index = whitespace(value, index);
        start = index;
        while (index < value.length() && token(value.charAt(index))) ++index;
        if (start == index || !AsciiCase.fold(value.substring(start, index)).equals("charset")) return mediaRejected();
        index = whitespace(value, index);
        if (index >= value.length() || value.charAt(index++) != '=') return mediaRejected();
        index = whitespace(value, index);
        if (index >= value.length()) return mediaRejected();
        if (value.charAt(index) == '"') {
            ++index;
            boolean any = false;
            while (index < value.length() && value.charAt(index) != '"') {
                char ch = value.charAt(index++);
                if (ch == '\\') {
                    if (index >= value.length()) return mediaRejected();
                    ch = value.charAt(index++);
                }
                if (!token(ch)) return mediaRejected();
                any = true;
            }
            if (!any || index >= value.length() || value.charAt(index++) != '"') return mediaRejected();
        } else {
            start = index;
            while (index < value.length() && token(value.charAt(index))) ++index;
            if (start == index) return mediaRejected();
        }
        return whitespace(value, index) == value.length() ? ScimContentTypeResult.Accepted.INSTANCE : mediaRejected();
    }

    static @NonNull ScimIfMatchResult ifMatch(@NonNull List<@NonNull String> values,
            @NonNull ScimResource current, @NonNull ScimLimits limits) {
        Conditional parsed = conditional(values, current, limits);
        if (parsed.error != null) return new ScimIfMatchResult.Rejected(parsed.error);
        return !parsed.present || parsed.wildcard || parsed.matched ? ScimIfMatchResult.Satisfied.INSTANCE
                : new ScimIfMatchResult.Rejected(ScimError.preconditionFailedInstance());
    }

    static @NonNull ScimIfNoneMatchResult ifNoneMatch(@NonNull List<@NonNull String> values,
            @NonNull ScimResource current, @NonNull ScimLimits limits) {
        Conditional parsed = conditional(values, current, limits);
        if (parsed.error != null) return new ScimIfNoneMatchResult.Rejected(parsed.error);
        return parsed.present && (parsed.wildcard || parsed.matched) ? ScimIfNoneMatchResult.NotModified.INSTANCE
                : ScimIfNoneMatchResult.Proceed.INSTANCE;
    }

    private static @NonNull Conditional conditional(@NonNull List<@NonNull String> values,
            @NonNull ScimResource current, @NonNull ScimLimits limits) {
        requireNonNull(values); requireNonNull(current); requireNonNull(limits);
        if (values.isEmpty()) return new Conditional(false, false, false, null);
        if (values.size() > limits.getMaximumConditionalTags()) return oversized();
        long bytes = 0;
        for (String value : values) {
            requireNonNull(value);
            if (value.length() > limits.getMaximumConditionalHeaderBytes() - bytes) return oversized();
            for (int index = 0; index < value.length(); ++index) {
                char ch = value.charAt(index);
                if (ch > 0xff || ch == 0x7f || (ch < 0x20 && ch != '\t')) return syntaxRejected();
                bytes += ch < 0x80 ? 1 : 2;
                if (bytes > limits.getMaximumConditionalHeaderBytes()) return oversized();
            }
        }
        if (values.size() == 1 && values.get(0).strip().equals("*")) return new Conditional(true, true, false, null);
        String version = current.getVersion().orElse(null);
        int versionStart = version != null && version.startsWith("W/") ? 2 : 0;
        int count = 0;
        boolean matched = false;
        for (String value : values) {
            int index = whitespace(value, 0);
            while (index < value.length()) {
                if (value.charAt(index) == ',') { index = whitespace(value, index + 1); continue; }
                if (value.startsWith("W/", index)) index += 2;
                int start = index;
                if (index >= value.length() || value.charAt(index++) != '"') return syntaxRejected();
                while (index < value.length() && value.charAt(index) != '"') {
                    char ch = value.charAt(index++);
                    if (!(ch == 0x21 || (ch >= 0x23 && ch <= 0x7e) || (ch >= 0x80 && ch <= 0xff))) return syntaxRejected();
                }
                if (index >= value.length()) return syntaxRejected();
                ++index;
                if (++count > limits.getMaximumConditionalTags()) return oversized();
                if (version != null && version.length() - versionStart == index - start
                        && value.regionMatches(start, version, versionStart, index - start)) matched = true;
                index = whitespace(value, index);
                if (index < value.length()) {
                    if (value.charAt(index++) != ',') return syntaxRejected();
                    index = whitespace(value, index);
                }
            }
        }
        return count == 0 ? syntaxRejected() : new Conditional(true, false, matched, null);
    }

    private static int whitespace(@NonNull String value, int index) {
        while (index < value.length() && (value.charAt(index) == ' ' || value.charAt(index) == '\t')) ++index;
        return index;
    }

    private static boolean token(char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                || "!#$%&'*+-.^_`|~".indexOf(ch) >= 0;
    }

    private static ScimContentTypeResult.@NonNull Rejected mediaRejected() {
        return new ScimContentTypeResult.Rejected(ScimError.unsupportedMediaTypeInstance());
    }
    private static @NonNull Conditional syntaxRejected() { return new Conditional(true, false, false, ScimError.invalidSyntaxInstance()); }
    private static @NonNull Conditional oversized() { return new Conditional(true, false, false, ScimError.requestTooLargeInstance()); }

    private static final class Conditional {
        private final boolean present;
        private final boolean wildcard;
        private final boolean matched;
        private final @Nullable ScimError error;
        private Conditional(boolean present, boolean wildcard, boolean matched, @Nullable ScimError error) {
            this.present = present; this.wildcard = wildcard; this.matched = matched; this.error = error;
        }
    }
}
