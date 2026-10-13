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

import com.revetsec.json.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import java.util.Arrays;
import java.math.BigDecimal;
import java.util.Map;

/** Streaming UTF-8 output that charges emitted bytes and work before buffer growth. */
@NotThreadSafe
final class ScimJsonOutput {
    private static final @NonNull String HEX = "0123456789abcdef";
    private final int maximum;
    private final @NonNull ScimWork work;
    private byte @NonNull [] bytes;
    private int size;

    private ScimJsonOutput(int maximum, @NonNull ScimWork work) {
        this.maximum = maximum; this.work = work; this.bytes = new byte[Math.min(256, maximum)];
    }

    static byte @Nullable [] write(@NonNull JsonValue value, int maximum, @NonNull ScimWork work) {
        ScimJsonOutput output = new ScimJsonOutput(maximum, work);
        return output.value(value) ? Arrays.copyOf(output.bytes, output.size) : null;
    }

    private boolean value(@NonNull JsonValue value) {
        if (!work.take(1)) return false;
        if (value instanceof JsonObject object) {
            if (!octet('{')) return false;
            boolean first = true;
            for (Map.Entry<String, JsonValue> member : object.getMembers().entrySet()) {
                if (!first && !octet(',')) return false;
                if (!string(member.getKey()) || !octet(':') || !value(member.getValue())) return false;
                first = false;
            }
            return octet('}');
        }
        if (value instanceof JsonArray array) {
            if (!octet('[')) return false;
            boolean first = true;
            for (JsonValue element : array.getElements()) {
                if (!first && !octet(',')) return false;
                if (!value(element)) return false;
                first = false;
            }
            return octet(']');
        }
        if (value instanceof JsonString string) return string(string.getValue());
        if (value instanceof JsonNumber number) return number(number.getValue());
        if (value instanceof JsonBoolean bool) return ascii(bool.getValue() ? "true" : "false");
        return ascii("null");
    }

    private boolean string(@NonNull String value) {
        if (!octet('"')) return false;
        for (int index = 0; index < value.length(); ++index) {
            char ch = value.charAt(index);
            if (ch == '"' || ch == '\\') {
                if (!reserve(2)) return false;
                bytes[size++] = '\\'; bytes[size++] = (byte) ch;
            } else if (ch < 0x20) {
                char escape = switch (ch) {
                    case '\b' -> 'b'; case '\f' -> 'f'; case '\n' -> 'n'; case '\r' -> 'r'; case '\t' -> 't'; default -> 0;
                };
                if (escape != 0) {
                    if (!reserve(2)) return false;
                    bytes[size++] = '\\'; bytes[size++] = (byte) escape;
                } else {
                    if (!reserve(6)) return false;
                    bytes[size++] = '\\'; bytes[size++] = 'u'; bytes[size++] = '0'; bytes[size++] = '0';
                    bytes[size++] = (byte) HEX.charAt(ch >>> 4); bytes[size++] = (byte) HEX.charAt(ch & 15);
                }
            } else if (ch < 0x80) {
                if (!octet(ch)) return false;
            } else if (ch < 0x800) {
                if (!reserve(2)) return false;
                bytes[size++] = (byte) (0xc0 | ch >>> 6); bytes[size++] = (byte) (0x80 | (ch & 63));
            } else if (Character.isHighSurrogate(ch)) {
                int point = Character.toCodePoint(ch, value.charAt(++index));
                if (!reserve(4)) return false;
                bytes[size++] = (byte) (0xf0 | point >>> 18); bytes[size++] = (byte) (0x80 | ((point >>> 12) & 63));
                bytes[size++] = (byte) (0x80 | ((point >>> 6) & 63)); bytes[size++] = (byte) (0x80 | (point & 63));
            } else {
                if (!reserve(3)) return false;
                bytes[size++] = (byte) (0xe0 | ch >>> 12); bytes[size++] = (byte) (0x80 | ((ch >>> 6) & 63));
                bytes[size++] = (byte) (0x80 | (ch & 63));
            }
        }
        return octet('"');
    }

    private boolean number(@NonNull BigDecimal value) {
        long exponent = (long) value.precision() - value.scale() - 1;
        long length;
        int sign = value.signum() < 0 ? 1 : 0;
        int precision = value.precision();
        if (value.scale() >= 0 && exponent >= -6) {
            if (value.scale() == 0) length = sign + (long) precision;
            else if (exponent >= 0) length = sign + (long) precision + 1;
            else length = sign + (long) precision - exponent + 1;
        } else {
            long digits = 1;
            for (long magnitude = Math.abs(exponent); magnitude >= 10; magnitude /= 10) ++digits;
            length = sign + (precision == 1 ? 1 : precision + 1L) + 2 + digits;
        }
        // Public JSON caps bound this canonical length to a few thousand bytes, so the conversion is exact.
        if (!reserve((int) length)) return false;
        String text = value.toString();
        for (int index = 0; index < text.length(); ++index) bytes[size++] = (byte) text.charAt(index);
        return true;
    }

    private boolean ascii(@NonNull String value) {
        if (!reserve(value.length())) return false;
        for (int index = 0; index < value.length(); ++index) bytes[size++] = (byte) value.charAt(index);
        return true;
    }
    private boolean octet(int value) {
        if (!reserve(1)) return false;
        bytes[size++] = (byte) value;
        return true;
    }
    private boolean reserve(int amount) {
        if (amount > maximum - size || !work.take(amount)) return false;
        int required = size + amount;
        if (required > bytes.length) {
            int grown = (int) Math.min(maximum, Math.max((long) required, bytes.length + (long) bytes.length / 2 + 1));
            bytes = Arrays.copyOf(bytes, grown);
        }
        return true;
    }
}
