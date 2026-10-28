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
package com.revetsec.password;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import java.util.Arrays;
import java.util.Base64;

/** Strict, bounded Argon2 PHC and Revetsec pepper-envelope encoding. This is an internal parser;
 * its fixed outcomes are translated by {@link PasswordHasher}.
 */
@NotThreadSafe
final class PasswordStoredForm {
    enum Status { VALID, INVALID, UNSUPPORTED }

    private final @NonNull Status status;
    private final boolean peppered;
    private final @Nullable String pepperKeyId;
    private final int memoryKiB;
    private final int passes;
    private final int lanes;
    private final byte @NonNull [] salt;
    private final byte @NonNull [] tag;

    private PasswordStoredForm(@NonNull Status status, boolean peppered, @Nullable String pepperKeyId,
            int memoryKiB, int passes, int lanes, byte @NonNull [] salt, byte @NonNull [] tag) {
        this.status = status;
        this.peppered = peppered;
        this.pepperKeyId = pepperKeyId;
        this.memoryKiB = memoryKiB;
        this.passes = passes;
        this.lanes = lanes;
        this.salt = salt;
        this.tag = tag;
    }

    static @NonNull PasswordStoredForm parse(@NonNull String input, @NonNull PasswordVerificationLimits limits) {
        if (input.length() > limits.getMaximumStoredFormChars()) return invalid();
        String[] parts = input.split("\\$", -1);
        if (parts.length < 2 || !parts[0].isEmpty()) return invalid();
        boolean peppered;
        String keyId = null;
        int offset;
        if (parts.length == 9 && "revetsec-pw".equals(parts[1])) {
            if (!"v=1".equals(parts[2]) || !parts[3].startsWith("kid=")) return invalid();
            keyId = parts[3].substring(4);
            if (!validKeyId(keyId)) return invalid();
            peppered = true;
            offset = 4;
        } else if (parts.length == 6 && "argon2id".equals(parts[1])) {
            peppered = false;
            offset = 1;
        } else {
            return parts[1].isEmpty() ? invalid() : unsupported();
        }
        if (!"argon2id".equals(parts[offset]) || !"v=19".equals(parts[offset + 1])) return unsupported();
        String cost = parts[offset + 2];
        if (!cost.startsWith("m=")) return invalid();
        int firstComma = cost.indexOf(',');
        int secondComma = cost.indexOf(',', firstComma + 1);
        if (firstComma < 3 || secondComma < firstComma + 4
                || !cost.startsWith("t=", firstComma + 1)
                || !cost.startsWith("p=", secondComma + 1)
                || cost.indexOf(',', secondComma + 1) >= 0) return invalid();
        int memory = decimal(cost, 2, firstComma);
        int passes = decimal(cost, firstComma + 3, secondComma);
        int lanes = decimal(cost, secondComma + 3, cost.length());
        if (memory < 8 || memory > limits.getMaximumArgon2idMemoryKiB()
                || passes < 1 || passes > limits.getMaximumArgon2idPasses()
                || lanes < 1 || lanes > limits.getMaximumArgon2idLanes()
                || memory < 8 * lanes) return invalid();

        byte[] salt = decodeCanonical(parts[offset + 3], 8, 64);
        if (salt == null) return invalid();
        byte[] tag = decodeCanonical(parts[offset + 4], 16, 64);
        if (tag == null) {
            Arrays.fill(salt, (byte) 0);
            return invalid();
        }
        return new PasswordStoredForm(Status.VALID, peppered, keyId, memory, passes, lanes, salt, tag);
    }

    static @NonNull String encode(@NonNull Argon2idParameters parameters, byte @NonNull [] salt,
            byte @NonNull [] tag, @Nullable String keyId) {
        String prefix = keyId == null ? "" : "$revetsec-pw$v=1$kid=" + keyId;
        return prefix + "$argon2id$v=19$m=" + parameters.getMemoryKiB() + ",t="
                + parameters.getPasses() + ",p=" + parameters.getLanes() + "$"
                + Base64.getEncoder().withoutPadding().encodeToString(salt) + "$"
                + Base64.getEncoder().withoutPadding().encodeToString(tag);
    }

    private static @NonNull PasswordStoredForm invalid() {
        return new PasswordStoredForm(Status.INVALID, false, null, 0, 0, 0, new byte[0], new byte[0]);
    }

    private static @NonNull PasswordStoredForm unsupported() {
        return new PasswordStoredForm(Status.UNSUPPORTED, false, null, 0, 0, 0, new byte[0], new byte[0]);
    }

    private static int decimal(@NonNull String text, int start, int end) {
        if (start >= end || end - start > 7 || (end - start > 1 && text.charAt(start) == '0')) return -1;
        int value = 0;
        for (int i = start; i < end; i++) {
            char c = text.charAt(i);
            if (c < '0' || c > '9') return -1;
            value = value * 10 + (c - '0');
        }
        return value;
    }

    private static boolean validKeyId(@NonNull String value) {
        if (value.isEmpty() || value.length() > 64) return false;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                    || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '~' || ch == '-')) return false;
        }
        return true;
    }

    private static byte @Nullable [] decodeCanonical(@NonNull String encoded, int minimum, int maximum) {
        if (encoded.length() < 11 || encoded.length() > 86) return null;
        for (int i = 0; i < encoded.length(); i++) {
            char c = encoded.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9') || c == '+' || c == '/')) return null;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(encoded);
            if (decoded.length < minimum || decoded.length > maximum
                    || !Base64.getEncoder().withoutPadding().encodeToString(decoded).equals(encoded)) {
                Arrays.fill(decoded, (byte) 0);
                return null;
            }
            return decoded;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    @NonNull Status status() { return status; }
    boolean peppered() { return peppered; }
    @Nullable String pepperKeyId() { return pepperKeyId; }
    int memoryKiB() { return memoryKiB; }
    int passes() { return passes; }
    int lanes() { return lanes; }
    byte @NonNull [] salt() { return salt; }
    byte @NonNull [] tag() { return tag; }

    void wipe() {
        Arrays.fill(salt, (byte) 0);
        Arrays.fill(tag, (byte) 0);
    }

    @Override public @NonNull String toString() { return "PasswordStoredForm{<redacted>}"; }
}
