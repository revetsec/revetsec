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

package com.revetsec.internal.crypto;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/** Bounded HOTP/TOTP and recovery encodings. No authentication decision is made here. */
@ThreadSafe
public final class TotpPrimitives {
    private static final @NonNull String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final @NonNull String CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    private TotpPrimitives() { }

    /** Computes RFC 4226 dynamic truncation; SHA-256/512 and eight digits support RFC 6238 vector tests. */
    public static @NonNull String hotp(byte @NonNull [] secret, long step,
            @NonNull String algorithm, int digits) throws GeneralSecurityException {
        Objects.requireNonNull(secret);
        if (step < 0 || (digits != 6 && digits != 8) || secret.length == 0
                || !switch (algorithm) { case "HmacSHA1", "HmacSHA256", "HmacSHA512" -> true; default -> false; }) throw new IllegalArgumentException("Invalid OTP profile");
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(secret, algorithm));
        byte[] digest = mac.doFinal(ByteBuffer.allocate(8).putLong(step).array());
        try {
            int offset = digest[digest.length - 1] & 15;
            int binary = ((digest[offset] & 127) << 24) | ((digest[offset + 1] & 255) << 16)
                    | ((digest[offset + 2] & 255) << 8) | (digest[offset + 3] & 255);
            int modulus = digits == 6 ? 1_000_000 : 100_000_000;
            String number = Integer.toString(binary % modulus);
            return "0".repeat(digits - number.length()) + number;
        } finally { Arrays.fill(digest, (byte) 0); }
    }

    /** Finds exactly one matching allowed step; -1 means invalid, replayed or ambiguous. */
    public static long matchingStep(byte @NonNull [] secret, @NonNull String code,
            long currentStep, long usedStep) throws GeneralSecurityException {
        if (code.length() != 6) return -1;
        for (int i = 0; i < code.length(); i++) if (code.charAt(i) < '0' || code.charAt(i) > '9') return -1;
        long found = -1;
        int matches = 0;
        for (long delta = -1; delta <= 1; delta++) {
            long candidate = currentStep + delta;
            if (candidate < 0) continue;
            boolean match = ConstantTime.isEqual(hotp(secret, candidate, "HmacSHA1", 6), code);
            if (match) { matches++; found = candidate; }
        }
        return matches == 1 && found > usedStep ? found : -1;
    }

    /** Canonical unpadded RFC 4648 Base32 for a provisioning secret. */
    public static @NonNull String base32(byte @NonNull [] bytes) { return encode(bytes, BASE32); }

    /** Canonical 26-character Crockford encoding of a random 128-bit code. */
    public static @NonNull String recoveryCode(byte @NonNull [] bytes) {
        if (bytes.length != 16) throw new IllegalArgumentException("Invalid recovery entropy length");
        String raw = encode(bytes, CROCKFORD);
        return raw.substring(0, 5) + '-' + raw.substring(5, 10) + '-' + raw.substring(10, 15)
                + '-' + raw.substring(15, 20) + '-' + raw.substring(20);
    }

    /** Accepts ASCII case folding and hyphens only, preserving canonical final unused bits. */
    public static @Nullable String normalizeRecoveryCode(@NonNull String input) {
        if (input.length() > 64) return null;
        StringBuilder result = new StringBuilder(26);
        for (int i = 0; i < input.length(); i++) {
            char character = input.charAt(i);
            if (character == '-') continue;
            if (character >= 'a' && character <= 'z') character = (char) (character - 32);
            if (CROCKFORD.indexOf(character) < 0 || result.length() == 26) return null;
            result.append(character);
        }
        if (result.length() != 26 || (CROCKFORD.indexOf(result.charAt(25)) & 3) != 0) return null;
        return result.toString();
    }

    /** SHA-256 over length-delimited domain and context fields; no ambiguous concatenation. */
    public static byte @NonNull [] digest(@NonNull String domain, @NonNull String @NonNull ... fields) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            feed(digest, domain);
            for (String field : fields) feed(digest, field);
            return digest.digest();
        } catch (GeneralSecurityException failure) { throw new IllegalStateException("SHA-256 unavailable", failure); }
    }

    private static void feed(@NonNull MessageDigest digest, @NonNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        try { digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array()); digest.update(bytes); }
        finally { Arrays.fill(bytes, (byte) 0); }
    }

    private static @NonNull String encode(byte @NonNull [] bytes, @NonNull String alphabet) {
        StringBuilder result = new StringBuilder((bytes.length * 8 + 4) / 5);
        int bits = 0;
        int buffer = 0;
        for (byte value : bytes) {
            buffer = (buffer << 8) | (value & 255);
            bits += 8;
            while (bits >= 5) { bits -= 5; result.append(alphabet.charAt((buffer >>> bits) & 31)); }
        }
        if (bits > 0) result.append(alphabet.charAt((buffer << (5 - bits)) & 31));
        return result.toString();
    }
}
