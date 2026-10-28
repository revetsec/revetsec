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

package com.revetsec.internal.password;

import com.revetsec.internal.password.vendor.spring.BCrypt;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * Verify-only migration primitives. Callers must opt in to a legacy format and must
 * map historical PBKDF2 record fields explicitly; there is no hash-string autodetection.
 * Inputs are borrowed for one call and are never retained or modified.
 *
 * <p>The absolute work ceilings are defense in depth. The application still must use
 * admission control and a smaller deployment-specific verification budget.</p>
 */
@ThreadSafe
public final class LegacyPasswordVerifier {
    /** The largest bcrypt cost Revetsec will perform, even if a caller asks for more. */
    public static final int MAX_BCRYPT_LOG_ROUNDS = 16;
    /** The largest PBKDF2 iteration count Revetsec will perform. */
    public static final int MAX_PBKDF2_ITERATIONS = 2_000_000;
    private static final int MAX_PASSWORD_BYTES = 65_536;
    private static final String BCRYPT_ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /** Complete, redacted outcomes from the verify-only primitives. */
    public enum Result {
        MATCHED,
        NOT_MATCHED,
        /** The input would have ambiguous legacy bcrypt truncation semantics. */
        TRUNCATED_INPUT,
        /** The stored form or its parameters fail the configured and absolute bounds. */
        MALFORMED,
        /** A required JCA provider failed or the operation was interrupted. */
        UNAVAILABLE
    }

    private LegacyPasswordVerifier() { }

    /**
     * Verifies one canonical bcrypt modular-crypt value. Only fixed semantics for
     * {@code $2a$}, {@code $2b$}, and {@code $2y$} are accepted. The historical
     * {@code $2x$} sign-extension bug and non-canonical encodings are refused.
     * A candidate longer than 72 UTF-8 bytes, or containing NUL, cannot establish
     * a full-password match and is rejected before bcrypt runs.
     *
     * @param passwordUtf8 caller-prepared password bytes, borrowed for this call
     * @param storedForm 60-character bcrypt modular-crypt value
     * @param maximumLogRounds trusted deployment limit, from 4 through 16
     * @return one complete verification outcome
     */
    public static @NonNull Result verifyBcrypt(byte @NonNull [] passwordUtf8,
                                               @NonNull String storedForm,
                                               int maximumLogRounds) {
        requireNonNull(passwordUtf8, "passwordUtf8");
        requireNonNull(storedForm, "storedForm");
        if (maximumLogRounds < 4 || maximumLogRounds > MAX_BCRYPT_LOG_ROUNDS) {
            throw new IllegalArgumentException("Invalid bcrypt verification budget.");
        }
        if (!validBcryptForm(storedForm, maximumLogRounds)) {
            return Result.MALFORMED;
        }
        if (passwordUtf8.length > 72 || containsZero(passwordUtf8)) {
            return Result.TRUNCATED_INPUT;
        }
        if (Thread.currentThread().isInterrupted()) {
            return Result.UNAVAILABLE;
        }
        try {
            boolean matched = BCrypt.checkpw(passwordUtf8, storedForm);
            if (Thread.currentThread().isInterrupted()) {
                return Result.UNAVAILABLE;
            }
            return matched ? Result.MATCHED : Result.NOT_MATCHED;
        } catch (RuntimeException e) {
            // The vendor parser must never leak a raw exception from a stored record.
            return Result.MALFORMED;
        }
    }

    /**
     * Verifies a caller-mapped historical PBKDF2-HMAC-SHA256 or HMAC-SHA512 record.
     * The explicit fields avoid inventing a universal legacy storage format. The
     * password bytes must match the old application's original preparation rule.
     *
     * @param passwordUtf8 caller-prepared password bytes, borrowed for this call
     * @param macAlgorithm exactly {@code HmacSHA256} or {@code HmacSHA512}
     * @param iterations stored positive iteration count
     * @param salt stored salt, 8 to 64 bytes
     * @param expectedTag stored derived key, 16 to 64 bytes
     * @param maximumIterations trusted deployment limit, 1 to 2,000,000
     * @return one complete verification outcome
     */
    public static @NonNull Result verifyPbkdf2(byte @NonNull [] passwordUtf8,
                                               @NonNull String macAlgorithm,
                                               int iterations,
                                               byte @NonNull [] salt,
                                               byte @NonNull [] expectedTag,
                                               int maximumIterations) {
        requireNonNull(passwordUtf8, "passwordUtf8");
        requireNonNull(macAlgorithm, "macAlgorithm");
        requireNonNull(salt, "salt");
        requireNonNull(expectedTag, "expectedTag");
        if (maximumIterations < 1 || maximumIterations > MAX_PBKDF2_ITERATIONS) {
            throw new IllegalArgumentException("Invalid PBKDF2 verification budget.");
        }
        if (!("HmacSHA256".equals(macAlgorithm) || "HmacSHA512".equals(macAlgorithm))
                || iterations < 1 || iterations > maximumIterations
                || salt.length < 8 || salt.length > 64
                || expectedTag.length < 16 || expectedTag.length > 64
                || passwordUtf8.length > MAX_PASSWORD_BYTES) {
            return Result.MALFORMED;
        }
        if (Thread.currentThread().isInterrupted()) {
            return Result.UNAVAILABLE;
        }
        try {
            return verifyPbkdf2Bounded(passwordUtf8, macAlgorithm, iterations, salt, expectedTag);
        } catch (GeneralSecurityException | RuntimeException e) {
            return Result.UNAVAILABLE;
        }
    }

    private static boolean validBcryptForm(@NonNull String storedForm, int maximumLogRounds) {
        if (storedForm.length() != 60 || storedForm.charAt(0) != '$' || storedForm.charAt(1) != '2'
                || (storedForm.charAt(2) != 'a' && storedForm.charAt(2) != 'b' && storedForm.charAt(2) != 'y')
                || storedForm.charAt(3) != '$' || storedForm.charAt(6) != '$') {
            return false;
        }
        char tens = storedForm.charAt(4);
        char ones = storedForm.charAt(5);
        if (tens < '0' || tens > '9' || ones < '0' || ones > '9') {
            return false;
        }
        int cost = (tens - '0') * 10 + ones - '0';
        if (cost < 4 || cost > maximumLogRounds) {
            return false;
        }
        for (int i = 7; i < 60; i++) {
            if (BCRYPT_ALPHABET.indexOf(storedForm.charAt(i)) < 0) {
                return false;
            }
        }
        // The 16-byte salt ends with four zero pad bits; the 23-byte tag ends with two.
        return (BCRYPT_ALPHABET.indexOf(storedForm.charAt(28)) & 15) == 0
                && (BCRYPT_ALPHABET.indexOf(storedForm.charAt(59)) & 3) == 0;
    }

    private static boolean containsZero(byte @NonNull [] candidate) {
        for (byte value : candidate) {
            if (value == 0) {
                return true;
            }
        }
        return false;
    }

    private static @NonNull Result verifyPbkdf2Bounded(byte @NonNull [] passwordUtf8,
                                                       @NonNull String macAlgorithm,
                                                       int iterations,
                                                       byte @NonNull [] salt,
                                                       byte @NonNull [] expectedTag)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance(macAlgorithm);
        // An all-zero block is the HMAC padding of an empty key. SecretKeySpec
        // refuses a zero-length key, so one zero byte is equivalent here.
        byte[] key = passwordUtf8.length == 0 ? new byte[1] : passwordUtf8.clone();
        byte[] input = Arrays.copyOf(salt, salt.length + 4);
        byte[] computed = new byte[expectedTag.length];
        byte[] u = new byte[mac.getMacLength()];
        byte[] next = new byte[u.length];
        byte[] block = new byte[u.length];
        try {
            mac.init(new SecretKeySpec(key, macAlgorithm));
            int count = (expectedTag.length + u.length - 1) / u.length;
            for (int b = 1; b <= count; b++) {
                input[salt.length] = (byte) (b >>> 24);
                input[salt.length + 1] = (byte) (b >>> 16);
                input[salt.length + 2] = (byte) (b >>> 8);
                input[salt.length + 3] = (byte) b;
                mac.update(input);
                mac.doFinal(u, 0);
                System.arraycopy(u, 0, block, 0, u.length);
                for (int i = 1; i < iterations; i++) {
                    if ((i & 1023) == 0 && Thread.currentThread().isInterrupted()) {
                        return Result.UNAVAILABLE;
                    }
                    mac.update(u);
                    mac.doFinal(next, 0);
                    for (int j = 0; j < block.length; j++) {
                        block[j] ^= next[j];
                    }
                    byte[] swap = u;
                    u = next;
                    next = swap;
                }
                int offset = (b - 1) * u.length;
                int bytes = Math.min(u.length, computed.length - offset);
                System.arraycopy(block, 0, computed, offset, bytes);
            }
            if (Thread.currentThread().isInterrupted()) {
                return Result.UNAVAILABLE;
            }
            return MessageDigest.isEqual(computed, expectedTag) ? Result.MATCHED : Result.NOT_MATCHED;
        } catch (ShortBufferException e) {
            return Result.UNAVAILABLE;
        } finally {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(input, (byte) 0);
            Arrays.fill(computed, (byte) 0);
            Arrays.fill(u, (byte) 0);
            Arrays.fill(next, (byte) 0);
            Arrays.fill(block, (byte) 0);
        }
    }
}
