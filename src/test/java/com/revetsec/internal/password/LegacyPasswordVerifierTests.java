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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static com.revetsec.internal.password.LegacyPasswordVerifier.Result.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class LegacyPasswordVerifierTests {
    // Openwall crypt_blowfish wrapper.c self-test vectors (primary C implementation).
    private static final String BCRYPT_2A = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
    private static final String BCRYPT_2B = "$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e";
    private static final String BCRYPT_2Y = "$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq";

    @Test void verifiesOpenwallBcryptVariantsAndWrongPassword() {
        assertEquals(MATCHED, LegacyPasswordVerifier.verifyBcrypt(bytes("U*U"), BCRYPT_2A, 5));
        assertEquals(NOT_MATCHED, LegacyPasswordVerifier.verifyBcrypt(bytes("U*U*"), BCRYPT_2A, 5));
        assertEquals(MATCHED, LegacyPasswordVerifier.verifyBcrypt(
                new byte[]{(byte) 0xff, (byte) 0xff, (byte) 0xa3}, BCRYPT_2B, 5));
        assertEquals(MATCHED, LegacyPasswordVerifier.verifyBcrypt(new byte[]{(byte) 0xa3}, BCRYPT_2Y, 5));
    }

    @Test void rejectsBcryptTruncationAndAmbiguousNulBeforeWork() {
        byte[] exactly72 = new byte[72];
        for (int i = 0; i < exactly72.length; i++) {
            exactly72[i] = (byte) ((i & 1) == 0 ? 0xaa : 0x55);
        }
        // Openwall's 72-byte boundary vector: all 72 bytes participate.
        assertEquals(MATCHED, LegacyPasswordVerifier.verifyBcrypt(exactly72,
                "$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy", 5));
        assertEquals(TRUNCATED_INPUT, LegacyPasswordVerifier.verifyBcrypt(new byte[73], BCRYPT_2A, 5));
        assertEquals(TRUNCATED_INPUT, LegacyPasswordVerifier.verifyBcrypt(new byte[]{'U', 0, 'U'}, BCRYPT_2A, 5));
    }

    @Test void rejectsMalformedOrOverBudgetBcryptBeforeWork() {
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyBcrypt(bytes("U*U"), BCRYPT_2A, 4));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyBcrypt(bytes("U*U"), BCRYPT_2A.replace("$2a$", "$2x$"), 5));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyBcrypt(bytes("U*U"), BCRYPT_2A.replace("$05$", "$31$"), 5));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyBcrypt(bytes("U*U"), BCRYPT_2A.substring(0, 59) + "P", 5));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyBcrypt(bytes("U*U"), BCRYPT_2A.substring(0, 28) + "P" + BCRYPT_2A.substring(29), 5));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyBcrypt(bytes("U*U"), BCRYPT_2A.substring(0, 28) + "C" + BCRYPT_2A.substring(29), 5));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyBcrypt(bytes("U*U"), BCRYPT_2A + "x", 5));
        assertThrows(IllegalArgumentException.class, () -> LegacyPasswordVerifier.verifyBcrypt(bytes("U*U"), BCRYPT_2A, 17));
    }

    @Test void verifiesIndependentPbkdf2Sha256AndSha512Vectors() {
        // Derived independently with CPython hashlib.pbkdf2_hmac.
        byte[] salt = bytes("saltysalt");
        assertEquals(MATCHED, LegacyPasswordVerifier.verifyPbkdf2(bytes("password"), "HmacSHA256", 1,
                salt, hex("08d487f3999f74aa4e1a56d250f885f3e3e241d223daa47ac9e715e484f1342f"), 1));
        assertEquals(MATCHED, LegacyPasswordVerifier.verifyPbkdf2(bytes("password"), "HmacSHA256", 4096,
                salt, hex("ab1c8ee34be9177464126f1fcd6e53c611857b705198ca74aef8551ac7e79d3547688f6223778c980997b111e3d78cd7573b56b1aa74a420bb6d239cd09bf051"), 4096));
        assertEquals(MATCHED, LegacyPasswordVerifier.verifyPbkdf2(bytes("password"), "HmacSHA512", 2,
                salt, hex("237f11ba3dde1ca37d9eb7d1f3cabfa288821c86f15da7f14a309d0bbd35e46284ccdd128d291b43ff0ba38a3ad5afc47188a4687c1bb45ed3e91504b007580a"), 2));
        assertEquals(MATCHED, LegacyPasswordVerifier.verifyPbkdf2(new byte[0], "HmacSHA256", 2,
                salt, hex("5711ba0fa7626e99b6ae1a4e531543037ada89792544f38364d05542562a150d"), 2));
        assertEquals(NOT_MATCHED, LegacyPasswordVerifier.verifyPbkdf2(bytes("wrong"), "HmacSHA512", 2,
                salt, hex("237f11ba3dde1ca37d9eb7d1f3cabfa288821c86f15da7f14a309d0bbd35e46284ccdd128d291b43ff0ba38a3ad5afc47188a4687c1bb45ed3e91504b007580a"), 2));
    }

    @Test void boundsPbkdf2ParametersBeforeWork() {
        byte[] salt = bytes("saltysalt");
        byte[] tag = new byte[32];
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyPbkdf2(bytes("p"), "HmacSHA1", 1, salt, tag, 1));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyPbkdf2(bytes("p"), "HmacSHA256", 0, salt, tag, 1));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyPbkdf2(bytes("p"), "HmacSHA256", 2, salt, tag, 1));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyPbkdf2(bytes("p"), "HmacSHA256", 1, new byte[7], tag, 1));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyPbkdf2(bytes("p"), "HmacSHA256", 1, salt, new byte[15], 1));
        assertEquals(MALFORMED, LegacyPasswordVerifier.verifyPbkdf2(new byte[65_537], "HmacSHA256", 1, salt, tag, 1));
        assertThrows(IllegalArgumentException.class, () -> LegacyPasswordVerifier.verifyPbkdf2(bytes("p"), "HmacSHA256", 1, salt, tag, 2_000_001));
    }

    @Test void interruptionCannotReleaseLegacyMatch() {
        Thread.currentThread().interrupt();
        try {
            assertEquals(UNAVAILABLE, LegacyPasswordVerifier.verifyBcrypt(bytes("U*U"), BCRYPT_2A, 5));
            assertEquals(UNAVAILABLE, LegacyPasswordVerifier.verifyPbkdf2(bytes("password"), "HmacSHA256", 1,
                    bytes("saltysalt"), hex("08d487f3999f74aa4e1a56d250f885f3e3e241d223daa47ac9e715e484f1342f"), 1));
        } finally {
            Thread.interrupted();
        }
    }

    @Test void pbkdf2ObservesInterruptionAfterWorkHasStarted() throws InterruptedException {
        AtomicReference<LegacyPasswordVerifier.Result> result = new AtomicReference<>();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicReference<Boolean> interruptedFlag = new AtomicReference<>();
        Thread verifying = new Thread(() -> {
            try {
                result.set(LegacyPasswordVerifier.verifyPbkdf2(bytes("password"), "HmacSHA256",
                        2_000_000, bytes("saltysalt"), new byte[32], 2_000_000));
            } catch (Throwable t) {
                failure.set(t);
            } finally {
                interruptedFlag.set(Thread.currentThread().isInterrupted());
            }
        }, "password-mid-pbkdf2-interruption-test");
        verifying.setDaemon(true);
        try {
            verifying.start();
            assertTrue(awaitPbkdf2Loop(verifying), "The worker must enter PBKDF2 before cancellation");
            verifying.interrupt();
            verifying.join(10_000);
            assertFalse(verifying.isAlive());
            assertEquals(null, failure.get());
            assertEquals(UNAVAILABLE, result.get());
            assertEquals(Boolean.TRUE, interruptedFlag.get());
        } finally {
            verifying.interrupt();
            verifying.join(10_000);
        }
    }

    private static boolean awaitPbkdf2Loop(@NonNull Thread worker) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (worker.isAlive() && System.nanoTime() < deadline) {
            boolean pbkdf2 = false;
            boolean mac = false;
            for (StackTraceElement frame : worker.getStackTrace()) {
                pbkdf2 |= frame.getClassName().equals(LegacyPasswordVerifier.class.getName())
                        && frame.getMethodName().equals("verifyPbkdf2Bounded");
                mac |= frame.getClassName().equals("javax.crypto.Mac")
                        && frame.getMethodName().equals("doFinal");
            }
            if (pbkdf2 && mac) return true;
            Thread.onSpinWait();
        }
        return false;
    }

    private static byte @NonNull [] bytes(@NonNull String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static byte @NonNull [] hex(@NonNull String text) { return HexFormat.of().parseHex(text); }
}
