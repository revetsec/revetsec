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
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Independent RFC 4226 section D and RFC 6238 appendix B expected values. */
final class TotpPrimitivesTests {
    @Test void rfc4226CounterVectors() throws GeneralSecurityException {
        byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        List<String> expected = List.of("755224", "287082", "359152", "969429", "338314",
                "254676", "287922", "162583", "399871", "520489");
        for (int counter = 0; counter < expected.size(); counter++)
            assertEquals(expected.get(counter), TotpPrimitives.hotp(secret, counter, "HmacSHA1", 6));
    }

    @Test void rfc6238Sha1Vectors() throws GeneralSecurityException {
        assertTimeVectors("12345678901234567890", "HmacSHA1",
                List.of("94287082", "07081804", "14050471", "89005924", "69279037", "65353130"));
    }

    @Test void rfc6238Sha256Vectors() throws GeneralSecurityException {
        assertTimeVectors("12345678901234567890123456789012", "HmacSHA256",
                List.of("46119246", "68084774", "67062674", "91819424", "90698825", "77737706"));
    }

    @Test void rfc6238Sha512Vectors() throws GeneralSecurityException {
        assertTimeVectors("1234567890123456789012345678901234567890123456789012345678901234", "HmacSHA512",
                List.of("90693936", "25091201", "99943326", "93441116", "38618901", "47863826"));
    }

    @Test void ambiguousWindowCannotAdvancePastAnAlreadyUsedMatchingStep() throws GeneralSecurityException {
        byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        // Independent fixed adjacent collision: both steps generate 911617. Choosing only the
        // unused candidate would let the same decimal code advance the replay high-water mark.
        assertEquals("911617", TotpPrimitives.hotp(secret, 910737, "HmacSHA1", 6));
        assertEquals("911617", TotpPrimitives.hotp(secret, 910738, "HmacSHA1", 6));
        assertEquals(-1, TotpPrimitives.matchingStep(secret, "911617", 910737, 910737));
        assertEquals(-1, TotpPrimitives.matchingStep(secret, "911617", 910738, -1));
    }

    @Test void fixedWindowAndStrictDecimalInputPreserveReplayRules() throws GeneralSecurityException {
        byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        assertEquals(2, TotpPrimitives.matchingStep(secret, "359152", 1, 0));
        assertEquals(-1, TotpPrimitives.matchingStep(secret, "359152", 1, 2));
        assertEquals(-1, TotpPrimitives.matchingStep(secret, "359152", 4, -1));
        assertEquals(-1, TotpPrimitives.matchingStep(secret, " 359152", 2, -1));
        assertEquals(-1, TotpPrimitives.matchingStep(secret, "３５９１５２", 2, -1));
        assertThrows(IllegalArgumentException.class,
                () -> TotpPrimitives.hotp(secret, -1, "HmacSHA1", 6));
        assertThrows(IllegalArgumentException.class,
                () -> TotpPrimitives.hotp(secret, 0, "HmacMD5", 6));
    }

    @Test void base32UsesCanonicalUnpaddedRfc4648Encoding() {
        assertEquals("", TotpPrimitives.base32(new byte[0]));
        assertEquals("MY", TotpPrimitives.base32("f".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXQ", TotpPrimitives.base32("fo".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXW6", TotpPrimitives.base32("foo".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXW6YTBOI", TotpPrimitives.base32("foobar".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test void recoveryEncodingRetainsAll128BitsAndRejectsNoncanonicalAliases() {
        byte[] entropy = new byte[16];
        entropy[15] = 1;
        String code = TotpPrimitives.recoveryCode(entropy);
        assertEquals("00000-00000-00000-00000-000004", code);
        String normalized = TotpPrimitives.normalizeRecoveryCode(code);
        assertEquals("00000000000000000000000004", normalized);
        assertEquals(normalized, TotpPrimitives.normalizeRecoveryCode("00000-00000-00000-00000-000004"));
        assertNull(TotpPrimitives.normalizeRecoveryCode("00000000000000000000000005"));
        assertNull(TotpPrimitives.normalizeRecoveryCode("O0000000000000000000000004"));
        assertNull(TotpPrimitives.normalizeRecoveryCode(" 00000000000000000000000004"));
        assertNull(TotpPrimitives.normalizeRecoveryCode("0".repeat(1000)));
        assertThrows(IllegalArgumentException.class, () -> TotpPrimitives.recoveryCode(new byte[15]));
        Arrays.fill(entropy, (byte) 255);
        String letters = TotpPrimitives.recoveryCode(entropy);
        assertTrue(letters.startsWith("ZZZZZ-"));
        assertEquals(TotpPrimitives.normalizeRecoveryCode(letters),
                TotpPrimitives.normalizeRecoveryCode("zzzzz-zzzzz-zzzzz-zzzzz-zzzzzw"));
    }

    @Test void recoveryVerifierDomainsAndLengthDelimitersAreUnambiguous() {
        assertFalse(Arrays.equals(TotpPrimitives.digest("domain", "ab", "c"),
                TotpPrimitives.digest("domain", "a", "bc")));
        assertFalse(Arrays.equals(TotpPrimitives.digest("first", "account", "code"),
                TotpPrimitives.digest("second", "account", "code")));
    }

    private static void assertTimeVectors(@NonNull String secret, @NonNull String algorithm,
            @NonNull List<@NonNull String> expected) throws GeneralSecurityException {
        List<Long> seconds = List.of(59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L);
        for (int index = 0; index < seconds.size(); index++)
            assertEquals(expected.get(index), TotpPrimitives.hotp(secret.getBytes(StandardCharsets.US_ASCII),
                    seconds.get(index) / 30, algorithm, 8));
    }
}
