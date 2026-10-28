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

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/** RFC 9106 section 5.3 and independent raw-tag vectors for Argon2id v19. */
final class Argon2idVectorsTests {
    @Test
    void rfc9106Argon2idSecretAndAssociatedDataVector() {
        byte[] password = filled(32, (byte) 1);
        byte[] salt = filled(16, (byte) 2);
        byte[] secret = filled(8, (byte) 3);
        byte[] ad = filled(12, (byte) 4);
        byte[] result = Argon2id.hash(password, salt, secret, ad, 32, 3, 4, 32);
        Assertions.assertEquals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
                                HexFormat.of().formatHex(result));
        Arrays.fill(result, (byte) 0);
    }

    @Test
    void matchesPinnedReferenceCVectorWithActualThirtyTwoBytePepper() {
        // Generated with argon2_ctx from the pinned 20190702 C source, using ref.c,
        // ARGON2_NO_THREADS, m=19456, t=2, p=1, v=19 and a 32-byte secret input.
        // This pins the public password API's actual pepper length independently of Java.
        byte[] password = "correct horse battery staple".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] salt = HexFormat.of().parseHex("101112131415161718191a1b1c1d1e1f");
        byte[] secret = HexFormat.of().parseHex(
            "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
        byte[] expected = HexFormat.of().parseHex(
            "93fcacdf9f4e824418e5bddf473e12111c078f9af7232390ca30c38baff0cb0f");
        byte[] actual = null;
        try {
            actual = Argon2id.hash(password, salt, secret, 19_456, 2, 1, 32);
            Assertions.assertArrayEquals(expected, actual);
        } finally {
            Arrays.fill(password, (byte) 0);
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(secret, (byte) 0);
            Arrays.fill(expected, (byte) 0);
            if (actual != null) Arrays.fill(actual, (byte) 0);
        }
    }

    @Test
    void rejectsUnboundedMemoryBeforeAllocation() {
        Assertions.assertThrows(IllegalArgumentException.class,
            () -> Argon2id.hash(new byte[0], new byte[16], new byte[0], 262_145, 1, 1, 32));
    }

    @Test
    void preservesThreadInterruptAndAbortsBeforeWork() {
        Thread.currentThread().interrupt();
        try {
            Assertions.assertThrows(Argon2idInterruptedException.class,
                () -> Argon2id.hash(new byte[0], new byte[16], new byte[0], 8, 1, 1, 32));
            Assertions.assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void matchesIndependentBouncyCastleOracleAcrossParameters() {
        int[][] cases = {
            {8, 1, 1, 16}, {9, 2, 1, 32}, {31, 3, 2, 64},
            {32, 3, 4, 32}, {64, 2, 2, 16}, {256, 1, 4, 64},
            {513, 2, 1, 32}, {1_024, 2, 1, 48}, {4_096, 2, 4, 32}
        };
        for (int[] testCase : cases) {
            int memoryKiB = testCase[0];
            int passes = testCase[1];
            int lanes = testCase[2];
            int tagBytes = testCase[3];
            byte[] password = filled(17 + lanes, (byte) (0x10 + lanes));
            byte[] salt = filled(16, (byte) (0x20 + passes));
            byte[] secret = lanes == 2 ? filled(16, (byte) 0x30) : new byte[0];
            byte[] ad = lanes == 4 ? filled(12, (byte) 0x40) : new byte[0];
            Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(memoryKiB)
                .withIterations(passes)
                .withParallelism(lanes)
                .withSalt(salt)
                .withSecret(secret)
                .withAdditional(ad)
                .build();
            Argon2BytesGenerator oracle = new Argon2BytesGenerator();
            oracle.init(parameters);
            byte[] expected = new byte[tagBytes];
            oracle.generateBytes(password, expected);
            byte[] actual = Argon2id.hash(password, salt, secret, ad, memoryKiB, passes, lanes, tagBytes);
            try {
                Assertions.assertArrayEquals(expected, actual,
                    "m=" + memoryKiB + " t=" + passes + " p=" + lanes + " tag=" + tagBytes);
            } finally {
                parameters.clear();
                Arrays.fill(expected, (byte) 0);
                Arrays.fill(actual, (byte) 0);
            }
        }
    }

    @Test
    void matchesPinnedReferenceImplementationCorpus() throws IOException, NoSuchAlgorithmException {
        List<String> original = checkCorpus("/vectors/argon2id-reference-20190702.tsv",
            "0f23d8a1d80268fc6d02e8aaee8e1b54ea78ad712393470246bad2e2bd7daee5");
        List<String> container = checkCorpus("/vectors/argon2id-reference-20190702-container.tsv",
            "b76f2f621482628205e6cae911731f86bf10bb86276b5dd185667a9147ab3f0a");
        Assertions.assertEquals(original, container, "Pinned Linux reference must reproduce the original rows");
    }

    private @NonNull List<@NonNull String> checkCorpus(@NonNull String resource, @NonNull String expectedSha256)
        throws IOException, NoSuchAlgorithmException {
        InputStream input = getClass().getResourceAsStream(resource);
        Assertions.assertNotNull(input);
        byte[] corpus;
        try (input) {
            corpus = input.readAllBytes();
        }
        Assertions.assertEquals(expectedSha256,
                                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(corpus)));
        List<String> dataRows = new ArrayList<>();
        try (BufferedReader lines = new BufferedReader(new InputStreamReader(
                new ByteArrayInputStream(corpus), StandardCharsets.US_ASCII))) {
            int count = 0;
            for (String line; (line = lines.readLine()) != null;) {
                if (line.startsWith("#")) continue;
                dataRows.add(line);
                String[] fields = line.split("\t", -1);
                Assertions.assertEquals(7, fields.length);
                byte[] password = HexFormat.of().parseHex(fields[4]);
                byte[] salt = HexFormat.of().parseHex(fields[5]);
                byte[] tag = Argon2id.hash(password, salt, new byte[0], Integer.parseInt(fields[0]),
                                           Integer.parseInt(fields[1]), Integer.parseInt(fields[2]),
                                           Integer.parseInt(fields[3]));
                try {
                    Assertions.assertEquals(fields[6], HexFormat.of().formatHex(tag),
                        resource + " case " + count);
                } finally {
                    Arrays.fill(password, (byte) 0);
                    Arrays.fill(salt, (byte) 0);
                    Arrays.fill(tag, (byte) 0);
                }
                count++;
            }
            Assertions.assertEquals(9, count);
        } finally {
            Arrays.fill(corpus, (byte) 0);
        }
        return dataRows;
    }

    private static byte @NonNull [] filled(int length, byte value) {
        byte[] result = new byte[length];
        Arrays.fill(result, value);
        return result;
    }
}
