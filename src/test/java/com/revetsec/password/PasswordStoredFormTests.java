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
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.SplittableRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

final class PasswordStoredFormTests {
    @Test void acceptsCanonicalNativeFormsAndWipesDecodedValues() {
        byte[] salt = new byte[16];
        byte[] tag = new byte[32];
        for (int i = 0; i < salt.length; i++) salt[i] = (byte) (i + 1);
        for (int i = 0; i < tag.length; i++) tag[i] = (byte) (i + 41);
        PasswordVerificationLimits limits = PasswordVerificationLimits.fromDefaults();
        String raw = PasswordStoredForm.encode(Argon2idParameters.withCosts(19_456, 2, 1), salt, tag, null);
        String keyed = PasswordStoredForm.encode(Argon2idParameters.withCosts(19_456, 2, 1), salt, tag, "key-1");
        PasswordStoredForm rawParsed = PasswordStoredForm.parse(raw, limits);
        PasswordStoredForm keyedParsed = PasswordStoredForm.parse(keyed, limits);
        assertEquals(PasswordStoredForm.Status.VALID, rawParsed.status());
        assertEquals(PasswordStoredForm.Status.VALID, keyedParsed.status());
        assertEquals("key-1", keyedParsed.pepperKeyId());
        rawParsed.wipe();
        keyedParsed.wipe();
        assertEquals(0, sum(rawParsed.salt()) + sum(rawParsed.tag()));
        assertEquals(0, sum(keyedParsed.salt()) + sum(keyedParsed.tag()));
    }

    @Test void rejectsNoncanonicalEncodingAndHostileCostFields() {
        PasswordVerificationLimits limits = PasswordVerificationLimits.fromDefaults();
        byte[] salt = new byte[16];
        byte[] tag = new byte[32];
        Arrays.fill(salt, (byte) 1);
        Arrays.fill(tag, (byte) 2);
        String canonical = PasswordStoredForm.encode(Argon2idParameters.withCosts(19_456, 2, 1), salt, tag, null);
        for (String malformed : new String[]{
                canonical + "=",
                canonical.replace("m=19456", "m=019456"),
                canonical.replace("m=19456", "m=2147483648"),
                canonical.replace("m=19456", "m=262145"),
                canonical.replace("t=2", "t=0"),
                canonical.replace("p=1", "p=0"),
                canonical.replace("m=19456,t=2,p=1", "t=2,m=19456,p=1"),
                canonical.replace("$argon2id$", "$argon2i$"),
                canonical.replace("$argon2id$", "$argon2id$$"),
                canonical.substring(0, canonical.length() - 1) + "="}) {
            assertNotEquals(PasswordStoredForm.Status.VALID,
                    PasswordStoredForm.parse(malformed, limits).status(), malformed);
        }
    }

    @Test void deterministicMalformedInputFuzzNeverReachesValidKdfState() {
        PasswordVerificationLimits limits = PasswordVerificationLimits.fromDefaults();
        SplittableRandom random = new SplittableRandom(0x52e71b5dL);
        for (int sample = 0; sample < 5_000; sample++) {
            int length = random.nextInt(700);
            StringBuilder input = new StringBuilder(length + 24);
            if ((sample & 1) == 0) input.append("$argon2id$v=19$");
            for (int i = 0; i < length; i++) input.append((char) random.nextInt(1, 128));
            PasswordStoredForm parsed = PasswordStoredForm.parse(input.toString(), limits);
            assertNotEquals(PasswordStoredForm.Status.VALID, parsed.status(), "sample " + sample);
            parsed.wipe();
        }
    }

    @Test void generatedBoundaryFormsAreCanonicalAndRespectConfiguredCosts() {
        PasswordVerificationLimits defaults = PasswordVerificationLimits.fromDefaults();
        for (int saltLength : new int[]{8, 16, 64}) {
            for (int tagLength : new int[]{16, 32, 64}) {
                byte[] salt = new byte[saltLength];
                byte[] tag = new byte[tagLength];
                for (int i = 0; i < salt.length; i++) salt[i] = (byte) (i * 7 + 3);
                for (int i = 0; i < tag.length; i++) tag[i] = (byte) (i * 11 + 5);
                for (String keyId : new String[]{"", "A", "k".repeat(64)}) {
                    String form = PasswordStoredForm.encode(
                            Argon2idParameters.withCosts(19_456, 2, 1), salt, tag,
                            keyId.isEmpty() ? null : keyId);
                    PasswordStoredForm parsed = PasswordStoredForm.parse(form, defaults);
                    try {
                        assertEquals(PasswordStoredForm.Status.VALID, parsed.status(), form);
                        assertEquals(form, reconstruct(parsed));
                    } finally {
                        parsed.wipe();
                    }
                }
            }
        }

        String base = PasswordStoredForm.encode(Argon2idParameters.withCosts(19_456, 2, 1),
                new byte[16], new byte[32], null);
        for (String accepted : new String[]{
                base.replace("m=19456", "m=131072"),
                base.replace("t=2", "t=6"),
                base.replace("p=1", "p=8")}) {
            PasswordStoredForm parsed = PasswordStoredForm.parse(accepted, defaults);
            try {
                assertEquals(PasswordStoredForm.Status.VALID, parsed.status(), accepted);
                assertEquals(accepted, reconstruct(parsed));
            } finally {
                parsed.wipe();
            }
        }
        for (String rejected : new String[]{
                base.replace("m=19456", "m=131073"),
                base.replace("t=2", "t=7"),
                base.replace("p=1", "p=9"),
                base.replace("m=19456", "m=+19456"),
                base.replace("m=19456", "m=19456.0"),
                base.replace("m=19456", "m=19456,t=2"),
                base.replace("m=19456", "m=9999999")}) {
            PasswordStoredForm parsed = PasswordStoredForm.parse(rejected, defaults);
            assertNotEquals(PasswordStoredForm.Status.VALID, parsed.status(), rejected);
            parsed.wipe();
        }
    }

    @Test void singleCharacterMutationsOfBothNativeFormsRemainTotalAndCanonicalWhenAccepted() {
        PasswordVerificationLimits limits = PasswordVerificationLimits.fromDefaults();
        String raw = PasswordStoredForm.encode(Argon2idParameters.withCosts(19_456, 2, 1),
                new byte[16], new byte[32], null);
        String keyed = PasswordStoredForm.encode(Argon2idParameters.withCosts(19_456, 2, 1),
                new byte[16], new byte[32], "key-A.1");
        char[] replacements = {'\0', '$', '=', ',', '+', '/', '0', '1', '9', 'A', 'a', '\uD800'};
        for (String seed : new String[]{raw, keyed}) {
            for (int position = 0; position < seed.length(); position++) {
                for (char replacement : replacements) {
                    if (seed.charAt(position) == replacement) continue;
                    String mutated = seed.substring(0, position) + replacement + seed.substring(position + 1);
                    PasswordStoredForm parsed = PasswordStoredForm.parse(mutated, limits);
                    try {
                        if (parsed.status() == PasswordStoredForm.Status.VALID)
                            assertEquals(mutated, reconstruct(parsed),
                                    "Accepted mutation must still be the exact canonical wire form");
                    } finally {
                        parsed.wipe();
                    }
                }
            }
        }
    }

    @Test void hostileStoredFormsDoNotConsultKeysOrEnterBusyKdfGate() {
        PasswordWorkGate gate = PasswordWorkGate.withLimits(1, 19_456);
        PasswordHasher hasher = PasswordHasher.withArgon2id(
                Argon2idParameters.withCosts(19_456, 2, 1))
                .workGate(gate)
                .pepperSource(() -> { throw new AssertionError("Malformed form reached pepper source"); })
                .build();
        String raw = PasswordStoredForm.encode(Argon2idParameters.withCosts(19_456, 2, 1),
                new byte[16], new byte[32], null);
        String keyed = PasswordStoredForm.encode(Argon2idParameters.withCosts(19_456, 2, 1),
                new byte[16], new byte[32], "key-A.1");
        try (PasswordWorkGate.Permit held = Objects.requireNonNull(gate.tryAcquire(19_456))) {
            for (String hostile : new String[]{
                    raw + "=", raw.repeat(8), raw.replace("m=19456", "m=99999999"),
                    raw.replace("$argon2id$", "$argon2i$"), raw.replace("$v=19$", "$v=16$"),
                    raw.replace("m=19456", "m=+19456"), raw.replace("t=2", "t=7"),
                    keyed.replace("kid=key-A.1", "kid="),
                    keyed.replace("kid=key-A.1", "kid=k\uD800")}) {
                assertInstanceOf(PasswordVerificationResult.Rejected.class,
                        hasher.verifyResult("synthetic".toCharArray(), hostile), hostile);
            }
            assertNotEquals(null, held);
        }
    }

    private static @NonNull String reconstruct(@NonNull PasswordStoredForm form) {
        String prefix = form.peppered() ? "$revetsec-pw$v=1$kid=" + form.pepperKeyId() : "";
        return prefix + "$argon2id$v=19$m=" + form.memoryKiB() + ",t=" + form.passes()
                + ",p=" + form.lanes() + "$"
                + Base64.getEncoder().withoutPadding().encodeToString(form.salt()) + "$"
                + Base64.getEncoder().withoutPadding().encodeToString(form.tag());
    }

    private static int sum(byte @NonNull [] bytes) {
        int result = 0;
        for (byte value : bytes) result |= value;
        return result;
    }
}
