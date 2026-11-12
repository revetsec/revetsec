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
package com.revetsec.saml;

import org.jspecify.annotations.NonNull;

import com.revetsec.StateSealer;
import com.revetsec.StateUnsealResult;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

final class SamlSessionReferenceSealResultTests {
    private static final Instant NOW = SamlSessionReferenceBudgetTests.NOW;
    private static final Clock CLOCK = SamlSessionReferenceBudgetTests.CLOCK;
    private static final String CONTEXT = "session-budget-result";
    private static final Instant END = NOW.plusSeconds(300);

    @TestFactory @NonNull Stream<@NonNull DynamicTest> exactConfiguredBoundAndOneByteOver() {
        return Stream.of(1024, 3800, 16384).flatMap(cap -> Stream.of(1, 64).map(keyLength ->
                DynamicTest.dynamicTest("cap " + cap + "; key ID " + keyLength, () -> {
                    StateSealer basis = sealer(cap, "k".repeat(keyLength));
                    // Independent v1 wire arithmetic; each cap is divisible by four.
                    int plaintextLength = cap / 4 * 3 - 54 - keyLength;
                    SamlSessionReference exact = atPlaintextLength(plaintextLength);
                    assertEquals(plaintextLength, exact.toSerializedForm().length());
                    Instrumented instrumented = instrument(basis, false);StateSealer sealer=instrumented.sealer();CountingRandom random=instrumented.random();
                    SamlSessionReferenceSealResult.Succeeded success = assertInstanceOf(
                            SamlSessionReferenceSealResult.Succeeded.class,
                            assertDoesNotThrow(() -> exact.toSealedFormResult(sealer, CONTEXT, END)));
                    assertEquals(cap, success.getSealedForm().length());
                    assertEquals(2, random.draws);
                    assertSameFields(exact, open(success.getSealedForm(), sealer, CONTEXT, CLOCK));
                    assertFalse(success.toString().contains(success.getSealedForm()));
                    assertTrue(success.toString().contains("<redacted>"));
                    SamlSessionReference over = atPlaintextLength(plaintextLength + 1);
                    instrumented=instrument(basis,true);StateSealer failingSealer=instrumented.sealer();random=instrumented.random();
                    assertSame(SamlSessionReferenceSealResult.TooLarge.INSTANCE,
                            assertDoesNotThrow(() -> over.toSealedFormResult(failingSealer, CONTEXT, END)));
                    assertEquals(0, random.draws, "size refusal must precede entropy/provider work");
                    assertThrows(IllegalArgumentException.class, () -> over.toSealedForm(failingSealer, CONTEXT, END),
                            "the existing throwing convenience remains available");
                    assertEquals(0, random.draws);
                })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> completeUnicodeProfileUsesTrustedStorageWhenItCannotBeSealed() {
        return Stream.of("ASCII", "BMP", "supplementary").map(alphabet -> DynamicTest.dynamicTest(alphabet, () -> {
            SamlSessionReference reference = SamlSessionReferenceBudgetTests.maximum(alphabet, Instant.MAX);
            Instrumented instrumented=instrument(sealer(16384,"largest-profile"),true);StateSealer sealer=instrumented.sealer();CountingRandom random=instrumented.random();
            assertSame(SamlSessionReferenceSealResult.TooLarge.INSTANCE,
                    assertDoesNotThrow(() -> reference.toSealedFormResult(sealer, CONTEXT, END)));
            assertEquals(0, random.draws);
            assertSameFields(reference, SamlSessionReferenceBudgetTests.parsed(reference.toSerializedForm()));
        }));
    }

    @Test void acceptedMaximumNameIdAloneCanExceedEvenTheLargestSeal() throws Exception {
        SamlSessionReference reference = new SamlSessionReference("connection", "idp",
                new SamlNameId("\u20ac".repeat(4096), null, null, null), null, null);
        Instrumented instrumented=instrument(sealer(16384,"maximum-nameid"),true);StateSealer sealer=instrumented.sealer();CountingRandom random=instrumented.random();
        assertSame(SamlSessionReferenceSealResult.TooLarge.INSTANCE,
                assertDoesNotThrow(() -> reference.toSealedFormResult(sealer, CONTEXT, END)));
        assertEquals(0, random.draws);
        assertEquals("\u20ac".repeat(4096), SamlSessionReferenceBudgetTests.parsed(reference.toSerializedForm())
                .getNameId().getValue());
    }

    @Test void providerFailureIsUnavailableWithoutProviderDetails() throws Exception {
        SamlSessionReference reference = small();
        Instrumented instrumented=instrument(sealer(3800,"provider-fault"),true);StateSealer sealer=instrumented.sealer();CountingRandom random=instrumented.random();
        SamlSessionReferenceSealResult result = assertDoesNotThrow(() -> reference.toSealedFormResult(sealer, CONTEXT, END));
        assertSame(SamlSessionReferenceSealResult.Unavailable.INSTANCE, result);
        assertEquals(1, random.draws);
        assertEquals("SamlSessionReferenceSealResult.Unavailable", result.toString());
        assertFalse(result.toString().contains("PRIVATE-PROVIDER-DETAIL"));
        assertThrows(IllegalStateException.class, () -> reference.toSealedForm(sealer, CONTEXT, END));
    }

    @Test void sealedResultRetainsTypeContextKeysTamperAndExpiryChecks() {
        StateSealer sealer = sealer(3800, "isolation");
        SamlSessionReference reference = small();
        String sealed = assertInstanceOf(SamlSessionReferenceSealResult.Succeeded.class,
                reference.toSealedFormResult(sealer, CONTEXT, END)).getSealedForm();
        assertSameFields(reference, open(sealed, sealer, CONTEXT, Clock.fixed(END.minusNanos(1), ZoneOffset.UTC)));
        assertInstanceOf(SamlSessionReferenceParseResult.RejectedSealedState.class,
                SamlSessionReference.fromSealedFormResult(sealed, sealer, CONTEXT, Clock.fixed(END, ZoneOffset.UTC)));
        assertInstanceOf(SamlSessionReferenceParseResult.RejectedSealedState.class,
                SamlSessionReference.fromSealedFormResult(sealed, sealer, "other-context", CLOCK));
        assertInstanceOf(SamlSessionReferenceParseResult.RejectedSealedState.class,
                SamlSessionReference.fromSealedFormResult(sealed, sealer(3800, "other-key"), CONTEXT, CLOCK));
        assertInstanceOf(SamlSessionReferenceParseResult.RejectedSealedState.class,
                SamlSessionReference.fromSealedFormResult(sealed.substring(0, sealed.length() - 1) + "!", sealer, CONTEXT, CLOCK));
        assertInstanceOf(StateUnsealResult.Rejected.class, sealer.unsealResult(sealed, CONTEXT));
        String app = sealer.seal(reference.toSerializedForm(), CONTEXT, Duration.ofMinutes(5));
        assertInstanceOf(SamlSessionReferenceParseResult.RejectedSealedState.class,
                SamlSessionReference.fromSealedFormResult(app, sealer, CONTEXT, CLOCK));
        String malformed = SealedStateAccess.get().seal(sealer, SealedStateType.SAML_SESSION,
                "not-a-reference", CONTEXT, END);
        assertInstanceOf(SamlSessionReferenceParseResult.Rejected.class,
                SamlSessionReference.fromSealedFormResult(malformed, sealer, CONTEXT, CLOCK));
    }

    @Test void fractionalExpiryStillUsesTheExistingCeilingRule() {
        StateSealer sealer = sealer(3800, "fractional");
        String sealed = assertInstanceOf(SamlSessionReferenceSealResult.Succeeded.class,
                small().toSealedFormResult(sealer, CONTEXT, END.plusNanos(1))).getSealedForm();
        open(sealed, sealer, CONTEXT, Clock.fixed(END, ZoneOffset.UTC));
        assertInstanceOf(SamlSessionReferenceParseResult.RejectedSealedState.class,
                SamlSessionReference.fromSealedFormResult(sealed, sealer, CONTEXT,
                        Clock.fixed(END.plusSeconds(1), ZoneOffset.UTC)));
    }

    @SuppressWarnings("NullAway") // Required argument violations remain programmer errors, including oversized references.
    @Test void invalidArgumentsAreNotMisclassifiedAsTooLarge() throws Exception {
        SamlSessionReference reference = SamlSessionReferenceBudgetTests.maximum("BMP", Instant.MAX);
        Instrumented instrumented=instrument(sealer(1024,"bad-arguments"),true);StateSealer sealer=instrumented.sealer();CountingRandom random=instrumented.random();
        assertThrows(NullPointerException.class, () -> reference.toSealedFormResult(null, CONTEXT, END));
        assertThrows(NullPointerException.class, () -> reference.toSealedFormResult(sealer, null, END));
        assertThrows(NullPointerException.class, () -> reference.toSealedFormResult(sealer, CONTEXT, null));
        for (String context : new String[] {"", "x".repeat(257), "\ud800"})
            assertThrows(IllegalArgumentException.class, () -> reference.toSealedFormResult(sealer, context, END));
        SamlSessionReference invalidText = new SamlSessionReference("connection", "idp",
                new SamlNameId("\ud800", null, null, null), null, null);
        assertThrows(IllegalArgumentException.class, () -> invalidText.toSealedFormResult(sealer, CONTEXT, END));
        assertEquals(0, random.draws);
    }

    @Test void theActualEntryVersionSealedFixtureStillOpens() throws Exception {
        String sealed;
        try (var input = getClass().getResourceAsStream("/fixtures/saml/session-reference-v1.txt")) {
            assertNotNull(input);
            sealed = new String(input.readAllBytes(), StandardCharsets.US_ASCII).strip();
        }
        StateSealer sealer = sealer(3800, "saml-session-budget-v1");
        assertEquals("1.Yw.aQ.YQ.-.-.-.-.-.-", open(sealed, sealer, "session-budget-v1", CLOCK).toSerializedForm());
    }

    private static @NonNull StateSealer sealer(int cap, @NonNull String id) {
        return StateSealer.withActiveKey(TestSealers.fixedKey(id)).maximumSealedLength(cap).clock(CLOCK).build();
    }
    private static @NonNull SamlSessionReference small() { return SamlSessionReferenceBudgetTests.parsed("1.Yw.aQ.YQ.-.-.-.-.-.-"); }
    private static @NonNull SamlSessionReference open(@NonNull String sealed, @NonNull StateSealer sealer, @NonNull String context, @NonNull Clock clock) {
        return assertInstanceOf(SamlSessionReferenceParseResult.Succeeded.class,
                SamlSessionReference.fromSealedFormResult(sealed, sealer, context, clock)).getReference();
    }
    private static void assertSameFields(@NonNull SamlSessionReference expected, @NonNull SamlSessionReference actual) {
        SamlSessionReferenceBudgetTests.assertSameFields(expected, actual);
    }
    private static int base64Length(int bytes) { return (4 * bytes + 2) / 3; }
    private static int optionalLength(int units) { return units == 0 ? 1 : base64Length(units + 1); }
    private static @Nullable String optionalText(int units) { return units == 0 ? null : "q".repeat(units); }
    private static @NonNull SamlSessionReference atPlaintextLength(int target) {
        // Search integer lengths, allocating strings only after an exact ASCII envelope is found.
        for (int units = 1; units <= 12288; units++) {
            int value = Math.min(units, 4096);
            int rest = units - value;
            int format = Math.min(rest, 2048); rest -= format;
            int qualifier = Math.min(rest, 2048); rest -= qualifier;
            int spQualifier = Math.min(rest, 2048); rest -= spQualifier;
            int index = Math.min(rest, 2048);
            int length = 10 + 2 + 2 + base64Length(value) + optionalLength(format)
                    + optionalLength(qualifier) + optionalLength(spQualifier) + 1 + optionalLength(index) + 1;
            for (int extra = 0; extra <= 1; extra++) {
                if (length + extra == target) return new SamlSessionReference("c", "i",
                        new SamlNameId("v".repeat(value), optionalText(format), optionalText(qualifier),
                                optionalText(spQualifier), extra == 1 ? "" : null), optionalText(index), null);
            }
        }
        throw new AssertionError("No legal envelope at length " + target);
    }

    private record Instrumented(@NonNull StateSealer sealer,@NonNull CountingRandom random) { }
    private static @NonNull Instrumented instrument(@NonNull StateSealer basis, boolean fail) throws Exception {
        // Per-instance constructor seam only; no global provider list or production SPI is modified.
        CountingRandom random=new CountingRandom(fail);Class<?> entropyType=Class.forName("com.revetsec.internal.crypto.EntropySource");
        var entropyConstructor=entropyType.getDeclaredConstructor(SecureRandom.class);entropyConstructor.setAccessible(true);Object entropy=entropyConstructor.newInstance(random);
        var constructor=java.util.Arrays.stream(StateSealer.class.getDeclaredConstructors()).filter(candidate->candidate.getParameterCount()==6).findFirst().orElseThrow();constructor.setAccessible(true);
        Object[] arguments={field(basis,"activeKey"),field(basis,"keysByKeyId"),field(basis,"verificationKeyIds"),field(basis,"clock"),field(basis,"maximumSealedLength"),entropy};
        return new Instrumented((StateSealer)constructor.newInstance(arguments),random);
    }
    private static @NonNull Object field(@NonNull StateSealer sealer,@NonNull String name)throws Exception{Field field=StateSealer.class.getDeclaredField(name);field.setAccessible(true);return java.util.Objects.requireNonNull(field.get(sealer));}
    private static final class CountingRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;
        private final boolean fail;
        private int draws;
        private CountingRandom(boolean fail) { this.fail = fail; }
        @Override public void nextBytes(byte @NonNull [] bytes) {
            draws++;
            if (fail) throw new ProviderException("PRIVATE-PROVIDER-DETAIL");
            super.nextBytes(bytes);
        }
    }
}
