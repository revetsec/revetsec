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
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestSealers;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Old-surface regressions: these tests also compile and run on the entry production sources. */
final class SamlSessionReferenceBudgetTests {
    static final Instant NOW = Instant.parse("2026-10-09T00:01:00Z");
    static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String SP = "https://sp.example.test/saml";
    private static final URI ACS = URI.create("https://sp.example.test/acs");
    private static final TestJwk.Fixture KEY = TestJwk.Fixture.IDP_SIGNING_RSA_2048;

    @TestFactory @NonNull Stream<@NonNull DynamicTest> acceptedSignedIdentitiesRetainTheirFullReference() {
        return Stream.of("ASCII", "BMP", "supplementary").flatMap(alphabet ->
                Stream.of("response", "assertion", "both").map(coverage -> DynamicTest.dynamicTest(
                        alphabet + "; " + coverage, () -> {
                            String connection = fill(alphabet, 256);
                            String idp = fill(alphabet, 2048);
                            String value = fill(alphabet, 4096);
                            String qualifier = fill(alphabet, 2048);
                            SamlIdentityProvider trusted = SamlIdentityProvider.withEntityId(idp).connectionId(connection)
                                    .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                                    .signingKeys(List.of(KEY.getPublicKey())).allowUnsolicitedResponses(true).build();
                            SamlServiceProvider sp = SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(ACS)
                                    .clock(CLOCK).replayCache(InMemorySamlReplayCache.fromLimit(CLOCK, 4)).build();
                            String name = "<a:NameID Format='" + qualifier + "' NameQualifier='" + qualifier
                                    + "' SPNameQualifier='" + qualifier + "' SPProvidedID='" + qualifier + "'>"
                                    + value + "</a:NameID>";
                            String xml = SamlResponseSemanticsTests.BASE.replace(" InResponseTo='_request'", "")
                                    .replace("https://idp.example.test/saml", idp)
                                    .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z")
                                    .replace("<a:NameID>alice</a:NameID>", name)
                                    .replace("<a:AuthnStatement AuthnInstant=", "<a:AuthnStatement SessionIndex='"
                                            + qualifier + "' SessionNotOnOrAfter='2026-10-09T01:00:00.123456789Z' AuthnInstant=");
                            String signed = SamlResponseSemanticsTests.signedXml(xml, !coverage.equals("assertion"),
                                    !coverage.equals("response"), KEY.getKeyPair().getPrivate());
                            String encoded = Base64.getEncoder().encodeToString(signed.getBytes(StandardCharsets.UTF_8))
                                    .replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
                            SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                                    SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded)
                                            .getBytes(StandardCharsets.UTF_8), List.of("application/x-www-form-urlencoded"), null))
                                    .getMessage();
                            SamlAuthentication authentication = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                                    sp.completeUnsolicitedAuthenticationResult(message, trusted)).getAuthentication();
                            SamlSessionReference reference = authentication.getSessionReference();
                            assertEquals(value, reference.getNameId().getValue());
                            assertEquals(connection, reference.getIdentityProviderConnectionId());
                            assertEquals(qualifier, reference.getSessionIndex().orElseThrow());
                            String serialized = assertDoesNotThrow(reference::toSerializedForm,
                                    "every admitted field must fit the trusted-storage envelope");
                            assertSameFields(reference, parsed(serialized));
                            assertEquals(serialized, parsed(serialized).toSerializedForm());
                        })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> canonicalEnvelopeCoversTheFieldProfile() {
        return Stream.of("ASCII", "BMP", "supplementary").map(alphabet -> DynamicTest.dynamicTest(alphabet, () -> {
            SamlSessionReference reference = maximum(alphabet, Instant.MAX);
            String serialized = assertDoesNotThrow(reference::toSerializedForm);
            assertTrue(serialized.chars().allMatch(c -> c < 128), "v1 storage is ASCII, including base64url fields");
            assertTrue(serialized.length() <= 66_631);
            if (alphabet.equals("BMP")) assertEquals(66_631, serialized.length(), "the derived ceiling is attainable");
            assertSameFields(reference, parsed(serialized));
            assertEquals(serialized, parsed(serialized).toSerializedForm());
        }));
    }

    @Test void optionalAbsenceEmptyAndUnicodeRemainDistinct() {
        for (String optional : new String[] {null, "", "\u20ac", "\ud83d\ude80"}) {
            SamlSessionReference reference = new SamlSessionReference("connection", "idp",
                    new SamlNameId("subject", optional, optional, optional, optional), optional, null);
            assertSameFields(reference, parsed(reference.toSerializedForm()));
        }
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> restoredFieldsStillEnforceTheirIndividualLimits() {
        List<DynamicTest> tests = new ArrayList<>();
        String valid = maximum("ASCII", Instant.MAX).toSerializedForm();
        int[] limits = {256, 2048, 4096, 2048, 2048, 2048, 2048, 2048};
        for (int field = 0; field < limits.length; field++) {
            int index = field;
            tests.add(DynamicTest.dynamicTest("field " + field + " one over", () -> {
                String[] fields = valid.split("\\.", -1);
                String text = (index >= 3 ? "x" : "") + "a".repeat(limits[index] + 1);
                fields[index + 1] = Base64.getUrlEncoder().withoutPadding().encodeToString(text.getBytes(StandardCharsets.UTF_8));
                assertInstanceOf(SamlSessionReferenceParseResult.Rejected.class,
                        SamlSessionReference.fromSerializedFormResult(String.join(".", fields)));
            }));
        }
        return tests.stream();
    }

    @Test void totalBoundMalformedUtf8AndNoncanonicalBase64RemainRejected() {
        assertInstanceOf(SamlSessionReferenceParseResult.Rejected.class,
                SamlSessionReference.fromSerializedFormResult("x".repeat(66_632)));
        for (String value : List.of("_w", "YQ=", "YR", "", "?")) {
            assertInstanceOf(SamlSessionReferenceParseResult.Rejected.class,
                    SamlSessionReference.fromSerializedFormResult("1.Yw.aQ." + value + ".-.-.-.-.-.-"));
        }
    }

    @Test void existingV1StorageAndTypedSealsRemainUsable() throws Exception {
        String v1 = "1.Yw.aQ.YQ.-.-.-.-.-.-";
        SamlSessionReference reference = parsed(v1);
        assertEquals(v1, reference.toSerializedForm());
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-session-budget-v1")).clock(CLOCK).build();
        String sealed = reference.toSealedForm(sealer, "session-budget-v1", NOW.plusSeconds(300));
        assertEquals(v1, assertInstanceOf(SamlSessionReferenceParseResult.Succeeded.class,
                SamlSessionReference.fromSealedFormResult(sealed, sealer, "session-budget-v1", CLOCK))
                .getReference().toSerializedForm());
        String fixture = System.getProperty("revetsec.saml.reference.fixture");
        if (fixture != null) Files.writeString(Path.of(fixture), sealed + "\n", StandardCharsets.US_ASCII);
    }

    static @NonNull SamlSessionReference maximum(@NonNull String alphabet, @NonNull Instant end) {
        String optional = fill(alphabet, 2048);
        return new SamlSessionReference(fill(alphabet, 256), fill(alphabet, 2048),
                new SamlNameId(fill(alphabet, 4096), optional, optional, optional, optional), optional, end);
    }
    private static @NonNull String fill(@NonNull String alphabet, int units) {
        return switch (alphabet) {
            case "ASCII" -> "a".repeat(units);
            case "BMP" -> "\u20ac".repeat(units);
            case "supplementary" -> "\ud83d\ude80".repeat(units / 2);
            default -> throw new AssertionError(alphabet);
        };
    }
    static @NonNull SamlSessionReference parsed(@NonNull String serialized) {
        return assertInstanceOf(SamlSessionReferenceParseResult.Succeeded.class,
                SamlSessionReference.fromSerializedFormResult(serialized)).getReference();
    }
    static void assertSameFields(@NonNull SamlSessionReference expected, @NonNull SamlSessionReference actual) {
        assertEquals(expected.getIdentityProviderConnectionId(), actual.getIdentityProviderConnectionId());
        assertEquals(expected.getIdentityProviderEntityId(), actual.getIdentityProviderEntityId());
        assertEquals(expected.getNameId().getValue(), actual.getNameId().getValue());
        assertEquals(expected.getNameId().getFormat(), actual.getNameId().getFormat());
        assertEquals(expected.getNameId().getNameQualifier(), actual.getNameId().getNameQualifier());
        assertEquals(expected.getNameId().getSpNameQualifier(), actual.getNameId().getSpNameQualifier());
        assertEquals(expected.getNameId().getSpProvidedId(), actual.getNameId().getSpProvidedId());
        assertEquals(expected.getSessionIndex(), actual.getSessionIndex());
        assertEquals(expected.getSessionNotOnOrAfter(), actual.getSessionNotOnOrAfter());
    }
}
