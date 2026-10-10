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
package com.revetsec.differential;

import com.revetsec.saml.InMemorySamlReplayCache;
import com.revetsec.saml.SamlAuthenticationResult;
import com.revetsec.saml.SamlCompatibilityMode;
import com.revetsec.saml.SamlCredential;
import com.revetsec.saml.SamlIdentityProvider;
import com.revetsec.saml.SamlPostBindingMessage;
import com.revetsec.saml.SamlPostBindingParseResult;
import com.revetsec.saml.SamlServiceProvider;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.assertion.ValidationResult;
import org.opensaml.saml.saml2.assertion.SAML20AssertionValidator;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.assertion.impl.AudienceRestrictionConditionValidator;
import org.opensaml.saml.saml2.assertion.impl.AuthnStatementValidator;
import org.opensaml.saml.saml2.assertion.impl.BearerSubjectConfirmationValidator;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Direct OpenSAML SP verdicts, independent of Spring Security and Revetsec internals. */
final class OpenSamlSpComparatorTests {
    private static final @NonNull Path FIXTURES = Path.of("../src/test/resources/fixtures");
    private static final @NonNull Instant NOW = Instant.parse("2026-09-01T00:01:00Z");
    private static final @NonNull String IDP = "https://idp.scripted-idp.test/";
    private static final @NonNull String SP = "https://sp.test/Selftest";
    private static final @NonNull String ACS = "https://sp.test/acs";
    private static final @NonNull String PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final @NonNull String ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

    @BeforeAll static void initializeOpenSaml() throws Exception {
        InitializationService.initialize();
    }

    @Test void signedPlacementsResolveOnlyTheTrustedIdentity() throws Exception {
        for (String fixture : modernFixtures()) {
            String xml = fixture(fixture);
            String credential = signingCredential(fixture);
            assertEquals("minted-user", authenticate(xml, credential), fixture);
            assertRevetsecIdentity(xml, credential, false, false, fixture);
            String tampered = xml.replace("minted-user", "attacker-user");
            assertNotEquals(xml, tampered, fixture + " signed identity must change");
            assertThrows(Exception.class, () -> authenticate(tampered, credential), fixture);
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    revetsec(tampered, credential, false, false), fixture + " Revetsec tamper");
        }
    }

    @Test void legacySha1NeedsExplicitRevetsecCompatibility() throws Exception {
        String xml = fixture("assertion-rsa-sha1");
        assertEquals("minted-user", authenticate(xml, "idp-signing-rsa-2048"));
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                revetsec(xml, "idp-signing-rsa-2048", false, false));
        assertRevetsecIdentity(xml, "idp-signing-rsa-2048", true, false, "legacy SHA1");
    }

    @Test void wrapperAndNamespaceMutationsNeverReleaseAnIdentity() throws Exception {
        for (String fixture : modernFixtures()) {
            String xml = fixture(fixture);
            String assertion = section(xml, "<saml:Assertion ", "</saml:Assertion>");
            String attacker = Pattern.compile("<ds:Signature\\b[^>]*>.*?</ds:Signature>", Pattern.DOTALL)
                    .matcher(assertion).replaceFirst("")
                    .replace("minted-user", "attacker-user")
                    .replace(id(xml, "saml:Assertion"), "_attacker_assertion");
            Matcher signature = Pattern.compile("<ds:Signature\\b[^>]*>.*?</ds:Signature>",
                    Pattern.DOTALL).matcher(xml);
            assertTrue(signature.find(), fixture + " signature missing");
            List<String> mutations = List.of(
                    xml.replace(assertion, attacker + assertion),
                    xml.replace("<samlp:Status>",
                            "<samlp:Extensions>" + attacker + "</samlp:Extensions><samlp:Status>"),
                    xml.replace(ACS, "https://attacker.example.test/acs"),
                    xml.replace("<samlp:Status>",
                            "<samlp:Status><samlp:StatusCode Value='" + StatusCode.SUCCESS
                                    + "'/></samlp:Status><samlp:Status>"),
                    xml.replace("<samlp:Response ",
                            "<samlp:Response samlp:ID='_attacker_response' "),
                    xml.replace("<saml:Assertion ",
                            "<saml:Assertion saml:ID='_attacker_assertion' "),
                    xml.replace("<samlp:Status>",
                            "<samlp:Extensions><Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>"
                                    + "<Child xml:xmlns='#other'>" + signature.group()
                                    + "</Child></Parent></samlp:Extensions><samlp:Status>"),
                    xml.replace("<samlp:Response ", "<samlp:Response xmlns:ns='1' ")
                            .replace(assertion, attacker + assertion),
                    xml.replace("minted-user", "minted-<!-- -->attacker"));
            for (int index = 0; index < mutations.size(); index++) {
                String candidate = mutations.get(index);
                assertNotEquals(xml, candidate, fixture + " mutation " + index + " is inert");
                boolean assertionOnly = fixture.startsWith("matrix-assertion-")
                        || fixture.equals("assertion-signxml") || fixture.equals("assertion-ec384");
                // OpenSAML ignores two unsigned Extensions changes when it validates the
                // original signed Assertion. Revetsec rejects the whole envelope.
                if (assertionOnly && (index == 1 || index == 6))
                    assertEquals("minted-user", authenticate(candidate, signingCredential(fixture)),
                            fixture + " mutation " + index);
                else
                    assertThrows(Exception.class,
                            () -> authenticate(candidate, signingCredential(fixture)),
                            fixture + " mutation " + index);
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        revetsec(candidate, signingCredential(fixture), false, false),
                        fixture + " mutation " + index + " Revetsec");
            }
        }
    }

    @Test void validlySignedAmbiguousResponsesShowIdentitySelectionDifferences() throws Exception {
        Path directory = FIXTURES.resolve("scripted-idp/signed-structure");
        List<String> names = Files.readAllLines(directory.resolve("sha256.txt")).stream()
                .map(line -> line.substring(0, line.indexOf(' '))).toList();
        assertEquals(15, names.size(), "signed structure corpus changed");
        assertEquals("clean", names.get(0));
        String clean = Files.readString(directory.resolve("clean.xml"));
        assertEquals("minted-user", authenticate(clean, "idp-signing-rsa-2048"));
        assertEquals("minted-user", SpringSamlComparatorTests.spring(clean,
                "idp-signing-rsa-2048").getName());
        assertRevetsecIdentity(clean, "idp-signing-rsa-2048", false, false, "signed clean");
        Map<String, String> opensamlAccepted = new LinkedHashMap<>();
        Map<String, String> springAccepted = new LinkedHashMap<>();
        for (String name : names.subList(1, names.size())) {
            String xml = Files.readString(directory.resolve(name + ".xml"));
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    revetsec(xml, "idp-signing-rsa-2048", false, false), name + " Revetsec");
            try {
                opensamlAccepted.put(name, authenticate(xml, "idp-signing-rsa-2048"));
            } catch (Exception ignored) {
                // The native OpenSAML path rejected this signed document.
            }
            try {
                springAccepted.put(name, SpringSamlComparatorTests.spring(
                        xml, "idp-signing-rsa-2048").getName());
            } catch (Exception ignored) {
                // The Spring service-provider path rejected this signed document.
            }
        }
        assertEquals(Map.of(
                "nested-assertion-advice", "minted-user",
                "attacker-assertion-extension", "minted-user",
                "duplicate-issuer", "minted-user",
                "assertion-before-status", "minted-user",
                "duplicate-subject", "minted-user",
                "duplicate-nameid", "minted-user",
                "duplicate-status-code", "minted-user"), opensamlAccepted);
        assertEquals(Map.of(
                "duplicate-assertion-before", "attacker-user",
                "duplicate-assertion-after", "minted-user",
                "nested-assertion-advice", "minted-user",
                "attacker-assertion-extension", "minted-user",
                "duplicate-status", "minted-user",
                "duplicate-issuer", "minted-user",
                "assertion-before-status", "minted-user",
                "duplicate-subject", "minted-user",
                "duplicate-nameid", "minted-user",
                "duplicate-status-code", "minted-user"), springAccepted);
    }

    @Test void assertionSignedAmbiguitiesKeepParserVerdictsPinned() throws Exception {
        Path directory = FIXTURES.resolve("scripted-idp/signed-assertion-structure");
        List<String> names = Files.readAllLines(directory.resolve("sha256.txt")).stream()
                .map(line -> line.substring(0, line.indexOf(' '))).toList();
        assertEquals(29, names.size(), "signed assertion corpus changed");
        assertEquals("clean", names.get(0));
        Map<String, String> opensamlAccepted = new LinkedHashMap<>();
        Map<String, String> springAccepted = new LinkedHashMap<>();
        for (String name : names) {
            String xml = Files.readString(directory.resolve(name + ".xml"));
            boolean positive = name.equals("clean") || name.equals("comment-split-nameid")
                    || name.equals("cdata-nameid") || name.equals("advice-before-authn")
                    || name.equals("typed-attribute-statement")
                    || name.equals("attribute-before-authn");
            if (positive)
                assertRevetsecIdentity(xml, "idp-signing-rsa-2048", false, false,
                        name + " Revetsec");
            else
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        revetsec(xml, "idp-signing-rsa-2048", false, false),
                        name + " Revetsec");
            try {
                opensamlAccepted.put(name, authenticate(xml, "idp-signing-rsa-2048"));
            } catch (Exception ignored) {
                // Direct OpenSAML rejected this signed assertion.
            }
            try {
                springAccepted.put(name, SpringSamlComparatorTests.spring(
                        xml, "idp-signing-rsa-2048").getName());
            } catch (Exception ignored) {
                // Spring rejected this signed assertion.
            }
        }
        assertEquals(Set.of("clean", "duplicate-subject", "duplicate-nameid",
                "duplicate-confirmation-data", "duplicate-conditions",
                "duplicate-authn-statement", "duplicate-authn-context",
                "duplicate-class-ref", "assertion-nil", "issuer-after-subject",
                "conditions-before-subject", "advice-after-authn", "duplicate-advice",
                "attribute-before-conditions", "attribute-statement-nil", "attribute-nil",
                "authn-statement-nil", "comment-split-nameid", "cdata-nameid",
                "advice-before-authn", "typed-attribute-statement", "attribute-before-authn"),
                opensamlAccepted.keySet());
        assertTrue(opensamlAccepted.values().stream().allMatch("minted-user"::equals));
        assertEquals(opensamlAccepted, springAccepted);
    }

    @Test void signedSchemaInstanceHintsKeepParserVerdictsPinned() throws Exception {
        Path directory = FIXTURES.resolve("scripted-idp/signed-attribute-values");
        List<String> names = Files.readAllLines(directory.resolve("sha256.txt")).stream()
                .map(line -> line.substring(0, line.indexOf(' '))).toList();
        assertEquals(12, names.size(), "signed attribute corpus changed");
        Map<String, String> opensamlAccepted = new LinkedHashMap<>();
        Map<String, String> springAccepted = new LinkedHashMap<>();
        for (String name : names) {
            String xml = Files.readString(directory.resolve(name + ".xml"));
            try {
                opensamlAccepted.put(name, authenticate(xml, "idp-signing-rsa-2048"));
            } catch (Exception ignored) {
                // The direct OpenSAML path rejected this signed assertion.
            }
            try {
                springAccepted.put(name, SpringSamlComparatorTests.spring(
                        xml, "idp-signing-rsa-2048").getName());
            } catch (Exception ignored) {
                // The Spring service-provider path rejected this signed assertion.
            }
        }
        assertEquals(Set.copyOf(names), opensamlAccepted.keySet());
        assertTrue(opensamlAccepted.values().stream().allMatch("minted-user"::equals));
        assertEquals(opensamlAccepted, springAccepted);
    }

    @Test void signedIdentityShapeKeepsParserSelectionPinned() throws Exception {
        Path directory = FIXTURES.resolve("scripted-idp/signed-identity-shape");
        List<String> names = Files.readAllLines(directory.resolve("sha256.txt")).stream()
                .map(line -> line.substring(0, line.indexOf(' '))).toList();
        assertEquals(20, names.size(), "signed identity-shape corpus changed");
        Map<String, String> opensamlAccepted = new LinkedHashMap<>();
        Map<String, String> springAccepted = new LinkedHashMap<>();
        for (String name : names) {
            String xml = Files.readString(directory.resolve(name + ".xml"));
            try {
                opensamlAccepted.put(name, authenticate(xml, "idp-signing-rsa-2048"));
            } catch (Exception ignored) {
                // The direct OpenSAML path rejected this signed assertion.
            }
            try {
                springAccepted.put(name, SpringSamlComparatorTests.spring(
                        xml, "idp-signing-rsa-2048").getName());
            } catch (Exception ignored) {
                // The Spring service-provider path rejected this signed assertion.
            }
        }
        assertEquals(Set.of("clean", "subject-nameid-type", "subject-nameid-nil-false",
                "assertion-version-missing", "subject-nameid-nil", "assertion-issuer-nil",
                "audience-nil", "authn-class-ref-nil",
                "subject-nameid-after-confirmation", "authn-duplicate-locality"),
                opensamlAccepted.keySet());
        assertTrue(opensamlAccepted.values().stream().allMatch("minted-user"::equals));
        assertEquals(Set.of("clean", "subject-nameid-type", "subject-nameid-nil-false",
                "authn-locality-before-context", "assertion-version-missing",
                "subject-nameid-nil", "assertion-issuer-nil", "audience-nil",
                "authn-class-ref-nil", "subject-nameid-after-confirmation",
                "authn-locality-after-context", "authn-duplicate-locality"),
                springAccepted.keySet());
        assertTrue(springAccepted.values().stream().allMatch("minted-user"::equals));
    }

    @Test void signedBearerAndConditionsShapeKeepsParserSelectionPinned() throws Exception {
        Path directory = FIXTURES.resolve("scripted-idp/signed-boundary-shape");
        List<String> names = Files.readAllLines(directory.resolve("sha256.txt")).stream()
                .map(line -> line.substring(0, line.indexOf(' '))).toList();
        assertEquals(19, names.size(), "signed boundary-shape corpus changed");
        Map<String, String> opensamlAccepted = new LinkedHashMap<>();
        Map<String, String> springAccepted = new LinkedHashMap<>();
        for (String name : names) {
            String xml = Files.readString(directory.resolve(name + ".xml"));
            try {
                opensamlAccepted.put(name, authenticate(xml, "idp-signing-rsa-2048"));
            } catch (Exception ignored) {
                // The direct OpenSAML path rejected this signed assertion.
            }
            try {
                springAccepted.put(name, SpringSamlComparatorTests.spring(
                        xml, "idp-signing-rsa-2048").getName());
            } catch (Exception ignored) {
                // The Spring service-provider path rejected this signed assertion.
            }
        }
        assertEquals(Set.of("clean", "matching-confirmation-nameid", "typed-confirmation-data",
                "subject-nil", "confirmation-nil", "data-nil", "inverted-bearer-window",
                "mismatched-confirmation-nameid", "conditions-nil",
                "audience-restriction-nil"), opensamlAccepted.keySet());
        assertTrue(opensamlAccepted.values().stream().allMatch("minted-user"::equals));
        assertEquals(Set.of("clean", "matching-confirmation-nameid", "one-time-and-proxy",
                "typed-confirmation-data", "subject-nil", "confirmation-nil", "data-nil",
                "inverted-bearer-window", "mismatched-confirmation-nameid", "conditions-nil",
                "audience-restriction-nil", "proxy-nil"), springAccepted.keySet());
        assertTrue(springAccepted.values().stream().allMatch("minted-user"::equals));
    }

    @Test void encryptedAssertionsAndEncryptedIdResolveTrustedIdentity() throws Exception {
        for (String data : List.of("aes128-gcm", "aes192-gcm", "aes256-gcm"))
            for (String transport : List.of("rsa-oaep-sha256-mgf1sha256", "rsa-oaep-mgf1p"))
                comparePositive("encrypted-" + data + "-" + transport,
                        "idp-signing-rsa-2048", false);
        for (String data : List.of("aes128-gcm", "aes192-gcm", "aes256-gcm"))
            for (String transport : List.of("rsa-oaep-mgf1p-sha1", "rsa-oaep-mgf1p-sha256",
                    "rsa-oaep-sha1-mgf1sha1", "rsa-oaep-sha256-mgf1sha1"))
                for (String placement : List.of("response", "assertion", "both")) {
                    String name = "oaep-" + data + "-" + transport + "-" + placement;
                    comparePositive(name, "idp-signing-rsa-2048", false);
                }
        for (String data : List.of("aes128-cbc", "aes192-cbc", "aes256-cbc")) {
            String name = "encrypted-" + data + "-response";
            comparePositive(name, "idp-signing-rsa-2048", true);
        }
        comparePositive("assertion-rsa512-encrypted", "idp-signing-rsa-3072", false);
        comparePositive("assertion-ec256-encrypted-id", "idp-signing-ec-p256", false);
    }

    @Test void encryptedNegativesAndUnsignedResponseDoNotAuthenticate() throws Exception {
        for (String name : List.of("negative-mgf-under-mgf1p",
                "encrypted-aes128-cbc-assertion", "negative-rsa-1_5")) {
            String xml = fixture(name);
            // OpenSAML authenticates the original signed identity. Revetsec's stricter
            // encryption policy rejects each whole response.
            assertEquals("minted-user", authenticate(xml, "idp-signing-rsa-2048"), name);
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    revetsec(xml, "idp-signing-rsa-2048", false, false), name);
        }
        for (String name : List.of("negative-nonempty-oaep-params",
                "negative-cipher-bit-flip", "unsigned-encrypted")) {
            String xml = fixture(name);
            assertThrows(Exception.class, () -> authenticate(xml, "idp-signing-rsa-2048"), name);
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    revetsec(xml, "idp-signing-rsa-2048", false, false), name);
        }
    }

    @Test void encryptedWrapperMatrixNeverReleasesAttackerIdentity() throws Exception {
        String signedTemplate = fixture("assertion-signxml");
        String templateAssertion = section(signedTemplate, "<saml:Assertion ", "</saml:Assertion>");
        String attacker = Pattern.compile("<ds:Signature\\b[^>]*>.*?</ds:Signature>", Pattern.DOTALL)
                .matcher(templateAssertion).replaceFirst("")
                .replace("minted-user", "attacker-user")
                .replace(id(signedTemplate, "saml:Assertion"), "_attacker_assertion");
        String copiedSignature = section(signedTemplate, "<ds:Signature ", "</ds:Signature>");
        List<String> fixtures = encryptedFixtures();
        assertEquals(47, fixtures.size(), "encrypted fixture matrix changed");
        for (String name : fixtures) {
            String xml = fixture(name);
            String signingKey = encryptedSigningCredential(name);
            boolean cbc = name.contains("-cbc-");
            boolean assertionOnly = name.endsWith("-assertion")
                    || name.equals("assertion-rsa512-encrypted")
                    || name.equals("assertion-ec256-encrypted-id");
            String carrier = name.equals("assertion-ec256-encrypted-id")
                    ? section(xml, "<saml:Assertion ", "</saml:Assertion>")
                    : section(xml, "<saml:EncryptedAssertion>", "</saml:EncryptedAssertion>");
            assertEquals("minted-user", authenticate(xml, signingKey), name + " baseline OpenSAML");
            assertRevetsecIdentity(xml, signingKey, false, cbc, name + " baseline");
            if (assertionOnly && !name.equals("assertion-ec256-encrypted-id"))
                assertThrows(Exception.class,
                        () -> SpringSamlComparatorTests.spring(xml, signingKey),
                        name + " Spring baseline");
            else
                assertEquals("minted-user", SpringSamlComparatorTests.spring(xml, signingKey)
                        .getName(), name + " Spring baseline");
            for (Mutation mutation : encryptedMutations(xml, carrier, attacker, copiedSignature)) {
                String label = name + ":" + mutation.name();
                assertNotEquals(xml, mutation.xml(), label + " is inert");
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        revetsec(mutation.xml(), signingKey, false, cbc),
                        label + " Revetsec");
                boolean extension = mutation.name().equals("attacker-extension")
                        || mutation.name().equals("copied-signature-extension");
                if (assertionOnly && extension)
                    assertEquals("minted-user", authenticate(mutation.xml(), signingKey),
                            label + " OpenSAML identity");
                else
                    assertThrows(Exception.class, () -> authenticate(mutation.xml(), signingKey),
                            label + " OpenSAML");
                boolean springAccepts = name.equals("assertion-ec256-encrypted-id")
                        && (extension || mutation.name().equals("duplicate-status"));
                if (springAccepts)
                    assertEquals("minted-user", SpringSamlComparatorTests.spring(
                            mutation.xml(), signingKey).getName(), label + " Spring identity");
                else
                    assertThrows(Exception.class,
                            () -> SpringSamlComparatorTests.spring(mutation.xml(), signingKey),
                            label + " Spring");
            }
        }
    }

    private static @NonNull List<String> encryptedFixtures() {
        List<String> fixtures = new ArrayList<>();
        for (String data : List.of("aes128-gcm", "aes192-gcm", "aes256-gcm"))
            for (String transport : List.of("rsa-oaep-sha256-mgf1sha256", "rsa-oaep-mgf1p"))
                fixtures.add("encrypted-" + data + "-" + transport);
        for (String data : List.of("aes128-gcm", "aes192-gcm", "aes256-gcm"))
            for (String transport : List.of("rsa-oaep-mgf1p-sha1", "rsa-oaep-mgf1p-sha256",
                    "rsa-oaep-sha1-mgf1sha1", "rsa-oaep-sha256-mgf1sha1"))
                for (String placement : List.of("response", "assertion", "both"))
                    fixtures.add("oaep-" + data + "-" + transport + "-" + placement);
        for (String data : List.of("aes128-cbc", "aes192-cbc", "aes256-cbc"))
            fixtures.add("encrypted-" + data + "-response");
        fixtures.add("assertion-rsa512-encrypted");
        fixtures.add("assertion-ec256-encrypted-id");
        return List.copyOf(fixtures);
    }

    private static @NonNull String encryptedSigningCredential(@NonNull String name) {
        if (name.equals("assertion-rsa512-encrypted")) return "idp-signing-rsa-3072";
        if (name.equals("assertion-ec256-encrypted-id")) return "idp-signing-ec-p256";
        return "idp-signing-rsa-2048";
    }

    private static @NonNull List<Mutation> encryptedMutations(@NonNull String xml,
            @NonNull String carrier, @NonNull String attacker, @NonNull String signature) {
        String extension = "<samlp:Extensions>" + attacker + "</samlp:Extensions>";
        String copied = "<samlp:Extensions><Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>"
                + "<Child xml:xmlns='#other'>" + signature + "</Child></Parent></samlp:Extensions>";
        return List.of(
                new Mutation("attacker-before-carrier", xml.replace(carrier, attacker + carrier)),
                new Mutation("attacker-after-carrier", xml.replace(carrier, carrier + attacker)),
                new Mutation("attacker-extension", xml.replace("<samlp:Status>",
                        extension + "<samlp:Status>")),
                new Mutation("duplicate-carrier", xml.replace(carrier, carrier + carrier)),
                new Mutation("destination", xml.replace(ACS, "https://attacker.example.test/acs")),
                new Mutation("duplicate-status", xml.replace("<samlp:Status>",
                        "<samlp:Status><samlp:StatusCode Value='" + StatusCode.SUCCESS
                                + "'/></samlp:Status><samlp:Status>")),
                new Mutation("qualified-response-id", xml.replace("<samlp:Response ",
                        "<samlp:Response samlp:ID='_attacker_response' ")),
                new Mutation("copied-signature-extension", xml.replace("<samlp:Status>",
                        copied + "<samlp:Status>")),
                new Mutation("relative-namespace-sibling", xml.replace("<samlp:Response ",
                        "<samlp:Response xmlns:ns='1' ").replace(carrier, attacker + carrier)),
                new Mutation("duplicate-issuer", xml.replace("<samlp:Status>",
                        "<saml:Issuer>https://attacker.example.test/</saml:Issuer><samlp:Status>")));
    }

    private record Mutation(@NonNull String name, @NonNull String xml) { }

    private static void comparePositive(@NonNull String name, @NonNull String credential,
            boolean cbc) throws Exception {
        String xml = fixture(name);
        assertEquals("minted-user", authenticate(xml, credential), name + " OpenSAML");
        assertRevetsecIdentity(xml, credential, false, cbc, name);
    }

    private static void assertRevetsecIdentity(@NonNull String xml, @NonNull String credential,
            boolean sha1, boolean cbc, @NonNull String label) throws Exception {
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class,
                revetsec(xml, credential, sha1, cbc), label + " Revetsec");
        assertEquals("minted-user", success.getAuthentication().getNameId().orElseThrow().getValue(),
                label + " Revetsec identity");
    }

    private static @NonNull SamlAuthenticationResult revetsec(@NonNull String xml,
            @NonNull String signingKey, boolean sha1, boolean cbc) throws Exception {
        SamlServiceProvider provider = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create(ACS))
                .replayCache(InMemorySamlReplayCache.withLimit(
                        Clock.fixed(NOW, ZoneOffset.UTC), 16))
                .decryptionCredentials(List.of(SamlCredential.fromPem(
                        Files.readString(FIXTURES.resolve("keys/sp-encryption-rsa-2048-key.pem")),
                        Files.readString(FIXTURES.resolve("keys/sp-encryption-rsa-2048-cert.pem")))))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
        EnumSet<SamlCompatibilityMode> compatibility = EnumSet.of(
                SamlCompatibilityMode.UNSOLICITED_RESPONSES);
        if (sha1) compatibility.add(SamlCompatibilityMode.SHA1_SIGNATURES);
        if (cbc) compatibility.add(SamlCompatibilityMode.AES_CBC_ENCRYPTION);
        SamlIdentityProvider identityProvider = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("opensaml-differential")
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .signingKeys(List.of(certificate(signingKey).getPublicKey()))
                .compatibility(Set.copyOf(compatibility)).build();
        String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        return provider.completeUnsolicitedAuthenticationResult(message, identityProvider);
    }

    private static @NonNull String authenticate(@NonNull String xml, @NonNull String signingKey)
            throws Exception {
        byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 128_000 || xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY"))
            throw new IllegalArgumentException("Unsafe SAML document");
        Element root = XMLObjectProviderRegistrySupport.getParserPool().parse(
                new ByteArrayInputStream(bytes)).getDocumentElement();
        if (!PROTOCOL_NS.equals(root.getNamespaceURI()) || !"Response".equals(root.getLocalName()))
            throw new IllegalArgumentException("Not a SAML Response");
        Response response = (Response) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
                .ensureUnmarshaller(root).unmarshall(root);
        if (response.getVersion() != SAMLVersion.VERSION_20
                || !ACS.equals(response.getDestination())
                || !IDP.equals(response.getIssuer().getValue())
                || response.getInResponseTo() != null
                || response.getIssueInstant() == null
                || response.getIssueInstant().isAfter(NOW.plusSeconds(180))
                || !StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())
                || countChildren(root, PROTOCOL_NS, "Status") != 1
                || countChildren(root, ASSERTION_NS, "Assertion")
                        + countChildren(root, ASSERTION_NS, "EncryptedAssertion") != 1)
            throw new IllegalArgumentException("Invalid Response envelope");

        BasicX509Credential signing = new BasicX509Credential(certificate(signingKey));
        boolean responseSigned = response.isSigned();
        if (responseSigned) verify(response, signing);
        Assertion assertion;
        if (!response.getEncryptedAssertions().isEmpty()) {
            BasicX509Credential decryption = new BasicX509Credential(
                    certificate("sp-encryption-rsa-2048"), decryptionKey());
            Decrypter decrypter = new Decrypter(null,
                    new StaticKeyInfoCredentialResolver(decryption),
                    new InlineEncryptedKeyResolver());
            assertion = decrypter.decrypt(response.getEncryptedAssertions().get(0));
            response.getDOM().replaceChild(assertion.getDOM(),
                    response.getEncryptedAssertions().get(0).getDOM());
            assertion.getDOM().setIdAttribute("ID", true);
        } else {
            assertion = response.getAssertions().get(0);
        }
        if (assertion.getVersion() != SAMLVersion.VERSION_20
                || !IDP.equals(assertion.getIssuer().getValue())
                || assertion.getIssueInstant() == null
                || assertion.getIssueInstant().isAfter(NOW.plusSeconds(180)))
            throw new IllegalArgumentException("Invalid Assertion envelope");
        if (assertion.isSigned()) verify(assertion, signing);
        if (!responseSigned && !assertion.isSigned())
            throw new IllegalArgumentException("Unsigned identity");
        var trustEngine = new ExplicitKeySignatureTrustEngine(
                new StaticCredentialResolver(signing),
                new StaticKeyInfoCredentialResolver(signing));
        var validator = new SAML20AssertionValidator(
                List.of(new AudienceRestrictionConditionValidator()),
                List.of(new BearerSubjectConfirmationValidator()),
                List.of(new AuthnStatementValidator()), null, trustEngine,
                new SAMLSignatureProfileValidator());
        var context = new ValidationContext(Map.of(
                SAML2AssertionValidationParameters.CLOCK_SKEW,
                Duration.between(NOW, Instant.now()).abs().plus(Duration.ofDays(1)),
                SAML2AssertionValidationParameters.VALID_ISSUERS, Set.of(IDP),
                SAML2AssertionValidationParameters.COND_VALID_AUDIENCES, Set.of(SP),
                SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, Set.of(ACS),
                SAML2AssertionValidationParameters.SIGNATURE_REQUIRED, false));
        if (validator.validate(assertion, context) != ValidationResult.VALID)
            throw new IllegalArgumentException("OpenSAML assertion validation failed: "
                    + context.getValidationFailureMessages());
        Conditions conditions = assertion.getConditions();
        if (conditions == null || conditions.getNotBefore() == null
                || conditions.getNotBefore().isAfter(NOW)
                || conditions.getNotOnOrAfter() == null
                || !conditions.getNotOnOrAfter().isAfter(NOW)
                || conditions.getAudienceRestrictions().isEmpty()
                || conditions.getAudienceRestrictions().stream().anyMatch(restriction ->
                        restriction.getAudiences().stream().noneMatch(audience ->
                                SP.equals(audience.getURI()))))
            throw new IllegalArgumentException("Invalid assertion conditions");
        Subject subject = assertion.getSubject();
        if (subject == null || subject.getSubjectConfirmations().size() != 1)
            throw new IllegalArgumentException("Invalid subject confirmation");
        SubjectConfirmation confirmation = subject.getSubjectConfirmations().get(0);
        if (!SubjectConfirmation.METHOD_BEARER.equals(confirmation.getMethod())
                || confirmation.getSubjectConfirmationData() == null
                || !ACS.equals(confirmation.getSubjectConfirmationData().getRecipient())
                || confirmation.getSubjectConfirmationData().getNotOnOrAfter() == null
                || !confirmation.getSubjectConfirmationData().getNotOnOrAfter().isAfter(NOW)
                || confirmation.getSubjectConfirmationData().getInResponseTo() != null
                || assertion.getAuthnStatements().isEmpty())
            throw new IllegalArgumentException("Invalid bearer authentication");
        NameID nameId = subject.getNameID();
        if (nameId == null && subject.getEncryptedID() != null) {
            BasicX509Credential decryption = new BasicX509Credential(
                    certificate("sp-encryption-rsa-2048"), decryptionKey());
            Decrypter decrypter = new Decrypter(null,
                    new StaticKeyInfoCredentialResolver(decryption),
                    new InlineEncryptedKeyResolver());
            nameId = (NameID) decrypter.decrypt(subject.getEncryptedID());
        }
        if (nameId == null || nameId.getValue() == null || nameId.getValue().isBlank())
            throw new IllegalArgumentException("Missing NameID");
        return nameId.getValue();
    }

    private static void verify(@NonNull SignableXMLObject signed,
            @NonNull BasicX509Credential credential) throws Exception {
        new SAMLSignatureProfileValidator().validate(signed.getSignature());
        SignatureValidator.validate(signed.getSignature(), credential);
    }

    private static int countChildren(@NonNull Element parent, @NonNull String namespace,
            @NonNull String localName) {
        int count = 0;
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) count++;
        return count;
    }

    private static @NonNull List<String> modernFixtures() {
        List<String> fixtures = new ArrayList<>(List.of("assertion-signxml", "assertion-ec384"));
        for (String placement : List.of("response", "assertion", "both"))
            for (String algorithm : List.of("rsa-sha256", "rsa-sha384", "rsa-sha512",
                    "ecdsa-sha256", "ecdsa-sha384", "ecdsa-sha512"))
                for (String digest : List.of("sha256", "sha384", "sha512"))
                    fixtures.add("matrix-" + placement + "-" + algorithm + "-" + digest);
        return List.copyOf(fixtures);
    }

    private static @NonNull String fixture(@NonNull String name) throws Exception {
        return Files.readString(FIXTURES.resolve("scripted-idp/" + name + ".xml"));
    }

    private static @NonNull String signingCredential(@NonNull String fixture) {
        if (fixture.contains("ecdsa-sha256")) return "idp-signing-ec-p256";
        if (fixture.contains("ecdsa-sha384") || fixture.equals("assertion-ec384"))
            return "idp-signing-ec-p384";
        if (fixture.contains("ecdsa-sha512")) return "idp-signing-ec-p521";
        if (fixture.contains("rsa-sha384") || fixture.contains("rsa-sha512"))
            return "idp-signing-rsa-3072";
        return "idp-signing-rsa-2048";
    }

    private static @NonNull String section(@NonNull String xml, @NonNull String opening,
            @NonNull String closing) {
        int start = xml.indexOf(opening);
        int end = xml.indexOf(closing, start);
        assertTrue(start >= 0 && end > start, "fixture shape changed");
        return xml.substring(start, end + closing.length());
    }

    private static @NonNull String id(@NonNull String xml, @NonNull String element) {
        Matcher matcher = Pattern.compile("<" + element + "\\b[^>]*\\bID=\"([^\"]+)\"")
                .matcher(xml);
        assertTrue(matcher.find(), "fixture ID missing: " + element);
        return matcher.group(1);
    }

    private static @NonNull X509Certificate certificate(@NonNull String name) throws Exception {
        try (var input = Files.newInputStream(FIXTURES.resolve("keys/" + name + "-cert.pem"))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
    }

    private static @NonNull PrivateKey decryptionKey() throws Exception {
        String pem = Files.readString(FIXTURES.resolve("keys/sp-encryption-rsa-2048-key.pem"));
        String body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(body)));
    }
}
