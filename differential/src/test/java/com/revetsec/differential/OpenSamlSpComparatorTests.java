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
import com.revetsec.saml.SamlAuthentication;
import com.revetsec.saml.SamlAuthenticationResult;
import com.revetsec.saml.SamlCompatibilityMode;
import com.revetsec.saml.SamlCredential;
import com.revetsec.saml.SamlIdentityProvider;
import com.revetsec.saml.SamlNameId;
import com.revetsec.saml.SamlPostBindingMessage;
import com.revetsec.saml.SamlPostBindingParseResult;
import com.revetsec.saml.SamlServiceProvider;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
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

    @Test void forgedKeyInfoCannotMakeAnAttackerSignatureTrusted() throws Exception {
        for (ForgedKeyInfoCorpus.Placement placement : ForgedKeyInfoCorpus.Placement.values()) {
            String label = placement.name();
            String original = fixture("matrix-" + label.toLowerCase(java.util.Locale.ROOT)
                    + "-rsa-sha256-sha256");
            assertEquals("minted-user", authenticate(original, ForgedKeyInfoCorpus.TRUSTED), label);

            String attackerAdvertised = ForgedKeyInfoCorpus.attackerSigned(placement, false);
            assertEquals("attacker-user", authenticate(attackerAdvertised,
                    ForgedKeyInfoCorpus.ATTACKER), label + " OpenSAML attacker control");
            assertEquals("attacker-user", SpringSamlComparatorTests.spring(attackerAdvertised,
                    ForgedKeyInfoCorpus.ATTACKER).getName(), label + " Spring attacker control");
            assertEquals("attacker-user", assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    revetsec(attackerAdvertised, ForgedKeyInfoCorpus.ATTACKER, false, false),
                    label + " Revetsec attacker control").getAuthentication()
                    .getNameId().orElseThrow().getValue());
            assertThrows(Exception.class, () -> authenticate(attackerAdvertised,
                    ForgedKeyInfoCorpus.TRUSTED), label + " OpenSAML untrusted certificate");
            assertThrows(Exception.class, () -> SpringSamlComparatorTests.spring(attackerAdvertised,
                    ForgedKeyInfoCorpus.TRUSTED), label + " Spring untrusted certificate");
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    revetsec(attackerAdvertised, ForgedKeyInfoCorpus.TRUSTED, false, false),
                    label + " Revetsec untrusted certificate");

            String trustedAdvertised = ForgedKeyInfoCorpus.attackerSigned(placement, true);
            assertNotEquals(attackerAdvertised, trustedAdvertised,
                    label + " KeyInfo certificate must change");
            assertEquals("attacker-user", authenticate(trustedAdvertised,
                    ForgedKeyInfoCorpus.ATTACKER), label + " OpenSAML misleading KeyInfo control");
            assertEquals("attacker-user", SpringSamlComparatorTests.spring(trustedAdvertised,
                    ForgedKeyInfoCorpus.ATTACKER).getName(),
                    label + " Spring misleading KeyInfo control");
            assertEquals("attacker-user", assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    revetsec(trustedAdvertised, ForgedKeyInfoCorpus.ATTACKER, false, false),
                    label + " Revetsec misleading KeyInfo control").getAuthentication()
                    .getNameId().orElseThrow().getValue());
            assertThrows(Exception.class, () -> authenticate(trustedAdvertised,
                    ForgedKeyInfoCorpus.TRUSTED), label + " OpenSAML misleading KeyInfo");
            assertThrows(Exception.class, () -> SpringSamlComparatorTests.spring(trustedAdvertised,
                    ForgedKeyInfoCorpus.TRUSTED), label + " Spring misleading KeyInfo");
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    revetsec(trustedAdvertised, ForgedKeyInfoCorpus.TRUSTED, false, false),
                    label + " Revetsec misleading KeyInfo");
        }
    }

    @Test void legacySha1NeedsExplicitRevetsecCompatibility() throws Exception {
        String xml = fixture("assertion-rsa-sha1");
        assertEquals("minted-user", authenticate(xml, "idp-signing-rsa-2048"));
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                revetsec(xml, "idp-signing-rsa-2048", false, false));
        assertRevetsecIdentity(xml, "idp-signing-rsa-2048", true, false, "legacy SHA1");
    }

    @Test void fullSignedXswAndFragileLockMatrixPinsIndependentSpVerdicts() throws Exception {
        List<String> fixtures = new ArrayList<>(modernFixtures());
        fixtures.addAll(List.of("assertion-rsa-sha1", "assertion-ec521",
                "both-rsa384", "response-rsa256", "digest-rsa256-sha1"));
        assertEquals(61, fixtures.size(), "signed fixture matrix changed");
        Set<String> openSamlUnsignedEnvelopeAcceptances = Set.of(
                "attacker-extension", "copied-signature-extension");
        Set<String> springUnsignedEnvelopeAcceptances = Set.of(
                "attacker-extension", "copied-signature-extension", "duplicate-status");
        for (String name : fixtures) {
            String original = fixture(name);
            String credential = signingCredential(name);
            boolean legacySha1 = name.equals("assertion-rsa-sha1")
                    || name.equals("digest-rsa256-sha1");
            boolean assertionOnly = name.startsWith("matrix-assertion-")
                    || name.equals("assertion-signxml") || name.equals("assertion-ec384")
                    || name.equals("assertion-ec521") || name.equals("assertion-rsa-sha1");
            List<SignedSamlMutationMatrix.Mutation> mutations = SignedSamlMutationMatrix.from(original);
            assertEquals(19, mutations.size(), name + " mutation matrix changed");
            assertEquals("minted-user", authenticate(original, credential), name + " OpenSAML baseline");
            assertEquals("minted-user", SpringSamlComparatorTests.spring(original, credential)
                    .getName(), name + " Spring baseline");
            assertRevetsecIdentity(original, credential, legacySha1, false, name + " Revetsec baseline");
            for (SignedSamlMutationMatrix.Mutation mutation : mutations) {
                String label = name + ":" + mutation.name();
                assertNotEquals(original, mutation.xml(), label + " is inert");
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        revetsec(mutation.xml(), credential, legacySha1, false),
                        label + " Revetsec");
                String openSamlIdentity = null;
                try { openSamlIdentity = authenticate(mutation.xml(), credential); }
                catch (Exception ignored) { }
                assertEquals(assertionOnly && openSamlUnsignedEnvelopeAcceptances.contains(mutation.name())
                                ? "minted-user" : null,
                        openSamlIdentity, label + " OpenSAML");
                String springIdentity = null;
                try { springIdentity = SpringSamlComparatorTests.spring(mutation.xml(), credential).getName(); }
                catch (Exception ignored) { }
                assertEquals(assertionOnly && springUnsignedEnvelopeAcceptances.contains(mutation.name())
                                ? "minted-user" : null,
                        springIdentity, label + " Spring");
            }
        }
    }

    @Test void signedSemanticCorpusControlsRetainOnlyTheirOriginalIdentityUnderEnvelopeMutations()
            throws Exception {
        Map<String, Integer> familySizes = Map.of(
                "signed-structure", 15,
                "signed-assertion-structure", 29,
                "signed-attribute-values", 12,
                "signed-boundary-shape", 19,
                "signed-identity-shape", 20);
        int acceptedControls = 0;
        int applicableMutations = 0;
        int revetsecAcceptances = 0;
        int openSamlAcceptances = 0;
        int springAcceptances = 0;
        Map<String, Integer> openSamlAcceptedByMutation = new LinkedHashMap<>();
        Map<String, Integer> springAcceptedByMutation = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> family : familySizes.entrySet()) {
            Path directory = FIXTURES.resolve("scripted-idp").resolve(family.getKey());
            List<Path> files;
            try (var paths = Files.list(directory)) {
                files = paths.filter(path -> path.getFileName().toString().endsWith(".xml"))
                        .sorted().toList();
            }
            assertEquals(family.getValue().intValue(), files.size(), family.getKey() + " fixture inventory");
            for (Path file : files) {
                String original = Files.readString(file);
                SamlAuthenticationResult baseline = revetsec(original, "idp-signing-rsa-2048", false, false);
                if (!(baseline instanceof SamlAuthenticationResult.Succeeded accepted)) continue;
                acceptedControls++;
                String originalName = accepted.getAuthentication().getNameId().orElseThrow().getValue();
                int perControlMutations = 0;
                for (SignedSamlMutationMatrix.Mutation mutation : SignedSamlMutationMatrix.from(original)) {
                    if (mutation.xml().equals(original)) continue;
                    applicableMutations++;
                    perControlMutations++;
                    String label = family.getKey() + "/" + file.getFileName() + ":" + mutation.name();
                    SamlAuthenticationResult changed = revetsec(mutation.xml(),
                            "idp-signing-rsa-2048", false, false);
                    if (changed instanceof SamlAuthenticationResult.Succeeded success) {
                        revetsecAcceptances++;
                        assertEquals(originalName, success.getAuthentication().getNameId()
                                .orElseThrow().getValue(), label + " Revetsec identity");
                    }
                    try {
                        String name = authenticate(mutation.xml(), "idp-signing-rsa-2048");
                        openSamlAcceptances++;
                        openSamlAcceptedByMutation.merge(mutation.name(), 1, Integer::sum);
                        assertEquals(originalName, name, label + " OpenSAML identity");
                    }
                    catch (Exception ignored) { }
                    try {
                        String name = SpringSamlComparatorTests.spring(
                                mutation.xml(), "idp-signing-rsa-2048").getName();
                        springAcceptances++;
                        springAcceptedByMutation.merge(mutation.name(), 1, Integer::sum);
                        assertEquals(originalName, name, label + " Spring identity");
                    }
                    catch (Exception ignored) { }
                }
                assertTrue(perControlMutations >= 15, family.getKey() + "/" + file.getFileName());
            }
        }
        assertEquals(30, acceptedControls, "signed semantic corpus control count");
        assertEquals(568, applicableMutations, "signed semantic corpus mutation coverage");
        assertEquals(0, revetsecAcceptances, "Revetsec changed-envelope acceptances");
        assertEquals(48, openSamlAcceptances, "OpenSAML changed-envelope acceptances");
        assertEquals(Map.of("attacker-extension", 24, "copied-signature-extension", 24),
                openSamlAcceptedByMutation);
        assertEquals(78, springAcceptances, "Spring changed-envelope acceptances");
        assertEquals(Map.of("attacker-extension", 26, "duplicate-status", 26,
                "copied-signature-extension", 26), springAcceptedByMutation);
    }

    @Test void signedSemanticCorpusRejectedFixturesRemainRejectedUnderEnvelopeMutations()
            throws Exception {
        Map<String, Integer> familySizes = Map.of(
                "signed-structure", 15,
                "signed-assertion-structure", 29,
                "signed-attribute-values", 12,
                "signed-boundary-shape", 19,
                "signed-identity-shape", 20);
        int rejectedFixtures = 0;
        int applicableMutations = 0;
        int openSamlAcceptances = 0;
        int springAcceptances = 0;
        for (Map.Entry<String, Integer> family : familySizes.entrySet()) {
            Path directory = FIXTURES.resolve("scripted-idp").resolve(family.getKey());
            List<Path> files;
            try (var paths = Files.list(directory)) {
                files = paths.filter(path -> path.getFileName().toString().endsWith(".xml"))
                        .sorted().toList();
            }
            assertEquals(family.getValue().intValue(), files.size(), family.getKey() + " fixture inventory");
            for (Path file : files) {
                String original = Files.readString(file);
                if (revetsec(original, "idp-signing-rsa-2048", false, false)
                        instanceof SamlAuthenticationResult.Succeeded) continue;
                rejectedFixtures++;
                String originalOpenSaml = null;
                try { originalOpenSaml = authenticate(original, "idp-signing-rsa-2048"); }
                catch (Exception ignored) { }
                String originalSpring = null;
                try { originalSpring = SpringSamlComparatorTests.spring(
                        original, "idp-signing-rsa-2048").getName(); }
                catch (Exception ignored) { }
                for (SignedSamlMutationMatrix.Mutation mutation : SignedSamlMutationMatrix.from(original)) {
                    if (mutation.xml().equals(original)) continue;
                    applicableMutations++;
                    String label = family.getKey() + "/" + file.getFileName() + ":" + mutation.name();
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                            revetsec(mutation.xml(), "idp-signing-rsa-2048", false, false),
                            label + " Revetsec");
                    String changedOpenSaml = null;
                    try { changedOpenSaml = authenticate(mutation.xml(), "idp-signing-rsa-2048"); }
                    catch (Exception ignored) { }
                    if (changedOpenSaml != null) {
                        openSamlAcceptances++;
                        assertEquals(originalOpenSaml, changedOpenSaml, label + " OpenSAML identity");
                    }
                    String changedSpring = null;
                    try { changedSpring = SpringSamlComparatorTests.spring(
                            mutation.xml(), "idp-signing-rsa-2048").getName(); }
                    catch (Exception ignored) { }
                    if (changedSpring != null) {
                        springAcceptances++;
                        assertEquals(originalSpring, changedSpring, label + " Spring identity");
                    }
                }
            }
        }
        assertEquals(65, rejectedFixtures, "rejected signed semantic corpus fixture count");
        assertEquals(1232, applicableMutations, "rejected fixture mutation coverage");
        assertEquals(60, openSamlAcceptances, "OpenSAML changed-envelope acceptances");
        assertEquals(96, springAcceptances, "Spring changed-envelope acceptances");
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
        List<String> fixtures = encryptedFixtures();
        assertEquals(47, fixtures.size(), "encrypted fixture matrix changed");
        for (String name : fixtures) {
            String xml = fixture(name);
            String signingKey = encryptedSigningCredential(name);
            boolean cbc = name.contains("-cbc-");
            boolean assertionOnly = name.endsWith("-assertion")
                    || name.equals("assertion-rsa512-encrypted")
                    || name.equals("assertion-ec256-encrypted-id");
            assertEquals("minted-user", authenticate(xml, signingKey), name + " baseline OpenSAML");
            SamlAuthentication baseline = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    revetsec(xml, signingKey, false, cbc), name + " baseline Revetsec")
                    .getAuthentication();
            assertEquals("minted-user", baseline.getNameId().orElseThrow().getValue(), name);
            if (assertionOnly && !name.equals("assertion-ec256-encrypted-id"))
                assertThrows(Exception.class,
                        () -> SpringSamlComparatorTests.spring(xml, signingKey),
                        name + " Spring baseline");
            else
                assertEquals("minted-user", SpringSamlComparatorTests.spring(xml, signingKey)
                        .getName(), name + " Spring baseline");
            for (Mutation mutation : encryptedMutations(xml, name)) {
                String label = name + ":" + mutation.name();
                assertNotEquals(xml, mutation.xml(), label + " is inert");
                if (assertionOnly && mutation.name().equals("missing-destination"))
                    assertSameAuthentication(baseline,
                            assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                                    revetsec(mutation.xml(), signingKey, false, cbc),
                                    label + " Revetsec acceptance").getAuthentication(), label);
                else
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                            revetsec(mutation.xml(), signingKey, false, cbc),
                            label + " Revetsec");
                boolean extension = mutation.name().equals("attacker-extension")
                        || mutation.name().equals("copied-signature-extension");
                if (assertionOnly && (extension || mutation.name().equals("duplicate-status-code")))
                    assertEquals("minted-user", authenticate(mutation.xml(), signingKey),
                            label + " OpenSAML identity");
                else
                    assertThrows(Exception.class, () -> authenticate(mutation.xml(), signingKey),
                            label + " OpenSAML");
                boolean springAccepts = name.equals("assertion-ec256-encrypted-id")
                        && (extension || mutation.name().equals("duplicate-status")
                                || mutation.name().equals("missing-status")
                                || mutation.name().equals("missing-destination")
                                || mutation.name().equals("duplicate-status-code"));
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

    @Test void rejectedEncryptedFixturesCannotGainIdentityUnderWrapperMutations() throws Exception {
        List<String> fixtures = List.of("negative-mgf-under-mgf1p",
                "encrypted-aes128-cbc-assertion", "negative-rsa-1_5",
                "negative-nonempty-oaep-params", "negative-cipher-bit-flip",
                "unsigned-encrypted");
        int applicableMutations = 0;
        int openSamlAcceptances = 0;
        int springAcceptances = 0;
        for (String name : fixtures) {
            String original = fixture(name);
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    revetsec(original, "idp-signing-rsa-2048", false, false), name + " baseline");
            String originalOpenSaml = null;
            try { originalOpenSaml = authenticate(original, "idp-signing-rsa-2048"); }
            catch (Exception ignored) { }
            String originalSpring = null;
            try { originalSpring = SpringSamlComparatorTests.spring(
                    original, "idp-signing-rsa-2048").getName(); }
            catch (Exception ignored) { }
            for (Mutation mutation : encryptedMutations(original, name)) {
                if (mutation.xml().equals(original)) continue;
                applicableMutations++;
                String label = name + ":" + mutation.name();
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        revetsec(mutation.xml(), "idp-signing-rsa-2048", false, false),
                        label + " Revetsec");
                String changedOpenSaml = null;
                try { changedOpenSaml = authenticate(mutation.xml(), "idp-signing-rsa-2048"); }
                catch (Exception ignored) { }
                if (changedOpenSaml != null) {
                    openSamlAcceptances++;
                    assertEquals(originalOpenSaml, changedOpenSaml, label + " OpenSAML identity");
                }
                String changedSpring = null;
                try { changedSpring = SpringSamlComparatorTests.spring(
                        mutation.xml(), "idp-signing-rsa-2048").getName(); }
                catch (Exception ignored) { }
                if (changedSpring != null) {
                    springAcceptances++;
                    assertEquals(originalSpring, changedSpring, label + " Spring identity");
                }
            }
        }
        assertEquals(114, applicableMutations, "rejected encrypted fixture mutation coverage");
        assertEquals(3, openSamlAcceptances, "OpenSAML changed-envelope acceptances");
        assertEquals(0, springAcceptances, "Spring changed-envelope acceptances");
    }

    @Test void siblingWrappedKeyFixturesCannotPromoteEnvelopeIdentity() throws Exception {
        List<String> fixtures = List.of("key-sibling-implicit",
                "key-sibling-implicit-multi", "key-sibling-retrieval",
                "encrypted-id-sibling-implicit", "encrypted-id-sibling-retrieval");
        int applicableMutations = 0;
        int revetsecAcceptances = 0;
        int openSamlAcceptances = 0;
        int springAcceptances = 0;
        Map<String, Integer> revetsecAcceptedByMutation = new LinkedHashMap<>();
        Map<String, Integer> springAcceptedByMutation = new LinkedHashMap<>();
        for (String name : fixtures) {
            String original = fixture(name);
            SamlAuthenticationResult.Succeeded baseline = assertInstanceOf(
                    SamlAuthenticationResult.Succeeded.class,
                    revetsec(original, "idp-signing-rsa-2048", false, false),
                    name + " Revetsec baseline");
            assertEquals("minted-user", baseline.getAuthentication().getNameId()
                    .orElseThrow().getValue(), name + " Revetsec baseline identity");
            String originalOpenSaml = null;
            try { originalOpenSaml = authenticate(original, "idp-signing-rsa-2048"); }
            catch (Exception ignored) { }
            String originalSpring = null;
            try { originalSpring = SpringSamlComparatorTests.spring(
                    original, "idp-signing-rsa-2048").getName(); }
            catch (Exception ignored) { }
            for (Mutation mutation : encryptedMutations(original, name)) {
                if (mutation.xml().equals(original)) continue;
                applicableMutations++;
                String label = name + ":" + mutation.name();
                SamlAuthenticationResult changed = revetsec(
                        mutation.xml(), "idp-signing-rsa-2048", false, false);
                if (changed instanceof SamlAuthenticationResult.Succeeded success) {
                    revetsecAcceptances++;
                    revetsecAcceptedByMutation.merge(mutation.name(), 1, Integer::sum);
                    assertSameAuthentication(baseline.getAuthentication(),
                            success.getAuthentication(), label + " Revetsec identity");
                }
                String changedOpenSaml = null;
                try { changedOpenSaml = authenticate(mutation.xml(), "idp-signing-rsa-2048"); }
                catch (Exception ignored) { }
                if (changedOpenSaml != null) {
                    openSamlAcceptances++;
                    assertEquals(originalOpenSaml, changedOpenSaml, label + " OpenSAML identity");
                }
                String changedSpring = null;
                try { changedSpring = SpringSamlComparatorTests.spring(
                        mutation.xml(), "idp-signing-rsa-2048").getName(); }
                catch (Exception ignored) { }
                if (changedSpring != null) {
                    springAcceptances++;
                    springAcceptedByMutation.merge(mutation.name(), 1, Integer::sum);
                    assertEquals(originalSpring, changedSpring, label + " Spring identity");
                }
            }
        }
        assertEquals(95, applicableMutations, "sibling wrapped-key mutation coverage");
        assertEquals(2, revetsecAcceptances, "Revetsec changed-envelope acceptances");
        assertEquals(Map.of("missing-destination", 2), revetsecAcceptedByMutation);
        assertEquals(0, openSamlAcceptances, "OpenSAML changed-envelope acceptances");
        assertEquals(12, springAcceptances, "Spring changed-envelope acceptances");
        assertEquals(Map.of("attacker-extension", 2, "copied-signature-extension", 2,
                "duplicate-status", 2, "missing-status", 2,
                "missing-destination", 2, "duplicate-status-code", 2),
                springAcceptedByMutation);
    }

    @Test void independentlyMintedFixturesKeepTheirSignedIdentityUnderApplicableMutations()
            throws Exception {
        List<String> fixtures = List.of("case1-response-assertion-rsa-sha256",
                "case2-assertion-rsa-sha1", "case3-assertion-ecdsa-p256",
                "case3-assertion-ecdsa-p384", "case3-assertion-ecdsa-p521",
                "case4-encrypted-assertion-gcm-rsa-oaep-sha256-mgf1sha256",
                "case5-encrypted-assertion-gcm-rsa-1_5",
                "case6-encrypted-id-gcm-rsa-oaep-sha256-mgf1sha256",
                "extra-signxml-assertion-rsa-sha256");
        X509Certificate decryptionCertificate = independentCertificate("sp-rsa-2048.crt");
        PrivateKey decryptionPrivateKey = independentDecryptionKey();
        int applicableMutations = 0;
        int revetsecAcceptances = 0;
        int openSamlAcceptances = 0;
        int springAcceptances = 0;
        Map<String, Integer> revetsecAcceptedByMutation = new LinkedHashMap<>();
        Map<String, Integer> openSamlAcceptedByMutation = new LinkedHashMap<>();
        Map<String, Integer> springAcceptedByMutation = new LinkedHashMap<>();
        for (String name : fixtures) {
            String xml = Files.readString(FIXTURES.resolve("saml-independent/" + name + ".xml"));
            String certificateName = name.contains("p256") ? "idp-ec-p256.crt"
                    : name.contains("p384") ? "idp-ec-p384.crt"
                    : name.contains("p521") ? "idp-ec-p521.crt" : "idp-rsa-2048.crt";
            X509Certificate signer = independentCertificate(certificateName);
            boolean sha1 = name.equals("case2-assertion-rsa-sha1");
            SamlAuthenticationResult baseline = revetsecIndependent(xml, signer, sha1);
            if (name.equals("case5-encrypted-assertion-gcm-rsa-1_5"))
                assertInstanceOf(SamlAuthenticationResult.Rejected.class, baseline, name);
            else assertInstanceOf(SamlAuthenticationResult.Succeeded.class, baseline, name);
            String originalOpenSaml = null;
            try { originalOpenSaml = authenticateCaptured(xml, signer, IDP, SP, ACS,
                    null, NOW, decryptionCertificate, decryptionPrivateKey); }
            catch (Exception ignored) { }
            String originalSpring = null;
            try { originalSpring = SpringSamlComparatorTests.springWithKeys(
                    xml, signer, decryptionCertificate, decryptionPrivateKey).getName(); }
            catch (Exception ignored) { }
            boolean encrypted = name.startsWith("case4-") || name.startsWith("case5-")
                    || name.startsWith("case6-");
            String originalName = baseline instanceof SamlAuthenticationResult.Succeeded success
                    ? success.getAuthentication().getNameId().orElseThrow().getValue() : "";
            List<Mutation> mutations = encrypted ? encryptedMutations(xml, name)
                    : SignedSamlMutationMatrix.from(xml, originalName).stream()
                            .map(value -> new Mutation(value.name(), value.xml())).toList();
            for (Mutation mutation : mutations) {
                String mutationName = mutation.name();
                String changedXml = mutation.xml();
                if (changedXml.equals(xml)) continue;
                applicableMutations++;
                String label = name + ":" + mutationName;
                SamlAuthenticationResult changed = revetsecIndependent(changedXml, signer, sha1);
                if (changed instanceof SamlAuthenticationResult.Succeeded success) {
                    revetsecAcceptances++;
                    revetsecAcceptedByMutation.merge(mutationName, 1, Integer::sum);
                    assertSameAuthentication(assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                            baseline, label + " baseline").getAuthentication(),
                            success.getAuthentication(), label + " Revetsec identity");
                }
                String changedOpenSaml = null;
                try { changedOpenSaml = authenticateCaptured(changedXml, signer, IDP, SP, ACS,
                        null, NOW, decryptionCertificate, decryptionPrivateKey); }
                catch (Exception ignored) { }
                if (changedOpenSaml != null) {
                    openSamlAcceptances++;
                    openSamlAcceptedByMutation.merge(mutationName, 1, Integer::sum);
                    assertEquals(originalOpenSaml, changedOpenSaml, label + " OpenSAML identity");
                }
                String changedSpring = null;
                try { changedSpring = SpringSamlComparatorTests.springWithKeys(
                        changedXml, signer, decryptionCertificate, decryptionPrivateKey).getName(); }
                catch (Exception ignored) { }
                if (changedSpring != null) {
                    springAcceptances++;
                    springAcceptedByMutation.merge(mutationName, 1, Integer::sum);
                    assertEquals(originalSpring, changedSpring, label + " Spring identity");
                }
            }
        }
        assertEquals(171, applicableMutations, "independent fixture mutation coverage");
        assertEquals(2, revetsecAcceptances, "Revetsec changed-envelope acceptances");
        assertEquals(19, openSamlAcceptances, "OpenSAML changed-envelope acceptances");
        assertEquals(21, springAcceptances, "Spring changed-envelope acceptances");
        assertEquals(Map.of("missing-destination", 2), revetsecAcceptedByMutation);
        assertEquals(Map.of("attacker-extension", 8, "copied-signature-extension", 8,
                "duplicate-status-code", 3), openSamlAcceptedByMutation);
        assertEquals(Map.of("attacker-extension", 6, "duplicate-status", 6,
                "copied-signature-extension", 6, "missing-status", 1,
                "missing-destination", 1, "duplicate-status-code", 1),
                springAcceptedByMutation);
    }

    static @NonNull List<String> encryptedFixtures() {
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

    static @NonNull String encryptedSigningCredential(@NonNull String name) {
        if (name.equals("assertion-rsa512-encrypted")) return "idp-signing-rsa-3072";
        if (name.equals("assertion-ec256-encrypted-id")) return "idp-signing-ec-p256";
        return "idp-signing-rsa-2048";
    }

    static @NonNull List<Mutation> encryptedMutations(@NonNull String xml,
            @NonNull String name) throws Exception {
        String signedTemplate = fixture("assertion-signxml");
        String templateAssertion = section(signedTemplate, "<saml:Assertion ", "</saml:Assertion>");
        String attacker = Pattern.compile("<ds:Signature\\b[^>]*>.*?</ds:Signature>", Pattern.DOTALL)
                .matcher(templateAssertion).replaceFirst("")
                .replace("minted-user", "attacker-user")
                .replace(id(signedTemplate, "saml:Assertion"), "_attacker_assertion");
        String copiedSignature = section(signedTemplate, "<ds:Signature ", "</ds:Signature>");
        String carrier = (name.equals("assertion-ec256-encrypted-id")
                || name.startsWith("encrypted-id-sibling-") || name.startsWith("case6-"))
                ? section(xml, "<saml:Assertion ", "</saml:Assertion>")
                : section(xml, "<saml:EncryptedAssertion>", "</saml:EncryptedAssertion>");
        String extension = "<samlp:Extensions>" + attacker + "</samlp:Extensions>";
        String copied = "<samlp:Extensions><Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>"
                + "<Child xml:xmlns='#other'>" + copiedSignature + "</Child></Parent></samlp:Extensions>";
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
                        "<saml:Issuer>https://attacker.example.test/</saml:Issuer><samlp:Status>")),
                new Mutation("attacker-sibling-end", xml.replace("</samlp:Response>",
                        attacker + "</samlp:Response>")),
                new Mutation("issuer-tamper", xml.replace(IDP, "https://attacker.example.test/")),
                new Mutation("failure-status", xml.replace(StatusCode.SUCCESS,
                        "urn:oasis:names:tc:SAML:2.0:status:Responder")),
                new Mutation("missing-status", xml.replaceFirst(
                        "(?s)<samlp:Status>.*?</samlp:Status>", "")),
                new Mutation("missing-destination", xml.replace("Destination=\"" + ACS + "\"", "")),
                new Mutation("unexpected-in-response-to", xml.replace("<samlp:Response ",
                        "<samlp:Response InResponseTo='_attacker_request' ")),
                new Mutation("duplicate-status-code", xml.replace("</samlp:Status>",
                        "<samlp:StatusCode Value='" + StatusCode.SUCCESS
                                + "'/></samlp:Status>")),
                new Mutation("copied-signature-direct", xml.replace("<samlp:Status>",
                        copiedSignature + "<samlp:Status>")),
                new Mutation("wrong-namespace-status", xml.replace("<samlp:Status>",
                        "<Status xmlns='https://attacker.example.test/ns'>")
                        .replace("</samlp:Status>", "</Status>")));
    }

    record Mutation(@NonNull String name, @NonNull String xml) { }

    private static void assertSameAuthentication(@NonNull SamlAuthentication expected,
            @NonNull SamlAuthentication actual, @NonNull String label) {
        assertEquals(expected.getIdentityProviderConnectionId(), actual.getIdentityProviderConnectionId(), label);
        assertEquals(expected.getIdentityProviderEntityId(), actual.getIdentityProviderEntityId(), label);
        assertEquals(expected.getAssertionId(), actual.getAssertionId(), label);
        assertSameNameId(expected.getNameId().orElseThrow(), actual.getNameId().orElseThrow(), label);
        assertEquals(expected.getSubjectKey().map(key -> key.toStableString()),
                actual.getSubjectKey().map(key -> key.toStableString()), label);
        assertEquals(expected.getSubjectId(), actual.getSubjectId(), label);
        assertEquals(expected.getPairwiseId(), actual.getPairwiseId(), label);
        assertEquals(expected.getAuthnInstant(), actual.getAuthnInstant(), label);
        assertEquals(expected.getSessionIndex(), actual.getSessionIndex(), label);
        assertEquals(expected.getSessionNotOnOrAfter(), actual.getSessionNotOnOrAfter(), label);
        assertEquals(expected.getAuthnContextClassRef(), actual.getAuthnContextClassRef(), label);
        assertEquals(expected.getAssertionExpiresAt(), actual.getAssertionExpiresAt(), label);
        assertEquals(expected.isResponseSigned(), actual.isResponseSigned(), label);
        assertEquals(expected.isAssertionSigned(), actual.isAssertionSigned(), label);
        assertEquals(expected.isAssertionEncrypted(), actual.isAssertionEncrypted(), label);
        assertEquals(expected.isUnsolicited(), actual.isUnsolicited(), label);
        assertEquals(expected.getAttributes().size(), actual.getAttributes().size(), label);
        for (int index = 0; index < expected.getAttributes().size(); index++) {
            var left = expected.getAttributes().get(index);
            var right = actual.getAttributes().get(index);
            assertEquals(left.getName(), right.getName(), label);
            assertEquals(left.getNameFormat(), right.getNameFormat(), label);
            assertEquals(left.getFriendlyName(), right.getFriendlyName(), label);
            assertEquals(left.getValues(), right.getValues(), label);
            assertEquals(left.getTypedValues().size(), right.getTypedValues().size(), label);
            for (int value = 0; value < left.getTypedValues().size(); value++) {
                var leftValue = left.getTypedValues().get(value);
                var rightValue = right.getTypedValues().get(value);
                assertEquals(leftValue.getKind(), rightValue.getKind(), label);
                assertEquals(leftValue.getText(), rightValue.getText(), label);
                if (leftValue.getNameId().isPresent())
                    assertSameNameId(leftValue.getNameId().orElseThrow(),
                            rightValue.getNameId().orElseThrow(), label);
                else assertTrue(rightValue.getNameId().isEmpty(), label);
            }
        }
    }

    private static void assertSameNameId(@NonNull SamlNameId expected, @NonNull SamlNameId actual,
            @NonNull String label) {
        assertEquals(expected.getValue(), actual.getValue(), label);
        assertEquals(expected.getFormat(), actual.getFormat(), label);
        assertEquals(expected.getNameQualifier(), actual.getNameQualifier(), label);
        assertEquals(expected.getSpNameQualifier(), actual.getSpNameQualifier(), label);
        assertEquals(expected.getSpProvidedId(), actual.getSpProvidedId(), label);
    }

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

    static @NonNull SamlAuthenticationResult revetsec(@NonNull String xml,
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

    private static @NonNull SamlAuthenticationResult revetsecIndependent(@NonNull String xml,
            @NonNull X509Certificate signingCertificate, boolean sha1) throws Exception {
        SamlCredential decryption = SamlCredential.fromPem(
                Files.readString(FIXTURES.resolve("saml-independent/keys/sp-rsa-2048.key")),
                Files.readString(FIXTURES.resolve("saml-independent/keys/sp-rsa-2048.crt")));
        SamlServiceProvider provider = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create(ACS))
                .replayCache(InMemorySamlReplayCache.withLimit(Clock.fixed(NOW, ZoneOffset.UTC), 16))
                .decryptionCredentials(List.of(decryption))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
        EnumSet<SamlCompatibilityMode> compatibility = EnumSet.of(
                SamlCompatibilityMode.UNSOLICITED_RESPONSES);
        if (sha1) compatibility.add(SamlCompatibilityMode.SHA1_SIGNATURES);
        SamlIdentityProvider identityProvider = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("independent-differential")
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .signingKeys(List.of(signingCertificate.getPublicKey()))
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
        return authenticateCaptured(xml, certificate(signingKey), IDP, SP, ACS, null, NOW);
    }

    static @NonNull String authenticateCaptured(@NonNull String xml,
            @NonNull X509Certificate signingCertificate, @NonNull String expectedIdp,
            @NonNull String expectedSp, @NonNull String expectedAcs,
            @Nullable String expectedRequestId, @NonNull Instant now) throws Exception {
        return authenticateCaptured(xml, signingCertificate, expectedIdp, expectedSp,
                expectedAcs, expectedRequestId, now,
                certificate("sp-encryption-rsa-2048"), decryptionKey());
    }

    static @NonNull String authenticateCaptured(@NonNull String xml,
            @NonNull X509Certificate signingCertificate, @NonNull String expectedIdp,
            @NonNull String expectedSp, @NonNull String expectedAcs,
            @Nullable String expectedRequestId, @NonNull Instant now,
            @NonNull X509Certificate decryptionCertificate,
            @NonNull PrivateKey decryptionPrivateKey) throws Exception {
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
                || !expectedAcs.equals(response.getDestination())
                || !expectedIdp.equals(response.getIssuer().getValue())
                || !java.util.Objects.equals(expectedRequestId, response.getInResponseTo())
                || response.getIssueInstant() == null
                || response.getIssueInstant().isAfter(now.plusSeconds(180))
                || !StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())
                || countChildren(root, PROTOCOL_NS, "Status") != 1
                || countChildren(root, ASSERTION_NS, "Assertion")
                        + countChildren(root, ASSERTION_NS, "EncryptedAssertion") != 1)
            throw new IllegalArgumentException("Invalid Response envelope");

        BasicX509Credential signing = new BasicX509Credential(signingCertificate);
        boolean responseSigned = response.isSigned();
        if (responseSigned) verify(response, signing);
        Assertion assertion;
        if (!response.getEncryptedAssertions().isEmpty()) {
            BasicX509Credential decryption = new BasicX509Credential(
                    decryptionCertificate, decryptionPrivateKey);
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
                || !expectedIdp.equals(assertion.getIssuer().getValue())
                || assertion.getIssueInstant() == null
                || assertion.getIssueInstant().isAfter(now.plusSeconds(180)))
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
        Map<String, Object> parameters = new java.util.HashMap<>(Map.of(
                SAML2AssertionValidationParameters.CLOCK_SKEW,
                Duration.between(now, Instant.now()).abs().plus(Duration.ofDays(1)),
                SAML2AssertionValidationParameters.VALID_ISSUERS, Set.of(expectedIdp),
                SAML2AssertionValidationParameters.COND_VALID_AUDIENCES, Set.of(expectedSp),
                SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, Set.of(expectedAcs),
                SAML2AssertionValidationParameters.SIGNATURE_REQUIRED, false));
        if (expectedRequestId != null) {
            parameters.put(SAML2AssertionValidationParameters.SC_VALID_IN_RESPONSE_TO,
                    expectedRequestId);
            // Offline captures do not retain an authenticated client-network address.
            // Keep issuer, audience, recipient, request ID, time and signature checks active.
            parameters.put(SAML2AssertionValidationParameters.SC_CHECK_ADDRESS, false);
            parameters.put(SAML2AssertionValidationParameters.STMT_AUTHN_CHECK_ADDRESS, false);
        }
        var context = new ValidationContext(parameters);
        if (validator.validate(assertion, context) != ValidationResult.VALID)
            throw new IllegalArgumentException("OpenSAML assertion validation failed: "
                    + context.getValidationFailureMessages());
        Conditions conditions = assertion.getConditions();
        if (conditions == null || conditions.getNotBefore() == null
                || conditions.getNotBefore().isAfter(now)
                || conditions.getNotOnOrAfter() == null
                || !conditions.getNotOnOrAfter().isAfter(now)
                || conditions.getAudienceRestrictions().isEmpty()
                || conditions.getAudienceRestrictions().stream().anyMatch(restriction ->
                        restriction.getAudiences().stream().noneMatch(audience ->
                                expectedSp.equals(audience.getURI()))))
            throw new IllegalArgumentException("Invalid assertion conditions");
        Subject subject = assertion.getSubject();
        if (subject == null || subject.getSubjectConfirmations().size() != 1)
            throw new IllegalArgumentException("Invalid subject confirmation");
        SubjectConfirmation confirmation = subject.getSubjectConfirmations().get(0);
        if (!SubjectConfirmation.METHOD_BEARER.equals(confirmation.getMethod())
                || confirmation.getSubjectConfirmationData() == null
                || !expectedAcs.equals(confirmation.getSubjectConfirmationData().getRecipient())
                || confirmation.getSubjectConfirmationData().getNotOnOrAfter() == null
                || !confirmation.getSubjectConfirmationData().getNotOnOrAfter().isAfter(now)
                || !java.util.Objects.equals(expectedRequestId,
                        confirmation.getSubjectConfirmationData().getInResponseTo())
                || assertion.getAuthnStatements().isEmpty())
            throw new IllegalArgumentException("Invalid bearer authentication");
        NameID nameId = subject.getNameID();
        if (nameId == null && subject.getEncryptedID() != null) {
            BasicX509Credential decryption = new BasicX509Credential(
                    decryptionCertificate, decryptionPrivateKey);
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

    static @NonNull List<String> modernFixtures() {
        List<String> fixtures = new ArrayList<>(List.of("assertion-signxml", "assertion-ec384"));
        for (String placement : List.of("response", "assertion", "both"))
            for (String algorithm : List.of("rsa-sha256", "rsa-sha384", "rsa-sha512",
                    "ecdsa-sha256", "ecdsa-sha384", "ecdsa-sha512"))
                for (String digest : List.of("sha256", "sha384", "sha512"))
                    fixtures.add("matrix-" + placement + "-" + algorithm + "-" + digest);
        return List.copyOf(fixtures);
    }

    static @NonNull String fixture(@NonNull String name) throws Exception {
        return Files.readString(FIXTURES.resolve("scripted-idp/" + name + ".xml"));
    }

    static @NonNull String signingCredential(@NonNull String fixture) {
        if (fixture.contains("ecdsa-sha256")) return "idp-signing-ec-p256";
        if (fixture.contains("ecdsa-sha384") || fixture.equals("assertion-ec384"))
            return "idp-signing-ec-p384";
        if (fixture.contains("ecdsa-sha512") || fixture.equals("assertion-ec521"))
            return "idp-signing-ec-p521";
        if (fixture.contains("rsa-sha384") || fixture.contains("rsa-sha512")
                || fixture.equals("both-rsa384"))
            return "idp-signing-rsa-3072";
        return "idp-signing-rsa-2048";
    }

    static @NonNull String section(@NonNull String xml, @NonNull String opening,
            @NonNull String closing) {
        int start = xml.indexOf(opening);
        int end = xml.indexOf(closing, start);
        assertTrue(start >= 0 && end > start, "fixture shape changed");
        return xml.substring(start, end + closing.length());
    }

    static @NonNull String id(@NonNull String xml, @NonNull String element) {
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

    private static @NonNull X509Certificate independentCertificate(@NonNull String name)
            throws Exception {
        try (var input = Files.newInputStream(FIXTURES.resolve("saml-independent/keys/" + name))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
    }

    private static @NonNull PrivateKey independentDecryptionKey() throws Exception {
        String pem = Files.readString(FIXTURES.resolve("saml-independent/keys/sp-rsa-2048.key"));
        String body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(body)));
    }

    private static @NonNull PrivateKey decryptionKey() throws Exception {
        String pem = Files.readString(FIXTURES.resolve("keys/sp-encryption-rsa-2048-key.pem"));
        String body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(body)));
    }
}
