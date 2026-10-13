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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.springframework.security.core.Authentication;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Whole-SP comparison for Shibboleth and SimpleSAMLphp encrypted captures. */
final class CapturedProviderSpComparatorTests {
    private static final @NonNull Path FIXTURES = Path.of("../src/test/resources/fixtures/shibboleth");
    private static final @NonNull Path SIMPLE_FIXTURES =
            Path.of("../src/test/resources/fixtures/simplesamlphp");
    private static final @NonNull String IDP = "https://idp.example.org/idp/shibboleth";
    private static final @NonNull String SP = "https://sp.test/ShibCapture";
    private static final @NonNull String ACS = "https://sp.example.test/acs";
    private static final @NonNull String SSO =
            "https://idp.example.org/idp/profile/SAML2/Redirect/SSO";

    @BeforeAll static void initializeOpenSaml() throws Exception {
        InitializationService.initialize();
    }

    @Test void hostedShibbolethCapturesAndEnvelopeMutationsPreserveSpIdentity() throws Exception {
        X509Certificate signing;
        try (var input = Files.newInputStream(FIXTURES.resolve("idp-signing.crt"))) {
            signing = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
        for (String mode : List.of("gcm", "cbc")) {
            String xml = Files.readString(FIXTURES.resolve(mode + "-response.xml"));
            List<String> pending = Files.readAllLines(FIXTURES.resolve(mode + "-pending.txt"));
            assertEquals(4, pending.size(), mode + " pending capture");
            Instant observed = Instant.parse(pending.get(2)).plusSeconds(60);
            String identity = OpenSamlSpComparatorTests.authenticateCaptured(
                    xml, signing, IDP, SP, ACS, pending.get(0), observed);
            assertFalse(identity.isBlank(), mode + " subject");
            assertNotEquals("attacker-user", identity, mode + " subject");
            String encodedRequest = encodedRequest(FIXTURES, mode);
            Authentication spring = SpringSamlComparatorTests.springCaptured(xml, signing, SP, ACS,
                    IDP, SSO, pending.get(0), pending.get(1), encodedRequest, observed);
            assertEquals(identity, spring.getName(), mode + " Spring subject");
            List<String> mutations = LibxmlsecOracleComparatorTests
                    .capturedEncryptedEnvelopeMutations(xml, "saml2p", "saml2");
            assertEquals(19, mutations.size(), mode + " envelope matrix");
            for (int index = 0; index < mutations.size(); index++) {
                String changed = mutations.get(index);
                String label = mode + ":" + index;
                assertNotEquals(xml, changed, label + " must change the capture");
                assertThrows(Exception.class, () -> OpenSamlSpComparatorTests.authenticateCaptured(
                        changed, signing, IDP, SP, ACS, pending.get(0), observed), label);
                assertThrows(Exception.class, () -> SpringSamlComparatorTests.springCaptured(
                        changed, signing, SP, ACS, IDP, SSO, pending.get(0), pending.get(1),
                        encodedRequest, observed), label + " Spring");
            }
        }
    }

    @Test void capturedSimpleSamlSignedCbcAndEnvelopeMutationsPreserveSpIdentity() throws Exception {
        X509Certificate signing;
        try (var input = Files.newInputStream(Path.of(
                "../src/test/resources/fixtures/keys/idp-signing-rsa-2048-cert.pem"))) {
            signing = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
        String label = "cbc-response-signed";
        String xml = Files.readString(SIMPLE_FIXTURES.resolve(label + "-response.xml"));
        List<String> pending = Files.readAllLines(SIMPLE_FIXTURES.resolve(label + "-pending.txt"));
        assertEquals(4, pending.size());
        Instant observed = Instant.parse(pending.get(2)).plusSeconds(60);
        String idp = "https://ssp.example.test/idp";
        String sp = "https://sp.test/SimpleCapture";
        String sso = "https://ssp.example.test/simplesaml/module.php/saml/idp/singleSignOnService";
        String encodedRequest = encodedRequest(SIMPLE_FIXTURES, label);
        String identity = OpenSamlSpComparatorTests.authenticateCaptured(
                xml, signing, idp, sp, ACS, pending.get(0), observed);
        assertFalse(identity.isBlank());
        assertNotEquals("attacker-user", identity);
        Authentication spring = SpringSamlComparatorTests.springCaptured(xml, signing,
                sp, ACS, idp, sso, pending.get(0), pending.get(1), encodedRequest, observed);
        assertEquals(identity, spring.getName());
        List<String> mutations = LibxmlsecOracleComparatorTests
                .capturedEncryptedEnvelopeMutations(xml, "samlp", "saml");
        assertEquals(19, mutations.size());
        for (int index = 0; index < mutations.size(); index++) {
            String changed = mutations.get(index);
            String caseLabel = label + ":" + index;
            assertNotEquals(xml, changed, caseLabel + " must change the capture");
            assertThrows(Exception.class, () -> OpenSamlSpComparatorTests.authenticateCaptured(
                    changed, signing, idp, sp, ACS, pending.get(0), observed), caseLabel);
            assertThrows(Exception.class, () -> SpringSamlComparatorTests.springCaptured(
                    changed, signing, sp, ACS, idp, sso, pending.get(0), pending.get(1),
                    encodedRequest, observed), caseLabel + " Spring");
        }
    }

    @Test void capturedSimpleSamlAssertionSignedCbcPinsWholeSpPolicyDifference() throws Exception {
        X509Certificate signing;
        try (var input = Files.newInputStream(Path.of(
                "../src/test/resources/fixtures/keys/idp-signing-rsa-2048-cert.pem"))) {
            signing = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
        String label = "cbc-assertion-signed";
        String xml = Files.readString(SIMPLE_FIXTURES.resolve(label + "-response.xml"));
        List<String> pending = Files.readAllLines(SIMPLE_FIXTURES.resolve(label + "-pending.txt"));
        assertEquals(4, pending.size());
        Instant observed = Instant.parse(pending.get(2)).plusSeconds(60);
        String idp = "https://ssp.example.test/idp";
        String sp = "https://sp.test/SimpleCapture";
        String sso = "https://ssp.example.test/simplesaml/module.php/saml/idp/singleSignOnService";
        String encodedRequest = encodedRequest(SIMPLE_FIXTURES, label);
        String originalIdentity = OpenSamlSpComparatorTests.authenticateCaptured(
                xml, signing, idp, sp, ACS, pending.get(0), observed);
        assertFalse(originalIdentity.isBlank());
        assertThrows(Exception.class, () -> SpringSamlComparatorTests.springCaptured(
                xml, signing, sp, ACS, idp, sso, pending.get(0), pending.get(1),
                encodedRequest, observed));
        List<String> mutations = LibxmlsecOracleComparatorTests
                .capturedEncryptedEnvelopeMutations(xml, "samlp", "saml");
        assertEquals(17, mutations.size());
        List<Integer> acceptedByOpenSaml = new ArrayList<>();
        for (int index = 0; index < mutations.size(); index++) {
            String changed = mutations.get(index);
            assertNotEquals(xml, changed, label + ":" + index + " must change the capture");
            try {
                String identity = OpenSamlSpComparatorTests.authenticateCaptured(
                        changed, signing, idp, sp, ACS, pending.get(0), observed);
                assertEquals(originalIdentity, identity, label + ":" + index + " identity");
                acceptedByOpenSaml.add(index);
            } catch (Exception rejected) {
                // The exact acceptance set below pins the separate SP's policy.
            }
            assertThrows(Exception.class, () -> SpringSamlComparatorTests.springCaptured(
                    changed, signing, sp, ACS, idp, sso, pending.get(0), pending.get(1),
                    encodedRequest, observed), label + ":" + index + " Spring");
        }
        // Direct OpenSAML tolerates an unsigned Extensions child (1) and an extra
        // success StatusCode (7), while still selecting the original signed subject.
        assertEquals(List.of(1, 7), acceptedByOpenSaml);
    }

    private static @NonNull String encodedRequest(@NonNull Path directory,
            @NonNull String label) throws Exception {
        URI redirect = URI.create(Files.readString(directory.resolve(label + "-redirect-url.txt")));
        return List.of(redirect.getRawQuery().split("&")).stream()
                .filter(part -> part.startsWith("SAMLRequest="))
                .map(part -> URLDecoder.decode(part.substring("SAMLRequest=".length()),
                        StandardCharsets.UTF_8))
                .findFirst().orElseThrow();
    }
}
