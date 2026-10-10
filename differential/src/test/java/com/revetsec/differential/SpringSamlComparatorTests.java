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
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

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
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A whole-SP Spring Security oracle, with OpenSAML isolated from the core library. */
final class SpringSamlComparatorTests {
    private static final @NonNull Path FIXTURES = Path.of("../src/test/resources/fixtures");
    private static final @NonNull Clock FIXTURE_CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:01:00Z"), ZoneOffset.UTC);

    @Test void signedPlacementsAgreeOnIdentityAndSignedTampering() throws Exception {
        for (String fixture : modernFixtures()) {
            String credential = signingCredential(fixture);
            String original = Files.readString(FIXTURES.resolve("scripted-idp/" + fixture + ".xml"));
            assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    revetsec(original, credential, false), fixture + " Revetsec baseline");
            assertEquals("minted-user", spring(original, credential).getName(),
                    fixture + " baseline Spring identity");

            String tampered = original.replace("minted-user", "attacker-user");
            assertTrue(!tampered.equals(original), fixture + " must contain a signed NameID");
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    revetsec(tampered, credential, false), fixture + " Revetsec tamper");
            assertThrows(AuthenticationException.class, () -> spring(tampered, credential),
                    fixture + " signed NameID tamper");
        }
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

    @Test void legacySha1NeedsExplicitRevetsecCompatibility() throws Exception {
        String fixture = Files.readString(FIXTURES.resolve("scripted-idp/assertion-rsa-sha1.xml"));
        String credential = "idp-signing-rsa-2048";
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                revetsec(fixture, credential, false));
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                revetsec(fixture, credential, true));
        // Spring's default provider accepts this SHA-1 signature. Revetsec requires the
        // explicit legacy compatibility mode; both reject a modified signed identity.
        assertEquals("minted-user", spring(fixture, credential).getName());
        String tampered = fixture.replace("minted-user", "attacker-user");
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                revetsec(tampered, credential, true));
        assertThrows(AuthenticationException.class, () -> spring(tampered, credential));
    }

    @Test void encryptedAssertionsAgreeOnIdentity() throws Exception {
        for (String name : List.of(
                "encrypted-aes128-gcm-rsa-oaep-sha256-mgf1sha256",
                "encrypted-aes128-gcm-rsa-oaep-mgf1p",
                "encrypted-aes192-gcm-rsa-oaep-sha256-mgf1sha256",
                "encrypted-aes192-gcm-rsa-oaep-mgf1p",
                "encrypted-aes256-gcm-rsa-oaep-sha256-mgf1sha256",
                "encrypted-aes256-gcm-rsa-oaep-mgf1p")) {
            checkEncryptedIdentity(name, "idp-signing-rsa-2048", false, true);
        }
        for (String data : List.of("aes128-gcm", "aes192-gcm", "aes256-gcm"))
            for (String transport : List.of("rsa-oaep-mgf1p-sha1", "rsa-oaep-mgf1p-sha256",
                    "rsa-oaep-sha1-mgf1sha1", "rsa-oaep-sha256-mgf1sha1"))
                for (String placement : List.of("response", "assertion", "both"))
                    checkEncryptedIdentity("oaep-" + data + "-" + transport + "-" + placement,
                            "idp-signing-rsa-2048", false, !placement.equals("assertion"));
        checkEncryptedIdentity("assertion-rsa512-encrypted", "idp-signing-rsa-3072", false, false);
        checkEncryptedIdentity("assertion-ec256-encrypted-id", "idp-signing-ec-p256", false, true);
    }

    private static void checkEncryptedIdentity(@NonNull String name, @NonNull String credential,
            boolean cbc, boolean springAccepts) throws Exception {
        String xml = Files.readString(FIXTURES.resolve("scripted-idp/" + name + ".xml"));
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class,
                revetsec(xml, credential, false, cbc), name + " Revetsec");
        assertEquals("minted-user", success.getAuthentication().getNameId().orElseThrow().getValue(),
                name + " Revetsec identity");
        if (springAccepts)
            assertEquals("minted-user", spring(xml, credential).getName(), name + " Spring identity");
        else
            assertThrows(AuthenticationException.class, () -> spring(xml, credential),
                    name + " Spring requires an outer Response signature before decryption");
    }

    @Test void cbcRequiresRevetsecOptInAndSignedResponse() throws Exception {
        String credential = "idp-signing-rsa-2048";
        for (String data : List.of("aes128-cbc", "aes192-cbc", "aes256-cbc")) {
            String name = "encrypted-" + data + "-response";
            String xml = Files.readString(FIXTURES.resolve("scripted-idp/" + name + ".xml"));
            SamlAuthenticationResult.Rejected defaultResult = assertInstanceOf(
                    SamlAuthenticationResult.Rejected.class, revetsec(xml, credential, false), name);
            assertEquals(SamlAuthenticationResult.Reason.DECRYPTION, defaultResult.getReason(), name);
            checkEncryptedIdentity(name, credential, true, true);
        }
        String assertionOnly = Files.readString(FIXTURES.resolve(
                "scripted-idp/encrypted-aes128-cbc-assertion.xml"));
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                revetsec(assertionOnly, credential, false, true));
        assertThrows(AuthenticationException.class, () -> spring(assertionOnly, credential));

        String unsigned = Files.readString(FIXTURES.resolve("scripted-idp/unsigned-encrypted.xml"));
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                revetsec(unsigned, credential, false));
        assertThrows(AuthenticationException.class, () -> spring(unsigned, credential));
    }

    @Test void encryptedNegativesDoNotReleaseAttackerIdentity() throws Exception {
        String credential = "idp-signing-rsa-2048";
        for (String name : List.of("negative-rsa-1_5", "negative-mgf-under-mgf1p",
                "negative-nonempty-oaep-params", "negative-cipher-bit-flip")) {
            String xml = Files.readString(FIXTURES.resolve("scripted-idp/" + name + ".xml"));
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    revetsec(xml, credential, false), name + " Revetsec");
            // Spring accepts RSA1_5 and the MGF child under mgf1p, while Revetsec
            // rejects both by policy. The remaining two fail decryption in both SPs.
            if (name.equals("negative-rsa-1_5") || name.equals("negative-mgf-under-mgf1p"))
                assertEquals("minted-user", spring(xml, credential).getName(),
                        name + " Spring signed identity");
            else
                assertThrows(AuthenticationException.class,
                        () -> spring(xml, credential), name + " Spring");
        }
    }

    @Test void wrapperMutationsNeverReleaseAttackerIdentity() throws Exception {
        for (String fixture : modernFixtures()) {
            String credential = signingCredential(fixture);
            String original = Files.readString(FIXTURES.resolve("scripted-idp/" + fixture + ".xml"));
            String assertion = section(original, "<saml:Assertion ", "</saml:Assertion>");
            String assertionId = id(original, "saml:Assertion");
            String attacker = Pattern.compile("<ds:Signature\\b[^>]*>.*?</ds:Signature>",
                    Pattern.DOTALL).matcher(assertion).replaceFirst("")
                    .replace("minted-user", "attacker-user")
                    .replace(assertionId, "_attacker_assertion");
            Matcher signature = Pattern.compile("<ds:Signature\\b[^>]*>.*?</ds:Signature>",
                    Pattern.DOTALL).matcher(original);
            assertTrue(signature.find(), fixture + " signature missing");
            String copiedSignature = signature.group();
            List<String> names = List.of("sibling-before", "extension-before-status", "destination",
                    "duplicate-status", "qualified-response-id", "qualified-assertion-id",
                    "copied-signature-in-extension", "relative-namespace-and-sibling",
                    "comment-split-name-id");
            List<String> candidates = List.of(
                    original.replace(assertion, attacker + assertion),
                    original.replace("<samlp:Status>",
                            "<samlp:Extensions>" + attacker + "</samlp:Extensions><samlp:Status>"),
                    replaceFirstLiteral(original, "https://sp.test/acs",
                            "https://attacker.example.test/acs"),
                    original.replace("<samlp:Status>",
                            "<samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                                    + "</samlp:Status><samlp:Status>"),
                    original.replace("<samlp:Response ",
                            "<samlp:Response samlp:ID='_attacker_response' "),
                    original.replace("<saml:Assertion ",
                            "<saml:Assertion saml:ID='_attacker_assertion' "),
                    original.replace("<samlp:Status>",
                            "<samlp:Extensions><Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>"
                                    + "<Child xml:xmlns='#other'>" + copiedSignature
                                    + "</Child></Parent></samlp:Extensions><samlp:Status>"),
                    original.replace("<samlp:Response ", "<samlp:Response xmlns:ns='1' ")
                            .replace(assertion, attacker + assertion),
                    original.replace("minted-user", "minted-<!-- -->attacker"));
            for (int index = 0; index < candidates.size(); index++) {
                String candidate = candidates.get(index);
                String label = fixture + ":" + names.get(index);
                assertTrue(!candidate.equals(original), label + " did not mutate");
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        revetsec(candidate, credential, false), label + " Revetsec");
                boolean assertionOnly = fixture.startsWith("matrix-assertion-")
                        || fixture.equals("assertion-signxml") || fixture.equals("assertion-ec384");
                // Spring accepts three unsigned envelope changes when the untouched Assertion
                // is the only signed element. It still returns the original, signed identity.
                if (assertionOnly && Set.of("extension-before-status", "duplicate-status",
                        "copied-signature-in-extension").contains(names.get(index)))
                    assertEquals("minted-user", spring(candidate, credential).getName(),
                            label + " unchanged signed identity");
                else
                    assertThrows(AuthenticationException.class,
                            () -> spring(candidate, credential), label + " Spring");
            }
        }
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

    private static @NonNull String replaceFirstLiteral(@NonNull String input,
            @NonNull String search, @NonNull String replacement) {
        int index = input.indexOf(search);
        assertTrue(index >= 0, "fixture field missing: " + search);
        return input.substring(0, index) + replacement + input.substring(index + search.length());
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

    private static @NonNull SamlAuthenticationResult revetsec(@NonNull String xml,
            @NonNull String credential, boolean sha1) throws Exception {
        return revetsec(xml, credential, sha1, false);
    }

    private static @NonNull SamlAuthenticationResult revetsec(@NonNull String xml,
            @NonNull String credential, boolean sha1, boolean cbc) throws Exception {
        X509Certificate certificate = certificate(credential);
        SamlServiceProvider provider = SamlServiceProvider.withEntityId("https://sp.test/Selftest")
                .assertionConsumerServiceUrl(URI.create("https://sp.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(FIXTURE_CLOCK, 16))
                .decryptionCredentials(List.of(SamlCredential.fromPem(
                        Files.readString(FIXTURES.resolve("keys/sp-encryption-rsa-2048-key.pem")),
                        Files.readString(FIXTURES.resolve("keys/sp-encryption-rsa-2048-cert.pem")))))
                .clock(FIXTURE_CLOCK).build();
        SamlIdentityProvider identityProvider = SamlIdentityProvider
                .withEntityId("https://idp.scripted-idp.test/")
                .connectionId("spring-differential")
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .signingKeys(List.of(certificate.getPublicKey()))
                .compatibility(compatibility(sha1, cbc)).build();
        String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        return provider.completeUnsolicitedAuthenticationResult(message, identityProvider);
    }

    private static @NonNull Set<SamlCompatibilityMode> compatibility(boolean sha1, boolean cbc) {
        EnumSet<SamlCompatibilityMode> modes = EnumSet.of(
                SamlCompatibilityMode.UNSOLICITED_RESPONSES);
        if (sha1) modes.add(SamlCompatibilityMode.SHA1_SIGNATURES);
        if (cbc) modes.add(SamlCompatibilityMode.AES_CBC_ENCRYPTION);
        return Set.copyOf(modes);
    }

    static @NonNull Authentication spring(@NonNull String xml,
            @NonNull String certificateName) throws Exception {
        Saml2X509Credential credential = Saml2X509Credential.verification(certificate(certificateName));
        Saml2X509Credential decryptingCredential = Saml2X509Credential.decryption(decryptionKey(),
                certificate("sp-encryption-rsa-2048"));
        RelyingPartyRegistration registration = RelyingPartyRegistration.withRegistrationId("scripted")
                .entityId("https://sp.test/Selftest")
                .assertionConsumerServiceLocation("https://sp.test/acs")
                .decryptionX509Credentials(credentials -> credentials.add(decryptingCredential))
                .assertingPartyMetadata(party -> party.entityId("https://idp.scripted-idp.test/")
                        .singleSignOnServiceLocation("https://idp.scripted-idp.test/sso")
                        .verificationX509Credentials(credentials -> credentials.add(credential)))
                .build();
        OpenSaml5AuthenticationProvider provider = new OpenSaml5AuthenticationProvider();
        // This comparison replays fixed-time signed fixtures. Derive the skew from fixture age so
        // the test never expires; timestamp validation has separate Revetsec tests.
        Duration replaySkew = Duration.between(FIXTURE_CLOCK.instant(), Instant.now())
                .abs().plus(Duration.ofDays(1));
        provider.setAssertionValidator(OpenSaml5AuthenticationProvider.AssertionValidator.builder()
                .clockSkew(replaySkew).build());
        Authentication authentication = provider.authenticate(
                new Saml2AuthenticationToken(registration, xml, null));
        return java.util.Objects.requireNonNull(authentication);
    }

    private static @NonNull X509Certificate certificate(@NonNull String name) throws Exception {
        try (var input = Files.newInputStream(FIXTURES.resolve(
                "keys/" + name + "-cert.pem"))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
    }

    private static @NonNull PrivateKey decryptionKey() {
        try {
            String pem = Files.readString(FIXTURES.resolve("keys/sp-encryption-rsa-2048-key.pem"));
            String body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(body)));
        } catch (Exception exception) {
            throw new IllegalStateException("Invalid test-only SP decryption key", exception);
        }
    }
}
