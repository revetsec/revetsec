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

import com.revetsec.StateSealer;
import com.revetsec.internal.xml.SecureXmlParser;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Offline CBC responses emitted by SimpleSAMLphp 2.5.0, not the scripted test IdP. */
final class SimpleSamlCapturedResponseTests {
    private static final @NonNull Path FIXTURES = Path.of(System.getProperty(
            "revetsec.simplesamlphp.fixtures", "src/test/resources/fixtures/simplesamlphp"));
    private static final @NonNull Path KEYS = Path.of("src/test/resources/fixtures/keys");
    private static final @NonNull String SP = "https://sp.test/SimpleCapture";
    private static final @NonNull String IDP = "https://ssp.example.test/idp";
    private static final @NonNull URI ACS = URI.create("https://sp.example.test/acs");
    private static final @NonNull URI SSO = URI.create(
            "https://ssp.example.test/simplesaml/module.php/saml/idp/singleSignOnService");

    @Test void responseSignedCbcAuthenticatesOnlyWithIdpOptInAndCannotReplay() throws Exception {
        String label = "cbc-response-signed";
        List<String> snapshot = Files.readAllLines(FIXTURES.resolve(label + "-pending.txt"));
        String xml = Files.readString(FIXTURES.resolve(label + "-response.xml"));
        assertTrue(xml.contains("http://www.w3.org/2001/04/xmlenc#aes128-cbc"));
        assertEquals(1, signatureCount(xml));
        Clock clock = clock(xml);
        SamlPostBindingMessage message = message(xml, snapshot.get(1));
        SamlServiceProvider serviceProvider = serviceProvider(clock);
        PendingSamlAuthenticationSource pending = pending(clock, snapshot);
        SamlAuthenticationResult.Rejected denied = assertInstanceOf(
                SamlAuthenticationResult.Rejected.class,
                serviceProvider.completeAuthenticationResult(message, pending, identityProvider(false)));
        assertEquals(SamlAuthenticationResult.Reason.DECRYPTION, denied.getReason());
        SamlIdentityProvider idp = identityProvider(true);
        SamlAuthenticationResult result = serviceProvider.completeAuthenticationResult(message, pending, idp);
        SamlAuthenticationResult.Succeeded accepted = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class, result,
                () -> "SimpleSAMLphp signed CBC result: " + result);
        assertEquals("simplesaml-capture", accepted.getAuthentication().getIdentityProviderConnectionId());
        assertTrue(accepted.getAuthentication().getNameId().isPresent());
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                serviceProvider.completeAuthenticationResult(message, pending, idp));
    }

    @Test void assertionSignedCbcWithoutResponseSignatureCannotAuthenticate() throws Exception {
        String label = "cbc-assertion-signed";
        List<String> snapshot = Files.readAllLines(FIXTURES.resolve(label + "-pending.txt"));
        String xml = Files.readString(FIXTURES.resolve(label + "-response.xml"));
        assertTrue(xml.contains("http://www.w3.org/2001/04/xmlenc#aes128-cbc"));
        assertEquals(0, signatureCount(xml));
        SamlAuthenticationResult.Rejected denied = assertInstanceOf(
                SamlAuthenticationResult.Rejected.class,
                serviceProvider(clock(xml)).completeAuthenticationResult(message(xml, snapshot.get(1)),
                        pending(clock(xml), snapshot), identityProvider(true)));
        assertEquals(SamlAuthenticationResult.Reason.DECRYPTION, denied.getReason());
    }

    @Test void capturedSignedCbcRejectsEnvelopeAttacksBeforeAcceptingOriginal() throws Exception {
        List<String> snapshot = Files.readAllLines(FIXTURES.resolve("cbc-response-signed-pending.txt"));
        String original = Files.readString(FIXTURES.resolve("cbc-response-signed-response.xml"));
        Clock clock = clock(original);
        SamlServiceProvider provider = serviceProvider(clock);
        SamlIdentityProvider idp = identityProvider(true);
        PendingSamlAuthenticationSource pending = pending(clock, snapshot);
        List<CapturedEncryptedResponseMutations.Mutation> envelope =
                CapturedEncryptedResponseMutations.from(original, "samlp", "saml");
        assertEquals(19, envelope.size(), "signed captured envelope matrix");
        for (CapturedEncryptedResponseMutations.Mutation mutation :
                Stream.concat(envelope.stream(),
                        CapturedEncryptedResponseMutations.cryptographicFrom(original).stream())
                        .toList()) {
            assertNotEquals(original, mutation.xml(), mutation.name() + " must change the capture");
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    provider.completeAuthenticationResult(message(mutation.xml(), snapshot.get(1)),
                            pending, idp), mutation.name());
        }
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                provider.completeAuthenticationResult(message(original, snapshot.get(1)),
                        pending, idp), "original remains usable after rejected attacks");
    }

    @Test void capturedAssertionSignedCbcCannotPromoteIdentityThroughEnvelopeAttacks() throws Exception {
        List<String> snapshot = Files.readAllLines(FIXTURES.resolve("cbc-assertion-signed-pending.txt"));
        String original = Files.readString(FIXTURES.resolve("cbc-assertion-signed-response.xml"));
        Clock clock = clock(original);
        SamlServiceProvider provider = serviceProvider(clock);
        SamlIdentityProvider idp = identityProvider(true);
        PendingSamlAuthenticationSource pending = pending(clock, snapshot);
        List<CapturedEncryptedResponseMutations.Mutation> envelope =
                CapturedEncryptedResponseMutations.from(original, "samlp", "saml");
        assertEquals(17, envelope.size(), "assertion-only captured envelope matrix");
        for (CapturedEncryptedResponseMutations.Mutation mutation :
                Stream.concat(envelope.stream(),
                        CapturedEncryptedResponseMutations.cryptographicFrom(original).stream())
                        .toList()) {
            assertNotEquals(original, mutation.xml(), mutation.name() + " must change the capture");
            assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                    provider.completeAuthenticationResult(message(mutation.xml(), snapshot.get(1)),
                            pending, idp), mutation.name());
        }
    }

    @Test void capturedSpMetadataMatchesCurrentGenerator() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-10-11T00:00:00Z"), ZoneOffset.UTC);
        String generated = assertInstanceOf(SamlServiceProviderMetadataResult.Generated.class,
                SamlServiceProviderMetadata.fromServiceProviderResult(serviceProvider(clock))).getXml();
        assertEquals(Files.readString(FIXTURES.resolve("cbc-response-signed-sp-metadata.xml")), generated);
        assertEquals(generated,
                Files.readString(FIXTURES.resolve("cbc-assertion-signed-sp-metadata.xml")));
    }

    private static @NonNull Clock clock(@NonNull String xml) {
        var parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8))).getDocument();
        Instant issued = Instant.parse(parsed.getDocumentElement().getAttribute("IssueInstant"));
        return Clock.fixed(issued.plusSeconds(1), ZoneOffset.UTC);
    }

    private static int signatureCount(@NonNull String xml) {
        var parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8))).getDocument();
        return parsed.getDocumentElement().getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "Signature").getLength();
    }

    private static @NonNull SamlServiceProvider serviceProvider(@NonNull Clock clock) throws Exception {
        return SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(ACS)
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 8))
                .signingCredential(SamlCredential.fromPem(
                        Files.readString(KEYS.resolve("sp-signing-rsa-2048-key.pem")),
                        Files.readString(KEYS.resolve("sp-signing-rsa-2048-cert.pem"))))
                .decryptionCredentials(List.of(SamlCredential.fromPem(
                        Files.readString(KEYS.resolve("sp-encryption-rsa-2048-key.pem")),
                        Files.readString(KEYS.resolve("sp-encryption-rsa-2048-cert.pem")))))
                .clock(clock).build();
    }

    private static @NonNull SamlIdentityProvider identityProvider(boolean cbc) throws Exception {
        X509Certificate certificate;
        try (var stream = Files.newInputStream(KEYS.resolve("idp-signing-rsa-2048-cert.pem"))) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(stream);
        }
        SamlIdentityProvider.Builder builder = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("simplesaml-capture")
                .redirectSingleSignOnService(SSO)
                .signingKeys(List.of(certificate.getPublicKey()));
        if (cbc) builder = builder.allowAesCbcEncryption(true);
        return builder.build();
    }

    private static @NonNull PendingSamlAuthenticationSource pending(@NonNull Clock clock,
            @NonNull List<@NonNull String> snapshot) {
        assertEquals(4, snapshot.size());
        PendingSamlAuthentication value = new PendingSamlAuthentication(SP, snapshot.get(0),
                snapshot.get(1), "simplesaml-capture", IDP, ACS.toASCIIString(),
                Instant.parse(snapshot.get(2)), Instant.parse(snapshot.get(3)));
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("simplesaml-capture"))
                .clock(clock).build();
        return PendingSamlAuthenticationSource.fromSealedForm(
                value.toSealedForm(sealer, "simplesaml-capture"), sealer, "simplesaml-capture");
    }

    private static @NonNull SamlPostBindingMessage message(@NonNull String xml,
            @NonNull String relayState) {
        String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8) + "&RelayState="
                + URLEncoder.encode(relayState, StandardCharsets.UTF_8);
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }
}
