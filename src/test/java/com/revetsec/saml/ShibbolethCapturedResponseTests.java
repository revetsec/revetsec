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

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Offline replay of a response emitted by unmodified Shibboleth IdP 5.2.3. */
final class ShibbolethCapturedResponseTests {
    private static final @NonNull Path FIXTURES = Path.of(System.getProperty(
            "revetsec.shibboleth.fixtures", "src/test/resources/fixtures/shibboleth"));
    private static final @NonNull Path KEYS = Path.of("src/test/resources/fixtures/keys");
    private static final @NonNull String SP = "https://sp.test/ShibCapture";
    private static final @NonNull String IDP = "https://idp.example.org/idp/shibboleth";
    private static final @NonNull URI ACS = URI.create("https://sp.example.test/acs");

    @Test void realShibbolethGcmResponseAuthenticatesOnlyOnce() throws Exception {
        List<String> snapshot = Files.readAllLines(FIXTURES.resolve("gcm-pending.txt"));
        assertEquals(4, snapshot.size());
        String xml = Files.readString(FIXTURES.resolve("gcm-response.xml"));
        var document = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8))).getDocument();
        assertEquals(snapshot.get(0), document.getDocumentElement().getAttribute("InResponseTo"));
        Instant responseIssued = Instant.parse(document.getDocumentElement().getAttribute("IssueInstant"));
        Clock clock = Clock.fixed(responseIssued.plusSeconds(1), ZoneOffset.UTC);
        SamlServiceProvider serviceProvider = serviceProvider(clock);
        SamlIdentityProvider identityProvider = identityProvider(false);
        PendingSamlAuthenticationSource pending = pending(clock, snapshot);
        SamlPostBindingMessage message = message(xml, snapshot.get(1));
        assertInstanceOf(PendingSamlAuthenticationSource.Resolved.class,
                pending.resolve(clock, message.relayState(), Duration.ofSeconds(2)));
        SamlAuthenticationResult result = serviceProvider.completeAuthenticationResult(message, pending,
                identityProvider);
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class, result,
                () -> "Shibboleth GCM result: " + result);
        assertEquals("shibboleth-capture", success.getAuthentication().getIdentityProviderConnectionId());
        assertTrue(success.getAuthentication().getNameId().isPresent());
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                serviceProvider.completeAuthenticationResult(message, pending, identityProvider));
    }

    @Test void realShibbolethCbcResponseRequiresPerIdpOptIn() throws Exception {
        List<String> snapshot = Files.readAllLines(FIXTURES.resolve("cbc-pending.txt"));
        assertEquals(4, snapshot.size());
        String xml = Files.readString(FIXTURES.resolve("cbc-response.xml"));
        var document = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8))).getDocument();
        assertEquals(snapshot.get(0), document.getDocumentElement().getAttribute("InResponseTo"));
        assertTrue(xml.contains("http://www.w3.org/2001/04/xmlenc#aes128-cbc"));
        assertTrue(xml.contains("<ds:Signature"));
        Instant responseIssued = Instant.parse(document.getDocumentElement().getAttribute("IssueInstant"));
        Clock clock = Clock.fixed(responseIssued.plusSeconds(1), ZoneOffset.UTC);
        PendingSamlAuthenticationSource pending = pending(clock, snapshot);
        SamlPostBindingMessage message = message(xml, snapshot.get(1));
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                serviceProvider(clock).completeAuthenticationResult(message, pending, identityProvider(false)));
        SamlAuthenticationResult result = serviceProvider(clock)
                .completeAuthenticationResult(message, pending, identityProvider(true));
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class, result,
                () -> "Shibboleth CBC result: " + result);
        assertEquals("shibboleth-capture", success.getAuthentication().getIdentityProviderConnectionId());
    }

    @Test void capturedEncryptedResponsesRejectEnvelopeAttacksBeforeAcceptingOriginal() throws Exception {
        for (String mode : List.of("gcm", "cbc")) {
            List<String> snapshot = Files.readAllLines(FIXTURES.resolve(mode + "-pending.txt"));
            String original = Files.readString(FIXTURES.resolve(mode + "-response.xml"));
            var document = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                    SecureXmlParser.parseMetadata(original.getBytes(StandardCharsets.UTF_8)))
                    .getDocument();
            Clock clock = Clock.fixed(Instant.parse(document.getDocumentElement()
                    .getAttribute("IssueInstant")).plusSeconds(1), ZoneOffset.UTC);
            SamlServiceProvider provider = serviceProvider(clock);
            SamlIdentityProvider idp = identityProvider(mode.equals("cbc"));
            PendingSamlAuthenticationSource pending = pending(clock, snapshot);
            for (CapturedEncryptedResponseMutations.Mutation mutation :
                    Stream.concat(CapturedEncryptedResponseMutations.from(original, "saml2p", "saml2")
                                    .stream(), CapturedEncryptedResponseMutations.cryptographicFrom(original)
                                    .stream()).toList()) {
                String label = mode + ":" + mutation.name();
                assertNotEquals(original, mutation.xml(), label + " must change the capture");
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        provider.completeAuthenticationResult(message(mutation.xml(), snapshot.get(1)),
                                pending, idp), label);
            }
            assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    provider.completeAuthenticationResult(message(original, snapshot.get(1)),
                            pending, idp), mode + " original remains usable after rejected attacks");
        }
    }

    @Test void capturedSpMetadataMatchesGeneratedOutputAndDocumentedCbcVariant() throws Exception {
        Clock clock = Clock.fixed(Instant.parse("2026-10-11T00:00:00Z"), ZoneOffset.UTC);
        String generated = assertInstanceOf(SamlServiceProviderMetadataResult.Generated.class,
                SamlServiceProviderMetadata.fromServiceProviderResult(serviceProvider(clock))).getXml();
        assertEquals(Files.readString(FIXTURES.resolve("gcm-sp-metadata.xml")), generated);
        assertEquals(4, generated.split("<md:EncryptionMethod", -1).length - 1);
        String cbcVariant = generated.replaceAll("<md:EncryptionMethod Algorithm=\"[^\"]+\"/>", "");
        assertEquals(Files.readString(FIXTURES.resolve("cbc-sp-metadata.xml")), cbcVariant);
    }

    @Test void capturedRedirectRequestsCarryValidSpBindingSignatures() throws Exception {
        X509Certificate certificate;
        try (var input = Files.newInputStream(KEYS.resolve("sp-signing-rsa-2048-cert.pem"))) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
        for (String mode : List.of("gcm", "cbc")) {
            URI redirect = URI.create(Files.readString(FIXTURES.resolve(mode + "-redirect-url.txt")));
            String raw = redirect.getRawQuery();
            String[] parts = raw.split("&", -1);
            assertEquals(4, parts.length, mode + " Redirect field count");
            assertTrue(parts[0].startsWith("SAMLRequest="));
            assertTrue(parts[1].startsWith("RelayState="));
            assertTrue(parts[2].startsWith("SigAlg="));
            assertTrue(parts[3].startsWith("Signature="));
            assertEquals("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                    URLDecoder.decode(parts[2].substring("SigAlg=".length()), StandardCharsets.UTF_8));
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(certificate.getPublicKey());
            verifier.update((parts[0] + "&" + parts[1] + "&" + parts[2])
                    .getBytes(StandardCharsets.US_ASCII));
            assertTrue(verifier.verify(Base64.getDecoder().decode(URLDecoder.decode(
                    parts[3].substring("Signature=".length()), StandardCharsets.UTF_8))),
                    mode + " Redirect signature");
            byte[] deflated = Base64.getDecoder().decode(URLDecoder.decode(
                    parts[0].substring("SAMLRequest=".length()), StandardCharsets.UTF_8));
            try (var input = new InflaterInputStream(new ByteArrayInputStream(deflated),
                    new Inflater(true))) {
                assertEquals(Files.readString(FIXTURES.resolve(mode + "-request.xml")),
                        new String(input.readAllBytes(), StandardCharsets.UTF_8));
            }
        }
    }

    private static @NonNull SamlServiceProvider serviceProvider(@NonNull Clock clock) throws Exception {
        return SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(ACS)
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
        try (var stream = Files.newInputStream(FIXTURES.resolve("idp-signing.crt"))) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(stream);
        }
        SamlIdentityProvider.Builder builder = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("shibboleth-capture")
                .redirectSingleSignOnService(URI.create(
                        "https://idp.example.org/idp/profile/SAML2/Redirect/SSO"))
                .signingKeys(List.of(certificate.getPublicKey()));
        if (cbc) builder = builder.allowAesCbcEncryption(true);
        return builder.build();
    }

    private static @NonNull PendingSamlAuthenticationSource pending(@NonNull Clock clock,
            @NonNull List<@NonNull String> snapshot) {
        PendingSamlAuthentication value = new PendingSamlAuthentication(SP, snapshot.get(0),
                snapshot.get(1), "shibboleth-capture", IDP, ACS.toASCIIString(),
                Instant.parse(snapshot.get(2)), Instant.parse(snapshot.get(3)));
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("shibboleth-capture"))
                .clock(clock).build();
        return PendingSamlAuthenticationSource.fromSealedForm(
                value.toSealedForm(sealer, "shibboleth-capture"), sealer, "shibboleth-capture");
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
