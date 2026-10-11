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
import org.w3c.dom.Element;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Offline SSO-to-SLO replay from SimpleSAMLphp 2.5.0, including its signed Redirect request. */
final class SimpleSamlCapturedLogoutTests {
    private static final @NonNull Path FIXTURES = Path.of(System.getProperty(
            "revetsec.simplesamlphp.slo.fixtures",
            "src/test/resources/fixtures/simplesamlphp/slo"));
    private static final @NonNull Path KEYS = Path.of("src/test/resources/fixtures/keys");
    private static final @NonNull String SP = "https://sp.test/SimpleCapture";
    private static final @NonNull String IDP = "https://ssp.example.test/idp";
    private static final @NonNull URI ACS = URI.create("https://sp.example.test/acs");
    private static final @NonNull URI SLO = URI.create("https://sp.example.test/slo");
    private static final @NonNull URI IDP_SSO = URI.create(
            "https://ssp.example.test/simplesaml/module.php/saml/idp/singleSignOnService");
    private static final @NonNull URI IDP_SLO = URI.create(
            "https://ssp.example.test/simplesaml/module.php/saml/idp/singleLogout");

    @Test void realIdpLogoutRequestMatchesAuthenticatedSessionAndReply() throws Exception {
        String loginXml = Files.readString(FIXTURES.resolve("login-response.xml"));
        var document = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(loginXml.getBytes(StandardCharsets.UTF_8))).getDocument();
        Clock clock = Clock.fixed(Instant.parse(document.getDocumentElement()
                .getAttribute("IssueInstant")).plusSeconds(1), ZoneOffset.UTC);
        SamlServiceProvider sp = serviceProvider(clock);
        SamlIdentityProvider idp = identityProvider();
        List<String> snapshot = Files.readAllLines(FIXTURES.resolve("login-pending.txt"));
        assertEquals(4, snapshot.size());
        PendingSamlAuthentication pending = new PendingSamlAuthentication(SP, snapshot.get(0),
                snapshot.get(1), "simplesaml-capture", IDP, ACS.toASCIIString(),
                Instant.parse(snapshot.get(2)), Instant.parse(snapshot.get(3)));
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("simplesaml-slo-capture"))
                .clock(clock).build();
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "simplesaml-slo-capture"), sealer,
                "simplesaml-slo-capture");
        String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                loginXml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(snapshot.get(1), StandardCharsets.UTF_8);
        SamlPostBindingMessage login = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        SamlAuthenticationResult result = sp.completeAuthenticationResult(login, source, idp);
        SamlSessionReference session = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                result, () -> "SimpleSAMLphp login result: " + result)
                .getAuthentication().getSessionReference();

        URI requestUri = URI.create(Files.readString(FIXTURES.resolve("logout-request-url.txt")).strip());
        assertEquals(SLO.toASCIIString(), requestUri.toASCIIString().split("\\?", 2)[0]);
        SamlRedirectBindingMessage request = redirect(requestUri);
        assertEquals(SamlRedirectBindingMessage.Kind.REQUEST, request.getKind());
        assertTrue(request.verify(idp.signingKeys()));
        assertEquals(Files.readString(FIXTURES.resolve("logout-request.xml")),
                new String(request.xml(), StandardCharsets.UTF_8));
        String tamperedQuery = requestUri.getRawQuery().replace("RelayState=", "RelayState=X");
        assertNotEquals(requestUri.getRawQuery(), tamperedQuery);
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                        SamlRedirectBindingMessage.fromRawQueryResult(tamperedQuery)).getMessage(), idp));

        SamlLogoutRequestResult logoutResult = sp.acceptLogoutRequestResult(request, idp);
        SamlLogoutRequest logout = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                logoutResult, () -> "SimpleSAMLphp logout result: " + logoutResult).getRequest();
        assertEquals(session.getIdentityProviderConnectionId(), logout.getIdentityProviderConnectionId());
        assertEquals(session.getNameId().getValue(), logout.getNameId().getValue());
        assertEquals(session.getNameId().getFormat(), logout.getNameId().getFormat());
        assertEquals(session.getNameId().getSpNameQualifier(), logout.getNameId().getSpNameQualifier());
        assertEquals(List.of(session.getSessionIndex().orElseThrow()), logout.getSessionIndexes());
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class, sp.acceptLogoutRequestResult(request, idp));

        SamlLogoutResponseRedirectResult response = sp.respondToLogoutRequestResult(
                logout, idp, SamlLogoutStatus.SUCCESS);
        SamlRedirectBindingMessage generated = redirect(assertInstanceOf(
                SamlLogoutResponseRedirectResult.Prepared.class, response).getRedirectUri());
        assertEquals(SamlRedirectBindingMessage.Kind.RESPONSE, generated.getKind());
        assertTrue(generated.verify(List.of(Objects.requireNonNull(sp.signingCredential())
                .getCertificate().getPublicKey())));
        URI capturedResponse = URI.create(Files.readString(FIXTURES.resolve("logout-response-url.txt")).strip());
        assertEquals(IDP_SLO.toASCIIString(), capturedResponse.toASCIIString().split("\\?", 2)[0]);
        SamlRedirectBindingMessage captured = redirect(capturedResponse);
        assertTrue(captured.verify(List.of(Objects.requireNonNull(sp.signingCredential())
                .getCertificate().getPublicKey())));
        assertTrue(new String(captured.xml(), StandardCharsets.UTF_8)
                .contains("InResponseTo=\"" + logout.getRequestId() + "\""));
        assertEquals("https://ssp.example.test/simplesaml/",
                Files.readString(FIXTURES.resolve("logout-final-url.txt")).strip());
    }

    @Test void realSpInitiatedRequestAndIdpResponseBindTheAuthenticatedSession() throws Exception {
        String loginXml = Files.readString(FIXTURES.resolve("sp-initiated-login-response.xml"));
        URI requestUri = URI.create(Files.readString(
                FIXTURES.resolve("sp-initiated-request-url.txt")).strip());
        URI responseUri = URI.create(Files.readString(
                FIXTURES.resolve("sp-initiated-response-url.txt")).strip());
        SamlRedirectBindingMessage request = redirect(requestUri);
        SamlRedirectBindingMessage response = redirect(responseUri);
        assertEquals(SamlRedirectBindingMessage.Kind.REQUEST, request.getKind());
        assertEquals(SamlRedirectBindingMessage.Kind.RESPONSE, response.getKind());
        assertEquals(IDP_SLO.toASCIIString(), requestUri.toASCIIString().split("\\?", 2)[0]);
        assertEquals(SLO.toASCIIString(), responseUri.toASCIIString().split("\\?", 2)[0]);
        assertEquals(Files.readString(FIXTURES.resolve("sp-initiated-response.xml")),
                new String(response.xml(), StandardCharsets.UTF_8));

        var requestDocument = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(request.xml())).getDocument();
        var responseDocument = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(response.xml())).getDocument();
        Instant requestIssued = Instant.parse(requestDocument.getDocumentElement()
                .getAttribute("IssueInstant"));
        Instant responseIssued = Instant.parse(responseDocument.getDocumentElement()
                .getAttribute("IssueInstant"));
        Clock clock = Clock.fixed(responseIssued.plusSeconds(1), ZoneOffset.UTC);
        SamlServiceProvider sp = serviceProvider(clock);
        SamlIdentityProvider idp = identityProvider();
        assertTrue(request.verify(List.of(Objects.requireNonNull(sp.signingCredential())
                .getCertificate().getPublicKey())));
        assertTrue(response.verify(idp.signingKeys()));
        assertEquals(requestDocument.getDocumentElement().getAttribute("ID"),
                responseDocument.getDocumentElement().getAttribute("InResponseTo"));

        List<String> loginSnapshot = Files.readAllLines(
                FIXTURES.resolve("sp-initiated-login-pending.txt"));
        assertEquals(4, loginSnapshot.size());
        PendingSamlAuthentication loginPending = new PendingSamlAuthentication(SP,
                loginSnapshot.get(0), loginSnapshot.get(1), "simplesaml-capture", IDP,
                ACS.toASCIIString(), Instant.parse(loginSnapshot.get(2)),
                Instant.parse(loginSnapshot.get(3)));
        StateSealer sealer = StateSealer.withActiveKey(
                TestSealers.fixedKey("simplesaml-sp-initiated-capture")).clock(clock).build();
        String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                loginXml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8)
                + "&RelayState=" + URLEncoder.encode(loginSnapshot.get(1), StandardCharsets.UTF_8);
        SamlPostBindingMessage login = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        SamlAuthenticationResult authenticated = sp.completeAuthenticationResult(login,
                PendingSamlAuthenticationSource.fromSealedForm(
                        loginPending.toSealedForm(sealer, "simplesaml-sp-login"), sealer,
                        "simplesaml-sp-login"), idp);
        SamlSessionReference session = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                authenticated, () -> "SimpleSAMLphp SP-initiated login: " + authenticated)
                .getAuthentication().getSessionReference();
        List<String> sessionSnapshot = Files.readAllLines(
                FIXTURES.resolve("sp-initiated-session.txt"));
        assertEquals(2, sessionSnapshot.size());
        assertEquals(sessionSnapshot.get(0), session.getNameId().getValue());
        assertEquals(sessionSnapshot.get(1), session.getSessionIndex().orElse(""));
        var nameIds = requestDocument.getDocumentElement().getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "NameID");
        assertEquals(1, nameIds.getLength());
        Element nameId = (Element) nameIds.item(0);
        assertEquals(session.getNameId().getValue(), nameId.getTextContent());
        assertEquals(session.getNameId().getFormat().orElse(""), nameId.getAttribute("Format"));
        assertEquals(session.getNameId().getNameQualifier().orElse(""),
                nameId.getAttribute("NameQualifier"));
        assertEquals(session.getNameId().getSpNameQualifier().orElse(""),
                nameId.getAttribute("SPNameQualifier"));
        assertEquals(session.getNameId().getSpProvidedId().orElse(""),
                nameId.getAttribute("SPProvidedID"));
        var sessionIndexes = requestDocument.getDocumentElement().getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:protocol", "SessionIndex");
        assertEquals(1, sessionIndexes.getLength());
        assertEquals(session.getSessionIndex().orElseThrow(),
                sessionIndexes.item(0).getTextContent());

        PendingSamlAuthentication logoutPending = new PendingSamlAuthentication(SP,
                requestDocument.getDocumentElement().getAttribute("ID"),
                Objects.requireNonNull(request.relayState()),
                "simplesaml-capture", IDP, SLO.toASCIIString(), requestIssued,
                responseIssued.plusSeconds(300));
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromSealedForm(
                new PendingSamlLogout(logoutPending).toSealedForm(sealer, "simplesaml-sp-logout"),
                sealer, "simplesaml-sp-logout");
        String tampered = responseUri.getRawQuery().replace("RelayState=", "RelayState=X");
        assertNotEquals(responseUri.getRawQuery(), tampered);
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                sp.completeLogoutResult(assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                        SamlRedirectBindingMessage.fromRawQueryResult(tampered)).getMessage(), source, idp));
        SamlLogoutResult completed = sp.completeLogoutResult(response, source, idp);
        assertInstanceOf(SamlLogoutResult.Succeeded.class, completed,
                () -> "SimpleSAMLphp SP-initiated response: " + completed);
        assertInstanceOf(SamlLogoutResult.Rejected.class,
                sp.completeLogoutResult(response, source, idp));
    }

    private static @NonNull SamlServiceProvider serviceProvider(@NonNull Clock clock) throws Exception {
        return SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(ACS)
                .singleLogoutServiceUrl(SLO)
                .signingCredential(SamlCredential.fromPem(
                        Files.readString(KEYS.resolve("sp-signing-rsa-2048-key.pem")),
                        Files.readString(KEYS.resolve("sp-signing-rsa-2048-cert.pem"))))
                .decryptionCredentials(List.of(SamlCredential.fromPem(
                        Files.readString(KEYS.resolve("sp-encryption-rsa-2048-key.pem")),
                        Files.readString(KEYS.resolve("sp-encryption-rsa-2048-cert.pem")))))
                .replayCache(InMemorySamlReplayCache.withLimit(clock, 16)).clock(clock).build();
    }

    private static @NonNull SamlIdentityProvider identityProvider() throws Exception {
        X509Certificate certificate;
        try (var stream = Files.newInputStream(KEYS.resolve("idp-signing-rsa-2048-cert.pem"))) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(stream);
        }
        return SamlIdentityProvider.withEntityId(IDP).connectionId("simplesaml-capture")
                .redirectSingleSignOnService(IDP_SSO).redirectSingleLogoutService(IDP_SLO)
                .signingKeys(List.of(certificate.getPublicKey()))
                .allowAesCbcEncryption(true).build();
    }

    private static @NonNull SamlRedirectBindingMessage redirect(@NonNull URI uri) {
        return assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(uri.getRawQuery())).getMessage();
    }
}
