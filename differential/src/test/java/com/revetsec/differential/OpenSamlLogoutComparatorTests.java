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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.saml.InMemorySamlReplayCache;
import com.revetsec.saml.PendingSamlLogoutSource;
import com.revetsec.saml.SamlAuthenticationResult;
import com.revetsec.saml.SamlCompatibilityMode;
import com.revetsec.saml.SamlCredential;
import com.revetsec.saml.SamlIdentityProvider;
import com.revetsec.saml.SamlLogoutRedirectResult;
import com.revetsec.saml.SamlLogoutRequestResult;
import com.revetsec.saml.SamlLogoutResult;
import com.revetsec.saml.SamlPostBindingMessage;
import com.revetsec.saml.SamlPostBindingParseResult;
import com.revetsec.saml.SamlRedirectBindingMessage;
import com.revetsec.saml.SamlRedirectBindingParseResult;
import com.revetsec.saml.SamlServiceProvider;
import com.revetsec.saml.SamlSessionReference;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.binding.security.impl.SAML2HTTPRedirectDeflateSignatureSecurityHandler;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.security.credential.impl.StaticCredentialResolver;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureValidationParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.lang.reflect.Proxy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Direct OpenSAML Redirect decoder and signature-handler comparison for logout. */
final class OpenSamlLogoutComparatorTests {
    private static final @NonNull Path FIXTURES = Path.of("../src/test/resources/fixtures");
    private static final @NonNull String SP = "https://sp.test/Selftest";
    private static final @NonNull String IDP = "https://idp.scripted-idp.test/";
    private static final @NonNull String SLO = "https://sp.test/logout";
    private static final @NonNull String RELAY = "AAAAAAAAAAAAAAAAAAAAAA";
    private static final @NonNull String SP_REQUEST_ID = "_" + "00".repeat(20);
    private static final @NonNull String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final @NonNull String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final @NonNull Instant NOW = Instant.parse("2026-09-01T00:01:00Z");
    private static final @NonNull Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final @NonNull List<@NonNull String> REQUEST_CASES = List.of(
            "request-valid", "request-wrong-destination", "request-wrong-issuer",
            "request-future-issue", "request-expired", "request-duplicate-nameid",
            "request-unknown-extension");
    private static final @NonNull List<@NonNull String> RESPONSE_CASES = List.of(
            "response-valid", "response-wrong-destination", "response-wrong-correlation",
            "response-wrong-issuer", "response-stale-issue", "response-duplicate-status",
            "response-empty-status");

    @BeforeAll static void initializeOpenSaml() throws Exception {
        InitializationService.initialize();
    }

    @Test void idpInitiatedLogoutRequestsAgreeOnSignedSemantics() throws Exception {
        for (String name : REQUEST_CASES) {
            String query = fixture(name);
            boolean accepted = name.equals("request-valid");
            if (accepted) {
                assertEquals("minted-user", openSamlRequest(query), name + " OpenSAML");
                assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                        revetsecRequest(query), name + " Revetsec");
            } else {
                assertThrows(IllegalArgumentException.class, () -> openSamlRequest(query),
                        name + " OpenSAML semantic check");
                assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                        revetsecRequest(query), name + " Revetsec");
            }
        }
    }

    @Test void spInitiatedLogoutResponsesAgreeOnSignedSemantics() throws Exception {
        for (String name : RESPONSE_CASES) {
            String query = fixture(name);
            boolean accepted = name.equals("response-valid");
            if (accepted) {
                assertEquals(StatusCode.SUCCESS, openSamlResponse(query), name + " OpenSAML");
                assertInstanceOf(SamlLogoutResult.Succeeded.class,
                        revetsecResponse(query), name + " Revetsec");
            } else {
                assertThrows(IllegalArgumentException.class, () -> openSamlResponse(query),
                        name + " OpenSAML semantic check");
                assertInstanceOf(SamlLogoutResult.Rejected.class,
                        revetsecResponse(query), name + " Revetsec");
            }
        }
    }

    @Test void equivalentRelayEncodingInvalidatesBothBindingSignatures() throws Exception {
        for (String name : List.of("request-valid", "response-valid")) {
            String original = fixture(name);
            String changed = original.replace("&RelayState=" + RELAY,
                    "&RelayState=%41" + RELAY.substring(1));
            assertNotEquals(original, changed, name);
            assertThrows(MessageHandlerException.class, () -> verifiedMessage(changed),
                    name + " OpenSAML Redirect signature");
            if (name.startsWith("request-"))
                assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                        revetsecRequest(changed), name + " Revetsec");
            else
                assertInstanceOf(SamlLogoutResult.Rejected.class,
                        revetsecResponse(changed), name + " Revetsec");
        }
    }

    private static @NonNull String openSamlRequest(@NonNull String query) throws Exception {
        LogoutRequest request = assertInstanceOf(LogoutRequest.class, verifiedMessage(query));
        Element root = request.getDOM();
        if (request.getVersion() != SAMLVersion.VERSION_20
                || !SLO.equals(request.getDestination())
                || request.getIssuer() == null || !IDP.equals(request.getIssuer().getValue())
                || request.getIssueInstant() == null
                || request.getIssueInstant().isAfter(NOW.plusSeconds(180))
                || NOW.isAfter(request.getIssueInstant().plusSeconds(480))
                || request.getNotOnOrAfter() == null || !NOW.isBefore(request.getNotOnOrAfter())
                || request.getNameID() == null || !"minted-user".equals(request.getNameID().getValue())
                || request.getExtensions() != null
                || request.getSessionIndexes().size() != 1
                || !"session-123".equals(request.getSessionIndexes().get(0).getValue())
                || countChildren(root, ASSERTION, "Issuer") != 1
                || countChildren(root, ASSERTION, "NameID") != 1)
            throw new IllegalArgumentException("Invalid OpenSAML LogoutRequest semantics");
        return request.getNameID().getValue();
    }

    private static @NonNull String openSamlResponse(@NonNull String query) throws Exception {
        LogoutResponse response = assertInstanceOf(LogoutResponse.class, verifiedMessage(query));
        Element root = response.getDOM();
        if (response.getVersion() != SAMLVersion.VERSION_20
                || !SLO.equals(response.getDestination())
                || !SP_REQUEST_ID.equals(response.getInResponseTo())
                || response.getIssuer() == null || !IDP.equals(response.getIssuer().getValue())
                || response.getIssueInstant() == null
                || response.getIssueInstant().isAfter(NOW.plusSeconds(180))
                || NOW.isAfter(response.getIssueInstant().plusSeconds(480))
                || response.getStatus() == null || response.getStatus().getStatusCode() == null
                || !StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())
                || countChildren(root, ASSERTION, "Issuer") != 1
                || countChildren(root, PROTOCOL, "Status") != 1)
            throw new IllegalArgumentException("Invalid OpenSAML LogoutResponse semantics");
        return response.getStatus().getStatusCode().getValue();
    }

    private static @NonNull Object verifiedMessage(@NonNull String rawQuery) throws Exception {
        HttpServletRequest request = servletRequest(rawQuery);
        HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
        decoder.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
        decoder.setHttpServletRequestSupplier(() -> request);
        decoder.initialize();
        decoder.decode();
        MessageContext context = decoder.getMessageContext();
        SAMLPeerEntityContext peer = context.ensureSubcontext(SAMLPeerEntityContext.class);
        peer.setEntityId(IDP);
        peer.setRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        context.ensureSubcontext(SAMLProtocolContext.class).setProtocol(PROTOCOL);
        BasicX509Credential signing = new BasicX509Credential(certificate("idp-signing-rsa-2048"));
        SignatureValidationParameters parameters = new SignatureValidationParameters();
        parameters.setSignatureTrustEngine(new ExplicitKeySignatureTrustEngine(
                new StaticCredentialResolver(signing),
                new StaticKeyInfoCredentialResolver(signing)));
        context.ensureSubcontext(SecurityParametersContext.class)
                .setSignatureValidationParameters(parameters);
        SAML2HTTPRedirectDeflateSignatureSecurityHandler handler =
                new SAML2HTTPRedirectDeflateSignatureSecurityHandler();
        handler.setHttpServletRequestSupplier(() -> request);
        handler.initialize();
        handler.invoke(context);
        assertTrue(peer.isAuthenticated(), "OpenSAML must authenticate the Redirect signature");
        return context.getMessage();
    }

    private static @NonNull HttpServletRequest servletRequest(@NonNull String rawQuery) {
        Map<String, String[]> parameters = new HashMap<>();
        for (String field : rawQuery.split("&")) {
            int equals = field.indexOf('=');
            if (equals < 1) throw new IllegalArgumentException("Invalid query fixture");
            String key = field.substring(0, equals);
            String value = URLDecoder.decode(field.substring(equals + 1), StandardCharsets.UTF_8);
            if (parameters.putIfAbsent(key, new String[]{value}) != null)
                throw new IllegalArgumentException("Duplicate fixture parameter");
        }
        return (HttpServletRequest) Proxy.newProxyInstance(
                HttpServletRequest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (proxy, method, arguments) -> switch (method.getName()) {
                    case "getMethod" -> "GET";
                    case "getQueryString" -> rawQuery;
                    case "getParameterMap" -> parameters;
                    case "getParameter" -> {
                        String[] values = parameters.get(arguments[0]);
                        yield values == null ? null : values[0];
                    }
                    case "getParameterValues" -> parameters.get(arguments[0]);
                    case "getContentType" -> null;
                    case "toString" -> "SLO fixture request";
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static @NonNull SamlLogoutRequestResult revetsecRequest(@NonNull String query)
            throws Exception {
        return serviceProvider().acceptLogoutRequestResult(revetsecMessage(query), identityProvider());
    }

    private static @NonNull SamlLogoutResult revetsecResponse(@NonNull String query)
            throws Exception {
        SamlServiceProvider provider = serviceProvider();
        SamlIdentityProvider identityProvider = identityProvider();
        String loginXml = Files.readString(FIXTURES.resolve("scripted-idp/response-rsa256.xml"));
        String form = "SAMLResponse=" + URLEncoder.encode(Base64.getEncoder().encodeToString(
                loginXml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        SamlPostBindingMessage login = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(form.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        SamlSessionReference session = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                provider.completeUnsolicitedAuthenticationResult(login, identityProvider))
                .getAuthentication().getSessionReference();
        SamlLogoutRedirectResult.Prepared begin = assertInstanceOf(
                SamlLogoutRedirectResult.Prepared.class,
                provider.beginLogoutResult(identityProvider, session));
        assertEquals(SP_REQUEST_ID, begin.getPendingLogout().getRequestId());
        assertEquals(RELAY, begin.getPendingLogout().getRelayStateHandle());
        byte[] key = new byte[32];
        for (int index = 0; index < key.length; index++) key[index] = (byte) (index + 1);
        StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64(
                "slo-comparator", Base64.getEncoder().encodeToString(key)))
                .clock(CLOCK).build();
        PendingSamlLogoutSource pending = PendingSamlLogoutSource.fromSealedForm(
                begin.getPendingLogout().toSealedForm(sealer, "slo-comparator"),
                sealer, "slo-comparator");
        return provider.completeLogoutResult(revetsecMessage(query), pending, identityProvider);
    }

    private static @NonNull SamlRedirectBindingMessage revetsecMessage(@NonNull String query) {
        return assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(query)).getMessage();
    }

    private static @NonNull SamlServiceProvider serviceProvider() throws Exception {
        // Fix the public beginLogout result's ID and RelayState to the Python-signed fixture.
        SecureRandom zeroRandom = new SecureRandom() {
            @Override public void nextBytes(byte @NonNull [] bytes) { Arrays.fill(bytes, (byte) 0); }
        };
        SamlCredential signing = SamlCredential.fromPem(
                Files.readString(FIXTURES.resolve("keys/sp-signing-rsa-2048-key.pem")),
                Files.readString(FIXTURES.resolve("keys/sp-signing-rsa-2048-cert.pem")));
        return SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create("https://sp.test/acs"))
                .singleLogoutServiceUrl(URI.create(SLO))
                .signingCredential(signing)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 16))
                .random(zeroRandom).clock(CLOCK).build();
    }

    private static @NonNull SamlIdentityProvider identityProvider() throws Exception {
        return SamlIdentityProvider.withEntityId(IDP)
                .connectionId("opensaml-slo-differential")
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .redirectSingleLogoutService(URI.create("https://idp.scripted-idp.test/slo"))
                .signingKeys(List.of(certificate("idp-signing-rsa-2048").getPublicKey()))
                .compatibility(Set.of(SamlCompatibilityMode.UNSOLICITED_RESPONSES))
                .build();
    }

    private static @NonNull X509Certificate certificate(@NonNull String name) throws Exception {
        try (var input = Files.newInputStream(FIXTURES.resolve("keys/" + name + "-cert.pem"))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
    }

    private static int countChildren(@NonNull Element root, @NonNull String namespace,
            @NonNull String localName) {
        int count = 0;
        for (Node child = root.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element element && namespace.equals(element.getNamespaceURI())
                    && localName.equals(element.getLocalName())) count++;
        return count;
    }

    private static @NonNull String fixture(@NonNull String name) throws Exception {
        Properties corpus = new Properties();
        try (var input = Files.newBufferedReader(FIXTURES.resolve("scripted-idp/slo-corpus.properties"),
                StandardCharsets.US_ASCII)) {
            corpus.load(input);
        }
        assertEquals(14, corpus.size(), "SLO corpus changed");
        String query = corpus.getProperty(name);
        if (query == null || query.isEmpty()) throw new IllegalArgumentException("Missing SLO fixture: " + name);
        return query;
    }
}
