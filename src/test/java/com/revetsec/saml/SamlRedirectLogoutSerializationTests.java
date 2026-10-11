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

import com.revetsec.internal.xml.SecureXmlParser;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Checks the exact identity, correlation and status fields sent in signed Redirect logout. */
final class SamlRedirectLogoutSerializationTests {
    private static final @NonNull String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final @NonNull String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final @NonNull String RELAY = "@AZ[az{09/:-._~+%";

    @Test void requestBindsAllSessionIdentityFieldsIntoTheSignedXml() throws Exception {
        SamlCredential credential = credential();
        SamlNameId nameId = new SamlNameId("alice", SamlNameId.PERSISTENT,
                "https://idp.example.test", "https://sp.example.test", "sp-original");
        SamlSessionReference session = new SamlSessionReference("connection-one",
                "https://idp.example.test", nameId, "session-123", null);
        URI destination = URI.create("https://idp.example.test/slo");
        URI redirect = Objects.requireNonNull(SamlRedirectLogout.request(destination,
                "https://sp.example.test", session, "_request-123", RELAY,
                Instant.parse("2026-10-11T00:00:00Z"), credential.privateKey()));
        assertTrue(redirect.getRawQuery().contains(
                "&RelayState=%40AZ%5Baz%7B09%2F%3A-._~%2B%25"));
        SamlRedirectBindingMessage message = parse(redirect);
        assertEquals(SamlRedirectBindingMessage.Kind.REQUEST, message.getKind());
        assertEquals(Optional.of(RELAY), message.getRelayState());
        assertTrue(message.verify(List.of(credential.getCertificate().getPublicKey())));
        String xml = new String(message.xml(), StandardCharsets.UTF_8);
        assertTrue(xml.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        Element root = root(message);
        assertEquals(PROTOCOL, root.getNamespaceURI());
        assertEquals("LogoutRequest", root.getLocalName());
        assertEquals("_request-123", root.getAttribute("ID"));
        assertEquals("2.0", root.getAttribute("Version"));
        assertEquals("2026-10-11T00:00:00Z", root.getAttribute("IssueInstant"));
        assertEquals(destination.toASCIIString(), root.getAttribute("Destination"));
        assertEquals(List.of("Issuer", "NameID", "SessionIndex"), children(root));
        assertEquals("https://sp.example.test", one(root, ASSERTION, "Issuer").getTextContent());
        Element emitted = one(root, ASSERTION, "NameID");
        assertEquals("alice", emitted.getTextContent());
        assertEquals(SamlNameId.PERSISTENT, emitted.getAttribute("Format"));
        assertEquals("https://idp.example.test", emitted.getAttribute("NameQualifier"));
        assertEquals("https://sp.example.test", emitted.getAttribute("SPNameQualifier"));
        assertEquals("sp-original", emitted.getAttribute("SPProvidedID"));
        assertEquals("session-123", one(root, PROTOCOL, "SessionIndex").getTextContent());

        SamlSessionReference withoutIndex = new SamlSessionReference("connection-one",
                "https://idp.example.test", nameId, null, null);
        Element noIndex = root(parse(Objects.requireNonNull(SamlRedirectLogout.request(destination,
                "https://sp.example.test", withoutIndex, "_request-456", "relay",
                Instant.parse("2026-10-11T00:00:00Z"), credential.privateKey()))));
        assertEquals(List.of("Issuer", "NameID"), children(noIndex));
    }

    @Test void responseBindsCorrelationAndEachApplicationStatusIntoSignedXml() throws Exception {
        SamlCredential credential = credential();
        URI destination = URI.create("https://idp.example.test/slo");
        for (SamlLogoutStatus status : SamlLogoutStatus.values()) {
            String relay = status == SamlLogoutStatus.SUCCESS ? RELAY : null;
            URI redirect = Objects.requireNonNull(SamlRedirectLogout.response(destination,
                    "https://sp.example.test", "_response-123", "_idp-request-123",
                    relay, Instant.parse("2026-10-11T00:00:00Z"), status,
                    credential.privateKey()));
            SamlRedirectBindingMessage message = parse(redirect);
            assertEquals(SamlRedirectBindingMessage.Kind.RESPONSE, message.getKind());
            assertEquals(Optional.ofNullable(relay), message.getRelayState());
            assertTrue(message.verify(List.of(credential.getCertificate().getPublicKey())));
            assertTrue(new String(message.xml(), StandardCharsets.UTF_8)
                    .startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
            Element root = root(message);
            assertEquals(PROTOCOL, root.getNamespaceURI());
            assertEquals("LogoutResponse", root.getLocalName());
            assertEquals("_response-123", root.getAttribute("ID"));
            assertEquals("2.0", root.getAttribute("Version"));
            assertEquals("2026-10-11T00:00:00Z", root.getAttribute("IssueInstant"));
            assertEquals(destination.toASCIIString(), root.getAttribute("Destination"));
            assertEquals("_idp-request-123", root.getAttribute("InResponseTo"));
            assertEquals(List.of("Issuer", "Status"), children(root));
            assertEquals("https://sp.example.test", one(root, ASSERTION, "Issuer").getTextContent());
            Element value = one(one(root, PROTOCOL, "Status"), PROTOCOL, "StatusCode");
            assertEquals(status.uri(), value.getAttribute("Value"));
        }
    }

    @Test void outboundIdentifiersConsumeTheInjectedRandomBytes() {
        SecureRandom random = new SecureRandom() {
            @Override public void nextBytes(byte @NonNull [] bytes) {
                Arrays.fill(bytes, (byte) 0xAB);
            }
        };
        assertEquals("_" + "AB".repeat(20), SamlRedirectLogout.id(random));
        assertEquals("q6urq6urq6urq6urq6urqw", SamlRedirectLogout.relay(random));
    }

    @Test void outboundSigningAllowsTheExactXmlLimitAndRejectsTheNextByte() throws Exception {
        SamlCredential credential = credential();
        URI destination = URI.create("https://idp.example.test/slo");
        byte[] maximum = new byte[16384];
        Arrays.fill(maximum, (byte) 'A');
        assertDoesNotThrow(() -> SamlRedirectLogout.sign(destination, "SAMLRequest",
                maximum, null, credential.privateKey()));
        byte[] tooLarge = Arrays.copyOf(maximum, maximum.length + 1);
        assertThrows(IllegalArgumentException.class,
                () -> SamlRedirectLogout.sign(destination, "SAMLRequest",
                        tooLarge, null, credential.privateKey()));
    }

    private static @NonNull SamlCredential credential() throws Exception {
        Path keys = Path.of("src/test/resources/fixtures/keys");
        return SamlCredential.fromPem(
                Files.readString(keys.resolve("sp-signing-rsa-2048-key.pem")),
                Files.readString(keys.resolve("sp-signing-rsa-2048-cert.pem")));
    }

    private static @NonNull SamlRedirectBindingMessage parse(@NonNull URI redirect) {
        return assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(redirect.getRawQuery())).getMessage();
    }

    private static @NonNull Element root(@NonNull SamlRedirectBindingMessage message) {
        return assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(message.xml())).getDocument().getDocumentElement();
    }

    private static @NonNull Element one(@NonNull Element parent, @NonNull String namespace,
            @NonNull String localName) {
        var matches = parent.getElementsByTagNameNS(namespace, localName);
        assertEquals(1, matches.getLength(), localName);
        return assertInstanceOf(Element.class, matches.item(0));
    }

    private static @NonNull List<@NonNull String> children(@NonNull Element parent) {
        List<String> names = new ArrayList<>();
        for (Node child = parent.getFirstChild(); child != null; child = child.getNextSibling())
            if (child instanceof Element element) names.add(element.getLocalName());
        return List.copyOf(names);
    }
}
