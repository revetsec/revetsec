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

import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.xml.SecureXmlParser;
import com.revetsec.internal.xml.SamlResponseStructure;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

import javax.xml.XMLConstants;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.ArrayDeque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/** SAML ingress and identity-release fuzz checks using independently minted signed fixtures. */
public final class SamlFuzzTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull String IDP = "https://idp.scripted-idp.test/";
    private static final @NonNull Pattern SIGNATURE = Pattern.compile(
            "<ds:Signature\\b[^>]*>.*?</ds:Signature>", Pattern.DOTALL);
    private static final @NonNull List<@NonNull String> FIXTURES = List.of(
            "scripted-idp/assertion-signxml.xml",
            "scripted-idp/matrix-response-rsa-sha256-sha256.xml",
            "saml-independent/case4-encrypted-assertion-gcm-rsa-oaep-sha256-mgf1sha256.xml");

    /** Raw POST bytes never release XML before exact form and Base64 parsing. */
    @FuzzTest(maxDuration = "5m")
    public void postBindingKeepsRawOctetsAndFixedRejections(byte @NonNull [] input) {
        SamlPostBindingParseResult result = SamlPostBindingMessage.fromFormBodyResult(input,
                List.of("application/x-www-form-urlencoded"), null);
        if (result instanceof SamlPostBindingParseResult.Parsed parsed) {
            byte[] xml = parsed.getMessage().xml();
            Assertions.assertTrue(xml.length > 0 && xml.length <= 256 * 1024);
            Assertions.assertEquals("SamlPostBindingMessage{<untrusted>}",
                    parsed.getMessage().toString());
            Assertions.assertEquals("SamlPostBindingParseResult.Parsed{<untrusted>}",
                    parsed.toString());
            if (input.length > 0) {
                byte old = input[0]; input[0] ^= 1;
                Assertions.assertArrayEquals(xml, parsed.getMessage().xml());
                input[0] = old;
            }
            xml[0] ^= 1;
            Assertions.assertNotEquals(xml[0], parsed.getMessage().xml()[0]);
        } else {
            SamlPostBindingParseResult.Rejected rejected = Assertions.assertInstanceOf(
                    SamlPostBindingParseResult.Rejected.class, result);
            Assertions.assertNotNull(rejected.getReason());
            Assertions.assertEquals("SamlPostBindingParseResult.Rejected{" + rejected.getReason() + "}",
                    rejected.toString());
        }
    }

    /** Raw Redirect bytes exercise percent decoding, deflate and signed-query framing. */
    @FuzzTest(maxDuration = "5m")
    public void redirectBindingKeepsRawOctetsAndBoundedInflation(byte @NonNull [] input) {
        String query = new String(input, StandardCharsets.ISO_8859_1);
        SamlRedirectBindingParseResult result = SamlRedirectBindingMessage.fromRawQueryResult(query);
        if (result instanceof SamlRedirectBindingParseResult.Parsed parsed) {
            SamlRedirectBindingMessage message = parsed.getMessage();
            byte[] xml = message.xml();
            Assertions.assertTrue(xml.length > 0 && xml.length <= 131072);
            Assertions.assertNotNull(message.getKind());
            Assertions.assertEquals("SamlRedirectBindingMessage{<redacted>}", message.toString());
            xml[0] ^= 1;
            Assertions.assertNotEquals(xml[0], message.xml()[0]);
        } else {
            Assertions.assertSame(SamlRedirectBindingParseResult.Rejected.INSTANCE, result);
        }
    }

    /** Arbitrary XML either stays untrusted or yields bounded, locally parsed metadata. */
    @FuzzTest(maxDuration = "5m")
    public void metadataParsingCannotApproveAnUntrustedDescriptor(byte @NonNull [] input) throws Exception {
        SecureXmlParser.Result xml = SecureXmlParser.parseMetadata(input);
        if (xml instanceof SecureXmlParser.Result.Accepted accepted)
            Assertions.assertNotNull(accepted.getDocument().getDocumentElement());
        else if (xml instanceof SecureXmlParser.Result.Rejected rejected)
            Assertions.assertNotNull(rejected.getReason());
        else Assertions.assertSame(SecureXmlParser.Result.Unavailable.INSTANCE, xml);

        SamlIdentityProviderMetadataResult result = SamlIdentityProviderMetadata.fromXmlResult(input,
                null, CLOCK);
        if (result instanceof SamlIdentityProviderMetadataResult.Parsed parsed) {
            SamlIdentityProviderMetadata metadata = parsed.getMetadata();
            Assertions.assertFalse(metadata.getEntityId().isEmpty());
            Assertions.assertTrue(metadata.getEntityId().length() <= 2048);
            Assertions.assertFalse(metadata.getSigningCertificates().isEmpty());
            Assertions.assertTrue(metadata.getSigningCertificates().size() <= 8);
            for (var certificate : metadata.getSigningCertificates())
                Assertions.assertTrue(certificate.getEncoded().length <= 24576);
            Assertions.assertTrue(metadata.getAuthorizedIdentifierScopes().size() <= 32);
            for (String scope : metadata.getAuthorizedIdentifierScopes()) {
                Assertions.assertFalse(scope.isEmpty());
                Assertions.assertTrue(scope.length() <= 255);
            }
            Assertions.assertTrue(metadata.getRedirectSingleSignOnService().isPresent()
                    || metadata.getPostSingleSignOnService().isPresent());
            for (URI endpoint : List.of(metadata.getRedirectSingleSignOnService(),
                    metadata.getPostSingleSignOnService(), metadata.getRedirectSingleLogoutService())
                    .stream().flatMap(java.util.Optional::stream).toList()) {
                Assertions.assertEquals("https", endpoint.getScheme().toLowerCase(java.util.Locale.ROOT));
                Assertions.assertNotNull(endpoint.getHost());
                Assertions.assertNull(endpoint.getRawUserInfo());
                Assertions.assertNull(endpoint.getRawFragment());
            }
        } else Assertions.assertTrue(result instanceof SamlIdentityProviderMetadataResult.Rejected
                || result instanceof SamlIdentityProviderMetadataResult.Unavailable);
    }

    /** Arbitrary SAML XML cannot smuggle duplicate IDs through the single parser and response walker. */
    @FuzzTest(maxDuration = "5m")
    public void xmlParserAndWalkerRejectAmbiguousDocuments(byte @NonNull [] input) {
        SecureXmlParser.Result parsed = SecureXmlParser.parseResponse(input);
        if (parsed instanceof SecureXmlParser.Result.Rejected rejected) {
            Assertions.assertNotNull(rejected.getReason());
            return;
        }
        if (parsed == SecureXmlParser.Result.Unavailable.INSTANCE) return;
        Document document = Assertions.assertInstanceOf(SecureXmlParser.Result.Accepted.class, parsed)
                .getDocument();
        Element root = document.getDocumentElement();
        Assertions.assertNotNull(root);
        Set<String> identifiers = new HashSet<>();
        ArrayDeque<Node> pending = new ArrayDeque<>();
        pending.add(root);
        while (!pending.isEmpty()) {
            Node node = pending.removeFirst();
            if (node instanceof Element element) {
                NamedNodeMap attributes = element.getAttributes();
                for (int index = 0; index < attributes.getLength(); index++) {
                    Attr attribute = (Attr) attributes.item(index);
                    String local = attribute.getLocalName();
                    if (!XMLConstants.XMLNS_ATTRIBUTE_NS_URI.equals(attribute.getNamespaceURI())
                            && ("ID".equals(local) || "Id".equals(local) || "id".equals(local)
                                    || "AssertionID".equals(local)))
                        Assertions.assertTrue(identifiers.add(attribute.getValue()),
                                "one XML document must not contain two ID-like values");
                }
            }
            for (Node child = node.getFirstChild(); child != null; child = child.getNextSibling())
                pending.addLast(child);
        }
        SamlResponseStructure.Result structure = SamlResponseStructure.inspect(document);
        if (structure instanceof SamlResponseStructure.Accepted accepted)
            Assertions.assertSame(root, accepted.getShape().getResponse());
        else Assertions.assertSame(SamlResponseStructure.Rejected.INSTANCE, structure);
    }

    /** GCM ciphertext or wrapped-key changes cannot release a claimed identity. */
    @FuzzTest(maxDuration = "5m")
    public void encryptedCiphertextChangesCannotReleaseIdentity(byte @NonNull [] input) throws Exception {
        String original = resource(FIXTURES.get(2));
        SamlAuthenticationResult.Succeeded control = Assertions.assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class, check(original));
        Assertions.assertFalse(control.getAuthentication().getNameId()
                .orElseThrow().getValue().isEmpty());
        var matcher = Pattern.compile("(?s)<xenc:CipherValue>([^<]+)</xenc:CipherValue>")
                .matcher(original);
        int carrier = octet(input, 0) % 2;
        Assertions.assertTrue(matcher.find());
        if (carrier == 1) Assertions.assertTrue(matcher.find());
        byte[] wire = Base64.getMimeDecoder().decode(matcher.group(1));
        Assertions.assertTrue(wire.length > 0);
        int position = octet(input, 1) % wire.length;
        wire[position] ^= (byte) (1 << (octet(input, 2) % 8));
        String changed = original.substring(0, matcher.start(1))
                + Base64.getEncoder().encodeToString(wire)
                + original.substring(matcher.end(1));
        Assertions.assertNotEquals(original, changed);
        Assertions.assertInstanceOf(SamlAuthenticationResult.Rejected.class, check(changed));
    }

    /** Unsigned wrapping content, signed-field edits and encrypted carriers cannot change released identity. */
    @FuzzTest(maxDuration = "5m")
    public void signedAndEncryptedResponsesNeverReleaseMutatedIdentity(byte @NonNull [] input)
            throws Exception {
        int fixture = octet(input, 0) % FIXTURES.size();
        String original = resource(FIXTURES.get(fixture));
        SamlAuthentication baseline = Assertions.assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                check(original)).getAuthentication();
        String candidate = mutate(original, input);
        SamlAuthenticationResult result = check(candidate);
        if (result instanceof SamlAuthenticationResult.Succeeded succeeded) {
            SamlAuthentication actual = succeeded.getAuthentication();
            Assertions.assertEquals(baseline.getIdentityProviderConnectionId(),
                    actual.getIdentityProviderConnectionId());
            Assertions.assertEquals(baseline.getIdentityProviderEntityId(),
                    actual.getIdentityProviderEntityId());
            Assertions.assertEquals(baseline.getAssertionId(), actual.getAssertionId());
            assertNameIdSame(baseline.getNameId().orElseThrow(), actual.getNameId().orElseThrow());
            Assertions.assertEquals(baseline.getSubjectKey().map(SamlSubjectKey::toStableString),
                    actual.getSubjectKey().map(SamlSubjectKey::toStableString));
            Assertions.assertEquals(baseline.getSubjectId(), actual.getSubjectId());
            Assertions.assertEquals(baseline.getPairwiseId(), actual.getPairwiseId());
            Assertions.assertEquals(baseline.getAuthnInstant(), actual.getAuthnInstant());
            Assertions.assertEquals(baseline.getSessionIndex(), actual.getSessionIndex());
            Assertions.assertEquals(baseline.getSessionNotOnOrAfter(), actual.getSessionNotOnOrAfter());
            Assertions.assertEquals(baseline.getAuthnContextClassRef(), actual.getAuthnContextClassRef());
            Assertions.assertEquals(baseline.getAttributes().size(), actual.getAttributes().size());
            for (int index = 0; index < baseline.getAttributes().size(); index++)
                assertAttributeSame(baseline.getAttributes().get(index), actual.getAttributes().get(index));
            Assertions.assertEquals(baseline.isResponseSigned(), actual.isResponseSigned());
            Assertions.assertEquals(baseline.isAssertionSigned(), actual.isAssertionSigned());
            Assertions.assertEquals(baseline.isAssertionEncrypted(), actual.isAssertionEncrypted());
        } else Assertions.assertInstanceOf(SamlAuthenticationResult.Rejected.class, result);
    }

    private static @NonNull String mutate(@NonNull String original, byte @NonNull [] input)
            throws IOException {
        int operation = octet(input, 1) % 10;
        if (operation == 0) return original;
        String signed = resource(FIXTURES.get(0));
        String assertion = section(signed, "<saml:Assertion ", "</saml:Assertion>");
        String marker = Integer.toHexString(octet(input, 2)) + Integer.toHexString(octet(input, 3));
        String attacker = SIGNATURE.matcher(assertion).replaceFirst("")
                .replace("minted-user", "attacker-user-" + marker)
                .replace("_mint_assertion_", "_attacker_assertion_");
        String duplicateId = SIGNATURE.matcher(assertion).replaceFirst("")
                .replace("minted-user", "attacker-user-" + marker);
        String candidate = switch (operation) {
            case 1 -> original.replace("</samlp:Response>", attacker + "</samlp:Response>");
            case 2 -> original.replace("<samlp:Status>",
                    "<samlp:Extensions>" + attacker + "</samlp:Extensions><samlp:Status>");
            case 3 -> original.replace("<samlp:Status>",
                    "<ds:Object xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
                            + attacker + "</ds:Object><samlp:Status>");
            case 4 -> original.replace("</samlp:Response>", duplicateId + "</samlp:Response>");
            case 5 -> original.replace("<samlp:Status>",
                    "<saml:Issuer>https://attacker.example.test/</saml:Issuer><samlp:Status>");
            case 6 -> original.replace("https://sp.test/acs", "https://attacker.example.test/acs");
            case 7 -> original.replace("<samlp:Status>",
                    "<samlp:Status><samlp:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/>"
                            + "</samlp:Status><samlp:Status>");
            case 8 -> original.replace("minted-user", "attacker-user-" + marker)
                    .replace("<saml:EncryptedAssertion", "<saml:Assertion ID='_attacker_assertion_"
                            + marker + "'><saml:Issuer>https://attacker.example.test/</saml:Issuer>"
                            + "</saml:Assertion><saml:EncryptedAssertion");
            default -> {
                int position = Math.min(original.length() - 1,
                        (octet(input, 2) << 8 | octet(input, 3)) % original.length());
                yield original.substring(0, position) + (char) ('A' + octet(input, 4) % 26)
                        + original.substring(position + 1);
            }
        };
        if (operation != 9) Assertions.assertNotEquals(original, candidate,
                "mutation did not reach a fixture field");
        return candidate;
    }

    private static void assertNameIdSame(@NonNull SamlNameId expected, @NonNull SamlNameId actual) {
        Assertions.assertEquals(expected.getValue(), actual.getValue());
        Assertions.assertEquals(expected.getFormat(), actual.getFormat());
        Assertions.assertEquals(expected.getNameQualifier(), actual.getNameQualifier());
        Assertions.assertEquals(expected.getSpNameQualifier(), actual.getSpNameQualifier());
    }

    private static void assertAttributeSame(@NonNull SamlAttribute expected, @NonNull SamlAttribute actual) {
        Assertions.assertEquals(expected.getName(), actual.getName());
        Assertions.assertEquals(expected.getNameFormat(), actual.getNameFormat());
        Assertions.assertEquals(expected.getFriendlyName(), actual.getFriendlyName());
        Assertions.assertEquals(expected.getTypedValues().size(), actual.getTypedValues().size());
        for (int index = 0; index < expected.getTypedValues().size(); index++) {
            SamlAttributeValue left = expected.getTypedValues().get(index);
            SamlAttributeValue right = actual.getTypedValues().get(index);
            Assertions.assertEquals(left.getKind(), right.getKind());
            Assertions.assertEquals(left.getText(), right.getText());
            Assertions.assertEquals(left.getNameId().isPresent(), right.getNameId().isPresent());
            if (left.getNameId().isPresent())
                assertNameIdSame(left.getNameId().orElseThrow(), right.getNameId().orElseThrow());
        }
    }

    private static @NonNull String section(@NonNull String xml, @NonNull String open,
            @NonNull String close) {
        int start = xml.indexOf(open);
        int end = xml.indexOf(close, start);
        if (start < 0 || end < 0) throw new IllegalArgumentException("fixture shape changed");
        return xml.substring(start, end + close.length());
    }

    private static @NonNull SamlAuthenticationResult check(@NonNull String xml) throws Exception {
        SamlCredential credential = SamlCredential.fromPem(
                resource("saml-independent/keys/sp-rsa-2048.key"),
                resource("saml-independent/keys/sp-rsa-2048.crt"));
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.test/Selftest")
                .assertionConsumerServiceUrl(URI.create("https://sp.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 16))
                .decryptionCredentials(List.of(credential)).clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("fuzz-fixture")
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .signingKeys(List.of(
                        Pem.parseCertificate(resource("keys/idp-signing-rsa-2048-cert.pem")).getPublicKey(),
                        Pem.parseCertificate(resource("saml-independent/keys/idp-rsa-2048.crt"))
                                .getPublicKey()))
                .allowUnsolicitedResponses(true).build();
        String encoded = java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        SamlPostBindingMessage message = Assertions.assertInstanceOf(
                SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded)
                        .getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        return sp.completeUnsolicitedAuthenticationResult(message, idp);
    }

    private static int octet(byte @NonNull [] input, int offset) {
        return offset < input.length ? input[offset] & 0xff : 0;
    }

    private static @NonNull String resource(@NonNull String name) throws IOException {
        try (var input = SamlFuzzTests.class.getResourceAsStream("/fixtures/" + name)) {
            return new String(java.util.Objects.requireNonNull(input, name).readAllBytes(),
                    StandardCharsets.UTF_8);
        }
    }
}
