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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlRedirectAuthnRequestTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:00:00Z"), ZoneOffset.UTC);
    private static final @NonNull URI ACS = URI.create("https://sp.example.test/acs");
    private static final @NonNull URI IDP = URI.create("https://idp.example.test/sso?tenant=one");

    @Test void writesRawDeflateAndSignsExactRedirectQuery() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        SamlRedirectAuthnRequest.Prepared prepared = assertInstanceOf(SamlRedirectAuthnRequest.Prepared.class,
                SamlRedirectAuthnRequest.prepare("https://sp.example.test/?x=1&y=2", ACS, IDP,
                        pair.getPrivate(), true, new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        assertTrue(prepared.signed());
        assertEquals(41, prepared.requestId().length());
        assertEquals(22, prepared.relayState().length());
        assertEquals(Instant.parse("2026-10-09T00:05:00Z"), prepared.expiresAt());
        String query = prepared.redirect().getRawQuery();
        assertTrue(query.startsWith("tenant=one&SAMLRequest="));
        int signatureStart = query.indexOf("&Signature=");
        String signed = query.substring("tenant=one&".length(), signatureStart);
        String encodedSignature = query.substring(signatureStart + "&Signature=".length());
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pair.getPublic());
        verifier.update(signed.getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(Base64.getDecoder().decode(URLDecoder.decode(encodedSignature,
                StandardCharsets.UTF_8))));
        String encodedRequest = signed.substring("SAMLRequest=".length(), signed.indexOf('&'));
        assertEquals(URLEncoder.encode(URLDecoder.decode(encodedRequest, StandardCharsets.UTF_8),
                StandardCharsets.UTF_8), encodedRequest);
        String encodedRelay = signed.substring(signed.indexOf("&RelayState=") + "&RelayState=".length(),
                signed.indexOf("&SigAlg="));
        assertEquals(URLEncoder.encode(prepared.relayState(), StandardCharsets.UTF_8), encodedRelay);
        String encodedAlgorithm = signed.substring(signed.indexOf("&SigAlg=") + "&SigAlg=".length());
        assertEquals(URLEncoder.encode("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                StandardCharsets.UTF_8), encodedAlgorithm);
        String xml = inflate(Base64.getDecoder().decode(URLDecoder.decode(encodedRequest, StandardCharsets.UTF_8)));
        assertTrue(xml.contains("ID=\"" + prepared.requestId() + "\""));
        assertTrue(xml.contains("InResponseTo=") == false);
        assertTrue(xml.contains("https://sp.example.test/?x=1&amp;y=2"));
        assertTrue(xml.contains("Version=\"2.0\""));
        assertTrue(xml.contains("IssueInstant=\"2026-10-09T00:00:00Z\""));
        assertTrue(xml.contains("Destination=\"" + IDP + "\""));
        assertTrue(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.test/acs\""));
        assertTrue(xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""));
        assertTrue(xml.contains("<saml:Issuer>https://sp.example.test/?x=1&amp;y=2</saml:Issuer>"));
        assertTrue(xml.contains("AllowCreate=\"true\""));
        assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8)));
        assertFalse(xml.contains("<ds:Signature"));
    }

    @Test void postRequestCarriesRequestedPolicyInWellFormedXml() throws Exception {
        SamlAuthenticationRequestOptions options = SamlAuthenticationRequestOptions.builder()
                .forceAuthn(true)
                .requestedAuthnContextClassRefs(List.of("urn:example:loa:high"))
                .build();
        SamlRedirectAuthnRequest.PostPrepared prepared = assertInstanceOf(
                SamlRedirectAuthnRequest.PostPrepared.class,
                SamlRedirectAuthnRequest.preparePost("https://sp.example.test/saml", ACS, IDP,
                        null, false, new SecureRandom(), CLOCK, Duration.ofMinutes(5), options));
        String xml = new String(Base64.getDecoder().decode(
                prepared.form().getFields().get("SAMLRequest")), StandardCharsets.UTF_8);
        assertTrue(xml.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8)));
        assertTrue(xml.contains("ID=\"" + prepared.requestId() + "\""));
        assertTrue(xml.contains("Version=\"2.0\""));
        assertTrue(xml.contains("IssueInstant=\"2026-10-09T00:00:00Z\""));
        assertTrue(xml.contains("Destination=\"" + IDP + "\""));
        assertTrue(xml.contains("AssertionConsumerServiceURL=\"" + ACS + "\""));
        assertTrue(xml.contains("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\""));
        assertTrue(xml.contains("ForceAuthn=\"true\""));
        assertTrue(xml.contains("<saml:Issuer>https://sp.example.test/saml</saml:Issuer>"));
        assertTrue(xml.contains("AllowCreate=\"true\""));
        assertTrue(xml.contains("Comparison=\"exact\""));
        assertTrue(xml.contains("<saml:AuthnContextClassRef>urn:example:loa:high"
                + "</saml:AuthnContextClassRef>"));
    }

    @Test void signedPostRequestHasDirectVerifiableSignatureAndRequiredChildOrder() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        SamlRedirectAuthnRequest.PostPrepared prepared = assertInstanceOf(
                SamlRedirectAuthnRequest.PostPrepared.class,
                SamlRedirectAuthnRequest.preparePost("https://sp.example.test/saml", ACS, IDP,
                        pair.getPrivate(), true, new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        String xml = new String(Base64.getDecoder().decode(
                prepared.form().getFields().get("SAMLRequest")), StandardCharsets.UTF_8);
        Document document = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8))).getDocument();
        Element root = document.getDocumentElement();
        assertEquals("AuthnRequest", root.getLocalName());
        assertEquals(prepared.requestId(), root.getAttribute("ID"));
        Element issuer = Objects.requireNonNull(firstElement(root));
        assertEquals("Issuer", issuer.getLocalName());
        Element signature = Objects.requireNonNull(nextElement(issuer));
        assertEquals("Signature", signature.getLocalName());
        Element policy = Objects.requireNonNull(nextElement(signature));
        assertEquals("NameIDPolicy", policy.getLocalName());
        assertEquals("true", policy.getAttribute("AllowCreate"));
        assertNull(nextElement(policy));
        root.setIdAttributeNS(null, "ID", true);
        DOMValidateContext context = new DOMValidateContext(pair.getPublic(), signature);
        XMLSignature checked = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(context);
        assertTrue(checked.validate(context));
        assertEquals("#" + prepared.requestId(), checked.getSignedInfo().getReferences().get(0).getURI());
    }

    private static @Nullable Element firstElement(@NonNull Element parent) {
        for (Node node = parent.getFirstChild(); node != null; node = node.getNextSibling())
            if (node instanceof Element element) return element;
        return null;
    }

    private static @Nullable Element nextElement(@NonNull Element sibling) {
        for (Node node = sibling.getNextSibling(); node != null; node = node.getNextSibling())
            if (node instanceof Element element) return element;
        return null;
    }

    @Test void passiveRequestIsExplicitAndUnsignedRedirectReportsItsSigningState() throws Exception {
        SamlAuthenticationRequestOptions options = SamlAuthenticationRequestOptions.builder()
                .passive(true).build();
        SamlRedirectAuthnRequest.Prepared prepared = assertInstanceOf(
                SamlRedirectAuthnRequest.Prepared.class,
                SamlRedirectAuthnRequest.prepare("sp", ACS, IDP, null, false,
                        new SecureRandom(), CLOCK, Duration.ofMinutes(5), options));
        assertFalse(prepared.signed());
        String query = prepared.redirect().getRawQuery();
        assertFalse(query.contains("SigAlg="));
        assertFalse(query.contains("Signature="));
        String encoded = query.substring(query.indexOf("SAMLRequest=") + "SAMLRequest=".length(),
                query.indexOf("&RelayState="));
        String xml = inflate(Base64.getDecoder().decode(URLDecoder.decode(encoded, StandardCharsets.UTF_8)));
        assertTrue(xml.contains("IsPassive=\"true\""));
        assertFalse(xml.contains("ForceAuthn="));
    }

    @Test void exactConfigurationCapsAreAcceptedAndOversizeRequestXmlIsRejected() {
        for (boolean post : new boolean[] {false, true}) {
            assertPrepared(post, prepare(post, "s".repeat(2048), ACS, IDP, null,
                    new SecureRandom(), CLOCK, Duration.ofMinutes(15)));
            URI lastAllowedQuery = URI.create("https://idp.example.test/sso?x=" + "a".repeat(2046));
            assertPrepared(post, prepare(post, "sp", ACS, lastAllowedQuery, null,
                    new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
            URI oversizedAcs = URI.create("https://sp.example.test/acs?x=" + "a".repeat(16_384));
            assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                    prepare(post, "sp", oversizedAcs, IDP, null,
                            new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        }
    }

    @Test void exactXmlByteLimitIsAcceptedForBothBindings() {
        URI baselineAcs = URI.create("https://sp.example.test/acs?x=");
        SamlRedirectAuthnRequest.PostPrepared baseline = assertInstanceOf(
                SamlRedirectAuthnRequest.PostPrepared.class,
                prepare(true, "sp", baselineAcs, IDP, null,
                        new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        int baselineLength = Base64.getDecoder().decode(
                baseline.form().getFields().get("SAMLRequest")).length;
        int fillLength = 16_384 - baselineLength;
        URI exactAcs = URI.create(baselineAcs + "a".repeat(fillLength));
        SamlRedirectAuthnRequest.PostPrepared exact = assertInstanceOf(
                SamlRedirectAuthnRequest.PostPrepared.class,
                prepare(true, "sp", exactAcs, IDP, null,
                        new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        assertEquals(16_384, Base64.getDecoder().decode(
                exact.form().getFields().get("SAMLRequest")).length);
        assertInstanceOf(SamlRedirectAuthnRequest.Prepared.class,
                prepare(false, "sp", exactAcs, IDP, null,
                        new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        URI overAcs = URI.create(exactAcs + "a");
        assertRejected(true, "sp", overAcs, IDP, null, Duration.ofMinutes(5));
        assertRejected(false, "sp", overAcs, IDP, null, Duration.ofMinutes(5));
    }

    @Test void bothBindingsPreserveEverySuppliedEntropyOctet() {
        byte[] requestEntropy = new byte[20];
        byte[] relayEntropy = new byte[16];
        for (int index = 0; index < requestEntropy.length; index++)
            requestEntropy[index] = (byte) (index + 1);
        for (int index = 0; index < relayEntropy.length; index++)
            relayEntropy[index] = (byte) (index + 41);
        String expectedId = "_" + HexFormat.of().withUpperCase().formatHex(requestEntropy);
        String expectedRelay = Base64.getUrlEncoder().withoutPadding().encodeToString(relayEntropy);
        for (boolean post : new boolean[] {false, true}) {
            SecureRandom random = new SecureRandom() {
                private int calls;
                @Override public void nextBytes(byte @NonNull [] bytes) {
                    int call = calls++;
                    byte[] source = call % 2 == 0 ? requestEntropy : relayEntropy;
                    for (int index = 0; index < bytes.length; index++)
                        bytes[index] = (byte) (source[index] + call / 2);
                }
            };
            SamlRedirectAuthnRequest.Result first = prepare(post, "sp", ACS, IDP, null,
                    random, CLOCK, Duration.ofMinutes(5));
            SamlRedirectAuthnRequest.Result second = prepare(post, "sp", ACS, IDP, null,
                    random, CLOCK, Duration.ofMinutes(5));
            if (post) {
                SamlRedirectAuthnRequest.PostPrepared checked = assertInstanceOf(
                        SamlRedirectAuthnRequest.PostPrepared.class, first);
                assertEquals(expectedId, checked.requestId());
                assertEquals(expectedRelay, checked.relayState());
                SamlRedirectAuthnRequest.PostPrepared later = assertInstanceOf(
                        SamlRedirectAuthnRequest.PostPrepared.class, second);
                assertNotEquals(checked.requestId(), later.requestId());
                assertNotEquals(checked.relayState(), later.relayState());
            } else {
                SamlRedirectAuthnRequest.Prepared checked = assertInstanceOf(
                        SamlRedirectAuthnRequest.Prepared.class, first);
                assertEquals(expectedId, checked.requestId());
                assertEquals(expectedRelay, checked.relayState());
                SamlRedirectAuthnRequest.Prepared later = assertInstanceOf(
                        SamlRedirectAuthnRequest.Prepared.class, second);
                assertNotEquals(checked.requestId(), later.requestId());
                assertNotEquals(checked.relayState(), later.relayState());
            }
        }
    }

    @Test void refusesUnsignedWhenRequiredAndRejectsInsecureEndpoints() {
        assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                SamlRedirectAuthnRequest.prepare("sp", ACS, IDP, null, true,
                        new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                SamlRedirectAuthnRequest.prepare("sp", ACS, URI.create("http://idp.example.test/sso"), null,
                        false, new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                SamlRedirectAuthnRequest.prepare("sp", ACS,
                        URI.create("https://idp.example.test/sso?SAML%52equest=spoofed"), null,
                        false, new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                SamlRedirectAuthnRequest.prepare("sp", ACS,
                        URI.create("https://idp.example.test/sso?%FF=broken"), null,
                        false, new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        for (String query : new String[] {"tenant=%FF", "tenant=%C0%AF", "=unnamed",
                "SAMLRequest%00=spoofed", "tenant=%0Aevil", "tenant=%7F"}) {
            assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                    SamlRedirectAuthnRequest.prepare("sp", ACS,
                            URI.create("https://idp.example.test/sso?" + query), null,
                            false, new SecureRandom(), CLOCK, Duration.ofMinutes(5)), query);
        }
        assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                SamlRedirectAuthnRequest.prepare("sp", ACS,
                        URI.create("https://idp.example.test/sso?tenant=one&"), null,
                        false, new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
    }

    @Test void postActionRejectsBindingFieldsInItsExistingQuery() {
        SamlRedirectAuthnRequest.PostPrepared safe = assertInstanceOf(
                SamlRedirectAuthnRequest.PostPrepared.class,
                SamlRedirectAuthnRequest.preparePost("sp", ACS, IDP, null, false,
                        new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        assertEquals(IDP, safe.form().getAction());
        for (String query : new String[] {"SAMLRequest=spoofed", "SAML%52equest=spoofed",
                "RelayState=spoofed", "%FF=broken", "tenant=%FF", "tenant=%C0%AF",
                "=unnamed", "tenant=one&", "SAMLRequest%00=spoofed", "tenant=%0Aevil",
                "tenant=%7F"}) {
            assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                    SamlRedirectAuthnRequest.preparePost("sp", ACS,
                            URI.create("https://idp.example.test/sso?" + query), null, false,
                            new SecureRandom(), CLOCK, Duration.ofMinutes(5)), query);
        }
    }

    @Test void bothRequestBindingsRejectUnsafeConfigurationBeforeGeneratingState() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(1024);
        PrivateKey undersized = rsa.generateKeyPair().getPrivate();
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(256);
        PrivateKey wrongAlgorithm = ec.generateKeyPair().getPrivate();
        for (boolean post : new boolean[] {false, true}) {
            for (String entity : new String[] {"", "x".repeat(2049)})
                assertRejected(post, entity, ACS, IDP, null, Duration.ofMinutes(5));
            for (URI acs : new URI[] {URI.create("http://sp.example.test/acs"),
                    URI.create("https://user@sp.example.test/acs")})
                assertRejected(post, "sp", acs, IDP, null, Duration.ofMinutes(5));
            for (URI endpoint : new URI[] {URI.create("http://idp.example.test/sso"),
                    URI.create("https://user@idp.example.test/sso"),
                    URI.create("https://idp.example.test/sso#fragment"),
                    URI.create("https://idp.example.test/sso?"),
                    URI.create("https://idp.example.test/sso?x=" + "a".repeat(2048)),
                    URI.create("https://idp.example.test/sso?x=1&&y=2"),
                    URI.create("https://idp.example.test/sso?SigAlg=spoof"),
                    URI.create("https://idp.example.test/sso?Signature=spoof"),
                    URI.create("https://idp.example.test/sso?SAMLResponse=spoof")})
                assertRejected(post, "sp", ACS, endpoint, null, Duration.ofMinutes(5));
            for (Duration lifetime : new Duration[] {Duration.ZERO,
                    Duration.ofSeconds(-1), Duration.ofMinutes(15).plusNanos(1)})
                assertRejected(post, "sp", ACS, IDP, null, lifetime);
            assertRejected(post, "sp", ACS, IDP, undersized, Duration.ofMinutes(5));
            assertRejected(post, "sp", ACS, IDP, wrongAlgorithm, Duration.ofMinutes(5));
        }
    }

    @Test void localClockAndEntropyFailuresStayUnavailableForBothBindings() {
        Clock failedClock = new Clock() {
            @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
            @Override public @NonNull Instant instant() { throw new IllegalStateException("clock failed"); }
        };
        SecureRandom failedRandom = new SecureRandom() {
            @Override public void nextBytes(byte @NonNull [] bytes) {
                throw new IllegalStateException("entropy failed");
            }
        };
        for (boolean post : new boolean[] {false, true}) {
            assertInstanceOf(SamlRedirectAuthnRequest.Unavailable.class,
                    prepare(post, "sp", ACS, IDP, null, new SecureRandom(), failedClock,
                            Duration.ofMinutes(5)));
            assertInstanceOf(SamlRedirectAuthnRequest.Unavailable.class,
                    prepare(post, "sp", ACS, IDP, null, failedRandom, CLOCK,
                            Duration.ofMinutes(5)));
        }
    }

    private static void assertRejected(boolean post, @NonNull String entity, @NonNull URI acs,
            @NonNull URI endpoint, @Nullable PrivateKey key, @NonNull Duration lifetime) {
        assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                prepare(post, entity, acs, endpoint, key, new SecureRandom(), CLOCK, lifetime),
                () -> "post=" + post + ", entity length=" + entity.length() + ", acs=" + acs
                        + ", endpoint=" + endpoint + ", lifetime=" + lifetime);
    }

    private static void assertPrepared(boolean post, SamlRedirectAuthnRequest.@NonNull Result result) {
        if (post) assertInstanceOf(SamlRedirectAuthnRequest.PostPrepared.class, result);
        else assertInstanceOf(SamlRedirectAuthnRequest.Prepared.class, result);
    }

    private static SamlRedirectAuthnRequest.@NonNull Result prepare(boolean post,
            @NonNull String entity, @NonNull URI acs, @NonNull URI endpoint, @Nullable PrivateKey key,
            @NonNull SecureRandom random, @NonNull Clock clock, @NonNull Duration lifetime) {
        return post ? SamlRedirectAuthnRequest.preparePost(entity, acs, endpoint, key, false,
                random, clock, lifetime)
                : SamlRedirectAuthnRequest.prepare(entity, acs, endpoint, key, false,
                        random, clock, lifetime);
    }

    private static @NonNull String inflate(byte @NonNull [] compressed) throws DataFormatException {
        Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(compressed);
            byte[] output = new byte[16_384];
            int used = inflater.inflate(output);
            assertTrue(inflater.finished());
            return new String(output, 0, used, StandardCharsets.UTF_8);
        } finally {
            inflater.end();
        }
    }
}
