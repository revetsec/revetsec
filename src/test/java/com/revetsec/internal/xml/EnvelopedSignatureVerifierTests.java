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

package com.revetsec.internal.xml;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class EnvelopedSignatureVerifierTests {
    private static final String XML = "<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
            + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='_response' Version='2.0' "
            + "IssueInstant='2026-10-09T00:00:00Z'><a:Issuer>idp</a:Issuer>"
            + "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status>"
            + "<a:Assertion ID='_assertion'><a:Issuer>idp</a:Issuer><a:Subject>alice</a:Subject>"
            + "</a:Assertion></p:Response>";

    @Test void verifiesResponseAgainstConfiguredRsaKeyAndPreservesOriginalNode() throws Exception {
        KeyPair key = rsa(2048);
        Fixture fixture = fixture(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE, SignatureMethod.RSA_SHA256));
        EnvelopedSignatureVerifier.Verified verified = assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic()));
        assertSame(fixture.shape().getResponse(), verified.getElement());
        assertEquals(SignatureMethod.RSA_SHA256, verified.getAlgorithm());
        assertSame(EnvelopedSignatureVerifier.Absent.INSTANCE,
                verify(fixture, EnvelopedSignatureVerifier.Target.ASSERTION, key.getPublic()));
        // The verifier deregisters the temporary ID, including on a successful result.
        assertEquals(null, fixture.parsed().getDocument().getElementById("_response"));
    }

    @Test void verifiesAssertionAgainstConfiguredEcKey() throws Exception {
        KeyPair key = ec();
        Fixture fixture = fixture(signed(key, EnvelopedSignatureVerifier.Target.ASSERTION, SignatureMethod.ECDSA_SHA256));
        EnvelopedSignatureVerifier.Verified verified = assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture, EnvelopedSignatureVerifier.Target.ASSERTION, key.getPublic()));
        assertSame(fixture.shape().getAssertion(), verified.getElement());
        assertSame(EnvelopedSignatureVerifier.Absent.INSTANCE,
                verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic()));
    }

    @Test void acceptsTheRemainingDefaultSignatureAndDigestPairs() throws Exception {
        KeyPair rsa = rsa(2048);
        KeyPair p384 = ec("secp384r1");
        KeyPair p521 = ec("secp521r1");
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture(signed(rsa, EnvelopedSignatureVerifier.Target.RESPONSE,
                                SignatureMethod.RSA_SHA384, DigestMethod.SHA384)),
                        EnvelopedSignatureVerifier.Target.RESPONSE, rsa.getPublic()));
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture(signed(rsa, EnvelopedSignatureVerifier.Target.RESPONSE,
                                SignatureMethod.RSA_SHA512, DigestMethod.SHA512)),
                        EnvelopedSignatureVerifier.Target.RESPONSE, rsa.getPublic()));
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture(signed(p384, EnvelopedSignatureVerifier.Target.ASSERTION,
                                SignatureMethod.ECDSA_SHA384, DigestMethod.SHA384)),
                        EnvelopedSignatureVerifier.Target.ASSERTION, p384.getPublic()));
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture(signed(p521, EnvelopedSignatureVerifier.Target.ASSERTION,
                                SignatureMethod.ECDSA_SHA512, DigestMethod.SHA512)),
                        EnvelopedSignatureVerifier.Target.ASSERTION, p521.getPublic()));
    }

    @Test void rejectsTamperingAndAnUntrustedKey() throws Exception {
        KeyPair key = rsa(2048);
        byte[] xml = signed(key, EnvelopedSignatureVerifier.Target.RESPONSE, SignatureMethod.RSA_SHA256);
        String tampered = new String(xml, StandardCharsets.UTF_8).replace("<a:Subject>alice</a:Subject>",
                "<a:Subject>mallory</a:Subject>");
        assertTrue(tampered.contains("mallory"));
        Fixture altered = fixture(tampered.getBytes(StandardCharsets.UTF_8));
        assertEquals(EnvelopedSignatureVerifier.Reason.INVALID_SIGNATURE,
                rejected(verify(altered, EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic())));
        Fixture original = fixture(xml);
        assertEquals(EnvelopedSignatureVerifier.Reason.INVALID_SIGNATURE,
                rejected(verify(original, EnvelopedSignatureVerifier.Target.RESPONSE, rsa(2048).getPublic())));
        EnvelopedSignatureVerifier.Result rollover = EnvelopedSignatureVerifier.verify(original.parsed(),
                original.shape(), EnvelopedSignatureVerifier.Target.RESPONSE,
                List.of(rsa(2048).getPublic(), key.getPublic()));
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class, rollover);
    }

    @Test void rejectsWrongReferenceDisallowedAlgorithmsAndObjectsBeforeValidation() throws Exception {
        KeyPair key = rsa(2048);
        String xml = new String(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256), StandardCharsets.UTF_8);
        assertEquals(EnvelopedSignatureVerifier.Reason.SIGNATURE_SHAPE,
                rejected(verify(fixture(xml.replace("URI=\"#_response\"", "URI=\"#_assertion\"")),
                        EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic())));
        assertEquals(EnvelopedSignatureVerifier.Reason.SIGNATURE_SHAPE,
                rejected(verify(fixture(xml.replace(SignatureMethod.RSA_SHA256, SignatureMethod.RSA_SHA1)),
                        EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic())));
        assertEquals(EnvelopedSignatureVerifier.Reason.SIGNATURE_SHAPE,
                rejected(verify(fixture(xml.replace("</ds:Signature>", "<ds:Object>hidden</ds:Object></ds:Signature>")),
                        EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic())));
    }

    @Test void rejectsKeyInfoRetrievalAndDuplicateIds() throws Exception {
        KeyPair key = rsa(2048);
        String xml = new String(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256), StandardCharsets.UTF_8);
        String retrieval = xml.replace("</ds:Signature>",
                "<ds:KeyInfo><ds:RetrievalMethod URI='file:///etc/passwd'/></ds:KeyInfo></ds:Signature>");
        assertEquals(EnvelopedSignatureVerifier.Reason.SIGNATURE_SHAPE,
                rejected(verify(fixture(retrieval), EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic())));
        String duplicate = xml.replace("<a:Subject>", "<a:Subject ID='_response'>");
        assertInstanceOf(SecureXmlParser.Result.Rejected.class,
                SecureXmlParser.parseResponse(duplicate.getBytes(StandardCharsets.UTF_8)));
    }

    @Test void rejectsWeakRsaAndShapeFromAnotherDocument() throws Exception {
        KeyPair weak = rsa(1024);
        Fixture weakFixture = fixture(signed(weak, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256));
        assertEquals(EnvelopedSignatureVerifier.Reason.NO_MATCHING_KEY,
                rejected(verify(weakFixture, EnvelopedSignatureVerifier.Target.RESPONSE, weak.getPublic())));
        KeyPair strong = rsa(2048);
        Fixture first = fixture(signed(strong, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256));
        Fixture second = fixture(signed(strong, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256));
        assertEquals(EnvelopedSignatureVerifier.Reason.DOCUMENT_MISMATCH,
                rejected(EnvelopedSignatureVerifier.verify(first.parsed(), second.shape(),
                        EnvelopedSignatureVerifier.Target.RESPONSE, List.of(strong.getPublic()))));
    }

    private static EnvelopedSignatureVerifier.@NonNull Result verify(@NonNull Fixture fixture,
            EnvelopedSignatureVerifier.@NonNull Target target, @NonNull PublicKey key) {
        return EnvelopedSignatureVerifier.verify(fixture.parsed(), fixture.shape(), target, List.of(key));
    }

    private static EnvelopedSignatureVerifier.@NonNull Reason rejected(
            EnvelopedSignatureVerifier.@NonNull Result result) {
        return assertInstanceOf(EnvelopedSignatureVerifier.Rejected.class, result).getReason();
    }

    private static @NonNull Fixture fixture(byte @NonNull [] xml) {
        SecureXmlParser.Result.Accepted parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(xml));
        SamlResponseStructure.Accepted accepted = assertInstanceOf(SamlResponseStructure.Accepted.class,
                SamlResponseStructure.inspect(parsed.getDocument()));
        return new Fixture(parsed, accepted.getShape());
    }

    private static @NonNull Fixture fixture(@NonNull String xml) {
        return fixture(xml.getBytes(StandardCharsets.UTF_8));
    }

    private static byte @NonNull [] signed(@NonNull KeyPair key, EnvelopedSignatureVerifier.@NonNull Target target,
            @NonNull String signatureAlgorithm) throws Exception {
        return signed(key, target, signatureAlgorithm, DigestMethod.SHA256);
    }

    private static byte @NonNull [] signed(@NonNull KeyPair key, EnvelopedSignatureVerifier.@NonNull Target target,
            @NonNull String signatureAlgorithm, @NonNull String digestAlgorithm) throws Exception {
        SecureXmlParser.Result.Accepted parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(XML.getBytes(StandardCharsets.UTF_8)));
        Document document = parsed.getDocument();
        Element response = document.getDocumentElement();
        Element element = target == EnvelopedSignatureVerifier.Target.RESPONSE ? response
                : (Element) response.getLastChild();
        String id = element.getAttributeNS(null, "ID");
        element.setIdAttributeNS(null, "ID", true);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        List<Transform> transforms = List.of(
                factory.newTransform(Transform.ENVELOPED, (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                factory.newTransform(CanonicalizationMethod.EXCLUSIVE,
                        (javax.xml.crypto.dsig.spec.TransformParameterSpec) null));
        Reference reference = factory.newReference("#" + id, factory.newDigestMethod(digestAlgorithm, null),
                transforms, null, null);
        SignedInfo info = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                        (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                factory.newSignatureMethod(signatureAlgorithm, null), List.of(reference));
        DOMSignContext context = new DOMSignContext(key.getPrivate(), element);
        context.setDefaultNamespacePrefix("ds");
        Node second = element.getFirstChild().getNextSibling();
        if (second != null) context.setNextSibling(second);
        factory.newXMLSignature(info, null).sign(context);
        Transformer transformer = TransformerFactory.newDefaultInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(output));
        return output.toByteArray();
    }

    private static @NonNull KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits);
        return generator.generateKeyPair();
    }

    private static @NonNull KeyPair ec() throws Exception {
        return ec("secp256r1");
    }

    private static @NonNull KeyPair ec(@NonNull String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private record Fixture(SecureXmlParser.Result.@NonNull Accepted parsed,
            SamlResponseStructure.@NonNull Shape shape) { }
}
