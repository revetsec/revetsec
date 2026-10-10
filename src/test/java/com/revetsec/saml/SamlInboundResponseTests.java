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
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlInboundResponseTests {
    private static final String MIME = "application/x-www-form-urlencoded";
    private static final String OPEN = "<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
            + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
            + "ID='_r' Version='2.0' IssueInstant='2026-10-09T00:00:00Z'>";
    private static final String STATUS = "<p:Status><p:StatusCode "
            + "Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status>";
    private static final String CLOSE = "</p:Response>";

    @Test void acceptsAFormResponseAsUnverifiedShapeOnly() {
        SamlInboundResponse.Accepted accepted = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(form(OPEN + STATUS + "<a:Assertion ID='_a'/>" + CLOSE,
                        "&RelayState=opaque-handle"), List.of(MIME), "tenant=one"));
        assertEquals("_r", accepted.shape().getResponse().getAttribute("ID"));
        assertEquals("_a", assertInstanceOf(Element.class, accepted.shape().getAssertion()).getAttribute("ID"));
        assertEquals("opaque-handle", accepted.relayState());
        assertTrue(accepted.toString().contains("<unverified>"));
    }

    @Test void rejectsMalformedBindingXmlAndWrappedAssertionsAtTheirRespectiveStages() {
        SamlInboundResponse.Rejected binding = assertInstanceOf(SamlInboundResponse.Rejected.class,
                SamlInboundResponse.parse(bytes("SAMLResponse=%%%"), List.of(MIME), null));
        assertEquals(SamlInboundResponse.Stage.BINDING, binding.stage());

        SamlInboundResponse.Rejected xml = assertInstanceOf(SamlInboundResponse.Rejected.class,
                SamlInboundResponse.parse(form("<!DOCTYPE r SYSTEM 'file:///etc/passwd'><r/>", ""),
                        List.of(MIME), null));
        assertEquals(SamlInboundResponse.Stage.XML, xml.stage());
        assertEquals("MALFORMED", xml.reason());

        SamlInboundResponse.Rejected structure = assertInstanceOf(SamlInboundResponse.Rejected.class,
                SamlInboundResponse.parse(form(OPEN + STATUS + "<p:Extensions>"
                        + "<a:Assertion ID='_a'/></p:Extensions>" + CLOSE, ""), List.of(MIME), null));
        assertEquals(SamlInboundResponse.Stage.STRUCTURE, structure.stage());
        assertEquals("INVALID_RESPONSE_SHAPE", structure.reason());
    }

    @Test void noRelayStateIsDistinctFromAnEmptyOne() {
        SamlInboundResponse.Accepted absent = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(form(OPEN + STATUS + "<a:Assertion ID='_a'/>" + CLOSE, ""),
                        List.of(MIME), null));
        assertNull(absent.relayState());
        SamlInboundResponse.Accepted empty = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(form(OPEN + STATUS + "<a:Assertion ID='_a'/>" + CLOSE,
                        "&RelayState="), List.of(MIME), null));
        assertEquals("", empty.relayState());
    }

    @Test void verifiesCoverageFromTheInboundPostAndRejectsUnsignedSuccess() throws Exception {
        KeyPair idp = rsa();
        String xml = signedXml(idp, false);
        SamlInboundResponse.Accepted accepted = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(form(xml, "&RelayState=opaque"), List.of(MIME), null));
        SamlInboundResponse.SignaturesVerified verified = assertInstanceOf(
                SamlInboundResponse.SignaturesVerified.class,
                SamlInboundResponse.verifySuccessSignatures(accepted, List.of(idp.getPublic())));
        assertNotNull(verified.response());
        assertNotNull(verified.assertion());
        assertEquals("opaque", verified.relayState());
        assertTrue(verified.toString().contains("semantics-unchecked"));

        SamlInboundResponse.Accepted unsigned = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(form(OPEN + STATUS + "<a:Assertion ID='_a'/>" + CLOSE, ""),
                        List.of(MIME), null));
        SamlInboundResponse.SignatureRejected rejection = assertInstanceOf(
                SamlInboundResponse.SignatureRejected.class,
                SamlInboundResponse.verifySuccessSignatures(unsigned, List.of(idp.getPublic())));
        assertEquals("UNSIGNED_RESPONSE", rejection.reason());
    }

    @Test void rejectsAnInvalidPresentAssertionEvenWhenResponseSignatureIsValid() throws Exception {
        KeyPair idp = rsa();
        SamlInboundResponse.Accepted accepted = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(form(signedXml(idp, true), ""), List.of(MIME), null));
        SamlInboundResponse.SignatureRejected rejection = assertInstanceOf(
                SamlInboundResponse.SignatureRejected.class,
                SamlInboundResponse.verifySuccessSignatures(accepted, List.of(idp.getPublic())));
        assertEquals("INVALID_SIGNATURE", rejection.reason());
    }

    private static @NonNull String signedXml(@NonNull KeyPair idp, boolean breakAssertionSignature)
            throws Exception {
        String xml = OPEN + "<a:Issuer>idp</a:Issuer>" + STATUS
                + "<a:Assertion ID='_a'><a:Issuer>idp</a:Issuer><a:Subject>alice</a:Subject>"
                + "</a:Assertion>" + CLOSE;
        SecureXmlParser.Result.Accepted parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(bytes(xml)));
        Document document = parsed.getDocument();
        Element response = document.getDocumentElement();
        Element assertion = (Element) response.getLastChild();
        sign(assertion, idp.getPrivate());
        if (breakAssertionSignature) {
            Element signature = (Element) assertion.getElementsByTagNameNS(
                    "http://www.w3.org/2000/09/xmldsig#", "SignatureValue").item(0);
            String value = signature.getTextContent();
            signature.setTextContent((value.charAt(0) == 'A' ? "B" : "A") + value.substring(1));
        }
        sign(response, idp.getPrivate());
        Transformer transformer = TransformerFactory.newDefaultInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(output));
        return output.toString(StandardCharsets.UTF_8);
    }

    private static void sign(@NonNull Element signed, @NonNull PrivateKey privateKey) throws Exception {
        String id = signed.getAttributeNS(null, "ID");
        signed.setIdAttributeNS(null, "ID", true);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        Reference reference = factory.newReference("#" + id,
                factory.newDigestMethod(DigestMethod.SHA256, null), List.of(
                        factory.newTransform(Transform.ENVELOPED,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                        factory.newTransform(CanonicalizationMethod.EXCLUSIVE,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)), null, null);
        SignedInfo info = factory.newSignedInfo(factory.newCanonicalizationMethod(
                        CanonicalizationMethod.EXCLUSIVE, (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        DOMSignContext context = new DOMSignContext(privateKey, signed);
        context.setDefaultNamespacePrefix("ds");
        Node next = signed.getFirstChild().getNextSibling();
        if (next != null) context.setNextSibling(next);
        factory.newXMLSignature(info, null).sign(context);
        signed.setIdAttributeNS(null, "ID", false);
    }

    private static @NonNull KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static byte @NonNull [] form(@NonNull String xml, @NonNull String suffix) {
        String encoded = Base64.getEncoder().encodeToString(bytes(xml))
                .replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        return bytes("SAMLResponse=" + encoded + suffix);
    }

    private static byte @NonNull [] bytes(@NonNull String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
