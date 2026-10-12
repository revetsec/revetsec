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

import org.jspecify.annotations.NonNull;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;

/** Test-only, independently signed SAML responses with untrusted or misleading KeyInfo. */
final class ForgedKeyInfoCorpus {
    private static final @NonNull String DSIG = "http://www.w3.org/2000/09/xmldsig#";
    private static final @NonNull String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final @NonNull Path KEYS = Path.of("../src/test/resources/fixtures/keys");
    static final @NonNull String ATTACKER = "negative-attacker-rsa-2048";
    static final @NonNull String TRUSTED = "idp-signing-rsa-2048";

    enum Placement { RESPONSE, ASSERTION, BOTH }

    private ForgedKeyInfoCorpus() { }

    static @NonNull String attackerSigned(@NonNull Placement placement,
            boolean advertiseTrustedCertificate) throws Exception {
        String fixture = "matrix-" + placement.name().toLowerCase(java.util.Locale.ROOT)
                + "-rsa-sha256-sha256";
        Document document = parse(OpenSamlSpComparatorTests.fixture(fixture));
        Element response = document.getDocumentElement();
        Element assertion = only(response, ASSERTION, "Assertion");
        NodeList signatures = document.getElementsByTagNameNS(DSIG, "Signature");
        while (signatures.getLength() != 0) {
            Node signature = signatures.item(0);
            signature.getParentNode().removeChild(signature);
        }
        only(assertion, ASSERTION, "NameID").setTextContent("attacker-user");
        PrivateKey attackerKey = privateKey(ATTACKER);
        X509Certificate advertised = certificate(
                advertiseTrustedCertificate ? TRUSTED : ATTACKER);
        if (placement != Placement.RESPONSE) sign(assertion, attackerKey, advertised);
        if (placement != Placement.ASSERTION) sign(response, attackerKey, advertised);
        return serialize(document);
    }

    private static @NonNull Document parse(@NonNull String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newDefaultNSInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(
                xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static @NonNull Element only(@NonNull Element parent, @NonNull String namespace,
            @NonNull String localName) {
        NodeList matches = parent.getElementsByTagNameNS(namespace, localName);
        if (matches.getLength() != 1 || !(matches.item(0) instanceof Element element))
            throw new IllegalArgumentException("Expected one " + localName);
        return element;
    }

    private static void sign(@NonNull Element target, @NonNull PrivateKey privateKey,
            @NonNull X509Certificate advertised) throws Exception {
        target.setIdAttributeNS(null, "ID", true);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        Reference reference = factory.newReference("#" + target.getAttribute("ID"),
                factory.newDigestMethod(DigestMethod.SHA256, null), List.of(
                        factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null),
                        factory.newTransform(CanonicalizationMethod.EXCLUSIVE,
                                (TransformParameterSpec) null)), null, null);
        SignedInfo signedInfo = factory.newSignedInfo(factory.newCanonicalizationMethod(
                        CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        var keyInfo = factory.getKeyInfoFactory().newKeyInfo(List.of(
                factory.getKeyInfoFactory().newX509Data(List.of(advertised))));
        DOMSignContext context = new DOMSignContext(privateKey, target);
        context.setDefaultNamespacePrefix("ds");
        Element issuer = null;
        for (Node child = target.getFirstChild(); child != null; child = child.getNextSibling()) {
            if (child instanceof Element element && ASSERTION.equals(element.getNamespaceURI())
                    && "Issuer".equals(element.getLocalName())) {
                if (issuer != null) throw new IllegalArgumentException("Multiple direct Issuers");
                issuer = element;
            }
        }
        if (issuer == null) throw new IllegalArgumentException("Missing direct Issuer");
        context.setNextSibling(issuer.getNextSibling());
        factory.newXMLSignature(signedInfo, keyInfo).sign(context);
    }

    private static @NonNull X509Certificate certificate(@NonNull String name) throws Exception {
        try (var input = Files.newInputStream(KEYS.resolve(name + "-cert.pem"))) {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
        }
    }

    private static @NonNull PrivateKey privateKey(@NonNull String name) throws Exception {
        String pem = Files.readString(KEYS.resolve(name + "-key.pem"));
        String body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(body)));
    }

    private static @NonNull String serialize(@NonNull Document document) throws Exception {
        var transformer = TransformerFactory.newDefaultInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(output));
        return output.toString(StandardCharsets.UTF_8);
    }
}
