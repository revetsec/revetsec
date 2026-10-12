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

import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.xml.EnvelopedSignatureVerifier;
import com.revetsec.internal.xml.SamlResponseStructure;
import com.revetsec.internal.xml.SecureXmlParser;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/** Wrapping and identity mutations across the independently signed RSA/ECDSA fixture matrix. */
final class SamlXswMutationTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull String IDP = "https://idp.scripted-idp.test/";
    private static final @NonNull Pattern SIGNATURE = Pattern.compile(
            "<ds:Signature\\b[^>]*>.*?</ds:Signature>", Pattern.DOTALL);

    @Test void attackerSignedResponseWithEmbeddedCertificateIsRejectedByTheSp() throws Exception {
        String original = resource("scripted-idp/matrix-response-rsa-sha256-sha256.xml");
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                check(original, "idp-signing-rsa-2048-cert.pem", false));
        Path keys = Path.of("src/test/resources/fixtures/keys");
        String attackerName = "negative-attacker-rsa-2048";
        var certificate = Pem.parseCertificate(Files.readString(keys.resolve(attackerName + "-cert.pem")));
        var privateKey = Pem.parsePrivateKey(Files.readString(keys.resolve(attackerName + "-key.pem")));
        Document document = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(original.getBytes(StandardCharsets.UTF_8))).getDocument();
        Element response = document.getDocumentElement();
        Element oldSignature = assertInstanceOf(Element.class, response.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "Signature").item(0));
        response.removeChild(oldSignature);
        Element nameId = assertInstanceOf(Element.class, response.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "NameID").item(0));
        nameId.setTextContent("attacker-user");
        response.setIdAttributeNS(null, "ID", true);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        Reference reference = factory.newReference("#" + response.getAttribute("ID"),
                factory.newDigestMethod(DigestMethod.SHA256, null), List.of(
                        factory.newTransform(Transform.ENVELOPED,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                        factory.newTransform(CanonicalizationMethod.EXCLUSIVE,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)), null, null);
        SignedInfo signedInfo = factory.newSignedInfo(factory.newCanonicalizationMethod(
                        CanonicalizationMethod.EXCLUSIVE,
                        (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        var keyInfo = factory.getKeyInfoFactory().newKeyInfo(List.of(
                factory.getKeyInfoFactory().newX509Data(List.of(certificate))));
        DOMSignContext context = new DOMSignContext(privateKey, response);
        context.setDefaultNamespacePrefix("ds");
        context.setNextSibling(response.getFirstChild().getNextSibling());
        factory.newXMLSignature(signedInfo, keyInfo).sign(context);
        var transformer = TransformerFactory.newDefaultInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(output));
        byte[] forged = output.toByteArray();
        SecureXmlParser.Result.Accepted parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(forged));
        SamlResponseStructure.Accepted shape = assertInstanceOf(SamlResponseStructure.Accepted.class,
                SamlResponseStructure.inspect(parsed.getDocument()));
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                EnvelopedSignatureVerifier.verify(parsed, shape.getShape(),
                        EnvelopedSignatureVerifier.Target.RESPONSE, List.of(certificate.getPublicKey())));
        SamlAuthenticationResult.Succeeded attackerControl = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class,
                check(new String(forged, StandardCharsets.UTF_8),
                        "negative-attacker-rsa-2048-cert.pem", false));
        assertEquals("attacker-user", attackerControl.getAuthentication()
                .getNameId().orElseThrow().getValue());
        assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                check(new String(forged, StandardCharsets.UTF_8), "idp-signing-rsa-2048-cert.pem", false));
    }

    @Test void wrappingAndIdentityInjectionsAreRejectedAcrossSignedFixtures() throws Exception {
        List<String> seeds = new ArrayList<>(List.of(
                "assertion-signxml", "assertion-ec384", "assertion-rsa-sha1"));
        for (String placement : List.of("response", "assertion", "both"))
            for (String algorithm : List.of("rsa-sha256", "rsa-sha384", "rsa-sha512",
                    "ecdsa-sha256", "ecdsa-sha384", "ecdsa-sha512"))
                for (String digest : List.of("sha256", "sha384", "sha512"))
                    seeds.add("matrix-" + placement + "-" + algorithm + "-" + digest);
        for (String name : seeds) {
            boolean sha1 = name.endsWith("sha1");
            String certificate = certificateFor(name);
            String original = resource("scripted-idp/" + name + ".xml");
            assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                    check(original, certificate, sha1), name + " baseline");
            String assertion = section(original, "<saml:Assertion ", "</saml:Assertion>");
            String attacker = SIGNATURE.matcher(assertion).replaceFirst("")
                    .replace("minted-user", "attacker-user")
                    .replace("_mint_assertion_", "_attacker_assertion_");
            String duplicateId = SIGNATURE.matcher(assertion).replaceFirst("")
                    .replace("minted-user", "attacker-user");
            java.util.regex.Matcher signatureMatch = SIGNATURE.matcher(original);
            if (!signatureMatch.find()) throw new IllegalArgumentException("fixture signature missing");
            String copiedSignature = signatureMatch.group();
            String issuer = "<saml:Issuer>https://attacker.example.test/</saml:Issuer>";
            String extension = "<samlp:Extensions>" + attacker + "</samlp:Extensions>";
            String responseClose = "</samlp:Response>";
            List<String> mutants = new ArrayList<>();
            mutants.add(original.replace(assertion, attacker + assertion));
            mutants.add(original.replace(assertion, assertion + attacker));
            mutants.add(original.replace(assertion, duplicateId + assertion));
            mutants.add(original.replace(assertion, assertion + duplicateId));
            mutants.add(original.replace("<samlp:Status>", extension + "<samlp:Status>"));
            mutants.add(original.replace(assertion, extension + attacker));
            mutants.add(original.replace(assertion, "<samlp:Extensions>" + assertion
                    + "</samlp:Extensions>" + attacker));
            mutants.add(original.replace(assertion, "<ds:Object xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
                    + assertion + "</ds:Object>" + attacker));
            mutants.add(original.replace("<samlp:Status>", issuer + "<samlp:Status>"));
            mutants.add(original.replace(responseClose, attacker + responseClose));
            mutants.add(original.replace("minted-user", "attacker-user"));
            mutants.add(original.replace("https://sp.test/acs", "https://attacker.example.test/acs"));
            mutants.add(original.replace("<saml:Subject>", "<saml:Subject>"
                    + "<saml:NameID>attacker-user</saml:NameID>"));
            mutants.add(original.replace("<samlp:Status>",
                    "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>"
                    + "</samlp:Status><samlp:Status>"));
            // PortSwigger's Fragile Lock classes: namespace-qualified ID pollution, a copied
            // Signature under an extension with xml:xmlns confusion, and relative-namespace
            // canonicalization with an attacker-controlled sibling Assertion.
            mutants.add(original.replace("<samlp:Response ",
                    "<samlp:Response samlp:ID='_attacker_response' "));
            mutants.add(original.replace("<saml:Assertion ",
                    "<saml:Assertion saml:ID='_attacker_assertion' "));
            mutants.add(original.replace("<samlp:Status>",
                    "<samlp:Extensions><Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>"
                    + "<Child xml:xmlns='#other'>" + copiedSignature
                    + "</Child></Parent></samlp:Extensions><samlp:Status>"));
            mutants.add(original.replace("<samlp:Response ",
                    "<samlp:Response xmlns:ns='1' ")
                    .replace(assertion, attacker + assertion));
            mutants.add(original.replace("minted-user", "minted-<!-- -->attacker"));
            for (int index = 0; index < mutants.size(); index++) {
                assertNotEquals(original, mutants.get(index), name + ":" + index + " did not mutate XML");
                SamlAuthenticationResult result = check(mutants.get(index), certificate, sha1);
                assertInstanceOf(SamlAuthenticationResult.Rejected.class, result,
                        name + ":" + index + " must reject the mutated envelope");
            }
        }
    }

    private static @NonNull String certificateFor(@NonNull String name) {
        if (name.contains("ecdsa-sha256")) return "idp-signing-ec-p256-cert.pem";
        if (name.contains("ecdsa-sha384") || name.contains("ec384"))
            return "idp-signing-ec-p384-cert.pem";
        if (name.contains("ecdsa-sha512")) return "idp-signing-ec-p521-cert.pem";
        if (name.contains("rsa-sha384") || name.contains("rsa-sha512"))
            return "idp-signing-rsa-3072-cert.pem";
        return "idp-signing-rsa-2048-cert.pem";
    }

    private static @NonNull String section(@NonNull String xml, @NonNull String opening,
            @NonNull String closing) {
        int start = xml.indexOf(opening);
        int end = xml.indexOf(closing, start);
        if (start < 0 || end < 0) throw new IllegalArgumentException("fixture shape changed");
        return xml.substring(start, end + closing.length());
    }

    private static @NonNull SamlAuthenticationResult check(@NonNull String xml,
            @NonNull String certificate, boolean sha1) throws Exception {
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.test/Selftest")
                .assertionConsumerServiceUrl(URI.create("https://sp.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 16)).clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP)
                .connectionId("xsw-fixture")
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .signingKeys(List.of(Pem.parseCertificate(resource("keys/" + certificate)).getPublicKey()))
                .allowUnsolicitedResponses(true)
                .compatibility(sha1 ? java.util.Set.of(SamlCompatibilityMode.SHA1_SIGNATURES)
                        : java.util.Set.of()).build();
        String encoded = java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        SamlPostBindingMessage message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded)
                        .getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
        return sp.completeUnsolicitedAuthenticationResult(message, idp);
    }

    private static @NonNull String resource(@NonNull String name) throws IOException {
        try (var input = SamlXswMutationTests.class.getResourceAsStream("/fixtures/" + name)) {
            return new String(java.util.Objects.requireNonNull(input).readAllBytes(),
                    StandardCharsets.UTF_8);
        }
    }
}
