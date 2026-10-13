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

import com.revetsec.internal.pem.Pem;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
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
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

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

    @Test void explicitVerificationContextWorksWithGlobalSecureValidationDisabled() throws Exception {
        KeyPair key = rsa(2048);
        Fixture fixture = fixture(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256));
        String property = "org.jcp.xml.dsig.secureValidation";
        String original = System.getProperty(property);
        try {
            System.setProperty(property, "false");
            assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                    verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic()));
        } finally {
            if (original == null) System.clearProperty(property);
            else System.setProperty(property, original);
        }
    }

    @Test void missingPinnedXmlDsigProviderFailsClosed() throws Exception {
        KeyPair key = rsa(2048);
        Fixture fixture = fixture(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256));
        Provider provider = java.util.Objects.requireNonNull(Security.getProvider("XMLDSig"));
        Provider[] providers = Security.getProviders();
        int position = 1;
        while (position <= providers.length
                && !providers[position - 1].getName().equals(provider.getName())) position++;
        int originalPosition = position;
        Security.removeProvider(provider.getName());
        try {
            assertSame(EnvelopedSignatureVerifier.Unavailable.INSTANCE,
                    verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic()));
        } finally {
            Security.insertProviderAt(provider, originalPosition);
        }
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic()));
    }

    @Test void aValidSignatureMovedPastItsSchemaPositionIsRejected() throws Exception {
        KeyPair key = rsa(2048);
        Fixture fixture = fixture(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256));
        Element response = fixture.shape().getResponse();
        Element signature = java.util.Objects.requireNonNull(fixture.shape().getResponseSignature());
        response.appendChild(signature);
        assertEquals(EnvelopedSignatureVerifier.Reason.SIGNATURE_SHAPE,
                rejected(verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic())));
    }

    @Test void digestInputMustBeginWithTheExactSignedQName() throws Exception {
        Element response = fixture(XML).shape().getResponse();
        assertFalse(EnvelopedSignatureVerifier.digestInputStartsWith(null, response));
        assertFalse(EnvelopedSignatureVerifier.digestInputStartsWith(
                new ByteArrayInputStream("<p:Res".getBytes(StandardCharsets.UTF_8)), response));
        assertFalse(EnvelopedSignatureVerifier.digestInputStartsWith(
                new ByteArrayInputStream("<a:Response".getBytes(StandardCharsets.UTF_8)), response));
        assertTrue(EnvelopedSignatureVerifier.digestInputStartsWith(
                new ByteArrayInputStream("<p:Response more".getBytes(StandardCharsets.UTF_8)), response));
    }

    @Test void trustedKeySetMustBeBoundedAndContainNoNullKey() throws Exception {
        KeyPair key = rsa(2048);
        Fixture fixture = fixture(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256));
        List<PublicKey> withNull = java.util.Arrays.asList(key.getPublic(), null);
        for (List<PublicKey> invalid : List.of(List.<PublicKey>of(),
                Collections.nCopies(9, key.getPublic()), withNull)) {
            assertThrows(IllegalArgumentException.class,
                    () -> EnvelopedSignatureVerifier.verify(fixture.parsed(), fixture.shape(),
                            EnvelopedSignatureVerifier.Target.RESPONSE, invalid));
        }
        for (List<PublicKey> invalid : List.of(List.<PublicKey>of(),
                Collections.nCopies(5, key.getPublic()), withNull)) {
            assertThrows(IllegalArgumentException.class,
                    () -> EnvelopedSignatureVerifier.verifyMetadata(fixture.parsed(),
                            fixture.shape().getResponse(), invalid));
        }
    }

    @Test void fourTrustedRolloverKeysRemainAcceptedAtTheConfiguredLimit() throws Exception {
        KeyPair signer = rsa(2048);
        Fixture fixture = fixture(signed(signer, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256));
        List<PublicKey> rollover = List.of(rsa(2048).getPublic(), rsa(2048).getPublic(),
                rsa(2048).getPublic(), signer.getPublic());
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                EnvelopedSignatureVerifier.verify(fixture.parsed(), fixture.shape(),
                        EnvelopedSignatureVerifier.Target.RESPONSE, rollover));
        assertEquals(EnvelopedSignatureVerifier.Reason.SIGNATURE_SHAPE,
                rejected(EnvelopedSignatureVerifier.verifyMetadata(fixture.parsed(),
                        fixture.shape().getResponse(), rollover)));
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

    @Test void ecKeyWithUnapprovedCurveParametersCannotBecomeACompatibleSigner() throws Exception {
        KeyPair key = ec();
        Fixture fixture = fixture(signed(key, EnvelopedSignatureVerifier.Target.ASSERTION,
                SignatureMethod.ECDSA_SHA256));
        ECPublicKey original = (ECPublicKey) key.getPublic();
        ECParameterSpec parameters = original.getParams();
        ECParameterSpec altered = new ECParameterSpec(parameters.getCurve(),
                parameters.getGenerator(), parameters.getOrder(), parameters.getCofactor() + 1);
        ECPublicKey wrongParameters = new ECPublicKey() {
            private static final long serialVersionUID = 1L;
            @Override public @NonNull ECPoint getW() { return original.getW(); }
            @Override public @NonNull ECParameterSpec getParams() { return altered; }
            @Override public @NonNull String getAlgorithm() { return original.getAlgorithm(); }
            @Override public @NonNull String getFormat() { return original.getFormat(); }
            @Override public byte @NonNull [] getEncoded() { return original.getEncoded(); }
        };
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture, EnvelopedSignatureVerifier.Target.ASSERTION, original));
        assertEquals(EnvelopedSignatureVerifier.Reason.NO_MATCHING_KEY,
                rejected(verify(fixture, EnvelopedSignatureVerifier.Target.ASSERTION, wrongParameters)));
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

    @Test void acceptsSignedInclusiveNamespacesParametersOnBothCanonicalizationSteps() throws Exception {
        KeyPair key = rsa(2048);
        ExcC14NParameterSpec parameters = new ExcC14NParameterSpec(List.of("a"));
        byte[] xml = signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256, DigestMethod.SHA256, XML, parameters, parameters);
        String serialized = new String(xml, StandardCharsets.UTF_8);
        assertTrue(serialized.contains("InclusiveNamespaces"));
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture(xml), EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic()));
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

    @Test void embeddedAttackerCertificateCannotBecomeATrustAnchor() throws Exception {
        Path keys = Path.of("src/test/resources/fixtures/keys");
        String attackerName = "negative-attacker-rsa-2048";
        var attackerCertificate = Pem.parseCertificate(Files.readString(
                keys.resolve(attackerName + "-cert.pem")));
        KeyPair attacker = new KeyPair(attackerCertificate.getPublicKey(), Pem.parsePrivateKey(
                Files.readString(keys.resolve(attackerName + "-key.pem"))));
        var trustedCertificate = Pem.parseCertificate(Files.readString(
                keys.resolve("idp-signing-rsa-2048-cert.pem")));
        String signed = new String(signed(attacker, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256), StandardCharsets.UTF_8);
        String embeddedCertificate = Base64.getEncoder().encodeToString(attackerCertificate.getEncoded());
        String forged = signed.replace("</ds:Signature>",
                "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + embeddedCertificate
                        + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>");
        assertTrue(forged.contains(embeddedCertificate));
        Fixture fixture = fixture(forged);
        // The signature is valid under the attacker's advertised key.
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, attacker.getPublic()));
        // The SP must use its configured IdP key, not the certificate inside the message.
        assertEquals(EnvelopedSignatureVerifier.Reason.INVALID_SIGNATURE,
                rejected(verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE,
                        trustedCertificate.getPublicKey())));
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

    @Test void exactMaximumRsaModulusIsStillACompatibleButWrongPinnedKey() throws Exception {
        KeyPair signer = rsa(2048);
        Fixture fixture = fixture(signed(signer, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256));
        BigInteger exponent = BigInteger.valueOf(65537);
        PublicKey maximum = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                BigInteger.ONE.shiftLeft(16383).add(BigInteger.valueOf(3)), exponent));
        assertEquals(EnvelopedSignatureVerifier.Reason.INVALID_SIGNATURE,
                rejected(verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, maximum)));
    }

    @Test void signaturePrecheckRejectsAlteredSignedInfoAndUnexpectedXmlDsigChildren() throws Exception {
        KeyPair key = rsa(2048);
        String valid = new String(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256), StandardCharsets.UTF_8);
        Map<String, String> mutations = Map.ofEntries(
                Map.entry("wrong canonicalization", valid.replace(CanonicalizationMethod.EXCLUSIVE,
                        "urn:example:unknown-c14n")),
                Map.entry("wrong signature method", valid.replace(SignatureMethod.RSA_SHA256,
                        "urn:example:unknown-signature")),
                Map.entry("external reference", valid.replace("URI=\"#_response\"",
                        "URI=\"https://attacker.example.test/signed.xml\"")),
                Map.entry("reference type", valid.replace("URI=\"#_response\"",
                        "URI=\"#_response\" Type=\"urn:example:other\"")),
                Map.entry("wrong first transform", valid.replace(Transform.ENVELOPED,
                        "urn:example:unknown-transform")),
                Map.entry("wrong digest", valid.replace(DigestMethod.SHA256,
                        "urn:example:unknown-digest")),
                Map.entry("nested signature value", valid.replace("</ds:SignatureValue>",
                        "<ds:Injected/></ds:SignatureValue>")),
                Map.entry("nested digest value", valid.replace("</ds:DigestValue>",
                        "<ds:Injected/></ds:DigestValue>")),
                Map.entry("extra signed info", valid.replace("</ds:SignedInfo>",
                        "<ds:Injected/></ds:SignedInfo>")),
                Map.entry("extra reference child", valid.replace("</ds:Reference>",
                        "<ds:Injected/></ds:Reference>")));
        for (Map.Entry<String, String> entry : mutations.entrySet()) {
            org.junit.jupiter.api.Assertions.assertNotEquals(valid, entry.getValue(), entry.getKey());
            assertEquals(EnvelopedSignatureVerifier.Reason.SIGNATURE_SHAPE,
                    rejected(verify(fixture(entry.getValue()), EnvelopedSignatureVerifier.Target.RESPONSE,
                            key.getPublic())), entry.getKey());
        }
        String safeKeyInfo = valid.replace("</ds:Signature>",
                "<ds:KeyInfo><ds:KeyName>untrusted-name</ds:KeyName></ds:KeyInfo></ds:Signature>");
        assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                verify(fixture(safeKeyInfo), EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic()));
    }

    @Test void canonicalizationMethodCannotHideBehindAnUnchangedReferenceTransform() throws Exception {
        KeyPair key = rsa(2048);
        String valid = new String(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256), StandardCharsets.UTF_8);
        String method = "<ds:CanonicalizationMethod Algorithm=\"" + CanonicalizationMethod.EXCLUSIVE + "\"/>";
        assertTrue(valid.contains(method));
        String unknown = valid.replace(method,
                "<ds:CanonicalizationMethod Algorithm=\"urn:example:unsupported-c14n\"/>");
        assertEquals(EnvelopedSignatureVerifier.Reason.SIGNATURE_SHAPE,
                rejected(verify(fixture(unknown), EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic())));
        String parameterized = valid.replace(method,
                "<ds:CanonicalizationMethod Algorithm=\"" + CanonicalizationMethod.EXCLUSIVE
                        + "\"><ds:Unexpected/></ds:CanonicalizationMethod>");
        assertEquals(EnvelopedSignatureVerifier.Reason.SIGNATURE_SHAPE,
                rejected(verify(fixture(parameterized), EnvelopedSignatureVerifier.Target.RESPONSE,
                        key.getPublic())));
    }

    @Test void rejectsSignatureShapeSmugglingAtEachDsigLayer() throws Exception {
        KeyPair key = rsa(2048);
        String valid = new String(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256), StandardCharsets.UTF_8);
        String transform = "<ds:Transform Algorithm=\"" + Transform.ENVELOPED + "\"/>";
        String exclusive = "<ds:Transform Algorithm=\"" + CanonicalizationMethod.EXCLUSIVE + "\"/>";
        String signatureMethod = "<ds:SignatureMethod Algorithm=\"" + SignatureMethod.RSA_SHA256 + "\"/>";
        String digestMethod = "<ds:DigestMethod Algorithm=\"" + DigestMethod.SHA256 + "\"/>";
        Map<String, String> mutations = Map.ofEntries(
                Map.entry("wrong SignedInfo element", valid.replace("ds:SignedInfo", "ds:WrongInfo")),
                Map.entry("wrong SignatureValue element", valid.replace("ds:SignatureValue", "ds:WrongValue")),
                Map.entry("missing SignatureValue", valid.replaceAll(
                        "(?s)<ds:SignatureValue>.*?</ds:SignatureValue>", "")),
                Map.entry("duplicate SignatureValue", valid.replace("</ds:SignatureValue>",
                        "</ds:SignatureValue><ds:SignatureValue>other</ds:SignatureValue>")),
                Map.entry("wrong CanonicalizationMethod element", valid.replace(
                        "ds:CanonicalizationMethod", "ds:WrongCanonicalization")),
                Map.entry("wrong SignatureMethod element", valid.replace("ds:SignatureMethod", "ds:WrongMethod")),
                Map.entry("wrong Reference element", valid.replace("ds:Reference", "ds:WrongReference")),
                Map.entry("nested signature method", valid.replace(signatureMethod,
                        signatureMethod.replace("/>", "><ds:Injected/></ds:SignatureMethod>"))),
                Map.entry("wrong Transforms element", valid.replace("ds:Transforms", "ds:WrongTransforms")),
                Map.entry("empty Transforms", valid.replace(transform + exclusive, "")),
                Map.entry("exclusive transform first", valid.replace(transform, "")),
                Map.entry("wrong first Transform element", valid.replace(transform,
                        transform.replace("ds:Transform", "ds:WrongTransform"))),
                Map.entry("wrong second Transform element", valid.replace(exclusive,
                        exclusive.replace("ds:Transform", "ds:WrongTransform"))),
                Map.entry("wrong DigestMethod element", valid.replace("ds:DigestMethod", "ds:WrongDigestMethod")),
                Map.entry("missing DigestMethod", valid.replace(digestMethod, "")),
                Map.entry("wrong DigestValue element", valid.replace("ds:DigestValue", "ds:WrongDigestValue")),
                Map.entry("nested digest method", valid.replace(digestMethod,
                        digestMethod.replace("/>", "><ds:Injected/></ds:DigestMethod>"))),
                Map.entry("nested enveloped transform", valid.replace(transform,
                        transform.replace("/>", "><ds:Injected/></ds:Transform>"))),
                Map.entry("wrong second transform", valid.replace(exclusive,
                        "<ds:Transform Algorithm=\"urn:example:wrong\"/>")),
                Map.entry("third transform", valid.replace(exclusive, exclusive + exclusive)),
                Map.entry("nested second transform", valid.replace(exclusive,
                        exclusive.replace("/>", "><ds:Injected/></ds:Transform>"))),
                Map.entry("unsafe KeyInfo child", valid.replace("</ds:Signature>",
                        "<ds:KeyInfo><ds:Unexpected/></ds:KeyInfo></ds:Signature>")),
                Map.entry("wrong final signature child", valid.replace("</ds:Signature>",
                        "<ds:Unknown/></ds:Signature>")),
                Map.entry("too many signature children", valid.replace("</ds:Signature>",
                        "<ds:KeyInfo/><ds:Unknown/></ds:Signature>")),
                Map.entry("KeyInfoReference", valid.replace("</ds:Signature>",
                        "<ds:KeyInfo><ds:KeyInfoReference URI='#_response'/></ds:KeyInfo></ds:Signature>")),
                Map.entry("nested Object in KeyInfo", valid.replace("</ds:Signature>",
                        "<ds:KeyInfo><ds:KeyName><ds:Object/></ds:KeyName></ds:KeyInfo></ds:Signature>")),
                Map.entry("nested retrieval in KeyInfo", valid.replace("</ds:Signature>",
                        "<ds:KeyInfo><ds:X509Data><ds:RetrievalMethod URI='file:///etc/passwd'/>"
                                + "</ds:X509Data></ds:KeyInfo></ds:Signature>")));
        for (Map.Entry<String, String> entry : mutations.entrySet()) {
            org.junit.jupiter.api.Assertions.assertNotEquals(valid, entry.getValue(), entry.getKey());
            assertEquals(EnvelopedSignatureVerifier.Reason.SIGNATURE_SHAPE,
                    rejected(verify(fixture(entry.getValue()), EnvelopedSignatureVerifier.Target.RESPONSE,
                            key.getPublic())), entry.getKey());
        }
    }

    @Test void signatureReferenceRequiresAnExactXmlNcName() throws Exception {
        KeyPair key = rsa(2048);
        for (String id : List.of("_response", "R-9.valid", "réponse", "𐀀-response")) {
            String source = XML.replace("ID='_response'", "ID='" + id + "'");
            Fixture fixture = fixture(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                    SignatureMethod.RSA_SHA256, DigestMethod.SHA256, source));
            assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                    verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic()), id);
        }
        String valid = new String(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256), StandardCharsets.UTF_8);
        for (String id : List.of("1response", "-response", ".response", "response:other",
                "response other")) {
            String altered = valid.replace("ID=\"_response\"", "ID=\"" + id + "\"")
                    .replace("URI=\"#_response\"", "URI=\"#" + id + "\"");
            org.junit.jupiter.api.Assertions.assertNotEquals(valid, altered, id);
            assertMalformedResponseIdRejectedBeforeVerification(altered, id);
        }
    }

    @Test void signatureReferenceAcceptsXmlNameStartAndContinuationBoundaries() throws Exception {
        KeyPair key = rsa(2048);
        int[] nameStarts = { 'A', 'Z', 'a', 'z', 0xC0, 0xD6, 0xD8, 0xF6, 0xF8,
                0x2FF, 0x370, 0x37D, 0x37F, 0x1FFF, 0x200C, 0x200D,
                0x2070, 0x218F, 0x2C00, 0x2FEF, 0x3001, 0xD7FF,
                0xF900, 0xFDCF, 0xFDF0, 0xFFE0, 0xFFFD, 0x10000, 0xEFFFF };
        for (int codePoint : nameStarts) {
            String id = new String(Character.toChars(codePoint)) + "-response";
            String source = XML.replace("ID='_response'", "ID='" + id + "'");
            Fixture fixture = fixture(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                    SignatureMethod.RSA_SHA256, DigestMethod.SHA256, source));
            assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                    verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic()),
                    "U+" + Integer.toHexString(codePoint));
        }
        String valid = new String(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                SignatureMethod.RSA_SHA256), StandardCharsets.UTF_8);
        for (int codePoint : new int[] { 0xBF, 0xD7, 0xF7, 0x300, 0x37E,
                0x200B, 0x200E, 0x206F, 0x2190, 0x2BFF, 0x2FF0, 0x3000,
                0xE000, 0xF8FF, 0xFDD0, 0xF0000 }) {
            String id = new String(Character.toChars(codePoint)) + "-response";
            String altered = valid.replace("ID=\"_response\"", "ID=\"" + id + "\"")
                    .replace("URI=\"#_response\"", "URI=\"#" + id + "\"");
            assertMalformedResponseIdRejectedBeforeVerification(altered,
                    "U+" + Integer.toHexString(codePoint));
        }
        for (String continuation : List.of("-", ".", "0", "9", "\u00B7", "\u0300", "\u036F",
                "\u203F", "\u2040")) {
            String id = "R" + continuation + "-response";
            Fixture fixture = fixture(signed(key, EnvelopedSignatureVerifier.Target.RESPONSE,
                    SignatureMethod.RSA_SHA256, DigestMethod.SHA256,
                    XML.replace("ID='_response'", "ID='" + id + "'")));
            assertInstanceOf(EnvelopedSignatureVerifier.Verified.class,
                    verify(fixture, EnvelopedSignatureVerifier.Target.RESPONSE, key.getPublic()), id);
        }
    }

    private static EnvelopedSignatureVerifier.@NonNull Result verify(@NonNull Fixture fixture,
            EnvelopedSignatureVerifier.@NonNull Target target, @NonNull PublicKey key) {
        return EnvelopedSignatureVerifier.verify(fixture.parsed(), fixture.shape(), target, List.of(key));
    }

    private static void assertMalformedResponseIdRejectedBeforeVerification(@NonNull String xml,
            @NonNull String description) {
        SecureXmlParser.Result.Accepted parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(xml.getBytes(StandardCharsets.UTF_8)));
        assertSame(SamlResponseStructure.Rejected.INSTANCE,
                SamlResponseStructure.inspect(parsed.getDocument()), description);
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
        return signed(key, target, signatureAlgorithm, digestAlgorithm, XML);
    }

    private static byte @NonNull [] signed(@NonNull KeyPair key, EnvelopedSignatureVerifier.@NonNull Target target,
            @NonNull String signatureAlgorithm, @NonNull String digestAlgorithm, @NonNull String source)
            throws Exception {
        return signed(key, target, signatureAlgorithm, digestAlgorithm, source, null, null);
    }

    private static byte @NonNull [] signed(@NonNull KeyPair key, EnvelopedSignatureVerifier.@NonNull Target target,
            @NonNull String signatureAlgorithm, @NonNull String digestAlgorithm, @NonNull String source,
            @Nullable C14NMethodParameterSpec canonicalizationParameters,
            @Nullable TransformParameterSpec transformParameters) throws Exception {
        SecureXmlParser.Result.Accepted parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(source.getBytes(StandardCharsets.UTF_8)));
        Document document = parsed.getDocument();
        Element response = document.getDocumentElement();
        Element element = target == EnvelopedSignatureVerifier.Target.RESPONSE ? response
                : (Element) response.getLastChild();
        String id = element.getAttributeNS(null, "ID");
        element.setIdAttributeNS(null, "ID", true);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        List<Transform> transforms = List.of(
                factory.newTransform(Transform.ENVELOPED, (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                factory.newTransform(CanonicalizationMethod.EXCLUSIVE, transformParameters));
        Reference reference = factory.newReference("#" + id, factory.newDigestMethod(digestAlgorithm, null),
                transforms, null, null);
        SignedInfo info = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                        canonicalizationParameters),
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
