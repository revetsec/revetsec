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
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.xml.SecureXmlParser;
import com.revetsec.internal.xml.XmlEncryptionDecryptor;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class SamlEncryptionTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);

    @Test void decryptedAssertionCannotReuseAnIdentifierFromTheSignedEnvelope() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpSigning = generator.generateKeyPair();
        SamlCredential decryption = credential();
        String plain = SamlResponseSemanticsTests.BASE;
        int begin = plain.indexOf("<a:Assertion");
        int end = plain.indexOf("</a:Assertion>") + "</a:Assertion>".length();
        String assertion = plain.substring(begin, end).replaceFirst("<a:Assertion",
                "<a:Assertion xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion'");
        for (String collision : List.of(
                assertion.replace("ID='_assertion'", "ID='_response'"),
                assertion.replace("<a:NameID>alice</a:NameID>",
                        "<a:NameID Id='_response'>alice</a:NameID>"))) {
            String response = plain.substring(0, begin) + encryptedAssertion(collision, decryption)
                    + plain.substring(end);
            String signed = SamlResponseSemanticsTests.signedXml(response, true, false,
                    idpSigning.getPrivate());
            SamlInboundResponse.Accepted parsed = assertInstanceOf(SamlInboundResponse.Accepted.class,
                    SamlInboundResponse.parse(message(signed, "relay")));
            SamlInboundResponse.SignatureRejected rejected = assertInstanceOf(
                    SamlInboundResponse.SignatureRejected.class,
                    SamlInboundResponse.verifySuccessSignatures(parsed, List.of(idpSigning.getPublic()),
                            List.of(decryption.privateKey()), false, new SecureRandom()));
            assertEquals("DECRYPTION", rejected.reason());
        }
    }

    @Test void clearAndEncryptedNameIdsCannotShareOneSignedSubject() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpSigning = generator.generateKeyPair();
        SamlCredential decryption = credential();
        String encryptedNameId = encryptedAssertion(
                "<a:NameID xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion'>alice</a:NameID>",
                decryption).replace("EncryptedAssertion", "EncryptedID");
        String mixed = SamlResponseSemanticsTests.BASE.replace(
                "<a:NameID>alice</a:NameID>",
                "<a:NameID>alice</a:NameID>" + encryptedNameId);
        String signed = SamlResponseSemanticsTests.signedXml(mixed, true, false,
                idpSigning.getPrivate());
        SamlInboundResponse.Accepted parsed = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(message(signed, "relay")));
        SamlInboundResponse.SignatureRejected rejected = assertInstanceOf(
                SamlInboundResponse.SignatureRejected.class,
                SamlInboundResponse.verifySuccessSignatures(parsed, List.of(idpSigning.getPublic()),
                        List.of(decryption.privateKey()), false, new SecureRandom()));
        assertEquals("DECRYPTION", rejected.reason());
    }

    @Test void pemCredentialLoaderUsesStrictParserAndPairsTheKey() throws Exception {
        String key;
        String certificate;
        try (var input = SamlEncryptionTests.class.getResourceAsStream(
                "/fixtures/keys/sp-encryption-rsa-2048-key.pem")) {
            key = new String(java.util.Objects.requireNonNull(input).readAllBytes(), StandardCharsets.US_ASCII);
        }
        try (var input = SamlEncryptionTests.class.getResourceAsStream(
                "/fixtures/keys/sp-encryption-rsa-2048-cert.pem")) {
            certificate = new String(java.util.Objects.requireNonNull(input).readAllBytes(), StandardCharsets.US_ASCII);
        }
        assertEquals(SamlCredential.fromPem(key, certificate).getCertificate(), credential().getCertificate());
        assertThrows(IllegalArgumentException.class, () -> SamlCredential.fromPem(key + "garbage", certificate));
    }

    @Test void decryptsGcmOaepAndRejectsTamperWithOneReason() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpSigning = generator.generateKeyPair();
        SamlCredential decryption = credential();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .decryptionCredentials(List.of(decryption)).clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("tenant-one").redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(idpSigning.getPublic())).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-encrypted"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "saml-cookie"), sealer, "saml-cookie");
        String plain = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z");
        int begin = plain.indexOf("<a:Assertion");
        int end = plain.indexOf("</a:Assertion>") + "</a:Assertion>".length();
        String assertion = plain.substring(begin, end).replaceFirst("<a:Assertion",
                "<a:Assertion xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion'");
        String encrypted = encryptedAssertion(assertion, decryption);
        String response = plain.substring(0, begin) + encrypted + plain.substring(end);
        String labelled = plain.substring(0, begin) + encrypted.replace(
                "</xenc:EncryptionMethod><xenc:CipherData>",
                "<xenc:OAEPparams>YQ==</xenc:OAEPparams></xenc:EncryptionMethod><xenc:CipherData>")
                + plain.substring(end);
        String signedLabelled = SamlResponseSemanticsTests.signedXml(labelled, true, false,
                idpSigning.getPrivate());
        assertEquals(SamlAuthenticationResult.Reason.DECRYPTION,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(signedLabelled,
                                pending.getRelayStateHandle()), source, idp)).getReason());
        String signed = SamlResponseSemanticsTests.signedXml(response, true, false,
                idpSigning.getPrivate());
        SamlInboundResponse.Result parsed = SamlInboundResponse.parse(message(signed,
                pending.getRelayStateHandle()));
        assertInstanceOf(SamlInboundResponse.Accepted.class, parsed, parsed.toString());
        SamlAuthenticationResult result = sp.completeAuthenticationResult(
                message(signed, pending.getRelayStateHandle()), source, idp);
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class, result, result.toString());
        assertTrue(success.getAuthentication().isAssertionEncrypted());
        assertEquals("alice", success.getAuthentication().getNameId().orElseThrow().getValue());
        String encryptedNameId = encryptedAssertion(
                "<a:NameID xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion'>alice</a:NameID>",
                decryption).replace("EncryptedAssertion", "EncryptedID");
        String nameIdResponse = plain.replace("_assertion", "_encryptedid")
                .replace("_response", "_encryptedidresponse")
                .replace("<a:NameID>alice</a:NameID>", encryptedNameId);
        SamlAuthenticationResult.Succeeded nameIdSuccess = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(
                        nameIdResponse, true, false, idpSigning.getPrivate()),
                        pending.getRelayStateHandle()), source, idp));
        assertEquals("alice", nameIdSuccess.getAuthentication().getNameId().orElseThrow().getValue());
        String siblingPlain = plain.replace("_assertion", "_sibling")
                .replace("_response", "_siblingresponse");
        String siblingAssertion = assertion.replace("_assertion", "_sibling");
        String siblingEncrypted = encryptedAssertion(siblingAssertion, decryption);
        int keyStart = siblingEncrypted.indexOf("<xenc:EncryptedKey>");
        int keyEnd = siblingEncrypted.indexOf("</xenc:EncryptedKey>")
                + "</xenc:EncryptedKey>".length();
        String key = siblingEncrypted.substring(keyStart, keyEnd)
                .replaceFirst("<xenc:EncryptedKey>", "<xenc:EncryptedKey Id='_wrapped'>");
        String referenced = siblingEncrypted.substring(0, keyStart)
                + "<ds:RetrievalMethod Type='http://www.w3.org/2001/04/xmlenc#EncryptedKey' URI='#_wrapped'/>"
                + siblingEncrypted.substring(keyEnd).replace("</a:EncryptedAssertion>",
                        key + "</a:EncryptedAssertion>");
        int siblingBegin = siblingPlain.indexOf("<a:Assertion");
        int siblingEnd = siblingPlain.indexOf("</a:Assertion>") + "</a:Assertion>".length();
        String siblingResponse = siblingPlain.substring(0, siblingBegin) + referenced
                + siblingPlain.substring(siblingEnd);
        String outside = siblingResponse.replace("URI='#_wrapped'", "URI='file:///etc/passwd'");
        assertEquals(SamlAuthenticationResult.Reason.DECRYPTION,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(
                                outside, true, false, idpSigning.getPrivate()),
                                pending.getRelayStateHandle()), source, idp)).getReason());
        SamlAuthenticationResult.Succeeded siblingSuccess = assertInstanceOf(
                SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(
                        siblingResponse, true, false, idpSigning.getPrivate()),
                        pending.getRelayStateHandle()), source, idp));
        assertEquals("alice", siblingSuccess.getAuthentication().getNameId().orElseThrow().getValue());
        String tampered = signed.replace("aes128-gcm", "aes256-gcm");
        assertEquals(SamlAuthenticationResult.Reason.SIGNATURE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(tampered, pending.getRelayStateHandle()),
                                source, idp)).getReason());
    }

    @Test void cbcRequiresVerifiedResponseSignature() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair idpSigning = generator.generateKeyPair();
        SamlCredential decryption = credential();
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .decryptionCredentials(List.of(decryption)).clock(CLOCK).build();
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId("https://idp.example.test/saml")
                .connectionId("tenant-one").redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(idpSigning.getPublic())).allowAesCbcEncryption(true).build();
        PendingSamlAuthentication pending = assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp)).getPendingAuthentication();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-cbc"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "saml-cookie"), sealer, "saml-cookie");
        String plain = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z");
        int begin = plain.indexOf("<a:Assertion");
        int end = plain.indexOf("</a:Assertion>") + "</a:Assertion>".length();
        String assertion = plain.substring(begin, end).replaceFirst("<a:Assertion",
                "<a:Assertion xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion'");
        String response = plain.substring(0, begin) + encryptedAssertion(assertion, decryption, true)
                + plain.substring(end);
        assertEquals(SamlAuthenticationResult.Reason.DECRYPTION,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(message(response, pending.getRelayStateHandle()),
                                source, idp)).getReason());
        SamlAuthenticationResult.Succeeded success = assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                sp.completeAuthenticationResult(message(SamlResponseSemanticsTests.signedXml(response,
                        true, false, idpSigning.getPrivate()), pending.getRelayStateHandle()), source, idp));
        assertTrue(success.getAuthentication().isAssertionEncrypted());
    }

    @Test void encryptionBoundaryRejectsCiphertextTamperingAndUnsupportedKeyDescriptions() throws Exception {
        SamlCredential credential = credential();
        byte[] plaintext = "<a:Assertion xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ID='_test'/>"
                .getBytes(StandardCharsets.UTF_8);
        String encrypted = encryptedAssertion(new String(plaintext, StandardCharsets.UTF_8), credential);
        SecureRandom random = new SecureRandom();
        List<PrivateKey> keys = List.of(credential.privateKey());
        assertArrayEquals(plaintext, XmlEncryptionDecryptor.decrypt(encryptedElement(encrypted), keys,
                false, false, random));
        assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(encrypted), List.of(),
                true, true, random));

        int keyStart = encrypted.indexOf("<xenc:EncryptedKey>");
        int keyEnd = encrypted.indexOf("</xenc:EncryptedKey>", keyStart)
                + "</xenc:EncryptedKey>".length();
        String wrappedKey = encrypted.substring(keyStart, keyEnd);
        String siblingKey = encrypted.replace("<ds:KeyInfo>" + wrappedKey + "</ds:KeyInfo>",
                "<ds:KeyInfo/>").replace("</a:EncryptedAssertion>",
                wrappedKey + "</a:EncryptedAssertion>");
        assertArrayEquals(plaintext, XmlEncryptionDecryptor.decrypt(encryptedElement(siblingKey), keys,
                false, false, random));
        assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(siblingKey.replace(
                        "<ds:KeyInfo/>", "<ds:KeyInfo/><ds:KeyInfo/>")), keys,
                false, false, random));
        for (int length : List.of(1, 256)) {
            String id = "x".repeat(length);
            String referenced = siblingKey.replace("<xenc:EncryptedKey>",
                            "<xenc:EncryptedKey Id='" + id + "'>")
                    .replace("<ds:KeyInfo/>", "<ds:KeyInfo><ds:RetrievalMethod "
                            + "Type='http://www.w3.org/2001/04/xmlenc#EncryptedKey' "
                            + "URI='#" + id + "'/></ds:KeyInfo>");
            assertArrayEquals(plaintext, XmlEncryptionDecryptor.decrypt(encryptedElement(referenced), keys,
                    false, false, random), "reference length " + length);
            if (length == 256)
                assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(referenced.replace(
                        "URI='#" + id + "'", "URI='#" + id + "x'").replace(
                        "Id='" + id + "'", "Id='" + id + "x'")), keys,
                        false, false, random));
        }

        int start = encrypted.lastIndexOf("<xenc:CipherValue>") + "<xenc:CipherValue>".length();
        int end = encrypted.indexOf("</xenc:CipherValue>", start);
        byte[] damaged = Base64.getDecoder().decode(encrypted.substring(start, end));
        damaged[damaged.length - 1] ^= 1;
        String altered = encrypted.substring(0, start) + Base64.getEncoder().encodeToString(damaged)
                + encrypted.substring(end);
        assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(altered), keys,
                true, true, random));

        for (String invalid : List.of(
                encrypted.replace("aes128-gcm", "aes128-ccm"),
                encrypted.replace("rsa-oaep'", "rsa-1_5'"),
                encrypted.replace("xmlenc#sha256", "xmlenc#sha512"),
                encrypted.replace("mgf1sha256", "mgf1sha512"),
                encrypted.replace("</xenc:EncryptionMethod><xenc:CipherData>",
                        "<xenc:OAEPparams>YQ==</xenc:OAEPparams></xenc:EncryptionMethod><xenc:CipherData>"),
                encrypted.replace("</xenc:EncryptionMethod><xenc:CipherData>",
                        "<xenc:OAEPparams/><xenc:OAEPparams/></xenc:EncryptionMethod><xenc:CipherData>"),
                encrypted.replace("</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>",
                        "</xenc:CipherValue><xenc:CipherValue>AA==</xenc:CipherValue>"
                                + "</xenc:CipherData></xenc:EncryptedData>"))) {
            assertNotEquals(encrypted, invalid);
            assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(invalid), keys,
                    true, true, random), invalid);
        }

        String cbc = encryptedAssertion(new String(plaintext, StandardCharsets.UTF_8), credential, true);
        assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(cbc), keys,
                false, true, random));
        assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(cbc), keys,
                true, false, random));
        assertArrayEquals(plaintext, XmlEncryptionDecryptor.decrypt(encryptedElement(cbc), keys,
                true, true, random));
    }

    @Test void retrievalMethodCannotSelectAnAmbiguousOrExternalWrappedKey() throws Exception {
        SamlCredential credential = credential();
        String encrypted = encryptedAssertion("<a:Assertion ID='_checked'/>", credential);
        int keyStart = encrypted.indexOf("<xenc:EncryptedKey>");
        int keyEnd = encrypted.indexOf("</xenc:EncryptedKey>", keyStart)
                + "</xenc:EncryptedKey>".length();
        String key = encrypted.substring(keyStart, keyEnd)
                .replace("<xenc:EncryptedKey>", "<xenc:EncryptedKey Id='_wrapped'>");
        String reference = "<ds:RetrievalMethod Type='http://www.w3.org/2001/04/xmlenc#EncryptedKey' "
                + "URI='#_wrapped'/>";
        String referenced = encrypted.substring(0, keyStart) + reference
                + encrypted.substring(keyEnd).replace("</a:EncryptedAssertion>",
                        key + "</a:EncryptedAssertion>");
        String anonymousKey = key.replace(" Id='_wrapped'", "");
        assertArrayEquals("<a:Assertion ID='_checked'/>".getBytes(StandardCharsets.UTF_8),
                XmlEncryptionDecryptor.decrypt(encryptedElement(referenced),
                        List.of(credential.privateKey()), false, false, new SecureRandom()));
        String eightKeys = referenced.replace("</a:EncryptedAssertion>",
                anonymousKey.repeat(7) + "</a:EncryptedAssertion>");
        assertArrayEquals("<a:Assertion ID='_checked'/>".getBytes(StandardCharsets.UTF_8),
                XmlEncryptionDecryptor.decrypt(encryptedElement(eightKeys),
                        List.of(credential.privateKey()), false, false, new SecureRandom()));
        String eightReferences = referenced.replace(reference, reference.repeat(8));
        assertArrayEquals("<a:Assertion ID='_checked'/>".getBytes(StandardCharsets.UTF_8),
                XmlEncryptionDecryptor.decrypt(encryptedElement(eightReferences),
                        List.of(credential.privateKey()), false, false, new SecureRandom()));

        List<String> invalidCases = List.of(
                referenced.replace("URI='#_wrapped'", "URI='#missing'"),
                referenced.replace("URI='#_wrapped'", "URI='https://example.test/key'"),
                referenced.replace("URI='#_wrapped'", "URI='#'"),
                referenced.replace("EncryptedKey' URI=", "EncryptedData' URI="),
                referenced.replace(reference, "<ds:KeyName>_wrapped</ds:KeyName>"),
                referenced.replace(reference, reference.replace("/>", "><xenc:CipherData/></ds:RetrievalMethod>")),
                referenced.replace(reference, reference.repeat(9)),
                referenced.replace("</a:EncryptedAssertion>",
                        anonymousKey.repeat(8) + "</a:EncryptedAssertion>"));
        for (int index = 0; index < invalidCases.size(); index++) {
            String invalid = invalidCases.get(index);
            assertNotEquals(referenced, invalid);
            SecureXmlParser.Result parsed = SecureXmlParser.parseResponse(invalid.replaceFirst(
                    "<a:EncryptedAssertion ",
                    "<a:EncryptedAssertion xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ")
                    .getBytes(StandardCharsets.UTF_8));
            Element wrapper = assertInstanceOf(SecureXmlParser.Result.Accepted.class, parsed,
                    "case " + index).getDocument().getDocumentElement();
            assertNull(XmlEncryptionDecryptor.decrypt(wrapper, List.of(credential.privateKey()),
                    false, false, new SecureRandom()), "case " + index);
        }
        String duplicateId = referenced.replace("</a:EncryptedAssertion>",
                key + "</a:EncryptedAssertion>");
        assertInstanceOf(SecureXmlParser.Result.Rejected.class,
                SecureXmlParser.parseResponse(duplicateId.replaceFirst("<a:EncryptedAssertion ",
                        "<a:EncryptedAssertion xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ")
                        .getBytes(StandardCharsets.UTF_8)));
    }

    @Test void wrappedKeyBase64IsBoundedBeforeWhitespaceRemoval() throws Exception {
        SamlCredential credential = credential();
        byte[] plaintext = "<a:Assertion ID='_bounded'/>".getBytes(StandardCharsets.UTF_8);
        String encrypted = encryptedAssertion(new String(plaintext, StandardCharsets.UTF_8), credential);
        String open = "<xenc:CipherValue>";
        int start = encrypted.indexOf(open) + open.length();
        int end = encrypted.indexOf("</xenc:CipherValue>", start);
        int maximumEncodedLength = 4 * 8192 / 3 + 16;
        String wrapped = encrypted.substring(start, end);
        String prefix = encrypted.substring(0, start);
        String suffix = encrypted.substring(end);
        String atLimit = prefix + " ".repeat(maximumEncodedLength - wrapped.length())
                + wrapped + suffix;
        String overLimit = prefix + " ".repeat(maximumEncodedLength - wrapped.length() + 1)
                + wrapped + suffix;
        List<PrivateKey> keys = List.of(credential.privateKey());
        assertArrayEquals(plaintext, XmlEncryptionDecryptor.decrypt(encryptedElement(atLimit), keys,
                false, false, new SecureRandom()));
        assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(overLimit), keys,
                false, false, new SecureRandom()));
    }

    @Test void gcmCiphertextAcceptsItsExactByteCapAndRejectsOneMore() throws Exception {
        SamlCredential credential = credential();
        List<PrivateKey> keys = List.of(credential.privateKey());
        SecureRandom random = new SecureRandom();
        // The wire value includes a 12-byte IV and a 16-byte GCM tag.
        String atLimit = "A".repeat(131072 - 12 - 16);
        assertArrayEquals(atLimit.getBytes(StandardCharsets.UTF_8),
                XmlEncryptionDecryptor.decrypt(encryptedElement(encryptedAssertion(atLimit, credential)),
                        keys, false, false, random));
        assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(encryptedAssertion(atLimit + "A", credential)),
                keys, false, false, random));
    }

    @Test void minimumCiphertextsAndKeyRolloverKeepOpaqueFailureWork() throws Exception {
        SamlCredential credential = credential();
        String gcm = encryptedAssertion("", credential);
        String cbc = encryptedAssertion("", credential, true);
        PrivateKey key = credential.privateKey();
        SecureRandom random = new SecureRandom();
        assertArrayEquals(new byte[0], XmlEncryptionDecryptor.decrypt(encryptedElement(gcm),
                List.of(key), false, false, random));
        assertArrayEquals(new byte[0], XmlEncryptionDecryptor.decrypt(encryptedElement(cbc),
                List.of(key), true, true, random));
        assertArrayEquals("fifteen-char-xx".getBytes(StandardCharsets.UTF_8),
                XmlEncryptionDecryptor.decrypt(encryptedElement(encryptedAssertion(
                        "fifteen-char-xx", credential, true)), List.of(key), true, true, random));
        assertArrayEquals(new byte[0], XmlEncryptionDecryptor.decrypt(encryptedElement(gcm),
                List.of(key, key, key, key), false, false, random));
        assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(gcm),
                List.of(key, key, key, key, key), false, false, random));

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        PrivateKey unrelated = generator.generateKeyPair().getPrivate();
        AtomicInteger substitutions = new AtomicInteger();
        SecureRandom substituteRandom = new SecureRandom() {
            @Override public void nextBytes(byte @NonNull [] bytes) {
                assertEquals(16, bytes.length, "AES-128 substitute CEK must retain the selected key length");
                substitutions.incrementAndGet();
                java.util.Arrays.fill(bytes, (byte) 0x5A);
            }
        };
        assertNull(XmlEncryptionDecryptor.decrypt(encryptedElement(gcm), List.of(unrelated),
                false, false, substituteRandom));
        assertEquals(1, substitutions.get(), "failed unwrap must still do substituted content work");
    }

    private static @NonNull Element encryptedElement(@NonNull String xml) {
        return assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(xml.replaceFirst("<a:EncryptedAssertion ",
                        "<a:EncryptedAssertion xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' ")
                        .getBytes(StandardCharsets.UTF_8)))
                .getDocument().getDocumentElement();
    }

    private static @NonNull String encryptedAssertion(@NonNull String assertion,
            @NonNull SamlCredential credential) throws Exception {
        return encryptedAssertion(assertion, credential, false);
    }

    private static @NonNull String encryptedAssertion(@NonNull String assertion,
            @NonNull SamlCredential credential, boolean cbc) throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        SecretKey cek = generator.generateKey();
        byte[] iv = new byte[cbc ? 16 : 12];
        new SecureRandom().nextBytes(iv);
        Cipher aes = Cipher.getInstance(cbc ? "AES/CBC/PKCS5Padding" : "AES/GCM/NoPadding");
        if (cbc) aes.init(Cipher.ENCRYPT_MODE, cek, new IvParameterSpec(iv));
        else aes.init(Cipher.ENCRYPT_MODE, cek, new GCMParameterSpec(128, iv));
        byte[] ciphertext = aes.doFinal(assertion.getBytes(StandardCharsets.UTF_8));
        byte[] wire = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, wire, 0, iv.length);
        System.arraycopy(ciphertext, 0, wire, iv.length, ciphertext.length);
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        rsa.init(Cipher.ENCRYPT_MODE, credential.getCertificate().getPublicKey(),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        byte[] wrapped = rsa.doFinal(cek.getEncoded());
        return "<a:EncryptedAssertion xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' "
                + "xmlns:xenc11='http://www.w3.org/2009/xmlenc11#' "
                + "xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>"
                + "<xenc:EncryptedData Type='http://www.w3.org/2001/04/xmlenc#Element'>"
                + "<xenc:EncryptionMethod Algorithm='"
                + (cbc ? "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
                    : "http://www.w3.org/2009/xmlenc11#aes128-gcm") + "'/>"
                + "<ds:KeyInfo><xenc:EncryptedKey>"
                + "<xenc:EncryptionMethod Algorithm='http://www.w3.org/2009/xmlenc11#rsa-oaep'>"
                + "<ds:DigestMethod Algorithm='http://www.w3.org/2001/04/xmlenc#sha256'/>"
                + "<xenc11:MGF Algorithm='http://www.w3.org/2009/xmlenc11#mgf1sha256'/>"
                + "</xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>"
                + Base64.getEncoder().encodeToString(wrapped)
                + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>"
                + "<xenc:CipherData><xenc:CipherValue>" + Base64.getEncoder().encodeToString(wire)
                + "</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></a:EncryptedAssertion>";
    }

    private static @NonNull SamlCredential credential() throws Exception {
        PrivateKey key;
        try (var input = SamlEncryptionTests.class.getResourceAsStream(
                "/fixtures/keys/sp-encryption-rsa-2048-key.pem")) {
            key = Pem.parsePrivateKey(new String(java.util.Objects.requireNonNull(input).readAllBytes(),
                    StandardCharsets.US_ASCII));
        }
        X509Certificate certificate;
        try (var input = SamlEncryptionTests.class.getResourceAsStream(
                "/fixtures/keys/sp-encryption-rsa-2048-cert.pem")) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(
                            java.util.Objects.requireNonNull(input).readAllBytes()));
        }
        return SamlCredential.fromPrivateKeyAndCertificate(key, certificate);
    }

    private static @NonNull SamlPostBindingMessage message(@NonNull String xml, @NonNull String relay) {
        String encoded = java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(
                xml.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded + "&RelayState=" + relay)
                        .getBytes(StandardCharsets.UTF_8), List.of("application/x-www-form-urlencoded"), null))
                .getMessage();
    }
}
