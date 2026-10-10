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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.io.ByteArrayInputStream;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.xml.SecureXmlParser;
import com.revetsec.internal.xml.SamlXmlWriter;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import java.security.KeyPairGenerator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

final class SamlIdentityProviderMetadataTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:00:00Z"), ZoneOffset.UTC);

    @Test void selectsOneEntityAndPrefillsExplicitConnectionBuilder() throws Exception {
        String certificate = certificate();
        String entity = entity("https://idp.example.test/", certificate);
        String aggregate = "<md:EntitiesDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' "
                + "validUntil='2026-10-10T00:00:00Z'>" + entity + "</md:EntitiesDescriptor>";
        SamlIdentityProviderMetadata metadata = assertInstanceOf(
                SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(aggregate.getBytes(StandardCharsets.UTF_8),
                        "https://idp.example.test/", CLOCK)).getMetadata();
        assertEquals("https://idp.example.test/", metadata.getEntityId());
        assertEquals(URI.create("https://idp.example.test/sso"),
                metadata.getRedirectSingleSignOnService().orElseThrow());
        assertEquals(Instant.parse("2026-10-10T00:00:00Z"), metadata.getValidUntil().orElseThrow());
        assertEquals("tenant-one", SamlIdentityProvider.withMetadata(metadata)
                .connectionId("tenant-one").build().getConnectionId());
    }

    @Test void rejectsExpiredDuplicateAndExternalEntityMetadata() throws Exception {
        String entity = entity("https://idp.example.test/", certificate());
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlResult(entity.replace("2026-10-10", "2026-10-08")
                        .getBytes(StandardCharsets.UTF_8), null, CLOCK));
        String aggregate = "<md:EntitiesDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata'>"
                + entity + entity + "</md:EntitiesDescriptor>";
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlResult(aggregate.getBytes(StandardCharsets.UTF_8),
                        "https://idp.example.test/", CLOCK));
        String hostile = "<!DOCTYPE x [<!ENTITY y SYSTEM 'file:///etc/passwd'>]>" + entity;
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlResult(hostile.getBytes(StandardCharsets.UTF_8), null, CLOCK));
    }

    @Test void pinnedMetadataSignatureCoversTheSelectedEntity() throws Exception {
        String unsigned = entity("https://idp.example.test/", certificate())
                .replace(" entityID=", " ID='_metadata' entityID=");
        String key;
        try (var input = SamlIdentityProviderMetadataTests.class.getResourceAsStream(
                "/fixtures/keys/idp-signing-rsa-2048-key.pem")) {
            key = new String(java.util.Objects.requireNonNull(input).readAllBytes(), StandardCharsets.US_ASCII);
        }
        var certificate = Pem.parseCertificate(readCertificatePem());
        var parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(unsigned.getBytes(StandardCharsets.UTF_8)));
        var document = parsed.getDocument();
        var root = document.getDocumentElement();
        root.setIdAttributeNS(null, "ID", true);
        var factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        var reference = factory.newReference("#_metadata", factory.newDigestMethod(DigestMethod.SHA256, null),
                List.of(factory.newTransform(Transform.ENVELOPED,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                        factory.newTransform(CanonicalizationMethod.EXCLUSIVE,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)), null, null);
        var info = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                        (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        var context = new DOMSignContext(Pem.parsePrivateKey(key), root);
        context.setDefaultNamespacePrefix("ds");
        context.setNextSibling(root.getFirstChild());
        factory.newXMLSignature(info, null).sign(context);
        byte[] signed = SamlXmlWriter.serialize(document);
        assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(signed, null, CLOCK,
                        List.of(certificate.getPublicKey())));
        var unrelated = KeyPairGenerator.getInstance("RSA");
        unrelated.initialize(2048);
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlResult(signed, null, CLOCK,
                        List.of(unrelated.generateKeyPair().getPublic())));
        String tampered = new String(signed, StandardCharsets.UTF_8)
                .replace("https://idp.example.test/sso", "https://evil.example.test/sso");
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlResult(tampered.getBytes(StandardCharsets.UTF_8),
                        null, CLOCK, List.of(certificate.getPublicKey())));
    }

    @Test void spMetadataPublishesExplicitSigningDescriptorOnly() throws Exception {
        String keyPem;
        try (var input = SamlIdentityProviderMetadataTests.class.getResourceAsStream(
                "/fixtures/keys/sp-signing-rsa-2048-key.pem")) {
            keyPem = new String(java.util.Objects.requireNonNull(input).readAllBytes(), StandardCharsets.US_ASCII);
        }
        X509Certificate certificate;
        try (var input = SamlIdentityProviderMetadataTests.class.getResourceAsStream(
                "/fixtures/keys/sp-signing-rsa-2048-cert.pem")) {
            certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(
                            java.util.Objects.requireNonNull(input).readAllBytes()));
        }
        SamlCredential credential = SamlCredential.fromPrivateKeyAndCertificate(
                Pem.parsePrivateKey(keyPem), certificate);
        SamlServiceProvider sp = SamlServiceProvider.withEntityId("https://sp.example.test/saml")
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .signingCredential(credential).clock(CLOCK).build();
        String xml = assertInstanceOf(SamlServiceProviderMetadataResult.Generated.class,
                SamlServiceProviderMetadata.fromServiceProviderResult(sp)).getXml();
        assertEquals(1, assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8)))
                .getDocument().getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata",
                        "KeyDescriptor").getLength());
        assertEquals(false, xml.contains("use=\"encryption\""));
    }

    private static @NonNull String certificate() throws Exception {
        try (var input = SamlIdentityProviderMetadataTests.class.getResourceAsStream(
                "/fixtures/keys/idp-signing-rsa-2048-cert.pem")) {
            String pem = new String(java.util.Objects.requireNonNull(input).readAllBytes(), StandardCharsets.US_ASCII);
            return pem.replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "").replaceAll("[ \\t\\r\\n]", "");
        }
    }

    private static @NonNull String readCertificatePem() throws Exception {
        try (var input = SamlIdentityProviderMetadataTests.class.getResourceAsStream(
                "/fixtures/keys/idp-signing-rsa-2048-cert.pem")) {
            return new String(java.util.Objects.requireNonNull(input).readAllBytes(), StandardCharsets.US_ASCII);
        }
    }

    private static @NonNull String entity(@NonNull String id, @NonNull String certificate) {
        return "<md:EntityDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' "
                + "xmlns:ds='http://www.w3.org/2000/09/xmldsig#' entityID='" + id
                + "' validUntil='2026-10-10T00:00:00Z'>"
                + "<md:IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol' "
                + "WantAuthnRequestsSigned='true'>"
                + "<md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + certificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
                + "<md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' "
                + "Location='https://idp.example.test/sso'/>"
                + "</md:IDPSSODescriptor></md:EntityDescriptor>";
    }
}
