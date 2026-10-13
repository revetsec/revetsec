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
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
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
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
        assertEquals("SamlIdentityProviderMetadata{<redacted>}", metadata.toString());
        assertEquals(true, metadata.wantsAuthnRequestsSigned());
        assertEquals(false, parsed(entity.replace("WantAuthnRequestsSigned='true'",
                "WantAuthnRequestsSigned='false'"), null).wantsAuthnRequestsSigned());
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

    @Test void entityIdLengthAcceptsTheExactLimitAndRejectsTheNextCharacter() throws Exception {
        String prefix = "https://idp.example.test/";
        String certificate = certificate();
        String atLimit = prefix + "a".repeat(2048 - prefix.length());
        String beyondLimit = atLimit + "a";
        assertEquals(2048, atLimit.length());
        assertEquals(atLimit, parsed(entity(atLimit, certificate), null).getEntityId());
        assertRejected("2049-character entity ID", entity(beyondLimit, certificate), null);
    }

    @Test void certificateBase64LengthAcceptsTheExactLimit() throws Exception {
        // A noncritical, unknown X.509 extension makes this valid test certificate exactly
        // 24,576 DER bytes without changing the metadata parser's certificate grammar.
        String encoded = certificate("/fixtures/keys/metadata-size-boundary-rsa-2048-cert.pem");
        assertEquals(32768, encoded.length());
        assertEquals(24576, Base64.getDecoder().decode(encoded).length);
        SamlIdentityProviderMetadata metadata = parsed(entity("https://idp.example.test/", encoded), null);
        assertEquals(24576, metadata.getSigningCertificates().get(0).getEncoded().length);
        assertRejected("certificate beyond Base64 text limit",
                entity("https://idp.example.test/", encoded + "AAAA"), null);
    }

    @Test void convenienceOverloadsAndClockFailureKeepResultContract() throws Exception {
        String metadata = entity("https://idp.example.test/", certificate())
                .replace("2026-10-10T00:00:00Z", "2030-10-10T00:00:00Z");
        byte[] xml = metadata.getBytes(StandardCharsets.UTF_8);
        assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(xml));
        assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(xml, "https://idp.example.test/"));
        Clock broken = new Clock() {
            @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
            @Override public @NonNull Instant instant() { throw new IllegalStateException("clock unavailable"); }
        };
        assertInstanceOf(SamlIdentityProviderMetadataResult.Unavailable.class,
                SamlIdentityProviderMetadata.fromXmlResult(xml, null, broken));
    }

    @Test void aggregateSelectionRejectsAmbiguityAndUsesTheEarliestExpiry() throws Exception {
        String first = entity("https://idp.example.test/", certificate());
        String second = entity("https://other.example.test/", certificate());
        String opening = "<md:EntitiesDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' "
                + "xmlns:ds='http://www.w3.org/2000/09/xmldsig#' "
                + "validUntil='2026-10-09T12:00:00Z'>";
        String aggregate = opening + first + second + "</md:EntitiesDescriptor>";
        SamlIdentityProviderMetadata selected = parsed(aggregate,
                "https://idp.example.test/");
        assertEquals(Instant.parse("2026-10-09T12:00:00Z"),
                selected.getValidUntil().orElseThrow());
        SamlIdentityProviderMetadata earlierEntity = parsed(aggregate.replace(
                "2026-10-09T12:00:00Z", "2026-10-11T12:00:00Z"),
                "https://idp.example.test/");
        assertEquals(Instant.parse("2026-10-10T00:00:00Z"),
                earlierEntity.getValidUntil().orElseThrow());
        assertRejected("aggregate requires explicit selection", aggregate, null);
        assertRejected("absent entity", aggregate, "https://missing.example.test/");
        assertRejected("duplicate selected entity", opening + first + first
                + "</md:EntitiesDescriptor>", "https://idp.example.test/");
        assertRejected("nested aggregate", opening + "<md:EntitiesDescriptor/>" + first
                + "</md:EntitiesDescriptor>", "https://idp.example.test/");
        assertRejected("unexpected aggregate child", opening + "<md:RoleDescriptor/>" + first
                + "</md:EntitiesDescriptor>", "https://idp.example.test/");
        assertRejected("signature after entity", opening + first + "<ds:Signature/>"
                + "</md:EntitiesDescriptor>", "https://idp.example.test/");
        assertRejected("expired aggregate", aggregate.replace("2026-10-09T12:00:00Z",
                "2026-10-08T12:00:00Z"), "https://idp.example.test/");
    }

    @Test void metadataCannotRedirectToUnapprovedEndpointsOrPromoteInvalidKeys() throws Exception {
        String certificate = certificate();
        String base = entity("https://idp.example.test/", certificate);
        String sso = "<md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' "
                + "Location='https://idp.example.test/sso'/>";
        String key = "<md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + certificate + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>";
        String slo = "<md:SingleLogoutService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' "
                + "Location='https://idp.example.test/logout'/>";
        String postOnlyXml = base.replace("HTTP-Redirect", "HTTP-POST");
        SamlIdentityProviderMetadata postOnly = parsed(postOnlyXml, null);
        assertEquals(URI.create("https://idp.example.test/sso"),
                postOnly.getPostSingleSignOnService().orElseThrow());
        SamlIdentityProviderMetadata rollover = parsed(base.replace(key, key + key)
                .replace(sso, slo + sso), null);
        assertEquals(2, rollover.getSigningCertificates().size());
        assertEquals(URI.create("https://idp.example.test/logout"),
                rollover.getRedirectSingleLogoutService().orElseThrow());

        Map<String, String> invalid = Map.ofEntries(
                Map.entry("duplicate SSO", base.replace(sso, sso + sso)),
                Map.entry("duplicate POST SSO", postOnlyXml.replace("</md:IDPSSODescriptor>",
                        sso.replace("HTTP-Redirect", "HTTP-POST") + "</md:IDPSSODescriptor>")),
                Map.entry("duplicate SLO", base.replace(sso, slo + slo + sso)),
                Map.entry("insecure SSO", base.replace("https://idp.example.test/sso",
                        "http://idp.example.test/sso")),
                Map.entry("credentialed SSO", base.replace("https://idp.example.test/sso",
                        "https://user@idp.example.test/sso")),
                Map.entry("fragment SSO", base.replace("https://idp.example.test/sso",
                        "https://idp.example.test/sso#fragment")),
                Map.entry("insecure SLO", base.replace(sso, slo.replace("https://", "http://") + sso)),
                Map.entry("no supported SSO", base.replace("HTTP-Redirect", "HTTP-Artifact")),
                Map.entry("missing signing key", base.replace(key, "")),
                Map.entry("encryption-only key", base.replace("use='signing'", "use='encryption'")),
                Map.entry("unknown key use", base.replace("use='signing'", "use='unsupported'")),
                Map.entry("malformed certificate", base.replace(certificate, "%%%")),
                Map.entry("too many signing keys", base.replace(key, key.repeat(9))),
                Map.entry("wrong protocol", base.replace("urn:oasis:names:tc:SAML:2.0:protocol",
                        "urn:example:protocol")),
                Map.entry("invalid signing request preference", base.replace(
                        "WantAuthnRequestsSigned='true'", "WantAuthnRequestsSigned='sometimes'")));
        for (Map.Entry<String, String> caseUnderTest : invalid.entrySet())
            assertRejected(caseUnderTest.getKey(), caseUnderTest.getValue(), null);
    }

    @Test void metadataScopesRemainLiteralAndRequireApplicationApproval() throws Exception {
        String base = entity("https://idp.example.test/", certificate());
        String extension = "<md:Extensions xmlns:shibmd='urn:mace:shibboleth:metadata:1.0'>"
                + "<shibmd:Scope regexp='false'>example.test</shibmd:Scope>"
                + "<shibmd:Scope regexp='true'>.*</shibmd:Scope></md:Extensions>";
        String extended = base.replace("<md:KeyDescriptor", extension + "<md:KeyDescriptor");
        SamlIdentityProviderMetadata metadata = parsed(extended, null);
        assertEquals(List.of("example.test"), metadata.getAuthorizedIdentifierScopes());
        String maximumScope = "x".repeat(255);
        assertEquals(List.of(maximumScope), parsed(extended.replace("example.test", maximumScope),
                null).getAuthorizedIdentifierScopes());
        for (String scope : List.of("bad@scope", "bad*scope", "bad scope", "x".repeat(256)))
            assertRejected("invalid literal scope: " + scope, extended.replace("example.test", scope), null);
        assertRejected("nested scope", extended.replace("example.test", "<md:RoleDescriptor/>"), null);

        StringBuilder scopes = new StringBuilder();
        for (int index = 0; index < 32; index++)
            scopes.append("<shibmd:Scope regexp='false'>scope").append(index)
                    .append(".example.test</shibmd:Scope>");
        String manyExtension = "<md:Extensions xmlns:shibmd='urn:mace:shibboleth:metadata:1.0'>"
                + scopes + "</md:Extensions>";
        String atLimit = base.replace("<md:KeyDescriptor", manyExtension + "<md:KeyDescriptor");
        assertEquals(32, parsed(atLimit, null).getAuthorizedIdentifierScopes().size());
        assertRejected("33 literal scopes", atLimit.replace("</md:Extensions>",
                "<shibmd:Scope regexp='false'>extra.example.test</shibmd:Scope></md:Extensions>"), null);
    }

    @Test void metadataRejectsAmbiguousCertificateContent() throws Exception {
        String encoded = certificate();
        String base = entity("https://idp.example.test/", encoded);
        byte[] der = Base64.getDecoder().decode(encoded);
        byte[] withTrailingOctet = Arrays.copyOf(der, der.length + 1);
        String trailing = Base64.getEncoder().encodeToString(withTrailingOctet);
        assertRejected("trailing DER octet", base.replace(encoded, trailing), null);
        assertEquals(0x82, Byte.toUnsignedInt(der[1]), "fixture uses a two-octet DER length");
        byte[] nonminimalLength = new byte[der.length + 1];
        nonminimalLength[0] = der[0];
        nonminimalLength[1] = (byte) 0x83;
        nonminimalLength[2] = 0;
        System.arraycopy(der, 2, nonminimalLength, 3, der.length - 2);
        assertRejected("nonminimal DER length", base.replace(encoded,
                Base64.getEncoder().encodeToString(nonminimalLength)), null);
        assertRejected("nested certificate content", base.replace(encoded,
                "<ds:Object>" + encoded + "</ds:Object>"), null);
        assertRejected("two certificates in one key descriptor", base.replace("</ds:X509Certificate>",
                "</ds:X509Certificate><ds:X509Certificate>" + encoded + "</ds:X509Certificate>"), null);
    }

    @Test void metadataRejectsAmbiguousDescriptorsKeysAndEndpointFields() throws Exception {
        String encoded = certificate();
        String base = entity("https://idp.example.test/", encoded);
        String keyInfo = "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>" + encoded
                + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>";
        String descriptor = base.substring(base.indexOf("<md:IDPSSODescriptor"),
                base.indexOf("</md:IDPSSODescriptor>") + "</md:IDPSSODescriptor>".length());
        Map<String, String> invalid = Map.ofEntries(
                Map.entry("empty entity ID", base.replace("entityID='https://idp.example.test/'", "entityID=''")),
                Map.entry("oversized entity ID", base.replace("entityID='https://idp.example.test/'",
                        "entityID='" + "x".repeat(2049) + "'")),
                Map.entry("missing IdP role", base.replace(descriptor, "")),
                Map.entry("duplicate IdP role", base.replace(descriptor, descriptor + descriptor)),
                Map.entry("duplicate KeyInfo", base.replace(keyInfo, keyInfo + keyInfo)),
                Map.entry("duplicate X509Data", base.replace("</ds:X509Data>",
                        "</ds:X509Data><ds:X509Data><ds:X509Certificate>" + encoded
                                + "</ds:X509Certificate></ds:X509Data>")),
                Map.entry("missing certificate", base.replace("<ds:X509Certificate>" + encoded
                        + "</ds:X509Certificate>", "")),
                Map.entry("malformed endpoint URI", base.replace("https://idp.example.test/sso",
                        "https://idp.example.test/sso%ZZ")),
                Map.entry("missing endpoint host", base.replace("https://idp.example.test/sso",
                        "https:///sso")),
                Map.entry("invalid expiry", base.replace("2026-10-10T00:00:00Z", "tomorrow")));
        for (Map.Entry<String, String> caseUnderTest : invalid.entrySet())
            assertRejected(caseUnderTest.getKey(), caseUnderTest.getValue(), null);
        assertRejected("wrong selected ID", base, "https://other.example.test/");
        assertEquals(1, parsed(base.replace("use='signing'", ""), null)
                .getSigningCertificates().size());
        assertEquals(true, parsed(base.replace("WantAuthnRequestsSigned='true'",
                "WantAuthnRequestsSigned='1'"), null).wantsAuthnRequestsSigned());
        assertEquals(false, parsed(base.replace("WantAuthnRequestsSigned='true'",
                "WantAuthnRequestsSigned='0'"), null).wantsAuthnRequestsSigned());
    }

    @Test void pinnedMetadataSignatureCoversTheSelectedEntity() throws Exception {
        String unsigned = entity("https://idp.example.test/", certificate())
                .replace(" entityID=", " ID='_metadata' entityID=")
                .replace(" validUntil='2026-10-10T00:00:00Z'", "");
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
        Provider provider = java.util.Objects.requireNonNull(Security.getProvider("XMLDSig"));
        Provider[] providers = Security.getProviders();
        int originalPosition = 1;
        while (originalPosition <= providers.length
                && !providers[originalPosition - 1].getName().equals(provider.getName()))
            originalPosition++;
        Security.removeProvider(provider.getName());
        try {
            assertInstanceOf(SamlIdentityProviderMetadataResult.Unavailable.class,
                    SamlIdentityProviderMetadata.fromXmlResult(signed, null, CLOCK,
                            List.of(certificate.getPublicKey())));
        } finally {
            Security.insertProviderAt(provider, originalPosition);
        }
        var rolloverGenerator = KeyPairGenerator.getInstance("RSA");
        rolloverGenerator.initialize(2048);
        assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(signed, null, CLOCK,
                        List.of(rolloverGenerator.generateKeyPair().getPublic(),
                                rolloverGenerator.generateKeyPair().getPublic(),
                                rolloverGenerator.generateKeyPair().getPublic(),
                                certificate.getPublicKey())));
        String signedEntity = new String(signed, StandardCharsets.UTF_8)
                .replaceFirst("^<\\?xml[^>]*\\?>", "");
        String unsignedAggregate = "<md:EntitiesDescriptor "
                + "xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' "
                + "validUntil='2030-01-01T00:00:00Z'>"
                + signedEntity + entity("https://other.example.test/", certificate())
                + "</md:EntitiesDescriptor>";
        SamlIdentityProviderMetadataResult.Parsed wrapped = assertInstanceOf(
                SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(unsignedAggregate.getBytes(StandardCharsets.UTF_8),
                        "https://idp.example.test/", CLOCK, List.of(certificate.getPublicKey())));
        assertEquals(false, wrapped.getMetadata().getValidUntil().isPresent(),
                "unsigned parent expiry must not become a signed entity expiry");
        String expiredParent = unsignedAggregate.replace("2030-01-01T00:00:00Z",
                "2020-01-01T00:00:00Z");
        SamlIdentityProviderMetadataResult.Parsed stillTrusted = assertInstanceOf(
                SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(expiredParent.getBytes(StandardCharsets.UTF_8),
                        "https://idp.example.test/", CLOCK, List.of(certificate.getPublicKey())));
        assertEquals(false, stillTrusted.getMetadata().getValidUntil().isPresent());
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

    @Test void pinnedAggregateSignatureCoversSelectedAndSiblingEntities() throws Exception {
        String aggregate = "<md:EntitiesDescriptor xmlns:md='urn:oasis:names:tc:SAML:2.0:metadata' "
                + "xmlns:ds='http://www.w3.org/2000/09/xmldsig#' ID='_aggregate' "
                + "validUntil='2026-10-10T00:00:00Z'>"
                + entity("https://idp.example.test/", certificate())
                + entity("https://other.example.test/", certificate())
                + "</md:EntitiesDescriptor>";
        String key;
        try (var input = SamlIdentityProviderMetadataTests.class.getResourceAsStream(
                "/fixtures/keys/idp-signing-rsa-2048-key.pem")) {
            key = new String(java.util.Objects.requireNonNull(input).readAllBytes(), StandardCharsets.US_ASCII);
        }
        var certificate = Pem.parseCertificate(readCertificatePem());
        var parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(aggregate.getBytes(StandardCharsets.UTF_8)));
        var document = parsed.getDocument();
        var root = document.getDocumentElement();
        root.setIdAttributeNS(null, "ID", true);
        var factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        var reference = factory.newReference("#_aggregate", factory.newDigestMethod(DigestMethod.SHA256, null),
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
        SamlIdentityProviderMetadataResult.Parsed verified = assertInstanceOf(
                SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(signed, "https://idp.example.test/", CLOCK,
                        List.of(certificate.getPublicKey())));
        assertEquals(Instant.parse("2026-10-10T00:00:00Z"),
                verified.getMetadata().getValidUntil().orElseThrow());
        String tampered = new String(signed, StandardCharsets.UTF_8)
                .replace("https://other.example.test/", "https://evil.example.test/");
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlResult(tampered.getBytes(StandardCharsets.UTF_8),
                        "https://idp.example.test/", CLOCK, List.of(certificate.getPublicKey())));
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
                .singleLogoutServiceUrl(URI.create("https://sp.example.test/slo"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .signingCredential(credential).clock(CLOCK).build();
        String xml = assertInstanceOf(SamlServiceProviderMetadataResult.Generated.class,
                SamlServiceProviderMetadata.fromServiceProviderResult(sp)).getXml();
        assertEquals(1, assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8)))
                .getDocument().getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata",
                        "KeyDescriptor").getLength());
        assertEquals(false, xml.contains("use=\"encryption\""));
        assertEquals(1, assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8)))
                .getDocument().getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:metadata",
                        "SingleLogoutService").getLength());
        assertTrue(xml.contains("Location=\"https://sp.example.test/slo\""));
        assertTrue(xml.contains("Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\""));
    }

    private static @NonNull String certificate() throws Exception {
        return certificate("/fixtures/keys/idp-signing-rsa-2048-cert.pem");
    }

    private static @NonNull String certificate(@NonNull String path) throws Exception {
        try (var input = SamlIdentityProviderMetadataTests.class.getResourceAsStream(
                path)) {
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

    private static @NonNull SamlIdentityProviderMetadata parsed(@NonNull String xml,
            @Nullable String entityId) {
        return assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(xml.getBytes(StandardCharsets.UTF_8),
                        entityId, CLOCK)).getMetadata();
    }

    private static void assertRejected(@NonNull String description, @NonNull String xml,
            @Nullable String entityId) {
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlResult(xml.getBytes(StandardCharsets.UTF_8),
                        entityId, CLOCK), description);
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
