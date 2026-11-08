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

import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.xml.SamlXmlWriter;
import com.revetsec.internal.xml.SecureXmlParser;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Common runtime regressions use only APIs available at slice entry. */
final class SamlMetadataFreshnessTests {
    static final String ENTITY = "https://idp.example.test/";
    static final Instant NOW = Instant.parse("2026-11-02T00:00:00Z");
    static final Instant END = NOW.plusSeconds(60);
    static final Clock FIXED = Clock.fixed(NOW, ZoneOffset.UTC);
    static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";

    @TestFactory @NonNull Stream<@NonNull DynamicTest> pinnedMetadataMustStillBeCurrentAtReturn() {
        return Stream.of(0, 1, 2).flatMap(scope -> Stream.of(-1, 0, 1, 2, 3).map(boundary ->
                DynamicTest.dynamicTest("scope=" + scope + " boundary=" + boundary, () -> {
            byte[] signed = fixture(scope, scope == 0 ? END.toString() : null,
                    scope == 2 ? END.toString() : null, scope == 1 ? END.toString() : null);
            Instant finish = boundary == -1 ? END.minusNanos(1) : boundary == 0 ? END
                    : boundary == 1 ? END.plusNanos(1) : NOW.minusNanos(1);
            var clock = new CompletionClock(finish, boundary == 3);
            var result = SamlIdentityProviderMetadata.fromXmlResult(signed, ENTITY, clock, keys());
            if (boundary == -1) {
                var metadata = assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class, result).getMetadata();
                assertEquals(END, metadata.getValidUntil().orElseThrow());
            } else if (boundary <= 1) assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class, result);
            else assertInstanceOf(SamlIdentityProviderMetadataResult.Unavailable.class, result);
        })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> existingPinnedOverloadRetainsApplicationManagedUndatedMetadata() {
        return Stream.of(0, 1, 2).map(scope -> DynamicTest.dynamicTest("undated scope=" + scope, () -> {
            var metadata = assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                    SamlIdentityProviderMetadata.fromXmlResult(fixture(scope, null, null, null), ENTITY, FIXED, keys())).getMetadata();
            assertTrue(metadata.getValidUntil().isEmpty());
        }));
    }

    @Test void unsignedParentCannotSupplyOrExpireTheEntitySignatureDeadline() throws Exception {
        for (String parent : List.of(NOW.minusSeconds(1).toString(), END.plusSeconds(600).toString(), "invalid")) {
            var metadata = assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                    SamlIdentityProviderMetadata.fromXmlResult(fixture(2, END.toString(), null, parent), ENTITY, FIXED, keys())).getMetadata();
            assertEquals(END, metadata.getValidUntil().orElseThrow());
        }
    }

    @Test void earliestCoveredLimitWinsWithoutRounding() throws Exception {
        Instant role = END.minusNanos(1);
        var metadata = assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(fixture(1, END.toString(), role.toString(), END.plusSeconds(10).toString()), ENTITY, FIXED, keys())).getMetadata();
        assertEquals(role, metadata.getValidUntil().orElseThrow());
    }

    @Test void tamperedSignatureCannotReachTheCompletionClock() throws Exception {
        String changed = new String(fixture(0, END.toString(), null, null), StandardCharsets.UTF_8)
                .replace("https://idp.example.test/sso", "https://evil.example.test/sso");
        var clock = new CompletionClock(END, true);
        assertInstanceOf(SamlIdentityProviderMetadataResult.Rejected.class,
                SamlIdentityProviderMetadata.fromXmlResult(changed.getBytes(StandardCharsets.UTF_8), ENTITY, clock, keys()));
        assertEquals(1, clock.reads.get());
    }

    @Test void rawParsingKeepsItsSeparateApplicationTrustContract() throws Exception {
        var clock = new CompletionClock(END, true);
        assertInstanceOf(SamlIdentityProviderMetadataResult.Parsed.class,
                SamlIdentityProviderMetadata.fromXmlResult(fixture(0, END.toString(), null, null), ENTITY, clock));
        assertEquals(1, clock.reads.get());
    }

    static byte @NonNull [] fixture(int scope, @Nullable String entityLimit, @Nullable String roleLimit,
            @Nullable String aggregateLimit) throws Exception {
        String entity = "<md:EntityDescriptor xmlns:md='" + MD + "' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' ID='_entity' entityID='" + ENTITY + "'" + until(entityLimit) + ">"
                + "<md:IDPSSODescriptor protocolSupportEnumeration='urn:oasis:names:tc:SAML:2.0:protocol'" + until(roleLimit) + ">"
                + "<md:KeyDescriptor use='signing'><ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
                + certificate() + "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
                + "<md:SingleSignOnService Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' Location='https://idp.example.test/sso'/>"
                + "</md:IDPSSODescriptor></md:EntityDescriptor>";
        String xml = scope == 0 ? entity : "<md:EntitiesDescriptor xmlns:md='" + MD + "' xmlns:ds='http://www.w3.org/2000/09/xmldsig#' ID='_aggregate'" + until(aggregateLimit) + ">" + entity + "</md:EntitiesDescriptor>";
        var document = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseMetadata(xml.getBytes(StandardCharsets.UTF_8))).getDocument();
        Element signed = scope == 2 ? (Element) document.getElementsByTagNameNS(MD, "EntityDescriptor").item(0) : document.getDocumentElement();
        signed.setIdAttributeNS(null, "ID", true);
        var factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        var reference = factory.newReference("#" + signed.getAttribute("ID"), factory.newDigestMethod(DigestMethod.SHA256, null),
                List.of(factory.newTransform(Transform.ENVELOPED, (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                        factory.newTransform(CanonicalizationMethod.EXCLUSIVE, (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)), null, null);
        var info = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                        (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        var context = new DOMSignContext(Pem.parsePrivateKey(resource("idp-signing-rsa-2048-key.pem")), signed);
        context.setDefaultNamespacePrefix("ds");
        context.setNextSibling(signed.getFirstChild());
        factory.newXMLSignature(info, null).sign(context);
        return SamlXmlWriter.serialize(document);
    }
    static @NonNull List<@NonNull PublicKey> keys() throws Exception { return List.of(Pem.parseCertificate(resource("idp-signing-rsa-2048-cert.pem")).getPublicKey()); }
    static @NonNull String certificate() throws Exception { return resource("idp-signing-rsa-2048-cert.pem").replaceAll("-----[^-]+-----", "").replaceAll("\\s", ""); }
    static @NonNull String resource(@NonNull String name) throws Exception {
        try (var input = SamlMetadataFreshnessTests.class.getResourceAsStream("/fixtures/keys/" + name)) {
            return new String(java.util.Objects.requireNonNull(input).readAllBytes(), StandardCharsets.US_ASCII);
        }
    }
    private static @NonNull String until(@Nullable String text) { return text == null ? "" : " validUntil='" + text + "'"; }
    static final class CompletionClock extends Clock {
        final AtomicInteger reads = new AtomicInteger();
        private final Instant finish;
        private final boolean fail;
        CompletionClock(@NonNull Instant finish, boolean fail) { this.finish = finish; this.fail = fail; }
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
        @Override public @NonNull Instant instant() {
            if (reads.getAndIncrement() == 0) return NOW;
            if (fail) throw new IllegalStateException("clock unavailable");
            return finish;
        }
    }
}
