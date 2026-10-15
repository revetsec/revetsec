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
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Valid signatures do not grant permission to publish malformed SAML identity fields. */
final class SamlRc3CloseoutSemanticTests {
    private static final @NonNull String BASE = SamlResponseSemanticsTests.BASE;
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull String XSI = " xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' ";

    @Test void signedSubjectNameIdsAndRedundantConfirmationsMustRetainTheCompleteIdentity() throws Exception {
        String confirmation = "<a:SubjectConfirmationData";
        List<String> invalid = List.of(
                BASE.replace("<a:NameID>alice</a:NameID>", ""),
                BASE.replace("<a:NameID>alice</a:NameID>", "<a:NameID Format='" + "x".repeat(2049) + "'>alice</a:NameID>"),
                BASE.replace("<a:NameID>alice</a:NameID>", "<a:NameID NameQualifier='" + "x".repeat(2049) + "'>alice</a:NameID>"),
                BASE.replace("<a:NameID>alice</a:NameID>", "<a:NameID SPNameQualifier='" + "x".repeat(2049) + "'>alice</a:NameID>"),
                BASE.replace(confirmation, "<a:NameID Format='urn:wrong'>alice</a:NameID>" + confirmation),
                BASE.replace(confirmation, "<a:NameID NameQualifier='wrong'>alice</a:NameID>" + confirmation),
                BASE.replace(confirmation, "<a:NameID SPNameQualifier='wrong'>alice</a:NameID>" + confirmation),
                BASE.replace("/></a:SubjectConfirmation>", "/><a:NameID>alice</a:NameID></a:SubjectConfirmation>"),
                BASE.replace(confirmation, "<a:NameID>alice</a:NameID><a:NameID>alice</a:NameID>" + confirmation));
        rejectsBeforeReplay(invalid);
    }

    @Test void signedConditionStatementsRejectUnknownAudienceAndProxyPayloadShapes() throws Exception {
        String restriction = "<a:AudienceRestriction>";
        List<String> invalid = List.of(
                BASE.replace(restriction, restriction + "shadow"),
                BASE.replace("<a:Audience>", "<a:UnknownAudience>" ).replace("</a:Audience>", "</a:UnknownAudience>"),
                BASE.replace("</a:Conditions>", "<a:OneTimeUse>shadow</a:OneTimeUse></a:Conditions>"),
                BASE.replace("</a:Conditions>", "<a:ProxyRestriction>shadow</a:ProxyRestriction></a:Conditions>"),
                BASE.replace("</a:Conditions>", "<a:ProxyRestriction Count='1a'/></a:Conditions>"),
                BASE.replace("</a:Conditions>", "<a:ProxyRestriction Count='1/'/></a:Conditions>"),
                BASE.replace("</a:Conditions>", "<a:ProxyRestriction><a:Audience" + XSI + "xsi:nil='true'>audience</a:Audience></a:ProxyRestriction></a:Conditions>"),
                BASE.replace("</a:Conditions>", "<a:ProxyRestriction><a:Audience><a:Other/></a:Audience></a:ProxyRestriction></a:Conditions>"),
                BASE.replace("</a:Conditions>", "<a:ProxyRestriction><a:Audience/></a:ProxyRestriction></a:Conditions>"));
        rejectsBeforeReplay(invalid);
        String withoutTimeBounds = BASE.replace(" NotBefore='2026-10-08T23:59:00Z'", "")
                .replace("<a:Conditions NotOnOrAfter='2026-10-09T00:05:00Z'>", "<a:Conditions>");
        assertInstanceOf(SamlResponseSemantics.Accepted.class, evaluate(withoutTimeBounds, new AtomicInteger()));
    }

    @Test void signedAuthenticationContextRequiresPlainNonemptyOrderedReferences() throws Exception {
        String original = SamlResponseSemanticsTests.AUTHN;
        String prefix = "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'><a:AuthnContext>";
        String suffix = "</a:AuthnContext></a:AuthnStatement>";
        List<String> contexts = List.of(
                "<a:AuthnContextClassRef/>",
                "<a:AuthnContextClassRef><a:Other/></a:AuthnContextClassRef>",
                "<a:AuthnContextDeclRef/>",
                "<a:AuthnContextDeclRef><a:Other/></a:AuthnContextDeclRef>",
                "<a:AuthnContextDeclRef" + XSI + "xsi:nil='true'>urn:example:decl</a:AuthnContextDeclRef>",
                "<a:AuthenticatingAuthority>https://idp.example.test</a:AuthenticatingAuthority>",
                "<a:AuthnContextDecl/><a:AuthenticatingAuthority/>",
                "<a:AuthnContextDecl/><a:AuthenticatingAuthority><a:Other/></a:AuthenticatingAuthority>",
                "<a:AuthnContextDecl/><a:AuthenticatingAuthority" + XSI + "xsi:nil='true'>https://idp.example.test</a:AuthenticatingAuthority>",
                "");
        rejectsBeforeReplay(contexts.stream().map(value -> BASE.replace(original, prefix + value + suffix)).toList());
        rejectsBeforeReplay(List.of(BASE.replace("AuthnInstant='2026-10-09T00:00:00Z'", "AuthnInstant='invalid'")));
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                evaluate(BASE.replace(original, prefix + "<a:AuthnContextDecl/>" + suffix), new AtomicInteger()));
    }

    @Test void signedAttributeBoundsAndTypedNameIdFallbackDoNotInventPlainIdentifiers() throws Exception {
        String attribute = "<a:AttributeStatement><a:Attribute Name='plain'%s><a:AttributeValue>%s</a:AttributeValue></a:Attribute></a:AttributeStatement>";
        rejectsBeforeReplay(List.of(
                BASE.replace("</a:Assertion>", attribute.formatted(" FriendlyName='" + "x".repeat(2049) + "'", "value") + "</a:Assertion>"),
                BASE.replace("</a:Assertion>", attribute.formatted("", "x".repeat(4097)) + "</a:Assertion>")));
        String typed = BASE.replace("</a:Assertion>", attribute.formatted("", "<a:NameID/>") + "</a:Assertion>");
        SamlResponseSemantics.Accepted result = assertInstanceOf(SamlResponseSemantics.Accepted.class, evaluate(typed, new AtomicInteger()));
        assertEquals(List.of(), result.attributes().get(0).getValues());
        assertEquals(SamlAttributeValue.Kind.COMPLEX, result.attributes().get(0).getTypedValues().get(0).getKind());
    }

    private static void rejectsBeforeReplay(@NonNull List<@NonNull String> values) throws Exception {
        AtomicInteger marks = new AtomicInteger();
        for (String xml : values) assertInstanceOf(SamlResponseSemantics.Rejected.class, evaluate(xml, marks), xml);
        assertEquals(0, marks.get());
        assertInstanceOf(SamlResponseSemantics.Accepted.class, evaluate(BASE, marks));
        assertEquals(1, marks.get());
    }

    private static SamlResponseSemantics.@NonNull Result evaluate(@NonNull String xml, @NonNull AtomicInteger marks) throws Exception {
        Path keys = Path.of("src/test/resources/fixtures/keys");
        PrivateKey privateKey = Pem.parsePrivateKey(Files.readString(keys.resolve("idp-signing-rsa-2048-key.pem")));
        PublicKey publicKey = Pem.parseCertificate(Files.readString(keys.resolve("idp-signing-rsa-2048-cert.pem"))).getPublicKey();
        String signed = SamlResponseSemanticsTests.signedXml(xml, true, false, privateKey);
        String encoded = Base64.getEncoder().encodeToString(signed.getBytes(StandardCharsets.UTF_8)).replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        SamlInboundResponse.Accepted inbound = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(("SAMLResponse=" + encoded + "&RelayState=relay").getBytes(StandardCharsets.UTF_8), List.of("application/x-www-form-urlencoded"), null));
        SamlInboundResponse.SignaturesVerified verified = assertInstanceOf(SamlInboundResponse.SignaturesVerified.class,
                SamlInboundResponse.verifySuccessSignatures(inbound, List.of(publicKey)));
        SamlReplayCache replay = (key, expires, remaining) -> { marks.incrementAndGet(); return SamlReplayCache.MarkResult.MARKED; };
        SamlResponseSemantics.Expectation expectation = new SamlResponseSemantics.Expectation("https://sp.example.test/saml", "tenant", "https://idp.example.test/saml", "https://sp.example.test/acs", "_request", "relay", Instant.parse("2026-10-09T00:10:00Z"), CLOCK, Duration.ofMinutes(3), Duration.ofMinutes(5), false, List.of(), replay, Duration.ofSeconds(5));
        return SamlResponseSemantics.validate(verified, expectation);
    }
}
