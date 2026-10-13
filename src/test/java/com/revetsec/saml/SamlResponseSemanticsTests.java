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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlResponseSemanticsTests {
    private static final String SP = "https://sp.example.test/saml";
    private static final String ACS = "https://sp.example.test/acs";
    private static final String IDP = "https://idp.example.test/saml";
    private static final String NOW = "2026-10-09T00:01:00Z";
    private static final String MIME = "application/x-www-form-urlencoded";
    static final String AUTHN = "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'>"
            + "<a:AuthnContext><a:AuthnContextClassRef>urn:example:password"
            + "</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement>";
    static final String BASE = "<p:Response xmlns:p='urn:oasis:names:tc:SAML:2.0:protocol' "
            + "xmlns:a='urn:oasis:names:tc:SAML:2.0:assertion' "
            + "ID='_response' Version='2.0' IssueInstant='2026-10-09T00:00:00Z' "
            + "Destination='" + ACS + "' InResponseTo='_request'>"
            + "<a:Issuer>" + IDP + "</a:Issuer>"
            + "<p:Status><p:StatusCode Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status>"
            + "<a:Assertion ID='_assertion' Version='2.0' IssueInstant='2026-10-09T00:00:00Z'>"
            + "<a:Issuer>" + IDP + "</a:Issuer>"
            + "<a:Subject><a:NameID>alice</a:NameID>"
            + "<a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>"
            + "<a:SubjectConfirmationData Recipient='" + ACS + "' InResponseTo='_request' "
            + "NotOnOrAfter='2026-10-09T00:05:00Z'/></a:SubjectConfirmation></a:Subject>"
            + "<a:Conditions NotBefore='2026-10-08T23:59:00Z' NotOnOrAfter='2026-10-09T00:05:00Z'>"
            + "<a:AudienceRestriction><a:Audience>" + SP + "</a:Audience></a:AudienceRestriction>"
            + "</a:Conditions>"
            + AUTHN
            + "</a:Assertion></p:Response>";

    @Test void signedAuthenticationStatementWithoutContextFailsBeforeReplayAdmission() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        assertEquals(SamlResponseSemantics.Reason.AUTHN_STATEMENT,
                rejected(validate(BASE.replace(AUTHN,
                        "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'/>"),
                        true, false, key, expected(cache))));
        assertEquals(0, writes.get());
    }

    @Test void validatesSignedResponseAndWritesReplayLast() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiresAt, remaining) -> {
            writes.incrementAndGet();
            assertEquals(43, replayKey.length());
            assertEquals(Instant.parse("2026-10-09T00:08:00Z"), expiresAt);
            return SamlReplayCache.MarkResult.MARKED;
        };
        SamlResponseSemantics.Accepted accepted = assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE, true, false, key, expected(cache)));
        assertEquals("_assertion", accepted.assertionId());
        assertEquals("alice", accepted.nameId().getValue());
        assertEquals(Instant.parse("2026-10-09T00:00:00Z"), accepted.authnInstant());
        assertTrue(accepted.responseSigned());
        assertEquals(false, accepted.assertionSigned());
        assertEquals(1, writes.get());
        assertTrue(accepted.toString().contains("<checked>"));
    }

    @Test void signedAssertionAllowsWhitespaceOnlyDirectText() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiresAt, remaining) ->
                SamlReplayCache.MarkResult.MARKED;
        String spaced = BASE.replace("<a:Issuer>" + IDP + "</a:Issuer><a:Subject>",
                "<a:Issuer>" + IDP + "</a:Issuer> \t\r\n<a:Subject>")
                .replace("<a:AudienceRestriction>", " \t\r\n<a:AudienceRestriction>");
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(spaced, true, false, key, expected(cache)));
    }

    @Test void responseSignatureCannotPromoteAnAssertionWithAnInvalidXmlId() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiresAt, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String malformed = BASE.replace("ID='_assertion'", "ID='bad:assertion'");
        assertEquals(SamlResponseSemantics.Reason.ASSERTION_SHAPE,
                rejected(validate(malformed, true, false, key, expected(cache))));
        assertEquals(0, writes.get());
    }

    @Test void spProvidedIdIsRetainedAndMustMatchRedundantConfirmationNameId() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String named = BASE.replace("<a:NameID>alice</a:NameID>",
                "<a:NameID SPProvidedID='sp-original'>alice</a:NameID>");
        SamlResponseSemantics.Accepted accepted = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(named, true, false, key, expected(cache)));
        assertEquals("sp-original", accepted.nameId().getSpProvidedId().orElseThrow());
        assertEquals(1, writes.get());
        SamlResponseSemantics.Accepted empty = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(named.replace("SPProvidedID='sp-original'", "SPProvidedID=''"),
                        true, false, key, expected(cache)));
        assertTrue(empty.nameId().getSpProvidedId().isPresent());
        assertEquals("", empty.nameId().getSpProvidedId().orElseThrow());
        assertEquals(2, writes.get());

        String mismatched = named.replace(
                "<a:SubjectConfirmationData Recipient='" + ACS + "'",
                "<a:NameID SPProvidedID='sp-other'>alice</a:NameID>"
                        + "<a:SubjectConfirmationData Recipient='" + ACS + "'");
        assertEquals(SamlResponseSemantics.Reason.CONFIRMATION,
                rejected(validate(mismatched, true, false, key, expected(cache))));
        assertEquals(2, writes.get());

        String longest = named.replace("sp-original", "x".repeat(2048));
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(longest, true, false, key, expected(cache)));
        String excessive = named.replace("sp-original", "x".repeat(2049));
        assertEquals(SamlResponseSemantics.Reason.SUBJECT,
                rejected(validate(excessive, true, false, key, expected(cache))));
        assertEquals(3, writes.get());
    }

    @Test void scopedSubjectIdentifierRequiresExplicitConnectionScope() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> SamlReplayCache.MarkResult.MARKED;
        String xml = BASE.replace("<a:NameID>alice</a:NameID>",
                "<a:NameID Format='urn:oasis:names:tc:SAML:2.0:nameid-format:transient'>alice</a:NameID>")
                .replace("</a:Assertion>", "<a:AttributeStatement>"
                        + "<a:Attribute Name='urn:oasis:names:tc:SAML:attribute:subject-id'>"
                        + "<a:AttributeValue>alice@example.test</a:AttributeValue></a:Attribute>"
                        + "</a:AttributeStatement></a:Assertion>");
        SamlResponseSemantics.Accepted unapproved = assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(xml, true, false, key, expected(cache)));
        assertEquals(null, unapproved.subjectId());
        assertEquals(List.of(), unapproved.attributes());
        SamlResponseSemantics.Expectation approved = new SamlResponseSemantics.Expectation(
                SP, "tenant-one", IDP, ACS, "_request", "relay", Instant.parse("2026-10-09T00:10:00Z"),
                fixedClock(), Duration.ofMinutes(3), Duration.ofMinutes(5), false,
                List.of("example.test"), cache, Duration.ofSeconds(5));
        SamlResponseSemantics.Accepted allowed = assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(xml, true, false, key, approved));
        assertEquals("alice@example.test", allowed.subjectId());
        assertEquals(List.of("alice@example.test"), allowed.attributes().get(0).getValues());
    }

    @Test void signedScopedIdentifiersRequireOnePlainValueWithinTheApprovedScope() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> SamlReplayCache.MarkResult.MARKED;
        SamlResponseSemantics.Expectation approved = new SamlResponseSemantics.Expectation(
                SP, "tenant-one", IDP, ACS, "_request", "relay",
                Instant.parse("2026-10-09T00:10:00Z"), fixedClock(), Duration.ofMinutes(3),
                Duration.ofMinutes(5), false, List.of("example.test"), cache,
                Duration.ofSeconds(5));
        String subjectName = "urn:oasis:names:tc:SAML:attribute:subject-id";
        String pairwiseName = "urn:oasis:names:tc:SAML:attribute:pairwise-id";
        String acceptedValue = "a".repeat(499) + "@example.test";
        SamlResponseSemantics.Accepted accepted = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(withAttribute(subjectName, acceptedValue), true, false, key, approved));
        assertEquals(512, acceptedValue.length());
        assertEquals(acceptedValue, accepted.subjectId());
        assertEquals(List.of(acceptedValue), accepted.attributes().get(0).getValues());
        SamlResponseSemantics.Accepted pairwise = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(withAttribute(pairwiseName, "bob@example.test"), true, false, key, approved));
        assertEquals("bob@example.test", pairwise.pairwiseId());
        assertEquals(null, pairwise.subjectId());
        assertEquals(List.of("bob@example.test"), pairwise.attributes().get(0).getValues());

        for (String value : List.of("alice", "@example.test", "alice@",
                "alice@unapproved.test", "alice name@example.test",
                "alice&#x7F;@example.test", "a".repeat(500) + "@example.test")) {
            SamlResponseSemantics.Accepted denied = assertInstanceOf(
                    SamlResponseSemantics.Accepted.class,
                    validate(withAttribute(subjectName, value), true, false, key, approved), value);
            assertEquals(null, denied.subjectId(), value);
            assertEquals(List.of(), denied.attributes(), value);
        }
        String attribute = "<a:Attribute Name='" + subjectName + "'>"
                + "<a:AttributeValue>alice@example.test</a:AttributeValue></a:Attribute>";
        String duplicate = BASE.replace("</a:Assertion>",
                "<a:AttributeStatement>" + attribute.repeat(2)
                        + "</a:AttributeStatement></a:Assertion>");
        String multiple = BASE.replace("</a:Assertion>",
                "<a:AttributeStatement><a:Attribute Name='" + subjectName + "'>"
                        + "<a:AttributeValue>alice@example.test</a:AttributeValue>"
                        + "<a:AttributeValue>bob@example.test</a:AttributeValue>"
                        + "</a:Attribute></a:AttributeStatement></a:Assertion>");
        String typed = BASE.replace("</a:Assertion>",
                "<a:AttributeStatement><a:Attribute Name='" + subjectName + "'>"
                        + "<a:AttributeValue><a:NameID>alice@example.test</a:NameID>"
                        + "</a:AttributeValue></a:Attribute></a:AttributeStatement></a:Assertion>");
        for (String xml : List.of(duplicate, multiple, typed)) {
            SamlResponseSemantics.Accepted denied = assertInstanceOf(
                    SamlResponseSemantics.Accepted.class,
                    validate(xml, true, false, key, approved));
            assertEquals(null, denied.subjectId());
            assertEquals(List.of(), denied.attributes());
        }
    }

    private static @NonNull String withAttribute(@NonNull String name, @NonNull String value) {
        return BASE.replace("</a:Assertion>",
                "<a:AttributeStatement><a:Attribute Name='" + name + "'>"
                        + "<a:AttributeValue>" + value + "</a:AttributeValue>"
                        + "</a:Attribute></a:AttributeStatement></a:Assertion>");
    }

    @Test void signedUnknownAssertionChildCannotPassThroughToIdentityRelease() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String unknown = BASE.replace("</a:Assertion>",
                "<a:UnknownStatement>attacker</a:UnknownStatement></a:Assertion>");
        assertEquals(SamlResponseSemantics.Reason.ASSERTION_SHAPE,
                rejected(validate(unknown, true, false, key, expected(cache))));
        assertEquals(0, writes.get());
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE, true, false, key, expected(cache)));
        assertEquals(1, writes.get());
    }

    @Test void signedAuthorizationStatementDoesNotBecomeApplicationAuthorization() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> SamlReplayCache.MarkResult.MARKED;
        String statement = "<a:AuthzDecisionStatement Resource='https://sp.example.test/saml' "
                + "Decision='Permit'><a:Action Namespace='urn:oasis:names:tc:SAML:1.0:action:rwedc'>"
                + "Read</a:Action></a:AuthzDecisionStatement>";
        String signed = BASE.replace("</a:Assertion>", statement + "</a:Assertion>");
        SamlResponseSemantics.Accepted accepted = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(signed, true, false, key, expected(cache)));
        assertEquals("alice", accepted.nameId().getValue());
        assertEquals(List.of(), accepted.attributes());
        String nilled = BASE.replace("</a:Assertion>",
                statement.replace("<a:AuthzDecisionStatement ",
                        "<a:AuthzDecisionStatement xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                                + "xsi:nil='true' ") + "</a:Assertion>");
        assertEquals(SamlResponseSemantics.Reason.ASSERTION_SHAPE,
                rejected(validate(nilled, true, false, key, expected(cache))));
    }

    @Test void nestedAttributeValuesAreTypedWithoutFlatteningOrIdentifierPromotion() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> SamlReplayCache.MarkResult.MARKED;
        String attributes = "<a:AttributeStatement>"
                + "<a:Attribute Name='eduPersonTargetedID'>"
                + "<a:AttributeValue><a:NameID Format='" + SamlNameId.PERSISTENT + "' "
                + "NameQualifier='https://idp.example.test/saml' SPNameQualifier='" + SP
                + "'>target-123</a:NameID></a:AttributeValue>"
                + "<a:AttributeValue>plain</a:AttributeValue>"
                + "<a:AttributeValue><x:Opaque xmlns:x='urn:example'>hidden</x:Opaque>"
                + "</a:AttributeValue></a:Attribute>"
                + "<a:Attribute Name='urn:oasis:names:tc:SAML:attribute:subject-id'>"
                + "<a:AttributeValue>alice@example.test</a:AttributeValue>"
                + "<a:AttributeValue><x:Opaque xmlns:x='urn:example'>ignored</x:Opaque>"
                + "</a:AttributeValue></a:Attribute>"
                + "</a:AttributeStatement>";
        String xml = BASE.replace("</a:Assertion>", attributes + "</a:Assertion>");
        SamlResponseSemantics.Expectation approved = new SamlResponseSemantics.Expectation(
                SP, "tenant-one", IDP, ACS, "_request", "relay", Instant.parse("2026-10-09T00:10:00Z"),
                fixedClock(), Duration.ofMinutes(3), Duration.ofMinutes(5), false,
                List.of("example.test"), cache, Duration.ofSeconds(5));
        SamlResponseSemantics.Accepted result = assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(xml, true, false, key, approved));
        assertEquals(null, result.subjectId());
        assertEquals(1, result.attributes().size());
        SamlAttribute attribute = result.attributes().get(0);
        assertEquals(List.of("plain"), attribute.getValues());
        assertEquals(List.of(SamlAttributeValue.Kind.NAME_ID, SamlAttributeValue.Kind.TEXT,
                SamlAttributeValue.Kind.COMPLEX),
                attribute.getTypedValues().stream().map(SamlAttributeValue::getKind).toList());
        SamlNameId nested = attribute.getTypedValues().get(0).getNameId().orElseThrow();
        assertEquals("target-123", nested.getValue());
        assertEquals(SP, nested.getSpNameQualifier().orElseThrow());
        assertTrue(attribute.getTypedValues().get(2).getText().isEmpty());
    }

    @Test void nonXmlWhitespaceCannotMakeNestedNameIdLookLikeASoleValue() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> SamlReplayCache.MarkResult.MARKED;
        String attribute = "<a:AttributeStatement><a:Attribute Name='eduPersonTargetedID'>"
                + "<a:AttributeValue>&#x2003;<a:NameID>nested-user</a:NameID>"
                + "</a:AttributeValue></a:Attribute></a:AttributeStatement>";
        SamlResponseSemantics.Accepted accepted = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(BASE.replace("</a:Assertion>", attribute + "</a:Assertion>"),
                        true, false, key, expected(cache)));
        assertEquals(SamlAttributeValue.Kind.COMPLEX,
                accepted.attributes().get(0).getTypedValues().get(0).getKind());
    }

    @Test void schemaInstanceHintsCannotPromoteAnOpaqueScopedIdentifier() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> SamlReplayCache.MarkResult.MARKED;
        SamlResponseSemantics.Expectation approved = new SamlResponseSemantics.Expectation(
                SP, "tenant-one", IDP, ACS, "_request", "relay", Instant.parse("2026-10-09T00:10:00Z"),
                fixedClock(), Duration.ofMinutes(3), Duration.ofMinutes(5), false,
                List.of("example.test"), cache, Duration.ofSeconds(5));
        String attribute = "<a:AttributeStatement><a:Attribute "
                + "Name='urn:oasis:names:tc:SAML:attribute:subject-id'>"
                + "<a:AttributeValue xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                + "xmlns:xs='http://www.w3.org/2001/XMLSchema' %s>alice@example.test"
                + "</a:AttributeValue></a:Attribute></a:AttributeStatement>";
        for (String hint : List.of("xsi:nil='true'", "xsi:nil='1'",
                "xsi:type='xs:boolean'", "xsi:type='xs:string' xsi:nil='true'",
                "xsi:type='shadow:string' xmlns:shadow='urn:attacker:shadow'")) {
            String xml = BASE.replace("</a:Assertion>", attribute.formatted(hint) + "</a:Assertion>");
            SamlResponseSemantics.Accepted accepted = assertInstanceOf(
                    SamlResponseSemantics.Accepted.class,
                    validate(xml, true, false, key, approved), hint);
            assertEquals(null, accepted.subjectId(), hint);
            assertEquals(List.of(), accepted.attributes(), hint);
        }
        for (String hint : List.of("xsi:type='xs:string'", "xsi:nil='false'")) {
            String xml = BASE.replace("</a:Assertion>", attribute.formatted(hint) + "</a:Assertion>");
            SamlResponseSemantics.Accepted accepted = assertInstanceOf(
                    SamlResponseSemantics.Accepted.class,
                    validate(xml, true, false, key, approved), hint);
            assertEquals("alice@example.test", accepted.subjectId(), hint);
            assertEquals(List.of("alice@example.test"), accepted.attributes().get(0).getValues(), hint);
        }
    }

    @Test void signedIdentityAndAudienceScalarsRejectMisleadingSchemaTypes() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String xsi = "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' ";
        String xs = "xmlns:xs='http://www.w3.org/2001/XMLSchema' ";
        String nameId = "<a:NameID>alice</a:NameID>";
        for (String attributes : List.of("xsi:nil='true'", "xsi:nil='1'",
                "xsi:type='xs:string'")) {
            String xml = BASE.replace(nameId,
                    "<a:NameID " + xsi + xs + attributes + ">alice</a:NameID>");
            assertEquals(SamlResponseSemantics.Reason.SUBJECT,
                    rejected(validate(xml, true, false, key, expected(cache))), attributes);
        }
        String emptyTypePrefix = BASE.replace(nameId,
                "<a:NameID xmlns='urn:oasis:names:tc:SAML:2.0:assertion' " + xsi
                        + "xsi:type=':NameIDType'>alice</a:NameID>");
        assertEquals(SamlResponseSemantics.Reason.SUBJECT,
                rejected(validate(emptyTypePrefix, true, false, key, expected(cache))));
        String issuer = "<a:Issuer>" + IDP + "</a:Issuer>";
        String nilIssuer = BASE.replace(issuer,
                "<a:Issuer " + xsi + "xsi:nil='true'>" + IDP + "</a:Issuer>");
        assertEquals(SamlResponseSemantics.Reason.ISSUER,
                rejected(validate(nilIssuer, true, false, key, expected(cache))));
        String audience = "<a:Audience>" + SP + "</a:Audience>";
        for (String attributes : List.of("xsi:nil='true'", "xsi:type='xs:string'")) {
            String xml = BASE.replace(audience,
                    "<a:Audience " + xsi + xs + attributes + ">" + SP + "</a:Audience>");
            assertEquals(SamlResponseSemantics.Reason.CONDITIONS,
                    rejected(validate(xml, true, false, key, expected(cache))), attributes);
        }
        String authn = AUTHN;
        String nilContext = "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'>"
                + "<a:AuthnContext><a:AuthnContextClassRef " + xsi + "xsi:nil='true'>"
                + "urn:example:loa2</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement>";
        assertEquals(SamlResponseSemantics.Reason.AUTHN_STATEMENT,
                rejected(validate(BASE.replace(authn, nilContext), true, false, key, expected(cache))));
        assertEquals(0, writes.get());

        String validNameId = BASE.replace(nameId,
                "<a:NameID " + xsi + "xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' "
                        + "xsi:type='saml:NameIDType'>alice</a:NameID>");
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(validNameId, true, false, key, expected(cache)));
        String validAudience = BASE.replace(audience,
                "<a:Audience " + xsi + xs + "xsi:type='xs:anyURI'>" + SP + "</a:Audience>");
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(validAudience, true, false, key, expected(cache)));
    }

    @Test void signedSuccessStatusRequiresAnUnambiguousTypedCodeBeforeReplay() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String original = "<p:Status><p:StatusCode "
                + "Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></p:Status>";
        String success = "urn:oasis:names:tc:SAML:2.0:status:Success";
        for (String status : List.of(
                "<p:Status xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:nil='true'>"
                        + "<p:StatusCode Value='" + success + "'/></p:Status>",
                "<p:Status xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                        + "xmlns:xs='http://www.w3.org/2001/XMLSchema' xsi:type='xs:string'>"
                        + "<p:StatusCode Value='" + success + "'/></p:Status>",
                "<p:Status>attacker<p:StatusCode Value='" + success + "'/></p:Status>",
                "<p:Status>&#x2003;<p:StatusCode Value='" + success + "'/></p:Status>",
                "<p:Status><p:StatusCode xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                        + "xsi:nil='true' Value='" + success + "'/></p:Status>",
                "<p:Status><p:StatusCode xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                        + "xmlns:xs='http://www.w3.org/2001/XMLSchema' xsi:type='xs:string' "
                        + "Value='" + success + "'/></p:Status>",
                "<p:Status><p:StatusCode Value='" + success + "'>attacker</p:StatusCode></p:Status>",
                "<p:Status><p:StatusCode Value='" + success + "'>&#x2003;</p:StatusCode></p:Status>",
                "<p:Status><x:Shadow xmlns:x='urn:attacker:shadow'/><p:StatusCode Value='"
                        + success + "'/></p:Status>",
                "<p:Status><p:StatusCode Value='" + success + "'/>"
                        + "<p:StatusMessage>ok</p:StatusMessage><p:StatusMessage>override</p:StatusMessage>"
                        + "</p:Status>")) {
            assertEquals(SamlResponseSemantics.Reason.STATUS,
                    rejected(validate(BASE.replace(original, status), true, false, key, expected(cache))), status);
        }
        assertEquals(0, writes.get());

        String valid = "<p:Status xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                + "xsi:nil='false'><p:StatusCode xsi:type='p:StatusCodeType' Value='" + success
                + "'/><p:StatusMessage>ok</p:StatusMessage>"
                + "<p:StatusDetail><x:Detail xmlns:x='urn:example:status'/></p:StatusDetail></p:Status>";
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE.replace(original, valid), true, false, key, expected(cache)));
        String detailWithoutMessage = "<p:Status><p:StatusCode Value='" + success + "'/>"
                + "<p:StatusDetail><x:Detail xmlns:x='urn:example:status'/>"
                + "</p:StatusDetail></p:Status>";
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE.replace(original, detailWithoutMessage), true, false, key, expected(cache)));
        assertEquals(2, writes.get());
    }

    @Test void signedSuccessRequiresNonNilledTextFreeResponseEnvelopeBeforeReplay() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        for (String malformed : List.of(
                BASE.replace("Destination='" + ACS + "' InResponseTo='",
                        "Destination='" + ACS + "' "
                        + "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                        + "xsi:nil='true' InResponseTo='"),
                BASE.replace("</p:Response>", "&#x2003;</p:Response>"))) {
            assertEquals(SamlResponseSemantics.Reason.ASSERTION_SHAPE,
                    rejected(validate(malformed, true, false, key, expected(cache))));
        }
        assertEquals(0, writes.get());
        String typed = BASE.replace("Destination='" + ACS + "' InResponseTo='",
                "Destination='" + ACS + "' "
                        + "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
                        + "xsi:type='p:ResponseType' xsi:nil='false' InResponseTo='");
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(typed, true, false, key, expected(cache)));
        assertEquals(1, writes.get());
    }

    @Test void signedSubjectAndAuthnStatementRejectOutOfOrderOrUnexpectedChildren() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> SamlReplayCache.MarkResult.MARKED;
        String originalNameId = "<a:NameID>alice</a:NameID>";
        String confirmation = "<a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>"
                + "<a:SubjectConfirmationData Recipient='" + ACS + "' InResponseTo='_request' "
                + "NotOnOrAfter='2026-10-09T00:05:00Z'/></a:SubjectConfirmation>";
        String outOfOrderSubject = BASE.replace(originalNameId + confirmation,
                confirmation + originalNameId);
        assertEquals(SamlResponseSemantics.Reason.SUBJECT,
                rejected(validate(outOfOrderSubject, true, false, key, expected(cache))));

        String authn = AUTHN;
        String context = "<a:AuthnContext><a:AuthnContextClassRef>urn:example:loa2"
                + "</a:AuthnContextClassRef></a:AuthnContext>";
        for (String content : List.of(
                context + "<a:SubjectLocality Address='127.0.0.1'/>",
                "<a:SubjectLocality/><a:SubjectLocality/>" + context,
                "<x:Shadow xmlns:x='urn:attacker:shadow'/>" + context)) {
            String xml = BASE.replace(authn,
                    "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'>"
                            + content + "</a:AuthnStatement>");
            assertEquals(SamlResponseSemantics.Reason.AUTHN_STATEMENT,
                    rejected(validate(xml, true, false, key, expected(cache))), content);
        }
        String ordered = BASE.replace(authn,
                "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'>"
                        + "<a:SubjectLocality Address='127.0.0.1'/>" + context
                        + "</a:AuthnStatement>");
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(ordered, true, false, key, expected(cache)));
    }

    @Test void signedBearerConfirmationRequiresOneUnambiguousBoundDataElement() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String xsi = "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' ";
        String data = "<a:SubjectConfirmationData Recipient='" + ACS + "' InResponseTo='_request' "
                + "NotOnOrAfter='2026-10-09T00:05:00Z'/>";
        String confirmation = "<a:SubjectConfirmation Method='urn:oasis:names:tc:SAML:2.0:cm:bearer'>";
        assertEquals(SamlResponseSemantics.Reason.SUBJECT,
                rejected(validate(BASE.replace("<a:Subject>",
                        "<a:Subject " + xsi + "xsi:nil='true'>"),
                        true, false, key, expected(cache))));
        for (String xml : List.of(
                BASE.replace(confirmation, confirmation.replace(" Method=", " " + xsi
                        + "xsi:nil='true' Method=")),
                BASE.replace(data, data.replace(" Recipient=", " " + xsi
                        + "xsi:nil='true' Recipient=")),
                BASE.replace(data, data.replace(" Recipient=", " " + xsi
                        + "xmlns:xs='http://www.w3.org/2001/XMLSchema' "
                        + "xsi:type='xs:string' Recipient=")),
                BASE.replace(confirmation, confirmation + "<x:Shadow xmlns:x='urn:shadow'/>") ,
                BASE.replace(data, data + "<x:Shadow xmlns:x='urn:shadow'/>") ,
                BASE.replace(data, data.substring(0, data.length() - 2)
                        + ">shadow</a:SubjectConfirmationData>"),
                BASE.replace(data, data.replace(" Recipient=",
                        " NotBefore='2026-10-09T00:03:00Z' Recipient=")
                        .replace("00:05:00Z", "00:02:00Z")),
                BASE.replace(data, data.replace(" Recipient=",
                        " NotBefore='2026-10-09T00:02:00Z' Recipient=")
                        .replace("00:05:00Z", "00:02:00Z")),
                BASE.replace(confirmation + data, confirmation
                        + "<a:NameID>mallory</a:NameID>" + data))) {
            assertEquals(SamlResponseSemantics.Reason.CONFIRMATION,
                    rejected(validate(xml, true, false, key, expected(cache))), xml);
        }
        assertEquals(0, writes.get());
        String matchingConfirmation = BASE.replace(confirmation + data, confirmation
                + "<a:NameID>alice</a:NameID>" + data);
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(matchingConfirmation, true, false, key, expected(cache)));
        String validBoundedWindow = BASE.replace(data,
                data.replace(" Recipient=", " NotBefore='2026-10-09T00:00:00Z' Recipient="));
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(validBoundedWindow, true, false, key, expected(cache)));
        assertEquals(2, writes.get());
    }

    @Test void signedConditionsRejectMalformedOptionalRestrictionsBeforeReplay() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String xsi = "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' ";
        String conditions = "<a:Conditions NotBefore='2026-10-08T23:59:00Z'";
        String restriction = "<a:AudienceRestriction>";
        for (String xml : List.of(
                BASE.replace(conditions, "<a:Conditions " + xsi + "xsi:nil='true'"
                        + " NotBefore='2026-10-08T23:59:00Z'"),
                BASE.replace(conditions, "<a:Conditions " + xsi
                        + "xmlns:xs='http://www.w3.org/2001/XMLSchema' xsi:type='xs:string'"
                        + " NotBefore='2026-10-08T23:59:00Z'"),
                BASE.replace(restriction, "<a:AudienceRestriction " + xsi
                        + "xsi:nil='true'>"),
                BASE.replace("</a:Conditions>",
                        "<a:OneTimeUse><x:Shadow xmlns:x='urn:shadow'/></a:OneTimeUse>"
                                + "</a:Conditions>"),
                BASE.replace("</a:Conditions>",
                        "<a:ProxyRestriction Count='-1'/></a:Conditions>"),
                BASE.replace("</a:Conditions>",
                        "<a:ProxyRestriction><x:Shadow xmlns:x='urn:shadow'/>"
                                + "</a:ProxyRestriction></a:Conditions>"),
                BASE.replace("</a:Conditions>",
                        "<a:ProxyRestriction " + xsi + "xsi:nil='true'/>"
                                + "</a:Conditions>"))) {
            assertEquals(SamlResponseSemantics.Reason.CONDITIONS,
                    rejected(validate(xml, true, false, key, expected(cache))), xml);
        }
        assertEquals(0, writes.get());
        String valid = BASE.replace("</a:Conditions>",
                "<a:OneTimeUse/><a:ProxyRestriction Count='0'>"
                        + "<a:Audience>https://downstream.example.test/</a:Audience>"
                        + "</a:ProxyRestriction></a:Conditions>");
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(valid, true, false, key, expected(cache)));
    }

    @Test void signedConditionsBoundAudienceAndOptionalRestrictionCardinality() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String audience = "<a:AudienceRestriction><a:Audience>" + SP
                + "</a:Audience></a:AudienceRestriction>";
        String oneTime = "<a:OneTimeUse/>";
        String proxy = "<a:ProxyRestriction Count='0'/>";
        Map<String, String> invalid = Map.ofEntries(
                Map.entry("no audience restriction", BASE.replace(audience, "")),
                Map.entry("unsupported restriction", BASE.replace(audience,
                        audience + "<a:OtherRestriction/>")),
                Map.entry("nested audience", BASE.replace("<a:Audience>" + SP + "</a:Audience>",
                        "<a:Audience><a:NameID>" + SP + "</a:NameID></a:Audience>")),
                Map.entry("duplicate one-time-use", BASE.replace(audience,
                        audience + oneTime + oneTime)),
                Map.entry("duplicate proxy restriction", BASE.replace(audience,
                        audience + proxy + proxy)),
                Map.entry("negative proxy count", BASE.replace(audience,
                        audience + "<a:ProxyRestriction Count='-1'/>")),
                Map.entry("noninteger proxy count", BASE.replace(audience,
                        audience + "<a:ProxyRestriction Count='1.0'/>")),
                Map.entry("empty proxy count", BASE.replace(audience,
                        audience + "<a:ProxyRestriction Count=''/>")),
                Map.entry("sign-only proxy count", BASE.replace(audience,
                        audience + "<a:ProxyRestriction Count='+'/>")),
                Map.entry("empty proxy audience", BASE.replace(audience,
                        audience + "<a:ProxyRestriction><a:Audience/></a:ProxyRestriction>")),
                Map.entry("unexpected proxy child", BASE.replace(audience,
                        audience + "<a:ProxyRestriction><a:NameID>alice</a:NameID>"
                                + "</a:ProxyRestriction>")));
        for (Map.Entry<String, String> caseUnderTest : invalid.entrySet())
            assertEquals(SamlResponseSemantics.Reason.CONDITIONS,
                    rejected(validate(caseUnderTest.getValue(), true, false, key, expected(cache))),
                    caseUnderTest.getKey());
        assertEquals(0, writes.get());
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE.replace(audience, audience + oneTime
                        + "<a:ProxyRestriction Count='+0'/>"), true, false, key, expected(cache)));
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE.replace(audience, audience + "<a:ProxyRestriction Count='9'/>"),
                        true, false, key, expected(cache)));
        assertEquals(2, writes.get());
    }

    @Test void signedAuthenticationStatementEnforcesSessionAndLocalityLimits() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String authn = AUTHN;
        String open = "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'>";
        String context = "<a:AuthnContext><a:AuthnContextClassRef>urn:example:password"
                + "</a:AuthnContextClassRef></a:AuthnContext>";
        String locality = "<a:SubjectLocality Address='127.0.0.1'/>";
        Map<String, String> invalid = Map.ofEntries(
                Map.entry("duplicate statement", BASE.replace(authn, authn + authn)),
                Map.entry("malformed session expiry", BASE.replace(authn, authn.replace(
                        "AuthnInstant=", "SessionNotOnOrAfter='invalid' AuthnInstant="))),
                Map.entry("expired session", BASE.replace(authn, authn.replace(
                        "AuthnInstant=", "SessionNotOnOrAfter='2026-10-08T00:00:00Z' AuthnInstant="))),
                Map.entry("long session index", BASE.replace(authn, authn.replace(
                        "AuthnInstant=", "SessionIndex='" + "x".repeat(2049) + "' AuthnInstant="))),
                Map.entry("duplicate subject locality", BASE.replace(authn,
                        open + locality + locality + context + "</a:AuthnStatement>")),
                Map.entry("nested subject locality", BASE.replace(authn,
                        open + "<a:SubjectLocality><a:NameID>alice</a:NameID>"
                                + "</a:SubjectLocality>" + context + "</a:AuthnStatement>")));
        for (Map.Entry<String, String> caseUnderTest : invalid.entrySet())
            assertEquals(SamlResponseSemantics.Reason.AUTHN_STATEMENT,
                    rejected(validate(caseUnderTest.getValue(), true, false, key, expected(cache))),
                    caseUnderTest.getKey());
        assertEquals(0, writes.get());
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE.replace(authn, authn.replace("AuthnInstant=",
                        "SessionIndex='" + "x".repeat(2048)
                                + "' SessionNotOnOrAfter='2026-10-09T00:05:00Z' AuthnInstant=")),
                        true, false, key, expected(cache)));
        assertEquals(1, writes.get());
    }

    @Test void signedAttributeLimitsFailBeforeReplayOrIdentityRelease() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String value = "<a:AttributeValue>member</a:AttributeValue>";
        String attribute = "<a:Attribute Name='role'>" + value + "</a:Attribute>";
        String statement = "<a:AttributeStatement>" + attribute + "</a:AttributeStatement>";
        Map<String, String> invalid = Map.ofEntries(
                Map.entry("too many attributes", BASE.replace("</a:Assertion>",
                        "<a:AttributeStatement>" + attribute.repeat(129)
                                + "</a:AttributeStatement></a:Assertion>")),
                Map.entry("too many values", BASE.replace("</a:Assertion>",
                        "<a:AttributeStatement><a:Attribute Name='role'>" + value.repeat(257)
                                + "</a:Attribute></a:AttributeStatement></a:Assertion>")),
                Map.entry("long attribute name", BASE.replace("</a:Assertion>",
                        statement.replace("Name='role'", "Name='" + "x".repeat(2049) + "'")
                                + "</a:Assertion>")),
                Map.entry("long name format", BASE.replace("</a:Assertion>",
                        statement.replace("Name='role'", "Name='role' NameFormat='"
                                + "x".repeat(2049) + "'") + "</a:Assertion>")),
                Map.entry("long friendly name", BASE.replace("</a:Assertion>",
                        statement.replace("Name='role'", "Name='role' FriendlyName='"
                                + "x".repeat(2049) + "'") + "</a:Assertion>")),
                Map.entry("long text value", BASE.replace("</a:Assertion>",
                        statement.replace("member", "x".repeat(4097)) + "</a:Assertion>")));
        for (Map.Entry<String, String> caseUnderTest : invalid.entrySet())
            assertEquals(SamlResponseSemantics.Reason.ASSERTION_SHAPE,
                    rejected(validate(caseUnderTest.getValue(), true, false, key, expected(cache))),
                    caseUnderTest.getKey());
        assertEquals(0, writes.get());
        SamlResponseSemantics.Accepted accepted = assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE.replace("</a:Assertion>", statement + "</a:Assertion>"),
                        true, false, key, expected(cache)));
        assertEquals(List.of("member"), accepted.attributes().get(0).getValues());
        assertEquals(1, writes.get());
    }

    @Test void signedAttributeValuesAtTheirDeclaredLimitsRemainUsable() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> SamlReplayCache.MarkResult.MARKED;
        String value = "<a:AttributeValue>member</a:AttributeValue>";
        String maximumName = "n".repeat(2048);
        String named = "<a:AttributeStatement><a:Attribute Name='" + maximumName + "'>"
                + value + "</a:Attribute></a:AttributeStatement>";
        SamlResponseSemantics.Accepted namedResult = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(BASE.replace("</a:Assertion>", named + "</a:Assertion>"),
                        true, false, key, expected(cache)));
        assertEquals(maximumName, namedResult.attributes().get(0).getName());

        String maximumValue = "v".repeat(4096);
        String valued = "<a:AttributeStatement><a:Attribute Name='role'>"
                + "<a:AttributeValue>" + maximumValue + "</a:AttributeValue>"
                + "</a:Attribute></a:AttributeStatement>";
        SamlResponseSemantics.Accepted valuedResult = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(BASE.replace("</a:Assertion>", valued + "</a:Assertion>"),
                        true, false, key, expected(cache)));
        assertEquals(maximumValue, valuedResult.attributes().get(0).getValues().get(0));

        String maximumValues = "<a:AttributeStatement><a:Attribute Name='role'>"
                + value.repeat(256) + "</a:Attribute></a:AttributeStatement>";
        SamlResponseSemantics.Accepted valuesResult = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(BASE.replace("</a:Assertion>", maximumValues + "</a:Assertion>"),
                        true, false, key, expected(cache)));
        assertEquals(256, valuesResult.attributes().get(0).getValues().size());
    }

    @Test void signedAssertionRequiresOrderedIssuerSubjectConditionsAndAdvice() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String xsi = "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' ";
        String subject = BASE.substring(BASE.indexOf("<a:Subject>"),
                BASE.indexOf("</a:Subject>") + "</a:Subject>".length());
        String conditions = BASE.substring(BASE.indexOf("<a:Conditions "),
                BASE.indexOf("</a:Conditions>") + "</a:Conditions>".length());
        String issuer = "<a:Issuer>" + IDP + "</a:Issuer>";
        for (String xml : List.of(
                BASE.replace("<a:Assertion ", "<a:Assertion " + xsi + "xsi:nil='true' "),
                BASE.replace("<a:Assertion ", "<a:Assertion " + xsi
                        + "xmlns:xs='http://www.w3.org/2001/XMLSchema' "
                        + "xsi:type='xs:string' "),
                BASE.replace(issuer + subject, subject + issuer),
                BASE.replace(subject + conditions, conditions + subject),
                BASE.replace("</a:Assertion>", "<a:Advice/></a:Assertion>"),
                BASE.replace("</a:Assertion>",
                        "<a:Advice/><a:Advice/></a:Assertion>"))) {
            assertEquals(SamlResponseSemantics.Reason.ASSERTION_SHAPE,
                    rejected(validate(xml, true, false, key, expected(cache))), xml);
        }
        assertEquals(0, writes.get());
        String ordered = BASE.replace("<a:AuthnStatement",
                "<a:Advice/><a:AuthnStatement");
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(ordered, true, false, key, expected(cache)));
    }

    @Test void signedAttributeContainersCannotPromoteNilledIdentity() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String xsi = "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' ";
        String attribute = "<a:Attribute Name='urn:oasis:names:tc:SAML:attribute:subject-id'>"
                + "<a:AttributeValue>alice@example.test</a:AttributeValue></a:Attribute>";
        String statement = "<a:AttributeStatement>" + attribute + "</a:AttributeStatement>";
        SamlResponseSemantics.Expectation approved = new SamlResponseSemantics.Expectation(
                SP, "tenant-one", IDP, ACS, "_request", "relay",
                Instant.parse("2026-10-09T00:10:00Z"), fixedClock(), Duration.ofMinutes(3),
                Duration.ofMinutes(5), false, List.of("example.test"), cache,
                Duration.ofSeconds(5));
        for (String xml : List.of(
                BASE.replace("<a:Conditions ", statement + "<a:Conditions "),
                BASE.replace("</a:Assertion>",
                        statement.replace("<a:AttributeStatement>",
                                "<a:AttributeStatement " + xsi + "xsi:nil='true'>")
                                + "</a:Assertion>"),
                BASE.replace("</a:Assertion>",
                        statement.replace("<a:Attribute Name=",
                                "<a:Attribute " + xsi + "xsi:nil='true' Name=")
                                + "</a:Assertion>"),
                BASE.replace("</a:Assertion>",
                        statement.replace("<a:Attribute Name=",
                                "<a:Attribute " + xsi
                                + "xmlns:xs='http://www.w3.org/2001/XMLSchema' "
                                + "xsi:type='xs:string' Name=") + "</a:Assertion>"),
                BASE.replace("</a:Assertion>",
                        statement.replace("<a:AttributeStatement>",
                                "<a:AttributeStatement>shadow") + "</a:Assertion>"))) {
            assertEquals(SamlResponseSemantics.Reason.ASSERTION_SHAPE,
                    rejected(validate(xml, true, false, key, approved)), xml);
        }
        assertEquals(0, writes.get());
        String valid = BASE.replace("<a:AuthnStatement",
                statement.replace("<a:AttributeStatement>",
                        "<a:AttributeStatement " + xsi
                                + "xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' "
                                + "xsi:type='saml:AttributeStatementType'>")
                        + "<a:AuthnStatement");
        SamlResponseSemantics.Accepted accepted = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(valid, true, false, key, approved));
        assertEquals("alice@example.test", accepted.subjectId());
    }

    @Test void acceptsAssertionOnlyAndRequiresAnAssertionSignatureWhenConfigured() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> SamlReplayCache.MarkResult.MARKED;
        SamlResponseSemantics.Accepted accepted = assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE, false, true, key, expected(cache)));
        assertEquals(false, accepted.responseSigned());
        assertTrue(accepted.assertionSigned());
        SamlResponseSemantics.Expectation strict = new SamlResponseSemantics.Expectation(
                SP, "tenant-one", IDP, ACS, "_request", "relay", Instant.parse("2026-10-09T00:10:00Z"),
                fixedClock(), Duration.ofMinutes(3), Duration.ofMinutes(5), true, List.of(), cache,
                Duration.ofSeconds(5));
        assertEquals(SamlResponseSemantics.Reason.COVERAGE,
                rejected(validate(BASE, true, false, key, strict)));
    }

    @Test void bindingAndAudienceFailuresCannotWriteReplay() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        assertEquals(SamlResponseSemantics.Reason.DESTINATION,
                rejected(validate(BASE.replace("Destination='" + ACS + "'", "Destination='https://evil.test/acs'"),
                        true, false, key, expected(cache))));
        assertEquals(SamlResponseSemantics.Reason.REQUEST_BINDING,
                rejected(validate(BASE.replace("InResponseTo='_request'>", "InResponseTo='_other'>"),
                        true, false, key, expected(cache))));
        assertEquals(SamlResponseSemantics.Reason.CONDITIONS,
                rejected(validate(BASE.replace("<a:Audience>" + SP, "<a:Audience>https://evil.test"),
                        true, false, key, expected(cache))));
        String secondRestriction = BASE.replace("</a:Conditions>",
                "<a:AudienceRestriction><a:Audience>https://evil.test</a:Audience>"
                        + "</a:AudienceRestriction></a:Conditions>");
        assertEquals(SamlResponseSemantics.Reason.CONDITIONS,
                rejected(validate(secondRestriction, true, false, key, expected(cache))));
        assertEquals(0, writes.get());
    }

    @Test void assertionOnlySignatureBindsRecipientWithoutResponseDestination() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String envelope = BASE.replace(" Destination='" + ACS + "'", "");
        String recipient = " Recipient='" + ACS + "'";
        for (String xml : List.of(
                envelope.replace(recipient, " Recipient='https://other.example.test/acs'"),
                envelope.replace(recipient, ""))) {
            assertEquals(SamlResponseSemantics.Reason.CONFIRMATION,
                    rejected(validate(xml, false, true, key, expected(cache))));
        }
        assertEquals(0, writes.get());
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(envelope, false, true, key, expected(cache)));
        assertEquals(1, writes.get());
    }

    @Test void rejectsNestedNameIdAndExpiredBearer() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> SamlReplayCache.MarkResult.MARKED;
        String nested = BASE.replace("<a:NameID>alice</a:NameID>",
                "<a:NameID>ali<x:Part xmlns:x='urn:test'>ce</x:Part></a:NameID>");
        assertEquals(SamlResponseSemantics.Reason.SUBJECT,
                rejected(validate(nested, true, false, key, expected(cache))));
        String expired = BASE.replace("NotOnOrAfter='2026-10-09T00:05:00Z'/></a:SubjectConfirmation>",
                "NotOnOrAfter='2026-10-08T00:00:00Z'/></a:SubjectConfirmation>");
        assertEquals(SamlResponseSemantics.Reason.CONFIRMATION,
                rejected(validate(expired, true, false, key, expected(cache))));
    }

    @Test void authnContextSchemaOrderAllowsOptionalDeclarationButRejectsDuplicates() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) ->
                SamlReplayCache.MarkResult.MARKED;
        String original = AUTHN;
        String withClassRef = "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'>"
                + "<a:AuthnContext><a:AuthnContextClassRef>urn:example:loa2"
                + "</a:AuthnContextClassRef><a:AuthenticatingAuthority>https://idp.example.test/saml"
                + "</a:AuthenticatingAuthority></a:AuthnContext></a:AuthnStatement>";
        SamlResponseSemantics.Accepted classRef = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(BASE.replace(original, withClassRef), true, false, key, expected(cache)));
        assertEquals("urn:example:loa2", classRef.authnContextClassRef());
        String withDeclRef = withClassRef.replace(
                "<a:AuthnContextClassRef>urn:example:loa2</a:AuthnContextClassRef>",
                "<a:AuthnContextDeclRef>urn:example:decl</a:AuthnContextDeclRef>");
        SamlResponseSemantics.Accepted declRef = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(BASE.replace(original, withDeclRef), true, false, key, expected(cache)));
        assertEquals(null, declRef.authnContextClassRef());
        String withBoth = withClassRef.replace("</a:AuthnContextClassRef>",
                "</a:AuthnContextClassRef><a:AuthnContextDeclRef>urn:example:decl"
                        + "</a:AuthnContextDeclRef>");
        SamlResponseSemantics.Accepted both = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(BASE.replace(original, withBoth), true, false, key, expected(cache)));
        assertEquals("urn:example:loa2", both.authnContextClassRef());
        String conflicting = withClassRef.replace("</a:AuthnContextClassRef>",
                "</a:AuthnContextClassRef><a:AuthnContextClassRef>urn:attacker:weak-context"
                        + "</a:AuthnContextClassRef>");
        assertEquals(SamlResponseSemantics.Reason.AUTHN_STATEMENT,
                rejected(validate(BASE.replace(original, conflicting), true, false,
                        key, expected(cache))));
        String outOfOrder = withClassRef.replace("</a:AuthnContext>",
                "<a:AuthnContextDeclRef>urn:example:decl</a:AuthnContextDeclRef>"
                        + "</a:AuthnContext>");
        assertEquals(SamlResponseSemantics.Reason.AUTHN_STATEMENT,
                rejected(validate(BASE.replace(original, outOfOrder), true, false,
                        key, expected(cache))));
    }

    @Test void signedAuthenticationContextTextHasAnExactBound() throws Exception {
        KeyPair key = rsa();
        SamlReplayCache cache = (replayKey, expiry, remaining) ->
                SamlReplayCache.MarkResult.MARKED;
        String original = AUTHN;
        String prefix = "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'>"
                + "<a:AuthnContext>";
        String suffix = "</a:AuthnContext></a:AuthnStatement>";
        String classRef = "<a:AuthnContextClassRef>urn:loa</a:AuthnContextClassRef>";
        for (int length : List.of(2048, 2049)) {
            String text = "u".repeat(length);
            for (String context : List.of(
                    "<a:AuthnContextClassRef>" + text + "</a:AuthnContextClassRef>",
                    "<a:AuthnContextDeclRef>" + text + "</a:AuthnContextDeclRef>",
                    classRef + "<a:AuthenticatingAuthority>" + text
                            + "</a:AuthenticatingAuthority>")) {
                SamlResponseSemantics.Result result = validate(BASE.replace(original,
                        prefix + context + suffix), true, false, key, expected(cache));
                if (length == 2048)
                    assertInstanceOf(SamlResponseSemantics.Accepted.class, result, context);
                else
                    assertEquals(SamlResponseSemantics.Reason.AUTHN_STATEMENT,
                            rejected(result), context);
            }
        }
    }

    @Test void signedAuthenticationContextAndLocalityRejectScalarOverridesBeforeReplay() throws Exception {
        KeyPair key = rsa();
        java.util.concurrent.atomic.AtomicInteger marks = new java.util.concurrent.atomic.AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            marks.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String original = AUTHN;
        String statement = "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'>"
                + "<a:SubjectLocality Address='192.0.2.1'/>"
                + "<a:AuthnContext><a:AuthnContextClassRef>urn:example:loa2"
                + "</a:AuthnContextClassRef></a:AuthnContext></a:AuthnStatement>";
        String valid = BASE.replace(original, statement);
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(valid, true, false, key, expected(cache)));
        marks.set(0);
        String xsi = " xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'";
        for (String mutation : List.of(
                valid.replace("<a:AuthnContext>", "<a:AuthnContext" + xsi + " xsi:nil='true'>"),
                valid.replace("<a:AuthnContext>", "<a:AuthnContext" + xsi + " xsi:type='xsi:string'>"),
                valid.replace("<a:AuthnContext>", "<a:AuthnContext>shadow"),
                valid.replace("<a:SubjectLocality Address='192.0.2.1'/>",
                        "<a:SubjectLocality Address='192.0.2.1'" + xsi + " xsi:nil='true'/>"),
                valid.replace("<a:SubjectLocality Address='192.0.2.1'/>",
                        "<a:SubjectLocality Address='192.0.2.1'>shadow</a:SubjectLocality>"))) {
            assertEquals(SamlResponseSemantics.Reason.AUTHN_STATEMENT,
                    rejected(validate(mutation, true, false, key, expected(cache))));
        }
        assertEquals(0, marks.get());
    }

    @Test void assertionSignatureCannotSupplyAResponseIssuer() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String missingResponseIssuer = BASE.replaceFirst(
                java.util.regex.Pattern.quote("<a:Issuer>" + IDP + "</a:Issuer>"), "");
        assertEquals(SamlResponseSemantics.Reason.ISSUER,
                rejected(validate(missingResponseIssuer, false, true, key, expected(cache))));
        assertEquals(0, writes.get());
    }

    @Test void replayStoreDistinguishesReplayUnavailableAndUncertainWrite() throws Exception {
        KeyPair key = rsa();
        Set<String> seen = new HashSet<>();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> seen.add(replayKey)
                ? SamlReplayCache.MarkResult.MARKED : SamlReplayCache.MarkResult.ALREADY_PRESENT;
        assertInstanceOf(SamlResponseSemantics.Accepted.class, validate(BASE, true, false, key, expected(cache)));
        assertEquals(SamlResponseSemantics.Reason.REPLAYED,
                rejected(validate(BASE, true, false, key, expected(cache))));
        SamlReplayCache unavailable = (replayKey, expiry, remaining) ->
                SamlReplayCache.MarkResult.UNAVAILABLE;
        assertInstanceOf(SamlResponseSemantics.Unavailable.class,
                validate(BASE, true, false, key, expected(unavailable)));
        SamlReplayCache indeterminate = (replayKey, expiry, remaining) ->
                SamlReplayCache.MarkResult.INDETERMINATE;
        assertInstanceOf(SamlResponseSemantics.Indeterminate.class,
                validate(BASE, true, false, key, expected(indeterminate)));
    }

    @Test void replayKeysSeparateTenantPartnerAssertionAndFieldBoundaries() throws Exception {
        KeyPair key = rsa();
        Set<String> keys = new HashSet<>();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            assertTrue(keys.add(replayKey));
            return SamlReplayCache.MarkResult.MARKED;
        };
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE, true, false, key, replayExpectation(SP, "xy", IDP, cache)));

        String longerSp = SP + "x";
        String otherSpResponse = BASE.replace("<a:Audience>" + SP + "</a:Audience>",
                "<a:Audience>" + longerSp + "</a:Audience>");
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(otherSpResponse, true, false, key,
                        replayExpectation(longerSp, "y", IDP, cache)));
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(otherSpResponse, true, false, key,
                        replayExpectation(longerSp, "xy", IDP, cache)));
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE, true, false, key, replayExpectation(SP, "xz", IDP, cache)));

        String otherIdp = IDP + "/other";
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE.replace(IDP, otherIdp), true, false, key,
                        replayExpectation(SP, "xy", otherIdp, cache)));
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE.replace("ID='_assertion'", "ID='_other-assertion'"),
                        true, false, key, replayExpectation(SP, "xy", IDP, cache)));
        assertEquals(6, keys.size());
    }

    @Test void pendingMismatchAndMalformedAssertionContentFailBeforeReplay() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        SamlResponseSemantics.Expectation wrongRelay = new SamlResponseSemantics.Expectation(
                SP, "tenant-one", IDP, ACS, "_request", "other", Instant.parse("2026-10-09T00:10:00Z"),
                fixedClock(), Duration.ofMinutes(3), Duration.ofMinutes(5), false, List.of(), cache,
                Duration.ofSeconds(5));
        assertEquals(SamlResponseSemantics.Reason.PENDING,
                rejected(validate(BASE, true, false, key, wrongRelay)));
        assertEquals(SamlResponseSemantics.Reason.ASSERTION_SHAPE,
                rejected(validate(BASE.replace("</a:Assertion>", "<a:EncryptedAttribute/></a:Assertion>"),
                        true, false, key, expected(cache))));
        assertEquals(0, writes.get());
    }

    @Test void signedConditionsRejectMalformedAndInvertedWindowsBeforeReplayAdmission() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String original = "<a:Conditions NotBefore='2026-10-08T23:59:00Z' "
                + "NotOnOrAfter='2026-10-09T00:05:00Z'>";
        for (String invalid : List.of(
                "<a:Conditions NotBefore='invalid' NotOnOrAfter='2026-10-09T00:05:00Z'>",
                "<a:Conditions NotBefore='2026-10-08T23:59:00Z' NotOnOrAfter='invalid'>",
                "<a:Conditions NotBefore='2026-10-09T00:00:30Z' "
                        + "NotOnOrAfter='2026-10-09T00:00:15Z'>",
                "<a:Conditions NotBefore='2026-10-09T00:00:30Z' "
                        + "NotOnOrAfter='2026-10-09T00:00:30Z'>",
                "<a:Conditions NotBefore='2026-10-09T00:04:00.001Z' "
                        + "NotOnOrAfter='2026-10-09T00:05:00Z'>",
                "<a:Conditions NotBefore='2026-10-08T23:57:00Z' "
                        + "NotOnOrAfter='2026-10-08T23:58:00Z'>")) {
            assertEquals(SamlResponseSemantics.Reason.CONDITIONS,
                    rejected(validate(BASE.replace(original, invalid), true, false, key, expected(cache))),
                    invalid);
        }
        assertEquals(0, writes.get());

        String exactStart = "<a:Conditions NotBefore='2026-10-09T00:04:00Z' "
                + "NotOnOrAfter='2026-10-09T00:05:00Z'>";
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(BASE.replace(original, exactStart), true, false, key, expected(cache)));
        assertEquals(1, writes.get());
    }

    @Test void signedTemporalAndIssuerBoundariesFailBeforeReplayAdmission() throws Exception {
        KeyPair key = rsa();
        AtomicInteger writes = new AtomicInteger();
        SamlReplayCache cache = (replayKey, expiry, remaining) -> {
            writes.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        String conditionHead = "<a:Conditions NotBefore='2026-10-08T23:59:00Z' "
                + "NotOnOrAfter='2026-10-09T00:05:00Z'>";
        Map<String, SamlResponseSemantics.Reason> invalid = Map.ofEntries(
                Map.entry(BASE.replace("Destination='" + ACS + "' ", ""),
                        SamlResponseSemantics.Reason.DESTINATION),
                Map.entry(BASE.replace("InResponseTo='_request'", ""),
                        SamlResponseSemantics.Reason.REQUEST_BINDING),
                Map.entry(BASE.replace("ID='_assertion'", "ID='" + "a".repeat(257) + "'"),
                        SamlResponseSemantics.Reason.ASSERTION_SHAPE),
                Map.entry(BASE.replace(IDP, "https://untrusted.example.test/idp"),
                        SamlResponseSemantics.Reason.ISSUER),
                Map.entry(BASE.replace("<a:Issuer>",
                        "<a:Issuer Format='urn:example:unsupported'>"),
                        SamlResponseSemantics.Reason.ISSUER),
                Map.entry(BASE.replace("ID='_response' Version='2.0' IssueInstant='2026-10-09T00:00:00Z'",
                        "ID='_response' Version='2.0' IssueInstant='2026-10-09T00:10:00Z'"),
                        SamlResponseSemantics.Reason.RESPONSE_AGE),
                Map.entry(BASE.replace("ID='_assertion' Version='2.0' IssueInstant='2026-10-09T00:00:00Z'",
                        "ID='_assertion' Version='2.0' IssueInstant='2026-10-09T00:10:00Z'"),
                        SamlResponseSemantics.Reason.RESPONSE_AGE),
                Map.entry(BASE.replace(conditionHead,
                        "<a:Conditions NotBefore='2026-10-09T00:10:00Z' "
                                + "NotOnOrAfter='2026-10-09T00:15:00Z'>"),
                        SamlResponseSemantics.Reason.CONDITIONS),
                Map.entry(BASE.replace(conditionHead,
                        "<a:Conditions NotBefore='2026-10-08T19:00:00Z' "
                                + "NotOnOrAfter='2026-10-08T20:00:00Z'>"),
                        SamlResponseSemantics.Reason.CONDITIONS),
                Map.entry(BASE.replace(AUTHN,
                        AUTHN.replace("AuthnInstant='2026-10-09T00:00:00Z'",
                                "AuthnInstant='2026-10-09T00:10:00Z'")),
                        SamlResponseSemantics.Reason.AUTHN_STATEMENT));
        for (Map.Entry<String, SamlResponseSemantics.Reason> caseUnderTest : invalid.entrySet()) {
            SamlResponseSemantics.Rejected rejected = assertInstanceOf(
                    SamlResponseSemantics.Rejected.class,
                    validate(caseUnderTest.getKey(), true, false, key, expected(cache)),
                    caseUnderTest.getKey());
            assertEquals(caseUnderTest.getValue(), rejected.reason(), caseUnderTest.getKey());
        }
        assertEquals(0, writes.get());

        String earlierCondition = BASE.replace(conditionHead,
                "<a:Conditions NotBefore='2026-10-08T23:59:00Z' "
                        + "NotOnOrAfter='2026-10-09T00:02:00Z'>");
        SamlResponseSemantics.Accepted early = assertInstanceOf(
                SamlResponseSemantics.Accepted.class,
                validate(earlierCondition, true, false, key, expected(cache)));
        assertEquals(Instant.parse("2026-10-09T00:05:00Z"), early.expiresAt());

        String longestNameId = BASE.replace("<a:NameID>alice</a:NameID>",
                "<a:NameID>" + "x".repeat(4096) + "</a:NameID>");
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(longestNameId, true, false, key, expected(cache)));
        String oversizedNameId = BASE.replace("<a:NameID>alice</a:NameID>",
                "<a:NameID>" + "x".repeat(4097) + "</a:NameID>");
        assertEquals(SamlResponseSemantics.Reason.SUBJECT,
                rejected(validate(oversizedNameId, true, false, key, expected(cache))));
        String longestAssertionId = BASE.replace("ID='_assertion'", "ID='" + "a".repeat(256) + "'");
        assertInstanceOf(SamlResponseSemantics.Accepted.class,
                validate(longestAssertionId, true, false, key, expected(cache)));
        assertEquals(3, writes.get());
    }

    private static SamlResponseSemantics.@NonNull Result validate(@NonNull String xml, boolean signResponse,
            boolean signAssertion, @NonNull KeyPair key, SamlResponseSemantics.@NonNull Expectation expectation)
            throws Exception {
        String signed = signedXml(xml, signResponse, signAssertion, key.getPrivate());
        String encoded = Base64.getEncoder().encodeToString(signed.getBytes(StandardCharsets.UTF_8))
                .replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        SamlInboundResponse.Accepted inbound = assertInstanceOf(SamlInboundResponse.Accepted.class,
                SamlInboundResponse.parse(("SAMLResponse=" + encoded + "&RelayState=relay")
                        .getBytes(StandardCharsets.UTF_8), List.of(MIME), null));
        SamlInboundResponse.SignaturesVerified verified = assertInstanceOf(
                SamlInboundResponse.SignaturesVerified.class,
                SamlInboundResponse.verifySuccessSignatures(inbound, List.of(key.getPublic())));
        return SamlResponseSemantics.validate(verified, expectation);
    }

    private static SamlResponseSemantics.@NonNull Reason rejected(SamlResponseSemantics.@NonNull Result result) {
        return assertInstanceOf(SamlResponseSemantics.Rejected.class, result).reason();
    }

    private static SamlResponseSemantics.@NonNull Expectation expected(
            @NonNull SamlReplayCache cache) {
        return new SamlResponseSemantics.Expectation(SP, "tenant-one", IDP, ACS, "_request", "relay",
                Instant.parse("2026-10-09T00:10:00Z"), fixedClock(), Duration.ofMinutes(3),
                Duration.ofMinutes(5), false, List.of(), cache, Duration.ofSeconds(5));
    }

    private static SamlResponseSemantics.@NonNull Expectation replayExpectation(
            @NonNull String sp, @NonNull String connection, @NonNull String idp,
            @NonNull SamlReplayCache cache) {
        return new SamlResponseSemantics.Expectation(sp, connection, idp, ACS, "_request", "relay",
                Instant.parse("2026-10-09T00:10:00Z"), fixedClock(), Duration.ofMinutes(3),
                Duration.ofMinutes(5), false, List.of(), cache, Duration.ofSeconds(5));
    }

    private static @NonNull Clock fixedClock() {
        return Clock.fixed(Instant.parse(NOW), ZoneOffset.UTC);
    }

    static @NonNull String signedXml(@NonNull String xml, boolean responseSignature,
            boolean assertionSignature, @NonNull PrivateKey key) throws Exception {
        SecureXmlParser.Result.Accepted parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(xml.getBytes(StandardCharsets.UTF_8)));
        Document document = parsed.getDocument();
        Element response = document.getDocumentElement();
        if (assertionSignature) sign(assertInstanceOf(Element.class,
                response.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Assertion")
                        .item(0)), key);
        if (responseSignature) sign(response, key);
        Transformer transformer = TransformerFactory.newDefaultInstance().newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        transformer.transform(new DOMSource(document), new StreamResult(output));
        return output.toString(StandardCharsets.UTF_8);
    }

    private static void sign(@NonNull Element signed, @NonNull PrivateKey key) throws Exception {
        String id = signed.getAttributeNS(null, "ID");
        signed.setIdAttributeNS(null, "ID", true);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        Reference reference = factory.newReference("#" + id, factory.newDigestMethod(DigestMethod.SHA256, null),
                List.of(factory.newTransform(Transform.ENVELOPED,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                        factory.newTransform(CanonicalizationMethod.EXCLUSIVE,
                                (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)), null, null);
        SignedInfo info = factory.newSignedInfo(factory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
                        (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                factory.newSignatureMethod(SignatureMethod.RSA_SHA256, null), List.of(reference));
        DOMSignContext context = new DOMSignContext(key, signed);
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
}
