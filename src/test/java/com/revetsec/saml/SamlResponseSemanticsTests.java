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
            + "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'/>"
            + "</a:Assertion></p:Response>";

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
        String authn = "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'/>";
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

        String authn = "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'/>";
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
        String original = "<a:AuthnStatement AuthnInstant='2026-10-09T00:00:00Z'/>";
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

    private static @NonNull Clock fixedClock() {
        return Clock.fixed(Instant.parse(NOW), ZoneOffset.UTC);
    }

    static @NonNull String signedXml(@NonNull String xml, boolean responseSignature,
            boolean assertionSignature, @NonNull PrivateKey key) throws Exception {
        SecureXmlParser.Result.Accepted parsed = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(xml.getBytes(StandardCharsets.UTF_8)));
        Document document = parsed.getDocument();
        Element response = document.getDocumentElement();
        Element assertion = (Element) response.getLastChild();
        if (assertionSignature) sign(assertion, key);
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
