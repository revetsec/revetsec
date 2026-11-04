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
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestSealers;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Signed public-flow conformance for the fixed attribute profile; original production already enforces it. */
final class SamlAttributeLimitsTests {
    private static final String SP = "https://sp.example.test/saml";
    private static final URI ACS = URI.create("https://sp.example.test/acs");
    private static final String IDP = "https://idp.example.test/saml";
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
    private static final TestJwk.Fixture KEY = TestJwk.Fixture.IDP_SIGNING_RSA_2048;

    enum Coverage {
        RESPONSE(true, false), ASSERTION(false, true), BOTH(true, true);
        final boolean response;
        final boolean assertion;
        Coverage(boolean response, boolean assertion) { this.response = response; this.assertion = assertion; }
    }

    private record Value(String xml, SamlAttributeValue.Kind kind, String scalar) {}
    private record Attribute(String name, String format, String friendly, List<Value> values) {
        String xml() {
            return "<a:Attribute Name='" + name + "' NameFormat='" + format + "' FriendlyName='" + friendly
                    + "'>" + values.stream().map(Value::xml).reduce("", String::concat) + "</a:Attribute>";
        }
    }
    private record Scenario(String label, List<List<Attribute>> statements, boolean admitted) {
        String xml() {
            return statements.stream().map(statement -> "<a:AttributeStatement>"
                    + statement.stream().map(Attribute::xml).reduce("", String::concat)
                    + "</a:AttributeStatement>").reduce("", String::concat);
        }
        List<Attribute> attributes() { return statements.stream().flatMap(List::stream).toList(); }
        @Override public String toString() { return label; }
    }

    @TestFactory
    Stream<DynamicTest> signedResponseBoundaries() {
        List<Scenario> cases = new ArrayList<>();
        cases.add(new Scenario("no attributes", List.of(), true));
        cases.add(value("empty scalar text", text(""), true));
        cases.add(one("128 attributes", attributes(128, false), true));
        cases.add(split("128 attributes across statements", attributes(128, false), 64, true));
        cases.add(one("128 duplicate empty attributes", attributes(128, true), true));
        cases.add(one("129 attributes", attributes(129, false), false));
        cases.add(split("129 attributes across statements", attributes(129, false), 64, false));
        cases.add(one("129 duplicate empty attributes", attributes(129, true), false));
        Value text = text("released");
        cases.add(one("256 values", List.of(attribute("roles", copies(256, text))), true));
        cases.add(one("257 values", List.of(attribute("roles", copies(257, text))), false));
        cases.add(one("256 values across attributes", List.of(attribute("first", copies(127, text)),
                attribute("last", copies(129, text))), true));
        cases.add(one("257 values across attributes", List.of(attribute("first", copies(128, text)),
                attribute("last", copies(129, text))), false));
        cases.add(split("256 values across statements", List.of(attribute("first", copies(128, text)),
                attribute("last", copies(128, text))), 1, true));
        cases.add(split("257 values across statements", List.of(attribute("first", copies(128, text)),
                attribute("last", copies(129, text))), 1, false));
        List<Value> mixed = IntStream.range(0, 64).boxed().flatMap(i -> Stream.of(text("v" + i),
                nameId("id" + i), complex("<a:Other>opaque</a:Other>"), nil("hidden"))).toList();
        cases.add(one("256 mixed values", List.of(attribute("mixed", mixed)), true));
        List<Value> tooMany = new ArrayList<>(mixed);
        tooMany.add(nil("one more"));
        cases.add(one("257 mixed values including nil", List.of(attribute("mixed", tooMany)), false));
        cases.add(value("4096 ASCII units", text("x".repeat(4096)), true));
        cases.add(value("4097 ASCII units", text("x".repeat(4097)), false));
        cases.add(value("4096 non-ASCII BMP units", text("\u20ac".repeat(4096)), true));
        cases.add(value("4096 UTF-16 units, 2048 supplementary characters", text("\ud83d\ude80".repeat(2048)), true));
        cases.add(value("4097 UTF-16 units, 2049 code points", text("\ud83d\ude80".repeat(2048) + "x"), false));
        cases.add(value("4096 decoded entities", text("&".repeat(4096)), true));
        cases.add(value("4097 decoded entities", text("&".repeat(4097)), false));
        cases.add(value("CDATA and text share one 4096-unit budget", new Value(
                "<a:AttributeValue>" + "x".repeat(2048) + "<![CDATA[" + "y".repeat(2048)
                        + "]]></a:AttributeValue>", SamlAttributeValue.Kind.TEXT,
                "x".repeat(2048) + "y".repeat(2048)), true));
        cases.add(value("CDATA and text share one 4097-unit budget", new Value(
                "<a:AttributeValue>" + "x".repeat(2049) + "<![CDATA[" + "y".repeat(2048)
                        + "]]></a:AttributeValue>", SamlAttributeValue.Kind.TEXT, ""), false));
        for (String field : List.of("Name", "NameFormat", "FriendlyName")) {
            for (int size : List.of(2048, 2049)) {
                cases.add(one(field + " " + size, List.of(new Attribute(
                        field.equals("Name") ? "x".repeat(size) : "roles",
                        field.equals("NameFormat") ? "x".repeat(size) : "urn:example:format",
                        field.equals("FriendlyName") ? "x".repeat(size) : "Roles", List.of(text))), size == 2048));
            }
        }
        cases.add(one("empty Name", List.of(attribute("", List.of(text))), false));
        cases.add(one("2048-unit supplementary Name", List.of(attribute("\ud83d\ude80".repeat(1024), List.of(text))), true));
        cases.add(one("2049-unit supplementary Name", List.of(attribute("\ud83d\ude80".repeat(1024) + "x", List.of(text))), false));
        cases.add(value("large opaque XML is never flattened", complex("<a:Other>" + "x".repeat(4097) + "</a:Other>"), true));
        cases.add(value("large nilled text stays opaque", nil("x".repeat(4097)), true));
        cases.add(value("4096-unit nested NameID", nameId("x".repeat(4096)), true));
        cases.add(value("overlong nested NameID stays opaque", complex("<a:NameID>" + "x".repeat(4097) + "</a:NameID>"), true));
        return cases.stream().flatMap(scenario -> Stream.of(Coverage.values())
                .map(coverage -> DynamicTest.dynamicTest(scenario + "; " + coverage,
                        () -> signedResponsesFollowTheFixedProfile(scenario, coverage))));
    }

    void signedResponsesFollowTheFixedProfile(Scenario scenario, Coverage coverage) throws Exception {
        AtomicInteger replayCalls = new AtomicInteger();
        SamlServiceProvider sp = provider(replayCalls);
        SamlIdentityProvider idp = identityProvider();
        PendingSamlAuthentication pending = pending(sp, idp);
        StateSealer sealer = sealer();
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromSealedForm(
                pending.toSealedForm(sealer, "attribute-limits"), sealer, "attribute-limits");
        SamlPostBindingMessage message = message(pending, scenario.xml(), coverage);
        SamlAuthenticationResult result = sp.completeAuthenticationResult(message, source, idp);
        if (!scenario.admitted()) {
            assertEquals(SamlAuthenticationResult.Reason.ASSERTION_SHAPE,
                    assertInstanceOf(SamlAuthenticationResult.Rejected.class, result).getReason());
            assertEquals(0, replayCalls.get(), "no replay fence is written for an over-limit assertion");
            return;
        }
        SamlAuthentication authentication = assertInstanceOf(SamlAuthenticationResult.Succeeded.class, result)
                .getAuthentication();
        assertEquals(1, replayCalls.get());
        assertEquals(coverage.response, authentication.isResponseSigned());
        assertEquals(coverage.assertion, authentication.isAssertionSigned());
        List<Attribute> expected = scenario.attributes();
        List<SamlAttribute> actual = authentication.getAttributes();
        assertEquals(expected.size(), actual.size(), "no attribute truncation or deduplication");
        for (int i = 0; i < expected.size(); i++) assertAttribute(expected.get(i), actual.get(i));
    }

    @TestFactory
    Stream<DynamicTest> storedPendingOutcomes() {
        return Stream.of(Coverage.values()).map(coverage -> DynamicTest.dynamicTest(coverage.toString(),
                () -> limitRejectionSpendsStoredPendingButDoesNotFenceTheAssertion(coverage)));
    }

    void limitRejectionSpendsStoredPendingButDoesNotFenceTheAssertion(Coverage coverage) throws Exception {
        AtomicInteger replayCalls = new AtomicInteger();
        SamlServiceProvider sp = provider(replayCalls);
        SamlIdentityProvider idp = identityProvider();
        PendingSamlAuthentication pending = pending(sp, idp);
        StateSealer sealer = sealer();
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.fromLimit(CLOCK, 2);
        assertEquals(SamlPendingSaveResult.SAVED, pending.saveToResult(store, sealer, "attribute-limits",
                "browser-one", Duration.ofSeconds(5)));
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromStore(
                store, "browser-one", sealer, "attribute-limits");
        String overLimit = value("over limit", text("x".repeat(4097)), false).xml();
        SamlPostBindingMessage rejected = message(pending, overLimit, coverage);
        assertEquals(SamlAuthenticationResult.Reason.ASSERTION_SHAPE,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(rejected, source, idp)).getReason());
        assertEquals(0, replayCalls.get());
        assertEquals(SamlAuthenticationResult.Reason.PENDING,
                assertInstanceOf(SamlAuthenticationResult.Rejected.class,
                        sp.completeAuthenticationResult(rejected, source, idp)).getReason());
        assertEquals(0, replayCalls.get());
        // A fresh pending login and independently signed, in-profile response can use the same assertion ID.
        PendingSamlAuthentication fresh = pending(sp, idp);
        assertEquals(SamlPendingSaveResult.SAVED, fresh.saveToResult(store, sealer, "attribute-limits",
                "browser-one", Duration.ofSeconds(5)));
        assertInstanceOf(SamlAuthenticationResult.Succeeded.class, sp.completeAuthenticationResult(
                message(fresh, value("within limit", text("x".repeat(4096)), true).xml(), coverage), source, idp));
        assertEquals(1, replayCalls.get());
    }

    @TestFactory
    Stream<DynamicTest> unsolicitedProfile() {
        return Stream.of(Coverage.values()).map(coverage -> DynamicTest.dynamicTest(coverage.toString(), () -> {
            AtomicInteger replayCalls = new AtomicInteger();
            SamlServiceProvider sp = provider(replayCalls);
            SamlIdentityProvider enabled = SamlIdentityProvider.withEntityId(IDP).connectionId("attribute-limits")
                    .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                    .signingKeys(List.of(KEY.getPublicKey())).allowUnsolicitedResponses(true).build();
            for (int length : List.of(4097, 4096)) {
                String xml = SamlResponseSemanticsTests.BASE.replace(" InResponseTo='_request'", "")
                        .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z")
                        .replace("</a:Assertion>", value("text", text("x".repeat(length)), length == 4096).xml()
                                + "</a:Assertion>");
                SamlAuthenticationResult result = sp.completeUnsolicitedAuthenticationResult(
                        signedMessage(xml, "", coverage), enabled);
                if (length == 4097) {
                    assertEquals(SamlAuthenticationResult.Reason.ASSERTION_SHAPE,
                            assertInstanceOf(SamlAuthenticationResult.Rejected.class, result).getReason());
                    assertEquals(0, replayCalls.get());
                } else {
                    assertEquals(List.of("x".repeat(4096)), assertInstanceOf(SamlAuthenticationResult.Succeeded.class,
                            result).getAuthentication().getAttributeValues("roles"));
                    assertEquals(1, replayCalls.get());
                }
            }
        }));
    }

    private static void assertAttribute(Attribute expected, SamlAttribute actual) {
        assertEquals(expected.name(), actual.getName());
        assertEquals(Optional.of(expected.format()), actual.getNameFormat());
        assertEquals(Optional.of(expected.friendly()), actual.getFriendlyName());
        assertEquals(expected.values().stream().filter(v -> v.kind() == SamlAttributeValue.Kind.TEXT)
                .map(Value::scalar).toList(), actual.getValues());
        assertEquals(expected.values().size(), actual.getTypedValues().size(), "no value truncation");
        for (int i = 0; i < expected.values().size(); i++) {
            Value wanted = expected.values().get(i);
            SamlAttributeValue found = actual.getTypedValues().get(i);
            assertEquals(wanted.kind(), found.getKind());
            assertEquals(wanted.kind() == SamlAttributeValue.Kind.TEXT ? Optional.of(wanted.scalar()) : Optional.empty(),
                    found.getText());
            assertEquals(wanted.kind() == SamlAttributeValue.Kind.NAME_ID ? Optional.of(wanted.scalar()) : Optional.empty(),
                    found.getNameId().map(SamlNameId::getValue));
        }
    }

    private static SamlServiceProvider provider(AtomicInteger replayCalls) {
        SamlReplayCache cache = InMemorySamlReplayCache.fromLimit(CLOCK, 16);
        return SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(ACS).clock(CLOCK)
                .replayCache((key, expiry, remaining) -> {
                    replayCalls.incrementAndGet();
                    return cache.markIfAbsent(key, expiry, remaining);
                }).build();
    }
    private static SamlIdentityProvider identityProvider() {
        return SamlIdentityProvider.withEntityId(IDP).connectionId("attribute-limits")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(KEY.getPublicKey())).build();
    }
    private static PendingSamlAuthentication pending(SamlServiceProvider sp, SamlIdentityProvider idp) {
        return assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class,
                sp.beginAuthenticationResult(idp)).getPendingAuthentication();
    }
    private static StateSealer sealer() {
        return StateSealer.withActiveKey(TestSealers.fixedKey("saml-attribute-limits")).clock(CLOCK).build();
    }
    private static SamlPostBindingMessage message(PendingSamlAuthentication pending, String attributes,
            Coverage coverage) throws Exception {
        String xml = SamlResponseSemanticsTests.BASE.replace("_request", pending.getRequestId())
                .replace("2026-10-09T00:00:00Z", "2026-10-09T00:01:00Z")
                .replace("</a:Assertion>", attributes + "</a:Assertion>");
        return signedMessage(xml, "&RelayState=" + pending.getRelayStateHandle(), coverage);
    }
    private static SamlPostBindingMessage signedMessage(String xml, String relayField, Coverage coverage) throws Exception {
        String signed = SamlResponseSemanticsTests.signedXml(xml, coverage.response, coverage.assertion,
                KEY.getKeyPair().getPrivate());
        if (xml.contains("<![CDATA[")) {
            // The signing parser coalesces CDATA. Restore its wire spelling after signing;
            // canonical XML has the same text, so the real signature must still verify.
            int start = xml.indexOf("<a:AttributeValue>") + "<a:AttributeValue>".length();
            String body = xml.substring(start, xml.indexOf("</a:AttributeValue>", start));
            String normalized = body.replace("<![CDATA[", "").replace("]]>", "");
            assertTrue(signed.contains(normalized));
            signed = signed.replace(normalized, body);
            assertTrue(signed.contains("<![CDATA["), "the response on the wire exercises CDATA");
        }
        String encoded = Base64.getEncoder().encodeToString(signed.getBytes(StandardCharsets.UTF_8))
                .replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded + relayField).getBytes(StandardCharsets.UTF_8),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }
    private static Scenario one(String name, List<Attribute> attributes, boolean admitted) {
        return new Scenario(name, List.of(attributes), admitted);
    }
    private static Scenario split(String name, List<Attribute> attributes, int position, boolean admitted) {
        return new Scenario(name, List.of(attributes.subList(0, position), attributes.subList(position, attributes.size())), admitted);
    }
    private static Scenario value(String name, Value value, boolean admitted) {
        return one(name, List.of(attribute("roles", List.of(value))), admitted);
    }
    private static List<Attribute> attributes(int count, boolean duplicates) {
        return IntStream.range(0, count).mapToObj(i -> attribute(duplicates ? "duplicate" : "claim-" + i,
                duplicates ? List.of() : List.of(text("value-" + i)))).toList();
    }
    private static Attribute attribute(String name, List<Value> values) {
        return new Attribute(name, "urn:example:format", "Roles", values);
    }
    private static List<Value> copies(int count, Value value) { return Collections.nCopies(count, value); }
    private static Value text(String value) {
        return new Value("<a:AttributeValue>" + value.replace("&", "&amp;").replace("<", "&lt;")
                + "</a:AttributeValue>", SamlAttributeValue.Kind.TEXT, value);
    }
    private static Value nameId(String value) {
        return new Value("<a:AttributeValue><a:NameID>" + value + "</a:NameID></a:AttributeValue>",
                SamlAttributeValue.Kind.NAME_ID, value);
    }
    private static Value complex(String content) {
        return new Value("<a:AttributeValue>" + content + "</a:AttributeValue>", SamlAttributeValue.Kind.COMPLEX, "");
    }
    private static Value nil(String content) {
        return new Value("<a:AttributeValue xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:nil='true'>"
                + content + "</a:AttributeValue>", SamlAttributeValue.Kind.COMPLEX, "");
    }
}
