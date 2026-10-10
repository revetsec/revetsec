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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SecureXmlParserTests {
    @Test void parsesNamespacedXmlOnceWithoutChangingTheVerifiedNodeShape() {
        SecureXmlParser.Result.Accepted accepted = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(bytes("<p:Response xmlns:p='urn:protocol' ID='r1'>"
                        + "<p:Assertion ID='a1'>a<!--split-->b<![CDATA[c]]></p:Assertion>"
                        + "</p:Response>")));
        Element root = accepted.getDocument().getDocumentElement();
        assertEquals("urn:protocol", root.getNamespaceURI());
        assertEquals("p:Response", root.getTagName());
        assertEquals("r1", root.getAttribute("ID"));
        Element assertion = assertInstanceOf(Element.class, root.getFirstChild());
        assertEquals("abc", assertion.getTextContent());
        assertEquals(1, assertion.getChildNodes().getLength());
        assertTrue(accepted.toString().contains("<unverified>"));
    }

    @Test void rejectsDtdAndProcessingInstructionsWithoutResolvingExternalResources() {
        assertRejected(SecureXmlParser.Reason.MALFORMED,
                "<!DOCTYPE r SYSTEM 'file:///etc/passwd'><r/>");
        assertRejected(SecureXmlParser.Reason.MALFORMED,
                "<!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><r>&x;</r>");
        assertRejected(SecureXmlParser.Reason.MALFORMED,
                "<r><?target instruction?></r>");
        assertRejected(SecureXmlParser.Reason.MALFORMED, "<r><a></r>");
        assertRejected(SecureXmlParser.Reason.MALFORMED, "<r/><s/>");
    }

    @Test void unsupportedDeclaredEncodingIsMalformedInput() {
        byte[] input = bytes("<?xml version='1.0' encoding='UTJ-8'?><r/>");
        assertEquals(SecureXmlParser.Reason.MALFORMED,
                assertInstanceOf(SecureXmlParser.Result.Rejected.class,
                        SecureXmlParser.parseResponse(input)).getReason());
        assertEquals(SecureXmlParser.Reason.MALFORMED,
                assertInstanceOf(SecureXmlParser.Result.Rejected.class,
                        SecureXmlParser.parseMetadata(input)).getReason());
    }

    @Test void coalescesManySmallTextEventsWithoutChangingTheReadValue() {
        String xml = "<r>" + "<![CDATA[x]]>".repeat(8_000) + "</r>";
        SecureXmlParser.Result.Accepted accepted = assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(bytes(xml)));
        Element root = accepted.getDocument().getDocumentElement();
        assertEquals("x".repeat(8_000), root.getTextContent());
        assertEquals(1, root.getChildNodes().getLength());
    }

    @Test void rejectsDuplicateIdentifiersAcrossAttributeSpellingsAndNamespaces() {
        assertRejected(SecureXmlParser.Reason.MALFORMED,
                "<r xmlns:s='urn:s'><a ID='shared'/><b s:Id='shared'/></r>");
        assertRejected(SecureXmlParser.Reason.MALFORMED,
                "<r><a id='shared'/><b ID='shared'/></r>");
        assertRejected(SecureXmlParser.Reason.MALFORMED,
                "<r><a xml:id='shared'/><b AssertionID='shared'/></r>");
        assertRejected(SecureXmlParser.Reason.MALFORMED, "<r ID=''/>");
        assertInstanceOf(SecureXmlParser.Result.Accepted.class,
                SecureXmlParser.parseResponse(bytes("<r><a ID='one'/><b Id='two'/></r>")));
    }

    @Test void countsLimitsDuringParsingAndRejectsOversizeBeforeParsing() {
        assertEquals(SecureXmlParser.Reason.INPUT_SIZE,
                assertInstanceOf(SecureXmlParser.Result.Rejected.class,
                        SecureXmlParser.parseResponse(new byte[262_145])).getReason());
        assertEquals(SecureXmlParser.Reason.INPUT_SIZE,
                assertInstanceOf(SecureXmlParser.Result.Rejected.class,
                        SecureXmlParser.parseResponse(new byte[0])).getReason());
        assertLimited("<r><a><b/></a></r>", 2, 10, 10, 10);
        assertLimited("<r><a/><b/></r>", 10, 2, 10, 10);
        assertLimited("<r a='1' b='2'/>", 10, 10, 1, 10);
        assertLimited("<longname/>", 10, 10, 10, 4);
        assertLimited("<r longname='1'/>", 10, 10, 10, 4);
    }

    private static void assertLimited(@NonNull String xml, int depth, int elements,
            int attributes, int nameLength) {
        SecureXmlParser.Result.Rejected rejected = assertInstanceOf(SecureXmlParser.Result.Rejected.class,
                SecureXmlParser.parse(bytes(xml), 1_000, depth, elements, attributes, nameLength));
        assertEquals(SecureXmlParser.Reason.STRUCTURE_LIMIT, rejected.getReason());
    }

    private static void assertRejected(SecureXmlParser.@NonNull Reason reason, @NonNull String xml) {
        SecureXmlParser.Result.Rejected rejected = assertInstanceOf(SecureXmlParser.Result.Rejected.class,
                SecureXmlParser.parseResponse(bytes(xml)));
        assertEquals(reason, rejected.getReason());
    }

    private static byte @NonNull [] bytes(@NonNull String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
