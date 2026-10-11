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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlPostBindingDecoderTests {
    private static final String MIME = "application/x-www-form-urlencoded; charset=UTF-8";

    @Test void acceptsOnlyFormEncodedPostXmlAndUntrustedRelayState() {
        byte[] xml = "<Response ID='_one'/>".getBytes(StandardCharsets.UTF_8);
        String encoded = Base64.getEncoder().encodeToString(xml);
        String form = "SAMLResponse=" + encoded.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
                + "&RelayState=handle-123";
        SamlPostBindingDecoder.Accepted accepted = assertInstanceOf(SamlPostBindingDecoder.Accepted.class,
                SamlPostBindingDecoder.decode(bytes(form), List.of(MIME), "tenant=acme"));
        assertArrayEquals(xml, accepted.xml());
        assertEquals("handle-123", accepted.relayState());
        byte[] borrowed = accepted.xml();
        borrowed[0] = '!';
        assertArrayEquals(xml, accepted.xml());
        assertTrue(accepted.toString().contains("<unverified>"));
    }

    @Test void acceptsCrLfLineWrapButRejectsOtherSkippedBase64Characters() {
        String encoded = Base64.getEncoder().encodeToString(bytes("<Response/>"));
        String wrapped = encoded.substring(0, 4) + "%0D%0A" + encoded.substring(4);
        assertInstanceOf(SamlPostBindingDecoder.Accepted.class,
                SamlPostBindingDecoder.decode(bytes("SAMLResponse=" + wrapped), List.of(MIME), null));
        rejects(SamlPostBindingDecoder.Reason.BASE64, "SAMLResponse=" + encoded.substring(0, 4)
                + "*" + encoded.substring(4));
    }

    @Test void rejectsMultiplicitySplitChannelsAndMalformedEncoding() {
        String encoded = Base64.getEncoder().encodeToString(bytes("<Response/>"));
        rejects(SamlPostBindingDecoder.Reason.PARAMETERS, "SAMLResponse=" + encoded
                + "&%53AMLResponse=" + encoded);
        rejects(SamlPostBindingDecoder.Reason.PARAMETERS, "SAMLRequest=" + encoded);
        rejects(SamlPostBindingDecoder.Reason.PARAMETERS, "RelayState=h");
        rejects(SamlPostBindingDecoder.Reason.PARAMETERS, "RelayState=a&RelayState=b");
        rejects(SamlPostBindingDecoder.Reason.PARAMETERS, "SAMLResponse=" + encoded + "&other=x");
        rejects(SamlPostBindingDecoder.Reason.PARAMETERS, "&SAMLResponse=" + encoded);
        rejects(SamlPostBindingDecoder.Reason.PARAMETERS, "SAMLResponse=" + encoded + "&&RelayState=h");
        rejects(SamlPostBindingDecoder.Reason.PARAMETERS, "SAMLResponse=" + encoded + "&");
        rejects(SamlPostBindingDecoder.Reason.FORM_ENCODING, "SAMLResponse=%GG");
        rejects(SamlPostBindingDecoder.Reason.FORM_ENCODING, "SAMLResponse=%C3%28");
        assertEquals(SamlPostBindingDecoder.Reason.QUERY,
                assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                        SamlPostBindingDecoder.decode(bytes("SAMLResponse=" + encoded), List.of(MIME),
                                "%53AMLResponse=other")).reason());
        assertEquals(SamlPostBindingDecoder.Reason.QUERY,
                assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                        SamlPostBindingDecoder.decode(bytes("SAMLResponse=" + encoded), List.of(MIME),
                                "RelayState=other")).reason());
    }

    @Test void enforcesMimeRelayStateAndBodyBoundsBeforeBase64() {
        String encoded = Base64.getEncoder().encodeToString(bytes("<Response/>"));
        String form = "SAMLResponse=" + encoded;
        assertEquals(SamlPostBindingDecoder.Reason.CONTENT_TYPE,
                assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                        SamlPostBindingDecoder.decode(bytes(form), List.of(MIME, MIME), null)).reason());
        assertEquals(SamlPostBindingDecoder.Reason.CONTENT_TYPE,
                assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                        SamlPostBindingDecoder.decode(bytes(form), List.of("text/plain"), null)).reason());
        assertEquals(SamlPostBindingDecoder.Reason.CONTENT_TYPE,
                assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                        SamlPostBindingDecoder.decode(bytes(form), List.of("application/x-www-form-urlencoded; charset=iso-8859-1"), null)).reason());
        rejects(SamlPostBindingDecoder.Reason.RELAY_STATE_SIZE, form + "&RelayState=" + "x".repeat(81));
        assertEquals(SamlPostBindingDecoder.Reason.BODY_SIZE,
                assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                        SamlPostBindingDecoder.decode(new byte[1_061_129], List.of(MIME), null)).reason());
    }

    @Test void postBindingRejectsAmbiguousContentTypeAndQueryChannels() {
        String form = "SAMLResponse=" + Base64.getEncoder().encodeToString(bytes("<Response/>"));
        for (String contentType : List.of("application/x-www-form-urlencoded, text/plain",
                "application/x-www-form-urlencoded; charset=UTF-8; boundary=x",
                "application/x-www-form-urlencoded; charset=UTF-16",
                "application/x-www-form-urlencoded; charset=",
                "application/x-www-form-urlencoded; bad=UTF-8",
                "application/x-www-form-urlencoded\r\n",
                "application/x-www-form-urlencoded" + "x".repeat(257)))
            assertEquals(SamlPostBindingDecoder.Reason.CONTENT_TYPE,
                    assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                            SamlPostBindingDecoder.decode(bytes(form), List.of(contentType), null))
                            .reason(), contentType);
        assertInstanceOf(SamlPostBindingDecoder.Accepted.class,
                SamlPostBindingDecoder.decode(bytes(form),
                        List.of("Application/X-WWW-Form-Urlencoded; charset=\"uTf-8\""), "tenant=one"));
        for (String query : List.of("SAMLResponse=shadow", "SAMLRequest=shadow",
                "%53AMLResponse=shadow", "%52elayState=shadow", "tenant=%FF&RelayState=x",
                "%GG=value", "tenant=x y", "tenant=x\n", "tenant=x\u007f",
                "tenant=" + "x".repeat(8193)))
            assertEquals(SamlPostBindingDecoder.Reason.QUERY,
                    assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                            SamlPostBindingDecoder.decode(bytes(form), List.of(MIME), query))
                            .reason(), query.length() > 100 ? "long query" : query);
    }

    @Test void acceptsExactRelayStateMimeAndQueryLimits() {
        String encoded = Base64.getEncoder().encodeToString(bytes("<Response/>"));
        String form = "SAMLResponse=" + encoded + "&RelayState=" + "x".repeat(80);
        String mime = "application/x-www-form-urlencoded";
        String longestMime = mime + " ".repeat(256 - mime.length());
        String longestQuery = "tenant=" + "x".repeat(8192 - "tenant=".length());
        SamlPostBindingDecoder.Accepted accepted = assertInstanceOf(
                SamlPostBindingDecoder.Accepted.class,
                SamlPostBindingDecoder.decode(bytes(form), List.of(longestMime), longestQuery));
        assertEquals("x".repeat(80), accepted.relayState());
        assertInstanceOf(SamlPostBindingDecoder.Accepted.class,
                SamlPostBindingDecoder.decode(bytes("SAMLResponse=" + encoded),
                        List.of(mime), "tenant=~"));
        assertEquals(SamlPostBindingDecoder.Reason.CONTENT_TYPE,
                assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                        SamlPostBindingDecoder.decode(bytes(form), List.of(longestMime + " "), null))
                        .reason());
        assertEquals(SamlPostBindingDecoder.Reason.QUERY,
                assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                        SamlPostBindingDecoder.decode(bytes(form), List.of(mime), longestQuery + "x"))
                        .reason());
    }

    @Test void acceptsTheExactBodyCapButRejectsTheNextByte() {
        String prefix = "SAMLResponse=PA==";
        byte[] body = bytes(prefix + " ".repeat(1_061_128 - prefix.length()));
        SamlPostBindingDecoder.Accepted accepted = assertInstanceOf(
                SamlPostBindingDecoder.Accepted.class,
                SamlPostBindingDecoder.decode(body, List.of(MIME), null));
        assertArrayEquals(bytes("<"), accepted.xml());
        assertEquals(SamlPostBindingDecoder.Reason.BODY_SIZE,
                assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                        SamlPostBindingDecoder.decode(bytes(prefix + " ".repeat(
                                1_061_129 - prefix.length())), List.of(MIME), null)).reason());
    }

    @Test void percentDecodingDistinguishesHexDigitsAndRejectsMalformedOctets() {
        String encoded = Base64.getEncoder().encodeToString(bytes("<Response/>"));
        SamlPostBindingDecoder.Accepted accepted = assertInstanceOf(
                SamlPostBindingDecoder.Accepted.class,
                SamlPostBindingDecoder.decode(bytes("SAMLResponse=" + encoded
                        + "&RelayState=%30%39%41%46%61%66%7a"), List.of(MIME), null));
        assertEquals("09AFafz", accepted.relayState());
        assertEquals("joJO", assertInstanceOf(SamlPostBindingDecoder.Accepted.class,
                SamlPostBindingDecoder.decode(bytes("SAMLResponse=" + encoded
                        + "&RelayState=%6a%6f%4A%4F"), List.of(MIME), null)).relayState());
        for (String invalid : List.of("%", "%0", "%G0", "%0G", "%@0", "%g0",
                "%3A%C3%28", "%FF"))
            rejects(SamlPostBindingDecoder.Reason.FORM_ENCODING,
                    "SAMLResponse=" + encoded + "&RelayState=" + invalid);
        assertEquals(SamlPostBindingDecoder.Reason.QUERY,
                assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                        SamlPostBindingDecoder.decode(bytes("SAMLResponse=" + encoded),
                                List.of(MIME), "SAMLResponse"))
                        .reason());
    }

    @Test void postBindingEnforcesExactFormAndDecodedXmlBounds() {
        String encoded = Base64.getEncoder().encodeToString(bytes("<Response/>"));
        for (String form : List.of("SAMLResponse", "SAMLResponse=", "SAMLResponse=" + encoded
                        + "&RelayState=x&RelayState=y", "SAMLResponse=" + encoded + "&RelayState=x&other=y",
                "SAMLResponse=" + encoded + "&%53AMLResponse=" + encoded))
            rejects(SamlPostBindingDecoder.Reason.PARAMETERS, form);
        for (String form : List.of("SAMLResponse=%", "SAMLResponse=%0", "SAMLResponse=%GG",
                "SAMLResponse=" + encoded + "&RelayState=%C0%AF", "%FF=" + encoded))
            rejects(SamlPostBindingDecoder.Reason.FORM_ENCODING, form);
        rejects(SamlPostBindingDecoder.Reason.PARAMETERS, "SAMLResponse=");
        byte[] maximum = new byte[256 * 1024];
        assertEquals(maximum.length,
                assertInstanceOf(SamlPostBindingDecoder.Accepted.class,
                        SamlPostBindingDecoder.decode(bytes("SAMLResponse="
                                + Base64.getEncoder().encodeToString(maximum)), List.of(MIME), null))
                        .xml().length);
        rejects(SamlPostBindingDecoder.Reason.XML_SIZE, "SAMLResponse="
                + Base64.getEncoder().encodeToString(new byte[256 * 1024 + 1]));
        rejects(SamlPostBindingDecoder.Reason.XML_SIZE, "SAMLResponse="
                + Base64.getEncoder().encodeToString(new byte[256 * 1024 + 3]));
    }

    private static void rejects(SamlPostBindingDecoder.@NonNull Reason reason, @NonNull String form) {
        SamlPostBindingDecoder.Rejected rejection = assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                SamlPostBindingDecoder.decode(bytes(form), List.of(MIME), null));
        assertEquals(reason, rejection.reason());
    }

    private static byte @NonNull [] bytes(@NonNull String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
