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
        rejects(SamlPostBindingDecoder.Reason.PARAMETERS, "SAMLResponse=" + encoded + "&other=x");
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

    private static void rejects(SamlPostBindingDecoder.@NonNull Reason reason, @NonNull String form) {
        SamlPostBindingDecoder.Rejected rejection = assertInstanceOf(SamlPostBindingDecoder.Rejected.class,
                SamlPostBindingDecoder.decode(bytes(form), List.of(MIME), null));
        assertEquals(reason, rejection.reason());
    }

    private static byte @NonNull [] bytes(@NonNull String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
