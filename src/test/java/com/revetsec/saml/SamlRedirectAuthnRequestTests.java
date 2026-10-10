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
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlRedirectAuthnRequestTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:00:00Z"), ZoneOffset.UTC);
    private static final @NonNull URI ACS = URI.create("https://sp.example.test/acs");
    private static final @NonNull URI IDP = URI.create("https://idp.example.test/sso?tenant=one");

    @Test void writesRawDeflateAndSignsExactRedirectQuery() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        SamlRedirectAuthnRequest.Prepared prepared = assertInstanceOf(SamlRedirectAuthnRequest.Prepared.class,
                SamlRedirectAuthnRequest.prepare("https://sp.example.test/?x=1&y=2", ACS, IDP,
                        pair.getPrivate(), true, new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        assertTrue(prepared.signed());
        assertEquals(41, prepared.requestId().length());
        assertEquals(22, prepared.relayState().length());
        assertEquals(Instant.parse("2026-10-09T00:05:00Z"), prepared.expiresAt());
        String query = prepared.redirect().getRawQuery();
        assertTrue(query.startsWith("tenant=one&SAMLRequest="));
        int signatureStart = query.indexOf("&Signature=");
        String signed = query.substring("tenant=one&".length(), signatureStart);
        String encodedSignature = query.substring(signatureStart + "&Signature=".length());
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(pair.getPublic());
        verifier.update(signed.getBytes(StandardCharsets.US_ASCII));
        assertTrue(verifier.verify(Base64.getDecoder().decode(URLDecoder.decode(encodedSignature,
                StandardCharsets.UTF_8))));
        String encodedRequest = signed.substring("SAMLRequest=".length(), signed.indexOf('&'));
        String xml = inflate(Base64.getDecoder().decode(URLDecoder.decode(encodedRequest, StandardCharsets.UTF_8)));
        assertTrue(xml.contains("ID=\"" + prepared.requestId() + "\""));
        assertTrue(xml.contains("InResponseTo=") == false);
        assertTrue(xml.contains("https://sp.example.test/?x=1&amp;y=2"));
        assertTrue(xml.contains("AssertionConsumerServiceURL=\"https://sp.example.test/acs\""));
        assertFalse(xml.contains("<ds:Signature"));
    }

    @Test void refusesUnsignedWhenRequiredAndRejectsInsecureEndpoints() {
        assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                SamlRedirectAuthnRequest.prepare("sp", ACS, IDP, null, true,
                        new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                SamlRedirectAuthnRequest.prepare("sp", ACS, URI.create("http://idp.example.test/sso"), null,
                        false, new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
        assertInstanceOf(SamlRedirectAuthnRequest.Rejected.class,
                SamlRedirectAuthnRequest.prepare("sp", ACS,
                        URI.create("https://idp.example.test/sso?SAML%52equest=spoofed"), null,
                        false, new SecureRandom(), CLOCK, Duration.ofMinutes(5)));
    }

    private static @NonNull String inflate(byte @NonNull [] compressed) throws DataFormatException {
        Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(compressed);
            byte[] output = new byte[16_384];
            int used = inflater.inflate(output);
            assertTrue(inflater.finished());
            return new String(output, 0, used, StandardCharsets.UTF_8);
        } finally {
            inflater.end();
        }
    }
}
