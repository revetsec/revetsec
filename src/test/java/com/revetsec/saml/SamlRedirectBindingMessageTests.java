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

import org.junit.jupiter.api.Test;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlRedirectBindingMessageTests {
    @Test void verifiesRawQueryAndRejectsAmbiguousInputs() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair key = generator.generateKeyPair();
        SamlRedirectAuthnRequest.Prepared prepared = assertInstanceOf(SamlRedirectAuthnRequest.Prepared.class,
                SamlRedirectAuthnRequest.prepare("https://sp.example.test/saml",
                        URI.create("https://sp.example.test/acs"), URI.create("https://idp.example.test/sso"),
                        key.getPrivate(), true, new SecureRandom(),
                        Clock.fixed(Instant.parse("2026-10-09T00:00:00Z"), ZoneOffset.UTC),
                        Duration.ofMinutes(5)));
        String query = prepared.redirect().getRawQuery();
        SamlRedirectBindingMessage message = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(query)).getMessage();
        assertEquals(SamlRedirectBindingMessage.Kind.REQUEST, message.getKind());
        assertTrue(message.verify(List.of(key.getPublic())));
        assertFalse(assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(query.replace("RelayState=", "RelayState=x")))
                .getMessage().verify(List.of(key.getPublic())));
        assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                SamlRedirectBindingMessage.fromRawQueryResult(query + "&RelayState=duplicate"));
        assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                SamlRedirectBindingMessage.fromRawQueryResult(query + "&unexpected=1"));
        assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                SamlRedirectBindingMessage.fromRawQueryResult(
                        query.replace("RelayState=", "RelayState=%ＦＦ")));
    }

    @Test void ecdsaRedirectAcceptsCanonicalDerAndRangeCheckedRaw() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        SamlRedirectAuthnRequest.Prepared request = assertInstanceOf(SamlRedirectAuthnRequest.Prepared.class,
                SamlRedirectAuthnRequest.prepare("https://sp.example.test/saml",
                        URI.create("https://sp.example.test/acs"), URI.create("https://idp.example.test/sso"),
                        rsa.generateKeyPair().getPrivate(), true, new SecureRandom(),
                        Clock.fixed(Instant.parse("2026-10-09T00:00:00Z"), ZoneOffset.UTC),
                        Duration.ofMinutes(5)));
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair signer = ec.generateKeyPair();
        String prefix = request.redirect().getRawQuery().split("&SigAlg=", 2)[0];
        String sigAlg = URLEncoder.encode("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                StandardCharsets.UTF_8);
        String signed = prefix + "&SigAlg=" + sigAlg;
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(signer.getPrivate());
        signature.update(signed.getBytes(StandardCharsets.US_ASCII));
        byte[] der = signature.sign();
        SamlRedirectBindingMessage derMessage = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(signed + "&Signature="
                        + URLEncoder.encode(Base64.getEncoder().encodeToString(der),
                                StandardCharsets.UTF_8))).getMessage();
        assertTrue(derMessage.verify(List.of(signer.getPublic())));
        byte[] raw = new byte[64];
        int offset = 2;
        for (int half = 0; half < 2; half++) {
            assertEquals(2, der[offset++] & 0xff);
            int size = der[offset++] & 0xff;
            int start = der[offset] == 0 ? offset + 1 : offset;
            int count = offset + size - start;
            System.arraycopy(der, start, raw, half * 32 + 32 - count, count);
            offset += size;
        }
        String rawQuery = signed + "&Signature=" + URLEncoder.encode(
                Base64.getEncoder().encodeToString(raw), StandardCharsets.UTF_8);
        SamlRedirectBindingMessage rawMessage = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(rawQuery)).getMessage();
        assertTrue(rawMessage.verify(List.of(signer.getPublic())));
        assertFalse(assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(signed + "&Signature="
                        + URLEncoder.encode(Base64.getEncoder().encodeToString(new byte[64]),
                                StandardCharsets.UTF_8))).getMessage().verify(List.of(signer.getPublic())));
    }
}
