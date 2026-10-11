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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Arrays;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;

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
        assertEquals(prepared.relayState(), message.getRelayState().orElseThrow());
        assertEquals("SamlRedirectBindingMessage{<redacted>}", message.toString());
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

    @Test void ecdsaRedirectAcceptsTheMaximumCanonicalP256IntegerLength() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair signer = generator.generateKeyPair();
        String base = signedBoundaryQuery().split("&SigAlg=", 2)[0];
        String algorithm = URLEncoder.encode(
                "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                StandardCharsets.US_ASCII);
        Signature signature = Signature.getInstance("SHA256withECDSA");
        boolean exercised = false;
        for (int attempt = 0; attempt < 128; attempt++) {
            String signed = field(base, "RelayState", "nonce-" + attempt) + "&SigAlg=" + algorithm;
            signature.initSign(signer.getPrivate());
            signature.update(signed.getBytes(StandardCharsets.US_ASCII));
            byte[] der = signature.sign();
            int firstIntegerLength = der[3] & 0xff;
            int secondIntegerLength = der[5 + firstIntegerLength] & 0xff;
            if (firstIntegerLength != 33 && secondIntegerLength != 33) continue;
            assertTrue(withSignature(signed, der).verify(List.of(signer.getPublic())));
            exercised = true;
            break;
        }
        assertTrue(exercised, "The fixture must exercise a padded 33-byte P-256 integer");
    }

    @Test void ecdsaRedirectRejectsMalformedDerAcrossP384AndP521() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair wrongKind = rsa.generateKeyPair();
        SamlRedirectAuthnRequest.Prepared request = assertInstanceOf(SamlRedirectAuthnRequest.Prepared.class,
                SamlRedirectAuthnRequest.prepare("https://sp.example.test/saml",
                        URI.create("https://sp.example.test/acs"), URI.create("https://idp.example.test/sso"),
                        wrongKind.getPrivate(), true, new SecureRandom(),
                        Clock.fixed(Instant.parse("2026-10-09T00:00:00Z"), ZoneOffset.UTC),
                        Duration.ofMinutes(5)));
        String prefix = request.redirect().getRawQuery().split("&SigAlg=", 2)[0];
        for (String curve : List.of("secp384r1", "secp521r1")) {
            boolean p521 = "secp521r1".equals(curve);
            String hash = p521 ? "SHA512" : "SHA384";
            String algorithm = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha"
                    + (p521 ? "512" : "384");
            KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
            ec.initialize(new java.security.spec.ECGenParameterSpec(curve));
            KeyPair signer = ec.generateKeyPair();
            String signed = prefix + "&SigAlg=" + URLEncoder.encode(algorithm, StandardCharsets.UTF_8);
            Signature signature = Signature.getInstance(hash + "withECDSA");
            signature.initSign(signer.getPrivate());
            signature.update(signed.getBytes(StandardCharsets.US_ASCII));
            byte[] der = signature.sign();
            assertEquals(p521 ? 0x81 : der.length - 2, der[1] & 0xff, curve);
            SamlRedirectBindingMessage valid = withSignature(signed, der);
            assertTrue(valid.verify(List.of(signer.getPublic())), curve);
            assertFalse(valid.verify(List.of(wrongKind.getPublic())), curve);
            int coordinateLength = p521 ? 66 : 48;
            byte[] raw = new byte[coordinateLength * 2];
            int offset = p521 ? 3 : 2;
            for (int half = 0; half < 2; half++) {
                assertEquals(0x02, der[offset++] & 0xff, curve);
                int integerLength = der[offset++] & 0xff;
                int start = der[offset] == 0 ? offset + 1 : offset;
                int magnitudeLength = offset + integerLength - start;
                System.arraycopy(der, start, raw,
                        half * coordinateLength + coordinateLength - magnitudeLength, magnitudeLength);
                offset += integerLength;
            }
            assertEquals(der.length, offset, curve);
            assertTrue(withSignature(signed, raw).verify(List.of(signer.getPublic())), curve);
            byte[] outOfRangeRaw = raw.clone();
            java.util.Arrays.fill(outOfRangeRaw, 0, coordinateLength, (byte) 0xff);
            assertFalse(withSignature(signed, outOfRangeRaw).verify(List.of(signer.getPublic())), curve);

            byte[] wrongSequence = der.clone();
            wrongSequence[0] = 0x31;
            byte[] wrongLength = der.clone();
            wrongLength[p521 ? 2 : 1]--;
            byte[] wrongInteger = der.clone();
            int firstInteger = p521 ? 3 : 2;
            wrongInteger[firstInteger] = 0x03;
            byte[] trailing = java.util.Arrays.copyOf(der, der.length + 1);
            byte[] trailingInsideSequence = trailing.clone();
            trailingInsideSequence[p521 ? 2 : 1]++;
            byte[] emptyInteger = der.clone();
            emptyInteger[firstInteger + 1] = 0;
            byte[] overlongInteger = der.clone();
            overlongInteger[firstInteger + 1] = (byte) 0xff;
            byte[] unnecessaryPadding = der.clone();
            unnecessaryPadding[firstInteger + 2] = 0;
            unnecessaryPadding[firstInteger + 3] = 1;
            byte[] negativeInteger = der.clone();
            negativeInteger[firstInteger + 2] = (byte) 0x80;
            for (byte[] malformed : List.of(wrongSequence, wrongLength, wrongInteger, trailing,
                    trailingInsideSequence, emptyInteger, overlongInteger, unnecessaryPadding,
                    negativeInteger))
                assertFalse(withSignature(signed, malformed).verify(List.of(signer.getPublic())), curve);
            if (!p521) {
                byte[] noncanonicalLength = new byte[der.length + 1];
                noncanonicalLength[0] = 0x30;
                noncanonicalLength[1] = (byte) 0x81;
                noncanonicalLength[2] = der[1];
                System.arraycopy(der, 2, noncanonicalLength, 3, der.length - 2);
                assertFalse(withSignature(signed, noncanonicalLength)
                        .verify(List.of(signer.getPublic())), curve);
            } else {
                byte[] missingSecondInteger = new byte[70];
                missingSecondInteger[0] = 0x30;
                missingSecondInteger[1] = 68;
                missingSecondInteger[2] = 0x02;
                missingSecondInteger[3] = 66;
                missingSecondInteger[4] = 1;
                assertFalse(withSignature(signed, missingSecondInteger)
                        .verify(List.of(signer.getPublic())));
                byte[] excessMagnitude = new byte[72];
                excessMagnitude[0] = 0x30;
                excessMagnitude[1] = 70;
                excessMagnitude[2] = 0x02;
                excessMagnitude[3] = 67;
                excessMagnitude[4] = 1;
                assertFalse(withSignature(signed, excessMagnitude)
                        .verify(List.of(signer.getPublic())));
            }
        }
    }

    @Test void rsaRedirectAlgorithmsEnforceSha1OptInAndRejectUnknownAlgorithms() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair signer = rsa.generateKeyPair();
        SamlRedirectAuthnRequest.Prepared request = assertInstanceOf(SamlRedirectAuthnRequest.Prepared.class,
                SamlRedirectAuthnRequest.prepare("https://sp.example.test/saml",
                        URI.create("https://sp.example.test/acs"), URI.create("https://idp.example.test/sso"),
                        signer.getPrivate(), true, new SecureRandom(),
                        Clock.fixed(Instant.parse("2026-10-09T00:00:00Z"), ZoneOffset.UTC),
                        Duration.ofMinutes(5)));
        String prefix = request.redirect().getRawQuery().split("&SigAlg=", 2)[0];
        for (Map.Entry<String, String> algorithm : Map.of(
                "SHA1withRSA", "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                "SHA384withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                "SHA512withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512").entrySet()) {
            String signed = prefix + "&SigAlg=" + URLEncoder.encode(algorithm.getValue(),
                    StandardCharsets.UTF_8);
            Signature signature = Signature.getInstance(algorithm.getKey());
            signature.initSign(signer.getPrivate());
            signature.update(signed.getBytes(StandardCharsets.US_ASCII));
            SamlRedirectBindingMessage message = withSignature(signed, signature.sign());
            assertTrue(message.verify(List.of(signer.getPublic()), true), algorithm.getKey());
            assertEquals(!"SHA1withRSA".equals(algorithm.getKey()),
                    message.verify(List.of(signer.getPublic())), algorithm.getKey());
        }
        String unknown = prefix + "&SigAlg=" + URLEncoder.encode("https://example.test/unknown",
                StandardCharsets.UTF_8);
        assertFalse(withSignature(unknown, new byte[256]).verify(List.of(signer.getPublic()), true));
    }

    @Test void redirectParserRejectsAmbiguousFieldsMalformedOctetsAndUnboundedPayloads() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair key = generator.generateKeyPair();
        String query = assertInstanceOf(SamlRedirectAuthnRequest.Prepared.class,
                SamlRedirectAuthnRequest.prepare("https://sp.example.test/saml",
                        URI.create("https://sp.example.test/acs"), URI.create("https://idp.example.test/sso"),
                        key.getPrivate(), true, new SecureRandom(),
                        Clock.fixed(Instant.parse("2026-10-09T00:00:00Z"), ZoneOffset.UTC),
                        Duration.ofMinutes(5))).redirect().getRawQuery();
        Map<String, String> invalid = Map.ofEntries(
                Map.entry("empty query", ""),
                Map.entry("query size", "x".repeat(65537)),
                Map.entry("empty field", query + "&"),
                Map.entry("field without equals", query + "&junk"),
                Map.entry("empty signature", query.replaceAll("Signature=[^&]+", "Signature=")),
                Map.entry("empty relay state", query.replaceAll("RelayState=[^&]+", "RelayState=")),
                Map.entry("duplicate message", query + "&SAMLRequest=x"),
                Map.entry("both message kinds", query + "&SAMLResponse=x"),
                Map.entry("missing algorithm", query.replaceAll("&SigAlg=[^&]+", "")),
                Map.entry("missing signature", query.replaceAll("&Signature=[^&]+", "")),
                Map.entry("malformed message escape", query.replaceAll("SAMLRequest=[^&]+", "SAMLRequest=%")),
                Map.entry("malformed algorithm escape", query.replaceAll("SigAlg=[^&]+", "SigAlg=%GG")),
                Map.entry("non-ASCII relay", query.replaceAll("RelayState=[^&]+", "RelayState=%FF")),
                Map.entry("overlong relay", query.replaceAll("RelayState=[^&]+",
                        "RelayState=" + "A".repeat(81))),
                Map.entry("invalid compressed Base64", query.replaceAll("SAMLRequest=[^&]+",
                        "SAMLRequest=!!!!")),
                Map.entry("invalid DEFLATE stream", query.replaceAll("SAMLRequest=[^&]+",
                        "SAMLRequest=AAAA")),
                Map.entry("short signature", query.replaceAll("Signature=[^&]+", "Signature=AA%3D%3D")),
                Map.entry("literal space", query.replaceAll("RelayState=[^&]+", "RelayState=bad value")));
        for (Map.Entry<String, String> caseUnderTest : invalid.entrySet())
            assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                    SamlRedirectBindingMessage.fromRawQueryResult(caseUnderTest.getValue()),
                    caseUnderTest.getKey());

        SamlRedirectBindingMessage parsed = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(query)).getMessage();
        assertTrue(parsed.verify(List.of(key.getPublic())));
        assertFalse(parsed.verify(List.of(generator.generateKeyPair().getPublic())));
    }

    @Test void redirectParserKeepsExactOctetAndSignatureSizeBoundaries() throws Exception {
        String query = signedBoundaryQuery();
        assertEquals("!~", assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(
                        field(query, "RelayState", "!~"))).getMessage().getRelayState().orElseThrow());
        assertEquals("09*/*/", assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(
                        field(query, "RelayState", "%30%39%2A%2F%2a%2f")))
                .getMessage().getRelayState().orElseThrow());
        for (String invalid : List.of("%20", "%7F", "%G0", "%2G", "%4G", "%A"))
            assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                    SamlRedirectBindingMessage.fromRawQueryResult(
                            field(query, "RelayState", invalid)), invalid);
        assertEquals("!".repeat(80), assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(
                        field(query, "RelayState", "%21".repeat(80))))
                .getMessage().getRelayState().orElseThrow());
        assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                SamlRedirectBindingMessage.fromRawQueryResult(
                        field(query, "RelayState", "%21".repeat(81))));

        for (int size : List.of(64, 1024)) {
            byte[] signature = new byte[size];
            Arrays.fill(signature, (byte) 0xA5);
            assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                    SamlRedirectBindingMessage.fromRawQueryResult(field(query, "Signature",
                            URLEncoder.encode(Base64.getEncoder().encodeToString(signature),
                                    StandardCharsets.US_ASCII))), "signature bytes " + size);
        }
        for (int size : List.of(63, 1025)) {
            byte[] signature = new byte[size];
            Arrays.fill(signature, (byte) 0xA5);
            assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                    SamlRedirectBindingMessage.fromRawQueryResult(field(query, "Signature",
                            URLEncoder.encode(Base64.getEncoder().encodeToString(signature),
                                    StandardCharsets.US_ASCII))), "signature bytes " + size);
        }
    }

    @Test void redirectParserKeepsCompressedAndInflatedSizeBoundaries() throws Exception {
        String query = signedBoundaryQuery();
        String exactCompressed = field(query, "SAMLRequest", URLEncoder.encode(
                Base64.getEncoder().encodeToString(storedDeflate(24571)),
                StandardCharsets.US_ASCII));
        SamlRedirectBindingMessage parsed = assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(exactCompressed)).getMessage();
        assertEquals(24571, parsed.xml().length);
        assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                SamlRedirectBindingMessage.fromRawQueryResult(field(query, "SAMLRequest",
                        URLEncoder.encode(Base64.getEncoder().encodeToString(storedDeflate(24572)),
                                StandardCharsets.US_ASCII))));

        byte[] exactXml = new byte[131072];
        Arrays.fill(exactXml, (byte) 'A');
        byte[] oversizedXml = Arrays.copyOf(exactXml, exactXml.length + 1);
        oversizedXml[oversizedXml.length - 1] = 'A';
        assertEquals(exactXml.length, assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(field(query, "SAMLRequest",
                        URLEncoder.encode(Base64.getEncoder().encodeToString(deflate(exactXml)),
                                StandardCharsets.US_ASCII)))).getMessage().xml().length);
        assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                SamlRedirectBindingMessage.fromRawQueryResult(field(query, "SAMLRequest",
                        URLEncoder.encode(Base64.getEncoder().encodeToString(deflate(oversizedXml)),
                                StandardCharsets.US_ASCII))));
    }

    @Test void redirectParserAcceptsTheExactRawQueryLimitAndRejectsTheNextByte() throws Exception {
        String encodedMessage = Base64.getEncoder().encodeToString(storedDeflate(24571));
        String query = field(signedBoundaryQuery(), "SAMLRequest", encodedMessage);
        String relay = "relay";
        int extra = 65536 - query.length();
        if ((extra & 1) != 0) {
            relay += "A";
            query = field(query, "RelayState", relay);
            extra--;
        }
        int escapedCharacters = extra / 2;
        assertTrue(escapedCharacters > 0 && escapedCharacters <= encodedMessage.length());
        String hex = "0123456789ABCDEF";
        StringBuilder expandedMessage = new StringBuilder(encodedMessage.length() + extra);
        for (int i = 0; i < encodedMessage.length(); i++) {
            char value = encodedMessage.charAt(i);
            if (i < escapedCharacters)
                expandedMessage.append('%').append(hex.charAt(value >>> 4))
                        .append(hex.charAt(value & 15));
            else expandedMessage.append(value);
        }
        String exact = field(query, "SAMLRequest", expandedMessage.toString());
        assertEquals(65536, exact.length());
        assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(exact));
        String overLimit = field(exact, "RelayState", relay + "A");
        assertEquals(65537, overLimit.length());
        assertInstanceOf(SamlRedirectBindingParseResult.Rejected.class,
                SamlRedirectBindingMessage.fromRawQueryResult(overLimit));
    }

    private static @NonNull String signedBoundaryQuery() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return SamlRedirectLogout.sign(URI.create("https://idp.example.test/slo"), "SAMLRequest",
                "<Request/>".getBytes(StandardCharsets.UTF_8), "relay",
                generator.generateKeyPair().getPrivate()).getRawQuery();
    }

    private static @NonNull String field(@NonNull String query, @NonNull String name,
            @NonNull String encoded) {
        int start = query.indexOf(name + "=");
        assertTrue(start >= 0, name);
        int value = start + name.length() + 1;
        int end = query.indexOf('&', value);
        if (end < 0) end = query.length();
        return query.substring(0, value) + encoded + query.substring(end);
    }

    private static byte @NonNull [] storedDeflate(int size) {
        byte[] output = new byte[size + 5];
        output[0] = 1;
        output[1] = (byte) size;
        output[2] = (byte) (size >>> 8);
        output[3] = (byte) ~size;
        output[4] = (byte) (~size >>> 8);
        Arrays.fill(output, 5, output.length, (byte) 'A');
        return output;
    }

    private static byte @NonNull [] deflate(byte @NonNull [] plain) {
        Deflater compressor = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        byte[] output = new byte[4096];
        try {
            compressor.setInput(plain);
            compressor.finish();
            int size = compressor.deflate(output);
            assertTrue(compressor.finished());
            return Arrays.copyOf(output, size);
        } finally {
            compressor.end();
        }
    }

    private static @NonNull SamlRedirectBindingMessage withSignature(@NonNull String signed,
            byte @NonNull [] bytes) {
        return assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(signed + "&Signature="
                        + URLEncoder.encode(Base64.getEncoder().encodeToString(bytes),
                                StandardCharsets.UTF_8))).getMessage();
    }
}
