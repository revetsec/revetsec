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

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

final class SamlPostBase64GrammarTests {
    private static final List<String> MIME = List.of("application/x-www-form-urlencoded; charset=UTF-8");
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private static final int XML_CAP = 256 * 1024;
    private static final int BODY_CAP = 1_061_128;

    @TestFactory @NonNull Stream<@NonNull DynamicTest> rejectsOmittedPaddingAndNonzeroUnusedBits() {
        return Stream.of(0, 1, 2).flatMap(channel -> Stream.of("PA", "PA=", "PHg", "AAA",
                "PB==", "PC==", "PHh=", "PHj=", "/x==", "//9=").map(value ->
                DynamicTest.dynamicTest("noncanonical channel=" + channel + " value=" + value,
                        () -> rejected(channel, value, SamlPostBindingParseResult.Reason.BASE64))));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> independentPadBitModelCoversEveryFinalSextet() {
        return Stream.of(0, 1, 2).flatMap(channel -> Stream.of(false, true).map(twoBytes ->
                DynamicTest.dynamicTest("pad-bit model channel=" + channel + " two bytes=" + twoBytes, () -> {
            // Literal sextet arithmetic is independent of the production re-encoding check.
            if (!twoBytes) {
                for (int first : new int[] {0, 15, 25, 26, 51, 52, 61, 62, 63}) {
                    for (int tail = 0; tail < 64; tail++) {
                        String value = "" + ALPHABET.charAt(first) + ALPHABET.charAt(tail) + "==";
                        if ((tail & 15) == 0) accepted(channel, value, new byte[] {(byte) (first << 2 | tail >> 4)});
                        else rejected(channel, value, SamlPostBindingParseResult.Reason.BASE64);
                    }
                }
            } else {
                for (int[] prefix : new int[][] {{0, 0}, {15, 7}, {62, 63}, {63, 62}}) {
                    for (int tail = 0; tail < 64; tail++) {
                        String value = "" + ALPHABET.charAt(prefix[0]) + ALPHABET.charAt(prefix[1]) + ALPHABET.charAt(tail) + "=";
                        if ((tail & 3) == 0) accepted(channel, value, new byte[] {
                                (byte) (prefix[0] << 2 | prefix[1] >> 4), (byte) (prefix[1] << 4 | tail >> 2)});
                        else rejected(channel, value, SamlPostBindingParseResult.Reason.BASE64);
                    }
                }
            }
        })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> exactAndExcessiveWhitespaceBudgets() {
        return Stream.of(0, 1, 2).flatMap(channel -> Stream.of(" ", "\t", "\r", "\n", " \t\r\n")
                .flatMap(unit -> Stream.of(false, true).map(over -> DynamicTest.dynamicTest(
                        "wrap channel=" + channel + " code=" + (int) unit.charAt(0) + " mixed=" + (unit.length() > 1) + " over=" + over, () -> {
            String whitespace = unit.repeat(4096 / unit.length()) + (over ? " " : "");
            String value = "P" + whitespace + "A==";
            if (over) rejected(channel, value, SamlPostBindingParseResult.Reason.BASE64);
            else accepted(channel, value, new byte[] {'<'});
        }))));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> canonicalQuantaAndPermittedWhitespacePositionsRemainReadable() {
        return Stream.of(0, 1, 2).flatMap(channel -> Stream.of("PA==", "PHg=", "PHgv", "++++", "////",
                " \t\r\nPA==", "PA== \t\r\n", "P A = =", "P\tH\r g=\n").map(value ->
                DynamicTest.dynamicTest("canonical channel=" + channel + " value=" + value, () -> {
            String clean = value.replace(" ", "").replace("\t", "").replace("\r", "").replace("\n", "");
            accepted(channel, value, Base64.getDecoder().decode(clean));
        })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> malformedAlphabetPaddingAndWhitespaceStillReject() {
        return Stream.of(0, 1, 2).flatMap(channel -> Stream.of("A", "=", "====", "A===", "AA=", "AA===",
                "AA==AA==", "A=AA", "AAA==", "AAAA=", "_A==", "-A==", "AA*==", "AA\u000b==",
                "AA\f==", "AA\u0085==", "AA\u00a0==", "AA\u2028==").map(value ->
                DynamicTest.dynamicTest("invalid channel=" + channel + " value=" + value, () ->
                        rejected(channel, value, SamlPostBindingParseResult.Reason.BASE64))));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> decodedXmlAndEncodedCeilingsAreIndependentOfWrapping() {
        return Stream.of(0, 1, 2).flatMap(channel -> Stream.of(1, 2, 3, XML_CAP - 1, XML_CAP,
                XML_CAP + 1, XML_CAP + 2, XML_CAP + 3).map(size -> DynamicTest.dynamicTest(
                        "XML channel=" + channel + " size=" + size, () -> {
            byte[] xml = new byte[size]; Arrays.fill(xml, (byte) 0xfb);
            String value = Base64.getEncoder().encodeToString(xml);
            if (size <= XML_CAP) accepted(channel, value + "\r\n".repeat(2048), xml);
            else rejected(channel, value, SamlPostBindingParseResult.Reason.XML_SIZE);
        })));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> encodedCeilingRejectsBeforeDecodingMalformedBase64() {
        return Stream.of(0, 1, 2).map(channel -> DynamicTest.dynamicTest("encoded cap channel=" + channel, () -> {
            // A malformed byte after the encoded cap must not reach the JDK Base64 decoder.
            rejected(channel, "A".repeat(349_528) + "*", SamlPostBindingParseResult.Reason.XML_SIZE);
        }));
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> bodyCapPrecedesTheWhitespaceGrammar() {
        return Stream.of(0, 1, 2).map(channel -> DynamicTest.dynamicTest("body cap channel=" + channel, () -> {
            String prefix = field(channel) + "=PA==";
            byte[] atCap = (prefix + " ".repeat(BODY_CAP - prefix.length())).getBytes(StandardCharsets.US_ASCII);
            assertEquals(BODY_CAP, atCap.length);
            assertReason(SamlPostBindingParseResult.Reason.BASE64, parse(channel, atCap, MIME, null));
            byte[] over = Arrays.copyOf(atCap, atCap.length + 1);
            assertReason(SamlPostBindingParseResult.Reason.BODY_SIZE, parse(channel, over, MIME, null));
        }));
    }

    @Test void formDecodingIsNotASecondBase64Alphabet() {
        // Form '+' means SPACE; a literal Base64 '+' must use %2B. Do not repair it implicitly.
        byte[] expected = Base64.getDecoder().decode("++++");
        accepted(0, "++++", expected);
        assertReason(SamlPostBindingParseResult.Reason.XML_SIZE, parse(0, bytes("SAMLResponse=++++"), MIME, null));
        accepted(0, " P A = = ", new byte[] {'<'});
        assertReason(SamlPostBindingParseResult.Reason.BASE64, parse(0, bytes("SAMLResponse=%252B%252B%252B%252B"), MIME, null));
        assertReason(SamlPostBindingParseResult.Reason.BASE64, parse(0, bytes("SAMLResponse=AAAA+AAA"), MIME, null));
        assertReason(SamlPostBindingParseResult.Reason.FORM_ENCODING, parse(0, bytes("SAMLResponse=%GG"), MIME, null));
    }

    @Test void transportFencesAndUntrustedClassificationRemainIntact() {
        byte[] good = body(0, "PA==");
        assertReason(SamlPostBindingParseResult.Reason.CONTENT_TYPE, parse(0, good, List.of("text/plain"), null));
        assertReason(SamlPostBindingParseResult.Reason.CONTENT_TYPE, parse(0, good, List.of(MIME.get(0), MIME.get(0)), null));
        assertReason(SamlPostBindingParseResult.Reason.QUERY, parse(0, good, MIME, "SAMLResponse=shadow"));
        assertReason(SamlPostBindingParseResult.Reason.PARAMETERS, parse(0, bytes("SAMLResponse=PA==&SAMLResponse=PA=="), MIME, null));
        assertReason(SamlPostBindingParseResult.Reason.PARAMETERS, parse(1, bytes("SAMLResponse=PA==&SAMLRequest=PA=="), MIME, null));
        assertReason(SamlPostBindingParseResult.Reason.PARAMETERS, parse(0, body(2, "PA=="), MIME, null));
        assertReason(SamlPostBindingParseResult.Reason.PARAMETERS, parse(0, bytes("SAMLResponse="), MIME, null));
        assertReason(SamlPostBindingParseResult.Reason.XML_SIZE, parse(0, body(0, " \t\r\n"), MIME, null));
        assertReason(SamlPostBindingParseResult.Reason.RELAY_STATE_SIZE,
                parse(0, bytes("SAMLResponse=PA==&RelayState=" + "a".repeat(81)), MIME, null));
        var parsed = assertInstanceOf(SamlPostBindingParseResult.Parsed.class, parse(0, good, MIME, null));
        assertTrue(parsed.getMessage().toString().contains("<untrusted>"));
        assertInstanceOf(SamlInboundResponse.Rejected.class, SamlInboundResponse.parse(parsed.getMessage()));
    }

    private static void accepted(int channel, @NonNull String value, byte @NonNull [] expected) {
        var message = assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                parse(channel, body(channel, value), MIME, "tenant=one")).getMessage();
        assertEquals(channel == 2 ? SamlPostBindingMessage.Kind.REQUEST : SamlPostBindingMessage.Kind.RESPONSE, message.getKind());
        assertArrayEquals(expected, message.xml());
        assertEquals("opaque", message.getRelayState().orElseThrow());
        byte[] borrowed = message.xml(); borrowed[0] ^= 1;
        assertArrayEquals(expected, message.xml());
    }
    private static void rejected(int channel, @NonNull String value, SamlPostBindingParseResult.@NonNull Reason reason) {
        assertReason(reason, parse(channel, body(channel, value), MIME, null));
    }
    private static void assertReason(SamlPostBindingParseResult.@NonNull Reason reason, @NonNull SamlPostBindingParseResult result) {
        assertEquals(reason, assertInstanceOf(SamlPostBindingParseResult.Rejected.class, result).getReason());
    }
    private static @NonNull SamlPostBindingParseResult parse(int channel, byte @NonNull [] body, @NonNull List<@NonNull String> mime,
            @org.jspecify.annotations.Nullable String query) {
        return channel == 0 ? SamlPostBindingMessage.fromFormBodyResult(body, mime, query)
                : SamlPostBindingMessage.fromLogoutFormBodyResult(body, mime, query);
    }
    private static @NonNull String field(int channel) { return channel == 2 ? "SAMLRequest" : "SAMLResponse"; }
    private static byte @NonNull [] body(int channel, @NonNull String value) {
        return bytes(field(channel) + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8) + "&RelayState=opaque");
    }
    private static byte @NonNull [] bytes(@NonNull String text) { return text.getBytes(StandardCharsets.UTF_8); }
}
