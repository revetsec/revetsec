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

import java.util.ArrayList;
import java.util.List;

/** Envelope attacks applied to independently captured, encrypted provider responses. */
final class CapturedEncryptedResponseMutations {
    private CapturedEncryptedResponseMutations() { }

    static @NonNull List<@NonNull Mutation> from(@NonNull String xml,
            @NonNull String protocolPrefix, @NonNull String assertionPrefix) {
        String carrierStart = "<" + assertionPrefix + ":EncryptedAssertion";
        String carrierEnd = "</" + assertionPrefix + ":EncryptedAssertion>";
        int start = xml.indexOf(carrierStart);
        int end = xml.indexOf(carrierEnd);
        if (start < 0 || end < start) throw new IllegalArgumentException("EncryptedAssertion missing");
        String carrier = xml.substring(start, end + carrierEnd.length());
        String status = "<" + protocolPrefix + ":Status>";
        if (!xml.contains(status)) throw new IllegalArgumentException("Status missing");
        String attacker = "<" + assertionPrefix + ":Assertion xmlns:" + assertionPrefix
                + "='urn:oasis:names:tc:SAML:2.0:assertion' ID='_attacker'>"
                + "<" + assertionPrefix + ":Issuer>https://attacker.example.test/</"
                + assertionPrefix + ":Issuer><" + assertionPrefix + ":Subject><" + assertionPrefix
                + ":NameID>attacker-user</" + assertionPrefix + ":NameID></" + assertionPrefix
                + ":Subject></" + assertionPrefix + ":Assertion>";
        String duplicateStatus = status + "<" + protocolPrefix + ":StatusCode "
                + "Value='urn:oasis:names:tc:SAML:2.0:status:Success'/></"
                + protocolPrefix + ":Status>" + status;
        String statusEnd = "</" + protocolPrefix + ":Status>";
        String responseStart = "<" + protocolPrefix + ":Response ";
        String responseEnd = "</" + protocolPrefix + ":Response>";
        String issuerStart = "<" + assertionPrefix + ":Issuer";
        int issuerOpening = xml.indexOf(issuerStart);
        int issuerContent = xml.indexOf('>', issuerOpening) + 1;
        String issuerEnd = "</" + assertionPrefix + ":Issuer>";
        int issuerClosing = xml.indexOf(issuerEnd, issuerContent);
        if (issuerOpening < 0 || issuerContent == 0 || issuerClosing < 0)
            throw new IllegalArgumentException("Response Issuer missing");
        String issuer = xml.substring(issuerContent, issuerClosing);
        String signatureStart = "<ds:Signature";
        int signatureOpening = xml.indexOf(signatureStart);
        int signatureClosing = xml.indexOf("</ds:Signature>", signatureOpening);
        if ((signatureOpening < 0) != (signatureClosing < 0))
            throw new IllegalArgumentException("Incomplete Response Signature");
        String attackerIssuer = "<" + assertionPrefix + ":Issuer xmlns:" + assertionPrefix
                + "='urn:oasis:names:tc:SAML:2.0:assertion'>https://attacker.example.test/</"
                + assertionPrefix + ":Issuer>";
        List<Mutation> mutations = new ArrayList<>(List.of(
                new Mutation("attacker-sibling", xml.replace(carrier, attacker + carrier)),
                new Mutation("attacker-after-carrier", xml.replace(carrier, carrier + attacker)),
                new Mutation("attacker-sibling-end", xml.replace(responseEnd,
                        attacker + responseEnd)),
                new Mutation("attacker-extension", xml.replace(status,
                        "<" + protocolPrefix + ":Extensions>" + attacker + "</"
                                + protocolPrefix + ":Extensions>" + status)),
                new Mutation("duplicate-carrier", xml.replace(carrier, carrier + carrier)),
                new Mutation("duplicate-status", xml.replace(status, duplicateStatus)),
                new Mutation("duplicate-status-code", xml.replace(statusEnd,
                        "<" + protocolPrefix + ":StatusCode Value='"
                                + "urn:oasis:names:tc:SAML:2.0:status:Success'/>" + statusEnd)),
                new Mutation("failure-status", xml.replace(
                        "urn:oasis:names:tc:SAML:2.0:status:Success",
                        "urn:oasis:names:tc:SAML:2.0:status:Responder")),
                new Mutation("missing-status", xml.replaceFirst("(?s)<" + protocolPrefix
                        + ":Status>.*?</" + protocolPrefix + ":Status>", "")),
                new Mutation("missing-destination", xml.replace(
                        "Destination=\"https://sp.example.test/acs\"", "")),
                new Mutation("destination-tamper", xml.replace("https://sp.example.test/acs",
                        "https://attacker.example.test/acs")),
                new Mutation("issuer-tamper", xml.replace(issuer,
                        "https://attacker.example.test/")),
                new Mutation("unexpected-in-response-to", xml.replaceFirst(
                        "InResponseTo=\"[^\"]+\"", "InResponseTo=\"_attacker_request\"")),
                new Mutation("qualified-response-id", xml.replace(responseStart,
                        responseStart + "xmlns:attacker='https://attacker.example.test/ns' "
                                + "attacker:ID='not-the-signed-ID' ")),
                new Mutation("relative-namespace-sibling", xml.replace(responseStart,
                        responseStart + "xmlns:ns='1' ").replace(carrier, attacker + carrier)),
                new Mutation("duplicate-issuer", xml.replace(status, attackerIssuer + status)),
                new Mutation("wrong-namespace-status", xml.replace(status,
                        "<Status xmlns='https://attacker.example.test/ns'>")
                        .replace(statusEnd, "</Status>"))));
        if (signatureOpening >= 0) {
            String signature = xml.substring(signatureOpening,
                    signatureClosing + "</ds:Signature>".length());
            String copiedSignature = "<" + protocolPrefix + ":Extensions>"
                    + "<Parent xmlns='http://www.w3.org/2000/09/xmldsig#'>"
                    + "<Child xml:xmlns='#other'>" + signature + "</Child></Parent></"
                    + protocolPrefix + ":Extensions>";
            mutations.add(new Mutation("copied-signature-extension", xml.replace(status,
                    copiedSignature + status)));
            mutations.add(new Mutation("copied-signature-direct", xml.replace(status,
                    signature + status)));
        }
        return List.copyOf(mutations);
    }

    /** Edits real provider ciphertext and XML Encryption fields without re-signing the response. */
    static @NonNull List<@NonNull Mutation> cryptographicFrom(@NonNull String xml) {
        String dataAlgorithm = xml.contains("http://www.w3.org/2009/xmlenc11#aes128-gcm")
                ? "http://www.w3.org/2009/xmlenc11#aes128-gcm"
                : "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
        String keyAlgorithm = xml.contains("http://www.w3.org/2009/xmlenc11#rsa-oaep")
                ? "http://www.w3.org/2009/xmlenc11#rsa-oaep"
                : "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
        if (!xml.contains(dataAlgorithm) || !xml.contains(keyAlgorithm))
            throw new IllegalArgumentException("Expected real-provider encryption algorithms");
        return List.of(
                new Mutation("wrapped-key-bit-flip", cipher(xml, 0, CipherEdit.FLIP)),
                new Mutation("data-bit-flip", cipher(xml, 1, CipherEdit.FLIP)),
                new Mutation("wrapped-key-truncated", cipher(xml, 0, CipherEdit.TRUNCATE)),
                new Mutation("data-truncated", cipher(xml, 1, CipherEdit.TRUNCATE)),
                new Mutation("duplicate-wrapped-key-cipher", cipher(xml, 0, CipherEdit.DUPLICATE)),
                new Mutation("duplicate-data-cipher", cipher(xml, 1, CipherEdit.DUPLICATE)),
                new Mutation("empty-wrapped-key-cipher", cipher(xml, 0, CipherEdit.EMPTY)),
                new Mutation("empty-data-cipher", cipher(xml, 1, CipherEdit.EMPTY)),
                new Mutation("rsa-v1-5-key-transport", xml.replace(keyAlgorithm,
                        "http://www.w3.org/2001/04/xmlenc#rsa-1_5")),
                new Mutation("wrong-aes-key-length", xml.replace(dataAlgorithm,
                        dataAlgorithm.replace("aes128", "aes256"))),
                new Mutation("wrong-aes-mode", xml.replace(dataAlgorithm,
                        dataAlgorithm.endsWith("-gcm")
                                ? "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
                                : "http://www.w3.org/2009/xmlenc11#aes128-gcm")));
    }

    private static @NonNull String cipher(@NonNull String xml, int ordinal, @NonNull CipherEdit edit) {
        String opening = "<xenc:CipherValue>";
        String closing = "</xenc:CipherValue>";
        int start = -1;
        for (int index = 0; index <= ordinal; index++) start = xml.indexOf(opening, start + 1);
        if (start < 0) throw new IllegalArgumentException("CipherValue missing");
        int contentStart = start + opening.length();
        int contentEnd = xml.indexOf(closing, contentStart);
        if (contentEnd < 0 || contentEnd - contentStart < 8)
            throw new IllegalArgumentException("CipherValue too short");
        String value = xml.substring(contentStart, contentEnd);
        String changed = switch (edit) {
            case FLIP -> {
                int position = value.length() / 2;
                yield value.substring(0, position) + (value.charAt(position) == 'A' ? 'B' : 'A')
                        + value.substring(position + 1);
            }
            case TRUNCATE -> value.substring(0, value.length() - 4);
            case EMPTY -> "";
            case DUPLICATE -> value + closing + opening + value;
        };
        return xml.substring(0, contentStart) + changed + xml.substring(contentEnd);
    }

    private enum CipherEdit { FLIP, TRUNCATE, DUPLICATE, EMPTY }

    record Mutation(@NonNull String name, @NonNull String xml) { }
}
