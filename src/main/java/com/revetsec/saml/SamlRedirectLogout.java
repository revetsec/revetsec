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
import org.jspecify.annotations.Nullable;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.zip.Deflater;

/** Signed outbound HTTP-Redirect logout messages. */
final class SamlRedirectLogout {
    private static final String PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";
    private static final String ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SIGALG = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String HEX = "0123456789ABCDEF";
    private SamlRedirectLogout() { }

    static @Nullable URI request(@NonNull URI destination, @NonNull String spEntityId,
            @NonNull SamlSessionReference session, @NonNull String requestId, @NonNull String relay,
            @NonNull Instant issued, @NonNull PrivateKey key) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            XMLStreamWriter xml = XMLOutputFactory.newDefaultFactory().createXMLStreamWriter(bytes, "UTF-8");
            try {
                xml.writeStartDocument("UTF-8", "1.0");
                xml.writeStartElement("p", "LogoutRequest", PROTOCOL);
                xml.writeNamespace("p", PROTOCOL);
                xml.writeNamespace("a", ASSERTION);
                xml.writeAttribute("ID", requestId);
                xml.writeAttribute("Version", "2.0");
                xml.writeAttribute("IssueInstant", issued.toString());
                xml.writeAttribute("Destination", destination.toASCIIString());
                xml.writeStartElement("a", "Issuer", ASSERTION);
                xml.writeCharacters(spEntityId);
                xml.writeEndElement();
                nameId(xml, session.getNameId());
                if (session.getSessionIndex().isPresent()) {
                    xml.writeStartElement("p", "SessionIndex", PROTOCOL);
                    xml.writeCharacters(session.getSessionIndex().orElseThrow());
                    xml.writeEndElement();
                }
                xml.writeEndElement();
                xml.writeEndDocument();
                xml.flush();
            } finally { xml.close(); }
            return sign(destination, "SAMLRequest", bytes.toByteArray(), relay, key);
        } catch (XMLStreamException | GeneralSecurityException | IllegalArgumentException exception) {
            return null;
        }
    }

    static @Nullable URI response(@NonNull URI destination, @NonNull String spEntityId,
            @NonNull String responseId, @NonNull String inResponseTo, @Nullable String relay,
            @NonNull Instant issued, @NonNull SamlLogoutStatus status,
            @NonNull PrivateKey key) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            XMLStreamWriter xml = XMLOutputFactory.newDefaultFactory().createXMLStreamWriter(bytes, "UTF-8");
            try {
                xml.writeStartDocument("UTF-8", "1.0");
                xml.writeStartElement("p", "LogoutResponse", PROTOCOL);
                xml.writeNamespace("p", PROTOCOL);
                xml.writeNamespace("a", ASSERTION);
                xml.writeAttribute("ID", responseId);
                xml.writeAttribute("Version", "2.0");
                xml.writeAttribute("IssueInstant", issued.toString());
                xml.writeAttribute("Destination", destination.toASCIIString());
                xml.writeAttribute("InResponseTo", inResponseTo);
                xml.writeStartElement("a", "Issuer", ASSERTION);
                xml.writeCharacters(spEntityId);
                xml.writeEndElement();
                xml.writeStartElement("p", "Status", PROTOCOL);
                xml.writeEmptyElement("p", "StatusCode", PROTOCOL);
                xml.writeAttribute("Value", status.uri());
                xml.writeEndElement();
                xml.writeEndElement();
                xml.writeEndDocument();
                xml.flush();
            } finally { xml.close(); }
            return sign(destination, "SAMLResponse", bytes.toByteArray(), relay, key);
        } catch (XMLStreamException | GeneralSecurityException | IllegalArgumentException exception) {
            return null;
        }
    }

    private static void nameId(@NonNull XMLStreamWriter xml, @NonNull SamlNameId nameId)
            throws XMLStreamException {
        xml.writeStartElement("a", "NameID", ASSERTION);
        if (nameId.getFormat().isPresent()) xml.writeAttribute("Format", nameId.getFormat().orElseThrow());
        if (nameId.getNameQualifier().isPresent())
            xml.writeAttribute("NameQualifier", nameId.getNameQualifier().orElseThrow());
        if (nameId.getSpNameQualifier().isPresent())
            xml.writeAttribute("SPNameQualifier", nameId.getSpNameQualifier().orElseThrow());
        xml.writeCharacters(nameId.getValue());
        xml.writeEndElement();
    }

    private static @NonNull URI sign(@NonNull URI destination, @NonNull String field,
            byte @NonNull [] xml, @Nullable String relay, @NonNull PrivateKey key)
            throws GeneralSecurityException {
        if (xml.length > 16384 || destination.getRawQuery() != null) throw new IllegalArgumentException();
        Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        byte[] output = new byte[16384];
        int count;
        try {
            deflater.setInput(xml);
            deflater.finish();
            count = deflater.deflate(output);
            if (!deflater.finished()) throw new IllegalArgumentException();
        } finally { deflater.end(); }
        String signed = field + "=" + percent(Base64.getEncoder().encodeToString(
                java.util.Arrays.copyOf(output, count)))
                + (relay == null ? "" : "&RelayState=" + percent(relay))
                + "&SigAlg=" + percent(SIGALG);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(signed.getBytes(StandardCharsets.US_ASCII));
        String query = signed + "&Signature=" + percent(Base64.getEncoder().encodeToString(signer.sign()));
        return URI.create(destination.toASCIIString() + "?" + query);
    }

    static @NonNull String id(@NonNull SecureRandom random) {
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        StringBuilder id = new StringBuilder(41).append('_');
        for (byte value : bytes) id.append(HEX.charAt((value >>> 4) & 15)).append(HEX.charAt(value & 15));
        return id.toString();
    }

    static @NonNull String relay(@NonNull SecureRandom random) {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static @NonNull String percent(@NonNull String text) {
        StringBuilder result = new StringBuilder();
        for (byte octet : text.getBytes(StandardCharsets.US_ASCII)) {
            int value = octet & 255;
            if ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
                    || (value >= '0' && value <= '9') || value == '-' || value == '.'
                    || value == '_' || value == '~') result.append((char) value);
            else result.append('%').append(HEX.charAt(value >>> 4)).append(HEX.charAt(value & 15));
        }
        return result.toString();
    }
}
