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

import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * An internal, result-first SAML HTTP-POST binding boundary. Its success carries only unverified XML bytes and
 * untrusted RelayState; no caller may treat either as an authenticated value.
 */
final class SamlPostBindingDecoder {
    private static final int MAXIMUM_XML_BYTES = Limits.SAML_RESPONSE_DECODED_SIZE.getDefaultIntValue();
    private static final int MAXIMUM_BASE64_CHARS = 4 * ((MAXIMUM_XML_BYTES + 2) / 3);
    private static final int MAXIMUM_LINE_WRAP_CHARS = 4096;
    private static final int MAXIMUM_BODY_BYTES = 3 * (MAXIMUM_BASE64_CHARS + MAXIMUM_LINE_WRAP_CHARS) + 256;
    private static final int MAXIMUM_QUERY_CHARS = 8192;

    private SamlPostBindingDecoder() { }

    static @NonNull Result decode(byte @NonNull [] body, @NonNull List<@NonNull String> contentTypes,
            @Nullable String rawQuery) {
        requireNonNull(body);
        requireNonNull(contentTypes);
        if (body.length == 0 || body.length > MAXIMUM_BODY_BYTES) return new Rejected(Reason.BODY_SIZE);
        if (contentTypes.size() != 1 || !validContentType(contentTypes.get(0)))
            return new Rejected(Reason.CONTENT_TYPE);
        if (rawQuery != null && !validQuery(rawQuery)) return new Rejected(Reason.QUERY);

        @Nullable String encodedResponse = null;
        @Nullable String relayState = null;
        int parameters = 0;
        int start = 0;
        while (start < body.length) {
            int end = start;
            while (end < body.length && body[end] != '&') end++;
            if (end > start) {
                if (++parameters > 2) return new Rejected(Reason.PARAMETERS);
                int separator = start;
                while (separator < end && body[separator] != '=') separator++;
                if (separator == end) return new Rejected(Reason.PARAMETERS);
                @Nullable String name = decodeComponent(body, start, separator);
                @Nullable String value = decodeComponent(body, separator + 1, end);
                if (name == null || value == null) return new Rejected(Reason.FORM_ENCODING);
                if (name.equals("SAMLResponse")) {
                    if (encodedResponse != null) return new Rejected(Reason.PARAMETERS);
                    encodedResponse = value;
                } else if (name.equals("RelayState")) {
                    if (relayState != null) return new Rejected(Reason.PARAMETERS);
                    relayState = value;
                } else return new Rejected(Reason.PARAMETERS);
            }
            start = end + 1;
        }
        if (encodedResponse == null || encodedResponse.isEmpty()) return new Rejected(Reason.PARAMETERS);
        if (relayState != null && relayState.getBytes(StandardCharsets.UTF_8).length > 80)
            return new Rejected(Reason.RELAY_STATE_SIZE);

        StringBuilder base64 = new StringBuilder(Math.min(encodedResponse.length(), MAXIMUM_BASE64_CHARS));
        for (int i = 0; i < encodedResponse.length(); i++) {
            char ch = encodedResponse.charAt(i);
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue;
            if (base64.length() == MAXIMUM_BASE64_CHARS) return new Rejected(Reason.XML_SIZE);
            base64.append(ch);
        }
        byte[] xml;
        try { xml = Base64.getDecoder().decode(base64.toString()); }
        catch (IllegalArgumentException exception) { return new Rejected(Reason.BASE64); }
        if (xml.length == 0 || xml.length > MAXIMUM_XML_BYTES) return new Rejected(Reason.XML_SIZE);
        return new Accepted(xml, relayState);
    }

    private static boolean validContentType(@Nullable String value) {
        if (value == null || value.length() > 256) return false;
        for (int i = 0; i < value.length(); i++)
            if (value.charAt(i) < 0x20 || value.charAt(i) > 0x7e || value.charAt(i) == ',') return false;
        String[] pieces = value.split(";", -1);
        if (pieces.length < 1 || pieces.length > 2
                || !pieces[0].trim().equalsIgnoreCase("application/x-www-form-urlencoded")) return false;
        if (pieces.length == 1) return true;
        String parameter = pieces[1].trim();
        int equals = parameter.indexOf('=');
        if (equals < 1 || !parameter.substring(0, equals).trim().equalsIgnoreCase("charset")) return false;
        String charset = parameter.substring(equals + 1).trim();
        if (charset.length() >= 2 && charset.charAt(0) == '"' && charset.charAt(charset.length() - 1) == '"')
            charset = charset.substring(1, charset.length() - 1);
        return charset.equalsIgnoreCase("utf-8");
    }

    private static boolean validQuery(@NonNull String rawQuery) {
        if (rawQuery.length() > MAXIMUM_QUERY_CHARS) return false;
        byte[] bytes = new byte[rawQuery.length()];
        for (int i = 0; i < rawQuery.length(); i++) {
            char ch = rawQuery.charAt(i);
            if (ch > 0x7f || ch < 0x20) return false;
            bytes[i] = (byte) ch;
        }
        int start = 0;
        while (start < bytes.length) {
            int end = start;
            while (end < bytes.length && bytes[end] != '&') end++;
            if (end > start) {
                int separator = start;
                while (separator < end && bytes[separator] != '=') separator++;
                @Nullable String name = decodeComponent(bytes, start, separator);
                if (name == null || name.equals("SAMLResponse") || name.equals("SAMLRequest")
                        || name.equals("RelayState")) return false;
            }
            start = end + 1;
        }
        return true;
    }

    private static @Nullable String decodeComponent(byte @NonNull [] input, int start, int end) {
        byte[] decoded = new byte[end - start];
        int used = 0;
        for (int i = start; i < end; i++) {
            int octet = input[i] & 0xff;
            if (octet == '%') {
                if (i + 2 >= end) return null;
                int high = hex(input[++i] & 0xff);
                int low = hex(input[++i] & 0xff);
                if (high < 0 || low < 0) return null;
                decoded[used++] = (byte) ((high << 4) | low);
            } else decoded[used++] = (byte) (octet == '+' ? ' ' : octet);
        }
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        CharBuffer characters = CharBuffer.allocate(used);
        if (!decoder.decode(ByteBuffer.wrap(decoded, 0, used), characters, true).isUnderflow()
                || !decoder.flush(characters).isUnderflow()) return null;
        characters.flip();
        return characters.toString();
    }

    private static int hex(int octet) {
        if (octet >= '0' && octet <= '9') return octet - '0';
        if (octet >= 'a' && octet <= 'f') return octet - 'a' + 10;
        if (octet >= 'A' && octet <= 'F') return octet - 'A' + 10;
        return -1;
    }

    sealed interface Result permits Accepted, Rejected { }

    static final class Accepted implements Result {
        private final byte @NonNull [] xml;
        private final @Nullable String relayState;

        private Accepted(byte @NonNull [] xml, @Nullable String relayState) {
            this.xml = xml.clone();
            this.relayState = relayState;
        }

        byte @NonNull [] xml() { return xml.clone(); }
        @Nullable String relayState() { return relayState; }
        @Override public @NonNull String toString() { return "SamlPostBindingDecoder.Accepted{<unverified>}"; }
    }

    static final class Rejected implements Result {
        private final @NonNull Reason reason;
        private Rejected(@NonNull Reason reason) { this.reason = reason; }
        @NonNull Reason reason() { return reason; }
        @Override public @NonNull String toString() { return "SamlPostBindingDecoder.Rejected{" + reason + "}"; }
    }

    enum Reason { BODY_SIZE, CONTENT_TYPE, QUERY, PARAMETERS, FORM_ENCODING, RELAY_STATE_SIZE, BASE64, XML_SIZE }
}
