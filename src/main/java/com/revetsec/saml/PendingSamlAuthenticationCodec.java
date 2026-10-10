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

import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.List;

/** A bounded, versioned format inside a separately authenticated SAML seal. */
final class PendingSamlAuthenticationCodec {
    private static final int MAXIMUM_LENGTH = 8192;
    private PendingSamlAuthenticationCodec() { }

    static @NonNull String encode(@NonNull PendingSamlAuthentication pending) {
        SamlAuthenticationRequestOptions options = pending.options();
        return "3." + part(pending.spEntityId()) + '.' + part(pending.requestId()) + '.'
                + part(pending.relayState()) + '.' + part(pending.connectionId()) + '.'
                + part(pending.idpEntityId()) + '.' + part(pending.acs()) + '.'
                + part(pending.issuedAt().toString()) + '.' + part(pending.expiresAt().toString()) + '.'
                + (options.isForceAuthn() ? '1' : '0') + '.'
                + (options.isPassive() ? '1' : '0') + '.'
                + (options.getRequestedAuthnContextClassRefs().isEmpty() ? "-" : part(String.join("\n",
                        options.getRequestedAuthnContextClassRefs()))) + '.'
                + options.getApplicationData().map(value -> part("x" + value)).orElse("-");
    }

    static @Nullable PendingSamlAuthentication decode(@NonNull String value) {
        if (value.length() == 0 || value.length() > MAXIMUM_LENGTH) return null;
        String[] fields = value.split("\\.", -1);
        boolean old = fields.length == 9 && fields[0].equals("1");
        boolean current = fields.length == 13 && fields[0].equals("3");
        boolean previous = fields.length == 13 && fields[0].equals("2");
        if (!old && !previous && !current) return null;
        String sp = fromPart(fields[1], 2048);
        String request = fromPart(fields[2], 128);
        String relay = fromPart(fields[3], 80);
        String connection = fromPart(fields[4], 256);
        String idp = fromPart(fields[5], 2048);
        String acs = fromPart(fields[6], 2048);
        if (sp == null || request == null || relay == null || connection == null || idp == null || acs == null
                || sp.isEmpty() || request.length() != 41 || request.charAt(0) != '_'
                || relay.length() != 22 || connection.isEmpty() || idp.isEmpty() || acs.isEmpty()) return null;
        try {
            String issuedText = current ? fromPart(fields[7], 64) : fields[7];
            String expiryText = current ? fromPart(fields[8], 64) : fields[8];
            if (issuedText == null || expiryText == null) return null;
            Instant issued = Instant.parse(issuedText);
            Instant expiry = Instant.parse(expiryText);
            if (!issued.isBefore(expiry)) return null;
            SamlAuthenticationRequestOptions options = SamlAuthenticationRequestOptions.builder().build();
            if (!old) {
                if (!(fields[9].equals("0") || fields[9].equals("1"))
                        || !(fields[10].equals("0") || fields[10].equals("1"))) return null;
                String contexts = fields[11].equals("-") ? null : fromPart(fields[11], 4096);
                String encodedData = fields[12].equals("-") ? null : fromPart(fields[12], 513);
                String applicationData = encodedData == null || !encodedData.startsWith("x")
                        ? null : encodedData.substring(1);
                if ((contexts == null && !fields[11].equals("-"))
                        || (applicationData == null && !fields[12].equals("-"))) return null;
                options = SamlAuthenticationRequestOptions.builder()
                        .forceAuthn(fields[9].equals("1")).passive(fields[10].equals("1"))
                        .requestedAuthnContextClassRefs(contexts == null ? List.of()
                                : List.of(contexts.split("\n", -1)))
                        .applicationData(applicationData).build();
            }
            return new PendingSamlAuthentication(sp, request, relay, connection, idp, acs,
                    issued, expiry, options);
        } catch (DateTimeParseException | IllegalArgumentException exception) { return null; }
    }

    private static @NonNull String part(@NonNull String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static @Nullable String fromPart(@NonNull String value, int maximumBytes) {
        if (value.isEmpty() || value.length() > 4 * ((maximumBytes + 2) / 3)) return null;
        byte[] bytes;
        try { bytes = Base64Url.decode(value); }
        catch (EncodingException exception) { return null; }
        if (bytes.length > maximumBytes) return null;
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        try { return decoder.decode(ByteBuffer.wrap(bytes)).toString(); }
        catch (java.nio.charset.CharacterCodingException exception) { return null; }
    }
}
