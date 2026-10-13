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
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

final class PendingSamlAuthenticationCodecTests {
    private static final @NonNull Instant ISSUED = Instant.parse("2026-10-09T00:00:00Z");
    private static final @NonNull Instant EXPIRES = Instant.parse("2026-10-09T00:05:00Z");

    @Test void roundTripKeepsRequestPolicyAndOlderFormatsReadable() {
        PendingSamlAuthentication pending = pending();
        String encoded = PendingSamlAuthenticationCodec.encode(pending);
        PendingSamlAuthentication decoded = requireNonNull(PendingSamlAuthenticationCodec.decode(encoded));
        assertEquals(pending.requestId(), decoded.requestId());
        assertEquals(pending.relayState(), decoded.relayState());
        assertEquals(ISSUED, decoded.issuedAt());
        assertEquals(EXPIRES, decoded.expiresAt());
        assertEquals(true, decoded.options().isForceAuthn());
        assertEquals(false, decoded.options().isPassive());
        assertEquals(List.of("urn:example:loa2"),
                decoded.options().getRequestedAuthnContextClassRefs());
        assertEquals("return=/records", decoded.options().getApplicationData().orElseThrow());

        String[] parts = encoded.split("\\.", -1);
        String legacy = "1." + String.join(".", List.of(parts).subList(1, 7))
                + '.' + ISSUED + '.' + EXPIRES;
        PendingSamlAuthentication old = requireNonNull(PendingSamlAuthenticationCodec.decode(legacy));
        assertEquals(pending.requestId(), old.requestId());
        assertEquals(false, old.options().isForceAuthn());
        String previous = with(parts, 0, "2");
        previous = with(previous.split("\\.", -1), 7, ISSUED.toString());
        previous = with(previous.split("\\.", -1), 8, EXPIRES.toString());
        assertEquals(pending.requestId(), requireNonNull(PendingSamlAuthenticationCodec.decode(previous)).requestId());
    }

    @Test void malformedSealedPayloadFieldsNeverBecomePendingAuthentication() {
        String encoded = PendingSamlAuthenticationCodec.encode(pending());
        String[] parts = encoded.split("\\.", -1);
        Map<String, String> invalid = Map.ofEntries(
                Map.entry("empty", ""),
                Map.entry("oversized frame", "x".repeat(8193)),
                Map.entry("unknown version", with(parts, 0, "4")),
                Map.entry("missing field", encoded.substring(0, encoded.lastIndexOf('.'))),
                Map.entry("invalid Base64", with(parts, 1, "!")),
                Map.entry("malformed UTF-8", with(parts, 1, "_w")),
                Map.entry("empty SP", with(parts, 1, "")),
                Map.entry("oversized SP", with(parts, 1, b64("x".repeat(2049)))),
                Map.entry("wrong request length", with(parts, 2, b64("_short"))),
                Map.entry("wrong request prefix", with(parts, 2, b64("x".repeat(41)))),
                Map.entry("wrong relay length", with(parts, 3, b64("short"))),
                Map.entry("empty connection", with(parts, 4, "")),
                Map.entry("empty IdP", with(parts, 5, "")),
                Map.entry("empty ACS", with(parts, 6, "")),
                Map.entry("invalid issue instant", with(parts, 7, b64("not-a-time"))),
                Map.entry("non-increasing expiry", with(parts, 8, parts[7])),
                Map.entry("invalid ForceAuthn flag", with(parts, 9, "2")),
                Map.entry("invalid IsPassive flag", with(parts, 10, "2")),
                Map.entry("invalid context encoding", with(parts, 11, "!")),
                Map.entry("missing application marker", with(parts, 12, b64("return=/records"))));
        for (Map.Entry<String, String> caseUnderTest : invalid.entrySet())
            assertNull(PendingSamlAuthenticationCodec.decode(caseUnderTest.getValue()),
                    caseUnderTest.getKey());
    }

    @Test void exactMaximumSealedEntityIdIsDecodedWithoutTruncation() {
        String[] parts = PendingSamlAuthenticationCodec.encode(pending()).split("\\.", -1);
        String maximum = "x".repeat(2048);
        String encoded = with(parts, 1, b64(maximum));
        PendingSamlAuthentication decoded = requireNonNull(PendingSamlAuthenticationCodec.decode(encoded));
        assertEquals(maximum, decoded.spEntityId());
        assertNull(PendingSamlAuthenticationCodec.decode(with(parts, 1, b64(maximum + "x"))));
    }

    @Test void exactMaximumSealedFrameRemainsReadable() {
        String[] parts = PendingSamlAuthenticationCodec.encode(pending()).split("\\.", -1);
        parts[1] = b64("x".repeat(1888));
        parts[5] = b64("x".repeat(2048));
        parts[6] = b64("x".repeat(2048));
        String maximum = String.join(".", parts);
        assertEquals(8192, maximum.length());
        PendingSamlAuthentication decoded = requireNonNull(PendingSamlAuthenticationCodec.decode(maximum));
        assertEquals("x".repeat(1888), decoded.spEntityId());
        assertNull(PendingSamlAuthenticationCodec.decode(maximum + "x"));
    }

    @Test void exactMaximumApplicationDataUsesTheFullBase64FieldBudget() {
        String applicationData = "x".repeat(512);
        PendingSamlAuthentication original = new PendingSamlAuthentication("https://sp.example.test/saml",
                "_" + "r".repeat(40), "h".repeat(22), "tenant-one", "https://idp.example.test/saml",
                "https://sp.example.test/acs", ISSUED, EXPIRES,
                SamlAuthenticationRequestOptions.builder().applicationData(applicationData).build());
        String encoded = PendingSamlAuthenticationCodec.encode(original);
        assertEquals(684, encoded.split("\\.", -1)[12].length());
        PendingSamlAuthentication decoded = requireNonNull(PendingSamlAuthenticationCodec.decode(encoded));
        assertEquals(applicationData, decoded.options().getApplicationData().orElseThrow());
    }

    private static @NonNull PendingSamlAuthentication pending() {
        return new PendingSamlAuthentication("https://sp.example.test/saml", "_" + "r".repeat(40),
                "h".repeat(22), "tenant-one", "https://idp.example.test/saml",
                "https://sp.example.test/acs", ISSUED, EXPIRES,
                SamlAuthenticationRequestOptions.builder().forceAuthn(true)
                        .requestedAuthnContextClassRefs(List.of("urn:example:loa2"))
                        .applicationData("return=/records").build());
    }

    private static @NonNull String with(@NonNull String @NonNull [] parts, int index, @NonNull String value) {
        String[] copy = parts.clone();
        copy[index] = value;
        return String.join(".", copy);
    }

    private static @NonNull String b64(@NonNull String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                value.getBytes(StandardCharsets.UTF_8));
    }
}
