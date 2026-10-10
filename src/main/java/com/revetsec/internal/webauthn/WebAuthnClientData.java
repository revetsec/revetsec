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

package com.revetsec.internal.webauthn;

import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Checks the browser-bound fields of one WebAuthn {@code clientDataJSON}. This does not verify an authenticator
 * signature, consume a challenge, or authorize a ceremony. The exact caller-selected origins are trusted only after
 * constructor validation; request headers never choose an origin.
 */
@Immutable
final class WebAuthnClientData {
    static final int DEFAULT_MAXIMUM_BYTES = 8_192;
    private static final int MAXIMUM_BYTES = 16_384;
    private static final int CHALLENGE_BYTES = 32;
    private static final int MAXIMUM_ORIGINS = 8;

    private final @NonNull Set<@NonNull String> allowedOrigins;
    private final @NonNull JsonLimits limits;
    private final byte @NonNull [] relyingPartyIdHash;

    WebAuthnClientData(@NonNull String relyingPartyId, @NonNull Set<@NonNull String> allowedOrigins,
                       int maximumBytes) {
        requireNonNull(relyingPartyId);
        requireNonNull(allowedOrigins);
        if (!isCanonicalRelyingPartyId(relyingPartyId))
            throw new IllegalArgumentException("Invalid WebAuthn relying-party ID.");
        if (allowedOrigins.isEmpty() || allowedOrigins.size() > MAXIMUM_ORIGINS)
            throw new IllegalArgumentException("Invalid WebAuthn origin count.");
        for (String origin : allowedOrigins) {
            requireNonNull(origin);
            if (!isExactHttpsOrigin(origin, relyingPartyId))
                throw new IllegalArgumentException("Invalid WebAuthn allowed origin.");
        }
        if (maximumBytes < 1 || maximumBytes > MAXIMUM_BYTES)
            throw new IllegalArgumentException("Invalid WebAuthn client-data limit.");
        this.allowedOrigins = Set.copyOf(allowedOrigins);
        this.limits = JsonLimits.webauthnClientData(maximumBytes);
        try {
            this.relyingPartyIdHash = MessageDigest.getInstance("SHA-256")
                    .digest(relyingPartyId.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable.", exception);
        }
    }

    byte @NonNull [] relyingPartyIdHash() {
        return this.relyingPartyIdHash.clone();
    }

    /** Verifies the exact browser-bound fields, allowing bounded future fields in any order. */
    void verify(byte @NonNull [] clientDataJson, @NonNull Ceremony ceremony,
                byte @NonNull [] expectedChallenge) throws WebAuthnClientDataException {
        requireNonNull(clientDataJson);
        requireNonNull(ceremony);
        requireNonNull(expectedChallenge);
        if (expectedChallenge.length != CHALLENGE_BYTES)
            throw new IllegalArgumentException("WebAuthn challenge must be 32 bytes.");

        JsonValue parsed;
        try {
            parsed = JsonCodec.parse(clientDataJson, this.limits);
        } catch (JsonParseException exception) {
            throw new WebAuthnClientDataException();
        }
        if (!(parsed instanceof JsonObject object))
            throw new WebAuthnClientDataException();
        Map<String, JsonValue> members = object.getMembers();
        if (!(members.get("type") instanceof JsonString type) || !ceremony.wireType.equals(type.getValue()))
            throw new WebAuthnClientDataException();
        if (!(members.get("origin") instanceof JsonString origin) || !this.allowedOrigins.contains(origin.getValue()))
            throw new WebAuthnClientDataException();
        if (members.containsKey("topOrigin"))
            throw new WebAuthnClientDataException();
        JsonValue crossOrigin = members.get("crossOrigin");
        if (crossOrigin != null && (!(crossOrigin instanceof JsonBoolean bool) || bool.getValue()))
            throw new WebAuthnClientDataException();
        if (!(members.get("challenge") instanceof JsonString challenge) || challenge.getValue().length() != 43)
            throw new WebAuthnClientDataException();
        byte[] challengeBytes;
        try {
            challengeBytes = Base64Url.decode(challenge.getValue());
        } catch (EncodingException exception) {
            throw new WebAuthnClientDataException();
        }
        try {
            if (challengeBytes.length != CHALLENGE_BYTES
                    || !MessageDigest.isEqual(challengeBytes, expectedChallenge))
                throw new WebAuthnClientDataException();
        } finally {
            Arrays.fill(challengeBytes, (byte) 0);
        }
    }

    private static boolean isExactHttpsOrigin(@NonNull String origin, @NonNull String relyingPartyId) {
        try {
            URI uri = new URI(origin);
            if (!"https".equals(uri.getScheme()) || !relyingPartyId.equals(uri.getHost())
                    || uri.getRawUserInfo() != null || uri.getRawPath() == null || !uri.getRawPath().isEmpty()
                    || uri.getRawQuery() != null || uri.getRawFragment() != null)
                return false;
            int port = uri.getPort();
            if (port == -1)
                return origin.equals("https://" + relyingPartyId);
            return port >= 1 && port <= 65_535
                    && origin.equals("https://" + relyingPartyId + ":" + port);
        } catch (URISyntaxException exception) {
            return false;
        }
    }

    private static boolean isCanonicalRelyingPartyId(@NonNull String id) {
        if (id.length() > 253 || id.indexOf('.') < 1 || id.endsWith("."))
            return false;
        String[] labels = id.split("\\.", -1);
        boolean ipv4 = labels.length == 4;
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63 || label.charAt(0) == '-'
                    || label.charAt(label.length() - 1) == '-')
                return false;
            boolean digits = true;
            int value = 0;
            for (int index = 0; index < label.length(); ++index) {
                char character = label.charAt(index);
                if (character >= '0' && character <= '9') {
                    if (value <= 255) value = value * 10 + (character - '0');
                } else {
                    digits = false;
                    if (!(character >= 'a' && character <= 'z') && character != '-')
                        return false;
                }
            }
            ipv4 &= digits && value <= 255;
        }
        return !ipv4;
    }

    enum Ceremony {
        REGISTRATION("webauthn.create"),
        AUTHENTICATION("webauthn.get");

        private final @NonNull String wireType;

        Ceremony(@NonNull String wireType) {
            this.wireType = wireType;
        }
    }
}
