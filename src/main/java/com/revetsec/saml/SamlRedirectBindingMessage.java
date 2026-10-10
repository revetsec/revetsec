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

import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.EcdsaSignatures;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * A raw-octet HTTP-Redirect binding message. It retains the exact received signing input and
 * does not release identity until the SP verifies the signature and SAML fields.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlRedirectBindingMessage {
    private final @NonNull Kind kind;
    private final byte @NonNull [] xml;
    private final @Nullable String relayState;
    private final @NonNull String signedQuery;
    private final @NonNull String algorithm;
    private final byte @NonNull [] signature;

    private SamlRedirectBindingMessage(@NonNull Kind kind, byte @NonNull [] xml,
            @Nullable String relayState, @NonNull String signedQuery,
            @NonNull String algorithm, byte @NonNull [] signature) {
        this.kind = kind;
        this.xml = xml.clone();
        this.relayState = relayState;
        this.signedQuery = signedQuery;
        this.algorithm = algorithm;
        this.signature = signature.clone();
    }

    /**
     * Parses one raw query string before servlet or framework parameter decoding.
     *
     * @param rawQuery exact ASCII query octets represented as a String, without the leading ?
     * @return parsed message or fixed rejection
     * @since 1.0.0
     */
    public static @NonNull SamlRedirectBindingParseResult fromRawQueryResult(@NonNull String rawQuery) {
        Objects.requireNonNull(rawQuery);
        if (rawQuery.isEmpty() || rawQuery.length() > 65536) return SamlRedirectBindingParseResult.Rejected.INSTANCE;
        Map<String, String> fields = new HashMap<>();
        for (String field : rawQuery.split("&", -1)) {
            int equals = field.indexOf('=');
            if (equals < 1 || equals == field.length() - 1) return SamlRedirectBindingParseResult.Rejected.INSTANCE;
            String name = field.substring(0, equals);
            if (!List.of("SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature").contains(name)
                    || fields.putIfAbsent(name, field.substring(equals + 1)) != null)
                return SamlRedirectBindingParseResult.Rejected.INSTANCE;
        }
        boolean request = fields.containsKey("SAMLRequest");
        if (request == fields.containsKey("SAMLResponse") || !fields.containsKey("SigAlg")
                || !fields.containsKey("Signature")) return SamlRedirectBindingParseResult.Rejected.INSTANCE;
        String messageName = request ? "SAMLRequest" : "SAMLResponse";
        byte[] message = percent(fields.get(messageName), 32768);
        byte[] alg = percent(fields.get("SigAlg"), 256);
        byte[] signed = percent(fields.get("Signature"), 8192);
        byte[] relayBytes = fields.containsKey("RelayState") ? percent(fields.get("RelayState"), 80) : null;
        if (message == null || alg == null || signed == null
                || (fields.containsKey("RelayState") && relayBytes == null))
            return SamlRedirectBindingParseResult.Rejected.INSTANCE;
        String algorithm = ascii(alg);
        String encoded = ascii(message);
        String signatureEncoded = ascii(signed);
        String relay = relayBytes == null ? null : ascii(relayBytes);
        if (algorithm == null || encoded == null || signatureEncoded == null
                || (relayBytes != null && relay == null))
            return SamlRedirectBindingParseResult.Rejected.INSTANCE;
        byte[] compressed;
        byte[] signature;
        try {
            compressed = Base64.getDecoder().decode(encoded);
            signature = Base64.getDecoder().decode(signatureEncoded);
        } catch (IllegalArgumentException exception) { return SamlRedirectBindingParseResult.Rejected.INSTANCE; }
        if (compressed.length > 24576 || signature.length < 64 || signature.length > 1024)
            return SamlRedirectBindingParseResult.Rejected.INSTANCE;
        byte[] xml = inflate(compressed);
        if (xml == null) return SamlRedirectBindingParseResult.Rejected.INSTANCE;
        String signingInput = messageName + "=" + fields.get(messageName)
                + (relay == null ? "" : "&RelayState=" + fields.get("RelayState"))
                + "&SigAlg=" + fields.get("SigAlg");
        return new SamlRedirectBindingParseResult.Parsed(new SamlRedirectBindingMessage(
                request ? Kind.REQUEST : Kind.RESPONSE, xml, relay, signingInput, algorithm, signature));
    }

    /**
     * Reports which SAML protocol message field was present.
     *
     * @return message kind
     * @since 1.0.0
     */
    public @NonNull Kind getKind() { return kind; }
    /**
     * Returns the optional RelayState handle.
     *
     * @return optional handle
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getRelayState() { return Optional.ofNullable(relayState); }
    byte @NonNull [] xml() { return xml.clone(); }
    @Nullable String relayState() { return relayState; }

    boolean verify(@NonNull List<@NonNull PublicKey> keys) {
        return verify(keys, false);
    }

    boolean verify(@NonNull List<@NonNull PublicKey> keys, boolean allowSha1) {
        String jca = switch (algorithm) {
            case "http://www.w3.org/2000/09/xmldsig#rsa-sha1" -> allowSha1 ? "SHA1withRSA" : "";
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" -> "SHA256withRSA";
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384" -> "SHA384withRSA";
            case "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" -> "SHA512withRSA";
            case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256" -> "SHA256withECDSA";
            case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384" -> "SHA384withECDSA";
            case "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512" -> "SHA512withECDSA";
            default -> "";
        };
        if (jca.isEmpty()) return false;
        for (PublicKey key : keys) {
            try {
                byte[] signatureBytes = signature;
                if (jca.contains("ECDSA")) {
                    if (!(key instanceof ECPublicKey ec)) continue;
                    EcCurve curve = EcCurve.findByParameterSpec(ec.getParams()).orElse(null);
                    if (curve == null) continue;
                    signatureBytes = canonicalEcdsaSignature(signature, curve);
                    if (signatureBytes == null) continue;
                }
                Signature verifier = Signature.getInstance(jca);
                verifier.initVerify(key);
                verifier.update(signedQuery.getBytes(StandardCharsets.US_ASCII));
                if (verifier.verify(signatureBytes)) return true;
            } catch (GeneralSecurityException exception) {
                // Continue across configured rollover keys.
            }
        }
        return false;
    }

    private static byte @Nullable [] canonicalEcdsaSignature(byte @NonNull [] value,
            @NonNull EcCurve curve) {
        if (value.length == curve.getSignatureLength()) {
            if (EcdsaSignatures.findShapeFailure(curve, value).isPresent()) return null;
            return EcdsaSignatures.toDer(curve, value);
        }
        int position = 0;
        if (value.length < 8 || value[position++] != 0x30) return null;
        int length = value[position++] & 0xff;
        if (length == 0x81) {
            if (position >= value.length || (length = value[position++] & 0xff) < 128) return null;
        } else if (length >= 128) return null;
        if (position + length != value.length) return null;
        byte[] raw = new byte[curve.getSignatureLength()];
        for (int half = 0; half < 2; half++) {
            if (position + 2 > value.length || value[position++] != 0x02) return null;
            int integerLength = value[position++] & 0xff;
            if (integerLength < 1 || integerLength > curve.getCoordinateLength() + 1
                    || position + integerLength > value.length) return null;
            int start = position;
            if (value[start] == 0) {
                if (integerLength == 1 || (value[start + 1] & 0x80) == 0) return null;
                start++;
            } else if ((value[start] & 0x80) != 0) return null;
            int magnitudeLength = position + integerLength - start;
            if (magnitudeLength > curve.getCoordinateLength()) return null;
            System.arraycopy(value, start, raw,
                    half * curve.getCoordinateLength() + curve.getCoordinateLength() - magnitudeLength,
                    magnitudeLength);
            position += integerLength;
        }
        if (position != value.length || EcdsaSignatures.findShapeFailure(curve, raw).isPresent())
            return null;
        byte[] canonical = EcdsaSignatures.toDer(curve, raw);
        return Arrays.equals(canonical, value) ? canonical : null;
    }

    private static byte @Nullable [] inflate(byte @NonNull [] compressed) {
        Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(compressed);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            while (!inflater.finished()) {
                if (output.size() >= 131072) return null;
                int count = inflater.inflate(chunk, 0, Math.min(chunk.length, 131072 - output.size()));
                if (count == 0) return null;
                output.write(chunk, 0, count);
            }
            return inflater.getRemaining() == 0 ? output.toByteArray() : null;
        } catch (DataFormatException exception) { return null; }
        finally { inflater.end(); }
    }

    private static byte @Nullable [] percent(@Nullable String input, int maximum) {
        if (input == null || input.length() > maximum * 3) return null;
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        for (int i = 0; i < input.length(); i++) {
            char current = input.charAt(i);
            if (current == '%') {
                if (i + 2 >= input.length()) return null;
                int high = asciiHex(input.charAt(++i));
                int low = asciiHex(input.charAt(++i));
                if (high < 0 || low < 0) return null;
                bytes.write((high << 4) | low);
            } else if (current >= 33 && current <= 126) bytes.write(current);
            else return null;
            if (bytes.size() > maximum) return null;
        }
        return bytes.toByteArray();
    }

    private static int asciiHex(char value) {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        return -1;
    }

    private static @Nullable String ascii(byte @NonNull [] value) {
        for (byte octet : value) if (octet < 33 || octet > 126) return null;
        return new String(value, StandardCharsets.US_ASCII);
    }

    /**
     * HTTP-Redirect message field kind.
     *
     * @since 1.0.0
     */
    @Immutable
    public enum Kind {
        /** SAMLRequest. */ REQUEST,
        /** SAMLResponse. */ RESPONSE
    }

    /**
     * Redacts query and XML contents.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlRedirectBindingMessage{<redacted>}"; }
}
