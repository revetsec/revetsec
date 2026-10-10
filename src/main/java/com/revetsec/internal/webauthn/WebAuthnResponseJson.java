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
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.security.MessageDigest;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Bounded decoder of the browser's {@code PublicKeyCredential.toJSON()} registration and assertion shapes. It checks
 * client data against a caller-held ceremony challenge, but returns no registration or authentication proof. Store
 * state, single-use challenge consumption and (for assertions) the stored-key signature check remain required.
 */
@Immutable
final class WebAuthnResponseJson {
    static final int DEFAULT_MAXIMUM_BODY_BYTES = 64 * 1_024;
    private static final int MAXIMUM_BODY_BYTES = 256 * 1_024;
    private static final int MAXIMUM_CREDENTIAL_ID_BYTES = 1_023;
    private static final int MAXIMUM_USER_HANDLE_BYTES = 64;
    private static final int MAXIMUM_SIGNATURE_BYTES = 512;

    private final @NonNull WebAuthnClientData clientData;
    private final byte @NonNull [] expectedRpIdHash;
    private final @NonNull JsonLimits limits;
    private final int maximumClientDataBytes;
    private final int maximumAttestationBytes;
    private final int maximumAuthenticatorDataBytes;

    WebAuthnResponseJson(@NonNull WebAuthnClientData clientData, int maximumBodyBytes) {
        this(clientData, maximumBodyBytes, WebAuthnClientData.DEFAULT_MAXIMUM_BYTES,
                WebAuthnNoneAttestation.MAXIMUM_INPUT_BYTES,
                WebAuthnNoneAttestation.MAXIMUM_AUTHENTICATOR_DATA_BYTES);
    }

    WebAuthnResponseJson(@NonNull WebAuthnClientData clientData, int maximumBodyBytes,
            int maximumClientDataBytes, int maximumAttestationBytes,
            int maximumAuthenticatorDataBytes) {
        this.clientData = requireNonNull(clientData);
        if (maximumBodyBytes < 1 || maximumBodyBytes > MAXIMUM_BODY_BYTES)
            throw new IllegalArgumentException("Invalid WebAuthn response-body limit.");
        if (maximumClientDataBytes < 1 || maximumClientDataBytes > 16_384
                || maximumAttestationBytes < 1 || maximumAttestationBytes > 64 * 1_024
                || maximumAuthenticatorDataBytes < WebAuthnNoneAttestation.MINIMUM_AUTHENTICATOR_DATA_BYTES
                || maximumAuthenticatorDataBytes > 32 * 1_024)
            throw new IllegalArgumentException("Invalid WebAuthn decoded-data limit.");
        this.expectedRpIdHash = clientData.relyingPartyIdHash();
        this.limits = JsonLimits.webauthnResponse(maximumBodyBytes);
        this.maximumClientDataBytes = maximumClientDataBytes;
        this.maximumAttestationBytes = maximumAttestationBytes;
        this.maximumAuthenticatorDataBytes = maximumAuthenticatorDataBytes;
    }

    WebAuthnAuthenticatorData.@NonNull Registration parseRegistration(byte @NonNull [] body,
            byte @NonNull [] expectedChallenge) throws WebAuthnResponseException {
        requireNonNull(expectedChallenge);
        JsonObject root = parseRoot(body);
        byte[] credentialId = credentialId(root);
        JsonObject response = object(root.getMembers().get("response"));
        requireRegistrationExtensions(root);
        byte[] clientJson = decoded(response.getMembers(), "clientDataJSON", 1, this.maximumClientDataBytes);
        try {
            this.clientData.verify(clientJson, WebAuthnClientData.Ceremony.REGISTRATION, expectedChallenge);
        } catch (WebAuthnClientDataException exception) {
            throw new WebAuthnResponseException();
        }
        byte[] attestationObject = decoded(response.getMembers(), "attestationObject", 1,
                this.maximumAttestationBytes);
        byte[] responseAuthData = decoded(response.getMembers(), "authenticatorData",
                WebAuthnNoneAttestation.MINIMUM_AUTHENTICATOR_DATA_BYTES,
                this.maximumAuthenticatorDataBytes);
        byte[] authenticatedData;
        try {
            authenticatedData = WebAuthnNoneAttestation.parse(attestationObject,
                    this.maximumAttestationBytes, this.maximumAuthenticatorDataBytes).getAuthenticatorData();
        } catch (WebAuthnCborException exception) {
            throw new WebAuthnResponseException();
        }
        if (!MessageDigest.isEqual(responseAuthData, authenticatedData))
            throw new WebAuthnResponseException();
        WebAuthnAuthenticatorData.Registration registration;
        try {
            registration = WebAuthnAuthenticatorData.parseRegistration(authenticatedData,
                    this.expectedRpIdHash, this.maximumAuthenticatorDataBytes);
        } catch (WebAuthnCborException exception) {
            throw new WebAuthnResponseException();
        }
        if (!MessageDigest.isEqual(credentialId, registration.credentialId())
                || algorithm(response.getMembers()) != registration.algorithm())
            throw new WebAuthnResponseException();
        requireTransports(response.getMembers());
        if (response.getMembers().containsKey("publicKey"))
            decoded(response.getMembers(), "publicKey", 1, 1_024);
        return registration;
    }

    @NonNull Assertion parseAssertion(byte @NonNull [] body, byte @NonNull [] expectedChallenge)
            throws WebAuthnResponseException {
        requireNonNull(expectedChallenge);
        JsonObject root = parseRoot(body);
        byte[] credentialId = credentialId(root);
        JsonObject response = object(root.getMembers().get("response"));
        requireEmptyExtensions(root);
        byte[] clientJson = decoded(response.getMembers(), "clientDataJSON", 1, this.maximumClientDataBytes);
        try {
            this.clientData.verify(clientJson, WebAuthnClientData.Ceremony.AUTHENTICATION, expectedChallenge);
        } catch (WebAuthnClientDataException exception) {
            throw new WebAuthnResponseException();
        }
        byte[] authenticatorData = decoded(response.getMembers(), "authenticatorData",
                WebAuthnNoneAttestation.MINIMUM_AUTHENTICATOR_DATA_BYTES,
                this.maximumAuthenticatorDataBytes);
        WebAuthnAuthenticatorData.Assertion flags;
        try {
            flags = WebAuthnAuthenticatorData.parseAssertion(authenticatorData,
                    this.expectedRpIdHash, this.maximumAuthenticatorDataBytes);
        } catch (WebAuthnCborException exception) {
            throw new WebAuthnResponseException();
        }
        byte[] signature = decoded(response.getMembers(), "signature", 1, MAXIMUM_SIGNATURE_BYTES);
        byte[] userHandle = decoded(response.getMembers(), "userHandle", 1, MAXIMUM_USER_HANDLE_BYTES);
        return new Assertion(credentialId, userHandle, authenticatorData, clientJson, signature, flags,
                this.expectedRpIdHash);
    }

    private @NonNull JsonObject parseRoot(byte @NonNull [] body) throws WebAuthnResponseException {
        requireNonNull(body);
        JsonValue parsed;
        try {
            parsed = JsonCodec.parse(body, this.limits);
        } catch (JsonParseException exception) {
            throw new WebAuthnResponseException();
        }
        JsonObject root = object(parsed);
        JsonValue type = root.getMembers().get("type");
        if (!(type instanceof JsonString string) || !"public-key".equals(string.getValue()))
            throw new WebAuthnResponseException();
        JsonValue attachment = root.getMembers().get("authenticatorAttachment");
        if (attachment != null && !(attachment instanceof JsonNull)
                && (!(attachment instanceof JsonString attachmentName) || attachmentName.getValue().length() > 64))
            throw new WebAuthnResponseException();
        return root;
    }

    private static byte @NonNull [] credentialId(@NonNull JsonObject root) throws WebAuthnResponseException {
        Map<String, JsonValue> members = root.getMembers();
        JsonValue rawId = members.get("rawId");
        JsonValue id = members.get("id");
        if (!(rawId instanceof JsonString) || !(id instanceof JsonString string))
            throw new WebAuthnResponseException();
        byte[] decoded = decoded(members, "rawId", 1, MAXIMUM_CREDENTIAL_ID_BYTES);
        if (!Base64Url.encode(decoded).equals(string.getValue()))
            throw new WebAuthnResponseException();
        return decoded;
    }

    private static @NonNull JsonObject object(@Nullable JsonValue value) throws WebAuthnResponseException {
        if (!(value instanceof JsonObject object))
            throw new WebAuthnResponseException();
        return object;
    }

    private static byte @NonNull [] decoded(@NonNull Map<@NonNull String, @NonNull JsonValue> members,
            @NonNull String name, int minimumBytes, int maximumBytes) throws WebAuthnResponseException {
        JsonValue value = members.get(name);
        if (!(value instanceof JsonString string)
                || string.getValue().length() > ((maximumBytes + 2) / 3) * 4)
            throw new WebAuthnResponseException();
        byte[] decoded;
        try {
            decoded = Base64Url.decode(string.getValue());
        } catch (EncodingException exception) {
            throw new WebAuthnResponseException();
        }
        if (decoded.length < minimumBytes || decoded.length > maximumBytes)
            throw new WebAuthnResponseException();
        return decoded;
    }

    private static int algorithm(@NonNull Map<@NonNull String, @NonNull JsonValue> response)
            throws WebAuthnResponseException {
        JsonValue value = response.get("publicKeyAlgorithm");
        if (!(value instanceof JsonNumber number))
            throw new WebAuthnResponseException();
        int algorithm;
        try {
            algorithm = number.getValue().intValueExact();
        } catch (ArithmeticException exception) {
            throw new WebAuthnResponseException();
        }
        if (algorithm != -7 && algorithm != -8 && algorithm != -257)
            throw new WebAuthnResponseException();
        return algorithm;
    }

    private static void requireTransports(@NonNull Map<@NonNull String, @NonNull JsonValue> response)
            throws WebAuthnResponseException {
        JsonValue transports = response.get("transports");
        if (!(transports instanceof JsonArray array) || array.getElements().size() > 16)
            throw new WebAuthnResponseException();
        for (JsonValue transport : array.getElements()) {
            if (!(transport instanceof JsonString string) || string.getValue().length() > 64)
                throw new WebAuthnResponseException();
        }
    }

    private static void requireRegistrationExtensions(@NonNull JsonObject root) throws WebAuthnResponseException {
        JsonObject extensions = object(root.getMembers().get("clientExtensionResults"));
        if (extensions.getMembers().size() != 1)
            throw new WebAuthnResponseException();
        JsonObject credentialProperties = object(extensions.getMembers().get("credProps"));
        if (credentialProperties.getMembers().size() != 1
                || !(credentialProperties.getMembers().get("rk") instanceof JsonBoolean resident)
                || !resident.getValue())
            throw new WebAuthnResponseException();
    }

    private static void requireEmptyExtensions(@NonNull JsonObject root) throws WebAuthnResponseException {
        if (!object(root.getMembers().get("clientExtensionResults")).getMembers().isEmpty())
            throw new WebAuthnResponseException();
    }

    /** Parsed assertion input, still subject to stored-key signature and authoritative-state checks. */
    @Immutable
    static final class Assertion {
        private final byte @NonNull [] credentialId;
        private final byte @NonNull [] userHandle;
        private final byte @NonNull [] authenticatorData;
        private final byte @NonNull [] clientDataJson;
        private final byte @NonNull [] signature;
        private final byte @NonNull [] expectedRpIdHash;
        private final WebAuthnAuthenticatorData.@NonNull Assertion flags;

        private Assertion(byte @NonNull [] credentialId, byte @NonNull [] userHandle,
                byte @NonNull [] authenticatorData, byte @NonNull [] clientDataJson,
                byte @NonNull [] signature, WebAuthnAuthenticatorData.@NonNull Assertion flags,
                byte @NonNull [] expectedRpIdHash) {
            this.credentialId = credentialId.clone();
            this.userHandle = userHandle.clone();
            this.authenticatorData = authenticatorData.clone();
            this.clientDataJson = clientDataJson.clone();
            this.signature = signature.clone();
            this.flags = flags;
            this.expectedRpIdHash = expectedRpIdHash.clone();
        }

        byte @NonNull [] credentialId() { return this.credentialId.clone(); }
        byte @NonNull [] userHandle() { return this.userHandle.clone(); }
        byte @NonNull [] authenticatorData() { return this.authenticatorData.clone(); }
        byte @NonNull [] clientDataJson() { return this.clientDataJson.clone(); }
        byte @NonNull [] signature() { return this.signature.clone(); }
        WebAuthnAuthenticatorData.@NonNull Assertion flags() { return this.flags; }

        WebAuthnAssertionSignature.@NonNull Check verifyWithStoredKey(byte @NonNull [] keyCbor)
                throws WebAuthnCborException {
            return WebAuthnAssertionSignature.verify(keyCbor, this.authenticatorData, this.clientDataJson,
                    this.signature, this.expectedRpIdHash);
        }

        @Override public @NonNull String toString() {
            return "WebAuthnResponseJson.Assertion{<unverified>}";
        }
    }
}
