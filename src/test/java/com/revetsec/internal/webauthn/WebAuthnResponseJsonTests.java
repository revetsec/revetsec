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
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class WebAuthnResponseJsonTests {
    private static final String RP_ID = "login.example.com";
    private static final byte[] RP_HASH = rpHash();
    private static final byte[] CHALLENGE = new byte[32];
    private static final byte[] CREDENTIAL_ID = {1, 2, 3};
    private static final byte[] USER_HANDLE = {4, 5, 6};
    private static final byte[] ES_X = HexFormat.of().parseHex(
            "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d");
    private static final byte[] ES_Y = HexFormat.of().parseHex(
            "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c");

    @Test
    void acceptsRegistrationAndCrossChecksRedundantAuthenticatorAndCredentialFields() throws Exception {
        byte[] auth = registrationData(CREDENTIAL_ID);
        String body = registrationJson(CREDENTIAL_ID, auth, attestation(auth));
        var parsed = decoder().parseRegistration(json(body), CHALLENGE);
        assertArrayEquals(CREDENTIAL_ID, parsed.credentialId());
        assertEquals(-7, parsed.algorithm());
        assertEquals(0, parsed.counter());
        assertEquals("WebAuthnAuthenticatorData.Registration{<unverified>}", parsed.toString());

        byte[] wrongAuth = auth.clone(); wrongAuth[36] = 1;
        rejectRegistration(registrationJson(CREDENTIAL_ID, wrongAuth, attestation(auth)));
        byte[] wrongId = {9};
        rejectRegistration(registrationJson(wrongId, auth, attestation(auth)));
        rejectRegistration(body.replace("\"publicKeyAlgorithm\":-7", "\"publicKeyAlgorithm\":-8"));
        rejectRegistration(body.replace("\"id\":\"" + Base64Url.encode(CREDENTIAL_ID) + "\"",
                "\"id\":\"" + Base64Url.encode(wrongId) + "\""));
    }

    @Test
    void acceptsAssertionAsUnverifiedInputAndDefensivelyCopiesSignedBytes() throws Exception {
        byte[] auth = assertionData();
        byte[] signature = {11, 12, 13};
        var parsed = decoder().parseAssertion(json(assertionJson(CREDENTIAL_ID, auth, signature, USER_HANDLE)),
                CHALLENGE);
        assertArrayEquals(CREDENTIAL_ID, parsed.credentialId());
        assertArrayEquals(USER_HANDLE, parsed.userHandle());
        assertArrayEquals(auth, parsed.authenticatorData());
        assertArrayEquals(signature, parsed.signature());
        assertEquals(7, parsed.flags().counter());
        parsed.credentialId()[0] = 99;
        parsed.signature()[0] = 99;
        assertArrayEquals(CREDENTIAL_ID, parsed.credentialId());
        assertArrayEquals(signature, parsed.signature());
        assertEquals("WebAuthnResponseJson.Assertion{<unverified>}", parsed.toString());
    }

    @Test
    void rejectsMissingFalseAndUnexpectedResidentKeyExtension() {
        byte[] auth = registrationData(CREDENTIAL_ID);
        String body = registrationJson(CREDENTIAL_ID, auth, attestation(auth));
        rejectRegistration(body.replace("\"rk\":true", "\"rk\":false"));
        rejectRegistration(body.replace("\"credProps\":{\"rk\":true}", ""));
        rejectRegistration(body.replace("\"rk\":true", "\"rk\":true,\"other\":true"));
        rejectRegistration(body.replace("\"credProps\":{\"rk\":true}",
                "\"credProps\":{\"rk\":true},\"other\":{}"));
    }

    @Test
    void rejectsContextAndMalformedJsonBeforeAnyInputCanBecomeProof() {
        String body = assertionJson(CREDENTIAL_ID, assertionData(), new byte[] {1}, USER_HANDLE);
        rejectAssertion(replaceClientData(body, "webauthn.get", "webauthn.create"));
        rejectAssertion(replaceClientData(body, "https://login.example.com", "https://evil.example.com"));
        rejectAssertion(body.replace("\"clientExtensionResults\":{}", "\"clientExtensionResults\":{\"prf\":{}}"));
        rejectAssertion(body.replace("\"type\":\"public-key\"", "\"type\":\"password\""));
        rejectAssertion(body.replace("\"rawId\":\"" + Base64Url.encode(CREDENTIAL_ID) + "\"",
                "\"rawId\":\"" + Base64Url.encode(CREDENTIAL_ID) + "=\""));
        rejectAssertion(body.substring(0, body.length() - 1)
                + ",\"\\u0074ype\":\"public-key\"}");
        rejectAssertion(body + "{}");
        byte[] invalidUtf8 = json(body);
        invalidUtf8[invalidUtf8.length - 2] = (byte) 0xc0;
        assertThrows(WebAuthnResponseException.class,
                () -> decoder().parseAssertion(invalidUtf8, CHALLENGE));
        assertThrows(WebAuthnResponseException.class,
                () -> decoder().parseAssertion(new byte[65_537], CHALLENGE));
    }

    @Test
    void rejectsMissingOrOversizedAssertionComponents() {
        String body = assertionJson(CREDENTIAL_ID, assertionData(), new byte[] {1}, USER_HANDLE);
        rejectAssertion(body.replace("\"signature\":\"AQ\"", "\"signature\":\"\""));
        rejectAssertion(body.replace("\"userHandle\":\"BAUG\"", "\"userHandle\":null"));
        rejectAssertion(body.replace("\"userHandle\":\"BAUG\"", "\"userHandle\":\""
                + Base64Url.encode(new byte[65]) + "\""));
        rejectAssertion(body.replace("\"signature\":\"AQ\"", "\"signature\":\""
                + Base64Url.encode(new byte[513]) + "\""));
        byte[] wrongRp = assertionData(); wrongRp[0] ^= 1;
        rejectAssertion(assertionJson(CREDENTIAL_ID, wrongRp, new byte[] {1}, USER_HANDLE));
    }

    @Test
    void rejectsBadTrustedLimitsAndUsesFixedRedactedFailure() {
        assertThrows(IllegalArgumentException.class,
                () -> new WebAuthnResponseJson(clientPolicy(), 256 * 1_024 + 1));
        String body = assertionJson(CREDENTIAL_ID, assertionData(), new byte[] {1}, USER_HANDLE);
        WebAuthnResponseException failure = assertThrows(WebAuthnResponseException.class,
                () -> decoder().parseAssertion(json(replaceClientData(body, "webauthn.get", "secret.invalid")),
                        CHALLENGE));
        assertEquals("WebAuthn response rejected.", failure.getMessage());
        assertNull(failure.getCause());
        assertEquals(0, failure.getStackTrace().length);
    }

    private static @NonNull WebAuthnResponseJson decoder() {
        return new WebAuthnResponseJson(clientPolicy(), WebAuthnResponseJson.DEFAULT_MAXIMUM_BODY_BYTES);
    }

    private static @NonNull WebAuthnClientData clientPolicy() {
        return new WebAuthnClientData(RP_ID, Set.of("https://" + RP_ID),
                WebAuthnClientData.DEFAULT_MAXIMUM_BYTES);
    }

    private static void rejectRegistration(@NonNull String body) {
        assertThrows(WebAuthnResponseException.class, () -> decoder().parseRegistration(json(body), CHALLENGE));
    }

    private static void rejectAssertion(@NonNull String body) {
        assertThrows(WebAuthnResponseException.class, () -> decoder().parseAssertion(json(body), CHALLENGE));
    }

    private static @NonNull String registrationJson(byte @NonNull [] id, byte @NonNull [] auth,
            byte @NonNull [] attestation) {
        String encodedId = Base64Url.encode(id);
        return "{\"id\":\"" + encodedId + "\",\"rawId\":\"" + encodedId
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.create")) + "\",\"authenticatorData\":\""
                + Base64Url.encode(auth) + "\",\"attestationObject\":\"" + Base64Url.encode(attestation)
                + "\",\"publicKeyAlgorithm\":-7,\"transports\":[\"internal\"]},"
                + "\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}";
    }

    private static @NonNull String assertionJson(byte @NonNull [] id, byte @NonNull [] auth,
            byte @NonNull [] signature, byte @NonNull [] handle) {
        String encodedId = Base64Url.encode(id);
        return "{\"id\":\"" + encodedId + "\",\"rawId\":\"" + encodedId
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.get")) + "\",\"authenticatorData\":\""
                + Base64Url.encode(auth) + "\",\"signature\":\"" + Base64Url.encode(signature)
                + "\",\"userHandle\":\"" + Base64Url.encode(handle) + "\"},"
                + "\"clientExtensionResults\":{}}";
    }

    private static byte @NonNull [] clientJson(@NonNull String type) {
        return json("{\"type\":\"" + type + "\",\"challenge\":\"" + Base64Url.encode(CHALLENGE)
                + "\",\"origin\":\"https://" + RP_ID + "\",\"crossOrigin\":false}");
    }

    private static @NonNull String replaceClientData(@NonNull String body, @NonNull String oldText,
            @NonNull String newText) {
        byte[] original = clientJson("webauthn.get");
        String altered = new String(original, StandardCharsets.UTF_8).replace(oldText, newText);
        return body.replace(Base64Url.encode(original), Base64Url.encode(json(altered)));
    }

    private static byte @NonNull [] registrationData(byte @NonNull [] id) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(RP_HASH); out.write(0x45); out.writeBytes(new byte[4]);
        out.writeBytes(new byte[16]); out.write(id.length >>> 8); out.write(id.length);
        out.writeBytes(id); out.writeBytes(esKey());
        return out.toByteArray();
    }

    private static byte @NonNull [] assertionData() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(RP_HASH); out.write(0x05);
        out.write(0); out.write(0); out.write(0); out.write(7);
        return out.toByteArray();
    }

    private static byte @NonNull [] esKey() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa5); out.write(1); out.write(2); out.write(3); out.write(0x26);
        out.write(0x20); out.write(1); out.write(0x21); bytes(out, ES_X);
        out.write(0x22); bytes(out, ES_Y);
        return out.toByteArray();
    }

    private static byte @NonNull [] attestation(byte @NonNull [] auth) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa3); text(out, "fmt"); text(out, "none");
        text(out, "authData"); bytes(out, auth);
        text(out, "attStmt"); out.write(0xa0);
        return out.toByteArray();
    }

    private static void text(@NonNull ByteArrayOutputStream out, @NonNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        out.write(0x60 | bytes.length); out.writeBytes(bytes);
    }

    private static void bytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] value) {
        if (value.length < 24) out.write(0x40 | value.length);
        else if (value.length < 256) { out.write(0x58); out.write(value.length); }
        else { out.write(0x59); out.write(value.length >>> 8); out.write(value.length); }
        out.writeBytes(value);
    }

    private static byte @NonNull [] rpHash() {
        try {
            return MessageDigest.getInstance("SHA-256").digest(RP_ID.getBytes(StandardCharsets.US_ASCII));
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static byte @NonNull [] json(@NonNull String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
