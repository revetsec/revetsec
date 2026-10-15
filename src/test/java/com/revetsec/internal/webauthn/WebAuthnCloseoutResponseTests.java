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

final class WebAuthnCloseoutResponseTests {
    private static final String RP_ID = "login.example.com";
    private static final byte[] RP_HASH = rpHash();
    private static final byte[] CHALLENGE = new byte[32];
    private static final byte[] CREDENTIAL_ID = {1, 2, 3};
    private static final byte[] USER_HANDLE = {4, 5, 6};
    private static final byte[] ES_X = HexFormat.of().parseHex(
            "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d");
    private static final byte[] ES_Y = HexFormat.of().parseHex(
            "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c");

    @Test void customDecodedLimitsRejectEachIndependentLowerAndUpperBound() {
        int[][] limits = {{0,8192,16384,8192},{262145,8192,16384,8192},{65536,0,16384,8192},
                {65536,16385,16384,8192},{65536,8192,0,8192},{65536,8192,65537,8192},
                {65536,8192,16384,36},{65536,8192,16384,32769}};
        for (int[] limit : limits) assertThrows(IllegalArgumentException.class, () -> new WebAuthnResponseJson(
                clientPolicy(),limit[0],limit[1],limit[2],limit[3]));
    }

    @Test void rootIdentityAndAttachmentTypeBranchesRejectBeforeSignatureUse() throws Exception {
        String valid = assertionJson(CREDENTIAL_ID, assertionData(), new byte[] {1}, USER_HANDLE);
        assertArrayEquals(CREDENTIAL_ID, decoder().parseAssertion(json(valid), CHALLENGE).credentialId());
        for (String attachment : java.util.List.of("null", "\"platform\"", "\"" + "x".repeat(64) + "\""))
            assertArrayEquals(CREDENTIAL_ID, decoder().parseAssertion(json(valid.substring(0,valid.length()-1)
                    + ",\"authenticatorAttachment\":"+attachment+"}"),CHALLENGE).credentialId());
        for (String bad : java.util.List.of("[]", valid.replace("\"type\":\"public-key\"", "\"type\":true"),
                valid.replace("\"rawId\":\"AQID\"", "\"rawId\":true"),
                valid.replace("\"id\":\"AQID\"", "\"id\":true"),
                valid.replace("\"rawId\":\"AQID\"", "\"rawId\":\"\""),
                valid.replace("\"rawId\":\"AQID\"", "\"rawId\":\""+"A".repeat(1365)+"\""),
                valid.substring(0,valid.length()-1)+",\"authenticatorAttachment\":true}",
                valid.substring(0,valid.length()-1)+",\"authenticatorAttachment\":\""+"x".repeat(65)+"\"}"))
            rejectAssertion(bad);
    }

    @Test void registrationAlgorithmAndTransportFacetsHaveExplicitTypeAndLengthRejections() throws Exception {
        byte[] auth=registrationData(CREDENTIAL_ID);
        String valid=registrationJson(CREDENTIAL_ID,auth,attestation(auth));
        assertArrayEquals(CREDENTIAL_ID, decoder().parseRegistration(json(valid), CHALLENGE).credentialId());
        for (String algorithm : java.util.List.of("true", "0", "-257", "1.5", "2147483648"))
            rejectRegistration(valid.replace("\"publicKeyAlgorithm\":-7", "\"publicKeyAlgorithm\":"+algorithm));
        for (String transports : java.util.List.of("true", "[true]", "[\""+"x".repeat(65)+"\"]",
                "["+String.join(",",java.util.Collections.nCopies(17,"\"usb\""))+"]"))
            rejectRegistration(valid.replace("[\"internal\"]",transports));
        assertArrayEquals(CREDENTIAL_ID,decoder().parseRegistration(json(valid.replace("[\"internal\"]","[]")),CHALLENGE).credentialId());
        String optional=valid.replace("\"transports\":[\"internal\"]", "\"transports\":[\"internal\"],\"publicKey\":\"AQ\"");
        assertArrayEquals(CREDENTIAL_ID,decoder().parseRegistration(json(optional),CHALLENGE).credentialId());
        rejectRegistration(optional.replace("\"publicKey\":\"AQ\"","\"publicKey\":true"));
    }

    @Test void registrationExtensionShapesAndMalformedAuthenticatorCarrierStayRejected() {
        byte[] auth=registrationData(CREDENTIAL_ID);
        String valid=registrationJson(CREDENTIAL_ID,auth,attestation(auth));
        rejectRegistration(valid.replace("\"rk\":true","\"rk\":\"true\""));
        rejectRegistration(valid.replace("\"credProps\":{\"rk\":true}","\"credProps\":true"));
        rejectRegistration(valid.replace(Base64Url.encode(attestation(auth)),Base64Url.encode(new byte[] {1})));
        byte[] invalidAuth=auth.clone(); invalidAuth[32]=0x41;
        rejectRegistration(registrationJson(CREDENTIAL_ID,invalidAuth,attestation(invalidAuth)));
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
