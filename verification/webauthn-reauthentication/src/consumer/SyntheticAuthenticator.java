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
package consumer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;

/** A test-only Ed25519 authenticator. It never speaks CTAP or substitutes for physical-key evidence. */
final class SyntheticAuthenticator {
    private static final String RP_ID = "passkeys.example.test";
    private static final String ORIGIN = "https://passkeys.example.test:9443";
    private static final byte [] CREDENTIAL_ID = new byte[] {11, 22, 33, 44};
    private final KeyPair keyPair;
    private final byte [] userHandle;

    SyntheticAuthenticator(byte [] userHandle) throws Exception {
        this.userHandle = userHandle.clone();
        this.keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    String credentialId() { return encode(CREDENTIAL_ID); }

    byte [] registration(String challenge) {
        byte[] auth = registrationAuth();
        return json("{\"id\":\"" + credentialId() + "\",\"rawId\":\"" + credentialId()
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + encode(clientData("webauthn.create", challenge))
                + "\",\"authenticatorData\":\"" + encode(auth)
                + "\",\"attestationObject\":\"" + encode(attestation(auth))
                + "\",\"publicKeyAlgorithm\":-8,\"transports\":[\"usb\"]},"
                + "\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}");
    }

    byte [] assertion(String challenge, long counter) throws Exception {
        byte[] auth = assertionAuth(counter);
        byte[] client = clientData("webauthn.get", challenge);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(this.keyPair.getPrivate());
        signer.update(auth);
        signer.update(hash(client));
        return json("{\"id\":\"" + credentialId() + "\",\"rawId\":\"" + credentialId()
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + encode(client) + "\",\"authenticatorData\":\"" + encode(auth)
                + "\",\"signature\":\"" + encode(signer.sign())
                + "\",\"userHandle\":\"" + encode(this.userHandle)
                + "\"},\"clientExtensionResults\":{}}");
    }

    private byte [] registrationAuth() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP_ID.getBytes(StandardCharsets.US_ASCII)));
        out.write(0x45); out.writeBytes(new byte[4]); out.writeBytes(new byte[16]);
        out.write(0); out.write(CREDENTIAL_ID.length); out.writeBytes(CREDENTIAL_ID);
        byte[] spki = this.keyPair.getPublic().getEncoded();
        out.write(0xa4); out.write(1); out.write(1); out.write(3); out.write(0x27);
        out.write(0x20); out.write(6); out.write(0x21); out.write(0x58); out.write(32);
        out.writeBytes(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        return out.toByteArray();
    }

    private static byte [] assertionAuth(long counter) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP_ID.getBytes(StandardCharsets.US_ASCII))); out.write(0x05);
        out.write((int) (counter >>> 24)); out.write((int) (counter >>> 16));
        out.write((int) (counter >>> 8)); out.write((int) counter);
        return out.toByteArray();
    }

    private static byte [] attestation(byte [] auth) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa3); text(out, "fmt"); text(out, "none");
        text(out, "authData"); bytes(out, auth); text(out, "attStmt"); out.write(0xa0);
        return out.toByteArray();
    }

    private static void text(ByteArrayOutputStream out, String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        out.write(0x60 | bytes.length); out.writeBytes(bytes);
    }

    private static void bytes(ByteArrayOutputStream out, byte [] value) {
        if (value.length < 24) out.write(0x40 | value.length);
        else if (value.length < 256) { out.write(0x58); out.write(value.length); }
        else { out.write(0x59); out.write(value.length >>> 8); out.write(value.length); }
        out.writeBytes(value);
    }

    private static byte [] clientData(String type, String challenge) {
        return json("{\"type\":\"" + type + "\",\"challenge\":\"" + challenge
                + "\",\"origin\":\"" + ORIGIN + "\",\"crossOrigin\":false}");
    }

    private static byte [] hash(byte [] input) {
        try { return MessageDigest.getInstance("SHA-256").digest(input); }
        catch (java.security.NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }

    private static String encode(byte [] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte [] json(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
