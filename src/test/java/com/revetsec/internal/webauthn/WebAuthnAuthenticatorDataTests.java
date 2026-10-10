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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnAuthenticatorDataTests {
    private static final byte[] RP_HASH = new byte[32];
    private static final byte[] ES_X = HexFormat.of().parseHex(
        "65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d");
    private static final byte[] ES_Y = HexFormat.of().parseHex(
        "1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c");
    private static final byte[] ED_X = HexFormat.of().parseHex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    @Test void parsesP256RegistrationWithUnsignedCounterAndDefensiveCopies() throws WebAuthnCborException {
        byte[] credentialId = "credential".getBytes(StandardCharsets.US_ASCII);
        byte[] input = registration(esKey(ES_X, ES_Y), credentialId, 0x45, 0xffff_ffffL);
        var parsed = WebAuthnAuthenticatorData.parseRegistration(input, RP_HASH);
        assertEquals(-7, parsed.algorithm());
        assertEquals(0xffff_ffffL, parsed.counter());
        assertFalse(parsed.backupEligible());
        assertFalse(parsed.backedUp());
        assertArrayEquals(credentialId, parsed.credentialId());
        assertArrayEquals(new byte[16], parsed.aaguid());
        assertArrayEquals(esKey(ES_X, ES_Y), parsed.keyCbor());
        input[55] = 0;
        credentialId[0] = 0;
        byte[] released = parsed.keyCbor(); released[0] = 0;
        assertEquals('c', parsed.credentialId()[0]);
        assertEquals(0xa5, parsed.keyCbor()[0] & 0xff);
        assertEquals("WebAuthnAuthenticatorData.Registration{<unverified>}", parsed.toString());
    }

    @Test void parsesEd25519AndRealJcaRsaPublicKeys() throws Exception {
        var ed = WebAuthnAuthenticatorData.parseRegistration(registration(edKey(ED_X), new byte[] {1}, 0x5d, 0), RP_HASH);
        assertEquals(-8, ed.algorithm());
        assertTrue(ed.backupEligible());
        assertTrue(ed.backedUp());

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        RSAPublicKey publicKey = (RSAPublicKey) generator.generateKeyPair().getPublic();
        byte[] modulus = unsigned(publicKey.getModulus());
        var rsa = WebAuthnAuthenticatorData.parseRegistration(
            registration(rsaKey(modulus, unsigned(publicKey.getPublicExponent())), new byte[] {2}, 0x45, 7), RP_HASH);
        assertEquals(-257, rsa.algorithm());
        assertEquals(7, rsa.counter());
    }

    @Test void parsesOnlyExactAssertionShape() throws WebAuthnCborException {
        var parsed = WebAuthnAuthenticatorData.parseAssertion(assertion(0x1d, 0xffff_ffffL), RP_HASH);
        assertEquals(0xffff_ffffL, parsed.counter());
        assertTrue(parsed.backupEligible());
        assertTrue(parsed.backedUp());
        assertEquals("WebAuthnAuthenticatorData.Assertion{<unverified>}", parsed.toString());
        rejectAssertion(assertion(0x5d, 0)); // AT
        rejectAssertion(assertion(0x85, 0)); // ED
        rejectAssertion(Arrays.copyOf(assertion(0x05, 0), 38));
    }

    @Test void rejectsWrongRpFlagsAndMissingAttestedData() {
        byte[] good = registration(esKey(ES_X, ES_Y), new byte[] {1}, 0x45, 0);
        byte[] wrongRp = good.clone(); wrongRp[0] = 1;
        rejectRegistration(wrongRp);
        for (int flags : new int[] {0x44, 0x41, 0x47, 0x65, 0xc5, 0x55, 0x05}) {
            rejectRegistration(registration(esKey(ES_X, ES_Y), new byte[] {1}, flags, 0));
        }
        assertThrows(IllegalArgumentException.class,
            () -> WebAuthnAuthenticatorData.parseRegistration(good, new byte[31]));
    }

    @Test void rejectsCredentialLengthTruncationAndUnconsumedData() {
        byte[] key = esKey(ES_X, ES_Y);
        rejectRegistration(registration(key, new byte[0], 0x45, 0));
        rejectRegistration(registration(key, new byte[1024], 0x45, 0));
        byte[] good = registration(key, new byte[] {1}, 0x45, 0);
        rejectRegistration(Arrays.copyOf(good, 52));
        rejectRegistration(Arrays.copyOf(good, good.length - 1));
        rejectRegistration(Arrays.copyOf(good, good.length + 1));
        rejectRegistration(new byte[WebAuthnNoneAttestation.MAXIMUM_AUTHENTICATOR_DATA_BYTES + 1]);
        byte[] overstated = good.clone(); overstated[53] = 4;
        rejectRegistration(overstated);
    }

    @Test void rejectsUnsupportedAndAmbiguousCoseKeyShapes() {
        byte[] x = ES_X.clone(); x[0] ^= 1;
        rejectKey(esKey(x, ES_Y)); // Not on P-256.
        byte[] noncanonicalEd = new byte[32]; Arrays.fill(noncanonicalEd, (byte) 0xff);
        rejectKey(edKey(noncanonicalEd));
        byte[] offCurveEd = new byte[32]; offCurveEd[0] = 2;
        rejectKey(edKey(offCurveEd));
        byte[] identityEd = new byte[32]; identityEd[0] = 1;
        rejectKey(edKey(identityEd));
        byte[] negativeZeroEd = identityEd.clone(); negativeZeroEd[31] = (byte) 0x80;
        rejectKey(edKey(negativeZeroEd));
        byte[] weakModulus = new byte[256]; weakModulus[0] = 0x40; weakModulus[255] = 1;
        rejectKey(rsaKey(weakModulus, new byte[] {1, 0, 1}));
        weakModulus[0] = (byte) 0x80; weakModulus[255] = 2;
        rejectKey(rsaKey(weakModulus, new byte[] {1, 0, 1}));
        weakModulus[255] = 1;
        rejectKey(rsaKey(weakModulus, new byte[] {3}));
        rejectKey(rsaKey(new byte[0], new byte[] {1, 0, 1}));

        byte[] duplicate = esKey(ES_X, ES_Y); duplicate[3] = 1; // alg label becomes duplicate kty.
        rejectKey(duplicate);
        byte[] wrongAlgorithm = esKey(ES_X, ES_Y); wrongAlgorithm[4] = 0x27; // -8 instead of -7.
        rejectKey(wrongAlgorithm);
        byte[] nonminimal = esKey(ES_X, ES_Y);
        byte[] inflated = new byte[nonminimal.length + 1];
        inflated[0] = (byte) 0xb8; inflated[1] = 5;
        System.arraycopy(nonminimal, 1, inflated, 2, nonminimal.length - 1);
        rejectKey(inflated);
        byte[] unsupportedParameter = Arrays.copyOf(esKey(ES_X, ES_Y), esKey(ES_X, ES_Y).length + 2);
        unsupportedParameter[0] = (byte) 0xa6;
        unsupportedParameter[unsupportedParameter.length - 2] = 2;
        unsupportedParameter[unsupportedParameter.length - 1] = 0x40;
        rejectKey(unsupportedParameter);
    }

    private static void rejectKey(byte @NonNull [] key) {
        rejectRegistration(registration(key, new byte[] {1}, 0x45, 0));
    }

    private static void rejectRegistration(byte @NonNull [] input) {
        var failure = assertThrows(WebAuthnCborException.class,
            () -> WebAuthnAuthenticatorData.parseRegistration(input, RP_HASH));
        assertEquals("WebAuthn binary input rejected.", failure.getMessage());
        assertEquals(0, failure.getStackTrace().length);
    }

    private static void rejectAssertion(byte @NonNull [] input) {
        assertThrows(WebAuthnCborException.class,
            () -> WebAuthnAuthenticatorData.parseAssertion(input, RP_HASH));
    }

    private static byte @NonNull [] registration(byte @NonNull [] key, byte @NonNull [] id, int flags, long counter) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(RP_HASH); out.write(flags);
        out.write((int) (counter >>> 24)); out.write((int) (counter >>> 16));
        out.write((int) (counter >>> 8)); out.write((int) counter);
        out.writeBytes(new byte[16]);
        out.write(id.length >>> 8); out.write(id.length);
        out.writeBytes(id); out.writeBytes(key);
        return out.toByteArray();
    }

    private static byte @NonNull [] assertion(int flags, long counter) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(RP_HASH); out.write(flags);
        out.write((int) (counter >>> 24)); out.write((int) (counter >>> 16));
        out.write((int) (counter >>> 8)); out.write((int) counter);
        return out.toByteArray();
    }

    private static byte @NonNull [] esKey(byte @NonNull [] x, byte @NonNull [] y) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa5); out.write(1); out.write(2); out.write(3); out.write(0x26);
        out.write(0x20); out.write(1); out.write(0x21); cborBytes(out, x);
        out.write(0x22); cborBytes(out, y);
        return out.toByteArray();
    }

    private static byte @NonNull [] edKey(byte @NonNull [] x) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(1); out.write(3); out.write(0x27);
        out.write(0x20); out.write(6); out.write(0x21); cborBytes(out, x);
        return out.toByteArray();
    }

    private static byte @NonNull [] rsaKey(byte @NonNull [] n, byte @NonNull [] e) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(3); out.write(3); out.write(0x39); out.write(1); out.write(0);
        out.write(0x20); cborBytes(out, n); out.write(0x21); cborBytes(out, e);
        return out.toByteArray();
    }

    private static void cborBytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] bytes) {
        if (bytes.length < 24) out.write(0x40 | bytes.length);
        else if (bytes.length < 256) { out.write(0x58); out.write(bytes.length); }
        else { out.write(0x59); out.write(bytes.length >>> 8); out.write(bytes.length); }
        out.writeBytes(bytes);
    }

    private static byte @NonNull [] unsigned(@NonNull BigInteger value) {
        byte[] encoded = value.toByteArray();
        return encoded[0] == 0 ? Arrays.copyOfRange(encoded, 1, encoded.length) : encoded;
    }
}
