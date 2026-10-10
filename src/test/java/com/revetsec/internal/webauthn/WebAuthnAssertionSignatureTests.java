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

import com.revetsec.internal.webauthn.WebAuthnAssertionSignature.Check;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import static com.revetsec.internal.webauthn.WebAuthnAssertionSignature.Check.INVALID_SIGNATURE;
import static com.revetsec.internal.webauthn.WebAuthnAssertionSignature.Check.MALFORMED_SIGNATURE;
import static com.revetsec.internal.webauthn.WebAuthnAssertionSignature.Check.VALID_SIGNATURE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

final class WebAuthnAssertionSignatureTests {
    private static final byte[] RP_HASH = new byte[32];
    private static final byte[] CLIENT_JSON = "{\"type\":\"webauthn.get\",\"challenge\":\"test\"}"
        .getBytes(StandardCharsets.US_ASCII);

    @Test void verifiesEs256AndBindsExactRawInputs() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        ECPublicKey key = (ECPublicKey) pair.getPublic();
        byte[] cose = esKey(fixed(key.getW().getAffineX(), 32), fixed(key.getW().getAffineY(), 32));
        byte[] authenticatorData = assertion(0x05);
        byte[] signature = sign("SHA256withECDSA", pair.getPrivate(), authenticatorData, CLIENT_JSON);
        assertEquals(VALID_SIGNATURE, verify(cose, authenticatorData, CLIENT_JSON, signature));

        byte[] changedClient = CLIENT_JSON.clone(); changedClient[1] ^= 1;
        assertEquals(INVALID_SIGNATURE, verify(cose, authenticatorData, changedClient, signature));
        byte[] changedCounter = authenticatorData.clone(); changedCounter[36] ^= 1;
        assertEquals(INVALID_SIGNATURE, verify(cose, changedCounter, CLIENT_JSON, signature));
        byte[] changedSignature = signature.clone(); changedSignature[changedSignature.length - 1] ^= 1;
        assertEquals(INVALID_SIGNATURE, verify(cose, authenticatorData, CLIENT_JSON, changedSignature));

        KeyPair other = generator.generateKeyPair();
        ECPublicKey otherKey = (ECPublicKey) other.getPublic();
        byte[] otherCose = esKey(fixed(otherKey.getW().getAffineX(), 32), fixed(otherKey.getW().getAffineY(), 32));
        assertEquals(INVALID_SIGNATURE, verify(otherCose, authenticatorData, CLIENT_JSON, signature));
    }

    @Test void verifiesEd25519AndRejectsTrailingSignatureOctet() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] spki = pair.getPublic().getEncoded();
        byte[] cose = edKey(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        byte[] authenticatorData = assertion(0x05);
        byte[] signature = sign("Ed25519", pair.getPrivate(), authenticatorData, CLIENT_JSON);
        assertEquals(VALID_SIGNATURE, verify(cose, authenticatorData, CLIENT_JSON, signature));
        assertEquals(MALFORMED_SIGNATURE, verify(cose, authenticatorData, CLIENT_JSON,
            Arrays.copyOf(signature, signature.length + 1)));
        byte[] changed = signature.clone(); changed[32] ^= 1;
        assertEquals(INVALID_SIGNATURE, verify(cose, authenticatorData, CLIENT_JSON, changed));
        byte[] malformedPoint = signature.clone(); malformedPoint[0] ^= 1;
        assertNotEquals(VALID_SIGNATURE, verify(cose, authenticatorData, CLIENT_JSON, malformedPoint));
    }

    @Test void verifiesRs256WithStoredModulusAndExactSignatureLength() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        RSAPublicKey key = (RSAPublicKey) pair.getPublic();
        byte[] cose = rsaKey(unsigned(key.getModulus()), unsigned(key.getPublicExponent()));
        byte[] authenticatorData = assertion(0x05);
        byte[] signature = sign("SHA256withRSA", pair.getPrivate(), authenticatorData, CLIENT_JSON);
        assertEquals(VALID_SIGNATURE, verify(cose, authenticatorData, CLIENT_JSON, signature));
        assertEquals(MALFORMED_SIGNATURE, verify(cose, authenticatorData, CLIENT_JSON,
            Arrays.copyOf(signature, signature.length - 1)));
        byte[] changed = signature.clone(); changed[changed.length - 1] ^= 1;
        assertEquals(INVALID_SIGNATURE, verify(cose, authenticatorData, CLIENT_JSON, changed));
    }

    @Test void rejectsNonDerAndOutOfRangeEs256SignaturesBeforeJca() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        ECPublicKey key = (ECPublicKey) generator.generateKeyPair().getPublic();
        byte[] cose = esKey(fixed(key.getW().getAffineX(), 32), fixed(key.getW().getAffineY(), 32));
        byte[] auth = assertion(0x05);
        byte[][] malformed = {
            new byte[] {0x30, 0x06, 0x02, 0x01, (byte) 0x80, 0x02, 0x01, 0x01}, // negative r
            new byte[] {0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01}, // redundant zero
            new byte[] {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01}, // r = 0
            new byte[] {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00}, // s = 0
            new byte[] {0x30, (byte) 0x81, 0x05, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}, // long length
            new byte[] {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00} // trailing
        };
        for (byte[] signature : malformed)
            assertEquals(MALFORMED_SIGNATURE, verify(cose, auth, CLIENT_JSON, signature));
        assertNull(WebAuthnEcdsaDer.toP1363(new byte[0]));
    }

    @Test void rejectsUnverifiedAuthenticatorContextAndMalformedStoredKey() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] spki = pair.getPublic().getEncoded();
        byte[] cose = edKey(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        byte[] auth = assertion(0x05);
        byte[] signature = sign("Ed25519", pair.getPrivate(), auth, CLIENT_JSON);
        byte[] wrongRp = auth.clone(); wrongRp[0] = 1;
        assertThrows(WebAuthnCborException.class, () -> verify(cose, wrongRp, CLIENT_JSON, signature));
        byte[] noUv = assertion(0x01);
        assertThrows(WebAuthnCborException.class, () -> verify(cose, noUv, CLIENT_JSON, signature));
        assertThrows(WebAuthnCborException.class, () -> verify(cose, auth, new byte[0], signature));
        assertThrows(WebAuthnCborException.class, () -> verify(new byte[] {(byte) 0xa0}, auth, CLIENT_JSON, signature));
    }

    private static @NonNull Check verify(byte @NonNull [] key, byte @NonNull [] auth,
                                                                      byte @NonNull [] client, byte @NonNull [] signature)
        throws WebAuthnCborException {
        return WebAuthnAssertionSignature.verify(key, auth, client, signature, RP_HASH);
    }

    private static byte @NonNull [] sign(@NonNull String algorithm, @NonNull PrivateKey key,
                                         byte @NonNull [] auth, byte @NonNull [] client) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(client);
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(key);
        signer.update(auth);
        signer.update(hash);
        return signer.sign();
    }

    private static byte @NonNull [] assertion(int flags) {
        byte[] data = new byte[37];
        System.arraycopy(RP_HASH, 0, data, 0, 32);
        data[32] = (byte) flags;
        data[36] = 1;
        return data;
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

    private static byte @NonNull [] rsaKey(byte @NonNull [] modulus, byte @NonNull [] exponent) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(3); out.write(3); out.write(0x39); out.write(1); out.write(0);
        out.write(0x20); cborBytes(out, modulus); out.write(0x21); cborBytes(out, exponent);
        return out.toByteArray();
    }

    private static void cborBytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] value) {
        if (value.length < 24) out.write(0x40 | value.length);
        else if (value.length < 256) { out.write(0x58); out.write(value.length); }
        else { out.write(0x59); out.write(value.length >>> 8); out.write(value.length); }
        out.writeBytes(value);
    }

    private static byte @NonNull [] fixed(@NonNull BigInteger number, int size) {
        byte[] unsigned = unsigned(number);
        byte[] fixed = new byte[size];
        System.arraycopy(unsigned, 0, fixed, size - unsigned.length, unsigned.length);
        return fixed;
    }

    private static byte @NonNull [] unsigned(@NonNull BigInteger number) {
        byte[] encoded = number.toByteArray();
        return encoded[0] == 0 ? Arrays.copyOfRange(encoded, 1, encoded.length) : encoded;
    }
}
