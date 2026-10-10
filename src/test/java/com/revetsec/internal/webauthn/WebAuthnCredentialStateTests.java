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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Set;

import static com.revetsec.internal.webauthn.WebAuthnCredentialState.Assessment.Status.CANDIDATE;
import static com.revetsec.internal.webauthn.WebAuthnCredentialState.Assessment.Status.COUNTER_RISK;
import static com.revetsec.internal.webauthn.WebAuthnCredentialState.Assessment.Status.REJECTED;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WebAuthnCredentialStateTests {
    private static final String RP_ID = "login.example.com";
    private static final byte[] RP_HASH = hash(RP_ID.getBytes(StandardCharsets.US_ASCII));
    private static final byte[] CHALLENGE = new byte[32];
    private static final byte[] CREDENTIAL_ID = {1, 2, 3};
    private static final byte[] USER_HANDLE = {4, 5, 6};
    private static final byte[] CLIENT_JSON = ("{\"type\":\"webauthn.get\",\"challenge\":\""
            + Base64Url.encode(CHALLENGE) + "\",\"origin\":\"https://" + RP_ID + "\"}")
            .getBytes(StandardCharsets.UTF_8);

    @Test
    void checksRealSignedBrowserAssertionAgainstAuthoritativeIdentityAndKey() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] storedKey = edKey(pair);
        var response = parsed(pair.getPrivate(), CREDENTIAL_ID, USER_HANDLE, 0x05, 8);
        var stored = WebAuthnCredentialState.checked(CREDENTIAL_ID, USER_HANDLE, storedKey, -8, 7, false, false);

        var assessment = stored.assess(response, USER_HANDLE);
        assertEquals(CANDIDATE, assessment.status());
        assertEquals(8, assessment.candidate().orElseThrow().counter());
        assertArrayEquals(CREDENTIAL_ID, assessment.candidate().orElseThrow().credentialId());
        assertEquals("WebAuthnCredentialState.Assessment{CANDIDATE, <no proof>}", assessment.toString());

        assertRejected(WebAuthnCredentialState.checked(new byte[] {9}, USER_HANDLE, storedKey, -8, 7,
                false, false).assess(response, null));
        assertRejected(WebAuthnCredentialState.checked(CREDENTIAL_ID, new byte[] {9}, storedKey, -8, 7,
                false, false).assess(response, null));
        assertRejected(stored.assess(response, new byte[] {9}));
        KeyPair otherPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        assertRejected(WebAuthnCredentialState.checked(CREDENTIAL_ID, USER_HANDLE, edKey(otherPair), -8, 7,
                false, false).assess(response, null));
        assertRejected(stored.assess(parsed(otherPair.getPrivate(), CREDENTIAL_ID, USER_HANDLE, 0x05, 8), null));
    }

    @Test
    void appliesCounterHighWaterAndBackupTransitionsOnlyAfterValidSignature() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] key = edKey(pair);
        var zero = WebAuthnCredentialState.checked(CREDENTIAL_ID, USER_HANDLE, key, -8, 0, true, false);
        var five = WebAuthnCredentialState.checked(CREDENTIAL_ID, USER_HANDLE, key, -8, 5, true, false);

        var stillZero = zero.assess(parsed(pair.getPrivate(), CREDENTIAL_ID, USER_HANDLE, 0x0d, 0), null);
        assertEquals(CANDIDATE, stillZero.status());
        assertEquals(0, stillZero.candidate().orElseThrow().counter());
        var firstNonzero = zero.assess(parsed(pair.getPrivate(), CREDENTIAL_ID, USER_HANDLE, 0x1d, 5), null);
        assertEquals(CANDIDATE, firstNonzero.status());
        assertEquals(5, firstNonzero.candidate().orElseThrow().counter());
        assertTrue(firstNonzero.candidate().orElseThrow().backedUp());
        assertFalse(zero.backedUp());

        var signedZero = five.assess(parsed(pair.getPrivate(), CREDENTIAL_ID, USER_HANDLE, 0x0d, 0), null);
        assertEquals(CANDIDATE, signedZero.status());
        assertEquals(5, signedZero.candidate().orElseThrow().counter());
        assertEquals(COUNTER_RISK, five.assess(parsed(pair.getPrivate(), CREDENTIAL_ID, USER_HANDLE, 0x0d, 5),
                null).status());
        assertEquals(COUNTER_RISK, five.assess(parsed(pair.getPrivate(), CREDENTIAL_ID, USER_HANDLE, 0x0d, 4),
                null).status());
        assertEquals(6, five.assess(parsed(pair.getPrivate(), CREDENTIAL_ID, USER_HANDLE, 0x0d, 6), null)
                .candidate().orElseThrow().counter());
        assertRejected(five.assess(parsed(pair.getPrivate(), CREDENTIAL_ID, USER_HANDLE, 0x05, 6), null));
    }

    @Test
    void reconstructsOnlyBoundedConsistentCredentialState() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] key = edKey(pair);
        var state = WebAuthnCredentialState.checked(CREDENTIAL_ID, USER_HANDLE, key, -8, 0xffff_ffffL,
                true, true);
        assertEquals(-8, state.algorithm());
        assertEquals(0xffff_ffffL, state.counter());
        assertTrue(state.backupEligible());
        assertTrue(state.backedUp());
        assertEquals("WebAuthnCredentialState{<unverified>}", state.toString());
        state.keyCbor()[0] = 0;
        assertEquals(0xa4, state.keyCbor()[0] & 0xff);

        for (byte[] badId : new byte[][]{new byte[0], new byte[1_024]})
            assertThrows(WebAuthnCborException.class,
                    () -> WebAuthnCredentialState.checked(badId, USER_HANDLE, key, -8, 0, false, false));
        assertThrows(WebAuthnCborException.class,
                () -> WebAuthnCredentialState.checked(CREDENTIAL_ID, new byte[65], key, -8, 0, false, false));
        assertThrows(WebAuthnCborException.class,
                () -> WebAuthnCredentialState.checked(CREDENTIAL_ID, USER_HANDLE, key, -7, 0, false, false));
        assertThrows(WebAuthnCborException.class,
                () -> WebAuthnCredentialState.checked(CREDENTIAL_ID, USER_HANDLE, key, -8, -1, false, false));
        assertThrows(WebAuthnCborException.class,
                () -> WebAuthnCredentialState.checked(CREDENTIAL_ID, USER_HANDLE, key, -8, 0x1_0000_0000L,
                        false, false));
        assertThrows(WebAuthnCborException.class,
                () -> WebAuthnCredentialState.checked(CREDENTIAL_ID, USER_HANDLE, key, -8, 0, false, true));
        assertThrows(WebAuthnCborException.class,
                () -> WebAuthnCredentialState.checked(CREDENTIAL_ID, USER_HANDLE, new byte[]{(byte) 0xa0},
                        -8, 0, false, false));
    }

    @Test
    void carriesApprovedUserHandleFromRegistrationWithoutTreatingItAsProof() throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] key = edKey(pair);
        ByteArrayOutputStream auth = new ByteArrayOutputStream();
        auth.writeBytes(RP_HASH); auth.write(0x45); auth.writeBytes(new byte[4]);
        auth.writeBytes(new byte[16]); auth.write(0); auth.write(CREDENTIAL_ID.length);
        auth.writeBytes(CREDENTIAL_ID); auth.writeBytes(key);
        var registration = WebAuthnAuthenticatorData.parseRegistration(auth.toByteArray(), RP_HASH);
        byte[] approved = USER_HANDLE.clone();
        var state = WebAuthnCredentialState.fromRegistration(registration, approved);
        approved[0] = 99;
        assertArrayEquals(USER_HANDLE, state.userHandle());
        assertArrayEquals(CREDENTIAL_ID, state.credentialId());
        assertEquals(0, state.counter());
    }

    private static void assertRejected(WebAuthnCredentialState.@NonNull Assessment assessment) {
        assertEquals(REJECTED, assessment.status());
        assertTrue(assessment.candidate().isEmpty());
    }

    private static WebAuthnResponseJson.@NonNull Assertion parsed(@NonNull PrivateKey key,
            byte @NonNull [] id, byte @NonNull [] handle, int flags, long counter) throws Exception {
        byte[] auth = authenticatorData(flags, counter);
        byte[] signature = sign(key, auth);
        String encodedId = Base64Url.encode(id);
        String body = "{\"id\":\"" + encodedId + "\",\"rawId\":\"" + encodedId
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(CLIENT_JSON) + "\",\"authenticatorData\":\"" + Base64Url.encode(auth)
                + "\",\"signature\":\"" + Base64Url.encode(signature) + "\",\"userHandle\":\""
                + Base64Url.encode(handle) + "\"},\"clientExtensionResults\":{}}";
        var policy = new WebAuthnClientData(RP_ID, Set.of("https://" + RP_ID), 8_192);
        return new WebAuthnResponseJson(policy, 64 * 1_024).parseAssertion(
                body.getBytes(StandardCharsets.UTF_8), CHALLENGE);
    }

    private static byte @NonNull [] authenticatorData(int flags, long counter) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(RP_HASH); out.write(flags);
        out.write((int) (counter >>> 24)); out.write((int) (counter >>> 16));
        out.write((int) (counter >>> 8)); out.write((int) counter);
        return out.toByteArray();
    }

    private static byte @NonNull [] sign(@NonNull PrivateKey key, byte @NonNull [] auth) throws Exception {
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(auth);
        signer.update(hash(CLIENT_JSON));
        return signer.sign();
    }

    private static byte @NonNull [] edKey(@NonNull KeyPair pair) {
        byte[] spki = pair.getPublic().getEncoded();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(1); out.write(3); out.write(0x27);
        out.write(0x20); out.write(6); out.write(0x21); out.write(0x58); out.write(32);
        out.writeBytes(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        return out.toByteArray();
    }

    private static byte @NonNull [] hash(byte @NonNull [] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
