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

import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.internal.crypto.SignatureVerifier;
import com.revetsec.internal.crypto.VerifyResult;
import org.jspecify.annotations.NonNull;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import static java.util.Objects.requireNonNull;

/** Signature-only check for a bounded WebAuthn assertion. It does not check client-data claims or store state. */
final class WebAuthnAssertionSignature {
    // The client-data policy applies the configured limit (8 KiB by default); this is the hard ceiling.
    private static final int MAXIMUM_CLIENT_DATA_BYTES = 16_384;
    private static final int MAXIMUM_SIGNATURE_BYTES = 512;

    private WebAuthnAssertionSignature() { }

    static @NonNull Check verify(byte @NonNull [] storedKeyCbor, byte @NonNull [] authenticatorData,
                                 byte @NonNull [] clientDataJson, byte @NonNull [] signature,
                                 byte @NonNull [] expectedRpIdHash) throws WebAuthnCborException {
        requireNonNull(storedKeyCbor);
        requireNonNull(authenticatorData);
        requireNonNull(clientDataJson);
        requireNonNull(signature);
        requireNonNull(expectedRpIdHash);
        WebAuthnAuthenticatorData.parseAssertion(authenticatorData, expectedRpIdHash);
        if (clientDataJson.length < 1 || clientDataJson.length > MAXIMUM_CLIENT_DATA_BYTES)
            throw new WebAuthnCborException();
        if (signature.length < 1 || signature.length > MAXIMUM_SIGNATURE_BYTES) return Check.MALFORMED_SIGNATURE;
        WebAuthnCoseKey.Parsed key = WebAuthnCoseKey.parse(storedKeyCbor);
        byte[] signed;
        try {
            byte[] clientHash = MessageDigest.getInstance("SHA-256").digest(clientDataJson);
            signed = new byte[authenticatorData.length + clientHash.length];
            System.arraycopy(authenticatorData, 0, signed, 0, authenticatorData.length);
            System.arraycopy(clientHash, 0, signed, authenticatorData.length, clientHash.length);
        } catch (GeneralSecurityException | RuntimeException exception) {
            return Check.UNAVAILABLE;
        }
        VerifyResult result;
        switch (key.algorithm()) {
            case -7 -> {
                byte[] p1363 = WebAuthnEcdsaDer.toP1363(signature);
                if (p1363 == null) return Check.MALFORMED_SIGNATURE;
                result = SignatureVerifier.verifyEcdsa(EcCurve.P_256, HashAlgorithm.SHA_256, key.key(), signed, p1363);
            }
            case -8 -> result = SignatureVerifier.verifyEd25519(key.key(), signed, signature);
            case -257 -> result = SignatureVerifier.verifyRsaPkcs1(HashAlgorithm.SHA_256, key.key(), signed, signature);
            default -> throw new IllegalStateException("Unsupported checked WebAuthn key algorithm.");
        }
        return switch (result) {
            case VALID -> Check.VALID_SIGNATURE;
            case WRONG_LENGTH, OUT_OF_RANGE -> Check.MALFORMED_SIGNATURE;
            case MISMATCH -> Check.INVALID_SIGNATURE;
            case PROVIDER_FAILURE -> Check.UNAVAILABLE;
        };
    }

    /** Only a signature result; even VALID_SIGNATURE is not a WebAuthn authentication result. */
    enum Check {
        VALID_SIGNATURE,
        MALFORMED_SIGNATURE,
        INVALID_SIGNATURE,
        UNAVAILABLE
    }
}
