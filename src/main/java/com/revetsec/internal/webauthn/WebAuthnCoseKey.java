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
import com.revetsec.internal.crypto.EcPublicKeys;
import com.revetsec.internal.crypto.Ed25519PublicKeys;
import com.revetsec.internal.crypto.KeyRejectedException;
import com.revetsec.internal.crypto.RsaPublicKeys;
import org.jspecify.annotations.NonNull;

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/** Decoder of the selected CTAP2-canonical public COSE key shapes; delegates cryptographic key checks to core. */
final class WebAuthnCoseKey {
    private WebAuthnCoseKey() { }

    static @NonNull Parsed parse(byte @NonNull [] encoding) throws WebAuthnCborException {
        requireNonNull(encoding);
        if (encoding.length > 1_024) throw new WebAuthnCborException();
        WebAuthnCborReader reader = new WebAuthnCborReader(encoding, 0);
        Parsed parsed = parse(reader, encoding);
        if (!reader.finished()) throw new WebAuthnCborException();
        return parsed;
    }

    static @NonNull Parsed parse(@NonNull WebAuthnCborReader reader, byte @NonNull [] input)
        throws WebAuthnCborException {
        requireNonNull(reader);
        requireNonNull(input);
        int start = reader.position();
        int members = reader.length(5, 5);
        expectLabel(reader, 1);
        int keyType = reader.integer();
        expectLabel(reader, 3);
        int algorithm = reader.integer();
        PublicKey key;
        try {
            if (keyType == 2 && algorithm == -7 && members == 5) {
                expectLabel(reader, -1);
                if (reader.integer() != 1) throw new WebAuthnCborException();
                expectLabel(reader, -2);
                byte[] x = reader.bytes(32);
                expectLabel(reader, -3);
                key = EcPublicKeys.fromCoordinates(EcCurve.P_256, x, reader.bytes(32));
            } else if (keyType == 1 && algorithm == -8 && members == 4) {
                expectLabel(reader, -1);
                if (reader.integer() != 6) throw new WebAuthnCborException();
                expectLabel(reader, -2);
                key = Ed25519PublicKeys.fromEncoded(reader.bytes(32));
            } else if (keyType == 3 && algorithm == -257 && members == 4) {
                expectLabel(reader, -1);
                byte[] modulus = reader.bytes(512);
                expectLabel(reader, -2);
                byte[] exponent = reader.bytes(3);
                if (modulus.length < 256 || new BigInteger(1, modulus).bitLength() > 4_096
                    || !Arrays.equals(exponent, new byte[] {1, 0, 1})) throw new WebAuthnCborException();
                key = RsaPublicKeys.fromComponents(modulus, exponent);
            } else throw new WebAuthnCborException();
        } catch (KeyRejectedException exception) {
            throw new WebAuthnCborException();
        }
        return new Parsed(algorithm, Arrays.copyOfRange(input, start, reader.position()), key);
    }

    private static void expectLabel(@NonNull WebAuthnCborReader reader, int label) throws WebAuthnCborException {
        if (reader.integer() != label) throw new WebAuthnCborException();
    }

    /** Checked key material and its original encoding; still no WebAuthn ceremony proof. */
    static final class Parsed {
        private final int algorithm;
        private final byte @NonNull [] encoding;
        private final @NonNull PublicKey key;

        private Parsed(int algorithm, byte @NonNull [] encoding, @NonNull PublicKey key) {
            this.algorithm = algorithm;
            this.encoding = encoding.clone();
            this.key = key;
        }

        int algorithm() {
            return algorithm;
        }

        byte @NonNull [] encoding() {
            return encoding.clone();
        }

        @NonNull PublicKey key() {
            return key;
        }
    }
}
