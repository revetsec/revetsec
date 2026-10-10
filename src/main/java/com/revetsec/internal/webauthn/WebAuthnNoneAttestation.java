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

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import static java.util.Objects.requireNonNull;

/**
 * Strict decoder for the initial WebAuthn registration profile's {@code fmt: "none"} attestation object. The only
 * accepted CBOR value is a three-member map containing a nonempty bounded authenticator-data byte string, the
 * literal format name and an empty attestation-statement map. It accepts member order variations, but no duplicate
 * or unknown members, non-minimal or indefinite lengths, unsupported CBOR types or trailing bytes. It does not
 * interpret authenticator data, a COSE key or client data, and cannot establish a verified registration by itself.
 *
 * <p>The caller must not modify the input during parsing. The returned data is copied before release.</p>
 * @since 1.0.0
 */
@ThreadSafe
public final class WebAuthnNoneAttestation {
    /** Default for the standalone parser; configured relying parties may select a different bound.
     * @since 1.0.0 */
    public static final int MAXIMUM_INPUT_BYTES = 16_384;
    /** Authenticator data includes at least the RP hash, flags and signature counter.
     * @since 1.0.0 */
    public static final int MINIMUM_AUTHENTICATOR_DATA_BYTES = 37;
    /** Gate-25 default for the registration authenticator data.
     * @since 1.0.0 */
    public static final int MAXIMUM_AUTHENTICATOR_DATA_BYTES = 8_192;

    private WebAuthnNoneAttestation() { }

    /**
     * Parses only the selected privacy-preserving none-attestation carrier.
     * @param input complete decoded attestation-object CBOR bytes
     * @return the bounded authenticator-data carrier, without a verification proof
     * @throws WebAuthnCborException for malformed, unsupported or oversized input
     * @since 1.0.0
     */
    public static @NonNull Parsed parse(byte @NonNull [] input) throws WebAuthnCborException {
        return parse(input, MAXIMUM_INPUT_BYTES, MAXIMUM_AUTHENTICATOR_DATA_BYTES);
    }

    static @NonNull Parsed parse(byte @NonNull [] input, int maximumInputBytes,
            int maximumAuthenticatorDataBytes) throws WebAuthnCborException {
        requireNonNull(input);
        if (maximumInputBytes < 1 || maximumInputBytes > 64 * 1_024
                || maximumAuthenticatorDataBytes < MINIMUM_AUTHENTICATOR_DATA_BYTES
                || maximumAuthenticatorDataBytes > 32 * 1_024)
            throw new IllegalArgumentException("Invalid WebAuthn attestation limit");
        if (input.length > maximumInputBytes) throw new WebAuthnCborException();
        WebAuthnCborReader reader = new WebAuthnCborReader(input, 0);
        if (reader.length(5, 3) != 3) throw new WebAuthnCborException();
        boolean formatSeen = false;
        boolean dataSeen = false;
        boolean statementSeen = false;
        byte[] authenticatorData = null;
        for (int i = 0; i < 3; i++) {
            String name = reader.ascii(16);
            switch (name) {
                case "fmt" -> {
                    if (formatSeen || !reader.ascii(16).equals("none")) throw new WebAuthnCborException();
                    formatSeen = true;
                }
                case "authData" -> {
                    if (dataSeen) throw new WebAuthnCborException();
                    authenticatorData = reader.bytes(maximumAuthenticatorDataBytes);
                    if (authenticatorData.length < MINIMUM_AUTHENTICATOR_DATA_BYTES) throw new WebAuthnCborException();
                    dataSeen = true;
                }
                case "attStmt" -> {
                    if (statementSeen || reader.length(5, 0) != 0) throw new WebAuthnCborException();
                    statementSeen = true;
                }
                default -> throw new WebAuthnCborException();
            }
        }
        if (!formatSeen || !dataSeen || !statementSeen || !reader.finished()) throw new WebAuthnCborException();
        return new Parsed(requireNonNull(authenticatorData));
    }

    /** An unverified, immutable copy of authenticator data.
     * @since 1.0.0 */
    @Immutable
    public static final class Parsed {
        private final byte @NonNull [] authenticatorData;

        private Parsed(byte @NonNull [] authenticatorData) {
            this.authenticatorData = authenticatorData.clone();
        }

        /** @return a new copy of the unverified authenticator data
         * @since 1.0.0 */
        public byte @NonNull [] getAuthenticatorData() {
            return authenticatorData.clone();
        }

        /** @since 1.0.0 */
        @Override public @NonNull String toString() {
            return "WebAuthnNoneAttestation.Parsed{<unverified>}";
        }
    }

}
