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
import java.security.MessageDigest;

import static java.util.Objects.requireNonNull;

/** Selected WebAuthn authenticator-data profile; it never verifies a signature or creates an authentication proof. */
final class WebAuthnAuthenticatorData {
    private static final int USER_PRESENT = 0x01;
    private static final int USER_VERIFIED = 0x04;
    private static final int BACKUP_ELIGIBLE = 0x08;
    private static final int BACKUP_STATE = 0x10;
    private static final int ATTESTED_CREDENTIAL_DATA = 0x40;
    private static final int EXTENSION_DATA = 0x80;
    private static final int RESERVED = 0x22;

    private WebAuthnAuthenticatorData() { }

    static @NonNull Registration parseRegistration(byte @NonNull [] input, byte @NonNull [] expectedRpIdHash)
        throws WebAuthnCborException {
        return parseRegistration(input, expectedRpIdHash,
                WebAuthnNoneAttestation.MAXIMUM_AUTHENTICATOR_DATA_BYTES);
    }

    static @NonNull Registration parseRegistration(byte @NonNull [] input,
            byte @NonNull [] expectedRpIdHash, int maximumBytes) throws WebAuthnCborException {
        Header header = header(input, expectedRpIdHash, true, maximumBytes);
        WebAuthnCborReader reader = header.reader;
        byte[] aaguid = reader.rawBytes(16);
        int credentialIdLength = reader.unsignedShort();
        if (credentialIdLength < 1 || credentialIdLength > 1_023) throw new WebAuthnCborException();
        byte[] credentialId = reader.rawBytes(credentialIdLength);
        WebAuthnCoseKey.Parsed key = WebAuthnCoseKey.parse(reader, input);
        if (!reader.finished()) throw new WebAuthnCborException();
        return new Registration(aaguid, credentialId, key.encoding(), key.algorithm(), header.counter,
            header.backupEligible, header.backedUp);
    }

    static @NonNull Assertion parseAssertion(byte @NonNull [] input, byte @NonNull [] expectedRpIdHash)
        throws WebAuthnCborException {
        return parseAssertion(input, expectedRpIdHash,
                WebAuthnNoneAttestation.MAXIMUM_AUTHENTICATOR_DATA_BYTES);
    }

    static @NonNull Assertion parseAssertion(byte @NonNull [] input,
            byte @NonNull [] expectedRpIdHash, int maximumBytes) throws WebAuthnCborException {
        Header header = header(input, expectedRpIdHash, false, maximumBytes);
        if (!header.reader.finished()) throw new WebAuthnCborException();
        return new Assertion(header.counter, header.backupEligible, header.backedUp);
    }

    private static @NonNull Header header(byte @NonNull [] input, byte @NonNull [] expectedRpIdHash,
                                          boolean registration, int maximumBytes) throws WebAuthnCborException {
        requireNonNull(input);
        requireNonNull(expectedRpIdHash);
        if (expectedRpIdHash.length != 32) throw new IllegalArgumentException("Expected RP ID hash must be 32 bytes.");
        if (maximumBytes < 37 || maximumBytes > 32 * 1_024)
            throw new IllegalArgumentException("Invalid WebAuthn authenticator-data limit");
        if (input.length < 37 || input.length > maximumBytes)
            throw new WebAuthnCborException();
        WebAuthnCborReader reader = new WebAuthnCborReader(input, 0);
        if (!MessageDigest.isEqual(reader.rawBytes(32), expectedRpIdHash)) throw new WebAuthnCborException();
        int flags = reader.unsignedByte();
        if ((flags & (USER_PRESENT | USER_VERIFIED)) != (USER_PRESENT | USER_VERIFIED)
            || (flags & (RESERVED | EXTENSION_DATA)) != 0
            || (flags & BACKUP_STATE) != 0 && (flags & BACKUP_ELIGIBLE) == 0
            || ((flags & ATTESTED_CREDENTIAL_DATA) != 0) != registration) throw new WebAuthnCborException();
        long counter = reader.unsignedInt();
        return new Header(reader, counter, (flags & BACKUP_ELIGIBLE) != 0, (flags & BACKUP_STATE) != 0);
    }

    private static final class Header {
        private final @NonNull WebAuthnCborReader reader;
        private final long counter;
        private final boolean backupEligible;
        private final boolean backedUp;

        private Header(@NonNull WebAuthnCborReader reader, long counter, boolean backupEligible, boolean backedUp) {
            this.reader = reader;
            this.counter = counter;
            this.backupEligible = backupEligible;
            this.backedUp = backedUp;
        }
    }

    /** Structurally checked registration data, not a verified enrollment. */
    @Immutable
    static final class Registration {
        private final byte @NonNull [] aaguid;
        private final byte @NonNull [] credentialId;
        private final byte @NonNull [] keyCbor;
        private final int algorithm;
        private final long counter;
        private final boolean backupEligible;
        private final boolean backedUp;

        private Registration(byte @NonNull [] aaguid, byte @NonNull [] credentialId, byte @NonNull [] keyCbor,
                             int algorithm, long counter, boolean backupEligible, boolean backedUp) {
            this.aaguid = aaguid.clone();
            this.credentialId = credentialId.clone();
            this.keyCbor = keyCbor.clone();
            this.algorithm = algorithm;
            this.counter = counter;
            this.backupEligible = backupEligible;
            this.backedUp = backedUp;
        }

        byte @NonNull [] aaguid() { return aaguid.clone(); }
        byte @NonNull [] credentialId() { return credentialId.clone(); }
        byte @NonNull [] keyCbor() { return keyCbor.clone(); }
        int algorithm() { return algorithm; }
        long counter() { return counter; }
        boolean backupEligible() { return backupEligible; }
        boolean backedUp() { return backedUp; }

        @Override public @NonNull String toString() {
            return "WebAuthnAuthenticatorData.Registration{<unverified>}";
        }
    }

    /** Structurally checked assertion data, not a verified sign-in. */
    @Immutable
    static final class Assertion {
        private final long counter;
        private final boolean backupEligible;
        private final boolean backedUp;

        private Assertion(long counter, boolean backupEligible, boolean backedUp) {
            this.counter = counter;
            this.backupEligible = backupEligible;
            this.backedUp = backedUp;
        }

        long counter() { return counter; }
        boolean backupEligible() { return backupEligible; }
        boolean backedUp() { return backedUp; }

        @Override public @NonNull String toString() {
            return "WebAuthnAuthenticatorData.Assertion{<unverified>}";
        }
    }
}
