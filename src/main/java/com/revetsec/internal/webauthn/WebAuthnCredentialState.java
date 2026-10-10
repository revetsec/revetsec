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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.security.MessageDigest;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Checked credential state and a stateless assertion assessment. A candidate update is only input to a future
 * compare-and-commit operation; it is never an authentication proof. The application store must keep this state
 * authoritative and condition its update on the exact version read with the ceremony and account fence.
 */
@Immutable
final class WebAuthnCredentialState {
    private static final long MAXIMUM_COUNTER = 0xffff_ffffL;

    private final byte @NonNull [] credentialId;
    private final byte @NonNull [] userHandle;
    private final byte @NonNull [] keyCbor;
    private final int algorithm;
    private final long counter;
    private final boolean backupEligible;
    private final boolean backedUp;

    private WebAuthnCredentialState(byte @NonNull [] credentialId, byte @NonNull [] userHandle,
            byte @NonNull [] keyCbor, int algorithm, long counter, boolean backupEligible, boolean backedUp) {
        this.credentialId = credentialId.clone();
        this.userHandle = userHandle.clone();
        this.keyCbor = keyCbor.clone();
        this.algorithm = algorithm;
        this.counter = counter;
        this.backupEligible = backupEligible;
        this.backedUp = backedUp;
    }

    static @NonNull WebAuthnCredentialState fromRegistration(
            WebAuthnAuthenticatorData.@NonNull Registration registration, byte @NonNull [] approvedUserHandle)
            throws WebAuthnCborException {
        requireNonNull(registration);
        return checked(registration.credentialId(), approvedUserHandle, registration.keyCbor(),
                registration.algorithm(), registration.counter(), registration.backupEligible(),
                registration.backedUp());
    }

    /** Rechecks untrusted reconstructed state before it is used for a signature decision. */
    static @NonNull WebAuthnCredentialState checked(byte @NonNull [] credentialId,
            byte @NonNull [] userHandle, byte @NonNull [] keyCbor, int algorithm, long counter,
            boolean backupEligible, boolean backedUp) throws WebAuthnCborException {
        requireNonNull(credentialId);
        requireNonNull(userHandle);
        requireNonNull(keyCbor);
        if (credentialId.length < 1 || credentialId.length > 1_023 || userHandle.length < 1
                || userHandle.length > 64 || counter < 0 || counter > MAXIMUM_COUNTER
                || (backedUp && !backupEligible))
            throw new WebAuthnCborException();
        WebAuthnCoseKey.Parsed key = WebAuthnCoseKey.parse(keyCbor);
        if (algorithm != key.algorithm())
            throw new WebAuthnCborException();
        return new WebAuthnCredentialState(credentialId, userHandle, keyCbor, algorithm, counter,
                backupEligible, backedUp);
    }

    @NonNull Assessment assess(WebAuthnResponseJson.@NonNull Assertion assertion,
            byte @Nullable [] expectedPinnedUserHandle) {
        requireNonNull(assertion);
        if (expectedPinnedUserHandle != null
                && (expectedPinnedUserHandle.length < 1 || expectedPinnedUserHandle.length > 64))
            throw new IllegalArgumentException("Expected WebAuthn user handle must be 1 to 64 bytes.");
        if (!MessageDigest.isEqual(this.credentialId, assertion.credentialId())
                || !MessageDigest.isEqual(this.userHandle, assertion.userHandle())
                || (expectedPinnedUserHandle != null
                && !MessageDigest.isEqual(this.userHandle, expectedPinnedUserHandle)))
            return Assessment.rejected();

        WebAuthnAssertionSignature.Check signature;
        try {
            signature = assertion.verifyWithStoredKey(this.keyCbor);
        } catch (WebAuthnCborException exception) {
            // The browser data was already decoded; failure here indicates unusable authoritative key state.
            return Assessment.unavailable();
        }
        if (signature == WebAuthnAssertionSignature.Check.UNAVAILABLE)
            return Assessment.unavailable();
        if (signature != WebAuthnAssertionSignature.Check.VALID_SIGNATURE)
            return Assessment.rejected();

        WebAuthnAuthenticatorData.Assertion flags = assertion.flags();
        if (flags.backupEligible() != this.backupEligible)
            return Assessment.rejected();
        long newCounter = flags.counter();
        if (this.counter != 0 && newCounter != 0 && newCounter <= this.counter)
            return Assessment.counterRisk();
        // A signed zero is allowed for a credential without a counter, but cannot lower the stored high-water value.
        long highWaterCounter = Math.max(this.counter, newCounter);
        return Assessment.candidate(new WebAuthnCredentialState(this.credentialId, this.userHandle,
                this.keyCbor, this.algorithm, highWaterCounter, this.backupEligible, flags.backedUp()));
    }

    byte @NonNull [] credentialId() { return this.credentialId.clone(); }
    byte @NonNull [] userHandle() { return this.userHandle.clone(); }
    byte @NonNull [] keyCbor() { return this.keyCbor.clone(); }
    int algorithm() { return this.algorithm; }
    long counter() { return this.counter; }
    boolean backupEligible() { return this.backupEligible; }
    boolean backedUp() { return this.backedUp; }

    @Override public @NonNull String toString() {
        return "WebAuthnCredentialState{<unverified>}";
    }

    /** A stateless assessment only; CANDIDATE still requires an authoritative commit before proof. */
    @Immutable
    static final class Assessment {
        private static final @NonNull Assessment REJECTED = new Assessment(Status.REJECTED, null);
        private static final @NonNull Assessment COUNTER_RISK = new Assessment(Status.COUNTER_RISK, null);
        private static final @NonNull Assessment UNAVAILABLE = new Assessment(Status.UNAVAILABLE, null);

        private final @NonNull Status status;
        private final @Nullable WebAuthnCredentialState candidate;

        private Assessment(@NonNull Status status, @Nullable WebAuthnCredentialState candidate) {
            this.status = status;
            this.candidate = candidate;
        }

        private static @NonNull Assessment rejected() { return REJECTED; }
        private static @NonNull Assessment counterRisk() { return COUNTER_RISK; }
        private static @NonNull Assessment unavailable() { return UNAVAILABLE; }
        private static @NonNull Assessment candidate(@NonNull WebAuthnCredentialState state) {
            return new Assessment(Status.CANDIDATE, state);
        }

        @NonNull Status status() { return this.status; }
        @NonNull Optional<@NonNull WebAuthnCredentialState> candidate() {
            return Optional.ofNullable(this.candidate);
        }

        @Override public @NonNull String toString() {
            return "WebAuthnCredentialState.Assessment{" + this.status + ", <no proof>}";
        }

        enum Status { CANDIDATE, REJECTED, COUNTER_RISK, UNAVAILABLE }
    }
}
