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

package com.revetsec.webauthn;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.nio.ByteBuffer;
import java.util.Optional;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/** Engine-created proof of a committed credential enrollment for an app-approved account.
 * This does not create an application session.
 * @since 1.0.0 */
@Immutable
public final class WebAuthnRegistration {
    private final @NonNull String credentialNamespace;
    private final @NonNull String relyingPartyId;
    private final byte @NonNull [] userHandle;
    private final byte @NonNull [] credentialId;
    private final @Nullable UUID aaguid;
    private final boolean backupEligible;
    private final boolean backedUp;
    private final boolean userVerifiedAtRegistration;
    WebAuthnRegistration(@NonNull String credentialNamespace, @NonNull String relyingPartyId,
            byte @NonNull [] userHandle, byte @NonNull [] credentialId, byte @NonNull [] aaguid,
            boolean backupEligible, boolean backedUp, boolean userVerifiedAtRegistration) {
        this.credentialNamespace = requireNonNull(credentialNamespace);
        this.relyingPartyId = requireNonNull(relyingPartyId);
        this.userHandle = requireNonNull(userHandle).clone();
        this.credentialId = requireNonNull(credentialId).clone();
        if (requireNonNull(aaguid).length != 16 || (backedUp && !backupEligible))
            throw new IllegalArgumentException("Invalid WebAuthn registration metadata");
        ByteBuffer identifier = ByteBuffer.wrap(aaguid);
        long most = identifier.getLong();
        long least = identifier.getLong();
        this.aaguid = most == 0 && least == 0 ? null : new UUID(most, least);
        this.backupEligible = backupEligible;
        this.backedUp = backedUp;
        this.userVerifiedAtRegistration = userVerifiedAtRegistration;
    }
    /** Returns the configured namespace.
     * @return namespace
     * @since 1.0.0 */
    public @NonNull String getCredentialNamespace() { return this.credentialNamespace; }
    /** Returns the configured RP ID.
     * @return relying-party ID
     * @since 1.0.0 */
    public @NonNull String getRelyingPartyId() { return this.relyingPartyId; }
    /** Returns the authoritative account handle.
     * @return defensive handle copy
     * @since 1.0.0 */
    public byte @NonNull [] getUserHandle() { return this.userHandle.clone(); }
    /** Returns the newly registered credential ID.
     * @return defensive ID copy
     * @since 1.0.0 */
    public byte @NonNull [] getCredentialId() { return this.credentialId.clone(); }
    /** Returns the display-only authenticator model identifier when the client supplied a nonzero value.
     * Under none attestation this value is not authenticated and must not drive authorization or policy.
     * @return authenticator model identifier, or empty for the zero AAGUID
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull UUID> getAaguid() { return Optional.ofNullable(this.aaguid); }
    /** Returns whether the credential is eligible for backup.
     * @return backup eligibility
     * @since 1.0.0 */
    public @NonNull Boolean isBackupEligible() { return Boolean.valueOf(this.backupEligible); }
    /** Returns whether the credential was backed up when registered.
     * @return backup state at registration
     * @since 1.0.0 */
    public @NonNull Boolean isBackedUp() { return Boolean.valueOf(this.backedUp); }
    /** Returns whether user verification was observed when this credential was registered.
     * This release requires user verification for every registration, so the value is always {@code true}.
     * @return registration user-verification fact
     * @since 1.0.0 */
    public @NonNull Boolean isUserVerifiedAtRegistration() {
        return Boolean.valueOf(this.userVerifiedAtRegistration);
    }
    /** Redacts account and credential identifiers.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "WebAuthnRegistration{identity=<redacted>}"; }
}
