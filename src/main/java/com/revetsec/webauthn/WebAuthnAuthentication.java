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
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/** Engine-created proof of a committed, stored-key WebAuthn authentication. The application
 * still decides whether to create a session or authorize a sensitive action.
 * @since 1.0.0 */
@Immutable
public final class WebAuthnAuthentication {
    private final @NonNull String credentialNamespace;
    private final @NonNull String relyingPartyId;
    private final byte @NonNull [] userHandle;
    private final byte @NonNull [] credentialId;
    private final @NonNull Kind kind;
    private final @Nullable String actionPurpose;
    WebAuthnAuthentication(@NonNull String credentialNamespace, @NonNull String relyingPartyId,
            byte @NonNull [] userHandle, byte @NonNull [] credentialId,
            @NonNull Kind kind, @Nullable String actionPurpose) {
        this.credentialNamespace = requireNonNull(credentialNamespace);
        this.relyingPartyId = requireNonNull(relyingPartyId);
        this.userHandle = requireNonNull(userHandle).clone();
        this.credentialId = requireNonNull(credentialId).clone();
        this.kind = requireNonNull(kind);
        this.actionPurpose = actionPurpose;
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
    /** Returns the verified credential ID.
     * @return defensive ID copy
     * @since 1.0.0 */
    public byte @NonNull [] getCredentialId() { return this.credentialId.clone(); }
    /** Returns whether this proof satisfied discoverable sign-in or account-pinned reauthentication.
     * @return ceremony kind
     * @since 1.0.0 */
    public @NonNull Kind getKind() { return this.kind; }
    /** Returns the action bound to an account-pinned reauthentication, when present.
     * @return action purpose
     * @since 1.0.0 */
    public @NonNull Optional<@NonNull String> getActionPurpose() {
        return Optional.ofNullable(this.actionPurpose);
    }
    /** Redacts the account, credential and action.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "WebAuthnAuthentication{identity=<redacted>}"; }

    /** The two authentication ceremonies.
     * @since 1.0.0 */
    @Immutable public enum Kind {
        /** Discoverable sign-in.
         * @since 1.0.0 */ SIGN_IN,
        /** Account-pinned sensitive action.
         * @since 1.0.0 */ REAUTHENTICATION
    }
}
