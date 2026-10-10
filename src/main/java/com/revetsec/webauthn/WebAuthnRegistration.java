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

import javax.annotation.concurrent.Immutable;

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
    WebAuthnRegistration(@NonNull String credentialNamespace, @NonNull String relyingPartyId,
            byte @NonNull [] userHandle, byte @NonNull [] credentialId) {
        this.credentialNamespace = requireNonNull(credentialNamespace);
        this.relyingPartyId = requireNonNull(relyingPartyId);
        this.userHandle = requireNonNull(userHandle).clone();
        this.credentialId = requireNonNull(credentialId).clone();
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
    /** Redacts account and credential identifiers.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "WebAuthnRegistration{identity=<redacted>}"; }
}
