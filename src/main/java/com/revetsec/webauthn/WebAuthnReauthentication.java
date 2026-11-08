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

/** Checked account-pinned, action-bound WebAuthn reauthentication after admitted commitment.
 * The application still authorizes its current session and atomically consumes its own action.
 * This fact is not a transferable permission and does not authorize replay or recovery.
 * @since 1.0.0 */
@Immutable
public final class WebAuthnReauthentication {
    private final @NonNull String credentialNamespace;
    private final @NonNull String relyingPartyId;
    private final byte @NonNull [] userHandle;
    private final byte @NonNull [] credentialId;
    private final @NonNull String actionPurpose;
    private final @NonNull String ceremonyId;

    WebAuthnReauthentication(@NonNull String credentialNamespace, @NonNull String relyingPartyId,
            byte @NonNull [] userHandle, byte @NonNull [] credentialId,
            @NonNull String actionPurpose, @NonNull String ceremonyId) {
        this.credentialNamespace = requireNonNull(credentialNamespace);
        this.relyingPartyId = requireNonNull(relyingPartyId);
        this.userHandle = requireNonNull(userHandle).clone();
        this.credentialId = requireNonNull(credentialId).clone();
        this.actionPurpose = requireNonNull(actionPurpose);
        this.ceremonyId = requireNonNull(ceremonyId);
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
    /** Returns the credential used to reauthenticate; it need not be a removal target.
     * @return defensive credential ID copy
     * @since 1.0.0 */
    public byte @NonNull [] getCredentialId() { return this.credentialId.clone(); }
    /** Returns the exact checked action label.
     * @return action purpose
     * @since 1.0.0 */
    public @NonNull String getActionPurpose() { return this.actionPurpose; }
    /** Returns the exact successfully completed ceremony handle. The application compares it
     * with its original pending action as well as current session, account, scope and purpose.
     * It is not a new correlation secret or permission, and must not be logged.
     * @return completed ceremony ID
     * @since 1.0.0 */
    public @NonNull String getCeremonyId() { return this.ceremonyId; }
    /** Redacts account, credential, ceremony and action data.
     * @return fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "WebAuthnReauthentication{identity=<redacted>}"; }
}
