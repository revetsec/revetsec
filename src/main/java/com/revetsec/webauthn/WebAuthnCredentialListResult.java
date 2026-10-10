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
import java.util.ArrayList;
import java.util.List;

/** App-authorized, authoritative credential listing result. No identity proof is conferred.
 * @since 1.0.0 */
@Immutable
public abstract sealed class WebAuthnCredentialListResult permits
        WebAuthnCredentialListResult.Listed, WebAuthnCredentialListResult.Unavailable {
    private static final @NonNull Unavailable UNAVAILABLE = new Unavailable();
    WebAuthnCredentialListResult() { }
    static @NonNull WebAuthnCredentialListResult listed(@NonNull List<byte @NonNull []> ids) {
        return new Listed(ids);
    }
    static @NonNull WebAuthnCredentialListResult unavailable() { return UNAVAILABLE; }
    /** Redacts credential identifiers.
     * @return fixed description
     * @since 1.0.0 */
    @Override public final @NonNull String toString() { return "WebAuthnCredentialListResult{<redacted>}"; }

    /** The account's active credential IDs at the authoritative read point.
     * @since 1.0.0 */
    @Immutable public static final class Listed extends WebAuthnCredentialListResult {
        private final byte @NonNull [][] credentialIds;
        private Listed(@NonNull List<byte @NonNull []> ids) {
            this.credentialIds = new byte[ids.size()][];
            for (int i = 0; i < ids.size(); i++) this.credentialIds[i] = ids.get(i).clone();
        }
        /** Returns defensive copies of active credential IDs.
         * @return immutable list containing copied IDs
         * @since 1.0.0 */
        public @NonNull List<byte @NonNull []> getCredentialIds() {
            List<byte[]> copy = new ArrayList<>(this.credentialIds.length);
            for (byte[] id : this.credentialIds) copy.add(id.clone());
            return List.copyOf(copy);
        }
    }

    /** The authoritative listing could not be established.
     * @since 1.0.0 */
    @Immutable public static final class Unavailable extends WebAuthnCredentialListResult {
        private Unavailable() { }
    }
}
