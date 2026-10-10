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

import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;

import static java.util.Objects.requireNonNull;

/** Library-prepared browser options and opaque single-use ceremony handle.
 * @since 1.0.0 */
@Immutable
public final class WebAuthnBrowserRequest {
    private final @NonNull String ceremonyId;
    private final @NonNull JsonObject publicKey;
    private final @NonNull String json;

    WebAuthnBrowserRequest(@NonNull String ceremonyId, @NonNull JsonObject publicKey) {
        this.ceremonyId = requireNonNull(ceremonyId);
        this.publicKey = requireNonNull(publicKey);
        this.json = JsonObject.builder().put("ceremonyId", ceremonyId)
                .put("publicKey", publicKey).build().toJson();
    }

    /** Returns the opaque ceremony handle for the completion call.
     * @return canonical base64url ceremony ID
     * @since 1.0.0 */
    public @NonNull String getCeremonyId() { return this.ceremonyId; }
    /** Returns the JSON options for the browser's WebAuthn conversion API.
     * @return immutable public-key options
     * @since 1.0.0 */
    public @NonNull JsonObject getPublicKeyOptions() { return this.publicKey; }
    /** Returns JSON containing {@code ceremonyId} and {@code publicKey}.
     * @return the browser request JSON
     * @since 1.0.0 */
    public @NonNull String getJson() { return this.json; }
    /** Redacts the challenge and account display fields.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "WebAuthnBrowserRequest{<redacted>}"; }
}
