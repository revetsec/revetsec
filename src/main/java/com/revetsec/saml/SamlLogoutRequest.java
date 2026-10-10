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
package com.revetsec.saml;

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.util.List;
import org.jspecify.annotations.Nullable;

/**
 * A verified IdP-initiated logout request. The application matches the NameID and session
 * indexes to its own stored session references and terminates matching sessions.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlLogoutRequest {
    private final @NonNull String connectionId;
    private final @NonNull String requestId;
    private final @NonNull String spEntityId;
    private final @NonNull String idpEntityId;
    private final @Nullable String relayState;
    private final @NonNull SamlNameId nameId;
    private final @NonNull List<@NonNull String> sessionIndexes;

    SamlLogoutRequest(@NonNull String connectionId, @NonNull String spEntityId,
            @NonNull String idpEntityId, @NonNull String requestId, @Nullable String relayState,
            @NonNull SamlNameId nameId, @NonNull List<@NonNull String> sessionIndexes) {
        this.connectionId = connectionId;
        this.spEntityId = spEntityId;
        this.idpEntityId = idpEntityId;
        this.requestId = requestId;
        this.relayState = relayState;
        this.nameId = nameId;
        this.sessionIndexes = List.copyOf(sessionIndexes);
    }

    /**
     * Returns the application-defined IdP connection namespace.
     *
     * @return connection ID
     * @since 1.0.0
     */
    public @NonNull String getIdentityProviderConnectionId() { return connectionId; }
    /**
     * Returns the verified logout request ID.
     *
     * @return request ID
     * @since 1.0.0
     */
    public @NonNull String getRequestId() { return requestId; }
    /**
     * Returns the full verified NameID and qualifiers.
     *
     * @return NameID
     * @since 1.0.0
     */
    public @NonNull SamlNameId getNameId() { return nameId; }
    /**
     * Returns exact session indexes supplied by the IdP.
     *
     * @return immutable indexes
     * @since 1.0.0
     */
    public @NonNull List<@NonNull String> getSessionIndexes() { return sessionIndexes; }
    @NonNull String spEntityId() { return spEntityId; }
    @NonNull String idpEntityId() { return idpEntityId; }
    @Nullable String relayState() { return relayState; }
    /**
     * Redacts session identifiers.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlLogoutRequest{<redacted>}"; }
}
