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
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.util.Optional;

/**
 * Identity and session fields from a checked assertion for later front-channel logout matching.
 * The application stores this reference alongside its own application session.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlSessionReference {
    private final @NonNull String connectionId;
    private final @NonNull String identityProviderEntityId;
    private final @NonNull SamlNameId nameId;
    private final @Nullable String sessionIndex;
    private final @Nullable Instant sessionNotOnOrAfter;

    SamlSessionReference(@NonNull String connectionId, @NonNull String identityProviderEntityId,
            @NonNull SamlNameId nameId, @Nullable String sessionIndex,
            @Nullable Instant sessionNotOnOrAfter) {
        this.connectionId = connectionId;
        this.identityProviderEntityId = identityProviderEntityId;
        this.nameId = nameId;
        this.sessionIndex = sessionIndex;
        this.sessionNotOnOrAfter = sessionNotOnOrAfter;
    }

    /**
     * Returns the application-defined IdP namespace.
     *
     * @return connection ID
     * @since 1.0.0
     */
    public @NonNull String getIdentityProviderConnectionId() { return connectionId; }
    /**
     * Returns the checked IdP entity ID.
     *
     * @return entity ID
     * @since 1.0.0
     */
    public @NonNull String getIdentityProviderEntityId() { return identityProviderEntityId; }
    /**
     * Returns the checked NameID and qualifiers used for logout matching.
     *
     * @return NameID
     * @since 1.0.0
     */
    public @NonNull SamlNameId getNameId() { return nameId; }
    /**
     * Returns the session index when the IdP supplied one.
     *
     * @return optional session index
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getSessionIndex() { return Optional.ofNullable(sessionIndex); }
    /**
     * Returns the IdP's session expiry when supplied.
     *
     * @return optional expiry
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull Instant> getSessionNotOnOrAfter() {
        return Optional.ofNullable(sessionNotOnOrAfter);
    }
    /**
     * Redacts the session identifiers.
     *
     * @return redacted description
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlSessionReference{<redacted>}"; }
}
