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
import java.util.List;
import java.util.ArrayList;

/**
 * Identity released only after signature, request, conditions, audience and replay checks succeed.
 * The application must map it within the returned connection ID namespace; the IdP entity ID alone
 * is not a cross-tenant account key.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlAuthentication {
    private final @NonNull String connectionId;
    private final @NonNull String identityProviderEntityId;
    private final @NonNull String assertionId;
    private final @NonNull SamlNameId nameId;
    private final @NonNull Instant authnInstant;
    private final @Nullable String sessionIndex;
    private final @Nullable Instant sessionNotOnOrAfter;
    private final @Nullable String authnContextClassRef;
    private final @NonNull List<@NonNull SamlAttribute> attributes;
    private final @Nullable String subjectId;
    private final @Nullable String pairwiseId;
    private final @NonNull Instant assertionExpiresAt;
    private final boolean responseSigned;
    private final boolean assertionSigned;
    private final boolean unsolicited;
    private final boolean encrypted;

    SamlAuthentication(@NonNull String connectionId, @NonNull String identityProviderEntityId,
            SamlResponseSemantics.@NonNull Accepted accepted, boolean unsolicited) {
        this.connectionId = connectionId;
        this.identityProviderEntityId = identityProviderEntityId;
        this.assertionId = accepted.assertionId();
        this.nameId = accepted.nameId();
        this.authnInstant = accepted.authnInstant();
        this.sessionIndex = accepted.sessionIndex();
        this.sessionNotOnOrAfter = accepted.sessionNotOnOrAfter();
        this.authnContextClassRef = accepted.authnContextClassRef();
        this.attributes = accepted.attributes();
        this.subjectId = accepted.subjectId();
        this.pairwiseId = accepted.pairwiseId();
        this.assertionExpiresAt = accepted.expiresAt();
        this.responseSigned = accepted.responseSigned();
        this.assertionSigned = accepted.assertionSigned();
        this.unsolicited = unsolicited;
        this.encrypted = accepted.encrypted();
    }

    /**
     * Returns the required application connection namespace.
     *
     * @return connection ID
     * @since 1.0.0
     */
    public @NonNull String getIdentityProviderConnectionId() { return connectionId; }
    /**
     * Returns the display-only IdP entity ID.
     *
     * @return IdP entity ID
     * @since 1.0.0
     */
    public @NonNull String getIdentityProviderEntityId() { return identityProviderEntityId; }
    /**
     * Returns the covered assertion ID.
     *
     * @return assertion ID
     * @since 1.0.0
     */
    public @NonNull String getAssertionId() { return assertionId; }
    /**
     * Returns the validated NameID and its qualifiers.
     *
     * @return NameID
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull SamlNameId> getNameId() { return Optional.of(nameId); }
    /**
     * Returns a stable key only for a persistent NameID. The application also uses the IdP
     * connection ID as the account namespace.
     *
     * @return stable subject key when the identifier is persistent
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull SamlSubjectKey> getSubjectKey() {
        if (nameId.persistent()) return Optional.of(SamlSubjectKey.fromPersistentNameId(nameId));
        if (pairwiseId != null) return Optional.of(SamlSubjectKey.fromScopedIdentifier("pairwise", pairwiseId));
        if (subjectId != null) return Optional.of(SamlSubjectKey.fromScopedIdentifier("subject", subjectId));
        return Optional.empty();
    }
    /**
     * Returns a scope-authorized subject-id only when the configured connection approved its scope.
     *
     * @return optional subject-id
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getSubjectId() { return Optional.ofNullable(subjectId); }
    /**
     * Returns a scope-authorized pairwise-id only when the configured connection approved its scope.
     *
     * @return optional pairwise-id
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getPairwiseId() { return Optional.ofNullable(pairwiseId); }
    /**
     * Returns the checked authentication instant.
     *
     * @return instant
     * @since 1.0.0
     */
    public @NonNull Instant getAuthnInstant() { return authnInstant; }
    /**
     * Returns the checked authentication context class when supplied.
     *
     * @return optional context class URI
     * @since 1.0.0
     */
    public @NonNull Optional<@NonNull String> getAuthnContextClassRef() {
        return Optional.ofNullable(authnContextClassRef);
    }
    /**
     * Returns attributes from the covered assertion, including opaque complex values.
     *
     * @return immutable attributes
     * @since 1.0.0
     */
    public @NonNull List<@NonNull SamlAttribute> getAttributes() { return List.copyOf(attributes); }
    /**
     * Returns all text values whose exact attribute name matches.
     *
     * @param name exact SAML Attribute Name
     * @return immutable values
     * @since 1.0.0
     */
    public @NonNull List<@NonNull String> getAttributeValues(@NonNull String name) {
        java.util.Objects.requireNonNull(name);
        List<String> values = new ArrayList<>();
        for (SamlAttribute attribute : attributes)
            if (name.equals(attribute.getName())) values.addAll(attribute.getValues());
        return List.copyOf(values);
    }
    /**
     * Returns the checked session index when supplied.
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
     * Returns the checked fields to retain with an application session for logout matching.
     *
     * @return session reference
     * @since 1.0.0
     */
    public @NonNull SamlSessionReference getSessionReference() {
        return new SamlSessionReference(connectionId, identityProviderEntityId, nameId,
                sessionIndex, sessionNotOnOrAfter);
    }
    /**
     * Returns the final possible assertion acceptance instant.
     *
     * @return expiry
     * @since 1.0.0
     */
    public @NonNull Instant getAssertionExpiresAt() { return assertionExpiresAt; }
    /**
     * Reports verified Response coverage.
     *
     * @return true when Response was signed
     * @since 1.0.0
     */
    public @NonNull Boolean isResponseSigned() { return responseSigned; }
    /**
     * Reports verified Assertion coverage.
     *
     * @return true when Assertion was signed
     * @since 1.0.0
     */
    public @NonNull Boolean isAssertionSigned() { return assertionSigned; }
    /**
     * Reports whether this was an explicitly enabled IdP-initiated login.
     *
     * @return true for unsolicited login
     * @since 1.0.0
     */
    public @NonNull Boolean isUnsolicited() { return unsolicited; }
    /**
     * Reports whether an EncryptedAssertion was decrypted before validation.
     *
     * @return true when assertion encryption was used
     * @since 1.0.0
     */
    public @NonNull Boolean isAssertionEncrypted() { return encrypted; }
    /**
     * Redacts the identity.
     *
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlAuthentication{<redacted>}"; }
}
