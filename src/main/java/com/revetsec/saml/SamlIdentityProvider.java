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
import com.google.errorprone.annotations.CheckReturnValue;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.net.URI;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * An immutable application-approved IdP connection. The required connection ID is the application's
 * account and replay namespace; the self-asserted SAML entity ID cannot replace it. Metadata parsing
 * never automatically approves a connection.
 *
 * @since 1.0.0
 */
@Immutable
public final class SamlIdentityProvider {
    private final @NonNull String connectionId;
    private final @NonNull String entityId;
    private final @Nullable URI redirectSingleSignOnService;
    private final @Nullable URI postSingleSignOnService;
    private final @Nullable URI redirectSingleLogoutService;
    private final @NonNull List<@NonNull PublicKey> signingKeys;
    private final boolean wantAuthnRequestsSigned;
    private final boolean requireSignedAssertions;
    private final boolean allowUnsolicitedResponses;
    private final boolean allowAesCbcEncryption;
    private final @NonNull Set<@NonNull SamlCompatibilityMode> compatibility;
    private final @NonNull List<@NonNull String> authorizedIdentifierScopes;

    private SamlIdentityProvider(@NonNull Builder builder) {
        this.connectionId = Objects.requireNonNull(builder.connectionId);
        this.entityId = builder.entityId;
        this.redirectSingleSignOnService = builder.redirectSingleSignOnService;
        this.postSingleSignOnService = builder.postSingleSignOnService;
        this.redirectSingleLogoutService = builder.redirectSingleLogoutService;
        this.signingKeys = List.copyOf(builder.signingKeys);
        this.wantAuthnRequestsSigned = builder.wantAuthnRequestsSigned;
        this.requireSignedAssertions = builder.requireSignedAssertions;
        this.allowUnsolicitedResponses = builder.allowUnsolicitedResponses;
        this.allowAesCbcEncryption = builder.allowAesCbcEncryption;
        this.compatibility = Set.copyOf(builder.compatibility);
        this.authorizedIdentifierScopes = List.copyOf(builder.authorizedIdentifierScopes);
    }

    /**
     * Starts manual trust configuration for one IdP.
     *
     * @param entityId exact SAML IdP entity ID
     * @return a builder
     * @since 1.0.0
     */
    public static @NonNull Builder withEntityId(@NonNull String entityId) {
        if (Objects.requireNonNull(entityId).isEmpty() || entityId.length() > 2048)
            throw new IllegalArgumentException("Invalid IdP entity ID");
        return new Builder(entityId);
    }

    /**
     * Prefills a builder from application-approved metadata. The application must assign a
     * connection ID and decide whether to trust the supplied metadata source.
     *
     * @param metadata selected IdP metadata
     * @return a builder requiring a connection ID
     * @since 1.0.0
     */
    public static @NonNull Builder withMetadata(@NonNull SamlIdentityProviderMetadata metadata) {
        Objects.requireNonNull(metadata);
        List<PublicKey> keys = metadata.getSigningCertificates().stream()
                .map(X509Certificate::getPublicKey).toList();
        return withEntityId(metadata.getEntityId())
                .redirectSingleSignOnService(metadata.getRedirectSingleSignOnService().orElse(null))
                .postSingleSignOnService(metadata.getPostSingleSignOnService().orElse(null))
                .redirectSingleLogoutService(metadata.getRedirectSingleLogoutService().orElse(null))
                .authorizedIdentifierScopes(metadata.getAuthorizedIdentifierScopes())
                .signingKeys(keys).wantAuthnRequestsSigned(metadata.wantsAuthnRequestsSigned());
    }

    /**
     * Returns this value.
     *
     * @return the application-assigned connection ID
     * @since 1.0.0
     */
    public @NonNull String getConnectionId() { return connectionId; }
    /**
     * Returns this value.
     *
     * @return the IdP's exact entity ID
     * @since 1.0.0
     */
    public @NonNull String getEntityId() { return entityId; }
    /**
     * Redacts connection and trust details.
     *
     * @since 1.0.0
     */
    @Override public @NonNull String toString() { return "SamlIdentityProvider{<redacted>}"; }

    @Nullable URI redirectSingleSignOnService() { return redirectSingleSignOnService; }
    @Nullable URI postSingleSignOnService() { return postSingleSignOnService; }
    @Nullable URI redirectSingleLogoutService() { return redirectSingleLogoutService; }
    @NonNull List<@NonNull PublicKey> signingKeys() { return signingKeys; }
    boolean wantAuthnRequestsSigned() { return wantAuthnRequestsSigned; }
    boolean requireSignedAssertions() { return requireSignedAssertions; }
    boolean allowUnsolicitedResponses() {
        return allowUnsolicitedResponses || compatibility.contains(SamlCompatibilityMode.UNSOLICITED_RESPONSES);
    }
    boolean allowAesCbcEncryption() {
        return allowAesCbcEncryption || compatibility.contains(SamlCompatibilityMode.AES_CBC_ENCRYPTION);
    }
    boolean allowSha1Signatures() { return compatibility.contains(SamlCompatibilityMode.SHA1_SIGNATURES); }
    @NonNull List<@NonNull String> authorizedIdentifierScopes() { return authorizedIdentifierScopes; }

    /**
     * Configures one trusted IdP connection.
     *
     * @since 1.0.0
     */
    @NotThreadSafe
    @CheckReturnValue
    public static final class Builder {
        private final @NonNull String entityId;
        private @Nullable String connectionId;
        private @Nullable URI redirectSingleSignOnService;
        private @Nullable URI postSingleSignOnService;
        private @Nullable URI redirectSingleLogoutService;
        private @NonNull List<@NonNull PublicKey> signingKeys = List.of();
        private boolean wantAuthnRequestsSigned;
        private boolean requireSignedAssertions;
        private boolean allowUnsolicitedResponses;
        private boolean allowAesCbcEncryption;
        private @NonNull Set<@NonNull SamlCompatibilityMode> compatibility = Set.of();
        private @NonNull List<@NonNull String> authorizedIdentifierScopes = List.of();

        private Builder(@NonNull String entityId) { this.entityId = entityId; }

        /**
         * Configures this option.
         *
         * @param value application-unique connection namespace
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder connectionId(@Nullable String value) {
            this.connectionId = value;
            return this;
        }

        /**
         * Configures this option.
         *
         * @param value HTTPS HTTP-Redirect SSO endpoint
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder redirectSingleSignOnService(@Nullable URI value) {
            this.redirectSingleSignOnService = value;
            return this;
        }

        /**
         * Configures this IdP's HTTP-POST AuthnRequest endpoint.
         *
         * @param value HTTPS endpoint, or null to clear
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder postSingleSignOnService(@Nullable URI value) {
            this.postSingleSignOnService = value;
            return this;
        }
        /**
         * Configures the IdP's HTTP-Redirect Single Logout endpoint.
         *
         * @param value HTTPS endpoint, or null to clear
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder redirectSingleLogoutService(@Nullable URI value) {
            this.redirectSingleLogoutService = value;
            return this;
        }

        /**
         * Configures this option.
         *
         * @param value trusted current and rollover verification keys
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder signingKeys(@Nullable List<@NonNull PublicKey> value) {
            this.signingKeys = value == null ? List.of() : List.copyOf(value);
            return this;
        }

        /**
         * Configures this option.
         *
         * @param value whether the IdP requires signed AuthnRequests
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder wantAuthnRequestsSigned(@Nullable Boolean value) {
            this.wantAuthnRequestsSigned = Boolean.TRUE.equals(value);
            return this;
        }

        /**
         * Configures this option.
         *
         * @param value whether the Assertion must carry its own valid signature
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder requireSignedAssertions(@Nullable Boolean value) {
            this.requireSignedAssertions = Boolean.TRUE.equals(value);
            return this;
        }

        /**
         * Enables a separate IdP-initiated login operation for this connection. It is off by
         * default and still requires signature, audience, bearer and replay checks.
         *
         * @param value true to allow unsolicited responses, or null to reset to false
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder allowUnsolicitedResponses(@Nullable Boolean value) {
            this.allowUnsolicitedResponses = Boolean.TRUE.equals(value);
            return this;
        }
        /**
         * Enables decrypting AES-CBC assertions only beneath a verified Response signature.
         * It is off by default and never advertised in SP metadata.
         *
         * @param value true to enable CBC for this IdP, or null to reset to false
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder allowAesCbcEncryption(@Nullable Boolean value) {
            this.allowAesCbcEncryption = Boolean.TRUE.equals(value);
            return this;
        }
        /**
         * Sets explicit compatibility modes for this one trusted IdP connection.
         * Null clears all modes. SHA-1 stays rejected unless listed here.
         *
         * @param value enabled modes, or null to clear
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder compatibility(
                @Nullable Set<@NonNull SamlCompatibilityMode> value) {
            this.compatibility = value == null ? Set.of() : Set.copyOf(value);
            return this;
        }
        /**
         * Sets exact approved scopes for SAML subject-id and pairwise-id attributes. A scope
         * advertised by metadata is only a starting value; the application approves this list.
         *
         * @param value exact literal scopes, or null to clear
         * @return this builder
         * @since 1.0.0
         */
        @CheckReturnValue public @NonNull Builder authorizedIdentifierScopes(
                @Nullable List<@NonNull String> value) {
            this.authorizedIdentifierScopes = value == null ? List.of() : List.copyOf(value);
            return this;
        }

        /**
         * Returns this value.
         *
         * @return the immutable IdP connection
         * @since 1.0.0
         */
        public @NonNull SamlIdentityProvider build() {
            if (connectionId == null || connectionId.isEmpty() || connectionId.length() > 256)
                throw new IllegalStateException("IdP connection ID is required");
            if ((redirectSingleSignOnService == null && postSingleSignOnService == null)
                    || !safeEndpoint(redirectSingleSignOnService) || !safeEndpoint(postSingleSignOnService)
                    || !safeEndpoint(redirectSingleLogoutService))
                throw new IllegalStateException("An IdP HTTPS SSO endpoint is required");
            if (signingKeys.isEmpty() || signingKeys.size() > 8)
                throw new IllegalStateException("IdP signing keys are required");
            for (PublicKey key : signingKeys) {
                if (!(key instanceof RSAPublicKey rsa && rsa.getModulus().bitLength() >= 2048)
                        && !(key instanceof ECPublicKey ec && ec.getParams().getCurve().getField().getFieldSize() >= 256))
                    throw new IllegalStateException("Unsupported or weak IdP signing key");
            }
            if (authorizedIdentifierScopes.size() > 32 || authorizedIdentifierScopes.stream()
                    .anyMatch(scope -> scope.isEmpty() || scope.length() > 255
                            || scope.contains("@") || scope.contains("*") || scope.contains(" ")))
                throw new IllegalStateException("Invalid SAML identifier scope policy");
            return new SamlIdentityProvider(this);
        }

        private static boolean safeEndpoint(@Nullable URI endpoint) {
            return endpoint == null || ("https".equalsIgnoreCase(endpoint.getScheme())
                    && endpoint.getHost() != null && endpoint.getRawUserInfo() == null
                    && endpoint.getRawFragment() == null);
        }
    }
}
