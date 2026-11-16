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

package com.revetsec;

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;

/** Fixed, value-free codes for a builder's configuration shape. A diagnostic does not establish
 * runtime readiness, provider health, storage durability or deployment trust.
 * @since 1.0.0
 */
@Immutable
public enum ConfigurationDiagnostic {
    /** TOTP credential namespace is absent. */ TOTP_CREDENTIAL_NAMESPACE_REQUIRED("credentialNamespace", "com.revetsec.totp.TotpAuthenticator.Builder#credentialNamespace"),
    /** TOTP recovery epoch is absent. */ TOTP_RECOVERY_EPOCH_REQUIRED("recoveryEpoch", "com.revetsec.totp.TotpAuthenticator.Builder#recoveryEpoch"),
    /** TOTP authoritative store is absent. */ TOTP_STORE_REQUIRED("store", "com.revetsec.totp.TotpAuthenticator.Builder#store"),
    /** TOTP state sealer is absent. */ TOTP_STATE_SEALER_REQUIRED("stateSealer", "com.revetsec.totp.TotpAuthenticator.Builder#stateSealer"),
    /** TOTP recovery gate is absent. */ TOTP_RECOVERY_GATE_REQUIRED("recoveryGate", "com.revetsec.totp.TotpAuthenticator.Builder#recoveryGate"),
    /** WebAuthn relying-party name is absent. */ WEBAUTHN_RELYING_PARTY_NAME_REQUIRED("relyingPartyName", "com.revetsec.webauthn.WebAuthnRelyingParty.Builder#relyingPartyName"),
    /** WebAuthn credential namespace is absent. */ WEBAUTHN_CREDENTIAL_NAMESPACE_REQUIRED("credentialNamespace", "com.revetsec.webauthn.WebAuthnRelyingParty.Builder#credentialNamespace"),
    /** WebAuthn allowed origins are absent. */ WEBAUTHN_ALLOWED_ORIGINS_REQUIRED("allowedOrigins", "com.revetsec.webauthn.WebAuthnRelyingParty.Builder#allowedOrigins"),
    /** WebAuthn authoritative store is absent. */ WEBAUTHN_STORE_REQUIRED("store", "com.revetsec.webauthn.WebAuthnRelyingParty.Builder#store"),
    /** WebAuthn state sealer is absent. */ WEBAUTHN_STATE_SEALER_REQUIRED("stateSealer", "com.revetsec.webauthn.WebAuthnRelyingParty.Builder#stateSealer"),
    /** WebAuthn recovery gate is absent. */ WEBAUTHN_RECOVERY_GATE_REQUIRED("recoveryGate", "com.revetsec.webauthn.WebAuthnRelyingParty.Builder#recoveryGate"),

    /** Authorization endpoint required. */ OAUTH_AUTHORIZATION_ENDPOINT_REQUIRED("authorizationEndpoint", "REQUIRED", "Required configuration is missing.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#authorizationEndpoint"),
    /** Token endpoint required. */ OAUTH_TOKEN_ENDPOINT_REQUIRED("tokenEndpoint", "REQUIRED", "Required configuration is missing.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#tokenEndpoint"),
    /** Jwks endpoint required. */ OAUTH_JWKS_ENDPOINT_REQUIRED("jwksEndpoint", "REQUIRED", "Required configuration is missing.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#jwksEndpoint"),
    /** Client repository required. */ OAUTH_CLIENT_REPOSITORY_REQUIRED("clientRepository", "REQUIRED", "Required configuration is missing.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#clientRepository"),
    /** Store required. */ OAUTH_STORE_REQUIRED("store", "REQUIRED", "Required configuration is missing.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#store"),
    /** Signing keys required. */ OAUTH_SIGNING_KEYS_REQUIRED("signingKeys", "REQUIRED", "Required configuration is missing.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#signingKeys"),
    /** State sealer required. */ OAUTH_STATE_SEALER_REQUIRED("stateSealer", "REQUIRED", "Required configuration is missing.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#stateSealer"),
    /** Grant policy required. */ OAUTH_GRANT_POLICY_REQUIRED("grantPolicy", "REQUIRED", "Required configuration is missing.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#grantPolicy"),
    /** Resources required. */ OAUTH_RESOURCES_REQUIRED("resources", "REQUIRED", "Required configuration is missing.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#resources"),
    /** Authorization endpoint invalid. */ OAUTH_AUTHORIZATION_ENDPOINT_INVALID("authorizationEndpoint", "INVALID", "Configured route is invalid or conflicts with another route.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#authorizationEndpoint"),
    /** Token endpoint invalid. */ OAUTH_TOKEN_ENDPOINT_INVALID("tokenEndpoint", "INVALID", "Configured route is invalid or conflicts with another route.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#tokenEndpoint"),
    /** Jwks endpoint invalid. */ OAUTH_JWKS_ENDPOINT_INVALID("jwksEndpoint", "INVALID", "Configured route is invalid or conflicts with another route.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#jwksEndpoint"),
    /** Revocation endpoint invalid. */ OAUTH_REVOCATION_ENDPOINT_INVALID("revocationEndpoint", "INVALID", "Configured route is invalid or conflicts with another route.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#revocationEndpoint"),
    /** Introspection endpoint invalid. */ OAUTH_INTROSPECTION_ENDPOINT_INVALID("introspectionEndpoint", "INVALID", "Configured route is invalid or conflicts with another route.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#introspectionEndpoint"),
    /** Authorization interaction lifetime invalid. */ OAUTH_AUTHORIZATION_INTERACTION_LIFETIME_INVALID("authorizationInteractionLifetime", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#authorizationInteractionLifetime"),
    /** Authorization code lifetime invalid. */ OAUTH_AUTHORIZATION_CODE_LIFETIME_INVALID("authorizationCodeLifetime", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#authorizationCodeLifetime"),
    /** Access token lifetime invalid. */ OAUTH_ACCESS_TOKEN_LIFETIME_INVALID("accessTokenLifetime", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#accessTokenLifetime"),
    /** Refresh token idle lifetime invalid. */ OAUTH_REFRESH_TOKEN_IDLE_LIFETIME_INVALID("refreshTokenIdleLifetime", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#refreshTokenIdleLifetime"),
    /** Refresh token absolute lifetime invalid. */ OAUTH_REFRESH_TOKEN_ABSOLUTE_LIFETIME_INVALID("refreshTokenAbsoluteLifetime", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#refreshTokenAbsoluteLifetime"),
    /** Clock skew invalid. */ OAUTH_CLOCK_SKEW_INVALID("clockSkew", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#clockSkew"),
    /** Total deadline invalid. */ OAUTH_TOTAL_DEADLINE_INVALID("totalDeadline", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#totalDeadline"),
    /** Request timeout invalid. */ OAUTH_REQUEST_TIMEOUT_INVALID("requestTimeout", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#requestTimeout"),
    /** Public metadata http cache max age invalid. */ OAUTH_PUBLIC_METADATA_HTTP_CACHE_MAX_AGE_INVALID("publicMetadataHttpCacheMaxAge", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#publicMetadataHttpCacheMaxAge"),
    /** Maximum request body bytes invalid. */ OAUTH_MAXIMUM_REQUEST_BODY_BYTES_INVALID("maximumRequestBodyBytes", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumRequestBodyBytes"),
    /** Maximum raw query length invalid. */ OAUTH_MAXIMUM_RAW_QUERY_LENGTH_INVALID("maximumRawQueryLength", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumRawQueryLength"),
    /** Maximum header bytes invalid. */ OAUTH_MAXIMUM_HEADER_BYTES_INVALID("maximumHeaderBytes", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumHeaderBytes"),
    /** Maximum response body bytes invalid. */ OAUTH_MAXIMUM_RESPONSE_BODY_BYTES_INVALID("maximumResponseBodyBytes", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumResponseBodyBytes"),
    /** Maximum store record bytes invalid. */ OAUTH_MAXIMUM_STORE_RECORD_BYTES_INVALID("maximumStoreRecordBytes", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumStoreRecordBytes"),
    /** Maximum store commit attempts invalid. */ OAUTH_MAXIMUM_STORE_COMMIT_ATTEMPTS_INVALID("maximumStoreCommitAttempts", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumStoreCommitAttempts"),
    /** Maximum resources invalid. */ OAUTH_MAXIMUM_RESOURCES_INVALID("maximumResources", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumResources"),
    /** Maximum redirect uris invalid. */ OAUTH_MAXIMUM_REDIRECT_URIS_INVALID("maximumRedirectUris", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumRedirectUris"),
    /** Maximum scopes per resource invalid. */ OAUTH_MAXIMUM_SCOPES_PER_RESOURCE_INVALID("maximumScopesPerResource", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumScopesPerResource"),
    /** Maximum scope length invalid. */ OAUTH_MAXIMUM_SCOPE_LENGTH_INVALID("maximumScopeLength", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumScopeLength"),
    /** Maximum state length invalid. */ OAUTH_MAXIMUM_STATE_LENGTH_INVALID("maximumStateLength", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumStateLength"),
    /** Maximum client id length invalid. */ OAUTH_MAXIMUM_CLIENT_ID_LENGTH_INVALID("maximumClientIdLength", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumClientIdLength"),
    /** Maximum subject length invalid. */ OAUTH_MAXIMUM_SUBJECT_LENGTH_INVALID("maximumSubjectLength", "INVALID", "Configuration value is outside its supported range.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumSubjectLength"),
    /** Resources invalid. */ OAUTH_RESOURCES_INVALID("resources", "INVALID", "Configured resources are invalid.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#resources"),
    /** Refresh requires revocation endpoint. */ OAUTH_REFRESH_REQUIRES_REVOCATION_ENDPOINT("revocationEndpoint", "INCOMPATIBLE", "Configuration settings are incompatible.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#revocationEndpoint"),
    /** Issuer scheme incompatible. */ OAUTH_ISSUER_SCHEME_INCOMPATIBLE("issuer", "INCOMPATIBLE", "Configuration settings are incompatible.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#allowInsecureLoopback"),
    /** Request timeout exceeds deadline. */ OAUTH_REQUEST_TIMEOUT_EXCEEDS_DEADLINE("requestTimeout", "INCOMPATIBLE", "Configuration settings are incompatible.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#requestTimeout"),
    /** Code lifetime exceeds interaction. */ OAUTH_CODE_LIFETIME_EXCEEDS_INTERACTION("authorizationCodeLifetime", "INCOMPATIBLE", "Configuration settings are incompatible.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#authorizationCodeLifetime"),
    /** Access lifetime exceeds idle. */ OAUTH_ACCESS_LIFETIME_EXCEEDS_IDLE("accessTokenLifetime", "INCOMPATIBLE", "Configuration settings are incompatible.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#accessTokenLifetime"),
    /** Idle lifetime exceeds absolute. */ OAUTH_IDLE_LIFETIME_EXCEEDS_ABSOLUTE("refreshTokenIdleLifetime", "INCOMPATIBLE", "Configuration settings are incompatible.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#refreshTokenIdleLifetime"),
    /** Clock skew exceeds half access. */ OAUTH_CLOCK_SKEW_EXCEEDS_HALF_ACCESS("clockSkew", "INCOMPATIBLE", "Configuration settings are incompatible.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#clockSkew"),
    /** Store record exceeds sealer. */ OAUTH_STORE_RECORD_EXCEEDS_SEALER("maximumStoreRecordBytes", "INCOMPATIBLE", "Configuration settings are incompatible.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#maximumStoreRecordBytes"),
    /** Client metadata runtime incompatible. */ OAUTH_CLIENT_METADATA_RUNTIME_INCOMPATIBLE("clientMetadataPolicy", "INCOMPATIBLE", "Configuration settings are incompatible.", "com.revetsec.oauth.server.OAuthAuthorizationServer.Builder#clientMetadataPolicy");

    private final @NonNull String fieldCode;
    private final @NonNull String reasonCode;
    private final @NonNull String message;
    private final @NonNull String documentationReference;

    ConfigurationDiagnostic(@NonNull String fieldCode, @NonNull String documentationReference) {
        this(fieldCode, "REQUIRED", "Required configuration is missing.", documentationReference);
    }

    ConfigurationDiagnostic(@NonNull String fieldCode, @NonNull String reasonCode,
            @NonNull String message, @NonNull String documentationReference) {
        this.fieldCode = fieldCode;
        this.reasonCode = reasonCode;
        this.message = message;
        this.documentationReference = documentationReference;
    }

    /** Returns a fixed field identifier, never a supplied value.
     * @return field identifier
     * @since 1.0.0 */
    public @NonNull String getFieldCode() { return this.fieldCode; }

    /** Returns the fixed reason code.
     * @return {@code REQUIRED}, {@code INVALID} or {@code INCOMPATIBLE}
     * @since 1.0.0 */
    public @NonNull String getReasonCode() { return this.reasonCode; }

    /** Returns a fixed API documentation reference, without configuration data.
     * @return static documentation reference
     * @since 1.0.0 */
    public @NonNull String getDocumentationReference() { return this.documentationReference; }

    /** Returns a fixed explanation without configuration values.
     * @return static explanation
     * @since 1.0.0 */
    public @NonNull String getMessage() { return this.message; }
}
