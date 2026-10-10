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
import java.util.Optional;

/**
 * The result of completing an SP-initiated SAML login. Only success contains identity.
 * Backend uncertainty and outage remain distinct from a protocol rejection.
 *
 * @since 1.0.0
 */
@Immutable
public sealed interface SamlAuthenticationResult permits SamlAuthenticationResult.Succeeded,
        SamlAuthenticationResult.StatusReceived, SamlAuthenticationResult.Rejected,
        SamlAuthenticationResult.Unavailable,
        SamlAuthenticationResult.Indeterminate {
    /**
     * A fully validated, replay-fenced authentication.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Succeeded implements SamlAuthenticationResult {
        private final @NonNull SamlAuthentication authentication;
        private final @Nullable String applicationData;
        Succeeded(@NonNull SamlAuthentication authentication) { this(authentication, null); }
        Succeeded(@NonNull SamlAuthentication authentication, @Nullable String applicationData) {
            this.authentication = authentication;
            this.applicationData = applicationData;
        }
        /**
         * Returns the checked identity.
         *
         * @return authentication
         * @since 1.0.0
         */
        public @NonNull SamlAuthentication getAuthentication() { return authentication; }
        /**
         * Returns the local application hint from authenticated pending state. The application
         * validates it as a local route before use; it never came from RelayState.
         * @return optional application data
         * @since 1.0.0
         */
        public @NonNull Optional<@NonNull String> getApplicationData() {
            return Optional.ofNullable(applicationData);
        }
        /**
         * Redacts the identity.
         *
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "SamlAuthenticationResult.Succeeded{<redacted>}"; }
    }

    /**
     * A request-bound non-success IdP status. Authentication reports whether a verified Response
     * signature covered that status. It never contains an identity.
     *
     * @since 1.0.0
     */
    @Immutable
    final class StatusReceived implements SamlAuthenticationResult {
        private final @NonNull StatusCode statusCode;
        private final boolean authenticated;
        StatusReceived(@NonNull StatusCode statusCode, boolean authenticated) {
            this.statusCode = statusCode;
            this.authenticated = authenticated;
        }
        /**
         * Returns a bounded status classification.
         *
         * @return status code
         * @since 1.0.0
         */
        public @NonNull StatusCode getStatusCode() { return statusCode; }
        /**
         * Reports whether the trusted IdP signed the Response containing this status.
         *
         * @return true when authenticated
         * @since 1.0.0
         */
        public @NonNull Boolean isAuthenticated() { return authenticated; }
        /**
         * Redacts the received response.
         *
         * @return fixed description
         * @since 1.0.0
         */
        @Override public @NonNull String toString() {
            return "SamlAuthenticationResult.StatusReceived{" + statusCode + ", authenticated="
                    + authenticated + "}";
        }
    }

    /**
     * Bounded classification of a SAML non-success StatusCode.
     *
     * @since 1.0.0
     */
    @Immutable
    enum StatusCode {
        /** The IdP could not authenticate the principal. */ AUTHN_FAILED,
        /** The requested authentication context was unavailable. */ NO_AUTHN_CONTEXT,
        /** The IdP denied the request. */ REQUEST_DENIED,
        /** The IdP rejected the request as invalid. */ REQUESTER,
        /** The IdP failed to process the request. */ RESPONDER,
        /** The IdP rejected a SAML version. */ VERSION_MISMATCH,
        /** A validly shaped status used another code. */ OTHER
    }

    /**
     * A fixed local validation rejection.
     *
     * @since 1.0.0
     */
    @Immutable
    final class Rejected implements SamlAuthenticationResult {
        private final @NonNull Reason reason;
        Rejected(@NonNull Reason reason) { this.reason = reason; }
        /**
         * Returns the fixed rejection reason.
         *
         * @return reason
         * @since 1.0.0
         */
        public @NonNull Reason getReason() { return reason; }
        /**
         * Contains no submitted values.
         *
         * @since 1.0.0
         */
        @Override public @NonNull String toString() { return "SamlAuthenticationResult.Rejected{" + reason + "}"; }
    }

    /**
     * A required local capability or backend was unavailable.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Unavailable implements SamlAuthenticationResult {
        /** The required operation was unavailable. */ INSTANCE
    }

    /**
     * A replay mutation may have succeeded, so the caller must reconcile before retrying.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Indeterminate implements SamlAuthenticationResult {
        /** The replay mutation outcome is uncertain. */ INSTANCE
    }

    /**
     * Bounded local validation reasons, with no raw input attached.
     *
     * @since 1.0.0
     */
    @Immutable
    enum Reason {
        /** The browser-bound pending state is absent, expired or inconsistent. */ PENDING,
        /** The POST binding, XML or SAML structure is invalid. */ MESSAGE,
        /** A required signature is missing or invalid. */ SIGNATURE,
        /** Decryption failed, with one opaque reason for all decryption failures. */ DECRYPTION,
        /** The IdP issuer does not match the trusted connection. */ ISSUER,
        /** Destination does not match the configured ACS. */ DESTINATION,
        /** Request binding does not match. */ REQUEST_BINDING,
        /** The SAML status is not successful. */ STATUS,
        /** Subject or NameID is invalid. */ SUBJECT,
        /** Bearer confirmation is invalid. */ CONFIRMATION,
        /** Assertion conditions or audience are invalid. */ CONDITIONS,
        /** Authentication statement is invalid. */ AUTHN_STATEMENT,
        /** The signed assertion is too old or in the future. */ RESPONSE_AGE,
        /** The assertion has already been accepted. */ REPLAYED,
        /** Assertion content is unsupported or malformed. */ ASSERTION_SHAPE
    }
}
