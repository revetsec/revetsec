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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.webauthn.WebAuthnEngine;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Immutable WebAuthn relying party for discoverable, user-verified passkeys and security keys.
 * The app owns account approval, sessions, CSRF, durable storage, and the external recovery
 * barrier. Only confirmed, admitted store transitions can produce a browser request or proof.
 * Construction performs no application callback or storage I/O.
 *
 * @since 1.0.0
 */
@ThreadSafe
public final class WebAuthnRelyingParty {
    private static final @NonNull WebAuthnSettings DEFAULT_SETTINGS = WebAuthnSettings.builder().build();

    private final @NonNull String relyingPartyId;
    private final @NonNull String relyingPartyName;
    private final @NonNull String credentialNamespace;
    private final @NonNull WebAuthnSettings settings;
    private final @NonNull WebAuthnEngine engine;

    private WebAuthnRelyingParty(@NonNull Builder builder) {
        this.relyingPartyId = builder.relyingPartyId;
        this.relyingPartyName = requireNonNull(builder.relyingPartyName, "relyingPartyName");
        this.credentialNamespace = requireNonNull(builder.credentialNamespace, "credentialNamespace");
        this.settings = builder.settings == null ? DEFAULT_SETTINGS : builder.settings;
        Set<String> origins = requireNonNull(builder.allowedOrigins, "allowedOrigins");
        this.engine = new WebAuthnEngine(this.credentialNamespace, this.relyingPartyId,
                origins, requireNonNull(builder.store, "store"),
                requireNonNull(builder.stateSealer, "stateSealer"),
                requireNonNull(builder.recoveryGate, "recoveryGate"), builder.clock,
                this.settings);
    }

    /** Starts trusted RP configuration. The ID must be canonical lower-case DNS with at least
     * two labels. The application must select a registrable domain it controls.
     * @param relyingPartyId trusted RP ID
     * @return builder
     * @since 1.0.0 */
    @CheckReturnValue public static @NonNull Builder withRelyingPartyId(@NonNull String relyingPartyId) {
        WebAuthnStoreKey.forNamespaceClock("main", requireNonNull(relyingPartyId));
        return new Builder(relyingPartyId);
    }

    /** Creates and commits account-approved enrollment options. The first approved enrollment
     * inserts an absent account fence as active; an existing disabled fence remains disabled.
     * @param options approved account display data and handle
     * @param browserBinding application-held random browser-session binding
     * @return a committed browser request or fixed failure
     * @since 1.0.0 */
    @CheckReturnValue public @NonNull WebAuthnRegistrationRequestResult beginRegistrationResult(
            @NonNull WebAuthnRegistrationOptions options, @NonNull String browserBinding) {
        requireNonNull(options);
        byte[] binding = parseBinding(browserBinding);
        WebAuthnEngine.Start start = this.engine.beginRegistration(options.getUserHandle(), binding);
        return switch (start.status()) {
            case PREPARED -> WebAuthnRegistrationRequestResult.prepared(
                    registrationRequest(requireNonNull(start.request()), options));
            case REJECTED -> WebAuthnRegistrationRequestResult.rejected();
            case UNAVAILABLE -> WebAuthnRegistrationRequestResult.unavailable();
            case INDETERMINATE -> WebAuthnRegistrationRequestResult.indeterminate();
            case SUCCEEDED, COUNTER_RISK -> throw new IllegalStateException("Invalid begin outcome");
        };
    }

    /** Creates and commits discoverable sign-in options, without an allowCredentials list.
     * @param browserBinding application-held random browser-session binding
     * @return a committed browser request or fixed failure
     * @since 1.0.0 */
    @CheckReturnValue public @NonNull WebAuthnAuthenticationRequestResult beginAuthenticationResult(
            @NonNull String browserBinding) {
        WebAuthnEngine.Start start = this.engine.beginAuthentication(parseBinding(browserBinding));
        return authenticationRequestResult(start);
    }

    /** Creates account-pinned reauthentication options for a specific sensitive action.
     * @param expectedUserHandle app-approved account handle
     * @param actionPurpose bounded application action label
     * @param browserBinding application-held random browser-session binding
     * @return a committed browser request or fixed failure
     * @since 1.0.0 */
    @CheckReturnValue public @NonNull WebAuthnAuthenticationRequestResult beginReauthenticationResult(
            byte @NonNull [] expectedUserHandle, @NonNull String actionPurpose,
            @NonNull String browserBinding) {
        WebAuthnStoreKey.forAccountFence(this.credentialNamespace, this.relyingPartyId,
                requireNonNull(expectedUserHandle));
        requireNonNull(actionPurpose);
        if (actionPurpose.isEmpty() || actionPurpose.length() > 128)
            throw new IllegalArgumentException("Invalid WebAuthn action purpose");
        for (int i = 0; i < actionPurpose.length(); i++)
            if (actionPurpose.charAt(i) < 0x20 || actionPurpose.charAt(i) > 0x7e)
                throw new IllegalArgumentException("Invalid WebAuthn action purpose");
        byte[] binding = parseBinding(browserBinding);
        return authenticationRequestResult(this.engine.beginReauthentication(
                expectedUserHandle.clone(), actionPurpose, binding));
    }

    /** Consumes a raw browser registration response under its single-use ceremony.
     * @param ceremonyId opaque request handle
     * @param responseBody browser {@code PublicKeyCredential.toJSON()} bytes
     * @param browserBinding application-held browser-session binding
     * @return verified registration only after a confirmed admitted write
     * @since 1.0.0 */
    @CheckReturnValue public @NonNull WebAuthnRegistrationResult completeRegistrationResult(
            @NonNull String ceremonyId, byte @NonNull [] responseBody,
            @NonNull String browserBinding) {
        requireNonNull(ceremonyId);
        requireNonNull(responseBody);
        byte[] binding = parseBinding(browserBinding);
        byte[] id = parseCeremonyId(ceremonyId);
        if (id == null || responseBody.length == 0
                || responseBody.length > this.settings.getMaximumResponseBodyBytes())
            return WebAuthnRegistrationResult.rejected(WebAuthnRejectionReason.REJECTED);
        WebAuthnEngine.Finish finished = this.engine.completeRegistration(id, binding, responseBody);
        return switch (finished.status()) {
            case SUCCEEDED -> {
                WebAuthnEngine.Verified verified = requireNonNull(finished.verified());
                if (verified.kind() != WebAuthnEngine.Kind.REGISTRATION)
                    throw new IllegalStateException("Invalid registration fact");
                yield WebAuthnRegistrationResult.succeeded(new WebAuthnRegistration(
                        this.credentialNamespace, this.relyingPartyId,
                        verified.userHandle(), verified.credentialId()));
            }
            case REJECTED, COUNTER_RISK -> WebAuthnRegistrationResult.rejected(WebAuthnRejectionReason.REJECTED);
            case UNAVAILABLE -> WebAuthnRegistrationResult.unavailable();
            case INDETERMINATE -> WebAuthnRegistrationResult.indeterminate();
            case PREPARED -> throw new IllegalStateException("Invalid completion outcome");
        };
    }

    /** Consumes a raw browser sign-in or account-pinned reauthentication response.
     * @param ceremonyId opaque request handle
     * @param responseBody browser {@code PublicKeyCredential.toJSON()} bytes
     * @param browserBinding application-held browser-session binding
     * @return verified authentication only after a confirmed admitted write
     * @since 1.0.0 */
    @CheckReturnValue public @NonNull WebAuthnAuthenticationResult completeAuthenticationResult(
            @NonNull String ceremonyId, byte @NonNull [] responseBody,
            @NonNull String browserBinding) {
        requireNonNull(ceremonyId);
        requireNonNull(responseBody);
        byte[] binding = parseBinding(browserBinding);
        byte[] id = parseCeremonyId(ceremonyId);
        if (id == null || responseBody.length == 0
                || responseBody.length > this.settings.getMaximumResponseBodyBytes())
            return WebAuthnAuthenticationResult.rejected(WebAuthnRejectionReason.REJECTED);
        WebAuthnEngine.Finish finished = this.engine.completeAuthentication(id, binding, responseBody);
        return switch (finished.status()) {
            case SUCCEEDED -> {
                WebAuthnEngine.Verified verified = requireNonNull(finished.verified());
                WebAuthnAuthentication.Kind kind = switch (verified.kind()) {
                    case AUTHENTICATION -> WebAuthnAuthentication.Kind.SIGN_IN;
                    case REAUTHENTICATION -> WebAuthnAuthentication.Kind.REAUTHENTICATION;
                    case REGISTRATION -> throw new IllegalStateException("Invalid authentication fact");
                };
                yield WebAuthnAuthenticationResult.succeeded(new WebAuthnAuthentication(
                        this.credentialNamespace, this.relyingPartyId, verified.userHandle(),
                        verified.credentialId(), kind, verified.purpose()));
            }
            case REJECTED -> WebAuthnAuthenticationResult.rejected(WebAuthnRejectionReason.REJECTED);
            case COUNTER_RISK -> WebAuthnAuthenticationResult.rejected(WebAuthnRejectionReason.COUNTER_RISK);
            case UNAVAILABLE -> WebAuthnAuthenticationResult.unavailable();
            case INDETERMINATE -> WebAuthnAuthenticationResult.indeterminate();
            case PREPARED -> throw new IllegalStateException("Invalid completion outcome");
        };
    }

    /** Lists active credential IDs for an app-approved account. The application must authorize
     * the current session and enforce CSRF and management policy before calling this method.
     * A listed ID is not an authentication proof.
     * @param approvedUserHandle app-approved account handle
     * @return authoritative listing or unavailable
     * @since 1.0.0 */
    @CheckReturnValue public @NonNull WebAuthnCredentialListResult listCredentialsResult(
            byte @NonNull [] approvedUserHandle) {
        WebAuthnEngine.Management result = this.engine.listCredentials(requireNonNull(approvedUserHandle).clone());
        return switch (result.status()) {
            case LISTED -> WebAuthnCredentialListResult.listed(result.credentialIds());
            case UNAVAILABLE -> WebAuthnCredentialListResult.unavailable();
            case REMOVED, ABSENT, DISABLED, INDETERMINATE ->
                    throw new IllegalStateException("Invalid listing outcome");
        };
    }

    /** Permanently revokes a credential ID belonging to an app-approved account. The application
     * must authorize the current session and enforce CSRF and management policy. An uncertain
     * write requires authoritative reconciliation before another management action.
     * @param approvedUserHandle app-approved account handle
     * @param credentialId credential ID to revoke
     * @return confirmed removal, absence or fixed failure
     * @since 1.0.0 */
    @CheckReturnValue public @NonNull WebAuthnCredentialRemovalResult removeCredentialResult(
            byte @NonNull [] approvedUserHandle, byte @NonNull [] credentialId) {
        WebAuthnEngine.Management result = this.engine.removeCredential(
                requireNonNull(approvedUserHandle).clone(), requireNonNull(credentialId).clone());
        return switch (result.status()) {
            case REMOVED -> WebAuthnCredentialRemovalResult.removed();
            case ABSENT -> WebAuthnCredentialRemovalResult.absent();
            case UNAVAILABLE -> WebAuthnCredentialRemovalResult.unavailable();
            case INDETERMINATE -> WebAuthnCredentialRemovalResult.indeterminate();
            case LISTED, DISABLED -> throw new IllegalStateException("Invalid removal outcome");
        };
    }

    /** Disables an app-approved account's passkey fence, including pending ceremonies. The app
     * must authorize this action, coordinate its own account state, and reconcile uncertain
     * transitions before any future reopening. This method does not terminate app sessions.
     * @param approvedUserHandle app-approved account handle
     * @return confirmed disabled state or fixed failure
     * @since 1.0.0 */
    @CheckReturnValue public @NonNull WebAuthnAccountDisableResult disableAccountResult(
            byte @NonNull [] approvedUserHandle) {
        WebAuthnEngine.Management result = this.engine.disableAccount(requireNonNull(approvedUserHandle).clone());
        return switch (result.status()) {
            case DISABLED -> WebAuthnAccountDisableResult.disabled();
            case UNAVAILABLE -> WebAuthnAccountDisableResult.unavailable();
            case INDETERMINATE -> WebAuthnAccountDisableResult.indeterminate();
            case LISTED, REMOVED, ABSENT -> throw new IllegalStateException("Invalid disable outcome");
        };
    }

    private @NonNull WebAuthnAuthenticationRequestResult authenticationRequestResult(
            WebAuthnEngine.@NonNull Start start) {
        return switch (start.status()) {
            case PREPARED -> WebAuthnAuthenticationRequestResult.prepared(
                    authenticationRequest(requireNonNull(start.request())));
            case REJECTED -> WebAuthnAuthenticationRequestResult.rejected();
            case UNAVAILABLE -> WebAuthnAuthenticationRequestResult.unavailable();
            case INDETERMINATE -> WebAuthnAuthenticationRequestResult.indeterminate();
            case SUCCEEDED, COUNTER_RISK -> throw new IllegalStateException("Invalid begin outcome");
        };
    }

    private @NonNull WebAuthnBrowserRequest registrationRequest(WebAuthnEngine.@NonNull Request request,
            @NonNull WebAuthnRegistrationOptions options) {
        JsonObject rp = JsonObject.builder().put("id", this.relyingPartyId)
                .put("name", this.relyingPartyName).build();
        JsonObject user = JsonObject.builder().put("id", Base64Url.encode(options.getUserHandle()))
                .put("name", options.getUserName()).put("displayName", options.getUserDisplayName()).build();
        JsonArray parameters = JsonArray.fromElements(List.of(
                algorithm(-7), algorithm(-8), algorithm(-257)));
        List<JsonObject> exclusions = new ArrayList<>();
        for (byte[] id : request.excludedIds()) exclusions.add(JsonObject.builder()
                .put("type", "public-key").put("id", Base64Url.encode(id)).build());
        JsonObject selection = JsonObject.builder().put("residentKey", "required")
                .put("requireResidentKey", true).put("userVerification", "required").build();
        JsonObject publicKey = JsonObject.builder().put("rp", rp).put("user", user)
                .put("challenge", Base64Url.encode(request.challenge()))
                .put("pubKeyCredParams", parameters)
                .put("timeout", Long.valueOf(this.settings.getCeremonyLifetime().toMillis()))
                .put("excludeCredentials", JsonArray.fromElements(exclusions))
                .put("authenticatorSelection", selection)
                .put("attestation", "none")
                .put("extensions", JsonObject.builder().put("credProps", true).build())
                .build();
        return new WebAuthnBrowserRequest(Base64Url.encode(request.ceremonyId()), publicKey);
    }

    private @NonNull WebAuthnBrowserRequest authenticationRequest(WebAuthnEngine.@NonNull Request request) {
        JsonObject publicKey = JsonObject.builder()
                .put("challenge", Base64Url.encode(request.challenge()))
                .put("rpId", this.relyingPartyId)
                .put("timeout", Long.valueOf(this.settings.getCeremonyLifetime().toMillis()))
                .put("userVerification", "required").build();
        return new WebAuthnBrowserRequest(Base64Url.encode(request.ceremonyId()), publicKey);
    }

    private static @NonNull JsonObject algorithm(int identifier) {
        return JsonObject.builder().put("type", "public-key")
                .put("alg", JsonNumber.fromValue(Long.valueOf(identifier))).build();
    }

    private static byte @NonNull [] parseBinding(@NonNull String binding) {
        requireNonNull(binding);
        if (binding.length() != 43) throw new IllegalArgumentException("Invalid browser binding");
        try {
            byte[] decoded = Base64Url.decode(binding);
            if (decoded.length != 32) throw new IllegalArgumentException("Invalid browser binding");
            return decoded;
        } catch (EncodingException failure) {
            throw new IllegalArgumentException("Invalid browser binding");
        }
    }

    private static byte @Nullable [] parseCeremonyId(@NonNull String value) {
        if (value.length() != 43) return null;
        try {
            byte[] decoded = Base64Url.decode(value);
            return decoded.length == 32 ? decoded : null;
        } catch (EncodingException failure) {
            return null;
        }
    }

    /** Redacts configuration and protocol state.
     * @return a fixed description
     * @since 1.0.0 */
    @Override public @NonNull String toString() { return "WebAuthnRelyingParty{<redacted>}"; }

    /** One caller-thread trusted configuration builder.
     * @since 1.0.0 */
    @NotThreadSafe
    public static final class Builder {
        private final @NonNull String relyingPartyId;
        private @Nullable String relyingPartyName;
        private @Nullable Set<@NonNull String> allowedOrigins;
        private @Nullable String credentialNamespace;
        private @Nullable WebAuthnStore store;
        private @Nullable StateSealer stateSealer;
        private @Nullable WebAuthnRecoveryGate recoveryGate;
        private @Nullable WebAuthnSettings settings;
        private @NonNull Clock clock = Clock.systemUTC();
        private Builder(@NonNull String relyingPartyId) { this.relyingPartyId = relyingPartyId; }

        /** Sets a bounded RP display name.
         * @param name RP name
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder relyingPartyName(@NonNull String name) {
            this.relyingPartyName = displayName(name); return this;
        }
        /** Sets exact trusted HTTPS origins whose host is the configured RP ID.
         * @param origins one to eight canonical origins
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder allowedOrigins(@NonNull Set<@NonNull String> origins) {
            requireNonNull(origins);
            if (origins.isEmpty() || origins.size() > 8)
                throw new IllegalArgumentException("Invalid WebAuthn origin count");
            Set<String> copy = Set.copyOf(origins);
            for (String origin : copy) validOrigin(origin, this.relyingPartyId);
            this.allowedOrigins = copy; return this;
        }
        /** Sets the app-controlled credential namespace.
         * @param namespace namespace
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder credentialNamespace(@NonNull String namespace) {
            WebAuthnStoreKey.forNamespaceClock(requireNonNull(namespace), this.relyingPartyId);
            this.credentialNamespace = namespace; return this;
        }
        /** Selects the app-owned authoritative store.
         * @param store store
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder store(@NonNull WebAuthnStore store) {
            this.store = requireNonNull(store); return this;
        }
        /** Selects the app-provisioned record sealer.
         * @param sealer sealer
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder stateSealer(@NonNull StateSealer sealer) {
            this.stateSealer = requireNonNull(sealer); return this;
        }
        /** Selects the app-owned durable restore admission barrier.
         * @param gate gate
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder recoveryGate(@NonNull WebAuthnRecoveryGate gate) {
            this.recoveryGate = requireNonNull(gate); return this;
        }
        /** Selects bounded WebAuthn settings. Null restores the selected defaults.
         * @param settings settings or null for defaults
         * @return this builder
         * @since 1.0.0 */
        public @NonNull Builder settings(@Nullable WebAuthnSettings settings) {
            this.settings = settings; return this;
        }
        @NonNull Builder clockForTesting(@NonNull Clock clock) {
            this.clock = requireNonNull(clock); return this;
        }
        /** Builds the immutable RP without performing a store or gate callback.
         * @return configured relying party
         * @since 1.0.0 */
        @CheckReturnValue public @NonNull WebAuthnRelyingParty build() {
            return new WebAuthnRelyingParty(this);
        }
        /** Redacts configuration.
         * @return a fixed description
         * @since 1.0.0 */
        @Override public @NonNull String toString() { return "WebAuthnRelyingParty.Builder{<redacted>}"; }
    }

    private static @NonNull String displayName(@NonNull String name) {
        requireNonNull(name);
        com.revetsec.json.JsonString.fromValue(name);
        if (name.isEmpty() || name.codePointCount(0, name.length()) > 64)
            throw new IllegalArgumentException("Invalid WebAuthn RP name");
        for (int offset = 0; offset < name.length();) {
            int point = name.codePointAt(offset);
            if (Character.isISOControl(point)) throw new IllegalArgumentException("Invalid WebAuthn RP name");
            offset += Character.charCount(point);
        }
        return name;
    }

    private static void validOrigin(@NonNull String value, @NonNull String relyingPartyId) {
        requireNonNull(value);
        URI uri;
        try { uri = URI.create(value); }
        catch (IllegalArgumentException failure) { throw new IllegalArgumentException("Invalid WebAuthn origin"); }
        int port = uri.getPort();
        String expected = "https://" + relyingPartyId + (port == -1 ? "" : ":" + port);
        if (!"https".equals(uri.getScheme()) || !relyingPartyId.equals(uri.getHost())
                || uri.getRawUserInfo() != null || uri.getRawQuery() != null
                || uri.getRawFragment() != null || port == 0 || port > 65_535
                || uri.getRawPath() != null && !uri.getRawPath().isEmpty()
                || !value.equals(expected))
            throw new IllegalArgumentException("Invalid WebAuthn origin");
    }
}
