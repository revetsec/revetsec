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

package com.revetsec.internal.webauthn;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Immutable pending ceremony or retained consumption marker. A matching record is only a
 * candidate for completion: the account, credential, recovery and observed-time predicates must
 * still be satisfied in one authoritative store transaction before any proof is released.
 */
@Immutable
final class WebAuthnCeremonyState {
    enum Kind { REGISTRATION, DISCOVERABLE_AUTHENTICATION, ACCOUNT_REAUTHENTICATION }

    private final @NonNull Kind kind;
    private final byte @NonNull [] ceremonyId;
    private final byte @NonNull [] challenge;
    private final byte @NonNull [] browserBinding;
    private final @NonNull Set<@NonNull String> allowedOrigins;
    private final byte @Nullable [] expectedHandle;
    private final @Nullable String actionPurpose;
    private final @NonNull Instant issuedAt;
    private final @NonNull Instant expiresAt;
    private final boolean consumed;

    private WebAuthnCeremonyState(@NonNull Kind kind, byte @NonNull [] ceremonyId,
            byte @NonNull [] challenge, byte @NonNull [] browserBinding,
            @NonNull Set<@NonNull String> allowedOrigins, byte @Nullable [] expectedHandle,
            @Nullable String actionPurpose, @NonNull Instant issuedAt,
            @NonNull Instant expiresAt, boolean consumed) {
        this.kind = requireNonNull(kind);
        this.ceremonyId = exact32(ceremonyId);
        this.challenge = exact32(challenge);
        this.browserBinding = exact32(browserBinding);
        this.allowedOrigins = Set.copyOf(requireNonNull(allowedOrigins));
        if (this.allowedOrigins.isEmpty() || this.allowedOrigins.size() > 8)
            throw new IllegalArgumentException("Invalid WebAuthn origin count");
        for (String origin : this.allowedOrigins) {
            if (origin == null || origin.length() > 267 || !isAscii(origin))
                throw new IllegalArgumentException("Invalid WebAuthn origin");
        }
        if (kind == Kind.DISCOVERABLE_AUTHENTICATION) {
            if (expectedHandle != null || actionPurpose != null)
                throw new IllegalArgumentException("Unexpected account binding");
        } else if (expectedHandle == null || expectedHandle.length < 1 || expectedHandle.length > 64) {
            throw new IllegalArgumentException("Invalid expected account handle");
        }
        if (kind == Kind.ACCOUNT_REAUTHENTICATION) {
            if (actionPurpose == null || actionPurpose.isEmpty() || actionPurpose.length() > 128
                    || !isPrintableAscii(actionPurpose))
                throw new IllegalArgumentException("Invalid action purpose");
        } else if (actionPurpose != null) {
            throw new IllegalArgumentException("Unexpected action purpose");
        }
        this.expectedHandle = expectedHandle == null ? null : expectedHandle.clone();
        this.actionPurpose = actionPurpose;
        this.issuedAt = requireNonNull(issuedAt);
        this.expiresAt = requireNonNull(expiresAt);
        Duration lifetime = Duration.between(issuedAt, expiresAt);
        if (lifetime.compareTo(Duration.ofSeconds(30)) < 0
                || lifetime.compareTo(Duration.ofMinutes(10)) > 0)
            throw new IllegalArgumentException("Invalid WebAuthn ceremony lifetime");
        this.consumed = consumed;
    }

    static @NonNull WebAuthnCeremonyState registration(byte @NonNull [] ceremonyId,
            byte @NonNull [] challenge, byte @NonNull [] browserBinding,
            @NonNull Set<@NonNull String> allowedOrigins, byte @NonNull [] approvedHandle,
            @NonNull Instant issuedAt, @NonNull Instant expiresAt) {
        return new WebAuthnCeremonyState(Kind.REGISTRATION, ceremonyId, challenge, browserBinding,
                allowedOrigins, approvedHandle, null, issuedAt, expiresAt, false);
    }

    static @NonNull WebAuthnCeremonyState discoverableAuthentication(byte @NonNull [] ceremonyId,
            byte @NonNull [] challenge, byte @NonNull [] browserBinding,
            @NonNull Set<@NonNull String> allowedOrigins, @NonNull Instant issuedAt,
            @NonNull Instant expiresAt) {
        return new WebAuthnCeremonyState(Kind.DISCOVERABLE_AUTHENTICATION, ceremonyId, challenge,
                browserBinding, allowedOrigins, null, null, issuedAt, expiresAt, false);
    }

    static @NonNull WebAuthnCeremonyState accountReauthentication(byte @NonNull [] ceremonyId,
            byte @NonNull [] challenge, byte @NonNull [] browserBinding,
            @NonNull Set<@NonNull String> allowedOrigins, byte @NonNull [] expectedHandle,
            @NonNull String actionPurpose, @NonNull Instant issuedAt, @NonNull Instant expiresAt) {
        return new WebAuthnCeremonyState(Kind.ACCOUNT_REAUTHENTICATION, ceremonyId, challenge,
                browserBinding, allowedOrigins, expectedHandle, actionPurpose, issuedAt, expiresAt, false);
    }

    static @NonNull WebAuthnCeremonyState restored(@NonNull Kind kind, byte @NonNull [] ceremonyId,
            byte @NonNull [] challenge, byte @NonNull [] browserBinding,
            @NonNull Set<@NonNull String> allowedOrigins, byte @Nullable [] expectedHandle,
            @Nullable String actionPurpose, @NonNull Instant issuedAt,
            @NonNull Instant expiresAt, boolean consumed) {
        return new WebAuthnCeremonyState(kind, ceremonyId, challenge, browserBinding, allowedOrigins,
                expectedHandle, actionPurpose, issuedAt, expiresAt, consumed);
    }

    @NonNull WebAuthnCeremonyState consume() {
        if (this.consumed) throw new IllegalStateException("Ceremony already consumed");
        return restored(this.kind, this.ceremonyId, this.challenge, this.browserBinding,
                this.allowedOrigins, this.expectedHandle, this.actionPurpose,
                this.issuedAt, this.expiresAt, true);
    }

    @NonNull Kind kind() { return this.kind; }
    byte @NonNull [] ceremonyId() { return this.ceremonyId.clone(); }
    byte @NonNull [] challenge() { return this.challenge.clone(); }
    byte @NonNull [] browserBinding() { return this.browserBinding.clone(); }
    @NonNull Set<@NonNull String> allowedOrigins() { return this.allowedOrigins; }
    byte @Nullable [] expectedHandle() { return this.expectedHandle == null ? null : this.expectedHandle.clone(); }
    @Nullable String actionPurpose() { return this.actionPurpose; }
    @NonNull Instant issuedAt() { return this.issuedAt; }
    @NonNull Instant expiresAt() { return this.expiresAt; }
    boolean isConsumed() { return this.consumed; }

    boolean isPendingAt(@NonNull Instant observedAt) {
        return !this.consumed && !requireNonNull(observedAt).isBefore(this.issuedAt)
                && observedAt.isBefore(this.expiresAt);
    }

    boolean matchesBrowserBinding(byte @NonNull [] candidate) {
        requireNonNull(candidate);
        return candidate.length == this.browserBinding.length
                && MessageDigest.isEqual(this.browserBinding, candidate);
    }

    boolean samePendingAs(@NonNull WebAuthnCeremonyState other) {
        requireNonNull(other);
        return !this.consumed && !other.consumed && this.kind == other.kind
                && Arrays.equals(this.ceremonyId, other.ceremonyId)
                && Arrays.equals(this.challenge, other.challenge)
                && Arrays.equals(this.browserBinding, other.browserBinding)
                && this.allowedOrigins.equals(other.allowedOrigins)
                && Arrays.equals(this.expectedHandle, other.expectedHandle)
                && Objects.equals(this.actionPurpose, other.actionPurpose)
                && this.issuedAt.equals(other.issuedAt) && this.expiresAt.equals(other.expiresAt);
    }

    @Override public @NonNull String toString() {
        return "WebAuthnCeremonyState{kind=" + this.kind + ", status="
                + (this.consumed ? "CONSUMED" : "PENDING") + ", details=<redacted>}";
    }

    private static byte @NonNull [] exact32(byte @NonNull [] bytes) {
        requireNonNull(bytes);
        if (bytes.length != 32) throw new IllegalArgumentException("Invalid WebAuthn random value");
        return Arrays.copyOf(bytes, bytes.length);
    }

    private static boolean isAscii(@NonNull String value) {
        return StandardCharsets.US_ASCII.newEncoder().canEncode(value);
    }

    private static boolean isPrintableAscii(@NonNull String value) {
        for (int index = 0; index < value.length(); index++)
            if (value.charAt(index) < 0x20 || value.charAt(index) > 0x7e) return false;
        return true;
    }
}
