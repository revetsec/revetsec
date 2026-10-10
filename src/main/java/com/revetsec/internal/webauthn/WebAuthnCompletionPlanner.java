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

import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import com.revetsec.webauthn.WebAuthnSettings;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Two-read registration and authentication transaction planner. The first read supplies the
 * sealed challenge and lets the bounded browser parser discover a credential/account key. The
 * expanded read must include the same ceremony and clock again; every acceptance predicate and
 * mutation then participates in one store write. A plan is not a verification proof. Callers
 * must obtain a timely confirmed commit and satisfy the external recovery admission gate.
 */
final class WebAuthnCompletionPlanner {
    private final @NonNull String namespace;
    private final @NonNull String relyingPartyId;
    private final @NonNull WebAuthnCeremonyRecordCodec ceremonies;
    private final @NonNull WebAuthnCredentialRecordCodec credentials;
    private final @NonNull WebAuthnCredentialIndex indexes;
    private final @NonNull WebAuthnAccountFence fences;
    private final @NonNull WebAuthnNamespaceClock namespaceClock;
    private final @NonNull WebAuthnSettings settings;

    WebAuthnCompletionPlanner(@NonNull String namespace, @NonNull String relyingPartyId,
            @NonNull WebAuthnRecordCodec records) {
        this(namespace, relyingPartyId, records, WebAuthnSettings.builder().build());
    }

    WebAuthnCompletionPlanner(@NonNull String namespace, @NonNull String relyingPartyId,
            @NonNull WebAuthnRecordCodec records, @NonNull WebAuthnSettings settings) {
        this.namespace = requireNonNull(namespace);
        this.relyingPartyId = requireNonNull(relyingPartyId);
        requireNonNull(records);
        this.ceremonies = new WebAuthnCeremonyRecordCodec(namespace, relyingPartyId, records);
        this.credentials = new WebAuthnCredentialRecordCodec(namespace, relyingPartyId, records);
        this.indexes = new WebAuthnCredentialIndex(namespace, relyingPartyId, records);
        this.fences = new WebAuthnAccountFence(namespace, relyingPartyId, records);
        this.namespaceClock = new WebAuthnNamespaceClock(namespace, relyingPartyId, records);
        this.settings = requireNonNull(settings);
    }

    @NonNull Set<@NonNull WebAuthnStoreKey> firstKeys(byte @NonNull [] ceremonyId) {
        return Set.of(WebAuthnStoreKey.forCeremony(this.namespace, this.relyingPartyId,
                requireNonNull(ceremonyId)), this.namespaceClock.key());
    }

    @NonNull Optional<@NonNull RegistrationInspection> inspectRegistration(
            @NonNull WebAuthnStoreSnapshot first, byte @NonNull [] ceremonyId,
            byte @NonNull [] browserBinding, byte @NonNull [] responseBody,
            @NonNull Clock clock) throws WebAuthnRecordException, WebAuthnResponseException {
        WebAuthnCeremonyState pending = firstPending(first, ceremonyId, browserBinding,
                WebAuthnCeremonyState.Kind.REGISTRATION, clock);
        if (pending == null) return Optional.empty();
        byte[] handle = pending.expectedHandle();
        if (handle == null) throw new WebAuthnRecordException();
        WebAuthnAuthenticatorData.Registration registration = response(pending)
                .parseRegistration(responseBody, pending.challenge());
        Set<WebAuthnStoreKey> keys = completeKeys(ceremonyId, registration.credentialId(), handle);
        return Optional.of(new RegistrationInspection(pending, registration, keys));
    }

    @NonNull Optional<@NonNull AuthenticationInspection> inspectAuthentication(
            @NonNull WebAuthnStoreSnapshot first, byte @NonNull [] ceremonyId,
            byte @NonNull [] browserBinding, byte @NonNull [] responseBody,
            @NonNull Clock clock) throws WebAuthnRecordException, WebAuthnResponseException {
        WebAuthnCeremonyState pending = firstPending(first, ceremonyId, browserBinding, null, clock);
        if (pending == null) return Optional.empty();
        if (pending.kind() == WebAuthnCeremonyState.Kind.REGISTRATION)
            return Optional.empty();
        WebAuthnResponseJson.Assertion assertion = response(pending)
                .parseAssertion(responseBody, pending.challenge());
        byte[] handle = assertion.userHandle();
        byte[] pinned = pending.expectedHandle();
        if (pinned != null && !MessageDigest.isEqual(pinned, handle))
            return Optional.empty();
        Set<WebAuthnStoreKey> keys = completeKeys(ceremonyId, assertion.credentialId(), handle);
        return Optional.of(new AuthenticationInspection(pending, assertion, keys));
    }

    @NonNull Preparation prepareRegistration(@NonNull RegistrationInspection inspected,
            @NonNull WebAuthnStoreSnapshot expanded, @NonNull Clock clock)
            throws WebAuthnRecordException, WebAuthnResponseException {
        requireNonNull(inspected);
        requireNonNull(expanded);
        requireNonNull(clock);
        if (!expanded.getEntries().keySet().equals(inspected.keys))
            throw new IllegalArgumentException("Incomplete WebAuthn registration read");
        Instant observedAt = clock.instant();
        WebAuthnCeremonyConsumption.Prepared consumed = recheck(inspected.pending, expanded,
                observedAt, clock);
        if (consumed == null) return Preparation.rejected();
        byte[] handle = inspected.pending.expectedHandle();
        if (handle == null) throw new WebAuthnRecordException();
        byte[] id = inspected.registration.credentialId();
        WebAuthnStoreKey credentialKey = WebAuthnStoreKey.forCredential(this.namespace,
                this.relyingPartyId, id);
        WebAuthnStoreKey indexKey = WebAuthnStoreKey.forAccountCredentialIndex(this.namespace,
                this.relyingPartyId, handle);
        WebAuthnStoreKey fenceKey = WebAuthnStoreKey.forAccountFence(this.namespace,
                this.relyingPartyId, handle);
        if (!activeFence(expanded, fenceKey, clock)) return Preparation.rejected();
        if (expanded.getEntry(credentialKey) instanceof WebAuthnStoreEntry.Present present) {
            this.credentials.decodeRecord(credentialKey, present.getSealedBytes(), clock);
            return Preparation.rejected();
        }
        WebAuthnStoreEntry indexEntry = expanded.getEntry(indexKey);
        WebAuthnCredentialIndex.State index = indexEntry instanceof WebAuthnStoreEntry.Present present
                ? this.indexes.decode(indexKey, present.getSealedBytes(), clock) : this.indexes.empty(handle);
        if (index.contains(id)) throw new WebAuthnRecordException();
        if (index.size() >= this.settings.getMaximumExcludedCredentials())
            return Preparation.capacity();
        WebAuthnCredentialState credential;
        try {
            credential = WebAuthnCredentialState.fromRegistration(inspected.registration, handle);
        } catch (WebAuthnCborException failure) {
            throw new WebAuthnResponseException();
        }
        var encodedCredential = this.credentials.encode(credential);
        var encodedIndex = this.indexes.encode(index.withAdded(id));
        List<WebAuthnStoreWrite.Mutation> changes = new ArrayList<>(4);
        changes.add(consumed.mutation());
        changes.add(WebAuthnStoreWrite.Mutation.insert(encodedCredential.key(),
                encodedCredential.sealedBytes()));
        changes.add(indexEntry instanceof WebAuthnStoreEntry.Present
                ? WebAuthnStoreWrite.Mutation.replace(encodedIndex.key(), encodedIndex.sealedBytes())
                : WebAuthnStoreWrite.Mutation.insert(encodedIndex.key(), encodedIndex.sealedBytes()));
        addClockChange(changes, expanded, observedAt, clock);
        return Preparation.candidate(WebAuthnStoreWrite.fromSnapshotAndMutations(expanded, changes));
    }

    @NonNull Preparation prepareAuthentication(@NonNull AuthenticationInspection inspected,
            @NonNull WebAuthnStoreSnapshot expanded, @NonNull Clock clock)
            throws WebAuthnRecordException {
        requireNonNull(inspected);
        requireNonNull(expanded);
        requireNonNull(clock);
        if (!expanded.getEntries().keySet().equals(inspected.keys))
            throw new IllegalArgumentException("Incomplete WebAuthn authentication read");
        Instant observedAt = clock.instant();
        WebAuthnCeremonyConsumption.Prepared consumed = recheck(inspected.pending, expanded,
                observedAt, clock);
        if (consumed == null) return Preparation.rejected();
        byte[] id = inspected.assertion.credentialId();
        byte[] handle = inspected.assertion.userHandle();
        WebAuthnStoreKey credentialKey = WebAuthnStoreKey.forCredential(this.namespace,
                this.relyingPartyId, id);
        WebAuthnStoreKey indexKey = WebAuthnStoreKey.forAccountCredentialIndex(this.namespace,
                this.relyingPartyId, handle);
        WebAuthnStoreKey fenceKey = WebAuthnStoreKey.forAccountFence(this.namespace,
                this.relyingPartyId, handle);
        if (!activeFence(expanded, fenceKey, clock)) return Preparation.rejected();
        if (!(expanded.getEntry(credentialKey) instanceof WebAuthnStoreEntry.Present presentCredential))
            return Preparation.rejected();
        WebAuthnCredentialRecordCodec.Decoded decoded = this.credentials.decodeRecord(
                credentialKey, presentCredential.getSealedBytes(), clock);
        if (decoded.isRevoked()) return Preparation.rejected();
        WebAuthnCredentialState stored = decoded.activeState();
        if (stored == null) throw new WebAuthnRecordException();
        if (!MessageDigest.isEqual(decoded.userHandle(), handle)) return Preparation.rejected();
        if (!(expanded.getEntry(indexKey) instanceof WebAuthnStoreEntry.Present presentIndex))
            throw new WebAuthnRecordException();
        WebAuthnCredentialIndex.State index = this.indexes.decode(indexKey,
                presentIndex.getSealedBytes(), clock);
        if (!index.contains(id)) throw new WebAuthnRecordException();
        var assessment = stored.assess(inspected.assertion, inspected.pending.expectedHandle());
        if (assessment.status() == WebAuthnCredentialState.Assessment.Status.REJECTED)
            return Preparation.rejected();
        if (assessment.status() == WebAuthnCredentialState.Assessment.Status.COUNTER_RISK)
            return Preparation.counterRisk();
        if (assessment.status() == WebAuthnCredentialState.Assessment.Status.UNAVAILABLE)
            return Preparation.unavailable();
        WebAuthnCredentialState updated = assessment.candidate().orElseThrow();
        var encoded = this.credentials.encode(updated);
        List<WebAuthnStoreWrite.Mutation> changes = new ArrayList<>(3);
        changes.add(consumed.mutation());
        changes.add(WebAuthnStoreWrite.Mutation.replace(encoded.key(), encoded.sealedBytes()));
        addClockChange(changes, expanded, observedAt, clock);
        return Preparation.candidate(WebAuthnStoreWrite.fromSnapshotAndMutations(expanded, changes));
    }

    @NonNull Optional<@NonNull WebAuthnStoreWrite> clockOnlyAdvance(
            @NonNull WebAuthnStoreSnapshot snapshot, @NonNull Clock clock)
            throws WebAuthnRecordException {
        WebAuthnStoreWrite.Mutation mutation = this.namespaceClock.prepare(
                requireNonNull(snapshot), requireNonNull(clock).instant(), clock).mutation();
        return mutation == null ? Optional.empty() : Optional.of(
                WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, List.of(mutation)));
    }

    private @Nullable WebAuthnCeremonyState firstPending(@NonNull WebAuthnStoreSnapshot first,
            byte @NonNull [] ceremonyId, byte @NonNull [] browserBinding,
            WebAuthnCeremonyState.@Nullable Kind requiredKind, @NonNull Clock clock)
            throws WebAuthnRecordException {
        requireNonNull(first);
        requireNonNull(clock);
        WebAuthnStoreKey key = WebAuthnStoreKey.forCeremony(this.namespace,
                this.relyingPartyId, requireNonNull(ceremonyId));
        if (!first.getEntries().keySet().equals(firstKeys(ceremonyId)))
            throw new IllegalArgumentException("Invalid first WebAuthn read");
        var time = this.namespaceClock.prepare(first, clock.instant(), clock);
        if (!(first.getEntry(key) instanceof WebAuthnStoreEntry.Present)) return null;
        WebAuthnCeremonyState.Kind kind = requiredKind == null
                ? this.ceremonies.decode(key,
                ((WebAuthnStoreEntry.Present) first.getEntry(key)).getSealedBytes(), clock).kind()
                : requiredKind;
        return WebAuthnCeremonyConsumption.prepare(first, this.ceremonies, key, ceremonyId,
                requireNonNull(browserBinding), kind, time, clock)
                .map(WebAuthnCeremonyConsumption.Prepared::pending).orElse(null);
    }

    private WebAuthnCeremonyConsumption.@Nullable Prepared recheck(@NonNull WebAuthnCeremonyState first,
            @NonNull WebAuthnStoreSnapshot expanded, @NonNull Instant observedAt,
            @NonNull Clock clock) throws WebAuthnRecordException {
        WebAuthnStoreKey key = WebAuthnStoreKey.forCeremony(this.namespace,
                this.relyingPartyId, first.ceremonyId());
        var time = this.namespaceClock.prepare(expanded, observedAt, clock);
        var candidate = WebAuthnCeremonyConsumption.prepare(expanded, this.ceremonies, key,
                first.ceremonyId(), first.browserBinding(), first.kind(), time, clock);
        if (candidate.isEmpty() || !first.samePendingAs(candidate.orElseThrow().pending())) return null;
        return candidate.orElseThrow();
    }

    private boolean activeFence(@NonNull WebAuthnStoreSnapshot snapshot,
            @NonNull WebAuthnStoreKey key, @NonNull Clock clock) throws WebAuthnRecordException {
        WebAuthnStoreEntry entry = snapshot.getEntry(key);
        return entry instanceof WebAuthnStoreEntry.Present present
                && this.fences.decode(key, present.getSealedBytes(), clock).isActive();
    }

    private @NonNull WebAuthnResponseJson response(@NonNull WebAuthnCeremonyState pending) {
        return new WebAuthnResponseJson(new WebAuthnClientData(this.relyingPartyId,
                pending.allowedOrigins(), this.settings.getMaximumClientDataJsonBytes()),
                this.settings.getMaximumResponseBodyBytes(),
                this.settings.getMaximumClientDataJsonBytes(),
                this.settings.getMaximumAttestationObjectBytes(),
                this.settings.getMaximumAuthenticatorDataBytes());
    }

    private @NonNull Set<@NonNull WebAuthnStoreKey> completeKeys(byte @NonNull [] ceremonyId,
            byte @NonNull [] credentialId, byte @NonNull [] handle) {
        return Set.of(WebAuthnStoreKey.forCeremony(this.namespace, this.relyingPartyId, ceremonyId),
                this.namespaceClock.key(),
                WebAuthnStoreKey.forCredential(this.namespace, this.relyingPartyId, credentialId),
                WebAuthnStoreKey.forAccountCredentialIndex(this.namespace, this.relyingPartyId, handle),
                WebAuthnStoreKey.forAccountFence(this.namespace, this.relyingPartyId, handle));
    }

    private void addClockChange(@NonNull List<WebAuthnStoreWrite.@NonNull Mutation> changes,
            @NonNull WebAuthnStoreSnapshot snapshot, @NonNull Instant observedAt,
            @NonNull Clock clock)
            throws WebAuthnRecordException {
        WebAuthnStoreWrite.Mutation mutation = this.namespaceClock.prepare(
                snapshot, observedAt, clock).mutation();
        if (mutation != null) changes.add(mutation);
    }

    @Immutable
    static final class RegistrationInspection {
        private final @NonNull WebAuthnCeremonyState pending;
        private final WebAuthnAuthenticatorData.@NonNull Registration registration;
        private final @NonNull Set<@NonNull WebAuthnStoreKey> keys;
        private RegistrationInspection(@NonNull WebAuthnCeremonyState pending,
                WebAuthnAuthenticatorData.@NonNull Registration registration,
                @NonNull Set<@NonNull WebAuthnStoreKey> keys) {
            this.pending = pending;
            this.registration = registration;
            this.keys = keys;
        }
        @NonNull Set<@NonNull WebAuthnStoreKey> expandedKeys() { return this.keys; }
        @NonNull Instant expiresAt() { return this.pending.expiresAt(); }
        byte @NonNull [] approvedHandle() { return requireNonNull(this.pending.expectedHandle()); }
        byte @NonNull [] credentialId() { return this.registration.credentialId(); }
        @Override public @NonNull String toString() { return "RegistrationInspection{<unverified>}"; }
    }

    @Immutable
    static final class AuthenticationInspection {
        private final @NonNull WebAuthnCeremonyState pending;
        private final WebAuthnResponseJson.@NonNull Assertion assertion;
        private final @NonNull Set<@NonNull WebAuthnStoreKey> keys;
        private AuthenticationInspection(@NonNull WebAuthnCeremonyState pending,
                WebAuthnResponseJson.@NonNull Assertion assertion,
                @NonNull Set<@NonNull WebAuthnStoreKey> keys) {
            this.pending = pending;
            this.assertion = assertion;
            this.keys = keys;
        }
        @NonNull Set<@NonNull WebAuthnStoreKey> expandedKeys() { return this.keys; }
        @NonNull Instant expiresAt() { return this.pending.expiresAt(); }
        byte @NonNull [] userHandle() { return this.assertion.userHandle(); }
        byte @NonNull [] credentialId() { return this.assertion.credentialId(); }
        WebAuthnCeremonyState.@NonNull Kind kind() { return this.pending.kind(); }
        @Nullable String actionPurpose() { return this.pending.actionPurpose(); }
        @Override public @NonNull String toString() { return "AuthenticationInspection{<unverified>}"; }
    }

    @Immutable
    static final class Preparation {
        enum Status { CANDIDATE, REJECTED, COUNTER_RISK, CAPACITY, UNAVAILABLE }
        private static final @NonNull Preparation REJECTED = new Preparation(Status.REJECTED, null);
        private static final @NonNull Preparation COUNTER_RISK = new Preparation(Status.COUNTER_RISK, null);
        private static final @NonNull Preparation CAPACITY = new Preparation(Status.CAPACITY, null);
        private static final @NonNull Preparation UNAVAILABLE = new Preparation(Status.UNAVAILABLE, null);
        private final @NonNull Status status;
        private final @Nullable WebAuthnStoreWrite write;
        private Preparation(@NonNull Status status, @Nullable WebAuthnStoreWrite write) {
            this.status = status;
            this.write = write;
        }
        private static @NonNull Preparation candidate(@NonNull WebAuthnStoreWrite write) {
            return new Preparation(Status.CANDIDATE, write);
        }
        private static @NonNull Preparation rejected() { return REJECTED; }
        private static @NonNull Preparation counterRisk() { return COUNTER_RISK; }
        private static @NonNull Preparation capacity() { return CAPACITY; }
        private static @NonNull Preparation unavailable() { return UNAVAILABLE; }
        @NonNull Status status() { return this.status; }
        @NonNull Optional<@NonNull WebAuthnStoreWrite> write() { return Optional.ofNullable(this.write); }
        @Override public @NonNull String toString() { return "Preparation{" + this.status + ", no proof}"; }
    }
}
