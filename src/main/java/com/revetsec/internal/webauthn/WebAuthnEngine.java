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

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.EntropySource;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnSettings;
import com.revetsec.webauthn.WebAuthnStore;
import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreCommitReceipt;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/** Internal bridge: only confirmed, recovery-admitted transitions carry a browser request or fact. */
@ThreadSafe
public final class WebAuthnEngine {
    private final @NonNull String namespace;
    private final @NonNull String relyingPartyId;
    private final @NonNull Set<@NonNull String> origins;
    private final @NonNull Duration ceremonyLifetime;
    private final int maximumExcludedCredentials;
    private final @NonNull EntropySource entropy;
    private final @NonNull WebAuthnRecoveryGate recoveryGate;
    private final @NonNull WebAuthnStoreCoordinator coordinator;
    private final @NonNull WebAuthnRecordCodec records;
    private final @NonNull WebAuthnCompletionRunner completion;
    private final @NonNull WebAuthnCeremonyRecordCodec ceremonies;
    private final @NonNull WebAuthnNamespaceClock namespaceClock;
    private final @NonNull WebAuthnAccountFence fences;
    private final @NonNull WebAuthnCredentialIndex indexes;
    private final @NonNull WebAuthnCredentialRemoval removal;

    public WebAuthnEngine(@NonNull String namespace, @NonNull String relyingPartyId,
            @NonNull Set<@NonNull String> origins, @NonNull WebAuthnStore store,
            @NonNull StateSealer sealer, @NonNull WebAuthnRecoveryGate recoveryGate,
            @NonNull Clock wallClock, @NonNull WebAuthnSettings settings) {
        this.namespace = requireNonNull(namespace);
        this.relyingPartyId = requireNonNull(relyingPartyId);
        this.origins = Set.copyOf(requireNonNull(origins));
        requireNonNull(wallClock);
        requireNonNull(settings);
        this.ceremonyLifetime = settings.getCeremonyLifetime();
        this.maximumExcludedCredentials = settings.getMaximumExcludedCredentials();
        this.entropy = EntropySource.fromDefaults();
        this.recoveryGate = requireNonNull(recoveryGate);
        WebAuthnRecordCodec records = new WebAuthnRecordCodec(requireNonNull(sealer));
        this.records = records;
        this.ceremonies = new WebAuthnCeremonyRecordCodec(namespace, relyingPartyId, records);
        this.namespaceClock = new WebAuthnNamespaceClock(namespace, relyingPartyId, records);
        this.coordinator = new WebAuthnStoreCoordinator(requireNonNull(store), settings.getOperationTimeout(), wallClock, this.namespaceClock);
        this.fences = new WebAuthnAccountFence(namespace, relyingPartyId, records);
        this.indexes = new WebAuthnCredentialIndex(namespace, relyingPartyId, records);
        this.removal = new WebAuthnCredentialRemoval(namespace, relyingPartyId, records);
        this.completion = new WebAuthnCompletionRunner(this.coordinator,
                new WebAuthnCompletionPlanner(namespace, relyingPartyId, records, settings),
                wallClock, recoveryGate);
    }

    public @NonNull Start beginRegistration(byte @NonNull [] approvedHandle,
            byte @NonNull [] browserBinding) {
        WebAuthnStoreKey.forAccountFence(this.namespace, this.relyingPartyId,
                requireNonNull(approvedHandle));
        return begin(WebAuthnCeremonyState.Kind.REGISTRATION, approvedHandle,
                requireNonNull(browserBinding), null);
    }

    public @NonNull Start beginAuthentication(byte @NonNull [] browserBinding) {
        return begin(WebAuthnCeremonyState.Kind.DISCOVERABLE_AUTHENTICATION, null,
                requireNonNull(browserBinding), null);
    }

    public @NonNull Start beginReauthentication(byte @NonNull [] approvedHandle,
            @NonNull String purpose, byte @NonNull [] browserBinding) {
        WebAuthnStoreKey.forAccountFence(this.namespace, this.relyingPartyId,
                requireNonNull(approvedHandle));
        return begin(WebAuthnCeremonyState.Kind.ACCOUNT_REAUTHENTICATION, approvedHandle,
                requireNonNull(browserBinding), requireNonNull(purpose));
    }

    public @NonNull Finish completeRegistration(byte @NonNull [] ceremonyId,
            byte @NonNull [] browserBinding, byte @NonNull [] responseBody) {
        return convert(this.completion.completeRegistrationFact(ceremonyId, browserBinding, responseBody));
    }

    public @NonNull Finish completeAuthentication(byte @NonNull [] ceremonyId,
            byte @NonNull [] browserBinding, byte @NonNull [] responseBody) {
        return convert(this.completion.completeAuthenticationFact(ceremonyId, browserBinding, responseBody));
    }

    public @NonNull Management listCredentials(byte @NonNull [] approvedHandle) {
        WebAuthnStoreKey.forAccountFence(this.namespace, this.relyingPartyId,
                requireNonNull(approvedHandle));
        return manage(ManagementOperation.LIST, approvedHandle, null);
    }

    public @NonNull Management removeCredential(byte @NonNull [] approvedHandle,
            byte @NonNull [] credentialId) {
        this.removal.keys(requireNonNull(approvedHandle), requireNonNull(credentialId));
        return manage(ManagementOperation.REMOVE, approvedHandle, credentialId);
    }

    public @NonNull Management disableAccount(byte @NonNull [] approvedHandle) {
        WebAuthnStoreKey.forAccountFence(this.namespace, this.relyingPartyId,
                requireNonNull(approvedHandle));
        return manage(ManagementOperation.DISABLE, approvedHandle, null);
    }

    /** Privileged factual CAS reseal of one permanent WAR2 row. */
    public @NonNull WebAuthnStoreCommitReceipt resealStoreEntry(@NonNull WebAuthnStoreKey key) {
        requireNonNull(key);
        String address=this.namespaceClock.key().getStorageKey();
        String scope=address.substring(0,address.indexOf(":NAMESPACE_CLOCK:")+1);
        if(key.getKind()==WebAuthnStoreKey.Kind.CEREMONY || !key.getStorageKey().startsWith(scope))
            throw new IllegalArgumentException("Invalid WebAuthn maintenance key");
        var attempt=this.coordinator.begin();Duration budget=attempt.remainingBudget();
        if(budget==null)return WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE);
        WebAuthnRecoveryGate.Permit permit;
        try{permit=this.recoveryGate.acquire(budget);}catch(VirtualMachineError fatal){throw fatal;}
        catch(Throwable failure){WebAuthnStoreCoordinator.preserveInterrupt(failure);return WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE);}
        if(permit==null)return WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE);
        attempt.admit(permit);
        WebAuthnStoreCommitReceipt result=WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE);
        try{
            if(attempt.remainingBudget()!=null && current(permit)){
                do{result=resealAdmitted(attempt,key);}while(attempt.retryAfterConflict());
            }
        }catch(VirtualMachineError fatal){close(permit);throw fatal;}
        catch(Throwable failure){WebAuthnStoreCoordinator.preserveInterrupt(failure);result=attempt.hasMutationEffect()?attempt.lastReceipt():WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE);}
        close(permit); // Effect-only acknowledgement remains factual after close/deadline failure.
        return result;
    }
    private @NonNull WebAuthnStoreCommitReceipt resealAdmitted(WebAuthnStoreCoordinator.@NonNull Attempt attempt,
            @NonNull WebAuthnStoreKey key) throws WebAuthnRecordException {
        Set<WebAuthnStoreKey> keys=key.equals(this.namespaceClock.key())?Set.of(key):Set.of(key,this.namespaceClock.key());
        var read=attempt.read(keys);
        if(!read.isAvailable())return WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE);
        if(!(read.getSnapshot().getEntry(key) instanceof WebAuthnStoreEntry.Present present))
            return WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.CONFLICT);
        byte[] resealed=this.records.resealAdmitted(key,present.getSealedBytes(),attempt.authorityClock());
        try{return attempt.commitRaw(List.of(WebAuthnStoreWrite.Mutation.replace(key,resealed)));}
        finally{Arrays.fill(resealed,(byte)0);}
    }

    private @NonNull Management manage(@NonNull ManagementOperation operation,
            byte @NonNull [] approvedHandle,byte @Nullable [] credentialId) {
        var attempt=this.coordinator.begin();Duration budget=attempt.remainingBudget();
        if(budget==null)return Management.failure(ManagementStatus.UNAVAILABLE);
        WebAuthnRecoveryGate.Permit permit;
        try{permit=this.recoveryGate.acquire(budget);}catch(VirtualMachineError fatal){throw fatal;}
        catch(Throwable failure){WebAuthnStoreCoordinator.preserveInterrupt(failure);return Management.failure(ManagementStatus.UNAVAILABLE);}
        if(permit==null)return Management.failure(ManagementStatus.UNAVAILABLE);
        attempt.admit(permit);
        Management result=Management.failure(ManagementStatus.UNAVAILABLE);
        try{
            if(attempt.remainingBudget()!=null && current(permit)){
                do{result=manageAdmitted(attempt,operation,approvedHandle,credentialId);}while(attempt.retryAfterConflict());
                if(normal(result.status()) && !attempt.finalAdmission(null))result=failedManagement(attempt);
                if(attempt.remainingBudget()==null || !current(permit))result=failedManagement(attempt);
            }
        }catch(VirtualMachineError fatal){close(permit);throw fatal;}
        catch(Throwable failure){WebAuthnStoreCoordinator.preserveInterrupt(failure);result=failedManagement(attempt);}
        if(!close(permit))result=failedManagement(attempt);
        if(normal(result.status()) && !attempt.releaseAllowed(null))result=failedManagement(attempt);
        return result;
    }
    private static boolean normal(@NonNull ManagementStatus status){
        return status!=ManagementStatus.UNAVAILABLE && status!=ManagementStatus.INDETERMINATE && status!=ManagementStatus.RECONCILIATION_REQUIRED;
    }
    private static @NonNull Management failedManagement(WebAuthnStoreCoordinator.@NonNull Attempt attempt){
        return Management.failure(switch(attempt.failed()){
            case INDETERMINATE -> ManagementStatus.INDETERMINATE;
            case RECONCILIATION_REQUIRED -> ManagementStatus.RECONCILIATION_REQUIRED;
            default -> ManagementStatus.UNAVAILABLE;
        });
    }

    private @NonNull Management manageAdmitted(WebAuthnStoreCoordinator.@NonNull Attempt attempt,
            @NonNull ManagementOperation operation, byte @NonNull [] approvedHandle,
            byte @Nullable [] credentialId) {
        WebAuthnStoreKey fenceKey = WebAuthnStoreKey.forAccountFence(
                this.namespace, this.relyingPartyId, approvedHandle);
        WebAuthnStoreKey indexKey = WebAuthnStoreKey.forAccountCredentialIndex(
                this.namespace, this.relyingPartyId, approvedHandle);
        Set<WebAuthnStoreKey> keys = switch (operation) {
            case LIST -> Set.of(fenceKey, indexKey, this.namespaceClock.key());
            case REMOVE -> this.removal.keys(approvedHandle, requireNonNull(credentialId)).all();
            case DISABLE -> Set.of(fenceKey, indexKey, this.namespaceClock.key());
        };
        var read = attempt.read(keys);
        if (!read.isAvailable()) return Management.failure(ManagementStatus.UNAVAILABLE);
        WebAuthnStoreSnapshot snapshot = read.getSnapshot();
        Clock authorityClock=attempt.authorityClock();
        try {
            if (operation != ManagementOperation.DISABLE && !this.namespaceClock.prepare(snapshot, authorityClock.instant(), authorityClock).present())
                return Management.failure(ManagementStatus.UNAVAILABLE);
            if (operation == ManagementOperation.LIST) {
                WebAuthnStoreEntry fence = snapshot.getEntry(fenceKey);
                WebAuthnStoreEntry index = snapshot.getEntry(indexKey);
                if (fence instanceof WebAuthnStoreEntry.Present present)
                    this.fences.decode(fenceKey, present.getSealedBytes(), authorityClock);
                else if (!(fence instanceof WebAuthnStoreEntry.Absent)
                        || !(index instanceof WebAuthnStoreEntry.Absent))
                    return Management.failure(ManagementStatus.UNAVAILABLE);
                List<byte[]> ids = index instanceof WebAuthnStoreEntry.Present present
                        ? this.indexes.decode(indexKey, present.getSealedBytes(), authorityClock).credentialIds()
                        : List.of();
                return Management.listed(ids);
            }
            if (operation == ManagementOperation.REMOVE) {
                Optional<WebAuthnCredentialRemoval.Prepared> prepared = this.removal.prepare(snapshot,
                        approvedHandle, requireNonNull(credentialId), authorityClock);
                if (prepared.isPresent())
                    return mutationResult(attempt, prepared.orElseThrow().write().getMutations(),
                            ManagementStatus.REMOVED);
                return mutationResult(attempt, List.of(), ManagementStatus.ABSENT);
            }
            if (snapshot.getEntry(indexKey) instanceof WebAuthnStoreEntry.Present indexPresent)
                this.indexes.decode(indexKey, indexPresent.getSealedBytes(), authorityClock);
            WebAuthnStoreEntry fence = snapshot.getEntry(fenceKey);
            if (fence instanceof WebAuthnStoreEntry.Present present) {
                if (!this.fences.decode(fenceKey, present.getSealedBytes(), authorityClock).isActive())
                    return mutationResult(attempt, List.of(), ManagementStatus.DISABLED);
                var encoded = this.fences.encode(approvedHandle, false, authorityClock.instant());
                List<WebAuthnStoreWrite.Mutation> mutations = new ArrayList<>(2);
                mutations.add(WebAuthnStoreWrite.Mutation.replace(encoded.key(), encoded.sealedBytes()));
                WebAuthnNamespaceClock.Advance time = this.namespaceClock.prepare(snapshot,
                        authorityClock.instant(), authorityClock);
                if (time.mutation() != null) mutations.add(time.mutation());
                return mutationResult(attempt, mutations, ManagementStatus.DISABLED);
            }
            if (!(snapshot.getEntry(indexKey) instanceof WebAuthnStoreEntry.Absent))
                return Management.failure(ManagementStatus.UNAVAILABLE);
            var encoded = this.fences.encode(approvedHandle, false, authorityClock.instant());
            List<WebAuthnStoreWrite.Mutation> mutations = new ArrayList<>(2);
            mutations.add(WebAuthnStoreWrite.Mutation.insert(encoded.key(), encoded.sealedBytes()));
            WebAuthnNamespaceClock.Advance time = this.namespaceClock.prepare(snapshot,
                    authorityClock.instant(), authorityClock);
            if (time.mutation() != null) mutations.add(time.mutation());
            return mutationResult(attempt, mutations, ManagementStatus.DISABLED);
        } catch (WebAuthnRecordException | DateTimeException failure) {
            return Management.failure(ManagementStatus.UNAVAILABLE);
        }
    }

    private static @NonNull Management mutationResult(WebAuthnStoreCoordinator.@NonNull Attempt attempt,
            @NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations,
            @NonNull ManagementStatus success) {
        return switch (attempt.commit(mutations)) {
            case COMMITTED -> Management.failure(success);
            case INDETERMINATE -> Management.failure(ManagementStatus.INDETERMINATE);
            case RECONCILIATION_REQUIRED -> Management.failure(ManagementStatus.RECONCILIATION_REQUIRED);
            case CONFLICT, CAPACITY, UNAVAILABLE, TIME_EXPIRED -> Management.failure(ManagementStatus.UNAVAILABLE);
        };
    }

    private @NonNull Start begin(WebAuthnCeremonyState.@NonNull Kind kind,
            byte @Nullable [] approvedHandle,byte @NonNull [] browserBinding,@Nullable String purpose) {
        requireNonNull(kind);if(browserBinding.length!=32)throw new IllegalArgumentException("Invalid browser binding");
        var attempt=this.coordinator.begin();Duration budget=attempt.remainingBudget();
        if(budget==null)return Start.failure(Status.UNAVAILABLE);
        WebAuthnRecoveryGate.Permit permit;
        try{permit=this.recoveryGate.acquire(budget);}catch(VirtualMachineError fatal){throw fatal;}
        catch(Throwable failure){WebAuthnStoreCoordinator.preserveInterrupt(failure);return Start.failure(Status.UNAVAILABLE);}
        if(permit==null)return Start.failure(Status.UNAVAILABLE);
        attempt.admit(permit);
        Start result=Start.failure(Status.UNAVAILABLE);Instant upper=null;
        byte[] id=null,challenge=null;
        try{
            if(attempt.remainingBudget()!=null && current(permit)){
                id=this.entropy.nextBytes(32);challenge=this.entropy.nextBytes(32);
                StartCandidate candidate=new StartCandidate(id,challenge);
                do{result=beginAdmitted(attempt,kind,approvedHandle,browserBinding,purpose,candidate);}while(attempt.retryAfterConflict());
                if(normal(result.status())){
                    upper=result.status()==Status.PREPARED?attempt.releaseBefore():null;
                    if(!attempt.finalAdmission(upper))result=failedStart(attempt);
                }
                if(attempt.remainingBudget()==null || !current(permit))result=failedStart(attempt);
            }
        }catch(VirtualMachineError fatal){close(permit);throw fatal;}
        catch(Throwable failure){WebAuthnStoreCoordinator.preserveInterrupt(failure);result=failedStart(attempt);}
        finally{if(id!=null)Arrays.fill(id,(byte)0);if(challenge!=null)Arrays.fill(challenge,(byte)0);}
        if(!close(permit))result=failedStart(attempt);
        if(normal(result.status()) && !attempt.releaseAllowed(upper))result=failedStart(attempt);
        return result;
    }
    private static boolean normal(@NonNull Status status){return status!=Status.UNAVAILABLE && status!=Status.INDETERMINATE && status!=Status.RECONCILIATION_REQUIRED;}
    private static @NonNull Start failedStart(WebAuthnStoreCoordinator.@NonNull Attempt attempt){
        return Start.failure(switch(attempt.failed()){
            case INDETERMINATE -> Status.INDETERMINATE;
            case RECONCILIATION_REQUIRED -> Status.RECONCILIATION_REQUIRED;
            default -> Status.UNAVAILABLE;
        });
    }
    @javax.annotation.concurrent.NotThreadSafe private static final class StartCandidate {
        private final byte @NonNull [] id,challenge;
        private @Nullable Instant issuedAt,expiresAt;
        private StartCandidate(byte @NonNull [] id,byte @NonNull [] challenge){this.id=id;this.challenge=challenge;}
    }

    private @NonNull Start beginAdmitted(WebAuthnStoreCoordinator.@NonNull Attempt attempt,
            WebAuthnCeremonyState.@NonNull Kind kind, byte @Nullable [] approvedHandle,
            byte @NonNull [] browserBinding, @Nullable String purpose, @NonNull StartCandidate candidate) {
        byte[] id = candidate.id;
        byte[] challenge = candidate.challenge;
        WebAuthnStoreKey ceremonyKey = WebAuthnStoreKey.forCeremony(this.namespace,
                this.relyingPartyId, id);
        Set<WebAuthnStoreKey> keys;
        WebAuthnStoreKey fenceKey = null;
        WebAuthnStoreKey indexKey = null;
        if (kind == WebAuthnCeremonyState.Kind.REGISTRATION) {
            fenceKey = WebAuthnStoreKey.forAccountFence(this.namespace, this.relyingPartyId,
                    requireNonNull(approvedHandle));
            indexKey = WebAuthnStoreKey.forAccountCredentialIndex(this.namespace,
                    this.relyingPartyId, approvedHandle);
            keys = Set.of(ceremonyKey, this.namespaceClock.key(), fenceKey, indexKey);
        } else if (kind == WebAuthnCeremonyState.Kind.ACCOUNT_REAUTHENTICATION) {
            fenceKey = WebAuthnStoreKey.forAccountFence(this.namespace, this.relyingPartyId,
                    requireNonNull(approvedHandle));
            keys = Set.of(ceremonyKey, this.namespaceClock.key(), fenceKey);
        } else {
            keys = Set.of(ceremonyKey, this.namespaceClock.key());
        }
        var read = attempt.read(keys);
        if (!read.isAvailable()) return Start.failure(Status.UNAVAILABLE);
        WebAuthnStoreSnapshot snapshot = read.getSnapshot();
        Clock authorityClock=attempt.authorityClock();
        try {
            WebAuthnNamespaceClock.Advance time = this.namespaceClock.prepare(snapshot,
                    authorityClock.instant(), authorityClock);
            if (!(snapshot.getEntry(ceremonyKey) instanceof WebAuthnStoreEntry.Absent))
                return Start.failure(Status.UNAVAILABLE);
            List<byte[]> excluded = List.of();
            WebAuthnStoreWrite.Mutation activeFence = null;
            if (fenceKey != null) {
                WebAuthnStoreEntry fenceEntry = snapshot.getEntry(fenceKey);
                if (fenceEntry instanceof WebAuthnStoreEntry.Absent) {
                    if (kind != WebAuthnCeremonyState.Kind.REGISTRATION)
                        return Start.failure(Status.REJECTED);
                    var encodedFence = this.fences.encode(requireNonNull(approvedHandle), true, authorityClock.instant());
                    activeFence = WebAuthnStoreWrite.Mutation.insert(encodedFence.key(),
                            encodedFence.sealedBytes());
                } else if (!(fenceEntry instanceof WebAuthnStoreEntry.Present presentFence)
                        || !this.fences.decode(fenceKey, presentFence.getSealedBytes(),
                        authorityClock).isActive()) {
                    return Start.failure(Status.REJECTED);
                }
            }
            if (indexKey != null) {
                WebAuthnStoreEntry indexEntry = snapshot.getEntry(indexKey);
                if (indexEntry instanceof WebAuthnStoreEntry.Present presentIndex) {
                    var index = this.indexes.decode(indexKey, presentIndex.getSealedBytes(), authorityClock);
                    if (index.size() >= this.maximumExcludedCredentials)
                        return Start.failure(Status.UNAVAILABLE);
                    excluded = index.credentialIds();
                }
            }
            if(candidate.issuedAt==null){candidate.issuedAt=time.effectiveAt();candidate.expiresAt=candidate.issuedAt.plus(this.ceremonyLifetime);}
            Instant issuedAt = candidate.issuedAt;
            Instant expiresAt = requireNonNull(candidate.expiresAt);
            WebAuthnCeremonyState state = switch (kind) {
                case REGISTRATION -> WebAuthnCeremonyState.registration(id, challenge,
                        browserBinding, this.origins, requireNonNull(approvedHandle), issuedAt, expiresAt);
                case DISCOVERABLE_AUTHENTICATION -> WebAuthnCeremonyState.discoverableAuthentication(
                        id, challenge, browserBinding, this.origins, issuedAt, expiresAt);
                case ACCOUNT_REAUTHENTICATION -> WebAuthnCeremonyState.accountReauthentication(
                        id, challenge, browserBinding, this.origins, requireNonNull(approvedHandle),
                        requireNonNull(purpose), issuedAt, expiresAt);
            };
            var encoded = this.ceremonies.encode(state, authorityClock.instant());
            List<WebAuthnStoreWrite.Mutation> changes = new ArrayList<>(2);
            changes.add(WebAuthnStoreWrite.Mutation.insertExpiring(encoded.key(), encoded.sealedBytes(),
                    encoded.expiresAt()));
            if (activeFence != null) changes.add(activeFence);
            if (time.mutation() != null) changes.add(time.mutation());
            Instant action=attempt.actionUpper();
            Instant upper=expiresAt.isBefore(action)?expiresAt:action;
            var committed = attempt.commit(changes,upper);
            if (committed == WebAuthnStoreCoordinator.Commit.INDETERMINATE)
                return Start.failure(Status.INDETERMINATE);
            if (committed == WebAuthnStoreCoordinator.Commit.RECONCILIATION_REQUIRED) return Start.failure(Status.RECONCILIATION_REQUIRED);
            if (committed == WebAuthnStoreCoordinator.Commit.TIME_EXPIRED) return Start.failure(Status.REJECTED);
            if (committed != WebAuthnStoreCoordinator.Commit.COMMITTED)
                return Start.failure(Status.UNAVAILABLE);
            return Start.prepared(new Request(id, challenge, excluded));
        } catch (WebAuthnRecordException | DateTimeException failure) {
            return Start.failure(Status.UNAVAILABLE);
        }
    }

    private static @NonNull Finish convert(WebAuthnCompletionRunner.@NonNull Completion completed) {
        return switch (completed.outcome()) {
            case COMMITTED_NO_PROOF -> {
                var fact = completed.fact().orElseThrow();
                yield Finish.succeeded(new Verified(fact.kind() == WebAuthnCeremonyState.Kind.REGISTRATION
                        ? Kind.REGISTRATION : fact.kind() == WebAuthnCeremonyState.Kind.ACCOUNT_REAUTHENTICATION
                        ? Kind.REAUTHENTICATION : Kind.AUTHENTICATION,
                        fact.userHandle(), fact.credentialId(), fact.actionPurpose()));
            }
            case REJECTED -> Finish.failure(Status.REJECTED);
            case COUNTER_RISK -> Finish.failure(Status.COUNTER_RISK);
            case CAPACITY, UNAVAILABLE -> Finish.failure(Status.UNAVAILABLE);
            case INDETERMINATE -> Finish.failure(Status.INDETERMINATE);
            case RECONCILIATION_REQUIRED -> Finish.failure(Status.RECONCILIATION_REQUIRED);
        };
    }

    private static boolean current(WebAuthnRecoveryGate.@NonNull Permit permit) {
        try { return Boolean.TRUE.equals(permit.isCurrent()); }
        catch (VirtualMachineError fatal) { throw fatal; }
        catch (Throwable failure) { WebAuthnStoreCoordinator.preserveInterrupt(failure); return false; }
    }

    private static boolean close(WebAuthnRecoveryGate.@NonNull Permit permit) {
        try { permit.close(); return true; }
        catch (VirtualMachineError fatal) { throw fatal; }
        catch (Throwable failure) { WebAuthnStoreCoordinator.preserveInterrupt(failure); return false; }
    }

    public enum Status { PREPARED, SUCCEEDED, REJECTED, COUNTER_RISK, UNAVAILABLE, INDETERMINATE, RECONCILIATION_REQUIRED }
    public enum Kind { REGISTRATION, AUTHENTICATION, REAUTHENTICATION }

    private enum ManagementOperation { LIST, REMOVE, DISABLE }
    public enum ManagementStatus { LISTED, REMOVED, ABSENT, DISABLED, UNAVAILABLE, INDETERMINATE, RECONCILIATION_REQUIRED }

    @Immutable public static final class Management {
        private final @NonNull ManagementStatus status;
        private final byte @NonNull [][] credentialIds;
        private Management(@NonNull ManagementStatus status, @NonNull List<byte @NonNull []> ids) {
            this.status = status;
            this.credentialIds = new byte[ids.size()][];
            for (int i = 0; i < ids.size(); i++) this.credentialIds[i] = ids.get(i).clone();
        }
        private static @NonNull Management listed(@NonNull List<byte @NonNull []> ids) {
            return new Management(ManagementStatus.LISTED, ids);
        }
        private static @NonNull Management failure(@NonNull ManagementStatus status) {
            if (status == ManagementStatus.LISTED) throw new IllegalArgumentException("Invalid listing");
            return new Management(status, List.of());
        }
        public @NonNull ManagementStatus status() { return this.status; }
        public @NonNull List<byte @NonNull []> credentialIds() {
            List<byte[]> copy = new ArrayList<>(this.credentialIds.length);
            for (byte[] id : this.credentialIds) copy.add(id.clone());
            return List.copyOf(copy);
        }
        @Override public @NonNull String toString() { return "Management{<redacted>}"; }
    }

    @Immutable public static final class Request {
        private final byte @NonNull [] ceremonyId;
        private final byte @NonNull [] challenge;
        private final byte @NonNull [][] excludedIds;
        private Request(byte @NonNull [] ceremonyId, byte @NonNull [] challenge,
                @NonNull List<byte @NonNull []> excludedIds) {
            this.ceremonyId = ceremonyId.clone();
            this.challenge = challenge.clone();
            this.excludedIds = new byte[excludedIds.size()][];
            for (int i = 0; i < excludedIds.size(); i++)
                this.excludedIds[i] = excludedIds.get(i).clone();
        }
        public byte @NonNull [] ceremonyId() { return this.ceremonyId.clone(); }
        public byte @NonNull [] challenge() { return this.challenge.clone(); }
        public @NonNull List<byte @NonNull []> excludedIds() {
            List<byte[]> copy = new ArrayList<>(this.excludedIds.length);
            for (byte[] id : this.excludedIds) copy.add(id.clone());
            return List.copyOf(copy);
        }
        @Override public @NonNull String toString() { return "Request{challenge=<redacted>}"; }
    }

    @Immutable public static final class Start {
        private final @NonNull Status status;
        private final @Nullable Request request;
        private Start(@NonNull Status status, @Nullable Request request) {
            this.status = status; this.request = request;
        }
        private static @NonNull Start prepared(@NonNull Request request) {
            return new Start(Status.PREPARED, request);
        }
        private static @NonNull Start failure(@NonNull Status status) {
            if (status == Status.PREPARED || status == Status.SUCCEEDED)
                throw new IllegalArgumentException("Invalid begin outcome");
            return new Start(status, null);
        }
        public @NonNull Status status() { return this.status; }
        public @Nullable Request request() { return this.request; }
        @Override public @NonNull String toString() { return "Start{status=" + this.status + ", details=<redacted>}"; }
    }

    @Immutable public static final class Verified {
        private final @NonNull Kind kind;
        private final byte @NonNull [] userHandle;
        private final byte @NonNull [] credentialId;
        private final @Nullable String purpose;
        private Verified(@NonNull Kind kind, byte @NonNull [] userHandle,
                byte @NonNull [] credentialId, @Nullable String purpose) {
            this.kind = kind;
            this.userHandle = userHandle.clone();
            this.credentialId = credentialId.clone();
            this.purpose = purpose;
        }
        public @NonNull Kind kind() { return this.kind; }
        public byte @NonNull [] userHandle() { return this.userHandle.clone(); }
        public byte @NonNull [] credentialId() { return this.credentialId.clone(); }
        public @Nullable String purpose() { return this.purpose; }
        @Override public @NonNull String toString() { return "Verified{identity=<redacted>}"; }
    }

    @Immutable public static final class Finish {
        private final @NonNull Status status;
        private final @Nullable Verified verified;
        private Finish(@NonNull Status status, @Nullable Verified verified) {
            this.status = status; this.verified = verified;
        }
        private static @NonNull Finish succeeded(@NonNull Verified verified) {
            return new Finish(Status.SUCCEEDED, verified);
        }
        private static @NonNull Finish failure(@NonNull Status status) {
            if (status == Status.SUCCEEDED || status == Status.PREPARED)
                throw new IllegalArgumentException("Invalid completion outcome");
            return new Finish(status, null);
        }
        public @NonNull Status status() { return this.status; }
        public @Nullable Verified verified() { return this.verified; }
        @Override public @NonNull String toString() { return "Finish{status=" + this.status + ", details=<redacted>}"; }
    }
}
