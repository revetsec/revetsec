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

package com.revetsec.totp;

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.ConstantTime;
import com.revetsec.internal.crypto.EntropySource;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.TotpPrimitives;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.Immutable;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Caller-thread TOTP transitions. Only timely, admitted, confirmed commits release checked values. */
@ThreadSafe
final class TotpEngine {
    private final @NonNull String issuer;
    private final @NonNull String namespace;
    private final @NonNull String epoch;
    private final @NonNull TotpStore store;
    private final @NonNull TotpRecoveryGate gate;
    private final @NonNull StateSealer sealer;
    private final @NonNull Clock clock;
    private final long timeoutNanos;
    private final @NonNull TotpRecords records;
    private final @NonNull TotpStoreKey namespaceKey;

    TotpEngine(@NonNull String issuer, @NonNull String namespace, @NonNull String epoch,
            @NonNull TotpStore store, @NonNull StateSealer sealer, @NonNull TotpRecoveryGate gate,
            @NonNull Clock clock, @NonNull Duration timeout) {
        this.issuer = issuer; this.namespace = namespace; this.epoch = epoch; this.store = store;
        this.sealer = sealer; this.gate = gate; this.clock = clock; this.timeoutNanos = timeout.toNanos();
        this.records = new TotpRecords(sealer); this.namespaceKey = TotpStoreKey.forNamespace(namespace, epoch);
    }

    @NonNull Result execute(@NonNull Command command) {
        Run run = new Run();
        TotpRecoveryGate.Permit permit = null;
        Result result = Result.unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);
        VirtualMachineError fatalFailure = null;
        try {
            Duration budget = run.remaining();
            if (budget == null) throw new Failure(Result.unavailable(TotpUnavailableReason.DEADLINE_EXCEEDED));
            TotpRecoveryContext context = TotpRecoveryContext.fromConfiguration(this.namespace, this.epoch,
                    SealedStateAccess.get().getActiveKeyId(this.sealer),
                    SealedStateAccess.get().getOpeningKeyIds(this.sealer),
                    command.action == Action.INITIALIZE ? TotpRecoveryContext.Purpose.INITIALIZE_NAMESPACE
                            : TotpRecoveryContext.Purpose.OPERATION);
            permit = this.gate.acquire(context, budget);
            if (permit == null || !run.current(permit)) throw new Failure(Result.unavailable(TotpUnavailableReason.ADMISSION_CLOSED));
            run.permit = permit;
            if (command.action == Action.CONFIRM || command.action == Action.VERIFY || command.action == Action.RECOVERY)
                result = authenticate(run, command);
            else result = transition(run, command);
            if (!run.current(permit)) result = run.failed(TotpUnavailableReason.ADMISSION_CLOSED);
        } catch (Failure failure) { result = failure.result(); }
        catch (IOException failure) { result = run.failed(TotpUnavailableReason.INVALID_STORED_STATE); }
        catch (VirtualMachineError fatal) { fatalFailure = fatal; }
        catch (Throwable failure) { preserveInterrupt(failure); result = run.failed(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE); }
        finally {
            if (permit != null) {
                try { permit.close(); }
                catch (VirtualMachineError fatal) { if (fatalFailure == null) fatalFailure = fatal; }
                catch (Throwable failure) { preserveInterrupt(failure); result = run.failed(TotpUnavailableReason.ADMISSION_CLOSED); }
            }
            if (run.remaining() == null) result = run.failed(TotpUnavailableReason.DEADLINE_EXCEEDED);
        }
        if (fatalFailure != null) throw fatalFailure;
        return result;
    }

    private @NonNull Result transition(@NonNull Run run, @NonNull Command command) throws Failure, IOException {
        for (int attempt = 0; attempt <= 8; attempt++) {
            try (State state = load(run, command.accountId, command.action == Action.INITIALIZE,
                    command.action == Action.RESEAL ? command.key : null)) {
                Result result = new Result(Status.SUCCEEDED);
                List<TotpStoreWrite.Mutation> changes = new ArrayList<>();
                if (command.action == Action.INITIALIZE) {
                    if (state.namespacePresent) result.status = Status.ALREADY_CURRENT;
                    else changes.add(TotpStoreWrite.Mutation.insert(this.records.seal(this.namespaceKey, state.namespace, null)));
                } else if (command.action == Action.RESEAL) {
                    TotpStoreKey key = Objects.requireNonNull(command.key);
                    TotpStoreEntry entry = state.snapshot.getEntry(key);
                    if (entry instanceof TotpStoreEntry.Absent) result.status = Status.ABSENT;
                    else {
                        TotpStoreRecord prior = ((TotpStoreEntry.Present) entry).getRecord();
                        try (TotpRecords.Decoded decoded = this.records.open(prior)) {
                            if (decoded.account != null && decoded.account.observedAt.isAfter(state.namespace.observedAt))
                                return Result.unavailable(TotpUnavailableReason.INVALID_STORED_STATE);
                            if (decoded.keyId.equals(SealedStateAccess.get().getActiveKeyId(this.sealer)))
                                result.status = Status.ALREADY_CURRENT;
                            else changes.add(TotpStoreWrite.Mutation.replace(this.records.seal(key, decoded.namespace, decoded.account)));
                        }
                    }
                } else if (command.action == Action.STATUS) {
                    TotpRecords.Account account = state.account;
                    if (account == null) result.status = Status.ABSENT;
                    else result.accountStatus = status(account);
                    advanceNamespace(state, changes);
                } else {
                    TotpRecords.Account account = state.account;
                    if (account == null) {
                        account = new TotpRecords.Account(Objects.requireNonNull(command.accountId),
                                this.records.freshId(), state.now);
                        state.account = account;
                    }
                    switch (command.action) {
                        case BEGIN -> begin(command, account, state.now, result);
                        case CANCEL -> {
                            TotpRecords.Pending pending = account.pending;
                            if (pending == null || !ConstantTime.isEqual(pending.enrollmentId, command.first)) {
                                result.reject(TotpRejectionReason.ENROLLMENT_NOT_FOUND); break;
                            }
                            if (!ConstantTime.isEqual(pending.browserHash, browserHash(command.third))) {
                                result.reject(TotpRejectionReason.BINDING_MISMATCH); break;
                            }
                            Arrays.fill(pending.secret, (byte) 0); Arrays.fill(pending.browserHash, (byte) 0); account.pending = null;
                        }
                        case REMOVE -> {
                            TotpRecords.Active active = account.active;
                            if (active == null || !ConstantTime.isEqual(active.factorId, command.first)) {
                                result.reject(TotpRejectionReason.FACTOR_MISMATCH); break;
                            }
                            account.erase(); account.active = null; account.pending = null;
                            account.batchId = null; account.recoveryHashes.clear(); account.fence = this.records.freshId();
                        }
                        case ROTATE -> {
                            TotpRecords.Active active = account.active;
                            if (active == null || !ConstantTime.isEqual(active.factorId, command.first)) {
                                result.reject(TotpRejectionReason.FACTOR_MISMATCH); break;
                            }
                            if (!ConstantTime.isEqual(account.batchId, command.second)) {
                                result.reject(TotpRejectionReason.RECOVERY_BATCH_MISMATCH); break;
                            }
                            result.codes = rotate(account, state.now);
                        }
                        default -> throw new IllegalStateException("Invalid transition");
                    }
                    changes.add(accountMutation(state, account));
                    advanceNamespace(state, changes);
                }
                TotpStoreCommitResult committed = run.commit(state.snapshot, changes,
                        command.action == Action.INITIALIZE && !state.namespacePresent ? TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE
                                : TotpStoreWrite.Purpose.UPDATE);
                if (committed == TotpStoreCommitResult.CONFLICT) continue;
                requireCommit(committed);
                return result;
            }
        }
        return Result.unavailable(TotpUnavailableReason.CONFLICT_LIMIT_REACHED);
    }

    private void begin(@NonNull Command command, TotpRecords.@NonNull Account account,
            @NonNull Instant now, @NonNull Result result) {
        if (account.charges.size() >= 5) { result.status = Status.THROTTLED; result.retryAfter = retryAfter(account, now, false); return; }
        if (account.pending != null) { result.reject(TotpRejectionReason.ENROLLMENT_CONFLICT); return; }
        TotpEnrollmentOptions options = Objects.requireNonNull(command.options);
        String expected = options.getReplacingFactorId().orElse(null);
        TotpRecords.Active active = account.active;
        if (expected == null && active != null) { result.reject(TotpRejectionReason.ALREADY_ENROLLED); return; }
        if (expected != null && (active == null || !ConstantTime.isEqual(expected, active.factorId))) {
            result.reject(TotpRejectionReason.FACTOR_MISMATCH); return;
        }
        byte[] secret = EntropySource.fromDefaults().nextBytes(20);
        String enrollmentId = this.records.freshId(); String factorId = this.records.freshId();
        Instant expires = now.plusSeconds(300);
        account.pending = new TotpRecords.Pending(enrollmentId, factorId, secret,
                browserHash(command.third), expires, expected);
        String manual = TotpPrimitives.base32(secret);
        String uri = "otpauth://totp/" + uri(this.issuer) + ':' + uri(options.getAccountName())
                + "?secret=" + manual + "&issuer=" + uri(this.issuer) + "&algorithm=SHA1&digits=6&period=30";
        result.enrollment = new TotpEnrollment(enrollmentId, factorId, expires, uri, manual, this.epoch);
    }

    private @NonNull Result authenticate(@NonNull Run run, @NonNull Command command) throws Failure, IOException {
        String chargeId = this.records.freshId();
        String expectedFactor = null;
        boolean sixDigitAttempt = command.action == Action.CONFIRM || command.action == Action.VERIFY;
        boolean reserved = false;
        for (int attempt = 0; attempt <= 8; attempt++) {
            try (State state = load(run, command.accountId, false, null)) {
                TotpRecords.Account account = state.account;
                if (account == null) {
                    account = new TotpRecords.Account(Objects.requireNonNull(command.accountId), this.records.freshId(), state.now);
                    state.account = account;
                }
                boolean throttled = account.charges.size() >= 5
                        || (sixDigitAttempt && account.totpCharges.size() >= 10);
                if (!throttled) {
                    expectedFactor = command.action == Action.CONFIRM
                            ? (account.pending == null ? null : account.pending.factorId)
                            : (account.active == null ? null : account.active.factorId);
                    account.charges.add(new TotpRecords.Charge(chargeId, state.now));
                    if (sixDigitAttempt) account.totpCharges.add(new TotpRecords.Charge(chargeId, state.now));
                }
                List<TotpStoreWrite.Mutation> changes = new ArrayList<>();
                changes.add(accountMutation(state, account)); advanceNamespace(state, changes);
                TotpStoreCommitResult committed = run.commit(state.snapshot, changes, TotpStoreWrite.Purpose.UPDATE);
                if (committed == TotpStoreCommitResult.CONFLICT) continue;
                requireCommit(committed);
                if (throttled) return Result.throttled(retryAfter(account, state.now, sixDigitAttempt));
                reserved = true; break;
            }
        }
        if (!reserved) return Result.unavailable(TotpUnavailableReason.CONFLICT_LIMIT_REACHED);
        for (int attempt = 0; attempt <= 8; attempt++) {
            try (State state = load(run, command.accountId, false, null)) {
                TotpRecords.Account account = state.account;
                if (account == null) throw new Failure(Result.unavailable(TotpUnavailableReason.INVALID_STORED_STATE));
                boolean chargePresent = false;
                for (TotpRecords.Charge charge : account.charges) if (charge.id.equals(chargeId)) chargePresent = true;
                Result result = new Result(Status.SUCCEEDED);
                if (!chargePresent) result.reject(TotpRejectionReason.REJECTED);
                else if (command.action == Action.CONFIRM) confirm(command, account, state.now, expectedFactor, result);
                else if (command.action == Action.VERIFY) verify(command, account, state.now, expectedFactor, result);
                else recovery(command, account, state.now, expectedFactor, result);
                if (result.status == Status.SUCCEEDED) {
                    account.charges.removeIf(charge -> charge.id.equals(chargeId));
                    if (sixDigitAttempt) account.totpCharges.removeIf(charge -> charge.id.equals(chargeId));
                }
                List<TotpStoreWrite.Mutation> changes = new ArrayList<>();
                changes.add(accountMutation(state, account)); advanceNamespace(state, changes);
                TotpStoreCommitResult committed = run.commit(state.snapshot, changes, TotpStoreWrite.Purpose.UPDATE);
                if (committed == TotpStoreCommitResult.CONFLICT) continue;
                requireCommit(committed); return result;
            }
        }
        return Result.unavailable(TotpUnavailableReason.CONFLICT_LIMIT_REACHED);
    }

    private void confirm(@NonNull Command command, TotpRecords.@NonNull Account account, @NonNull Instant now,
            @Nullable String expectedFactor, @NonNull Result result) throws Failure {
        TotpRecords.Pending pending = account.pending;
        if (pending == null || !ConstantTime.isEqual(pending.enrollmentId, command.first)
                || !ConstantTime.isEqual(pending.factorId, expectedFactor)) {
            result.reject(TotpRejectionReason.ENROLLMENT_NOT_FOUND); return;
        }
        if (!ConstantTime.isEqual(pending.browserHash, browserHash(command.third))) {
            result.reject(TotpRejectionReason.BINDING_MISMATCH); return;
        }
        TotpRecords.Active active = account.active;
        if ((pending.expectedFactorId == null && active != null)
                || (pending.expectedFactorId != null && (active == null
                || !ConstantTime.isEqual(active.factorId, pending.expectedFactorId)))) {
            result.reject(TotpRejectionReason.FACTOR_MISMATCH); return;
        }
        long matched = matching(pending.secret, command.second, now, -1);
        if (matched < 0) { result.reject(TotpRejectionReason.INVALID_CODE); return; }
        if (active != null) Arrays.fill(active.secret, (byte) 0);
        account.active = new TotpRecords.Active(pending.factorId, pending.secret.clone(), now, matched);
        Arrays.fill(pending.secret, (byte) 0); Arrays.fill(pending.browserHash, (byte) 0); account.pending = null; account.fence = this.records.freshId();
        result.factor = factor(account, Objects.requireNonNull(account.active));
        result.codes = rotate(account, now);
    }

    private void verify(@NonNull Command command, TotpRecords.@NonNull Account account, @NonNull Instant now,
            @Nullable String expectedFactor, @NonNull Result result) throws Failure {
        TotpRecords.Active active = account.active;
        if (active == null || !ConstantTime.isEqual(active.factorId, expectedFactor)) {
            result.reject(TotpRejectionReason.NOT_ENROLLED); return;
        }
        long matched = matching(active.secret, command.second, now, active.usedStep);
        if (matched < 0) { result.reject(TotpRejectionReason.INVALID_CODE); return; }
        active.usedStep = matched;
        result.verification = new TotpVerification(this.namespace, this.epoch, account.accountId,
                active.factorId, now, command.third);
    }

    private void recovery(@NonNull Command command, TotpRecords.@NonNull Account account, @NonNull Instant now,
            @Nullable String expectedFactor, @NonNull Result result) {
        TotpRecords.Active active = account.active;
        if (active == null || !ConstantTime.isEqual(active.factorId, expectedFactor)) {
            result.reject(TotpRejectionReason.NOT_ENROLLED); return;
        }
        String normalized = TotpPrimitives.normalizeRecoveryCode(command.second);
        if (normalized == null) { result.reject(TotpRejectionReason.INVALID_CODE); return; }
        byte[] expected = recoveryHash(account, normalized);
        int matched = -1;
        try {
            for (int index = 0; index < account.recoveryHashes.size(); index++)
                if (ConstantTime.isEqual(account.recoveryHashes.get(index), expected)) matched = index;
        } finally { Arrays.fill(expected, (byte) 0); }
        if (matched < 0) { result.reject(TotpRejectionReason.INVALID_CODE); return; }
        Arrays.fill(account.recoveryHashes.remove(matched), (byte) 0);
        result.recoveryUse = new RecoveryCodeUse(this.namespace, this.epoch, account.accountId,
                active.factorId, now, command.third, account.recoveryHashes.size());
    }

    private @NonNull RecoveryCodes rotate(TotpRecords.@NonNull Account account, @NonNull Instant now) {
        for (byte[] hash : account.recoveryHashes) Arrays.fill(hash, (byte) 0);
        account.recoveryHashes.clear(); account.batchId = this.records.freshId();
        List<String> codes = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            byte[] random = EntropySource.fromDefaults().nextBytes(16);
            String presented;
            try { presented = TotpPrimitives.recoveryCode(random); } finally { Arrays.fill(random, (byte) 0); }
            String normalized = Objects.requireNonNull(TotpPrimitives.normalizeRecoveryCode(presented));
            account.recoveryHashes.add(recoveryHash(account, normalized)); codes.add(presented);
        }
        return new RecoveryCodes(this.namespace, this.epoch, account.accountId,
                Objects.requireNonNull(account.active).factorId, account.batchId, now, codes);
    }
    private byte @NonNull [] recoveryHash(TotpRecords.@NonNull Account account, @NonNull String code) {
        return TotpPrimitives.digest("revetsec/totp/recovery-verifier/v1", this.namespace, this.epoch,
                account.accountId, Objects.requireNonNull(account.active).factorId,
                Objects.requireNonNull(account.batchId), code);
    }
    private static byte @NonNull [] browserHash(@NonNull String binding) {
        return TotpPrimitives.digest("revetsec/totp/browser-binding/v1", binding);
    }
    private static long matching(byte @NonNull [] secret, @NonNull String code, @NonNull Instant now,
            long usedStep) throws Failure {
        try { return TotpPrimitives.matchingStep(secret, code, now.getEpochSecond() / 30, usedStep); }
        catch (java.security.GeneralSecurityException failure) {
            throw new Failure(Result.unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE));
        }
    }
    private @NonNull TotpFactor factor(TotpRecords.@NonNull Account account, TotpRecords.@NonNull Active active) {
        return new TotpFactor(this.namespace, this.epoch, account.accountId, active.factorId, active.enrolledAt);
    }
    private @NonNull TotpStatus status(TotpRecords.@NonNull Account account) {
        TotpRecords.Active active = account.active; TotpRecords.Pending pending = account.pending;
        return new TotpStatus(active == null ? null : factor(account, active),
                pending == null ? null : new TotpPendingEnrollment(pending.enrollmentId, pending.factorId, pending.expiresAt),
                account.batchId, account.recoveryHashes.size());
    }
    private static @NonNull Duration retryAfter(TotpRecords.@NonNull Account account, @NonNull Instant now,
            boolean sixDigitAttempt) {
        Instant blockedUntil = now;
        if (account.charges.size() >= 5)
            blockedUntil = firstChargeExpiry(account.charges, 300);
        if (sixDigitAttempt && account.totpCharges.size() >= 10) {
            Instant longExpiry = firstChargeExpiry(account.totpCharges, 86_400);
            if (longExpiry.isAfter(blockedUntil)) blockedUntil = longExpiry;
        }
        Duration remaining = Duration.between(now, blockedUntil);
        return remaining.isNegative() || remaining.isZero() ? Duration.ofSeconds(1) : remaining;
    }
    private static @NonNull Instant firstChargeExpiry(@NonNull List<TotpRecords.@NonNull Charge> charges,
            long windowSeconds) {
        Instant first = charges.get(0).at;
        for (TotpRecords.Charge charge : charges) if (charge.at.isBefore(first)) first = charge.at;
        return first.plusSeconds(windowSeconds);
    }
    private static @NonNull String uri(@NonNull String text) {
        return URLEncoder.encode(text, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private @NonNull State load(@NonNull Run run, @Nullable String accountId, boolean initializing,
            @Nullable TotpStoreKey maintenanceKey) throws Failure, IOException {
        Set<TotpStoreKey> keys = accountId != null
                ? Set.of(this.namespaceKey, TotpStoreKey.forAccount(this.namespace, this.epoch, accountId))
                : maintenanceKey != null && !maintenanceKey.equals(this.namespaceKey)
                ? Set.of(this.namespaceKey, maintenanceKey) : Set.of(this.namespaceKey);
        Duration budget = run.remaining();
        if (budget == null || run.permit == null || !run.current(run.permit)) throw new Failure(run.failed(TotpUnavailableReason.DEADLINE_EXCEEDED));
        TotpStoreReadResult read = this.store.read(keys, budget);
        if (read instanceof TotpStoreReadResult.Fenced) throw new Failure(run.failed(TotpUnavailableReason.FENCED));
        if (!(read instanceof TotpStoreReadResult.Available available)
                || !available.getSnapshot().getEntries().keySet().equals(keys))
            throw new Failure(run.failed(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE));
        TotpStoreSnapshot snapshot = available.getSnapshot();
        Instant now = this.clock.instant();
        if (now.getEpochSecond() < 0 || now.getEpochSecond() > 253_402_300_000L)
            throw new Failure(run.failed(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE));
        TotpStoreEntry root = snapshot.getEntry(this.namespaceKey);
        TotpRecords.Namespace namespace;
        boolean namespacePresent = root instanceof TotpStoreEntry.Present;
        if (root instanceof TotpStoreEntry.Present present) {
            try (TotpRecords.Decoded decoded = this.records.open(present.getRecord())) { namespace = decoded.namespace; }
        } else if (initializing) namespace = new TotpRecords.Namespace(now);
        else throw new Failure(Result.unavailable(TotpUnavailableReason.NAMESPACE_NOT_INITIALIZED));
        if (Duration.between(now, namespace.observedAt).compareTo(Duration.ofSeconds(30)) > 0)
            throw new Failure(run.failed(TotpUnavailableReason.INVALID_STORED_STATE));
        if (namespace.observedAt.isAfter(now)) now = namespace.observedAt;
        TotpRecords.Account account = null;
        TotpStoreKey accountKey = accountId == null ? null : TotpStoreKey.forAccount(this.namespace, this.epoch, accountId);
        if (accountKey != null && snapshot.getEntry(accountKey) instanceof TotpStoreEntry.Present present) {
            TotpRecords.Decoded decoded = this.records.open(present.getRecord());
            account = Objects.requireNonNull(decoded.account);
            if (account.observedAt.isAfter(namespace.observedAt)) {
                account.erase(); throw new Failure(run.failed(TotpUnavailableReason.INVALID_STORED_STATE));
            }
        }
        if (account != null) {
            TotpRecords.Pending pending = account.pending;
            if (pending != null && !now.isBefore(pending.expiresAt)) {
                Arrays.fill(pending.secret, (byte) 0); Arrays.fill(pending.browserHash, (byte) 0); account.pending = null;
            }
            Instant floor = now.minusSeconds(300);
            account.charges.removeIf(charge -> !charge.at.isAfter(floor));
            Instant totpFloor = now.minusSeconds(86_400);
            account.totpCharges.removeIf(charge -> !charge.at.isAfter(totpFloor));
            account.observedAt = now;
        }
        return new State(snapshot, namespace, account, now, namespacePresent, accountKey);
    }
    private TotpStoreWrite.@NonNull Mutation accountMutation(@NonNull State state, TotpRecords.@NonNull Account account) {
        TotpStoreKey key = Objects.requireNonNull(state.accountKey);
        account.observedAt = state.now;
        TotpStoreRecord record = this.records.seal(key, state.namespace, account);
        return state.snapshot.getEntry(key) instanceof TotpStoreEntry.Present
                ? TotpStoreWrite.Mutation.replace(record) : TotpStoreWrite.Mutation.insert(record);
    }
    private void advanceNamespace(@NonNull State state, @NonNull List<TotpStoreWrite.@NonNull Mutation> changes) {
        if (state.now.isAfter(state.namespace.observedAt)) {
            state.namespace.observedAt = state.now;
            changes.add(TotpStoreWrite.Mutation.replace(this.records.seal(this.namespaceKey, state.namespace, null)));
        }
    }
    private static void requireCommit(@NonNull TotpStoreCommitResult result) throws Failure {
        if (result == TotpStoreCommitResult.COMMITTED) return;
        if (result == TotpStoreCommitResult.UNKNOWN) throw new Failure(new Result(Status.INDETERMINATE));
        TotpUnavailableReason reason = switch (result) {
            case FENCED -> TotpUnavailableReason.FENCED;
            case CAPACITY_REFUSED -> TotpUnavailableReason.CAPACITY_REFUSED;
            default -> TotpUnavailableReason.DEPENDENCY_UNAVAILABLE;
        };
        throw new Failure(Result.unavailable(reason));
    }
    @SuppressWarnings("ReferenceEquality") // Throwable.equals can be overridden; detect a self-cause by identity.
    private static void preserveInterrupt(@NonNull Throwable failure) {
        Throwable current = failure;
        for (int depth = 0; depth < 16; depth++) {
            if (current instanceof InterruptedException || current instanceof java.io.InterruptedIOException) {
                Thread.currentThread().interrupt(); return;
            }
            Throwable cause;
            try { cause = current.getCause(); } catch (RuntimeException unavailable) { return; }
            if (cause == null || cause == current) return;
            current = cause;
        }
    }

    @Immutable enum Action { INITIALIZE, BEGIN, CONFIRM, VERIFY, RECOVERY, ROTATE, REMOVE, CANCEL, STATUS, RESEAL }
    @Immutable enum Status { SUCCEEDED, ALREADY_CURRENT, ABSENT, REJECTED, THROTTLED, UNAVAILABLE, INDETERMINATE }
    @Immutable static final class Command {
        final @NonNull Action action;
        final @Nullable String accountId;
        final @NonNull String first;
        final @NonNull String second;
        final @NonNull String third;
        final @Nullable TotpEnrollmentOptions options;
        final @Nullable TotpStoreKey key;
        Command(@NonNull Action action, @Nullable String accountId, @NonNull String first,
                @NonNull String second, @NonNull String third, @Nullable TotpEnrollmentOptions options,
                @Nullable TotpStoreKey key) {
            this.action = action; this.accountId = accountId; this.first = first; this.second = second;
            this.third = third; this.options = options; this.key = key;
        }
    }
    @NotThreadSafe static final class Result {
        @NonNull Status status;
        @NonNull TotpRejectionReason rejection = TotpRejectionReason.REJECTED;
        @NonNull TotpUnavailableReason unavailable = TotpUnavailableReason.DEPENDENCY_UNAVAILABLE;
        @NonNull Duration retryAfter = Duration.ofMinutes(5);
        @Nullable TotpEnrollment enrollment;
        @Nullable TotpFactor factor;
        @Nullable RecoveryCodes codes;
        @Nullable TotpVerification verification;
        @Nullable RecoveryCodeUse recoveryUse;
        @Nullable TotpStatus accountStatus;
        Result(@NonNull Status status) { this.status = status; }
        void reject(@NonNull TotpRejectionReason reason) { this.status = Status.REJECTED; this.rejection = reason; }
        static @NonNull Result rejected(@NonNull TotpRejectionReason reason) { Result r = new Result(Status.REJECTED); r.rejection = reason; return r; }
        static @NonNull Result unavailable(@NonNull TotpUnavailableReason reason) { Result r = new Result(Status.UNAVAILABLE); r.unavailable = reason; return r; }
        static @NonNull Result throttled(@NonNull Duration retry) { Result r = new Result(Status.THROTTLED); r.retryAfter = retry; return r; }
    }
    @NotThreadSafe private static final class State implements AutoCloseable {
        final @NonNull TotpStoreSnapshot snapshot;
        final TotpRecords.@NonNull Namespace namespace;
        TotpRecords.@Nullable Account account;
        final @NonNull Instant now;
        final boolean namespacePresent;
        final @Nullable TotpStoreKey accountKey;
        State(@NonNull TotpStoreSnapshot snapshot, TotpRecords.@NonNull Namespace namespace,
                TotpRecords.@Nullable Account account, @NonNull Instant now, boolean namespacePresent,
                @Nullable TotpStoreKey accountKey) {
            this.snapshot = snapshot; this.namespace = namespace; this.account = account;
            this.now = now; this.namespacePresent = namespacePresent; this.accountKey = accountKey;
        }
        @Override public void close() { TotpRecords.Account a = this.account; if (a != null) a.erase(); }
    }
    @NotThreadSafe private final class Run {
        private final long started = System.nanoTime();
        private long lastRemaining = timeoutNanos;
        private boolean wrote;
        private TotpRecoveryGate.@Nullable Permit permit;
        private @Nullable Duration remaining() {
            long elapsed = System.nanoTime() - this.started;
            long remaining = Math.min(this.lastRemaining, timeoutNanos - elapsed);
            if (elapsed < 0 || remaining <= 0 || Thread.currentThread().isInterrupted()) return null;
            this.lastRemaining = remaining; return Duration.ofNanos(remaining);
        }
        private boolean current(TotpRecoveryGate.@NonNull Permit currentPermit) {
            return remaining() != null && currentPermit.isCurrent() && remaining() != null;
        }
        private @NonNull Result failed(@NonNull TotpUnavailableReason reason) {
            return this.wrote ? new Result(Status.INDETERMINATE) : Result.unavailable(reason);
        }
        private @NonNull TotpStoreCommitResult commit(@NonNull TotpStoreSnapshot snapshot,
                @NonNull List<TotpStoreWrite.@NonNull Mutation> mutations, TotpStoreWrite.@NonNull Purpose purpose) throws Failure {
            Duration budget = remaining();
            if (budget == null || this.permit == null || !current(this.permit)) throw new Failure(failed(TotpUnavailableReason.DEADLINE_EXCEEDED));
            TotpStoreWrite write = TotpStoreWrite.fromSnapshotAndMutations(purpose, snapshot, mutations);
            boolean prior = this.wrote;
            this.wrote = true;
            TotpStoreCommitResult result = store.compareAndCommit(write, budget);
            if (result == null || result == TotpStoreCommitResult.UNKNOWN) return TotpStoreCommitResult.UNKNOWN;
            if (result != TotpStoreCommitResult.COMMITTED) this.wrote = prior;
            if (remaining() == null) throw new Failure(failed(TotpUnavailableReason.DEADLINE_EXCEEDED));
            return result;
        }
    }
    @Immutable private static final class Failure extends Exception {
        private static final long serialVersionUID = 1L;
        private final @NonNull Status status;
        private final @NonNull TotpUnavailableReason reason;
        Failure(@NonNull Result result) {
            super("TOTP operation unavailable", null, false, false);
            this.status = result.status; this.reason = result.unavailable;
        }
        @NonNull Result result() { Result result = new Result(this.status); result.unavailable = this.reason; return result; }
    }
}
