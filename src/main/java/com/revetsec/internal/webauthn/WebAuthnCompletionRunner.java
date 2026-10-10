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

import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * One bounded two-read completion attempt and at most one authoritative write. COMMITTED means
 * only that the store transition was timely confirmed; this runner creates and exposes no
 * verification proof. Public success still requires the external recovery admission gate.
 */
final class WebAuthnCompletionRunner {
    private final @NonNull WebAuthnStoreCoordinator coordinator;
    private final @NonNull WebAuthnCompletionPlanner planner;
    private final @NonNull Clock clock;
    private final @NonNull WebAuthnRecoveryGate recoveryGate;

    WebAuthnCompletionRunner(@NonNull WebAuthnStoreCoordinator coordinator,
            @NonNull WebAuthnCompletionPlanner planner, @NonNull Clock clock,
            @NonNull WebAuthnRecoveryGate recoveryGate) {
        this.coordinator = requireNonNull(coordinator);
        this.planner = requireNonNull(planner);
        this.clock = requireNonNull(clock);
        this.recoveryGate = requireNonNull(recoveryGate);
    }

    @NonNull Outcome completeRegistration(byte @NonNull [] ceremonyId,
            byte @NonNull [] browserBinding, byte @NonNull [] responseBody) {
        return completeRegistrationFact(ceremonyId, browserBinding, responseBody).outcome();
    }

    @NonNull Completion completeRegistrationFact(byte @NonNull [] ceremonyId,
            byte @NonNull [] browserBinding, byte @NonNull [] responseBody) {
        requireNonNull(ceremonyId);
        requireNonNull(browserBinding);
        requireNonNull(responseBody);
        var attempt = this.coordinator.begin();
        return withAdmission(attempt, () -> completeRegistrationAdmitted(
                attempt, ceremonyId, browserBinding, responseBody));
    }

    private @NonNull Completion completeRegistrationAdmitted(
            WebAuthnStoreCoordinator.@NonNull Attempt attempt, byte @NonNull [] ceremonyId,
            byte @NonNull [] browserBinding, byte @NonNull [] responseBody) {
        var first = attempt.read(this.planner.firstKeys(ceremonyId));
        if (!first.isAvailable()) return Completion.failure(Outcome.UNAVAILABLE);
        WebAuthnStoreSnapshot firstSnapshot = first.getSnapshot();
        Optional<WebAuthnCompletionPlanner.RegistrationInspection> inspected;
        try {
            inspected = this.planner.inspectRegistration(firstSnapshot, ceremonyId,
                    browserBinding, responseBody, this.clock);
        } catch (WebAuthnResponseException failure) {
            return Completion.failure(rejectWithClock(attempt, firstSnapshot, Outcome.REJECTED));
        } catch (WebAuthnRecordException failure) {
            return Completion.failure(Outcome.UNAVAILABLE);
        }
        if (inspected.isEmpty()) return Completion.failure(rejectWithClock(attempt, firstSnapshot, Outcome.REJECTED));
        var expanded = attempt.readExpanded(inspected.orElseThrow().expandedKeys());
        if (!expanded.isAvailable()) return Completion.failure(Outcome.UNAVAILABLE);
        WebAuthnStoreSnapshot snapshot = expanded.getSnapshot();
        WebAuthnCompletionPlanner.Preparation preparation;
        try {
            preparation = this.planner.prepareRegistration(inspected.orElseThrow(), snapshot, this.clock);
        } catch (WebAuthnResponseException failure) {
            return Completion.failure(rejectWithClock(attempt, snapshot, Outcome.REJECTED));
        } catch (WebAuthnRecordException failure) {
            return Completion.failure(Outcome.UNAVAILABLE);
        }
        Outcome outcome = finish(attempt, snapshot, preparation, inspected.orElseThrow().expiresAt());
        return outcome == Outcome.COMMITTED_NO_PROOF
                ? Completion.verified(new VerifiedFact(WebAuthnCeremonyState.Kind.REGISTRATION,
                inspected.orElseThrow().approvedHandle(), inspected.orElseThrow().credentialId(), null))
                : Completion.failure(outcome);
    }

    @NonNull Outcome completeAuthentication(byte @NonNull [] ceremonyId,
            byte @NonNull [] browserBinding, byte @NonNull [] responseBody) {
        return completeAuthenticationFact(ceremonyId, browserBinding, responseBody).outcome();
    }

    @NonNull Completion completeAuthenticationFact(byte @NonNull [] ceremonyId,
            byte @NonNull [] browserBinding, byte @NonNull [] responseBody) {
        requireNonNull(ceremonyId);
        requireNonNull(browserBinding);
        requireNonNull(responseBody);
        var attempt = this.coordinator.begin();
        return withAdmission(attempt, () -> completeAuthenticationAdmitted(
                attempt, ceremonyId, browserBinding, responseBody));
    }

    private @NonNull Completion completeAuthenticationAdmitted(
            WebAuthnStoreCoordinator.@NonNull Attempt attempt, byte @NonNull [] ceremonyId,
            byte @NonNull [] browserBinding, byte @NonNull [] responseBody) {
        var first = attempt.read(this.planner.firstKeys(ceremonyId));
        if (!first.isAvailable()) return Completion.failure(Outcome.UNAVAILABLE);
        WebAuthnStoreSnapshot firstSnapshot = first.getSnapshot();
        Optional<WebAuthnCompletionPlanner.AuthenticationInspection> inspected;
        try {
            inspected = this.planner.inspectAuthentication(firstSnapshot, ceremonyId,
                    browserBinding, responseBody, this.clock);
        } catch (WebAuthnResponseException failure) {
            return Completion.failure(rejectWithClock(attempt, firstSnapshot, Outcome.REJECTED));
        } catch (WebAuthnRecordException failure) {
            return Completion.failure(Outcome.UNAVAILABLE);
        }
        if (inspected.isEmpty()) return Completion.failure(rejectWithClock(attempt, firstSnapshot, Outcome.REJECTED));
        var expanded = attempt.readExpanded(inspected.orElseThrow().expandedKeys());
        if (!expanded.isAvailable()) return Completion.failure(Outcome.UNAVAILABLE);
        WebAuthnStoreSnapshot snapshot = expanded.getSnapshot();
        WebAuthnCompletionPlanner.Preparation preparation;
        try {
            preparation = this.planner.prepareAuthentication(inspected.orElseThrow(), snapshot, this.clock);
        } catch (WebAuthnRecordException failure) {
            return Completion.failure(Outcome.UNAVAILABLE);
        }
        Outcome outcome = finish(attempt, snapshot, preparation, inspected.orElseThrow().expiresAt());
        return outcome == Outcome.COMMITTED_NO_PROOF
                ? Completion.verified(new VerifiedFact(inspected.orElseThrow().kind(),
                inspected.orElseThrow().userHandle(), inspected.orElseThrow().credentialId(),
                inspected.orElseThrow().actionPurpose()))
                : Completion.failure(outcome);
    }

    /** The permit covers both reads and the optional write; a restore must drain it. */
    private @NonNull Completion withAdmission(WebAuthnStoreCoordinator.@NonNull Attempt attempt,
            @NonNull Supplier<@NonNull Completion> operation) {
        Duration budget = attempt.remainingBudget();
        if (budget == null) return Completion.failure(Outcome.UNAVAILABLE);
        WebAuthnRecoveryGate.Permit permit;
        try {
            permit = this.recoveryGate.acquire(budget);
        } catch (VirtualMachineError fatal) {
            throw fatal;
        } catch (Throwable failure) {
            WebAuthnStoreCoordinator.preserveInterrupt(failure);
            return Completion.failure(Outcome.UNAVAILABLE);
        }
        if (permit == null) return Completion.failure(Outcome.UNAVAILABLE);
        Completion completion;
        try {
            if (attempt.remainingBudget() == null || !isCurrent(permit)) {
                completion = Completion.failure(Outcome.UNAVAILABLE);
            } else {
                completion = operation.get();
                // A write may already have occurred. A changed marker or expired budget cannot
                // be reported as success, even if the store acknowledged the write.
                if (attempt.remainingBudget() == null || !isCurrent(permit))
                    completion = Completion.failure(Outcome.INDETERMINATE);
            }
        } catch (RuntimeException | Error failure) {
            closePermit(permit);
            throw failure;
        }
        return closePermit(permit) ? completion : Completion.failure(Outcome.INDETERMINATE);
    }

    private static boolean isCurrent(WebAuthnRecoveryGate.@NonNull Permit permit) {
        try {
            return permit.isCurrent();
        } catch (VirtualMachineError fatal) {
            throw fatal;
        } catch (Throwable failure) {
            WebAuthnStoreCoordinator.preserveInterrupt(failure);
            return false;
        }
    }

    private static boolean closePermit(WebAuthnRecoveryGate.@NonNull Permit permit) {
        try {
            permit.close();
            return true;
        } catch (VirtualMachineError fatal) {
            throw fatal;
        } catch (Throwable failure) {
            WebAuthnStoreCoordinator.preserveInterrupt(failure);
            return false;
        }
    }

    private @NonNull Outcome finish(WebAuthnStoreCoordinator.@NonNull Attempt attempt,
            @NonNull WebAuthnStoreSnapshot snapshot,
            WebAuthnCompletionPlanner.@NonNull Preparation preparation,
            @NonNull Instant expiresAt) {
        return switch (preparation.status()) {
            case CANDIDATE -> {
                if (!this.clock.instant().isBefore(expiresAt))
                    yield rejectWithClock(attempt, snapshot, Outcome.REJECTED);
                Outcome committed = commit(attempt, preparation.write().orElseThrow());
                yield committed == Outcome.COMMITTED_NO_PROOF && !this.clock.instant().isBefore(expiresAt)
                        ? Outcome.INDETERMINATE : committed;
            }
            case REJECTED -> rejectWithClock(attempt, snapshot, Outcome.REJECTED);
            case COUNTER_RISK -> rejectWithClock(attempt, snapshot, Outcome.COUNTER_RISK);
            case CAPACITY -> rejectWithClock(attempt, snapshot, Outcome.CAPACITY);
            case UNAVAILABLE -> Outcome.UNAVAILABLE;
        };
    }

    private @NonNull Outcome rejectWithClock(WebAuthnStoreCoordinator.@NonNull Attempt attempt,
            @NonNull WebAuthnStoreSnapshot snapshot, @NonNull Outcome rejection) {
        Optional<WebAuthnStoreWrite> clockWrite;
        try {
            clockWrite = this.planner.clockOnlyAdvance(snapshot, this.clock);
        } catch (WebAuthnRecordException failure) {
            return Outcome.UNAVAILABLE;
        }
        if (clockWrite.isEmpty()) return rejection;
        return switch (attempt.commit(clockWrite.orElseThrow().getMutations())) {
            case COMMITTED -> rejection;
            case CONFLICT, CAPACITY, UNAVAILABLE -> Outcome.UNAVAILABLE;
            case INDETERMINATE -> Outcome.INDETERMINATE;
        };
    }

    private static @NonNull Outcome commit(WebAuthnStoreCoordinator.@NonNull Attempt attempt,
            @NonNull WebAuthnStoreWrite write) {
        return switch (attempt.commit(write.getMutations())) {
            case COMMITTED -> Outcome.COMMITTED_NO_PROOF;
            case CONFLICT, UNAVAILABLE -> Outcome.UNAVAILABLE;
            case CAPACITY -> Outcome.CAPACITY;
            case INDETERMINATE -> Outcome.INDETERMINATE;
        };
    }

    enum Outcome { COMMITTED_NO_PROOF, REJECTED, COUNTER_RISK, CAPACITY, UNAVAILABLE, INDETERMINATE }

    /** Internal fact released only after a timely confirmed write and a current admission permit. */
    @Immutable
    static final class VerifiedFact {
        private final WebAuthnCeremonyState.@NonNull Kind kind;
        private final byte @NonNull [] userHandle;
        private final byte @NonNull [] credentialId;
        private final @Nullable String actionPurpose;
        private VerifiedFact(WebAuthnCeremonyState.@NonNull Kind kind, byte @NonNull [] userHandle,
                byte @NonNull [] credentialId, @Nullable String actionPurpose) {
            this.kind = requireNonNull(kind);
            this.userHandle = requireNonNull(userHandle).clone();
            this.credentialId = requireNonNull(credentialId).clone();
            this.actionPurpose = actionPurpose;
        }
        WebAuthnCeremonyState.@NonNull Kind kind() { return this.kind; }
        byte @NonNull [] userHandle() { return this.userHandle.clone(); }
        byte @NonNull [] credentialId() { return this.credentialId.clone(); }
        @Nullable String actionPurpose() { return this.actionPurpose; }
        @Override public @NonNull String toString() { return "VerifiedFact{identity=<redacted>}"; }
    }

    /** No fact is reachable on a failed or uncertain outcome. */
    @Immutable
    static final class Completion {
        private final @NonNull Outcome outcome;
        private final @Nullable VerifiedFact fact;
        private Completion(@NonNull Outcome outcome, @Nullable VerifiedFact fact) {
            this.outcome = requireNonNull(outcome);
            this.fact = fact;
        }
        private static @NonNull Completion verified(@NonNull VerifiedFact fact) {
            return new Completion(Outcome.COMMITTED_NO_PROOF, requireNonNull(fact));
        }
        private static @NonNull Completion failure(@NonNull Outcome outcome) {
            if (outcome == Outcome.COMMITTED_NO_PROOF)
                throw new IllegalArgumentException("Verified outcome requires a fact");
            return new Completion(outcome, null);
        }
        @NonNull Outcome outcome() { return this.outcome; }
        @NonNull Optional<@NonNull VerifiedFact> fact() { return Optional.ofNullable(this.fact); }
        @Override public @NonNull String toString() { return "Completion{" + this.outcome + ", identity=<redacted>}"; }
    }
}
