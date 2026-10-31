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

import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.internal.StoreTimeRules;
import com.revetsec.internal.crypto.EntropySource;
import com.revetsec.webauthn.WebAuthnStore;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnStoreCommitReceipt;
import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.LockSupport;
import java.util.function.LongSupplier;

import static java.util.Objects.requireNonNull;

/** Caller-thread admitted reads, cumulative factual effects and a minimum final admission read. */
final class WebAuthnStoreCoordinator {
    private final @NonNull WebAuthnStore store;
    private final long timeoutNanos;
    private final @NonNull LongSupplier nanoTime;
    private final @NonNull Clock workerClock;
    private final @Nullable WebAuthnNamespaceClock namespaceClock;

    WebAuthnStoreCoordinator(@NonNull WebAuthnStore store, @NonNull Duration timeout) {
        this(store, timeout, Clock.systemUTC(), null, System::nanoTime);
    }
    WebAuthnStoreCoordinator(@NonNull WebAuthnStore store, @NonNull Duration timeout,
            @NonNull LongSupplier nanoTime) {
        this(store, timeout, Clock.systemUTC(), null, nanoTime);
    }
    WebAuthnStoreCoordinator(@NonNull WebAuthnStore store, @NonNull Duration timeout,
            @NonNull Clock workerClock, @NonNull WebAuthnNamespaceClock namespaceClock) {
        this(store, timeout, workerClock, namespaceClock, System::nanoTime);
    }
    WebAuthnStoreCoordinator(@NonNull WebAuthnStore store, @NonNull Duration timeout,
            @NonNull Clock workerClock, @Nullable WebAuthnNamespaceClock namespaceClock,
            @NonNull LongSupplier nanoTime) {
        this.store=requireNonNull(store); requireNonNull(timeout);
        if (timeout.compareTo(Duration.ofMillis(100))<0 || timeout.compareTo(Duration.ofSeconds(30))>0)
            throw new IllegalArgumentException("Invalid WebAuthn operation timeout");
        this.timeoutNanos=timeout.toNanos();this.nanoTime=requireNonNull(nanoTime);
        this.workerClock=requireNonNull(workerClock);this.namespaceClock=namespaceClock;
    }
    @NonNull Attempt begin() { return new Attempt(this.nanoTime.getAsLong()); }

    final class Attempt {
        private final @NonNull Thread owner=Thread.currentThread();
        private final long startNanos;
        private long lastRemainingNanos;
        private int readCount,conflictRetries;
        private boolean finished,lastCommitConflicted,mutationUnknown,requestedCommitted,barrierUnknown;
        private @Nullable WebAuthnStoreSnapshot snapshot;
        private WebAuthnRecoveryGate.@Nullable Permit permit;
        private @Nullable Set<@NonNull WebAuthnStoreKey> firstKeys;
        private StoreTimeObservation.@Nullable Healthy profile;
        private StoreTimeObservation.@Nullable Healthy finalObservation;
        private @Nullable Instant latestTime,minimum,actionUpper,lastUpper;
        private @Nullable Duration firstObservationBudget;
        private @Nullable WebAuthnCeremonyState pinnedCeremony;
        private long finalCallStart;
        private @NonNull WebAuthnStoreCommitReceipt lastReceipt=WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE);
        private Attempt(long started) { this.startNanos=started;this.lastRemainingNanos=timeoutNanos; }

        void admit(WebAuthnRecoveryGate.@NonNull Permit permit){checkOwner();this.permit=requireNonNull(permit);}
        private boolean admitted(){
            if(remaining()==null)return false;
            try{return (this.permit==null || Boolean.TRUE.equals(this.permit.isCurrent())) && remaining()!=null;}
            catch(VirtualMachineError fatal){throw fatal;}
            catch(Throwable failure){preserveInterrupt(failure);return false;}
        }
        @NonNull Read read(@NonNull Set<@NonNull WebAuthnStoreKey> keys) {
            checkOwner();if(this.readCount!=0 || this.finished)throw new IllegalStateException("Read already attempted");
            Set<WebAuthnStoreKey> requested=Set.copyOf(keys);
            if(requested.isEmpty() || requested.size()>16)throw new IllegalArgumentException("Invalid WebAuthn read set");
            this.readCount=1;this.firstKeys=requested;return performRead(requested);
        }
        @NonNull Read readExpanded(@NonNull Set<@NonNull WebAuthnStoreKey> keys) {
            checkOwner();if(this.readCount!=1 || this.finished || this.snapshot==null || this.firstKeys==null)
                throw new IllegalStateException("No usable first read or expansion already attempted");
            Set<WebAuthnStoreKey> requested=Set.copyOf(keys);
            if(requested.size()<=this.firstKeys.size() || requested.size()>16 || !requested.containsAll(this.firstKeys))
                throw new IllegalArgumentException("Invalid expanded WebAuthn read set");
            this.readCount=2;this.snapshot=null;return performRead(requested);
        }
        private @NonNull Read performRead(@NonNull Set<@NonNull WebAuthnStoreKey> requested) {
            if(!admitted())return failRead();
            Duration budget=remaining();if(budget==null)return failRead();
            long callStart=nanoTime.getAsLong();
            try {
                WebAuthnStoreReadResult reply=store.read(requested,budget);
                if(!(reply instanceof WebAuthnStoreReadResult.Available available)
                        || !available.getSnapshot().getEntries().keySet().equals(requested))return failRead();
                WebAuthnStoreSnapshot received=available.getSnapshot();
                if(!(received.getTimeObservation() instanceof StoreTimeObservation.Healthy observed)
                        || !accept(observed,callStart,workerClock.instant(),nanoTime.getAsLong()))return failRead();
                if(namespaceClock!=null){
                    if(!requested.contains(namespaceClock.key()))return failRead();
                    var root=namespaceClock.prepare(received,observed.getObservedAt(),authorityClock(observed));
                    if(root.present()){
                        if(this.minimum!=null && !this.minimum.equals(root.minimum()))return failRead();
                        this.minimum=root.minimum();
                    }
                }
                this.snapshot=received;return Read.available(received);
            }catch(VirtualMachineError fatal){throw fatal;}
            catch(Throwable failure){preserveInterrupt(failure);return failRead();}
        }
        private @NonNull Read failRead(){this.finished=true;return Read.unavailable();}
        private boolean accept(StoreTimeObservation.@NonNull Healthy observed,long callStart,
                @NonNull Instant wall,long end) {
            if(this.profile!=null && !StoreTimeRules.sameProfile(this.profile,observed))return false;
            if(this.latestTime!=null && observed.getObservedAt().isBefore(this.latestTime))return false;
            Duration elapsed=StoreTimeRules.elapsed(callStart,end).orElse(null);
            if(elapsed==null || !StoreTimeRules.isWorkerClockHealthy(observed,wall,elapsed))return false;
            if(this.profile==null){this.profile=observed;this.firstObservationBudget=remaining();}
            this.latestTime=observed.getObservedAt();return remaining()!=null;
        }
        @NonNull Clock authorityClock(){
            if(this.snapshot==null)throw new IllegalStateException("No authoritative snapshot");
            return authorityClock((StoreTimeObservation.Healthy)this.snapshot.getTimeObservation());
        }
        private @NonNull Clock authorityClock(StoreTimeObservation.@NonNull Healthy observation){
            return Clock.fixed(observation.getObservedAt(),ZoneOffset.UTC);
        }
        @NonNull Instant observedAt(){return authorityClock().instant();}
        @NonNull Instant actionUpper(){
            checkOwner();if(this.actionUpper==null){
                if(this.profile==null || this.firstObservationBudget==null)throw new IllegalStateException("No authoritative snapshot");
                Instant upper=this.profile.getObservedAt().plus(this.firstObservationBudget);
                if(upper.getEpochSecond()<0 || upper.getEpochSecond()>253402300799L)throw new IllegalStateException("Invalid action deadline");
                this.actionUpper=upper;
            }
            return this.actionUpper;
        }
        boolean pinCeremony(@NonNull WebAuthnCeremonyState state){
            if(this.pinnedCeremony==null){this.pinnedCeremony=state;return true;}
            return this.pinnedCeremony.samePendingAs(state);
        }
        @NonNull Commit commit(@NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations){return commit(mutations,null);}
        @NonNull Commit commit(@NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations,@Nullable Instant upper){
            checkOwner();
            if(this.readCount==0 || this.finished || this.snapshot==null)throw new IllegalStateException("No usable read or write already attempted");
            WebAuthnStoreSnapshot current=this.snapshot;
            StoreTimeObservation.Healthy original=(StoreTimeObservation.Healthy)current.getTimeObservation();
            long callStart=nanoTime.getAsLong();
            WebAuthnStoreCommitReceipt receipt=invoke(mutations,upper);
            WebAuthnStoreCommitResult status=receipt.getStatus();
            if(status==WebAuthnStoreCommitResult.COMMITTED){
                StoreCommitTiming timing=receipt.getTiming().orElse(null);
                if(timing==null)return failed();
                StoreTimeObservation.Healthy validated=timing.getValidatedTime();
                if(!StoreTimeRules.sameProfile(original,validated)
                        || validated.getObservedAt().isBefore(original.getObservedAt())
                        || (upper!=null && !validated.getObservedAt().isBefore(upper)))return failed();
                if(!accept(validated,callStart,workerClock.instant(),nanoTime.getAsLong()))return failed();
                if(timing.getCompletedTime().isPresent()){
                    var completed=timing.getCompletedTime().orElseThrow();
                    if(!StoreTimeRules.sameProfile(original,completed)
                            || completed.getObservedAt().isBefore(validated.getObservedAt()))return failed();
                    this.latestTime=completed.getObservedAt();
                }
                return remaining()==null?failed():Commit.COMMITTED;
            }
            if(status==WebAuthnStoreCommitResult.UNKNOWN)return failed();
            if(remaining()==null)return failed();
            return switch(status){
                case CONFLICT -> Commit.CONFLICT;
                case CAPACITY -> Commit.CAPACITY;
                case TIME_EXPIRED -> Commit.TIME_EXPIRED;
                default -> Commit.UNAVAILABLE;
            };
        }
        /** Factual raw maintenance receipt; no service-release check may erase its effect. */
        @NonNull WebAuthnStoreCommitReceipt commitRaw(@NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations){return invoke(mutations,null);}
        private @NonNull WebAuthnStoreCommitReceipt invoke(@NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations,@Nullable Instant upper){
            checkOwner();if(this.readCount==0 || this.finished || this.snapshot==null)throw new IllegalStateException("No usable read or write already attempted");
            WebAuthnStoreSnapshot current=this.snapshot;
            StoreTimeObservation.Healthy original=(StoreTimeObservation.Healthy)current.getTimeObservation();
            Duration budget=remaining();this.finished=true;this.lastCommitConflicted=false;this.lastUpper=upper;
            if(budget==null)return rememberReceipt(WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE));
            if(upper!=null && !original.getObservedAt().isBefore(upper))
                return rememberReceipt(WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.TIME_EXPIRED));
            StoreTemporalCondition condition=StoreTimeAccess.get().fromObservation(original,original.getObservedAt(),upper);
            WebAuthnStoreWrite write=WebAuthnStoreWrite.fromSnapshotAndMutations(current,mutations,condition);
            if(!admitted())return rememberReceipt(WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE));
            budget=remaining();if(budget==null)return rememberReceipt(WebAuthnStoreCommitReceipt.fromRefusal(WebAuthnStoreCommitResult.UNAVAILABLE));
            WebAuthnStoreCommitReceipt receipt;
            try{receipt=store.compareAndCommit(write,budget);}
            catch(VirtualMachineError fatal){if(mutations.isEmpty())this.barrierUnknown=true;else this.mutationUnknown=true;throw fatal;}
            catch(Throwable failure){preserveInterrupt(failure);receipt=null;}
            if(receipt==null || receipt.getStatus()==WebAuthnStoreCommitResult.UNKNOWN){
                if(mutations.isEmpty())this.barrierUnknown=true;else this.mutationUnknown=true;
                return rememberReceipt(WebAuthnStoreCommitReceipt.unknownInstance());
            }
            this.lastReceipt=receipt;
            if(receipt.getStatus()==WebAuthnStoreCommitResult.COMMITTED){
                if(!mutations.isEmpty())this.requestedCommitted=true;
                if(namespaceClock!=null && mutations.stream().anyMatch(m->m.getKey().equals(namespaceClock.key()) && m.getKind()==WebAuthnStoreWrite.Mutation.Kind.INSERT))
                    this.minimum=original.getObservedAt();
            }
            this.lastCommitConflicted=receipt.getStatus()==WebAuthnStoreCommitResult.CONFLICT;
            return receipt;
        }
        private @NonNull WebAuthnStoreCommitReceipt rememberReceipt(@NonNull WebAuthnStoreCommitReceipt receipt){this.lastReceipt=receipt;return receipt;}
        @NonNull WebAuthnStoreCommitReceipt lastReceipt(){return this.lastReceipt;}
        @Nullable Instant releaseBefore(){return this.lastUpper;}
        @NonNull Commit failed(){return this.mutationUnknown?Commit.INDETERMINATE:this.requestedCommitted?Commit.RECONCILIATION_REQUIRED:Commit.UNAVAILABLE;}
        boolean hasMutationEffect(){return this.mutationUnknown || this.requestedCommitted;}
        boolean finalAdmission(@Nullable Instant upper){
            checkOwner();if(this.barrierUnknown)return false;
            if(namespaceClock==null)return admitted();
            if(!admitted())return false;
            Duration budget=remaining();if(budget==null)return false;
            this.finalCallStart=nanoTime.getAsLong();
            try{
                WebAuthnStoreReadResult reply=store.read(Set.of(namespaceClock.key()),budget);
                if(!(reply instanceof WebAuthnStoreReadResult.Available available)
                        || !available.getSnapshot().getEntries().keySet().equals(Set.of(namespaceClock.key())))return false;
                WebAuthnStoreSnapshot received=available.getSnapshot();
                if(!(received.getTimeObservation() instanceof StoreTimeObservation.Healthy observed))return false;
                var root=namespaceClock.prepare(received,observed.getObservedAt(),authorityClock(observed));
                if(!root.present() || this.minimum==null || !this.minimum.equals(root.minimum()))return false;
                if(!accept(observed,this.finalCallStart,workerClock.instant(),nanoTime.getAsLong()))return false;
                this.finalObservation=observed;return releaseAllowed(upper);
            }catch(VirtualMachineError fatal){throw fatal;}
            catch(Throwable failure){preserveInterrupt(failure);return false;}
        }
        boolean releaseAllowed(@Nullable Instant upper){
            if(this.finalObservation==null || remaining()==null)return false;
            Duration elapsed=StoreTimeRules.elapsed(this.finalCallStart,nanoTime.getAsLong()).orElse(null);
            return elapsed!=null && StoreTimeRules.isWorkerClockHealthy(this.finalObservation,workerClock.instant(),elapsed)
                    && (upper==null || StoreTimeRules.isReleaseBefore(this.finalObservation,elapsed,upper));
        }
        boolean retryAfterConflict(){
            checkOwner();if(!this.finished || !this.lastCommitConflicted || this.conflictRetries>=8 || hasMutationEffect())return false;
            Duration budget=remaining();if(budget==null)return false;this.conflictRetries++;
            byte[] bytes=EntropySource.fromDefaults().nextBytes(2);
            long random;try{random=((long)(bytes[0]&255)<<8)|(bytes[1]&255);}finally{Arrays.fill(bytes,(byte)0);}
            long ceiling=Math.min(2_000_000L,100_000L<<Math.min(this.conflictRetries,4));
            LockSupport.parkNanos(Math.min(50_000L+random*(ceiling-50_000L)/65535L,budget.toNanos()));
            if(remaining()==null)return false;
            this.readCount=0;this.snapshot=null;this.firstKeys=null;this.finished=false;this.lastCommitConflicted=false;return true;
        }
        @Nullable Duration remainingBudget(){checkOwner();return remaining();}
        private @Nullable Duration remaining(){
            if(Thread.currentThread().isInterrupted())return null;
            Duration left=StoreTimeRules.remainingBudget(Duration.ofNanos(timeoutNanos),this.startNanos,nanoTime.getAsLong()).orElse(null);
            if(left==null)return null;long nanos=Math.min(this.lastRemainingNanos,left.toNanos());this.lastRemainingNanos=nanos;
            return nanos>0?Duration.ofNanos(nanos):null;
        }
        private void checkOwner(){if(!Thread.currentThread().equals(this.owner))throw new IllegalStateException("WebAuthn store attempt used on another thread");}
    }
    @SuppressWarnings("ReferenceEquality")
    static void preserveInterrupt(@NonNull Throwable failure){
        Throwable current=failure;
        for(int depth=0;depth<16;depth++){
            if(current instanceof InterruptedException || current instanceof java.io.InterruptedIOException){Thread.currentThread().interrupt();return;}
            Throwable cause;try{cause=current.getCause();}catch(VirtualMachineError fatal){throw fatal;}catch(Throwable malformed){return;}
            if(cause==null || cause==current)return;current=cause;
        }
    }
    @Immutable static final class Read {
        private static final @NonNull Read UNAVAILABLE=new Read(null);
        private final @Nullable WebAuthnStoreSnapshot snapshot;
        private Read(@Nullable WebAuthnStoreSnapshot snapshot){this.snapshot=snapshot;}
        private static @NonNull Read available(@NonNull WebAuthnStoreSnapshot snapshot){return new Read(requireNonNull(snapshot));}
        private static @NonNull Read unavailable(){return UNAVAILABLE;}
        boolean isAvailable(){return this.snapshot!=null;}
        @NonNull WebAuthnStoreSnapshot getSnapshot(){if(this.snapshot==null)throw new IllegalStateException("No authoritative snapshot");return this.snapshot;}
        @Override public @NonNull String toString(){return this.snapshot==null?"Read{UNAVAILABLE}":"Read{AVAILABLE, <redacted>}";}
    }
    enum Commit { COMMITTED, CONFLICT, CAPACITY, UNAVAILABLE, INDETERMINATE, RECONCILIATION_REQUIRED, TIME_EXPIRED }
}
