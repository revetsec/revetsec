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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.testing.ScriptedWebAuthnStore;
import com.revetsec.webauthn.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

/** Genuine engine transactions with separate worker/authority controls and independent retained-state checks. */
final class WebAuthnSharedClockEngineTests {
    private static final @NonNull String NAMESPACE="shared-clock-tests",RP="login.example.com",ORIGIN="https://"+RP;
    private static final @NonNull Instant BASE=Instant.parse("2026-10-09T12:00:00Z");
    private static final byte @NonNull [] HANDLE={4,5,6},CREDENTIAL_ID={1,2,3},BINDING=filled(65);

    @Test void toleratedWorkerOffsetNeverBecomesRootFloorEntityFloorOrCeremonyExpiry() throws Exception {
        F f=new F();f.worker.set(BASE.plusSeconds(2));var request=prepared(f.begin(HANDLE));
        for(var key:f.source.records().keySet())try(var decoded=f.decoded(key)){assertEquals(BASE,decoded.floor());}
        WebAuthnCeremonyState pending=f.ceremony(request);assertEquals(BASE,pending.issuedAt());assertEquals(BASE.plusSeconds(300),pending.expiresAt());
    }
    @Test void fastWorkerCannotPoisonTheNamespaceOrAnotherWorker() {
        F f=new F();f.worker.set(BASE.plusSeconds(6));assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.begin(HANDLE).status());
        assertEquals(0,f.store.writes.size());assertTrue(f.source.records().isEmpty());
        var healthy=f.engine(new WorkerClock(BASE),Duration.ofSeconds(30));assertEquals(WebAuthnEngine.Status.PREPARED,healthy.beginRegistration(HANDLE,BINDING).status());
    }
    @Test void wholeCausalWorkerSampleOccursAfterTheStoreReply() {
        F f=new F();f.store.afterRead=(n,result)->{if(n==1)f.worker.set(BASE.plusSeconds(6));return result;};
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.begin(HANDLE).status());assertEquals(0,f.store.writes.size());
    }
    @Test void unrelatedAccountsNeverRewriteOrConflictForNamespaceTime() throws Exception {
        F f=new F();prepared(f.begin(HANDLE));byte[] version=f.record(f.root()).getVersion();f.advance(Duration.ofSeconds(1));f.reset();
        var pool=Executors.newFixedThreadPool(8);CountDownLatch start=new CountDownLatch(1);
        try{
            List<java.util.concurrent.Future<WebAuthnEngine.Start>> jobs=new ArrayList<>();
            for(int i=0;i<8;i++){byte[] handle={(byte)(20+i)};jobs.add(pool.submit(()->{assertTrue(start.await(5,TimeUnit.SECONDS));return f.begin(handle);}));}
            start.countDown();for(var job:jobs)assertEquals(WebAuthnEngine.Status.PREPARED,job.get(10,TimeUnit.SECONDS).status());
        }finally{pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}
        assertEquals(8,f.store.writes.size());assertEquals(0,f.store.conflicts.get());assertArrayEquals(version,f.record(f.root()).getVersion());
        assertTrue(f.store.writes.stream().flatMap(w->w.getMutations().stream()).noneMatch(m->m.getKey().getKind()==WebAuthnStoreKey.Kind.NAMESPACE_CLOCK));
    }
    @Test void listingIsPureEvenAfterUnrelatedCeremonyExpiry() {
        F f=new F();prepared(f.begin(HANDLE));f.advance(Duration.ofSeconds(301));var before=f.source.records();f.reset();
        assertEquals(WebAuthnEngine.ManagementStatus.LISTED,f.engine.listCredentials(HANDLE).status());assertEquals(0,f.store.writes.size());
        assertRecordsSame(before,f.source.records());
    }
    @Test void futureAuthenticatedEntityFloorClosesUntilAuthorityCatchupWithoutClamping() throws Exception {
        F f=new F();var root=WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{1},f.records.sealNamespace(f.root(),f.source.admission().getAuthorityId(),BASE));
        var fenceCodec=new WebAuthnAccountFence(NAMESPACE,RP,f.records);var fence=fenceCodec.encode(HANDLE,true,BASE.plusSeconds(10));
        f.source.seedClosedMigration(Map.of(f.root(),root,fence.key(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{2},fence.sealedBytes())));
        assertEquals(WebAuthnEngine.ManagementStatus.UNAVAILABLE,f.engine.listCredentials(HANDLE).status());assertEquals(0,f.store.writes.size());
        f.advance(Duration.ofSeconds(10));assertEquals(WebAuthnEngine.ManagementStatus.LISTED,f.engine.listCredentials(HANDLE).status());assertEquals(0,f.store.writes.size());
    }
    @Test void negativeAuthenticatedRootMinimumKeepsTimedAdmissionClosed() {
        F f=new F();seedFloors(f,BASE.minusSeconds(BASE.getEpochSecond()+1),BASE);
        var before=f.source.records();assertEquals(WebAuthnEngine.ManagementStatus.UNAVAILABLE,f.engine.listCredentials(HANDLE).status());
        assertEquals(0,f.store.writes.size());assertRecordsSame(before,f.source.records());
    }
    @Test void negativeAuthenticatedEntityFloorKeepsTimedAdmissionClosed() {
        F f=new F();seedFloors(f,BASE,Instant.EPOCH.minusNanos(1));
        var before=f.source.records();assertEquals(WebAuthnEngine.ManagementStatus.UNAVAILABLE,f.engine.listCredentials(HANDLE).status());
        assertEquals(0,f.store.writes.size());assertRecordsSame(before,f.source.records());
    }
    @Test void epochZeroRemainsAValidNonnegativeAuthenticatedFloor() {
        F f=new F();seedFloors(f,Instant.EPOCH,Instant.EPOCH);
        assertEquals(WebAuthnEngine.ManagementStatus.LISTED,f.engine.listCredentials(HANDLE).status());assertEquals(0,f.store.writes.size());
    }
    @Test void admissionClosingAfterReadPreventsAnUnenteredBeginMutation() {
        F f=new F();f.store.afterRead=(n,r)->{if(n==1)f.gate.open.set(false);return r;};
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.begin(HANDLE).status());assertEquals(0,f.store.writes.size());assertTrue(f.source.records().isEmpty());
    }
    @Test void admissionClosingAfterExpandedReadPreventsCredentialAndCeremonyConsumption() throws Exception {
        F f=new F();KeyPair pair=f.enroll();var request=prepared(f.engine.beginAuthentication(BINDING));f.reset();var before=f.source.records();
        f.store.afterRead=(n,r)->{if(n==2)f.gate.open.set(false);return r;};
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.engine.completeAuthentication(request.ceremonyId(),BINDING,assertionJson(pair.getPrivate(),Base64Url.encode(request.challenge()),1)).status());
        assertEquals(0,f.store.writes.size());assertRecordsSame(before,f.source.records());
    }
    private static void seedFloors(@NonNull F f,@NonNull Instant rootFloor,@NonNull Instant entityFloor) {
        var root=WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{1},f.records.sealNamespace(f.root(),f.source.admission().getAuthorityId(),rootFloor));
        var encoded=new WebAuthnAccountFence(NAMESPACE,RP,f.records).encode(HANDLE,true,entityFloor);
        f.source.seedClosedMigration(Map.of(f.root(),root,encoded.key(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{2},encoded.sealedBytes())));
    }
    @Test void normalOperationsRejectLegacyWar1InsteadOfPromotingIt() {
        F f=new F();byte[] oldRoot=ByteBuffer.allocate(13).put((byte)1).putLong(BASE.getEpochSecond()).putInt(BASE.getNano()).array();
        byte[] legacy=f.records.seal(f.root(),oldRoot,WebAuthnRecordPayloadV2.PERMANENT);
        f.source.seedClosedMigration(Map.of(f.root(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{1},legacy)));
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.begin(HANDLE).status());assertEquals(0,f.store.writes.size());
    }
    @Test void ownRootInitializationPinsExactlyItsCommittedMinimum() {
        F f=new F();f.store.afterRead=(n,result)->{
            if(n!=2 || !(result instanceof WebAuthnStoreReadResult.Available available))return result;
            byte[] alternate=f.records.sealNamespace(f.root(),f.source.admission().getAuthorityId(),BASE.minusSeconds(1));
            var original=assertInstanceOf(WebAuthnStoreEntry.Present.class,available.getSnapshot().getEntry(f.root()));
            return WebAuthnStoreReadResult.Available.fromSnapshot(WebAuthnStoreSnapshot.fromEntries(Set.of(f.root()),
                    Map.of(f.root(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(original.getVersion(),alternate)),available.getSnapshot().getTimeObservation()));
        };
        assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,f.begin(HANDLE).status());assertEquals(1,f.store.writes.size());
    }
    @Test void knownBeginCommitWithTimeOutageRequiresReconciliationWithoutRequest() {
        F f=new F();f.store.afterCommit=(n,w,r)->{f.source.setHealthy(false);return r;};var result=f.begin(HANDLE);
        assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,result.status());assertNull(result.request());assertEquals(1,f.store.writes.size());
        assertTrue(f.source.records().keySet().stream().anyMatch(k->k.getKind()==WebAuthnStoreKey.Kind.CEREMONY));
    }
    @SuppressWarnings("NullAway") // Deliberately broken application SPI: a null acknowledgement is uncertain.
    @Test void unknownAppliedBeginIsNeverRescuedByAReadableMatchingRow() {
        for(boolean brokenNull:List.of(false,true)){
            F f=new F();f.store.afterCommit=(n,w,r)->brokenNull?null:WebAuthnStoreCommitReceipt.unknownInstance();var result=f.begin(HANDLE);
            assertEquals(WebAuthnEngine.Status.INDETERMINATE,result.status());assertNull(result.request());assertEquals(1,f.store.writes.size());assertEquals(1,f.store.reads.get());
            assertFalse(f.source.records().isEmpty());
        }
    }
    @Test void disablingBeforeEnrollmentInitializesAResistantFenceAndStableRoot() {
        F f=new F();assertEquals(WebAuthnEngine.ManagementStatus.DISABLED,f.engine.disableAccount(HANDLE).status());
        assertEquals(1,f.store.writes.size());assertTrue(f.source.records().containsKey(f.root()));f.reset();
        assertEquals(WebAuthnEngine.Status.REJECTED,f.begin(HANDLE).status());assertEquals(0,f.store.writes.size());
    }
    @Test void committedDisableKeepsItsFactAcrossPermitCloseFailure() throws Exception {
        F f=new F();prepared(f.begin(HANDLE));f.reset();f.gate.failClose.set(true);
        assertEquals(WebAuthnEngine.ManagementStatus.RECONCILIATION_REQUIRED,f.engine.disableAccount(HANDLE).status());assertEquals(1,f.store.writes.size());
        var key=WebAuthnStoreKey.forAccountFence(NAMESPACE,RP,HANDLE);assertFalse(new WebAuthnAccountFence(NAMESPACE,RP,f.records).decode(key,f.record(key).getSealedBytes(),f.authorityClock()).isActive());
    }
    @Test void rawPermanentResealKeepsKnownCommitAfterPermitCloseFailureAndReadsNoFinalCheckpoint() throws Exception {
        F f=new F();prepared(f.begin(HANDLE));var key=WebAuthnStoreKey.forAccountFence(NAMESPACE,RP,HANDLE);Instant before;
        try(var decoded=f.decoded(key)){before=decoded.floor();}f.advance(Duration.ofSeconds(3));f.reset();f.gate.failClose.set(true);
        var receipt=f.engine.resealStoreEntry(key);assertEquals(WebAuthnStoreCommitResult.COMMITTED,receipt.getStatus());assertTrue(receipt.getTiming().isPresent());
        assertEquals(1,f.store.reads.get());assertEquals(1,f.store.writes.size());try(var decoded=f.decoded(key)){assertEquals(before,decoded.floor());}
    }
    @Test void generationChangeBeforeFinalReadWithholdsKnownCommit() {
        F f=new F();f.store.afterCommit=(n,w,r)->{f.source.rotateClockGeneration();return r;};assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,f.begin(HANDLE).status());
    }
    @Test void generationChangeAfterCapturedFinalSnapshotIsLaterState() {
        F f=new F();f.store.afterRead=(n,r)->{if(n==2)f.source.rotateClockGeneration();return r;};assertEquals(WebAuthnEngine.Status.PREPARED,f.begin(HANDLE).status());
    }
    @Test void missingOptionalCompletionIsRescuedByFreshMinimalRootRead() {
        F f=new F();f.store.afterCommit=(n,w,r)->{assertTrue(r.getTiming().orElseThrow().getCompletedTime().isEmpty());return r;};
        assertEquals(WebAuthnEngine.Status.PREPARED,f.begin(HANDLE).status());assertEquals(2,f.store.reads.get());assertEquals(Set.of(f.root()),f.store.lastRead);
    }
    @Test void foreignRequiredValidationProfileKeepsKnownCommitWithoutReadRescue() {
        F f=new F();f.store.afterCommit=(n,w,r)->{var v=r.getTiming().orElseThrow().getValidatedTime();return WebAuthnStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(StoreTimeObservation.Healthy.fromObservation(v.getAdmission(),v.getClockGeneration(),v.getObservedAt(),Duration.ofMillis(1)),null));};
        assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,f.begin(HANDLE).status());assertEquals(1,f.store.reads.get());assertEquals(1,f.store.writes.size());
    }
    @Test void malformedKnownCommitMissingRequiredTimingCannotBeRescued() throws Exception {
        F f=new F();f.store.afterCommit=(n,w,r)->{try{Field field=WebAuthnStoreCommitReceipt.class.getDeclaredField("timing");field.setAccessible(true);field.set(r,null);}catch(ReflectiveOperationException e){throw new LinkageError(e.getMessage(),e);}return r;};
        assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,f.begin(HANDLE).status());assertEquals(1,f.store.reads.get());assertFalse(f.source.records().isEmpty());
    }
    @Test void finalReadCannotRegressBelowUsableCompletionTime() {
        F f=new F();f.store.afterCommit=(n,w,r)->{var v=r.getTiming().orElseThrow().getValidatedTime();return WebAuthnStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(v,ScriptedWebAuthnStore.observation(v.getAdmission(),v.getClockGeneration(),BASE.plusMillis(1))));};
        assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,f.begin(HANDLE).status());assertEquals(2,f.store.reads.get());
    }
    @Test void conflictKeepsOriginalCeremonyIdentityChallengeIssuedTimeAndExpiry() throws Exception {
        F f=new F();prepared(f.begin(HANDLE));f.reset();List<WebAuthnCeremonyState> candidates=new ArrayList<>();
        f.store.beforeCommit=(n,w)->{var m=w.getMutations().stream().filter(v->v.getKey().getKind()==WebAuthnStoreKey.Kind.CEREMONY).findFirst().orElseThrow();candidates.add(new WebAuthnCeremonyRecordCodec(NAMESPACE,RP,f.records).decode(m.getKey(),m.getSealedBytes().orElseThrow(),f.authorityClock()));if(n==1){f.advance(Duration.ofSeconds(5));return refusal(WebAuthnStoreCommitResult.CONFLICT);}return null;};
        var request=prepared(f.begin(new byte[]{9}));assertEquals(2,candidates.size());assertArrayEquals(candidates.get(0).ceremonyId(),candidates.get(1).ceremonyId());assertArrayEquals(candidates.get(0).challenge(),candidates.get(1).challenge());assertEquals(BASE,candidates.get(1).issuedAt());assertEquals(BASE.plusSeconds(300),candidates.get(1).expiresAt());assertArrayEquals(request.ceremonyId(),candidates.get(0).ceremonyId());
        assertEquals(f.store.writes.get(0).getTemporalCondition().getValidBeforeExclusive(),f.store.writes.get(1).getTemporalCondition().getValidBeforeExclusive());
    }
    @Test void exactExpiryBeforeStoreValidationRejectsWithoutMutationOrRetry() {
        F f=new F();prepared(f.begin(HANDLE));f.reset();var before=f.source.records();
        f.store.beforeCommit=(n,w)->{Instant upper=w.getTemporalCondition().getValidBeforeExclusive().orElseThrow();f.advance(Duration.between(f.source.authorityTime(),upper));return null;};
        assertEquals(WebAuthnEngine.Status.REJECTED,f.begin(new byte[]{11}).status());assertEquals(1,f.store.writes.size());assertRecordsSame(before,f.source.records());
    }
    @Test void committedRegistrationWithLostFinalAdmissionDoesNotReleaseProof() throws Exception {
        F f=new F();var request=prepared(f.begin(HANDLE));KeyPair pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();f.reset();f.store.afterCommit=(n,w,r)->{f.source.setHealthy(false);return r;};
        var done=f.engine.completeRegistration(request.ceremonyId(),BINDING,registrationJson(pair,Base64Url.encode(request.challenge())));
        assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,done.status());assertNull(done.verified());assertEquals(1,f.store.writes.size());
        assertTrue(f.source.records().containsKey(WebAuthnStoreKey.forCredential(NAMESPACE,RP,CREDENTIAL_ID)));
    }
    @Test void committedAuthenticationGenerationLossPreservesConsumptionAndCounter() throws Exception {
        F f=new F();KeyPair pair=f.enroll();var request=prepared(f.engine.beginAuthentication(BINDING));f.reset();f.store.afterCommit=(n,w,r)->{f.source.rotateClockGeneration();return r;};
        var done=f.engine.completeAuthentication(request.ceremonyId(),BINDING,assertionJson(pair.getPrivate(),Base64Url.encode(request.challenge()),1));
        assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,done.status());assertNull(done.verified());assertEquals(1,f.store.writes.size());
        var key=WebAuthnStoreKey.forCredential(NAMESPACE,RP,CREDENTIAL_ID);assertEquals(1,new WebAuthnCredentialRecordCodec(NAMESPACE,RP,f.records).decode(key,f.record(key).getSealedBytes(),f.authorityClock()).counter());
        assertFalse(f.ceremony(request).isPendingAt(f.source.authorityTime()));
    }
    @Test void authenticationExpiryDuringStoreWaitCannotConsumeTheCeremonyOrCounter() throws Exception {
        F f=new F();KeyPair pair=f.enroll();var request=prepared(f.engine.beginAuthentication(BINDING));f.reset();var before=f.source.records();
        f.store.beforeCommit=(n,w)->{Instant upper=w.getTemporalCondition().getValidBeforeExclusive().orElseThrow();f.advance(Duration.between(f.source.authorityTime(),upper));return null;};
        assertEquals(WebAuthnEngine.Status.REJECTED,f.engine.completeAuthentication(request.ceremonyId(),BINDING,assertionJson(pair.getPrivate(),Base64Url.encode(request.challenge()),1)).status());
        assertEquals(1,f.store.writes.size());assertRecordsSame(before,f.source.records());
    }
    @Test void queryOnlyExpiryCannotReviveAfterAnEarlierClockGeneration() {
        F f=new F();prepared(f.begin(HANDLE));f.advance(Duration.ofSeconds(301));assertEquals(WebAuthnEngine.ManagementStatus.LISTED,f.engine.listCredentials(HANDLE).status());f.reset();
        f.source.rotateClockGeneration();f.source.setTime(BASE);f.worker.set(BASE);
        assertEquals(WebAuthnEngine.ManagementStatus.UNAVAILABLE,f.engine.listCredentials(HANDLE).status());assertEquals(0,f.store.writes.size());
    }
    @Test void lateKnownAcknowledgementRemainsReconciliationAndLateNoEffectRemainsUnavailable() {
        for(boolean effect:List.of(false,true)){
            F f=new F();prepared(f.begin(HANDLE));f.reset();WebAuthnEngine shortBudget=f.engine(f.worker,Duration.ofMillis(100));
            if(effect)f.store.afterCommit=(n,w,r)->{pause();return r;};else f.store.beforeCommit=(n,w)->{pause();return refusal(WebAuthnStoreCommitResult.CAPACITY);};
            var result=shortBudget.beginRegistration(new byte[]{12},BINDING);
            assertEquals(effect?WebAuthnEngine.Status.RECONCILIATION_REQUIRED:WebAuthnEngine.Status.UNAVAILABLE,result.status());assertNull(result.request());assertEquals(1,f.store.writes.size());
        }
    }
    @Test void rawResealRefusesCeremoniesAndPreservesUnknownRatherThanReadingForRescue() {
        F f=new F();var request=prepared(f.begin(HANDLE));assertThrows(IllegalArgumentException.class,()->f.engine.resealStoreEntry(WebAuthnStoreKey.forCeremony(NAMESPACE,RP,request.ceremonyId())));f.reset();
        f.store.afterCommit=(n,w,r)->WebAuthnStoreCommitReceipt.unknownInstance();assertEquals(WebAuthnStoreCommitResult.UNKNOWN,f.engine.resealStoreEntry(f.root()).getStatus());assertEquals(1,f.store.writes.size());assertEquals(1,f.store.reads.get());
    }
    private static void pause(){try{Thread.sleep(200);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new IllegalStateException(e);}}
    private static @NonNull WebAuthnStoreCommitReceipt refusal(@NonNull WebAuthnStoreCommitResult status){return WebAuthnStoreCommitReceipt.fromRefusal(status);}
    private static WebAuthnEngine.@NonNull Request prepared(WebAuthnEngine.@NonNull Start result){assertEquals(WebAuthnEngine.Status.PREPARED,result.status());return Objects.requireNonNull(result.request());}
    private static void assertRecordsSame(@NonNull Map<@NonNull WebAuthnStoreKey,WebAuthnStoreEntry.@NonNull Present> first,@NonNull Map<@NonNull WebAuthnStoreKey,WebAuthnStoreEntry.@NonNull Present> second){assertEquals(first.keySet(),second.keySet());for(var key:first.keySet()){assertArrayEquals(Objects.requireNonNull(first.get(key)).getVersion(),Objects.requireNonNull(second.get(key)).getVersion());assertArrayEquals(Objects.requireNonNull(first.get(key)).getSealedBytes(),Objects.requireNonNull(second.get(key)).getSealedBytes());}}
    @FunctionalInterface private interface BeforeCommit { @Nullable WebAuthnStoreCommitReceipt apply(int number,@NonNull WebAuthnStoreWrite write) throws Exception; }
    @FunctionalInterface private interface AfterCommit { @NonNull WebAuthnStoreCommitReceipt apply(int number,@NonNull WebAuthnStoreWrite write,@NonNull WebAuthnStoreCommitReceipt receipt); }
    @FunctionalInterface private interface AfterRead { @NonNull WebAuthnStoreReadResult apply(int number,@NonNull WebAuthnStoreReadResult result); }
    @ThreadSafe private static final class RecordingStore implements WebAuthnStore {
        final @NonNull ScriptedWebAuthnStore source;
        final @NonNull AtomicInteger reads=new AtomicInteger(),conflicts=new AtomicInteger();
        final @NonNull List<@NonNull WebAuthnStoreWrite> writes=new CopyOnWriteArrayList<>();
        volatile @Nullable BeforeCommit beforeCommit;volatile @Nullable AfterCommit afterCommit;volatile @Nullable AfterRead afterRead;
        volatile @NonNull Set<@NonNull WebAuthnStoreKey> lastRead=Set.of();
        RecordingStore(@NonNull ScriptedWebAuthnStore source){this.source=source;}
        @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){int n=this.reads.incrementAndGet();this.lastRead=keys;var reply=this.source.read(keys,budget);AfterRead hook=this.afterRead;return hook==null?reply:hook.apply(n,reply);}
        @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){this.writes.add(write);int n=this.writes.size();BeforeCommit before=this.beforeCommit;WebAuthnStoreCommitReceipt result;
            try{result=before==null?null:before.apply(n,write);}catch(Exception e){throw new IllegalStateException(e);}
            if(result==null)result=this.source.compareAndCommit(write,budget);if(result.getStatus()==WebAuthnStoreCommitResult.CONFLICT)this.conflicts.incrementAndGet();AfterCommit after=this.afterCommit;return after==null?result:after.apply(n,write,result);}
    }
    @ThreadSafe private static final class WorkerClock extends Clock {
        private final @NonNull AtomicReference<@NonNull Instant> value;
        WorkerClock(@NonNull Instant initial){this.value=new AtomicReference<>(initial);}
        void set(@NonNull Instant time){this.value.set(time);}
        @Override public @NonNull Instant instant(){return Objects.requireNonNull(this.value.get());}
        @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return Clock.fixed(instant(),zone);}
    }
    @ThreadSafe private static final class Gate implements WebAuthnRecoveryGate {
        final @NonNull AtomicBoolean failClose=new AtomicBoolean(),open=new AtomicBoolean(true);
        @Override public @NonNull Permit acquire(@NonNull Duration budget){return new Permit(){@Override public @NonNull Boolean isCurrent(){return open.get();}@Override public void close(){if(failClose.getAndSet(false))throw new IllegalStateException("Scripted close failure");}};}
    }
    @NotThreadSafe private static final class F {
        final @NonNull ScriptedWebAuthnStore source=new ScriptedWebAuthnStore(BASE);
        final @NonNull RecordingStore store=new RecordingStore(this.source);
        final @NonNull WorkerClock worker=new WorkerClock(BASE);
        final @NonNull Gate gate=new Gate();
        final @NonNull StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).clock(Clock.fixed(BASE,ZoneOffset.UTC)).maximumSealedLength(16384).build();
        final @NonNull WebAuthnRecordCodec records=new WebAuthnRecordCodec(this.sealer);
        final @NonNull WebAuthnEngine engine=engine(this.worker,Duration.ofSeconds(30));
        @NonNull WebAuthnEngine engine(@NonNull Clock workerClock,@NonNull Duration timeout){return new WebAuthnEngine(NAMESPACE,RP,Set.of(ORIGIN),this.store,this.sealer,this.gate,workerClock,WebAuthnSettings.builder().operationTimeout(timeout).build());}
        WebAuthnEngine.@NonNull Start begin(byte @NonNull [] handle){return this.engine.beginRegistration(handle,BINDING);}
        void advance(@NonNull Duration duration){this.source.advance(duration);this.worker.set(this.worker.instant().plus(duration));}
        void reset(){this.store.reads.set(0);this.store.conflicts.set(0);this.store.writes.clear();this.store.beforeCommit=null;this.store.afterCommit=null;this.store.afterRead=null;}
        @NonNull WebAuthnStoreKey root(){return WebAuthnStoreKey.forNamespaceClock(NAMESPACE,RP);}
        WebAuthnStoreEntry.@NonNull Present record(@NonNull WebAuthnStoreKey key){return Objects.requireNonNull(this.source.records().get(key));}
        @NonNull Clock authorityClock(){return Clock.fixed(this.source.authorityTime(),ZoneOffset.UTC);}
        WebAuthnRecordPayloadV2.@NonNull Decoded decoded(@NonNull WebAuthnStoreKey key) throws WebAuthnRecordException{return this.records.openAdmittedRecord(key,record(key).getSealedBytes(),authorityClock());}
        @NonNull WebAuthnCeremonyState ceremony(WebAuthnEngine.@NonNull Request request) throws WebAuthnRecordException {var key=WebAuthnStoreKey.forCeremony(NAMESPACE,RP,request.ceremonyId());return new WebAuthnCeremonyRecordCodec(NAMESPACE,RP,this.records).decode(key,record(key).getSealedBytes(),authorityClock());}
        @NonNull KeyPair enroll() throws Exception {var request=prepared(begin(HANDLE));KeyPair pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();assertEquals(WebAuthnEngine.Status.SUCCEEDED,this.engine.completeRegistration(request.ceremonyId(),BINDING,registrationJson(pair,Base64Url.encode(request.challenge()))).status());return pair;}
    }
    private static byte @NonNull [] registrationJson(@NonNull KeyPair pair,
            @NonNull String challenge) {
        byte[] auth = registrationAuth(pair);
        String id = Base64Url.encode(CREDENTIAL_ID);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.create", challenge))
                + "\",\"authenticatorData\":\"" + Base64Url.encode(auth)
                + "\",\"attestationObject\":\"" + Base64Url.encode(attestation(auth))
                + "\",\"publicKeyAlgorithm\":-8,\"transports\":[\"usb\"]},"
                + "\"clientExtensionResults\":{\"credProps\":{\"rk\":true}}}");
    }

    private static byte @NonNull [] assertionJson(@NonNull PrivateKey key,
            @NonNull String challenge, long counter) throws Exception {
        byte[] auth = assertionAuth(counter);
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(key);
        signer.update(auth);
        signer.update(hash(clientJson("webauthn.get", challenge)));
        String id = Base64Url.encode(CREDENTIAL_ID);
        return json("{\"id\":\"" + id + "\",\"rawId\":\"" + id
                + "\",\"type\":\"public-key\",\"response\":{\"clientDataJSON\":\""
                + Base64Url.encode(clientJson("webauthn.get", challenge))
                + "\",\"authenticatorData\":\"" + Base64Url.encode(auth)
                + "\",\"signature\":\"" + Base64Url.encode(signer.sign())
                + "\",\"userHandle\":\"" + Base64Url.encode(HANDLE)
                + "\"},\"clientExtensionResults\":{}}");
    }

    private static byte @NonNull [] clientJson(@NonNull String type, @NonNull String challenge) {
        return json("{\"type\":\"" + type + "\",\"challenge\":\"" + challenge
                + "\",\"origin\":\"" + ORIGIN + "\",\"crossOrigin\":false}");
    }

    private static byte @NonNull [] registrationAuth(@NonNull KeyPair pair) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII)));
        out.write(0x45); out.writeBytes(new byte[4]); out.writeBytes(new byte[16]);
        out.write(0); out.write(CREDENTIAL_ID.length); out.writeBytes(CREDENTIAL_ID);
        out.writeBytes(edKey(pair));
        return out.toByteArray();
    }

    private static byte @NonNull [] assertionAuth(long counter) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(hash(RP.getBytes(StandardCharsets.US_ASCII))); out.write(0x05);
        out.write((int) (counter >>> 24)); out.write((int) (counter >>> 16));
        out.write((int) (counter >>> 8)); out.write((int) counter);
        return out.toByteArray();
    }

    private static byte @NonNull [] attestation(byte @NonNull [] auth) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa3); text(out, "fmt"); text(out, "none");
        text(out, "authData"); bytes(out, auth); text(out, "attStmt"); out.write(0xa0);
        return out.toByteArray();
    }

    private static byte @NonNull [] edKey(@NonNull KeyPair pair) {
        byte[] spki = pair.getPublic().getEncoded();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(0xa4); out.write(1); out.write(1); out.write(3); out.write(0x27);
        out.write(0x20); out.write(6); out.write(0x21); out.write(0x58); out.write(32);
        out.writeBytes(Arrays.copyOfRange(spki, spki.length - 32, spki.length));
        return out.toByteArray();
    }

    private static void text(@NonNull ByteArrayOutputStream out, @NonNull String value) {
        byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
        out.write(0x60 | bytes.length); out.writeBytes(bytes);
    }
    private static void bytes(@NonNull ByteArrayOutputStream out, byte @NonNull [] value) {
        if (value.length < 24) out.write(0x40 | value.length);
        else if (value.length < 256) { out.write(0x58); out.write(value.length); }
        else { out.write(0x59); out.write(value.length >>> 8); out.write(value.length); }
        out.writeBytes(value);
    }
    private static byte @NonNull [] hash(byte @NonNull [] input) {
        try { return MessageDigest.getInstance("SHA-256").digest(input); }
        catch (java.security.NoSuchAlgorithmException exception) { throw new IllegalStateException(exception); }
    }
    private static byte @NonNull [] json(@NonNull String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
    private static byte @NonNull [] filled(int first) {
        byte[] result = new byte[32];
        for (int i = 0; i < result.length; i++) result[i] = (byte) (first + i);
        return result;
    }

}
