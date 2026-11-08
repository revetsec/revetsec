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
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.util.stream.Stream;
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
import java.util.HashMap;
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
    @org.junit.jupiter.api.TestFactory
    @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk01OneDayFastWorkerCannotPoisonExactHealthyComparison() {
        List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
        for(int healthyNanos:List.of(0,1))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-01/WEBAUTHN/fast=1day/healthy="+healthyNanos+"ns",()->{
            F f=new F();prepared(f.begin(new byte[]{7,8,9}));var before=Map.copyOf(f.source.records());f.reset();f.worker.set(BASE.plus(Duration.ofDays(1)));
            assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.begin(HANDLE).status());assertTrue(f.store.writes.isEmpty());assertEquals(before,f.source.records());
            var healthy=f.engine(new WorkerClock(BASE.plusNanos(healthyNanos)),Duration.ofSeconds(30));var request=prepared(healthy.beginRegistration(HANDLE,BINDING));
            var pending=f.ceremony(request);assertEquals(BASE,pending.issuedAt());assertEquals(BASE.plusSeconds(300),pending.expiresAt());
            KeyPair pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            assertEquals(WebAuthnEngine.Status.SUCCEEDED,healthy.completeRegistration(request.ceremonyId(),BINDING,registrationJson(pair,Base64Url.encode(request.challenge()))).status());
            for(var key:before.keySet()){assertArrayEquals(before.get(key).getVersion(),f.record(key).getVersion());assertArrayEquals(before.get(key).getSealedBytes(),f.record(key).getSealedBytes());}
            for(var key:f.source.records().keySet())try(var decoded=f.decoded(key)){assertEquals(BASE,decoded.floor());}
        }));return cases;
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
    @TestFactory @NonNull Stream<@NonNull DynamicTest> scEng09CredentialListStateAndRawClockMatrixIsPure() {
        return Stream.of("live","empty","missing-root","corrupt-fence","corrupt-index","read-unavailable","worker-backward","worker-forward")
            .map(state->DynamicTest.dynamicTest("SC-ENG-09/WEBAUTHN/list/"+state,()->{
                F f=new F();
                if(state.equals("empty"))prepared(f.begin(new byte[]{7,8,9}));
                else f.enroll();
                if(state.equals("missing-root"))mig15FixtureRows(f.source).remove(f.root());
                var before=f.source.records();f.reset();
                if(state.startsWith("corrupt-"))f.store.afterRead=(number,result)->{
                    if(number!=1)return result;
                    WebAuthnStoreSnapshot snapshot=assertInstanceOf(WebAuthnStoreReadResult.Available.class,result).getSnapshot();
                    WebAuthnStoreKey key=state.equals("corrupt-fence")
                        ?WebAuthnStoreKey.forAccountFence(NAMESPACE,RP,HANDLE)
                        :WebAuthnStoreKey.forAccountCredentialIndex(NAMESPACE,RP,HANDLE);
                    WebAuthnStoreEntry.Present original=Objects.requireNonNull(before.get(key));byte[] damaged=original.getSealedBytes();damaged[damaged.length/2]^=1;
                    Map<WebAuthnStoreKey,WebAuthnStoreEntry> entries=new HashMap<>(snapshot.getEntries());
                    entries.put(key,WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(original.getVersion(),damaged));
                    return WebAuthnStoreReadResult.Available.fromSnapshot(WebAuthnStoreSnapshot.fromEntries(entries.keySet(),entries,snapshot.getTimeObservation()));
                };
                if(state.equals("read-unavailable"))f.store.afterRead=(number,result)->number==1?WebAuthnStoreReadResult.Unavailable.get():result;
                if(state.equals("worker-backward"))f.worker.set(BASE.minusSeconds(6));
                if(state.equals("worker-forward"))f.worker.set(BASE.plusSeconds(6));
                WebAuthnEngine.Management result=f.engine.listCredentials(HANDLE);
                if(state.equals("live")){assertEquals(WebAuthnEngine.ManagementStatus.LISTED,result.status());assertEquals(1,result.credentialIds().size());}
                else if(state.equals("empty")){assertEquals(WebAuthnEngine.ManagementStatus.LISTED,result.status());assertTrue(result.credentialIds().isEmpty());}
                else {assertEquals(WebAuthnEngine.ManagementStatus.UNAVAILABLE,result.status());assertTrue(result.credentialIds().isEmpty());}
                assertTrue(f.store.writes.isEmpty());assertRecordsSame(before,f.source.records());
            }));
    }
    @Test void scEng09FullCapacityRefusesMutationButCannotEvictOrDistortCredentialList() {
        ScriptedWebAuthnStore source=new ScriptedWebAuthnStore(BASE,2,268435456L);RecordingStore store=new RecordingStore(source);
        WorkerClock worker=new WorkerClock(BASE);Gate gate=new Gate();
        StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="))
            .clock(Clock.fixed(BASE,ZoneOffset.UTC)).maximumSealedLength(16384).build();
        WebAuthnEngine engine=new WebAuthnEngine(NAMESPACE,RP,Set.of(ORIGIN),store,sealer,gate,worker,WebAuthnSettings.builder().build());
        prepared(engine.beginRegistration(HANDLE,BINDING));assertEquals(2,source.records().size());store.writes.clear();store.reads.set(0);store.conflicts.set(0);
        assertEquals(WebAuthnEngine.Status.UNAVAILABLE,engine.beginRegistration(new byte[]{7,8,9},BINDING).status());assertEquals(1,store.writes.size());
        var full=source.records();store.writes.clear();store.reads.set(0);store.conflicts.set(0);
        WebAuthnEngine.Management listed=engine.listCredentials(HANDLE);assertEquals(WebAuthnEngine.ManagementStatus.LISTED,listed.status());assertTrue(listed.credentialIds().isEmpty());
        assertTrue(store.writes.isEmpty());assertRecordsSame(full,source.records());
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
    @org.junit.jupiter.api.TestFactory
    @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> migrationCatchupChecksBothImmutableMinimumAndEntityFloor() {
        List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
        for(int shape=0;shape<3;shape++)for(int edge=-1;edge<=1;edge++){
            Instant minimum=BASE.plusSeconds(shape==0?10:1),floor=BASE.plusSeconds(shape==1?10:shape==2?20:1);
            Instant bound=minimum.isAfter(floor)?minimum:floor,now=bound.plusNanos(edge);int position=edge;
            cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG11/WEBAUTHN/"+shape+"/"+edge,()->{
                F f=new F();seedFloors(f,minimum,floor);f.source.setTime(now);f.worker.set(now);var before=f.source.records();f.reset();
                assertEquals(position<0?WebAuthnEngine.ManagementStatus.UNAVAILABLE:WebAuthnEngine.ManagementStatus.LISTED,f.engine.listCredentials(HANDLE).status());
                assertEquals(0,f.store.writes.size());assertRecordsSame(before,f.source.records());
                try(var decoded=f.records.openAdmittedRecord(f.root(),f.record(f.root()).getSealedBytes(),Clock.fixed(bound,ZoneOffset.UTC))){assertEquals(minimum,decoded.floor());}
                var key=WebAuthnStoreKey.forAccountFence(NAMESPACE,RP,HANDLE);try(var decoded=f.records.openAdmittedRecord(key,f.record(key).getSealedBytes(),Clock.fixed(bound,ZoneOffset.UTC))){assertEquals(floor,decoded.floor());}
            }));
        }return cases;
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
        F f=new F();f.enroll();var key=WebAuthnStoreKey.forAccountFence(NAMESPACE,RP,HANDLE);Instant before;
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

    @org.junit.jupiter.api.TestFactory
    @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi02ErrorProfileCannotChangeAtReceiptOrFinalRead(){
        List<org.junit.jupiter.api.DynamicTest> tests=new ArrayList<>();
        for(Duration initial:List.of(Duration.ZERO,Duration.ofMillis(250)))for(String stage:List.of("CONTROL","VALIDATION","FINAL")){
            Duration changed=initial.isZero()?Duration.ofMillis(250):Duration.ZERO;
            tests.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-02/WEBAUTHN/"+stage+"/"+initial,()->{
                F f=new F();
                f.store.afterRead=(n,result)->{
                    var snapshot=assertInstanceOf(WebAuthnStoreReadResult.Available.class,result).getSnapshot();
                    var time=assertInstanceOf(StoreTimeObservation.Healthy.class,snapshot.getTimeObservation());
                    Duration error=stage.equals("FINAL") && n==2?changed:initial;
                    return WebAuthnStoreReadResult.Available.fromSnapshot(WebAuthnStoreSnapshot.fromEntries(snapshot.getEntries().keySet(),snapshot.getEntries(),
                        StoreTimeObservation.Healthy.fromObservation(time.getAdmission(),time.getClockGeneration(),time.getObservedAt(),error)));
                };
                f.store.afterCommit=(n,write,receipt)->{
                    var time=receipt.getTiming().orElseThrow().getValidatedTime();
                    return WebAuthnStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(
                        StoreTimeObservation.Healthy.fromObservation(time.getAdmission(),time.getClockGeneration(),time.getObservedAt(),stage.equals("VALIDATION")?changed:initial),null));
                };
                var result=f.begin(HANDLE);
                assertEquals(stage.equals("CONTROL")?WebAuthnEngine.Status.PREPARED:WebAuthnEngine.Status.RECONCILIATION_REQUIRED,result.status());
                if(!stage.equals("CONTROL"))assertNull(result.request());
                assertEquals(1,f.store.writes.size());assertEquals(stage.equals("VALIDATION")?1:2,f.store.reads.get());
                assertFalse(f.source.records().isEmpty());
            }));
        }
        return tests;
    }
    @Test void scApi02InvalidLocalHandleDoesNotLookUpStoreOrChangeState(){
        F f=new F();
        for(byte[] handle:List.of(new byte[0],new byte[65])){
            assertThrows(IllegalArgumentException.class,()->f.engine.beginRegistration(handle,BINDING));
            assertEquals(0,f.store.reads.get());assertTrue(f.store.writes.isEmpty());assertTrue(f.source.records().isEmpty());
        }
    }
    private static @NonNull WebAuthnStoreCommitReceipt refusal(@NonNull WebAuthnStoreCommitResult status){return WebAuthnStoreCommitReceipt.fromRefusal(status);}
    private static WebAuthnEngine.@NonNull Request prepared(WebAuthnEngine.@NonNull Start result){assertEquals(WebAuthnEngine.Status.PREPARED,result.status());return Objects.requireNonNull(result.request());}
    private static void assertRecordsSame(@NonNull Map<@NonNull WebAuthnStoreKey,WebAuthnStoreEntry.@NonNull Present> first,@NonNull Map<@NonNull WebAuthnStoreKey,WebAuthnStoreEntry.@NonNull Present> second){assertEquals(first.keySet(),second.keySet());for(var key:first.keySet()){assertArrayEquals(Objects.requireNonNull(first.get(key)).getVersion(),Objects.requireNonNull(second.get(key)).getVersion());assertArrayEquals(Objects.requireNonNull(first.get(key)).getSealedBytes(),Objects.requireNonNull(second.get(key)).getSealedBytes());}}
    @FunctionalInterface private interface BeforeCommit { @Nullable WebAuthnStoreCommitReceipt apply(int number,@NonNull WebAuthnStoreWrite write) throws Exception; }
    @FunctionalInterface private interface AfterCommit { @NonNull WebAuthnStoreCommitReceipt apply(int number,@NonNull WebAuthnStoreWrite write,@NonNull WebAuthnStoreCommitReceipt receipt); }
    @FunctionalInterface private interface AfterRead { @NonNull WebAuthnStoreReadResult apply(int number,@NonNull WebAuthnStoreReadResult result); }
    @ThreadSafe private static final class RecordingStore implements WebAuthnStore {
        final @NonNull ScriptedWebAuthnStore source;
        volatile java.util.concurrent.@Nullable CopyOnWriteArrayList<@NonNull String> phaseTrace;
        final @NonNull AtomicInteger reads=new AtomicInteger(),conflicts=new AtomicInteger();
        final @NonNull List<@NonNull WebAuthnStoreWrite> writes=new CopyOnWriteArrayList<>();
        volatile @Nullable BeforeCommit beforeCommit;volatile @Nullable AfterCommit afterCommit;volatile @Nullable AfterRead afterRead;
        volatile @NonNull Set<@NonNull WebAuthnStoreKey> lastRead=Set.of();
        RecordingStore(@NonNull ScriptedWebAuthnStore source){this.source=source;}
        @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){var trace=this.phaseTrace;if(trace!=null)trace.add("read-call");int n=this.reads.incrementAndGet();this.lastRead=keys;var reply=this.source.read(keys,budget);AfterRead hook=this.afterRead;WebAuthnStoreReadResult delivered=hook==null?reply:hook.apply(n,reply);if(trace!=null)trace.add("read-reply");return delivered;}
        @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){var trace=this.phaseTrace;if(trace!=null)trace.add("commit-call");this.writes.add(write);int n=this.writes.size();BeforeCommit before=this.beforeCommit;WebAuthnStoreCommitReceipt result;
            try{result=before==null?null:before.apply(n,write);}catch(Exception e){throw new IllegalStateException(e);}
            if(result==null)result=this.source.compareAndCommit(write,budget);if(result.getStatus()==WebAuthnStoreCommitResult.CONFLICT)this.conflicts.incrementAndGet();AfterCommit after=this.afterCommit;WebAuthnStoreCommitReceipt delivered=after==null?result:after.apply(n,write,result);if(trace!=null)trace.add("commit-reply");return delivered;}
    }
    @ThreadSafe private static final class WorkerClock extends Clock {
        private final @NonNull AtomicReference<@NonNull Instant> value;
        volatile java.util.concurrent.@Nullable CopyOnWriteArrayList<@NonNull String> phaseTrace;
        WorkerClock(@NonNull Instant initial){this.value=new AtomicReference<>(initial);}
        void set(@NonNull Instant time){this.value.set(time);}
        @Override public @NonNull Instant instant(){var trace=this.phaseTrace;if(trace!=null)trace.add("worker-wall");return Objects.requireNonNull(this.value.get());}
        @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return Clock.fixed(instant(),zone);}
    }

    @TestFactory @NonNull Stream<@NonNull DynamicTest> scEng03CompetingSignedCompletionsPreserveCeremonyAndCounterPredicates() {
        return java.util.stream.Stream.of(false,true).map(sameCeremony -> org.junit.jupiter.api.DynamicTest.dynamicTest(
                "ENG03/competing-authentication/same-ceremony="+sameCeremony, () -> {
            F f=new F();KeyPair pair=f.enroll();var first=prepared(f.engine.beginAuthentication(BINDING));
            var second=sameCeremony?first:prepared(f.engine.beginAuthentication(BINDING));
            byte[] firstResponse=assertionJson(pair.getPrivate(),Base64Url.encode(first.challenge()),1);
            byte[] secondResponse=sameCeremony?firstResponse:assertionJson(pair.getPrivate(),Base64Url.encode(second.challenge()),1);
            byte[] rootVersion=f.record(f.root()).getVersion();
            var credentialKey=WebAuthnStoreKey.forCredential(NAMESPACE,RP,CREDENTIAL_ID);
            var indexKey=WebAuthnStoreKey.forAccountCredentialIndex(NAMESPACE,RP,HANDLE);
            var fenceKey=WebAuthnStoreKey.forAccountFence(NAMESPACE,RP,HANDLE);
            var ceremonyKey=WebAuthnStoreKey.forCeremony(NAMESPACE,RP,first.ceremonyId());
            byte[] indexVersion=f.record(indexKey).getVersion(),fenceVersion=f.record(fenceKey).getVersion();
            AtomicReference<WebAuthnEngine.Finish> winner=new AtomicReference<>();f.reset();
            f.store.beforeCommit=(number,write)->{
                if(number==1){
                    f.store.beforeCommit=null;
                    assertEquals(Set.of(f.root(),ceremonyKey,credentialKey,indexKey,fenceKey),write.getSnapshot().getEntries().keySet());
                    assertEquals(Set.of(ceremonyKey,credentialKey),write.getMutations().stream().map(WebAuthnStoreWrite.Mutation::getKey).collect(java.util.stream.Collectors.toSet()));
                    winner.set(f.engine.completeAuthentication(second.ceremonyId(),BINDING,secondResponse));
                    assertEquals(WebAuthnEngine.Status.SUCCEEDED,Objects.requireNonNull(winner.get()).status());
                }
                return null;
            };
            var loser=f.engine.completeAuthentication(first.ceremonyId(),BINDING,firstResponse);
            assertEquals(sameCeremony?WebAuthnEngine.Status.REJECTED:WebAuthnEngine.Status.COUNTER_RISK,loser.status());
            assertNull(loser.verified());assertNotNull(Objects.requireNonNull(winner.get()).verified());
            assertEquals(2,f.store.writes.size());assertEquals(1,f.store.conflicts.get());
            assertEquals(1,new WebAuthnCredentialRecordCodec(NAMESPACE,RP,f.records).decode(credentialKey,f.record(credentialKey).getSealedBytes(),f.authorityClock()).counter());
            assertTrue(f.ceremony(second).isConsumed());assertEquals(sameCeremony,f.ceremony(first).isConsumed());
            assertArrayEquals(rootVersion,f.record(f.root()).getVersion());
            assertArrayEquals(indexVersion,f.record(indexKey).getVersion());assertArrayEquals(fenceVersion,f.record(fenceKey).getVersion());
        }));
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

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig14PreparedFloorSurvivesLaterValidationAndCompletion(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
  for(boolean initialize:List.of(false,true))for(int nano:List.of(1,123456789,999999999))for(boolean completed:List.of(false,true))for(int offset:List.of(-2,2))
   cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-14/WA/timing/"+initialize+"/"+nano+"/"+completed+"/"+offset,()->{
    F f=new F();if(!initialize)prepared(f.begin(HANDLE));f.reset();var before=f.source.records();
    Instant at=BASE.plusSeconds(5).plusNanos(nano),validated=at.plusMillis(200),finished=validated.plusMillis(300);f.source.setTime(at);f.worker.set(at.plusSeconds(offset));
    f.store.beforeCommit=(n,w)->{assertEquals(at,w.getTemporalCondition().getNotBeforeInclusive());f.source.setTime(validated);f.worker.set(validated.plusSeconds(offset));return null;};
    f.store.afterCommit=(n,w,r)->{
     assertEquals(WebAuthnStoreCommitResult.COMMITTED,r.getStatus());var v=r.getTiming().orElseThrow().getValidatedTime();assertEquals(validated,v.getObservedAt());f.source.setTime(finished);f.worker.set(finished.plusSeconds(offset));
     var c=StoreTimeObservation.Healthy.fromObservation(v.getAdmission(),v.getClockGeneration(),finished,v.getMaximumUtcError());return WebAuthnStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(v,completed?c:null));
    };
    var request=prepared(f.begin(new byte[]{9,8,7}));assertEquals(at,f.ceremony(request).issuedAt());assertEquals(at.plusSeconds(300),f.ceremony(request).expiresAt());assertEquals(1,f.store.writes.size());
    for(var mutation:f.store.writes.get(0).getMutations()){
     assertArrayEquals(mutation.getSealedBytes().orElseThrow(),f.record(mutation.getKey()).getSealedBytes());try(var decoded=f.decoded(mutation.getKey())){assertEquals(at,decoded.floor());}
    }
    for(var key:before.keySet()){assertArrayEquals(Objects.requireNonNull(before.get(key)).getVersion(),f.record(key).getVersion());assertArrayEquals(Objects.requireNonNull(before.get(key)).getSealedBytes(),f.record(key).getSealedBytes());}
   }));return cases;
 }
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig14ListIsPureAtCeremonyExpiryBoundaries(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
  for(int edge:List.of(-1,0,1))for(int offset:List.of(-2,0,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-14/WA/list/"+edge+"/"+offset,()->{
   F f=new F();var request=prepared(f.begin(HANDLE));var before=f.source.records();Instant time=f.ceremony(request).expiresAt().plusNanos(edge);f.source.setTime(time);f.worker.set(time.plusSeconds(offset));f.reset();
   assertEquals(WebAuthnEngine.ManagementStatus.LISTED,f.engine.listCredentials(HANDLE).status());assertEquals(0,f.store.writes.size());assertRecordsSame(before,f.source.records());
  }));return cases;
 }

 private static @NonNull Map<?,?> mig15FixtureRows(@NonNull ScriptedWebAuthnStore source)throws Exception{var f=source.getClass().getDeclaredField("entries");f.setAccessible(true);return (Map<?,?>)Objects.requireNonNull(f.get(source));}
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15BootstrapNeedsCurrentAuthorizationAndExactAbsence(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(String mode:List.of("CLEAN","CLOSED","UTC_DOWN","PRESENT"))for(int offset:List.of(-2,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/WA/bootstrap/"+mode+"/"+offset,()->{
   F f=new F();if(mode.equals("PRESENT"))prepared(f.begin(HANDLE));f.reset();var before=f.source.records();f.worker.set(BASE.plusSeconds(offset));if(mode.equals("CLOSED"))f.gate.open.set(false);if(mode.equals("UTC_DOWN"))f.source.setHealthy(false);
   var result=f.begin(new byte[]{8,9,10});
   if(mode.equals("CLEAN")){prepared(result);var snapshot=f.store.writes.get(0).getSnapshot();assertInstanceOf(WebAuthnStoreEntry.Absent.class,snapshot.getEntry(f.root()));}
   else if(mode.equals("PRESENT")){prepared(result);assertArrayEquals(Objects.requireNonNull(before.get(f.root())).getSealedBytes(),f.record(f.root()).getSealedBytes());assertTrue(f.store.writes.stream().flatMap(w->w.getMutations().stream()).noneMatch(m->m.getKey().equals(f.root())));}
   else {assertEquals(WebAuthnEngine.Status.UNAVAILABLE,result.status());assertRecordsSame(before,f.source.records());assertEquals(0,f.store.writes.size());f.gate.open.set(true);f.source.setHealthy(true);prepared(f.begin(new byte[]{8,9,10}));}
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15KnownRootLossOrOrphansNeverBecomeFreshAbsence(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(String loss:List.of("ESTABLISHED_EMPTY","ESTABLISHED_RETAINED","ORPHAN"))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/WA/root-loss/"+loss,()->{
   F f=new F();if(loss.equals("ORPHAN")){var fence=new WebAuthnAccountFence(NAMESPACE,RP,f.records).encode(HANDLE,true,BASE);f.source.seedClosedMigration(Map.of(fence.key(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{1},fence.sealedBytes())));}
   else {if(loss.equals("ESTABLISHED_RETAINED"))f.enroll();else prepared(f.begin(HANDLE));var rows=mig15FixtureRows(f.source);rows.remove(f.root());if(loss.equals("ESTABLISHED_EMPTY"))rows.clear();}
   f.reset();var before=f.source.records();assertInstanceOf(WebAuthnStoreReadResult.Unavailable.class,f.source.read(Set.of(f.root()),Duration.ofSeconds(5)));assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.begin(HANDLE).status());assertRecordsSame(before,f.source.records());assertEquals(0,f.store.writes.size());
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15ChangedAuthorityCannotRepairExistingRoot(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(int offset:List.of(-2,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/WA/authority/"+offset,()->{
   F f=new F();f.enroll();var before=f.source.records();var field=f.source.getClass().getDeclaredField("admission");field.setAccessible(true);field.set(f.source,com.revetsec.StoreAdmission.fromIdentifiers("A".repeat(43),f.source.admission().getRecoveryGeneration()));f.worker.set(BASE.plusSeconds(offset));f.reset();assertEquals(WebAuthnEngine.ManagementStatus.UNAVAILABLE,f.engine.listCredentials(HANDLE).status());assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.begin(HANDLE).status());assertRecordsSame(before,f.source.records());assertEquals(0,f.store.writes.size());
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15ClockOnlyReadmissionKeepsOriginalCredentialUsable(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(boolean close:List.of(false,true))for(int offset:List.of(-2,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/WA/clock/"+close+"/"+offset,()->{
   F f=new F();KeyPair pair=f.enroll();var request=prepared(f.engine.beginAuthentication(BINDING));var before=f.source.records();var admission=f.source.admission();f.worker.set(BASE.plusSeconds(offset));f.reset();f.source.rotateClockGeneration();
   byte[] assertion=assertionJson(pair.getPrivate(),Base64Url.encode(request.challenge()),1);
   if(close){f.gate.open.set(false);assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.engine.completeAuthentication(request.ceremonyId(),BINDING,assertion).status());assertRecordsSame(before,f.source.records());assertEquals(0,f.store.writes.size());f.gate.open.set(true);}
   assertEquals(WebAuthnEngine.ManagementStatus.LISTED,f.engine.listCredentials(HANDLE).status());assertRecordsSame(before,f.source.records());assertEquals(admission,f.source.admission());assertEquals(WebAuthnEngine.Status.SUCCEEDED,f.engine.completeAuthentication(request.ceremonyId(),BINDING,assertion).status());assertArrayEquals(Objects.requireNonNull(before.get(f.root())).getSealedBytes(),f.record(f.root()).getSealedBytes());
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15CompetingBootstrapCannotOverwriteWinner(){
  return List.of(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/WA/absent-CAS",()->{
   F f=new F();AtomicReference<byte[]> winner=new AtomicReference<>();f.store.beforeCommit=(n,w)->{f.store.beforeCommit=null;prepared(f.begin(new byte[]{8}));winner.set(f.record(f.root()).getSealedBytes());return null;};prepared(f.begin(HANDLE));assertArrayEquals(winner.get(),f.record(f.root()).getSealedBytes());assertEquals(1,f.store.conflicts.get());
  }));
 }

 @Test void cap09CapacityIsNotConflictOrCredentialRejectionAndNeverRetries() throws Exception {
  F f=new F();prepared(f.begin(HANDLE));var before=f.source.records();f.reset();
  f.store.beforeCommit=(n,w)->refusal(WebAuthnStoreCommitResult.CAPACITY);
  assertEquals(WebAuthnEngine.ManagementStatus.UNAVAILABLE,f.engine.disableAccount(new byte[]{71,72,73}).status());
  assertEquals(1,f.store.writes.size());assertEquals(0,f.store.conflicts.get());assertRecordsSame(before,f.source.records());
  f.reset();assertEquals(WebAuthnEngine.ManagementStatus.DISABLED,f.engine.disableAccount(new byte[]{71,72,73}).status());assertEquals(1,f.store.writes.size());
 }

 @Test void scEng08RepeatedConflictExhaustionStopsAfterNineCallbacks() {
  F f=new F();f.store.beforeCommit=(number,write)->refusal(WebAuthnStoreCommitResult.CONFLICT);
  var result=f.begin(HANDLE);
  assertEquals(WebAuthnEngine.Status.UNAVAILABLE,result.status());assertNull(result.request());
  assertEquals(9,f.store.reads.get());assertEquals(9,f.store.writes.size());assertEquals(9,f.store.conflicts.get());
  assertTrue(f.source.records().isEmpty());
 }


 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk02WorkerHealthLossAfterKnownCommitWithholdsOutputWithoutErasingMutation(){
  List<org.junit.jupiter.api.DynamicTest> cells=new ArrayList<>();for(int offset:List.of(-6,6))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-02/WEBAUTHN/known-commit/worker="+offset+"s",()->{F f=new F();f.store.afterCommit=(n,w,r)->{assertEquals(WebAuthnStoreCommitResult.COMMITTED,r.getStatus());f.worker.set(BASE.plusSeconds(offset));return r;};var result=f.begin(HANDLE);assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,result.status());assertNull(result.request());assertEquals(1,f.store.writes.size());assertTrue(f.source.records().keySet().stream().anyMatch(k->k.getKind()==WebAuthnStoreKey.Kind.CEREMONY));}));return cells;
 }

 @Test void scClk03ActualReadCommitAndFinalReadKeepIdenticalNumericSamplesAfterReplies(){
  F f=new F();java.util.concurrent.CopyOnWriteArrayList<String> trace=new java.util.concurrent.CopyOnWriteArrayList<>();f.store.phaseTrace=trace;f.worker.phaseTrace=trace;var result=f.begin(HANDLE);assertEquals(WebAuthnEngine.Status.PREPARED,result.status());assertNotNull(result.request());assertEquals(List.of("read-call","read-reply","worker-wall","commit-call","commit-reply","worker-wall","read-call","read-reply","worker-wall","worker-wall","worker-wall"),trace);f.worker.phaseTrace=null;f.store.phaseTrace=null;assertEquals(BASE,f.source.authorityTime());assertEquals(BASE,f.worker.instant());assertEquals(1,f.store.writes.size());
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi08KnownCommitValidationAndCompletionMatrix(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(var scenario:com.revetsec.testing.StoreReceiptMatrix.Case.values())cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-08/WEBAUTHN/"+scenario,()->{
   F f=new F();java.util.concurrent.atomic.AtomicReference<@Nullable Instant> target=new java.util.concurrent.atomic.AtomicReference<>();f.store.afterCommit=(n,w,r)->{assertEquals(WebAuthnStoreCommitResult.COMMITTED,r.getStatus());var validated=r.getTiming().orElseThrow().getValidatedTime();Instant next=com.revetsec.testing.StoreReceiptMatrix.finalTime(scenario,validated,w.getTemporalCondition());target.set(next);WebAuthnStoreCommitReceipt delivered=(WebAuthnStoreCommitReceipt)com.revetsec.testing.StoreReceiptMatrix.apply(r,scenario,validated,w.getTemporalCondition());if(next!=null)f.source.setTime(next);return delivered;};f.store.afterRead=(n,r)->{Instant next=target.get();if(n==2&&next!=null)f.worker.set(next);return r;};var result=f.engine(f.worker,Duration.ofSeconds(1)).beginRegistration(HANDLE,BINDING);WebAuthnEngine.Status expected=scenario.isNormal()?WebAuthnEngine.Status.PREPARED:scenario.isUnknown()?WebAuthnEngine.Status.INDETERMINATE:WebAuthnEngine.Status.RECONCILIATION_REQUIRED;assertEquals(expected,result.status());if(!scenario.isNormal())assertNull(result.request());assertEquals(1,f.store.writes.size());assertEquals(scenario.needsFinalRead()?2:1,f.store.reads.get());assertTrue(f.source.records().keySet().stream().anyMatch(k->k.getKind()==WebAuthnStoreKey.Kind.CEREMONY));for(var key:f.source.records().keySet())try(var decoded=f.decoded(key)){assertEquals(BASE,decoded.floor());}
  }));return cases;
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi08NormalStatusesDistinguishZeroEffectUnknownAndOneAllowedConflictRetry(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(var status:WebAuthnStoreCommitResult.values())for(boolean applied:status==WebAuthnStoreCommitResult.UNKNOWN?List.of(false,true):List.of(status==WebAuthnStoreCommitResult.COMMITTED))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-08/WEBAUTHN/status="+status+"/applied="+applied,()->{
   F f=new F();prepared(f.begin(new byte[]{7,8,9}));var before=f.source.records();f.reset();f.store.beforeCommit=(n,w)->{if(status==WebAuthnStoreCommitResult.COMMITTED||(status==WebAuthnStoreCommitResult.CONFLICT&&n>1)||(status==WebAuthnStoreCommitResult.UNKNOWN&&applied))return null;return status==WebAuthnStoreCommitResult.UNKNOWN?WebAuthnStoreCommitReceipt.unknownInstance():WebAuthnStoreCommitReceipt.fromRefusal(status);};f.store.afterCommit=(n,w,r)->status==WebAuthnStoreCommitResult.UNKNOWN&&applied?WebAuthnStoreCommitReceipt.unknownInstance():r;var result=f.begin(HANDLE);WebAuthnEngine.Status expected=status==WebAuthnStoreCommitResult.COMMITTED||status==WebAuthnStoreCommitResult.CONFLICT?WebAuthnEngine.Status.PREPARED:status==WebAuthnStoreCommitResult.UNKNOWN?WebAuthnEngine.Status.INDETERMINATE:status==WebAuthnStoreCommitResult.TIME_EXPIRED?WebAuthnEngine.Status.REJECTED:WebAuthnEngine.Status.UNAVAILABLE;assertEquals(expected,result.status());if(expected!=WebAuthnEngine.Status.PREPARED)assertNull(result.request());assertEquals(status==WebAuthnStoreCommitResult.CONFLICT?2:1,f.store.writes.size());assertEquals(status==WebAuthnStoreCommitResult.CONFLICT?3:status==WebAuthnStoreCommitResult.COMMITTED||status==WebAuthnStoreCommitResult.TIME_EXPIRED?2:1,f.store.reads.get());boolean changed=status==WebAuthnStoreCommitResult.COMMITTED||status==WebAuthnStoreCommitResult.CONFLICT||applied;if(changed){assertEquals(before.size()+1,f.source.records().size());for(var key:before.keySet()){assertArrayEquals(before.get(key).getVersion(),f.record(key).getVersion());assertArrayEquals(before.get(key).getSealedBytes(),f.record(key).getSealedBytes());}}else assertRecordsSame(before,f.source.records());
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi08EnteredNullOrThrowNeverInfersRollbackFromInstrumentedEffects(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(boolean applied:List.of(false,true))for(boolean throwing:List.of(false,true))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-08/WEBAUTHN/lost-receipt/applied="+applied+"/throw="+throwing,()->{F f=new F();prepared(f.begin(new byte[]{7,8,9}));var before=f.source.records();f.reset();if(!applied)f.store.beforeCommit=(n,w)->WebAuthnStoreCommitReceipt.unknownInstance();f.store.afterCommit=(n,w,r)->{if(throwing)throw new IllegalStateException("TEST-ONLY-lost-acknowledgement");return com.revetsec.testing.StoreReceiptMatrix.brokenNull();};var result=f.begin(HANDLE);assertEquals(WebAuthnEngine.Status.INDETERMINATE,result.status());assertNull(result.request());assertEquals(1,f.store.writes.size());assertEquals(1,f.store.reads.get());if(applied)assertEquals(before.size()+1,f.source.records().size());else assertRecordsSame(before,f.source.records());}));return cases;
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi01ActualInitialExpandedAndFinalReadFaultsNeverAuthorizeNewMutation(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(String phase:List.of("INITIAL","EXPANDED","FINAL"))for(var fault:com.revetsec.testing.StoreReadFaults.values()){
   if(phase.equals("FINAL")&&!fault.appliesToRootOnly())continue;
   cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-01/WEBAUTHN/"+phase+"/"+fault,()->{
    F f=new F();prepared(f.begin(new byte[]{7,8,9}));WebAuthnEngine.Request request=phase.equals("EXPANDED")?prepared(f.begin(HANDLE)):null;var before=f.source.records();f.reset();int target=phase.equals("INITIAL")?1:2;f.store.afterRead=(n,r)->n==target?scApi01ReadFault(f,fault,r):r;
    if(phase.equals("EXPANDED")){KeyPair pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();var actual=Objects.requireNonNull(request);assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.engine.completeRegistration(actual.ceremonyId(),BINDING,registrationJson(pair,Base64Url.encode(actual.challenge()))).status());assertRecordsSame(before,f.source.records());}
    else {var actual=f.begin(HANDLE);assertEquals(phase.equals("FINAL")?WebAuthnEngine.Status.RECONCILIATION_REQUIRED:WebAuthnEngine.Status.UNAVAILABLE,actual.status());assertNull(actual.request());if(phase.equals("INITIAL"))assertRecordsSame(before,f.source.records());else{assertEquals(before.size()+1,f.source.records().size());for(var key:before.keySet()){assertArrayEquals(Objects.requireNonNull(before.get(key)).getVersion(),f.record(key).getVersion());assertArrayEquals(Objects.requireNonNull(before.get(key)).getSealedBytes(),f.record(key).getSealedBytes());}}}
    assertEquals(phase.equals("FINAL")?1:0,f.store.writes.size());assertEquals(target,f.store.reads.get());
   }));
  }return cases;
 }
 private static @NonNull WebAuthnStoreReadResult scApi01ReadFault(@NonNull F f,com.revetsec.testing.@NonNull StoreReadFaults fault,@NonNull WebAuthnStoreReadResult result){
  if(fault==com.revetsec.testing.StoreReadFaults.UNAVAILABLE)return WebAuthnStoreReadResult.Unavailable.get();
  if(fault==com.revetsec.testing.StoreReadFaults.NULL)return com.revetsec.testing.StoreReceiptMatrix.brokenNull();
  if(fault==com.revetsec.testing.StoreReadFaults.THROW)throw new IllegalStateException("TEST-ONLY read fault");
  var original=assertInstanceOf(WebAuthnStoreReadResult.Available.class,result).getSnapshot();Map<WebAuthnStoreKey,WebAuthnStoreEntry> rows=new java.util.HashMap<>(original.getEntries());WebAuthnStoreKey entity=WebAuthnStoreKey.forAccountFence(NAMESPACE,RP,HANDLE);
  switch(fault){
   case OMIT_ROOT->rows.remove(f.root());case OMIT_ENTITY->rows.remove(entity);
   case EXTRA_ABSENCE->rows.put(WebAuthnStoreKey.forAccountFence(NAMESPACE,RP,new byte[]{88}),WebAuthnStoreEntry.Absent.confirmed());
   case FOREIGN_SCOPE->{rows.clear();rows.put(WebAuthnStoreKey.forNamespaceClock("foreign",RP),WebAuthnStoreEntry.Absent.confirmed());}
   case WRONG_KIND->{rows.remove(f.root());rows.put(WebAuthnStoreKey.forAccountFence(NAMESPACE,RP,new byte[]{99}),WebAuthnStoreEntry.Absent.confirmed());}
   case AUTHENTICATED_BAD_AUTHORITY,AUTHENTICATED_NEGATIVE_FLOOR->{String authority=fault==com.revetsec.testing.StoreReadFaults.AUTHENTICATED_BAD_AUTHORITY?"A".repeat(43):f.source.admission().getAuthorityId();Instant minimum=fault==com.revetsec.testing.StoreReadFaults.AUTHENTICATED_NEGATIVE_FLOOR?Instant.EPOCH.minusNanos(1):BASE;rows.put(f.root(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{9},f.records.sealNamespace(f.root(),authority,minimum)));}
   case CORRUPT_ROOT,CORRUPT_ENTITY->{WebAuthnStoreKey key=fault==com.revetsec.testing.StoreReadFaults.CORRUPT_ROOT?f.root():entity;rows.put(key,WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{9},new byte[]{1,2,3}));}
   default->throw new AssertionError("Unexpected read-fault control");
  }
  return WebAuthnStoreReadResult.Available.fromSnapshot(WebAuthnStoreSnapshot.fromEntries(rows.keySet(),rows,original.getTimeObservation()));
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi03EveryObservationDomainMustMatchAtExpandedReadAndFinalCheckpoint(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(String phase:List.of("EXPANDED","FINAL"))for(var fault:com.revetsec.testing.StoreProfileFaults.values())cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-03/WEBAUTHN/"+phase+"/"+fault,()->{
   F f=new F();prepared(f.begin(new byte[]{7,8,9}));WebAuthnEngine.Request pending=phase.equals("EXPANDED")?prepared(f.begin(HANDLE)):null;var before=f.source.records();f.reset();AtomicBoolean delivered=new AtomicBoolean();f.store.afterRead=(n,r)->{if(n!=2)return r;delivered.set(true);var snapshot=assertInstanceOf(WebAuthnStoreReadResult.Available.class,r).getSnapshot();var original=assertInstanceOf(com.revetsec.StoreTimeObservation.Healthy.class,snapshot.getTimeObservation());var changed=assertInstanceOf(com.revetsec.StoreTimeObservation.Healthy.class,fault.apply(original));assertEquals(original.getObservedAt(),changed.getObservedAt());assertEquals(fault==com.revetsec.testing.StoreProfileFaults.CLOCK?!original.getClockGeneration().equals(changed.getClockGeneration()):original.getClockGeneration().equals(changed.getClockGeneration()),true);return WebAuthnStoreReadResult.Available.fromSnapshot(WebAuthnStoreSnapshot.fromEntries(snapshot.getEntries().keySet(),snapshot.getEntries(),changed));};
   if(phase.equals("EXPANDED")){var actual=Objects.requireNonNull(pending);KeyPair pair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();assertEquals(WebAuthnEngine.Status.UNAVAILABLE,f.engine.completeRegistration(actual.ceremonyId(),BINDING,registrationJson(pair,Base64Url.encode(actual.challenge()))).status());assertRecordsSame(before,f.source.records());}
   else{var result=f.begin(HANDLE);assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,result.status());assertNull(result.request());assertEquals(before.size()+1,f.source.records().size());for(var key:before.keySet()){assertArrayEquals(Objects.requireNonNull(before.get(key)).getVersion(),f.record(key).getVersion());assertArrayEquals(Objects.requireNonNull(before.get(key)).getSealedBytes(),f.record(key).getSealedBytes());}}
   assertTrue(delivered.get());assertEquals(phase.equals("FINAL")?1:0,f.store.writes.size());assertEquals(2,f.store.reads.get());
  }));return cases;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk05GoodCompletionStillRequiresFreshFinalAdmissionAndCurrentRelease(){
  List<org.junit.jupiter.api.DynamicTest> cells=new ArrayList<>();
  for(String fault:List.of("UNAVAILABLE","THROW","DELAY","PERMIT_CLOSE"))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-05/WEBAUTHN/good-completion/"+fault,()->{
   F f=new F();var delivered=new AtomicReference<@Nullable StoreCommitTiming>();
   f.store.afterCommit=(number,write,receipt)->{var validated=receipt.getTiming().orElseThrow().getValidatedTime();var completed=StoreTimeObservation.Healthy.fromObservation(validated.getAdmission(),validated.getClockGeneration(),f.source.authorityTime(),validated.getMaximumUtcError());var timing=StoreCommitTiming.fromTimes(validated,completed);delivered.set(timing);return WebAuthnStoreCommitReceipt.fromCommittedTiming(timing);};
   f.store.afterRead=(number,result)->{if(number==2){if(fault.equals("UNAVAILABLE"))return WebAuthnStoreReadResult.Unavailable.get();if(fault.equals("THROW"))throw new IllegalStateException("Test-only final read failure");if(fault.equals("DELAY"))scMeasuredReleaseDelay(150_000_000L);}return result;};
   if(fault.equals("PERMIT_CLOSE"))f.gate.failClose.set(true);
   var result=f.engine(f.worker,Duration.ofMillis(100)).beginRegistration(HANDLE,BINDING);assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,result.status());assertNull(result.request());
   assertTrue(Objects.requireNonNull(delivered.get()).getCompletedTime().isPresent());assertEquals(1,f.store.writes.size());assertEquals(2,f.store.reads.get());assertEquals(Set.of(f.root()),f.store.lastRead);
   assertTrue(f.source.records().keySet().stream().anyMatch(key->key.getKind()==WebAuthnStoreKey.Kind.CEREMONY));for(var key:f.source.records().keySet())try(var decoded=f.decoded(key)){assertEquals(BASE,decoded.floor());}
  }));return cells;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk08ActualValidationAtLastNanosecondKeepsCommitWhenFinalReleaseCrossesOriginalUpper(){
  List<org.junit.jupiter.api.DynamicTest> cells=new ArrayList<>();
  for(boolean finalAtExpiry:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-05+CLK-08/WEBAUTHN/E-minus-1/finalAtE="+finalAtExpiry,()->{
   F f=new F();var originalUpper=new AtomicReference<@Nullable Instant>();var committed=new AtomicReference<@Nullable StoreCommitTiming>();var finalSample=new AtomicReference<StoreTimeObservation.@Nullable Healthy>();var finalElapsed=new AtomicReference<@Nullable Duration>();
   f.store.beforeCommit=(number,write)->{Instant upper=write.getTemporalCondition().getValidBeforeExclusive().orElseThrow();originalUpper.set(upper);Instant validated=upper.minusNanos(1);f.source.setTime(validated);f.worker.set(validated);return null;};
   f.store.afterCommit=(number,write,receipt)->{assertEquals(WebAuthnStoreCommitResult.COMMITTED,receipt.getStatus());committed.set(receipt.getTiming().orElseThrow());Instant upper=Objects.requireNonNull(originalUpper.get());assertEquals(upper.minusNanos(1),receipt.getTiming().orElseThrow().getValidatedTime().getObservedAt());if(finalAtExpiry){f.source.setTime(upper);f.worker.set(upper);}return receipt;};
   f.store.afterRead=(number,result)->{if(number==2&&!finalAtExpiry){var sample=assertInstanceOf(StoreTimeObservation.Healthy.class,assertInstanceOf(WebAuthnStoreReadResult.Available.class,result).getSnapshot().getTimeObservation());finalSample.set(sample);finalElapsed.set(scMeasuredReleaseDelay(2_000_000L));}return result;};
   var result=f.begin(HANDLE);assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,result.status());assertNull(result.request());assertEquals(1,f.store.writes.size());assertEquals(2,f.store.reads.get());
   Instant upper=Objects.requireNonNull(originalUpper.get());assertEquals(upper.minusNanos(1),Objects.requireNonNull(committed.get()).getValidatedTime().getObservedAt());assertTrue(Objects.requireNonNull(committed.get()).getCompletedTime().isEmpty());assertEquals(upper,f.store.writes.get(0).getTemporalCondition().getValidBeforeExclusive().orElseThrow());if(!finalAtExpiry){var sample=Objects.requireNonNull(finalSample.get());assertEquals(upper.minusNanos(1),sample.getObservedAt());assertTrue(com.revetsec.internal.StoreTimeRules.isReleaseBefore(sample,Duration.ZERO,upper));assertFalse(com.revetsec.internal.StoreTimeRules.isReleaseBefore(sample,Objects.requireNonNull(finalElapsed.get()),upper),"A pre-expiry stamp is insufficient when the conservative bound crosses E");}
   var ceremony=f.source.records().keySet().stream().filter(key->key.getKind()==WebAuthnStoreKey.Kind.CEREMONY).findFirst().orElseThrow();var state=new WebAuthnCeremonyRecordCodec(NAMESPACE,RP,f.records).decode(ceremony,f.record(ceremony).getSealedBytes(),f.authorityClock());assertEquals(BASE,state.issuedAt());assertEquals(BASE.plusSeconds(300),state.expiresAt());for(var key:f.source.records().keySet())try(var decoded=f.decoded(key)){assertEquals(BASE,decoded.floor());}
  }));return cells;
 }
 private static @NonNull Duration scMeasuredReleaseDelay(long nanos){long start=System.nanoTime(),end=start+nanos;long remaining;while((remaining=end-System.nanoTime())>0)java.util.concurrent.locks.LockSupport.parkNanos(remaining);Duration elapsed=com.revetsec.internal.StoreTimeRules.elapsed(start,System.nanoTime()).orElseThrow();assertTrue(elapsed.compareTo(Duration.ofNanos(nanos))>=0);return elapsed;}

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk09AuthorityAndRecoveryRotateBeforeOrAfterEligibleFinalSnapshot(){
  List<org.junit.jupiter.api.DynamicTest> cells=new ArrayList<>();
  for(boolean authority:List.of(false,true))for(boolean after:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-09/WA/authority="+authority+"/after-captured-checkpoint="+after,()->{
   F f=new F();var original=f.source.admission();var receipt=new java.util.concurrent.atomic.AtomicReference<@Nullable WebAuthnStoreCommitReceipt>();var changed=new java.util.concurrent.atomic.AtomicBoolean();var checkpoint=new java.util.concurrent.atomic.AtomicReference<@Nullable WebAuthnStoreSnapshot>();
   Runnable rotate=()->{scClk09RotateAdmission(f,authority);changed.set(true);};f.store.afterCommit=(number,write,result)->{receipt.set(result);if(!after)rotate.run();return result;};f.store.afterRead=(number,result)->{if(number==2){var snapshot=assertInstanceOf(WebAuthnStoreReadResult.Available.class,result).getSnapshot();checkpoint.set(snapshot);if(after)rotate.run();}return result;};
   var result=f.begin(HANDLE);if(after){assertEquals(WebAuthnEngine.Status.PREPARED,result.status());assertEquals(32,Objects.requireNonNull(result.request()).challenge().length);}else{assertEquals(WebAuthnEngine.Status.RECONCILIATION_REQUIRED,result.status());assertNull(result.request());}
   assertTrue(changed.get());assertEquals(authority?"A".repeat(43):original.getAuthorityId(),f.source.admission().getAuthorityId());assertEquals(authority?original.getRecoveryGeneration():"A".repeat(43),f.source.admission().getRecoveryGeneration());assertEquals(BASE,f.source.authorityTime());assertEquals(BASE,f.worker.instant());assertEquals(1,f.store.writes.size());assertEquals(2,f.store.reads.get());assertEquals(Set.of(f.root()),f.store.lastRead);
   var acknowledged=Objects.requireNonNull(receipt.get());assertEquals(WebAuthnStoreCommitResult.COMMITTED,acknowledged.getStatus());assertEquals(original,acknowledged.getTiming().orElseThrow().getValidatedTime().getAdmission());assertEquals(BASE,acknowledged.getTiming().orElseThrow().getValidatedTime().getObservedAt());assertEquals(after?original:f.source.admission(),Objects.requireNonNull(checkpoint.get()).getTimeObservation().getAdmission());
   var ceremony=f.source.records().keySet().stream().filter(key->key.getKind()==WebAuthnStoreKey.Kind.CEREMONY).findFirst().orElseThrow();var state=new WebAuthnCeremonyRecordCodec(NAMESPACE,RP,f.records).decode(ceremony,f.record(ceremony).getSealedBytes(),f.authorityClock());assertEquals(BASE,state.issuedAt());assertEquals(BASE.plusSeconds(300),state.expiresAt());
  }));return cells;
 }
 @SuppressWarnings("unchecked") // Explicit isolated authority control; never a production writer or recovery mechanism.
 private static void scClk09RotateAdmission(@NonNull F f,boolean authority){
  synchronized(f.source){try{var old=f.source.admission();var next=com.revetsec.StoreAdmission.fromIdentifiers(authority?"A".repeat(43):old.getAuthorityId(),authority?old.getRecoveryGeneration():"A".repeat(43));var field=f.source.getClass().getDeclaredField("admission");field.setAccessible(true);field.set(f.source,next);if(authority){var rows=f.source.getClass().getDeclaredField("entries");rows.setAccessible(true);((Map<WebAuthnStoreKey,WebAuthnStoreEntry.Present>)Objects.requireNonNull(rows.get(f.source))).put(f.root(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(new byte[]{99},f.records.sealNamespace(f.root(),next.getAuthorityId(),BASE)));}}catch(ReflectiveOperationException fault){throw new AssertionError("Isolated admission control failed",fault);}}
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk10LaterCredentialRemovalAndUnrelatedWorkDoNotRepeatTheCommittedBusinessRead(){
  return List.of(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-10/WEBAUTHN/later-removal-and-unrelated-account",()->{
   F f=new F();KeyPair pair=f.enroll();var request=prepared(f.engine.beginAuthentication(BINDING));var root=f.record(f.root());byte[] response=assertionJson(pair.getPrivate(),Base64Url.encode(request.challenge()),1);f.reset();var finalPhase=new AtomicBoolean();List<Set<WebAuthnStoreKey>> finalReads=new CopyOnWriteArrayList<>();var originalReceipt=new AtomicReference<@Nullable WebAuthnStoreCommitReceipt>();
   f.store.afterRead=(number,result)->{if(finalPhase.get())finalReads.add(assertInstanceOf(WebAuthnStoreReadResult.Available.class,result).getSnapshot().getEntries().keySet());return result;};
   f.store.afterCommit=(number,write,receipt)->{assertEquals(1,number);assertFalse(Thread.holdsLock(f.source));f.store.afterCommit=null;originalReceipt.set(receipt);prepared(f.begin(new byte[]{8}));assertEquals(WebAuthnEngine.ManagementStatus.REMOVED,f.engine.removeCredential(HANDLE,CREDENTIAL_ID).status());finalPhase.set(true);return receipt;};
   var result=f.engine.completeAuthentication(request.ceremonyId(),BINDING,response);finalPhase.set(false);assertEquals(WebAuthnEngine.Status.SUCCEEDED,result.status());var fact=Objects.requireNonNull(result.verified());assertArrayEquals(HANDLE,fact.userHandle());assertArrayEquals(CREDENTIAL_ID,fact.credentialId());assertEquals(WebAuthnStoreCommitResult.COMMITTED,Objects.requireNonNull(originalReceipt.get()).getStatus());assertEquals(List.of(Set.of(f.root())),finalReads);assertEquals(3,f.store.writes.size());assertEquals(7,f.store.reads.get());assertArrayEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());var credentialKey=WebAuthnStoreKey.forCredential(NAMESPACE,RP,CREDENTIAL_ID);var tombstone=new WebAuthnCredentialRecordCodec(NAMESPACE,RP,f.records).decodeRecord(credentialKey,f.record(credentialKey).getSealedBytes(),f.authorityClock());assertTrue(tombstone.isRevoked());assertArrayEquals(HANDLE,tombstone.userHandle());assertArrayEquals(CREDENTIAL_ID,tombstone.credentialId());var index=WebAuthnStoreKey.forAccountCredentialIndex(NAMESPACE,RP,HANDLE);assertEquals(0,new WebAuthnCredentialIndex(NAMESPACE,RP,f.records).decode(index,f.record(index).getSealedBytes(),f.authorityClock()).size());assertTrue(f.ceremony(request).isConsumed());
  }));
 }
}
