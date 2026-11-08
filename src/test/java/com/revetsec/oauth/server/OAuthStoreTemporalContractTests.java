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

package com.revetsec.oauth.server;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.testing.ScriptedOAuthStore;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Modifier;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Exact public envelopes, temporal validation and narrow fence-only structural conformance. */
final class OAuthStoreTemporalContractTests {
    private static final @NonNull Instant NOW=Instant.parse("2026-10-04T00:00:00Z");
    private static final @NonNull Duration BUDGET=Duration.ofSeconds(1);
    private static final @NonNull String NS=nonce(1);
    private static final @NonNull OAuthStoreKey ROOT=key(OAuthStoreKey.Kind.ISSUER_STATE,NS);
    private static final @NonNull OAuthStoreKey SUBJECT=key(OAuthStoreKey.Kind.SUBJECT_STATE,nonce(4));
    private static final @NonNull OAuthStoreKey CODE=key(OAuthStoreKey.Kind.CODE,nonce(5));

    @Test void availableBindsExactAddressAndNeverInventsAbsence(){
        StoreTimeObservation sample=ScriptedOAuthStore.observation(NOW);
        var absent=OAuthStoreReadResult.Available.fromObservation(ROOT,null,sample);
        assertEquals(ROOT,absent.getKey());assertTrue(absent.getEntry().isEmpty());assertSame(sample,absent.getTimeObservation());
        OAuthStoreEntry root=entry(ROOT,2);
        assertSame(root,OAuthStoreReadResult.Available.fromObservation(ROOT,root,sample).getEntry().orElseThrow());
        assertThrows(IllegalArgumentException.class,()->OAuthStoreReadResult.Available.fromObservation(SUBJECT,root,sample));
        assertSame(OAuthStoreReadResult.Fenced.get(),OAuthStoreReadResult.Fenced.get());
        assertSame(OAuthStoreReadResult.Unavailable.get(),OAuthStoreReadResult.Unavailable.get());
    }
    @Test @SuppressWarnings("NullAway") // Intentional required-null transport boundary probe.
    void availableRejectsNullTimeObservation(){
        assertThrows(NullPointerException.class,()->OAuthStoreReadResult.Available.fromObservation(ROOT,null,null));
    }
    @Test void receiptFormsAreExactAndRedacted(){
        var sample=ScriptedOAuthStore.observation(NOW);
        var timing=StoreCommitTiming.fromTimes(sample,null);
        var committed=OAuthStoreCommitReceipt.fromCommittedTiming(timing);
        assertEquals(OAuthStoreCommitStatus.COMMITTED,committed.getStatus());
        assertSame(timing,committed.getTiming().orElseThrow());assertSame(sample.getAdmission(),committed.getAdmission().orElseThrow());
        var fence=OAuthStoreCommitReceipt.fromFenceAdmission(sample.getAdmission());
        assertEquals(OAuthStoreCommitStatus.COMMITTED,fence.getStatus());assertTrue(fence.getTiming().isEmpty());
        assertSame(sample.getAdmission(),fence.getAdmission().orElseThrow());
        assertFalse(committed.toString().contains(NOW.toString()));assertFalse(fence.toString().contains(NS));
        for(OAuthStoreCommitStatus status:OAuthStoreCommitStatus.values()){
            if(status==OAuthStoreCommitStatus.COMMITTED || status==OAuthStoreCommitStatus.UNKNOWN)assertThrows(IllegalArgumentException.class,()->OAuthStoreCommitReceipt.fromRefusal(status));
            else {var refusal=OAuthStoreCommitReceipt.fromRefusal(status);assertEquals(status,refusal.getStatus());assertTrue(refusal.getAdmission().isEmpty());assertTrue(refusal.getTiming().isEmpty());}
        }
        assertEquals(OAuthStoreCommitStatus.UNKNOWN,OAuthStoreCommitReceipt.unknownInstance().getStatus());
        assertTrue(OAuthStoreCommitReceipt.unknownInstance().getAdmission().isEmpty());
        assertTrue(OAuthStoreCommitReceipt.unknownInstance().getTiming().isEmpty());
    }
    @Test void newCarrierConstructionRemainsRestricted(){
        for(Class<?> type:List.of(OAuthStoreCommitReceipt.class,OAuthStoreReadResult.Available.class,OAuthStoreReadResult.Fenced.class,OAuthStoreReadResult.Unavailable.class)){
            assertTrue(Modifier.isFinal(type.getModifiers()));
            for(var constructor:type.getDeclaredConstructors())assertTrue(Modifier.isPrivate(constructor.getModifiers()));
        }
        assertEquals(8,java.util.Arrays.stream(OAuthStoreCommitReceipt.class.getDeclaredMethods()).filter(m->Modifier.isPublic(m.getModifiers())).count());
    }
    @Test void timedFactoryRequiresMatchingAdmissionAndCondition(){
        var sample=ScriptedOAuthStore.observation(NOW);
        StoreTemporalCondition condition=condition(sample,NOW.plusSeconds(10));
        var tx=OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.TIMED,sample.getAdmission(),condition,List.of(absent(ROOT)),List.of(put(entry(ROOT,2))));
        assertEquals(OAuthStoreTransaction.Purpose.TIMED,tx.getPurpose());assertSame(condition,tx.getTemporalCondition().orElseThrow());
        assertThrows(IllegalArgumentException.class,()->OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.TIMED,sample.getAdmission(),null,tx.getConditions(),tx.getMutations()));
        StoreAdmission other=StoreAdmission.fromIdentifiers(nonce(9),nonce(10));
        assertThrows(IllegalArgumentException.class,()->OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.TIMED,other,condition,tx.getConditions(),tx.getMutations()));
        assertThrows(UnsupportedOperationException.class,()->tx.getConditions().clear());
    }
    @Test void transactionRejectsMixedNamespacesAndUnconditionedOrUnfreshWrites(){
        var sample=ScriptedOAuthStore.observation(NOW);var condition=condition(sample,null);
        OAuthStoreKey elsewhere=OAuthStoreFormat.key(nonce(10),OAuthStoreKey.Kind.ISSUER_STATE,nonce(10));
        assertThrows(IllegalArgumentException.class,()->timed(sample,condition,List.of(absent(ROOT),absent(elsewhere)),List.of()));
        assertThrows(IllegalArgumentException.class,()->timed(sample,condition,List.of(absent(ROOT)),List.of(put(entry(SUBJECT,2)))));
        assertThrows(IllegalArgumentException.class,()->timed(sample,condition,List.of(present(ROOT,2)),List.of(put(entry(ROOT,2)))));
        assertThrows(IllegalArgumentException.class,()->timed(sample,condition,List.of(absent(ROOT)),List.of(OAuthStoreTransaction.Mutation.fromRemove(ROOT))));
    }
    @Test void fenceOnlyFactoryAllowsExactlyExistingIssuerOrSubjectEpochShape(){
        var sample=ScriptedOAuthStore.observation(NOW);
        var issuer=fence(sample,List.of(present(ROOT,2)),List.of(put(entry(ROOT,3))));
        assertEquals(OAuthStoreTransaction.Purpose.FENCE_ONLY,issuer.getPurpose());assertTrue(issuer.getTemporalCondition().isEmpty());
        assertEquals(2,fence(sample,List.of(present(ROOT,2),present(SUBJECT,3)),List.of(put(entry(SUBJECT,4)))).getConditions().size());
        assertThrows(IllegalArgumentException.class,()->fence(sample,List.of(absent(ROOT)),List.of(put(entry(ROOT,3)))));
        assertThrows(IllegalArgumentException.class,()->fence(sample,List.of(present(ROOT,2)),List.of()));
        assertThrows(IllegalArgumentException.class,()->fence(sample,List.of(present(ROOT,2),present(CODE,3)),List.of(put(entry(CODE,4)))));
        assertThrows(IllegalArgumentException.class,()->fence(sample,List.of(present(SUBJECT,3)),List.of(put(entry(SUBJECT,4)))));
        assertThrows(IllegalArgumentException.class,()->fence(sample,List.of(present(ROOT,2),present(SUBJECT,3)),List.of(put(entry(ROOT,4)))));
        assertThrows(IllegalArgumentException.class,()->OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.FENCE_ONLY,sample.getAdmission(),condition(sample,null),issuer.getConditions(),issuer.getMutations()));
    }
    @Test void scriptedStoreEnforcesFreshExactBoundsBeforeCapacity(){
        var store=new ScriptedOAuthStore(NOW,1,65536);var sample=ScriptedOAuthStore.observation(NOW);
        assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(timed(sample,condition(sample,null),List.of(absent(ROOT)),List.of(put(entry(ROOT,2)))),BUDGET).getStatus());
        var tx=timed(sample,condition(sample,NOW.plusSeconds(1)),List.of(present(ROOT,2),absent(SUBJECT)),List.of(put(entry(SUBJECT,3))));
        store.setTime(NOW.plusSeconds(1));
        assertEquals(OAuthStoreCommitStatus.TIME_EXPIRED,store.commit(tx,BUDGET).getStatus());
        assertEquals(1,store.records().size());
    }
    @Test void lowerBoundIsInclusiveAndWrongClockFences(){
        var store=new ScriptedOAuthStore(NOW);var sample=ScriptedOAuthStore.observation(NOW);
        var future=StoreTimeAccess.get().fromObservation(sample,NOW.plusSeconds(1),NOW.plusSeconds(2));
        var tx=timed(sample,future,List.of(absent(ROOT)),List.of(put(entry(ROOT,2))));
        assertEquals(OAuthStoreCommitStatus.TIME_BEFORE_FLOOR,store.commit(tx,BUDGET).getStatus());
        store.setTime(NOW.plusSeconds(1));assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(tx,BUDGET).getStatus());
        store.rotateClockGeneration();
        assertEquals(OAuthStoreCommitStatus.FENCED,store.commit(timed(sample,condition(sample,null),List.of(present(ROOT,2)),List.of()),BUDGET).getStatus());
    }
    @Test void unavailableClockDoesNotAuthorizeTimedMutationButFenceStillWorks(){
        var store=new ScriptedOAuthStore(NOW);store.seedClosedMigration(Map.of(ROOT,entry(ROOT,2),SUBJECT,entry(SUBJECT,3)));
        var sample=ScriptedOAuthStore.observation(NOW);store.setHealthy(false);
        var read=(OAuthStoreReadResult.Available)store.read(ROOT,BUDGET);assertInstanceOf(StoreTimeObservation.Unavailable.class,read.getTimeObservation());
        assertEquals(OAuthStoreCommitStatus.TIME_UNAVAILABLE,store.commit(timed(sample,condition(sample,null),List.of(present(ROOT,2)),List.of()),BUDGET).getStatus());
        var committed=store.commit(fence(sample,List.of(present(ROOT,2),present(SUBJECT,3)),List.of(put(entry(SUBJECT,4)))),BUDGET);
        assertEquals(OAuthStoreCommitStatus.COMMITTED,committed.getStatus());assertTrue(committed.getTiming().isEmpty());
        assertEquals(nonce(4),requireNonNull(store.records().get(SUBJECT)).getVersion());
    }
    @Test void changedAdmissionFencesWithoutMutation(){
        var store=new ScriptedOAuthStore(NOW);store.seedClosedMigration(Map.of(ROOT,entry(ROOT,2)));var sample=ScriptedOAuthStore.observation(NOW);
        store.rotateRecoveryGeneration();
        assertEquals(OAuthStoreCommitStatus.FENCED,store.commit(fence(sample,List.of(present(ROOT,2)),List.of(put(entry(ROOT,3)))),BUDGET).getStatus());
        assertEquals(nonce(2),requireNonNull(store.records().get(ROOT)).getVersion());
    }
    @Test void readAndRefusalNeverPruneRetainedBytes(){
        var store=new ScriptedOAuthStore(NOW);store.seedClosedMigration(Map.of(ROOT,entry(ROOT,2),CODE,entry(CODE,3)));var before=store.records();
        store.setTime(NOW.plusSeconds(60));assertInstanceOf(OAuthStoreReadResult.Available.class,store.read(CODE,BUDGET));assertEquals(before,store.records());
        var sample=ScriptedOAuthStore.observation(NOW.plusSeconds(60));
        assertEquals(OAuthStoreCommitStatus.CONFLICT,store.commit(timed(sample,condition(sample,null),List.of(present(ROOT,9)),List.of()),BUDGET).getStatus());assertEquals(before,store.records());
        assertInstanceOf(OAuthStoreReadResult.Unavailable.class,store.read(ROOT,Duration.ZERO));assertEquals(before,store.records());
    }
    @Test void emptyBarrierNeverRewritesVersionsOrCapacity(){
        var store=new ScriptedOAuthStore(NOW,1,65536);store.seedClosedMigration(Map.of(ROOT,entry(ROOT,2)));var before=store.records();var sample=ScriptedOAuthStore.observation(NOW);
        var receipt=store.commit(timed(sample,condition(sample,null),List.of(present(ROOT,2)),List.of()),BUDGET);
        assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());assertEquals(before,store.records());assertEquals(NOW,receipt.getTiming().orElseThrow().getValidatedTime().getObservedAt());
    }
    @Test void missingEstablishedRootCannotBeReinitialized(){
        var store=new OAuthAtomicStoreFixture(NOW);var sample=ScriptedOAuthStore.observation(NOW);
        assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(timed(sample,condition(sample,null),List.of(absent(ROOT)),List.of(put(entry(ROOT,2)))),BUDGET).getStatus());
        store.rows.clear();
        assertInstanceOf(OAuthStoreReadResult.Unavailable.class,store.read(ROOT,BUDGET));
        assertEquals(OAuthStoreCommitStatus.UNAVAILABLE,store.commit(timed(sample,condition(sample,null),List.of(absent(ROOT)),List.of(put(entry(ROOT,3)))),BUDGET).getStatus());assertTrue(store.rows.isEmpty());
    }
    @Test void knownAndUnknownReceiptsRemainDifferentAfterAcknowledgementHook(){
        var store=new OAuthAtomicStoreFixture(NOW);var sample=ScriptedOAuthStore.observation(NOW);
        store.afterCommit=()->store.healthy=false;
        var receipt=store.commit(timed(sample,condition(sample,null),List.of(absent(ROOT)),List.of(put(entry(ROOT,2)))),BUDGET);
        assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());assertEquals(NOW,receipt.getTiming().orElseThrow().getValidatedTime().getObservedAt());
        store.unknownAfter=true;
        var unknown=store.commit(fence(sample,List.of(present(ROOT,2)),List.of(put(entry(ROOT,3)))),BUDGET);
        assertEquals(OAuthStoreCommitStatus.UNKNOWN,unknown.getStatus());assertEquals(nonce(3),requireNonNull(store.rows.get(ROOT)).getVersion());
    }
    @Test void confirmedNotAdmittedReasonIsRestrictedNontransientAndWireGeneric(){
        var failure=OAuthServerStoreException.fromReason(OAuthServerException.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,true);
        assertFalse(failure.isTemporaryCondition());assertNull(failure.getCause());assertEquals(0,failure.getSuppressed().length);
        var response=OAuthServerFailureBoundary.failure(failure,16384,16384);
        assertEquals(503,response.getStatusCode());
        assertEquals(OAuthServerException.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,OAuthServerFailureBoundary.store(new OAuthStoreFailure(OAuthStoreFailure.Reason.COMMIT_CONFIRMED_NOT_ADMITTED)).getReason());
    }
    private static @NonNull OAuthStoreTransaction timed(StoreTimeObservation.@NonNull Healthy sample,@NonNull StoreTemporalCondition condition,@NonNull List<OAuthStoreTransaction.@NonNull Condition> conditions,@NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations){return OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.TIMED,sample.getAdmission(),condition,conditions,mutations);}
    private static @NonNull OAuthStoreTransaction fence(StoreTimeObservation.@NonNull Healthy sample,@NonNull List<OAuthStoreTransaction.@NonNull Condition> conditions,@NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations){return OAuthStoreTransaction.fromConditions(OAuthStoreTransaction.Purpose.FENCE_ONLY,sample.getAdmission(),null,conditions,mutations);}
    private static @NonNull StoreTemporalCondition condition(StoreTimeObservation.@NonNull Healthy sample,@Nullable Instant upper){return StoreTimeAccess.get().fromObservation(sample,sample.getObservedAt(),upper);}
    private static OAuthStoreTransaction.@NonNull Condition absent(@NonNull OAuthStoreKey key){return OAuthStoreTransaction.Condition.fromAbsent(key);}
    private static OAuthStoreTransaction.@NonNull Condition present(@NonNull OAuthStoreKey key,int version){return OAuthStoreTransaction.Condition.fromVersion(key,nonce(version));}
    private static OAuthStoreTransaction.@NonNull Mutation put(@NonNull OAuthStoreEntry entry){return OAuthStoreTransaction.Mutation.fromPut(entry);}
    private static @NonNull OAuthStoreKey key(OAuthStoreKey.@NonNull Kind kind,@NonNull String id){return OAuthStoreFormat.key(NS,kind,id);}
    private static @NonNull OAuthStoreEntry entry(@NonNull OAuthStoreKey key,int version){return OAuthStoreEntry.fromStoredForm(key,nonce(version),key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE || key.getKind()==OAuthStoreKey.Kind.SUBJECT_STATE?OAuthStoreFormat.PERMANENT:NOW.plusSeconds(30),"opaque-fixture");}
    private static @NonNull String nonce(int seed){byte[] bytes=new byte[32];for(int n=0;n<32;n++)bytes[n]=(byte)(seed+n);return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}

 @Test @SuppressWarnings("NullAway") void scApi08IssuerReceiptFactoriesRejectEveryRequiredNull(){
  assertThrows(NullPointerException.class,()->OAuthStoreCommitReceipt.fromCommittedTiming(null));assertThrows(NullPointerException.class,()->OAuthStoreCommitReceipt.fromFenceAdmission(null));assertThrows(NullPointerException.class,()->OAuthStoreCommitReceipt.fromRefusal(null));
 }

 @SuppressWarnings("try") // Early close releases waiting writers before joining the executor; repeated close is idempotent.
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi07DeclaredIssuerMonitorProtectsValidationThroughApplyAndOrdersLaterRecovery(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();for(boolean fenceOnly:List.of(false,true))for(boolean recovery:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-07/ISSUER-volatile/"+(fenceOnly?"FENCE_ONLY":"TIMED")+"/"+(recovery?"recovery":"entity"),()->{
   ScriptedOAuthStore store=new ScriptedOAuthStore(NOW);OAuthStoreEntry root=entry(ROOT,2),old=entry(SUBJECT,3),replacement=entry(SUBJECT,4),newCode=entry(CODE,5);store.seedClosedMigration(Map.of(ROOT,root,SUBJECT,old));StoreTimeObservation.Healthy observed=ScriptedOAuthStore.observation(store.admission(),store.clockGeneration(),NOW);List<OAuthStoreTransaction.Condition> predicates=fenceOnly?List.of(present(ROOT,2),present(SUBJECT,3)):List.of(present(ROOT,2),present(SUBJECT,3),absent(CODE));OAuthStoreTransaction primary=fenceOnly?fence(observed,predicates,List.of(put(replacement))):timed(observed,condition(observed,null),predicates,List.of(put(replacement),put(newCode)));OAuthStoreTransaction competitor=fenceOnly?fence(observed,predicates,List.of(put(entry(SUBJECT,6)))):timed(observed,condition(observed,null),predicates,List.of(put(entry(SUBJECT,6)),put(entry(CODE,7))));if(fenceOnly)store.setHealthy(false);List<String> trace=new java.util.concurrent.CopyOnWriteArrayList<>();var executor=java.util.concurrent.Executors.newFixedThreadPool(2);var rival=new java.util.concurrent.atomic.AtomicReference<Thread>();var called=new java.util.concurrent.CountDownLatch(1);
   try(var pause=com.revetsec.testing.StoreCommitPause.install(store,"entries",trace,()->Thread.holdsLock(store))){
    try{
     var one=executor.submit(()->{trace.add("primary-call");pause.selectCurrentWriter();var result=store.commit(primary,Duration.ofSeconds(10));trace.add("primary-returned");return result;});assertTrue(pause.awaitEntered());assertTrue(pause.wasProtected(),"Post-validation state apply lost its actual store monitor");assertEquals(ScriptedOAuthStore.class.getName(),pause.getCallSite().getClassName());assertEquals("commit",pause.getCallSite().getMethodName());
     var two=executor.submit(()->{rival.set(Thread.currentThread());trace.add("competitor-call");called.countDown();Object result;if(recovery){store.rotateRecoveryGeneration();result=store.admission();}else result=store.commit(competitor,Duration.ofSeconds(10));trace.add("competitor-returned");return result;});assertTrue(called.await(2,java.util.concurrent.TimeUnit.SECONDS));long end=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(2);boolean blocked=false;while(System.nanoTime()<end&&!two.isDone()){Thread thread=requireNonNull(rival.get());var info=java.lang.management.ManagementFactory.getThreadMXBean().getThreadInfo(thread.getId());if(info!=null&&info.getThreadState()==Thread.State.BLOCKED&&info.getLockInfo()!=null&&info.getLockInfo().getIdentityHashCode()==System.identityHashCode(store)){blocked=true;break;}Thread.yield();}assertTrue(blocked,"Competing operation must block on the actual issuer fixture monitor");assertFalse(two.isDone());trace.add("competitor-queued");pause.resume();var committed=one.get(5,java.util.concurrent.TimeUnit.SECONDS);assertEquals(OAuthStoreCommitStatus.COMMITTED,committed.getStatus());assertEquals(observed.getAdmission(),committed.getAdmission().orElseThrow());assertEquals(fenceOnly,committed.getTiming().isEmpty());if(!fenceOnly)assertEquals(NOW,committed.getTiming().orElseThrow().getValidatedTime().getObservedAt());Object later=two.get(5,java.util.concurrent.TimeUnit.SECONDS);
     assertSame(root,store.records().get(ROOT));assertSame(replacement,store.records().get(SUBJECT));if(fenceOnly)assertFalse(store.records().containsKey(CODE));else assertSame(newCode,store.records().get(CODE));if(recovery){assertInstanceOf(StoreAdmission.class,later);assertNotEquals(observed.getAdmission(),store.admission());var fresh=assertInstanceOf(OAuthStoreReadResult.Available.class,store.read(ROOT,BUDGET));assertEquals(store.admission(),fresh.getTimeObservation().getAdmission());assertNotEquals(committed.getAdmission().orElseThrow(),fresh.getTimeObservation().getAdmission(),"Known receipt is a factual effect, not fresh service admission");assertEquals(OAuthStoreCommitStatus.FENCED,store.commit(competitor,BUDGET).getStatus());}else{var refused=assertInstanceOf(OAuthStoreCommitReceipt.class,later);assertEquals(OAuthStoreCommitStatus.CONFLICT,refused.getStatus());assertTrue(refused.getTiming().isEmpty());assertEquals(observed.getAdmission(),store.admission());}assertEquals(List.of("primary-call","validated-copy-paused","competitor-call","competitor-queued","release-copy","copy-resumed"),trace.subList(0,6));assertEquals(8,trace.size());
    }finally{pause.close();executor.shutdown();if(!executor.awaitTermination(3,java.util.concurrent.TimeUnit.SECONDS)){executor.shutdownNow();assertTrue(executor.awaitTermination(3,java.util.concurrent.TimeUnit.SECONDS));}}
   }finally{executor.shutdownNow();assertTrue(executor.awaitTermination(3,java.util.concurrent.TimeUnit.SECONDS));}
  }));return cells;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi06DeclaredIssuerSamplesFreshAuthorityAfterActualMonitorWait(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();
  for(boolean expires:List.of(false,true))for(boolean mutate:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-06/ISSUER-monitor/"+(expires?"valid-to-E":"below-N-to-valid")+"/mutation="+mutate,()->{
   ScriptedOAuthStore store=new ScriptedOAuthStore(NOW);OAuthStoreEntry root=entry(ROOT,2);store.seedClosedMigration(Map.of(ROOT,root));
   StoreTimeObservation.Healthy original=assertInstanceOf(StoreTimeObservation.Healthy.class,assertInstanceOf(OAuthStoreReadResult.Available.class,store.read(ROOT,BUDGET)).getTimeObservation());
   Instant lower=expires?NOW:NOW.plusSeconds(1),upper=expires?NOW.plusSeconds(1):NOW.plusSeconds(10),afterWait=expires?upper:NOW.plusSeconds(2);
   StoreTemporalCondition predicate=StoreTimeAccess.get().fromObservation(original,lower,upper);
   OAuthStoreTransaction tx=timed(original,predicate,List.of(present(ROOT,2),absent(CODE)),mutate?List.of(put(entry(CODE,3))):List.of());
   var executor=java.util.concurrent.Executors.newSingleThreadExecutor();var called=new java.util.concurrent.CountDownLatch(1);var thread=new java.util.concurrent.atomic.AtomicReference<Thread>();List<String> trace=new java.util.concurrent.CopyOnWriteArrayList<>();java.util.concurrent.Future<OAuthStoreCommitReceipt> waiting;
   try{
    synchronized(store){
     trace.add("snapshot-before-wait");waiting=executor.submit(()->{thread.set(Thread.currentThread());trace.add("commit-call");called.countDown();var result=store.commit(tx,Duration.ofSeconds(10));trace.add("commit-returned");return result;});assertTrue(called.await(2,java.util.concurrent.TimeUnit.SECONDS));
     long end=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(2);boolean blocked=false;
     while(System.nanoTime()<end&&!waiting.isDone()){var info=java.lang.management.ManagementFactory.getThreadMXBean().getThreadInfo(requireNonNull(thread.get()).getId());if(info!=null&&info.getThreadState()==Thread.State.BLOCKED&&info.getLockInfo()!=null&&info.getLockInfo().getIdentityHashCode()==System.identityHashCode(store)){blocked=true;break;}Thread.yield();}
     assertTrue(blocked,"The real issuer commit must wait on its actual monitor");assertFalse(waiting.isDone());trace.add("blocked-on-real-monitor");store.setTime(afterWait);trace.add("authority-moved-under-monitor");assertFalse(waiting.isDone());trace.add("releasing-monitor");
    }
    OAuthStoreCommitReceipt receipt=waiting.get(5,java.util.concurrent.TimeUnit.SECONDS);
    assertEquals(expires?OAuthStoreCommitStatus.TIME_EXPIRED:OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());
    if(expires){assertTrue(receipt.getTiming().isEmpty());assertEquals(Map.of(ROOT,root),store.records());}
    else{var stamp=receipt.getTiming().orElseThrow().getValidatedTime();assertEquals(afterWait,stamp.getObservedAt(),"Validation must use authority sampled after the wait");assertEquals(original.getAdmission(),stamp.getAdmission());assertEquals(original.getClockGeneration(),stamp.getClockGeneration());assertTrue(receipt.getTiming().orElseThrow().getCompletedTime().isEmpty());assertSame(root,store.records().get(ROOT));if(mutate)assertEquals(entry(CODE,3).toSealedForm(),requireNonNull(store.records().get(CODE)).toSealedForm());else assertEquals(Map.of(ROOT,root),store.records());}
    assertEquals(List.of("snapshot-before-wait","commit-call","blocked-on-real-monitor","authority-moved-under-monitor","releasing-monitor","commit-returned"),trace);
   }finally{executor.shutdownNow();assertTrue(executor.awaitTermination(3,java.util.concurrent.TimeUnit.SECONDS));}
  }));return cells;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi09DeclaredIssuerAuthorityLossAfterHealthyReadRefusesNormalButAllowsExactFence(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();
  for(boolean mutate:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-09/ISSUER-volatile/authority-loss-before-validation/mutation="+mutate,()->{
   ScriptedOAuthStore store=new ScriptedOAuthStore(NOW);OAuthStoreEntry root=entry(ROOT,2),subject=entry(SUBJECT,3);store.seedClosedMigration(Map.of(ROOT,root,SUBJECT,subject));
   var observed=assertInstanceOf(StoreTimeObservation.Healthy.class,assertInstanceOf(OAuthStoreReadResult.Available.class,store.read(ROOT,BUDGET)).getTimeObservation());
   StoreTemporalCondition condition=condition(observed,NOW.plusSeconds(30));OAuthStoreTransaction tx=timed(observed,condition,List.of(present(ROOT,2),present(SUBJECT,3),absent(CODE)),mutate?List.of(put(entry(CODE,4))):List.of());
   store.setTime(NOW.plusSeconds(1));store.setHealthy(false);Instant rawStore=store.authorityTime(),worker=java.time.Clock.fixed(NOW.plusSeconds(1),java.time.ZoneOffset.UTC).instant();assertFalse(rawStore.isBefore(condition.getNotBeforeInclusive()));assertFalse(worker.isBefore(condition.getNotBeforeInclusive()));assertTrue(rawStore.isBefore(condition.getValidBeforeExclusive().orElseThrow()));assertTrue(worker.isBefore(condition.getValidBeforeExclusive().orElseThrow()));
   var refused=store.commit(tx,BUDGET);assertEquals(OAuthStoreCommitStatus.TIME_UNAVAILABLE,refused.getStatus(),"Raw store/worker instants cannot substitute for healthy authority");assertTrue(refused.getTiming().isEmpty());assertEquals(Map.of(ROOT,root,SUBJECT,subject),store.records());assertInstanceOf(StoreTimeObservation.Unavailable.class,assertInstanceOf(OAuthStoreReadResult.Available.class,store.read(ROOT,BUDGET)).getTimeObservation());
   var permanent=entry(SUBJECT,5);var receipt=store.commit(fence(observed,List.of(present(ROOT,2),present(SUBJECT,3)),List.of(put(permanent))),BUDGET);assertEquals(OAuthStoreCommitStatus.COMMITTED,receipt.getStatus());assertTrue(receipt.getTiming().isEmpty());assertEquals(observed.getAdmission(),receipt.getAdmission().orElseThrow());assertEquals(Map.of(ROOT,root,SUBJECT,permanent),store.records());
  }));return cells;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi04EveryIssuerKindAndAbsenceDefeatsBothWholeMutationAndBarrier(){
  List<org.junit.jupiter.api.DynamicTest> cells=new java.util.ArrayList<>();
  for(OAuthStoreKey.Kind kind:OAuthStoreKey.Kind.values())for(boolean exists:List.of(false,true))for(boolean mutate:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-04+10/ISSUER/"+kind+"/present="+exists+"/mutation="+mutate,()->{
   ScriptedOAuthStore store=new ScriptedOAuthStore(NOW);OAuthStoreKey target=kind==OAuthStoreKey.Kind.ISSUER_STATE?ROOT:key(kind,nonce(6)),first=key(OAuthStoreKey.Kind.CODE,nonce(7)),second=key(OAuthStoreKey.Kind.CODE,nonce(8));var seed=new java.util.LinkedHashMap<OAuthStoreKey,OAuthStoreEntry>();
   if(kind!=OAuthStoreKey.Kind.ISSUER_STATE || exists)seed.put(ROOT,entry(ROOT,2));if(exists&&!target.equals(ROOT))seed.put(target,entry(target,3));store.seedClosedMigration(seed);
   var keys=new java.util.LinkedHashSet<OAuthStoreKey>(List.of(ROOT,target,first,second));var predicates=new java.util.ArrayList<OAuthStoreTransaction.Condition>();StoreTimeObservation.Healthy original=null;
   for(OAuthStoreKey key:keys){var read=assertInstanceOf(OAuthStoreReadResult.Available.class,store.read(key,BUDGET));var time=assertInstanceOf(StoreTimeObservation.Healthy.class,read.getTimeObservation());if(original==null)original=time;else assertEquals(original.getAdmission(),time.getAdmission());predicates.add(read.getEntry().isPresent()?OAuthStoreTransaction.Condition.fromVersion(key,read.getEntry().orElseThrow().getVersion()):absent(key));}
   var sample=requireNonNull(original);List<OAuthStoreTransaction.Mutation> candidates=target.equals(ROOT)&&!exists?List.of(put(entry(ROOT,20)),put(entry(first,21))):List.of(put(entry(first,20)),put(entry(second,21)));
   var pending=timed(sample,condition(sample,NOW.plusSeconds(10)),predicates,mutate?candidates:List.of());var rival=timed(sample,condition(sample,NOW.plusSeconds(10)),predicates,List.of(put(entry(target,10))));
   assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(rival,BUDGET).getStatus());var retained=store.records();var backing=ScriptedOAuthStore.class.getDeclaredField("entries");backing.setAccessible(true);Object retainedBacking=requireNonNull(backing.get(store));var refused=store.commit(pending,BUDGET);
   assertAll(()->assertEquals(OAuthStoreCommitStatus.CONFLICT,refused.getStatus()),()->assertTrue(refused.getTiming().isEmpty()),()->assertEquals(retained,store.records(),"No prefix put may survive a conflicting predicate"),()->assertSame(retainedBacking,backing.get(store)));
   assertEquals(keys,pending.getConditions().stream().map(OAuthStoreTransaction.Condition::getKey).collect(java.util.stream.Collectors.toSet()));assertEquals(mutate?2:0,pending.getMutations().size());var fresh=new java.util.ArrayList<OAuthStoreTransaction.Condition>();for(OAuthStoreKey key:keys){var read=assertInstanceOf(OAuthStoreReadResult.Available.class,store.read(key,BUDGET));fresh.add(read.getEntry().isPresent()?OAuthStoreTransaction.Condition.fromVersion(key,read.getEntry().orElseThrow().getVersion()):absent(key));}
   assertEquals(OAuthStoreCommitStatus.COMMITTED,store.commit(timed(sample,condition(sample,NOW.plusSeconds(10)),fresh,List.of()),BUDGET).getStatus());assertEquals(retained,store.records());assertSame(retainedBacking,backing.get(store));
  }));return cells;
 }
}
