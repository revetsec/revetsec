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
        assertThrows(NullPointerException.class,()->OAuthStoreReadResult.Available.fromObservation(ROOT,null,null));
        assertSame(OAuthStoreReadResult.Fenced.get(),OAuthStoreReadResult.Fenced.get());
        assertSame(OAuthStoreReadResult.Unavailable.get(),OAuthStoreReadResult.Unavailable.get());
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
        assertEquals(nonce(4),store.records().get(SUBJECT).getVersion());
    }
    @Test void changedAdmissionFencesWithoutMutation(){
        var store=new ScriptedOAuthStore(NOW);store.seedClosedMigration(Map.of(ROOT,entry(ROOT,2)));var sample=ScriptedOAuthStore.observation(NOW);
        store.rotateRecoveryGeneration();
        assertEquals(OAuthStoreCommitStatus.FENCED,store.commit(fence(sample,List.of(present(ROOT,2)),List.of(put(entry(ROOT,3)))),BUDGET).getStatus());
        assertEquals(nonce(2),store.records().get(ROOT).getVersion());
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
        assertEquals(OAuthStoreCommitStatus.UNKNOWN,unknown.getStatus());assertEquals(nonce(3),store.rows.get(ROOT).getVersion());
    }
    @Test void confirmedNotAdmittedReasonIsRestrictedNontransientAndWireGeneric(){
        var failure=OAuthServerStoreException.fromReason(OAuthServerException.Reason.COMMIT_CONFIRMED_NOT_ADMITTED,true);
        assertFalse(failure.isTransient());assertNull(failure.getCause());assertEquals(0,failure.getSuppressed().length);
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
}
