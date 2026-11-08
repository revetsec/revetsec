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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.crypto.TotpPrimitives;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
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

/** Independent authority/worker and factual-effect regressions over genuine engine writes. */
final class TotpSharedClockEngineTests {
	private static final @NonNull Instant BASE=Instant.ofEpochSecond(1700000010);
	private static final @NonNull Duration BUDGET=Duration.ofSeconds(2);
	private static final @NonNull String NAMESPACE="shared-clock-tests",EPOCH="epoch-one",ACCOUNT="account-a";

	@Test void toleratedWorkerOffsetNeverBecomesStoredTimeOrPendingExpiry() throws Exception {
		F f=new F();TotpStoreRecord root=f.record(f.root());f.worker.set(BASE.plusSeconds(2));
		TotpEnrollment pending=assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.begin()).getEnrollment();
		assertEquals(BASE.plusSeconds(300),pending.getExpiresAt());
		try(TotpRecordsV3.Decoded decoded=f.account()){assertEquals(BASE,Objects.requireNonNull(decoded.account).observedAt);}
		assertEquals(root.getVersion(),f.record(f.root()).getVersion());
	}
	@Test void fastWorkerCannotPoisonNamespaceOrAnotherWorker() throws Exception {
		F f=new F();TotpStoreRecord root=f.record(f.root());f.worker.set(BASE.plusSeconds(6));
		assertEquals(TotpUnavailableReason.CLOCK_HEALTH_UNCONFIRMED,assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,f.begin()).getReason());
		assertEquals(0,f.store.commits.get());assertEquals(root.getVersion(),f.record(f.root()).getVersion());
		WorkerClock healthy=new WorkerClock(BASE);TotpAuthenticator other=f.auth(healthy);
		assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,other.beginEnrollmentResult(options("another"),"browser"));
		assertEquals(root.getVersion(),f.record(f.root()).getVersion());
	}
	@org.junit.jupiter.api.TestFactory
	@NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk01ThirtyOneSecondFastWorkerCannotPoisonExactHealthyComparison() {
		List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
		for(int healthyNanos:List.of(0,1))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-01/TOTP/fast=31s/healthy="+healthyNanos+"ns",()->{
			F f=new F();TotpStoreRecord root=f.record(f.root());f.worker.set(BASE.plusSeconds(31));
			assertEquals(TotpUnavailableReason.CLOCK_HEALTH_UNCONFIRMED,assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,f.begin()).getReason());
			assertEquals(0,f.store.commits.get());assertTrue(f.store.writes.isEmpty());
			assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());
			assertInstanceOf(TotpStoreEntry.Absent.class,assertInstanceOf(TotpStoreReadResult.Available.class,f.source.read(Set.of(f.key()),BUDGET)).getSnapshot().getEntry(f.key()));
			TotpAuthenticator healthy=f.auth(new WorkerClock(BASE.plusNanos(healthyNanos)));
			TotpEnrollment pending=assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,healthy.beginEnrollmentResult(options(ACCOUNT),"browser")).getEnrollment();
			assertEquals(BASE.plusSeconds(300),pending.getExpiresAt());
			try(TotpRecordsV3.Decoded decoded=f.account()){assertEquals(BASE,Objects.requireNonNull(decoded.account).observedAt);}
			assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());
		}));return cases;
	}
	@Test void wholeCausalWorkerSampleIsTakenAfterStoreReply() {
		F f=new F();f.store.afterRead=(number,result)->{if(number==1)f.worker.set(BASE.plusSeconds(6));return result;};
		assertEquals(TotpUnavailableReason.CLOCK_HEALTH_UNCONFIRMED,assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,f.begin()).getReason());
		assertEquals(0,f.store.commits.get());
	}
	@Test void independentAccountsNeverRewriteTheStableRootOrConflictForTime() throws Exception {
		F f=new F();TotpStoreRecord root=f.record(f.root());f.advance(Duration.ofSeconds(1));
		var pool=Executors.newFixedThreadPool(16);CountDownLatch start=new CountDownLatch(1);
		try {
			List<java.util.concurrent.Future<TotpEnrollmentRequestResult>> jobs=new ArrayList<>();
			for(int i=0;i<16;i++){String account="parallel-"+i;jobs.add(pool.submit(()->{assertTrue(start.await(5,TimeUnit.SECONDS));return f.totp.beginEnrollmentResult(options(account),"browser");}));}
			start.countDown();for(var job:jobs)assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,job.get(10,TimeUnit.SECONDS));
		}finally{pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}
		assertEquals(16,f.store.commits.get());assertEquals(0,f.store.conflicts.get());
		assertEquals(root.getVersion(),f.record(f.root()).getVersion());
		assertTrue(f.store.writes.stream().allMatch(w->w.getMutations().size()==1 && w.getMutations().get(0).getKey().getKind()==TotpStoreKey.Kind.ACCOUNT_STATE));
		TotpStoreKey key=TotpStoreKey.forAccount(NAMESPACE,EPOCH,"parallel-0");
		try(TotpRecordsV3.Decoded decoded=f.codec.open(f.record(key))){assertTrue(Objects.requireNonNull(decoded.account).observedAt.isAfter(BASE));}
	}
	@Test void statusObservesExpiryWithoutAnyDataOrFloorWrite() throws Exception {
		F f=new F();assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.begin());TotpStoreRecord before=f.record(f.key());f.advance(Duration.ofSeconds(301));f.reset();
		TotpStatus status=assertInstanceOf(TotpStatusResult.Present.class,f.totp.getStatusResult(ACCOUNT)).getStatus();
		assertTrue(status.getPendingEnrollment().isEmpty());assertEquals(0,f.store.commits.get());
		assertEquals(before.getVersion(),f.record(f.key()).getVersion());assertArrayEquals(before.getSealedBytes(),f.record(f.key()).getSealedBytes());
	}
	@Test void validFutureAccountFloorClosesUntilAuthorityCatchupWithoutClamping() throws Exception {
		F f=new F(false);TotpRecords.Account account=new TotpRecords.Account(ACCOUNT,f.codec.freshId(),BASE.plusSeconds(10));
		try {f.source.seedClosedMigration(List.of(f.codec.sealNamespace(f.root(),new TotpRecordsV3.Namespace(f.source.admission().getAuthorityId(),BASE)),f.codec.sealAccount(f.key(),account)));}finally{account.erase();}
		assertEquals(TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE,assertInstanceOf(TotpStatusResult.Unavailable.class,f.totp.getStatusResult(ACCOUNT)).getReason());assertEquals(0,f.store.commits.get());
		f.advance(Duration.ofSeconds(10));assertInstanceOf(TotpStatusResult.Present.class,f.totp.getStatusResult(ACCOUNT));assertEquals(0,f.store.commits.get());
	}
	@Test void normalTrafficRejectsAuthenticatedLegacyInsteadOfPromotingIt() {
		F f=new F(false);TotpRecords old=new TotpRecords(f.sealer);
		f.source.seedClosedMigration(List.of(old.seal(f.root(),new TotpRecords.Namespace(BASE),null)));
		assertEquals(TotpUnavailableReason.INVALID_STORED_STATE,assertInstanceOf(TotpStatusResult.Unavailable.class,f.totp.getStatusResult(ACCOUNT)).getReason());assertEquals(0,f.store.commits.get());
	}
	@org.junit.jupiter.api.TestFactory
	@NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scEng09StatusStateAndRawClockMatrixIsPure() {
		List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
		for(String state:List.of("live","missing","corrupt","read-unavailable","worker-backward","worker-forward"))
			cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-ENG-09/TOTP/status/"+state,()->{
				F f=new F();
				if(!state.equals("missing"))assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.begin());
				Map<TotpStoreKey,TotpStoreRecord> before=statusRows(f.source,f.root(),f.key());f.reset();
				if(state.equals("corrupt"))f.store.afterRead=(number,result)->{
					if(number!=1)return result;
					TotpStoreSnapshot snapshot=assertInstanceOf(TotpStoreReadResult.Available.class,result).getSnapshot();
					TotpStoreRecord original=Objects.requireNonNull(before.get(f.key()));byte[] damaged=original.getSealedBytes();damaged[damaged.length/2]^=1;
					Map<TotpStoreKey,TotpStoreEntry> entries=new HashMap<>(snapshot.getEntries());
					entries.put(f.key(),TotpStoreEntry.Present.fromRecord(TotpStoreRecord.fromStoredForm(f.key(),original.getVersion(),damaged)));
					return TotpStoreReadResult.Available.fromSnapshot(TotpStoreSnapshot.fromEntries(entries.keySet(),entries,snapshot.getTimeObservation()));
				};
				if(state.equals("read-unavailable"))f.store.failRead.set(true);
				if(state.equals("worker-backward"))f.worker.set(BASE.minusSeconds(6));
				if(state.equals("worker-forward"))f.worker.set(BASE.plusSeconds(6));
				TotpStatusResult result=f.totp.getStatusResult(ACCOUNT);
				if(state.equals("live"))assertTrue(assertInstanceOf(TotpStatusResult.Present.class,result).getStatus().getPendingEnrollment().isPresent());
				else if(state.equals("missing"))assertInstanceOf(TotpStatusResult.Absent.class,result);
				else {
					TotpUnavailableReason expected=switch(state){
						case "corrupt"->TotpUnavailableReason.INVALID_STORED_STATE;
						case "read-unavailable"->TotpUnavailableReason.DEPENDENCY_UNAVAILABLE;
						default->TotpUnavailableReason.CLOCK_HEALTH_UNCONFIRMED;
					};
					assertEquals(expected,assertInstanceOf(TotpStatusResult.Unavailable.class,result).getReason());
				}
				assertEquals(0,f.store.commits.get());assertTrue(f.store.writes.isEmpty());
				assertStatusRowsSame(before,statusRows(f.source,f.root(),f.key()));
			}));
		return cases;
	}
	@Test void scEng09ExpiredPendingAndChargesAreFilteredWithoutPersistedCleanup() throws Exception {
		F f=new F(false);TotpRecords.Account account=new TotpRecords.Account(ACCOUNT,f.codec.freshId(),BASE);
		try {
			account.pending=new TotpRecords.Pending(f.codec.freshId(),f.codec.freshId(),new byte[20],new byte[32],BASE.plusSeconds(300),null);
			String charge=f.codec.freshId();account.charges.add(new TotpRecords.Charge(charge,BASE));
			account.totpCharges.add(new TotpRecords.Charge(charge,BASE));
			f.source.seedClosedMigration(List.of(
				f.codec.sealNamespace(f.root(),new TotpRecordsV3.Namespace(f.source.admission().getAuthorityId(),BASE)),
				f.codec.sealAccount(f.key(),account)));
		} finally { account.erase(); }
		Instant expired=BASE.plusSeconds(86401);f.source.setTime(expired);f.worker.set(expired);
		Map<TotpStoreKey,TotpStoreRecord> before=statusRows(f.source,f.root(),f.key());f.reset();
		TotpStatus status=assertInstanceOf(TotpStatusResult.Present.class,f.totp.getStatusResult(ACCOUNT)).getStatus();
		assertTrue(status.getPendingEnrollment().isEmpty());assertEquals(0,f.store.commits.get());assertTrue(f.store.writes.isEmpty());
		assertStatusRowsSame(before,statusRows(f.source,f.root(),f.key()));
		try(TotpRecordsV3.Decoded decoded=f.account()){
			TotpRecords.Account retained=Objects.requireNonNull(decoded.account);assertNotNull(retained.pending);
			assertEquals(1,retained.charges.size());assertEquals(1,retained.totpCharges.size());
		}
	}
	@Test void scEng09FullCapacityRefusesMutationButCannotEvictOrDistortStatus() {
		ScriptedTotpStore source=new ScriptedTotpStore(NAMESPACE,EPOCH,BASE,2,268435456L);
		RecordingStore store=new RecordingStore(source);WorkerClock worker=new WorkerClock(BASE);Gate gate=new Gate();
		StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).maximumSealedLength(16384).build();
		TotpAuthenticator totp=TotpAuthenticator.withIssuer("Shared Clock").credentialNamespace(NAMESPACE).recoveryEpoch(EPOCH)
			.store(store).clock(worker).stateSealer(sealer).recoveryGate(gate).operationTimeout(Duration.ofSeconds(30)).build();
		assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,totp.initializeNamespaceResult());
		assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,totp.beginEnrollmentResult(options(ACCOUNT),"browser"));
		TotpStoreKey root=TotpStoreKey.forNamespace(NAMESPACE,EPOCH),account=TotpStoreKey.forAccount(NAMESPACE,EPOCH,ACCOUNT);
		Map<TotpStoreKey,TotpStoreRecord> full=statusRows(source,root,account);store.commits.set(0);store.reads.set(0);store.writes.clear();
		TotpEnrollmentRequestResult.Unavailable refused=assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,
			totp.beginEnrollmentResult(options("capacity-other"),"browser"));
		assertEquals(TotpUnavailableReason.CAPACITY_REFUSED,refused.getReason());assertEquals(1,store.commits.get());
		assertStatusRowsSame(full,statusRows(source,root,account));store.commits.set(0);store.reads.set(0);store.writes.clear();
		assertInstanceOf(TotpStatusResult.Present.class,totp.getStatusResult(ACCOUNT));
		assertInstanceOf(TotpStatusResult.Absent.class,totp.getStatusResult("capacity-other"));
		assertEquals(0,store.commits.get());assertTrue(store.writes.isEmpty());assertStatusRowsSame(full,statusRows(source,root,account));
	}
	@Test void ownInitializationPinsExactlyTheCommittedMinimumForFinalRead() {
		F f=new F(false);f.store.afterRead=(number,result)->{
			if(number!=2 || !(result instanceof TotpStoreReadResult.Available available))return result;
			TotpStoreRecord alternate=f.codec.sealNamespace(f.root(),new TotpRecordsV3.Namespace(f.source.admission().getAuthorityId(),BASE.minusSeconds(1)));
			Map<TotpStoreKey,TotpStoreEntry> entries=new HashMap<>(available.getSnapshot().getEntries());entries.put(f.root(),TotpStoreEntry.Present.fromRecord(alternate));
			return TotpStoreReadResult.Available.fromSnapshot(TotpStoreSnapshot.fromEntries(Set.of(f.root()),entries,available.getSnapshot().getTimeObservation()));
		};
		assertInstanceOf(TotpNamespaceInitializationResult.ReconciliationRequired.class,f.totp.initializeNamespaceResult());assertEquals(1,f.store.commits.get());
	}
	@Test void knownEnrollmentCommitWithTimeOnlyOutageRequiresReconciliation() throws Exception {
		F f=new F();f.store.afterCommit=(number,write,receipt)->{f.source.setHealthy(false);return receipt;};
		assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,f.begin());assertEquals(1,f.store.commits.get());
		try(TotpRecordsV3.Decoded decoded=f.account()){assertNotNull(Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending));}
		f.source.setHealthy(true);f.store.afterCommit=null;
		assertEquals(TotpRejectionReason.ENROLLMENT_CONFLICT,assertInstanceOf(TotpEnrollmentRequestResult.Rejected.class,f.begin()).getReason());
	}
	@Test void unknownEnrollmentIsNeverRescuedFromAReadableMatchingRow() {
		F f=new F();f.store.afterCommit=(number,write,receipt)->TotpStoreCommitReceipt.unknownInstance();
		assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,f.begin());assertEquals(1,f.store.commits.get());assertEquals(1,f.store.reads.get());
	}
	@Test void confirmedChargeAndDefinitelyUnperformedSettlementIsAttemptIncomplete() throws Exception {
		F f=new F();f.enroll();f.advance(Duration.ofSeconds(60));f.reset();
		f.store.afterCommit=(number,write,receipt)->{if(number==1)f.store.failRead.set(true);return receipt;};
		assertEquals(TotpUnavailableReason.ATTEMPT_INCOMPLETE,assertInstanceOf(TotpVerificationResult.Unavailable.class,f.totp.verifyResult(ACCOUNT,f.code(0),"login")).getReason());
		assertEquals(1,f.store.commits.get());try(TotpRecordsV3.Decoded decoded=f.account()){assertEquals(1,Objects.requireNonNull(decoded.account).charges.size());assertEquals(Objects.requireNonNull(decoded.account).charges.get(0).id,Objects.requireNonNull(decoded.account).totpCharges.get(0).id);}
	}
	@Test void chargePlusUnknownSettlementRetainsUncertaintyWithoutRetry() throws Exception {
		for(boolean effect:List.of(false,true)){
			F f=new F();f.enroll();f.advance(Duration.ofSeconds(60));f.reset();
			if(effect)f.store.afterCommit=(number,write,receipt)->number==2?TotpStoreCommitReceipt.unknownInstance():receipt;
			else f.store.beforeCommit=(number,write)->number==2?TotpStoreCommitReceipt.unknownInstance():null;
			assertInstanceOf(TotpVerificationResult.Indeterminate.class,f.totp.verifyResult(ACCOUNT,f.code(0),"login"));assertEquals(2,f.store.commits.get());
			try(TotpRecordsV3.Decoded decoded=f.account()){assertEquals(effect?0:1,Objects.requireNonNull(decoded.account).charges.size());}
		}
	}
	@Test void explicitNoEffectAfterChargeDoesNotEraseTheReservation() throws Exception {
		F f=new F();f.enroll();f.advance(Duration.ofSeconds(60));f.reset();
		f.store.beforeCommit=(number,write)->number==2?TotpStoreCommitReceipt.fromRefusal(TotpStoreCommitResult.CAPACITY_REFUSED):null;
		assertEquals(TotpUnavailableReason.ATTEMPT_INCOMPLETE,assertInstanceOf(TotpVerificationResult.Unavailable.class,f.totp.verifyResult(ACCOUNT,f.code(0),"login")).getReason());assertEquals(2,f.store.commits.get());
		try(TotpRecordsV3.Decoded decoded=f.account()){assertEquals(1,Objects.requireNonNull(decoded.account).charges.size());}
	}
	@Test void knownProofConsumptionSurvivesPermitCloseFailureWithoutProofRelease() throws Exception {
		F f=new F();f.enroll();f.advance(Duration.ofSeconds(60));String code=f.code(0);f.reset();f.gate.failClose.set(true);
		assertInstanceOf(TotpVerificationResult.ReconciliationRequired.class,f.totp.verifyResult(ACCOUNT,code,"login"));assertEquals(2,f.store.commits.get());
		try(TotpRecordsV3.Decoded decoded=f.account()){assertEquals(0,Objects.requireNonNull(decoded.account).charges.size());assertEquals(f.source.authorityTime().getEpochSecond()/30,Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).usedStep);}
	}
	@Test void previousStepKeepsItsOriginalConfiguredWindowAcrossTheFinalWait() throws Exception {
		F f=new F();f.enroll();f.advance(Duration.ofSeconds(70));String code=f.code(-1);Instant end=Instant.ofEpochSecond((f.source.authorityTime().getEpochSecond()/30+1)*30);f.reset();
		f.store.beforeCommit=(number,write)->{if(number==2){assertEquals(end,write.getTemporalCondition().getValidBeforeExclusive().orElseThrow());f.advance(Duration.between(f.source.authorityTime(),end));}return null;};
		assertEquals(TotpUnavailableReason.ATTEMPT_INCOMPLETE,assertInstanceOf(TotpVerificationResult.Unavailable.class,f.totp.verifyResult(ACCOUNT,code,"login")).getReason());
		try(TotpRecordsV3.Decoded decoded=f.account()){assertEquals(1,Objects.requireNonNull(decoded.account).charges.size());}
	}
	@Test void committedProofAtExpiryIsReconciliationRatherThanUnknownOrSuccess() throws Exception {
		F f=new F();f.enroll();f.advance(Duration.ofSeconds(89).plusMillis(900));String code=f.code(-1);Instant end=Instant.ofEpochSecond((f.source.authorityTime().getEpochSecond()/30+1)*30);f.reset();
		f.store.afterCommit=(number,write,receipt)->{if(number==2)f.advance(Duration.between(f.source.authorityTime(),end));return receipt;};
		assertInstanceOf(TotpVerificationResult.ReconciliationRequired.class,f.totp.verifyResult(ACCOUNT,code,"login"));
		try(TotpRecordsV3.Decoded decoded=f.account()){assertEquals(0,Objects.requireNonNull(decoded.account).charges.size());}
	}
	@Test void generationChangeBeforeFinalReadWithholdsKnownCommit() {
		F f=new F();f.store.afterCommit=(number,write,receipt)->{f.source.rotateClockGeneration();return receipt;};
		assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,f.begin());assertEquals(1,f.store.commits.get());
	}
	@Test void generationChangeAfterFinalSnapshotIsLaterState() {
		F f=new F();f.store.afterRead=(number,result)->{if(number==2)f.source.rotateClockGeneration();return result;};
		assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.begin());assertEquals(1,f.store.commits.get());
	}
	@Test void queryOnlyExpiryCannotReviveAfterAnEarlierNewGeneration() throws Exception {
		F f=new F();assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.begin());f.advance(Duration.ofSeconds(301));f.reset();
		assertTrue(assertInstanceOf(TotpStatusResult.Present.class,f.totp.getStatusResult(ACCOUNT)).getStatus().getPendingEnrollment().isEmpty());
		f.source.rotateClockGeneration();f.source.setTime(BASE);f.worker.set(BASE);
		assertEquals(TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE,assertInstanceOf(TotpStatusResult.Unavailable.class,f.totp.getStatusResult(ACCOUNT)).getReason());assertEquals(0,f.store.commits.get());
	}
	@org.junit.jupiter.api.TestFactory
	@NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> migrationCatchupChecksBothImmutableMinimumAndEntityFloor() {
		List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
		for(int shape=0;shape<3;shape++)for(int edge=-1;edge<=1;edge++){
			Instant minimum=BASE.plusSeconds(shape==0?10:1),floor=BASE.plusSeconds(shape==1?10:shape==2?20:1);
			Instant bound=minimum.isAfter(floor)?minimum:floor,now=bound.plusNanos(edge);int position=edge;
			cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG11/TOTP/"+shape+"/"+edge,()->{
				F f=new F(false);TotpRecords.Account account=new TotpRecords.Account(ACCOUNT,f.codec.freshId(),floor);
				try{f.source.seedClosedMigration(List.of(f.codec.sealNamespace(f.root(),new TotpRecordsV3.Namespace(f.source.admission().getAuthorityId(),minimum)),f.codec.sealAccount(f.key(),account)));}finally{account.erase();}
				f.source.setTime(now);f.worker.set(now);TotpStoreRecord root=f.record(f.root()),entity=f.record(f.key());f.reset();
				var result=f.totp.getStatusResult(ACCOUNT);
				if(position<0)assertInstanceOf(TotpStatusResult.Unavailable.class,result);else assertInstanceOf(TotpStatusResult.Present.class,result);
				assertEquals(0,f.store.commits.get());assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());
				assertEquals(entity.getVersion(),f.record(f.key()).getVersion());assertArrayEquals(entity.getSealedBytes(),f.record(f.key()).getSealedBytes());
				try(var decoded=f.codec.open(root)){assertEquals(minimum,Objects.requireNonNull(decoded.namespace).getMinimum());}
				try(var decoded=f.codec.open(entity)){assertEquals(floor,Objects.requireNonNull(decoded.account).observedAt);}
			}));
		}return cases;
	}
	private static @NonNull TotpEnrollmentOptions options(@NonNull String account){return TotpEnrollmentOptions.withAccountId(account).accountName("person@example.test").build();}
	private static @NonNull Map<@NonNull TotpStoreKey,@NonNull TotpStoreRecord> statusRows(
			@NonNull ScriptedTotpStore source,@NonNull TotpStoreKey root,@NonNull TotpStoreKey account){
		TotpStoreSnapshot snapshot=assertInstanceOf(TotpStoreReadResult.Available.class,source.read(Set.of(root,account),BUDGET)).getSnapshot();
		Map<TotpStoreKey,TotpStoreRecord> rows=new HashMap<>();
		for(TotpStoreKey key:List.of(root,account))if(snapshot.getEntry(key) instanceof TotpStoreEntry.Present present)rows.put(key,present.getRecord());
		return Map.copyOf(rows);
	}
	private static void assertStatusRowsSame(@NonNull Map<@NonNull TotpStoreKey,@NonNull TotpStoreRecord> expected,
			@NonNull Map<@NonNull TotpStoreKey,@NonNull TotpStoreRecord> actual){
		assertEquals(expected.keySet(),actual.keySet());
		for(TotpStoreKey key:expected.keySet()){
			TotpStoreRecord first=Objects.requireNonNull(expected.get(key)),second=Objects.requireNonNull(actual.get(key));
			assertEquals(first.getVersion(),second.getVersion());assertArrayEquals(first.getSealedBytes(),second.getSealedBytes());
		}
	}

	@org.junit.jupiter.api.TestFactory
	@NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi02ErrorProfileCannotChangeAtReceiptOrFinalRead() {
		List<org.junit.jupiter.api.DynamicTest> tests=new ArrayList<>();
		for(Duration initial:List.of(Duration.ZERO,Duration.ofMillis(250)))for(String stage:List.of("CONTROL","VALIDATION","FINAL")){
			Duration changed=initial.isZero()?Duration.ofMillis(250):Duration.ZERO;
			tests.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-02/TOTP/"+stage+"/"+initial,()->{
				F f=new F();
				f.store.afterRead=(n,result)->{
					var snapshot=assertInstanceOf(TotpStoreReadResult.Available.class,result).getSnapshot();
					var time=assertInstanceOf(com.revetsec.StoreTimeObservation.Healthy.class,snapshot.getTimeObservation());
					Duration error=stage.equals("FINAL") && n==2?changed:initial;
					return TotpStoreReadResult.Available.fromSnapshot(TotpStoreSnapshot.fromEntries(snapshot.getEntries().keySet(),snapshot.getEntries(),
						com.revetsec.StoreTimeObservation.Healthy.fromObservation(time.getAdmission(),time.getClockGeneration(),time.getObservedAt(),error)));
				};
				f.store.afterCommit=(n,write,receipt)->{
					var time=receipt.getTiming().orElseThrow().getValidatedTime();
					return TotpStoreCommitReceipt.fromCommittedTiming(com.revetsec.StoreCommitTiming.fromTimes(
						com.revetsec.StoreTimeObservation.Healthy.fromObservation(time.getAdmission(),time.getClockGeneration(),time.getObservedAt(),stage.equals("VALIDATION")?changed:initial),null));
				};
				TotpEnrollmentRequestResult result=f.begin();
				if(stage.equals("CONTROL"))assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,result);
				else assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,result);
				assertEquals(1,f.store.commits.get());assertEquals(stage.equals("VALIDATION")?1:2,f.store.reads.get());
				try(var decoded=f.account()){assertNotNull(Objects.requireNonNull(decoded.account).pending);}
				assertTrue(f.store.writes.stream().flatMap(w->w.getMutations().stream()).allMatch(m->m.getKey().getRecoveryEpoch().equals(EPOCH)));
			}));
		}
		return tests;
	}
	@Test void scApi02InvalidLocalAccountDoesNotLookUpStoreOrChangeState(){
		F f=new F();String rootVersion=f.record(f.root()).getVersion();
		for(String account:List.of("","a".repeat(1025),"\ud800")){
			assertThrows(IllegalArgumentException.class,()->f.totp.getStatusResult(account));
			assertEquals(0,f.store.reads.get());assertEquals(0,f.store.commits.get());
		}
		assertEquals(rootVersion,f.record(f.root()).getVersion());
	}

	@FunctionalInterface private interface BeforeCommit { @Nullable TotpStoreCommitReceipt apply(int number,@NonNull TotpStoreWrite write); }
	@FunctionalInterface private interface AfterCommit { @NonNull TotpStoreCommitReceipt apply(int number,@NonNull TotpStoreWrite write,@NonNull TotpStoreCommitReceipt result); }
	@FunctionalInterface private interface AfterRead { @NonNull TotpStoreReadResult apply(int number,@NonNull TotpStoreReadResult result); }
	@ThreadSafe private static final class RecordingStore implements TotpStore {
		final @NonNull ScriptedTotpStore source;
		volatile java.util.concurrent.@Nullable CopyOnWriteArrayList<@NonNull String> phaseTrace;
		final @NonNull AtomicInteger commits=new AtomicInteger(),reads=new AtomicInteger(),conflicts=new AtomicInteger();
		final @NonNull List<@NonNull TotpStoreWrite> writes=new CopyOnWriteArrayList<>();
		final @NonNull AtomicBoolean failRead=new AtomicBoolean();
		volatile @Nullable BeforeCommit beforeCommit;
		volatile @Nullable AfterCommit afterCommit;
		volatile @Nullable AfterRead afterRead;
		RecordingStore(@NonNull ScriptedTotpStore source){this.source=source;}
		@Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget){
			var trace=this.phaseTrace;if(trace!=null)trace.add("read-call");int number=this.reads.incrementAndGet();if(this.failRead.get())throw new IllegalStateException("Scripted read outage");
			TotpStoreReadResult result=this.source.read(keys,budget);AfterRead hook=this.afterRead;TotpStoreReadResult delivered=hook==null?result:hook.apply(number,result);if(trace!=null)trace.add("read-reply");return delivered;
		}
		@Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration budget){
			var trace=this.phaseTrace;if(trace!=null)trace.add("commit-call");int number=this.commits.incrementAndGet();this.writes.add(write);BeforeCommit before=this.beforeCommit;
			TotpStoreCommitReceipt result=before==null?null:before.apply(number,write);
			if(result==null)result=this.source.compareAndCommit(write,budget);
			if(result.getStatus()==TotpStoreCommitResult.CONFLICT)this.conflicts.incrementAndGet();
			AfterCommit after=this.afterCommit;TotpStoreCommitReceipt delivered=after==null?result:after.apply(number,write,result);if(trace!=null)trace.add("commit-reply");return delivered;
		}
	}
	@ThreadSafe private static final class WorkerClock extends Clock {
		private final @NonNull AtomicReference<@NonNull Instant> time;
		volatile java.util.concurrent.@Nullable CopyOnWriteArrayList<@NonNull String> phaseTrace;
		WorkerClock(@NonNull Instant time){this.time=new AtomicReference<>(time);}
		void set(@NonNull Instant time){this.time.set(time);}
		@Override public @NonNull Instant instant(){var trace=this.phaseTrace;if(trace!=null)trace.add("worker-wall");return Objects.requireNonNull(this.time.get());}
		@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
		@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return Clock.fixed(instant(),zone);}
	}
	@ThreadSafe private static final class Gate implements TotpRecoveryGate {
		final @NonNull AtomicBoolean failClose=new AtomicBoolean(),open=new AtomicBoolean(true);
		@Override public @NonNull Permit acquire(@NonNull TotpRecoveryContext context,@NonNull Duration budget){return new Permit(){
			@Override public @NonNull Boolean isCurrent(){return open.get();}
			@Override public void close(){if(failClose.getAndSet(false))throw new IllegalStateException("Scripted close failure");}
		};}
	}
	@NotThreadSafe private static final class F {
		final @NonNull ScriptedTotpStore source=new ScriptedTotpStore(NAMESPACE,EPOCH,BASE);
		final @NonNull RecordingStore store=new RecordingStore(this.source);
		final @NonNull WorkerClock worker=new WorkerClock(BASE);
		final @NonNull Gate gate=new Gate();
		final @NonNull StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).maximumSealedLength(16384).build();
		final @NonNull TotpRecordsV3 codec=new TotpRecordsV3(this.sealer);
		final @NonNull TotpAuthenticator totp=auth(this.worker);
		F(){this(true);}
		F(boolean initialize){if(initialize)assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,this.totp.initializeNamespaceResult());reset();}
		@NonNull TotpAuthenticator auth(@NonNull Clock clock){return auth(clock,Duration.ofSeconds(30));}
		@NonNull TotpAuthenticator auth(@NonNull Clock clock,@NonNull Duration timeout){return TotpAuthenticator.withIssuer("Shared Clock").credentialNamespace(NAMESPACE).recoveryEpoch(EPOCH).store(this.store).clock(clock).stateSealer(this.sealer).recoveryGate(this.gate).operationTimeout(timeout).build();}
		void reset(){this.store.commits.set(0);this.store.reads.set(0);this.store.conflicts.set(0);this.store.writes.clear();this.store.failRead.set(false);this.store.beforeCommit=null;this.store.afterCommit=null;this.store.afterRead=null;}
		void advance(@NonNull Duration duration){this.source.advance(duration);this.worker.set(this.worker.instant().plus(duration));}
		@NonNull TotpStoreKey root(){return TotpStoreKey.forNamespace(NAMESPACE,EPOCH);}
		@NonNull TotpStoreKey key(){return TotpStoreKey.forAccount(NAMESPACE,EPOCH,ACCOUNT);}
		@NonNull TotpStoreRecord record(@NonNull TotpStoreKey key){return assertInstanceOf(TotpStoreEntry.Present.class,assertInstanceOf(TotpStoreReadResult.Available.class,this.source.read(Set.of(key),BUDGET)).getSnapshot().getEntry(key)).getRecord();}
		TotpRecordsV3.@NonNull Decoded account() throws Exception {return this.codec.open(record(key()));}
		@NonNull TotpEnrollmentRequestResult begin(){return this.totp.beginEnrollmentResult(options(ACCOUNT),"browser");}
		void enroll() throws Exception {
			TotpEnrollment pending=assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,begin()).getEnrollment();
			String code=null;
			for(int n=0;n<8 && code==null;n++){
				try(TotpRecordsV3.Decoded decoded=account()){
					byte[] secret=Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending).secret;long step=this.source.authorityTime().getEpochSecond()/30;
					String candidate=TotpPrimitives.hotp(secret,step,"HmacSHA1",6);
					if(TotpPrimitives.matchingStep(secret,candidate,step,-1)==step)code=candidate;
				}
				if(code==null)advance(Duration.ofSeconds(30));
			}
			assertNotNull(code);assertInstanceOf(TotpEnrollmentResult.Succeeded.class,this.totp.confirmEnrollmentResult(ACCOUNT,pending.getEnrollmentId(),code,"browser"));
		}
		@NonNull String code(int delta) throws Exception {
			try(TotpRecordsV3.Decoded decoded=account()){
				long current=this.source.authorityTime().getEpochSecond()/30,step=current+delta;byte[] secret=Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).secret;
				String value=TotpPrimitives.hotp(secret,step,"HmacSHA1",6);
				assertEquals(step,TotpPrimitives.matchingStep(secret,value,current,Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).usedStep));return value;
			}
		}
	}
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig14PreparedFloorSurvivesLaterValidationAndCompletion(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
  for(boolean initialize:List.of(false,true))for(int nano:List.of(1,123456789,999999999))for(boolean completed:List.of(false,true))for(int offset:List.of(-2,2))
   cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-14/TOTP/timing/"+initialize+"/"+nano+"/"+completed+"/"+offset,()->{
    F f=new F(!initialize);Instant prepared=BASE.plusSeconds(5).plusNanos(nano),validated=prepared.plusMillis(200),finished=validated.plusMillis(300);
    f.source.setTime(prepared);f.worker.set(prepared.plusSeconds(offset));TotpStoreRecord oldRoot=initialize?null:f.record(f.root());
    f.store.beforeCommit=(n,w)->{assertEquals(prepared,w.getTemporalCondition().getNotBeforeInclusive());f.source.setTime(validated);f.worker.set(validated.plusSeconds(offset));return null;};
    f.store.afterCommit=(n,w,r)->{
     assertEquals(TotpStoreCommitResult.COMMITTED,r.getStatus());var v=r.getTiming().orElseThrow().getValidatedTime();assertEquals(validated,v.getObservedAt());
     f.source.setTime(finished);f.worker.set(finished.plusSeconds(offset));
     var c=com.revetsec.StoreTimeObservation.Healthy.fromObservation(v.getAdmission(),v.getClockGeneration(),finished,v.getMaximumUtcError());
     return TotpStoreCommitReceipt.fromCommittedTiming(com.revetsec.StoreCommitTiming.fromTimes(v,completed?c:null));
    };
    if(initialize)assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,f.totp.initializeNamespaceResult());else assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.begin());
    assertEquals(1,f.store.writes.size());
    for(var mutation:f.store.writes.get(0).getMutations()){
     TotpStoreRecord input=mutation.getRecord(),stored=f.record(input.getKey());assertEquals(input.getVersion(),stored.getVersion());assertArrayEquals(input.getSealedBytes(),stored.getSealedBytes());
     try(var opened=f.codec.open(stored)){assertEquals(prepared,opened.namespace!=null?opened.namespace.getMinimum():Objects.requireNonNull(opened.account).observedAt);}
    }
    if(oldRoot!=null){assertEquals(oldRoot.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(oldRoot.getSealedBytes(),f.record(f.root()).getSealedBytes());}
   }));return cases;
 }
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig14StatusIsPureAtPendingExpiryBoundaries(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
  for(int edge:List.of(-1,0,1))for(int offset:List.of(-2,0,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-14/TOTP/status/"+edge+"/"+offset,()->{
   F f=new F();var pending=assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.begin()).getEnrollment();var root=f.record(f.root());var account=f.record(f.key());
   Instant time=pending.getExpiresAt().plusNanos(edge);f.source.setTime(time);f.worker.set(time.plusSeconds(offset));f.reset();
   var status=assertInstanceOf(TotpStatusResult.Present.class,f.totp.getStatusResult(ACCOUNT)).getStatus();assertEquals(edge<0,status.getPendingEnrollment().isPresent());assertEquals(0,f.store.commits.get());
   assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());assertEquals(account.getVersion(),f.record(f.key()).getVersion());assertArrayEquals(account.getSealedBytes(),f.record(f.key()).getSealedBytes());
  }));return cases;
 }

 private static @NonNull Map<?,?> mig15FixtureRows(@NonNull Object source,@NonNull String field)throws Exception{var f=source.getClass().getDeclaredField(field);f.setAccessible(true);return (Map<?,?>)Objects.requireNonNull(f.get(source));}
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15BootstrapNeedsCurrentAuthorizationAndExactAbsence(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
  for(String mode:List.of("CLEAN","CLOSED","UTC_DOWN","PRESENT"))for(int offset:List.of(-2,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/TOTP/bootstrap/"+mode+"/"+offset,()->{
   F f=new F(mode.equals("PRESENT"));f.worker.set(BASE.plusSeconds(offset));var before=new HashMap<>(mig15FixtureRows(f.source,"records"));if(mode.equals("CLOSED"))f.gate.open.set(false);if(mode.equals("UTC_DOWN"))f.source.setHealthy(false);
   var result=f.totp.initializeNamespaceResult();
   if(mode.equals("CLEAN")){assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,result);var write=f.store.writes.get(0);assertInstanceOf(TotpStoreEntry.Absent.class,write.getSnapshot().getEntry(f.root()));assertEquals(TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE,write.getPurpose());}
   else if(mode.equals("PRESENT")){assertInstanceOf(TotpNamespaceInitializationResult.AlreadyInitialized.class,result);assertEquals(before,mig15FixtureRows(f.source,"records"));assertTrue(f.store.writes.stream().allMatch(w->w.getMutations().isEmpty()));}
   else {assertInstanceOf(TotpNamespaceInitializationResult.Unavailable.class,result);assertEquals(0,f.store.commits.get());assertEquals(before,mig15FixtureRows(f.source,"records"));f.gate.open.set(true);f.source.setHealthy(true);assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,f.totp.initializeNamespaceResult());}
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15KnownRootLossOrOrphansNeverBecomeFreshAbsence(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();
  for(String loss:List.of("ESTABLISHED_EMPTY","ESTABLISHED_RETAINED","ORPHAN"))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/TOTP/root-loss/"+loss,()->{
   F f=new F(!loss.equals("ORPHAN"));
   if(loss.equals("ORPHAN")){var account=new TotpRecords.Account(ACCOUNT,f.codec.freshId(),BASE);try{f.source.seedClosedMigration(List.of(f.codec.sealAccount(f.key(),account)));}finally{account.erase();}}
   else {if(loss.equals("ESTABLISHED_RETAINED"))f.enroll();var rows=mig15FixtureRows(f.source,"records");rows.remove(f.root());if(loss.equals("ESTABLISHED_EMPTY"))rows.clear();}
   f.reset();var before=new HashMap<>(mig15FixtureRows(f.source,"records"));assertInstanceOf(TotpStoreReadResult.Unavailable.class,f.source.read(Set.of(f.root()),BUDGET));assertInstanceOf(TotpStoreReadResult.Unavailable.class,f.source.read(Set.of(f.key()),BUDGET));
   assertInstanceOf(TotpNamespaceInitializationResult.Unavailable.class,f.totp.initializeNamespaceResult());assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,f.begin());assertEquals(before,mig15FixtureRows(f.source,"records"));assertEquals(0,f.store.commits.get());
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15ChangedAuthorityCannotRepairExistingRoot(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(int offset:List.of(-2,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/TOTP/authority/"+offset,()->{
   F f=new F();f.enroll();var before=new HashMap<>(mig15FixtureRows(f.source,"records"));var field=f.source.getClass().getDeclaredField("admission");field.setAccessible(true);field.set(f.source,com.revetsec.StoreAdmission.fromIdentifiers("A".repeat(43),f.source.admission().getRecoveryGeneration()));f.worker.set(BASE.plusSeconds(offset));f.reset();
   assertInstanceOf(TotpStatusResult.Unavailable.class,f.totp.getStatusResult(ACCOUNT));assertInstanceOf(TotpNamespaceInitializationResult.Unavailable.class,f.totp.initializeNamespaceResult());assertEquals(before,mig15FixtureRows(f.source,"records"));assertEquals(0,f.store.commits.get());
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15ClockOnlyReadmissionKeepsOriginalCredentialUsable(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(boolean close:List.of(false,true))for(int offset:List.of(-2,2))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/TOTP/clock/"+close+"/"+offset,()->{
   F f=new F();f.enroll();f.advance(Duration.ofSeconds(60));f.worker.set(f.source.authorityTime().plusSeconds(offset));var before=new HashMap<>(mig15FixtureRows(f.source,"records"));var root=f.record(f.root());var admission=f.source.admission();f.reset();f.source.rotateClockGeneration();
   if(close){f.gate.open.set(false);assertInstanceOf(TotpStatusResult.Unavailable.class,f.totp.getStatusResult(ACCOUNT));assertEquals(before,mig15FixtureRows(f.source,"records"));assertEquals(0,f.store.commits.get());f.gate.open.set(true);}
   assertInstanceOf(TotpStatusResult.Present.class,f.totp.getStatusResult(ACCOUNT));assertEquals(before,mig15FixtureRows(f.source,"records"));assertEquals(admission,f.source.admission());String code=f.code(0);assertInstanceOf(TotpVerificationResult.Succeeded.class,f.totp.verifyResult(ACCOUNT,code,"mig15-original-secret"));assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> mig15CompetingBootstrapCannotOverwriteWinner(){
  return List.of(org.junit.jupiter.api.DynamicTest.dynamicTest("MIG-15/TOTP/absent-CAS",()->{
   F f=new F(false);AtomicReference<TotpStoreRecord> winner=new AtomicReference<>();f.store.beforeCommit=(n,w)->{f.store.beforeCommit=null;assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,f.totp.initializeNamespaceResult());winner.set(f.record(f.root()));return null;};
   assertInstanceOf(TotpNamespaceInitializationResult.Unavailable.class,f.totp.initializeNamespaceResult());assertSame(winner.get(),f.record(f.root()));
  }));
 }

 @Test void cap09CapacityIsNotConflictOrCredentialRejectionAndNeverRetries() throws Exception {
  F f=new F();TotpStoreRecord root=f.record(f.root());
  f.store.beforeCommit=(n,w)->TotpStoreCommitReceipt.fromRefusal(TotpStoreCommitResult.CAPACITY_REFUSED);
  assertEquals(TotpUnavailableReason.CAPACITY_REFUSED,assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,f.begin()).getReason());
  assertEquals(1,f.store.commits.get());assertEquals(0,f.store.conflicts.get());
  assertInstanceOf(TotpStoreEntry.Absent.class,assertInstanceOf(TotpStoreReadResult.Available.class,f.source.read(Set.of(f.root(),f.key()),BUDGET)).getSnapshot().getEntry(f.key()));
  assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());
  f.reset();assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.begin());assertEquals(1,f.store.commits.get());
 }

 @Test void scPub04PublicNoEffectAdmissionAndDeadlineReasonsAreExact() {
  F closed=new F();closed.gate.open.set(false);
  assertEquals(TotpUnavailableReason.ADMISSION_CLOSED,assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,closed.begin()).getReason());
  assertEquals(0,closed.store.reads.get());assertEquals(0,closed.store.commits.get());assertTrue(closed.store.writes.isEmpty());

  F expired=new F();expired.store.afterRead=(number,result)->{if(number==1)scMeasuredReleaseDelay(150_000_000L);return result;};
  var deadline=expired.auth(expired.worker,Duration.ofMillis(100)).beginEnrollmentResult(options(ACCOUNT),"browser");
  assertEquals(TotpUnavailableReason.DEADLINE_EXCEEDED,assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,deadline).getReason());
  assertEquals(1,expired.store.reads.get());assertEquals(0,expired.store.commits.get());assertTrue(expired.store.writes.isEmpty());
 }

 @Test void scEng02And08PostChargeConflictExhaustionStopsAfterNineSettlementCallbacks() throws Exception {
  F f=new F();f.enroll();f.advance(Duration.ofSeconds(60));String code=f.code(0);long used;
  try(var decoded=f.account()){used=Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).usedStep;}f.reset();
  f.store.beforeCommit=(number,write)->number==1?null:TotpStoreCommitReceipt.fromRefusal(TotpStoreCommitResult.CONFLICT);
  var result=f.totp.verifyResult(ACCOUNT,code,"SC-ENG-02+08/conflict-exhaustion");
  assertEquals(TotpUnavailableReason.ATTEMPT_INCOMPLETE,assertInstanceOf(TotpVerificationResult.Unavailable.class,result).getReason());
  assertEquals(10,f.store.commits.get());assertEquals(9,f.store.conflicts.get());assertEquals(10,f.store.reads.get());assertEquals(10,f.store.writes.size());
  assertEquals(1,f.store.writes.stream().map(write->write.getTemporalCondition().getValidBeforeExclusive().orElseThrow()).distinct().count());
  try(var decoded=f.account()){var account=Objects.requireNonNull(decoded.account);assertEquals(1,account.charges.size());assertEquals(1,account.totpCharges.size());assertEquals(account.charges.get(0).id,account.totpCharges.get(0).id);assertEquals(used,Objects.requireNonNull(account.active).usedStep);}
 }

 @Test void scEng02PostChargeOriginalBudgetExpiresBeforeSettlementCallback() throws Exception {
  F f=new F();f.enroll();f.advance(Duration.ofSeconds(60));String code=f.code(0);long used;
  try(var decoded=f.account()){used=Objects.requireNonNull(Objects.requireNonNull(decoded.account).active).usedStep;}f.reset();
  f.store.afterCommit=(number,write,receipt)->{if(number==1)scMeasuredReleaseDelay(150_000_000L);return receipt;};
  var result=f.auth(f.worker,Duration.ofMillis(100)).verifyResult(ACCOUNT,code,"SC-ENG-02/pre-settlement-timeout");
  assertEquals(TotpUnavailableReason.ATTEMPT_INCOMPLETE,assertInstanceOf(TotpVerificationResult.Unavailable.class,result).getReason());
  assertEquals(1,f.store.commits.get());assertEquals(0,f.store.conflicts.get());assertEquals(1,f.store.reads.get());assertEquals(1,f.store.writes.size());
  try(var decoded=f.account()){var account=Objects.requireNonNull(decoded.account);assertEquals(1,account.charges.size());assertEquals(1,account.totpCharges.size());assertEquals(account.charges.get(0).id,account.totpCharges.get(0).id);assertEquals(used,Objects.requireNonNull(account.active).usedStep);}
 }


 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk02WorkerHealthLossAfterKnownCommitWithholdsOutputWithoutErasingMutation(){
  List<org.junit.jupiter.api.DynamicTest> cells=new ArrayList<>();for(int offset:List.of(-6,6))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-02/TOTP/known-commit/worker="+offset+"s",()->{F f=new F();TotpStoreRecord root=f.record(f.root());f.store.afterCommit=(n,w,r)->{assertEquals(TotpStoreCommitResult.COMMITTED,r.getStatus());f.worker.set(BASE.plusSeconds(offset));return r;};assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,f.begin());assertEquals(1,f.store.commits.get());assertEquals(1,f.store.writes.size());try(var decoded=f.account()){assertNotNull(Objects.requireNonNull(decoded.account).pending);}assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());}));return cells;
 }

 @Test void scClk03ActualReadCommitAndFinalReadKeepIdenticalNumericSamplesAfterReplies(){
  F f=new F();java.util.concurrent.CopyOnWriteArrayList<String> trace=new java.util.concurrent.CopyOnWriteArrayList<>();f.store.phaseTrace=trace;f.worker.phaseTrace=trace;TotpStoreRecord root=f.record(f.root());assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.begin());assertEquals(List.of("read-call","read-reply","worker-wall","commit-call","commit-reply","worker-wall","read-call","read-reply","worker-wall","worker-wall","worker-wall"),trace);f.worker.phaseTrace=null;f.store.phaseTrace=null;assertEquals(BASE,f.source.authorityTime());assertEquals(BASE,f.worker.instant());assertEquals(1,f.store.commits.get());assertEquals(root.getVersion(),f.record(f.root()).getVersion());
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi08KnownCommitValidationAndCompletionMatrix(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(var scenario:com.revetsec.testing.StoreReceiptMatrix.Case.values())cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-08/TOTP/"+scenario,()->{
   F f=new F();TotpStoreRecord root=f.record(f.root());java.util.concurrent.atomic.AtomicReference<@Nullable Instant> target=new java.util.concurrent.atomic.AtomicReference<>();f.store.afterCommit=(n,w,r)->{assertEquals(TotpStoreCommitResult.COMMITTED,r.getStatus());var validated=r.getTiming().orElseThrow().getValidatedTime();Instant next=com.revetsec.testing.StoreReceiptMatrix.finalTime(scenario,validated,w.getTemporalCondition());target.set(next);TotpStoreCommitReceipt delivered=(TotpStoreCommitReceipt)com.revetsec.testing.StoreReceiptMatrix.apply(r,scenario,validated,w.getTemporalCondition());if(next!=null)f.source.setTime(next);return delivered;};f.store.afterRead=(n,r)->{Instant next=target.get();if(n==2&&next!=null)f.worker.set(next);return r;};var result=f.auth(f.worker,Duration.ofSeconds(1)).beginEnrollmentResult(options(ACCOUNT),"browser");if(scenario.isNormal())assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,result);else if(scenario.isUnknown())assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,result);else assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,result);assertEquals(1,f.store.commits.get());assertEquals(1,f.store.writes.size());assertEquals(scenario.needsFinalRead()?2:1,f.store.reads.get());try(var decoded=f.account()){assertNotNull(Objects.requireNonNull(decoded.account).pending);assertEquals(BASE,Objects.requireNonNull(decoded.account).observedAt);}assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());
  }));return cases;
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi08NormalStatusesDistinguishZeroEffectUnknownAndOneAllowedConflictRetry(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(var status:TotpStoreCommitResult.values())for(boolean applied:status==TotpStoreCommitResult.UNKNOWN?List.of(false,true):List.of(status==TotpStoreCommitResult.COMMITTED))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-08/TOTP/status="+status+"/applied="+applied,()->{
   F f=new F();TotpStoreRecord root=f.record(f.root());f.store.beforeCommit=(n,w)->{if(status==TotpStoreCommitResult.COMMITTED||(status==TotpStoreCommitResult.CONFLICT&&n>1)||(status==TotpStoreCommitResult.UNKNOWN&&applied))return null;return status==TotpStoreCommitResult.UNKNOWN?TotpStoreCommitReceipt.unknownInstance():TotpStoreCommitReceipt.fromRefusal(status);};f.store.afterCommit=(n,w,r)->status==TotpStoreCommitResult.UNKNOWN&&applied?TotpStoreCommitReceipt.unknownInstance():r;var result=f.begin();boolean changed=status==TotpStoreCommitResult.COMMITTED||status==TotpStoreCommitResult.CONFLICT||applied;
   if(status==TotpStoreCommitResult.COMMITTED||status==TotpStoreCommitResult.CONFLICT)assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,result);else if(status==TotpStoreCommitResult.UNKNOWN)assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,result);else if(status==TotpStoreCommitResult.TIME_EXPIRED)assertEquals(TotpRejectionReason.REJECTED,assertInstanceOf(TotpEnrollmentRequestResult.Rejected.class,result).getReason());else{TotpUnavailableReason expected=switch(status){case FENCED->TotpUnavailableReason.FENCED;case CAPACITY_REFUSED->TotpUnavailableReason.CAPACITY_REFUSED;case TIME_UNAVAILABLE,TIME_BEFORE_FLOOR->TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE;default->TotpUnavailableReason.DEPENDENCY_UNAVAILABLE;};assertEquals(expected,assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,result).getReason());}
   assertEquals(status==TotpStoreCommitResult.CONFLICT?2:1,f.store.commits.get());assertEquals(status==TotpStoreCommitResult.CONFLICT?3:status==TotpStoreCommitResult.COMMITTED||status==TotpStoreCommitResult.TIME_EXPIRED?2:1,f.store.reads.get());var after=assertInstanceOf(TotpStoreReadResult.Available.class,f.source.read(Set.of(f.root(),f.key()),BUDGET)).getSnapshot();if(changed)assertInstanceOf(TotpStoreEntry.Present.class,after.getEntry(f.key()));else assertInstanceOf(TotpStoreEntry.Absent.class,after.getEntry(f.key()));assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());
  }));return cases;
 }
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi08EnteredNullOrThrowNeverInfersRollbackFromInstrumentedEffects(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(boolean applied:List.of(false,true))for(boolean throwing:List.of(false,true))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-08/TOTP/lost-receipt/applied="+applied+"/throw="+throwing,()->{F f=new F();if(!applied)f.store.beforeCommit=(n,w)->TotpStoreCommitReceipt.unknownInstance();f.store.afterCommit=(n,w,r)->{if(throwing)throw new IllegalStateException("TEST-ONLY-lost-acknowledgement");return com.revetsec.testing.StoreReceiptMatrix.brokenNull();};assertInstanceOf(TotpEnrollmentRequestResult.Indeterminate.class,f.begin());assertEquals(1,f.store.commits.get());assertEquals(1,f.store.reads.get());var after=assertInstanceOf(TotpStoreReadResult.Available.class,f.source.read(Set.of(f.key()),BUDGET)).getSnapshot();if(applied)assertInstanceOf(TotpStoreEntry.Present.class,after.getEntry(f.key()));else assertInstanceOf(TotpStoreEntry.Absent.class,after.getEntry(f.key()));}));return cases;
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi01ActualInitialChargeAndFinalReadFaultsNeverAuthorizeNewMutation(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(String phase:List.of("INITIAL","AFTER_CHARGE","FINAL"))for(var fault:com.revetsec.testing.StoreReadFaults.values()){
   if(phase.equals("FINAL")&&!fault.appliesToRootOnly())continue;
   cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-01/TOTP/"+phase+"/"+fault,()->{
    F f=new F();long used=-1;if(phase.equals("AFTER_CHARGE")){f.enroll();f.advance(Duration.ofSeconds(60));try(var d=f.account()){used=Objects.requireNonNull(Objects.requireNonNull(d.account).active).usedStep;}}f.reset();var before=new HashMap<>(mig15FixtureRows(f.source,"records"));TotpStoreRecord root=f.record(f.root());int target=phase.equals("INITIAL")?1:2;f.store.afterRead=(n,r)->n==target?scApi01ReadFault(f,fault,r):r;
    if(phase.equals("AFTER_CHARGE")){String code=f.code(0);assertEquals(TotpUnavailableReason.ATTEMPT_INCOMPLETE,assertInstanceOf(TotpVerificationResult.Unavailable.class,f.totp.verifyResult(ACCOUNT,code,"SC-API-01/read-fault")).getReason());try(var d=f.account()){var a=Objects.requireNonNull(d.account);assertEquals(1,a.charges.size());assertEquals(1,a.totpCharges.size());assertEquals(a.charges.get(0).id,a.totpCharges.get(0).id);assertEquals(used,Objects.requireNonNull(a.active).usedStep);}}
    else if(phase.equals("FINAL")){assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,f.begin());try(var d=f.account()){assertNotNull(Objects.requireNonNull(d.account).pending);}}
    else{assertInstanceOf(TotpEnrollmentRequestResult.Unavailable.class,f.begin());assertEquals(before,mig15FixtureRows(f.source,"records"));}
    assertEquals(phase.equals("INITIAL")?0:1,f.store.commits.get());assertEquals(target,f.store.reads.get());assertEquals(phase.equals("INITIAL")?0:1,f.store.writes.size());assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());
   }));
  }return cases;
 }
 private static @NonNull TotpStoreReadResult scApi01ReadFault(@NonNull F f,com.revetsec.testing.@NonNull StoreReadFaults fault,@NonNull TotpStoreReadResult result){
  if(fault==com.revetsec.testing.StoreReadFaults.UNAVAILABLE)return TotpStoreReadResult.Unavailable.get();
  if(fault==com.revetsec.testing.StoreReadFaults.NULL)return com.revetsec.testing.StoreReceiptMatrix.brokenNull();
  if(fault==com.revetsec.testing.StoreReadFaults.THROW)throw new IllegalStateException("TEST-ONLY read fault");
  var original=assertInstanceOf(TotpStoreReadResult.Available.class,result).getSnapshot();Map<TotpStoreKey,TotpStoreEntry> rows=new HashMap<>(original.getEntries());
  switch(fault){
   case OMIT_ROOT->rows.remove(f.root());case OMIT_ENTITY->rows.remove(f.key());
   case EXTRA_ABSENCE->rows.put(TotpStoreKey.forAccount(NAMESPACE,EPOCH,"extra"),TotpStoreEntry.Absent.confirmed());
   case FOREIGN_SCOPE->{rows.clear();rows.put(TotpStoreKey.forNamespace("foreign",EPOCH),TotpStoreEntry.Absent.confirmed());}
   case WRONG_KIND->{rows.remove(f.root());rows.put(TotpStoreKey.forAccount(NAMESPACE,EPOCH,"substitute"),TotpStoreEntry.Absent.confirmed());}
   case AUTHENTICATED_BAD_AUTHORITY,AUTHENTICATED_NEGATIVE_FLOOR->{String authority=fault==com.revetsec.testing.StoreReadFaults.AUTHENTICATED_BAD_AUTHORITY?"A".repeat(43):f.source.admission().getAuthorityId();Instant minimum=fault==com.revetsec.testing.StoreReadFaults.AUTHENTICATED_NEGATIVE_FLOOR?Instant.EPOCH.minusNanos(1):BASE;rows.put(f.root(),TotpStoreEntry.Present.fromRecord(f.codec.sealNamespace(f.root(),new TotpRecordsV3.Namespace(authority,minimum))));}
   case CORRUPT_ROOT,CORRUPT_ENTITY->{TotpStoreKey key=fault==com.revetsec.testing.StoreReadFaults.CORRUPT_ROOT?f.root():f.key();rows.put(key,TotpStoreEntry.Present.fromRecord(TotpStoreRecord.fromStoredForm(key,"corrupt",new byte[]{1,2,3})));}
   default->throw new AssertionError("Unexpected read-fault control");
  }
  return TotpStoreReadResult.Available.fromSnapshot(TotpStoreSnapshot.fromEntries(rows.keySet(),rows,original.getTimeObservation()));
 }

 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi03EveryObservationDomainMustMatchAfterChargeAndAtFinalCheckpoint(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(String phase:List.of("AFTER_CHARGE","FINAL"))for(var fault:com.revetsec.testing.StoreProfileFaults.values())cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-03/TOTP/"+phase+"/"+fault,()->{
   F f=new F();long used=-1;if(phase.equals("AFTER_CHARGE")){f.enroll();f.advance(Duration.ofSeconds(60));try(var d=f.account()){used=Objects.requireNonNull(Objects.requireNonNull(d.account).active).usedStep;}}TotpStoreRecord root=f.record(f.root());f.reset();AtomicBoolean delivered=new AtomicBoolean();f.store.afterRead=(n,r)->{if(n!=2)return r;delivered.set(true);var snapshot=assertInstanceOf(TotpStoreReadResult.Available.class,r).getSnapshot();var original=assertInstanceOf(com.revetsec.StoreTimeObservation.Healthy.class,snapshot.getTimeObservation());var changed=assertInstanceOf(com.revetsec.StoreTimeObservation.Healthy.class,fault.apply(original));assertEquals(original.getObservedAt(),changed.getObservedAt());assertEquals(fault==com.revetsec.testing.StoreProfileFaults.CLOCK?!original.getClockGeneration().equals(changed.getClockGeneration()):original.getClockGeneration().equals(changed.getClockGeneration()),true);return TotpStoreReadResult.Available.fromSnapshot(TotpStoreSnapshot.fromEntries(snapshot.getEntries().keySet(),snapshot.getEntries(),changed));};
   if(phase.equals("AFTER_CHARGE")){assertEquals(TotpUnavailableReason.ATTEMPT_INCOMPLETE,assertInstanceOf(TotpVerificationResult.Unavailable.class,f.totp.verifyResult(ACCOUNT,f.code(0),"SC-API-03/context")).getReason());try(var d=f.account()){var account=Objects.requireNonNull(d.account);assertEquals(1,account.charges.size());assertEquals(1,account.totpCharges.size());assertEquals(account.charges.get(0).id,account.totpCharges.get(0).id);assertEquals(used,Objects.requireNonNull(account.active).usedStep);}}
   else{assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,f.begin());try(var d=f.account()){assertNotNull(Objects.requireNonNull(d.account).pending);}}
   assertTrue(delivered.get());assertEquals(1,f.store.commits.get());assertEquals(2,f.store.reads.get());assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());
  }));return cases;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk05GoodCompletionStillRequiresFreshFinalAdmissionAndCurrentRelease(){
  List<org.junit.jupiter.api.DynamicTest> cells=new ArrayList<>();
  for(String fault:List.of("UNAVAILABLE","THROW","DELAY","PERMIT_CLOSE"))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-05/TOTP/good-completion/"+fault,()->{
   F f=new F();TotpStoreRecord root=f.record(f.root());var delivered=new AtomicReference<@Nullable StoreCommitTiming>();
   f.store.afterCommit=(number,write,receipt)->{var validated=receipt.getTiming().orElseThrow().getValidatedTime();var completed=StoreTimeObservation.Healthy.fromObservation(validated.getAdmission(),validated.getClockGeneration(),f.source.authorityTime(),validated.getMaximumUtcError());var timing=StoreCommitTiming.fromTimes(validated,completed);delivered.set(timing);return TotpStoreCommitReceipt.fromCommittedTiming(timing);};
   f.store.afterRead=(number,result)->{if(number==2){if(fault.equals("UNAVAILABLE"))return TotpStoreReadResult.Unavailable.get();if(fault.equals("THROW"))throw new IllegalStateException("Test-only final read failure");if(fault.equals("DELAY"))scMeasuredReleaseDelay(150_000_000L);}return result;};
   if(fault.equals("PERMIT_CLOSE"))f.gate.failClose.set(true);
   var result=f.auth(f.worker,Duration.ofMillis(100)).beginEnrollmentResult(options(ACCOUNT),"browser");
   assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,result);
   assertTrue(Objects.requireNonNull(delivered.get()).getCompletedTime().isPresent());assertEquals(1,f.store.commits.get());assertEquals(2,f.store.reads.get());assertEquals(1,f.store.writes.size());
   assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());
   try(var decoded=f.account()){var account=Objects.requireNonNull(decoded.account);assertNotNull(account.pending);assertEquals(BASE,account.observedAt);assertEquals(BASE.plusSeconds(300),Objects.requireNonNull(account.pending).expiresAt);}
  }));return cells;
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk08ActualValidationAtLastNanosecondKeepsCommitWhenFinalReleaseCrossesOriginalUpper(){
  List<org.junit.jupiter.api.DynamicTest> cells=new ArrayList<>();
  for(boolean finalAtExpiry:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-05+CLK-08/TOTP/E-minus-1/finalAtE="+finalAtExpiry,()->{
   F f=new F();TotpStoreRecord root=f.record(f.root());var originalUpper=new AtomicReference<@Nullable Instant>();var committed=new AtomicReference<@Nullable StoreCommitTiming>();var finalSample=new AtomicReference<StoreTimeObservation.@Nullable Healthy>();var finalElapsed=new AtomicReference<@Nullable Duration>();
   f.store.beforeCommit=(number,write)->{Instant upper=write.getTemporalCondition().getValidBeforeExclusive().orElseThrow();originalUpper.set(upper);Instant validated=upper.minusNanos(1);f.source.setTime(validated);f.worker.set(validated);return null;};
   f.store.afterCommit=(number,write,receipt)->{assertEquals(TotpStoreCommitResult.COMMITTED,receipt.getStatus());committed.set(receipt.getTiming().orElseThrow());Instant upper=Objects.requireNonNull(originalUpper.get());assertEquals(upper.minusNanos(1),receipt.getTiming().orElseThrow().getValidatedTime().getObservedAt());if(finalAtExpiry){f.source.setTime(upper);f.worker.set(upper);}return receipt;};
   f.store.afterRead=(number,result)->{if(number==2&&!finalAtExpiry){var sample=assertInstanceOf(StoreTimeObservation.Healthy.class,assertInstanceOf(TotpStoreReadResult.Available.class,result).getSnapshot().getTimeObservation());finalSample.set(sample);finalElapsed.set(scMeasuredReleaseDelay(2_000_000L));}return result;};
   assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,f.begin());assertEquals(1,f.store.commits.get());assertEquals(2,f.store.reads.get());assertEquals(1,f.store.writes.size());
   Instant upper=Objects.requireNonNull(originalUpper.get());assertEquals(upper.minusNanos(1),Objects.requireNonNull(committed.get()).getValidatedTime().getObservedAt());assertTrue(Objects.requireNonNull(committed.get()).getCompletedTime().isEmpty());assertEquals(upper,f.store.writes.get(0).getTemporalCondition().getValidBeforeExclusive().orElseThrow());if(!finalAtExpiry){var sample=Objects.requireNonNull(finalSample.get());assertEquals(upper.minusNanos(1),sample.getObservedAt());assertTrue(com.revetsec.internal.StoreTimeRules.isReleaseBefore(sample,Duration.ZERO,upper));assertFalse(com.revetsec.internal.StoreTimeRules.isReleaseBefore(sample,Objects.requireNonNull(finalElapsed.get()),upper),"A pre-expiry stamp is insufficient when the conservative bound crosses E");}
   assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());try(var decoded=f.account()){var account=Objects.requireNonNull(decoded.account);assertEquals(BASE,account.observedAt);assertEquals(BASE.plusSeconds(300),Objects.requireNonNull(account.pending).expiresAt);}
  }));return cells;
 }
 private static @NonNull Duration scMeasuredReleaseDelay(long nanos){long start=System.nanoTime(),end=start+nanos;long remaining;while((remaining=end-System.nanoTime())>0)java.util.concurrent.locks.LockSupport.parkNanos(remaining);Duration elapsed=com.revetsec.internal.StoreTimeRules.elapsed(start,System.nanoTime()).orElseThrow();assertTrue(elapsed.compareTo(Duration.ofNanos(nanos))>=0);return elapsed;}

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk09AuthorityAndRecoveryRotateBeforeOrAfterEligibleFinalSnapshot(){
  List<org.junit.jupiter.api.DynamicTest> cells=new ArrayList<>();
  for(boolean authority:List.of(false,true))for(boolean after:List.of(false,true))cells.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-09/TOTP/authority="+authority+"/after-captured-checkpoint="+after,()->{
   F f=new F();var original=f.source.admission();var receipt=new AtomicReference<@Nullable TotpStoreCommitReceipt>();var changed=new AtomicBoolean();var checkpoint=new AtomicReference<@Nullable TotpStoreSnapshot>();
   Runnable rotate=()->{scClk09RotateAdmission(f,authority);changed.set(true);};
   f.store.afterCommit=(number,write,result)->{receipt.set(result);if(!after)rotate.run();return result;};
   f.store.afterRead=(number,result)->{if(number==2){var snapshot=assertInstanceOf(TotpStoreReadResult.Available.class,result).getSnapshot();checkpoint.set(snapshot);if(after)rotate.run();}return result;};
   var result=f.begin();if(after){var prepared=assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,result);assertTrue(prepared.getEnrollment().getProvisioningUri().startsWith("otpauth://totp/"));}else assertInstanceOf(TotpEnrollmentRequestResult.ReconciliationRequired.class,result);
   assertTrue(changed.get());assertEquals(authority?"A".repeat(43):original.getAuthorityId(),f.source.admission().getAuthorityId());assertEquals(authority?original.getRecoveryGeneration():"A".repeat(43),f.source.admission().getRecoveryGeneration());assertEquals(BASE,f.source.authorityTime());assertEquals(BASE,f.worker.instant());assertEquals(1,f.store.commits.get());assertEquals(1,f.store.writes.size());assertEquals(2,f.store.reads.get());
   var acknowledged=Objects.requireNonNull(receipt.get());assertEquals(TotpStoreCommitResult.COMMITTED,acknowledged.getStatus());assertEquals(original,acknowledged.getTiming().orElseThrow().getValidatedTime().getAdmission());assertEquals(BASE,acknowledged.getTiming().orElseThrow().getValidatedTime().getObservedAt());var finalSnapshot=Objects.requireNonNull(checkpoint.get());assertEquals(Set.of(f.root()),finalSnapshot.getEntries().keySet());assertEquals(after?original:f.source.admission(),finalSnapshot.getTimeObservation().getAdmission());
   try(var decoded=f.account()){var account=Objects.requireNonNull(decoded.account);assertEquals(BASE,account.observedAt);assertEquals(BASE.plusSeconds(300),Objects.requireNonNull(account.pending).expiresAt);}
  }));return cells;
 }
 @SuppressWarnings("unchecked") // Explicit isolated authority control; never a production writer or recovery mechanism.
 private static void scClk09RotateAdmission(@NonNull F f,boolean authority){
  synchronized(f.source){try{var old=f.source.admission();var next=com.revetsec.StoreAdmission.fromIdentifiers(authority?"A".repeat(43):old.getAuthorityId(),authority?old.getRecoveryGeneration():"A".repeat(43));var field=f.source.getClass().getDeclaredField("admission");field.setAccessible(true);field.set(f.source,next);if(authority){var rows=f.source.getClass().getDeclaredField("records");rows.setAccessible(true);((Map<TotpStoreKey,TotpStoreRecord>)Objects.requireNonNull(rows.get(f.source))).put(f.root(),f.codec.sealNamespace(f.root(),new TotpRecordsV3.Namespace(next.getAuthorityId(),BASE)));}}catch(ReflectiveOperationException fault){throw new AssertionError("Isolated admission control failed",fault);}}
 }

 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scClk10LaterCancellationAndUnrelatedWorkDoNotRepeatTheCommittedBusinessRead(){
  return List.of(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-CLK-10/TOTP/later-cancel-and-unrelated-account",()->{
   F f=new F();var root=f.record(f.root());var finalPhase=new AtomicBoolean();List<Set<TotpStoreKey>> finalReads=new CopyOnWriteArrayList<>();var enrollmentId=new AtomicReference<@Nullable String>();var originalReceipt=new AtomicReference<@Nullable TotpStoreCommitReceipt>();
   f.store.afterRead=(number,result)->{if(finalPhase.get())finalReads.add(assertInstanceOf(TotpStoreReadResult.Available.class,result).getSnapshot().getEntries().keySet());return result;};
   f.store.afterCommit=(number,write,receipt)->{assertEquals(1,number);assertFalse(Thread.holdsLock(f.source));f.store.afterCommit=null;originalReceipt.set(receipt);try(var decoded=f.account()){enrollmentId.set(Objects.requireNonNull(Objects.requireNonNull(decoded.account).pending).enrollmentId);}catch(Exception failure){throw new AssertionError("Test committed account unavailable",failure);}assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.totp.beginEnrollmentResult(options("unrelated"),"browser"));assertInstanceOf(TotpEnrollmentCancellationResult.Succeeded.class,f.totp.cancelEnrollmentResult(ACCOUNT,Objects.requireNonNull(enrollmentId.get()),"browser"));finalPhase.set(true);return receipt;};
   var result=assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,f.begin());finalPhase.set(false);assertEquals(Objects.requireNonNull(enrollmentId.get()),result.getEnrollment().getEnrollmentId());assertEquals(TotpStoreCommitResult.COMMITTED,Objects.requireNonNull(originalReceipt.get()).getStatus());assertEquals(List.of(Set.of(f.root())),finalReads);assertEquals(3,f.store.commits.get());assertEquals(3,f.store.writes.size());assertEquals(6,f.store.reads.get());assertEquals(root.getVersion(),f.record(f.root()).getVersion());assertArrayEquals(root.getSealedBytes(),f.record(f.root()).getSealedBytes());try(var decoded=f.account()){assertNull(Objects.requireNonNull(decoded.account).pending);}assertNotNull(f.record(TotpStoreKey.forAccount(NAMESPACE,EPOCH,"unrelated")));assertEquals(1,f.store.writes.get(0).getMutations().size());assertEquals(f.key(),f.store.writes.get(0).getMutations().get(0).getKey());
  }));
 }
}
