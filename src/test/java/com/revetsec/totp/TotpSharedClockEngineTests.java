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
	private static @NonNull TotpEnrollmentOptions options(@NonNull String account){return TotpEnrollmentOptions.withAccountId(account).accountName("person@example.test").build();}

	@FunctionalInterface private interface BeforeCommit { @Nullable TotpStoreCommitReceipt apply(int number,@NonNull TotpStoreWrite write); }
	@FunctionalInterface private interface AfterCommit { @NonNull TotpStoreCommitReceipt apply(int number,@NonNull TotpStoreWrite write,@NonNull TotpStoreCommitReceipt result); }
	@FunctionalInterface private interface AfterRead { @NonNull TotpStoreReadResult apply(int number,@NonNull TotpStoreReadResult result); }
	@ThreadSafe private static final class RecordingStore implements TotpStore {
		final @NonNull ScriptedTotpStore source;
		final @NonNull AtomicInteger commits=new AtomicInteger(),reads=new AtomicInteger(),conflicts=new AtomicInteger();
		final @NonNull List<@NonNull TotpStoreWrite> writes=new CopyOnWriteArrayList<>();
		final @NonNull AtomicBoolean failRead=new AtomicBoolean();
		volatile @Nullable BeforeCommit beforeCommit;
		volatile @Nullable AfterCommit afterCommit;
		volatile @Nullable AfterRead afterRead;
		RecordingStore(@NonNull ScriptedTotpStore source){this.source=source;}
		@Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget){
			int number=this.reads.incrementAndGet();if(this.failRead.get())throw new IllegalStateException("Scripted read outage");
			TotpStoreReadResult result=this.source.read(keys,budget);AfterRead hook=this.afterRead;return hook==null?result:hook.apply(number,result);
		}
		@Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration budget){
			int number=this.commits.incrementAndGet();this.writes.add(write);BeforeCommit before=this.beforeCommit;
			TotpStoreCommitReceipt result=before==null?null:before.apply(number,write);
			if(result==null)result=this.source.compareAndCommit(write,budget);
			if(result.getStatus()==TotpStoreCommitResult.CONFLICT)this.conflicts.incrementAndGet();
			AfterCommit after=this.afterCommit;return after==null?result:after.apply(number,write,result);
		}
	}
	@ThreadSafe private static final class WorkerClock extends Clock {
		private final @NonNull AtomicReference<@NonNull Instant> time;
		WorkerClock(@NonNull Instant time){this.time=new AtomicReference<>(time);}
		void set(@NonNull Instant time){this.time.set(time);}
		@Override public @NonNull Instant instant(){return Objects.requireNonNull(this.time.get());}
		@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
		@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return Clock.fixed(instant(),zone);}
	}
	@ThreadSafe private static final class Gate implements TotpRecoveryGate {
		final @NonNull AtomicBoolean failClose=new AtomicBoolean();
		@Override public @NonNull Permit acquire(@NonNull TotpRecoveryContext context,@NonNull Duration budget){return new Permit(){
			@Override public @NonNull Boolean isCurrent(){return Boolean.TRUE;}
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
		@NonNull TotpAuthenticator auth(@NonNull Clock clock){return TotpAuthenticator.withIssuer("Shared Clock").credentialNamespace(NAMESPACE).recoveryEpoch(EPOCH).store(this.store).clock(clock).stateSealer(this.sealer).recoveryGate(this.gate).operationTimeout(Duration.ofSeconds(30)).build();}
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
}
