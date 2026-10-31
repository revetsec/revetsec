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
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.internal.StoreTimeRules;
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
import java.util.concurrent.locks.LockSupport;

/** Caller-thread admitted-time TOTP transitions with cumulative factual effects. */
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
	private final @NonNull TotpRecordsV3 records;
	private final @NonNull TotpStoreKey namespaceKey;

	TotpEngine(@NonNull String issuer, @NonNull String namespace, @NonNull String epoch,
			@NonNull TotpStore store, @NonNull StateSealer sealer, @NonNull TotpRecoveryGate gate,
			@NonNull Clock clock, @NonNull Duration timeout) {
		this.issuer=issuer; this.namespace=namespace; this.epoch=epoch; this.store=store;
		this.sealer=sealer; this.gate=gate; this.clock=clock; this.timeoutNanos=timeout.toNanos();
		this.records=new TotpRecordsV3(sealer); this.namespaceKey=TotpStoreKey.forNamespace(namespace,epoch);
	}

	@NonNull Result execute(@NonNull Command command) {
		Run run=new Run();
		TotpRecoveryGate.Permit permit=null;
		Result result=Result.unavailable(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);
		VirtualMachineError fatalFailure=null;
		try {
			Duration budget=run.remaining();
			if(budget==null) throw new Failure(run.failed(TotpUnavailableReason.DEADLINE_EXCEEDED));
			TotpRecoveryContext context=TotpRecoveryContext.fromConfiguration(this.namespace,this.epoch,
					SealedStateAccess.get().getActiveKeyId(this.sealer),SealedStateAccess.get().getOpeningKeyIds(this.sealer),
					command.action==Action.INITIALIZE?TotpRecoveryContext.Purpose.INITIALIZE_NAMESPACE:TotpRecoveryContext.Purpose.OPERATION);
			permit=this.gate.acquire(context,budget);
			if(permit==null || !run.current(permit)) throw new Failure(run.failed(TotpUnavailableReason.ADMISSION_CLOSED));
			run.permit=permit;
			try {
				result=command.action==Action.CONFIRM || command.action==Action.VERIFY || command.action==Action.RECOVERY
						? authenticate(run,command):transition(run,command);
			} catch(Failure failure) {result=failure.result();}
			if(normal(result)) run.finish(result);
			if(!run.current(permit)) result=run.failed(TotpUnavailableReason.ADMISSION_CLOSED);
		} catch(Failure failure) {result=failure.result();}
		catch(IOException failure) {result=run.failed(TotpUnavailableReason.INVALID_STORED_STATE);}
		catch(VirtualMachineError fatal) {fatalFailure=fatal;}
		catch(Throwable failure) {preserveInterrupt(failure);result=run.failed(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE);}
		finally {
			run.erase();
			if(permit!=null) {
				try {
					if(normal(result) && !run.current(permit)) result=run.failed(TotpUnavailableReason.ADMISSION_CLOSED);
					permit.close();
				} catch(VirtualMachineError fatal) {if(fatalFailure==null)fatalFailure=fatal;}
				catch(Throwable failure) {preserveInterrupt(failure);result=run.failed(TotpUnavailableReason.ADMISSION_CLOSED);}
			}
			if(run.remaining()==null) result=run.failed(TotpUnavailableReason.DEADLINE_EXCEEDED);
			if(normal(result)) {
				try {if(!run.releaseAllowed(result.releaseBefore))result=run.failed(TotpUnavailableReason.CLOCK_HEALTH_UNCONFIRMED);}
				catch(VirtualMachineError fatal) {if(fatalFailure==null)fatalFailure=fatal;}
				catch(Throwable failure) {preserveInterrupt(failure);result=run.failed(TotpUnavailableReason.CLOCK_HEALTH_UNCONFIRMED);}
			}
		}
		if(fatalFailure!=null)throw fatalFailure;
		return result;
	}

	private static boolean normal(@NonNull Result result) {
		return result.status!=Status.UNAVAILABLE && result.status!=Status.INDETERMINATE && result.status!=Status.RECONCILIATION_REQUIRED;
	}

	private @NonNull Result transition(@NonNull Run run,@NonNull Command command) throws Failure,IOException {
		for(int retry=0;retry<=8;retry++) {
			try(State state=load(run,command.accountId,command.action==Action.INITIALIZE,command.action==Action.RESEAL?command.key:null)) {
				Result result=new Result(Status.SUCCEEDED);
				List<TotpStoreWrite.Mutation> changes=new ArrayList<>();
				Instant upper=null;
				if(command.action==Action.INITIALIZE) {
					if(state.namespacePresent)result.status=Status.ALREADY_CURRENT;
					else changes.add(TotpStoreWrite.Mutation.insert(this.records.sealNamespace(this.namespaceKey,state.namespace)));
				} else if(command.action==Action.RESEAL) {
					TotpStoreKey key=Objects.requireNonNull(command.key);
					TotpStoreEntry entry=state.snapshot.getEntry(key);
					if(entry instanceof TotpStoreEntry.Absent)result.status=Status.ABSENT;
					else {
						String keyId=key.equals(this.namespaceKey)?state.namespaceKeyId:state.accountKeyId;
						if(Objects.equals(keyId,SealedStateAccess.get().getActiveKeyId(this.sealer)))result.status=Status.ALREADY_CURRENT;
						else changes.add(TotpStoreWrite.Mutation.replace(key.equals(this.namespaceKey)
								?this.records.sealNamespace(key,state.namespace):this.records.sealAccount(key,Objects.requireNonNull(state.account))));
					}
				} else if(command.action==Action.STATUS) {
					if(state.account==null)result.status=Status.ABSENT;
					else result.accountStatus=status(state.account);
					return result; // Snapshot-point query: no write, quota action or barrier.
				} else {
					TotpRecords.Account account=state.account;
					if(account==null && command.action==Action.BEGIN) {
						account=new TotpRecords.Account(Objects.requireNonNull(command.accountId),this.records.freshId(),state.now);
						state.account=account;
					}
					if(account==null)result.reject(TotpRejectionReason.FACTOR_MISMATCH);
					else switch(command.action) {
						case BEGIN -> {
							begin(command,account,state.now,result,run);
							upper=minimum(run.artifactUpper(),account.pending==null?null:account.pending.expiresAt);
						}
						case CANCEL -> {
							TotpRecords.Pending pending=account.pending;
							if(pending==null || !ConstantTime.isEqual(pending.enrollmentId,command.first))result.reject(TotpRejectionReason.ENROLLMENT_NOT_FOUND);
							else if(!ConstantTime.isEqual(pending.browserHash,browserHash(command.third)))result.reject(TotpRejectionReason.BINDING_MISMATCH);
							else {
								upper=pending.expiresAt;
								Arrays.fill(pending.secret,(byte)0);Arrays.fill(pending.browserHash,(byte)0);account.pending=null;
							}
						}
						case REMOVE -> {
							TotpRecords.Active active=account.active;
							if(active==null || !ConstantTime.isEqual(active.factorId,command.first))result.reject(TotpRejectionReason.FACTOR_MISMATCH);
							else {account.erase();account.active=null;account.pending=null;account.batchId=null;account.recoveryHashes.clear();account.fence=this.records.freshId();}
						}
						case ROTATE -> {
							TotpRecords.Active active=account.active;
							if(active==null || !ConstantTime.isEqual(active.factorId,command.first))result.reject(TotpRejectionReason.FACTOR_MISMATCH);
							else if(!ConstantTime.isEqual(account.batchId,command.second))result.reject(TotpRejectionReason.RECOVERY_BATCH_MISMATCH);
							else {upper=run.artifactUpper();result.codes=rotate(account,state.now);}
						}
						default -> throw new IllegalStateException("Invalid TOTP transition");
					}
					if(result.status==Status.SUCCEEDED)changes.add(accountMutation(state,Objects.requireNonNull(account)));
				}
				CommitRole role=changes.isEmpty()?CommitRole.BARRIER:CommitRole.REQUESTED_TRANSITION;
				TotpStoreCommitResult committed=run.commit(state,changes,
						command.action==Action.INITIALIZE && !state.namespacePresent?TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE:TotpStoreWrite.Purpose.UPDATE,role,upper);
				if(committed==TotpStoreCommitResult.CONFLICT){run.backoff(retry);continue;}
				TotpRejectionReason expired=command.action==Action.CANCEL?TotpRejectionReason.ENROLLMENT_NOT_FOUND:TotpRejectionReason.REJECTED;
				if(command.action==Action.BEGIN && state.account!=null && state.account.pending!=null && Objects.equals(upper,state.account.pending.expiresAt))expired=TotpRejectionReason.ENROLLMENT_NOT_FOUND;
				run.requireCommit(committed,expired);
				result.releaseBefore=upper;
				return result;
			}
		}
		return run.failed(TotpUnavailableReason.CONFLICT_LIMIT_REACHED);
	}

	private void begin(@NonNull Command command, TotpRecords.@NonNull Account account,
			@NonNull Instant now, @NonNull Result result, @NonNull Run run) {
		if (account.charges.size() >= 5) { result.status = Status.THROTTLED; result.retryAfter = retryAfter(account, now, false); return; }
		if (account.pending != null) { result.reject(TotpRejectionReason.ENROLLMENT_CONFLICT); return; }
		TotpEnrollmentOptions options = Objects.requireNonNull(command.options);
		String expected = options.getReplacingFactorId().orElse(null);
		TotpRecords.Active active = account.active;
		if (expected == null && active != null) { result.reject(TotpRejectionReason.ALREADY_ENROLLED); return; }
		if (expected != null && (active == null || !ConstantTime.isEqual(expected, active.factorId))) {
			result.reject(TotpRejectionReason.FACTOR_MISMATCH); return;
		}
		TotpRecords.Pending prepared=run.enrollment;
		if(prepared==null){
			prepared=new TotpRecords.Pending(this.records.freshId(),this.records.freshId(),EntropySource.fromDefaults().nextBytes(20),
					browserHash(command.third),now.plusSeconds(300),expected);
			run.enrollment=prepared;
		}
		String enrollmentId=prepared.enrollmentId,factorId=prepared.factorId;
		Instant expires=prepared.expiresAt;
		byte[] secret=prepared.secret.clone();
		account.pending=new TotpRecords.Pending(enrollmentId,factorId,secret,prepared.browserHash.clone(),expires,expected);
		String manual = TotpPrimitives.base32(secret);
		String uri = "otpauth://totp/" + uri(this.issuer) + ':' + uri(options.getAccountName())
				+ "?secret=" + manual + "&issuer=" + uri(this.issuer) + "&algorithm=SHA1&digits=6&period=30";
		result.enrollment = new TotpEnrollment(enrollmentId, factorId, expires, uri, manual, this.epoch);
	}


	private @NonNull Result authenticate(@NonNull Run run,@NonNull Command command) throws Failure,IOException {
		AuthAttempt authentication=new AuthAttempt(this.records.freshId(),command.action!=Action.RECOVERY);
		boolean reserved=false;
		for(int retry=0;retry<=8;retry++) {
			try(State state=load(run,command.accountId,false,null)) {
				TotpRecords.Account account=state.account;
				if(account==null){account=new TotpRecords.Account(Objects.requireNonNull(command.accountId),this.records.freshId(),state.now);state.account=account;}
				if(!authentication.prepared)authentication.prepare(run,command,account,state.now);
				boolean throttled=account.charges.size()>=5 || (authentication.sixDigit && account.totpCharges.size()>=10);
				List<TotpStoreWrite.Mutation> changes=new ArrayList<>();
				if(!throttled){account.charges.add(new TotpRecords.Charge(authentication.chargeId,state.now));if(authentication.sixDigit)account.totpCharges.add(new TotpRecords.Charge(authentication.chargeId,state.now));changes.add(accountMutation(state,account));}
				TotpStoreCommitResult committed=run.commit(state,changes,TotpStoreWrite.Purpose.UPDATE,
						throttled?CommitRole.BARRIER:CommitRole.CHARGE_RESERVATION,authentication.upper);
				if(committed==TotpStoreCommitResult.CONFLICT){run.backoff(retry);continue;}
				run.requireCommit(committed,authentication.expiredReason);
				if(throttled){Result result=Result.throttled(retryAfter(account,state.now,authentication.sixDigit));result.releaseBefore=authentication.upper;return result;}
				reserved=true;break;
			}
		}
		if(!reserved)return run.failed(TotpUnavailableReason.CONFLICT_LIMIT_REACHED);
		for(int retry=0;retry<=8;retry++) {
			try(State state=load(run,command.accountId,false,null)) {
				TotpRecords.Account account=state.account;
				if(account==null)throw new Failure(run.failed(TotpUnavailableReason.INVALID_STORED_STATE));
				boolean chargePresent=account.charges.stream().anyMatch(charge->charge.id.equals(authentication.chargeId));
				if(authentication.sixDigit)chargePresent &= account.totpCharges.stream().anyMatch(charge->charge.id.equals(authentication.chargeId));
				Result result=new Result(Status.SUCCEEDED);
				if(!chargePresent || !account.fence.equals(authentication.fence))result.reject(TotpRejectionReason.REJECTED);
				else if(command.action==Action.CONFIRM)confirm(command,account,state.now,authentication,result);
				else if(command.action==Action.VERIFY)verify(command,account,state.now,authentication,result);
				else recovery(command,account,state.now,authentication,result);
				List<TotpStoreWrite.Mutation> changes=new ArrayList<>();
				if(result.status==Status.SUCCEEDED){
					account.charges.removeIf(charge->charge.id.equals(authentication.chargeId));
					if(authentication.sixDigit)account.totpCharges.removeIf(charge->charge.id.equals(authentication.chargeId));
					changes.add(accountMutation(state,account));
				}
				TotpStoreCommitResult committed=run.commit(state,changes,TotpStoreWrite.Purpose.UPDATE,
						changes.isEmpty()?CommitRole.AUXILIARY:CommitRole.REQUESTED_TRANSITION,authentication.upper);
				if(committed==TotpStoreCommitResult.CONFLICT){run.backoff(retry);continue;}
				run.requireCommit(committed,authentication.expiredReason);
				run.chargeDecisionSettled=true;
				result.releaseBefore=authentication.upper;
				return result;
			}
		}
		return run.failed(TotpUnavailableReason.CONFLICT_LIMIT_REACHED);
	}

	private void confirm(@NonNull Command command, TotpRecords.@NonNull Account account, @NonNull Instant now,
			@NonNull AuthAttempt attempt, @NonNull Result result) throws Failure {
		TotpRecords.Pending pending = account.pending;
		if (pending == null || !ConstantTime.isEqual(pending.enrollmentId, command.first)
				|| !ConstantTime.isEqual(pending.factorId, attempt.factorId)) {
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
		long matched = attempt.matchedStep;
		if (matched < 0) { result.reject(TotpRejectionReason.INVALID_CODE); return; }
		if (active != null) Arrays.fill(active.secret, (byte) 0);
		account.active = new TotpRecords.Active(pending.factorId, pending.secret.clone(), now, matched);
		Arrays.fill(pending.secret, (byte) 0); Arrays.fill(pending.browserHash, (byte) 0); account.pending = null; account.fence = this.records.freshId();
		result.factor = factor(account, Objects.requireNonNull(account.active));
		result.codes = rotate(account, now);
	}

	private void verify(@NonNull Command command, TotpRecords.@NonNull Account account, @NonNull Instant now,
			@NonNull AuthAttempt attempt, @NonNull Result result) throws Failure {
		TotpRecords.Active active = account.active;
		if (active == null || !ConstantTime.isEqual(active.factorId, attempt.factorId)) {
			result.reject(TotpRejectionReason.NOT_ENROLLED); return;
		}
		long matched = attempt.matchedStep;
		if (matched <= active.usedStep) matched = -1;
		if (matched < 0) { result.reject(TotpRejectionReason.INVALID_CODE); return; }
		active.usedStep = matched;
		result.verification = new TotpVerification(this.namespace, this.epoch, account.accountId,
				active.factorId, now, command.third);
	}

	private void recovery(@NonNull Command command, TotpRecords.@NonNull Account account, @NonNull Instant now,
			@NonNull AuthAttempt attempt, @NonNull Result result) {
		TotpRecords.Active active = account.active;
		if (active == null || !ConstantTime.isEqual(active.factorId, attempt.factorId)) {
			result.reject(TotpRejectionReason.NOT_ENROLLED); return;
		}
		if (!Objects.equals(account.batchId, attempt.batchId)) { result.reject(TotpRejectionReason.RECOVERY_BATCH_MISMATCH); return; }
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


	private @NonNull State load(@NonNull Run run,@Nullable String accountId,boolean initializing,@Nullable TotpStoreKey maintenanceKey) throws Failure,IOException {
		TotpStoreKey accountKey=accountId!=null?TotpStoreKey.forAccount(this.namespace,this.epoch,accountId)
				:maintenanceKey!=null && !maintenanceKey.equals(this.namespaceKey)?maintenanceKey:null;
		Set<TotpStoreKey> keys=accountKey==null?Set.of(this.namespaceKey):Set.of(this.namespaceKey,accountKey);
		TotpStoreSnapshot snapshot=run.read(keys);
		StoreTimeObservation.Healthy observation=(StoreTimeObservation.Healthy)snapshot.getTimeObservation();
		Instant now=observation.getObservedAt();
		TotpStoreEntry root=snapshot.getEntry(this.namespaceKey);
		TotpRecordsV3.Namespace namespace;
		String rootKeyId=null,accountKeyId=null;
		boolean present=root instanceof TotpStoreEntry.Present;
		if(root instanceof TotpStoreEntry.Present entry){try(TotpRecordsV3.Decoded decoded=this.records.open(entry.getRecord())){namespace=Objects.requireNonNull(decoded.namespace);rootKeyId=decoded.keyId;}}
		else if(initializing)namespace=new TotpRecordsV3.Namespace(observation.getAdmission().getAuthorityId(),now);
		else throw new Failure(run.failed(TotpUnavailableReason.NAMESPACE_NOT_INITIALIZED));
		run.root(namespace,observation,present);
		TotpRecords.Account account=null;
		if(accountKey!=null && snapshot.getEntry(accountKey) instanceof TotpStoreEntry.Present entry){
			TotpRecordsV3.Decoded decoded=this.records.open(entry.getRecord());account=Objects.requireNonNull(decoded.account);accountKeyId=decoded.keyId;
		}
		try {
			if(account!=null){
				if(!supported(account.observedAt) || account.observedAt.isAfter(now))throw new Failure(run.failed(TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE));
				if(maintenanceKey==null){
					TotpRecords.Pending pending=account.pending;
					if(pending!=null && !now.isBefore(pending.expiresAt)){Arrays.fill(pending.secret,(byte)0);Arrays.fill(pending.browserHash,(byte)0);account.pending=null;}
					Instant shortFloor=now.minusSeconds(300),dailyFloor=now.minusSeconds(86400);
					account.charges.removeIf(charge->!charge.at.isAfter(shortFloor));account.totpCharges.removeIf(charge->!charge.at.isAfter(dailyFloor));
				}
			}
			return new State(snapshot,namespace,account,now,present,accountKey,rootKeyId,accountKeyId);
		}catch(Failure | RuntimeException failure){if(account!=null)account.erase();throw failure;}
	}
	private TotpStoreWrite.@NonNull Mutation accountMutation(@NonNull State state,TotpRecords.@NonNull Account account){
		TotpStoreKey key=Objects.requireNonNull(state.accountKey);account.observedAt=state.now;
		TotpStoreRecord record=this.records.sealAccount(key,account);
		return state.snapshot.getEntry(key) instanceof TotpStoreEntry.Present?TotpStoreWrite.Mutation.replace(record):TotpStoreWrite.Mutation.insert(record);
	}
	private static boolean supported(@NonNull Instant value){return value.getEpochSecond()>=0 && value.getEpochSecond()<=253402300799L;}
	private static @Nullable Instant minimum(@Nullable Instant first,@Nullable Instant second){return first==null?second:second==null || first.isBefore(second)?first:second;}
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
	@Immutable enum Status { SUCCEEDED, ALREADY_CURRENT, ABSENT, REJECTED, THROTTLED, UNAVAILABLE, INDETERMINATE, RECONCILIATION_REQUIRED }
	@Immutable private enum CommitRole { CHARGE_RESERVATION, REQUESTED_TRANSITION, AUXILIARY, BARRIER }
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
		@Nullable Instant releaseBefore;
		Result(@NonNull Status status) { this.status = status; }
		void reject(@NonNull TotpRejectionReason reason) { this.status = Status.REJECTED; this.rejection = reason; }
		static @NonNull Result rejected(@NonNull TotpRejectionReason reason) { Result r = new Result(Status.REJECTED); r.rejection = reason; return r; }
		static @NonNull Result unavailable(@NonNull TotpUnavailableReason reason) { Result r = new Result(Status.UNAVAILABLE); r.unavailable = reason; return r; }
		static @NonNull Result throttled(@NonNull Duration retry) { Result r = new Result(Status.THROTTLED); r.retryAfter = retry; return r; }
	}

	@NotThreadSafe private static final class State implements AutoCloseable {
		final @NonNull TotpStoreSnapshot snapshot;
		final TotpRecordsV3.@NonNull Namespace namespace;
		TotpRecords.@Nullable Account account;
		final @NonNull Instant now;
		final boolean namespacePresent;
		final @Nullable TotpStoreKey accountKey;
		final @Nullable String namespaceKeyId;
		final @Nullable String accountKeyId;
		State(@NonNull TotpStoreSnapshot snapshot,TotpRecordsV3.@NonNull Namespace namespace,
				TotpRecords.@Nullable Account account,@NonNull Instant now,boolean present,@Nullable TotpStoreKey key,
				@Nullable String rootKeyId,@Nullable String accountKeyId){
			this.snapshot=snapshot;this.namespace=namespace;this.account=account;this.now=now;this.namespacePresent=present;this.accountKey=key;
			this.namespaceKeyId=rootKeyId;this.accountKeyId=accountKeyId;
		}
		@Override public void close(){if(this.account!=null)this.account.erase();}
	}
	@NotThreadSafe private static final class AuthAttempt {
		final @NonNull String chargeId;
		final boolean sixDigit;
		boolean prepared;
		@Nullable String factorId;
		@Nullable String batchId;
		@Nullable String fence;
		long matchedStep=-1;
		@Nullable Instant upper;
		@NonNull TotpRejectionReason expiredReason=TotpRejectionReason.REJECTED;
		AuthAttempt(@NonNull String chargeId,boolean sixDigit){this.chargeId=chargeId;this.sixDigit=sixDigit;}
		void prepare(@NonNull Run run,@NonNull Command command,TotpRecords.@NonNull Account account,@NonNull Instant now) throws Failure {
			this.fence=account.fence;this.batchId=account.batchId;this.upper=run.artifactUpper();
			if(command.action==Action.CONFIRM){
				TotpRecords.Pending pending=account.pending;
				if(pending!=null){
					this.factorId=pending.factorId;
					if(!pending.expiresAt.isAfter(Objects.requireNonNull(this.upper))){this.upper=pending.expiresAt;this.expiredReason=TotpRejectionReason.ENROLLMENT_NOT_FOUND;}
					this.matchedStep=matching(pending.secret,command.second,now,-1);
				}
			}else if(account.active!=null){
				this.factorId=account.active.factorId;
				if(this.sixDigit)this.matchedStep=matching(account.active.secret,command.second,now,account.active.usedStep);
			}
			if(this.matchedStep>=0){
				Instant end=Instant.ofEpochSecond(Math.multiplyExact(Math.addExact(this.matchedStep,2),30));
				if(!supported(end))throw new Failure(run.failed(TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE));
				if(end.isBefore(Objects.requireNonNull(this.upper))){this.upper=end;this.expiredReason=TotpRejectionReason.INVALID_CODE;}
			}
			this.prepared=true;
		}
	}
	@NotThreadSafe private final class Run {
		private final long started=System.nanoTime();
		private long lastRemaining=timeoutNanos;
		private boolean requestedCommitted;
		private boolean chargeCommitted;
		private boolean chargeDecisionSettled;
		private boolean mutationUnknown;
		private boolean barrierUnknown;
		private boolean malformedCommitted;
		private TotpRecoveryGate.@Nullable Permit permit;
		private StoreTimeObservation.@Nullable Healthy profile;
		private @Nullable Instant latestTime;
		private @Nullable Instant minimum;
		private @Nullable Instant actionUpper;
		private @Nullable Duration firstObservationBudget;
		private TotpRecords.@Nullable Pending enrollment;
		private StoreTimeObservation.@Nullable Healthy finalObservation;
		private long finalCallStart;
		Run() {}
		private @Nullable Duration remaining(){
			Duration value=StoreTimeRules.remainingBudget(Duration.ofNanos(timeoutNanos),this.started,System.nanoTime()).orElse(null);
			if(value==null || Thread.currentThread().isInterrupted())return null;
			long nanos=Math.min(this.lastRemaining,value.toNanos());this.lastRemaining=nanos;return nanos<=0?null:Duration.ofNanos(nanos);
		}
		private boolean current(TotpRecoveryGate.@NonNull Permit currentPermit){return remaining()!=null && currentPermit.isCurrent() && remaining()!=null;}
		private @NonNull Result failed(@NonNull TotpUnavailableReason reason){
			if(this.mutationUnknown)return new Result(Status.INDETERMINATE);
			if(this.requestedCommitted)return new Result(Status.RECONCILIATION_REQUIRED);
			if(this.chargeCommitted && !this.chargeDecisionSettled)return Result.unavailable(TotpUnavailableReason.ATTEMPT_INCOMPLETE);
			return Result.unavailable(reason);
		}
		private void checkCurrent() throws Failure {
			if(remaining()==null)throw new Failure(failed(TotpUnavailableReason.DEADLINE_EXCEEDED));
			if(this.permit==null || !current(this.permit))throw new Failure(failed(TotpUnavailableReason.ADMISSION_CLOSED));
		}
		private void accept(StoreTimeObservation.@NonNull Healthy observation,long callStart,@NonNull Instant wall,long end) throws Failure {
			if(this.profile!=null && !StoreTimeRules.sameProfile(this.profile,observation))throw new Failure(failed(TotpUnavailableReason.FENCED));
			if(this.latestTime!=null && observation.getObservedAt().isBefore(this.latestTime))throw new Failure(failed(TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE));
			Duration duration=StoreTimeRules.elapsed(callStart,end).orElse(null);
			if(duration==null || !StoreTimeRules.isWorkerClockHealthy(observation,wall,duration))throw new Failure(failed(TotpUnavailableReason.CLOCK_HEALTH_UNCONFIRMED));
			if(this.profile==null){this.profile=observation;this.firstObservationBudget=remaining();}
			this.latestTime=observation.getObservedAt();checkCurrent();
		}
		private @NonNull TotpStoreSnapshot read(@NonNull Set<@NonNull TotpStoreKey> keys) throws Failure {
			checkCurrent();Duration budget=Objects.requireNonNull(remaining());long callStart=System.nanoTime();
			TotpStoreReadResult reply=store.read(keys,budget);
			if(reply instanceof TotpStoreReadResult.Fenced)throw new Failure(failed(TotpUnavailableReason.FENCED));
			if(!(reply instanceof TotpStoreReadResult.Available available) || !available.getSnapshot().getEntries().keySet().equals(keys))throw new Failure(failed(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE));
			TotpStoreSnapshot snapshot=available.getSnapshot();
			if(!(snapshot.getTimeObservation() instanceof StoreTimeObservation.Healthy healthy))throw new Failure(failed(TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE));
			Instant wall=clock.instant();long end=System.nanoTime();accept(healthy,callStart,wall,end);return snapshot;
		}
		private void root(TotpRecordsV3.@NonNull Namespace root,StoreTimeObservation.@NonNull Healthy observation,boolean pin) throws Failure {
			if(!root.getAuthorityId().equals(observation.getAdmission().getAuthorityId()))throw new Failure(failed(TotpUnavailableReason.FENCED));
			if(!supported(root.getMinimum()) || root.getMinimum().isAfter(observation.getObservedAt()))throw new Failure(failed(TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE));
			if(this.minimum!=null && !this.minimum.equals(root.getMinimum()))throw new Failure(failed(TotpUnavailableReason.FENCED));
			if(pin)this.minimum=root.getMinimum();
		}
		private @NonNull Instant artifactUpper() throws Failure {
			if(this.actionUpper==null){
				Duration left=remaining();
				if(left==null)throw new Failure(failed(TotpUnavailableReason.DEADLINE_EXCEEDED));
				try{this.actionUpper=Objects.requireNonNull(this.profile).getObservedAt().plus(Objects.requireNonNull(this.firstObservationBudget));}
				catch(RuntimeException failure){throw new Failure(failed(TotpUnavailableReason.CLOCK_HEALTH_UNCONFIRMED));}
				if(!supported(this.actionUpper))throw new Failure(failed(TotpUnavailableReason.CLOCK_HEALTH_UNCONFIRMED));
			}
			return this.actionUpper;
		}
		private @NonNull TotpStoreCommitResult commit(@NonNull State state,@NonNull List<TotpStoreWrite.@NonNull Mutation> mutations,
				TotpStoreWrite.@NonNull Purpose purpose,@NonNull CommitRole role,@Nullable Instant upper) throws Failure {
			checkCurrent();
			if(upper!=null && !state.now.isBefore(upper))return TotpStoreCommitResult.TIME_EXPIRED;
			StoreTimeObservation.Healthy observation=(StoreTimeObservation.Healthy)state.snapshot.getTimeObservation();
			StoreTemporalCondition condition=StoreTimeAccess.get().fromObservation(observation,state.now,upper);
			TotpStoreWrite write=TotpStoreWrite.fromSnapshotAndMutations(purpose,state.snapshot,mutations,condition);
			Duration budget=Objects.requireNonNull(remaining());long callStart=System.nanoTime();
			TotpStoreCommitReceipt receipt;
			try{receipt=store.compareAndCommit(write,budget);}
			catch(Throwable failure){if(mutations.isEmpty())this.barrierUnknown=true;else this.mutationUnknown=true;throw failure;}
			if(receipt==null){if(mutations.isEmpty())this.barrierUnknown=true;else this.mutationUnknown=true;return TotpStoreCommitResult.UNKNOWN;}
			TotpStoreCommitResult status=receipt.getStatus();
			if(status==TotpStoreCommitResult.UNKNOWN){if(mutations.isEmpty())this.barrierUnknown=true;else this.mutationUnknown=true;return status;}
			if(status==TotpStoreCommitResult.COMMITTED){
				if(role==CommitRole.CHARGE_RESERVATION)this.chargeCommitted=true;
				if(role==CommitRole.REQUESTED_TRANSITION)this.requestedCommitted=true;
				if(purpose==TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE)this.minimum=state.namespace.getMinimum();
				StoreCommitTiming timing=receipt.getTiming().orElse(null);
				if(timing==null){this.malformedCommitted=true;throw new Failure(failed(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE));}
				StoreTimeObservation.Healthy validated=timing.getValidatedTime();
				if(!StoreTimeRules.sameProfile(observation,validated) || validated.getObservedAt().isBefore(condition.getNotBeforeInclusive())
						|| (upper!=null && !validated.getObservedAt().isBefore(upper))){
					this.malformedCommitted=true;throw new Failure(failed(TotpUnavailableReason.FENCED));
				}
				if(role==CommitRole.AUXILIARY && this.chargeCommitted)this.chargeDecisionSettled=true;
				Instant wall=clock.instant();long end=System.nanoTime();accept(validated,callStart,wall,end);
				if(timing.getCompletedTime().isPresent()){
					StoreTimeObservation.Healthy completed=timing.getCompletedTime().orElseThrow();
					if(!StoreTimeRules.sameProfile(observation,completed) || completed.getObservedAt().isBefore(validated.getObservedAt())){
						this.malformedCommitted=true;throw new Failure(failed(TotpUnavailableReason.FENCED));
					}
					this.latestTime=completed.getObservedAt();
				}
			}
			checkCurrent();return status;
		}
		private void requireCommit(@NonNull TotpStoreCommitResult status,@NonNull TotpRejectionReason expired) throws Failure {
			if(status==TotpStoreCommitResult.COMMITTED)return;
			if(status==TotpStoreCommitResult.TIME_EXPIRED){
				if(this.chargeCommitted && !this.chargeDecisionSettled)throw new Failure(failed(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE));
				throw new Failure(Result.rejected(expired));
			}
			TotpUnavailableReason reason=switch(status){
				case FENCED -> TotpUnavailableReason.FENCED;
				case CAPACITY_REFUSED -> TotpUnavailableReason.CAPACITY_REFUSED;
				case TIME_UNAVAILABLE,TIME_BEFORE_FLOOR -> TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE;
				default -> TotpUnavailableReason.DEPENDENCY_UNAVAILABLE;
			};
			throw new Failure(failed(reason));
		}
		private void finish(@NonNull Result result) throws Failure,IOException {
			if(this.malformedCommitted || this.barrierUnknown)throw new Failure(failed(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE));
			checkCurrent();Duration budget=Objects.requireNonNull(remaining());this.finalCallStart=System.nanoTime();
			TotpStoreReadResult reply=store.read(Set.of(namespaceKey),budget);
			if(reply instanceof TotpStoreReadResult.Fenced)throw new Failure(failed(TotpUnavailableReason.FENCED));
			if(!(reply instanceof TotpStoreReadResult.Available available) || available.getSnapshot().getEntries().size()!=1
					|| !available.getSnapshot().getEntries().containsKey(namespaceKey))throw new Failure(failed(TotpUnavailableReason.DEPENDENCY_UNAVAILABLE));
			TotpStoreSnapshot snapshot=available.getSnapshot();
			if(!(snapshot.getTimeObservation() instanceof StoreTimeObservation.Healthy observation))throw new Failure(failed(TotpUnavailableReason.TIME_AUTHORITY_UNAVAILABLE));
			if(!(snapshot.getEntry(namespaceKey) instanceof TotpStoreEntry.Present present))throw new Failure(failed(TotpUnavailableReason.NAMESPACE_NOT_INITIALIZED));
			try(TotpRecordsV3.Decoded decoded=records.open(present.getRecord())){root(Objects.requireNonNull(decoded.namespace),observation,true);}
			accept(observation,this.finalCallStart,clock.instant(),System.nanoTime());
			this.finalObservation=observation;
			if(!releaseAllowed(result.releaseBefore))throw new Failure(failed(TotpUnavailableReason.CLOCK_HEALTH_UNCONFIRMED));
		}
		private boolean releaseAllowed(@Nullable Instant upper){
			StoreTimeObservation.Healthy observation=this.finalObservation;
			if(observation==null || remaining()==null)return false;
			Instant wall=clock.instant();Duration elapsed=StoreTimeRules.elapsed(this.finalCallStart,System.nanoTime()).orElse(null);
			return elapsed!=null && StoreTimeRules.isWorkerClockHealthy(observation,wall,elapsed)
					&& (upper==null || StoreTimeRules.isReleaseBefore(observation,elapsed,upper));
		}
		private void erase(){TotpRecords.Pending pending=this.enrollment;if(pending!=null){Arrays.fill(pending.secret,(byte)0);Arrays.fill(pending.browserHash,(byte)0);this.enrollment=null;}}
		private void backoff(int retry) throws Failure {
			if(retry>=8)return;
			checkCurrent();byte[] random=EntropySource.fromDefaults().nextBytes(2);
			long value;try{value=((long)(random[0]&255)<<8)|(random[1]&255);}finally{Arrays.fill(random,(byte)0);}
			long ceiling=Math.min(2_000_000L,100_000L<<Math.min(retry,5));
			long nanos=50_000L+value*(ceiling-50_000L)/65535L;
			Duration left=remaining();if(left==null)throw new Failure(failed(TotpUnavailableReason.DEADLINE_EXCEEDED));
			LockSupport.parkNanos(Math.min(nanos,left.toNanos()));checkCurrent();
		}
	}
	@Immutable private static final class Failure extends Exception {
		private static final long serialVersionUID=1L;
		private final @NonNull Status status;
		private final @NonNull TotpUnavailableReason reason;
		private final @NonNull TotpRejectionReason rejection;
		Failure(@NonNull Result result){super("TOTP operation unavailable",null,false,false);this.status=result.status;this.reason=result.unavailable;this.rejection=result.rejection;}
		@NonNull Result result(){Result result=new Result(this.status);result.unavailable=this.reason;result.rejection=this.rejection;return result;}
	}
}
