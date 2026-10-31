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
package example.pending;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.totp.TotpStore;
import com.revetsec.totp.TotpStoreCommitReceipt;
import com.revetsec.totp.TotpStoreCommitResult;
import com.revetsec.totp.TotpStoreEntry;
import com.revetsec.totp.TotpStoreKey;
import com.revetsec.totp.TotpStoreReadResult;
import com.revetsec.totp.TotpStoreRecord;
import com.revetsec.totp.TotpStoreSnapshot;
import com.revetsec.totp.TotpStoreWrite;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import javax.annotation.concurrent.Immutable;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Objects.requireNonNull;

/**
 * Application-owned PostgreSQL TOTP fixture for the new admitted-time contract.
 * The required authority is a trusted independent admission/time source, not a worker clock or
 * database timestamp. The application owns its witness, SQL role fence and closed migration.
 * Constructors perform no I/O. Existing deployments cannot mix this writer with legacy writers.
 * Ordinary callbacks take shared physical admission, exact logical-key locks and changed escrow
 * buckets in that order. Namespace initialization starts with exclusive physical admission;
 * no lock upgrade, namespace mutex, count/sum, cleanup or observation write is used.
 */
@ThreadSafe
public final class PostgresqlTotpStore implements TotpStore {
	private static final int MAXIMUM_ENTRIES=65_536;
	private static final long MAXIMUM_BYTES=268_435_456L;
	private static final int MAXIMUM_EPOCHS=65_536;
	private static final @NonNull Duration MAXIMUM_BUDGET=Duration.ofSeconds(30);
	private static final @NonNull Duration MAXIMUM_AUTHORITY_BUDGET=Duration.ofMillis(100);

	/** Existing application-session recovery metadata projection, not a time authority. */
	@Immutable public record NamespaceRow(@NonNull String activeEpoch,@NonNull String activationState){
		@Override public @NonNull String toString(){return "NamespaceRow[redacted]";}
	}

	/** Opens a distinct clean primary connection within the shrinking original budget. */
	@FunctionalInterface @ThreadSafe
	public interface ConnectionSource {
		@NonNull Connection open(@NonNull Duration remaining) throws SQLException;
	}

	/**
	 * Trusted application witness boundary. The physical namespace is exact, not a digest of a
	 * different SQL name. Return time-Unavailable only while current data/recovery admission can
	 * still be attested; transport/ownership failure throws and withholds the complete envelope.
	 * The call must obey its positive remaining budget and never substitute a worker or DB clock.
	 */
	@FunctionalInterface @ThreadSafe
	public interface Authority {
		@NonNull StoreTimeObservation observe(@NonNull String physicalNamespaceId,
				@NonNull Duration remaining) throws Exception;
	}

	private final @NonNull String namespace;
	private final @NonNull String physicalNamespaceId;
	private final @NonNull TotpPgScope scope;
	private final @NonNull ConnectionSource source;
	private final @NonNull Authority authority;
	private final int maximumEntries;
	private final long maximumSealedBytes;
	private final @NonNull AtomicInteger failAcknowledgementOnCommit=new AtomicInteger();

	/**
	 * Selects one externally provisioned physical namespace and independent witness. SQL admission
	 * must bind both this physical ID and the unchanged credential namespace, exact profile/caps,
	 * authority/recovery/clock generations and target format before ordinary service can proceed.
	 */
	public PostgresqlTotpStore(@NonNull String namespace,@NonNull String physicalNamespaceId,
			@NonNull ConnectionSource source,int maximumEntries,long maximumSealedBytes,
			@NonNull Authority authority) {
		TotpStoreKey.forNamespace(requireNonNull(namespace),"fixture-validation");
		this.namespace=namespace;
		this.physicalNamespaceId=canonicalId(requireNonNull(physicalNamespaceId));
		this.scope=TotpPgScope.from("TOTP",physicalNamespaceId);
		this.source=requireNonNull(source);this.authority=requireNonNull(authority);
		if(maximumEntries<1 || maximumEntries>MAXIMUM_ENTRIES || maximumSealedBytes<1 || maximumSealedBytes>MAXIMUM_BYTES)
			throw new IllegalArgumentException("Invalid TOTP assigned capacity");
		this.maximumEntries=maximumEntries;this.maximumSealedBytes=maximumSealedBytes;
	}

	/** Test-only serial lost-response simulation after the next actual mutating commitment. */
	public void failNextCommitAcknowledgement(){failNthCommitAcknowledgement(1);}
	/** Test-only serial lost-response simulation after the given actual mutating commitment. */
	public void failNthCommitAcknowledgement(int ordinal){if(ordinal<1)throw new IllegalArgumentException("Invalid commit ordinal");this.failAcknowledgementOnCommit.set(ordinal);}

	@Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration remainingBudget) {
		Set<TotpStoreKey> requested=Set.copyOf(requireNonNull(keys));validateKeys(requested);Duration budget=capped(remainingBudget);
		if(budget.isZero() || Thread.currentThread().isInterrupted())return TotpStoreReadResult.Unavailable.get();
		long deadline=System.nanoTime()+budget.toNanos();
		TotpPgTransactions.Outcome<TotpStoreReadResult> outcome=TotpPgTransactions.execute(this.source::open,left(deadline),context->{
			TotpPgLocks.sharedAdmission(context.connection(),this.scope,context.deadlineNanos());
			Map<String,Boolean> locks=new TreeMap<>();for(TotpStoreKey key:requested)locks.put(key.getStorageKey(),false);
			TotpPgLocks.entities(context.connection(),TotpPgLocks.entitySet(this.scope,locks),context.deadlineNanos());
			Namespace admitted=namespace(context);
			String epoch=requested.iterator().next().getRecoveryEpoch();
			if(!admitted.epoch.equals(epoch))return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.FENCED);
			TotpStoreKey root=TotpStoreKey.forNamespace(this.namespace,epoch);
			if(admitted.state.equals("NEW") && (requested.size()!=1 || !requested.contains(root)))
				return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.UNAVAILABLE);
			Map<TotpStoreKey,TotpStoreEntry> entries=new LinkedHashMap<>();
			for(TotpStoreKey key:requested){TotpStoreRecord record=entry(context,key);entries.put(key,record==null?TotpStoreEntry.Absent.confirmed():TotpStoreEntry.Present.fromRecord(record));}
			if(admitted.state.equals("NEW") && !(entries.get(root) instanceof TotpStoreEntry.Absent))
				return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.UNAVAILABLE);
			StoreTimeObservation observation;try{observation=observe(context,admitted);}catch(AdmissionChanged fenced){return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.FENCED);}
			return TotpPgTransactions.Decision.commit(TotpStoreReadResult.Available.fromSnapshot(TotpStoreSnapshot.fromEntries(requested,entries,observation)));
		});
		if(outcome.status()==TotpPgTransactions.Status.COMMITTED && !expired(deadline))return outcome.value().orElseThrow();
		if(outcome.refusal().orElse(null)==TotpPgTransactions.Refusal.FENCED)return TotpStoreReadResult.Fenced.get();
		return TotpStoreReadResult.Unavailable.get();
	}

	@Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration remainingBudget) {
		requireNonNull(write);if(!this.namespace.equals(write.getCredentialNamespace()))throw new IllegalArgumentException("Wrong TOTP namespace");
		Duration budget=capped(remainingBudget);if(budget.isZero() || Thread.currentThread().isInterrupted())return refusal(TotpStoreCommitResult.UNAVAILABLE);
		long deadline=System.nanoTime()+budget.toNanos();
		TotpPgTransactions.Outcome<StoreCommitTiming> outcome=TotpPgTransactions.execute(this.source::open,left(deadline),context->{
			Connection connection=context.connection();
			if(write.getPurpose()==TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE)
				TotpPgLocks.exclusiveAdmission(connection,List.of(this.scope),context.deadlineNanos());
			else TotpPgLocks.sharedAdmission(connection,this.scope,context.deadlineNanos());
			Map<String,Boolean> locks=new TreeMap<>();
			for(TotpStoreKey key:write.getSnapshot().getEntries().keySet())locks.put(key.getStorageKey(),false);
			for(TotpStoreWrite.Mutation mutation:write.getMutations())locks.put(mutation.getKey().getStorageKey(),true);
			TotpPgLocks.entities(connection,TotpPgLocks.entitySet(this.scope,locks),context.deadlineNanos());
			Namespace admitted=namespace(context);StoreTemporalCondition condition=write.getTemporalCondition();
			if(!admitted.epoch.equals(write.getRecoveryEpoch()) || !matches(admitted,condition.getAdmission(),condition.getClockGeneration()))
				return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.FENCED);
			if(!(write.getSnapshot().getTimeObservation() instanceof StoreTimeObservation.Healthy original)
					|| !original.getMaximumUtcError().equals(admitted.error))return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.FENCED);
			if(write.getPurpose()==TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE && !admitted.state.equals("NEW"))
				return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.CONFLICT);
			if(write.getPurpose()!=TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE && !admitted.state.equals("ACTIVATED"))
				return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.UNAVAILABLE);
			Map<TotpStoreKey,TotpStoreRecord> current=new HashMap<>();
			for(Map.Entry<TotpStoreKey,TotpStoreEntry> predicate:write.getSnapshot().getEntries().entrySet()) {
				TotpStoreRecord actual=entry(context,predicate.getKey());if(actual!=null)current.put(predicate.getKey(),actual);
				if(predicate.getValue() instanceof TotpStoreEntry.Absent && actual!=null
						|| predicate.getValue() instanceof TotpStoreEntry.Present present && (actual==null || !present.getRecord().getVersion().equals(actual.getVersion())))
					return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.CONFLICT);
			}
			List<TotpPgCapacity.Delta> deltas=new ArrayList<>();
			for(TotpStoreWrite.Mutation mutation:write.getMutations()) {
				TotpStoreRecord changed=mutation.getRecord(),old=current.get(mutation.getKey());
				long reservation=TotpPgCapacity.totpReservation(changed.getSealedBytes()).getReservedBytes();
				long previous=old==null?0:TotpPgCapacity.totpReservation(old.getSealedBytes()).getReservedBytes();
				deltas.add(TotpPgCapacity.Delta.from(TotpPgCapacity.bucket(mutation.getKey().getStorageKey()),old==null?1:0,reservation-previous));
			}
			TotpPgCapacity.LockedPlan capacity=TotpPgCapacity.lockForValidation(connection,this.scope,admitted.allocation,deltas,context.deadlineNanos());
			StoreTimeObservation sample;try{sample=observe(context,admitted);}catch(AdmissionChanged fenced){return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.FENCED);}
			if(!(sample instanceof StoreTimeObservation.Healthy healthy))return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.TIME_UNAVAILABLE);
			if(healthy.getObservedAt().isBefore(condition.getNotBeforeInclusive()))return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.TIME_BEFORE_FLOOR);
			if(condition.getValidBeforeExclusive().isPresent() && !healthy.getObservedAt().isBefore(condition.getValidBeforeExclusive().orElseThrow()))
				return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.TIME_EXPIRED);
			try{capacity.checkCapacity();}catch(TotpPgCapacity.CapacityRefused exhausted){return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.CAPACITY);}
			for(TotpStoreWrite.Mutation mutation:write.getMutations())apply(context,mutation,current.get(mutation.getKey()));
			if(!capacity.isEmpty()){context.markPossibleMutation();capacity.apply(connection,context.deadlineNanos());}
			if(write.getPurpose()==TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE) {
				context.markPossibleMutation();
				try(PreparedStatement statement=connection.prepareStatement("UPDATE totp_store_namespace SET activation_state='ACTIVATED' WHERE namespace=? AND physical_namespace=? AND active_epoch=? AND activation_state='NEW'")){
					context.bound(statement);statement.setString(1,this.namespace);statement.setString(2,this.physicalNamespaceId);statement.setString(3,write.getRecoveryEpoch());
					if(statement.executeUpdate()!=1)throw new SQLException("TOTP activation lost its exact metadata");
				}
				try(PreparedStatement statement=connection.prepareStatement("UPDATE totp_store_epoch SET activated=true WHERE namespace=? AND recovery_epoch=? AND NOT activated")){
					context.bound(statement);statement.setString(1,this.namespace);statement.setString(2,write.getRecoveryEpoch());if(statement.executeUpdate()!=1)throw new SQLException("TOTP epoch activation was reused");
				}
			}
			return TotpPgTransactions.Decision.commit(StoreCommitTiming.fromTimes(healthy,null));
		});
		if(outcome.status()==TotpPgTransactions.Status.COMMITTED){
			if(outcome.possibleMutation() && loseAcknowledgement())return TotpStoreCommitReceipt.unknownInstance();
			return TotpStoreCommitReceipt.fromCommittedTiming(outcome.value().orElseThrow());
		}
		return outcome.status()==TotpPgTransactions.Status.UNKNOWN?TotpStoreCommitReceipt.unknownInstance():refusal(status(outcome));
	}

	/**
	 * Factual out-of-band address-epoch administration only. The trusted application must first
	 * close external admission, fence/drain writers and retain its independent recovery intent.
	 * This changes no authority/recovery/clock identity, old record, floor or quota usage; it is
	 * not shared-clock readmission. Old epochs stay charged and the history cap stays 65536.
	 */
	public @NonNull TotpStoreCommitResult provisionRecoveryEpoch(@NonNull String epoch,@NonNull Duration remainingBudget) {
		TotpStoreKey.forNamespace(this.namespace,requireNonNull(epoch));Duration budget=capped(remainingBudget);
		if(budget.isZero())return TotpStoreCommitResult.UNAVAILABLE;
		TotpPgTransactions.Outcome<Boolean> outcome=TotpPgTransactions.execute(this.source::open,budget,context->{
			TotpPgLocks.exclusiveAdmission(context.connection(),List.of(this.scope),context.deadlineNanos());Namespace current=namespace(context);
			try(PreparedStatement statement=context.connection().prepareStatement("SELECT count(*),count(*) FILTER(WHERE recovery_epoch=?) FROM totp_store_epoch WHERE namespace=?")){
				context.bound(statement);statement.setString(1,epoch);statement.setString(2,this.namespace);
				try(ResultSet result=statement.executeQuery()){result.next();if(result.getLong(2)!=0 || current.epoch.equals(epoch))return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.CONFLICT);if(result.getLong(1)>=MAXIMUM_EPOCHS)return TotpPgTransactions.Decision.refuse(TotpPgTransactions.Refusal.CAPACITY);}
			}
			context.markPossibleMutation();
			try(PreparedStatement statement=context.connection().prepareStatement("INSERT INTO totp_store_epoch(namespace,recovery_epoch,activated) VALUES(?,?,false)")){
				context.bound(statement);statement.setString(1,this.namespace);statement.setString(2,epoch);if(statement.executeUpdate()!=1)throw new SQLException("TOTP epoch insert failed");
			}
			try(PreparedStatement statement=context.connection().prepareStatement("UPDATE totp_store_namespace SET active_epoch=?,activation_state='NEW' WHERE namespace=? AND physical_namespace=? AND active_epoch=?")){
				context.bound(statement);statement.setString(1,epoch);statement.setString(2,this.namespace);statement.setString(3,this.physicalNamespaceId);statement.setString(4,current.epoch);if(statement.executeUpdate()!=1)throw new SQLException("TOTP epoch transition lost its exact metadata");
			}
			return TotpPgTransactions.Decision.commit(Boolean.TRUE);
		});
		if(outcome.status()==TotpPgTransactions.Status.COMMITTED)return loseAcknowledgement()?TotpStoreCommitResult.UNKNOWN:TotpStoreCommitResult.COMMITTED;
		return outcome.status()==TotpPgTransactions.Status.UNKNOWN?TotpStoreCommitResult.UNKNOWN:status(outcome);
	}

	private @NonNull Namespace namespace(TotpPgTransactions.@NonNull Context context) throws SQLException {
		try(PreparedStatement statement=context.connection().prepareStatement("SELECT active_epoch,activation_state,physical_namespace,authority_id,recovery_generation,clock_generation,maximum_utc_error_nanos,allocation_generation,format_version,maximum_entries,maximum_reserved_bytes FROM totp_store_namespace WHERE namespace=?")) {
			context.bound(statement);statement.setString(1,this.namespace);
			try(ResultSet result=statement.executeQuery()){
				if(!result.next() || !this.physicalNamespaceId.equals(result.getString(3)) || result.getInt(9)!=3 || result.getInt(10)!=this.maximumEntries || result.getLong(11)!=this.maximumSealedBytes)
					throw new SQLException("TOTP admission/profile unavailable");
				String epoch=result.getString(1),state=result.getString(2);TotpStoreKey.forNamespace(this.namespace,epoch);
				if(!state.equals("NEW") && !state.equals("ACTIVATED"))throw new SQLException("Invalid TOTP activation state");
				long nanos=result.getLong(7);if(nanos<0 || nanos>250000000)throw new SQLException("Invalid TOTP UTC profile");
				return new Namespace(epoch,state,StoreAdmission.fromIdentifiers(result.getString(4),result.getString(5)),canonicalId(result.getString(6)),Duration.ofNanos(nanos),canonicalId(result.getString(8)));
			}
		}
	}
	private @NonNull StoreTimeObservation observe(TotpPgTransactions.@NonNull Context context,@NonNull Namespace admitted) throws Exception {
		Duration left=context.remaining();if(left.compareTo(MAXIMUM_AUTHORITY_BUDGET)>0)left=MAXIMUM_AUTHORITY_BUDGET;long started=System.nanoTime();
		StoreTimeObservation point=requireNonNull(this.authority.observe(this.physicalNamespaceId,left));context.check();
		if(System.nanoTime()-started>=left.toNanos())throw new SQLException("TOTP authority request exceeded its original budget");
		if(!point.getAdmission().getAuthorityId().equals(admitted.admission.getAuthorityId()) || !point.getAdmission().getRecoveryGeneration().equals(admitted.admission.getRecoveryGeneration()))
			throw new AdmissionChanged();
		if(point instanceof StoreTimeObservation.Healthy healthy && (!healthy.getClockGeneration().equals(admitted.clock) || !healthy.getMaximumUtcError().equals(admitted.error)))
			throw new AdmissionChanged();
		return point;
	}
	private static boolean matches(@NonNull Namespace value,@NonNull StoreAdmission admission,@NonNull String clock){return value.admission.getAuthorityId().equals(admission.getAuthorityId()) && value.admission.getRecoveryGeneration().equals(admission.getRecoveryGeneration()) && value.clock.equals(clock);}
	private @Nullable TotpStoreRecord entry(TotpPgTransactions.@NonNull Context context,@NonNull TotpStoreKey key) throws SQLException {
		try(PreparedStatement statement=context.connection().prepareStatement("SELECT kind,version,sealed_form,sealed_size,reserved_size FROM totp_store_entry WHERE namespace=? AND recovery_epoch=? AND storage_key=?")){
			context.bound(statement);statement.setString(1,this.namespace);statement.setString(2,key.getRecoveryEpoch());statement.setString(3,key.getStorageKey());
			try(ResultSet result=statement.executeQuery()){
				if(!result.next())return null;if(!key.getKind().name().equals(result.getString(1)))throw new SQLException("TOTP kind/address mismatch");
				byte[] sealed=sealedBytes(result.getString(3));long reservation=TotpPgCapacity.totpReservation(sealed).getReservedBytes();
				if(sealed.length!=result.getInt(4) || reservation!=result.getLong(5))throw new SQLException("TOTP actual/reserved carrier size mismatch");
				return TotpStoreRecord.fromStoredForm(key,result.getString(2),sealed);
			}
		}
	}
	private void apply(TotpPgTransactions.@NonNull Context context,TotpStoreWrite.@NonNull Mutation mutation,@Nullable TotpStoreRecord old) throws SQLException {
		TotpStoreRecord record=mutation.getRecord();TotpStoreKey key=record.getKey();byte[] sealed=record.getSealedBytes();long reserved=TotpPgCapacity.totpReservation(sealed).getReservedBytes();
		String sql=mutation.getKind()==TotpStoreWrite.Mutation.Kind.INSERT?"INSERT INTO totp_store_entry(namespace,recovery_epoch,storage_key,kind,version,sealed_form,sealed_size,reserved_size) VALUES(?,?,?,?,?,?,?,?)":"UPDATE totp_store_entry SET kind=?,version=?,sealed_form=?,sealed_size=?,reserved_size=? WHERE namespace=? AND recovery_epoch=? AND storage_key=? AND version=?";
		try(PreparedStatement statement=context.connection().prepareStatement(sql)){
			context.bound(statement);context.markPossibleMutation();
			if(mutation.getKind()==TotpStoreWrite.Mutation.Kind.INSERT){statement.setString(1,this.namespace);statement.setString(2,key.getRecoveryEpoch());statement.setString(3,key.getStorageKey());statement.setString(4,key.getKind().name());statement.setString(5,record.getVersion());statement.setString(6,sealedForm(sealed));statement.setInt(7,sealed.length);statement.setLong(8,reserved);}
			else{statement.setString(1,key.getKind().name());statement.setString(2,record.getVersion());statement.setString(3,sealedForm(sealed));statement.setInt(4,sealed.length);statement.setLong(5,reserved);statement.setString(6,this.namespace);statement.setString(7,key.getRecoveryEpoch());statement.setString(8,key.getStorageKey());statement.setString(9,requireNonNull(old).getVersion());}
			if(statement.executeUpdate()!=1)throw new SQLException("TOTP exact mutation lost its row");
		}
	}
	private void validateKeys(@NonNull Set<@NonNull TotpStoreKey> keys){
		requireNonNull(keys);if(keys.isEmpty() || keys.size()>16)throw new IllegalArgumentException("Invalid TOTP read set");TotpStoreKey first=requireNonNull(keys.iterator().next());
		for(TotpStoreKey key:keys)if(!this.namespace.equals(requireNonNull(key).getCredentialNamespace()) || !first.getRecoveryEpoch().equals(key.getRecoveryEpoch()))throw new IllegalArgumentException("Mixed TOTP read scope");
	}
	private static @NonNull TotpStoreCommitReceipt refusal(@NonNull TotpStoreCommitResult result){return TotpStoreCommitReceipt.fromRefusal(result);}
	private static @NonNull TotpStoreCommitResult status(TotpPgTransactions.@NonNull Outcome<?> outcome){
		TotpPgTransactions.Refusal value=outcome.refusal().orElse(TotpPgTransactions.Refusal.UNAVAILABLE);
		return switch(value){case CAPACITY->TotpStoreCommitResult.CAPACITY_REFUSED;default->TotpStoreCommitResult.valueOf(value.name());};
	}
	private boolean loseAcknowledgement(){return this.failAcknowledgementOnCommit.getAndUpdate(value->value>0?value-1:0)==1;}
	private static @NonNull Duration capped(@NonNull Duration budget){requireNonNull(budget);if(budget.isNegative() || budget.isZero())return Duration.ZERO;return budget.compareTo(MAXIMUM_BUDGET)>0?MAXIMUM_BUDGET:budget;}
	private static @NonNull Duration left(long deadline){long left=deadline-System.nanoTime();return left<=0?Duration.ZERO:Duration.ofNanos(left);}
	private static boolean expired(long deadline){return deadline-System.nanoTime()<=0 || Thread.currentThread().isInterrupted();}
	private static @NonNull String sealedForm(byte @NonNull [] bytes){return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
	private static byte @NonNull [] sealedBytes(@NonNull String form){if(form.isEmpty() || form.length()>87382)throw new IllegalArgumentException("Invalid TOTP SQL form");byte[] value=Base64.getUrlDecoder().decode(form);if(value.length<1 || value.length>65536 || !sealedForm(value).equals(form))throw new IllegalArgumentException("Invalid TOTP SQL form");return value;}
	private static @NonNull String canonicalId(@NonNull String id){try{byte[] bytes=Base64.getUrlDecoder().decode(id);if(bytes.length!=32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(id))throw new IllegalArgumentException("Invalid fixture identity");return id;}catch(IllegalArgumentException failure){throw new IllegalArgumentException("Invalid fixture identity",failure);}}
	private static final class AdmissionChanged extends SQLException {
		@java.io.Serial private static final long serialVersionUID=1L;
		AdmissionChanged(){super("TOTP external admission changed");}
	}
	private static final class Namespace {
		final @NonNull String epoch,state,clock,allocation;final @NonNull StoreAdmission admission;final @NonNull Duration error;
		Namespace(@NonNull String epoch,@NonNull String state,@NonNull StoreAdmission admission,@NonNull String clock,@NonNull Duration error,@NonNull String allocation){this.epoch=epoch;this.state=state;this.admission=admission;this.clock=clock;this.error=error;this.allocation=allocation;}
	}
	@Override public @NonNull String toString(){return "PostgresqlTotpStore[storage and authority redacted]";}
}
