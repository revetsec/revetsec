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
import com.revetsec.webauthn.WebAuthnStore;
import com.revetsec.webauthn.WebAuthnStoreCommitReceipt;
import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import static java.util.Objects.requireNonNull;

/**
 * Application-owned PostgreSQL WebAuthn fixture for admitted-time WAR2 data. The application
 * supplies an independent trusted authority and separately owns writer fencing and closed migration.
 * Normal callbacks use shared admission, sorted logical entity locks, then changed entry escrow
 * buckets. New namespace-root insertion takes exclusive admission first. Time is sampled after
 * all waits. Reads and failed writes perform no pruning or data/quota/floor writes. Constructors
 * perform no I/O. This one-primary fixture does not qualify UTC, a witness owner or a deployment.
 */
@ThreadSafe
public final class PostgresqlWebAuthnStore implements WebAuthnStore {
	private static final @NonNull Duration MAXIMUM_BUDGET=Duration.ofSeconds(30);
	private static final @NonNull Duration MAXIMUM_AUTHORITY_BUDGET=Duration.ofMillis(100);
	@FunctionalInterface @ThreadSafe public interface ConnectionSource {
		@NonNull Connection open(@NonNull Duration remaining) throws SQLException;
	}
	/** Trusted source; a data-admitted time outage is represented as Unavailable, transport loss throws. */
	@FunctionalInterface @ThreadSafe public interface Authority {
		@NonNull StoreTimeObservation observe(@NonNull String physicalNamespaceId,@NonNull Duration remaining) throws Exception;
	}
	private final @NonNull String namespace,keyPrefix,physicalNamespaceId;
	private final @NonNull WebAuthnPgScope scope;
	private final @NonNull ConnectionSource source;
	private final @NonNull Authority authority;
	private final int maximumEntries;
	public PostgresqlWebAuthnStore(@NonNull String namespace,@NonNull String physicalNamespaceId,
			@NonNull ConnectionSource source,int maximumEntries,@NonNull Authority authority) {
		this.namespace=requireNonNull(namespace);this.source=requireNonNull(source);this.authority=requireNonNull(authority);
		if(namespace.isEmpty() || namespace.length()>128 || !namespace.matches("[A-Za-z0-9_-]+"))throw new IllegalArgumentException("Invalid WebAuthn namespace");
		if(maximumEntries<1 || maximumEntries>1_000_000)throw new IllegalArgumentException("Invalid WebAuthn capacity");
		this.maximumEntries=maximumEntries;this.physicalNamespaceId=canonicalId(requireNonNull(physicalNamespaceId));
		this.scope=WebAuthnPgScope.from("WEBAUTHN",this.physicalNamespaceId);
		this.keyPrefix="wa1:"+Base64.getUrlEncoder().withoutPadding().encodeToString(namespace.getBytes(StandardCharsets.US_ASCII))+':';
	}
	@Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration remainingBudget) {
		Set<WebAuthnStoreKey> requested=Set.copyOf(requireNonNull(keys));validateKeys(requested);Duration budget=capped(remainingBudget);
		if(budget.isZero() || Thread.currentThread().isInterrupted())return WebAuthnStoreReadResult.Unavailable.get();
		long deadline=System.nanoTime()+budget.toNanos();
		WebAuthnPgTransactions.Outcome<WebAuthnStoreReadResult> outcome=WebAuthnPgTransactions.execute(this.source::open,left(deadline),context->{
			WebAuthnPgLocks.sharedAdmission(context.connection(),this.scope,context.deadlineNanos());
			Map<String,Boolean> locks=new TreeMap<>();for(WebAuthnStoreKey key:requested)locks.put(key.getStorageKey(),false);
			WebAuthnPgLocks.entities(context.connection(),WebAuthnPgLocks.entitySet(this.scope,locks),context.deadlineNanos());
			Namespace admitted=namespace(context);Map<WebAuthnStoreKey,WebAuthnStoreEntry> entries=new LinkedHashMap<>();
			for(WebAuthnStoreKey key:requested){WebAuthnStoreEntry.Present actual=entry(context,key);if(key.getKind()==WebAuthnStoreKey.Kind.NAMESPACE_CLOCK && registeredRoot(context,key)!=(actual!=null))throw new SQLException("WebAuthn established root missing or unregistered");entries.put(key,actual==null?WebAuthnStoreEntry.Absent.confirmed():actual);}
			StoreTimeObservation point;try{point=observe(context,admitted);}catch(AdmissionChanged fenced){return WebAuthnPgTransactions.Decision.refuse(WebAuthnPgTransactions.Refusal.FENCED);}
			return WebAuthnPgTransactions.Decision.commit(WebAuthnStoreReadResult.Available.fromSnapshot(WebAuthnStoreSnapshot.fromEntries(requested,entries,point)));
		});
		if(outcome.status()==WebAuthnPgTransactions.Status.COMMITTED && !expired(deadline))return outcome.value().orElseThrow();
		return outcome.refusal().orElse(null)==WebAuthnPgTransactions.Refusal.FENCED?WebAuthnStoreReadResult.Fenced.get():WebAuthnStoreReadResult.Unavailable.get();
	}
	@Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration remainingBudget) {
		requireNonNull(write);validateKeys(write.getSnapshot().getEntries().keySet());Duration budget=capped(remainingBudget);
		if(budget.isZero() || Thread.currentThread().isInterrupted())return refusal(WebAuthnStoreCommitResult.UNAVAILABLE);
		long deadline=System.nanoTime()+budget.toNanos();
		WebAuthnPgTransactions.Outcome<StoreCommitTiming> outcome=WebAuthnPgTransactions.execute(this.source::open,left(deadline),context->{
			Connection connection=context.connection();
			boolean initializing=write.getMutations().stream().anyMatch(m->m.getKind()==WebAuthnStoreWrite.Mutation.Kind.INSERT && m.getKey().getKind()==WebAuthnStoreKey.Kind.NAMESPACE_CLOCK);
			if(initializing)WebAuthnPgLocks.exclusiveAdmission(connection,List.of(this.scope),context.deadlineNanos());
			else WebAuthnPgLocks.sharedAdmission(connection,this.scope,context.deadlineNanos());
			Map<String,Boolean> locks=new TreeMap<>();for(WebAuthnStoreKey key:write.getSnapshot().getEntries().keySet())locks.put(key.getStorageKey(),false);
			for(WebAuthnStoreWrite.Mutation mutation:write.getMutations())locks.put(mutation.getKey().getStorageKey(),true);
			WebAuthnPgLocks.entities(connection,WebAuthnPgLocks.entitySet(this.scope,locks),context.deadlineNanos());
			Namespace admitted=namespace(context);StoreTemporalCondition condition=write.getTemporalCondition();
			if(!matches(admitted,condition) || !(write.getSnapshot().getTimeObservation() instanceof StoreTimeObservation.Healthy original)
					|| !original.getMaximumUtcError().equals(admitted.error))return WebAuthnPgTransactions.Decision.refuse(WebAuthnPgTransactions.Refusal.FENCED);
			Map<WebAuthnStoreKey,WebAuthnStoreEntry.Present> current=new HashMap<>();
			for(Map.Entry<WebAuthnStoreKey,WebAuthnStoreEntry> predicate:write.getSnapshot().getEntries().entrySet()){
				WebAuthnStoreEntry.Present actual=entry(context,predicate.getKey());if(predicate.getKey().getKind()==WebAuthnStoreKey.Kind.NAMESPACE_CLOCK && registeredRoot(context,predicate.getKey())!=(actual!=null))throw new SQLException("WebAuthn established root missing or unregistered");if(actual!=null)current.put(predicate.getKey(),actual);
				if((predicate.getValue() instanceof WebAuthnStoreEntry.Absent && actual!=null)
						|| (predicate.getValue() instanceof WebAuthnStoreEntry.Present expected && (actual==null || !Arrays.equals(expected.getVersion(),actual.getVersion()))))
					return WebAuthnPgTransactions.Decision.refuse(WebAuthnPgTransactions.Refusal.CONFLICT);
			}
			List<WebAuthnPgCapacity.Delta> deltas=new ArrayList<>();
			for(WebAuthnStoreWrite.Mutation mutation:write.getMutations()){
				long change=mutation.getKind()==WebAuthnStoreWrite.Mutation.Kind.INSERT?1:mutation.getKind()==WebAuthnStoreWrite.Mutation.Kind.DELETE?-1:0;
				deltas.add(WebAuthnPgCapacity.Delta.from(WebAuthnPgCapacity.bucket(mutation.getKey().getStorageKey()),change,0));
			}
			WebAuthnPgCapacity.LockedPlan capacity=WebAuthnPgCapacity.lockForValidation(connection,this.scope,admitted.allocation,deltas,context.deadlineNanos());
			StoreTimeObservation point;try{point=observe(context,admitted);}catch(AdmissionChanged fenced){return WebAuthnPgTransactions.Decision.refuse(WebAuthnPgTransactions.Refusal.FENCED);}
			if(!(point instanceof StoreTimeObservation.Healthy healthy))return WebAuthnPgTransactions.Decision.refuse(WebAuthnPgTransactions.Refusal.TIME_UNAVAILABLE);
			if(healthy.getObservedAt().isBefore(condition.getNotBeforeInclusive()))return WebAuthnPgTransactions.Decision.refuse(WebAuthnPgTransactions.Refusal.TIME_BEFORE_FLOOR);
			if(condition.getValidBeforeExclusive().isPresent() && !healthy.getObservedAt().isBefore(condition.getValidBeforeExclusive().orElseThrow()))return WebAuthnPgTransactions.Decision.refuse(WebAuthnPgTransactions.Refusal.TIME_EXPIRED);
			try{capacity.checkCapacity();}catch(WebAuthnPgCapacity.CapacityRefused exhausted){return WebAuthnPgTransactions.Decision.refuse(WebAuthnPgTransactions.Refusal.CAPACITY);}
			for(WebAuthnStoreWrite.Mutation mutation:write.getMutations())apply(context,mutation,current.get(mutation.getKey()));
			if(!capacity.isEmpty()){context.markPossibleMutation();capacity.apply(connection,context.deadlineNanos());}
			return WebAuthnPgTransactions.Decision.commit(StoreCommitTiming.fromTimes(healthy,null));
		});
		if(outcome.status()==WebAuthnPgTransactions.Status.COMMITTED)return WebAuthnStoreCommitReceipt.fromCommittedTiming(outcome.value().orElseThrow());
		return outcome.status()==WebAuthnPgTransactions.Status.UNKNOWN?WebAuthnStoreCommitReceipt.unknownInstance():refusal(WebAuthnStoreCommitResult.valueOf(outcome.refusal().orElse(WebAuthnPgTransactions.Refusal.UNAVAILABLE).name()));
	}
	private @NonNull Namespace namespace(WebAuthnPgTransactions.@NonNull Context context)throws SQLException{
		try(PreparedStatement statement=context.connection().prepareStatement("SELECT physical_namespace,authority_id,recovery_generation,clock_generation,maximum_utc_error_nanos,allocation_generation,format_version,maximum_entries,admission_open FROM webauthn_store_namespace WHERE namespace=?")){
			context.bound(statement);statement.setString(1,this.namespace);
			try(ResultSet result=statement.executeQuery()){
				if(!result.next() || !this.physicalNamespaceId.equals(result.getString(1)) || result.getInt(7)!=2 || result.getInt(8)!=this.maximumEntries || !result.getBoolean(9))throw new SQLException("WebAuthn admission/profile unavailable");
				long nanos=result.getLong(5);if(nanos<0 || nanos>250000000)throw new SQLException("Invalid WebAuthn UTC profile");
				return new Namespace(StoreAdmission.fromIdentifiers(result.getString(2),result.getString(3)),canonicalId(result.getString(4)),Duration.ofNanos(nanos),canonicalId(result.getString(6)));
			}
		}
	}
	private @NonNull StoreTimeObservation observe(WebAuthnPgTransactions.@NonNull Context context,@NonNull Namespace admitted)throws Exception{
		Duration remaining=context.remaining();if(remaining.compareTo(MAXIMUM_AUTHORITY_BUDGET)>0)remaining=MAXIMUM_AUTHORITY_BUDGET;long started=System.nanoTime();
		StoreTimeObservation point=requireNonNull(this.authority.observe(this.physicalNamespaceId,remaining));context.check();
		if(System.nanoTime()-started>=remaining.toNanos())throw new SQLException("WebAuthn authority exceeded original request budget");
		if(!point.getAdmission().getAuthorityId().equals(admitted.admission.getAuthorityId()) || !point.getAdmission().getRecoveryGeneration().equals(admitted.admission.getRecoveryGeneration()))throw new AdmissionChanged();
		if(point instanceof StoreTimeObservation.Healthy healthy && (!healthy.getClockGeneration().equals(admitted.clock) || !healthy.getMaximumUtcError().equals(admitted.error)))throw new AdmissionChanged();
		return point;
	}
	private static boolean matches(@NonNull Namespace admitted,@NonNull StoreTemporalCondition condition){return admitted.admission.getAuthorityId().equals(condition.getAdmission().getAuthorityId()) && admitted.admission.getRecoveryGeneration().equals(condition.getAdmission().getRecoveryGeneration()) && admitted.clock.equals(condition.getClockGeneration());}
	private WebAuthnStoreEntry.@Nullable Present entry(WebAuthnPgTransactions.@NonNull Context context,@NonNull WebAuthnStoreKey key)throws SQLException{
		try(PreparedStatement statement=context.connection().prepareStatement("SELECT kind,version,sealed_form,sealed_size,expires_seconds,expires_nanos FROM webauthn_store_entry WHERE namespace=? AND storage_key=?")){
			context.bound(statement);statement.setString(1,this.namespace);statement.setString(2,key.getStorageKey());
			try(ResultSet result=statement.executeQuery()){
				if(!result.next())return null;if(!key.getKind().name().equals(result.getString(1)))throw new SQLException("WebAuthn stored kind/address mismatch");
				byte[] sealed=sealedBytes(result.getString(3));if(sealed.length!=result.getInt(4))throw new SQLException("WebAuthn stored length mismatch");
				long version=result.getLong(2);versionBytes(version);
				Long seconds=(Long)result.getObject(5);Integer nanos=(Integer)result.getObject(6);
				if(key.getKind()==WebAuthnStoreKey.Kind.CEREMONY){if(seconds==null || nanos==null)throw new SQLException("Missing exact ceremony expiry");Instant.ofEpochSecond(seconds,nanos);}
				else if(seconds!=null || nanos!=null)throw new SQLException("Permanent WebAuthn row carries expiry");
				return WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(versionBytes(version),sealed);
			}
		}
	}
	private boolean registeredRoot(WebAuthnPgTransactions.@NonNull Context context,@NonNull WebAuthnStoreKey key)throws SQLException{
		try(PreparedStatement statement=context.connection().prepareStatement("SELECT 1 FROM webauthn_store_root WHERE namespace=? AND storage_key=?")){context.bound(statement);statement.setString(1,this.namespace);statement.setString(2,key.getStorageKey());try(ResultSet result=statement.executeQuery()){return result.next();}}
	}
	private void apply(WebAuthnPgTransactions.@NonNull Context context,WebAuthnStoreWrite.@NonNull Mutation mutation,WebAuthnStoreEntry.@Nullable Present old)throws SQLException{
		WebAuthnStoreKey key=mutation.getKey();boolean insert=mutation.getKind()==WebAuthnStoreWrite.Mutation.Kind.INSERT,delete=mutation.getKind()==WebAuthnStoreWrite.Mutation.Kind.DELETE;
		if(delete && key.getKind()!=WebAuthnStoreKey.Kind.CEREMONY)throw new SQLException("Permanent WebAuthn records cannot be deleted");
		if(insert && key.getKind()==WebAuthnStoreKey.Kind.NAMESPACE_CLOCK){
			try(PreparedStatement activation=context.connection().prepareStatement("INSERT INTO webauthn_store_root(namespace,storage_key) VALUES(?,?)")){context.bound(activation);context.markPossibleMutation();activation.setString(1,this.namespace);activation.setString(2,key.getStorageKey());if(activation.executeUpdate()!=1)throw new SQLException("WebAuthn root activation failed");}
		}
		String sql=delete?"DELETE FROM webauthn_store_entry WHERE namespace=? AND storage_key=? AND version=?":insert?"INSERT INTO webauthn_store_entry(namespace,storage_key,kind,version,sealed_form,sealed_size,expires_seconds,expires_nanos) VALUES(?,?,?,nextval('webauthn_store_version_seq'),?,?,?,?)":"UPDATE webauthn_store_entry SET kind=?,version=nextval('webauthn_store_version_seq'),sealed_form=?,sealed_size=?,expires_seconds=?,expires_nanos=? WHERE namespace=? AND storage_key=? AND version=?";
		try(PreparedStatement statement=context.connection().prepareStatement(sql)){
			context.bound(statement);context.markPossibleMutation();
			if(delete){statement.setString(1,this.namespace);statement.setString(2,key.getStorageKey());statement.setLong(3,versionLong(requireNonNull(old).getVersion()));}
			else{
				byte[] sealed=mutation.getSealedBytes().orElseThrow();String form=sealedForm(sealed);if(form.length()>350000)throw new SQLException("WebAuthn SQL carrier too large");
				Instant expiry=mutation.getExpiresAt().orElse(null);
				if(insert){statement.setString(1,this.namespace);statement.setString(2,key.getStorageKey());statement.setString(3,key.getKind().name());statement.setString(4,form);statement.setInt(5,sealed.length);bindExpiry(statement,6,expiry);}
				else{statement.setString(1,key.getKind().name());statement.setString(2,form);statement.setInt(3,sealed.length);bindExpiry(statement,4,expiry);statement.setString(6,this.namespace);statement.setString(7,key.getStorageKey());statement.setLong(8,versionLong(requireNonNull(old).getVersion()));}
			}
			if(statement.executeUpdate()!=1)throw new SQLException("WebAuthn exact mutation lost its row");
		}
	}
	private static void bindExpiry(@NonNull PreparedStatement statement,int index,@Nullable Instant expiry)throws SQLException{if(expiry==null){statement.setNull(index,Types.BIGINT);statement.setNull(index+1,Types.INTEGER);}else{statement.setLong(index,expiry.getEpochSecond());statement.setInt(index+1,expiry.getNano());}}
	private void validateKeys(@NonNull Set<@NonNull WebAuthnStoreKey> keys){if(keys.isEmpty() || keys.size()>16)throw new IllegalArgumentException("Invalid WebAuthn read set");String first=keys.iterator().next().getStorageKey();String prefix=first.substring(0,first.indexOf(':',first.indexOf(':',first.indexOf(':')+1)+1)+1);for(WebAuthnStoreKey key:keys)if(!requireNonNull(key).getStorageKey().startsWith(this.keyPrefix) || !key.getStorageKey().startsWith(prefix))throw new IllegalArgumentException("WebAuthn key belongs to another namespace or RP");}
	private static @NonNull WebAuthnStoreCommitReceipt refusal(@NonNull WebAuthnStoreCommitResult status){return WebAuthnStoreCommitReceipt.fromRefusal(status);}
	private static @NonNull Duration capped(@NonNull Duration value){requireNonNull(value);return value.isZero() || value.isNegative()?Duration.ZERO:value.compareTo(MAXIMUM_BUDGET)>0?MAXIMUM_BUDGET:value;}
	private static @NonNull Duration left(long deadline){long value=deadline-System.nanoTime();return value<=0?Duration.ZERO:Duration.ofNanos(value);}
	private static boolean expired(long deadline){return deadline-System.nanoTime()<=0 || Thread.currentThread().isInterrupted();}
	private static byte @NonNull [] versionBytes(long version){if(version<=0)throw new IllegalArgumentException("Invalid WebAuthn version");return ByteBuffer.allocate(Long.BYTES).putLong(version).array();}
	private static long versionLong(byte @NonNull [] bytes){if(bytes.length!=Long.BYTES)throw new IllegalArgumentException("Invalid WebAuthn stored version");return ByteBuffer.wrap(bytes).getLong();}
	private static @NonNull String sealedForm(byte @NonNull [] value){return Base64.getUrlEncoder().withoutPadding().encodeToString(value);}
	private static byte @NonNull [] sealedBytes(@NonNull String form){if(form.isEmpty() || form.length()>350000)throw new IllegalArgumentException("Invalid WebAuthn SQL form");byte[] value=Base64.getUrlDecoder().decode(form);if(value.length<1 || value.length>262144 || !sealedForm(value).equals(form))throw new IllegalArgumentException("Invalid WebAuthn SQL form");return value;}
	private static @NonNull String canonicalId(@NonNull String id){try{byte[] value=Base64.getUrlDecoder().decode(id);if(value.length!=32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(value).equals(id))throw new IllegalArgumentException("Invalid fixture identity");return id;}catch(IllegalArgumentException failure){throw new IllegalArgumentException("Invalid fixture identity",failure);}}
	private static final class AdmissionChanged extends SQLException{@java.io.Serial private static final long serialVersionUID=1L;AdmissionChanged(){super("WebAuthn external admission changed");}}
	private static final class Namespace{final @NonNull StoreAdmission admission;final @NonNull String clock,allocation;final @NonNull Duration error;Namespace(@NonNull StoreAdmission admission,@NonNull String clock,@NonNull Duration error,@NonNull String allocation){this.admission=admission;this.clock=clock;this.error=error;this.allocation=allocation;}}
	@Override public @NonNull String toString(){return "PostgresqlWebAuthnStore[storage and authority redacted]";}
}
