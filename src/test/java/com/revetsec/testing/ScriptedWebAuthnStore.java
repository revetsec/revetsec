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

package com.revetsec.testing;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.internal.StoreTimeRules;
import com.revetsec.webauthn.WebAuthnStore;
import com.revetsec.webauthn.WebAuthnStoreCommitReceipt;
import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/** Test-only atomic opaque storage with explicit authority controls separate from any worker clock. */
@ThreadSafe
public final class ScriptedWebAuthnStore implements WebAuthnStore {
	private final @NonNull Map<@NonNull WebAuthnStoreKey,WebAuthnStoreEntry.@NonNull Present> entries=new HashMap<>();
	private final int maximumEntries;
	private final long maximumBytes;
	private @NonNull Instant time;
	private @NonNull Instant lastPublished=Instant.EPOCH;
	private @NonNull StoreAdmission admission=StoreAdmission.fromIdentifiers(identifier(1),identifier(2));
	private @NonNull String clockGeneration=identifier(3);
	private int clockSequence=3;
	private long version;
	private boolean healthy=true;

	public ScriptedWebAuthnStore(@NonNull Instant time){this(time,65536,268435456L);}
	public ScriptedWebAuthnStore(@NonNull Instant time,int maximumEntries,long maximumBytes){
		this.time=Objects.requireNonNull(time);this.maximumEntries=maximumEntries;this.maximumBytes=maximumBytes;
	}
	public synchronized @NonNull Instant authorityTime(){return this.time;}
	public synchronized void advance(@NonNull Duration amount){this.time=this.time.plus(amount);}
	public synchronized void setTime(@NonNull Instant value){this.time=Objects.requireNonNull(value);}
	public synchronized void setHealthy(boolean value){this.healthy=value;}
	public synchronized void rotateClockGeneration(){this.clockGeneration=identifier(++this.clockSequence);}
	public synchronized void rotateRecoveryGeneration(){this.admission=StoreAdmission.fromIdentifiers(this.admission.getAuthorityId(),identifier(++this.clockSequence));}
	public synchronized @NonNull StoreAdmission admission(){return this.admission;}
	public synchronized @NonNull String clockGeneration(){return this.clockGeneration;}
	/** Explicit closed fixture inventory; this is never an operational write or migration controller. */
	public synchronized void seedClosedMigration(@NonNull Map<@NonNull WebAuthnStoreKey,WebAuthnStoreEntry.@NonNull Present> values){
		if(!this.entries.isEmpty())throw new IllegalStateException("Fixture inventory must be empty");
		this.entries.putAll(values);
	}
	public synchronized @NonNull Map<@NonNull WebAuthnStoreKey,WebAuthnStoreEntry.@NonNull Present> records(){return Map.copyOf(this.entries);}
	@Override public synchronized @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){
		if(badBudget(budget))return WebAuthnStoreReadResult.Unavailable.get();
		Map<WebAuthnStoreKey,WebAuthnStoreEntry> observed=new HashMap<>();
		for(WebAuthnStoreKey key:keys){WebAuthnStoreEntry present=this.entries.get(key);observed.put(key,present==null?WebAuthnStoreEntry.Absent.confirmed():present);}
		StoreTimeObservation sample=available()?observation():StoreTimeObservation.Unavailable.fromAdmission(this.admission);
		return WebAuthnStoreReadResult.Available.fromSnapshot(WebAuthnStoreSnapshot.fromEntries(keys,observed,sample));
	}
	@Override public synchronized @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){
		if(badBudget(budget))return refusal(WebAuthnStoreCommitResult.UNAVAILABLE);
		StoreTemporalCondition condition=write.getTemporalCondition();
		if(!StoreTimeRules.sameAdmission(this.admission,condition.getAdmission()) || !this.clockGeneration.equals(condition.getClockGeneration()))return refusal(WebAuthnStoreCommitResult.FENCED);
		for(var predicate:write.getSnapshot().getEntries().entrySet()){
			WebAuthnStoreEntry.Present actual=this.entries.get(predicate.getKey());
			if(predicate.getValue() instanceof WebAuthnStoreEntry.Absent?actual!=null:actual==null || !Arrays.equals(((WebAuthnStoreEntry.Present)predicate.getValue()).getVersion(),actual.getVersion()))return refusal(WebAuthnStoreCommitResult.CONFLICT);
		}
		if(!available())return refusal(WebAuthnStoreCommitResult.TIME_UNAVAILABLE);
		StoreTimeObservation.Healthy validated=observation();
		if(validated.getObservedAt().isBefore(condition.getNotBeforeInclusive()))return refusal(WebAuthnStoreCommitResult.TIME_BEFORE_FLOOR);
		if(condition.getValidBeforeExclusive().isPresent() && !validated.getObservedAt().isBefore(condition.getValidBeforeExclusive().orElseThrow()))return refusal(WebAuthnStoreCommitResult.TIME_EXPIRED);
		Map<WebAuthnStoreKey,WebAuthnStoreEntry.Present> projected=new HashMap<>(this.entries);
		long next=this.version;
		for(var mutation:write.getMutations()){
			if(mutation.getKind()==WebAuthnStoreWrite.Mutation.Kind.DELETE)projected.remove(mutation.getKey());
			else projected.put(mutation.getKey(),WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(ByteBuffer.allocate(8).putLong(++next).array(),mutation.getSealedBytes().orElseThrow()));
		}
		long bytes=0;for(var value:projected.values())bytes+=value.getSealedBytes().length;
		if(projected.size()>this.maximumEntries || bytes>this.maximumBytes)return refusal(WebAuthnStoreCommitResult.CAPACITY);
		if(!write.getMutations().isEmpty()){this.entries.clear();this.entries.putAll(projected);this.version=next;}
		return WebAuthnStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(validated,null));
	}
	private boolean available(){return this.healthy && !this.time.isBefore(this.lastPublished);}
	private StoreTimeObservation.@NonNull Healthy observation(){this.lastPublished=this.time;return observation(this.admission,this.clockGeneration,this.time);}
	public static StoreTimeObservation.@NonNull Healthy observation(@NonNull Instant time){return observation(StoreAdmission.fromIdentifiers(identifier(1),identifier(2)),identifier(3),time);}
	public static StoreTimeObservation.@NonNull Healthy observation(@NonNull StoreAdmission admission,@NonNull String generation,@NonNull Instant time){return StoreTimeObservation.Healthy.fromObservation(admission,generation,time,Duration.ZERO);}
	public static @NonNull StoreTemporalCondition condition(@NonNull WebAuthnStoreSnapshot snapshot){return StoreTimeAccess.get().fromObservation((StoreTimeObservation.Healthy)snapshot.getTimeObservation(),((StoreTimeObservation.Healthy)snapshot.getTimeObservation()).getObservedAt(),null);}
	public static @NonNull WebAuthnStoreSnapshot snapshot(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Map<@NonNull WebAuthnStoreKey,@NonNull WebAuthnStoreEntry> entries,@NonNull Instant time){return WebAuthnStoreSnapshot.fromEntries(keys,entries,observation(time));}
	public static @NonNull WebAuthnStoreWrite write(@NonNull WebAuthnStoreSnapshot snapshot,@NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations){return WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot,mutations,condition(snapshot));}
	private static @NonNull WebAuthnStoreCommitReceipt refusal(@NonNull WebAuthnStoreCommitResult value){return WebAuthnStoreCommitReceipt.fromRefusal(value);}
	private static boolean badBudget(@NonNull Duration budget){return budget.isZero() || budget.isNegative() || Thread.currentThread().isInterrupted();}
	private static @NonNull String identifier(int seed){byte[] bytes=new byte[32];for(int n=0;n<bytes.length;n++)bytes[n]=(byte)(seed+n);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
}
