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

import org.jspecify.annotations.NonNull;
import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTimeObservation;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.internal.StoreTimeRules;
import com.revetsec.testing.ScriptedOAuthStore;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;

/** Atomic single-process test double. No persistence, failover or durable-backend claim. */
final class OAuthAtomicStoreFixture implements OAuthAuthorizationServerStore {
	final @NonNull Map<@NonNull OAuthStoreKey, @NonNull OAuthStoreEntry> rows = new LinkedHashMap<>();
	final @NonNull List<@NonNull Duration> budgets = new ArrayList<>();
	@Nullable Runnable beforeRead;
	@Nullable Runnable beforeCommit;
	@Nullable Runnable afterCommit;
	@Nullable Throwable fault;
	boolean nullRead;
	boolean nullCommit;
	boolean unknownBefore;
	boolean unknownAfter;
	int conflicts;
	int reads;
	int commits;
	@Nullable OAuthStoreEntry substitute;
	@Nullable OAuthStoreTransaction lastTransaction;
    @NonNull Instant authorityNow;
    boolean healthy=true;
    @NonNull StoreAdmission admission=ScriptedOAuthStore.observation(Instant.EPOCH).getAdmission();
    @NonNull String clockGeneration=ScriptedOAuthStore.observation(Instant.EPOCH).getClockGeneration();
    private @NonNull Instant lastPublished=Instant.EPOCH;
    private final @NonNull Set<@NonNull String> activatedScopes=new HashSet<>();
    OAuthAtomicStoreFixture(){this(Instant.parse("2026-10-04T00:00:00.123456789Z"));}
    OAuthAtomicStoreFixture(@NonNull Instant authorityNow){this.authorityNow=java.util.Objects.requireNonNull(authorityNow);}
    /** Explicit new isolated fixture universe between test cases, never an operational reset. */
    void resetClosedFixture(){synchronized(this.rows){this.rows.clear();this.activatedScopes.clear();this.lastPublished=Instant.EPOCH;this.healthy=true;}}
    @NonNull StoreTimeObservation observation(){
        if(!this.healthy || this.authorityNow.isBefore(this.lastPublished))return StoreTimeObservation.Unavailable.fromAdmission(this.admission);
        this.lastPublished=this.authorityNow;
        return ScriptedOAuthStore.observation(this.admission,this.clockGeneration,this.authorityNow);
    }
    private boolean missingRoot(@NonNull OAuthStoreKey key){
        String scope=OAuthStoreFormat.namespace(key);boolean data=false;
        for(OAuthStoreKey present:this.rows.keySet())if(scope.equals(OAuthStoreFormat.namespace(present))){
            if(present.getKind()==OAuthStoreKey.Kind.ISSUER_STATE)return false;data=true;
        }
        return data || this.activatedScopes.contains(scope);
    }
    private static @NonNull OAuthStoreCommitReceipt refusal(@NonNull OAuthStoreCommitStatus status){return OAuthStoreCommitReceipt.fromRefusal(status);}
	@Override @NonNull @SuppressWarnings("NullAway") // Deliberate invalid SPI return exercises caller checks.
	public OAuthStoreReadResult read(@NonNull OAuthStoreKey key, @NonNull Duration budget) {
		this.reads++; this.budgets.add(budget);
		Runnable hook = this.beforeRead; this.beforeRead = null; if (hook != null) hook.run();
		if (this.fault != null) raise(this.fault);
		if (this.nullRead) return null;
		synchronized (this.rows) {
            if(missingRoot(key))return OAuthStoreReadResult.Unavailable.get();
            return OAuthStoreReadResult.Available.fromObservation(key,this.substitute == null ? this.rows.get(key) : this.substitute,observation());
        }
	}
	@Override @NonNull @SuppressWarnings("NullAway") // Deliberate invalid SPI return exercises caller checks.
	public OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction, @NonNull Duration budget) {
		this.commits++; this.budgets.add(budget); this.lastTransaction = transaction;
		Runnable hook = this.beforeCommit; this.beforeCommit = null; if (hook != null) hook.run();
		if (this.fault != null) raise(this.fault);
		if (this.nullCommit) return null;
		if (this.unknownBefore) return OAuthStoreCommitReceipt.unknownInstance();
		if (this.conflicts > 0) { this.conflicts--; return refusal(OAuthStoreCommitStatus.CONFLICT); }
        OAuthStoreCommitReceipt committed;
        synchronized (this.rows) {
            if(!StoreTimeRules.sameAdmission(this.admission,transaction.getExpectedAdmission()))return refusal(OAuthStoreCommitStatus.FENCED);
            if(missingRoot(transaction.getConditions().get(0).getKey()))return refusal(OAuthStoreCommitStatus.UNAVAILABLE);
            for (OAuthStoreTransaction.Condition condition : transaction.getConditions()) {
				OAuthStoreEntry current = this.rows.get(condition.getKey());
				if (!condition.getExpectedVersion().equals(current == null ? Optional.empty() : Optional.of(current.getVersion())))
					return refusal(OAuthStoreCommitStatus.CONFLICT);
			}
            if(transaction.getPurpose()==OAuthStoreTransaction.Purpose.FENCE_ONLY)committed=OAuthStoreCommitReceipt.fromFenceAdmission(this.admission);
            else {
                StoreTemporalCondition condition=transaction.getTemporalCondition().orElseThrow();
                if(!this.clockGeneration.equals(condition.getClockGeneration()))return refusal(OAuthStoreCommitStatus.FENCED);
                StoreTimeObservation sampled=observation();
                if(!(sampled instanceof StoreTimeObservation.Healthy validated))return refusal(OAuthStoreCommitStatus.TIME_UNAVAILABLE);
                if(validated.getObservedAt().isBefore(condition.getNotBeforeInclusive()))return refusal(OAuthStoreCommitStatus.TIME_BEFORE_FLOOR);
                if(condition.getValidBeforeExclusive().isPresent() && !validated.getObservedAt().isBefore(condition.getValidBeforeExclusive().orElseThrow()))return refusal(OAuthStoreCommitStatus.TIME_EXPIRED);
                committed=OAuthStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(validated,null));
            }
            for (OAuthStoreTransaction.Mutation mutation : transaction.getMutations()) {
				if (mutation.getKind() == OAuthStoreTransaction.Mutation.Kind.REMOVE) this.rows.remove(mutation.getKey());
				else {
                    this.rows.put(mutation.getKey(), mutation.getEntry().orElseThrow());
                    if(mutation.getKey().getKind()==OAuthStoreKey.Kind.ISSUER_STATE)this.activatedScopes.add(OAuthStoreFormat.namespace(mutation.getKey()));
                }
			}
		}
		hook = this.afterCommit; this.afterCommit = null; if (hook != null) hook.run();
		return this.unknownAfter ? OAuthStoreCommitReceipt.unknownInstance() : committed;
	}
	@SuppressWarnings("unchecked")
	private static <T extends Throwable> void raise(@NonNull Throwable failure) throws T { throw (T) failure; }
}
