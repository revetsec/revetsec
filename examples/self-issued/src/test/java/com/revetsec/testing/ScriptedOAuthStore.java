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
import com.revetsec.internal.StoreTimeRules;
import com.revetsec.oauth.server.OAuthAuthorizationServerStore;
import com.revetsec.oauth.server.OAuthStoreCommitReceipt;
import com.revetsec.oauth.server.OAuthStoreCommitStatus;
import com.revetsec.oauth.server.OAuthStoreEntry;
import com.revetsec.oauth.server.OAuthStoreKey;
import com.revetsec.oauth.server.OAuthStoreReadResult;
import com.revetsec.oauth.server.OAuthStoreTransaction;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/** Test-only opaque atomic issuer storage with independent explicit authority controls. */
@ThreadSafe
public final class ScriptedOAuthStore implements OAuthAuthorizationServerStore {
    private final @NonNull Map<@NonNull OAuthStoreKey,@NonNull OAuthStoreEntry> entries=new HashMap<>();
    private final @NonNull Set<@NonNull String> activatedScopes=new HashSet<>();
    private final int maximumEntries;
    private final long maximumBytes;
    private @NonNull Instant time;
    private @NonNull Instant lastPublished=Instant.EPOCH;
    private @NonNull StoreAdmission admission=StoreAdmission.fromIdentifiers(identifier(1),identifier(2));
    private @NonNull String clockGeneration=identifier(3);
    private int identitySequence=3;
    private boolean healthy=true;
    public ScriptedOAuthStore(@NonNull Instant time){this(time,65536,268435456L);}
    public ScriptedOAuthStore(@NonNull Instant time,int maximumEntries,long maximumBytes){
        this.time=Objects.requireNonNull(time);this.maximumEntries=maximumEntries;this.maximumBytes=maximumBytes;
    }
    public synchronized @NonNull Instant authorityTime(){return this.time;}
    public synchronized void setTime(@NonNull Instant value){this.time=Objects.requireNonNull(value);}
    public synchronized void advance(@NonNull Duration amount){this.time=this.time.plus(amount);}
    public synchronized void setHealthy(boolean value){this.healthy=value;}
    public synchronized void rotateClockGeneration(){this.clockGeneration=identifier(++this.identitySequence);}
    public synchronized void rotateRecoveryGeneration(){this.admission=StoreAdmission.fromIdentifiers(this.admission.getAuthorityId(),identifier(++this.identitySequence));}
    public synchronized @NonNull StoreAdmission admission(){return this.admission;}
    public synchronized @NonNull String clockGeneration(){return this.clockGeneration;}
    public synchronized @NonNull Map<@NonNull OAuthStoreKey,@NonNull OAuthStoreEntry> records(){return Map.copyOf(this.entries);}
    /** Closed fixture inventory only; no normal migration or writer authority is implied. */
    public synchronized void seedClosedMigration(@NonNull Map<@NonNull OAuthStoreKey,@NonNull OAuthStoreEntry> values){
        if(!this.entries.isEmpty())throw new IllegalStateException("Fixture inventory must be empty");
        this.entries.putAll(values);
        for(OAuthStoreKey key:values.keySet())if(key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE)this.activatedScopes.add(scope(key));
    }
    @Override public synchronized @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){
        Objects.requireNonNull(key);
        if(badBudget(budget) || missingRoot(key))return OAuthStoreReadResult.Unavailable.get();
        return OAuthStoreReadResult.Available.fromObservation(key,this.entries.get(key),sample());
    }
    @Override public synchronized @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){
        Objects.requireNonNull(transaction);
        if(badBudget(budget))return refusal(OAuthStoreCommitStatus.UNAVAILABLE);
        if(!StoreTimeRules.sameAdmission(this.admission,transaction.getExpectedAdmission()))return refusal(OAuthStoreCommitStatus.FENCED);
        if(missingRoot(transaction.getConditions().get(0).getKey()))return refusal(OAuthStoreCommitStatus.UNAVAILABLE);
        for(var predicate:transaction.getConditions()){
            OAuthStoreEntry actual=this.entries.get(predicate.getKey());
            if(!predicate.getExpectedVersion().equals(actual==null?Optional.empty():Optional.of(actual.getVersion())))return refusal(OAuthStoreCommitStatus.CONFLICT);
        }
        OAuthStoreCommitReceipt committed;
        if(transaction.getPurpose()==OAuthStoreTransaction.Purpose.FENCE_ONLY)committed=OAuthStoreCommitReceipt.fromFenceAdmission(this.admission);
        else {
            StoreTemporalCondition condition=transaction.getTemporalCondition().orElseThrow();
            if(!this.clockGeneration.equals(condition.getClockGeneration()))return refusal(OAuthStoreCommitStatus.FENCED);
            StoreTimeObservation sampled=sample();
            if(!(sampled instanceof StoreTimeObservation.Healthy validated))return refusal(OAuthStoreCommitStatus.TIME_UNAVAILABLE);
            if(validated.getObservedAt().isBefore(condition.getNotBeforeInclusive()))return refusal(OAuthStoreCommitStatus.TIME_BEFORE_FLOOR);
            if(condition.getValidBeforeExclusive().isPresent() && !validated.getObservedAt().isBefore(condition.getValidBeforeExclusive().orElseThrow()))return refusal(OAuthStoreCommitStatus.TIME_EXPIRED);
            committed=OAuthStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(validated,null));
        }
        if(transaction.getMutations().isEmpty())return committed;
        Map<OAuthStoreKey,OAuthStoreEntry> next=new HashMap<>(this.entries);
        for(var mutation:transaction.getMutations()){
            if(mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE)next.remove(mutation.getKey());
            else next.put(mutation.getKey(),mutation.getEntry().orElseThrow());
        }
        long bytes=0;for(OAuthStoreEntry entry:next.values())bytes+=entry.getKey().getStorageKey().length()+entry.getVersion().length()+entry.toSealedForm().length()+128L;
        if(next.size()>this.maximumEntries || bytes>this.maximumBytes)return refusal(OAuthStoreCommitStatus.CAPACITY);
        this.entries.clear();this.entries.putAll(next);
        for(var mutation:transaction.getMutations())if(mutation.getKey().getKind()==OAuthStoreKey.Kind.ISSUER_STATE)this.activatedScopes.add(scope(mutation.getKey()));
        return committed;
    }
    private @NonNull StoreTimeObservation sample(){
        if(!this.healthy || this.time.isBefore(this.lastPublished))return StoreTimeObservation.Unavailable.fromAdmission(this.admission);
        this.lastPublished=this.time;return observation(this.admission,this.clockGeneration,this.time);
    }
    private boolean missingRoot(@NonNull OAuthStoreKey key){
        String ns=scope(key);boolean hasData=false;
        for(OAuthStoreKey stored:this.entries.keySet())if(scope(stored).equals(ns)){
            if(stored.getKind()==OAuthStoreKey.Kind.ISSUER_STATE)return false;hasData=true;
        }
        return hasData || this.activatedScopes.contains(ns);
    }
    public static StoreTimeObservation.@NonNull Healthy observation(@NonNull Instant time){return observation(StoreAdmission.fromIdentifiers(identifier(1),identifier(2)),identifier(3),time);}
    public static StoreTimeObservation.@NonNull Healthy observation(@NonNull StoreAdmission admission,@NonNull String generation,@NonNull Instant time){return StoreTimeObservation.Healthy.fromObservation(admission,generation,time,Duration.ZERO);}
    private static @NonNull String scope(@NonNull OAuthStoreKey key){return key.getStorageKey().split(":")[3];}
    private static boolean badBudget(@NonNull Duration budget){Objects.requireNonNull(budget);return budget.isNegative() || budget.isZero() || Thread.currentThread().isInterrupted();}
    private static @NonNull OAuthStoreCommitReceipt refusal(@NonNull OAuthStoreCommitStatus status){return OAuthStoreCommitReceipt.fromRefusal(status);}
    private static @NonNull String identifier(int seed){byte[] bytes=new byte[32];for(int n=0;n<bytes.length;n++)bytes[n]=(byte)(seed+n);return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);}
}
