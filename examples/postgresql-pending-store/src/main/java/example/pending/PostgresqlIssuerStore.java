/*
 * Copyright 2026 Revetware LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
 */
package example.pending;

import com.revetsec.StoreAdmission;
import com.revetsec.StoreCommitTiming;
import com.revetsec.StoreTimeObservation;
import com.revetsec.oauth.server.OAuthAuthorizationServerStore;
import com.revetsec.oauth.server.OAuthStoreCommitReceipt;
import com.revetsec.oauth.server.OAuthStoreCommitStatus;
import com.revetsec.oauth.server.OAuthStoreEntry;
import com.revetsec.oauth.server.OAuthStoreKey;
import com.revetsec.oauth.server.OAuthStoreReadResult;
import com.revetsec.oauth.server.OAuthStoreTransaction;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import static java.util.Objects.requireNonNull;

/**
 * One-primary schema-2 issuer fixture. The application supplies independent admitted authority time.
 * Every callback holds shared admission and sorted logical locks, including confirmed absences.
 * Fresh root insertion takes exclusive admission first; only changed entry escrows are locked.
 * No namespace mutex, global count, read cleanup, worker-time admission or transaction retry exists.
 * Constructors perform no I/O. Real UTC, witness ownership and deployment exclusion are not qualified here.
 */
@ThreadSafe
public final class PostgresqlIssuerStore implements OAuthAuthorizationServerStore {
 private static final @NonNull Duration MAXIMUM_BUDGET=Duration.ofSeconds(30);
 private static final @NonNull Duration AUTHORITY_BUDGET=Duration.ofMillis(100);
 @FunctionalInterface @ThreadSafe public interface ConnectionSource {
  @NonNull Connection open(@NonNull Duration remaining) throws SQLException;
 }
 /** Independent source; an admitted UTC outage returns Unavailable rather than inventing healthy time. */
 @FunctionalInterface @ThreadSafe public interface Authority {
  @NonNull StoreTimeObservation observe(@NonNull String physicalNamespaceId,@NonNull Duration remaining) throws Exception;
 }
 private final @NonNull String namespace,physicalNamespaceId;
 private final @NonNull IssuerPgScope scope;
 private final @NonNull ConnectionSource source;
 private final @NonNull Authority authority;
 private final int maximumEntries;
 public PostgresqlIssuerStore(@NonNull String namespace,@NonNull String physicalNamespaceId,
   @NonNull ConnectionSource source,int maximumEntries,@NonNull Authority authority) {
  this.namespace=requireNonNull(namespace);this.source=requireNonNull(source);this.authority=requireNonNull(authority);
  if(namespace.isEmpty() || namespace.length()>128 || !namespace.matches("[A-Za-z0-9_-]+"))throw new IllegalArgumentException("Invalid issuer namespace");
  if(maximumEntries<1 || maximumEntries>1_000_000)throw new IllegalArgumentException("Invalid issuer capacity");
  this.physicalNamespaceId=canonicalId(requireNonNull(physicalNamespaceId));this.maximumEntries=maximumEntries;
  this.scope=IssuerPgScope.from("ISSUER",this.physicalNamespaceId);
 }
 @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration remainingBudget) {
  requireNonNull(key);Duration budget=capped(remainingBudget);
  if(budget.isZero() || Thread.currentThread().isInterrupted())return OAuthStoreReadResult.Unavailable.get();
  long deadline=System.nanoTime()+budget.toNanos();
  IssuerPgTransactions.Outcome<OAuthStoreReadResult> outcome=IssuerPgTransactions.execute(this.source::open,left(deadline),context->{
   IssuerPgLocks.sharedAdmission(context.connection(),this.scope,context.deadlineNanos());
   IssuerPgLocks.entities(context.connection(),IssuerPgLocks.entitySet(this.scope,Map.of(key.getStorageKey(),false)),context.deadlineNanos());
   Namespace admitted=namespace(context);OAuthStoreEntry actual=entry(context,key);
   rootPresent(context,key,actual);
   StoreTimeObservation point;try{point=observe(context,admitted,false);}catch(AdmissionChanged fenced){return IssuerPgTransactions.Decision.refuse(IssuerPgTransactions.Refusal.FENCED);}
   // Current data admission survives a clock-only transition. Only the narrow fence service can
   // use an available entry with unavailable time; ordinary timed service remains closed.
   if(point instanceof StoreTimeObservation.Healthy healthy && (!healthy.getClockGeneration().equals(admitted.clock) || !healthy.getMaximumUtcError().equals(admitted.error)))point=StoreTimeObservation.Unavailable.fromAdmission(point.getAdmission());
   return IssuerPgTransactions.Decision.commit(OAuthStoreReadResult.Available.fromObservation(key,actual,point));
  });
  if(outcome.status()==IssuerPgTransactions.Status.COMMITTED && !expired(deadline))return outcome.value().orElseThrow();
  return outcome.refusal().orElse(null)==IssuerPgTransactions.Refusal.FENCED?OAuthStoreReadResult.Fenced.get():OAuthStoreReadResult.Unavailable.get();
 }
 @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration remainingBudget) {
  requireNonNull(transaction);validateScope(transaction);Duration budget=capped(remainingBudget);
  if(budget.isZero() || Thread.currentThread().isInterrupted())return refusal(OAuthStoreCommitStatus.UNAVAILABLE);
  long deadline=System.nanoTime()+budget.toNanos();
  IssuerPgTransactions.Outcome<OAuthStoreCommitReceipt> outcome=IssuerPgTransactions.execute(this.source::open,left(deadline),context->{
   Connection connection=context.connection();boolean initializing=false;
   for(OAuthStoreTransaction.Condition condition:transaction.getConditions())if(condition.getKey().getKind()==OAuthStoreKey.Kind.ISSUER_STATE && condition.getExpectedVersion().isEmpty() && transaction.getMutations().stream().anyMatch(m->m.getKey().equals(condition.getKey()) && m.getKind()==OAuthStoreTransaction.Mutation.Kind.PUT))initializing=true;
   if(initializing)IssuerPgLocks.exclusiveAdmission(connection,List.of(this.scope),context.deadlineNanos());
   else IssuerPgLocks.sharedAdmission(connection,this.scope,context.deadlineNanos());
   Map<String,Boolean> locks=new TreeMap<>();for(OAuthStoreTransaction.Condition condition:transaction.getConditions())locks.put(condition.getKey().getStorageKey(),false);
   for(OAuthStoreTransaction.Mutation mutation:transaction.getMutations())locks.put(mutation.getKey().getStorageKey(),true);
   IssuerPgLocks.entities(connection,IssuerPgLocks.entitySet(this.scope,locks),context.deadlineNanos());
   Namespace admitted=namespace(context);
   if(!sameAdmission(admitted.admission,transaction.getExpectedAdmission()))return IssuerPgTransactions.Decision.refuse(IssuerPgTransactions.Refusal.FENCED);
   if(transaction.getPurpose()==OAuthStoreTransaction.Purpose.TIMED && !admitted.clock.equals(transaction.getTemporalCondition().orElseThrow().getClockGeneration()))return IssuerPgTransactions.Decision.refuse(IssuerPgTransactions.Refusal.FENCED);
   Map<OAuthStoreKey,OAuthStoreEntry> current=new HashMap<>();
   for(OAuthStoreTransaction.Condition condition:transaction.getConditions()){
    OAuthStoreEntry actual=entry(context,condition.getKey());rootPresent(context,condition.getKey(),actual);if(actual!=null)current.put(condition.getKey(),actual);
    if(!condition.getExpectedVersion().equals(actual==null?java.util.Optional.empty():java.util.Optional.of(actual.getVersion())))return IssuerPgTransactions.Decision.refuse(IssuerPgTransactions.Refusal.CONFLICT);
   }
   List<IssuerPgCapacity.Delta> deltas=new ArrayList<>();
   for(OAuthStoreTransaction.Mutation mutation:transaction.getMutations()){
    OAuthStoreEntry old=current.get(mutation.getKey());boolean remove=mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE;
    if(remove && permanent(mutation.getKey()))throw new SQLException("Permanent issuer fences cannot be removed");
    if(!remove && old!=null && old.getVersion().equals(mutation.getEntry().orElseThrow().getVersion()))throw new SQLException("Issuer replacement version unchanged");
    deltas.add(IssuerPgCapacity.Delta.from(IssuerPgCapacity.bucket(mutation.getKey().getStorageKey()),remove?-1:old==null?1:0,0));
   }
   IssuerPgCapacity.LockedPlan capacity=IssuerPgCapacity.lockForValidation(connection,this.scope,admitted.allocation,deltas,context.deadlineNanos());
   StoreTimeObservation point;try{point=observe(context,admitted,transaction.getPurpose()==OAuthStoreTransaction.Purpose.TIMED);}catch(AdmissionChanged fenced){return IssuerPgTransactions.Decision.refuse(IssuerPgTransactions.Refusal.FENCED);}
   OAuthStoreCommitReceipt candidate;
   if(transaction.getPurpose()==OAuthStoreTransaction.Purpose.FENCE_ONLY)candidate=OAuthStoreCommitReceipt.fromFenceAdmission(point.getAdmission());
   else{
    if(!(point instanceof StoreTimeObservation.Healthy healthy))return IssuerPgTransactions.Decision.refuse(IssuerPgTransactions.Refusal.TIME_UNAVAILABLE);
    var temporal=transaction.getTemporalCondition().orElseThrow();
    if(healthy.getObservedAt().isBefore(temporal.getNotBeforeInclusive()))return IssuerPgTransactions.Decision.refuse(IssuerPgTransactions.Refusal.TIME_BEFORE_FLOOR);
    if(temporal.getValidBeforeExclusive().isPresent() && !healthy.getObservedAt().isBefore(temporal.getValidBeforeExclusive().orElseThrow()))return IssuerPgTransactions.Decision.refuse(IssuerPgTransactions.Refusal.TIME_EXPIRED);
    candidate=OAuthStoreCommitReceipt.fromCommittedTiming(StoreCommitTiming.fromTimes(healthy,null));
   }
   try{capacity.checkCapacity();}catch(IssuerPgCapacity.CapacityRefused exhausted){return IssuerPgTransactions.Decision.refuse(IssuerPgTransactions.Refusal.CAPACITY);}
   for(OAuthStoreTransaction.Mutation mutation:transaction.getMutations())apply(context,mutation,current.get(mutation.getKey()));
   if(!capacity.isEmpty()){context.markPossibleMutation();capacity.apply(connection,context.deadlineNanos());}
   return IssuerPgTransactions.Decision.commit(candidate);
  });
  if(outcome.status()==IssuerPgTransactions.Status.COMMITTED)return outcome.value().orElseThrow();
  if(outcome.status()==IssuerPgTransactions.Status.UNKNOWN)return OAuthStoreCommitReceipt.unknownInstance();
  String reason=outcome.refusal().orElse(IssuerPgTransactions.Refusal.UNAVAILABLE).name();
  return refusal(OAuthStoreCommitStatus.valueOf(reason));
 }
 private @NonNull Namespace namespace(IssuerPgTransactions.@NonNull Context context)throws SQLException{
  try(PreparedStatement statement=context.connection().prepareStatement("SELECT physical_namespace,authority_id,recovery_generation,clock_generation,maximum_utc_error_nanos,allocation_generation,format_version,maximum_entries,admission_open FROM issuer_store_namespace WHERE namespace=?")){
   context.bound(statement);statement.setString(1,this.namespace);
   try(ResultSet result=statement.executeQuery()){
    if(!result.next() || !this.physicalNamespaceId.equals(result.getString(1)) || result.getInt(7)!=2 || result.getInt(8)!=this.maximumEntries || !result.getBoolean(9))throw new SQLException("Issuer admission/profile unavailable");
    long nanos=result.getLong(5);if(nanos<0 || nanos>250000000)throw new SQLException("Invalid issuer UTC profile");
    return new Namespace(StoreAdmission.fromIdentifiers(result.getString(2),result.getString(3)),canonicalId(result.getString(4)),Duration.ofNanos(nanos),canonicalId(result.getString(6)));
   }
  }
 }
 private @NonNull StoreTimeObservation observe(IssuerPgTransactions.@NonNull Context context,@NonNull Namespace admitted,boolean timed)throws Exception{
  Duration remaining=context.remaining();if(remaining.compareTo(AUTHORITY_BUDGET)>0)remaining=AUTHORITY_BUDGET;long started=System.nanoTime();
  StoreTimeObservation point=requireNonNull(this.authority.observe(this.physicalNamespaceId,remaining));context.check();
  if(System.nanoTime()-started>=remaining.toNanos())throw new SQLException("Issuer authority exceeded original request budget");
  if(!sameAdmission(point.getAdmission(),admitted.admission))throw new AdmissionChanged();
  if(timed && point instanceof StoreTimeObservation.Healthy healthy && (!healthy.getClockGeneration().equals(admitted.clock) || !healthy.getMaximumUtcError().equals(admitted.error)))throw new AdmissionChanged();
  return point;
 }
 private @Nullable OAuthStoreEntry entry(IssuerPgTransactions.@NonNull Context context,@NonNull OAuthStoreKey key)throws SQLException{
  try(PreparedStatement statement=context.connection().prepareStatement("SELECT kind,version,retain_seconds,retain_nanos,sealed_form FROM issuer_store_entry WHERE namespace=? AND storage_key=?")){
   context.bound(statement);statement.setString(1,this.namespace);statement.setString(2,key.getStorageKey());
   try(ResultSet result=statement.executeQuery()){
    if(!result.next())return null;if(!key.getKind().name().equals(result.getString(1)))throw new SQLException("Issuer stored kind/address mismatch");
    String form=result.getString(5);if(form==null || form.length()>16384)throw new SQLException("Issuer SQL carrier too large");
    return OAuthStoreEntry.fromStoredForm(key,result.getString(2),Instant.ofEpochSecond(result.getLong(3),result.getInt(4)),form);
   }
  }
 }
 private void rootPresent(IssuerPgTransactions.@NonNull Context context,@NonNull OAuthStoreKey key,@Nullable OAuthStoreEntry actual)throws SQLException{
  if(key.getKind()!=OAuthStoreKey.Kind.ISSUER_STATE)return;
  try(PreparedStatement statement=context.connection().prepareStatement("SELECT 1 FROM issuer_store_root WHERE namespace=? AND storage_key=?")){
   context.bound(statement);statement.setString(1,this.namespace);statement.setString(2,key.getStorageKey());try(ResultSet result=statement.executeQuery()){if(result.next()!=(actual!=null))throw new SQLException("Issuer established root missing or unregistered");}
  }
 }
 private void apply(IssuerPgTransactions.@NonNull Context context,OAuthStoreTransaction.@NonNull Mutation mutation,@Nullable OAuthStoreEntry old)throws SQLException{
  OAuthStoreKey key=mutation.getKey();boolean insert=old==null,remove=mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE;
  if(insert && key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE){
   String prefix=issuerPrefix(key);
   try(PreparedStatement statement=context.connection().prepareStatement("SELECT 1 FROM issuer_store_entry WHERE namespace=? AND left(storage_key,?)=? LIMIT 1")){
    context.bound(statement);statement.setString(1,this.namespace);statement.setInt(2,prefix.length());statement.setString(3,prefix);try(ResultSet result=statement.executeQuery()){if(result.next())throw new SQLException("Orphan issuer rows forbid root activation");}
   }
   try(PreparedStatement statement=context.connection().prepareStatement("INSERT INTO issuer_store_root(namespace,storage_key) VALUES(?,?)")){
    context.bound(statement);context.markPossibleMutation();statement.setString(1,this.namespace);statement.setString(2,key.getStorageKey());if(statement.executeUpdate()!=1)throw new SQLException("Issuer root activation failed");
   }
  }
  String sql=remove?"DELETE FROM issuer_store_entry WHERE namespace=? AND storage_key=? AND version=?":insert?"INSERT INTO issuer_store_entry(namespace,storage_key,kind,version,retain_seconds,retain_nanos,sealed_form) VALUES(?,?,?,?,?,?,?)":"UPDATE issuer_store_entry SET version=?,retain_seconds=?,retain_nanos=?,sealed_form=? WHERE namespace=? AND storage_key=? AND version=?";
  try(PreparedStatement statement=context.connection().prepareStatement(sql)){
   context.bound(statement);context.markPossibleMutation();
   if(remove){statement.setString(1,this.namespace);statement.setString(2,key.getStorageKey());statement.setString(3,requireNonNull(old).getVersion());}
   else{
    OAuthStoreEntry value=mutation.getEntry().orElseThrow();
    if(insert){statement.setString(1,this.namespace);statement.setString(2,key.getStorageKey());statement.setString(3,key.getKind().name());statement.setString(4,value.getVersion());statement.setLong(5,value.getRetainUntil().getEpochSecond());statement.setInt(6,value.getRetainUntil().getNano());statement.setString(7,value.toSealedForm());}
    else{statement.setString(1,value.getVersion());statement.setLong(2,value.getRetainUntil().getEpochSecond());statement.setInt(3,value.getRetainUntil().getNano());statement.setString(4,value.toSealedForm());statement.setString(5,this.namespace);statement.setString(6,key.getStorageKey());statement.setString(7,requireNonNull(old).getVersion());}
   }
   if(statement.executeUpdate()!=1)throw new SQLException("Issuer exact mutation lost its row");
  }
 }
 private static void validateScope(@NonNull OAuthStoreTransaction transaction){String prefix=issuerPrefix(transaction.getConditions().get(0).getKey());for(OAuthStoreTransaction.Condition condition:transaction.getConditions())if(!issuerPrefix(condition.getKey()).equals(prefix))throw new IllegalArgumentException("Mixed issuer namespace");}
 private static @NonNull String issuerPrefix(@NonNull OAuthStoreKey key){String value=key.getStorageKey();return value.substring(0,value.indexOf(':',"revetsec:as:1:".length())+1);}
 private static boolean permanent(@NonNull OAuthStoreKey key){return key.getKind()==OAuthStoreKey.Kind.ISSUER_STATE || key.getKind()==OAuthStoreKey.Kind.SUBJECT_STATE;}
 private static boolean sameAdmission(@NonNull StoreAdmission left,@NonNull StoreAdmission right){return left.getAuthorityId().equals(right.getAuthorityId()) && left.getRecoveryGeneration().equals(right.getRecoveryGeneration());}
 private static @NonNull OAuthStoreCommitReceipt refusal(@NonNull OAuthStoreCommitStatus status){return OAuthStoreCommitReceipt.fromRefusal(status);}
 private static @NonNull Duration capped(@NonNull Duration value){requireNonNull(value);return value.isNegative() || value.isZero()?Duration.ZERO:value.compareTo(MAXIMUM_BUDGET)>0?MAXIMUM_BUDGET:value;}
 private static @NonNull Duration left(long deadline){long left=deadline-System.nanoTime();return left>0?Duration.ofNanos(left):Duration.ZERO;}
 private static boolean expired(long deadline){return deadline-System.nanoTime()<=0 || Thread.currentThread().isInterrupted();}
 private static @NonNull String canonicalId(@NonNull String value){byte[] raw=Base64.getUrlDecoder().decode(value);if(value.length()!=43 || raw.length!=32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(raw).equals(value))throw new IllegalArgumentException("Invalid issuer physical identifier");return value;}
 private static final class Namespace {private final @NonNull StoreAdmission admission;private final @NonNull String clock,allocation;private final @NonNull Duration error;private Namespace(@NonNull StoreAdmission admission,@NonNull String clock,@NonNull Duration error,@NonNull String allocation){this.admission=admission;this.clock=clock;this.error=error;this.allocation=allocation;}}
 private static final class AdmissionChanged extends SQLException {@java.io.Serial private static final long serialVersionUID=1L;private AdmissionChanged(){super("Issuer admission changed");}}
 @Override public @NonNull String toString(){return "PostgresqlIssuerStore{storage=<redacted>}";}
}
