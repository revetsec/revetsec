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
import com.revetsec.internal.StoreTimeRules;
import com.revetsec.internal.http.Deadline;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthStoreFailure.Reason.*;

/** Caller-thread coordination of admitted issuer observations, exact joins and factual commit effects. */
final class OAuthStoreCoordinator {
 private final @NonNull OAuthAuthorizationServerStore store;
 private final @NonNull OAuthStoreRecordCodec codec;
 private final @NonNull Clock workerClock;
 private final int maximumAttempts, maximumSubjectLength;
 private final @NonNull ThreadLocal<@Nullable Operation> operation = new ThreadLocal<>();
 OAuthStoreCoordinator(@NonNull OAuthAuthorizationServerStore store, @NonNull OAuthStoreRecordCodec codec,
   @NonNull Clock clock, int maximumAttempts, int maximumSubjectLength) {
  this(store,codec,clock,Duration.ZERO,maximumAttempts,maximumSubjectLength);
 }
 OAuthStoreCoordinator(@NonNull OAuthAuthorizationServerStore store, @NonNull OAuthStoreRecordCodec codec,
   @NonNull Clock clock, @NonNull Duration clockSkew, int maximumAttempts, int maximumSubjectLength) {
  this.store=requireNonNull(store);this.codec=requireNonNull(codec);this.workerClock=requireNonNull(clock);
  com.revetsec.internal.Limits.AS_CLOCK_SKEW.require(requireNonNull(clockSkew));
  if(maximumAttempts<1 || maximumAttempts>8 || maximumSubjectLength<16 || maximumSubjectLength>1024)
   throw OAuthStoreFormat.invalid();
  this.maximumAttempts=maximumAttempts;this.maximumSubjectLength=maximumSubjectLength;
 }
 /** One public operation may contain several sessions; earlier requested effects must survive later failure. */
 @NonNull Operation operation(@NonNull Deadline deadline) {
  Operation next=new Operation(deadline,this.operation.get());this.operation.set(next);return next;
 }
 final class Operation implements AutoCloseable {
  private final @NonNull Deadline deadline;
  private final @Nullable Operation previous;
  private boolean committed,unknown,raw,allowedRejection;
  private @Nullable Session release;
  private Operation(@NonNull Deadline deadline,@Nullable Operation previous){this.deadline=deadline;this.previous=previous;}
  void rethrowEffect(){if(this.unknown)throw failure(COMMIT_OUTCOME_UNKNOWN);if(this.committed)throw failure(COMMIT_CONFIRMED_NOT_ADMITTED);}
  void rethrowRejectionEffect(){if(this.allowedRejection && this.release!=null && this.release.releaseAllowed())return;rethrowEffect();}
  void release(){Session admitted=this.release;if(!this.raw && admitted!=null && !admitted.releaseAllowed()){
   rethrowEffect();throw failure(UNAVAILABLE);
  }}
  @Override public void close(){if(this.previous==null)operation.remove();else operation.set(this.previous);}
 }
 private @Nullable Operation current(@NonNull Deadline deadline){
  Operation current=this.operation.get();return current!=null && current.deadline.equals(deadline)?current:null;
 }
 /** Raw initialization reports factual effects; it is not a readiness or credential-release operation. */
 @NonNull OAuthStoreCommitReceipt initializeFreshIssuerResult(@NonNull Deadline deadline){
  Operation scope=current(deadline);if(scope!=null)scope.raw=true;
  Session session=new Session(deadline,false,false);
  Optional<OAuthStoreEntry> old=session.read(this.codec.issuerKey());
  if(old.isPresent()){
   session.root(old.orElseThrow());return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.CONFLICT);
  }
  Instant minimum=session.effectiveNow();StoreAdmission admission=session.admission();
  OAuthIssuerRootV2 root=crypto(()->OAuthIssuerRootV2.initial(this.codec.freshVersion(),admission.getAuthorityId(),minimum));
  OAuthStoreEntry entry=crypto(()->this.codec.sealAdmitted(this.codec.issuerKey(),OAuthStoreFormat.PERMANENT,minimum,root.toPayload()));
  return session.finishRaw(List.of(OAuthStoreTransaction.Mutation.fromPut(entry)),false);
 }
 @NonNull OAuthStoreCommitReceipt initializeFreshIssuer(@NonNull Deadline deadline){return initializeFreshIssuerResult(deadline);}
 @NonNull Session begin(@NonNull Deadline deadline){return new Session(deadline,false,true);}
 @NonNull OAuthStoreFence establishNewSubject(@NonNull String subject,@NonNull Deadline deadline){
  OAuthStoreKey key=subjectKey(subject);
  for(int attempt=0;attempt<this.maximumAttempts;attempt++){
   Session session=begin(deadline);Optional<OAuthStoreEntry> old=session.read(key);
   OAuthStoreFence fence=old.isPresent()?session.decodeSubject(old.orElseThrow()):crypto(()->OAuthStoreFence.initialSubject(this.codec.freshVersion()));
   List<OAuthStoreTransaction.Mutation> changes=old.isPresent()?List.of():List.of(OAuthStoreTransaction.Mutation.fromPut(session.seal(key,OAuthStoreFormat.PERMANENT,fence.toPayload())));
   if(session.commit(changes)==OAuthStoreCommitStatus.COMMITTED)return fence;
  }
  throw failure(UNAVAILABLE);
 }
 /** Only these two methods enter FENCE_ONLY. They cannot create a root or subject or refresh a floor. */
 @NonNull OAuthStoreFence revokeSubject(@NonNull String subject,@NonNull Deadline deadline){
  OAuthStoreKey key=subjectKey(subject);
  for(int attempt=0;attempt<this.maximumAttempts;attempt++){
   Session session=new Session(deadline,true,true);OAuthStoreFence old=session.subject(subject);
   OAuthStoreFence next=crypto(()->old.advance(old.highWater()));
   Instant floor=requireNonNull(session.floors.get(key));
   OAuthStoreEntry entry=crypto(()->this.codec.sealAdmitted(key,OAuthStoreFormat.PERMANENT,floor,next.toPayload()));
   if(session.finishFence(List.of(OAuthStoreTransaction.Mutation.fromPut(entry)))==OAuthStoreCommitStatus.COMMITTED)return next;
  }
  throw failure(UNAVAILABLE);
 }
 @NonNull OAuthStoreFence revokeAll(@NonNull Deadline deadline){
  for(int attempt=0;attempt<this.maximumAttempts;attempt++){
   Session session=new Session(deadline,true,true);OAuthIssuerRootV2 next=crypto(()->requireNonNull(session.root).advance());
   OAuthStoreEntry entry=crypto(()->this.codec.sealAdmitted(this.codec.issuerKey(),OAuthStoreFormat.PERMANENT,next.minimum(),next.toPayload()));
   if(session.finishFence(List.of(OAuthStoreTransaction.Mutation.fromPut(entry)))==OAuthStoreCommitStatus.COMMITTED)return OAuthStoreFence.fromRoot(next);
  }
  throw failure(UNAVAILABLE);
 }
 /** Raw retained-state maintenance preserves the original payload, floor and full retention horizon. */
 @NonNull OAuthStoreCommitReceipt reseal(@NonNull OAuthStoreKey key,@NonNull Deadline deadline){
  namespace(key);Operation scope=current(deadline);if(scope!=null)scope.raw=true;
  Session session=begin(deadline);Optional<OAuthStoreEntry> found=session.read(key);
  if(found.isEmpty() || !session.effectiveNow().isBefore(found.orElseThrow().getRetainUntil()))
   return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.CONFLICT);
  OAuthStoreEntry old=found.orElseThrow();OAuthStoreRecordCodecV2.Opened opened=session.opened(old);
  if(!old.getRetainUntil().equals(OAuthStoreFormat.PERMANENT))session.requireBefore(old.getRetainUntil());
  OAuthStoreEntry replacement=crypto(()->this.codec.sealAdmitted(key,old.getRetainUntil(),opened.floor(),opened.payload().toJson()));
  return session.finishRaw(List.of(OAuthStoreTransaction.Mutation.fromPut(replacement)),true);
 }
 private @NonNull OAuthStoreKey subjectKey(@NonNull String subject){OAuthServerConfiguration.text(subject,this.maximumSubjectLength);return this.codec.subjectKey(subject);}
 private void namespace(@NonNull OAuthStoreKey key){requireNonNull(key);if(!OAuthStoreFormat.namespace(key).equals(OAuthStoreFormat.namespace(this.codec.issuerKey())))throw OAuthStoreFormat.invalid();}
 private static boolean ordinary(@NonNull Instant time){return time.getEpochSecond()>=0 && time.getEpochSecond()<=253402300799L;}
 private static <T> @NonNull T crypto(@NonNull Supplier<@NonNull T> work){
  try{return work.get();}catch(VirtualMachineError fatal){throw fatal;}catch(OAuthStoreFailure failure){throw failure;}
  catch(Throwable failure){preserveInterrupt(failure);throw failure(CORRUPT_STATE);}
 }
 private static @NonNull Duration remaining(@NonNull Deadline deadline){
  if(Thread.currentThread().isInterrupted())throw failure(UNAVAILABLE);Duration left=requireNonNull(deadline).remaining();
  if(left.isZero() || left.isNegative())throw failure(UNAVAILABLE);return left;
 }
 static void preserveInterrupt(@NonNull Throwable fault){
  if(fault instanceof InterruptedException || fault instanceof java.io.InterruptedIOException)Thread.currentThread().interrupt();
 }
 private static @NonNull OAuthStoreFailure failure(OAuthStoreFailure.@NonNull Reason reason){return new OAuthStoreFailure(reason);}

 /** One full preparation attempt. Every external callback precedes the final exact fact join. */
 final class Session {
  private final @NonNull Deadline deadline;
  private final boolean fenceOnly;
  private final @NonNull OAuthStoreReadSet reads=new OAuthStoreReadSet();
  private final @NonNull Map<@NonNull OAuthStoreKey,@NonNull Optional<@NonNull OAuthStoreEntry>> loaded=new LinkedHashMap<>();
  private final @NonNull Map<@NonNull OAuthStoreKey,@NonNull Instant> floors=new LinkedHashMap<>();
  private @Nullable StoreAdmission expectedAdmission;
  private StoreTimeObservation.@Nullable Healthy profile,lastObservation;
  private @Nullable Instant latestTime,validBefore;
  private @Nullable OAuthIssuerRootV2 root;
  private @Nullable OAuthStoreEntry rootEntry;
  private boolean finished,requestedCommitted,mutationUnknown,expiryNoop;
  void allowExpiryNoop(){this.expiryNoop=true;}
  private OAuthServerException.@NonNull Reason expiryReason=OAuthServerException.Reason.INVALID_GRANT;
  void expiresAs(OAuthServerException.@NonNull Reason reason){this.expiryReason=requireNonNull(reason);}
  private StoreTimeObservation.@Nullable Healthy finalObservation;
  private long finalCallStart;
  private Session(@NonNull Deadline deadline,boolean fenceOnly,boolean established){
   this.deadline=requireNonNull(deadline);this.fenceOnly=fenceOnly;remaining(deadline);
   Operation scope=current(deadline);if(scope!=null){scope.release=null;scope.allowedRejection=false;}
   if(established){OAuthStoreEntry entry=read(codec.issuerKey()).orElseThrow(()->failure(CORRUPT_STATE));root(entry);}
  }
  private @NonNull StoreAdmission admission(){return requireNonNull(this.expectedAdmission);}
  private StoreTimeObservation.@NonNull Healthy profile(){return requireNonNull(this.profile);}
  private @NonNull OAuthIssuerRootV2 root(@NonNull OAuthStoreEntry entry){
   OAuthStoreRecordCodecV2.Opened opened=this.fenceOnly?crypto(()->codec.openPermanentFence(entry,admission(),entry)):opened(entry);
   OAuthIssuerRootV2 decoded=crypto(()->OAuthIssuerRootV2.decode(opened.payload()));
   if(!decoded.authorityId().equals(admission().getAuthorityId()) || !opened.floor().equals(decoded.minimum()))throw failure(CORRUPT_STATE);
   if(!this.fenceOnly)floor(decoded.minimum());
   this.root=decoded;this.rootEntry=entry;return decoded;
  }
  @NonNull OAuthStoreFence issuer(){checkOpen();return OAuthStoreFence.fromRoot(requireNonNull(this.root));}
  @NonNull Instant effectiveNow(){checkOpen();return requireNonNull(this.latestTime);}
  void requireBefore(@NonNull Instant expiry){
   checkOpen();requireNonNull(expiry);if(!ordinary(expiry))throw failure(UNAVAILABLE);
   if(this.validBefore==null || expiry.isBefore(this.validBefore))this.validBefore=expiry;
  }
  @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key){
   checkOpen();namespace(key);Optional<OAuthStoreEntry> old=this.loaded.get(key);if(old!=null)return old;
   if(this.loaded.size()==16)throw OAuthStoreFormat.invalid();Optional<OAuthStoreEntry> entry=observe(key);
   this.loaded.put(key,entry);this.reads.observe(key,entry);return entry;
  }
  private @NonNull Optional<@NonNull OAuthStoreEntry> observe(@NonNull OAuthStoreKey key){
   Duration budget=remaining(this.deadline);long started=System.nanoTime();OAuthStoreReadResult reply;
   try{reply=store.read(key,budget);}catch(VirtualMachineError fatal){throw fatal;}
   catch(Throwable fault){preserveInterrupt(fault);throw failure(UNAVAILABLE);}
   if(!(reply instanceof OAuthStoreReadResult.Available available) || !available.getKey().equals(key))throw failure(UNAVAILABLE);
   StoreTimeObservation observation=available.getTimeObservation();StoreAdmission admission=observation.getAdmission();
   if(this.expectedAdmission!=null && !StoreTimeRules.sameAdmission(this.expectedAdmission,admission))throw failure(UNAVAILABLE);
   if(this.expectedAdmission==null)this.expectedAdmission=admission;
   if(!this.fenceOnly){
    if(!(observation instanceof StoreTimeObservation.Healthy healthy))throw failure(UNAVAILABLE);
    accept(healthy,started);
   }
   remaining(this.deadline);return available.getEntry();
  }
  private void accept(StoreTimeObservation.@NonNull Healthy observation,long started){
   if(this.profile!=null && !StoreTimeRules.sameProfile(this.profile,observation))throw failure(UNAVAILABLE);
   if(this.latestTime!=null && observation.getObservedAt().isBefore(this.latestTime))throw failure(UNAVAILABLE);
   Instant wall;try{wall=requireNonNull(workerClock.instant());}catch(VirtualMachineError fatal){throw fatal;}
   catch(Throwable fault){preserveInterrupt(fault);throw failure(UNAVAILABLE);}
   Duration elapsed=StoreTimeRules.elapsed(started,System.nanoTime()).orElseThrow(()->failure(UNAVAILABLE));
   if(!StoreTimeRules.isWorkerClockHealthy(observation,wall,elapsed))throw failure(UNAVAILABLE);
   if(this.profile==null)this.profile=observation;this.lastObservation=observation;this.latestTime=observation.getObservedAt();remaining(this.deadline);
  }
  private void floor(@NonNull Instant value){
   if(!ordinary(value) || value.isAfter(requireNonNull(this.latestTime)))throw failure(UNAVAILABLE);
  }
  private OAuthStoreRecordCodecV2.@NonNull Opened opened(@NonNull OAuthStoreEntry entry){
   OAuthStoreRecordCodecV2.Opened opened=crypto(()->codec.openAdmitted(entry,Clock.fixed(requireNonNull(this.latestTime),ZoneOffset.UTC)));
   floor(opened.floor());this.floors.put(entry.getKey(),opened.floor());return opened;
  }
  @NonNull JsonObject open(@NonNull OAuthStoreEntry entry){checkOpen();return opened(entry).payload();}
  @NonNull OAuthStoreEntry seal(@NonNull OAuthStoreKey key,@NonNull Instant retainUntil,@NonNull String payload){
   checkOpen();return crypto(()->codec.sealAdmitted(key,retainUntil,effectiveNow(),payload));
  }
  private @NonNull OAuthStoreFence decodeSubject(@NonNull OAuthStoreEntry entry){
   OAuthStoreRecordCodecV2.Opened opened=this.fenceOnly?crypto(()->codec.openPermanentFence(entry,admission(),requireNonNull(this.rootEntry))):opened(entry);
   this.floors.put(entry.getKey(),opened.floor());return crypto(()->OAuthStoreFence.decode(opened.payload(),OAuthStoreKey.Kind.SUBJECT_STATE));
  }
  @NonNull OAuthStoreFence subject(@NonNull String subject){return decodeSubject(read(subjectKey(subject)).orElseThrow(()->failure(CORRUPT_STATE)));}
  /** Fresh authority time for key checks after provider/signing work; expected epoch predicates remain pinned. */
  @NonNull Instant authorityNow(){
   checkOpen();OAuthStoreEntry entry=observe(codec.issuerKey()).orElseThrow(()->failure(CORRUPT_STATE));
   OAuthStoreRecordCodecV2.Opened opened=opened(entry);OAuthIssuerRootV2 observed=crypto(()->OAuthIssuerRootV2.decode(opened.payload()));
   sameRoot(observed);return effectiveNow();
  }
  private void sameRoot(@NonNull OAuthIssuerRootV2 observed){
   OAuthIssuerRootV2 expected=requireNonNull(this.root);
   if(!expected.authorityId().equals(observed.authorityId()) || !expected.minimum().equals(observed.minimum())
     || !expected.incarnation().equals(observed.incarnation()))throw failure(UNAVAILABLE);
  }
  private boolean join(){
   for(var item:this.loaded.entrySet()){
    Optional<OAuthStoreEntry> actual=observe(item.getKey());if(!sameEntry(item.getValue(),actual))return false;
   }
   return true;
  }
  private boolean sameEntry(@NonNull Optional<@NonNull OAuthStoreEntry> a,@NonNull Optional<@NonNull OAuthStoreEntry> b){
   if(a.isEmpty() || b.isEmpty())return a.isEmpty() && b.isEmpty();OAuthStoreEntry x=a.orElseThrow(),y=b.orElseThrow();
   return x.getKey().equals(y.getKey()) && x.getVersion().equals(y.getVersion()) && x.getRetainUntil().equals(y.getRetainUntil()) && x.toSealedForm().equals(y.toSealedForm());
  }
  @NonNull OAuthStoreCommitStatus barrier(){return commit(List.of());}
  @NonNull OAuthStoreCommitStatus commit(@NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations){
   for(OAuthStoreTransaction.Mutation mutation:mutations)if(mutation.getKey().equals(codec.issuerKey())){this.finished=true;throw OAuthStoreFormat.invalid();}
   OAuthStoreCommitReceipt receipt=finishRaw(mutations,false);OAuthStoreCommitStatus status=receipt.getStatus();
   if(status==OAuthStoreCommitStatus.UNKNOWN){if(mutations.isEmpty())throw failure(UNAVAILABLE);throw failure(COMMIT_OUTCOME_UNKNOWN);}
   if(status!=OAuthStoreCommitStatus.COMMITTED){
    if(status==OAuthStoreCommitStatus.CONFLICT)return status;
    if(status==OAuthStoreCommitStatus.TIME_EXPIRED){
     if(this.expiryNoop){this.validBefore=null;finalTimed();return status;}
     if(this.expiryReason==OAuthServerException.Reason.TOKEN_REVOKED)throw OAuthServerClientAdmission.failure(OAuthServerAdmissionFailure.Reason.INVALID_TOKEN);
     if(this.expiryReason==OAuthServerException.Reason.INVALID_GRANT)throw OAuthServerClientAdmission.failure(OAuthServerAdmissionFailure.Reason.INVALID_GRANT);
     throw OAuthServerValidationException.fromReason(this.expiryReason);
    }
    throw failure(UNAVAILABLE);
   }
   if(!validTimedReceipt(receipt))throw effectFailure();
   finalTimed();return status;
  }
  @NonNull OAuthStoreCommitStatus commitRejection(@NonNull List<OAuthStoreTransaction.@NonNull Mutation> changes){
   OAuthStoreCommitStatus result=commit(changes);Operation scope=current(this.deadline);
   if(result==OAuthStoreCommitStatus.COMMITTED && scope!=null)scope.allowedRejection=true;return result;
  }
  private @NonNull OAuthStoreCommitReceipt finishRaw(@NonNull List<OAuthStoreTransaction.@NonNull Mutation> mutations,boolean preserveFloor){
   checkOpen();requireNonNull(mutations);
   if(!join()){this.finished=true;return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.CONFLICT);}
   this.finished=true;Instant lower=requireNonNull(this.latestTime),upper=this.validBefore;
   if(upper!=null && !lower.isBefore(upper)){this.finished=true;return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.TIME_EXPIRED);}
   List<OAuthStoreTransaction.Mutation> changes=new ArrayList<>();
   for(OAuthStoreTransaction.Mutation mutation:mutations){
    if(mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE || preserveFloor){changes.add(mutation);continue;}
    OAuthStoreEntry old=mutation.getEntry().orElseThrow();OAuthStoreRecordCodecV2.Opened opened=crypto(()->codec.openAdmitted(old,Clock.fixed(lower,ZoneOffset.UTC)));
    Instant nextFloor=old.getKey().equals(codec.issuerKey())?opened.floor():lower;
    changes.add(OAuthStoreTransaction.Mutation.fromPut(crypto(()->codec.sealAdmitted(old.getKey(),old.getRetainUntil(),nextFloor,opened.payload().toJson()))));
   }
   StoreTemporalCondition condition=StoreTimeAccess.get().fromObservation(profile(),lower,upper);
   OAuthStoreTransaction transaction=this.reads.transaction(OAuthStoreTransaction.Purpose.TIMED,admission(),condition,changes);
   return invoke(transaction);
  }
  private long commitCallStart;
  private @Nullable StoreTemporalCondition submittedCondition;
  private @NonNull OAuthStoreCommitReceipt invoke(@NonNull OAuthStoreTransaction transaction){
   Duration budget=remaining(this.deadline);this.finished=true;this.submittedCondition=transaction.getTemporalCondition().orElse(null);
   this.commitCallStart=System.nanoTime();OAuthStoreCommitReceipt receipt;
   try{receipt=store.commit(transaction,budget);}catch(VirtualMachineError fatal){rememberUnknown(transaction);throw fatal;}
   catch(Throwable fault){preserveInterrupt(fault);receipt=null;}
   if(receipt==null || receipt.getStatus()==OAuthStoreCommitStatus.UNKNOWN){rememberUnknown(transaction);return OAuthStoreCommitReceipt.unknownInstance();}
   // Record durable facts before checking timing, elapsed budget, worker health or final admission.
   if(receipt.getStatus()==OAuthStoreCommitStatus.COMMITTED && !transaction.getMutations().isEmpty()){
    this.requestedCommitted=true;Operation scope=current(this.deadline);if(scope!=null)scope.committed=true;
   }
   return receipt;
  }
  private void rememberUnknown(@NonNull OAuthStoreTransaction transaction){
   if(!transaction.getMutations().isEmpty()){this.mutationUnknown=true;Operation scope=current(this.deadline);if(scope!=null)scope.unknown=true;}
  }
  private @NonNull OAuthStoreFailure effectFailure(){return failure(this.mutationUnknown?COMMIT_OUTCOME_UNKNOWN:this.requestedCommitted?COMMIT_CONFIRMED_NOT_ADMITTED:UNAVAILABLE);}
  private boolean validTimedReceipt(@NonNull OAuthStoreCommitReceipt receipt){
   try{
    StoreTemporalCondition condition=requireNonNull(this.submittedCondition);StoreCommitTiming timing=receipt.getTiming().orElseThrow();
    StoreTimeObservation.Healthy validated=timing.getValidatedTime();Instant at=validated.getObservedAt();
    if(!StoreTimeRules.sameProfile(profile(),validated) || at.isBefore(condition.getNotBeforeInclusive())
      || condition.getValidBeforeExclusive().filter(bound->!at.isBefore(bound)).isPresent())return false;
    accept(validated,this.commitCallStart);
    if(timing.getCompletedTime().isPresent()){
     StoreTimeObservation.Healthy completed=timing.getCompletedTime().orElseThrow();
     if(!StoreTimeRules.sameProfile(profile(),completed) || completed.getObservedAt().isBefore(at))return false;
     this.latestTime=completed.getObservedAt();
    }
    return true;
   }catch(VirtualMachineError fatal){throw fatal;}catch(Throwable fault){preserveInterrupt(fault);return false;}
  }
  private void finalTimed(){
   try{
    this.finalCallStart=System.nanoTime();OAuthStoreEntry entry=observe(codec.issuerKey()).orElseThrow(()->failure(CORRUPT_STATE));
    OAuthStoreRecordCodecV2.Opened opened=opened(entry);OAuthIssuerRootV2 current=crypto(()->OAuthIssuerRootV2.decode(opened.payload()));sameRoot(current);
    this.finalObservation=requireNonNull(this.lastObservation);
    if(!releaseAllowed())throw effectFailure();Operation scope=current(this.deadline);if(scope!=null)scope.release=this;
   }catch(VirtualMachineError fatal){throw fatal;}catch(Throwable fault){preserveInterrupt(fault);throw effectFailure();}
  }
  private boolean releaseAllowed(){
   try{remaining(this.deadline);if(this.fenceOnly)return true;StoreTimeObservation.Healthy observation=this.finalObservation;if(observation==null)return false;
    Duration elapsed=StoreTimeRules.elapsed(this.finalCallStart,System.nanoTime()).orElseThrow();
    return StoreTimeRules.isWorkerClockHealthy(observation,workerClock.instant(),elapsed)
      && (this.validBefore==null || StoreTimeRules.isReleaseBefore(observation,elapsed,this.validBefore));
   }catch(VirtualMachineError fatal){throw fatal;}catch(Throwable fault){preserveInterrupt(fault);return false;}
  }
  private @NonNull OAuthStoreCommitStatus finishFence(@NonNull List<OAuthStoreTransaction.@NonNull Mutation> changes){
   checkOpen();OAuthStoreTransaction transaction=this.reads.transaction(OAuthStoreTransaction.Purpose.FENCE_ONLY,admission(),null,changes);
   OAuthStoreCommitReceipt receipt=invoke(transaction);OAuthStoreCommitStatus status=receipt.getStatus();
   if(status==OAuthStoreCommitStatus.UNKNOWN)throw failure(COMMIT_OUTCOME_UNKNOWN);
   if(status==OAuthStoreCommitStatus.CONFLICT)return status;if(status!=OAuthStoreCommitStatus.COMMITTED)throw failure(UNAVAILABLE);
   try{
    if(receipt.getTiming().isPresent() || receipt.getAdmission().isEmpty() || !StoreTimeRules.sameAdmission(admission(),receipt.getAdmission().orElseThrow()))throw effectFailure();
    OAuthStoreEntry rootAfter=observe(codec.issuerKey()).orElseThrow(()->failure(CORRUPT_STATE));
    OAuthStoreRecordCodecV2.Opened opened=crypto(()->codec.openPermanentFence(rootAfter,admission(),rootAfter));
    sameRoot(crypto(()->OAuthIssuerRootV2.decode(opened.payload())));remaining(this.deadline);
    Operation scope=current(this.deadline);if(scope!=null)scope.release=this;return status;
   }catch(VirtualMachineError fatal){throw fatal;}catch(Throwable fault){preserveInterrupt(fault);throw effectFailure();}
  }
  private void checkOpen(){if(this.finished)throw new IllegalStateException("OAuth store attempt is closed.");}
 }
}
