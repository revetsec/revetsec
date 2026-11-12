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
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Duration;
import java.time.Instant;

/** Explicit SC-API-08 test-only known-receipt faults. Impossible factory shapes invoke private constructors, never production APIs. */
public final class StoreReceiptMatrix {
 private StoreReceiptMatrix() { }
 public enum Case {
  VALIDATION_VALID_NO_COMPLETION, MISSING_TIMING, MISSING_VALIDATION, VALIDATION_BELOW_FLOOR,
  VALIDATION_AT_UPPER, VALIDATION_AFTER_UPPER, VALIDATION_AUTHORITY, VALIDATION_RECOVERY,
  VALIDATION_CLOCK, VALIDATION_ERROR, COMPLETION_EQUAL, COMPLETION_PLUS_NANO,
  COMPLETION_REGRESSED, COMPLETION_AUTHORITY, COMPLETION_RECOVERY, COMPLETION_CLOCK,
  COMPLETION_ERROR, COMPLETION_AT_UPPER, COMPLETION_AFTER_UPPER, POST_ACK_FACTORY_THROW;
  public boolean isNormal(){return this==VALIDATION_VALID_NO_COMPLETION||this==COMPLETION_EQUAL||this==COMPLETION_PLUS_NANO;}
  public boolean isUnknown(){return this==POST_ACK_FACTORY_THROW;}
  public boolean needsFinalRead(){return isNormal()||this==COMPLETION_AT_UPPER||this==COMPLETION_AFTER_UPPER;}
 }
 public static @Nullable Instant finalTime(@NonNull Case scenario,StoreTimeObservation.@NonNull Healthy validated,@NonNull StoreTemporalCondition condition){
  return switch(scenario){case COMPLETION_PLUS_NANO->validated.getObservedAt().plusNanos(1);case COMPLETION_AT_UPPER->condition.getValidBeforeExclusive().orElseThrow();case COMPLETION_AFTER_UPPER->condition.getValidBeforeExclusive().orElseThrow().plusNanos(1);default->null;};
 }
 public static @NonNull Object apply(@NonNull Object receipt,@NonNull Case scenario,StoreTimeObservation.@NonNull Healthy validated,@NonNull StoreTemporalCondition condition){
  if(scenario==Case.POST_ACK_FACTORY_THROW){var unused = StoreCommitTiming.fromTimes(validated,at(validated,validated.getObservedAt().minusNanos(1),scenario));throw new AssertionError("Control factory must reject completion preceding validation");}
  if(scenario==Case.MISSING_TIMING)return withTiming(receipt,null,validated.getAdmission());
  if(scenario==Case.MISSING_VALIDATION)return withTiming(receipt,timing(null,null),validated.getAdmission());
  Instant validationTime=switch(scenario){case VALIDATION_BELOW_FLOOR->condition.getNotBeforeInclusive().minusNanos(1);case VALIDATION_AT_UPPER->condition.getValidBeforeExclusive().orElseThrow();case VALIDATION_AFTER_UPPER->condition.getValidBeforeExclusive().orElseThrow().plusNanos(1);default->validated.getObservedAt();};
  StoreTimeObservation.Healthy candidate=at(validated,validationTime,scenario);StoreCommitTiming timing;
  if(scenario.name().startsWith("COMPLETION_")){
   Instant completionTime=switch(scenario){case COMPLETION_PLUS_NANO->validated.getObservedAt().plusNanos(1);case COMPLETION_REGRESSED->validated.getObservedAt().minusNanos(1);case COMPLETION_AT_UPPER->condition.getValidBeforeExclusive().orElseThrow();case COMPLETION_AFTER_UPPER->condition.getValidBeforeExclusive().orElseThrow().plusNanos(1);default->validated.getObservedAt();};
   StoreTimeObservation.Healthy completed=at(validated,completionTime,scenario);
   if(scenario==Case.COMPLETION_EQUAL||scenario==Case.COMPLETION_PLUS_NANO||scenario==Case.COMPLETION_AT_UPPER||scenario==Case.COMPLETION_AFTER_UPPER)timing=StoreCommitTiming.fromTimes(validated,completed);
   else timing=timing(validated,completed);
  }else timing=StoreCommitTiming.fromTimes(candidate,null);
  return withTiming(receipt,timing,validated.getAdmission());
 }
 private static @NonNull Object withTiming(@NonNull Object receipt,@Nullable StoreCommitTiming timing,@Nullable StoreAdmission admission){
  try{
   if(receipt instanceof com.revetsec.totp.TotpStoreCommitReceipt){var constructor=receipt.getClass().getDeclaredConstructor(com.revetsec.totp.TotpStoreCommitResult.class,StoreCommitTiming.class);constructor.setAccessible(true);return constructor.newInstance(com.revetsec.totp.TotpStoreCommitResult.COMMITTED,timing);}
   if(receipt instanceof com.revetsec.webauthn.WebAuthnStoreCommitReceipt){var constructor=receipt.getClass().getDeclaredConstructor(com.revetsec.webauthn.WebAuthnStoreCommitResult.class,StoreCommitTiming.class);constructor.setAccessible(true);return constructor.newInstance(com.revetsec.webauthn.WebAuthnStoreCommitResult.COMMITTED,timing);}
   if(receipt instanceof com.revetsec.oauth.server.OAuthStoreCommitReceipt){var constructor=receipt.getClass().getDeclaredConstructor(com.revetsec.oauth.server.OAuthStoreCommitStatus.class,StoreAdmission.class,StoreCommitTiming.class);constructor.setAccessible(true);return constructor.newInstance(com.revetsec.oauth.server.OAuthStoreCommitStatus.COMMITTED,admission,timing);}
  }catch(ReflectiveOperationException failure){throw new AssertionError("Receipt fixture constructor unavailable",failure);}
  throw new AssertionError("Unsupported receipt fixture kind");
 }
 private static @NonNull StoreCommitTiming timing(StoreTimeObservation.@Nullable Healthy validated,StoreTimeObservation.@Nullable Healthy completed){
  try{var constructor=StoreCommitTiming.class.getDeclaredConstructor(StoreTimeObservation.Healthy.class,StoreTimeObservation.Healthy.class);constructor.setAccessible(true);return constructor.newInstance(validated,completed);}
  catch(ReflectiveOperationException failure){throw new AssertionError("Timing fixture constructor unavailable",failure);}
 }
 private static StoreTimeObservation.@NonNull Healthy at(StoreTimeObservation.@NonNull Healthy basis,@NonNull Instant time,@NonNull Case scenario){
  String authority=basis.getAdmission().getAuthorityId(),recovery=basis.getAdmission().getRecoveryGeneration(),generation=basis.getClockGeneration();Duration error=basis.getMaximumUtcError();
  if(scenario==Case.VALIDATION_AUTHORITY||scenario==Case.COMPLETION_AUTHORITY)authority=other(authority);
  if(scenario==Case.VALIDATION_RECOVERY||scenario==Case.COMPLETION_RECOVERY)recovery=other(recovery);
  if(scenario==Case.VALIDATION_CLOCK||scenario==Case.COMPLETION_CLOCK)generation=other(generation);
  if(scenario==Case.VALIDATION_ERROR||scenario==Case.COMPLETION_ERROR)error=error.isZero()?Duration.ofMillis(250):Duration.ZERO;
  return StoreTimeObservation.Healthy.fromObservation(StoreAdmission.fromIdentifiers(authority,recovery),generation,time,error);
 }
 private static @NonNull String other(@NonNull String value){return value.equals("A".repeat(43))?"E".repeat(42)+"A":"A".repeat(43);}
 @SuppressWarnings({"NullAway","TypeParameterUnusedInFormals"}) public static <T> @NonNull T brokenNull(){return null;}

 public static com.revetsec.oauth.server.@NonNull OAuthStoreCommitReceipt withoutAdmission(){
  return (com.revetsec.oauth.server.OAuthStoreCommitReceipt)withTiming(com.revetsec.oauth.server.OAuthStoreCommitReceipt.unknownInstance(),null,null);
 }
}
