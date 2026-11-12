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

import com.revetsec.StoreTemporalCondition;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Additional store checks for a backend with an independently controllable authority.
 * The controller must order samples; it is not a worker clock or a production SPI method. */
@javax.annotation.concurrent.NotThreadSafe
public abstract class TotpControlledStoreConformanceTests extends TotpStoreConformanceTests {
 protected abstract void setAuthorityTime(@NonNull TotpStore store,@NonNull Instant time);
 protected abstract void setAuthorityHealthy(@NonNull TotpStore store,boolean healthy);
 protected abstract void rotateClockGeneration(@NonNull TotpStore store);

 @Test void lowerInclusiveAndUpperExclusiveAtExactNanosecondBoundaries(){
  TotpStore store=initialized();
  TotpStoreSnapshot before=snapshot(store,Set.of(ROOT));
  StoreTimeObservation.Healthy observed=assertInstanceOf(StoreTimeObservation.Healthy.class,before.getTimeObservation());
  Instant lower=observed.getObservedAt().plusNanos(1),upper=lower.plusNanos(2);
  StoreTemporalCondition window=StoreTimeAccess.get().fromObservation(observed,lower,upper);
  TotpStoreWrite barrier=TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.UPDATE,
    before,List.of(),window);
  assertEquals(TotpStoreCommitResult.TIME_BEFORE_FLOOR,commit(store,barrier,BUDGET));
  setAuthorityTime(store,lower);
  assertEquals(TotpStoreCommitResult.COMMITTED,commit(store,barrier,BUDGET));
  setAuthorityTime(store,upper.minusNanos(1));
  assertEquals(TotpStoreCommitResult.COMMITTED,commit(store,barrier,BUDGET));
  setAuthorityTime(store,upper);
  assertEquals(TotpStoreCommitResult.TIME_EXPIRED,commit(store,barrier,BUDGET));
  setAuthorityTime(store,upper.plusNanos(1));
  assertEquals(TotpStoreCommitResult.TIME_EXPIRED,commit(store,barrier,BUDGET));
  assertEquals(present(before,ROOT).getVersion(),present(snapshot(store,Set.of(ROOT)),ROOT).getVersion());
 }

 @Test void utcOutageKeepsFactsReadableButRefusesTimedMutation(){
  TotpStore store=initialized();
  TotpStoreSnapshot before=snapshot(store,Set.of(ROOT,ACCOUNT));
  TotpStoreWrite attempted=update(before,List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT,7))));
  setAuthorityHealthy(store,false);
  TotpStoreSnapshot unavailable=snapshot(store,Set.of(ROOT,ACCOUNT));
  assertInstanceOf(StoreTimeObservation.Unavailable.class,unavailable.getTimeObservation());
  assertEquals(present(before,ROOT).getVersion(),present(unavailable,ROOT).getVersion());
  assertInstanceOf(TotpStoreEntry.Absent.class,unavailable.getEntry(ACCOUNT));
  assertEquals(TotpStoreCommitResult.TIME_UNAVAILABLE,commit(store,attempted,BUDGET));
  setAuthorityHealthy(store,true);
  assertEquals(TotpStoreCommitResult.COMMITTED,commit(store,attempted,BUDGET));
  assertArrayEquals(new byte[]{7},present(snapshot(store,Set.of(ROOT,ACCOUNT)),ACCOUNT).getSealedBytes());
 }

 @Test void clockGenerationRotationFencesAnOldPreparedWrite(){
  TotpStore store=initialized();
  TotpStoreSnapshot before=snapshot(store,Set.of(ROOT,ACCOUNT));
  TotpStoreWrite stale=update(before,List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT,8))));
  rotateClockGeneration(store);
  assertEquals(TotpStoreCommitResult.FENCED,commit(store,stale,BUDGET));
  assertInstanceOf(TotpStoreEntry.Absent.class,snapshot(store,Set.of(ROOT,ACCOUNT)).getEntry(ACCOUNT));
  TotpStoreSnapshot fresh=snapshot(store,Set.of(ROOT,ACCOUNT));
  assertEquals(TotpStoreCommitResult.COMMITTED,commit(store,
    update(fresh,List.of(TotpStoreWrite.Mutation.insert(record(ACCOUNT,8)))),BUDGET));
 }

 private @NonNull TotpStore initialized(){
  TotpStore store=newStore();
  assertEquals(TotpStoreCommitResult.COMMITTED,commit(store,
    initialize(snapshot(store,Set.of(ROOT)),ROOT,1),BUDGET));
  return store;
 }
}
