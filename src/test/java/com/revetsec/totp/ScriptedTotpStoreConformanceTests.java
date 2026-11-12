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

import java.time.Duration;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@javax.annotation.concurrent.NotThreadSafe
final class ScriptedTotpStoreConformanceTests extends TotpControlledStoreConformanceTests {
 private static final @NonNull Instant NOW=Instant.parse("2026-10-04T00:00:00Z");

 @Override protected @NonNull TotpStore newStore(){
  return new ScriptedTotpStore("conformance-accounts","conformance-epoch-one",NOW);
 }
 @Override protected @NonNull TotpStore newStoreWithEntryLimit(int maximumEntries){
  return new ScriptedTotpStore("conformance-accounts","conformance-epoch-one",NOW,maximumEntries,268435456L);
 }
 @Override protected void provisionSecondEpoch(@NonNull TotpStore store){
  org.junit.jupiter.api.Assertions.assertEquals(TotpStoreCommitResult.COMMITTED,
    ((ScriptedTotpStore)store).provisionRecoveryEpoch("conformance-epoch-two",Duration.ofSeconds(5)));
 }
 @Override protected void setAuthorityTime(@NonNull TotpStore store,@NonNull Instant time){
  ((ScriptedTotpStore)store).setTime(time);
 }
 @Override protected void setAuthorityHealthy(@NonNull TotpStore store,boolean healthy){
  ((ScriptedTotpStore)store).setHealthy(healthy);
 }
 @Override protected void rotateClockGeneration(@NonNull TotpStore store){
  ((ScriptedTotpStore)store).rotateClockGeneration();
 }
}
