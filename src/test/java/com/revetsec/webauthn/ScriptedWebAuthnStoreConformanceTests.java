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
package com.revetsec.webauthn;

import com.revetsec.testing.ScriptedWebAuthnStore;
import java.time.Instant;
import org.jspecify.annotations.NonNull;

@javax.annotation.concurrent.NotThreadSafe
final class ScriptedWebAuthnStoreConformanceTests extends WebAuthnControlledStoreConformanceTests {
 private static final @NonNull Instant NOW=Instant.parse("2026-10-04T00:00:00Z");

 @Override protected @NonNull WebAuthnStore newStore(){return new ScriptedWebAuthnStore(NOW);}
 @Override protected @NonNull WebAuthnStore newStoreWithEntryLimit(int maximumEntries){
  return new ScriptedWebAuthnStore(NOW,maximumEntries,268435456L);
 }
 @Override protected void advanceAuthorityPast(@NonNull WebAuthnStore store,@NonNull Instant exclusiveEnd){
  ((ScriptedWebAuthnStore)store).setTime(exclusiveEnd);
 }
 @Override protected void setAuthorityTime(@NonNull WebAuthnStore store,@NonNull Instant time){
  ((ScriptedWebAuthnStore)store).setTime(time);
 }
 @Override protected void setAuthorityHealthy(@NonNull WebAuthnStore store,boolean healthy){
  ((ScriptedWebAuthnStore)store).setHealthy(healthy);
 }
 @Override protected void rotateClockGeneration(@NonNull WebAuthnStore store){
  ((ScriptedWebAuthnStore)store).rotateClockGeneration();
 }
 @Override protected void rotateRecoveryGeneration(@NonNull WebAuthnStore store){
  ((ScriptedWebAuthnStore)store).rotateRecoveryGeneration();
 }
}
