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

import java.time.Instant;
import org.jspecify.annotations.NonNull;

@javax.annotation.concurrent.NotThreadSafe
final class InMemoryWebAuthnStoreConformanceTests extends WebAuthnStoreConformanceTests {
 @Override protected @NonNull WebAuthnStore newStore(){return InMemoryWebAuthnStore.fromLimits(16,10000L);}
 @Override protected @NonNull WebAuthnStore newStoreWithEntryLimit(int maximumEntries){
  return InMemoryWebAuthnStore.fromLimits(maximumEntries,10000L);
 }
 @Override protected void advanceAuthorityPast(@NonNull WebAuthnStore store,@NonNull Instant exclusiveEnd)
   throws InterruptedException {Thread.sleep(1);}
}
