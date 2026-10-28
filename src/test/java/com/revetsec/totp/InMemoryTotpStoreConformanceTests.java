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
import org.jspecify.annotations.NonNull;

import static org.junit.jupiter.api.Assertions.assertEquals;

@javax.annotation.concurrent.NotThreadSafe
final class InMemoryTotpStoreConformanceTests extends TotpStoreConformanceTests {
 @Override protected @NonNull TotpStore newStore() {
  return InMemoryTotpStore.withNamespace("conformance-accounts", "conformance-epoch-one").build();
 }

 @Override protected void provisionSecondEpoch(@NonNull TotpStore store) {
  assertEquals(TotpStoreCommitResult.COMMITTED,
    ((InMemoryTotpStore) store).provisionRecoveryEpoch("conformance-epoch-two", Duration.ofSeconds(5)));
 }
}
