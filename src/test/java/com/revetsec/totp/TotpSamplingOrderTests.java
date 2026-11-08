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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.testing.CapturedReadOrder;
import com.revetsec.testing.IndependentAccountWorkload;
import org.jspecify.annotations.NonNull;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Actual producer chronology and controlled reverse delivery to independent account operations. */
final class TotpSamplingOrderTests {
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi11EarlierCapturedReplyCanFollowNewerCompletedIndependentWork(){return List.of(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-11/TOTP/reverse-delivery",TotpSamplingOrderTests::run));}
 private static void run()throws Exception{
  String namespace="order-totp",epoch="epoch-one";var root=TotpStoreKey.forNamespace(namespace,epoch);var order=new CapturedReadOrder();var delegate=InMemoryTotpStore.withNamespace(namespace,epoch).maximumEntries(1024).maximumSealedBytes(16_777_216L).build();List<TotpStoreWrite> writes=new CopyOnWriteArrayList<>();
  TotpStore store=new TotpStore(){@Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget){long began=System.nanoTime();var result=delegate.read(keys,budget);if(result instanceof TotpStoreReadResult.Available available)order.observed(available.getSnapshot().getTimeObservation(),began);return result;}@Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration budget){if(order.isArmed())writes.add(write);return delegate.compareAndCommit(write,budget);}};
  var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).maximumSealedLength(16_384).build();TotpRecoveryGate gate=(context,budget)->new TotpRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){}};Clock clock=Clock.systemUTC();var totp=TotpAuthenticator.withIssuer("Sampling order").credentialNamespace(namespace).recoveryEpoch(epoch).store(store).stateSealer(sealer).clock(clock).recoveryGate(gate).operationTimeout(Duration.ofSeconds(10)).build();assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,totp.initializeNamespaceResult());var before=record(delegate,root);var pool=Executors.newSingleThreadExecutor();order.arm();
  try{var older=pool.submit(()->totp.beginEnrollmentResult(options("older"),"browser"));order.awaitCaptured();IndependentAccountWorkload.pauseAtLeast(Duration.ofMillis(1));assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,totp.beginEnrollmentResult(options("newer"),"browser"));assertFalse(older.isDone());order.newerCompleted();order.releaseNormally(clock.instant());var result=assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,older.get(10,TimeUnit.SECONDS));assertEquals(order.older().getObservedAt().plusSeconds(300),result.getEnrollment().getExpiresAt());}finally{order.releaseFinally();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}
  order.assertOrder("TOTP");assertEquals(2,writes.size());assertEquals(before.getVersion(),record(delegate,root).getVersion());assertArrayEquals(before.getSealedBytes(),record(delegate,root).getSealedBytes());Set<TotpStoreKey> accounts=Set.of(TotpStoreKey.forAccount(namespace,epoch,"older"),TotpStoreKey.forAccount(namespace,epoch,"newer"));for(var write:writes){assertEquals(1,write.getMutations().size());assertTrue(accounts.contains(write.getMutations().get(0).getKey()));assertEquals(Set.of(root,write.getMutations().get(0).getKey()),write.getSnapshot().getEntries().keySet());assertEquals(before.getVersion(),assertInstanceOf(TotpStoreEntry.Present.class,write.getSnapshot().getEntry(root)).getRecord().getVersion());}try(var decoded=new TotpRecordsV3(sealer).open(record(delegate,TotpStoreKey.forAccount(namespace,epoch,"older")))){assertEquals(order.older().getObservedAt(),requireNonNull(decoded.account).observedAt);}
 }
 private static @NonNull TotpEnrollmentOptions options(@NonNull String account){return TotpEnrollmentOptions.withAccountId(account).accountName("person@example.test").build();}
 private static @NonNull TotpStoreRecord record(@NonNull TotpStore store,@NonNull TotpStoreKey key){return assertInstanceOf(TotpStoreEntry.Present.class,assertInstanceOf(TotpStoreReadResult.Available.class,store.read(Set.of(key),Duration.ofSeconds(10))).getSnapshot().getEntry(key)).getRecord();}
}
