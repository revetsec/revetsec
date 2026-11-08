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
import com.revetsec.testing.IndependentAccountWorkload;
import org.jspecify.annotations.NonNull;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Actual volatile backend with declared elapsed delay and concurrent pure-query traffic. */
final class TotpIndependentAccountClockTests {
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scBound03RealDelayedIndependentAccountsWithStatusPoller(){
  return List.of(cell(8),cell(16));
 }
 private static org.junit.jupiter.api.@NonNull DynamicTest cell(int count){return org.junit.jupiter.api.DynamicTest.dynamicTest("SC-BOUND-03/TOTP/accounts="+count,()->run(count));}
 private static void run(int count)throws Exception{
  String namespace="bound03-totp",epoch="epoch-one";var root=TotpStoreKey.forNamespace(namespace,epoch);var work=new IndependentAccountWorkload(count);
  var delegate=InMemoryTotpStore.withNamespace(namespace,epoch).maximumEntries(1024).maximumSealedBytes(16_777_216L).build();var trace=new AtomicBoolean();List<TotpStoreWrite> writes=new CopyOnWriteArrayList<>();var conflicts=new AtomicInteger();
  TotpStore store=new TotpStore(){
   @Override public @NonNull TotpStoreReadResult read(@NonNull Set<@NonNull TotpStoreKey> keys,@NonNull Duration budget){return delegate.read(keys,work.beforeBackend(budget));}
   @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(@NonNull TotpStoreWrite write,@NonNull Duration budget){Duration left=work.beforeBackend(budget);if(trace.get())writes.add(write);var result=delegate.compareAndCommit(write,left);if(result.getStatus()==TotpStoreCommitResult.CONFLICT)conflicts.incrementAndGet();return result;}
  };
  var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).maximumSealedLength(16_384).build();
  TotpRecoveryGate gate=(context,budget)->new TotpRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){}};
  var totp=TotpAuthenticator.withIssuer("Independent accounts").credentialNamespace(namespace).recoveryEpoch(epoch).store(store).stateSealer(sealer).clock(Clock.systemUTC()).recoveryGate(gate).operationTimeout(IndependentAccountWorkload.budget()).build();assertInstanceOf(TotpNamespaceInitializationResult.Initialized.class,totp.initializeNamespaceResult());var before=record(delegate,root);trace.set(true);
  work.run("TOTP",()->assertInstanceOf(TotpStatusResult.Absent.class,totp.getStatusResult("poller-account")),n->assertInstanceOf(TotpEnrollmentRequestResult.Prepared.class,totp.beginEnrollmentResult(TotpEnrollmentOptions.withAccountId("account-"+n).accountName("person@example.test").build(),"browser")));
  assertEquals(count,writes.size());assertEquals(0,conflicts.get());assertEquals(before.getVersion(),record(delegate,root).getVersion());assertArrayEquals(before.getSealedBytes(),record(delegate,root).getSealedBytes());
  for(var write:writes){assertEquals(TotpStoreWrite.Purpose.UPDATE,write.getPurpose());assertEquals(1,write.getMutations().size());assertEquals(TotpStoreKey.Kind.ACCOUNT_STATE,write.getMutations().get(0).getKey().getKind());var predicate=assertInstanceOf(TotpStoreEntry.Present.class,write.getSnapshot().getEntry(root));assertEquals(before.getVersion(),predicate.getRecord().getVersion());assertEquals(Set.of(root,write.getMutations().get(0).getKey()),write.getSnapshot().getEntries().keySet());assertInstanceOf(TotpStoreEntry.Absent.class,write.getSnapshot().getEntry(write.getMutations().get(0).getKey()));}
 }
 private static @NonNull TotpStoreRecord record(@NonNull TotpStore store,@NonNull TotpStoreKey key){return assertInstanceOf(TotpStoreEntry.Present.class,assertInstanceOf(TotpStoreReadResult.Available.class,store.read(Set.of(key),IndependentAccountWorkload.budget())).getSnapshot().getEntry(key)).getRecord();}
}
