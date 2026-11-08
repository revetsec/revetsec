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

package com.revetsec.internal.webauthn;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.testing.IndependentAccountWorkload;
import com.revetsec.webauthn.*;
import org.jspecify.annotations.NonNull;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Actual volatile backend; global atomic protection is not a nonblocking/backend-profile claim. */
final class WebAuthnIndependentAccountClockTests {
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scBound03RealDelayedIndependentAccountsWithListPoller(){return List.of(cell(8),cell(16));}
 private static org.junit.jupiter.api.@NonNull DynamicTest cell(int count){return org.junit.jupiter.api.DynamicTest.dynamicTest("SC-BOUND-03/WEBAUTHN/accounts="+count,()->run(count));}
 private static void run(int count)throws Exception{
  String namespace="bound03-wa",rp="login.example.test";var root=WebAuthnStoreKey.forNamespaceClock(namespace,rp);var work=new IndependentAccountWorkload(count);var delegate=InMemoryWebAuthnStore.fromLimits(1024,16_777_216L);var trace=new AtomicBoolean();List<WebAuthnStoreWrite> writes=new CopyOnWriteArrayList<>();var conflicts=new AtomicInteger();java.util.Map<WebAuthnStoreKey,byte[]> handles=new java.util.concurrent.ConcurrentHashMap<>();
  WebAuthnStore store=new WebAuthnStore(){
   @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){return delegate.read(keys,work.beforeBackend(budget));}
   @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){Duration left=work.beforeBackend(budget);if(trace.get())writes.add(write);var result=delegate.compareAndCommit(write,left);if(result.getStatus()==WebAuthnStoreCommitResult.CONFLICT)conflicts.incrementAndGet();return result;}
  };
  var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).maximumSealedLength(16_384).build();WebAuthnRecoveryGate gate=budget->new WebAuthnRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){}};
  var engine=new WebAuthnEngine(namespace,rp,Set.of("https://"+rp),store,sealer,gate,Clock.systemUTC(),WebAuthnSettings.builder().operationTimeout(IndependentAccountWorkload.budget()).build());byte[] binding=new byte[32],pollHandle={90};assertEquals(WebAuthnEngine.Status.PREPARED,engine.beginRegistration(pollHandle,binding).status());var before=record(delegate,root);trace.set(true);
  work.run("WEBAUTHN",()->assertEquals(WebAuthnEngine.ManagementStatus.LISTED,engine.listCredentials(pollHandle).status()),n->{byte[] handle={(byte)(n+1)};var result=engine.beginRegistration(handle,binding);assertEquals(WebAuthnEngine.Status.PREPARED,result.status());handles.put(WebAuthnStoreKey.forCeremony(namespace,rp,java.util.Objects.requireNonNull(result.request()).ceremonyId()),handle);});
  var mutations=writes.stream().filter(w->!w.getMutations().isEmpty()).toList();assertEquals(count,mutations.size());assertEquals(0,conflicts.get());assertArrayEquals(before.getVersion(),record(delegate,root).getVersion());assertArrayEquals(before.getSealedBytes(),record(delegate,root).getSealedBytes());
  for(var write:writes){var predicate=assertInstanceOf(WebAuthnStoreEntry.Present.class,write.getSnapshot().getEntry(root));assertArrayEquals(before.getVersion(),predicate.getVersion());if(write.getMutations().isEmpty()){assertEquals(Set.of(root,WebAuthnStoreKey.forAccountFence(namespace,rp,pollHandle),WebAuthnStoreKey.forAccountCredentialIndex(namespace,rp,pollHandle)),write.getSnapshot().getEntries().keySet());}else{assertEquals(1,write.getMutations().size());var ceremony=write.getMutations().get(0).getKey();assertEquals(WebAuthnStoreKey.Kind.CEREMONY,ceremony.getKind());byte[] handle=java.util.Objects.requireNonNull(handles.get(ceremony));var fence=WebAuthnStoreKey.forAccountFence(namespace,rp,handle);var index=WebAuthnStoreKey.forAccountCredentialIndex(namespace,rp,handle);assertEquals(Set.of(root,ceremony,fence,index),write.getSnapshot().getEntries().keySet());for(var absent:List.of(ceremony,fence,index))assertInstanceOf(WebAuthnStoreEntry.Absent.class,write.getSnapshot().getEntry(absent));}}
 }
 private static WebAuthnStoreEntry.@NonNull Present record(@NonNull WebAuthnStore store,@NonNull WebAuthnStoreKey key){return assertInstanceOf(WebAuthnStoreEntry.Present.class,assertInstanceOf(WebAuthnStoreReadResult.Available.class,store.read(Set.of(key),IndependentAccountWorkload.budget())).getSnapshot().getEntry(key));}
}
