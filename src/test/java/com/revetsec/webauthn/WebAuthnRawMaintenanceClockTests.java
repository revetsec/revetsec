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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeRules;
import com.revetsec.internal.webauthn.WebAuthnRawMaintenanceInspector;
import com.revetsec.testing.ScriptedWebAuthnStore;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Actual public raw acknowledgements retain known effect after late return; pre-call time is mandatory. */
final class WebAuthnRawMaintenanceClockTests {
 private static final @NonNull Instant BASE=Instant.parse("2026-11-06T12:00:00Z");
 private static final @NonNull Duration ORIGINAL=Duration.ofMillis(100),HOLD=Duration.ofMillis(150);
 private static final @NonNull String NAMESPACE="raw-maintenance",RP="login.example.test",BINDING="A".repeat(43);
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scPub05PublicRawResealRetainsLateKnownCommitWithoutNormalReadmission(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(String mode:List.of("HEALTHY","UTC","WORKER","BOTH"))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-PUB-05/WEBAUTHN/public-raw-late/"+mode,()->late(mode)));return cases;
 }
 @org.junit.jupiter.api.TestFactory
 @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scPub05PublicRawResealCannotEnterDuringInitialTimeOrWorkerFailure(){
  List<org.junit.jupiter.api.DynamicTest> cases=new ArrayList<>();for(boolean worker:List.of(false,true))cases.add(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-PUB-05/WEBAUTHN/raw-pre-call/worker="+worker,()->{
   F f=new F();var before=f.source.records();if(worker)f.worker.broken.set(true);else f.source.setHealthy(false);var receipt=f.party(ORIGINAL).resealStoreEntry(f.key);assertEquals(WebAuthnStoreCommitResult.UNAVAILABLE,receipt.getStatus());assertTrue(receipt.getTiming().isEmpty());assertEquals(0,f.store.commits.get());assertEquals(1,f.store.reads.get());assertEquals(before,f.source.records());assertEquals(1,f.gate.acquires.get());assertEquals(1,f.gate.closes.get());
  }));return cases;
 }
 private static void late(@NonNull String mode)throws Exception{
  F f=new F();var before=Map.copyOf(f.source.records());var old=requireNonNull(before.get(f.key));var facts=WebAuthnRawMaintenanceInspector.namespaceFacts(f.sealer,f.key,old.getSealedBytes(),Clock.fixed(BASE,ZoneOffset.UTC));var actual=new AtomicReference<@Nullable WebAuthnStoreCommitReceipt>();var held=new AtomicLong();
  f.store.afterCommit=receipt->{assertEquals(WebAuthnStoreCommitResult.COMMITTED,receipt.getStatus());var timing=receipt.getTiming().orElseThrow();assertTrue(timing.getCompletedTime().isEmpty());assertEquals(BASE,timing.getValidatedTime().getObservedAt());actual.set(receipt);f.worker.afterCommit.set(true);if(mode.equals("UTC")||mode.equals("BOTH"))f.source.setHealthy(false);if(mode.equals("WORKER")||mode.equals("BOTH"))f.worker.broken.set(true);long start=System.nanoTime(),left;while((left=HOLD.toNanos()-(System.nanoTime()-start))>0){LockSupport.parkNanos(left);assertFalse(Thread.currentThread().isInterrupted());}held.set(System.nanoTime()-start);};
  long start=System.nanoTime();var returned=f.party(ORIGINAL).resealStoreEntry(f.key);long elapsed=System.nanoTime()-start;assertSame(requireNonNull(actual.get()),returned);assertEquals(WebAuthnStoreCommitResult.COMMITTED,returned.getStatus());assertTrue(returned.getTiming().orElseThrow().getCompletedTime().isEmpty());assertTrue(held.get()>=HOLD.toNanos());assertTrue(elapsed>=HOLD.toNanos());assertTrue(elapsed>ORIGINAL.toNanos());assertEquals(1,f.store.reads.get());assertEquals(1,f.store.commits.get());assertEquals(0,f.worker.callsAfterCommit.get());assertEquals(1,f.gate.acquires.get());assertEquals(1,f.gate.closes.get());assertEquals(List.of(Set.of(f.key)),f.store.readSets);var write=requireNonNull(f.store.write.get());assertEquals(Set.of(f.key),write.getSnapshot().getEntries().keySet());assertEquals(1,write.getMutations().size());assertEquals(f.key,write.getMutations().get(0).getKey());var next=requireNonNull(f.source.records().get(f.key));assertFalse(java.util.Arrays.equals(old.getVersion(),next.getVersion()));assertEquals(facts,WebAuthnRawMaintenanceInspector.namespaceFacts(f.sealer,f.key,next.getSealedBytes(),Clock.fixed(BASE,ZoneOffset.UTC)));for(var entry:before.entrySet())if(!entry.getKey().equals(f.key)){var unchanged=requireNonNull(f.source.records().get(entry.getKey()));assertArrayEquals(entry.getValue().getVersion(),unchanged.getVersion());assertArrayEquals(entry.getValue().getSealedBytes(),unchanged.getSealedBytes());}assertEquals("WebAuthnStoreCommitReceipt{receipt=<redacted>}",returned.toString());System.out.println("SC-PUB-05 mode="+mode+" originalBudgetNanos="+ORIGINAL.toNanos()+" heldAfterCommitNanos="+held.get()+" totalElapsedNanos="+elapsed);
 }
 @FunctionalInterface private interface AfterCommit {void apply(@NonNull WebAuthnStoreCommitReceipt receipt);}
 @ThreadSafe private static final class Store implements WebAuthnStore {
  private final @NonNull ScriptedWebAuthnStore source;final @NonNull AtomicInteger reads=new AtomicInteger(),commits=new AtomicInteger();final @NonNull List<@NonNull Set<@NonNull WebAuthnStoreKey>> readSets=new java.util.concurrent.CopyOnWriteArrayList<>();final @NonNull AtomicReference<@Nullable WebAuthnStoreWrite> write=new AtomicReference<>();volatile @Nullable AfterCommit afterCommit;
  Store(@NonNull ScriptedWebAuthnStore source){this.source=source;}
  @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){long start=System.nanoTime();var result=this.source.read(keys,budget);this.reads.incrementAndGet();this.readSets.add(keys);if(result instanceof WebAuthnStoreReadResult.Available available&&available.getSnapshot().getTimeObservation() instanceof StoreTimeObservation.Healthy healthy){Duration elapsed=Duration.ofNanos(System.nanoTime()-start);assertTrue(StoreTimeRules.isWorkerClockHealthy(healthy,BASE,elapsed.plusMillis(250)),"Initial metadata must be causally eligible with250ms scheduling reserve before raw timing is tested");}return result;}
  @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){assertFalse(budget.isZero()||budget.isNegative());this.commits.incrementAndGet();this.write.set(write);var receipt=this.source.compareAndCommit(write,budget);AfterCommit hook=this.afterCommit;if(hook!=null)hook.apply(receipt);return receipt;}
  void reset(){this.reads.set(0);this.commits.set(0);this.readSets.clear();this.write.set(null);this.afterCommit=null;}
 }
 @ThreadSafe private static final class Worker extends Clock {
  final @NonNull AtomicBoolean broken=new AtomicBoolean(),afterCommit=new AtomicBoolean();final @NonNull AtomicInteger callsAfterCommit=new AtomicInteger();
  @Override public @NonNull Instant instant(){if(this.afterCommit.get())this.callsAfterCommit.incrementAndGet();if(this.broken.get())throw new IllegalStateException("Test worker unavailable");return BASE;}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
 }
 @ThreadSafe private static final class Gate implements WebAuthnRecoveryGate {
  final @NonNull AtomicInteger acquires=new AtomicInteger(),closes=new AtomicInteger();
  @Override public @NonNull Permit acquire(@NonNull Duration budget){this.acquires.incrementAndGet();return new Permit(){private boolean closed;@Override public @NonNull Boolean isCurrent(){return !this.closed;}@Override public void close(){closes.incrementAndGet();this.closed=true;}};}
 }
 @NotThreadSafe private static final class F {
  final @NonNull ScriptedWebAuthnStore source=new ScriptedWebAuthnStore(BASE,1024,16_777_216L);final @NonNull Store store=new Store(this.source);final @NonNull Worker worker=new Worker();final @NonNull Gate gate=new Gate();final @NonNull WebAuthnStoreKey key=WebAuthnStoreKey.forNamespaceClock(NAMESPACE,RP);final @NonNull StateSealer sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).clock(Clock.fixed(BASE,ZoneOffset.UTC)).build();
  F(){assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class,party(Duration.ofSeconds(10)).beginAuthenticationResult(BINDING));this.store.reset();this.gate.acquires.set(0);this.gate.closes.set(0);}
  @NonNull WebAuthnRelyingParty party(@NonNull Duration budget){return WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Raw maintenance").credentialNamespace(NAMESPACE).allowedOrigins(Set.of("https://"+RP)).store(this.store).stateSealer(this.sealer).recoveryGate(this.gate).clockForTesting(this.worker).settings(WebAuthnSettings.builder().operationTimeout(budget).build()).build();}
 }
}
