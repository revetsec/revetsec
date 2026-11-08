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
import com.revetsec.testing.CapturedReadOrder;
import com.revetsec.testing.IndependentAccountWorkload;
import com.revetsec.webauthn.*;
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

/** Metadata sampled by the actual volatile producer may be delivered in reverse invocation order. */
final class WebAuthnSamplingOrderTests {
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi11EarlierCapturedReplyCanFollowNewerCompletedIndependentWork(){return List.of(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-11/WEBAUTHN/reverse-delivery",WebAuthnSamplingOrderTests::run));}
 private static void run()throws Exception{
  String namespace="order-wa",rp="login.example.test";var root=WebAuthnStoreKey.forNamespaceClock(namespace,rp);var order=new CapturedReadOrder();var delegate=InMemoryWebAuthnStore.fromLimits(1024,16_777_216L);List<WebAuthnStoreWrite> writes=new CopyOnWriteArrayList<>();
  WebAuthnStore store=new WebAuthnStore(){@Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys,@NonNull Duration budget){long began=System.nanoTime();var result=delegate.read(keys,budget);if(result instanceof WebAuthnStoreReadResult.Available available)order.observed(available.getSnapshot().getTimeObservation(),began);return result;}@Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write,@NonNull Duration budget){if(order.isArmed())writes.add(write);return delegate.compareAndCommit(write,budget);}};
  var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).maximumSealedLength(16_384).build();WebAuthnRecoveryGate gate=budget->new WebAuthnRecoveryGate.Permit(){@Override public @NonNull Boolean isCurrent(){return true;}@Override public void close(){}};Clock clock=Clock.systemUTC();var engine=new WebAuthnEngine(namespace,rp,Set.of("https://"+rp),store,sealer,gate,clock,WebAuthnSettings.builder().operationTimeout(Duration.ofSeconds(10)).build());byte[] binding=new byte[32];assertEquals(WebAuthnEngine.Status.PREPARED,engine.beginRegistration(new byte[]{90},binding).status());var before=record(delegate,root);var pool=Executors.newSingleThreadExecutor();order.arm();WebAuthnEngine.Request olderRequest;
  try{var older=pool.submit(()->engine.beginRegistration(new byte[]{1},binding));order.awaitCaptured();IndependentAccountWorkload.pauseAtLeast(Duration.ofMillis(1));assertEquals(WebAuthnEngine.Status.PREPARED,engine.beginRegistration(new byte[]{2},binding).status());assertFalse(older.isDone());order.newerCompleted();order.releaseNormally(clock.instant());var result=older.get(10,TimeUnit.SECONDS);assertEquals(WebAuthnEngine.Status.PREPARED,result.status());olderRequest=requireNonNull(result.request());}finally{order.releaseFinally();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}
  order.assertOrder("WEBAUTHN");assertEquals(2,writes.size());assertArrayEquals(before.getVersion(),record(delegate,root).getVersion());assertArrayEquals(before.getSealedBytes(),record(delegate,root).getSealedBytes());for(var write:writes){assertEquals(1,write.getMutations().size());assertEquals(WebAuthnStoreKey.Kind.CEREMONY,write.getMutations().get(0).getKey().getKind());assertArrayEquals(before.getVersion(),assertInstanceOf(WebAuthnStoreEntry.Present.class,write.getSnapshot().getEntry(root)).getVersion());assertEquals(4,write.getSnapshot().getEntries().size());}var key=WebAuthnStoreKey.forCeremony(namespace,rp,olderRequest.ceremonyId());var pending=new WebAuthnCeremonyRecordCodec(namespace,rp,new WebAuthnRecordCodec(sealer)).decode(key,record(delegate,key).getSealedBytes(),clock);assertEquals(order.older().getObservedAt(),pending.issuedAt());assertEquals(order.older().getObservedAt().plusSeconds(300),pending.expiresAt());
 }
 private static WebAuthnStoreEntry.@NonNull Present record(@NonNull WebAuthnStore store,@NonNull WebAuthnStoreKey key){return assertInstanceOf(WebAuthnStoreEntry.Present.class,assertInstanceOf(WebAuthnStoreReadResult.Available.class,store.read(Set.of(key),Duration.ofSeconds(10))).getSnapshot().getEntry(key));}
}
