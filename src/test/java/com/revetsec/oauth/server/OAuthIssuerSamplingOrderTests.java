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

package com.revetsec.oauth.server;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.http.Deadline;
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

/** Actual Coordinator subject operations with declared atomic realtime authority, not native/backend qualification. */
final class OAuthIssuerSamplingOrderTests {
 @org.junit.jupiter.api.TestFactory @NonNull List<org.junit.jupiter.api.@NonNull DynamicTest> scApi11EarlierCapturedReplyCanFollowNewerCompletedIndependentWork(){return List.of(org.junit.jupiter.api.DynamicTest.dynamicTest("SC-API-11/ISSUER-coordinator/reverse-delivery",OAuthIssuerSamplingOrderTests::run));}
 private static void run()throws Exception{
  Clock clock=Clock.systemUTC();var order=new CapturedReadOrder();var delegate=new OAuthAtomicStoreFixture(clock.instant());List<OAuthStoreTransaction> transactions=new CopyOnWriteArrayList<>();var sealer=StateSealer.withActiveKey(SealingKey.fromBase64("key","AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).build();var codec=new OAuthStoreRecordCodec("https://issuer.example/order",sealer,3800);
  OAuthAuthorizationServerStore store=new OAuthAuthorizationServerStore(){
   @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key,@NonNull Duration budget){long began=System.nanoTime();OAuthStoreReadResult result;synchronized(delegate.rows){delegate.authorityNow=clock.instant();result=delegate.read(key,budget);}if(result instanceof OAuthStoreReadResult.Available available)order.observed(available.getTimeObservation(),began);return result;}
   @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget){if(order.isArmed())transactions.add(transaction);synchronized(delegate.rows){delegate.authorityNow=clock.instant();return delegate.commit(transaction,budget);}}
  };
  var coordinator=new OAuthStoreCoordinator(store,codec,clock,3,255);assertEquals(OAuthStoreCommitStatus.COMMITTED,coordinator.initializeFreshIssuerResult(deadline()).getStatus());var before=requireNonNull(delegate.rows.get(codec.issuerKey()));var pool=Executors.newSingleThreadExecutor();order.arm();
  try{var older=pool.submit(()->coordinator.establishNewSubject("older",deadline()));order.awaitCaptured();IndependentAccountWorkload.pauseAtLeast(Duration.ofMillis(1));assertNotNull(assertDoesNotThrow(()->coordinator.establishNewSubject("newer",deadline())));assertFalse(older.isDone());order.newerCompleted();order.releaseNormally(clock.instant());assertNotNull(assertDoesNotThrow(()->older.get(10,TimeUnit.SECONDS)));}finally{order.releaseFinally();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}
  order.assertOrder("ISSUER-coordinator-fixture");assertEquals(2,transactions.size());assertEquals(3,delegate.rows.size());assertEquals(before.getVersion(),requireNonNull(delegate.rows.get(codec.issuerKey())).getVersion());assertEquals(before.toSealedForm(),requireNonNull(delegate.rows.get(codec.issuerKey())).toSealedForm());Set<OAuthStoreKey> subjects=Set.of(codec.subjectKey("older"),codec.subjectKey("newer"));for(var transaction:transactions){assertEquals(OAuthStoreTransaction.Purpose.TIMED,transaction.getPurpose());assertEquals(1,transaction.getMutations().size());var subject=transaction.getMutations().get(0).getKey();assertTrue(subjects.contains(subject));assertEquals(Set.of(codec.issuerKey(),subject),transaction.getConditions().stream().map(c->c.getKey()).collect(java.util.stream.Collectors.toSet()));for(var condition:transaction.getConditions())assertEquals(condition.getKey().equals(subject)?java.util.Optional.empty():java.util.Optional.of(before.getVersion()),condition.getExpectedVersion());}
 }
 private static @NonNull Deadline deadline(){return Deadline.fromNow(Duration.ofSeconds(10));}
}
