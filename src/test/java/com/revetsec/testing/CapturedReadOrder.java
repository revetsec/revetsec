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

package com.revetsec.testing;

import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeRules;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Actual metadata capture precedes the controlled reply delay; no source order is inferred from delivery. */
@ThreadSafe
public final class CapturedReadOrder {
 private final @NonNull AtomicBoolean armed=new AtomicBoolean(),first=new AtomicBoolean();
 private final @NonNull CountDownLatch captured=new CountDownLatch(1),release=new CountDownLatch(1);
 private final @NonNull AtomicReference<StoreTimeObservation.@Nullable Healthy> older=new AtomicReference<>(),latest=new AtomicReference<>();
 private final @NonNull AtomicLong began=new AtomicLong();
 private final @NonNull List<StoreTimeObservation.@NonNull Healthy> observations=new CopyOnWriteArrayList<>();
 private final @NonNull List<@NonNull String> events=new CopyOnWriteArrayList<>();
 public void arm(){this.armed.set(true);}
 public boolean isArmed(){return this.armed.get();}
 public void observed(@NonNull StoreTimeObservation observation,long callBegan){
  if(!this.armed.get())return;var healthy=assertInstanceOf(StoreTimeObservation.Healthy.class,observation);this.observations.add(healthy);
  if(this.first.compareAndSet(false,true)){this.older.set(healthy);this.began.set(callBegan);this.events.add("older-captured");this.captured.countDown();await(this.release);this.events.add("older-delivered");}
  else{this.latest.set(healthy);this.events.add("later-sample");}
 }
 public void awaitCaptured(){await(this.captured);}
 public void newerCompleted(){assertEquals(1L,this.release.getCount());assertTrue(requireNonNull(this.latest.get()).getObservedAt().isAfter(older().getObservedAt()),"Real producer must sample newer time before reverse delivery is tested");this.events.add("newer-completed");}
 public void releaseNormally(@NonNull Instant workerNow){
  Duration span=Duration.ofNanos(System.nanoTime()-this.began.get());
  // Reserve another250ms for actual release/scheduling: a legitimate over-age sample is a fixture-precondition failure.
  assertTrue(StoreTimeRules.isWorkerClockHealthy(older(),workerNow,span.plusMillis(250)),"Causal-health precondition lost before release; no false-rollback claim is valid");
  this.events.add("older-released");this.release.countDown();System.out.println("SC-API-11 causalSpanNanos="+span.toNanos()+" sourceErrorNanos="+older().getMaximumUtcError().toNanos());
 }
 public void releaseFinally(){this.release.countDown();}
 public StoreTimeObservation.@NonNull Healthy older(){return requireNonNull(this.older.get());}
 public void assertOrder(@NonNull String family){assertTrue(this.events.indexOf("older-captured")<this.events.indexOf("newer-completed"));assertTrue(this.events.indexOf("newer-completed")<this.events.indexOf("older-released"));assertTrue(this.events.indexOf("older-released")<this.events.indexOf("older-delivered"));for(var sample:this.observations){assertEquals(older().getAdmission().getAuthorityId(),sample.getAdmission().getAuthorityId());assertEquals(older().getAdmission().getRecoveryGeneration(),sample.getAdmission().getRecoveryGeneration());assertEquals(older().getClockGeneration(),sample.getClockGeneration());assertEquals(older().getMaximumUtcError(),sample.getMaximumUtcError());}System.out.println("SC-API-11 family="+family+" events="+this.events);}
 private static void await(@NonNull CountDownLatch latch){try{assertTrue(latch.await(5,TimeUnit.SECONDS),"Bounded controlled reply checkpoint unavailable");}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new AssertionError("Reply-order control interrupted");}}
}
