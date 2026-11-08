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

import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAccumulator;
import java.util.concurrent.locks.LockSupport;
import java.util.function.IntConsumer;
import static org.junit.jupiter.api.Assertions.*;

/** Test-only bounded schedule; declares delay outside backend protection, not a throughput target. */
@ThreadSafe
public final class IndependentAccountWorkload {
 private static final @NonNull Duration BUDGET=Duration.ofSeconds(10);
 private enum Role { SETUP, WORKER, POLLER }
 private final @NonNull ThreadLocal<@NonNull Role> role=ThreadLocal.withInitial(()->Role.SETUP);
 private final @NonNull ThreadLocal<@NonNull Boolean> firstBackend=ThreadLocal.withInitial(()->true);
 private final @NonNull ThreadLocal<@NonNull Duration> previousBudget=ThreadLocal.withInitial(()->BUDGET.plusNanos(1));
 private final @NonNull CountDownLatch workersAtBackend,initialPoll=new CountDownLatch(1);
 private final @NonNull AtomicBoolean running=new AtomicBoolean();
 private final @NonNull AtomicInteger callbacks=new AtomicInteger(),polls=new AtomicInteger(),budgetViolations=new AtomicInteger();
 private final @NonNull LongAccumulator minimumDelay=new LongAccumulator(Long::min,Long.MAX_VALUE);
 private final @NonNull List<@NonNull Long> operationNanos=new java.util.concurrent.CopyOnWriteArrayList<>();
 private final int count;
 public IndependentAccountWorkload(int count){if(count!=8&&count!=16)throw new IllegalArgumentException("Fixed workload count required");this.count=count;this.workersAtBackend=new CountDownLatch(count);}
 public static @NonNull Duration budget(){return BUDGET;}
 /** Runs before the delegate's monitor/lock and returns the caller's strictly smaller remaining budget. */
 public @NonNull Duration beforeBackend(@NonNull Duration budget){
  long start=System.nanoTime();Role current=this.role.get();
  if(this.running.get()&&current==Role.WORKER){
   if(budget.compareTo(this.previousBudget.get())>=0)this.budgetViolations.incrementAndGet();this.previousBudget.set(budget);
   if(this.firstBackend.get()){this.firstBackend.set(false);this.workersAtBackend.countDown();await(this.initialPoll);}
  }
  pauseAtLeast(Duration.ofMillis(1));long elapsed=System.nanoTime()-start;assertTrue(elapsed>=1_000_000L);Duration remaining=budget.minusNanos(elapsed);assertTrue(!remaining.isNegative()&&!remaining.isZero(),"Declared sufficient budget exhausted at delayed backend boundary");
  if(this.running.get()){this.callbacks.incrementAndGet();this.minimumDelay.accumulate(elapsed);}return remaining;
 }
 public void run(@NonNull String family,@NonNull Runnable poll,@NonNull IntConsumer operation)throws Exception{
  var pool=Executors.newFixedThreadPool(this.count+1);var start=new CountDownLatch(1);var ready=new CountDownLatch(this.count+1);var done=new AtomicBoolean();long began=System.nanoTime();this.running.set(true);
  try{
   var poller=pool.submit(()->{this.role.set(Role.POLLER);try{ready.countDown();await(start);await(this.workersAtBackend);poll.run();this.polls.incrementAndGet();this.initialPoll.countDown();while(!done.get()){poll.run();this.polls.incrementAndGet();}}finally{this.initialPoll.countDown();this.role.remove();}});
   List<java.util.concurrent.Future<?>> workers=new ArrayList<>();
   for(int n=0;n<this.count;n++){int index=n;workers.add(pool.submit(()->{this.role.set(Role.WORKER);try{ready.countDown();await(start);long before=System.nanoTime();operation.accept(index);this.operationNanos.add(System.nanoTime()-before);}finally{this.role.remove();this.firstBackend.remove();this.previousBudget.remove();}}));}
   await(ready);start.countDown();for(var worker:workers)result(worker);done.set(true);result(poller);
  }finally{done.set(true);start.countDown();this.initialPoll.countDown();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));this.running.set(false);}
  assertEquals(0,this.budgetViolations.get(),"Every actual callback must retain the shrinking original operation budget");assertEquals(this.count,this.operationNanos.size());assertTrue(this.polls.get()>=1);assertTrue(this.callbacks.get()>this.count);assertTrue(this.minimumDelay.get()>=1_000_000L);
  System.out.println("SC-BOUND-03 family="+family+" accounts="+this.count+" pollCalls="+this.polls.get()+" backendCalls="+this.callbacks.get()+" elapsedNanos="+(System.nanoTime()-began)+" minCallbackDelayNanos="+this.minimumDelay.get()+" operationNanos="+this.operationNanos);
 }
 public static void pauseAtLeast(@NonNull Duration duration){long end=System.nanoTime()+duration.toNanos();long left;while((left=end-System.nanoTime())>0){LockSupport.parkNanos(left);assertFalse(Thread.currentThread().isInterrupted());}}
 private static void result(java.util.concurrent.@NonNull Future<?> future)throws Exception{try{future.get(20,TimeUnit.SECONDS);}catch(java.util.concurrent.ExecutionException failure){if(failure.getCause() instanceof AssertionError assertion)throw assertion;throw failure;}}
 private static void await(@NonNull CountDownLatch latch){try{assertTrue(latch.await(5,TimeUnit.SECONDS),"Bounded declared schedule did not reach checkpoint");}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new AssertionError("Declared schedule interrupted");}}
}
