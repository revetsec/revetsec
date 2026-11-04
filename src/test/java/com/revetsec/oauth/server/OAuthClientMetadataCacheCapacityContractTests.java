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

import com.revetsec.internal.ConcurrentLruMap;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Stream;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Entry publication is observed inside the actual wrapper lock, not sampled only after quiescence. */
final class OAuthClientMetadataCacheCapacityContractTests {
 private static final @NonNull Duration BUDGET=Duration.ofSeconds(30);
 private static @NonNull String nonce(int value){return Base64.getUrlEncoder().withoutPadding().encodeToString(ByteBuffer.allocate(32).putInt(value).array());}
 private static @NonNull OAuthClientMetadataCacheKey key(int value){return OAuthClientMetadataCacheKey.fromStoredForm("revetsec:cimd-cache:1:"+nonce(1)+":"+nonce(value));}
 private static @NonNull OAuthClientMetadataCacheEntry entry(int key,int version,@NonNull String body){return OAuthClientMetadataCacheEntry.fromStoredForm(key(key),nonce(version),Instant.parse("2026-11-03T12:00:00Z"),body);}
 private static final class CheckingMap extends ConcurrentLruMap<@NonNull OAuthClientMetadataCacheKey,@NonNull OAuthClientMetadataCacheEntry> {
  final @NonNull ReentrantLock owner;final int limit;final @NonNull AtomicInteger peak=new AtomicInteger(),calls=new AtomicInteger(),pending;
  CheckingMap(int limit,@NonNull ReentrantLock owner) throws Exception {super(limit);this.limit=limit;this.owner=owner;var f=ConcurrentLruMap.class.getDeclaredField("writeBufferSize");f.setAccessible(true);this.pending=(AtomicInteger)requireNonNull(f.get(this));}
  void checked(){assertTrue(this.owner.isHeldByCurrentThread(),"Raw cache access escaped the wrapper lock");this.calls.incrementAndGet();}
  @Override public @Nullable OAuthClientMetadataCacheEntry get(@NonNull Object key){checked();return super.get(key);}
  @Override public int size(){checked();return super.size();}
  @Override public @Nullable OAuthClientMetadataCacheEntry put(@NonNull OAuthClientMetadataCacheKey key,@NonNull OAuthClientMetadataCacheEntry value){checked();if(!super.containsKey(key))assertTrue(super.size()<this.limit,"New entry was published before capacity admission");var old=super.put(key,value);int size=super.size();assertTrue(size<=this.limit);this.peak.accumulateAndGet(size,Math::max);return old;}
  @Override public @Nullable OAuthClientMetadataCacheEntry remove(@NonNull Object key){checked();return super.remove(key);}
  @Override public void drain(){checked();super.drain();assertEquals(0,this.pending.get());}
  @Override public @NonNull List<@NonNull OAuthClientMetadataCacheKey> keysInAccessOrder(){checked();return super.keysInAccessOrder();}
 }
 private record F(@NonNull InMemoryOAuthClientMetadataCache cache,@NonNull CheckingMap map){}
 private static @NonNull F fixture(int limit) throws Exception {var cache=InMemoryOAuthClientMetadataCache.fromMaximumEntries(limit);var map=new CheckingMap(limit,cache.lockForTests());var field=InMemoryOAuthClientMetadataCache.class.getDeclaredField("entries");field.setAccessible(true);field.set(cache,map);return new F(cache,map);}
 private static void bounded(@NonNull F f){var lock=f.cache().lockForTests();lock.lock();try{assertTrue(f.map().size()<=f.cache().getMaximumEntries());assertEquals(0,f.map().pending.get());}finally{lock.unlock();}}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> everyPublicationAndMutationRetainsTheConfiguredEntryBound(){return Stream.of(1,2,16,128,4096).flatMap(limit->Stream.of(1,16384).map(length->DynamicTest.dynamicTest("capacity="+limit+" envelope="+length,()->{
  F f=fixture(limit);String body="A".repeat(length);
  for(int i=0;i<limit+32;i++){var entry=entry(i,10000+i,body);assertTrue(f.cache().compareAndSet(entry.getKey(),null,entry,BUDGET));bounded(f);}
  assertEquals(limit,f.cache().sizeForTests());assertEquals(limit,f.map().peak.get());int last=limit+31;var current=f.cache().read(key(last),BUDGET).orElseThrow();var replacement=entry(last,20000+last,body);assertTrue(f.cache().compareAndSet(key(last),current.getVersion(),replacement,BUDGET));bounded(f);assertEquals(limit,f.cache().sizeForTests());assertFalse(f.cache().compareAndSet(key(last),nonce(999999),null,BUDGET));bounded(f);assertTrue(f.cache().compareAndSet(key(last),replacement.getVersion(),null,BUDGET));bounded(f);assertEquals(limit-1,f.cache().sizeForTests());assertTrue(f.map().calls.get()>0);
 })));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> competingReadersWritersAndDeletesNeverPublishOverCapacity(){return Stream.of(1,2,8).map(limit->DynamicTest.dynamicTest("capacity="+limit,()->{
  F f=fixture(limit);var pool=Executors.newFixedThreadPool(8);CountDownLatch start=new CountDownLatch(1);
  try{var jobs=new java.util.ArrayList<java.util.concurrent.Future<?>>();for(int worker=0;worker<8;worker++){int number=worker;jobs.add(pool.submit(()->{assertTrue(start.await(5,TimeUnit.SECONDS));for(int i=0;i<64;i++){int id=number*1000+i;var entry=entry(id,10000+id,"A");assertTrue(f.cache().compareAndSet(entry.getKey(),null,entry,BUDGET));f.cache().read(entry.getKey(),BUDGET).ifPresent(observed->assertEquals(entry.getVersion(),observed.getVersion()));boolean deleted=f.cache().compareAndSet(entry.getKey(),entry.getVersion(),null,BUDGET);assertTrue(deleted||f.cache().read(entry.getKey(),BUDGET).isEmpty());assertTrue(f.cache().read(entry.getKey(),BUDGET).isEmpty());bounded(f);}return null;}));}start.countDown();for(var job:jobs)assertNull(assertDoesNotThrow(()->job.get(30,TimeUnit.SECONDS)));}
  finally{pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}bounded(f);assertTrue(f.map().peak.get()<=limit);
 }));}
 @TestFactory @NonNull Stream<@NonNull DynamicTest> blockedAdmissionCannotTouchOrPublishRawEntries(){return Stream.of("read","write").flatMap(operation->Stream.of(false,true).map(interrupt->DynamicTest.dynamicTest(operation+" interrupt="+interrupt,()->{
  F f=fixture(1);var pool=Executors.newSingleThreadExecutor();CountDownLatch started=new CountDownLatch(1);java.util.concurrent.atomic.AtomicReference<Thread> caller=new java.util.concurrent.atomic.AtomicReference<>();var lock=f.cache().lockForTests();lock.lock();
  try{var job=pool.submit(()->{caller.set(Thread.currentThread());started.countDown();try{var failure=assertThrows(OAuthClientMetadataCacheException.class,()->{if(operation.equals("read")){assertNotNull(f.cache().read(key(1),interrupt?BUDGET:Duration.ofMillis(100)));}else{var e=entry(1,2,"A");assertNotNull(f.cache().compareAndSet(e.getKey(),null,e,interrupt?BUDGET:Duration.ofMillis(100)));}});assertEquals(interrupt?OAuthClientMetadataCacheException.Reason.INTERRUPTED:OAuthClientMetadataCacheException.Reason.TIMEOUT,failure.getReason());assertEquals(interrupt,Thread.currentThread().isInterrupted());return true;}finally{Thread.interrupted();}});assertTrue(started.await(5,TimeUnit.SECONDS));if(interrupt)requireNonNull(caller.get()).interrupt();assertTrue(job.get(5,TimeUnit.SECONDS));assertEquals(0,f.map().calls.get());}
  finally{lock.unlock();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS));}assertEquals(0,f.cache().sizeForTests());bounded(f);
 })));}
}
