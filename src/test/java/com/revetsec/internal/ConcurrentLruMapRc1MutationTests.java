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

package com.revetsec.internal;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

/** Access, cleanup and callback contracts, including controlled publication races. */
final class ConcurrentLruMapRc1MutationTests {
 @Test void clearDiscardsPendingWritesAndReadReferencesWithoutCallbacks() throws Exception {
  List<Integer> evicted = new ArrayList<>();
  var map = new ConcurrentLruMap<Integer, String>(8, (key, value) -> evicted.add(key));
  map.put(1, "one"); map.put(2, "two"); map.drain();
  assertEquals("one", map.get(1));
  map.put(3, "three");
  map.clear();
  assertTrue(map.isEmpty());
  assertTrue(evicted.isEmpty());
  assertEquals(0, pending(map));
  assertTrue(((ConcurrentLinkedQueue<?>) field(map, "writeBuffer")).isEmpty());
  var reads = (AtomicReferenceArray<?>) field(map, "readBuffer");
  for (int slot = 0; slot < reads.length(); slot++) assertNull(reads.get(slot), "clear retained a read reference");
  assertFalse(lock(map).isLocked(), "clear retained maintenance ownership");
  map.put(4, "four");
  assertEquals(List.of(4), map.keysInAccessOrder());
 }

 @Test void directMapEqualityComparesMappings() {
  var map = new ConcurrentLruMap<Integer, String>(3);
  map.put(1, "one");
  assertTrue(map.equals(Map.of(1, "one")));
  assertFalse(map.equals(Map.of(1, "different")));
  assertFalse(map.equals(Map.of(2, "one")));
 }

 @Test void getOrDefaultRecordsAccess() { assertAccessPromotes(map -> assertEquals("one", map.getOrDefault(1, "missing"))); }
 @Test void putIfAbsentExistingRecordsAccess() { assertAccessPromotes(map -> assertEquals("one", map.putIfAbsent(1, "ignored"))); }
 @Test void computeIfAbsentExistingRecordsAccess() {
  assertAccessPromotes(map -> assertEquals("one", map.computeIfAbsent(1, key -> { throw new AssertionError("existing mapping was recomputed"); })));
 }

 @Test void computeIfAbsentNewMappingsEnforceCapacity() {
  List<Integer> evicted = new ArrayList<>();
  var map = new ConcurrentLruMap<Integer, String>(1, (key, value) -> evicted.add(key));
  assertEquals("one", map.computeIfAbsent(1, key -> "one"));
  assertEquals("two", map.computeIfAbsent(2, key -> "two"));
  assertEquals(1, map.size());
  assertEquals(List.of(1), evicted);
  assertEquals(List.of(2), map.keysInAccessOrder());
 }

 @Test void putIfAbsentPublishesNewMappingsToAccessOrder() {
  var map = new ConcurrentLruMap<Integer, String>(2);
  assertNull(map.putIfAbsent(1, "one"));
  assertEquals(List.of(1), map.keysInAccessOrder());
 }

 @Test void replacementRemovesOldNodeAndPromotesNewNode() {
  var map = new ConcurrentLruMap<Integer, String>(3);
  map.put(1, "one"); map.put(2, "two"); map.drain();
  assertEquals("one", map.put(1, "new"));
  map.drain();
  assertEquals(List.of(1, 2), map.keysInAccessOrder());
  assertEquals("new", map.get(1));
 }

 @Test void removalRetiresAndUnlinksTheOldNode() {
  var map = new ConcurrentLruMap<Integer, String>(3);
  map.put(1, "one"); map.put(2, "two"); map.drain();
  assertEquals("one", map.remove(1));
  map.drain();
  assertEquals(List.of(2), map.keysInAccessOrder());
  map.put(3, "three");
  assertEquals(List.of(3, 2), map.keysInAccessOrder());
 }

 @Test void writeBacklogDrainsAtItsBoundAndReleasesMaintenance() throws Exception {
  var map = new ConcurrentLruMap<Integer, String>(64);
  for (int key = 0; key < 15; key++) map.put(key, "value");
  assertEquals(15, pending(map));
  map.put(15, "value");
  assertEquals(0, pending(map));
  assertFalse(lock(map).isLocked(), "automatic maintenance retained ownership");
  assertEquals(16, map.keysInAccessOrder().size());
 }

 @Test void exactCapacityDefersWritesAndOverflowEvictsImmediately() throws Exception {
  List<Integer> evicted = new ArrayList<>();
  var map = new ConcurrentLruMap<Integer, String>(2, (key, value) -> evicted.add(key));
  map.put(1, "one"); map.put(2, "two");
  assertEquals(2, pending(map));
  assertTrue(evicted.isEmpty());
  map.put(3, "three");
  assertEquals(0, pending(map));
  assertEquals(2, map.size());
  assertEquals(List.of(1), evicted);
 }

 @Test void readBurstHelpsPendingWritesAtTheRingBoundary() throws Exception {
  var map = new ConcurrentLruMap<Integer, String>(8);
  map.put(1, "one"); map.drain();
  map.put(2, "two");
  for (int read = 0; read < 63; read++) assertEquals("one", map.get(1));
  assertEquals(1, pending(map));
  assertEquals("one", map.get(1));
  assertEquals(0, pending(map));
  assertFalse(lock(map).isLocked());
  assertEquals(List.of(2, 1), map.keysInAccessOrder());
 }

 @Test void forcedMaintenanceNotifiesDeferredEvictionsAndReleasesLock() throws Exception {
  List<Integer> evicted = new ArrayList<>();
  var map = new ConcurrentLruMap<Integer, String>(1, (key, value) -> evicted.add(key));
  deferMaintenance(map, () -> { map.put(1, "one"); map.put(2, "two"); });
  assertTrue(evicted.isEmpty());
  map.drain();
  assertEquals(List.of(1), evicted);
  assertFalse(lock(map).isLocked(), "drain retained maintenance ownership");
 }

 @Test void accessOrderMaintenanceNotifiesDeferredEvictionsAndReleasesLock() throws Exception {
  List<Integer> evicted = new ArrayList<>();
  var map = new ConcurrentLruMap<Integer, String>(1, (key, value) -> evicted.add(key));
  deferMaintenance(map, () -> { map.put(1, "one"); map.put(2, "two"); });
  assertEquals(List.of(2), map.keysInAccessOrder());
  assertEquals(List.of(1), evicted);
  assertFalse(lock(map).isLocked(), "access-order snapshot retained maintenance ownership");
 }

 @Test void allEvictionCallbacksRunAndLaterFailuresAreSuppressed() throws Exception {
  List<Integer> evicted = new ArrayList<>();
  var map = new ConcurrentLruMap<Integer, String>(1, (key, value) -> {
   evicted.add(key); throw new IllegalArgumentException("evicted " + key);
  });
  deferMaintenance(map, () -> { map.put(1, "one"); map.put(2, "two"); map.put(3, "three"); });
  IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, map::drain);
  assertEquals(List.of(1, 2), evicted);
  assertEquals("evicted 1", failure.getMessage());
  assertEquals(1, failure.getSuppressed().length);
  assertEquals("evicted 2", failure.getSuppressed()[0].getMessage());
  assertEquals(List.of(3), map.keysInAccessOrder());
  assertFalse(lock(map).isLocked());
 }

 @Test void computeRaceRecordsTheMappingInstalledByAnotherWriter() throws Exception {
  var first = new GatedKey(1); var other = new GatedKey(2);
  var map = new ConcurrentLruMap<GatedKey, String>(2);
  map.put(other, "other"); map.drain();
  AtomicReference<String> result = new AtomicReference<>();
  AtomicReference<Throwable> failure = new AtomicReference<>();
  Thread worker = thread(() -> {
   try { result.set(map.computeIfAbsent(first, key -> { throw new AssertionError("racing mapping was recomputed"); })); }
   catch (Throwable problem) { failure.set(problem); }
  });
  first.gateSecondHashFrom(worker); worker.start();
  try {
   await(first.reached);
   map.put(first, "winner"); map.drain();
   assertEquals("other", map.get(other)); map.drain();
   assertEquals(List.of(other, first), map.keysInAccessOrder());
  } finally { first.release.countDown(); join(worker); }
  assertNull(failure.get());
  assertEquals("winner", result.get());
  assertEquals(List.of(first, other), map.keysInAccessOrder());
 }

 @Test void conditionalRemoveCannotClaimAReplacedMapping() throws Exception {
  var key = new GatedKey(1);
  var map = new ConcurrentLruMap<GatedKey, String>(2);
  map.put(key, "old"); map.drain();
  AtomicReference<Boolean> removed = new AtomicReference<>();
  AtomicReference<Throwable> failure = new AtomicReference<>();
  Thread worker = thread(() -> {
   try { removed.set(map.remove(key, "old")); } catch (Throwable problem) { failure.set(problem); }
  });
  key.gateSecondHashFrom(worker); worker.start();
  try { await(key.reached); map.put(key, "new"); }
  finally { key.release.countDown(); join(worker); }
  assertNull(failure.get());
  assertEquals(Boolean.FALSE, removed.get());
  assertEquals("new", map.get(key));
 }

 @Test void evictionUnlinksAStaleVictimBeforeTryingTheNextVictim() throws Exception {
  var stale = new GatedKey(1); var victim = new GatedKey(2);
  var third = new GatedKey(3); var fourth = new GatedKey(4);
  List<GatedKey> evicted = new ArrayList<>();
  var map = new ConcurrentLruMap<GatedKey, String>(2, (key, value) -> evicted.add(key));
  map.put(stale, "stale"); map.put(victim, "victim"); map.drain();
  // Pause a genuine removal after map publication and before its lossless task is enqueued.
  PausingQueue queue = new PausingQueue(); setField(map, "writeBuffer", queue);
  AtomicReference<Throwable> failure = new AtomicReference<>();
  Thread worker = thread(() -> { try { map.remove(stale); } catch (Throwable problem) { failure.set(problem); } });
  queue.pausedThread = worker; worker.start();
  try {
   await(queue.reached);
   stale.rejectRepeatedHashes = true;
   map.put(third, "third"); map.put(fourth, "fourth");
   assertEquals(List.of(victim), evicted);
   assertEquals(List.of(fourth, third), map.keysInAccessOrder());
  } finally { queue.release.countDown(); join(worker); }
  assertNull(failure.get());
 }

 private static void assertAccessPromotes(@NonNull Consumer<@NonNull ConcurrentLruMap<@NonNull Integer, @NonNull String>> access) {
  List<Integer> evicted = new ArrayList<>();
  var map = new ConcurrentLruMap<Integer, String>(2, (key, value) -> evicted.add(key));
  map.put(1, "one"); map.put(2, "two"); map.drain();
  access.accept(map); map.put(3, "three");
  assertEquals(List.of(2), evicted);
  assertEquals(List.of(3, 1), map.keysInAccessOrder());
 }

 private static void deferMaintenance(@NonNull ConcurrentLruMap<?, ?> map, @NonNull Runnable writes) throws Exception {
  ReentrantLock lock = lock(map);
  CountDownLatch held = new CountDownLatch(1), release = new CountDownLatch(1);
  Thread owner = thread(() -> { lock.lock(); try { held.countDown(); await(release); } finally { lock.unlock(); } });
  owner.start();
  try { await(held); writes.run(); } finally { release.countDown(); join(owner); }
 }

 private static @NonNull ReentrantLock lock(@NonNull ConcurrentLruMap<?, ?> map) throws Exception {
  return (ReentrantLock) field(map, "maintenanceLock");
 }
 private static int pending(@NonNull ConcurrentLruMap<?, ?> map) throws Exception { return ((AtomicInteger) field(map, "writeBufferSize")).get(); }
 private static @NonNull Object field(@NonNull Object target, @NonNull String name) throws Exception {
  var field = ConcurrentLruMap.class.getDeclaredField(name); field.setAccessible(true); return java.util.Objects.requireNonNull(field.get(target));
 }
 private static void setField(@NonNull Object target, @NonNull String name, @NonNull Object value) throws Exception {
  var field = ConcurrentLruMap.class.getDeclaredField(name); field.setAccessible(true); field.set(target, value);
 }
 private static @NonNull Thread thread(@NonNull Runnable action) { Thread thread = new Thread(action); thread.setDaemon(true); return thread; }
 private static void await(@NonNull CountDownLatch latch) {
  try { assertTrue(latch.await(3, TimeUnit.SECONDS), "controlled interleaving did not reach its gate"); }
  catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new AssertionError(interrupted); }
 }
 private static void join(@NonNull Thread thread) throws Exception { thread.join(3000); assertFalse(thread.isAlive(), "controlled worker did not terminate"); }

 private static final class GatedKey {
  private final int value;
  private final @NonNull CountDownLatch reached = new CountDownLatch(1), release = new CountDownLatch(1);
  private volatile @Nullable Thread gatedThread;
  private int gatedHashes;
  private volatile boolean rejectRepeatedHashes;
  private final @NonNull AtomicInteger guardedHashes = new AtomicInteger();
  private GatedKey(int value) { this.value = value; }
  private void gateSecondHashFrom(@NonNull Thread thread) { this.gatedThread = thread; }
  @Override public int hashCode() {
   if (Thread.currentThread().equals(this.gatedThread) && ++this.gatedHashes == 2) { this.reached.countDown(); await(this.release); }
   if (this.rejectRepeatedHashes && this.guardedHashes.incrementAndGet() > 1) throw new AssertionError("stale eviction victim was revisited");
   return this.value;
  }
  @Override public boolean equals(@Nullable Object other) { return other instanceof GatedKey key && this.value == key.value; }
  @Override public @NonNull String toString() { return Integer.toString(this.value); }
 }

 private static final class PausingQueue extends ConcurrentLinkedQueue<@NonNull Object> {
  private static final long serialVersionUID = 1L;
  private final transient @NonNull CountDownLatch reached = new CountDownLatch(1), release = new CountDownLatch(1);
  private transient volatile @Nullable Thread pausedThread;
  @Override public boolean offer(@NonNull Object task) {
   if (Thread.currentThread().equals(this.pausedThread)) { this.reached.countDown(); await(this.release); }
   return super.offer(task);
  }
 }
}
