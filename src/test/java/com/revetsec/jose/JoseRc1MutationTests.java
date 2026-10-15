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

package com.revetsec.jose;

import com.revetsec.ErrorCategory;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.jose.JwkSetParser;
import com.revetsec.internal.jose.KeySelection;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/** Deterministic decision, publication and cleanup probes retained from RC-1 qualification. */
final class JoseRc1MutationTests {
 @Test void everyFreshAnswerDecisionReleasesItsLock() throws Exception {
  for (int branch = 0; branch < 3; ++branch) {
   JwksCache cache = cache();
   JwksCache.Snapshot snapshot = snapshot(true, true);
   set(cache, "snapshot", snapshot);
   Object decision = call(cache, "decide", branch == 2 ? JwksCacheTests.rs256("a") : null,
     Deadline.fromNow(Duration.ofSeconds(2)), branch == 0 ? null : snapshot);
   Assertions.assertNotNull(decision);
   Assertions.assertEquals("ANSWER", Objects.requireNonNull(field(decision, "action")).toString());
   if (branch == 2) Assertions.assertEquals(KeySelection.Kind.FOUND, ((KeySelection) Objects.requireNonNull(field(decision, "selection"))).getKind());
   Assertions.assertEquals(0, lock(cache).getHoldCount());
  }
 }

 @Test void firstUseFlightKeepsItsFullExchangeAndPublicationBudget() throws Exception {
  JwksCache cache = cache();
  Object decision = call(cache, "decide", JwksCacheTests.rs256("a"), Deadline.fromNow(Duration.ofSeconds(10)), null);
  Assertions.assertNotNull(decision);
  Assertions.assertEquals("LEAD", Objects.requireNonNull(field(decision, "action")).toString());
  Object flight = Objects.requireNonNull(field(decision, "flight"));
  Assertions.assertEquals(Boolean.FALSE, call(flight, "isOverdue", System.nanoTime()));
  Assertions.assertEquals(0, lock(cache).getHoldCount());
 }

 @Test void joiningAFlightIncrementsAndNotifiesWaiters() throws Exception {
  JwksCache cache = cache();
  Object flight = flight();
  set(cache, "flight", flight);
  RecordingCondition condition = new RecordingCondition();
  set(cache, "waitersChanged", condition);
  Object decision = call(cache, "decide", JwksCacheTests.rs256("a"), Deadline.fromNow(Duration.ofSeconds(2)), null);
  Assertions.assertNotNull(decision);
  Assertions.assertEquals("JOIN", Objects.requireNonNull(field(decision, "action")).toString());
  Assertions.assertEquals(1, field(cache, "waiterCount"));
  Assertions.assertEquals(1, condition.signals);
  Assertions.assertEquals(0, lock(cache).getHoldCount());
 }

 @Test void staleKeyAnswersImmediatelyWhileARefreshIsInFlight() throws Exception {
  JwksCache cache = cache();
  JwksCache.Snapshot old = snapshot(false, true);
  set(cache, "snapshot", old);
  set(cache, "flight", flight());
  Object decision = call(cache, "decide", JwksCacheTests.rs256("a"), Deadline.fromNow(Duration.ofSeconds(2)), old);
  Assertions.assertNotNull(decision);
  Assertions.assertEquals("ANSWER", Objects.requireNonNull(field(decision, "action")).toString());
  Assertions.assertEquals(KeySelection.Kind.FOUND, ((KeySelection) Objects.requireNonNull(field(decision, "selection"))).getKind());
  Assertions.assertEquals(0, lock(cache).getHoldCount());
  KeySelection stale = (KeySelection) call(cache, "currentStaleSelection", JwksCacheTests.rs256("a"));
  Assertions.assertNotNull(stale);
  Assertions.assertEquals(KeySelection.Kind.FOUND, stale.getKind());
  Assertions.assertEquals(0, lock(cache).getHoldCount());
 }

 @Test void twoStartedAttemptsSuppressTheNextFirstUseFetch() throws Exception {
  JwksCache cache = cache();
  set(cache, "latestAttemptStart", JwksCacheTests.START);
  set(cache, "earlierAttemptStart", JwksCacheTests.START);
  Object decision = call(cache, "decide", JwksCacheTests.rs256("a"), Deadline.fromNow(Duration.ofSeconds(2)), null);
  Assertions.assertNotNull(decision);
  Assertions.assertEquals("SUPPRESS", Objects.requireNonNull(field(decision, "action")).toString());
  Assertions.assertNotNull(field(decision, "failure"));
  Assertions.assertEquals(0, lock(cache).getHoldCount());
 }

 @Test void publicationClearsTheCurrentFlightAndReleasesItsLock() throws Exception {
  JwksCache cache = cache();
  Object flight = flight();
  set(cache, "flight", flight);
  call(cache, "publish", flight, null, true);
  Assertions.assertNull(field(cache, "flight"));
  Assertions.assertTrue(future(flight).isDone());
  Assertions.assertEquals(0, lock(cache).getHoldCount());
 }

 @Test void successfulLeaderAlwaysPublishesBeforeReturning() throws Exception {
  JwksCache cache = cache();
  cache.warmUp(Deadline.fromNow(Duration.ofSeconds(2)));
  Assertions.assertNull(field(cache, "flight"));
  Assertions.assertNotNull(field(cache, "snapshot"));
  Assertions.assertEquals(0, lock(cache).getHoldCount());
 }

 @Test void everyWaitOutcomeDecrementsNotifiesAndUnlocks() throws Exception {
  for (String outcome : List.of("success", "exceptional", "timeout", "interrupt")) {
   JwksCache cache = cache();
   Object flight = flight();
   Object cutShort = staticField("FlightResult", "CUT_SHORT");
   if (outcome.equals("success")) future(flight).complete(cutShort);
   if (outcome.equals("exceptional")) future(flight).completeExceptionally(new IllegalStateException("private defensive probe"));
   set(cache, "waiterCount", 1);
   RecordingCondition condition = new RecordingCondition();
   set(cache, "waitersChanged", condition);
   try {
    if (outcome.equals("interrupt")) Thread.currentThread().interrupt();
    if (outcome.equals("timeout") || outcome.equals("interrupt")) {
     InvocationTargetException thrown = Assertions.assertThrows(InvocationTargetException.class,
       () -> call(cache, "await", flight, Deadline.fromNow(outcome.equals("timeout") ? Duration.ZERO : Duration.ofSeconds(2))));
     Assertions.assertInstanceOf(JsonWebKeySetUnavailableException.class, thrown.getCause());
     if (outcome.equals("interrupt")) Assertions.assertTrue(Thread.currentThread().isInterrupted());
    } else Assertions.assertSame(cutShort, call(cache, "await", flight, Deadline.fromNow(Duration.ofSeconds(2))));
    Assertions.assertEquals(0, field(cache, "waiterCount"));
    Assertions.assertEquals(1, condition.signals);
    Assertions.assertEquals(0, lock(cache).getHoldCount());
   } finally { Thread.interrupted(); }
  }
 }

 @Test void waiterObservationAtEqualitySucceedsAndZeroBudgetNeverWaits() throws Exception {
  JwksCache cache = cache();
  RecordingCondition condition = new RecordingCondition();
  set(cache, "waitersChanged", condition);
  Assertions.assertTrue(cache.awaitWaitersForTests(0, Duration.ZERO));
  Assertions.assertFalse(cache.awaitWaitersForTests(1, Duration.ZERO));
  Assertions.assertEquals(0, condition.waits);
  Assertions.assertEquals(0, lock(cache).getHoldCount());
 }

 @Test void publicSelectionReleasesFastAndSlowPathLocks() throws Exception {
  JwksCache cache = JwksCacheTests.source(JwksCacheTests.MemoryHttpClient.answering(JwksCacheTests.Answer.fromKeySet(null, "a")),
    TestClock.fromInstant(JwksCacheTests.START)).build().cacheForTests();
  for (int attempt = 0; attempt < 2; ++attempt) {
   Assertions.assertEquals(KeySelection.Kind.FOUND, cache.select(JwksCacheTests.rs256("a"), Deadline.fromNow(Duration.ofSeconds(2))).getKind());
   Assertions.assertEquals(0, lock(cache).getHoldCount());
  }
 }

 @Test void failedJoinedRefreshCanUseANewerUsableSnapshot() throws Exception {
  JwksCache cache = cache();
  JwksCache.Snapshot old = snapshot(false, false);
  JwksCache.Snapshot newer = snapshot(true, true);
  set(cache, "snapshot", old);
  Object flight = flight();
  PublishingFuture completion = new PublishingFuture(() -> Assertions.assertDoesNotThrow(() -> {
   set(cache, "snapshot", newer); set(cache, "flight", null);
  }), failedResult());
  set(flight, "result", completion);
  set(cache, "flight", flight);
  Object answer = call(cache, "resolve", JwksCacheTests.rs256("a"), Deadline.fromNow(Duration.ofSeconds(2)), old);
  Assertions.assertInstanceOf(KeySelection.class, answer);
  Assertions.assertEquals(KeySelection.Kind.FOUND, ((KeySelection) answer).getKind());
  Assertions.assertEquals(0, field(cache, "waiterCount"));
  Assertions.assertEquals(0, lock(cache).getHoldCount());
 }

 @Test void failureCounterSaturatesWithoutWrapping() throws Exception {
  JwksCache cache = cache();
  set(cache, "consecutiveFailures", Integer.MAX_VALUE);
  Constructor<?> constructor = nested("Failure").getDeclaredConstructor(ErrorCategory.class, boolean.class);
  constructor.setAccessible(true);
  Object failure = constructor.newInstance(ErrorCategory.TRANSPORT, true);
  call(cache, "recordFailure", JwksCacheTests.START, failure, null);
  Assertions.assertEquals(Integer.MAX_VALUE, field(cache, "consecutiveFailures"));
  Assertions.assertEquals(Duration.ofMinutes(5), field(cache, "backoff"));
 }

 @Test void reportedUriPreservesTheExplicitZeroPort() {
  Assertions.assertEquals(URI.create("https://example.com:0/keys"), JwksCache.cut(URI.create("https://example.com:0/keys?q=sensitive#fragment")));
 }

 @Test void flightExpiryUsesStrictElapsedBudgetAndAlreadyCompletedState()throws Exception {
  Object flight=flight();long start=(Long)Objects.requireNonNull(field(flight,"startNanos")),budget=(Long)Objects.requireNonNull(field(flight,"budgetNanos"));
  Assertions.assertEquals(Boolean.FALSE,call(flight,"isOverdue",start+budget-1));
  Assertions.assertEquals(Boolean.FALSE,call(flight,"isOverdue",start+budget));
  Assertions.assertEquals(Boolean.TRUE,call(flight,"isOverdue",start+budget+1));
  future(flight).complete(staticField("FlightResult","CUT_SHORT"));
  Assertions.assertEquals(Boolean.TRUE,call(flight,"isOverdue",start));
 }

 private static @NonNull JwksCache cache() {
  return JwksCacheTests.source(JwksCacheTests.MemoryHttpClient.answering(JwksCacheTests.Answer.fromKeySet(null)),
    TestClock.fromInstant(JwksCacheTests.START)).build().cacheForTests();
 }
 private static JwksCache.@NonNull Snapshot snapshot(boolean fresh, boolean withKey) throws Exception {
  String json = withKey ? TestJsonWebKeys.keySet(List.of(TestJsonWebKeys.withFixture(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048).kid("a").toJson())) : "{\"keys\":[]}";
  return new JwksCache.Snapshot(JwkSetParser.parse(json, 256 * 1024, 100).keys(), JwksCacheTests.START.minusSeconds(60),
    fresh ? JwksCacheTests.START.plusSeconds(60) : JwksCacheTests.START.minusSeconds(1), JwksCacheTests.START.plusSeconds(3600));
 }
 private static @NonNull Class<?> nested(@NonNull String name) throws ClassNotFoundException { return Class.forName(JwksCache.class.getName() + "$" + name); }
 private static @NonNull Object flight() throws Exception {
  Constructor<?> constructor = nested("Flight").getDeclaredConstructor(java.time.Instant.class, java.time.Instant.class, java.time.Instant.class, long.class, long.class);
  constructor.setAccessible(true);
  return constructor.newInstance(null, null, null, System.nanoTime(), Duration.ofSeconds(20).toNanos());
 }
 private static @NonNull Object staticField(@NonNull String type, @NonNull String name) throws Exception {
  Field field = nested(type).getDeclaredField(name);field.setAccessible(true);return Objects.requireNonNull(field.get(null));
 }
 private static @Nullable Object field(@NonNull Object object, @NonNull String name) throws Exception {
  Field field = object.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(object);
 }
 private static void set(@NonNull Object object, @NonNull String name, @Nullable Object value) throws Exception {
  Field field = object.getClass().getDeclaredField(name);field.setAccessible(true);field.set(object, value);
 }
 private static @Nullable Object call(@NonNull Object object, @NonNull String name, @Nullable Object @NonNull ... arguments) throws Exception {
  Method method = java.util.Arrays.stream(object.getClass().getDeclaredMethods()).filter(candidate -> candidate.getName().equals(name)).findFirst().orElseThrow();
  method.setAccessible(true);return method.invoke(object, arguments);
 }
 private static @NonNull ReentrantLock lock(@NonNull JwksCache cache) throws Exception { return (ReentrantLock) Objects.requireNonNull(field(cache, "lock")); }
 @SuppressWarnings("unchecked") private static @NonNull CompletableFuture<@NonNull Object> future(@NonNull Object flight) throws Exception { return (CompletableFuture<@NonNull Object>) Objects.requireNonNull(field(flight, "result")); }
 private static @NonNull Object failedResult() throws Exception {
  Constructor<?> constructor = nested("Failure").getDeclaredConstructor(ErrorCategory.class, boolean.class);
  constructor.setAccessible(true);
  Object failure = constructor.newInstance(ErrorCategory.TRANSPORT, true);
  Method method = nested("FlightResult").getDeclaredMethod("failed", nested("Failure"));
  method.setAccessible(true);return Objects.requireNonNull(method.invoke(null, failure));
 }
 private static final class PublishingFuture extends CompletableFuture<@NonNull Object> {
  private final @NonNull Runnable beforeGet;
  private final @NonNull Object outcome;
  private PublishingFuture(@NonNull Runnable beforeGet, @NonNull Object outcome) { this.beforeGet = beforeGet; this.outcome = outcome; }
  @Override public @NonNull Object get(long timeout, @NonNull TimeUnit unit)
    throws InterruptedException, java.util.concurrent.ExecutionException, java.util.concurrent.TimeoutException {
   this.beforeGet.run(); complete(this.outcome);return super.get(timeout, unit);
  }
 }
 private static final class RecordingCondition implements Condition {
  int signals; int waits;
  @Override public long awaitNanos(long nanos) { ++this.waits; return -1; }
  @Override public void signalAll() { ++this.signals; }
  @Override public void await() { throw new UnsupportedOperationException(); }
  @Override public void awaitUninterruptibly() { throw new UnsupportedOperationException(); }
  @Override public boolean await(long time, @NonNull TimeUnit unit) { throw new UnsupportedOperationException(); }
  @Override public boolean awaitUntil(@NonNull Date deadline) { throw new UnsupportedOperationException(); }
  @Override public void signal() { throw new UnsupportedOperationException(); }
 }
}
