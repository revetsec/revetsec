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

package com.revetsec.internal.http;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Terminal body callbacks, bounded growth and erasure, through the injected client's subscriber seam. */
final class HttpExchangeBodyRc1MutationTests {
 @Test void exactCapacityCompletionCopiesTheBodyAndErasesItsRetainedBuffer() throws Exception {
  Fixture fixture=fixture(200,8,4,4);RecordingSubscription subscription=new RecordingSubscription();
  fixture.subscriber().onSubscribe(subscription);fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{1,2})));
  byte[] retained=buffer(fixture);assertArrayEquals(new byte[]{1,2,0,0},retained);
  fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{3,4})));fixture.subscriber().onComplete();
  assertArrayEquals(new byte[]{1,2,3,4},response(fixture).body());assertArrayEquals(new byte[4],retained);
  assertEquals(0,buffer(fixture).length);assertEquals(0,field(fixture.subscriber(),"size"));assertBodyCompleted(fixture);
  assertEquals(3,subscription.requested);assertEquals(0,subscription.cancels);assertLockReleased(fixture);
 }
 @Test void growthErasesTheOldBufferBeforePublishingTheNewCapacity() throws Exception {
  Fixture fixture=fixture(200,8,4,1);RecordingSubscription subscription=new RecordingSubscription();fixture.subscriber().onSubscribe(subscription);
  fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{31})));byte[] old=buffer(fixture);assertArrayEquals(new byte[]{31},old);
  fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{32,33})));assertNotSame(old,buffer(fixture));assertArrayEquals(new byte[old.length],old);
  byte[] grown=buffer(fixture);assertArrayEquals(new byte[]{31,32,33},grown);fixture.subscriber().onComplete();
  assertArrayEquals(new byte[]{31,32,33},response(fixture).body());assertArrayEquals(new byte[grown.length],grown);assertBodyCompleted(fixture);
 }
 @Test void partialCapacityCompletionDiscardsItsSpareBufferWithoutPublishingPadding() throws Exception {
  Fixture fixture=fixture(200,8,4,8);fixture.subscriber().onSubscribe(new RecordingSubscription());
  fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{41,42,43})));byte[] old=buffer(fixture);assertEquals(8,old.length);
  fixture.subscriber().onComplete();assertArrayEquals(new byte[]{41,42,43},response(fixture).body());assertArrayEquals(new byte[8],old);assertBodyCompleted(fixture);
 }
 @Test void exactBodyLimitIsAcceptedAndOneExtraOctetStopsAndErases() throws Exception {
  Fixture exact=fixture(200,4,2,null);exact.subscriber().onSubscribe(new RecordingSubscription());exact.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{1,2,3,4})));exact.subscriber().onComplete();assertArrayEquals(new byte[]{1,2,3,4},response(exact).body());
  Fixture excess=fixture(200,4,2,null);RecordingSubscription subscription=new RecordingSubscription();excess.subscriber().onSubscribe(subscription);
  excess.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{11,12})));byte[] old=buffer(excess);assertEquals(4,old.length);
  excess.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{13,14,15})));assertArrayEquals(new byte[4],old);assertEquals(HttpExchangeException.Kind.TOO_LARGE,exception(excess).getKind());assertEquals(1,subscription.cancels);assertBodyFailed(excess);
 }
 @Test void errorBodyOverflowKeepsTheStatusAndDropsEveryBufferedOctet() throws Exception {
  Fixture fixture=fixture(503,8,2,null);RecordingSubscription subscription=new RecordingSubscription();fixture.subscriber().onSubscribe(subscription);
  fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{51})));byte[] old=buffer(fixture);assertEquals(2,old.length);
  fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{52,53})));RawResponse response=response(fixture);assertEquals(503,response.status());assertTrue(response.errorBodyDropped());assertArrayEquals(new byte[0],response.body());assertArrayEquals(new byte[2],old);assertBodyFailed(fixture);assertEquals(1,subscription.cancels);
 }
 @Test void abandonmentErasesAndLateCallbacksCannotReadOrPublishAnotherBody() throws Exception {
  Fixture fixture=fixture(200,4,2,4);RecordingSubscription subscription=new RecordingSubscription();fixture.subscriber().onSubscribe(subscription);fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{61,62})));byte[] old=buffer(fixture);
  invoke(fixture.sink(),"abandon");assertArrayEquals(new byte[4],old);assertEquals(1,subscription.cancels);assertBodyFailed(fixture);
  ByteBuffer late=ByteBuffer.wrap(new byte[]{63,64});fixture.subscriber().onNext(List.of(late));assertEquals(2,late.remaining());assertEquals(2,subscription.cancels);
  RecordingSubscription duplicate=new RecordingSubscription();fixture.subscriber().onSubscribe(duplicate);assertEquals(0,duplicate.requested);assertEquals(1,duplicate.cancels);
  fixture.subscriber().onError(new IOException("late terminal"));fixture.subscriber().onComplete();assertFalse(outcome(fixture).isDone());assertBodyFailed(fixture);assertArrayEquals(new byte[4],old);
 }
 @Test void providerErrorErasesBufferedDataAndRetainsTheFirstTerminalFailure() throws Exception {
  Fixture fixture=fixture(200,4,2,4);fixture.subscriber().onSubscribe(new RecordingSubscription());fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{71,72})));byte[] old=buffer(fixture);
  IOException first=new IOException("fixture first");fixture.subscriber().onError(first);assertLockReleased(fixture);assertSame(first,field(outcome(fixture).get(2,TimeUnit.SECONDS),"failure"));assertArrayEquals(new byte[4],old);assertBodyFailed(fixture);
  fixture.subscriber().onError(new IOException("fixture second"));assertSame(first,field(outcome(fixture).get(2,TimeUnit.SECONDS),"failure"));
 }
 @Test void subscriptionFailuresAreContainedAndStillFinishTheBodyFuture() throws Exception {
  Fixture fixture=fixture(200,4,2,4);RecordingSubscription subscription=new RecordingSubscription();IllegalStateException requestFailure=new IllegalStateException("fixture request");subscription.requestFailure=requestFailure;subscription.cancelFailure=new AssertionError("fixture cancel");
  assertDoesNotThrow(()->fixture.subscriber().onSubscribe(subscription));assertEquals(1,subscription.cancels);assertSame(requestFailure,field(outcome(fixture).get(2,TimeUnit.SECONDS),"failure"));assertBodyFailed(fixture);
 }
 @Test void subscriptionRequestAndCancelAlwaysRunOutsideTheBodyLock() throws Exception {
  Fixture fixture=fixture(200,4,2,4);ReentrantLock lock=(ReentrantLock)requireNonNull(field(fixture.subscriber(),"lock"));List<Boolean> unlocked=new ArrayList<>();
  RecordingSubscription subscription=new RecordingSubscription();subscription.onRequest=()->unlocked.add(acquirableByAnotherThread(lock));subscription.onCancel=()->unlocked.add(acquirableByAnotherThread(lock));
  fixture.subscriber().onSubscribe(subscription);fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{81})));invoke(fixture.sink(),"abandon");assertEquals(List.of(true,true,true),unlocked);
 }
 @Test void earlyRejectionCancelsEvenAThrowingSubscriptionAndKeepsItsFailedBody() throws Exception {
  Fixture fixture=fixture(302,4,2,null);RecordingSubscription subscription=new RecordingSubscription();subscription.cancelFailure=new AssertionError("fixture cancel");
  assertDoesNotThrow(()->fixture.subscriber().onSubscribe(subscription));assertEquals(0,subscription.requested);assertEquals(1,subscription.cancels);assertEquals(HttpExchangeException.Kind.REDIRECT,exception(fixture).getKind());assertBodyFailed(fixture);
  fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{91})));fixture.subscriber().onError(new IOException("late"));fixture.subscriber().onComplete();assertBodyFailed(fixture);
 }
 @Test void anEmptyCallbackAtCapacityDoesNotReplaceOrEraseTheRetainedBuffer() throws Exception {
  Fixture fixture=fixture(200,8,4,4);fixture.subscriber().onSubscribe(new RecordingSubscription());
  fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{1,2,3,4})));byte[] retained=buffer(fixture);
  fixture.subscriber().onNext(List.of(ByteBuffer.allocate(0)));assertSame(retained,buffer(fixture));assertArrayEquals(new byte[]{1,2,3,4},retained);
  fixture.subscriber().onComplete();assertArrayEquals(new byte[]{1,2,3,4},response(fixture).body());assertArrayEquals(new byte[4],retained);assertLockReleased(fixture);
 }
 @Test void zeroDeclaredLengthUsesOnlyTheNeededCapacityWhenAnInjectedClientDeliversData() throws Exception {
  Fixture fixture=fixture(200,20000,4,0);fixture.subscriber().onSubscribe(new RecordingSubscription());
  fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{101})));byte[] retained=buffer(fixture);assertArrayEquals(new byte[]{101},retained);
  fixture.subscriber().onComplete();assertArrayEquals(new byte[]{101},response(fixture).body());assertArrayEquals(new byte[1],retained);assertBodyCompleted(fixture);
 }
 @Test void aRequestFailureDuringOnNextErasesTheBufferAndFinishesBothOutcomes() throws Exception {
  Fixture fixture=fixture(200,4,2,4);RecordingSubscription subscription=new RecordingSubscription();fixture.subscriber().onSubscribe(subscription);
  IllegalStateException failure=new IllegalStateException("fixture second request");subscription.requestFailure=failure;
  assertDoesNotThrow(()->fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{111,112}))));
  assertSame(failure,field(outcome(fixture).get(2,TimeUnit.SECONDS),"failure"));assertArrayEquals(new byte[4],buffer(fixture));assertEquals(1,subscription.cancels);assertBodyFailed(fixture);assertLockReleased(fixture);
 }
 @Test void aPrivateBodyFutureCompletionFaultStillErasesDataAndFailsTheBody() throws Exception {
  Fixture fixture=fixture(200,4,2,4);fixture.subscriber().onSubscribe(new RecordingSubscription());fixture.subscriber().onNext(List.of(ByteBuffer.wrap(new byte[]{121,122,123,124})));
  byte[] retained=buffer(fixture);assertArrayEquals(new byte[]{121,122,123,124},retained);
  // The stock CompletableFuture does not expose this fault through wire input; this is a private dependency probe.
  ThrowingCompleteFuture body=new ThrowingCompleteFuture();setField(fixture.subscriber(),"body",body);
  assertDoesNotThrow(()->fixture.subscriber().onComplete());assertEquals(1,body.attempts);
  assertArrayEquals(new byte[]{121,122,123,124},response(fixture).body());assertArrayEquals(new byte[4],retained);
  assertBodyFailed(fixture);assertLockReleased(fixture);
 }
 private record Fixture(@NonNull Object sink,HttpResponse.@NonNull BodySubscriber<@NonNull Void> subscriber) { }
 @SuppressWarnings("unchecked") private static @NonNull Fixture fixture(int status,int maximum,int maximumError,@Nullable Integer length) throws Exception {
  Class<?> type=Class.forName(HttpExchange.class.getName()+"$Sink");var constructor=type.getDeclaredConstructor(HttpExchangeRequest.class,long.class);constructor.setAccessible(true);
  Object sink=constructor.newInstance(new HttpExchangeRequest(URI.create("https://issuer.example/jwks"),ResponseProfile.JWKS,null,Map.of(),maximum,maximumError,Duration.ofSeconds(1)),System.nanoTime());
  Map<String,List<String>> fields=new HashMap<>();fields.put("Content-Type",List.of("application/json"));if(length!=null)fields.put("Content-Length",List.of(length.toString()));HttpHeaders headers=HttpHeaders.of(fields,(a,b)->true);
  HttpResponse.BodyHandler<Void> handler=(HttpResponse.BodyHandler<Void>)sink;
  return new Fixture(sink,handler.apply(new HttpResponse.ResponseInfo(){@Override public int statusCode(){return status;}@Override public @NonNull HttpHeaders headers(){return headers;}@Override public HttpClient.@NonNull Version version(){return HttpClient.Version.HTTP_1_1;}}));
 }
 private static byte @NonNull [] buffer(@NonNull Fixture fixture) throws Exception {return (byte[])requireNonNull(field(fixture.subscriber(),"buffer"));}
 private static @NonNull CompletableFuture<?> outcome(@NonNull Fixture fixture) throws Exception {return (CompletableFuture<?>)requireNonNull(field(fixture.sink(),"outcome"));}
 private static @NonNull RawResponse response(@NonNull Fixture fixture) throws Exception {return (RawResponse)requireNonNull(invoke(outcome(fixture).get(2,TimeUnit.SECONDS),"getResponse"));}
 private static @NonNull HttpExchangeException exception(@NonNull Fixture fixture) throws Exception {return (HttpExchangeException)requireNonNull(invoke(outcome(fixture).get(2,TimeUnit.SECONDS),"toException"));}
 private static void assertBodyCompleted(@NonNull Fixture fixture){var body=fixture.subscriber().getBody().toCompletableFuture();assertTrue(body.isDone());assertFalse(body.isCompletedExceptionally());assertNull(body.join());}
 private static void assertBodyFailed(@NonNull Fixture fixture){var body=fixture.subscriber().getBody().toCompletableFuture();assertTrue(body.isDone());assertTrue(body.isCompletedExceptionally());}
 private static void assertLockReleased(@NonNull Fixture fixture) throws Exception {ReentrantLock lock=(ReentrantLock)requireNonNull(field(fixture.subscriber(),"lock"));assertFalse(lock.isLocked());assertTrue(acquirableByAnotherThread(lock));}
 private static @Nullable Object field(@NonNull Object target,@NonNull String name) throws Exception {var field=target.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(target);}
 private static void setField(@NonNull Object target,@NonNull String name,@NonNull Object value) throws Exception {var field=target.getClass().getDeclaredField(name);field.setAccessible(true);field.set(target,value);}
 private static @Nullable Object invoke(@NonNull Object target,@NonNull String name,@Nullable Object @NonNull ... args) throws Exception {
  var method=Arrays.stream(target.getClass().getDeclaredMethods()).filter(m->m.getName().equals(name)&&m.getParameterCount()==args.length).findFirst().orElseThrow();method.setAccessible(true);
  try{return method.invoke(target,args);}catch(InvocationTargetException failure){if(failure.getCause() instanceof Exception cause)throw cause;if(failure.getCause() instanceof Error cause)throw cause;throw failure;}
 }
 private static boolean acquirableByAnotherThread(@NonNull ReentrantLock lock){FutureTask<Boolean> future=new FutureTask<>(()->{if(!lock.tryLock())return false;try{return true;}finally{lock.unlock();}});Thread thread=new Thread(future,"rc1-body-lock-probe");thread.setDaemon(true);thread.start();try{return assertDoesNotThrow(()->future.get(2,TimeUnit.SECONDS));}finally{future.cancel(true);}}
 private static final class RecordingSubscription implements Flow.Subscription {
  private long requested;private int cancels;private @Nullable RuntimeException requestFailure;private @Nullable Error cancelFailure;private @Nullable Runnable onRequest,onCancel;
  @Override public void request(long count){requested+=count;if(onRequest!=null)onRequest.run();if(requestFailure!=null)throw requestFailure;}
  @Override public void cancel(){cancels++;if(onCancel!=null)onCancel.run();if(cancelFailure!=null)throw cancelFailure;}
 }
 private static final class ThrowingCompleteFuture extends CompletableFuture<@NonNull Void> {
  private int attempts;
  @Override public boolean complete(@Nullable Void value){attempts++;if(attempts==1)throw new IllegalStateException("fixture private future completion");return super.complete(value);}
 }
}
