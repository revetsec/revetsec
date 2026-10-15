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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Controlled orderings of response selection, exchange attachment and caller abandonment. */
final class HttpExchangeCoordinationRc1MutationTests {
 @Test void hostileResponseInfoFinishesTheFailureAndCancelsTheAttachedExchange() throws Exception {
  Fixture fixture=fixture(System.nanoTime());CompletableFuture<Void> sent=new CompletableFuture<>();invoke(fixture.sink(),"attach",sent);
  AssertionError failure=new AssertionError("fixture status provider");
  HttpResponse.BodySubscriber<Void> subscriber=assertDoesNotThrow(()->fixture.handler().apply(new HttpResponse.ResponseInfo(){
   @Override public int statusCode(){throw failure;}
   @Override public @NonNull HttpHeaders headers(){return HttpExchangeCoordinationRc1MutationTests.headers(Map.of());}
   @Override public HttpClient.@NonNull Version version(){return HttpClient.Version.HTTP_1_1;}
  }));
  assertNotNull(subscriber);assertSame(failure,field(outcome(fixture).get(2,TimeUnit.SECONDS),"failure"));assertTrue(sent.isCancelled());assertFailedBody(subscriber);
  RecordingSubscription subscription=new RecordingSubscription();subscriber.onSubscribe(subscription);assertEquals(1,subscription.cancelled);assertEquals(0,subscription.requested);
 }
 @Test void everyEarlyResponseReturnsAFailedSubscriberAndCancelsThePendingExchange() throws Exception {
  for(int scenario=0;scenario<5;scenario++){
   Fixture fixture=fixture(System.nanoTime());CompletableFuture<Void> sent=new CompletableFuture<>();invoke(fixture.sink(),"attach",sent);
   int status=scenario==0?302:scenario==2?503:200;
   Map<String,List<String>> fields=switch(scenario){case 1,2->Map.of("Content-Type",List.of("application/json"),"Content-Encoding",List.of("gzip"));case 3->Map.of("Content-Type",List.of("application/json"),"Content-Length",List.of("9"));case 4->Map.of("Content-Type",List.of("text/plain"));default->Map.of();};
   HttpResponse.BodySubscriber<Void> subscriber=fixture.handler().apply(info(status,fields));assertNotNull(subscriber,"scenario "+scenario);assertFailedBody(subscriber);assertTrue(sent.isCancelled(),"scenario "+scenario);assertTrue(outcome(fixture).isDone());
   if(scenario==2){RawResponse response=(RawResponse)requireNonNull(invoke(outcome(fixture).get(2,TimeUnit.SECONDS),"getResponse"));assertEquals(503,response.status());assertTrue(response.errorBodyDropped());assertEquals(0,response.body().length);}
  }
 }
 @Test void theInclusiveThreeDigitStatusEndpointsProduceRawResponses() throws Exception {
  for(int status:new int[]{100,999}){
   Fixture fixture=fixture(System.nanoTime());HttpResponse.BodySubscriber<Void> subscriber=fixture.handler().apply(info(status,Map.of("Content-Type",List.of("application/json"))));
   subscriber.onSubscribe(new RecordingSubscription());subscriber.onComplete();Object completed=outcome(fixture).get(2,TimeUnit.SECONDS);
   RawResponse response=(RawResponse)requireNonNull(invoke(completed,"getResponse"));assertEquals(status,response.status());assertFalse(response.errorBodyDropped());assertEquals(0,response.body().length);assertFalse(subscriber.getBody().toCompletableFuture().isCompletedExceptionally());
  }
 }
 @Test void callerAbandonmentBeforeResponseSelectionCancelsTheLateSubscription() throws Exception {
  Fixture fixture=fixture(System.nanoTime());invoke(fixture.sink(),"abandon");HttpResponse.BodySubscriber<Void> subscriber=fixture.handler().apply(info(200,Map.of("Content-Type",List.of("application/json"))));
  RecordingSubscription subscription=new RecordingSubscription();subscriber.onSubscribe(subscription);assertEquals(0,subscription.requested);assertEquals(1,subscription.cancelled);assertFailedBody(subscriber);
  ByteBuffer late=ByteBuffer.wrap(new byte[]{1,2});subscriber.onNext(List.of(late));assertEquals(2,late.remaining());subscriber.onComplete();assertFalse(outcome(fixture).isDone());
 }
 @Test void elapsedTimeSubtractsTheRecordedStartWithinRealClockBounds() throws Exception {
  long started=System.nanoTime()-TimeUnit.SECONDS.toNanos(1);Fixture fixture=fixture(started);long before=System.nanoTime();Duration elapsed=(Duration)requireNonNull(invoke(fixture.sink(),"elapsed"));long after=System.nanoTime();
  assertTrue(elapsed.toNanos()>=Math.max(0,before-started));assertTrue(elapsed.toNanos()<=Math.max(0,after-started));
 }
 @Test void anEarlyOutcomeCancelsAnExchangeAttachedAfterResponseSelection() throws Exception {
  Fixture fixture=fixture(System.nanoTime());HttpResponse.BodySubscriber<Void> subscriber=fixture.handler().apply(info(302,Map.of()));assertFailedBody(subscriber);
  CompletableFuture<Void> sent=new CompletableFuture<>();assertFalse(sent.isDone());invoke(fixture.sink(),"attach",sent);assertTrue(sent.isCancelled());
 }
 @Test void aPrivateExceptionalOutcomeFutureStillReturnsATransportFailure() throws Exception {
  Fixture fixture=fixture(System.nanoTime());IOException failure=new IOException("fixture private exceptional future");
  // Sink only publishes normal Outcome values in production; this explicitly controls its private dependency state.
  assertTrue(outcome(fixture).completeExceptionally(failure));Object completed=requireNonNull(invoke(fixture.sink(),"await",TimeUnit.SECONDS.toNanos(1)));
  HttpExchangeException exception=(HttpExchangeException)requireNonNull(invoke(completed,"toException"));assertEquals(HttpExchangeException.Kind.IO,exception.getKind());assertSame(failure,exception.getCause());
 }
 @Test void theLastAsciiOctetIsAcceptedInAnInjectedFormBody() {
  HttpExchangeRequest request=new HttpExchangeRequest(URI.create("https://issuer.example/token"),ResponseProfile.TOKEN,"\u007f",Map.of(),8,4,Duration.ofSeconds(1));
  assertEquals("\u007f",request.formBody());assertEquals("POST",request.method());
 }
 @Test void aRequestDescriptionRetainsAnExplicitZeroPortAndOmitsSecrets() {
  URI uri=URI.create("https://issuer.example:0/token?secret-query#secret-fragment");
  assertEquals("https://issuer.example:0/token",HttpExchangeRequest.describe(uri));
  HttpExchangeRequest request=new HttpExchangeRequest(uri,ResponseProfile.TOKEN,null,Map.of(),8,4,Duration.ofSeconds(1));
  assertTrue(request.toString().contains("https://issuer.example:0/token"));assertFalse(request.toString().contains("secret-"));
 }
 private record Fixture(@NonNull Object sink,HttpResponse.@NonNull BodyHandler<@NonNull Void> handler) { }
 @SuppressWarnings("unchecked") private static @NonNull Fixture fixture(long started) throws Exception {
  Class<?> type=Class.forName(HttpExchange.class.getName()+"$Sink");var constructor=type.getDeclaredConstructor(HttpExchangeRequest.class,long.class);constructor.setAccessible(true);
  Object sink=constructor.newInstance(new HttpExchangeRequest(URI.create("https://issuer.example/jwks"),ResponseProfile.JWKS,null,Map.of(),8,4,Duration.ofSeconds(1)),started);
  return new Fixture(sink,(HttpResponse.BodyHandler<Void>)sink);
 }
 private static @NonNull HttpHeaders headers(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> fields){return HttpHeaders.of(fields,(a,b)->true);}
 private static HttpResponse.@NonNull ResponseInfo info(int status,@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> fields){return new HttpResponse.ResponseInfo(){@Override public int statusCode(){return status;}@Override public @NonNull HttpHeaders headers(){return HttpExchangeCoordinationRc1MutationTests.headers(fields);}@Override public HttpClient.@NonNull Version version(){return HttpClient.Version.HTTP_1_1;}};}
 private static @NonNull CompletableFuture<?> outcome(@NonNull Fixture fixture) throws Exception {return (CompletableFuture<?>)requireNonNull(field(fixture.sink(),"outcome"));}
 private static void assertFailedBody(HttpResponse.@NonNull BodySubscriber<@NonNull Void> subscriber){var body=subscriber.getBody().toCompletableFuture();assertTrue(body.isDone());assertTrue(body.isCompletedExceptionally());}
 private static @Nullable Object field(@NonNull Object target,@NonNull String name) throws Exception {var field=target.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(target);}
 private static @Nullable Object invoke(@NonNull Object target,@NonNull String name,@Nullable Object @NonNull ... args) throws Exception {
  var method=Arrays.stream(target.getClass().getDeclaredMethods()).filter(m->m.getName().equals(name)&&m.getParameterCount()==args.length).findFirst().orElseThrow();method.setAccessible(true);
  try{return method.invoke(target,args);}catch(InvocationTargetException failure){if(failure.getCause() instanceof Exception cause)throw cause;if(failure.getCause() instanceof Error cause)throw cause;throw failure;}
 }
 private static final class RecordingSubscription implements Flow.Subscription {
  private int requested,cancelled;
  @Override public void request(long count){assertEquals(1,count);requested++;}
  @Override public void cancel(){cancelled++;}
 }
}
