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
import com.revetsec.OutboundUriPolicy;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import javax.net.ssl.*;
import java.io.IOException;
import java.lang.reflect.*;
import java.net.*;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

/** Private helper boundaries and deterministic injected-client cancellation, without network I/O. */
final class HttpExchangeRc1MutationTests {
 @Test void cancellationTouchesOnlyPendingFutures()throws Exception{
  ProbeFuture pending=new ProbeFuture();call("cancelIfPending",new Class<?>[]{CompletableFuture.class},pending);Assertions.assertEquals(1,pending.cancels);
  ProbeFuture completed=new ProbeFuture();completed.complete(null);call("cancelIfPending",new Class<?>[]{CompletableFuture.class},completed);Assertions.assertEquals(0,completed.cancels);
  Assertions.assertDoesNotThrow(()->{call("cancelIfPending",new Class<?>[]{CompletableFuture.class},(Object)null);});
 }
 @Test void contentLengthDistinguishesAbsenceLeadingZerosEighteenDigitsAndSaturation(){
  Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2),()->{
   Assertions.assertEquals(-1L,contentLength(Map.of()));Assertions.assertEquals(0L,contentLength(Map.of("Content-Length",List.of("0000"))));
   Assertions.assertEquals(7L,contentLength(Map.of("Content-Length",List.of("000000000000000000000007"))));
   Assertions.assertEquals(123456789012345678L,contentLength(Map.of("Content-Length",List.of("123456789012345678"))));
   Assertions.assertEquals(Long.MAX_VALUE,contentLength(Map.of("Content-Length",List.of("1234567890123456789"))));
  });
 }
 @Test void framingChecksTransferEncodingAndDigitsWithoutHanging(){
  Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2),()->{
   Assertions.assertFalse(HttpExchange.hasFramingAnomaly(headers(Map.of())));
   Assertions.assertFalse(HttpExchange.hasFramingAnomaly(headers(Map.of("Transfer-Encoding",List.of(" chunked\t")))));
   Assertions.assertTrue(HttpExchange.hasFramingAnomaly(headers(Map.of("Transfer-Encoding",List.of("identity")))));
   Assertions.assertTrue(HttpExchange.hasFramingAnomaly(headers(Map.of("Content-Length",List.of("1x")))));
   Assertions.assertTrue(HttpExchange.hasFramingAnomaly(headers(Map.of("Content-Length",List.of("")))));
  });
 }
 @Test void encodingListSkipsEmptyElementsAndAlwaysAdvances(){
  Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2),()->{
   for(String value:List.of("",",identity",", identity,",",,identity,,","identity,identity","\tIDENTITY ,"))Assertions.assertFalse(HttpExchange.hasNonIdentityContentEncoding(headers(Map.of("Content-Encoding",List.of(value)))),value);
   Assertions.assertTrue(HttpExchange.hasNonIdentityContentEncoding(headers(Map.of("Content-Encoding",List.of(",gzip")))));
  });
 }
 @Test void redirectsIncludeBothEndpointsAndExcludeTheirNeighbors()throws Exception{
  for(int status:new int[]{299,300,399,400})Assertions.assertEquals(status>=300&&status<=399,call("isRedirect",new Class<?>[]{int.class},status));
 }
 @Test void causeDepthIsCappedAtSixtyFourDistinctCauses(){
  Throwable timeout=new HttpTimeoutException("fixture");Throwable at63=timeout;for(int i=0;i<63;i++)at63=new RuntimeException(at63);
  Assertions.assertEquals(HttpExchangeException.Kind.TIMEOUT,HttpExchange.fromTransportFailure(at63).getKind());
  Assertions.assertEquals(HttpExchangeException.Kind.IO,HttpExchange.fromTransportFailure(new RuntimeException(at63)).getKind());
 }
 @Test void requestTimeoutSaturatesInsteadOfBecomingZero()throws Exception{
  HttpExchangeRequest request=request(Duration.ofSeconds(Long.MAX_VALUE));Assertions.assertEquals(Long.MAX_VALUE,call("requestTimeoutNanos",new Class<?>[]{HttpExchangeRequest.class},request));
 }
 @Test void earlyResponseRejectionCancelsTheJustReturnedFuture()throws Exception{
  InspectingClient client=new InspectingClient(false);HttpExchange exchange=HttpExchange.fromHttpClient(client,OutboundUriPolicy.defaultInstance(),false);
  HttpExchangeException failure=Assertions.assertThrows(HttpExchangeException.class,()->exchange.execute(request(Duration.ofSeconds(1)),Deadline.fromNow(Duration.ofSeconds(2))));
  Assertions.assertEquals(HttpExchangeException.Kind.REDIRECT,failure.getKind());Assertions.assertEquals(1,client.future.cancels);Assertions.assertTrue(client.future.cancelBeforeAbandon);
 }
 @Test void asynchronousPreResponseFailureIsDeliveredAsIoBeforeDeadline()throws Exception{
  InspectingClient client=new InspectingClient(true);HttpExchange exchange=HttpExchange.fromHttpClient(client,OutboundUriPolicy.defaultInstance(),false);
  HttpExchangeException failure=Assertions.assertThrows(HttpExchangeException.class,()->exchange.execute(request(Duration.ofMillis(100)),Deadline.fromNow(Duration.ofSeconds(2))));Assertions.assertEquals(HttpExchangeException.Kind.IO,failure.getKind());
 }
 @Test void missingCacheDirectiveArgumentUsesTheMinimumLifetime(){
  Assertions.assertEquals(Duration.ofSeconds(5),CacheLifetime.timeToLive(headers(Map.of("Cache-Control",List.of("max-age="))),java.time.Instant.EPOCH,Duration.ofSeconds(5),Duration.ofSeconds(60),Duration.ofSeconds(120)));
 }
 private static long contentLength(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> fields)throws Exception{return (Long)Objects.requireNonNull(call("contentLength",new Class<?>[]{HttpHeaders.class},headers(fields)));}
 private static @NonNull HttpHeaders headers(@NonNull Map<@NonNull String,@NonNull List<@NonNull String>> fields){return HttpHeaders.of(fields,(name,value)->true);}
 private static @NonNull HttpExchangeRequest request(@NonNull Duration timeout){return new HttpExchangeRequest(URI.create("https://issuer.example/jwks"),ResponseProfile.JWKS,null,Map.of(),1024,1024,timeout);}
 private static @Nullable Object call(@NonNull String name,@NonNull Class<?> @NonNull [] types,@Nullable Object @NonNull ... args)throws Exception{Method method=HttpExchange.class.getDeclaredMethod(name,types);method.setAccessible(true);try{return method.invoke(null,args);}catch(InvocationTargetException failure){if(failure.getCause() instanceof Exception cause)throw cause;throw failure;}}
 private static final class ProbeFuture extends CompletableFuture<HttpResponse<Void>> {private int cancels;private @Nullable Object sink;private boolean cancelBeforeAbandon;@Override public boolean cancel(boolean interrupt){cancels++;if(sink!=null){try{var field=sink.getClass().getDeclaredField("abandoned");field.setAccessible(true);cancelBeforeAbandon=!field.getBoolean(sink);}catch(ReflectiveOperationException failure){throw new AssertionError(failure);}}return super.cancel(interrupt);}}
 private static final class InspectingClient extends HttpClient {
  private final boolean fail;private final @NonNull ProbeFuture future=new ProbeFuture();private final @NonNull HttpClient delegate=HttpClient.newHttpClient();
  private InspectingClient(boolean fail){this.fail=fail;}
  @Override public @NonNull Optional<@NonNull CookieHandler> cookieHandler(){return Optional.empty();}
  @Override public @NonNull Optional<@NonNull Duration> connectTimeout(){return Optional.empty();}
  @Override public HttpClient.@NonNull Redirect followRedirects(){return Redirect.NEVER;}
  @Override public @NonNull Optional<@NonNull ProxySelector> proxy(){return Optional.empty();}
  @Override public @NonNull SSLContext sslContext(){return delegate.sslContext();}
  @Override public @NonNull SSLParameters sslParameters(){return delegate.sslParameters();}
  @Override public @NonNull Optional<@NonNull Authenticator> authenticator(){return Optional.empty();}
  @Override public HttpClient.@NonNull Version version(){return Version.HTTP_1_1;}
  @Override public @NonNull Optional<@NonNull Executor> executor(){return Optional.empty();}
  @Override public <T> @NonNull HttpResponse<@NonNull T> send(@NonNull HttpRequest request,HttpResponse.@NonNull BodyHandler<@NonNull T> handler){throw new UnsupportedOperationException();}
  @SuppressWarnings("unchecked") @Override public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(@NonNull HttpRequest request,HttpResponse.@NonNull BodyHandler<@NonNull T> handler){
   future.sink=handler;if(fail)future.completeExceptionally(new IOException("controlled pre-response failure"));else handler.apply(new HttpResponse.ResponseInfo(){@Override public int statusCode(){return 300;}@Override public @NonNull HttpHeaders headers(){return HttpHeaders.of(Map.of(),(name,value)->true);}@Override public HttpClient.@NonNull Version version(){return Version.HTTP_1_1;}});
   return (CompletableFuture<HttpResponse<T>>)(CompletableFuture<?>)future;
  }
  @Override public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(@NonNull HttpRequest request,HttpResponse.@NonNull BodyHandler<@NonNull T> handler,HttpResponse.@NonNull PushPromiseHandler<@NonNull T> pushes){return sendAsync(request,handler);}
 }
}
