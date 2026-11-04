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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.json.*;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import static org.junit.jupiter.api.Assertions.*;

/** Deterministic sample/publication reordering and actual authenticated cache admission. */
final class OAuthCimdCacheOrderingTests {
 private static final Instant NOW=Instant.parse("2026-10-31T12:00:00Z");
 private static final String ID="https://client.example.com/metadata",ISSUER="https://issuer.example.com";
 private static final OAuthServerIngressLimits LIMITS=OAuthServerIngressLimits.fromDefaults();
 private static Deadline deadline(){return Deadline.fromNow(Duration.ofSeconds(5));}
 private static byte[] body(String name){return JsonObject.builder().put("client_id",ID).put("client_name",name).put("token_endpoint_auth_method","none").put("redirect_uris",JsonArray.fromElements(List.of(JsonString.fromValue("https://client.example.com/callback")))).build().toJson().getBytes(StandardCharsets.UTF_8);}
 private static StateSealer sealer(){byte[] key=new byte[32];for(int i=0;i<32;i++)key[i]=(byte)(i+1);return StateSealer.withActiveKey(SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(key))).maximumSealedLength(16384).build();}
 private static final class PausingClock extends Clock {
  final AtomicReference<Instant> time=new AtomicReference<>(NOW);
  final AtomicReference<Thread> target=new AtomicReference<>();
  final AtomicReference<List<Instant>> script=new AtomicReference<>();
  final AtomicInteger reads=new AtomicInteger();final int pauseAt;
  final CountDownLatch paused=new CountDownLatch(1),release=new CountDownLatch(1);
  PausingClock(int pauseAt){this.pauseAt=pauseAt;}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
  @Override public @NonNull Instant instant(){
   boolean selected=Thread.currentThread().equals(this.target.get());int read=selected?this.reads.incrementAndGet():0;
   List<Instant> scripted=this.script.get();
   Instant captured=selected && scripted!=null?scripted.get(Math.min(read-1,scripted.size()-1)):Objects.requireNonNull(this.time.get());
   if(selected && read==this.pauseAt){
    this.paused.countDown();try{if(!this.release.await(5,TimeUnit.SECONDS))throw new IllegalStateException("clock release");}
    catch(InterruptedException cancelled){Thread.currentThread().interrupt();}
   }
   return captured;
  }
 }
 private static final class Capture {
  final FutureTask<OAuthClientMetadataDocument> result;final Thread thread;
  Capture(Supplier<OAuthClientMetadataDocument> action){this.result=new FutureTask<>(action::get);this.thread=new Thread(this.result,"cimd-clock-order");this.thread.setDaemon(true);}
  void start(){this.thread.start();}
  OAuthClientMetadataDocument success(){return assertDoesNotThrow(()->this.result.get(2,TimeUnit.SECONDS));}
  void stop() throws InterruptedException{this.thread.interrupt();this.thread.join(3000);assertFalse(this.thread.isAlive());}
 }
 private static final class Fixture {
  final StateSealer sealer=sealer();final InMemoryOAuthClientMetadataCache cache=InMemoryOAuthClientMetadataCache.fromMaximumEntries(32);
  final OAuthClientMetadataPolicy policy=OAuthClientMetadataPolicy.fromAddressResolverAndCache((host,budget)->{throw new AssertionError("no DNS");},this.cache);
  final OAuthClientMetadataCacheCodec codec=new OAuthClientMetadataCacheCodec(ISSUER,this.sealer,this.policy,LIMITS,false,false);
  final PausingClock clock;final AtomicInteger fetches=new AtomicInteger();final AtomicReference<Runnable> fetchHook=new AtomicReference<>();final OAuthClientMetadataFetcher fetcher;
  Fixture(int pauseAt){this(pauseAt,Map.of("Cache-Control",List.of("max-age=120")));}
  Fixture(int pauseAt,Map<String,List<String>> headers){
   this.clock=new PausingClock(pauseAt);
   this.fetcher=new OAuthClientMetadataFetcher(ISSUER,this.sealer,this.policy,LIMITS,false,false,OutboundUriPolicy.defaultInstance(),this.clock,(uri,budget)->{
    int call=this.fetches.incrementAndGet();Runnable hook=this.fetchHook.getAndSet(null);if(hook!=null)hook.run();
    return new RawResponse(200,HttpHeaders.of(headers,(a,b)->true),body("fetch"+call),null,false,Duration.ZERO);
   });
  }
  OAuthClientMetadataCacheEntry seed(Instant expiry){var entry=this.codec.seal(ID,body("cached"),NOW,expiry);assertTrue(this.cache.compareAndSet(this.codec.key(ID),null,entry,Duration.ofSeconds(1)));return entry;}
  Optional<OAuthClientMetadataCacheEntry> stored(){return this.cache.read(this.codec.key(ID),Duration.ofSeconds(1));}
  Capture delayed(boolean fresh){var c=new Capture(()->fresh?this.fetcher.fresh(ID,deadline()):this.fetcher.reusable(ID,deadline()));this.clock.target.set(c.thread);return c;}
  void paused() throws InterruptedException{assertTrue(this.clock.paused.await(2,TimeUnit.SECONDS));}
 }
 @TestFactory Stream<DynamicTest> orderedClockSamplesDoNotTurnCacheHitsIntoFetches() {
  return Stream.of(1,2,3).map(stage->DynamicTest.dynamicTest("clock-stage-"+stage,()->{
   var f=new Fixture(stage);var old=f.seed(NOW.plusSeconds(120));var a=f.delayed(false);var b=new Capture(()->f.fetcher.reusable(ID,deadline()));
   try {
    a.start();f.paused();f.clock.time.set(NOW.plusSeconds(10));b.start();assertEquals("cached",b.success().clientName());
    f.clock.release.countDown();assertEquals("cached",a.success().clientName());assertEquals(0,f.fetches.get());assertEquals(old.getVersion(),assertDoesNotThrow(()->f.stored().orElseThrow()).getVersion());
   } finally {f.clock.release.countDown();a.stop();b.stop();}
  }));
 }
 @Test void correctedReleaseSampleCannotReturnAnExpiredSnapshot() throws Exception {
  var f=new Fixture(3);f.seed(NOW.plusSeconds(5));var a=f.delayed(false);var b=new Capture(()->f.fetcher.fresh(ID,deadline()));
  try{a.start();f.paused();f.clock.time.set(NOW.plusSeconds(5));b.start();b.success();f.clock.release.countDown();assertNotEquals("cached",a.success().clientName());assertEquals(2,f.fetches.get());}
  finally{f.clock.release.countDown();a.stop();b.stop();}
 }
 @Test void reorderedFetchSampleKeepsTheFirstReceiptTimeAndCannotExtendFreshness() throws Exception {
  var f=new Fixture(3);var a=f.delayed(false);var b=new Capture(()->f.fetcher.fresh(ID,deadline()));
  try {
   a.start();f.paused();f.clock.time.set(NOW.plusSeconds(10));b.start();b.success();f.clock.release.countDown();assertEquals("fetch1",a.success().clientName());
   var cached=f.codec.open(ID,assertDoesNotThrow(()->f.stored().orElseThrow()),NOW.plusSeconds(10)).orElseThrow();assertEquals(NOW,cached.fetchedAt());assertEquals(NOW.plusSeconds(120),cached.expiresAt());
  } finally{f.clock.release.countDown();a.stop();b.stop();}
 }
 @Test void recheckedTimePastTheReceiptExpirySkipsOptionalStorage() throws Exception {
  var f=new Fixture(3);var a=f.delayed(false);var b=new Capture(()->f.fetcher.fresh(ID,deadline()));
  try{a.start();f.paused();f.clock.time.set(NOW.plusSeconds(120));b.start();b.success();f.clock.release.countDown();assertEquals("fetch1",a.success().clientName());assertTrue(f.stored().isEmpty());}
  finally{f.clock.release.countDown();a.stop();b.stop();}
 }
 @Test void reorderedOlderFetchCannotReplaceAConcurrentWinner() throws Exception {
  var f=new Fixture(3);var a=f.delayed(false);var b=new Capture(()->f.fetcher.reusable(ID,deadline()));
  try{a.start();f.paused();f.clock.time.set(NOW.plusSeconds(10));b.start();assertEquals("fetch2",b.success().clientName());var winner=assertDoesNotThrow(()->f.stored().orElseThrow());f.clock.release.countDown();a.success();assertEquals(winner.getVersion(),assertDoesNotThrow(()->f.stored().orElseThrow()).getVersion());}
  finally{f.clock.release.countDown();a.stop();b.stop();}
 }
 @Test void aRollbackDuringResamplingRetainsTheHighestTimeActuallyRead() throws Exception {
  var f=new Fixture(3);f.fetchHook.set(()->f.clock.time.set(NOW.plusSeconds(100)));var a=f.delayed(false);var b=new Capture(()->f.fetcher.fresh(ID,deadline()));
  try {
   a.start();f.paused();f.clock.time.set(NOW.plusSeconds(10));b.start();b.success();f.clock.release.countDown();a.success();assertTrue(f.stored().isEmpty());
   f.clock.time.set(NOW.plusSeconds(11));assertEquals("fetch3",f.fetcher.reusable(ID,deadline()).clientName());assertTrue(f.stored().isEmpty());
   f.clock.time.set(NOW.plusSeconds(101));assertEquals("fetch4",f.fetcher.reusable(ID,deadline()).clientName());assertTrue(f.stored().isPresent());
  } finally{f.clock.release.countDown();a.stop();b.stop();}
 }
 @Test void aLateObservedRollbackPreventsOptionalPublication() throws Exception {
  var f=new Fixture(4);var a=f.delayed(false);var b=new Capture(()->f.fetcher.fresh(ID,deadline()));
  try{a.start();f.paused();f.clock.time.set(NOW.plusSeconds(10));b.start();b.success();f.clock.time.set(NOW.plusSeconds(5));f.clock.release.countDown();a.success();assertTrue(f.stored().isEmpty());}
  finally{f.clock.release.countDown();a.stop();b.stop();}
 }
 @TestFactory Stream<DynamicTest> aTransientObservedRollbackStaysLocalForTheEntireOperation() {
  return Stream.of(1,2,3).map(stage->DynamicTest.dynamicTest("rollback-stage-"+stage,()->{
   var f=new Fixture(0);var old=f.seed(NOW.plusSeconds(120));f.clock.time.set(NOW.plusSeconds(10));assertEquals("cached",f.fetcher.reusable(ID,deadline()).clientName());
   f.clock.target.set(Thread.currentThread());
   f.clock.script.set(stage==1?List.of(NOW.plusSeconds(5),NOW.plusSeconds(10)):stage==2?List.of(NOW.plusSeconds(10),NOW.plusSeconds(5),NOW.plusSeconds(10)):List.of(NOW.plusSeconds(10),NOW.plusSeconds(10),NOW.plusSeconds(5),NOW.plusSeconds(10)));
   assertEquals("fetch1",f.fetcher.reusable(ID,deadline()).clientName());assertEquals(old.getVersion(),assertDoesNotThrow(()->f.stored().orElseThrow()).getVersion());
  }));
 }
 @Test void trueRollbackStillPreventsReuseAndPublicationUntilTimeCatchesUp() {
  var f=new Fixture(0);var old=f.seed(NOW.plusSeconds(120));f.clock.time.set(NOW.plusSeconds(10));assertEquals("cached",f.fetcher.reusable(ID,deadline()).clientName());
  f.clock.time.set(NOW.plusSeconds(5));assertEquals("fetch1",f.fetcher.reusable(ID,deadline()).clientName());assertEquals("fetch2",f.fetcher.reusable(ID,deadline()).clientName());assertEquals(old.getVersion(),assertDoesNotThrow(()->f.stored().orElseThrow()).getVersion());
  f.clock.time.set(NOW.plusSeconds(11));assertEquals("cached",f.fetcher.reusable(ID,deadline()).clientName());
 }
 @Test void cancellationDuringAnOrderedSampleCannotFetchOrReplaceTheCache() throws Exception {
  var f=new Fixture(1);var old=f.seed(NOW.plusSeconds(120));var a=f.delayed(false);
  try{a.start();f.paused();a.thread.interrupt();var error=assertThrows(ExecutionException.class,()->a.result.get(2,TimeUnit.SECONDS));assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,assertInstanceOf(OAuthServerAdmissionFailure.class,error.getCause()).reason());assertEquals(0,f.fetches.get());assertEquals(old.getVersion(),assertDoesNotThrow(()->f.stored().orElseThrow()).getVersion());}
  finally{f.clock.release.countDown();a.stop();}
 }
 @TestFactory Stream<DynamicTest> sharedDirectivesAndNamedVariantsAreReusableThroughTheActualCache() {
  return Stream.of("s-maxage=5,max-age=120","s-maxage=5","max-age=5").map(control->DynamicTest.dynamicTest(control,()->{
   var f=new Fixture(0,Map.of("Cache-Control",List.of(control),"Vary",List.of("Accept,Accept-Encoding,X-Absent")));
   assertEquals("fetch1",f.fetcher.reusable(ID,deadline()).clientName());assertEquals("fetch1",f.fetcher.reusable(ID,deadline()).clientName());assertEquals(1,f.fetches.get());assertEquals(NOW.plusSeconds(5),assertDoesNotThrow(()->f.stored().orElseThrow()).getExpiresAt());
   f.clock.time.set(NOW.plusSeconds(5));assertEquals("fetch2",f.fetcher.reusable(ID,deadline()).clientName());
  }));
 }
 @Test void sharedZeroAgeCannotBorrowPrivateMaxAge() {
  var f=new Fixture(0,Map.of("Cache-Control",List.of("s-maxage=0,max-age=120")));f.fetcher.reusable(ID,deadline());f.fetcher.reusable(ID,deadline());assertEquals(2,f.fetches.get());assertTrue(f.stored().isEmpty());
 }
 @Test void freshCredentialOperationsStillBypassSharedReusableVariants() {
  var f=new Fixture(0,Map.of("Cache-Control",List.of("s-maxage=120"),"Vary",List.of("Accept")));f.fetcher.reusable(ID,deadline());var old=assertDoesNotThrow(()->f.stored().orElseThrow());
  assertEquals("fetch2",f.fetcher.fresh(ID,deadline()).clientName());assertEquals("fetch3",f.fetcher.fresh(ID,deadline()).clientName());assertEquals(old.getVersion(),assertDoesNotThrow(()->f.stored().orElseThrow()).getVersion());
 }
 private static OAuthClientMetadataCacheEntry legacyEntry(Fixture f) {
  String namespace=OAuthAuthorizationRecord.digest(JsonObject.builder().put("schema",1L).put("issuer",ISSUER).put("originsRestricted",false).put("origins",JsonArray.fromElements(List.of()))
   .put("documentBytes",f.policy.getMaximumDocumentBytes().longValue()).put("freshness",f.policy.getMaximumFreshness().toString())
   .put("clientIdLength",(long)LIMITS.clientIdLength).put("redirects",(long)LIMITS.redirects).put("native",false).put("localhost",false).build().toJson());
  var key=OAuthClientMetadataCacheKey.fromStoredForm("revetsec:cimd-cache:1:"+namespace+":"+OAuthAuthorizationRecord.digest(ID));String version="A".repeat(43);Instant expiry=NOW.plusSeconds(120);
  String plaintext=JsonObject.builder().put("schema",1L).put("namespace",namespace).put("key",key.getStorageKey()).put("version",version).put("fetchedAt",NOW.toString()).put("expiresAt",expiry.getEpochSecond()).put("body",Base64Url.encode(body("legacy"))).build().toJson();
  String sealed=SealedStateAccess.get().seal(f.sealer,SealedStateType.AS_CLIENT_METADATA_CACHE,plaintext,"revetsec/as-client-metadata-cache/v1:"+key.getStorageKey(),expiry);
  return OAuthClientMetadataCacheEntry.fromStoredForm(key,version,expiry,sealed);
 }
 @Test void entriesWithoutTheSharedPolicyAndFixedRequestBindingAreColdMisses() {
  var f=new Fixture(0);var old=legacyEntry(f);assertNotEquals(old.getKey(),f.codec.key(ID));assertTrue(f.codec.open(ID,old,NOW).isEmpty());
 }
 @Test void rekeyingALegacyEnvelopeCannotTurnItIntoACurrentVariant() {
  var f=new Fixture(0);var old=legacyEntry(f);var rekeyed=OAuthClientMetadataCacheEntry.fromStoredForm(f.codec.key(ID),old.getVersion(),old.getExpiresAt(),old.toSealedForm());assertTrue(f.codec.open(ID,rekeyed,NOW).isEmpty());
 }
}
