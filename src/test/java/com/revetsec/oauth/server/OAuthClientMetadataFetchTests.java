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
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HttpExchangeException;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class OAuthClientMetadataFetchTests {
 private static final @NonNull Instant NOW=Instant.parse("2026-10-06T12:00:00Z");
 private static final @NonNull String ID="https://client.example.com/metadata", ISSUER="https://issuer.example.com/tenant";
 private static byte @NonNull [] body(@NonNull String name) {
  return JsonObject.builder().put("client_id",ID).put("client_name",name).put("token_endpoint_auth_method","none")
   .put("redirect_uris",com.revetsec.json.JsonArray.fromElements(List.of(JsonString.fromValue("https://client.example.com/callback")))).build().toJson().getBytes(java.nio.charset.StandardCharsets.UTF_8);
 }
 private static @NonNull StateSealer sealer(@NonNull String id, byte fill, int cap) {
  byte[] bytes=new byte[32];for(int i=0;i<bytes.length;i++)bytes[i]=(byte)(fill+i);
  return StateSealer.withActiveKey(SealingKey.fromBase64(id,Base64.getEncoder().encodeToString(bytes))).maximumSealedLength(cap).build();
 }
 private static @NonNull StateSealer sealer() {return sealer("k",(byte)1,16384);}
 private static @NonNull OAuthClientMetadataPolicy policy(@Nullable OAuthClientMetadataCache cache) {
  return OAuthClientMetadataPolicy.withAddressResolver((host,budget)->{throw new AssertionError("No resolver in deterministic seam.");}).cache(cache).build();
 }
 private static @NonNull OAuthClientMetadataCacheCodec codec(@NonNull StateSealer sealer,@NonNull OAuthClientMetadataPolicy policy) {
  return new OAuthClientMetadataCacheCodec(ISSUER,sealer,policy,OAuthServerIngressLimits.fromDefaults(),false,false);
 }
 private static @NonNull RawResponse response(@NonNull String name) {return response(name,"max-age=120");}
 private static @NonNull RawResponse response(@NonNull String name,@NonNull String control) {
  return new RawResponse(200,HttpHeaders.of(Map.of("Cache-Control",List.of(control)),(a,b)->true),body(name),null,false,Duration.ZERO);
 }
 private static @NonNull Deadline deadline() {return Deadline.fromNow(Duration.ofSeconds(5));}
 private static @NonNull OAuthClientMetadataFetcher fetcher(@NonNull StateSealer sealer,@NonNull OAuthClientMetadataPolicy policy,
   @NonNull Clock clock,OAuthClientMetadataFetcher.@NonNull Transport transport) {
  return new OAuthClientMetadataFetcher(ISSUER,sealer,policy,OAuthServerIngressLimits.fromDefaults(),false,false,OutboundUriPolicy.defaultInstance(),clock,transport);
 }
 @Test void productionTransportInvokesPinnedResolverBeforeRejectingPrivateAddress() {
  AtomicInteger resolutions=new AtomicInteger();
  OAuthClientMetadataPolicy enabled=OAuthClientMetadataPolicy.fromAddressResolver((host,budget)->{
   assertEquals("client.example.com",host);resolutions.incrementAndGet();
   return List.of(java.net.InetAddress.getLoopbackAddress());
  });
  OAuthClientMetadataFetcher fetcher=new OAuthClientMetadataFetcher(ISSUER,sealer(),enabled,
   OAuthServerIngressLimits.fromDefaults(),false,false,OutboundUriPolicy.defaultInstance(),Clock.fixed(NOW,ZoneOffset.UTC),Duration.ofSeconds(1));
  infrastructure(()->fetcher.reusable(ID,deadline()));
  assertEquals(1,resolutions.get());
 }
 @Test void nullTransportResultFailsClosedBeforeCaching() {
  InMemoryOAuthClientMetadataCache cache=InMemoryOAuthClientMetadataCache.fromMaximumEntries(8);
  OAuthClientMetadataPolicy enabled=policy(cache);
  OAuthClientMetadataFetcher.Transport absent=new OAuthClientMetadataFetcher.Transport() {
   @SuppressWarnings("NullAway") @Override public @NonNull RawResponse fetch(@NonNull URI uri,@NonNull Deadline budget) {return null;}
  };
  OAuthClientMetadataFetcher fetcher=fetcher(sealer(),enabled,Clock.fixed(NOW,ZoneOffset.UTC),absent);
  infrastructure(()->fetcher.reusable(ID,deadline()));
  assertTrue(cache.read(codec(sealer(),enabled).key(ID),Duration.ofSeconds(1)).isEmpty());
 }
 private static void infrastructure(org.junit.jupiter.api.function.@NonNull Executable operation) {
  OAuthServerAdmissionFailure failure=assertThrows(OAuthServerAdmissionFailure.class,operation);
  assertEquals(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE,failure.reason());assertNull(failure.getCause());
  assertEquals("OAuth server admission failed.",failure.getMessage());assertEquals(0,failure.getSuppressed().length);
 }
 @Test void serializedRoundTripNeverExposesMetadataAndCanonicalIdentityIsExact() {
  OAuthClientMetadataCacheCodec codec=codec(sealer(),policy(null));
  OAuthClientMetadataCacheEntry entry=codec.seal(ID,body("display"),NOW,NOW.plusSeconds(120));
  OAuthClientMetadataCacheEntry copy=OAuthClientMetadataCacheEntry.fromStoredForm(OAuthClientMetadataCacheKey.fromStoredForm(entry.getKey().getStorageKey()),entry.getVersion(),entry.getExpiresAt(),entry.toSealedForm());
  var cached=codec.open(ID,copy,NOW.plusSeconds(1)).orElseThrow();assertEquals("display",cached.document().clientName());
  assertEquals(NOW,cached.fetchedAt());assertEquals(NOW.plusSeconds(120),cached.expiresAt());
  assertEquals("CachedClientMetadata{metadata=redacted}",cached.toString());assertFalse(cached.toString().contains("display"));
  assertEquals(codec.key(ID),codec(sealer(),policy(null)).key(ID));
  assertNotEquals(codec.key(ID),codec.key("https://CLIENT.example.com/metadata"));
  assertNotEquals(codec.key(ID),codec.key(ID+"?a=1"));
  assertTrue(codec.open(ID.toUpperCase(java.util.Locale.ROOT),entry,NOW).isEmpty());
 }
 @Test void issuerConfigurationAndPurposeAreSeparated() {
  StateSealer sealer=sealer();OAuthClientMetadataPolicy p=policy(null);OAuthClientMetadataCacheCodec c=codec(sealer,p);
  var entry=c.seal(ID,body("display"),NOW,NOW.plusSeconds(120));
  OAuthClientMetadataCacheCodec other=new OAuthClientMetadataCacheCodec(ISSUER+"/",sealer,p,OAuthServerIngressLimits.fromDefaults(),false,false);
  assertTrue(other.open(ID,entry,NOW).isEmpty());assertNotEquals(c.key(ID),other.key(ID));
  OAuthClientMetadataPolicy narrower=OAuthClientMetadataPolicy.withAddressResolver((h,b)->List.of()).maximumFreshness(Duration.ofSeconds(30)).build();
  assertTrue(codec(sealer,narrower).open(ID,entry,NOW).isEmpty());
  assertNotEquals(c.key(ID),new OAuthClientMetadataCacheCodec(ISSUER,sealer,p,OAuthServerIngressLimits.fromDefaults(),true,false).key(ID));
  String app=sealer.seal("untrusted", "context",Duration.ofSeconds(300));
  assertTrue(c.open(ID,OAuthClientMetadataCacheEntry.fromStoredForm(entry.getKey(),entry.getVersion(),entry.getExpiresAt(),app),NOW).isEmpty());
  String store=SealedStateAccess.get().seal(sealer,SealedStateType.AS_RECORD,"{}",context(entry),entry.getExpiresAt());
  assertTrue(c.open(ID,copy(entry,store),NOW).isEmpty());
 }
 private static @NonNull String context(@NonNull OAuthClientMetadataCacheEntry entry) {return "revetsec/as-client-metadata-cache/v1:"+entry.getKey().getStorageKey();}
 private static @NonNull OAuthClientMetadataCacheEntry copy(@NonNull OAuthClientMetadataCacheEntry entry,@NonNull String sealed) {
  return OAuthClientMetadataCacheEntry.fromStoredForm(entry.getKey(),entry.getVersion(),entry.getExpiresAt(),sealed);
 }
 @Test void carrierTamperingAndWrongKeysAreMisses() {
  StateSealer sealer=sealer();var c=codec(sealer,policy(null));var entry=c.seal(ID,body("display".repeat(100)),NOW,NOW.plusSeconds(120));
  assertTrue(c.open(ID,copy(entry,entry.toSealedForm().substring(0,entry.toSealedForm().length()-2)+"AA"),NOW).isEmpty());
  assertTrue(c.open(ID,OAuthClientMetadataCacheEntry.fromStoredForm(entry.getKey(),"A".repeat(43),entry.getExpiresAt(),entry.toSealedForm()),NOW).isEmpty());
  assertTrue(c.open(ID,OAuthClientMetadataCacheEntry.fromStoredForm(entry.getKey(),entry.getVersion(),NOW.plusSeconds(121),entry.toSealedForm()),NOW).isEmpty());
  assertTrue(codec(sealer("other",(byte)2,16384),policy(null)).open(ID,entry,NOW).isEmpty());
  assertTrue(codec(sealer("k",(byte)2,16384),policy(null)).open(ID,entry,NOW).isEmpty());
  assertTrue(codec(sealer("k",(byte)1,1024),policy(null)).open(ID,entry,NOW).isEmpty());
 }
 @Test void oldDecryptKeyWorksOnlyWhileRetained() {
  StateSealer old=sealer();var c=codec(old,policy(null));var entry=c.seal(ID,body("display"),NOW,NOW.plusSeconds(120));
  byte[] bytes=new byte[32];for(int i=0;i<bytes.length;i++)bytes[i]=(byte)(1+i);SealingKey previous=SealingKey.fromBase64("k",Base64.getEncoder().encodeToString(bytes));
  for(int i=0;i<bytes.length;i++)bytes[i]=(byte)(2+i);StateSealer rotated=StateSealer.withActiveKey(SealingKey.fromBase64("new",Base64.getEncoder().encodeToString(bytes))).verificationKeys(List.of(previous)).maximumSealedLength(16384).build();
  assertTrue(codec(rotated,policy(null)).open(ID,entry,NOW).isPresent());
  assertTrue(codec(sealer("new",(byte)2,16384),policy(null)).open(ID,entry,NOW).isEmpty());
 }
 @Test void expiryFutureAndPreciseFetchedTimeAreAuthenticated() {
  var c=codec(sealer(),policy(null));var entry=c.seal(ID,body("display"),NOW.plusNanos(1),NOW.plusSeconds(120));
  assertTrue(c.open(ID,entry,NOW).isEmpty());assertTrue(c.open(ID,entry,NOW.plusNanos(1)).isPresent());
  assertTrue(c.open(ID,entry,NOW.plusSeconds(120)).isEmpty());assertTrue(c.open(ID,entry,NOW.plusSeconds(121)).isEmpty());
  assertEquals(NOW.plusNanos(1),c.authenticatedFetchedAt(ID,entry).orElseThrow());
  assertThrows(IllegalArgumentException.class,()->c.seal(ID,body("display"),NOW,NOW.plusSeconds(301)));
  assertThrows(IllegalArgumentException.class,()->c.seal(ID,body("display"),NOW,NOW));
  assertThrows(IllegalArgumentException.class,()->c.seal(ID,body("display"),NOW,NOW.plusNanos(1)));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> authenticatedButMalformedSchemaAndBodyAreStillUnusable() {
  return Stream.of("schema","namespace","key","version","expiresAt","fetchedAt","body","extra","missing","json-array","json-invalid","body-invalid","body-noncanonical","body-too-large","future","overlong-lifetime").map(field->DynamicTest.dynamicTest(field,()->{
   StateSealer sealer=sealer();var c=codec(sealer,policy(null));var entry=c.seal(ID,body("display"),NOW,NOW.plusSeconds(120));
   String text=SealedStateAccess.get().unseal(sealer,SealedStateType.AS_CLIENT_METADATA_CACHE,entry.toSealedForm(),context(entry),Clock.fixed(NOW,ZoneOffset.UTC));
   JsonObject original=(JsonObject)com.revetsec.internal.json.JsonCodec.parse(StrictUtf8.encode(text),com.revetsec.internal.json.JsonLimits.protocolDocument(16000));JsonObject.Builder builder=JsonObject.builder();
   for(var item:original.getMembers().entrySet()) {
    if((field.equals("missing")||field.startsWith("body-"))&&item.getKey().equals("body"))continue;
    if((field.equals("future")||field.equals("overlong-lifetime"))&&item.getKey().equals("fetchedAt"))continue;
    if(item.getKey().equals(field))builder.put(item.getKey(),"wrong");else builder.put(item.getKey(),item.getValue());
   }
   if(field.equals("extra"))builder.put("extra",1L);
   if(field.equals("body-invalid"))builder.put("body",com.revetsec.internal.encoding.Base64Url.encode(new byte[]{(byte)0xc0,(byte)0x80}));
   if(field.equals("body-noncanonical"))builder.put("body","AB");
   if(field.equals("body-too-large"))builder.put("body","A".repeat(7000));
   if(field.equals("future"))builder.put("fetchedAt",NOW.plusSeconds(1).toString());
   if(field.equals("overlong-lifetime"))builder.put("fetchedAt",NOW.minusSeconds(300).toString());
   String changed=field.equals("json-array")?"[]":field.equals("json-invalid")?"{":builder.build().toJson();
   String sealed=SealedStateAccess.get().seal(sealer,SealedStateType.AS_CLIENT_METADATA_CACHE,changed,context(entry),entry.getExpiresAt());
   assertTrue(c.open(ID,copy(entry,sealed),NOW).isEmpty());
  }));
 }
 @Test void twoIndependentCoordinatorsReuseOnlyAuthenticatedSharedRecords() {
  OAuthClientMetadataCache cache=InMemoryOAuthClientMetadataCache.fromDefaults();var p=policy(cache);StateSealer s=sealer();AtomicInteger calls=new AtomicInteger();
  OAuthClientMetadataFetcher.Transport transport=(uri,d)->{calls.incrementAndGet();return response("display");};
  var first=fetcher(s,p,Clock.fixed(NOW,ZoneOffset.UTC),transport);var second=fetcher(s,p,Clock.fixed(NOW.plusSeconds(1),ZoneOffset.UTC),transport);
  assertEquals("display",first.reusable(ID,deadline()).clientName());assertEquals("display",second.reusable(ID,deadline()).clientName());assertEquals(1,calls.get());
  assertEquals("display",second.fresh(ID,deadline()).clientName());assertEquals("display",second.fresh(ID,deadline()).clientName());assertEquals(3,calls.get());
 }
 @Test void defaultSelectionIsPerCoordinatorAndConstructionDoesNoCallbacks() {
  var p=policy(null);StateSealer s=sealer();AtomicInteger calls=new AtomicInteger();var clock=new MutableClock(NOW);
  var a=fetcher(s,p,clock,(u,d)->{calls.incrementAndGet();return response("display");});var b=fetcher(s,p,clock,(u,d)->{calls.incrementAndGet();return response("display");});
  assertEquals(0,calls.get());assertEquals(0,clock.calls.get());a.reusable(ID,deadline());b.reusable(ID,deadline());assertEquals(2,calls.get());
 }
 @Test void localObservedRollbackDisablesReuseAndWrites() {
  var cache=InMemoryOAuthClientMetadataCache.fromDefaults();var p=policy(cache);var clock=new MutableClock(NOW);AtomicInteger calls=new AtomicInteger();
  var f=fetcher(sealer(),p,clock,(u,d)->response("fetch"+calls.incrementAndGet()));
  assertEquals("fetch1",f.reusable(ID,deadline()).clientName());clock.time.set(NOW.plusSeconds(10));assertEquals("fetch1",f.reusable(ID,deadline()).clientName());
  clock.time.set(NOW.plusSeconds(5));assertEquals("fetch2",f.reusable(ID,deadline()).clientName());assertEquals("fetch3",f.reusable(ID,deadline()).clientName());
  clock.time.set(NOW.plusSeconds(11));assertEquals("fetch1",f.reusable(ID,deadline()).clientName());
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> noReuseOrMalformedSuccessfulFetchDeletesOnlyObservedCarrier() {
  return Stream.of("no-store","no-cache","max-age=0","public","max-age=1,max-age=2").map(control->DynamicTest.dynamicTest(control,()->{
   var cache=InMemoryOAuthClientMetadataCache.fromDefaults();var p=policy(cache);StateSealer s=sealer();var c=codec(s,p);
   var old=c.seal(ID,body("old"),NOW.minusSeconds(200),NOW.minusSeconds(80));assertTrue(cache.compareAndSet(c.key(ID),null,old,Duration.ofSeconds(1)));
   AtomicInteger calls=new AtomicInteger();var f=fetcher(s,p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{calls.incrementAndGet();return response("fresh",control);});
   assertEquals("fresh",f.reusable(ID,deadline()).clientName());assertTrue(cache.read(c.key(ID),Duration.ofSeconds(1)).isEmpty());
   f.reusable(ID,deadline());assertEquals(2,calls.get());
  }));
 }
 @Test void exhaustedSealerCapSkipsOptionalWriteWithoutChangingConfiguredLimit() {
  var cache=InMemoryOAuthClientMetadataCache.fromDefaults();var p=policy(cache);StateSealer s=sealer("k",(byte)1,1024);AtomicInteger calls=new AtomicInteger();
  var f=fetcher(s,p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{calls.incrementAndGet();return response("display".repeat(100));});
  f.reusable(ID,deadline());f.reusable(ID,deadline());assertEquals(2,calls.get());assertEquals(1024,SealedStateAccess.get().getMaximumSealedLength(s));
  assertTrue(cache.read(codec(s,p).key(ID),Duration.ofSeconds(1)).isEmpty());
 }
 @Test void failedFetchAndInvalidDocumentNeverFallbackOrCacheError() {
  var cache=InMemoryOAuthClientMetadataCache.fromDefaults();var p=policy(cache);StateSealer s=sealer();var c=codec(s,p);var old=c.seal(ID,body("old"),NOW.minusSeconds(200),NOW.minusSeconds(80));assertTrue(cache.compareAndSet(c.key(ID),null,old,Duration.ofSeconds(1)));
  var failed=fetcher(s,p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{throw new IllegalStateException("untrusted remote diagnostic");});
  infrastructure(()->failed.reusable(ID,deadline()));assertEquals(old.getVersion(),cache.read(c.key(ID),Duration.ofSeconds(1)).orElseThrow().getVersion());
  var invalid=fetcher(s,p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->new RawResponse(200,HttpHeaders.of(Map.of(),(a,b)->true),new byte[]{1},null,false,Duration.ZERO));
  assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,assertThrows(OAuthServerAdmissionFailure.class,()->invalid.reusable(ID,deadline())).reason());
  var error=fetcher(s,p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->new RawResponse(503,HttpHeaders.of(Map.of(),(a,b)->true),new byte[0],null,false,Duration.ZERO));infrastructure(()->error.reusable(ID,deadline()));
 }
 @Test void slowOldFetchCannotOverwriteConcurrentNewerWriteOrRemoveIt() {
  var cache=InMemoryOAuthClientMetadataCache.fromDefaults();var p=policy(cache);StateSealer s=sealer();var c=codec(s,p);
  var newer=c.seal(ID,body("newer"),NOW.plusSeconds(1),NOW.plusSeconds(121));
  var f=fetcher(s,p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{assertTrue(cache.compareAndSet(c.key(ID),null,newer,Duration.ofSeconds(1)));return response("older");});
  assertEquals("older",f.reusable(ID,deadline()).clientName());assertEquals(newer.getVersion(),cache.read(c.key(ID),Duration.ofSeconds(1)).orElseThrow().getVersion());
 }
 @Test void authenticFutureRecordCannotBeOverwrittenByOlderClockFetch() {
  var cache=InMemoryOAuthClientMetadataCache.fromDefaults();var p=policy(cache);StateSealer s=sealer();var c=codec(s,p);
  var newer=c.seal(ID,body("newer"),NOW.plusSeconds(10),NOW.plusSeconds(130));assertTrue(cache.compareAndSet(c.key(ID),null,newer,Duration.ofSeconds(1)));
  var f=fetcher(s,p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->response("older","no-store"));assertEquals("older",f.reusable(ID,deadline()).clientName());
  assertEquals(newer.getVersion(),cache.read(c.key(ID),Duration.ofSeconds(1)).orElseThrow().getVersion());
 }
 @Test void corruptedCarrierRequiresFreshAdmissionAndMatchedReplacement() {
  var cache=InMemoryOAuthClientMetadataCache.fromDefaults();var p=policy(cache);StateSealer s=sealer();var c=codec(s,p);
  var bad=OAuthClientMetadataCacheEntry.fromStoredForm(c.key(ID),"A".repeat(43),NOW.plusSeconds(120),"opaque");assertTrue(cache.compareAndSet(c.key(ID),null,bad,Duration.ofSeconds(1)));
  var f=fetcher(s,p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->response("fresh"));assertEquals("fresh",f.reusable(ID,deadline()).clientName());
  assertNotEquals(bad.getVersion(),cache.read(c.key(ID),Duration.ofSeconds(1)).orElseThrow().getVersion());
 }
 @Test void providerFaultsStayOptionalAndInterruptedFaultAborts() {
  for(var reason:List.of(OAuthClientMetadataCacheException.Reason.UNAVAILABLE,OAuthClientMetadataCacheException.Reason.TIMEOUT)) {
   var p=policy(new FaultCache(reason));AtomicInteger calls=new AtomicInteger();var f=fetcher(sealer(),p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{calls.incrementAndGet();return response("fresh");});
   assertEquals("fresh",f.reusable(ID,deadline()).clientName());assertEquals(1,calls.get());
  }
  AtomicInteger calls=new AtomicInteger();var f=fetcher(sealer(),policy(new FaultCache(OAuthClientMetadataCacheException.Reason.INTERRUPTED)),Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{calls.incrementAndGet();return response("fresh");});
  try {infrastructure(()->f.reusable(ID,deadline()));assertTrue(Thread.currentThread().isInterrupted());assertEquals(0,calls.get());}finally{Thread.interrupted();}
 }
 @Test void writeFailureDoesNotTurnValidFetchIntoStaleFallback() {
  OAuthClientMetadataCache bad=new OAuthClientMetadataCache(){
   @Override public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(@NonNull OAuthClientMetadataCacheKey k,@NonNull Duration b){return Optional.empty();}
   @Override public @NonNull Boolean compareAndSet(@NonNull OAuthClientMetadataCacheKey k,@Nullable String v,@Nullable OAuthClientMetadataCacheEntry e,@NonNull Duration b){throw new IllegalStateException("backend diagnostic");}
  };
  assertEquals("fresh",fetcher(sealer(),policy(bad),Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->response("fresh")).reusable(ID,deadline()).clientName());
 }
 @Test void interruptedOptionalWriteAbortsReleaseAndRestoresTheFlag() {
  OAuthClientMetadataCache interrupted=new OAuthClientMetadataCache(){
   @Override public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(@NonNull OAuthClientMetadataCacheKey key,@NonNull Duration budget){return Optional.empty();}
   @Override public @NonNull Boolean compareAndSet(@NonNull OAuthClientMetadataCacheKey key,@Nullable String version,@Nullable OAuthClientMetadataCacheEntry replacement,@NonNull Duration budget){throw OAuthClientMetadataCacheException.fromReason(OAuthClientMetadataCacheException.Reason.INTERRUPTED);}
  };
  var f=fetcher(sealer(),policy(interrupted),Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->response("fresh"));
  try {infrastructure(()->f.reusable(ID,deadline()));assertTrue(Thread.currentThread().isInterrupted());}
  finally {Thread.interrupted();}
 }
 @Test void originalDeadlineAndInterruptAreCheckedAroundCallbacks() {
  AtomicInteger calls=new AtomicInteger();var f=fetcher(sealer(),policy(null),Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{calls.incrementAndGet();return response("fresh");});
  infrastructure(()->f.reusable(ID,Deadline.fromNow(Duration.ZERO)));assertEquals(0,calls.get());
  try{Thread.currentThread().interrupt();infrastructure(()->f.fresh(ID,deadline()));assertEquals(0,calls.get());}finally{Thread.interrupted();}
  var slow=fetcher(sealer(),policy(null),Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{while(!d.isExpired())Thread.onSpinWait();return response("fresh");});
  infrastructure(()->slow.reusable(ID,Deadline.fromNow(Duration.ofMillis(5))));
 }
 @Test void unsafeOriginAndCurrentRestrictionRejectBeforeAnyProviderOrFetch() {
  AtomicInteger calls=new AtomicInteger();var f=fetcher(sealer(),policy(null),Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{calls.incrementAndGet();return response("fresh");});
  assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,assertThrows(OAuthServerAdmissionFailure.class,()->f.reusable("https://127.0.0.1/metadata",deadline())).reason());assertEquals(0,calls.get());
 }
 @Test void actualParallelAdmissionIsBoundedAndBypassesDoNotShareFetch() throws Exception {
  var p=OAuthClientMetadataPolicy.withAddressResolver((h,b)->List.of()).maximumConcurrentFetches(1).build();
  CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);AtomicInteger calls=new AtomicInteger();AtomicReference<Throwable> error=new AtomicReference<>();
  var f=fetcher(sealer(),p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{calls.incrementAndGet();entered.countDown();try{if(!release.await(2,TimeUnit.SECONDS))throw new AssertionError("release");}catch(InterruptedException failure){Thread.currentThread().interrupt();throw new IllegalStateException("interrupted");}return response("fresh");});
  Thread worker=new Thread(()->{try{f.fresh(ID,deadline());}catch(Throwable failure){error.set(failure);}},"cimd-owned-test");worker.start();
  try{assertTrue(entered.await(2,TimeUnit.SECONDS));infrastructure(()->f.fresh(ID,deadline()));assertEquals(1,calls.get());}finally{release.countDown();worker.join(3000);if(worker.isAlive()){worker.interrupt();worker.join(3000);}}
  assertFalse(worker.isAlive());assertNull(error.get());f.fresh(ID,deadline());assertEquals(2,calls.get());
 }
 @Test void productionSelectionUsesPinnedDriverAndOriginalResolverBudget() {
  AtomicInteger calls=new AtomicInteger();AtomicReference<Duration> budget=new AtomicReference<>();
  var p=OAuthClientMetadataPolicy.withAddressResolver((host,remaining)->{assertEquals("client.example.com",host);calls.incrementAndGet();budget.set(remaining);try{return List.of(java.net.InetAddress.getByAddress(new byte[]{127,0,0,1}));}catch(java.net.UnknownHostException failure){throw new AssertionError(failure);}}).build();
  var f=new OAuthClientMetadataFetcher(ISSUER,sealer(),p,OAuthServerIngressLimits.fromDefaults(),false,false,OutboundUriPolicy.defaultInstance(),Clock.fixed(NOW,ZoneOffset.UTC),Duration.ofSeconds(1));
  infrastructure(()->f.fresh(ID,deadline()));assertEquals(1,calls.get());assertTrue(java.util.Objects.requireNonNull(budget.get()).compareTo(Duration.ofSeconds(1))<=0);
  assertThrows(IllegalArgumentException.class,()->new OAuthClientMetadataFetcher(ISSUER,sealer(),p,OAuthServerIngressLimits.fromDefaults(),false,false,OutboundUriPolicy.defaultInstance(),Clock.fixed(NOW,ZoneOffset.UTC),Duration.ZERO));
 }
 @Test void callbackBudgetExpiryNeverStartsAnotherFetch() {
  AtomicInteger calls=new AtomicInteger();OAuthClientMetadataCache slow=new OAuthClientMetadataCache(){
   @Override public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(@NonNull OAuthClientMetadataCacheKey key,@NonNull Duration budget){Deadline end=Deadline.fromNow(budget);while(!end.isExpired())Thread.onSpinWait();return Optional.empty();}
   @Override public @NonNull Boolean compareAndSet(@NonNull OAuthClientMetadataCacheKey key,@Nullable String version,@Nullable OAuthClientMetadataCacheEntry replacement,@NonNull Duration budget){throw new AssertionError("no write");}
  };
  var f=fetcher(sealer(),policy(slow),Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{calls.incrementAndGet();return response("fresh");});
  infrastructure(()->f.reusable(ID,Deadline.fromNow(Duration.ofMillis(5))));assertEquals(0,calls.get());
 }
 @Test void failedClockAndNullProviderAreFixedFailuresOrBoundedFreshFallback() {
  Clock broken=new Clock(){@Override public @NonNull Instant instant(){throw new IllegalStateException("clock diagnostic");}@Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}@Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}};
  infrastructure(()->fetcher(sealer(),policy(null),broken,(u,d)->response("fresh")).reusable(ID,deadline()));
  OAuthClientMetadataCache nullCache=new OAuthClientMetadataCache(){
   @SuppressWarnings("NullAway") @Override public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(@NonNull OAuthClientMetadataCacheKey key,@NonNull Duration budget){return null;}
   @Override public @NonNull Boolean compareAndSet(@NonNull OAuthClientMetadataCacheKey key,@Nullable String version,@Nullable OAuthClientMetadataCacheEntry replacement,@NonNull Duration budget){throw new AssertionError("failed read skips optional write");}
  };
  assertEquals("fresh",fetcher(sealer(),policy(nullCache),Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->response("fresh")).reusable(ID,deadline()).clientName());
 }
 @Test void originSnapshotNamespaceIsStableAcrossInsertionOrderAndRestrictsCurrentReads() {
  var p=OAuthClientMetadataPolicy.withAddressResolver((h,b)->List.of()).allowedOrigins(new java.util.LinkedHashSet<>(List.of(URI.create("https://client.example.com"),URI.create("https://other.example.com")))).build();
  var q=OAuthClientMetadataPolicy.withAddressResolver((h,b)->List.of()).allowedOrigins(new java.util.LinkedHashSet<>(List.of(URI.create("https://other.example.com"),URI.create("https://client.example.com")))).build();
  assertEquals(codec(sealer(),p).key(ID),codec(sealer(),q).key(ID));assertNotEquals(codec(sealer(),p).key(ID),codec(sealer(),policy(null)).key(ID));
  var deny=OAuthClientMetadataPolicy.withAddressResolver((h,b)->List.of()).allowedOrigins(java.util.Set.of()).build();
  assertEquals(OAuthServerAdmissionFailure.Reason.INVALID_CLIENT,assertThrows(OAuthServerAdmissionFailure.class,()->fetcher(sealer(),deny,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{throw new AssertionError("deny before fetch");}).reusable(ID,deadline())).reason());
 }
 @Test void successfulNoStoreCannotRemoveConcurrentWinningReplacement() {
  var cache=InMemoryOAuthClientMetadataCache.fromDefaults();var p=policy(cache);StateSealer s=sealer();var c=codec(s,p);
  var old=c.seal(ID,body("old"),NOW.minusSeconds(200),NOW.minusSeconds(80));assertTrue(cache.compareAndSet(c.key(ID),null,old,Duration.ofSeconds(1)));
  var newer=c.seal(ID,body("newer"),NOW,NOW.plusSeconds(120));
  var f=fetcher(s,p,Clock.fixed(NOW,ZoneOffset.UTC),(u,d)->{assertTrue(cache.compareAndSet(c.key(ID),old.getVersion(),newer,Duration.ofSeconds(1)));return response("fresh","no-store");});
  assertEquals("fresh",f.reusable(ID,deadline()).clientName());assertEquals(newer.getVersion(),cache.read(c.key(ID),Duration.ofSeconds(1)).orElseThrow().getVersion());
 }
 private static final class FaultCache implements OAuthClientMetadataCache {
  private final OAuthClientMetadataCacheException.@NonNull Reason reason;
  private FaultCache(OAuthClientMetadataCacheException.@NonNull Reason reason){this.reason=reason;}
  @Override public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(@NonNull OAuthClientMetadataCacheKey key,@NonNull Duration budget){throw OAuthClientMetadataCacheException.fromReason(this.reason);}
  @Override public @NonNull Boolean compareAndSet(@NonNull OAuthClientMetadataCacheKey key,@Nullable String version,@Nullable OAuthClientMetadataCacheEntry replacement,@NonNull Duration budget){throw OAuthClientMetadataCacheException.fromReason(this.reason);}
 }
 private static final class MutableClock extends Clock {
  private final @NonNull AtomicReference<@NonNull Instant> time;private final @NonNull AtomicInteger calls=new AtomicInteger();
  private MutableClock(@NonNull Instant time){this.time=new AtomicReference<>(time);}
  @Override public @NonNull Instant instant(){this.calls.incrementAndGet();return java.util.Objects.requireNonNull(this.time.get());}
  @Override public @NonNull ZoneId getZone(){return ZoneOffset.UTC;}
  @Override public @NonNull Clock withZone(@NonNull ZoneId zone){return this;}
 }
}
