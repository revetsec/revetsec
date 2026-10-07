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

import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.URI;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OAuthClientMetadataTests {
 private static final @NonNull String ID = "https://client.example.com/metadata";
 private static final @NonNull String BASE = "{\"client_id\":\""+ID+"\",\"client_name\":\"Display\",\"redirect_uris\":[\"https://client.example.com/callback\"],\"token_endpoint_auth_method\":\"none\"}";
 private static final @NonNull OAuthClientMetadataAddressResolver RESOLVER = (host, budget) -> { throw new AssertionError("No resolution during configuration or parsing"); };
 private static @NonNull OAuthClientMetadataPolicy policy() { return OAuthClientMetadataPolicy.fromAddressResolver(RESOLVER); }
 private static @NonNull OAuthClientMetadataDocument parse(@NonNull String json) { return parse(json, false, false); }
 private static @NonNull OAuthClientMetadataDocument parse(@NonNull String json, boolean nativeLoopback, boolean localhost) {
  return OAuthClientMetadataDocument.parse(ID, json.getBytes(StandardCharsets.UTF_8), policy(), OAuthServerIngressLimits.fromDefaults(), nativeLoopback, localhost);
 }
 private static @NonNull String change(@NonNull String name, @Nullable JsonValue value) {
  var json = JsonObject.builder();
  json.put("client_id",ID).put("client_name","Display").put("redirect_uris",com.revetsec.json.JsonArray.fromElements(List.of(JsonString.fromValue("https://client.example.com/callback"))))
   .put("token_endpoint_auth_method","none");
  // Build a replacement object explicitly, so missing/null/wrong-type fixtures stay distinct.
  var result = JsonObject.builder();
  json.build().getMembers().forEach((key,item) -> { if (!key.equals(name)) result.put(key,item); });
  if (value != null) result.put(name,value);
  return result.build().toJson();
 }
 @Test void pureConstructionAndDefaultsHaveNoResolverCalls() {
  AtomicInteger calls = new AtomicInteger(); OAuthClientMetadataAddressResolver resolver = (host,budget) -> { calls.incrementAndGet(); return List.of(); };
  var a=OAuthClientMetadataPolicy.withAddressResolver(resolver).build(); var b=OAuthClientMetadataPolicy.fromAddressResolver(resolver);
  assertEquals(0,calls.get()); assertEquals(resolver,a.getAddressResolver().orElseThrow()); assertEquals(resolver,b.getAddressResolver().orElseThrow());
  assertTrue(a.getEnabled()); assertTrue(a.getAllowedOrigins().isEmpty()); assertEquals(5120,a.getMaximumDocumentBytes()); assertEquals(128,a.getMaximumCacheEntries());
  assertEquals(Duration.ofSeconds(300),a.getMaximumFreshness()); assertEquals(8,a.getMaximumConcurrentFetches()); assertEquals(16,a.getMaximumResolvedAddresses());
  var disabled=OAuthClientMetadataPolicy.disabledInstance(); assertSame(disabled,OAuthClientMetadataPolicy.disabledInstance());
  assertFalse(disabled.getEnabled()); assertTrue(disabled.getAddressResolver().isEmpty()); assertTrue(disabled.getAllowedOrigins().isEmpty());
  assertEquals(a.getMaximumDocumentBytes(),disabled.getMaximumDocumentBytes()); assertEquals(a.getMaximumCacheEntries(),disabled.getMaximumCacheEntries());
  assertEquals(a.getMaximumFreshness(),disabled.getMaximumFreshness()); assertEquals(a.getMaximumConcurrentFetches(),disabled.getMaximumConcurrentFetches());
  assertEquals(a.getMaximumResolvedAddresses(),disabled.getMaximumResolvedAddresses());
 }
 @Test @SuppressWarnings("NullAway") void requiredResolverNullAndClearSemantics() {
  assertThrows(NullPointerException.class,()->OAuthClientMetadataPolicy.withAddressResolver(null));
  assertThrows(NullPointerException.class,()->OAuthClientMetadataPolicy.fromAddressResolver(null));
  var builder=OAuthClientMetadataPolicy.withAddressResolver(RESOLVER); assertSame(builder,builder.addressResolver(null));
  assertThrows(IllegalStateException.class,builder::build); assertTrue(builder.addressResolver(RESOLVER).build().getEnabled());
 }
 @Test void originRestrictionsSnapshotResetAndDenyAll() {
  var origins=new LinkedHashSet<>(Set.of(URI.create("https://client.example.com")));
  var builder=OAuthClientMetadataPolicy.withAddressResolver(RESOLVER).allowedOrigins(origins); var a=builder.build(); origins.clear();
  assertEquals(1,a.getAllowedOrigins().orElseThrow().size()); assertThrows(UnsupportedOperationException.class,()->a.getAllowedOrigins().orElseThrow().clear());
  assertEquals(ID,OAuthClientMetadataUri.clientId(ID,a,2048).toString());
  assertThrows(IllegalArgumentException.class,()->OAuthClientMetadataUri.clientId("https://client.example.com:443/metadata",a,2048));
  assertThrows(IllegalArgumentException.class,()->OAuthClientMetadataUri.clientId("https://other.example.com/metadata",a,2048));
  assertThrows(IllegalArgumentException.class,()->OAuthClientMetadataUri.clientId(ID,builder.allowedOrigins(Set.of()).build(),2048));
  assertEquals(ID,OAuthClientMetadataUri.clientId(ID,builder.allowedOrigins(null).build(),2048).toString());
  assertEquals(ID,OAuthClientMetadataUri.clientId(ID.replace("https", "HTTPS").replace("client.example.com", "CLIENT.EXAMPLE.COM"),a,2048).toString().toLowerCase(java.util.Locale.ROOT));
  assertEquals(ID,OAuthClientMetadataUri.clientId(ID,policy(),2048).toString());
 }
 @Test @SuppressWarnings("NullAway") void nullOriginElementRejected() {
  assertThrows(NullPointerException.class,()->OAuthClientMetadataPolicy.withAddressResolver(RESOLVER).allowedOrigins(new LinkedHashSet<>(Arrays.asList((URI)null))));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> invalidOrigins() {
  return Stream.of("http://client.example.com","https://client.example.com/","https://client.example.com/path","https://client.example.com?x", "https://client.example.com#x",
   "https://user@client.example.com", "https://client.example.com:0", "https://client.example.com:65536", "https://127.0.0.1", "https://10.0.0.1",
   "https://[::1]", "https://localhost", "https://bad_host", "https://client.example.com:*", "mailto:client@example.com")
   .map(origin->DynamicTest.dynamicTest(origin,()->assertThrows(IllegalArgumentException.class,()->OAuthClientMetadataPolicy.withAddressResolver(RESOLVER).allowedOrigins(Set.of(URI.create(origin))))));
 }
 @Test void originCountAndAggregateBounds() {
  Set<URI> origins=new LinkedHashSet<>();for(int i=0;i<4096;i++)origins.add(URI.create("https://c"+i+".example.com"));
  assertEquals(4096,OAuthClientMetadataPolicy.withAddressResolver(RESOLVER).allowedOrigins(origins).build().getAllowedOrigins().orElseThrow().size());
  origins.add(URI.create("https://overflow.example.com"));assertThrows(IllegalArgumentException.class,()->OAuthClientMetadataPolicy.withAddressResolver(RESOLVER).allowedOrigins(origins));
  Set<URI> large=new LinkedHashSet<>();for(int i=0;i<3000;i++)large.add(URI.create("https://"+"long".repeat(10)+i+".example.com"));
  assertThrows(IllegalArgumentException.class,()->OAuthClientMetadataPolicy.withAddressResolver(RESOLVER).allowedOrigins(large));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> integerBoundsAndNullResets() {
  List<Function<OAuthClientMetadataPolicy.Builder,Integer>> getters=List.of(b->b.build().getMaximumDocumentBytes(),b->b.build().getMaximumCacheEntries(),b->b.build().getMaximumConcurrentFetches(),b->b.build().getMaximumResolvedAddresses());
  List<java.util.function.BiFunction<OAuthClientMetadataPolicy.Builder,Integer,OAuthClientMetadataPolicy.Builder>> setters=List.of(OAuthClientMetadataPolicy.Builder::maximumDocumentBytes,OAuthClientMetadataPolicy.Builder::maximumCacheEntries,OAuthClientMetadataPolicy.Builder::maximumConcurrentFetches,OAuthClientMetadataPolicy.Builder::maximumResolvedAddresses);
  int[] low={1024,1,1,1},high={5120,4096,64,64},defaults={5120,128,8,16};List<DynamicTest> tests=new ArrayList<>();
  for(int i=0;i<4;i++){int row=i;for(int v:new int[]{-1,0,low[i]-1,low[i],high[i],high[i]+1,Integer.MAX_VALUE}){
   tests.add(DynamicTest.dynamicTest("limit"+row+"="+v,()->{var b=OAuthClientMetadataPolicy.withAddressResolver(RESOLVER);var setter=setters.get(row);
    if(v<low[row]||v>high[row]) assertThrows(IllegalArgumentException.class,()->setter.apply(b,v));
    else {assertSame(b,setter.apply(b,v));assertEquals(v,getters.get(row).apply(b));}
    assertEquals(defaults[row],getters.get(row).apply(setter.apply(b,null)));
   }));}}
  return tests.stream();
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> freshnessBoundsAndNullReset() {
  return Stream.of(Duration.ofNanos(-1),Duration.ZERO,Duration.ofNanos(1),Duration.ofSeconds(300),Duration.ofHours(1),Duration.ofHours(1).plusNanos(1),Duration.ofSeconds(Long.MAX_VALUE))
   .map(v->DynamicTest.dynamicTest(v.toString(),()->{var b=OAuthClientMetadataPolicy.withAddressResolver(RESOLVER);
    if(v.isNegative()||v.compareTo(Duration.ofHours(1))>0)assertThrows(IllegalArgumentException.class,()->b.maximumFreshness(v));
    else assertEquals(v,b.maximumFreshness(v).build().getMaximumFreshness());
    assertEquals(Duration.ofSeconds(300),b.maximumFreshness(null).build().getMaximumFreshness());
   }));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> ineligibleClientIds() {
  return Stream.of("http://client.example.com/doc","https://client.example.com","https://user@client.example.com/doc","https://client.example.com/doc#fragment",
   "https://client.example.com/./doc","https://client.example.com/../doc","https://client.example.com/%2e/doc","https://client.example.com/%2e%2e/doc",
   "https://client.example.com/%2E%2fdoc","https://client.example.com/a%5cb","https://client.example.com/%C0%AF", "https://client.example.com/%00",
   "https://127.0.0.1/doc","https://[::1]/doc","https://localhost/doc","https://169.254.169.254/doc","https://2852039166/doc",
   "https://127.1/doc","https://[::ffff:127.0.0.1]/doc","https://client.example.com:0/doc","https://client.example.com:65536/doc","https://bad_host/doc","https://*.example/doc")
   .map(id->DynamicTest.dynamicTest(id,()->assertThrows(IllegalArgumentException.class,()->OAuthClientMetadataUri.clientId(id,policy(),2048))));
 }
 @Test void eligibleIdsKeepExactIdentityAndQuerySpelling() {
  for(String id:List.of(ID,"https://client.example.com/","https://client.example.com:443/doc?x=1+2","https://client.example.com:65535/doc","HTTPS://CLIENT.EXAMPLE.COM/a%2Bb"))
   assertEquals(id,OAuthClientMetadataUri.clientId(id,policy(),2048).toString());
  assertThrows(IllegalArgumentException.class,()->OAuthClientMetadataUri.clientId(ID,OAuthClientMetadataPolicy.disabledInstance(),2048));
  assertThrows(IllegalArgumentException.class,()->OAuthClientMetadataUri.clientId("https://client.example.com/"+"a".repeat(2048),policy(),2048));
 }
 @Test void validDocumentDoesNotGrantAuthorityOrExposeDiagnostics() {
  var d=parse(BASE);assertEquals(ID,d.clientId());assertEquals("Display",d.clientName());assertEquals(List.of(URI.create("https://client.example.com/callback")),d.redirectUris());
  assertFalse(d.nativeApplication());assertFalse(d.refreshTokenPermitted());assertEquals(43,d.fingerprint().length());
  assertThrows(UnsupportedOperationException.class,()->d.redirectUris().clear());
  assertEquals("OAuthClientMetadataDocument{metadata=redacted}",d.toString());
  assertEquals("OAuthClientMetadataPolicy{enabled=true, configuration=redacted}",policy().toString());
  assertFalse(d.toString().contains(ID));assertFalse(policy().toString().contains("example"));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> requiredMembersAndWrongTypes() {
  List<DynamicTest> result=new ArrayList<>();for(String field:List.of("client_id","client_name","redirect_uris","token_endpoint_auth_method")) {
   result.add(DynamicTest.dynamicTest(field+" missing",()->assertThrows(OAuthServerAdmissionFailure.class,()->parse(change(field,null)))));
   for(JsonValue value:List.of(com.revetsec.json.JsonNull.defaultInstance(),com.revetsec.json.JsonBoolean.fromValue(true),com.revetsec.json.JsonNumber.fromValue(1L),JsonObject.builder().build()))
    result.add(DynamicTest.dynamicTest(field+" "+value.toJson(),()->assertThrows(OAuthServerAdmissionFailure.class,()->parse(change(field,value)))));
  }return result.stream();
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> hostileAndUnsupportedMetadata() {
  List<String> bad=List.of("[]","null","{}",BASE+"{}",BASE.replace("Display",""),BASE.replace("Display","bad\\u0000"),BASE.replace(ID,ID+"/").replaceFirst("/metadata/","/metadata/"),
   BASE.replace("none","client_secret_basic"),BASE.replace("none","private_key_jwt"),BASE.replace("none","client_secret_post"),BASE.replace("none","NONE"),
   BASE.replace("[\"https://client.example.com/callback\"]","[]"),BASE.replace("[\"https://client.example.com/callback\"]","[7]"),
   BASE.replace("https://client.example.com/callback","https://client.example.com/callback#x"),BASE.replace("https://client.example.com/callback","https://user@client.example.com/callback"),
   BASE.replace("https://client.example.com/callback","https://client.example.com/callback?%63ode=x"),BASE.replace("https://client.example.com/callback","com.example:callback"),
   BASE.replace("https://client.example.com/callback","http://127.0.0.1:123/callback"),BASE.replace("https://client.example.com/callback","http://localhost/callback"),
   BASE.substring(0,BASE.length()-1)+",\"client_name\":\"duplicate\"}",
   BASE.substring(0,BASE.length()-1)+",\"client_secret\":null}",BASE.substring(0,BASE.length()-1)+",\"client_secret_expires_at\":0}",
   BASE.substring(0,BASE.length()-1)+",\"extension\":{\"d\":\"private\"}}",
   BASE.substring(0,BASE.length()-1)+",\"extension\":[{\"kty\":\"oct\"}]}",
   BASE.substring(0,BASE.length()-1)+",\"grant_types\":[\"client_credentials\"]}",
   BASE.substring(0,BASE.length()-1)+",\"grant_types\":[\"authorization_code\",\"authorization_code\"]}",
   BASE.substring(0,BASE.length()-1)+",\"response_types\":[\"token\"]}",
   BASE.substring(0,BASE.length()-1)+",\"application_type\":\"unknown\"}",
   BASE.substring(0,BASE.length()-1)+",\"jwks\":[]}",BASE.substring(0,BASE.length()-1)+",\"jwks\":{\"keys\":[7]}}",
   BASE.substring(0,BASE.length()-1)+",\"jwks\":{\"keys\":[{\"kty\":\"unknown\"}]}}",
   BASE.substring(0,BASE.length()-1)+",\"scope\":\"one  two\"}",BASE.substring(0,BASE.length()-1)+",\"token_endpoint_auth_signing_alg\":\"RS256\"}");
  return java.util.stream.IntStream.range(0,bad.size()).mapToObj(i->DynamicTest.dynamicTest("bad document "+i,()->{
   var failure=assertThrows(OAuthServerAdmissionFailure.class,()->parse(bad.get(i)));assertFalse(failure.toString().contains(ID));assertNull(failure.getCause());
  }));
 }
 @Test void strictUtf8BomDepthAndByteCap() {
  for(byte[] bytes:List.of(new byte[]{(byte)0xc0,(byte)0xaf},new byte[]{(byte)0xef,(byte)0xbb,(byte)0xbf,'{'},new byte[5121]))
   assertThrows(OAuthServerAdmissionFailure.class,()->OAuthClientMetadataDocument.parse(ID,bytes,policy(),OAuthServerIngressLimits.fromDefaults(),false,false));
  assertThrows(OAuthServerAdmissionFailure.class,()->parse(BASE.substring(0,BASE.length()-1)+",\"extension\":"+"[".repeat(33)+"0"+"]".repeat(33)+"}"));
  String boundary=BASE+" ".repeat(5120-BASE.getBytes(StandardCharsets.UTF_8).length);assertEquals(ID,parse(boundary).clientId());assertThrows(OAuthServerAdmissionFailure.class,()->parse(boundary+" "));
  assertThrows(OAuthServerAdmissionFailure.class,()->OAuthClientMetadataDocument.parse(ID,boundary.getBytes(StandardCharsets.UTF_8),OAuthClientMetadataPolicy.withAddressResolver(RESOLVER).maximumDocumentBytes(1024).build(),OAuthServerIngressLimits.fromDefaults(),false,false));
 }
 @Test void freshParsingHasNoPositiveOrNegativeCache() {
  assertThrows(OAuthServerAdmissionFailure.class,()->parse("{}"));assertEquals("Display",parse(BASE).clientName());assertThrows(OAuthServerAdmissionFailure.class,()->parse("{}"));
  assertEquals("Changed",parse(BASE.replace("Display","Changed")).clientName());
 }
 @Test void fingerprintIncludesSecuritySemanticsButNotDisplayOrOrder() {
  var first=parse(BASE);assertEquals(first.fingerprint(),parse(BASE.replace("Display","Changed")).fingerprint());
  assertNotEquals(first.fingerprint(),parse(BASE.replace("/callback","/other")).fingerprint());
  String two=BASE.replace("[\"https://client.example.com/callback\"]","[\"https://client.example.com/one\",\"https://client.example.com/two\"]");
  assertEquals(parse(two).fingerprint(),parse(two.replace("/one","/TEMP").replace("/two","/one").replace("/TEMP","/two")).fingerprint());
  assertNotEquals(first.fingerprint(),parse(BASE.substring(0,BASE.length()-1)+",\"application_type\":\"native\"}").fingerprint());
  String refresh=BASE.substring(0,BASE.length()-1)+",\"grant_types\":[\"refresh_token\",\"authorization_code\"]}";
  assertTrue(parse(refresh).refreshTokenPermitted());assertNotEquals(first.fingerprint(),parse(refresh).fingerprint());
 }
 @Test void nativeAndLocalhostAreSeparateExplicitPolicies() {
  String nativeDoc=BASE.substring(0,BASE.length()-1)+",\"application_type\":\"native\"}";
  for(String host:List.of("127.0.0.1","[::1]")) {
   String document=nativeDoc.replace("https://client.example.com/callback","http://"+host+":49152/callback");
   assertTrue(parse(document,true,false).nativeApplication());assertThrows(OAuthServerAdmissionFailure.class,()->parse(document,false,true));
   assertThrows(OAuthServerAdmissionFailure.class,()->parse(document.replace(",\"application_type\":\"native\"",""),true,false));
  }
  String localhost=BASE.replace("https://client.example.com/callback","http://localhost:49152/callback");assertEquals("localhost",parse(localhost,false,true).redirectUris().get(0).getHost());
  assertThrows(OAuthServerAdmissionFailure.class,()->parse(localhost,true,false));
  for(String host:List.of("127.0.0.2","foo.localhost","192.168.1.1"))assertThrows(OAuthServerAdmissionFailure.class,()->parse(nativeDoc.replace("https://client.example.com/callback","http://"+host+"/callback"),true,true));
 }
 @Test void safeExtensionsHaveExactTypesAndAreNeverFetched() {
  String fields=",\"client_uri\":\"https://evil.example.com/client\",\"logo_uri\":\"https://evil.example.com/logo\",\"policy_uri\":\"https://evil.example.com/policy\",\"tos_uri\":\"https://evil.example.com/tos\",\"jwks_uri\":\"https://evil.example.com/keys\",\"contacts\":[\"a@example.com\"],\"scope\":\"untrusted admin\",\"software_id\":\"untrusted\",\"software_version\":\"1\",\"software_statement\":\"unverified\",\"unknown_uri\":\"http://127.0.0.1/private\",\"jwks\":{\"keys\":[{\"kty\":\"RSA\",\"n\":\"AQ\",\"e\":\"Aw\"},{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AQ\",\"y\":\"AQ\"},{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"AQ\"}]}";
  assertEquals(parse(BASE).fingerprint(),parse(BASE.substring(0,BASE.length()-1)+fields+"}").fingerprint());
  for(String name:List.of("client_uri","logo_uri","policy_uri","tos_uri","jwks_uri","contacts","scope","software_id","software_version","software_statement","grant_types","response_types","application_type"))
   assertThrows(OAuthServerAdmissionFailure.class,()->parse(change(name,com.revetsec.json.JsonBoolean.fromValue(false))));
 }
}
