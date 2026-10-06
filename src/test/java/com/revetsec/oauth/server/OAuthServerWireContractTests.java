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

import com.revetsec.internal.Limits;
import com.revetsec.internal.Limit;
import com.revetsec.internal.Limit.Unit;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;
import static java.util.Objects.requireNonNull;

/** Independent wire/immutability boundaries; internal settings await the public engine builder. */
final class OAuthServerWireContractTests {
 // Approved privileged credential emission methods; additions require a new review of the exported surface.
 private static final @NonNull Set<@NonNull String> SECRET_EMISSIONS = Set.of("getLocationWithCredentials", "toHttpBodyWithCredentials");
 private static final @NonNull String NONCE = "A".repeat(43);
 private static OAuthServerSettings.@NonNull Builder compatible() {
  return OAuthServerSettings.builder().authorizationInteractionLifetime(Duration.ofHours(1))
   .accessTokenLifetime(Duration.ofMinutes(15)).clockSkew(Duration.ZERO).totalDeadline(Duration.ofSeconds(60));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> everyIssuerSettingChecksRangesAndNullResets() throws Exception {
  List<DynamicTest> tests = new ArrayList<>();
  for (java.lang.reflect.Field constant : Limits.class.getFields()) {
   if (!constant.getName().startsWith("AS_")) continue;
   Limit row = (Limit)requireNonNull(constant.get(null)); String name = row.getName().substring("Issuer ".length());
   boolean duration = row.getUnit() == Unit.DURATION;
   List<Object> accepted = duration ? List.of(row.getFloorDuration(), row.getDefaultDuration(), row.getCapDuration())
    : List.of((int)row.getFloor(), row.getDefaultIntValue(), (int)row.getCap());
   for (Object value : accepted) tests.add(DynamicTest.dynamicTest(name+" accepts "+value, () -> {
    OAuthServerSettings.Builder builder = compatible();
    if (name.equals("authorizationInteractionLifetime")) builder.authorizationCodeLifetime(Duration.ofSeconds(30));
    if (name.equals("totalDeadline")) builder.requestTimeout(Duration.ofSeconds(1));
    set(builder, name, value, duration);
    OAuthServerSettings settings = builder.build(false, 16384);
    assertEquals(value, OAuthServerSettings.class.getDeclaredField(name).get(settings));
   }));
   List<Object> rejected = duration ? List.of(row.getFloorDuration().minusNanos(1), row.getCapDuration().plusNanos(1))
    : List.of((int)row.getFloor()-1, (int)row.getCap()+1, Integer.MIN_VALUE, Integer.MAX_VALUE);
   for (Object value : rejected) tests.add(DynamicTest.dynamicTest(name+" rejects "+value, () -> {
    OAuthServerSettings.Builder builder = compatible(); set(builder, name, value, duration);
    assertThrows(IllegalArgumentException.class, () -> builder.build(false, 16384));
   }));
   tests.add(DynamicTest.dynamicTest(name+" null resets exact default", () -> {
    OAuthServerSettings.Builder builder = OAuthServerSettings.builder(); set(builder, name, accepted.get(0), duration);
    set(builder, name, null, duration); OAuthServerSettings settings = builder.build(false, 3800);
    assertEquals(duration ? row.getDefaultDuration() : row.getDefaultIntValue(), OAuthServerSettings.class.getDeclaredField(name).get(settings));
   }));
  }
  assertEquals(158, tests.size()); return tests.stream();
 }
 private static void set(OAuthServerSettings.@NonNull Builder builder, @NonNull String name, @Nullable Object value, boolean duration) throws Exception {
  try { OAuthServerSettings.Builder.class.getDeclaredMethod(name, duration ? Duration.class : Integer.class).invoke(builder, value); }
  catch (InvocationTargetException failure) { throw new AssertionError(failure.getCause()); }
 }
 @Test void crossFieldOrderingAndExactEqualityAreChecked() {
  assertThrows(IllegalArgumentException.class, () -> OAuthServerSettings.builder().totalDeadline(Duration.ofSeconds(1)).build(false,3800));
  assertThrows(IllegalArgumentException.class, () -> OAuthServerSettings.builder().authorizationInteractionLifetime(Duration.ofMinutes(1)).build(false,3800));
  assertThrows(IllegalArgumentException.class, () -> OAuthServerSettings.builder().accessTokenLifetime(Duration.ofSeconds(30)).build(false,3800));
  assertThrows(IllegalArgumentException.class, () -> OAuthServerSettings.builder().refreshTokenIdleLifetime(Duration.ofDays(7)).refreshTokenAbsoluteLifetime(Duration.ofDays(1)).build(true,3800));
  assertThrows(IllegalArgumentException.class, () -> OAuthServerSettings.builder().accessTokenLifetime(Duration.ofMinutes(15)).refreshTokenIdleLifetime(Duration.ofMinutes(5)).build(true,3800));
  assertNotNull(OAuthServerSettings.builder().clockSkew(Duration.ofSeconds(15)).accessTokenLifetime(Duration.ofSeconds(30))
   .authorizationInteractionLifetime(Duration.ofMinutes(2)).totalDeadline(Duration.ofSeconds(5)).refreshTokenIdleLifetime(Duration.ofHours(1))
   .refreshTokenAbsoluteLifetime(Duration.ofHours(1)).build(true,3800));
  assertNotNull(OAuthServerSettings.builder().refreshTokenIdleLifetime(Duration.ofDays(7)).refreshTokenAbsoluteLifetime(Duration.ofDays(1)).build(false,3800));
 }
 @Test void sealerCapacityMustBeExplicitlyAligned() {
  assertThrows(IllegalArgumentException.class, () -> OAuthServerSettings.builder().maximumStoreRecordBytes(3801).build(false,3800));
  assertThrows(IllegalArgumentException.class, () -> OAuthServerSettings.builder().build(false,1024));
  assertThrows(IllegalArgumentException.class, () -> OAuthServerSettings.builder().build(false,16385));
  assertEquals(16384,OAuthServerSettings.builder().maximumStoreRecordBytes(16384).build(false,16384).maximumStoreRecordBytes);
 }
 @Test void fractionalDurationsRemainExactAndSettingsAreSnapshots() {
  var b=OAuthServerSettings.builder().authorizationCodeLifetime(Duration.ofSeconds(30).plusNanos(1));var a=b.build(false,3800);
  b.authorizationCodeLifetime(null);assertEquals(Duration.ofSeconds(30).plusNanos(1),a.authorizationCodeLifetime);
  assertEquals(Duration.ofMinutes(2),b.build(false,3800).authorizationCodeLifetime);
  assertEquals(Duration.ofSeconds(400),a.retentionExtension);assertEquals(16384,a.ingress().bodyBytes);assertEquals(32,a.ingress().scopes);assertEquals(1024,a.ingress().stateLength);
  assertEquals("OAuthServerSettings{<redacted>}",a.toString());assertEquals("OAuthServerSettings.Builder{<redacted>}",b.toString());
 }
 @Test void completeTypedSpellingSeparatesCodeAndRefreshLedgerKeys() throws Exception {
  String code=OAuthServerCredential.code(NONCE),refresh=OAuthServerCredential.refresh(NONCE);
  assertEquals("rsc1_"+NONCE,code);assertEquals("rsr1_"+NONCE,refresh);assertNotEquals(OAuthServerCredential.codeDigest(code),OAuthServerCredential.refreshDigest(refresh));
  String oracle=java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(code.getBytes(StandardCharsets.US_ASCII)));
  assertEquals(oracle,OAuthServerCredential.codeDigest(code));
  assertThrows(IllegalArgumentException.class,()->OAuthServerCredential.codeDigest(refresh));assertThrows(IllegalArgumentException.class,()->OAuthServerCredential.refreshDigest(code));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> typedHandlesRejectNoncanonicalAndLegacySpellings() {
  List<String> bad=List.of("",NONCE,"rsc2_"+NONCE,"rsr2_"+NONCE,"rsc1_"+NONCE+"=","rsr1_"+NONCE+"=",
   "rsc1_"+"A".repeat(42)+"B","rsr1_"+"A".repeat(42)+"B","rsc1_"+NONCE+"x","rsr1_"+NONCE+"x",
   "rsc1_"+"A".repeat(42)+"✓","rsr1_"+"A".repeat(42)+"✓","rsc1_"+NONCE+"\r\n", "rsr1_"+NONCE+"\r\n");
  return bad.stream().map(v -> DynamicTest.dynamicTest("reject handle "+bad.indexOf(v),()->{
   assertThrows(IllegalArgumentException.class,()->OAuthServerCredential.codeDigest(v));assertThrows(IllegalArgumentException.class,()->OAuthServerCredential.refreshDigest(v));
  }));
 }
 @Test void invalidMintInputCannotCreateAHandle() {
  assertThrows(IllegalArgumentException.class,()->OAuthServerCredential.code("A".repeat(42)+"B"));
  assertThrows(IllegalArgumentException.class,()->OAuthServerCredential.refresh("x"));
 }
 private static @NonNull OAuthServerResponse response(byte @NonNull [] body, int bodyCap, int headerCap) {
  return OAuthServerResponse.prepare(200,OAuthServerResponse.privateHeaders(body.length),null,body,bodyCap,headerCap);
 }
 @Test void responseHasIdentityEqualityRestrictedConstructionAndExplicitEmissions() {
  String secret="access-token-sentinel";byte[] body=secret.getBytes(StandardCharsets.US_ASCII);
  Map<String,List<String>> headers=OAuthServerResponse.privateHeaders(body.length);List<String> ct=new ArrayList<>(List.of("application/json"));headers.put("Content-Type",ct);
  OAuthServerResponse a=OAuthServerResponse.prepare(200,headers,null,body,4096,1024),b=response(body,4096,1024);
  body[0]=0;ct.set(0,"text/plain");headers.clear();assertNotEquals(a,b);assertEquals(200,a.getStatusCode());assertEquals("application/json",requireNonNull(a.getHeaders().get("Content-Type")).get(0));
  byte[] emitted=a.toHttpBodyWithCredentials();assertEquals(secret,new String(emitted,StandardCharsets.US_ASCII));emitted[0]=0;
  assertEquals(secret,new String(a.toHttpBodyWithCredentials(),StandardCharsets.US_ASCII));assertTrue(a.getLocationWithCredentials().isEmpty());
  assertThrows(UnsupportedOperationException.class,()->a.getHeaders().clear());assertThrows(UnsupportedOperationException.class,()->requireNonNull(a.getHeaders().get("Content-Type")).clear());
  assertEquals("OAuthServerResponse{<redacted>}",a.toString());assertFalse(a.getHeaders().toString().contains(secret));
  assertEquals(0,OAuthServerResponse.class.getConstructors().length);assertEquals(0,OAuthServerResponse.class.getFields().length);
  assertEquals(Set.of("getLocationWithCredentials", "toHttpBodyWithCredentials"),SECRET_EMISSIONS);
  assertEquals(Set.of("getStatusCode","getHeaders","getLocationWithCredentials","toHttpBodyWithCredentials","toString"),
   java.util.Arrays.stream(OAuthServerResponse.class.getDeclaredMethods()).filter(m->java.lang.reflect.Modifier.isPublic(m.getModifiers())).map(java.lang.reflect.Method::getName).collect(java.util.stream.Collectors.toSet()));
 }
 @Test void bodyAndSerializedHeaderCapsAreDistinctAndInclusive() {
  assertEquals(4096,response(new byte[4096],4096,1024).toHttpBodyWithCredentials().length);
  assertThrows(IllegalArgumentException.class,()->response(new byte[4097],4096,1024));
  var headers=OAuthServerResponse.privateHeaders(0);int base=OAuthServerResponse.prepare(200,headers,null,new byte[0],4096,1024).wireHeaders().length;
  // ETag adds its name, colon/space and CRLF to the full serialized count.
  headers.put("ETag",List.of("x".repeat(1024-base-8)));assertEquals(1024,OAuthServerResponse.prepare(200,headers,null,new byte[0],4096,1024).wireHeaders().length);
  headers.put("ETag",List.of("x".repeat(1024-base-7)));assertThrows(IllegalArgumentException.class,()->OAuthServerResponse.prepare(200,headers,null,new byte[0],4096,1024));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> restrictedResponseRejectsHeaderSmugglingAndInvalidStatusLocation() {
  List<DynamicTest> cases=new ArrayList<>();
  for(String value:List.of("x\r\nLocation: https://evil.example","x\n", "x\t", "✓", "x".repeat(1025))) cases.add(DynamicTest.dynamicTest("unsafe header "+cases.size(),()->{
   var headers=OAuthServerResponse.privateHeaders(0);headers.put("ETag",List.of(value));assertThrows(IllegalArgumentException.class,()->OAuthServerResponse.prepare(200,headers,null,new byte[0],4096,1024));
  }));
  for(String name:List.of("Location","location","Set-Cookie","Bad\r\n")) cases.add(DynamicTest.dynamicTest("restricted header "+cases.size(),()->{
   var headers=OAuthServerResponse.privateHeaders(0);headers.put(name,List.of("x"));assertThrows(IllegalArgumentException.class,()->OAuthServerResponse.prepare(200,headers,null,new byte[0],4096,1024));
  }));
  for(int status:List.of(100,201,302,307,308,500)) cases.add(DynamicTest.dynamicTest("invalid status "+status,()->assertThrows(IllegalArgumentException.class,()->OAuthServerResponse.prepare(status,OAuthServerResponse.privateHeaders(0),null,new byte[0],4096,1024))));
  for(String uri:List.of("/relative","https://client.example/#fragment","https://u@client.example/")) cases.add(DynamicTest.dynamicTest("unsafe Location "+uri,()->assertThrows(IllegalArgumentException.class,()->OAuthServerResponse.prepare(303,OAuthServerResponse.privateHeaders(0),URI.create(uri),new byte[0],4096,1024))));
  return cases.stream();
 }
 @Test void responsePolicyAndSingleHeaderValuesAreRequired() {
  var headers=OAuthServerResponse.privateHeaders(0);headers.remove("Referrer-Policy");assertThrows(IllegalArgumentException.class,()->OAuthServerResponse.prepare(200,headers,null,new byte[0],4096,1024));
  headers.put("Referrer-Policy",List.of("no-referrer"));headers.put("ETag",List.of());assertThrows(IllegalArgumentException.class,()->OAuthServerResponse.prepare(200,headers,null,new byte[0],4096,1024));
  headers.put("ETag",List.of("one","two"));assertThrows(IllegalArgumentException.class,()->OAuthServerResponse.prepare(200,headers,null,new byte[0],4096,1024));
  assertThrows(IllegalArgumentException.class,()->OAuthServerResponse.prepare(200,OAuthServerResponse.privateHeaders(0),URI.create("https://client.example/"),new byte[0],4096,1024));
  assertThrows(IllegalArgumentException.class,()->OAuthServerResponse.prepare(303,OAuthServerResponse.privateHeaders(0),null,new byte[0],4096,1024));
  for(int status:List.of(400,401,403,404,405,503))assertEquals(status,OAuthServerResponse.prepare(status,OAuthServerResponse.privateHeaders(0),null,new byte[0],4096,1024).getStatusCode());
 }
 @Test void metadataHeadRetainsRepresentationLengthAndCredentialFreeLocation() {
  var json=com.revetsec.json.JsonObject.builder().put("issuer","https://issuer.example").build();
  var get=OAuthPublicMetadataResponse.prepare(json,"GET",Duration.ZERO,4096,1024).response();var head=OAuthPublicMetadataResponse.prepare(json,"HEAD",Duration.ZERO,4096,1024).response();
  assertEquals(0,head.toHttpBodyWithCredentials().length);assertEquals(get.getHeaders(),head.getHeaders());assertTrue(get.getLocationWithCredentials().isEmpty());
  assertEquals("public, max-age=0, must-revalidate",requireNonNull(get.getHeaders().get("Cache-Control")).get(0));
  assertEquals(get.toHttpBodyWithCredentials().length,Integer.parseInt(requireNonNull(head.getHeaders().get("Content-Length")).get(0)));
  assertThrows(IllegalArgumentException.class,()->OAuthPublicMetadataResponse.prepare(com.revetsec.json.JsonObject.builder().put("x","a".repeat(4096)).build(),"HEAD",Duration.ZERO,4096,1024));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> encoderChecksIssuerAndExplicitLocalhostPolicy() {
  return Stream.of("http://issuer.example","https://u@issuer.example/","https://issuer.example/?x","https://issuer.example/#x","/relative","https://issuer.example:65536/","http://localhost/")
   .map(uri->DynamicTest.dynamicTest("reject issuer "+uri,()->assertThrows(IllegalArgumentException.class,()->new OAuthAuthorizationResponseEncoder(URI.create(uri),true,4096,1024,1024))));
 }
 @Test void loopbackIssuerIsExplicitAndDiagnosticsAreFixed() {
  assertThrows(IllegalArgumentException.class,()->new OAuthAuthorizationResponseEncoder(URI.create("http://127.0.0.1"),false,4096,1024,1024));
  assertEquals("OAuthAuthorizationResponseEncoder{<redacted>}",new OAuthAuthorizationResponseEncoder(URI.create("http://127.0.0.1"),true,4096,1024,1024).toString());
 }
}
