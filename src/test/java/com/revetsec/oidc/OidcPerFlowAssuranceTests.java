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

package com.revetsec.oidc;

import com.revetsec.StateSealer;
import com.revetsec.oauth.*;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.internal.json.*;
import com.revetsec.json.*;
import com.revetsec.testing.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

/** Genuine public login -> saved reference -> refresh, with no identity constructed from storage. */
final class OidcPerFlowAssuranceTests {
 private static final @NonNull Instant NOW=Instant.parse("2026-09-29T12:00:00Z");
 private static final @NonNull Clock CLOCK=Clock.fixed(NOW,ZoneOffset.UTC);
 private static final @NonNull URI CALLBACK=URI.create("https://rp.example/callback");
 record Login(@NonNull OidcAuthentication authentication,@NonNull String nonce){}
 static @NonNull Login login(@NonNull TestHttpsServer server,@NonNull OidcClient client,@NonNull Set<@NonNull String> policy,@Nullable String acr)throws Exception{
  var begin=client.beginAuthentication(OidcAuthenticationOptions.builder().requiredAcrValues(policy).build());var query=QueryParameters.parse(begin.getAuthorizationUri().getRawQuery());String nonce=query.getValues("nonce").get(0);respond(server,token(claims(server,nonce,acr)));
  var sealer=StateSealer.withActiveKey(TestSealers.fixedKey("flow")).clock(CLOCK).build();var source=PendingAuthorizationSource.fromSealedForm(begin.getPendingAuthorization().toSealedForm(sealer,"flow"),sealer,"flow");var callback=assertInstanceOf(AuthorizationResponseParseResult.Succeeded.class,AuthorizationResponse.fromQueryStringResult("state="+query.getValues("state").get(0)+"&code=TEST-ONLY-code")).getResponse();return new Login(assertInstanceOf(OidcAuthenticationResult.Succeeded.class,client.completeAuthenticationResult(callback,source,CALLBACK)).getAuthentication(),nonce);
 }
 private static @NonNull String claims(@NonNull TestHttpsServer server,@Nullable String nonce,@Nullable String acr){var b=JsonObject.builder().put("iss",server.getBaseUri().toString()).put("sub","TEST-ONLY-subject").put("aud","client").put("iat",NOW.getEpochSecond()).put("exp",NOW.plusSeconds(300).getEpochSecond());for(var entry:optional(nonce,acr).entrySet())b.put(entry.getKey(),entry.getValue());return b.build().toJson();}
 private static @NonNull Map<@NonNull String,@NonNull JsonValue> optional(@Nullable String nonce,@Nullable String acr){Map<String,JsonValue> m=new LinkedHashMap<>();if(nonce!=null)m.put("nonce",JsonString.fromValue(nonce));if(acr!=null)m.put("acr",JsonString.fromValue(acr));return m;}
 private static @NonNull String token(@Nullable String claims){String id=claims==null?null:TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("key").payload(claims).sign(TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());var b=JsonObject.builder().put("access_token","TEST-ONLY-access").put("token_type","Bearer").put("refresh_token","TEST-ONLY-refresh");if(id!=null)b.put("id_token",id);return b.build().toJson();}
 private static void respond(@NonNull TestHttpsServer server,@NonNull String body){server.script("/token",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,body)));}
 @TestFactory @NonNull List<@NonNull DynamicTest> effectiveLoginPolicySurvivesRefreshAndChangedClientDefaults(){
  record Case(@NonNull String name,@NonNull Set<@NonNull String> defaults,@NonNull Set<@NonNull String> policy,@Nullable String loginAcr,@Nullable String refreshAcr,boolean id,boolean accepted,boolean restore,boolean replaceClient){}
  var strong=Set.of("urn:strong");var weak=Set.of("urn:weak");List<Case> cases=List.of(
   new Case("strong-flow/strong-refresh",weak,strong,"urn:strong","urn:strong",true,true,false,false),
   new Case("strong-flow/weak-refresh",weak,strong,"urn:strong","urn:weak",true,false,false,false),
   new Case("required-claim-omitted",weak,strong,"urn:strong",null,true,false,false,false),
   new Case("explicit-empty-flow",weak,Set.of(),null,null,true,true,false,false),
   new Case("empty-default/strong-flow",Set.of(),strong,"urn:strong","urn:weak",true,false,false,false),
   new Case("multiple-acceptable-values",Set.of(),Set.of("urn:strong","urn:alternate"),"urn:strong","urn:alternate",true,true,false,false),
   new Case("omitted-id-token",weak,strong,"urn:strong",null,false,true,false,false),
   new Case("sealed-restored-policy",weak,strong,"urn:strong","urn:strong",true,true,true,false),
   new Case("fresh-client-default-cannot-drop-policy",weak,strong,"urn:strong","urn:weak",true,false,false,true));
  List<DynamicTest> tests=new ArrayList<>();for(var value:cases)tests.add(DynamicTest.dynamicTest(value.name(),()->{
   try(var server=TestHttpsServer.start()){
    var client=OidcRefreshTests.builder(server).requiredAcrValues(value.defaults()).build();var login=login(server,client,value.policy(),value.loginAcr());var reference=login.authentication().getSessionReference();
    if(value.restore()){var sealer=StateSealer.withActiveKey(TestSealers.fixedKey("stored-flow")).clock(CLOCK).build();reference=assertInstanceOf(OidcSessionReferenceParseResult.Succeeded.class,OidcSessionReference.fromSealedFormResult(reference.toSealedForm(sealer,"stored-flow",Duration.ofHours(1)),sealer,"stored-flow")).getReference();}
    if(value.replaceClient())client=OidcRefreshTests.builder(server).requiredAcrValues(Set.of()).build();respond(server,token(value.id()?claims(server,null,value.refreshAcr()):null));var outcome=client.refreshResult(login.authentication().getTokens().getRefreshToken().orElseThrow(),reference);
    if(value.accepted()){var refreshed=assertInstanceOf(OidcRefreshOutcome.Succeeded.class,outcome).getRefreshResult();assertSame(reference,refreshed.getSessionReference());assertEquals(value.id(),refreshed.getIdToken().isPresent());}
    else assertEquals(OidcValidationException.Reason.INSUFFICIENT_ACR,assertInstanceOf(OidcRefreshOutcome.Rejected.class,outcome).getReason());
    assertEquals(2,server.getHitCount("/token"));assertEquals(0,server.getHitCount("/jwks"));assertFalse(outcome.toString().contains("TEST-ONLY"));
   }
  }));return tests;
 }
 @Test void currentReferenceSnapshotsPolicyAndRoundTripsWithinExistingByteLimit()throws Exception{
  try(var server=TestHttpsServer.start()){
   var login=login(server,OidcRefreshTests.builder(server).requiredAcrValues(Set.of()).build(),Set.of("urn:strong"),"urn:strong");var original=login.authentication().getSessionReference();String text=original.toSerializedForm();var json=parse(text);
   assertEquals("2",java.util.Objects.requireNonNull(json.getMembers().get("v")).toJson());var policy=assertInstanceOf(JsonArray.class,json.getMembers().get("required_acr_values"));assertEquals(List.of(JsonString.fromValue("urn:strong")),policy.getElements());
   var restored=assertInstanceOf(OidcSessionReferenceParseResult.Succeeded.class,OidcSessionReference.fromSerializedFormResult(text)).getReference();assertEquals(text,restored.toSerializedForm());assertTrue(original.matchesOriginalReference(restored));assertFalse(text.contains("TEST-ONLY-refresh"));assertFalse(text.contains(login.nonce()));
  }
 }
 @Test void oldVersionWithoutPolicyIsRejectedRatherThanInferringCurrentDefaults()throws Exception{
  try(var server=TestHttpsServer.start()){
   var login=login(server,OidcRefreshTests.builder(server).build(),Set.of("urn:strong"),"urn:strong");Map<String,JsonValue> legacy=new LinkedHashMap<>(parse(login.authentication().getSessionReference().toSerializedForm()).getMembers());legacy.put("v",JsonNumber.fromValue(1L));legacy.remove("required_acr_values");var rejected=assertInstanceOf(OidcSessionReferenceParseResult.Rejected.class,OidcSessionReference.fromSerializedFormResult(JsonObject.fromMembers(legacy).toJson()));assertEquals(OidcValidationException.Reason.SESSION_REFERENCE_INVALID,rejected.getReason());
  }
 }
 static @NonNull JsonObject parse(@NonNull String text)throws Exception{return (JsonObject)JsonCodec.parse(text.getBytes(StandardCharsets.UTF_8),JsonLimits.protocolDocument(64*1024));}
}
