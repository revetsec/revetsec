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

import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.json.*;
import com.revetsec.testing.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

final class OidcAcrPreferenceTests {
 @TestFactory @NonNull List<@NonNull DynamicTest> orderedRequestPreferencesAreIndependentFromAcceptance(){
  List<DynamicTest> tests=new ArrayList<>();for(String mode:List.of("default","flow","empty-flow","reset-flow","reset-client","required-fallback","preference-only"))tests.add(DynamicTest.dynamicTest(mode,()->{
   try(var server=TestHttpsServer.start()){
    var builder=OidcRefreshTests.builder(server).requiredAcrValues(Set.of("urn:z","urn:a")).acrPreferences(List.of("urn:z","urn:a"));var options=OidcAuthenticationOptions.builder();List<String> expected=List.of("urn:z urn:a");
    if(mode.equals("flow")){options=options.acrPreferences(List.of("urn:y","urn:b"));expected=List.of("urn:y urn:b");}
    if(mode.equals("empty-flow")){options=options.acrPreferences(List.of());expected=List.of();}
    if(mode.equals("reset-flow"))options=options.acrPreferences(List.of("urn:unused")).acrPreferences(null);
    if(mode.equals("reset-client")){builder=builder.acrPreferences(null);expected=List.of("urn:a urn:z");}
    if(mode.equals("required-fallback")){builder=builder.acrPreferences(null);options=options.requiredAcrValues(Set.of("urn:c","urn:b"));expected=List.of("urn:b urn:c");}
    if(mode.equals("preference-only"))builder=builder.requiredAcrValues(Set.of());
    var client=builder.build();var begin=client.beginAuthentication(options.build());assertEquals(expected,QueryParameters.parse(begin.getAuthorizationUri().getRawQuery()).getValues("acr_values"));assertEquals(0,server.getRequests().size());
   }
  }));return tests;
 }
 @Test void preferencesAreCopiedAndGetterIsImmutable(){
  var list=new ArrayList<>(List.of("urn:z","urn:a"));var builder=OidcAuthenticationOptions.builder().acrPreferences(list);list.clear();var options=builder.build();assertEquals(List.of("urn:z","urn:a"),options.getAcrPreferences().orElseThrow());assertThrows(UnsupportedOperationException.class,()->options.getAcrPreferences().orElseThrow().add("urn:c"));assertTrue(OidcAuthenticationOptions.builder().acrPreferences(List.of()).build().getAcrPreferences().orElseThrow().isEmpty());assertTrue(OidcAuthenticationOptions.builder().acrPreferences(null).build().getAcrPreferences().isEmpty());
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> malformedOrRepeatedPreferencesAreRefused(){
  List<DynamicTest> tests=new ArrayList<>();for(var values:List.of(List.of(""),List.of("urn:a","urn:a"),List.of("a b"),List.of("a\tb"),List.of("\u007f"),List.of("é")))tests.add(DynamicTest.dynamicTest("invalid-"+tests.size(),()->{assertThrows(IllegalArgumentException.class,()->OidcAuthenticationOptions.builder().acrPreferences(values));assertThrows(IllegalArgumentException.class,()->OidcClient.withIssuer("https://issuer.example").acrPreferences(values));}));return tests;
 }
 @Test void preferenceOnlyLoginDoesNotCreateAnAcceptanceRequirement()throws Exception{
  try(var server=TestHttpsServer.start()){
   var client=OidcRefreshTests.builder(server).requiredAcrValues(Set.of()).acrPreferences(List.of("urn:preferred")).build();var login=OidcPerFlowAssuranceTests.login(server,client,Set.of(),"urn:other");assertTrue(login.authentication().getSessionReference().getRequiredAcrValues().isEmpty());assertEquals(1,server.getHitCount("/token"));
  }
 }
 @Test void savedPolicyParticipatesInReferenceComparisonButParsingDoesNotAuthenticateStorage()throws Exception{
  try(var server=TestHttpsServer.start()){
   var original=OidcPerFlowAssuranceTests.login(server,OidcRefreshTests.builder(server).build(),Set.of("urn:strong"),"urn:strong").authentication().getSessionReference();Map<String,JsonValue> fields=new LinkedHashMap<>(OidcPerFlowAssuranceTests.parse(original.toSerializedForm()).getMembers());fields.put("required_acr_values",JsonArray.fromElements(List.of()));var changed=assertInstanceOf(OidcSessionReferenceParseResult.Succeeded.class,OidcSessionReference.fromSerializedFormResult(JsonObject.fromMembers(fields).toJson())).getReference();assertFalse(original.matchesOriginalReference(changed));assertTrue(changed.getRequiredAcrValues().isEmpty());assertEquals(Set.of("urn:strong"),original.getRequiredAcrValues());assertThrows(UnsupportedOperationException.class,()->original.getRequiredAcrValues().clear());assertFalse(original.toString().contains("urn:strong"));
  }
 }
 @TestFactory @NonNull List<@NonNull DynamicTest> policyArrayMustBePresentTypedUniqueAndValid(){
  List<DynamicTest> tests=new ArrayList<>();for(String value:List.of("null","\"urn:strong\"","[1]","[\"urn:strong\",\"urn:strong\"]","[\"\"]","[\"a b\"]","[\"é\"]","[[\"urn:strong\"]]","{}"))tests.add(DynamicTest.dynamicTest("policy-"+tests.size(),()->{
   try(var server=TestHttpsServer.start()){
    var original=OidcPerFlowAssuranceTests.login(server,OidcRefreshTests.builder(server).build(),Set.of("urn:strong"),"urn:strong").authentication().getSessionReference();String text=original.toSerializedForm();String changed=text.replace("\"required_acr_values\":[\"urn:strong\"]","\"required_acr_values\":"+value);assertNotEquals(text,changed);assertEquals(OidcValidationException.Reason.SESSION_REFERENCE_INVALID,assertInstanceOf(OidcSessionReferenceParseResult.Rejected.class,OidcSessionReference.fromSerializedFormResult(changed)).getReason());
   }
  }));return tests;
 }
}
