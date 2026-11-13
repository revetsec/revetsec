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

import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonNull;
import com.revetsec.oauth.OAuthEndpoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.jspecify.annotations.NonNull;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Inactive logout metadata/endpoint contract; browser flow is a separate slice. */
final class OidcLogoutMetadataTests {
 private static final String ISSUER="https://idp.example";
 private static final URI END=URI.create(ISSUER+"/logout?tenant=one");
 private static JsonObject.@NonNull Builder document(){return JsonObject.builder().put("issuer",ISSUER).put("authorization_endpoint",ISSUER+"/authorize").put("token_endpoint",ISSUER+"/token").put("jwks_uri",ISSUER+"/keys").put("subject_types_supported",JsonArray.fromElements(List.of(JsonString.fromValue("public")))).put("id_token_signing_alg_values_supported",JsonArray.fromElements(List.of(JsonString.fromValue("RS256")))).put("response_types_supported",JsonArray.fromElements(List.of(JsonString.fromValue("code"))));}
 private static @NonNull OidcProviderMetadata parsed(@NonNull String document){return assertInstanceOf(OidcProviderMetadataParseResult.Succeeded.class,OidcProviderMetadata.fromJsonResult(ISSUER,document)).getMetadata();}
 private static @NonNull Object endpoint(@NonNull OidcProviderMetadata metadata){return assertDoesNotThrow(()->OidcProviderMetadata.class.getMethod("getEndSessionEndpoint").invoke(metadata),"The logout endpoint must have a public optional metadata accessor");}
 @Test void logoutHasItsOwnEndpointCategory(){assertEquals("END_SESSION",assertDoesNotThrow(()->OAuthEndpoint.valueOf("END_SESSION"),"Logout needs its selected endpoint category").name());}
 @Test void absentRemoteLogoutEndpointStaysAbsent(){assertEquals(Optional.empty(),endpoint(parsed(document().build().toJson())));}
 @Test void remoteLogoutEndpointRetainsTheExactConfiguredUri(){assertEquals(Optional.of(END),endpoint(parsed(document().put("end_session_endpoint",END.toString()).build().toJson())));}
 @Test void explicitBuilderSnapshotsAndNullClearsWithoutDiscovery(){
  var b=OidcProviderMetadata.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).jwksUri(URI.create(ISSUER+"/keys"));
  var method=assertDoesNotThrow(()->OidcProviderMetadata.Builder.class.getMethod("endSessionEndpoint",URI.class));
  assertSame(b,assertDoesNotThrow(()->method.invoke(b,END)));var first=b.build();
  assertSame(b,assertDoesNotThrow(()->method.invoke(b,new Object[]{null})));assertEquals(Optional.of(END),endpoint(first));assertEquals(Optional.empty(),endpoint(b.build()));
 }
 @TestFactory @NonNull Stream<@NonNull DynamicTest> malformedRemoteLogoutValuesAreRejected(){
  List<JsonValue> values=List.of(JsonNull.defaultInstance(),JsonBoolean.fromValue(true),JsonNumber.fromValue(1L),JsonString.fromValue(""),JsonString.fromValue("http://[broken"),JsonObject.builder().build(),JsonArray.fromElements(List.of(JsonString.fromValue("https://idp.example/logout"))));
  return java.util.stream.IntStream.range(0,values.size()).mapToObj(i->DynamicTest.dynamicTest("malformed-logout-metadata-"+i,()->assertInstanceOf(OidcProviderMetadataParseResult.Rejected.class,OidcProviderMetadata.fromJsonResult(ISSUER,document().put("end_session_endpoint",values.get(i)).build().toJson()))));
 }
 @Test void duplicateLogoutMetadataRemainsMalformed(){String value=document().put("end_session_endpoint",END.toString()).build().toJson();value=value.substring(0,value.length()-1)+",\"end_session_endpoint\":\"https://other.example/logout\"}";assertInstanceOf(OidcProviderMetadataParseResult.Rejected.class,OidcProviderMetadata.fromJsonResult(ISSUER,value));}
 @Test void nullableMetadataCollectionsRestoreExactDefaults(){var metadata=OidcProviderMetadata.withIssuer(ISSUER).authorizationEndpoint(URI.create(ISSUER+"/authorize")).tokenEndpoint(URI.create(ISSUER+"/token")).jwksUri(URI.create(ISSUER+"/keys")).subjectTypesSupported(null).idTokenSigningAlgValuesSupported(null).responseTypesSupported(null).userInfoSigningAlgValuesSupported(null).build();assertEquals(Set.of("public"),metadata.getSubjectTypesSupported());assertEquals(Set.of("RS256"),metadata.getIdTokenSigningAlgValuesSupported());assertEquals(Set.of("code"),metadata.getResponseTypesSupported());assertTrue(metadata.getUserInfoSigningAlgValuesSupported().isEmpty());assertThrows(IllegalArgumentException.class,()->OidcProviderMetadata.withIssuer(ISSUER).userInfoSigningAlgValuesSupported(Set.of("")));}
 @Test void metadataDiagnosticsRemainValueFree(){String rendered=parsed(document().put("end_session_endpoint",END.toString()).build().toJson()).toString();assertEquals("OidcProviderMetadata{configuration=<redacted>}",rendered);}
}
