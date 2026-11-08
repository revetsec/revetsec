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

package com.revetsec.oauth;

import org.junit.jupiter.api.Test;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

/** Pre-freeze reserved-name contract; this selects no rich-authorization request implementation. */
final class OAuthAdditiveApiHygieneTests {
 @Test void authorizationDetailsCannotOccupyAnAuthorizationExtensionSlot(){
  for(String value:List.of("", "[]", "[{\"type\":\"payment\"}]"))
   assertThrows(IllegalArgumentException.class,()->AuthorizationRequestOptions.builder().additionalParameters(Map.of("authorization_details",value)));
 }
 @Test void authorizationDetailsCannotOccupyATokenExtensionSlot(){
  for(String value:List.of("", "[]", "[{\"type\":\"payment\"}]"))
   assertThrows(IllegalArgumentException.class,()->TokenRequestOptions.builder().additionalParameters(Map.of("authorization_details",value)));
 }
 @Test void nonreservedExtensionsRemainSnapshottedAndNullRestoresDefaults(){
  var source=new HashMap<>(Map.of("example_extension","first"));
  var auth=AuthorizationRequestOptions.builder().additionalParameters(source).build();
  var token=TokenRequestOptions.builder().additionalParameters(source).build();
  source.put("example_extension","second");
  assertEquals(Map.of("example_extension","first"),auth.getAdditionalParameters());
  assertEquals(Map.of("example_extension","first"),token.getAdditionalParameters());
  assertThrows(UnsupportedOperationException.class,()->auth.getAdditionalParameters().put("another","x"));
  assertThrows(UnsupportedOperationException.class,()->token.getAdditionalParameters().put("another","x"));
  assertTrue(AuthorizationRequestOptions.builder().additionalParameters(source).additionalParameters(null).build().getAdditionalParameters().isEmpty());
  assertTrue(TokenRequestOptions.builder().additionalParameters(source).additionalParameters(null).build().getAdditionalParameters().isEmpty());
 }
}
