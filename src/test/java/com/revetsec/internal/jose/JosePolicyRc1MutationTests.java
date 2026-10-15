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

package com.revetsec.internal.jose;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.Set;
final class JosePolicyRc1MutationTests {
 @Test void requiredClaimsGetterRetainsConfiguredNamesAndIsUnmodifiable(){
  JwtClaimsPolicy policy=JwtClaimsPolicy.fromSettings("https://issuer.example",Set.of("aud"),Set.of("sub","jti"),Duration.ZERO);
  Assertions.assertEquals(Set.of("sub","jti"),policy.getRequiredClaims());
  Assertions.assertThrows(UnsupportedOperationException.class,()->policy.getRequiredClaims().add("other"));
 }
 @Test void verifiedJwsRetainsItsReceivedHeaderFacts(){
  VerifiedJws present=new VerifiedJws(com.revetsec.jose.JwsAlgorithm.RS256,"fixture-key","JWT",new byte[]{1,2},null);
  Assertions.assertEquals(java.util.Optional.of("fixture-key"),present.findKeyId());
  Assertions.assertEquals(java.util.Optional.of("JWT"),present.findType());
  Assertions.assertEquals(com.revetsec.jose.JwsAlgorithm.RS256,present.getAlgorithm());
  Assertions.assertTrue(new VerifiedJws(com.revetsec.jose.JwsAlgorithm.RS256,null,null,new byte[0],null).findKeyId().isEmpty());
 }

}
