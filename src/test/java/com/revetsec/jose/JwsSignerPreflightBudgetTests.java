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
package com.revetsec.jose;

import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.*;

/** Public 1ns-budget precedence controls on the declared JDK17/21/27 qualification lanes. */
final class JwsSignerPreflightBudgetTests {
 @Test void typedInvalidClaimsCannotOverrideTheExpiredPreflightBudget(){
  var signer=signer();var header=JwtSigningHeader.fromType(JwtType.JWT);var invalid=oversized();
  for(int warmup=0;warmup<100;warmup++)expectBudget(signer,header,invalid,Duration.ofNanos(1));
  for(int sample=0;sample<1000;sample++)expectBudget(signer,header,invalid,Duration.ofNanos(1));
 }
 @Test void zeroEntryBudgetKeepsItsDeterministicPrecedenceOverTypedInvalidClaims(){
  expectBudget(signer(),JwtSigningHeader.fromType(JwtType.JWT),oversized(),Duration.ZERO);
 }
 @Test void ordinaryBudgetPreservesTheTypedInvalidInputDiagnostic(){
  var signer=signer();var header=JwtSigningHeader.fromType(JwtType.JWT);var invalid=oversized();
  assertThrows(IllegalArgumentException.class,()->signer.withHeaderAndClaims(header,invalid).remainingBudget(Duration.ofSeconds(5)).build());
 }
 @Test void tinyValidClaimsStillRespectTheExistingPublicOneNanosecondBudget(){
  expectBudget(signer(),JwtSigningHeader.fromType(JwtType.JWT),JwtClaimsSet.builder().claim("control",true).build(),Duration.ofNanos(1));
 }
 private static @NonNull JwsSigner signer(){var key=TestJwk.Fixture.IDP_SIGNING_RSA_2048;return JwsSigner.fromRsaKeyPair(key.getPrivateKey(),key.getPublicKey(),JwsAlgorithm.RS256);}
 private static @NonNull JwtClaimsSet oversized(){return JwtClaimsSet.builder().claim("padding","a".repeat(32769)).build();}
 private static void expectBudget(@NonNull JwsSigner signer,@NonNull JwtSigningHeader header,@NonNull JwtClaimsSet claims,@NonNull Duration budget){
  RuntimeException observed=assertThrows(RuntimeException.class,()->signer.withHeaderAndClaims(header,claims).remainingBudget(budget).build());
  var failure=assertInstanceOf(JwsSigningException.class,observed);
  assertEquals(JwsSigningException.Reason.BUDGET_EXHAUSTED,failure.getReason());assertNull(failure.getCause());assertEquals(0,failure.getSuppressed().length);
 }
}
