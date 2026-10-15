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
import com.revetsec.RevetsecException;
import com.revetsec.internal.jose.*;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJws;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.Set;

/** The prepared-validation entry point must publish its success and both failure categories. */
final class JwtValidatorRc1MutationTests {
 @Test void preparedSuccessPublishesExactlyOneMeasuredSuccess()throws Exception{
  Recording observer=new Recording();JwtValidator validator=JwtFixtures.validator(JwtFixtures.source(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048)).observer(observer).build();
  Jwt jwt=JwtValidationAccess.get().validatePrepared(validator,prepared(JwtFixtures.signed(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048,TestJws.Algorithm.RS256)),()->1_000_000_000L);
  Assertions.assertEquals(JwsAlgorithm.RS256,jwt.getAlgorithm());Assertions.assertEquals(1,observer.success);Assertions.assertEquals(0,observer.failure);measured(observer.elapsed);
 }
 @Test void preparedSignatureFailurePublishesTheExactMappedException(){
  Recording observer=new Recording();JwtValidator validator=JwtFixtures.validator(JwtFixtures.source(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048)).observer(observer).build();
  String token=JwtFixtures.signed(TestJsonWebKeys.Fixture.SP_SIGNING_RSA_2048,TestJws.Algorithm.RS256);
  JoseException failure=Assertions.assertThrows(JoseException.class,()->JwtValidationAccess.get().validatePrepared(validator,prepared(token),()->1_000_000_000L));
  Assertions.assertEquals(JoseException.Reason.SIGNATURE_MISMATCH,failure.getReason());Assertions.assertSame(failure,observer.exception);Assertions.assertEquals(0,observer.success);Assertions.assertEquals(1,observer.failure);measured(observer.elapsed);
 }
 @Test void preparedPolicyFailurePublishesTheExactPublicException(){
  Recording observer=new Recording();JwtValidator validator=JwtFixtures.validator(JwtFixtures.source(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048)).allowedAlgorithms(Set.of(JwsAlgorithm.ES256)).observer(observer).build();
  JoseException failure=Assertions.assertThrows(JoseException.class,()->JwtValidationAccess.get().validatePrepared(validator,prepared(JwtFixtures.signed(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048,TestJws.Algorithm.RS256)),()->1_000_000_000L));
  Assertions.assertEquals(JoseException.Reason.ALGORITHM_NOT_ALLOWED,failure.getReason());Assertions.assertSame(failure,observer.exception);Assertions.assertEquals(0,observer.success);Assertions.assertEquals(1,observer.failure);measured(observer.elapsed);
 }
 @Test void unexpectedStaticSelectionFailureMapsToUnknownKey()throws Exception{
  StaticJsonWebKeySource source=JwtFixtures.source(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048);
  var field=JsonWebKeySet.class.getDeclaredField("verificationKeys");field.setAccessible(true);
  field.set(source.getJsonWebKeySet(),new java.util.AbstractList<VerificationKey>(){
   @Override public @NonNull VerificationKey get(int index){throw new IllegalStateException("controlled selector fault");}
   @Override public int size(){return 1;}
  });
  JwtValidator validator=JwtFixtures.validator(source).build();
  JoseException failure=Assertions.assertThrows(JoseException.class,()->JwtValidationAccess.get().validatePrepared(validator,prepared(JwtFixtures.signed(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048,TestJws.Algorithm.RS256)),()->1_000_000_000L));
  Assertions.assertEquals(JoseException.Reason.UNKNOWN_KEY,failure.getReason());
 }
 @Test void redactedResultDiagnosticRetainsItsOutcomeKind(){
  JwtValidationResult rejected=JwtValidationResult.fromReason(JoseException.Reason.UNKNOWN_KEY);
  Assertions.assertTrue(rejected.toString().contains("Rejected"));Assertions.assertFalse(rejected.toString().contains(JoseException.Reason.UNKNOWN_KEY.name()));
 }
 private static @NonNull PreparedJws prepared(@NonNull String token)throws JoseFailure{return JwtProcessor.prepare(token,JoseHeaderPolicy.fromSettings(65536,Set.of(JwsAlgorithm.RS256),Set.of("JWT"),false));}
 private static void measured(@Nullable Duration elapsed){Assertions.assertNotNull(elapsed);Assertions.assertFalse(elapsed.isNegative());Assertions.assertTrue(elapsed.compareTo(Duration.ofSeconds(2))<0,"elapsed must be a nanoTime difference");}
 private static final class Recording implements JoseObserver {
  private int success;private int failure;private @Nullable Duration elapsed;private @Nullable RevetsecException exception;
  @Override public void didValidateJwt(@NonNull JwsAlgorithm algorithm,@NonNull Duration elapsed){success++;this.elapsed=elapsed;}
  @Override public void didFailToValidateJwt(@NonNull RevetsecException exception,@NonNull Duration elapsed){failure++;this.exception=exception;this.elapsed=elapsed;}
 }
}
