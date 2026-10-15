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
import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.Base64;
import java.security.interfaces.RSAPublicKey;
final class JwsProjectionRc1MutationTests {
 @Test void projectedSignatureLengthMatchesTheActualRsaSignature()throws Exception{
  JwsSigner signer=signer();Object key=projection(signer);var length=key.getClass().getDeclaredMethod("signatureLength");length.setAccessible(true);
  String compact=signer.toCompactSerialization("JWT",null,null,new byte[]{'{','}'},Duration.ofSeconds(5));
  int actual=Base64.getUrlDecoder().decode(compact.substring(compact.lastIndexOf('.')+1)).length;
  Assertions.assertTrue(actual>0);Assertions.assertEquals(actual,length.invoke(key));
 }
 @Test void providerKeyDescriptionIsUsefulAndOmitsRsaMaterial()throws Exception{
  RSAPublicKey key=(RSAPublicKey)projection(signer());String description=key.toString();Assertions.assertFalse(description.isBlank());Assertions.assertFalse(description.contains(key.getModulus().toString()));Assertions.assertFalse(description.contains(key.getPublicExponent().toString()));
 }
 private static @NonNull Object projection(@NonNull JwsSigner signer)throws Exception{var field=JwsSigner.class.getDeclaredField("publicKey");field.setAccessible(true);return java.util.Objects.requireNonNull(field.get(signer));}
 private static @NonNull JwsSigner signer(){return JwsSigner.fromRsaKeyPair(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey(),TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPublicKey(),JwsAlgorithm.RS256);}
}
