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

import com.revetsec.internal.crypto.RsaPublicKeys;
import com.revetsec.internal.crypto.KeyRejectedException;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import java.util.ArrayList;
import java.util.List;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import static java.util.Objects.requireNonNull;

/** Bounded immutable public projections and canonical, public-only JWKS. No private key encoding. */
final class OAuthIssuerPublicKeys {
 private OAuthIssuerPublicKeys() { }
 static @NonNull PublicKey snapshot(@NonNull PublicKey key) {
  requireNonNull(key);
  try {
   if (!(key instanceof RSAPublicKey rsa) || !"RSA".equalsIgnoreCase(key.getAlgorithm()) || rsa.getParams()!=null)
    throw OAuthStoreFormat.invalid();
   Projection result=new Projection(integer(requireNonNull(rsa.getModulus()),16384,2049),
    integer(requireNonNull(rsa.getPublicExponent()),32,5));
   RsaPublicKeys.checkPublicKey(result); return result;
  } catch (KeyRejectedException | RuntimeException fault) { throw OAuthStoreFormat.invalid(); }
 }
 private static @NonNull BigInteger integer(@NonNull BigInteger value,int bits,int bytes) {
  if(value.bitLength()<1 || value.bitLength()>bits) throw OAuthStoreFormat.invalid();
  byte[] copy=value.toByteArray();
  if(copy.length==0 || copy.length>bytes) throw OAuthStoreFormat.invalid();
  return new BigInteger(copy);
 }
 static @NonNull String material(@NonNull PublicKey key) {
  RSAPublicKey rsa=(RSAPublicKey)key;
  return unsigned(rsa.getModulus())+"."+unsigned(rsa.getPublicExponent());
 }
 private static @NonNull String unsigned(@NonNull BigInteger value) {
  byte[] bytes=value.toByteArray();
  return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes[0]==0 && bytes.length>1 ? Arrays.copyOfRange(bytes,1,bytes.length) : bytes);
 }
 static @NonNull JsonObject jwks(@NonNull Map<@NonNull String,@NonNull PublicKey> keys) {
  List<JsonValue> array=new ArrayList<>();
  for(String id:keys.keySet().stream().sorted().toList()) {
   RSAPublicKey rsa=(RSAPublicKey)requireNonNull(keys.get(id));
   array.add(JsonObject.builder().put("kty","RSA").put("alg","RS256").put("use","sig")
    .put("key_ops",JsonArray.fromElements(List.of(JsonString.fromValue("verify")))).put("kid",id)
    .put("n",unsigned(rsa.getModulus())).put("e",unsigned(rsa.getPublicExponent())).build());
  }
  return JsonObject.builder().put("keys",JsonArray.fromElements(array)).build();
 }
 private static final class Projection implements RSAPublicKey {
  private static final long serialVersionUID=1L;
  private final @NonNull BigInteger modulus,exponent;
  private Projection(@NonNull BigInteger modulus,@NonNull BigInteger exponent) { this.modulus=modulus;this.exponent=exponent; }
  @Override public @NonNull BigInteger getModulus() { return this.modulus; }
  @Override public @NonNull BigInteger getPublicExponent() { return this.exponent; }
  @Override public @NonNull String getAlgorithm() { return "RSA"; }
  @Override public @Nullable String getFormat() { return null; }
  @Override public byte @Nullable [] getEncoded() { return null; }
  @Override public @Nullable AlgorithmParameterSpec getParams() { return null; }
  @Override public @NonNull String toString() { return "OAuthIssuerPublicKey{<redacted>}"; }
 }
}
