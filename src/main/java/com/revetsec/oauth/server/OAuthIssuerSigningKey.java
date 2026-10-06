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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import org.jspecify.annotations.NonNull;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.annotation.concurrent.Immutable;

/**
 * One application-owned RS256 signing key. Construction checks the public RSA structure without signing or
 * encoding private material. Pair agreement is checked during bounded signing or explicit engine warm-up.
 * The application must keep provider-backed private handles usable during in-flight operations and keep
 * identifiers permanently bound to their public material across nodes and restarts.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class OAuthIssuerSigningKey {
 private final @NonNull String keyId;
 private final @NonNull JwsSigner signer;
 private OAuthIssuerSigningKey(@NonNull String keyId, @NonNull JwsSigner signer) { this.keyId=keyId; this.signer=signer; }
 /**
  * Checks one RS256 key pair structurally, without testing or encoding the private key.
  * @param keyId nonempty identifier, at most 256 characters
  * @param privateKey application-owned RSA private key or provider handle
  * @param publicKey inspectable RSA public key, 2048–16384 bits under the existing exponent and ROCA policy
  * @return an immutable redacted holder
  * @throws NullPointerException if a required argument is null
  * @throws IllegalArgumentException if supplied structure is invalid
  * @since 1.0.0
  */
 @CheckReturnValue
 public static @NonNull OAuthIssuerSigningKey fromKeyPair(@NonNull String keyId, @NonNull PrivateKey privateKey,
   @NonNull PublicKey publicKey) {
  return new OAuthIssuerSigningKey(OAuthServerConfiguration.text(keyId,256),
   JwsSigner.fromRsaKeyPair(privateKey,publicKey,JwsAlgorithm.RS256));
 }
 /** Returns the exact key identifier.
  * @return the exact public identifier
  * @since 1.0.0
  */
 public @NonNull String getKeyId() { return this.keyId; }
 /** Returns the checked public verification projection.
  * @return the immutable checked public projection, without private material
  * @since 1.0.0
  */
 public @NonNull PublicKey getPublicKey() { return this.signer.getPublicKey(); }
 @NonNull JwsSigner signer() { return this.signer; }
 /** @return a description without identifiers or key material
  * @since 1.0.0
  */
 @Override public @NonNull String toString() { return "OAuthIssuerSigningKey{<redacted>}"; }
}
