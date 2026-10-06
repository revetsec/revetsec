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

import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** Retains the exact prepared success body/header bytes. Emission uses the restricted public response boundary. */
final class OAuthTokenResponse {
 private final @NonNull OAuthServerResponse response;
 private OAuthTokenResponse(@NonNull OAuthServerResponse response) { this.response = response; }
 byte @NonNull [] body() { return this.response.toHttpBodyWithCredentials(); }
 byte @NonNull [] headers() { return this.response.wireHeaders(); }
 @NonNull OAuthServerResponse response() { return this.response; }
 @Override public @NonNull String toString() { return "OAuthTokenResponse{<redacted>}"; }

 /** Fixed issuer/RS256 profile with an optional managed publication and retirement boundary. */
 static final class Encoder {
  private final @NonNull String issuer;
  private final @Nullable String keyId;
  private final @Nullable JwsSigner signer;
  private final @Nullable OAuthIssuerKeyLifecycle lifecycle;
  private final int bodyCap, headerCap;
  Encoder(@NonNull String issuer, @NonNull String keyId, @NonNull JwsSigner signer, int bodyCap, int headerCap) {
   OAuthServerConfiguration.text(issuer, 2048); OAuthServerConfiguration.text(keyId, 256);
   this.issuer = issuer; this.keyId = keyId; this.signer = requireNonNull(signer);
   if (signer.getAlgorithm() != JwsAlgorithm.RS256 || bodyCap < 4096 || bodyCap > 131072
     || headerCap < 1024 || headerCap > 65536) throw OAuthStoreFormat.invalid();
   this.bodyCap = bodyCap; this.headerCap = headerCap; this.lifecycle = null;
  }
  Encoder(@NonNull String issuer, @NonNull OAuthIssuerKeyLifecycle lifecycle, int bodyCap, int headerCap) {
   this.issuer=OAuthServerConfiguration.text(issuer,2048);this.lifecycle=requireNonNull(lifecycle);
   this.keyId=null;this.signer=null;
   if(bodyCap<4096 || bodyCap>131072 || headerCap<1024 || headerCap>65536) throw OAuthStoreFormat.invalid();
   this.bodyCap=bodyCap;this.headerCap=headerCap;
  }
  @NonNull String issuer() { return this.issuer; }
  @NonNull OAuthTokenResponse prepare(@NonNull OAuthAuthorizationRecord grant, @NonNull String jti,
    @NonNull Instant issued, @NonNull Instant expires, @NonNull Set<@NonNull String> scopes,
    @Nullable String refresh, @NonNull Deadline deadline) {
   String scope = String.join(" ", scopes.stream().sorted().toList());
   JsonObject claims = JsonObject.builder().put("iss", this.issuer).put("sub", grant.text("subject"))
    .put("aud", grant.text("resource")).put("client_id", grant.text("clientId"))
    .put("iat", issued.getEpochSecond()).put("exp", expires.getEpochSecond()).put("jti", jti).put("scope", scope).build();
   byte[] bytes = JsonCodec.toUtf8Bytes(claims);
   String compact;
   try { compact = this.lifecycle==null ? requireNonNull(this.signer).toCompactSerialization("at+jwt", this.keyId, null, bytes, OAuthServerClientAdmission.remaining(deadline))
    : this.lifecycle.sign(bytes, expires, deadline); }
   finally { Arrays.fill(bytes, (byte) 0); }
   OAuthServerClientAdmission.remaining(deadline);
   JsonObject.Builder response = JsonObject.builder().put("access_token", compact).put("token_type", "Bearer")
    .put("expires_in", java.time.Duration.between(issued, expires).getSeconds()).put("scope", scope);
   if (refresh != null) response.put("refresh_token", refresh);
   byte[] body = JsonCodec.toUtf8Bytes(response.build());
   try {
    OAuthServerResponse prepared = OAuthServerResponse.prepare(200, OAuthServerResponse.privateHeaders(body.length), null, body, this.bodyCap, this.headerCap);
    OAuthServerClientAdmission.remaining(deadline); return new OAuthTokenResponse(prepared);
   } catch (RuntimeException failure) { throw OAuthStoreFormat.invalid(); }
   finally { Arrays.fill(body, (byte) 0); }
  }
  @Override public @NonNull String toString() { return "OAuthTokenResponse.Encoder{<redacted>}"; }
 }
}
