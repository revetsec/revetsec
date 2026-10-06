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

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.List;
import java.util.LinkedHashMap;
import static java.util.Objects.requireNonNull;

/** Exact bounded public metadata bytes. Finite freshness and explicit revalidation; no credential emission. */
final class OAuthPublicMetadataResponse {
 private final @NonNull OAuthServerResponse response;
 private OAuthPublicMetadataResponse(@NonNull OAuthServerResponse response) { this.response = response; }
 @NonNull OAuthServerResponse response() { return this.response; }
 static @NonNull OAuthPublicMetadataResponse prepare(@NonNull JsonObject json,@NonNull String method,
   @NonNull Duration freshness,int bodyCap,int headerCap) {
  requireNonNull(json);requireNonNull(method);OAuthGrantRetention.duration(freshness,Duration.ZERO,Duration.ofMinutes(5));
  if(bodyCap<4096 || bodyCap>131072 || headerCap<1024 || headerCap>65536) throw OAuthStoreFormat.invalid();
  boolean allowed=method.equals("GET") || method.equals("HEAD");
  byte[] representation=allowed ? JsonCodec.toUtf8Bytes(json) : new byte[0];
  if(representation.length>bodyCap) throw OAuthStoreFormat.invalid();
  try {
   String tag=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(representation));
   Map<String, List<String>> headers = new LinkedHashMap<>();
   headers.put("Content-Type", List.of("application/json"));
   headers.put("Cache-Control", List.of(allowed ? "public, max-age="+freshness.toSeconds()+", must-revalidate" : "no-store"));
   headers.put("Referrer-Policy", List.of("no-referrer"));
   if (allowed) headers.put("ETag", List.of("\""+tag+"\"")); else headers.put("Allow", List.of("GET, HEAD"));
   headers.put("Content-Length", List.of(Integer.toString(representation.length)));
   return new OAuthPublicMetadataResponse(OAuthServerResponse.prepare(allowed ? 200 : 405, headers, null,
    method.equals("HEAD") ? new byte[0] : representation, bodyCap, headerCap));
  } catch(GeneralSecurityException fault) { throw new OAuthServerAdmissionFailure(OAuthServerAdmissionFailure.Reason.INFRASTRUCTURE); }
 }
 byte @NonNull [] body() { return this.response.toHttpBodyWithCredentials(); }
 byte @NonNull [] headers() { return this.response.wireHeaders(); }
 @Override public @NonNull String toString() { return "OAuthPublicMetadataResponse{<redacted>}"; }
}
