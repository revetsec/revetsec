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
import java.util.Arrays;

/** Exact bounded internal endpoint bytes, prepared before any successful state admission. */
final class OAuthStatusResponse {
 private final @NonNull OAuthServerResponse response;
 private OAuthStatusResponse(@NonNull OAuthServerResponse response) { this.response = response; }
 @NonNull OAuthServerResponse response() { return this.response; }
 static @NonNull OAuthStatusResponse prepare(@NonNull JsonObject json, int bodyCap, int headerCap) {
  return prepare(JsonCodec.toUtf8Bytes(json), bodyCap, headerCap);
 }
 static @NonNull OAuthStatusResponse revocation(int bodyCap, int headerCap) {
  return prepare(new byte[0], bodyCap, headerCap);
 }
 private static @NonNull OAuthStatusResponse prepare(byte @NonNull [] body, int bodyCap, int headerCap) {
  try {
   return new OAuthStatusResponse(OAuthServerResponse.prepare(200, OAuthServerResponse.privateHeaders(body.length), null, body, bodyCap, headerCap));
  } catch (RuntimeException failure) { throw new OAuthStoreFailure(OAuthStoreFailure.Reason.CORRUPT_STATE); }
  finally { Arrays.fill(body, (byte) 0); }
 }
 byte @NonNull [] body() { return this.response.toHttpBodyWithCredentials(); }
 byte @NonNull [] headers() { return this.response.wireHeaders(); }
 @Override public @NonNull String toString() { return "OAuthStatusResponse{<redacted>}"; }
}
