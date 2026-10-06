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

import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.Immutable;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/**
 * An immutable, bounded response prepared by the authorization server. Credential emission is explicit;
 * ordinary headers exclude Location. Instances retain identity equality and fixed redacted diagnostics.
 * Applications may add their own browser cookies at the HTTP edge.
 *
 * @since 1.0.0
 */
@Immutable
public final class OAuthServerResponse {
 private static final @NonNull Set<@NonNull String> HEADER_NAMES = Set.of("Content-Type", "Cache-Control", "Pragma",
  "Content-Length", "Referrer-Policy", "Allow", "ETag", "WWW-Authenticate");
 private final int status;
 private final @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers;
 private final @Nullable URI location;
 private final byte @NonNull [] body, wireHeaders;
 private OAuthServerResponse(int status, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers,
   @Nullable URI location, byte @NonNull [] body, byte @NonNull [] wireHeaders) {
  this.status = status; this.headers = Map.copyOf(headers); this.location = location; this.body = body; this.wireHeaders = wireHeaders;
 }
 /** Returns the HTTP status code.
  *
  * @return the HTTP status code
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull Integer getStatusCode() { return this.status; }
 /** Returns immutable ordinary headers; credential-bearing Location is separate.
  *
  * @return immutable response headers, excluding Location
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> getHeaders() { return this.headers; }
 /** Returns the optional credential-bearing redirect for HTTP emission.
  *
  * @return the optional credential-bearing redirect; use only for HTTP emission
  * @since 1.0.0
  */
 @CheckReturnValue public @NonNull Optional<@NonNull URI> getLocationWithCredentials() { return Optional.ofNullable(this.location); }
 /** Emits a defensive bounded HTTP body copy that may contain credentials or personal data.
  *
  * @return a defensive copy of the bounded HTTP body, which may contain credentials or personal data
  * @since 1.0.0
  */
 @CheckReturnValue public byte @NonNull [] toHttpBodyWithCredentials() { return this.body.clone(); }
 /** Returns a fixed description that omits response contents.
  *
  * @return a fixed description that omits response contents
  * @since 1.0.0
  */
 @Override public @NonNull String toString() { return "OAuthServerResponse{<redacted>}"; }

 // Restricted to core preparation; never expose a public raw-holder factory or builder.
 static @NonNull OAuthServerResponse prepare(int status, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers,
   @Nullable URI location, byte @NonNull [] body, int bodyCap, int headerCap) {
  Limits.AS_MAXIMUM_RESPONSE_BODY_BYTES.require(bodyCap); Limits.AS_MAXIMUM_HEADER_BYTES.require(headerCap);
  requireNonNull(body); requireNonNull(headers);
  String reason = switch (status) {
   case 200 -> "OK"; case 303 -> "See Other"; case 400 -> "Bad Request"; case 401 -> "Unauthorized";
   case 403 -> "Forbidden"; case 404 -> "Not Found"; case 405 -> "Method Not Allowed"; case 503 -> "Service Unavailable";
   default -> throw OAuthStoreFormat.invalid();
  };
  if (body.length > bodyCap || (location != null && status != 303) || (status == 303 && location == null)) throw OAuthStoreFormat.invalid();
  Map<String, List<String>> copy = new LinkedHashMap<>();
  StringBuilder wire = new StringBuilder("HTTP/1.1 ").append(status).append(' ').append(reason).append("\r\n");
  for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
   String name = requireNonNull(entry.getKey());
   if (!HEADER_NAMES.contains(name)) throw OAuthStoreFormat.invalid();
   List<String> values = List.copyOf(requireNonNull(entry.getValue()));
   if (values.size() != 1) throw OAuthStoreFormat.invalid();
   String value = values.get(0);
   if (value.length() > headerCap) throw OAuthStoreFormat.invalid();
   for (int i = 0; i < value.length(); i++) if (value.charAt(i) < 0x20 || value.charAt(i) > 0x7e) throw OAuthStoreFormat.invalid();
   copy.put(name, values); wire.append(name).append(": ").append(value).append("\r\n");
   if (wire.length() > headerCap) throw OAuthStoreFormat.invalid();
  }
  if (!List.of("no-referrer").equals(copy.get("Referrer-Policy"))) throw OAuthStoreFormat.invalid();
  if (location != null) {
   if (!location.isAbsolute() || location.getRawFragment() != null || location.getRawUserInfo() != null) throw OAuthStoreFormat.invalid();
   String ascii = location.toASCIIString();
   if (ascii.length() > headerCap) throw OAuthStoreFormat.invalid();
   for (int i = 0; i < ascii.length(); i++) if (ascii.charAt(i) < 0x21 || ascii.charAt(i) > 0x7e) throw OAuthStoreFormat.invalid();
   wire.append("Location: ").append(ascii).append("\r\n");
  }
  wire.append("\r\n");
  if (wire.length() > headerCap) throw OAuthStoreFormat.invalid();
  return new OAuthServerResponse(status, Collections.unmodifiableMap(copy), location, body.clone(), wire.toString().getBytes(StandardCharsets.US_ASCII));
 }
 static @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> privateHeaders(int length) {
  Map<String, List<String>> headers = new LinkedHashMap<>();
  headers.put("Content-Type", List.of("application/json")); headers.put("Cache-Control", List.of("no-store"));
  headers.put("Pragma", List.of("no-cache")); headers.put("Referrer-Policy", List.of("no-referrer"));
  headers.put("Content-Length", List.of(Integer.toString(length))); return headers;
 }
 byte @NonNull [] wireHeaders() { return this.wireHeaders.clone(); }
}
