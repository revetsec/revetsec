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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.encoding.EncodingException;
import org.jspecify.annotations.NonNull;
import java.net.URI;
import static java.util.Objects.requireNonNull;

/** Pure URL eligibility only. DNS, all-answer public-address checks and peer pinning remain mandatory transport work. */
final class OAuthClientMetadataUri {
 private OAuthClientMetadataUri() {}
 static @NonNull URI clientId(@NonNull String id, @NonNull OAuthClientMetadataPolicy policy, int cap) {
  requireNonNull(policy); OAuthServerConfiguration.text(id, cap);
  URI uri = URI.create(id); checked(uri);
  if (!policy.getEnabled()) throw OAuthServerConfiguration.invalid();
  String path = uri.getRawPath();
  if (path == null || path.isEmpty()) throw OAuthServerConfiguration.invalid();
  try {
   String decoded = FormUrlEncoding.decode(path.replace("+", "%2B"));
   for (String part : decoded.split("/", -1)) if (part.equals(".") || part.equals("..")) throw OAuthServerConfiguration.invalid();
   if (decoded.indexOf('\\') >= 0) throw OAuthServerConfiguration.invalid();
   OAuthServerConfiguration.text(decoded, OAuthServerConfiguration.MAXIMUM_URI_LENGTH);
  } catch (EncodingException failure) { throw OAuthServerConfiguration.invalid(); }
  var allowed = policy.getAllowedOrigins();
  if (allowed.isPresent() && allowed.orElseThrow().stream().noneMatch(origin -> sameOrigin(origin, uri)))
   throw OAuthServerConfiguration.invalid();
  return uri;
 }
 static void origin(@NonNull URI uri) {
  checked(uri);
  if (!"".equals(uri.getRawPath()) || uri.getRawQuery() != null) throw OAuthServerConfiguration.invalid();
 }
 private static void checked(@NonNull URI uri) {
  requireNonNull(uri); OAuthServerConfiguration.text(uri.toString(), OAuthServerConfiguration.MAXIMUM_URI_LENGTH);
  if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.isOpaque()
    || uri.getRawUserInfo() != null || uri.getRawFragment() != null || uri.getPort() == 0 || uri.getPort() > 65535
    || uri.toString().indexOf('*') >= 0 || !OutboundUriPolicy.publicAddressesOnlyInstance().permits(uri))
   throw OAuthServerConfiguration.invalid();
 }
 private static boolean sameOrigin(@NonNull URI origin, @NonNull URI uri) {
  return requireNonNull(origin.getScheme()).equalsIgnoreCase(uri.getScheme())
   && requireNonNull(origin.getHost()).equalsIgnoreCase(uri.getHost()) && origin.getPort() == uri.getPort();
 }
}
