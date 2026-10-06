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
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.encoding.EncodingException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.util.List;

/** Only called with an authenticated, browser/client-bound interaction before consent commit. */
final class OAuthAuthorizationResponseEncoder {
 private final @NonNull String issuer;
 private final int bodyCap, headerCap, stateCap;
 OAuthAuthorizationResponseEncoder(@NonNull URI issuer, boolean insecureLoopback, int bodyCap, int headerCap, int stateCap) {
  boolean loopback = "http".equalsIgnoreCase(issuer.getScheme()) && ("127.0.0.1".equals(issuer.getHost()) || "[::1]".equals(issuer.getHost()));
  if (issuer.isOpaque() || issuer.getHost() == null || issuer.getRawQuery() != null || issuer.getRawFragment() != null
    || issuer.getRawUserInfo() != null || issuer.getPort() > 65535
    || !("https".equalsIgnoreCase(issuer.getScheme()) || (insecureLoopback && loopback))) throw OAuthStoreFormat.invalid();
  this.issuer = OAuthServerConfiguration.text(issuer.toString(), 2048);
  this.bodyCap = Limits.AS_MAXIMUM_RESPONSE_BODY_BYTES.require(bodyCap); this.headerCap = Limits.AS_MAXIMUM_HEADER_BYTES.require(headerCap);
  this.stateCap = Limits.AS_MAXIMUM_STATE_LENGTH.require(stateCap);
 }
 @NonNull OAuthServerResponse prepare(@NonNull OAuthAuthorizationRecord interaction, @Nullable String code) {
  String redirect = interaction.text("redirect"), state = interaction.state(this.stateCap);
  URI checked = URI.create(redirect); OAuthServerConfiguration.redirects(List.of(checked));
  if (code != null) OAuthServerCredential.codeDigest(code);
  try {
   // Preserve every original query octet, including percent spelling, ordering and empty query presence.
   String location = redirect + (checked.getRawQuery() == null ? "?" : checked.getRawQuery().isEmpty() ? "" : "&")
    + (code == null ? "error=access_denied" : "code=" + FormUrlEncoding.encode(code))
    + (state == null ? "" : "&state=" + FormUrlEncoding.encode(state)) + "&iss=" + FormUrlEncoding.encode(this.issuer);
   return OAuthServerResponse.prepare(303, OAuthServerResponse.privateHeaders(0), URI.create(location), new byte[0], this.bodyCap, this.headerCap);
  } catch (EncodingException failure) { throw OAuthStoreFormat.invalid(); }
 }
 @Override public @NonNull String toString() { return "OAuthAuthorizationResponseEncoder{<redacted>}"; }
}
