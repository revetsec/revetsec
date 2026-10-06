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
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** RFC 8414 trusted configuration. No Host/Forwarded inference, OP, DCR, ID token or unimplemented CIMD advertisement. */
final class OAuthIssuerMetadata {
 private final @NonNull URI wellKnown;
 private final @NonNull JsonObject metadata;
 private final @NonNull Duration freshness;
 private final int bodyCap,headerCap;
 OAuthIssuerMetadata(@NonNull URI issuer,@NonNull URI authorization,@NonNull URI token,@NonNull URI jwks,
   @Nullable URI revocation,@Nullable URI introspection,boolean refresh,boolean insecureLoopback,
   @NonNull Set<@NonNull String> scopes,@NonNull Duration freshness,int bodyCap,int headerCap) {
  this(issuer,authorization,token,jwks,revocation,introspection,refresh,insecureLoopback,scopes,freshness,bodyCap,headerCap,false);
 }
 OAuthIssuerMetadata(@NonNull URI issuer,@NonNull URI authorization,@NonNull URI token,@NonNull URI jwks,
   @Nullable URI revocation,@Nullable URI introspection,boolean refresh,boolean insecureLoopback,
   @NonNull Set<@NonNull String> scopes,@NonNull Duration freshness,int bodyCap,int headerCap,boolean cimd) {
  endpoint(issuer,insecureLoopback);endpoint(authorization,insecureLoopback);endpoint(token,insecureLoopback);endpoint(jwks,insecureLoopback);
  if(issuer.getRawQuery()!=null || bodyCap<4096 || bodyCap>131072 || headerCap<1024 || headerCap>65536) throw OAuthStoreFormat.invalid();
  this.freshness=OAuthGrantRetention.duration(freshness,Duration.ZERO,Duration.ofMinutes(5));this.bodyCap=bodyCap;this.headerCap=headerCap;
  String path=issuer.getRawPath();if(path.endsWith("/")) path=path.substring(0,path.length()-1);
  this.wellKnown=URI.create(issuer.getScheme()+"://"+issuer.getRawAuthority()+"/.well-known/oauth-authorization-server"+path);
  JsonObject.Builder builder=JsonObject.builder().put("issuer",issuer.toString()).put("authorization_endpoint",authorization.toString())
   .put("token_endpoint",token.toString()).put("jwks_uri",jwks.toString()).put("response_types_supported",array(List.of("code")))
   .put("grant_types_supported",array(refresh ? List.of("authorization_code","refresh_token") : List.of("authorization_code")))
   .put("token_endpoint_auth_methods_supported",array(List.of("none","client_secret_basic")))
   .put("code_challenge_methods_supported",array(List.of("S256"))).put("authorization_response_iss_parameter_supported",true);
  requireNonNull(scopes);if(scopes.size()>OAuthServerConfiguration.MAXIMUM_CONFIGURATION_BYTES) throw OAuthStoreFormat.invalid();
  int size=0;for(URI uri:List.of(issuer,authorization,token,jwks)) size=OAuthServerConfiguration.addBytes(size,uri.toString());
  if(revocation!=null) size=OAuthServerConfiguration.addBytes(size,revocation.toString());
  if(introspection!=null) size=OAuthServerConfiguration.addBytes(size,introspection.toString());
  List<String> sorted=scopes.stream().sorted().toList();for(String scope:sorted) size=OAuthServerConfiguration.addBytes(size,OAuthServerConfiguration.scope(scope));
  if(!sorted.isEmpty()) builder.put("scopes_supported",array(sorted));
  if(revocation!=null) { endpoint(revocation,insecureLoopback);builder.put("revocation_endpoint",revocation.toString())
    .put("revocation_endpoint_auth_methods_supported",array(List.of("none","client_secret_basic"))); }
  if(introspection!=null) { endpoint(introspection,insecureLoopback);builder.put("introspection_endpoint",introspection.toString())
    .put("introspection_endpoint_auth_methods_supported",array(List.of("client_secret_basic"))); }
  if(cimd) builder.put("client_id_metadata_document_supported",true);
  this.metadata=builder.build();
 }
 private static void endpoint(@NonNull URI value,boolean insecureLoopback) {
  requireNonNull(value);OAuthServerConfiguration.text(value.toString(),OAuthServerConfiguration.MAXIMUM_URI_LENGTH);
  boolean loopback="http".equalsIgnoreCase(value.getScheme()) && ("127.0.0.1".equals(value.getHost()) || "[::1]".equals(value.getHost()));
  if(value.isOpaque() || value.getHost()==null || value.getRawUserInfo()!=null || value.getRawFragment()!=null || value.getPort()>65535
    || !("https".equalsIgnoreCase(value.getScheme()) || (insecureLoopback && loopback))) throw OAuthStoreFormat.invalid();
 }
 private static @NonNull JsonArray array(@NonNull List<@NonNull String> values) {
  return JsonArray.fromElements(values.stream().map(JsonString::fromValue).toList());
 }
 @NonNull URI wellKnownUri() { return this.wellKnown; }
 @NonNull OAuthPublicMetadataResponse metadata(@NonNull String method,@NonNull Deadline deadline) {
  OAuthServerClientAdmission.remaining(deadline);
  OAuthPublicMetadataResponse response=OAuthPublicMetadataResponse.prepare(this.metadata,method,this.freshness,this.bodyCap,this.headerCap);
  OAuthServerClientAdmission.remaining(deadline);return response;
 }
 @NonNull OAuthPublicMetadataResponse jwks(@NonNull String method,@NonNull OAuthIssuerKeyLifecycle keys,@NonNull Deadline deadline) {
  OAuthServerClientAdmission.remaining(deadline);
  if(!method.equals("GET") && !method.equals("HEAD")) return OAuthPublicMetadataResponse.prepare(JsonObject.builder().build(),method,this.freshness,this.bodyCap,this.headerCap);
  OAuthIssuerKeySnapshot snapshot=keys.snapshot(deadline);
  OAuthPublicMetadataResponse response=OAuthPublicMetadataResponse.prepare(OAuthIssuerPublicKeys.jwks(snapshot.getVerificationKeys()),method,this.freshness,this.bodyCap,this.headerCap);
  OAuthServerClientAdmission.remaining(deadline);return response;
 }
 @Override public @NonNull String toString() { return "OAuthIssuerMetadata{<redacted>}"; }
}
