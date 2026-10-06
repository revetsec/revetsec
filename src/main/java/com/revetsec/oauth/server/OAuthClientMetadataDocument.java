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
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import static java.util.Objects.requireNonNull;
import static com.revetsec.oauth.server.OAuthServerAdmissionFailure.Reason.INVALID_CLIENT;

/** Bounded pure untrusted document admission, not a fetched-current or authorized-client proof. */
final class OAuthClientMetadataDocument {
 private static final @NonNull Set<@NonNull String> SECRET_MEMBERS = Set.of(
  "client_secret", "client_secret_expires_at", "d", "p", "q", "dp", "dq", "qi", "oth", "k");
 private final @NonNull String clientId, clientName, fingerprint;
 private final @NonNull List<@NonNull URI> redirectUris;
 private final boolean nativeApplication, refreshTokenPermitted;
 private OAuthClientMetadataDocument(@NonNull String clientId, @NonNull String name,
   @NonNull List<@NonNull URI> redirects, boolean nativeApplication, boolean refresh) {
  this.clientId = clientId; this.clientName = name; this.redirectUris = List.copyOf(redirects);
  this.nativeApplication = nativeApplication; this.refreshTokenPermitted = refresh;
  // Canonical structured facts, never delimiter concatenation or display text.
  List<JsonValue> values = redirects.stream().map(URI::toString).sorted().map(JsonString::fromValue)
   .map(value -> (JsonValue) value).toList();
  this.fingerprint = OAuthAuthorizationRecord.digest(JsonObject.builder().put("client_id", clientId)
   .put("auth", "none").put("native", nativeApplication).put("refresh", refresh)
   .put("redirects", JsonArray.fromElements(values)).build().toJson());
 }
 static @NonNull OAuthClientMetadataDocument parse(@NonNull String clientId, byte @NonNull [] body,
   @NonNull OAuthClientMetadataPolicy policy, @NonNull OAuthServerIngressLimits limits,
   boolean allowNativeLoopback, boolean allowLocalhost) {
  requireNonNull(body); requireNonNull(policy); requireNonNull(limits);
  try {
   OAuthClientMetadataUri.clientId(clientId, policy, limits.clientIdLength);
   JsonValue value = JsonCodec.parse(body, JsonLimits.protocolDocument(policy.getMaximumDocumentBytes()));
   if (!(value instanceof JsonObject json)) throw invalid();
   secrets(value);
   if (!clientId.equals(string(json, "client_id", null)) || !"none".equals(string(json, "token_endpoint_auth_method", null))) throw invalid();
   String name = OAuthServerConfiguration.text(string(json, "client_name", null), OAuthServerConfiguration.MAXIMUM_TEXT_LENGTH);
   String application = string(json, "application_type", "web");
   if (!application.equals("web") && !application.equals("native")) throw invalid();
   boolean nativeApplication = application.equals("native");
   List<String> grants = strings(json, "grant_types", List.of("authorization_code"));
   if (!grants.contains("authorization_code") || grants.stream().anyMatch(g -> !g.equals("authorization_code") && !g.equals("refresh_token"))) throw invalid();
   if (!strings(json, "response_types", List.of("code")).equals(List.of("code"))) throw invalid();
   List<String> spellings = strings(json, "redirect_uris", null);
   if (spellings.isEmpty() || spellings.size() > limits.redirects) throw invalid();
   List<URI> redirects = new ArrayList<>();
   for (String spelling : spellings) {
    URI redirect = URI.create(spelling); String host = redirect.getHost();
    if ("http".equalsIgnoreCase(redirect.getScheme())) {
     boolean ip = "127.0.0.1".equals(host) || "[::1]".equals(host);
     if (ip ? !nativeApplication || !allowNativeLoopback : !"localhost".equals(host) || !allowLocalhost) throw invalid();
    }
    redirects.add(redirect);
   }
   redirects = OAuthServerConfiguration.redirects(redirects);
   // Known optional fields have exact types, but confer no scopes, key or software identity authority.
   for (String field : List.of("client_uri", "logo_uri", "policy_uri", "tos_uri", "jwks_uri")) {
    if (json.getMembers().containsKey(field)) OAuthServerConfiguration.resource(string(json, field, null));
   }
   if (json.getMembers().containsKey("contacts")) for (String contact : strings(json, "contacts", null)) OAuthServerConfiguration.text(contact, 4096);
   if (json.getMembers().containsKey("scope")) {
    String scope = string(json, "scope", null);
    if (!scope.isEmpty()) for (String token : scope.split(" ", -1)) OAuthServerConfiguration.scope(token);
   }
   if (json.getMembers().containsKey("software_id")) OAuthServerConfiguration.text(string(json, "software_id", null), 4096);
   if (json.getMembers().containsKey("software_version")) OAuthServerConfiguration.text(string(json, "software_version", null), 4096);
   // No unverified software statement or signing-algorithm declaration is treated as authentication.
   if (json.getMembers().containsKey("software_statement")) OAuthServerConfiguration.text(string(json, "software_statement", null), 4096);
   if (json.getMembers().containsKey("token_endpoint_auth_signing_alg")) throw invalid();
   if (json.getMembers().containsKey("jwks")) publicKeys(json.getMembers().get("jwks"));
   return new OAuthClientMetadataDocument(clientId, name, redirects, nativeApplication, grants.contains("refresh_token"));
  } catch (JsonParseException | IllegalArgumentException failure) { throw invalid(); }
 }
 private static void secrets(@NonNull JsonValue value) {
  if (value instanceof JsonObject json) {
   for (var entry : json.getMembers().entrySet()) {
    if (SECRET_MEMBERS.contains(entry.getKey())) throw invalid();
    if (entry.getKey().equals("kty") && entry.getValue() instanceof JsonString text && text.getValue().equals("oct")) throw invalid();
    secrets(entry.getValue());
   }
  } else if (value instanceof JsonArray array) for (JsonValue item : array.getElements()) secrets(item);
 }
 private static void publicKeys(@Nullable JsonValue value) {
  if (!(value instanceof JsonObject object) || !(object.getMembers().get("keys") instanceof JsonArray keys)) throw invalid();
  for (JsonValue item : keys.getElements()) {
   if (!(item instanceof JsonObject key)) throw invalid();
   String type = string(key, "kty", null);
   if (type.equals("RSA")) { string(key, "n", null); string(key, "e", null); }
   else if (type.equals("EC")) { string(key, "crv", null); string(key, "x", null); string(key, "y", null); }
   else if (type.equals("OKP")) { string(key, "crv", null); string(key, "x", null); }
   else throw invalid();
  }
 }
 private static @NonNull String string(@NonNull JsonObject json, @NonNull String name, @Nullable String fallback) {
  JsonValue value = json.getMembers().get(name);
  if (value == null && fallback != null) return fallback;
  if (!(value instanceof JsonString text)) throw invalid();
  return text.getValue();
 }
 private static @NonNull List<@NonNull String> strings(@NonNull JsonObject json, @NonNull String name,
   @Nullable List<@NonNull String> fallback) {
  JsonValue value = json.getMembers().get(name);
  if (value == null && fallback != null) return fallback;
  if (!(value instanceof JsonArray array)) throw invalid();
  List<String> result = new ArrayList<>();
  for (JsonValue item : array.getElements()) {
   if (!(item instanceof JsonString text) || result.contains(text.getValue())) throw invalid();
   result.add(text.getValue());
  }
  return List.copyOf(result);
 }
 @NonNull String clientId() { return this.clientId; }
 @NonNull String clientName() { return this.clientName; }
 @NonNull List<@NonNull URI> redirectUris() { return this.redirectUris; }
 @NonNull String fingerprint() { return this.fingerprint; }
 boolean nativeApplication() { return this.nativeApplication; }
 boolean refreshTokenPermitted() { return this.refreshTokenPermitted; }
 @Override public @NonNull String toString() { return "OAuthClientMetadataDocument{metadata=redacted}"; }
 private static @NonNull OAuthServerAdmissionFailure invalid() { return OAuthServerClientAdmission.failure(INVALID_CLIENT); }
}
