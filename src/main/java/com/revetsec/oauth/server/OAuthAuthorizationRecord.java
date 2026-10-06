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

import com.revetsec.internal.crypto.ConstantTime;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** Exact bounded consent and issuance schemas; authentication alone does not prove protocol authority. */
final class OAuthAuthorizationRecord {
 private static final @NonNull Set<@NonNull String> INTERACTION = Set.of("schema", "id", "status", "expires",
   "issuerIncarnation", "issuerEpoch", "browserHash", "clientHash", "clientId", "redirect", "resource", "scopes", "challenge", "state");
 private static final @NonNull Set<@NonNull String> CODE = Set.of("schema", "id", "status", "expires",
   "issuerIncarnation", "issuerEpoch", "subjectIncarnation", "subjectEpoch", "grantId", "challenge", "redirect");
 private static final @NonNull Set<@NonNull String> GRANT = Set.of("schema", "id", "status", "expires",
   "issuerIncarnation", "issuerEpoch", "subjectIncarnation", "subjectEpoch", "codeId", "subject", "clientId", "clientHash", "resource", "scopes", "refresh");
 private static final @NonNull Set<@NonNull String> USED_CODE = Set.copyOf(fields(CODE, "horizon"));
 private static final @NonNull Set<@NonNull String> ISSUED_GRANT = Set.copyOf(fields(GRANT,
   "horizon", "maximumAccessSeconds", "maximumAccessNanos", "refreshId"));
 private static final @NonNull Set<@NonNull String> ACCESS = Set.of("schema", "id", "status", "expires",
   "issuerIncarnation", "issuerEpoch", "subjectIncarnation", "subjectEpoch", "grantId", "subject", "clientId",
   "resource", "scopes", "issued", "retain");
 private static final @NonNull Set<@NonNull String> REFRESH = Set.of("schema", "id", "status", "expires",
   "issuerIncarnation", "issuerEpoch", "subjectIncarnation", "subjectEpoch", "grantId", "horizon");
 private static void whole(@NonNull Instant value) { OAuthStoreFormat.retention(OAuthStoreKey.Kind.CODE, value); }
 private static @NonNull Set<@NonNull String> fields(@NonNull Set<@NonNull String> original, @NonNull String @NonNull ... extra) {
  Set<String> result = new LinkedHashSet<>(original); result.addAll(List.of(extra)); return Set.copyOf(result);
 }
 private final OAuthStoreKey.@NonNull Kind kind;
 private final @NonNull JsonObject payload;
 private OAuthAuthorizationRecord(OAuthStoreKey.@NonNull Kind kind, @NonNull JsonObject payload) {
  this.kind = kind; this.payload = payload;
 }
 static @NonNull OAuthAuthorizationRecord interaction(@NonNull String id, @NonNull String browserHash,
   @NonNull String clientHash, @NonNull OAuthServerAuthorizationAdmission admission,
   @NonNull OAuthStoreFence issuer, @NonNull Instant expires, @NonNull OAuthServerIngressLimits limits) {
  JsonObject.Builder b = base(id, "PENDING", expires, issuer).put("browserHash", browserHash).put("clientHash", clientHash)
   .put("clientId", admission.client().getClientId()).put("redirect", admission.redirect()).put("resource", admission.resource())
   .put("scopes", array(admission.scopes())).put("challenge", admission.challenge());
  String state = admission.state(); b.put("state", state == null ? JsonNull.defaultInstance() : JsonString.fromValue(state));
  return decode(OAuthStoreKey.Kind.INTERACTION, id, b.build(), limits, 1024);
 }
 static @NonNull OAuthAuthorizationRecord code(@NonNull String id, @NonNull String grantId,
   @NonNull OAuthAuthorizationRecord interaction, @NonNull OAuthStoreFence issuer, @NonNull OAuthStoreFence subject,
   @NonNull Instant expires, @NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  JsonObject p = subject(base(id, "UNUSED", expires, issuer), subject).put("grantId", grantId)
   .put("challenge", interaction.text("challenge")).put("redirect", interaction.text("redirect")).build();
  return decode(OAuthStoreKey.Kind.CODE, id, p, limits, subjectLimit);
 }
 static @NonNull OAuthAuthorizationRecord grant(@NonNull String id, @NonNull String codeId,
   @NonNull OAuthAuthorizationRecord interaction, @NonNull String subjectValue, @NonNull Set<@NonNull String> scopes,
   boolean refresh, @NonNull OAuthStoreFence issuer, @NonNull OAuthStoreFence subject,
   @NonNull Instant expires, @NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  JsonObject p = subject(base(id, "PENDING", expires, issuer), subject).put("codeId", codeId).put("subject", subjectValue)
   .put("clientId", interaction.text("clientId")).put("clientHash", interaction.text("clientHash"))
   .put("resource", interaction.text("resource")).put("scopes", array(scopes)).put("refresh", refresh).build();
  return decode(OAuthStoreKey.Kind.GRANT, id, p, limits, subjectLimit);
 }
 static @NonNull OAuthAuthorizationRecord decode(OAuthStoreKey.@NonNull Kind kind, @NonNull String identifier,
   @NonNull JsonObject payload, @NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  String status = payload.findString("status").orElseThrow(OAuthStoreFormat::invalid);
  Set<String> fields = switch (kind) {
   case INTERACTION -> INTERACTION;
   case CODE -> status.equals("USED") ? USED_CODE : CODE;
   case GRANT -> status.equals("ACTIVE") || status.equals("REVOKED") ? ISSUED_GRANT : GRANT;
   case ACCESS_TOKEN -> ACCESS; case REFRESH_TOKEN -> REFRESH;
   default -> throw OAuthStoreFormat.invalid(); };
  if (!payload.getMembers().keySet().equals(fields) || payload.findLong("schema").orElse(-1L) != 1L)
   throw OAuthStoreFormat.invalid();
  OAuthAuthorizationRecord r = new OAuthAuthorizationRecord(kind, payload);
  OAuthStoreFormat.nonce(identifier); nonce(r.text("id"));
  if (!identifier.equals(r.text("id"))) throw OAuthStoreFormat.invalid();
  nonce(r.text("issuerIncarnation")); nonnegative(r.number("issuerEpoch"));
  Instant expires = r.expires(); OAuthStoreFormat.retention(kind, expires);
  if (kind == OAuthStoreKey.Kind.INTERACTION) {
   if (!status.equals("PENDING") && !status.equals("COMPLETED")) throw OAuthStoreFormat.invalid();
   nonce(r.text("browserHash")); nonce(r.text("clientHash"));
   OAuthServerConfiguration.text(r.text("clientId"), limits.clientIdLength);
   OAuthServerConfiguration.redirects(List.of(URI.create(r.text("redirect"))));
   resource(r.text("resource")); r.scopes(limits);
   if (!OAuthServerAuthorizationAdmission.challenge(r.text("challenge"))) throw OAuthStoreFormat.invalid();
   r.state(limits.stateLength);
  } else {
   nonce(r.text("subjectIncarnation")); nonnegative(r.number("subjectEpoch"));
   if (kind == OAuthStoreKey.Kind.CODE) {
    if (!status.equals("UNUSED") && !status.equals("USED") && !status.equals("CANCELLED")) throw OAuthStoreFormat.invalid();
    if (status.equals("USED")) r.horizon();
    nonce(r.text("grantId"));
    if (!OAuthServerAuthorizationAdmission.challenge(r.text("challenge"))) throw OAuthStoreFormat.invalid();
    OAuthServerConfiguration.redirects(List.of(URI.create(r.text("redirect"))));
   } else if (kind == OAuthStoreKey.Kind.GRANT) {
    if (!status.equals("PENDING") && !status.equals("DENIED") && !status.equals("ACTIVE") && !status.equals("REVOKED")) throw OAuthStoreFormat.invalid();
    nonce(r.text("codeId")); nonce(r.text("clientHash"));
    OAuthServerConfiguration.text(r.text("subject"), subjectLimit);
    OAuthServerConfiguration.text(r.text("clientId"), limits.clientIdLength);
    resource(r.text("resource")); r.scopes(limits); r.refresh();
    if (status.equals("ACTIVE") || status.equals("REVOKED")) {
     Instant h = r.horizon(); Duration pin = r.maximumAccessLifetime();
     try { if (h.isBefore(OAuthGrantRetention.retain(expires.plus(pin)))) throw OAuthStoreFormat.invalid(); }
     catch (DateTimeException | ArithmeticException failure) { throw OAuthStoreFormat.invalid(); }
     JsonValue refreshId = payload.find("refreshId").orElseThrow(OAuthStoreFormat::invalid);
     if (r.refresh()) { if (!(refreshId instanceof JsonString s)) throw OAuthStoreFormat.invalid(); nonce(s.getValue()); }
     else if (!(refreshId instanceof JsonNull)) throw OAuthStoreFormat.invalid();
    }
   } else if (kind == OAuthStoreKey.Kind.ACCESS_TOKEN) {
    if (!status.equals("ISSUED")) throw OAuthStoreFormat.invalid(); nonce(r.text("grantId"));
    OAuthServerConfiguration.text(r.text("subject"), subjectLimit);
    OAuthServerConfiguration.text(r.text("clientId"), limits.clientIdLength);
    resource(r.text("resource")); r.scopes(limits);
    Instant issued = r.instant("issued"), retain = r.instant("retain");
    if (!issued.isBefore(expires) || retain.isBefore(expires)) throw OAuthStoreFormat.invalid();
   } else {
    if (!status.equals("ACTIVE") && !status.equals("USED")) throw OAuthStoreFormat.invalid(); nonce(r.text("grantId")); r.horizon();
   }
  }
  return r;
 }
 @NonNull OAuthAuthorizationRecord consumed(@NonNull Instant horizon, @NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  if (this.kind != OAuthStoreKey.Kind.CODE || !text("status").equals("UNUSED")) throw OAuthStoreFormat.invalid();
  whole(horizon);
  return updated(Map.of("status", JsonString.fromValue("USED"), "horizon", com.revetsec.json.JsonNumber.fromValue(horizon.getEpochSecond())), limits, subjectLimit);
 }
 @NonNull OAuthAuthorizationRecord activated(@NonNull Instant expiry, @NonNull Instant horizon, @NonNull Duration pin,
   @NonNull Set<@NonNull String> scopes, @Nullable String refreshId, @NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  if (this.kind != OAuthStoreKey.Kind.GRANT || !text("status").equals("PENDING")) throw OAuthStoreFormat.invalid();
  whole(expiry); whole(horizon);
  return updated(Map.of("status", JsonString.fromValue("ACTIVE"), "expires", com.revetsec.json.JsonNumber.fromValue(expiry.getEpochSecond()),
   "horizon", com.revetsec.json.JsonNumber.fromValue(horizon.getEpochSecond()), "maximumAccessSeconds", com.revetsec.json.JsonNumber.fromValue(pin.getSeconds()),
   "maximumAccessNanos", com.revetsec.json.JsonNumber.fromValue((long) pin.getNano()), "scopes", array(scopes),
   "refresh", com.revetsec.json.JsonBoolean.fromValue(refreshId != null),
   "refreshId", refreshId == null ? JsonNull.defaultInstance() : JsonString.fromValue(refreshId)), limits, subjectLimit);
 }
 @NonNull OAuthAuthorizationRecord terminated(@NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  String status = text("status"); String next;
  if (this.kind == OAuthStoreKey.Kind.GRANT && status.equals("PENDING")) next = "DENIED";
  else if (this.kind == OAuthStoreKey.Kind.GRANT && (status.equals("ACTIVE") || status.equals("REVOKED"))) next = "REVOKED";
  else if (this.kind == OAuthStoreKey.Kind.CODE && status.equals("UNUSED")) next = "CANCELLED";
  else throw OAuthStoreFormat.invalid();
  return updated(Map.of("status", JsonString.fromValue(next)), limits, subjectLimit);
 }
 /** Rotate only the head; original scopes, absolute expiry, lifetime pin and H remain immutable. */
 @NonNull OAuthAuthorizationRecord rotated(@NonNull String refreshId, @NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  if (this.kind != OAuthStoreKey.Kind.GRANT || !text("status").equals("ACTIVE") || !refresh()) throw OAuthStoreFormat.invalid();
  nonce(refreshId);
  if (text("refreshId").equals(refreshId)) throw OAuthStoreFormat.invalid();
  return updated(Map.of("refreshId", JsonString.fromValue(refreshId)), limits, subjectLimit);
 }
 @NonNull OAuthAuthorizationRecord refreshUsed(@NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  if (this.kind != OAuthStoreKey.Kind.REFRESH_TOKEN || !text("status").equals("ACTIVE")) throw OAuthStoreFormat.invalid();
  return updated(Map.of("status", JsonString.fromValue("USED")), limits, subjectLimit);
 }
 private @NonNull OAuthAuthorizationRecord updated(@NonNull Map<@NonNull String, @NonNull JsonValue> changes,
   @NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  Map<String, JsonValue> values = new java.util.LinkedHashMap<>(this.payload.getMembers()); values.putAll(changes);
  return decode(this.kind, text("id"), JsonObject.fromMembers(values), limits, subjectLimit);
 }
 static @NonNull OAuthAuthorizationRecord access(@NonNull String jti, @NonNull OAuthAuthorizationRecord grant,
   @NonNull Instant issued, @NonNull Instant expiry, @NonNull Instant retain, @NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  return access(jti, grant, issued, expiry, retain, grant.scopes(limits), limits, subjectLimit);
 }
 static @NonNull OAuthAuthorizationRecord access(@NonNull String jti, @NonNull OAuthAuthorizationRecord grant,
   @NonNull Instant issued, @NonNull Instant expiry, @NonNull Instant retain, @NonNull Set<@NonNull String> scopes,
   @NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  whole(expiry); whole(retain);
  if (scopes.isEmpty() || !grant.scopes(limits).containsAll(scopes)) throw OAuthStoreFormat.invalid();
  JsonObject p = issuance(grant, jti, "ISSUED", expiry).put("subject", grant.text("subject")).put("clientId", grant.text("clientId"))
   .put("resource", grant.text("resource")).put("scopes", array(scopes))
   .put("issued", issued.getEpochSecond()).put("retain", retain.getEpochSecond()).build();
  return decode(OAuthStoreKey.Kind.ACCESS_TOKEN, jti, p, limits, subjectLimit);
 }
 static @NonNull OAuthAuthorizationRecord refresh(@NonNull String id, @NonNull OAuthAuthorizationRecord grant,
   @NonNull Instant expiry, @NonNull OAuthServerIngressLimits limits, int subjectLimit) {
  whole(expiry);
  JsonObject p = issuance(grant, id, "ACTIVE", expiry).put("horizon", grant.horizon().getEpochSecond()).build();
  if (!grant.refresh() || !grant.text("refreshId").equals(id) || expiry.isAfter(grant.expires())) throw OAuthStoreFormat.invalid();
  return decode(OAuthStoreKey.Kind.REFRESH_TOKEN, id, p, limits, subjectLimit);
 }
 private static JsonObject.@NonNull Builder issuance(@NonNull OAuthAuthorizationRecord grant, @NonNull String id,
   @NonNull String status, @NonNull Instant expiry) {
  if (grant.kind != OAuthStoreKey.Kind.GRANT || !grant.text("status").equals("ACTIVE")) throw OAuthStoreFormat.invalid();
  return JsonObject.builder().put("schema", 1L).put("id", id).put("status", status).put("expires", expiry.getEpochSecond())
   .put("issuerIncarnation", grant.text("issuerIncarnation")).put("issuerEpoch", grant.number("issuerEpoch"))
   .put("subjectIncarnation", grant.text("subjectIncarnation")).put("subjectEpoch", grant.number("subjectEpoch")).put("grantId", grant.text("id"));
 }
 @NonNull Instant retention() {
  if (this.kind == OAuthStoreKey.Kind.ACCESS_TOKEN) return instant("retain");
  String status = text("status");
  return status.equals("USED") || status.equals("ACTIVE") || status.equals("REVOKED") ? horizon() : expires();
 }
 @NonNull Instant horizon() {
  Instant value = instant("horizon"); if (value.isBefore(expires())) throw OAuthStoreFormat.invalid(); return value;
 }
 @NonNull Duration maximumAccessLifetime() {
  long seconds = number("maximumAccessSeconds"), nanos = number("maximumAccessNanos");
  if (nanos < 0 || nanos > 999999999) throw OAuthStoreFormat.invalid();
  return OAuthGrantRetention.duration(Duration.ofSeconds(seconds, nanos), Duration.ofSeconds(30), Duration.ofMinutes(15));
 }
 private @NonNull Instant instant(@NonNull String name) {
  try { Instant value = Instant.ofEpochSecond(number(name)); OAuthStoreFormat.retention(this.kind, value); return value; }
  catch (DateTimeException failure) { throw OAuthStoreFormat.invalid(); }
 }
 boolean sameLineage(@NonNull OAuthAuthorizationRecord other) {
  return text("issuerIncarnation").equals(other.text("issuerIncarnation")) && number("issuerEpoch") == other.number("issuerEpoch")
   && text("subjectIncarnation").equals(other.text("subjectIncarnation")) && number("subjectEpoch") == other.number("subjectEpoch");
 }
 private static JsonObject.@NonNull Builder base(@NonNull String id, @NonNull String status,
   @NonNull Instant expires, @NonNull OAuthStoreFence issuer) {
  if (!expires.equals(expires.truncatedTo(java.time.temporal.ChronoUnit.SECONDS))) throw OAuthStoreFormat.invalid();
  return JsonObject.builder().put("schema", 1L).put("id", id).put("status", status).put("expires", expires.getEpochSecond())
   .put("issuerIncarnation", issuer.incarnation()).put("issuerEpoch", issuer.epoch());
 }
 private static JsonObject.@NonNull Builder subject(JsonObject.@NonNull Builder b, @NonNull OAuthStoreFence subject) {
  return b.put("subjectIncarnation", subject.incarnation()).put("subjectEpoch", subject.epoch());
 }
 @NonNull OAuthAuthorizationRecord completed() {
  if (this.kind != OAuthStoreKey.Kind.INTERACTION || !text("status").equals("PENDING")) throw OAuthStoreFormat.invalid();
  Map<String, JsonValue> changed = new java.util.LinkedHashMap<>(this.payload.getMembers());
  changed.put("status", JsonString.fromValue("COMPLETED"));
  return new OAuthAuthorizationRecord(this.kind, JsonObject.fromMembers(changed));
 }
 @NonNull String text(@NonNull String name) { return this.payload.findString(name).orElseThrow(OAuthStoreFormat::invalid); }
 long number(@NonNull String name) { return this.payload.findLong(name).orElseThrow(OAuthStoreFormat::invalid); }
 @NonNull Instant expires() {
  try { return Instant.ofEpochSecond(number("expires")); }
  catch (DateTimeException failure) { throw OAuthStoreFormat.invalid(); }
 }
 @NonNull Set<@NonNull String> scopes(@NonNull OAuthServerIngressLimits limits) {
  JsonValue value = this.payload.find("scopes").orElseThrow(OAuthStoreFormat::invalid);
  if (!(value instanceof JsonArray a) || a.getElements().isEmpty() || a.getElements().size() > limits.scopes)
   throw OAuthStoreFormat.invalid();
  Set<String> result = new LinkedHashSet<>();
  for (JsonValue item : a.getElements()) {
   if (!(item instanceof JsonString string)) throw OAuthStoreFormat.invalid();
   String scope = string.getValue(); OAuthServerConfiguration.scope(scope);
   if (scope.length() > limits.scopeLength || !result.add(scope)) throw OAuthStoreFormat.invalid();
  }
  return Set.copyOf(result);
 }
 @Nullable String state(int maximum) {
  JsonValue value = this.payload.find("state").orElseThrow(OAuthStoreFormat::invalid);
  if (value instanceof JsonNull) return null;
  if (!(value instanceof JsonString string) || string.getValue().length() > maximum) throw OAuthStoreFormat.invalid();
  String state = string.getValue(); if (!state.isEmpty()) OAuthServerConfiguration.text(state, maximum); return state;
 }
 boolean refresh() { return this.payload.findBoolean("refresh").orElseThrow(OAuthStoreFormat::invalid); }
 boolean matchesIssuer(@NonNull OAuthStoreFence fence) { return matches("issuer", fence); }
 boolean matchesSubject(@NonNull OAuthStoreFence fence) { return matches("subject", fence); }
 private boolean matches(@NonNull String prefix, @NonNull OAuthStoreFence fence) {
  return text(prefix + "Incarnation").equals(fence.incarnation()) && number(prefix + "Epoch") == fence.epoch();
 }
 @NonNull String toPayload() { return this.payload.toJson(); }
 private static void nonce(@NonNull String value) { OAuthStoreFormat.nonce(value); }
 private static void nonnegative(long value) { if (value < 0) throw OAuthStoreFormat.invalid(); }
 private static void resource(@NonNull String value) { OAuthServerConfiguration.resources(Map.of(value, Set.of()), 1); }
 private static @NonNull JsonArray array(@NonNull Set<@NonNull String> scopes) {
  return JsonArray.fromElements(scopes.stream().sorted().map(JsonString::fromValue).toList());
 }
 /** Canonical credential/browser bindings are independent random 32-byte values, not passwords or state. */
 static @NonNull String credentialDigest(@NonNull String credential) { nonce(credential); return digest(credential); }
 static @NonNull String verifierDigest(@NonNull String verifier) {
  if (verifier.length() < 43 || verifier.length() > 128) throw OAuthStoreFormat.invalid();
  for (int n = 0; n < verifier.length(); n++) {
   char c = verifier.charAt(n);
   if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || "-._~".indexOf(c) >= 0)) throw OAuthStoreFormat.invalid();
  }
  return digest(verifier);
 }
 static boolean equalDigest(@NonNull String expected, @NonNull String supplied) {
  nonce(expected); nonce(supplied);
  byte[] left = expected.getBytes(java.nio.charset.StandardCharsets.US_ASCII), right = supplied.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
  try { return ConstantTime.isEqual(left, right); } finally { Arrays.fill(left, (byte) 0); Arrays.fill(right, (byte) 0); }
 }
 /** App configurationVersion must change when verifier/key semantics change; callbacks are never serialized/invoked. */
 static @NonNull String clientFingerprint(@NonNull OAuthServerClientRegistration client) {
  JsonObject.Builder resources = JsonObject.builder();
  for (String resource : client.getAllowedScopesByResource().keySet().stream().sorted().toList())
   resources.put(resource, array(requireNonNull(client.getAllowedScopesByResource().get(resource))));
  return digest(JsonObject.builder().put("version", client.getConfigurationVersion()).put("clientId", client.getClientId())
   .put("auth", client.getAuthentication().isConfidential() ? "client_secret_basic" : "none")
   .put("code", client.isAuthorizationCodePermitted()).put("refresh", client.isRefreshTokenPermitted())
   .put("redirects", JsonArray.fromElements(client.getRedirectUris().stream().map(URI::toString).sorted().map(JsonString::fromValue).toList()))
   .put("resources", resources.build()).build().toJson());
 }
 static @NonNull String digest(@NonNull String value) {
  byte[] bytes;
  try { bytes = StrictUtf8.encode(value); } catch (EncodingException failure) { throw OAuthStoreFormat.invalid(); }
  byte[] digest = null;
  try { digest = MessageDigest.getInstance("SHA-256").digest(bytes); return Base64Url.encode(digest); }
  catch (NoSuchAlgorithmException failure) { throw new IllegalStateException("SHA-256 is unavailable."); }
  finally { Arrays.fill(bytes, (byte) 0); if (digest != null) Arrays.fill(digest, (byte) 0); }
 }
 @Override public @NonNull String toString() { return "OAuthAuthorizationRecord{<redacted>}"; }
}
