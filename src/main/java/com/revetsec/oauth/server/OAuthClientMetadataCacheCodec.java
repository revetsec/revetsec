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

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.EntropySource;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/** Optional cache provenance only; never an authorization-store or operation-current proof. */
final class OAuthClientMetadataCacheCodec {
 private static final @NonNull Set<@NonNull String> FIELDS = Set.of("schema", "namespace", "key", "version", "fetchedAt", "expiresAt", "body");
 private final @NonNull StateSealer sealer;
 private final @NonNull OAuthClientMetadataPolicy policy;
 private final @NonNull OAuthServerIngressLimits limits;
 private final boolean nativeLoopback, localhost;
 private final @NonNull String namespace;
 private final int sealedCap, plaintextCap;
 OAuthClientMetadataCacheCodec(@NonNull String issuer, @NonNull StateSealer sealer,
   @NonNull OAuthClientMetadataPolicy policy, @NonNull OAuthServerIngressLimits limits,
   boolean nativeLoopback, boolean localhost) {
  OAuthServerConfiguration.text(issuer, 2048); this.sealer = requireNonNull(sealer);
  this.policy = requireNonNull(policy); this.limits = requireNonNull(limits);
  this.nativeLoopback = nativeLoopback; this.localhost = localhost;
  if (!policy.getEnabled()) throw OAuthServerConfiguration.invalid();
  List<JsonValue> origins = policy.getAllowedOrigins().orElse(Set.of()).stream().map(java.net.URI::toString).sorted()
    .map(JsonString::fromValue).map(value -> (JsonValue)value).toList();
  this.namespace = OAuthAuthorizationRecord.digest(JsonObject.builder().put("schema", 1L).put("issuer", issuer)
    .put("originsRestricted", policy.getAllowedOrigins().isPresent()).put("origins", JsonArray.fromElements(origins))
    .put("documentBytes", policy.getMaximumDocumentBytes().longValue()).put("freshness", policy.getMaximumFreshness().toString())
    .put("clientIdLength", (long)limits.clientIdLength).put("redirects", (long)limits.redirects)
    .put("native", nativeLoopback).put("localhost", localhost).build().toJson());
  this.sealedCap = Math.min(16384, SealedStateAccess.get().getMaximumSealedLength(sealer));
  this.plaintextCap = this.sealedCap * 3 / 4 - 55;
 }
 @NonNull OAuthClientMetadataCacheKey key(@NonNull String clientId) {
  OAuthClientMetadataUri.clientId(clientId, this.policy, this.limits.clientIdLength);
  return OAuthClientMetadataCacheKey.fromStoredForm("revetsec:cimd-cache:1:" + this.namespace + ":" + OAuthAuthorizationRecord.digest(clientId));
 }
 @NonNull OAuthClientMetadataCacheEntry seal(@NonNull String clientId, byte @NonNull [] body,
   @NonNull Instant fetchedAt, @NonNull Instant expiresAt) {
  OAuthClientMetadataDocument.parse(clientId, body, this.policy, this.limits, this.nativeLoopback, this.localhost);
  times(fetchedAt, expiresAt, fetchedAt);
  OAuthClientMetadataCacheKey key = key(clientId);
  byte[] random = EntropySource.fromDefaults().nextBytes(32); String version;
  try { version = Base64Url.encode(random); } finally { Arrays.fill(random, (byte)0); }
  String plaintext = JsonObject.builder().put("schema", 1L).put("namespace", this.namespace)
    .put("key", key.getStorageKey()).put("version", version).put("fetchedAt", fetchedAt.toString())
    .put("expiresAt", expiresAt.getEpochSecond()).put("body", Base64Url.encode(body)).build().toJson();
  byte[] bytes = bounded(plaintext); Arrays.fill(bytes, (byte)0);
  String sealed = SealedStateAccess.get().seal(this.sealer, SealedStateType.AS_CLIENT_METADATA_CACHE,
    plaintext, context(key), expiresAt);
  OAuthStoreFormat.sealed(sealed, this.sealedCap);
  return OAuthClientMetadataCacheEntry.fromStoredForm(key, version, expiresAt, sealed);
 }
 @NonNull Optional<@NonNull Cached> open(@NonNull String clientId, @NonNull OAuthClientMetadataCacheEntry entry,
   @NonNull Instant now) {
  return decode(clientId, entry, now, false);
 }
 @NonNull Optional<@NonNull Instant> authenticatedFetchedAt(@NonNull String clientId, @NonNull OAuthClientMetadataCacheEntry entry) {
  return decode(clientId, entry, Instant.MIN, true).map(Cached::fetchedAt);
 }
 private @NonNull Optional<@NonNull Cached> decode(@NonNull String clientId, @NonNull OAuthClientMetadataCacheEntry entry,
   @NonNull Instant now, boolean historical) {
  requireNonNull(entry); requireNonNull(now); byte[] plaintext = null; byte[] body = null;
  try {
   OAuthClientMetadataCacheKey key = key(clientId);
   if (!key.equals(entry.getKey())) return Optional.empty();
   OAuthStoreFormat.sealed(entry.toSealedForm(), this.sealedCap);
   String text = SealedStateAccess.get().unseal(this.sealer, SealedStateType.AS_CLIENT_METADATA_CACHE,
     entry.toSealedForm(), context(key), Clock.fixed(now, ZoneOffset.UTC));
   plaintext = bounded(text);
   JsonValue value = JsonCodec.parse(plaintext, JsonLimits.protocolDocument(this.plaintextCap));
   if (!(value instanceof JsonObject json) || !json.getMembers().keySet().equals(FIELDS)
     || json.findLong("schema").orElse(-1L) != 1L || !this.namespace.equals(json.findString("namespace").orElse(""))
     || !key.getStorageKey().equals(json.findString("key").orElse(""))
     || !entry.getVersion().equals(json.findString("version").orElse(""))
     || entry.getExpiresAt().getEpochSecond() != json.findLong("expiresAt").orElse(Long.MIN_VALUE)) return Optional.empty();
   Instant fetched = Instant.parse(json.findString("fetchedAt").orElse(""));
   times(fetched, entry.getExpiresAt(), historical ? fetched : now);
   String encoded = json.findString("body").orElse("");
   if (encoded.length() > (this.policy.getMaximumDocumentBytes() + 2) / 3 * 4) return Optional.empty();
   body = Base64Url.decode(encoded);
   if (!Base64Url.encode(body).equals(encoded)) return Optional.empty();
   OAuthClientMetadataDocument document = OAuthClientMetadataDocument.parse(clientId, body, this.policy,
     this.limits, this.nativeLoopback, this.localhost);
   return Optional.of(new Cached(document, fetched, entry.getExpiresAt()));
  } catch (UnsealException | JsonParseException | EncodingException | IllegalArgumentException | java.time.DateTimeException | ArithmeticException | OAuthServerAdmissionFailure failure) {
   return Optional.empty();
  } finally { if (plaintext != null) Arrays.fill(plaintext, (byte)0); if (body != null) Arrays.fill(body, (byte)0); }
 }
 private void times(@NonNull Instant fetched, @NonNull Instant expiry, @NonNull Instant now) {
  if (fetched.isAfter(now) || expiry.getNano() != 0 || !now.isBefore(expiry) || !fetched.isBefore(expiry)
    || expiry.isAfter(fetched.plus(this.policy.getMaximumFreshness()))) throw OAuthStoreFormat.invalid();
 }
 private byte @NonNull [] bounded(@NonNull String text) {
  if (text.length() > this.plaintextCap) throw OAuthStoreFormat.invalid();
  try {
   byte[] bytes = StrictUtf8.encode(text);
   if (bytes.length <= this.plaintextCap) return bytes;
   Arrays.fill(bytes, (byte)0); throw OAuthStoreFormat.invalid();
  } catch (EncodingException failure) { throw OAuthStoreFormat.invalid(); }
 }
 private static @NonNull String context(@NonNull OAuthClientMetadataCacheKey key) { return "revetsec/as-client-metadata-cache/v1:" + key.getStorageKey(); }
 static final class Cached {
  private final @NonNull OAuthClientMetadataDocument document;
  private final @NonNull Instant fetchedAt, expiresAt;
  private Cached(@NonNull OAuthClientMetadataDocument document, @NonNull Instant fetchedAt, @NonNull Instant expiresAt) {
   this.document = document; this.fetchedAt = fetchedAt; this.expiresAt = expiresAt;
  }
  @NonNull OAuthClientMetadataDocument document() { return this.document; }
  @NonNull Instant fetchedAt() { return this.fetchedAt; }
  @NonNull Instant expiresAt() { return this.expiresAt; }
  @Override public @NonNull String toString() { return "CachedClientMetadata{metadata=redacted}"; }
 }
}
