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
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Set;
import static java.util.Objects.requireNonNull;

/**
 * Bounded issuer envelope codec. Authenticates only common storage bindings; kind-specific credential
 * validity, epochs, replay and transition checks remain the consuming engine's responsibility.
 * Format generation is fixed at one; the durable issuer epoch is distinct and lives in the payload.
 */
final class OAuthStoreRecordCodec {
 private static final @NonNull Set<@NonNull String> FIELDS =
   Set.of("schema", "issuer", "key", "version", "retainUntil", "payload");
 private final @NonNull String issuer;
 private final @NonNull String namespace;
 private final @NonNull StateSealer sealer;
 private final int maximumRecordBytes;
 private final int maximumPlaintextBytes;
 
 OAuthStoreRecordCodec(@NonNull String issuer, @NonNull StateSealer sealer, int maximumRecordBytes) {
  requireNonNull(issuer); this.sealer = requireNonNull(sealer);
  if (issuer.isEmpty() || issuer.length() > 2048 || maximumRecordBytes < 1024
    || maximumRecordBytes > SealedStateAccess.get().getMaximumSealedLength(sealer)) throw OAuthStoreFormat.invalid();
  this.issuer = issuer; this.namespace = digest(issuer); this.maximumRecordBytes = maximumRecordBytes;
  // Base64 expands the fixed envelope and at least one key-ID byte. This is an upper allocation bound;
  // the sealer checks its actual key ID/UTF-8 size and we check the final configured record cap too.
  this.maximumPlaintextBytes = maximumRecordBytes * 3 / 4 - 55;

 }
 @NonNull OAuthStoreKey key(OAuthStoreKey.@NonNull Kind kind, @NonNull String identifier) {
  return OAuthStoreFormat.key(this.namespace, kind, identifier);
 }
 @NonNull OAuthStoreKey issuerKey() { return key(OAuthStoreKey.Kind.ISSUER_STATE, this.namespace); }
 @NonNull OAuthStoreKey subjectKey(@NonNull String subject) {
  requireNonNull(subject);
  if (subject.isEmpty() || subject.length() > 2048) throw OAuthStoreFormat.invalid();
  return key(OAuthStoreKey.Kind.SUBJECT_STATE, digest(subject));
 }
 @NonNull String freshVersion() {
  byte[] bytes = EntropySource.fromDefaults().nextBytes(32);
  try { return Base64Url.encode(bytes); } finally { Arrays.fill(bytes, (byte) 0); }
 }
 @NonNull OAuthStoreEntry seal(@NonNull OAuthStoreKey key, @NonNull Instant retainUntil,
   @NonNull String payloadJson) {
  namespace(key); OAuthStoreFormat.retention(key.getKind(), retainUntil);
  byte[] payload = boundedUtf8(payloadJson);
  try {
   if (!(JsonCodec.parse(payload, JsonLimits.protocolDocument(this.maximumPlaintextBytes)) instanceof JsonObject))
    throw OAuthStoreFormat.invalid();
  } catch (JsonParseException failure) { throw OAuthStoreFormat.invalid(); }
  finally { Arrays.fill(payload, (byte) 0); }
  String version = freshVersion();
  StringBuilder text = new StringBuilder(Math.min(this.maximumPlaintextBytes, 1024));
  append(text, "{\"schema\":1,\"issuer\":"); append(text, JsonString.fromValue(this.issuer).toJson());
  append(text, ",\"key\":"); append(text, JsonString.fromValue(key.getStorageKey()).toJson());
  append(text, ",\"version\":"); append(text, JsonString.fromValue(version).toJson());
  append(text, ",\"retainUntil\":"); append(text, Long.toString(retainUntil.getEpochSecond()));
  append(text, ",\"payload\":"); append(text, payloadJson); append(text, "}");
  String plaintext = text.toString(); byte[] bytes = boundedUtf8(plaintext);
  Arrays.fill(bytes, (byte) 0);
  String sealed = SealedStateAccess.get().seal(this.sealer, SealedStateType.AS_RECORD,
    plaintext, context(key), retainUntil);
  OAuthStoreFormat.sealed(sealed, this.maximumRecordBytes);
  return OAuthStoreEntry.fromStoredForm(key, version, retainUntil, sealed);
 }
 @NonNull JsonObject open(@NonNull OAuthStoreEntry entry, @NonNull Clock clock) {
  requireNonNull(entry); requireNonNull(clock);
  byte[] bytes = null;
  try {
   namespace(entry.getKey()); OAuthStoreFormat.sealed(entry.toSealedForm(), this.maximumRecordBytes);
   Instant now = clock.instant();
   if (!now.isBefore(entry.getRetainUntil())) throw OAuthStoreFormat.invalid();
   String plaintext = SealedStateAccess.get().unseal(this.sealer, SealedStateType.AS_RECORD,
     entry.toSealedForm(), context(entry.getKey()), Clock.fixed(now, ZoneOffset.UTC));
   bytes = boundedUtf8(plaintext);
   JsonValue value = JsonCodec.parse(bytes, JsonLimits.protocolDocument(this.maximumPlaintextBytes));
   if (!(value instanceof JsonObject object) || !object.getMembers().keySet().equals(FIELDS)
     || object.findLong("schema").orElse(-1L) != 1L
     || !object.findString("issuer").orElse("").equals(this.issuer)
     || !object.findString("key").orElse("").equals(entry.getKey().getStorageKey())
     || !object.findString("version").orElse("").equals(entry.getVersion())
     || object.findLong("retainUntil").orElse(Long.MIN_VALUE) != entry.getRetainUntil().getEpochSecond()
     || !(object.find("payload").orElseThrow() instanceof JsonObject payload)) throw OAuthStoreFormat.invalid();
   return payload;
  } catch (UnsealException | JsonParseException | IllegalArgumentException failure) {
   // No payload, address, provider message or cause escapes. Infrastructure wrapping belongs to the engine.
   throw OAuthStoreFormat.invalid();
  } finally { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
 }
 private void namespace(@NonNull OAuthStoreKey key) {
  requireNonNull(key);
  if (!OAuthStoreFormat.namespace(key).equals(this.namespace)) throw OAuthStoreFormat.invalid();
 }
 private @NonNull String context(@NonNull OAuthStoreKey key) {
  return "revetsec/as-record/v1:" + key.getStorageKey();
 }
 private void append(@NonNull StringBuilder text, @NonNull String part) {
  if (part.length() > this.maximumPlaintextBytes - text.length()) throw OAuthStoreFormat.invalid();
  text.append(part);
 }
 private byte @NonNull [] boundedUtf8(@NonNull String text) {
  requireNonNull(text);
  if (text.length() > this.maximumPlaintextBytes) throw OAuthStoreFormat.invalid();
  try {
   byte[] bytes = StrictUtf8.encode(text);
   if (bytes.length <= this.maximumPlaintextBytes) return bytes;
   Arrays.fill(bytes, (byte) 0); throw OAuthStoreFormat.invalid();
  } catch (EncodingException failure) { throw OAuthStoreFormat.invalid(); }
 }
 private static @NonNull String digest(@NonNull String text) {
  byte[] bytes;
  try { bytes = StrictUtf8.encode(text); } catch (EncodingException failure) { throw OAuthStoreFormat.invalid(); }
  byte[] hash = null;
  try { hash = MessageDigest.getInstance("SHA-256").digest(bytes); return Base64Url.encode(hash); }
  catch (NoSuchAlgorithmException failure) { throw new IllegalStateException("SHA-256 is unavailable."); }
  finally { Arrays.fill(bytes, (byte) 0); if (hash != null) Arrays.fill(hash, (byte) 0); }
 }
}
