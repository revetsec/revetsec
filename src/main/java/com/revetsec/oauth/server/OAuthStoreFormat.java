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

import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/** Pure bounded storage grammar, shared by transport reconstruction and the engine. */
final class OAuthStoreFormat {
 static final @NonNull Instant PERMANENT = Instant.ofEpochSecond(Instant.MAX.getEpochSecond());
 private static final @NonNull String PREFIX = "revetsec:as:1:";
 private OAuthStoreFormat() { }
 static OAuthStoreKey.@NonNull Kind keyKind(@NonNull String key) {
  requireNonNull(key);
  if (key.length() > 256 || !key.startsWith(PREFIX)) throw invalid();
  int nsEnd = PREFIX.length() + 43;
  if (key.length() < nsEnd + 46 || key.charAt(nsEnd) != ':') throw invalid();
  nonce(key.substring(PREFIX.length(), nsEnd));
  int kindEnd = key.indexOf(':', nsEnd + 1);
  if (kindEnd < 0 || key.length() != kindEnd + 44) throw invalid();
  OAuthStoreKey.Kind kind;
  try { kind = OAuthStoreKey.Kind.valueOf(key.substring(nsEnd + 1, kindEnd)); }
  catch (IllegalArgumentException failure) { throw invalid(); }
  nonce(key.substring(kindEnd + 1));
  if (kind == OAuthStoreKey.Kind.ISSUER_STATE
    && !key.substring(PREFIX.length(), nsEnd).equals(key.substring(kindEnd + 1))) throw invalid();
  return kind;
 }
 static @NonNull OAuthStoreKey key(@NonNull String namespace, OAuthStoreKey.@NonNull Kind kind,
   @NonNull String identifier) {
  nonce(namespace); requireNonNull(kind); nonce(identifier);
  return OAuthStoreKey.fromStoredForm(PREFIX + namespace + ':' + kind.name() + ':' + identifier);
 }
 static @NonNull String namespace(@NonNull OAuthStoreKey key) {
  return key.getStorageKey().substring(PREFIX.length(), PREFIX.length() + 43);
 }
 static void nonce(@NonNull String value) {
  requireNonNull(value);
  if (value.length() != 43) throw invalid();
  for (int i = 0; i < 43; ++i) if (!com.revetsec.internal.encoding.Base64Url.isAlphabet(value.charAt(i))) throw invalid();
  // Thirty-two bytes leave two unused bits in the final base64 sextet. No decode/allocation is needed.
  if ("AEIMQUYcgkosw048".indexOf(value.charAt(42)) < 0) throw invalid();
 }
 @SuppressWarnings("JavaInstantGetSecondsGetNano") // Check only fractional-second presence.
 static void retention(OAuthStoreKey.@NonNull Kind kind, @NonNull Instant retainUntil) {
  requireNonNull(kind); requireNonNull(retainUntil);
  boolean permanent = kind == OAuthStoreKey.Kind.ISSUER_STATE || kind == OAuthStoreKey.Kind.SUBJECT_STATE;
  if (retainUntil.getNano() != 0 || (permanent ? !retainUntil.equals(PERMANENT) : !retainUntil.isBefore(PERMANENT))) throw invalid();
 }
 static void sealed(@NonNull String value, int cap) {
  requireNonNull(value);
  if (value.isEmpty() || value.length() > cap) throw invalid();
  for (int i = 0; i < value.length(); ++i) if (value.charAt(i) > 127) throw invalid();
 }
 static @NonNull IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid OAuth store value."); }
}
