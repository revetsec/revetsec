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

import com.revetsec.internal.encoding.Base64Url;
import org.jspecify.annotations.NonNull;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import static java.util.Objects.requireNonNull;

/** Typed wire handles contain 256 random bits. The complete wire spelling is hashed into the ledger key. */
final class OAuthServerCredential {
 private static final @NonNull String CODE = "rsc1_", REFRESH = "rsr1_";
 private OAuthServerCredential() {}
 static @NonNull String code(@NonNull String nonce) { OAuthStoreFormat.nonce(nonce); return CODE + nonce; }
 static @NonNull String refresh(@NonNull String nonce) { OAuthStoreFormat.nonce(nonce); return REFRESH + nonce; }
 static @NonNull String codeDigest(@NonNull String value) { return digest(value, CODE); }
 static @NonNull String refreshDigest(@NonNull String value) { return digest(value, REFRESH); }
 private static @NonNull String digest(@NonNull String value, @NonNull String prefix) {
  requireNonNull(value);
  if (value.length() != prefix.length() + 43 || !value.startsWith(prefix)) throw OAuthStoreFormat.invalid();
  OAuthStoreFormat.nonce(value.substring(prefix.length()));
  byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
  try { return Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(bytes)); }
  catch (GeneralSecurityException failure) { throw OAuthStoreFormat.invalid(); }
  finally { Arrays.fill(bytes, (byte) 0); }
 }
}
