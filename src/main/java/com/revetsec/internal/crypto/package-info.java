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

/**
 * Internal cryptographic helpers built on the JDK's JCA providers: entropy, constant-time comparison, HMAC,
 * HKDF-SHA256, AES-256-GCM, and the StateSealer v1 format with its type labels and the set-once accessor that the
 * protocol packages use to reach those labels.
 * <p>
 * It also holds the signature primitives that JOSE and XML signature processing share: the three ECDSA curves, the
 * ECDSA shape check and DER encoding, the RSA, EC and Ed25519 public key policies, the signature verifier and the HMAC
 * tag check. They are written in hash and curve terms and never mention a protocol package, so every protocol layer
 * can use them. Their checks run in {@code BigInteger} before the JCA sees a key or a signature, and they report
 * failures as {@link com.revetsec.internal.crypto.VerifyResult} values or a checked
 * {@link com.revetsec.internal.crypto.KeyRejectedException}, never as an unchecked exception (INV-G1). JCA algorithm
 * names are pinned; providers are not.
 * <p>
 * <strong>Not API.</strong> This package is public only because other Revetsec packages need access to it.
 * Its types may change or disappear in any release without notice, are not covered by semantic versioning,
 * are excluded from the published Javadoc, and never appear in a public or protected signature of an
 * exported package.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NullMarked
package com.revetsec.internal.crypto;

import org.jspecify.annotations.NullMarked;
