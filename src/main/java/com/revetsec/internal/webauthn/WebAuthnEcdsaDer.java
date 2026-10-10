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

package com.revetsec.internal.webauthn;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import static java.util.Objects.requireNonNull;

/** Strict DER Ecdsa-Sig-Value decoding for WebAuthn ES256 assertion signatures. */
final class WebAuthnEcdsaDer {
    private WebAuthnEcdsaDer() { }

    /** Returns fixed-width {@code r || s}, or null for any non-minimal, negative, truncated or trailing DER. */
    static byte @Nullable [] toP1363(byte @NonNull [] der) {
        requireNonNull(der);
        if (der.length < 8 || der.length > 72 || (der[0] & 0xff) != 0x30
            || (der[1] & 0xff) != der.length - 2 || (der[2] & 0xff) != 0x02) return null;
        int rLength = der[3] & 0xff;
        int sTag = 4 + rLength;
        if (rLength < 1 || rLength > 33 || sTag + 2 > der.length || (der[sTag] & 0xff) != 0x02)
            return null;
        int sLength = der[sTag + 1] & 0xff;
        if (sLength < 1 || sLength > 33 || sTag + 2 + sLength != der.length) return null;
        byte[] fixed = new byte[64];
        if (!copyPositiveMinimalInteger(der, 4, rLength, fixed, 0)
            || !copyPositiveMinimalInteger(der, sTag + 2, sLength, fixed, 32)) return null;
        return fixed;
    }

    private static boolean copyPositiveMinimalInteger(byte @NonNull [] der, int start, int length,
                                                       byte @NonNull [] fixed, int destination) {
        int first = der[start] & 0xff;
        if ((first & 0x80) != 0 || length > 1 && first == 0 && (der[start + 1] & 0x80) == 0)
            return false;
        int skip = length == 33 ? 1 : 0;
        if (length == 33 && first != 0) return false;
        int significant = length - skip;
        System.arraycopy(der, start + skip, fixed, destination + 32 - significant, significant);
        return true;
    }
}
