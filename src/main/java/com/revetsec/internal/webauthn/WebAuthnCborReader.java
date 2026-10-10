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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Small, forward-only decoder for the selected WebAuthn CBOR shapes. It does not accept 64-bit or indefinite arguments. */
final class WebAuthnCborReader {
    private final byte @NonNull [] input;
    private int position;

    WebAuthnCborReader(byte @NonNull [] input, int position) {
        this.input = input;
        this.position = position;
    }

    boolean finished() {
        return position == input.length;
    }

    int position() {
        return position;
    }

    int length(int majorType, int maximum) throws WebAuthnCborException {
        int head = next();
        if ((head >>> 5) != majorType) throw new WebAuthnCborException();
        long value = argument(head & 31);
        if (value > maximum || (majorType == 2 || majorType == 3) && value > input.length - position)
            throw new WebAuthnCborException();
        return (int) value;
    }

    int integer() throws WebAuthnCborException {
        int head = next();
        int majorType = head >>> 5;
        if (majorType != 0 && majorType != 1) throw new WebAuthnCborException();
        long value = argument(head & 31);
        if (value > (majorType == 0 ? Integer.MAX_VALUE : 1L + Integer.MAX_VALUE))
            throw new WebAuthnCborException();
        return majorType == 0 ? (int) value : (int) (-1L - value);
    }

    @NonNull String ascii(int maximum) throws WebAuthnCborException {
        int size = length(3, maximum);
        for (int i = 0; i < size; i++) {
            int octet = input[position + i] & 0xff;
            if (octet < 0x20 || octet > 0x7e) throw new WebAuthnCborException();
        }
        String result = new String(input, position, size, StandardCharsets.US_ASCII);
        position += size;
        return result;
    }

    byte @NonNull [] bytes(int maximum) throws WebAuthnCborException {
        int size = length(2, maximum);
        return rawBytes(size);
    }

    byte @NonNull [] rawBytes(int size) throws WebAuthnCborException {
        if (size < 0 || size > input.length - position) throw new WebAuthnCborException();
        byte[] result = Arrays.copyOfRange(input, position, position + size);
        position += size;
        return result;
    }

    int unsignedShort() throws WebAuthnCborException {
        return (next() << 8) | next();
    }

    int unsignedByte() throws WebAuthnCborException {
        return next();
    }

    long unsignedInt() throws WebAuthnCborException {
        return ((long) next() << 24) | ((long) next() << 16) | ((long) next() << 8) | next();
    }

    private int next() throws WebAuthnCborException {
        if (position >= input.length) throw new WebAuthnCborException();
        return input[position++] & 0xff;
    }

    private long argument(int additional) throws WebAuthnCborException {
        if (additional < 24) return additional;
        if (additional == 24) {
            int value = next();
            if (value < 24) throw new WebAuthnCborException();
            return value;
        }
        if (additional == 25) {
            int value = unsignedShort();
            if (value < 256) throw new WebAuthnCborException();
            return value;
        }
        if (additional == 26) {
            long value = ((long) next() << 24) | ((long) next() << 16) | ((long) next() << 8) | next();
            if (value < 65_536) throw new WebAuthnCborException();
            return value;
        }
        throw new WebAuthnCborException();
    }
}
