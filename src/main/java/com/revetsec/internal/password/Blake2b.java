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

/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

// Java translation of src/blake2/blake2b.c, tag 20190702. See docs/password-vendored-source.md.
package com.revetsec.internal.password;

import org.jspecify.annotations.NonNull;

import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * The unkeyed BLAKE2b functions used by Argon2. Names, function order and round schedule follow
 * the pinned C reference. State and byte-array offsets replace C pointers; unused keyed and tree
 * variants are deliberately absent. This internal translation has no public API role.
 */
final class Blake2b {
    private static final int BLAKE2B_BLOCKBYTES = 128;
    private static final int BLAKE2B_OUTBYTES = 64;
    private static final long[] blake2b_IV = {
        0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL,
        0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
        0x510e527fade682d1L, 0x9b05688c2b3e6c1fL,
        0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };
    private static final int[][] blake2b_sigma = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };

    /** C blake2b_state, restricted to the unkeyed sequential path used by Argon2. */
    static final class State {
        final long[] h = new long[8];
        final long[] t = new long[2];
        final long[] f = new long[2];
        final byte[] buf = new byte[BLAKE2B_BLOCKBYTES];
        int buflen;
        int outlen;
        boolean last_node;

        void clear() {
            Arrays.fill(h, 0);
            Arrays.fill(t, 0);
            Arrays.fill(f, 0);
            Arrays.fill(buf, (byte) 0);
            buflen = 0;
            outlen = 0;
            last_node = false;
        }
    }

    private Blake2b() { }

    private static void blake2b_set_lastnode(@NonNull State S) {
        S.f[1] = -1L;
    }

    private static void blake2b_set_lastblock(@NonNull State S) {
        if (S.last_node) blake2b_set_lastnode(S);
        S.f[0] = -1L;
    }

    private static void blake2b_increment_counter(@NonNull State S, long inc) {
        long before = S.t[0];
        S.t[0] += inc;
        if (Long.compareUnsigned(S.t[0], before) < 0) S.t[1]++;
    }

    private static void blake2b_invalidate_state(@NonNull State S) {
        S.clear();
        blake2b_set_lastblock(S);
    }

    private static void blake2b_init0(@NonNull State S) {
        S.clear();
        System.arraycopy(blake2b_IV, 0, S.h, 0, S.h.length);
    }

    private static void blake2b_init_param(@NonNull State S, byte @NonNull [] P) {
        blake2b_init0(S);
        // C's blake2b_param is a 64-byte packed structure. Unused fields remain zero.
        for (int i = 0; i < 8; ++i) S.h[i] ^= load64(P, i * 8);
        S.outlen = P[0] & 0xff;
    }

    static void blake2b_init(@NonNull State S, int outlen) {
        if (outlen < 1 || outlen > BLAKE2B_OUTBYTES) {
            blake2b_invalidate_state(S);
            throw new IllegalArgumentException("Invalid BLAKE2b digest length");
        }
        byte[] P = new byte[64];
        try {
            P[0] = (byte) outlen; // digest_length
            P[1] = 0;            // key_length
            P[2] = 1;            // fanout
            P[3] = 1;            // depth
            blake2b_init_param(S, P);
        } finally {
            Arrays.fill(P, (byte) 0);
        }
    }

    private static void blake2b_compress(@NonNull State S, byte @NonNull [] block, int offset) {
        long[] m = new long[16];
        long[] v = new long[16];
        try {
            for (int i = 0; i < 16; ++i) m[i] = load64(block, offset + i * 8);
            for (int i = 0; i < 8; ++i) v[i] = S.h[i];
            v[8] = blake2b_IV[0];
            v[9] = blake2b_IV[1];
            v[10] = blake2b_IV[2];
            v[11] = blake2b_IV[3];
            v[12] = blake2b_IV[4] ^ S.t[0];
            v[13] = blake2b_IV[5] ^ S.t[1];
            v[14] = blake2b_IV[6] ^ S.f[0];
            v[15] = blake2b_IV[7] ^ S.f[1];
            for (int r = 0; r < 12; ++r) ROUND(r, v, m);
            for (int i = 0; i < 8; ++i) S.h[i] ^= v[i] ^ v[i + 8];
        } finally {
            Arrays.fill(m, 0);
            Arrays.fill(v, 0);
        }
    }

    private static void G(int r, int i, long @NonNull [] v, long @NonNull [] m,
                          int a, int b, int c, int d) {
        v[a] = v[a] + v[b] + m[blake2b_sigma[r][2 * i]];
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + m[blake2b_sigma[r][2 * i + 1]];
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }

    private static void ROUND(int r, long @NonNull [] v, long @NonNull [] m) {
        G(r, 0, v, m, 0, 4, 8, 12);
        G(r, 1, v, m, 1, 5, 9, 13);
        G(r, 2, v, m, 2, 6, 10, 14);
        G(r, 3, v, m, 3, 7, 11, 15);
        G(r, 4, v, m, 0, 5, 10, 15);
        G(r, 5, v, m, 1, 6, 11, 12);
        G(r, 6, v, m, 2, 7, 8, 13);
        G(r, 7, v, m, 3, 4, 9, 14);
    }

    static void blake2b_update(@NonNull State S, byte @NonNull [] in, int offset, int inlen) {
        requireNonNull(in);
        if (offset < 0 || inlen < 0 || offset > in.length - inlen || S.f[0] != 0)
            throw new IllegalArgumentException("Invalid BLAKE2b update");
        if (inlen == 0) return;
        if (S.buflen + inlen > BLAKE2B_BLOCKBYTES) {
            int left = S.buflen;
            int fill = BLAKE2B_BLOCKBYTES - left;
            System.arraycopy(in, offset, S.buf, left, fill);
            blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
            blake2b_compress(S, S.buf, 0);
            S.buflen = 0;
            inlen -= fill;
            offset += fill;
            while (inlen > BLAKE2B_BLOCKBYTES) {
                blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
                blake2b_compress(S, in, offset);
                inlen -= BLAKE2B_BLOCKBYTES;
                offset += BLAKE2B_BLOCKBYTES;
            }
        }
        System.arraycopy(in, offset, S.buf, S.buflen, inlen);
        S.buflen += inlen;
    }

    static byte @NonNull [] blake2b_final(@NonNull State S) {
        if (S.f[0] != 0 || S.outlen < 1 || S.outlen > BLAKE2B_OUTBYTES)
            throw new IllegalArgumentException("Invalid BLAKE2b final");
        byte[] buffer = new byte[BLAKE2B_OUTBYTES];
        try {
            blake2b_increment_counter(S, S.buflen);
            blake2b_set_lastblock(S);
            Arrays.fill(S.buf, S.buflen, BLAKE2B_BLOCKBYTES, (byte) 0);
            blake2b_compress(S, S.buf, 0);
            for (int i = 0; i < 8; ++i) store64(buffer, i * 8, S.h[i]);
            return Arrays.copyOf(buffer, S.outlen);
        } finally {
            Arrays.fill(buffer, (byte) 0);
            S.clear();
        }
    }

    private static byte @NonNull [] blake2b(byte @NonNull [] in, int outlen) {
        State S = new State();
        try {
            blake2b_init(S, outlen);
            blake2b_update(S, in, 0, in.length);
            return blake2b_final(S);
        } finally {
            S.clear();
        }
    }

    static byte @NonNull [] blake2b_long(byte @NonNull [] in, int outlen) {
        requireNonNull(in);
        if (outlen < 1 || outlen > 1024)
            throw new IllegalArgumentException("Invalid Argon2 BLAKE2b output length");
        byte[] outlen_bytes = new byte[4];
        byte[] out_buffer = null;
        byte[] in_buffer = null;
        State blake_state = new State();
        store32(outlen_bytes, 0, outlen);
        try {
            if (outlen <= BLAKE2B_OUTBYTES) {
                blake2b_init(blake_state, outlen);
                blake2b_update(blake_state, outlen_bytes, 0, outlen_bytes.length);
                blake2b_update(blake_state, in, 0, in.length);
                return blake2b_final(blake_state);
            }
            byte[] out = new byte[outlen];
            blake2b_init(blake_state, BLAKE2B_OUTBYTES);
            blake2b_update(blake_state, outlen_bytes, 0, outlen_bytes.length);
            blake2b_update(blake_state, in, 0, in.length);
            out_buffer = blake2b_final(blake_state);
            System.arraycopy(out_buffer, 0, out, 0, BLAKE2B_OUTBYTES / 2);
            int out_offset = BLAKE2B_OUTBYTES / 2;
            int toproduce = outlen - BLAKE2B_OUTBYTES / 2;
            while (toproduce > BLAKE2B_OUTBYTES) {
                in_buffer = Arrays.copyOf(out_buffer, BLAKE2B_OUTBYTES);
                Arrays.fill(out_buffer, (byte) 0);
                out_buffer = blake2b(in_buffer, BLAKE2B_OUTBYTES);
                Arrays.fill(in_buffer, (byte) 0);
                in_buffer = null;
                System.arraycopy(out_buffer, 0, out, out_offset, BLAKE2B_OUTBYTES / 2);
                out_offset += BLAKE2B_OUTBYTES / 2;
                toproduce -= BLAKE2B_OUTBYTES / 2;
            }
            in_buffer = Arrays.copyOf(out_buffer, BLAKE2B_OUTBYTES);
            Arrays.fill(out_buffer, (byte) 0);
            out_buffer = blake2b(in_buffer, toproduce);
            System.arraycopy(out_buffer, 0, out, out_offset, toproduce);
            return out;
        } finally {
            blake_state.clear();
            Arrays.fill(outlen_bytes, (byte) 0);
            if (out_buffer != null) Arrays.fill(out_buffer, (byte) 0);
            if (in_buffer != null) Arrays.fill(in_buffer, (byte) 0);
        }
    }

    /** Minimal checked entry point for same-package tests. */
    static byte @NonNull [] digest(byte @NonNull [] input, int outLength) {
        requireNonNull(input);
        if (outLength < 1 || outLength > BLAKE2B_OUTBYTES)
            throw new IllegalArgumentException("Invalid BLAKE2b digest length");
        return blake2b(input, outLength);
    }

    private static long load64(byte @NonNull [] input, int offset) {
        long value = 0;
        for (int i = 0; i < 8; i++) value |= (input[offset + i] & 0xffL) << (i * 8);
        return value;
    }

    private static void store32(byte @NonNull [] output, int offset, int value) {
        for (int i = 0; i < 4; i++) output[offset + i] = (byte) (value >> (i * 8));
    }

    private static void store64(byte @NonNull [] output, int offset, long value) {
        for (int i = 0; i < 8; i++) output[offset + i] = (byte) (value >>> (i * 8));
    }
}
