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

// Java translation from tag 20190702; Apache-2.0 option selected. See docs/password-vendored-source.md.
package com.revetsec.internal.password;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * Argon2id v19, translated from the pinned C reference's core.c, ref.c and blamka-round-ref.h.
 * C blocks are views over one contiguous long array, so the C pointer arithmetic becomes block
 * indexes without changing the reference's initialization, addressing, fill or finalization order.
 * The caller owns work admission. This primitive enforces independent hard bounds and clears
 * derived arrays on a best-effort basis; the JVM may retain other copies.
 */
@ThreadSafe
public final class Argon2id {
    private static final int ARGON2_BLOCK_SIZE = 1024;
    private static final int ARGON2_QWORDS_IN_BLOCK = 128;
    private static final int ARGON2_SYNC_POINTS = 4;
    private static final int ARGON2_ADDRESSES_IN_BLOCK = 128;
    private static final int ARGON2_PREHASH_DIGEST_LENGTH = 64;
    private static final int ARGON2_PREHASH_SEED_LENGTH = 72;
    private static final int ARGON2_VERSION_13 = 0x13;
    private static final int Argon2_id = 2;
    private static final int MAX_MEMORY_KIB = 262_144;

    /** C block: a 1024-byte view, possibly into the contiguous instance memory. */
    private static final class Block {
        final long[] v;
        final int offset;

        Block() {
            this(new long[ARGON2_QWORDS_IN_BLOCK], 0);
        }

        Block(long @NonNull [] v, int offset) {
            this.v = v;
            this.offset = offset;
        }

        long get(int i) {
            return v[offset + i];
        }

        void set(int i, long value) {
            v[offset + i] = value;
        }

        void clear() {
            Arrays.fill(v, offset, offset + ARGON2_QWORDS_IN_BLOCK, 0);
        }
    }

    /** C argon2_position_t. */
    private static final class Position {
        int pass;
        int lane;
        int slice;
        int index;

        Position(int pass, int lane, int slice) {
            this.pass = pass;
            this.lane = lane;
            this.slice = slice;
        }
    }

    /** Fields from C argon2_context; input arrays are borrowed. */
    private static final class Context {
        final byte[] pwd;
        final byte[] salt;
        final byte[] secret;
        final byte[] ad;
        final int m_cost;
        final int t_cost;
        final int lanes;
        final int outlen;

        Context(byte @NonNull [] pwd, byte @NonNull [] salt, byte @NonNull [] secret,
                byte @NonNull [] ad,
                int m_cost, int t_cost, int lanes, int outlen) {
            this.pwd = pwd;
            this.salt = salt;
            this.secret = secret;
            this.ad = ad;
            this.m_cost = m_cost;
            this.t_cost = t_cost;
            this.lanes = lanes;
            this.outlen = outlen;
        }
    }

    /** Fields from C argon2_instance_t; lane scheduling is intentionally single-threaded. */
    private static final class Instance {
        Block @NonNull [] memory = new Block[0];
        long @NonNull [] memory_words = new long[0];
        final int memory_blocks;
        final int segment_length;
        final int lane_length;
        final int lanes;
        final int passes;
        final Block blockR = new Block();
        final Block block_tmp = new Block();

        Instance(int memory_blocks, int lanes, int passes) {
            this.memory_blocks = memory_blocks;
            this.segment_length = memory_blocks / (lanes * ARGON2_SYNC_POINTS);
            this.lane_length = segment_length * ARGON2_SYNC_POINTS;
            this.lanes = lanes;
            this.passes = passes;
        }

        void clear() {
            if (memory_words != null) Arrays.fill(memory_words, 0);
            blockR.clear();
            block_tmp.clear();
        }
    }

    private Argon2id() { }

    /** Returns a raw tag which its caller must clear. */
    public static byte @NonNull [] hash(byte @NonNull [] password, byte @NonNull [] salt,
                                        byte @NonNull [] secret, int memoryKiB, int passes,
                                        int lanes, int tagBytes) {
        return hash(password, salt, secret, new byte[0], memoryKiB, passes, lanes, tagBytes);
    }

    // Associated data is available to same-package vector tests, not the public password API.
    static byte @NonNull [] hash(byte @NonNull [] password, byte @NonNull [] salt,
                                 byte @NonNull [] secret, byte @NonNull [] associatedData,
                                 int memoryKiB, int passes, int lanes, int tagBytes) {
        requireNonNull(password);
        requireNonNull(salt);
        requireNonNull(secret);
        requireNonNull(associatedData);
        if (lanes < 1 || lanes > 16 || memoryKiB < 8 * lanes || memoryKiB > MAX_MEMORY_KIB
            || passes < 1 || passes > 32 || tagBytes < 16 || tagBytes > 64
            || password.length > 65_536 || salt.length < 8 || salt.length > 64
            || secret.length > 64 || associatedData.length > 64)
            throw new IllegalArgumentException("Invalid Argon2id parameters");
        if (Thread.currentThread().isInterrupted()) throw new Argon2idInterruptedException();

        int memory_blocks = memoryKiB - memoryKiB % (ARGON2_SYNC_POINTS * lanes);
        Context context = new Context(password, salt, secret, associatedData,
                                      memoryKiB, passes, lanes, tagBytes);
        Instance instance = new Instance(memory_blocks, lanes, passes);
        try {
            initialize(instance, context);
            fill_memory_blocks_st(instance);
            return finalize(instance, context);
        } finally {
            instance.clear();
        }
    }

    // core.c: the following block helpers retain the original operation order.
    private static void init_block_value(@NonNull Block b, byte in) {
        Arrays.fill(b.v, b.offset, b.offset + ARGON2_QWORDS_IN_BLOCK,
                    (in & 0xffL) * 0x0101010101010101L);
    }

    private static void copy_block(@NonNull Block dst, @NonNull Block src) {
        System.arraycopy(src.v, src.offset, dst.v, dst.offset, ARGON2_QWORDS_IN_BLOCK);
    }

    private static void xor_block(@NonNull Block dst, @NonNull Block src) {
        for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) dst.set(i, dst.get(i) ^ src.get(i));
    }

    private static void load_block(@NonNull Block dst, byte @NonNull [] input) {
        for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) dst.set(i, load64(input, i * 8));
    }

    private static void store_block(byte @NonNull [] output, @NonNull Block src) {
        for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) store64(output, i * 8, src.get(i));
    }

    private static byte @NonNull [] finalize(@NonNull Instance instance, @NonNull Context context) {
        Block blockhash = new Block();
        byte[] blockhash_bytes = new byte[ARGON2_BLOCK_SIZE];
        try {
            copy_block(blockhash, instance.memory[instance.lane_length - 1]);
            for (int l = 1; l < instance.lanes; ++l) {
                int last_block_in_lane = l * instance.lane_length + instance.lane_length - 1;
                xor_block(blockhash, instance.memory[last_block_in_lane]);
            }
            store_block(blockhash_bytes, blockhash);
            return Blake2b.blake2b_long(blockhash_bytes, context.outlen);
        } finally {
            blockhash.clear();
            Arrays.fill(blockhash_bytes, (byte) 0);
        }
    }

    private static int index_alpha(@NonNull Instance instance, @NonNull Position position,
                                   long pseudo_rand, boolean same_lane) {
        long reference_area_size;
        long relative_position;
        int start_position;
        if (position.pass == 0) {
            if (position.slice == 0) {
                reference_area_size = position.index - 1;
            } else if (same_lane) {
                reference_area_size = position.slice * instance.segment_length + position.index - 1;
            } else {
                reference_area_size = position.slice * instance.segment_length
                    + (position.index == 0 ? -1 : 0);
            }
        } else if (same_lane) {
            reference_area_size = instance.lane_length - instance.segment_length + position.index - 1;
        } else {
            reference_area_size = instance.lane_length - instance.segment_length
                + (position.index == 0 ? -1 : 0);
        }
        relative_position = pseudo_rand;
        relative_position = (relative_position * relative_position) >>> 32;
        relative_position = reference_area_size - 1
            - ((reference_area_size * relative_position) >>> 32);
        start_position = 0;
        if (position.pass != 0)
            start_position = position.slice == ARGON2_SYNC_POINTS - 1
                ? 0 : (position.slice + 1) * instance.segment_length;
        return (int) ((start_position + relative_position) % instance.lane_length);
    }

    private static void fill_memory_blocks_st(@NonNull Instance instance) {
        for (int r = 0; r < instance.passes; ++r) {
            for (int s = 0; s < ARGON2_SYNC_POINTS; ++s) {
                for (int l = 0; l < instance.lanes; ++l) {
                    if (Thread.currentThread().isInterrupted())
                        throw new Argon2idInterruptedException();
                    Position position = new Position(r, l, s);
                    fill_segment(instance, position);
                }
            }
        }
    }

    private static void fill_first_blocks(byte @NonNull [] blockhash, @NonNull Instance instance) {
        byte[] blockhash_bytes = null;
        try {
            for (int l = 0; l < instance.lanes; ++l) {
                store32(blockhash, ARGON2_PREHASH_DIGEST_LENGTH, 0);
                store32(blockhash, ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
                blockhash_bytes = Blake2b.blake2b_long(blockhash, ARGON2_BLOCK_SIZE);
                load_block(instance.memory[l * instance.lane_length], blockhash_bytes);
                Arrays.fill(blockhash_bytes, (byte) 0);
                blockhash_bytes = null;

                store32(blockhash, ARGON2_PREHASH_DIGEST_LENGTH, 1);
                blockhash_bytes = Blake2b.blake2b_long(blockhash, ARGON2_BLOCK_SIZE);
                load_block(instance.memory[l * instance.lane_length + 1], blockhash_bytes);
                Arrays.fill(blockhash_bytes, (byte) 0);
                blockhash_bytes = null;
            }
        } finally {
            if (blockhash_bytes != null) Arrays.fill(blockhash_bytes, (byte) 0);
        }
    }

    private static void initial_hash(byte @NonNull [] blockhash, @NonNull Context context) {
        Blake2b.State BlakeHash = new Blake2b.State();
        byte[] value = new byte[4];
        byte[] digest = null;
        try {
            Blake2b.blake2b_init(BlakeHash, ARGON2_PREHASH_DIGEST_LENGTH);
            store32(value, 0, context.lanes);
            Blake2b.blake2b_update(BlakeHash, value, 0, 4);
            store32(value, 0, context.outlen);
            Blake2b.blake2b_update(BlakeHash, value, 0, 4);
            store32(value, 0, context.m_cost);
            Blake2b.blake2b_update(BlakeHash, value, 0, 4);
            store32(value, 0, context.t_cost);
            Blake2b.blake2b_update(BlakeHash, value, 0, 4);
            store32(value, 0, ARGON2_VERSION_13);
            Blake2b.blake2b_update(BlakeHash, value, 0, 4);
            store32(value, 0, Argon2_id);
            Blake2b.blake2b_update(BlakeHash, value, 0, 4);

            store32(value, 0, context.pwd.length);
            Blake2b.blake2b_update(BlakeHash, value, 0, 4);
            Blake2b.blake2b_update(BlakeHash, context.pwd, 0, context.pwd.length);
            store32(value, 0, context.salt.length);
            Blake2b.blake2b_update(BlakeHash, value, 0, 4);
            Blake2b.blake2b_update(BlakeHash, context.salt, 0, context.salt.length);
            store32(value, 0, context.secret.length);
            Blake2b.blake2b_update(BlakeHash, value, 0, 4);
            Blake2b.blake2b_update(BlakeHash, context.secret, 0, context.secret.length);
            store32(value, 0, context.ad.length);
            Blake2b.blake2b_update(BlakeHash, value, 0, 4);
            Blake2b.blake2b_update(BlakeHash, context.ad, 0, context.ad.length);
            digest = Blake2b.blake2b_final(BlakeHash);
            System.arraycopy(digest, 0, blockhash, 0, ARGON2_PREHASH_DIGEST_LENGTH);
        } finally {
            BlakeHash.clear();
            Arrays.fill(value, (byte) 0);
            if (digest != null) Arrays.fill(digest, (byte) 0);
        }
    }

    private static void initialize(@NonNull Instance instance, @NonNull Context context) {
        byte[] blockhash = new byte[ARGON2_PREHASH_SEED_LENGTH];
        try {
            instance.memory_words = new long[instance.memory_blocks * ARGON2_QWORDS_IN_BLOCK];
            instance.memory = new Block[instance.memory_blocks];
            for (int i = 0; i < instance.memory_blocks; i++)
                instance.memory[i] = new Block(instance.memory_words, i * ARGON2_QWORDS_IN_BLOCK);
            initial_hash(blockhash, context);
            Arrays.fill(blockhash, ARGON2_PREHASH_DIGEST_LENGTH, ARGON2_PREHASH_SEED_LENGTH, (byte) 0);
            fill_first_blocks(blockhash, instance);
        } finally {
            Arrays.fill(blockhash, (byte) 0);
        }
    }

    // ref.c: fill_block, next_addresses and fill_segment retain reference branch and loop order.
    private static void fill_block(@NonNull Instance instance, @NonNull Block prev_block,
                                   @NonNull Block ref_block, @NonNull Block next_block,
                                   boolean with_xor) {
        Block blockR = instance.blockR;
        Block block_tmp = instance.block_tmp;
        copy_block(blockR, ref_block);
        xor_block(blockR, prev_block);
        copy_block(block_tmp, blockR);
        if (with_xor) xor_block(block_tmp, next_block);

        for (int i = 0; i < 8; ++i)
            BLAKE2_ROUND_NOMSG(blockR, 16 * i, 16 * i + 1, 16 * i + 2, 16 * i + 3,
                               16 * i + 4, 16 * i + 5, 16 * i + 6, 16 * i + 7,
                               16 * i + 8, 16 * i + 9, 16 * i + 10, 16 * i + 11,
                               16 * i + 12, 16 * i + 13, 16 * i + 14, 16 * i + 15);
        for (int i = 0; i < 8; ++i)
            BLAKE2_ROUND_NOMSG(blockR, 2 * i, 2 * i + 1, 2 * i + 16, 2 * i + 17,
                               2 * i + 32, 2 * i + 33, 2 * i + 48, 2 * i + 49,
                               2 * i + 64, 2 * i + 65, 2 * i + 80, 2 * i + 81,
                               2 * i + 96, 2 * i + 97, 2 * i + 112, 2 * i + 113);
        copy_block(next_block, block_tmp);
        xor_block(next_block, blockR);
    }

    private static void next_addresses(@NonNull Instance instance, @NonNull Block address_block,
                                       @NonNull Block input_block, @NonNull Block zero_block) {
        input_block.set(6, input_block.get(6) + 1);
        fill_block(instance, zero_block, input_block, address_block, false);
        fill_block(instance, zero_block, address_block, address_block, false);
    }

    private static void fill_segment(@NonNull Instance instance, @NonNull Position position) {
        Block address_block = new Block();
        Block input_block = new Block();
        Block zero_block = new Block();
        try {
            boolean data_independent_addressing = position.pass == 0
                && position.slice < ARGON2_SYNC_POINTS / 2;
            if (data_independent_addressing) {
                init_block_value(zero_block, (byte) 0);
                init_block_value(input_block, (byte) 0);
                input_block.set(0, position.pass);
                input_block.set(1, position.lane);
                input_block.set(2, position.slice);
                input_block.set(3, instance.memory_blocks);
                input_block.set(4, instance.passes);
                input_block.set(5, Argon2_id);
            }
            int starting_index = 0;
            if (position.pass == 0 && position.slice == 0) {
                starting_index = 2;
                if (data_independent_addressing)
                    next_addresses(instance, address_block, input_block, zero_block);
            }
            int curr_offset = position.lane * instance.lane_length
                + position.slice * instance.segment_length + starting_index;
            int prev_offset = curr_offset % instance.lane_length == 0
                ? curr_offset + instance.lane_length - 1 : curr_offset - 1;

            for (int i = starting_index; i < instance.segment_length;
                 ++i, ++curr_offset, ++prev_offset) {
                if ((i & 127) == 0 && Thread.currentThread().isInterrupted())
                    throw new Argon2idInterruptedException();
                if (curr_offset % instance.lane_length == 1) prev_offset = curr_offset - 1;
                long pseudo_rand;
                if (data_independent_addressing) {
                    if (i % ARGON2_ADDRESSES_IN_BLOCK == 0)
                        next_addresses(instance, address_block, input_block, zero_block);
                    pseudo_rand = address_block.get(i % ARGON2_ADDRESSES_IN_BLOCK);
                } else {
                    pseudo_rand = instance.memory[prev_offset].get(0);
                }
                int ref_lane = (int) ((pseudo_rand >>> 32) % instance.lanes);
                if (position.pass == 0 && position.slice == 0) ref_lane = position.lane;
                position.index = i;
                int ref_index = index_alpha(instance, position, pseudo_rand & 0xffff_ffffL,
                                            ref_lane == position.lane);
                Block ref_block = instance.memory[instance.lane_length * ref_lane + ref_index];
                Block curr_block = instance.memory[curr_offset];
                if (ARGON2_VERSION_13 == 0x10) {
                    fill_block(instance, instance.memory[prev_offset], ref_block, curr_block, false);
                } else if (position.pass == 0) {
                    fill_block(instance, instance.memory[prev_offset], ref_block, curr_block, false);
                } else {
                    fill_block(instance, instance.memory[prev_offset], ref_block, curr_block, true);
                }
            }
        } finally {
            address_block.clear();
            input_block.clear();
            zero_block.clear();
        }
    }

    // blamka-round-ref.h: the C macros become methods over block word indexes.
    private static long fBlaMka(long x, long y) {
        long m = 0xffff_ffffL;
        long xy = (x & m) * (y & m);
        return x + y + 2 * xy;
    }

    private static void G(@NonNull Block v, int a, int b, int c, int d) {
        v.set(a, fBlaMka(v.get(a), v.get(b)));
        v.set(d, Long.rotateRight(v.get(d) ^ v.get(a), 32));
        v.set(c, fBlaMka(v.get(c), v.get(d)));
        v.set(b, Long.rotateRight(v.get(b) ^ v.get(c), 24));
        v.set(a, fBlaMka(v.get(a), v.get(b)));
        v.set(d, Long.rotateRight(v.get(d) ^ v.get(a), 16));
        v.set(c, fBlaMka(v.get(c), v.get(d)));
        v.set(b, Long.rotateRight(v.get(b) ^ v.get(c), 63));
    }

    private static void BLAKE2_ROUND_NOMSG(@NonNull Block v,
                                            int v0, int v1, int v2, int v3,
                                            int v4, int v5, int v6, int v7,
                                            int v8, int v9, int v10, int v11,
                                            int v12, int v13, int v14, int v15) {
        G(v, v0, v4, v8, v12);
        G(v, v1, v5, v9, v13);
        G(v, v2, v6, v10, v14);
        G(v, v3, v7, v11, v15);
        G(v, v0, v5, v10, v15);
        G(v, v1, v6, v11, v12);
        G(v, v2, v7, v8, v13);
        G(v, v3, v4, v9, v14);
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
