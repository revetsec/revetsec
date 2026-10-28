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

package com.revetsec.internal.password;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

/** BLAKE2b digest-size and block-boundary vectors, independent of Argon2id. */
final class Blake2bTests {
    @Test
    void digestSizeIsPartOfTheHash() {
        Assertions.assertEquals(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
                + "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            HexFormat.of().formatHex(Blake2b.digest(new byte[0], 64)));
        Assertions.assertEquals("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
                                HexFormat.of().formatHex(Blake2b.digest(new byte[0], 32)));
        Assertions.assertEquals(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17"
                + "d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            HexFormat.of().formatHex(Blake2b.digest("abc".getBytes(StandardCharsets.US_ASCII), 64)));
    }

    @Test
    void exactAndBeyondBlockBoundary() {
        byte[] input = new byte[129];
        for (int i = 0; i < input.length; i++) input[i] = (byte) i;
        Assertions.assertEquals(
            "2319e3789c47e2daa5fe807f61bec2a1a6537fa03f19ff32e87eecbfd64b7e0e"
                + "8ccff439ac333b040f19b0c4ddd11a61e24ac1fe0f10a039806c5dcc0da3d115",
            HexFormat.of().formatHex(Blake2b.digest(java.util.Arrays.copyOf(input, 128), 64)));
        Assertions.assertEquals(
            "f59711d44a031d5f97a9413c065d1e614c417ede998590325f49bad2fd444d3e44"
                + "18be19aec4e11449ac1a57207898bc57d76a1bcf3566292c20c683a5c4648f",
            HexFormat.of().formatHex(Blake2b.digest(input, 64)));
    }
}
