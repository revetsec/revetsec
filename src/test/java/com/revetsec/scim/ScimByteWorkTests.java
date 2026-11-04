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
package com.revetsec.scim;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Final-only arithmetic conformance for the new internal byte-cost helper. */
final class ScimByteWorkTests {
    @Test void startedBlocksUseWideArithmeticAndRejectNegativeCounts() {
        for (int bytes : new int[] {0,1,15,16,17,31,32,33,255,256,257,1_048_576,10_485_760,33_554_432,Integer.MAX_VALUE}) {
            long expected = BigInteger.valueOf(bytes).add(BigInteger.valueOf(15)).divide(BigInteger.valueOf(16)).longValueExact();
            assertEquals(expected, ScimWork.byteUnits(bytes));
        }
        assertThrows(IllegalArgumentException.class, () -> ScimWork.byteUnits(-1));
        assertThrows(IllegalArgumentException.class, () -> ScimWork.byteUnits(Integer.MIN_VALUE));
    }
}
