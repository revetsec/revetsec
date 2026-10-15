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

package com.revetsec.internal.encoding;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.time.Duration;
final class StrictUtf8Rc1MutationTests {
 @Test void wellFormedSupplementaryPairsAlwaysAdvance(){Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2),()->Assertions.assertTrue(StrictUtf8.isWellFormed("\uD800\uDC00\uD83D\uDE00")));}
 @Test void supplementaryLengthCountingAlwaysAdvances(){Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2),()->Assertions.assertEquals(8,StrictUtf8.encodedLength("\uD800\uDC00\uD83D\uDE00")));}
 @Test void firstSupplementaryCodePointUsesFourOctets()throws Exception{Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2),()->Assertions.assertArrayEquals(new byte[]{(byte)0xF0,(byte)0x90,(byte)0x80,(byte)0x80},StrictUtf8.encode("\uD800\uDC00")));}
}
