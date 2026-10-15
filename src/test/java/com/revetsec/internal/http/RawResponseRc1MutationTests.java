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

package com.revetsec.internal.http;

import org.junit.jupiter.api.Test;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/** Raw responses admit every documented three-digit status, including both endpoints. */
final class RawResponseRc1MutationTests {
    @Test
    void statusRangeIncludesBothThreeDigitEndpoints() {
        HttpHeaders headers = HttpHeaders.of(Map.of(), (name, value) -> true);
        assertEquals(100, new RawResponse(100, headers, new byte[0], null, false, Duration.ZERO).status());
        assertEquals(999, new RawResponse(999, headers, new byte[0], null, false, Duration.ZERO).status());
        assertThrows(IllegalArgumentException.class,
                () -> new RawResponse(99, headers, new byte[0], null, false, Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> new RawResponse(1000, headers, new byte[0], null, false, Duration.ZERO));
    }

    @Test
    void equalityIsReflexiveAndRejectsOtherObjectKinds() {
        RawResponse response = new RawResponse(200, HttpHeaders.of(Map.of(), (name, value) -> true),
                new byte[0], null, false, Duration.ZERO);
        Object alias = response;
        assertTrue(response.equals(alias));
        assertNotEquals(response, new Object());
        assertNotEquals(response, null);
    }

    @Test
    void successfulRangeIncludesBothTwoHundredEndpoints() {
        for (int status : new int[] {200, 299}) {
            RawResponse response = new RawResponse(status, HttpHeaders.of(Map.of(), (name, value) -> true),
                    new byte[0], null, false, Duration.ZERO);
            assertTrue(response.isSuccessful());
        }
        for (int status : new int[] {199, 300}) {
            RawResponse response = new RawResponse(status, HttpHeaders.of(Map.of(), (name, value) -> true),
                    new byte[0], null, false, Duration.ZERO);
            assertFalse(response.isSuccessful());
        }
    }
}
