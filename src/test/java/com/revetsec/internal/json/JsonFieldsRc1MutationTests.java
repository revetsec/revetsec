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
package com.revetsec.internal.json;

import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class JsonFieldsRc1MutationTests {
    @Test void numericDatesRetainWholeNanosecondsAndFloorSmallerFractions() throws Exception {
        assertNumericDate("1E-9", Instant.EPOCH.plusNanos(1));
        assertNumericDate("9E-9", Instant.EPOCH.plusNanos(9));
        assertNumericDate("-1E-9", Instant.EPOCH.minusNanos(1));
        assertNumericDate("-9E-9", Instant.EPOCH.minusNanos(9));
        assertNumericDate("9E-10", Instant.EPOCH);
        assertNumericDate("-9E-10", Instant.EPOCH.minusNanos(1));
        assertNumericDate("9E-11", Instant.EPOCH);
        assertNumericDate("-9E-11", Instant.EPOCH.minusNanos(1));
    }

    @Test void numericDatesKeepValidWholeSecondsWithPositiveDecimalExponents() throws Exception {
        Instant positive = Instant.ofEpochSecond(10_000_000_000L);
        Instant negative = Instant.ofEpochSecond(-10_000_000_000L);
        assertNumericDate("1E+10", positive);
        assertNumericDate("10E+9", positive);
        assertNumericDate("10000000000", positive);
        assertNumericDate("-1E+10", negative);
        assertNumericDate("-10E+9", negative);
        assertNumericDate("-10000000000", negative);
    }

    private static void assertNumericDate(@NonNull String seconds, @NonNull Instant expected) throws Exception {
        JsonObject claims = JsonObject.builder().put("exp", new BigDecimal(seconds)).build();
        assertEquals(Optional.of(expected), JsonFields.numericDate(claims, "exp"), seconds);
    }
}
