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

package com.revetsec.saml;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

final class SamlDateTimeTests {
    @Test void acceptsUtcOffsetAndTimezoneFreeValuesWithLongFractions() {
        Instant expected = Instant.parse("2026-10-09T00:00:00.123456789Z");
        assertEquals(expected, SamlDateTime.parse("2026-10-09T00:00:00.123456789987654321Z"));
        assertEquals(expected, SamlDateTime.parse("2026-10-09T02:00:00.123456789+02:00"));
        assertEquals(expected, SamlDateTime.parse("2026-10-08T19:00:00.123456789-05:00"));
        assertEquals(expected, SamlDateTime.parse("2026-10-09T00:00:00.123456789"));
    }

    @Test void rejectsLeapSecondsBadOffsetsAndNonLexicalDates() {
        assertNull(SamlDateTime.parse("2026-10-09T00:00:60Z"));
        assertNull(SamlDateTime.parse("2026-10-09T00:00:00+14:01"));
        assertNull(SamlDateTime.parse("2026-10-09T00:00:00+15:00"));
        assertNull(SamlDateTime.parse("2026-02-30T00:00:00Z"));
        assertNull(SamlDateTime.parse("2026-10-09 00:00:00Z"));
        assertNull(SamlDateTime.parse("2026-10-09T00:00:00. Z"));
    }
}
