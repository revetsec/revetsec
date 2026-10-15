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

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/** Explicit metadata freshness and progress boundaries found by the RC-1 inventory. */
final class ClientMetadataFreshnessRc1MutationTests {
    private static final @NonNull Instant NOW = Instant.parse("2026-10-06T12:00:00Z");

    private static @NonNull Duration remaining(@NonNull String cacheControl) {
        RawResponse response = new RawResponse(200,
                HttpHeaders.of(Map.of("Cache-Control", List.of(cacheControl)), (name, value) -> true),
                new byte[] {1}, null, false, Duration.ZERO);
        return ClientMetadataFreshness.remaining(response, NOW, Duration.ofSeconds(300));
    }

    @Test
    void emptyAndCommaOnlyDirectivesFinishWithoutReusableMetadata() {
        assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
            for (String value : List.of("", ",", ",,", " , , "))
                assertEquals(Duration.ZERO, remaining(value));
        });
    }

    @Test
    void malformedUnknownDirectivesCannotBorrowAnOtherwiseFreshMaxAge() {
        assertTimeoutPreemptively(Duration.ofSeconds(1), () -> {
            for (String value : List.of("max-age=120, {bad}", "max-age=120, unknown=\"unfinished",
                    "max-age=120, unknown=", "max-age=120, unknown=value garbage"))
                assertEquals(Duration.ZERO, remaining(value));
        });
    }
}
