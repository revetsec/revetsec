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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

final class SamlReplayUnlockMutationTests {
    @Test void completedAdmissionReleasesLockForAnotherThread() throws Exception {
        Instant now = Instant.parse("2026-10-09T00:00:00Z");
        SamlReplayCache cache = InMemorySamlReplayCache.withLimit(Clock.fixed(now, ZoneOffset.UTC), 2);
        Instant expiry = now.plusSeconds(30);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            assertEquals(SamlReplayCache.MarkResult.MARKED,
                    executor.submit(() -> cache.markIfAbsent("first", expiry, Duration.ofSeconds(5)))
                            .get(5, TimeUnit.SECONDS));
            assertEquals(SamlReplayCache.MarkResult.MARKED,
                    cache.markIfAbsent("second", expiry, Duration.ofSeconds(2)));
        } finally {
            executor.shutdownNow();
        }
    }
}
