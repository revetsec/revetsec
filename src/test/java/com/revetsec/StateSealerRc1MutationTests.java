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

package com.revetsec;

import com.revetsec.testing.TestSealers;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;

final class StateSealerRc1MutationTests {
    @Test
    void invalidUnsealContextIsRejectedBeforeReadingTheApplicationClock() {
        AtomicInteger clockCalls = new AtomicInteger();
        Clock clock = new Clock() {
            @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone) {
                requireNonNull(zone);
                return this;
            }
            @Override public @NonNull Instant instant() {
                clockCalls.incrementAndGet();
                throw new IllegalStateException("Owned application clock must not run for invalid context.");
            }
        };
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("rc1-context-order"))
                .clock(clock).build();
        for (String context : new String[]{"", "x".repeat(257), "\ud800"}) {
            assertThrows(IllegalArgumentException.class, () -> sealer.unseal("untrusted-not-a-seal", context));
            assertEquals(0, clockCalls.get());
            assertThrows(IllegalArgumentException.class, () -> SealedStateAccess.get().unseal(sealer,
                    SealedStateType.APP, "untrusted-not-a-seal", context, clock));
            assertEquals(0, clockCalls.get());
        }
    }

    @Test
    void outcomeDiagnosticsNameTheVariantWithoutRenderingInputOrPlaintext() {
        StateSealer sealer = TestSealers.fromFixedKey();
        String secret = "TEST-ONLY-rc1-outcome-private-plaintext";
        String sealed = sealer.seal(secret, "rc1-diagnostics", Duration.ofMinutes(1));
        String succeeded = sealer.unsealResult(sealed, "rc1-diagnostics").toString();
        String rejected = sealer.unsealResult(sealed, "wrong-context").toString();
        assertTrue(succeeded.contains("Succeeded"));
        assertTrue(rejected.contains("Rejected"));
        for (String diagnostic : new String[]{succeeded, rejected}) {
            assertFalse(diagnostic.contains(secret));
            assertFalse(diagnostic.contains(sealed));
            assertFalse(diagnostic.contains("rc1-diagnostics"));
        }
    }
}
