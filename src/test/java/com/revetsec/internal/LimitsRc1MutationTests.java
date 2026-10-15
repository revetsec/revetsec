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

package com.revetsec.internal;

import org.junit.jupiter.api.Test;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** The discovery lifetime order admits its documented inclusive boundaries. */
final class LimitsRc1MutationTests {
    @Test
    void discoveryDefaultMayEqualTheMaximum() {
        assertDoesNotThrow(() -> Limits.requireDiscoveryTimeToLiveOrder(Duration.ofSeconds(60),
                Duration.ofSeconds(120), Duration.ofSeconds(120), Duration.ofSeconds(30)));
        assertThrows(IllegalArgumentException.class, () -> Limits.requireDiscoveryTimeToLiveOrder(
                Duration.ofSeconds(60), Duration.ofSeconds(121), Duration.ofSeconds(120), Duration.ofSeconds(30)));
    }

    @Test
    void discoveryCooldownMayEqualTheMinimum() {
        assertDoesNotThrow(() -> Limits.requireDiscoveryTimeToLiveOrder(Duration.ofSeconds(60),
                Duration.ofSeconds(120), Duration.ofSeconds(180), Duration.ofSeconds(60)));
        assertThrows(IllegalArgumentException.class, () -> Limits.requireDiscoveryTimeToLiveOrder(
                Duration.ofSeconds(60), Duration.ofSeconds(120), Duration.ofSeconds(180), Duration.ofSeconds(61)));
    }
}
