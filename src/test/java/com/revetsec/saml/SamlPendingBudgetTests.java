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

import com.revetsec.StateSealer;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlPendingBudgetTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);
    private static final @NonNull Duration LARGE_BUDGET = Duration.ofSeconds(Long.MAX_VALUE);

    @Test void elapsedBudgetBoundaryAndClockRegressionAreExact() {
        Duration budget = Duration.ofNanos(10);
        assertFalse(SamlPendingBudget.exhaustedAt(100, 100, false, budget));
        assertFalse(SamlPendingBudget.exhaustedAt(100, 109, false, budget));
        assertTrue(SamlPendingBudget.exhaustedAt(100, 110, false, budget));
        assertTrue(SamlPendingBudget.exhaustedAt(100, 99, false, budget));
        assertTrue(SamlPendingBudget.exhaustedAt(100, 100, true, budget));
        assertTrue(SamlPendingBudget.exhausted(System.nanoTime() - Duration.ofSeconds(1).toNanos(),
                Duration.ofMillis(1)));
    }

    @Test void largePositiveBudgetPreservesCompletedLoginSaveAndConsume() {
        PendingSamlAuthentication pending = pending();
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-large-login-budget"))
                .clock(CLOCK).build();
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(CLOCK, 1);
        assertEquals(SamlPendingSaveResult.SAVED,
                pending.saveToResult(store, sealer, "login", "browser", LARGE_BUDGET));
        PendingSamlAuthenticationSource.Resolved resolved = assertInstanceOf(
                PendingSamlAuthenticationSource.Resolved.class,
                PendingSamlAuthenticationSource.fromStore(store, "browser", sealer, "login")
                        .resolve(CLOCK, pending.getRelayStateHandle(), LARGE_BUDGET));
        assertEquals(pending.getRequestId(), resolved.pending().getRequestId());
    }

    @Test void largePositiveBudgetPreservesCompletedLogoutSaveAndConsume() {
        PendingSamlLogout pending = new PendingSamlLogout(pending());
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-large-logout-budget"))
                .clock(CLOCK).build();
        InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(CLOCK, 1);
        assertEquals(SamlPendingSaveResult.SAVED,
                pending.saveToResult(store, sealer, "logout", "browser", LARGE_BUDGET));
        PendingSamlLogoutSource.Resolved resolved = assertInstanceOf(
                PendingSamlLogoutSource.Resolved.class,
                PendingSamlLogoutSource.fromStore(store, "browser", sealer, "logout")
                        .resolve(CLOCK, pending.getRelayStateHandle(), LARGE_BUDGET));
        assertEquals(pending.getRequestId(), resolved.pending().getRequestId());
    }

    private static @NonNull PendingSamlAuthentication pending() {
        SecureRandom random = new SecureRandom();
        return new PendingSamlAuthentication("https://sp.example.test/saml", SamlRedirectLogout.id(random),
                SamlRedirectLogout.relay(random), "tenant-one", "https://idp.example.test/saml",
                "https://sp.example.test/acs", CLOCK.instant(), CLOCK.instant().plusSeconds(300));
    }
}
