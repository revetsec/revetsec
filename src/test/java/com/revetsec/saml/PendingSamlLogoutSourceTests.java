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

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class PendingSamlLogoutSourceTests {
    private static final @NonNull String SP = "https://sp.example.test/saml";
    private static final @NonNull String IDP = "https://idp.example.test/saml";
    private static final @NonNull String CONNECTION = "tenant-one";
    private static final @NonNull String ENDPOINT = "https://sp.example.test/logout";
    private static final @NonNull String REQUEST = "_" + "a".repeat(40);
    private static final @NonNull String RELAY = "b".repeat(22);
    private static final @NonNull String BROWSER = "browser-secret";
    private static final @NonNull String CONTEXT = "pending-logout-source";
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-10-14T12:00:00Z"), ZoneOffset.UTC);
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);

    @Test void providerCannotResolveConsumedStateWithoutObtainingApproval() {
        StateSealer sealer = sealer();
        String record = sealed(pending(), sealer, BROWSER, CONTEXT);
        AtomicInteger approvals = new AtomicInteger();
        StoreBase store = new StoreBase() {
            @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
                    @NonNull String relayStateHandle, @NonNull Predicate<@NonNull String> matches,
                    @NonNull Duration remaining) {
                return SamlPendingConsumeResult.Consumed.fromSealedRecord(record);
            }
        };
        PendingSamlLogoutSource source = source(store, sealer);
        assertInstanceOf(PendingSamlLogoutSource.Indeterminate.class,
                source.resolve(CLOCK, RELAY, BUDGET, value -> {
                    approvals.incrementAndGet();
                    return matchesPending(value);
                }));
        assertEquals(0, approvals.get());
        assertEquals(0, store.legacyConsumes.get());
    }

    @Test void providerCannotSubstituteAnotherRecordAfterObtainingApproval() {
        StateSealer sealer = sealer();
        String approved = sealed(pending(), sealer, BROWSER, CONTEXT);
        // Even another authentic seal of the same fields was not the approved storage snapshot.
        String replacement = sealed(pending(), sealer, BROWSER, CONTEXT);
        assertNotEquals(approved, replacement);
        AtomicInteger approvals = new AtomicInteger();
        StoreBase store = new StoreBase() {
            @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
                    @NonNull String relayStateHandle, @NonNull Predicate<@NonNull String> matches,
                    @NonNull Duration remaining) {
                assertTrue(matches.test(approved));
                return SamlPendingConsumeResult.Consumed.fromSealedRecord(replacement);
            }
        };
        assertInstanceOf(PendingSamlLogoutSource.Indeterminate.class,
                source(store, sealer).resolve(CLOCK, RELAY, BUDGET, value -> {
                    approvals.incrementAndGet();
                    return matchesPending(value);
                }));
        assertEquals(1, approvals.get());
        assertEquals(0, store.legacyConsumes.get());
    }

    @Test void invalidSealTypeBrowserAndContextCannotObtainConsumptionApproval() {
        StateSealer sealer = sealer();
        String bound = SamlPendingBinding.context(CONTEXT + "|logout", BROWSER);
        List<String> invalidRecords = List.of("invalid-seal", pending().toSealedForm(sealer, bound),
                sealed(pending(), sealer, "other-browser", CONTEXT),
                sealed(pending(), sealer, BROWSER, "other-context"));
        for (String record : invalidRecords) {
            GuardedRecordStore store = new GuardedRecordStore(record);
            assertInstanceOf(PendingSamlLogoutSource.Rejected.class,
                    source(store, sealer).resolve(CLOCK, RELAY, BUDGET));
            assertEquals(1, store.conditionalCalls.get());
            assertEquals(0, store.removals.get());
            assertEquals(0, store.legacyConsumes.get());
        }
    }

    @Test void authenticatedPendingBindingMismatchesRemainUnconsumed() {
        StateSealer sealer = sealer();
        List<PendingSamlAuthentication> mismatches = List.of(
                pending(SP + "/other", REQUEST, RELAY, CONNECTION, IDP, ENDPOINT),
                pending(SP, "_" + "x".repeat(40), RELAY, CONNECTION, IDP, ENDPOINT),
                pending(SP, REQUEST, "x".repeat(22), CONNECTION, IDP, ENDPOINT),
                pending(SP, REQUEST, RELAY, "other-tenant", IDP, ENDPOINT),
                pending(SP, REQUEST, RELAY, CONNECTION, IDP + "/other", ENDPOINT),
                pending(SP, REQUEST, RELAY, CONNECTION, IDP, ENDPOINT + "/post"));
        for (PendingSamlAuthentication mismatch : mismatches) {
            GuardedRecordStore store = new GuardedRecordStore(sealed(mismatch, sealer, BROWSER, CONTEXT));
            assertInstanceOf(PendingSamlLogoutSource.Rejected.class,
                    source(store, sealer).resolve(CLOCK, RELAY, BUDGET,
                            PendingSamlLogoutSourceTests::matchesPending));
            assertEquals(1, store.conditionalCalls.get());
            assertEquals(0, store.removals.get());
            assertEquals(0, store.legacyConsumes.get());
        }
    }

    @Test void legacyOnlyStoreFailsClosedWithoutCallingDestructiveConsume() {
        StoreBase store = new StoreBase() { };
        assertInstanceOf(PendingSamlLogoutSource.Unavailable.class,
                source(store, sealer()).resolve(CLOCK, RELAY, BUDGET));
        assertEquals(0, store.legacyConsumes.get());
    }

    @Test void unsealingClockFailureIsUnavailableAndPreservesPendingState() {
        StateSealer sealer = sealer();
        GuardedRecordStore store = new GuardedRecordStore(sealed(pending(), sealer, BROWSER, CONTEXT));
        Clock failedClock = new Clock() {
            @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
            @Override public @NonNull Instant instant() { throw new IllegalStateException("clock failed"); }
        };
        assertInstanceOf(PendingSamlLogoutSource.Unavailable.class,
                source(store, sealer).resolve(failedClock, RELAY, BUDGET));
        assertEquals(1, store.conditionalCalls.get());
        assertEquals(0, store.removals.get());
        assertEquals(0, store.legacyConsumes.get());
        assertInstanceOf(PendingSamlLogoutSource.Resolved.class,
                source(store, sealer).resolve(CLOCK, RELAY, BUDGET));
        assertEquals(1, store.removals.get());
    }

    @Test void validationFailureIsUnavailableAndPreservesPendingState() {
        StateSealer sealer = sealer();
        GuardedRecordStore store = new GuardedRecordStore(sealed(pending(), sealer, BROWSER, CONTEXT));
        assertInstanceOf(PendingSamlLogoutSource.Unavailable.class,
                source(store, sealer).resolve(CLOCK, RELAY, BUDGET,
                        value -> { throw new IllegalStateException("validation failed"); }));
        assertEquals(1, store.conditionalCalls.get());
        assertEquals(0, store.removals.get());
        assertEquals(0, store.legacyConsumes.get());
        assertInstanceOf(PendingSamlLogoutSource.Resolved.class,
                source(store, sealer).resolve(CLOCK, RELAY, BUDGET,
                        PendingSamlLogoutSourceTests::matchesPending));
        assertEquals(1, store.removals.get());
    }

    @Test void exactAuthenticatedApprovedRecordResolvesOnlyOnce() {
        StateSealer sealer = sealer();
        GuardedRecordStore store = new GuardedRecordStore(sealed(pending(), sealer, BROWSER, CONTEXT));
        PendingSamlLogoutSource source = source(store, sealer);
        PendingSamlLogoutSource.Resolved resolved = assertInstanceOf(PendingSamlLogoutSource.Resolved.class,
                source.resolve(CLOCK, RELAY, BUDGET, PendingSamlLogoutSourceTests::matchesPending));
        assertTrue(matchesPending(resolved.pending()));
        assertTrue(resolved.consumed());
        assertEquals(1, store.removals.get());
        assertInstanceOf(PendingSamlLogoutSource.Rejected.class,
                source.resolve(CLOCK, RELAY, BUDGET, PendingSamlLogoutSourceTests::matchesPending));
        assertEquals(1, store.removals.get());
        assertEquals(0, store.legacyConsumes.get());
    }

    @Test void sealedCookieResolutionDoesNotClaimAtomicConsumption() {
        StateSealer sealer = sealer();
        PendingSamlLogoutSource source = PendingSamlLogoutSource.fromSealedForm(
                new PendingSamlLogout(pending()).toSealedForm(sealer, CONTEXT), sealer, CONTEXT);
        for (int attempt = 0; attempt < 2; attempt++) {
            PendingSamlLogoutSource.Resolved resolved = assertInstanceOf(PendingSamlLogoutSource.Resolved.class,
                    source.resolve(CLOCK, RELAY, BUDGET, PendingSamlLogoutSourceTests::matchesPending));
            assertTrue(matchesPending(resolved.pending()));
            assertFalse(resolved.consumed());
        }
    }

    @Test void failuresAfterConfirmedConsumptionAreIndeterminateAndCannotConsumeAgain() {
        for (String fault : List.of("pending expiry", "validator false", "clock failure", "validator failure")) {
            StateSealer sealer = sealer();
            PendingSamlAuthentication pending = pending();
            InMemoryPendingSamlAuthenticationStore backing = InMemoryPendingSamlAuthenticationStore.withLimit(CLOCK, 1);
            assertEquals(SamlPendingSaveResult.SAVED, backing.save(BROWSER, RELAY,
                    sealed(pending, sealer, BROWSER, CONTEXT), pending.expiresAt(), BUDGET));
            AtomicReference<@NonNull Instant> current = new AtomicReference<>(CLOCK.instant());
            AtomicBoolean clockFailed = new AtomicBoolean();
            AtomicBoolean validatorFailed = new AtomicBoolean();
            AtomicBoolean matches = new AtomicBoolean(true);
            AtomicInteger removals = new AtomicInteger();
            Clock clock = new Clock() {
                @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
                @Override public @NonNull Instant instant() {
                    if (clockFailed.get()) throw new IllegalStateException("clock failed");
                    return Objects.requireNonNull(current.get());
                }
            };
            StoreBase store = new StoreBase() {
                @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
                        @NonNull String handle, @NonNull Predicate<@NonNull String> validation,
                        @NonNull Duration remaining) {
                    SamlPendingConsumeResult result = backing.consumeIfMatches(browserBinding, handle, validation, remaining);
                    if (result instanceof SamlPendingConsumeResult.Consumed) {
                        removals.incrementAndGet();
                        switch (fault) {
                            case "pending expiry" -> current.set(pending.expiresAt());
                            case "validator false" -> matches.set(false);
                            case "clock failure" -> clockFailed.set(true);
                            case "validator failure" -> validatorFailed.set(true);
                            default -> throw new AssertionError("Unknown post-consume fault");
                        }
                    }
                    return result;
                }
            };
            PendingSamlLogoutSource source = source(store, sealer);
            assertInstanceOf(PendingSamlLogoutSource.Indeterminate.class,
                    source.resolve(clock, RELAY, BUDGET, value -> {
                        if (validatorFailed.get()) throw new IllegalStateException("validation failed");
                        return matches.get() && matchesPending(value);
                    }), fault);
            assertEquals(1, removals.get(), fault);
            assertEquals(0, store.legacyConsumes.get(), fault);
            assertInstanceOf(PendingSamlLogoutSource.Rejected.class,
                    source.resolve(CLOCK, RELAY, BUDGET, PendingSamlLogoutSourceTests::matchesPending), fault);
            assertInstanceOf(SamlPendingConsumeResult.Missing.class, backing.consume(BROWSER, RELAY, BUDGET), fault);
            assertEquals(1, removals.get(), fault);
        }
    }

    @Test void failuresBeforeConsumptionPreserveRealStoreAndTheirTypedResults() {
        for (String fault : List.of("validator false", "clock failure", "validator failure")) {
            StateSealer sealer = sealer();
            PendingSamlAuthentication pending = pending();
            InMemoryPendingSamlAuthenticationStore store = InMemoryPendingSamlAuthenticationStore.withLimit(CLOCK, 1);
            assertEquals(SamlPendingSaveResult.SAVED, store.save(BROWSER, RELAY,
                    sealed(pending, sealer, BROWSER, CONTEXT), pending.expiresAt(), BUDGET));
            Clock clock = fault.equals("clock failure") ? new Clock() {
                @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
                @Override public @NonNull Instant instant() { throw new IllegalStateException("clock failed"); }
            } : CLOCK;
            PendingSamlLogoutSource source = source(store, sealer);
            PendingSamlLogoutSource.Resolution result = source.resolve(clock, RELAY, BUDGET, value -> {
                if (fault.equals("validator failure")) throw new IllegalStateException("validation failed");
                return !fault.equals("validator false") && matchesPending(value);
            });
            if (fault.equals("validator false")) assertInstanceOf(PendingSamlLogoutSource.Rejected.class, result, fault);
            else assertInstanceOf(PendingSamlLogoutSource.Unavailable.class, result, fault);
            assertInstanceOf(PendingSamlLogoutSource.Resolved.class,
                    source.resolve(CLOCK, RELAY, BUDGET, PendingSamlLogoutSourceTests::matchesPending), fault);
            assertInstanceOf(SamlPendingConsumeResult.Missing.class, store.consume(BROWSER, RELAY, BUDGET), fault);
        }
    }

    private static boolean matchesPending(@NonNull PendingSamlAuthentication value) {
        return SP.equals(value.spEntityId()) && REQUEST.equals(value.requestId())
                && RELAY.equals(value.relayState()) && CONNECTION.equals(value.connectionId())
                && IDP.equals(value.idpEntityId()) && ENDPOINT.equals(value.acs())
                && CLOCK.instant().isBefore(value.expiresAt());
    }

    private static @NonNull PendingSamlAuthentication pending() {
        return pending(SP, REQUEST, RELAY, CONNECTION, IDP, ENDPOINT);
    }

    private static @NonNull PendingSamlAuthentication pending(@NonNull String sp,
            @NonNull String request, @NonNull String relay, @NonNull String connection,
            @NonNull String idp, @NonNull String endpoint) {
        return new PendingSamlAuthentication(sp, request, relay, connection, idp, endpoint,
                CLOCK.instant(), CLOCK.instant().plusSeconds(120));
    }

    private static @NonNull StateSealer sealer() {
        return StateSealer.withActiveKey(TestSealers.fixedKey("pending-logout-source"))
                .clock(CLOCK).build();
    }

    private static @NonNull String sealed(@NonNull PendingSamlAuthentication pending,
            @NonNull StateSealer sealer, @NonNull String browser, @NonNull String context) {
        return new PendingSamlLogout(pending).toSealedForm(sealer,
                SamlPendingBinding.context(context + "|logout", browser));
    }

    private static @NonNull PendingSamlLogoutSource source(@NonNull PendingSamlAuthenticationStore store,
            @NonNull StateSealer sealer) {
        return PendingSamlLogoutSource.fromStore(store, BROWSER, sealer, CONTEXT);
    }

    private abstract static class StoreBase implements PendingSamlAuthenticationStore {
        final @NonNull AtomicInteger legacyConsumes = new AtomicInteger();

        @Override public @NonNull SamlPendingSaveResult save(@NonNull String browserBinding,
                @NonNull String relayStateHandle, @NonNull String sealedRecord,
                @NonNull Instant expiresAt, @NonNull Duration remaining) {
            throw new AssertionError("resolution must not save pending state");
        }

        @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
                @NonNull String relayStateHandle, @NonNull Duration remaining) {
            legacyConsumes.incrementAndGet();
            throw new AssertionError("resolution must not fall back to destructive consume");
        }
    }

    private static final class GuardedRecordStore extends StoreBase {
        private final @NonNull String record;
        private final @NonNull AtomicInteger conditionalCalls = new AtomicInteger();
        private final @NonNull AtomicInteger removals = new AtomicInteger();

        private GuardedRecordStore(@NonNull String record) { this.record = record; }

        @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
                @NonNull String relayStateHandle, @NonNull Predicate<@NonNull String> matches,
                @NonNull Duration remaining) {
            conditionalCalls.incrementAndGet();
            if (removals.get() != 0 || !matches.test(record)) return SamlPendingConsumeResult.Missing.INSTANCE;
            assertTrue(removals.compareAndSet(0, 1));
            return SamlPendingConsumeResult.Consumed.fromSealedRecord(record);
        }
    }
}
