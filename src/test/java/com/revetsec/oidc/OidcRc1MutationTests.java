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

package com.revetsec.oidc;

import com.revetsec.oauth.PendingAuthorizationSaveResult;

import com.revetsec.oauth.AuthorizationResponseParseResult;

import com.revetsec.jose.JwksParseResult;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HttpExchange;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.jose.Jwks;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.RemoteJwksSource;
import com.revetsec.jose.StaticJwksSource;
import com.revetsec.oauth.OAuthEndpoint;
import com.revetsec.oauth.OAuthException;
import com.revetsec.oauth.AuthorizationRedirect;
import com.revetsec.oauth.AuthorizationResponse;
import com.revetsec.oauth.InMemoryPendingAuthorizationStore;
import com.revetsec.oauth.PendingAuthorizationSource;
import com.revetsec.testing.JsonText;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestJwk;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestTls;
import com.revetsec.testing.TestClock;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ExecutionException;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Focused contracts found by the fresh RC-1 mutation inventory. */
final class OidcRc1MutationTests {
    private static final String COMMON = "https://login.microsoftonline.com/common/v2.0";
    private static final String TENANT = "11111111-2222-3333-4444-555555555555";
    private static final String TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0";
    private static final String EXACT = "https://issuer.example";
    private static final String NONCE = "TEST-ONLY-rc1-nonce";
    private static final Instant NOW = Instant.parse("2026-10-14T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    void zeroDeadlineNeverAllowsAnIssuerPolicyOperation() {
        for (int attempt = 0; attempt < 10_000; attempt++) {
            Deadline deadline = Deadline.fromNow(Duration.ZERO);
            assertEquals(OAuthException.Reason.NETWORK_FAILURE,
                    assertThrows(OAuthException.class, () -> OidcIssuerPolicy.checkDeadline(deadline)).getReason());
        }
    }

    @Test
    void directValidatorConstructionAlsoRejectsAnUnsupportedEntraTrustIssuer() {
        AtomicInteger predicates = new AtomicInteger();
        OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> {
            predicates.incrementAndGet();
            return true;
        });
        StaticJwksSource keys = StaticJwksSource.fromJwks(assertInstanceOf(JwksParseResult.Succeeded.class, Jwks.fromJsonResult(keySet(false))).getJwks());
        assertThrows(IllegalArgumentException.class, () -> new IdTokenValidator(EXACT, "client", keys,
                Set.of(JwsAlgorithm.RS256), Set.of(), Set.of(), Duration.ZERO, Duration.ofMinutes(5),
                CLOCK, OidcObserver.disabledInstance(), false, policy));
        assertEquals(0, predicates.get());
        OidcProviderMetadata metadata = OidcProviderMetadata.withIssuer(EXACT)
                .authorizationEndpoint(URI.create(EXACT + "/authorize")).tokenEndpoint(URI.create(EXACT + "/token"))
                .jwksUri(URI.create(EXACT + "/jwks")).build();
        assertThrows(IllegalArgumentException.class, () -> policy.checkMetadata(metadata));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> anOmittedOverallDeadlineStillAllowsTheBoundedRemoteKeyRequest() {
        return Stream.of(false, true).map(entra -> DynamicTest.dynamicTest(entra ? "Entra" : "HMAC opt-in with RSA", () -> {
            try (TestHttpsServer server = TestHttpsServer.start()) {
                server.script("/jwks", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(200)
                        .header("Content-Type", "application/json").body(keySet(entra)).build()));
                RemoteJwksSource keys = RemoteJwksSource.withUri(server.uri("/jwks"))
                        .httpClient(TestTls.httpClient()).build();
                AtomicInteger predicates = new AtomicInteger();
                OidcIssuerPolicy policy = entra ? OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> {
                    assertEquals(TENANT, tenant);
                    predicates.incrementAndGet();
                    return true;
                }) : OidcIssuerPolicy.exactInstance();
                IdTokenValidator validator = new IdTokenValidator(entra ? COMMON : EXACT, "client", keys,
                        entra ? Set.of(JwsAlgorithm.RS256) : Set.of(JwsAlgorithm.RS256, JwsAlgorithm.HS256),
                        Set.of(), Set.of(), Duration.ZERO, Duration.ofMinutes(5), CLOCK,
                        OidcObserver.disabledInstance(), !entra, policy);
                String compact = token(entra);
                IdToken result = validator.validate(compact, NONCE, "TEST-ONLY-access", "TEST-ONLY-code", null,
                        Set.of(), null, entra ? null : "TEST-ONLY-secret-" + "s".repeat(64));
                assertEquals("subject", result.getClaims().getSubject().orElseThrow());
                assertEquals(compact, result.toCompactSerialization());
                assertEquals(1, server.getHitCount("/jwks"));
                assertEquals(entra ? 1 : 0, predicates.get());
            }
        }));
    }

    @Test
    void discoveryAllowsTheNextFetchExactlyWhenTheOldestAttemptLeavesItsCooldown() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            TestClock clock = TestClock.fromInstant(NOW);
            AtomicLong nanos = new AtomicLong();
            URI issuer = server.uri("/tenant/");
            server.script("/tenant/.well-known/openid-configuration", TestHttpsServer.Script.fromResponse(
                    TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
                            .body(metadata(issuer)).build()));
            OidcProviderCache<OidcProviderMetadata> cache = cache(server, clock, nanos);
            assertEquals(issuer.toString(), cache.get(Deadline.fromNow(Duration.ofSeconds(5))).getIssuer());
            clock.advance(Duration.ofSeconds(31));
            nanos.set(Duration.ofSeconds(15).toNanos());
            assertEquals(issuer.toString(), cache.get(Deadline.fromNow(Duration.ofSeconds(5))).getIssuer());
            clock.advance(Duration.ofSeconds(31));
            nanos.set(Duration.ofSeconds(30).toNanos());
            assertEquals(issuer.toString(), cache.get(Deadline.fromNow(Duration.ofSeconds(5))).getIssuer());
            clock.advance(Duration.ofSeconds(31));
            nanos.set(Duration.ofSeconds(31).toNanos());
            assertEquals(OAuthException.Reason.ATTEMPT_LIMIT, assertThrows(OAuthException.class,
                    () -> cache.get(Deadline.fromNow(Duration.ofSeconds(5)))).getReason());
            assertEquals(3, server.getHitCount("/tenant/.well-known/openid-configuration"));
        }
    }

    @Test
    void aFlightAtItsExactReplacementBoundaryRemainsSharedAndEveryCallerCanLeave() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            AtomicLong nanos = new AtomicLong(Duration.ofSeconds(100).toNanos());
            OidcProviderCache<OidcProviderMetadata> cache = cache(server, CLOCK, nanos);
            URI issuer = server.uri("/tenant/");
            TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(
                    TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
                            .body(metadata(issuer)).build());
            server.script("/tenant/.well-known/openid-configuration", held);
            ExecutorService workers = Executors.newFixedThreadPool(3, operation -> {
                Thread thread = new Thread(operation, "rc1-oidc-caller");
                thread.setDaemon(true);
                return thread;
            });
            try {
                Future<OidcProviderMetadata> first = workers.submit(() -> cache.get(Deadline.fromNow(Duration.ofSeconds(5))));
                assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(2)));
                // A two-second request allowance plus its replacement grace is exactly four seconds.
                nanos.set(Duration.ofSeconds(104).toNanos());
                Future<OidcProviderMetadata> second = workers.submit(() -> cache.get(Deadline.fromNow(Duration.ofSeconds(5))));
                Future<Boolean> waiter = workers.submit(() -> cache.awaitWaitersForTests(1, Duration.ofSeconds(2)));
                assertTrue(assertDoesNotThrow(() -> waiter.get(3, TimeUnit.SECONDS)));
                assertEquals(1, held.getArrivalCount());
                held.release();
                OidcProviderMetadata found = assertDoesNotThrow(() -> first.get(3, TimeUnit.SECONDS));
                assertSame(found, assertDoesNotThrow(() -> second.get(3, TimeUnit.SECONDS)));
                assertEquals(issuer.toString(), found.getIssuer());
                Future<OidcProviderMetadata> subsequent = workers.submit(() -> cache.get(Deadline.fromNow(Duration.ofSeconds(5))));
                assertSame(found, assertDoesNotThrow(() -> subsequent.get(3, TimeUnit.SECONDS)));
            } finally {
                held.release();
                workers.shutdownNow();
            }
        }
    }

    @Test
    void waiterProbeReportsZeroWaitersImmediatelyForAZeroAllowance() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            OidcProviderCache<OidcProviderMetadata> cache = cache(server, CLOCK, new AtomicLong());
            assertFalse(cache.awaitWaitersForTests(1, Duration.ZERO));
            assertTrue(server.getRequests().isEmpty());
        }
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> recoveryProbesAreReplacedOnlyAfterTheirExactAllowance() {
        return Stream.of(false, true).map(expiredDeadline -> DynamicTest.dynamicTest(
                expiredDeadline ? "expired caller allowance" : "normal caller allowance", () -> {
                    AtomicLong nanos = new AtomicLong();
                    Duration request = Duration.ofSeconds(1);
                    UserInfoAttemptGate gate = new UserInfoAttemptGate(Duration.ofSeconds(1), nanos::get);
                    OAuthException failed = OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.NETWORK_FAILURE);
                    gate.failed(gate.acquire(Deadline.fromNow(Duration.ofSeconds(5)), request), failed);
                    nanos.set(request.toNanos());
                    UserInfoAttemptGate.Attempt first = gate.acquire(
                            Deadline.fromNow(expiredDeadline ? Duration.ZERO : Duration.ofSeconds(5)), request);
                    nanos.set(Duration.ofSeconds(expiredDeadline ? 2 : 3).toNanos());
                    assertEquals(OAuthException.Reason.ATTEMPT_LIMIT, assertThrows(OAuthException.class,
                            () -> gate.acquire(Deadline.fromNow(Duration.ofSeconds(5)), request)).getReason());
                    nanos.incrementAndGet();
                    UserInfoAttemptGate.Attempt replacement = gate.acquire(Deadline.fromNow(Duration.ofSeconds(5)), request);
                    gate.healthy(first);
                    gate.failed(first, failed);
                    assertEquals(OAuthException.Reason.ATTEMPT_LIMIT, assertThrows(OAuthException.class,
                            () -> gate.acquire(Deadline.fromNow(Duration.ofSeconds(5)), request)).getReason());
                    gate.healthy(replacement);
                    gate.failed(first, failed);
                    assertNotNull(gate.acquire(Deadline.fromNow(Duration.ofSeconds(5)), request));
                }));
    }

    @Test
    void userInfoGateAlwaysReleasesOwnershipBeforeTheNextCallerThread() {
        AtomicLong nanos = new AtomicLong();
        Duration request = Duration.ofSeconds(1);
        UserInfoAttemptGate gate = new UserInfoAttemptGate(Duration.ofSeconds(1), nanos::get);
        UserInfoAttemptGate.Attempt first = onFreshCaller(() -> gate.acquire(Deadline.fromNow(Duration.ofSeconds(5)), request));
        onFreshCaller(() -> { gate.healthy(first); return true; });
        UserInfoAttemptGate.Attempt second = onFreshCaller(() -> gate.acquire(Deadline.fromNow(Duration.ofSeconds(5)), request));
        OAuthException failed = OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.NETWORK_FAILURE);
        onFreshCaller(() -> { gate.failed(second, failed); return true; });
        onFreshCaller(() -> {
            assertSame(failed, assertThrows(OAuthException.class,
                    () -> gate.acquire(Deadline.fromNow(Duration.ofSeconds(5)), request)));
            return true;
        });
        nanos.set(request.toNanos());
        UserInfoAttemptGate.Attempt recovery = onFreshCaller(() -> gate.acquire(Deadline.fromNow(Duration.ofSeconds(5)), request));
        onFreshCaller(() -> { gate.healthy(recovery); return true; });
        assertNotNull(onFreshCaller(() -> gate.acquire(Deadline.fromNow(Duration.ofSeconds(5)), request)));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> timeChangesBeforeTheTenantCallbackRejectWithoutCallingApplicationPolicy() {
        return Stream.of(false, true).map(rollback -> DynamicTest.dynamicTest(rollback ? "rollback" : "expiry", () -> {
            AtomicInteger reads = new AtomicInteger();
            AtomicInteger predicates = new AtomicInteger();
            Instant changed = rollback ? NOW.minusNanos(1) : NOW.plusSeconds(300);
            Clock clock = new Clock() {
                @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
                @Override public @NonNull Instant instant() { return reads.incrementAndGet() == 1 ? NOW : changed; }
            };
            IdTokenValidator validator = entraValidator(clock, OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> {
                predicates.incrementAndGet();
                return true;
            }));
            if (rollback) {
                assertEquals(OAuthException.Reason.ISSUER_POLICY_UNAVAILABLE, assertThrows(OAuthException.class,
                        () -> validator.validate(token(true), NONCE, "TEST-ONLY-access", "TEST-ONLY-code", null, Set.of())).getReason());
            } else {
                assertEquals(OidcValidationException.Reason.EXPIRED, assertThrows(OidcValidationException.class,
                        () -> validator.validate(token(true), NONCE, "TEST-ONLY-access", "TEST-ONLY-code", null, Set.of())).getReason());
            }
            assertEquals(0, predicates.get());
            assertEquals(2, reads.get());
        }));
    }

    @Test
    void anAlreadyExpiredEntraDeadlineRejectsBeforeParsingOrReadingTheClock() {
        AtomicInteger reads = new AtomicInteger();
        Clock clock = new Clock() {
            @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
            @Override public @NonNull Instant instant() { reads.incrementAndGet(); return NOW; }
        };
        IdTokenValidator validator = entraValidator(clock, OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> true));
        assertEquals(OAuthException.Reason.NETWORK_FAILURE, assertThrows(OAuthException.class,
                () -> validator.validate("malformed", NONCE, "TEST-ONLY-access", "TEST-ONLY-code", null,
                        Set.of(), Deadline.fromNow(Duration.ZERO))).getReason());
        assertEquals(0, reads.get());
    }

    @Test
    void theFinalDeadlineCheckIncludesThePostPolicyApplicationClockRead() {
        String compact = token(true);
        AtomicInteger reads = new AtomicInteger();
        AtomicInteger predicates = new AtomicInteger();
        AtomicReference<Deadline> deadline = new AtomicReference<>();
        Clock clock = new Clock() {
            @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
            @Override public @NonNull Instant instant() {
                if (reads.incrementAndGet() == 3) {
                    Deadline current = java.util.Objects.requireNonNull(deadline.get());
                    consumeBudget(current);
                }
                return NOW;
            }
        };
        IdTokenValidator validator = entraValidator(clock, OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> {
            predicates.incrementAndGet();
            return true;
        }));
        Deadline current = Deadline.fromNow(Duration.ofMillis(250));
        deadline.set(current);
        assertEquals(OAuthException.Reason.NETWORK_FAILURE, assertThrows(OAuthException.class,
                () -> validator.validate(compact, NONCE, "TEST-ONLY-access", "TEST-ONLY-code", null, Set.of(), current)).getReason());
        assertEquals(3, reads.get());
        assertEquals(1, predicates.get());
    }

    @Test
    void coalescedDiscoveryFailurePreservesTheLeadersFixedFailureAndRestoresWaiterAccounting() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            OidcProviderCache<OidcProviderMetadata> cache = cache(server, CLOCK, new AtomicLong());
            TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(
                    TestHttpsServer.Response.withStatus(302).header("Location", "/other").build());
            server.script("/tenant/.well-known/openid-configuration", held);
            ExecutorService workers = callers(3);
            try {
                Future<OidcProviderMetadata> first = workers.submit(() -> cache.get(Deadline.fromNow(Duration.ofSeconds(5))));
                assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(2)));
                Future<OidcProviderMetadata> second = workers.submit(() -> cache.get(Deadline.fromNow(Duration.ofSeconds(5))));
                Future<Boolean> waiter = workers.submit(() -> cache.awaitWaitersForTests(1, Duration.ofSeconds(2)));
                assertTrue(assertDoesNotThrow(() -> waiter.get(3, TimeUnit.SECONDS)));
                held.release();
                OAuthException leaderFailure = assertInstanceOf(OAuthException.class,
                        assertThrows(ExecutionException.class, () -> first.get(3, TimeUnit.SECONDS)).getCause());
                OAuthException followerFailure = assertInstanceOf(OAuthException.class,
                        assertThrows(ExecutionException.class, () -> second.get(3, TimeUnit.SECONDS)).getCause());
                assertSame(leaderFailure, followerFailure);
                assertNotEquals(OAuthException.Reason.NETWORK_FAILURE, leaderFailure.getReason());
                assertFalse(onFreshCaller(() -> assertDoesNotThrow(() -> cache.awaitWaitersForTests(1, Duration.ZERO))));
                assertEquals(1, server.getHitCount("/tenant/.well-known/openid-configuration"));
            } finally {
                held.release();
                workers.shutdownNow();
            }
        }
    }

    @Test
    void anUnexpectedDiscoveryClockFailureIsRedactedSharedAndBackedOff() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            AtomicInteger reads = new AtomicInteger();
            Clock clock = new Clock() {
                @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
                @Override public @NonNull Instant instant() {
                    if (reads.incrementAndGet() == 2) throw new IllegalStateException("TEST-ONLY-clock-secret");
                    return NOW;
                }
            };
            server.script("/tenant/.well-known/openid-configuration", TestHttpsServer.Script.fromResponse(
                    TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
                            .body(metadata(server.uri("/tenant/"))).build()));
            OidcProviderCache<OidcProviderMetadata> cache = cache(server, clock, new AtomicLong());
            OAuthException first = onFreshCaller(() -> assertThrows(OAuthException.class,
                    () -> cache.get(Deadline.fromNow(Duration.ofSeconds(5)))));
            assertEquals(OAuthException.Reason.NETWORK_FAILURE, first.getReason());
            assertNull(first.getCause());
            assertFalse(first.toString().contains("TEST-ONLY-clock-secret"));
            assertSame(first, onFreshCaller(() -> assertThrows(OAuthException.class,
                    () -> cache.get(Deadline.fromNow(Duration.ofSeconds(5))))));
            assertEquals(1, server.getHitCount("/tenant/.well-known/openid-configuration"));
        }
    }

    @Test
    void aLateUnexpectedLeaderFailureCannotPoisonTheNewGeneration() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            AtomicLong nanos = new AtomicLong();
            AtomicInteger validations = new AtomicInteger();
            AtomicInteger arrivals = new AtomicInteger();
            TestClock clock = TestClock.fromInstant(NOW);
            TestHttpsServer.Response response = TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
                    .body(metadata(server.uri("/tenant/"))).build();
            TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(response);
            server.script("/tenant/.well-known/openid-configuration", exchange -> {
                if (arrivals.incrementAndGet() == 1) held.run(exchange);
                else exchange.send(response);
            });
            OidcProviderCache<OidcProviderMetadata> cache = new OidcProviderCache<>(server.uri("/tenant/"),
                    HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false),
                    OutboundUriPolicy.defaultInstance(), false, Duration.ofSeconds(2), clock, OidcObserver.disabledInstance(),
                    Duration.ofSeconds(30), Duration.ofSeconds(30), Duration.ofSeconds(60), Duration.ofSeconds(30),
                    value -> {
                        if (validations.incrementAndGet() == 2) throw new IllegalStateException("TEST-ONLY-late-secret");
                        return value;
                    }, nanos::get);
            ExecutorService workers = callers(2);
            try {
                Future<OidcProviderMetadata> old = workers.submit(() -> cache.get(Deadline.fromNow(Duration.ofSeconds(5))));
                assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(2)));
                nanos.set(Duration.ofSeconds(4).toNanos() + 1);
                Future<OidcProviderMetadata> replacement = workers.submit(() -> cache.get(Deadline.fromNow(Duration.ofSeconds(5))));
                assertEquals(server.uri("/tenant/").toString(),
                        assertDoesNotThrow(() -> replacement.get(3, TimeUnit.SECONDS)).getIssuer());
                held.release();
                OAuthException failed = assertInstanceOf(OAuthException.class,
                        assertThrows(ExecutionException.class, () -> old.get(3, TimeUnit.SECONDS)).getCause());
                assertEquals(OAuthException.Reason.NETWORK_FAILURE, failed.getReason());
                assertNull(failed.getCause());
                assertFalse(failed.toString().contains("TEST-ONLY-late-secret"));
                clock.advance(Duration.ofSeconds(31));
                nanos.set(Duration.ofSeconds(30).toNanos());
                assertEquals(server.uri("/tenant/").toString(), onFreshCaller(
                        () -> cache.get(Deadline.fromNow(Duration.ofSeconds(5)))).getIssuer());
                assertEquals(3, server.getHitCount("/tenant/.well-known/openid-configuration"));
            } finally {
                held.release();
                workers.shutdownNow();
            }
        }
    }

    @Test
    void explicitlyConfiguredClientsReleaseStateOwnershipBetweenCallerThreads() {
        OidcProviderMetadata metadata = OidcProviderMetadata.withIssuer(EXACT)
                .authorizationEndpoint(URI.create(EXACT + "/authorize")).tokenEndpoint(URI.create(EXACT + "/token"))
                .jwksUri(URI.create(EXACT + "/jwks")).build();
        OidcClient client = OidcClient.withProviderMetadata(metadata).clientId("client")
                .redirectUri(URI.create("https://rp.example/callback")).clock(CLOCK)
                .jwksSource(StaticJwksSource.fromJwks(assertInstanceOf(JwksParseResult.Succeeded.class, Jwks.fromJsonResult(keySet(false))).getJwks())).build();
        AuthorizationRedirect first = onFreshCaller(client::beginAuthentication);
        AuthorizationRedirect second = onFreshCaller(client::beginAuthentication);
        assertEquals(EXACT, first.getPendingAuthorization().getIssuer());
        assertEquals(EXACT, second.getPendingAuthorization().getIssuer());
        assertNotEquals(first.getAuthorizationUri(), second.getAuthorizationUri());
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> discoveryRefreshReusesKeysOnlyForTheUnchangedExactKeySetUri() {
        return Stream.of(false, true).map(changes -> DynamicTest.dynamicTest(changes ? "changed URI" : "same URI", () -> {
            try (TestHttpsServer server = TestHttpsServer.start()) {
                TestClock clock = TestClock.fromInstant(NOW);
                URI firstKeys = server.uri("/keys-one");
                URI secondKeys = changes ? server.uri("/keys-two") : firstKeys;
                server.script("/tenant/.well-known/openid-configuration", TestHttpsServer.Script.fromSequence(List.of(
                        TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
                                .body(metadata(server, server.uri("/token"), firstKeys)).build(),
                        TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
                                .body(metadata(server, server.uri("/token"), secondKeys)).build())));
                TestHttpsServer.Response jwks = TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
                        .header("Cache-Control", "max-age=600").body(keySet(false)).build();
                server.script("/keys-one", TestHttpsServer.Script.fromResponse(jwks));
                server.script("/keys-two", TestHttpsServer.Script.fromResponse(jwks));
                OidcClient client = lazyClient(server, clock).build();
                onFreshCaller(() -> { client.warmUp(); return true; });
                clock.advance(Duration.ofSeconds(31));
                onFreshCaller(() -> { client.warmUp(); return true; });
                assertEquals(2, server.getHitCount("/tenant/.well-known/openid-configuration"));
                assertEquals(1, server.getHitCount("/keys-one"));
                assertEquals(changes ? 1 : 0, server.getHitCount("/keys-two"));
            }
        }));
    }

    @Test
    void endpointDriftRemainsAnExceptionInsteadOfARejectedAuthorizationOutcome() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            TestClock clock = TestClock.fromInstant(NOW);
            server.script("/tenant/.well-known/openid-configuration", TestHttpsServer.Script.fromSequence(List.of(
                    TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
                            .body(metadata(server, server.uri("/token-one"), server.uri("/jwks"))).build(),
                    TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json")
                            .body(metadata(server, server.uri("/token-two"), server.uri("/jwks"))).build())));
            OidcClient client = lazyClient(server, clock)
                    .jwksSource(StaticJwksSource.fromJwks(assertInstanceOf(JwksParseResult.Succeeded.class, Jwks.fromJsonResult(keySet(false))).getJwks())).build();
            AuthorizationRedirect redirect = client.beginAuthentication();
            InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().clock(clock).build();
            org.junit.jupiter.api.Assertions.assertEquals(PendingAuthorizationSaveResult.SAVED, redirect.getPendingAuthorization().saveToResult(store, "TEST-ONLY-browser"));
            String state = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
            AuthorizationResponse callback = assertInstanceOf(AuthorizationResponseParseResult.Succeeded.class, AuthorizationResponse.fromQueryStringResult("code=TEST-ONLY-code&state=" + state
                    + "&iss=" + URLEncoder.encode(server.uri("/tenant/").toString(), StandardCharsets.UTF_8))).getResponse();
            clock.advance(Duration.ofSeconds(31));
            assertEquals(OAuthException.Reason.METADATA_ENDPOINT_DRIFT, assertThrows(OAuthException.class,
                    () -> client.completeAuthenticationResult(callback, PendingAuthorizationSource.fromStore(store, "TEST-ONLY-browser"),
                            URI.create("https://rp.example/callback"))).getReason());
            assertEquals(2, server.getHitCount("/tenant/.well-known/openid-configuration"));
            assertEquals(0, server.getHitCount("/token-one"));
            assertEquals(0, server.getHitCount("/token-two"));
        }
    }

    @Test
    void storedReferenceVersionIsCheckedAndItsOriginalClaimsSurviveTheRefreshShortcut() {
        OidcSessionReference reference = assertInstanceOf(OidcSessionReferenceParseResult.Succeeded.class, OidcSessionReference.fromSerializedFormResult(serializedReference("1"))).getReference();
        assertEquals(EXACT, reference.continuityClaims().find("iss").map(value -> ((com.revetsec.json.JsonString) value).getValue()).orElseThrow());
        assertEquals("subject", reference.continuityClaims().find("sub").map(value -> ((com.revetsec.json.JsonString) value).getValue()).orElseThrow());
        for (String version : List.of("0", "-1", "2"))
            assertEquals(OidcValidationException.Reason.SESSION_REFERENCE_INVALID, assertInstanceOf(OidcSessionReferenceParseResult.Rejected.class, OidcSessionReference.fromSerializedFormResult(serializedReference(version))).getReason());
        IdTokenValidator validator = new IdTokenValidator(EXACT, "client",
                StaticJwksSource.fromJwks(assertInstanceOf(JwksParseResult.Succeeded.class, Jwks.fromJsonResult(keySet(false))).getJwks()), Set.of(JwsAlgorithm.RS256),
                Set.of(), Set.of(), Duration.ZERO, Duration.ofMinutes(5), CLOCK);
        String compact = token(false);
        IdToken refreshed = validator.validateRefresh(compact, reference, "TEST-ONLY-access", Set.of(),
                Deadline.fromNow(Duration.ofSeconds(2)));
        assertEquals("subject", refreshed.getClaims().getSubject().orElseThrow());
        assertEquals(compact, refreshed.toCompactSerialization());
        assertEquals("subject", UserInfoValidator.signed(compact, EXACT, "client", "subject", JwsAlgorithm.RS256,
                StaticJwksSource.fromJwks(assertInstanceOf(JwksParseResult.Succeeded.class, Jwks.fromJsonResult(keySet(false))).getJwks()), Duration.ZERO, CLOCK,
                OidcObserver.disabledInstance(), Set.of(), Deadline.fromNow(Duration.ofSeconds(2))).find("sub").map(value -> ((com.revetsec.json.JsonString) value).getValue()).orElseThrow());
    }

    @Test
    void tenantPolicyDeadlineChecksSurroundTheApplicationCallback() {
        AtomicInteger predicates = new AtomicInteger();
        OidcIssuerPolicy early = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> {
            predicates.incrementAndGet();
            return true;
        });
        assertEquals(OAuthException.Reason.NETWORK_FAILURE, assertThrows(OAuthException.class,
                () -> early.checkTenant(TENANT, Deadline.fromNow(Duration.ZERO))).getReason());
        assertEquals(0, predicates.get());
        Deadline deadline = Deadline.fromNow(Duration.ofMillis(250));
        OidcIssuerPolicy late = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> {
            predicates.incrementAndGet();
            consumeBudget(deadline);
            return true;
        });
        assertEquals(OAuthException.Reason.NETWORK_FAILURE, assertThrows(OAuthException.class,
                () -> late.checkTenant(TENANT, deadline)).getReason());
        assertEquals(1, predicates.get());
    }

    @Test
    void nonemptyLoginOptionsAndMetadataMethodPoliciesAreIndependentCallerSnapshots() {
        Set<String> scopes = new java.util.HashSet<>(Set.of("profile"));
        Map<String, String> data = new LinkedHashMap<>(Map.of("return", "/owned"));
        OidcAuthenticationOptions options = OidcAuthenticationOptions.builder().scopes(scopes).prompt("login")
                .loginHint("TEST-ONLY-login").applicationData(data).build();
        scopes.clear();
        data.clear();
        assertEquals(Set.of("profile"), options.getScopes().orElseThrow());
        assertEquals("login", options.getPrompt().orElseThrow());
        assertEquals("TEST-ONLY-login", options.getLoginHint().orElseThrow());
        assertEquals(Map.of("return", "/owned"), options.getApplicationData());
        assertThrows(UnsupportedOperationException.class, () -> options.getScopes().orElseThrow().clear());
        assertThrows(UnsupportedOperationException.class, () -> options.getApplicationData().clear());
        Set<String> methods = new java.util.HashSet<>(Set.of("private_key_jwt"));
        OidcProviderMetadata.Builder builder = OidcProviderMetadata.withIssuer(EXACT)
                .authorizationEndpoint(URI.create(EXACT + "/authorize")).tokenEndpoint(URI.create(EXACT + "/token"))
                .jwksUri(URI.create(EXACT + "/jwks"));
        assertSame(builder, builder.tokenEndpointAuthMethodsSupported(methods));
        assertSame(builder, builder.introspectionEndpointAuthMethodsSupported(methods));
        OidcProviderMetadata metadata = builder.build();
        methods.clear();
        assertEquals(Set.of("private_key_jwt"), metadata.oauthMetadata().getTokenEndpointAuthMethodsSupported().orElseThrow());
        assertEquals(Set.of("private_key_jwt"), metadata.getIntrospectionEndpointAuthMethodsSupported().orElseThrow());
        OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> true);
        assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED, assertInstanceOf(OidcProviderMetadataParseResult.Rejected.class, OidcProviderMetadata.fromJsonResult(COMMON, "\ud800", policy)).getReason());
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> userInfoObserverDurationsFitTheActualCallAndFailureIdentityIsPreserved() {
        return Stream.of(false, true).map(fails -> DynamicTest.dynamicTest(fails ? "failure" : "success", () -> {
            try (TestHttpsServer server = TestHttpsServer.start()) {
                AtomicReference<Duration> elapsed = new AtomicReference<>();
                AtomicReference<OAuthException> observedFailure = new AtomicReference<>();
                AtomicInteger entraUses = new AtomicInteger();
                List<String> events = new ArrayList<>();
                OidcObserver observer = new OidcObserver() {
                    @Override public void didUseMicrosoftEntraMultiTenant() { entraUses.incrementAndGet(); }
                    @Override public void willRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri) {
                        if (endpoint == OAuthEndpoint.USERINFO) events.add("will:" + uri);
                    }
                    @Override public void didRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri,
                            @NonNull Integer status, @NonNull Duration duration) {
                        if (endpoint == OAuthEndpoint.USERINFO) { elapsed.set(duration); events.add("success:" + uri + ":" + status); }
                    }
                    @Override public void didFailEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri,
                            @NonNull OAuthException failure, @NonNull Duration duration) {
                        if (endpoint == OAuthEndpoint.USERINFO) { elapsed.set(duration); observedFailure.set(failure); events.add("failure:" + uri); }
                    }
                };
                Authenticated authenticated = authenticate(server, true, observer);
                entraUses.set(0);
                server.script("/userinfo", TestHttpsServer.Script.fromResponse(fails
                        ? TestHttpsServer.Response.withStatus(302).header("Location", "/other").build()
                        : TestHttpsServer.Response.fromJson(200, "{\"sub\":\"subject\"}")));
                long started = System.nanoTime();
                if (fails) {
                    OAuthException failure = assertThrows(OAuthException.class,
                            () -> authenticated.client().fetchUserInfoResult(authenticated.authentication()));
                    assertSame(failure, observedFailure.get());
                } else {
                    assertEquals("subject", assertInstanceOf(OidcUserInfoResult.Succeeded.class, authenticated.client().fetchUserInfoResult(authenticated.authentication())).getUserInfo().getSubject());
                    assertNull(observedFailure.get());
                }
                long total = System.nanoTime() - started;
                assertNotNull(elapsed.get());
                Duration observed = java.util.Objects.requireNonNull(elapsed.get());
                assertFalse(observed.isNegative());
                assertTrue(observed.toNanos() <= total);
                assertEquals(List.of("will:" + server.uri("/userinfo"),
                        (fails ? "failure:" : "success:") + server.uri("/userinfo") + (fails ? "" : ":200")), events);
                assertEquals(1, server.getHitCount("/userinfo"));
                assertEquals(1, entraUses.get());
            }
        }));
    }

    @Test
    void anExpiredEntraUserInfoDeadlineRejectsBeforeCredentialInspectionOrObserverDelivery() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            Authenticated authenticated = authenticate(server, true, OidcObserver.disabledInstance());
            AtomicInteger reads = new AtomicInteger();
            AtomicInteger callbacks = new AtomicInteger();
            Clock clock = new Clock() {
                @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
                @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
                @Override public @NonNull Instant instant() { reads.incrementAndGet(); return NOW; }
            };
            UserInfoEndpoint endpoint = new UserInfoEndpoint(
                    HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false),
                    Duration.ofSeconds(2), clock, new OidcObserver() {
                        @Override public void willRequestEndpoint(@NonNull OAuthEndpoint kind, @NonNull URI uri) { callbacks.incrementAndGet(); }
                    }, new UserInfoAttemptGate(Duration.ofSeconds(1), System::nanoTime));
            assertEquals(OAuthException.Reason.NETWORK_FAILURE, assertThrows(OAuthException.class,
                    () -> endpoint.fetch(authenticated.metadata(), authenticated.keys(), authenticated.authentication(), "client", null,
                            Duration.ZERO, Set.of(), Deadline.fromNow(Duration.ZERO), authenticated.policy())).getReason());
            assertEquals(0, reads.get());
            assertEquals(0, callbacks.get());
            assertEquals(0, server.getHitCount("/userinfo"));
        }
    }

    @Test
    void theEntraUserInfoDeadlineIncludesApplicationResponseObservers() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            Authenticated authenticated = authenticate(server, true, OidcObserver.disabledInstance());
            server.script("/userinfo", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200, "{\"sub\":\"subject\"}")));
            AtomicReference<Deadline> deadline = new AtomicReference<>();
            AtomicInteger callbacks = new AtomicInteger();
            UserInfoEndpoint endpoint = new UserInfoEndpoint(
                    HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false),
                    Duration.ofSeconds(2), CLOCK, new OidcObserver() {
                        @Override public void didRequestEndpoint(@NonNull OAuthEndpoint kind, @NonNull URI uri,
                                @NonNull Integer status, @NonNull Duration elapsed) {
                            callbacks.incrementAndGet();
                            Deadline current = java.util.Objects.requireNonNull(deadline.get());
                            consumeBudget(current);
                        }
                    }, new UserInfoAttemptGate(Duration.ofSeconds(1), System::nanoTime));
            Deadline current = Deadline.fromNow(Duration.ofMillis(250));
            deadline.set(current);
            assertEquals(OAuthException.Reason.NETWORK_FAILURE, assertThrows(OAuthException.class,
                    () -> endpoint.fetch(authenticated.metadata(), authenticated.keys(), authenticated.authentication(), "client", null,
                            Duration.ZERO, Set.of(), current, authenticated.policy())).getReason());
            assertEquals(1, callbacks.get());
            assertEquals(1, server.getHitCount("/userinfo"));
        }
    }

    @Test
    void idTokenHashesAcceptTheAsciiEndpointAndRejectTheFirstNonAsciiCodeUnit() throws Exception {
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(new byte[]{0x7f});
        String expected = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(java.util.Arrays.copyOfRange(digest, 0, 16));
        assertEquals(expected, IdTokenHash.hash(JwsAlgorithm.RS256, "\u007f"));
        assertThrows(IllegalArgumentException.class, () -> IdTokenHash.hash(JwsAlgorithm.RS256, "\u0080"));
        assertThrows(IllegalArgumentException.class, () -> IdTokenHash.hash(JwsAlgorithm.RS256, "\ud800"));
    }

    @Test
    void reducedObserverUrisRemoveEmptyAndNonemptyUserInfoWithoutChangingEscapedPaths() {
        assertEquals(URI.create("https://issuer.example:8443/a%2Fb"), OidcProviderCache.reduced(
                URI.create("https://user:TEST-ONLY-secret@issuer.example:8443/a%2Fb?token=TEST-ONLY-query#fragment")));
        assertEquals(URI.create("https://issuer.example/a"), OidcProviderCache.reduced(URI.create("https://@issuer.example/a")));
        assertThrows(IllegalArgumentException.class, () -> OidcProviderCache.reduced(URI.create("mailto:TEST-ONLY-user@example.test")));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> discoveryObserversReceiveTheActualElapsedTimeAndFailureInstance() {
        return Stream.of(false, true).map(fails -> DynamicTest.dynamicTest(fails ? "transport rejection" : "success", () -> {
            try (TestHttpsServer server = TestHttpsServer.start()) {
                AtomicLong nanos = new AtomicLong(100);
                List<String> events = new ArrayList<>();
                AtomicReference<OAuthException> observedFailure = new AtomicReference<>();
                URI issuer = server.uri("/tenant/");
                URI discovery = server.uri("/tenant/.well-known/openid-configuration");
                OidcObserver observer = new OidcObserver() {
                    @Override public void willRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri) {
                        events.add("will:" + endpoint + ":" + uri);
                    }
                    @Override public void didRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri,
                            @NonNull Integer status, @NonNull Duration elapsed) {
                        events.add("success:" + endpoint + ":" + uri + ":" + status + ":" + elapsed.toNanos());
                    }
                    @Override public void didFailEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri,
                            @NonNull OAuthException failure, @NonNull Duration elapsed) {
                        observedFailure.set(failure);
                        events.add("failure:" + endpoint + ":" + uri + ":" + elapsed.toNanos());
                    }
                };
                String metadata = "{\"issuer\":" + JsonText.string(issuer.toString())
                        + ",\"authorization_endpoint\":\"https://issuer.example/authorize\""
                        + ",\"token_endpoint\":\"https://issuer.example/token\",\"jwks_uri\":\"https://issuer.example/jwks\""
                        + ",\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"]"
                        + ",\"id_token_signing_alg_values_supported\":[\"RS256\"]}";
                server.script(discovery.getPath(), exchange -> {
                    nanos.set(107);
                    exchange.send(fails ? TestHttpsServer.Response.withStatus(302).header("Location", "/other").build()
                            : TestHttpsServer.Response.withStatus(200).header("Content-Type", "application/json").body(metadata).build());
                });
                OidcProviderCache<OidcProviderMetadata> cache = new OidcProviderCache<>(issuer,
                        HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false),
                        OutboundUriPolicy.defaultInstance(), false, Duration.ofSeconds(2), CLOCK, observer,
                        Duration.ofSeconds(30), Duration.ofSeconds(30), Duration.ofSeconds(60), Duration.ofSeconds(30),
                        value -> value, nanos::get);
                if (fails) {
                    OAuthException failure = assertThrows(OAuthException.class,
                            () -> cache.get(Deadline.fromNow(Duration.ofSeconds(5))));
                    assertSame(failure, observedFailure.get());
                    assertEquals(List.of("will:METADATA:" + discovery, "failure:METADATA:" + discovery + ":7"), events);
                } else {
                    OidcProviderMetadata first = cache.get(Deadline.fromNow(Duration.ofSeconds(5)));
                    assertSame(first, cache.get(Deadline.fromNow(Duration.ofSeconds(5))));
                    assertEquals(issuer.toString(), first.getIssuer());
                    assertEquals(List.of("will:METADATA:" + discovery, "success:METADATA:" + discovery + ":200:7"), events);
                    assertNull(observedFailure.get());
                }
                assertEquals(1, server.getHitCount(discovery.getPath()));
            }
        }));
    }

    private static @NonNull String keySet(boolean entra) {
        return TestJwk.withFixture(TestJwk.Fixture.IDP_SIGNING_RSA_2048)
                .kid("rc1").alg("RS256").issuer(entra ? TEMPLATE : null).toKeySetJson();
    }

    private static @NonNull OidcProviderCache<@NonNull OidcProviderMetadata> cache(
            @NonNull TestHttpsServer server, @NonNull Clock clock, @NonNull AtomicLong nanos) {
        return new OidcProviderCache<>(server.uri("/tenant/"),
                HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false),
                OutboundUriPolicy.defaultInstance(), false, Duration.ofSeconds(2), clock, OidcObserver.disabledInstance(),
                Duration.ofSeconds(30), Duration.ofSeconds(30), Duration.ofSeconds(60), Duration.ofSeconds(30),
                value -> value, nanos::get);
    }

    private static @NonNull IdTokenValidator entraValidator(@NonNull Clock clock, @NonNull OidcIssuerPolicy policy) {
        return new IdTokenValidator(COMMON, "client", StaticJwksSource.fromJwks(assertInstanceOf(JwksParseResult.Succeeded.class, Jwks.fromJsonResult(keySet(true))).getJwks()),
                Set.of(JwsAlgorithm.RS256), Set.of(), Set.of(), Duration.ZERO, Duration.ofMinutes(5), clock,
                OidcObserver.disabledInstance(), false, policy);
    }

    private static @NonNull String metadata(@NonNull URI issuer) {
        return "{\"issuer\":" + JsonText.string(issuer.toString())
                + ",\"authorization_endpoint\":\"https://issuer.example/authorize\""
                + ",\"token_endpoint\":\"https://issuer.example/token\",\"jwks_uri\":\"https://issuer.example/jwks\""
                + ",\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"]"
                + ",\"id_token_signing_alg_values_supported\":[\"RS256\"]}";
    }

    private static @NonNull String metadata(@NonNull TestHttpsServer server, @NonNull URI token, @NonNull URI keys) {
        return metadata(server.uri("/tenant/"))
                .replace(JsonText.string("https://issuer.example/authorize"), JsonText.string(server.uri("/authorize").toString()))
                .replace(JsonText.string("https://issuer.example/token"), JsonText.string(token.toString()))
                .replace(JsonText.string("https://issuer.example/jwks"), JsonText.string(keys.toString()));
    }

    private static OidcClient.@NonNull Builder lazyClient(@NonNull TestHttpsServer server, @NonNull Clock clock) {
        return OidcClient.withIssuer(server.uri("/tenant/").toString()).clientId("client")
                .redirectUri(URI.create("https://rp.example/callback")).clock(clock).httpClient(TestTls.httpClient())
                .minimumTimeToLive(Duration.ofSeconds(30)).defaultTimeToLive(Duration.ofSeconds(30))
                .maximumTimeToLive(Duration.ofSeconds(60)).discoveryCooldown(Duration.ofSeconds(1));
    }

    private static @NonNull String serializedReference(@NonNull String version) {
        return "{\"v\":" + version + ",\"client_id\":\"client\",\"claims\":{\"iss\":" + JsonText.string(EXACT)
                + ",\"sub\":\"subject\",\"aud\":\"client\",\"iat\":" + NOW.getEpochSecond()
                + "},\"nonce_digest\":" + JsonText.string(OidcSessionReference.digest(NONCE)) + "}";
    }

    private record Authenticated(@NonNull OidcClient client, @NonNull OidcAuthentication authentication,
            @NonNull OidcProviderMetadata metadata, @NonNull StaticJwksSource keys, @NonNull OidcIssuerPolicy policy) { }

    private static @NonNull Authenticated authenticate(@NonNull TestHttpsServer server, boolean entra,
            @NonNull OidcObserver observer) throws Exception {
        String issuer = entra ? COMMON : EXACT;
        OidcProviderMetadata metadata = OidcProviderMetadata.withIssuer(issuer).authorizationEndpoint(server.uri("/authorize"))
                .tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks")).userInfoEndpoint(server.uri("/userinfo")).build();
        StaticJwksSource keys = StaticJwksSource.fromJwks(assertInstanceOf(JwksParseResult.Succeeded.class, Jwks.fromJsonResult(keySet(entra))).getJwks());
        OidcIssuerPolicy policy = entra ? OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> true) : OidcIssuerPolicy.exactInstance();
        OidcClient client = OidcClient.withProviderMetadata(metadata).clientId("client").redirectUri(URI.create("https://rp.example/callback"))
                .clock(CLOCK).clockSkew(Duration.ZERO).httpClient(TestTls.httpClient()).jwksSource(keys).issuerPolicy(policy)
                .observer(observer).build();
        AuthorizationRedirect redirect = client.beginAuthentication();
        QueryParameters query = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery());
        String compact = token(entra, query.getValues("nonce").get(0));
        server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
                "{\"access_token\":\"TEST-ONLY-access\",\"token_type\":\"Bearer\",\"expires_in\":300,\"id_token\":" + JsonText.string(compact) + "}")));
        InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().clock(CLOCK).build();
        org.junit.jupiter.api.Assertions.assertEquals(PendingAuthorizationSaveResult.SAVED, redirect.getPendingAuthorization().saveToResult(store, "TEST-ONLY-browser"));
        AuthorizationResponse response = assertInstanceOf(AuthorizationResponseParseResult.Succeeded.class, AuthorizationResponse.fromQueryStringResult("code=TEST-ONLY-code&state=" + query.getValues("state").get(0)
                + "&iss=" + URLEncoder.encode(issuer, StandardCharsets.UTF_8))).getResponse();
        OidcAuthentication authentication = assertInstanceOf(OidcAuthenticationResult.Succeeded.class, client.completeAuthenticationResult(response,
                PendingAuthorizationSource.fromStore(store, "TEST-ONLY-browser"), URI.create("https://rp.example/callback"))).getAuthentication();
        return new Authenticated(client, authentication, metadata, keys, policy);
    }

    private static <T> @NonNull T onFreshCaller(@NonNull Supplier<@NonNull T> operation) {
        FutureTask<T> task = new FutureTask<>(operation::get);
        Thread thread = new Thread(task, "rc1-oidc-independent-caller");
        thread.setDaemon(true);
        thread.start();
        try {
            return assertDoesNotThrow(() -> task.get(2, TimeUnit.SECONDS));
        } finally {
            task.cancel(true);
        }
    }

    private static @NonNull ExecutorService callers(int count) {
        return Executors.newFixedThreadPool(count, operation -> {
            Thread thread = new Thread(operation, "rc1-oidc-caller");
            thread.setDaemon(true);
            return thread;
        });
    }

    private static void consumeBudget(@NonNull Deadline deadline) {
        long started = System.nanoTime();
        long watchdog = Duration.ofSeconds(2).toNanos();
        while (!deadline.isExpired() && System.nanoTime() - started < watchdog) Thread.onSpinWait();
    }

    private static @NonNull String token(boolean entra) {
        return token(entra, NONCE);
    }

    private static @NonNull String token(boolean entra, @NonNull String nonce) {
        Map<String, String> claims = new LinkedHashMap<>();
        claims.put("iss", JsonText.string(entra ? "https://login.microsoftonline.com/" + TENANT + "/v2.0" : EXACT));
        claims.put("sub", "\"subject\"");
        claims.put("aud", "\"client\"");
        claims.put("iat", Long.toString(NOW.getEpochSecond()));
        claims.put("exp", Long.toString(NOW.plusSeconds(300).getEpochSecond()));
        claims.put("nonce", JsonText.string(nonce));
        if (entra) claims.put("tid", JsonText.string(TENANT));
        return TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("rc1")
                .payload(JsonText.object(new ArrayList<>(claims.entrySet())))
                .sign(TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
    }
}
