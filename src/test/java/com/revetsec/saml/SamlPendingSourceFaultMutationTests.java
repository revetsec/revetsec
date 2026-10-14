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
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

final class SamlPendingSourceFaultMutationTests {
    private static final @NonNull String SP = "https://sp.example.test/saml";
    private static final @NonNull String IDP = "https://idp.example.test/saml";
    private static final @NonNull URI ACS = URI.create("https://sp.example.test/acs");
    private static final @NonNull URI LOGOUT = URI.create("https://sp.example.test/logout");
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-10-09T00:01:00Z"), ZoneOffset.UTC);

    private enum StoreOutcome { MISSING_RELAY, THROWS, NULL, MISSING, UNAVAILABLE, INDETERMINATE }

    @Test void loginPendingStoreFaultsReturnTypedResultsBeforeXmlOrReplay() throws Exception {
        KeyPair key = rsa();
        AtomicInteger replayWrites = new AtomicInteger();
        SamlServiceProvider sp = serviceProvider(key, replayWrites);
        SamlIdentityProvider idp = identityProvider(key);
        StateSealer sealer = sealer();
        for (StoreOutcome outcome : StoreOutcome.values()) {
            AtomicInteger consumes = new AtomicInteger();
            PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromStore(
                    store(outcome, consumes), "browser", sealer, "pending-fault");
            SamlAuthenticationResult result = sp.completeAuthenticationResult(
                    post(outcome == StoreOutcome.MISSING_RELAY ? null : "relay"), source, idp);
            switch (outcome) {
                case MISSING_RELAY, MISSING -> assertEquals(SamlAuthenticationResult.Reason.PENDING,
                        assertInstanceOf(SamlAuthenticationResult.Rejected.class, result).getReason());
                case UNAVAILABLE -> assertInstanceOf(SamlAuthenticationResult.Unavailable.class, result);
                case THROWS, NULL, INDETERMINATE ->
                        assertInstanceOf(SamlAuthenticationResult.Indeterminate.class, result);
            }
            assertEquals(outcome == StoreOutcome.MISSING_RELAY ? 0 : 1, consumes.get(), outcome.name());
            assertEquals(0, replayWrites.get(), outcome.name());
        }
    }

    @Test void logoutPendingStoreFaultsReturnTypedResultsBeforeSessionOrReplay() throws Exception {
        KeyPair key = rsa();
        AtomicInteger replayWrites = new AtomicInteger();
        SamlServiceProvider sp = serviceProvider(key, replayWrites);
        SamlIdentityProvider idp = identityProvider(key);
        StateSealer sealer = sealer();
        for (StoreOutcome outcome : StoreOutcome.values()) {
            AtomicInteger consumes = new AtomicInteger();
            PendingSamlLogoutSource source = PendingSamlLogoutSource.fromStore(
                    store(outcome, consumes), "browser", sealer, "pending-fault");
            SamlLogoutResult result = sp.completeLogoutResult(
                    redirect(key, outcome == StoreOutcome.MISSING_RELAY ? null : "relay"), source, idp);
            switch (outcome) {
                case MISSING_RELAY, MISSING -> assertInstanceOf(SamlLogoutResult.Rejected.class, result);
                case UNAVAILABLE -> assertInstanceOf(SamlLogoutResult.Unavailable.class, result);
                case THROWS, NULL, INDETERMINATE ->
                        assertInstanceOf(SamlLogoutResult.Indeterminate.class, result);
            }
            assertEquals(outcome == StoreOutcome.MISSING_RELAY ? 0 : 1, consumes.get(), outcome.name());
            assertEquals(0, replayWrites.get(), outcome.name());
        }
    }

    private static @NonNull PendingSamlAuthenticationStore store(@NonNull StoreOutcome outcome,
            @NonNull AtomicInteger consumes) {
        return new PendingSamlAuthenticationStore() {
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String browserBinding,
                    @NonNull String relayStateHandle, @NonNull String sealedRecord,
                    @NonNull Instant expiresAt, @NonNull Duration remaining) {
                throw new AssertionError("completion must not save pending state");
            }

            @SuppressWarnings("NullAway") // Deliberately simulate a broken application store.
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
                    @NonNull String relayStateHandle, @NonNull Duration remaining) {
                consumes.incrementAndGet();
                return switch (outcome) {
                    case THROWS -> throw new IllegalStateException("store failed");
                    case NULL -> null;
                    case MISSING -> SamlPendingConsumeResult.Missing.INSTANCE;
                    case UNAVAILABLE -> SamlPendingConsumeResult.Unavailable.INSTANCE;
                    case INDETERMINATE -> SamlPendingConsumeResult.Indeterminate.INSTANCE;
                    case MISSING_RELAY -> throw new AssertionError("missing relay must not consume");
                };
            }

            @Override public @NonNull SamlPendingConsumeResult consumeIfMatches(@NonNull String browserBinding,
                    @NonNull String relayStateHandle, @NonNull Predicate<@NonNull String> sealedRecordMatches,
                    @NonNull Duration remaining) {
                // This fault provider never claims to have removed a record.
                return consume(browserBinding, relayStateHandle, remaining);
            }
        };
    }

    private static @NonNull SamlServiceProvider serviceProvider(@NonNull KeyPair key,
            @NonNull AtomicInteger replayWrites) {
        SamlReplayCache replay = (replayKey, expiresAt, remaining) -> {
            replayWrites.incrementAndGet();
            return SamlReplayCache.MarkResult.MARKED;
        };
        return SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(ACS)
                .singleLogoutServiceUrl(LOGOUT).signingPrivateKey(key.getPrivate())
                .replayCache(replay).clock(CLOCK).build();
    }

    private static @NonNull SamlIdentityProvider identityProvider(@NonNull KeyPair key) {
        return SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-one")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
    }

    private static @NonNull StateSealer sealer() {
        return StateSealer.withActiveKey(TestSealers.fixedKey("pending-fault"))
                .clock(CLOCK).build();
    }

    private static @NonNull SamlPostBindingMessage post(@Nullable String relay) {
        String body = "SAMLResponse=PGEvPg%3D%3D" + (relay == null ? "" : "&RelayState=" + relay);
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(body.getBytes(StandardCharsets.UTF_8),
                        List.of("application/x-www-form-urlencoded"), null)).getMessage();
    }

    private static @NonNull SamlRedirectBindingMessage redirect(@NonNull KeyPair key,
            @Nullable String relay) {
        URI signed = Objects.requireNonNull(SamlRedirectLogout.response(LOGOUT, IDP, "_response",
                "_request", relay, CLOCK.instant(), SamlLogoutStatus.SUCCESS, key.getPrivate()));
        return assertInstanceOf(SamlRedirectBindingParseResult.Parsed.class,
                SamlRedirectBindingMessage.fromRawQueryResult(
                        Objects.requireNonNull(signed.getRawQuery()))).getMessage();
    }

    private static @NonNull KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }
}
