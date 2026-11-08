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

package com.revetsec.oauth.server;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.internal.Limits;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** CAP-01 public construction rejects incompatible caps before any store or repository callback. */
final class OAuthStoreCapacityProfileTests {
    private static final @NonNull Instant NOW = Instant.parse("2026-10-06T12:00:00Z");
    private static final class CountingStore implements OAuthAuthorizationServerStore {
        int reads, commits, clients;
        @Override public @NonNull OAuthStoreReadResult read(@NonNull OAuthStoreKey key, @NonNull Duration budget) {
            this.reads++; return OAuthStoreReadResult.Unavailable.get();
        }
        @Override public @NonNull OAuthStoreCommitReceipt commit(@NonNull OAuthStoreTransaction transaction, @NonNull Duration budget) {
            this.commits++; return OAuthStoreCommitReceipt.fromRefusal(OAuthStoreCommitStatus.UNAVAILABLE);
        }
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> explicitIssuerAndSealerCapsMustAgreeBeforeAnyIo() {
        List<DynamicTest> tests = new ArrayList<>();
        for (int issuer : List.of(1023, 1024, 3799, 3800, 3801, 16383, 16384, 16385))
            for (int seal : List.of(1024, 3800, 16384)) for (int k : List.of(1, 64))
                tests.add(DynamicTest.dynamicTest("CAP-01/config/" + issuer + '/' + seal + "/K" + k, () -> {
                    var store = new CountingStore(); var s = sealer(k).maximumSealedLength(seal).build();
                    var builder = builder(store, s).maximumStoreRecordBytes(issuer);
                    if (issuer < 1024 || issuer > 16384 || issuer > seal)
                        assertThrows(IllegalArgumentException.class, builder::build);
                    else {
                        var server = assertDoesNotThrow(builder::build);
                        assertEquals(issuer, settings(server).maximumStoreRecordBytes);
                    }
                    assertEquals(0, store.reads); assertEquals(0, store.commits); assertEquals(0, store.clients);
                    assertEquals(seal, SealedStateAccess.get().getMaximumSealedLength(s));
                }));
        return tests;
    }
    @TestFactory @NonNull List<@NonNull DynamicTest> omittedCapsKeepTheGlobal3800Defaults() {
        List<DynamicTest> tests = new ArrayList<>();
        for (int k : List.of(1, 64)) tests.add(DynamicTest.dynamicTest("CAP-01/defaults/K" + k, () -> {
            var store = new CountingStore(); var s = sealer(k).build();
            var server = assertDoesNotThrow(() -> builder(store, s).build());
            assertEquals(3800, SealedStateAccess.get().getMaximumSealedLength(s));
            assertEquals(3800, settings(server).maximumStoreRecordBytes);
            assertEquals(3800, Limits.STATE_SEALER_MAXIMUM_SEALED_LENGTH.getDefaultIntValue());
            assertEquals(3800, Limits.AS_MAXIMUM_STORE_RECORD_BYTES.getDefaultIntValue());
            assertEquals(0, store.reads); assertEquals(0, store.commits); assertEquals(0, store.clients);
        }));
        return tests;
    }
    private static StateSealer.@NonNull Builder sealer(int k) {
        return StateSealer.withActiveKey(SealingKey.fromBase64("k".repeat(k), "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="))
                .clock(Clock.fixed(NOW, ZoneOffset.UTC));
    }
    private static OAuthAuthorizationServer.@NonNull Builder builder(@NonNull CountingStore store, @NonNull StateSealer s) {
        var key = TestJwk.Fixture.IDP_SIGNING_RSA_2048;
        return OAuthAuthorizationServer.withIssuer("https://issuer.example")
                .authorizationEndpoint(URI.create("https://issuer.example/authorize"))
                .tokenEndpoint(URI.create("https://issuer.example/token"))
                .jwksEndpoint(URI.create("https://issuer.example/jwks"))
                .clientRepository((id, budget) -> { store.clients++; return Optional.empty(); })
                .store(store).stateSealer(s).clock(Clock.fixed(NOW, ZoneOffset.UTC))
                .signingKeys(OAuthIssuerKeyProvider.fromSnapshot(OAuthIssuerKeySnapshot.withActiveKey(
                        OAuthIssuerSigningKey.fromRsaKeyPair("signing", key.getPrivateKey(), key.getPublicKey()))
                        .generation("cap-01").publishedAt(NOW.minusSeconds(120)).build()))
                .resources(Map.of("https://resource.example/mcp", Set.of("read")))
                .grantPolicy((context, budget) -> OAuthAuthorizationDecision.deniedInstance()).acknowledgeUnpatchedRuntime(true);
    }
    private static @NonNull OAuthServerSettings settings(@NonNull OAuthAuthorizationServer server) throws Exception {
        var field = OAuthAuthorizationServer.class.getDeclaredField("settings"); field.setAccessible(true);
        return (OAuthServerSettings) java.util.Objects.requireNonNull(field.get(server));
    }
}
