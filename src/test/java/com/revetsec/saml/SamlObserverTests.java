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

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class SamlObserverTests {
    private static final @NonNull Clock CLOCK = Clock.fixed(Instant.parse("2026-10-09T00:01:00Z"),
            ZoneOffset.UTC);
    private static final @NonNull String SP = "https://sp.example.test/saml";
    private static final @NonNull String IDP = "https://idp.example.test/saml";

    @Test void recordsOneRedactedPairForEachPreparationResult() throws Exception {
        KeyPair key = rsa();
        RecordingObserver observer = new RecordingObserver();
        SamlServiceProvider sp = serviceProvider(observer);
        SamlIdentityProvider idp = SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-secret")
                .postSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();

        assertInstanceOf(SamlAuthenticationRequestResult.Rejected.class, sp.beginAuthenticationResult(idp));
        assertInstanceOf(SamlAuthenticationRequestResult.PostPrepared.class,
                sp.beginPostAuthenticationResult(idp));
        assertEquals(List.of("will:BEGIN_AUTHENTICATION", "did:BEGIN_AUTHENTICATION:REJECTED",
                "will:BEGIN_POST_AUTHENTICATION", "did:BEGIN_POST_AUTHENTICATION:SUCCEEDED"), observer.events);
        assertTrue(observer.elapsed.stream().allMatch(value -> !value.isNegative()));
        assertTrue(observer.events.stream().noneMatch(value -> value.contains("tenant-secret")));
    }

    @Test void completionReportsIndeterminateStoreWithoutCallingItARejection() throws Exception {
        KeyPair key = rsa();
        RecordingObserver observer = new RecordingObserver();
        SamlServiceProvider sp = serviceProvider(observer);
        SamlIdentityProvider idp = idp(key);
        SamlPostBindingMessage message = message("<untrusted/>", "relay");
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("saml-observer"))
                .clock(CLOCK).build();
        PendingSamlAuthenticationStore uncertainStore = new PendingSamlAuthenticationStore() {
            @Override public @NonNull SamlPendingSaveResult save(@NonNull String browserBinding,
                    @NonNull String relayStateHandle, @NonNull String sealedRecord,
                    @NonNull Instant expiresAt, @NonNull Duration remainingBudget) {
                throw new IllegalStateException("secret backend text");
            }
            @Override public @NonNull SamlPendingConsumeResult consume(@NonNull String browserBinding,
                    @NonNull String relayStateHandle, @NonNull Duration remainingBudget) {
                throw new IllegalStateException("secret backend text");
            }
        };
        PendingSamlAuthenticationSource source = PendingSamlAuthenticationSource.fromStore(uncertainStore,
                "browser-secret", sealer, "observer-context");
        assertInstanceOf(SamlAuthenticationResult.Indeterminate.class,
                sp.completeAuthenticationResult(message, source, idp));
        assertEquals(List.of("will:COMPLETE_AUTHENTICATION", "did:COMPLETE_AUTHENTICATION:INDETERMINATE"),
                observer.events);
        assertTrue(observer.events.stream().noneMatch(value -> value.contains("secret")));
    }

    @Test void throwingHooksCannotChangeResultOrEscapeAsCredentialText() throws Exception {
        KeyPair key = rsa();
        SamlObserver broken = new SamlObserver() {
            @Override public void willHandleOperation(@NonNull Operation operation) {
                throw new IllegalStateException("secret from start hook");
            }
            @Override public void didHandleOperation(@NonNull Operation operation, @NonNull Outcome outcome,
                    @NonNull Duration elapsed) {
                throw new IllegalStateException("secret from terminal hook");
            }
        };
        SamlServiceProvider sp = serviceProvider(broken);
        SamlIdentityProvider idp = idp(key);
        assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class, sp.beginAuthenticationResult(idp));
        assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class, sp.beginAuthenticationResult(idp));

        SamlServiceProvider reset = SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).observer(broken).observer(null).build();
        assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class, reset.beginAuthenticationResult(idp));
    }

    @Test @SuppressWarnings("NullAway") // Deliberate required-argument misuse.
    void unexpectedRuntimeFailureIsObservedThenRethrownWithoutItsMessage() throws Exception {
        KeyPair key = rsa();
        RecordingObserver observer = new RecordingObserver();
        SamlServiceProvider sp = serviceProvider(observer);
        NullPointerException failure = assertThrows(NullPointerException.class,
                () -> sp.beginAuthenticationResult(null));
        assertEquals(List.of("will:BEGIN_AUTHENTICATION", "did:BEGIN_AUTHENTICATION:FAILED"), observer.events);
        assertTrue(failure.getMessage() == null || !failure.getMessage().contains("tenant-secret"));
        assertInstanceOf(SamlAuthenticationRequestResult.Prepared.class, sp.beginAuthenticationResult(idp(key)));
    }

    private static @NonNull SamlServiceProvider serviceProvider(@NonNull SamlObserver observer) {
        return SamlServiceProvider.withEntityId(SP)
                .assertionConsumerServiceUrl(URI.create("https://sp.example.test/acs"))
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 4))
                .clock(CLOCK).observer(observer).build();
    }

    private static @NonNull SamlIdentityProvider idp(@NonNull KeyPair key) {
        return SamlIdentityProvider.withEntityId(IDP).connectionId("tenant-secret")
                .redirectSingleSignOnService(URI.create("https://idp.example.test/sso"))
                .signingKeys(List.of(key.getPublic())).build();
    }

    private static @NonNull SamlPostBindingMessage message(@NonNull String xml, @NonNull String relay) {
        String encoded = Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8))
                .replace("+", "%2B").replace("/", "%2F").replace("=", "%3D");
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromFormBodyResult(("SAMLResponse=" + encoded + "&RelayState=" + relay)
                        .getBytes(StandardCharsets.UTF_8), List.of("application/x-www-form-urlencoded"), null))
                .getMessage();
    }

    private static @NonNull KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static final class RecordingObserver implements SamlObserver {
        private final @NonNull List<@NonNull String> events = new ArrayList<>();
        private final @NonNull List<@NonNull Duration> elapsed = new ArrayList<>();
        @Override public void willHandleOperation(@NonNull Operation operation) {
            events.add("will:" + operation);
        }
        @Override public void didHandleOperation(@NonNull Operation operation, @NonNull Outcome outcome,
                @NonNull Duration duration) {
            events.add("did:" + operation + ":" + outcome);
            elapsed.add(duration);
        }
    }
}
