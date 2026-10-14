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
import com.revetsec.internal.pem.Pem;
import com.revetsec.testing.TestSealers;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

/** Offline replay of the fixed-key libxmlsec POST logout corpus without Docker. */
final class SamlPostLogoutFixtureTests {
    private static final @NonNull String SP = "https://sp.test/Selftest";
    private static final @NonNull String IDP = "https://idp.scripted-idp.test/";
    private static final @NonNull String SLO = "https://sp.test/logout";
    private static final @NonNull String RELAY = "AAAAAAAAAAAAAAAAAAAAAA";
    private static final @NonNull String CONNECTION = "post-slo-fixtures";
    private static final @NonNull Clock CLOCK = Clock.fixed(
            Instant.parse("2026-09-01T00:01:00Z"), ZoneOffset.UTC);

    @Test void signedRequestNegativesLeaveTheValidSessionAndReplayProtectionIntact() throws Exception {
        Properties corpus = corpus();
        SamlServiceProvider sp = serviceProvider();
        SamlIdentityProvider identityProvider = identityProvider();
        for (String name : corpus.stringPropertyNames().stream().sorted().toList()) {
            if (!name.startsWith("request-") || "request-valid".equals(name)) continue;
            assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                    sp.acceptLogoutRequestResult(message(corpus, name), identityProvider), name);
        }
        SamlPostBindingMessage valid = message(corpus, "request-valid");
        SamlLogoutRequest request = assertInstanceOf(SamlLogoutRequestResult.Accepted.class,
                sp.acceptLogoutRequestResult(valid, identityProvider)).getRequest();
        assertEquals(CONNECTION, request.getIdentityProviderConnectionId());
        assertEquals("minted-user", request.getNameId().getValue());
        assertEquals(List.of("session-123"), request.getSessionIndexes());
        assertInstanceOf(SamlLogoutRequestResult.Rejected.class,
                sp.acceptLogoutRequestResult(valid, identityProvider));
    }

    @Test void signedResponseNegativesPreservePendingUntilTheValidResponseConsumesIt() throws Exception {
        Properties corpus = corpus();
        SamlServiceProvider sp = serviceProvider();
        SamlIdentityProvider identityProvider = identityProvider();
        PendingSamlAuthentication pendingFields = new PendingSamlAuthentication(SP, "_" + "00".repeat(20),
                RELAY, CONNECTION, IDP, SLO, CLOCK.instant().minusSeconds(60), CLOCK.instant().plusSeconds(300));
        StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("post-slo-fixtures"))
                .clock(CLOCK).build();
        PendingSamlLogoutSource pending = PendingSamlLogoutSource.fromSealedForm(
                new PendingSamlLogout(pendingFields).toSealedForm(sealer, "post-slo-fixtures"),
                sealer, "post-slo-fixtures");
        for (String name : corpus.stringPropertyNames().stream().sorted().toList()) {
            if (!name.startsWith("response-") || "response-valid".equals(name)) continue;
            assertInstanceOf(SamlLogoutResult.Rejected.class,
                    sp.completeLogoutResult(message(corpus, name), pending, identityProvider), name);
        }
        SamlPostBindingMessage valid = message(corpus, "response-valid");
        assertInstanceOf(SamlLogoutResult.Succeeded.class, sp.completeLogoutResult(valid, pending, identityProvider));
        assertInstanceOf(SamlLogoutResult.Rejected.class, sp.completeLogoutResult(valid, pending, identityProvider));
    }

    private static @NonNull SamlServiceProvider serviceProvider() throws Exception {
        SamlCredential credential = SamlCredential.fromPem(resource("keys/sp-signing-rsa-2048-key.pem"),
                resource("keys/sp-signing-rsa-2048-cert.pem"));
        return SamlServiceProvider.withEntityId(SP).assertionConsumerServiceUrl(URI.create("https://sp.test/acs"))
                .postSingleLogoutServiceUrl(URI.create(SLO)).signingCredential(credential)
                .replayCache(InMemorySamlReplayCache.withLimit(CLOCK, 8)).clock(CLOCK).build();
    }

    private static @NonNull SamlIdentityProvider identityProvider() throws Exception {
        return SamlIdentityProvider.withEntityId(IDP).connectionId(CONNECTION)
                .redirectSingleSignOnService(URI.create("https://idp.scripted-idp.test/sso"))
                .signingKeys(List.of(Pem.parseCertificate(resource("keys/idp-signing-rsa-2048-cert.pem"))
                        .getPublicKey())).build();
    }

    private static @NonNull Properties corpus() throws Exception {
        Properties corpus = new Properties();
        try (InputStream input = SamlPostLogoutFixtureTests.class.getResourceAsStream(
                "/fixtures/scripted-idp/slo-post-corpus.properties")) {
            if (input == null) throw new IllegalStateException("Missing POST logout fixtures");
            corpus.load(input);
        }
        assertEquals(23, corpus.size());
        return corpus;
    }

    private static @NonNull SamlPostBindingMessage message(@NonNull Properties corpus, @NonNull String name) {
        String body = corpus.getProperty(name);
        if (body == null) throw new IllegalStateException("Missing POST logout case: " + name);
        return assertInstanceOf(SamlPostBindingParseResult.Parsed.class,
                SamlPostBindingMessage.fromLogoutFormBodyResult(body.getBytes(StandardCharsets.US_ASCII),
                        List.of("application/x-www-form-urlencoded"), null), name).getMessage();
    }

    private static @NonNull String resource(@NonNull String name) throws Exception {
        try (InputStream input = SamlPostLogoutFixtureTests.class.getResourceAsStream("/fixtures/" + name)) {
            if (input == null) throw new IllegalStateException("Missing POST logout test credential");
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
