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

package com.revetsec.oauth;

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import java.net.URI;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/** Operation-specific effect controls: a failure classification never supplies replay permission. */
final class OAuthTemporaryConditionEffectsTests {
    private static final URI CALLBACK = URI.create("https://app.example/callback");

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> consumedRemoteRequestsDoNotRepeatOnTemporaryConditions() {
        return Stream.of("sealed-code", "atomic-code", "refresh", "client-credentials",
                "refresh-429", "refresh-503", "refresh-temporarily-unavailable", "refresh-invalid-grant")
                .map(mode -> DynamicTest.dynamicTest(mode, () -> run(mode)));
    }

    private static void run(@NonNull String mode) throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            AtomicInteger requests = new AtomicInteger();
            AtomicInteger committed = new AtomicInteger();
            server.script("/token", exchange -> {
                // The real TLS fixture reads the full request before this callback. Record its simulated
                // consumption/rotation before losing the acknowledgement, not just a connection refusal.
                int attempt = requests.incrementAndGet();
                if (attempt == 1) committed.incrementAndGet();
                if (attempt > 1) {
                    exchange.send(TestHttpsServer.Response.fromJson(400, "{\"error\":\"invalid_grant\"}"));
                } else if (mode.equals("refresh-429")) {
                    exchange.send(TestHttpsServer.Response.withStatus(429).header("Retry-After", "1")
                            .header("Content-Type", "application/json").body("{\"error\":\"temporarily_unavailable\"}").build());
                } else if (mode.equals("refresh-503")) {
                    exchange.send(TestHttpsServer.Response.fromJson(503, "{\"error\":\"server_error\"}"));
                } else if (mode.equals("refresh-temporarily-unavailable")) {
                    exchange.send(TestHttpsServer.Response.fromJson(400, "{\"error\":\"temporarily_unavailable\"}"));
                } else if (mode.equals("refresh-invalid-grant")) {
                    exchange.send(TestHttpsServer.Response.fromJson(400, "{\"error\":\"invalid_grant\"}"));
                } else {
                    exchange.getHttpExchange().close();
                }
            });
            OAuthClient client = OAuthClient.withAuthorizationServerMetadata(
                    AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
                            .authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).build())
                    .clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret"))
                    .redirectUri(CALLBACK).httpClient(TestTls.httpClient()).build();
            if (mode.endsWith("code")) {
                PendingAuthorization pending = client.beginAuthorization().getPendingAuthorization();
                PendingAuthorizationSource source;
                if (mode.equals("atomic-code")) {
                    InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().build();
                    assertEquals(PendingAuthorizationSaveResult.SAVED, pending.saveToResult(store, "TEST-ONLY-browser"));
                    source = PendingAuthorizationSource.fromStore(store, "TEST-ONLY-browser");
                } else {
                    var sealer = TestSealers.fromFixedKey();
                    source = PendingAuthorizationSource.fromSealedForm(pending.toSealedForm(sealer, "effect-test"), sealer, "effect-test");
                }
                AuthorizationResponse response = assertInstanceOf(AuthorizationResponseParseResult.Succeeded.class,
                        AuthorizationResponse.fromQueryStringResult("state=" + pending.state() + "&code=TEST-ONLY-code")).getResponse();
                assertLostAcknowledgement(() -> client.completeAuthorizationResult(response, source, CALLBACK));
                if (mode.equals("atomic-code")) {
                    var replay = assertInstanceOf(AuthorizationCompletionResult.Rejected.class,
                            client.completeAuthorizationResult(response, source, CALLBACK));
                    assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_NOT_FOUND, replay.getReason());
                }
            } else if (mode.equals("client-credentials")) {
                assertLostAcknowledgement(() -> client.requestClientCredentialsResult(TokenRequestOptions.builder().build()));
            } else if (mode.equals("refresh-invalid-grant")) {
                // This terminal protocol rejection follows the fixture's simulated consumption.
                // It grants neither a zero-effect conclusion nor permission to replay the old refresh.
                var rejected = assertInstanceOf(OAuthTokenRequestResult.Rejected.class,
                        client.refreshResult(RefreshToken.fromValue("TEST-ONLY-old-refresh"), TokenRequestOptions.builder().build()));
                assertEquals(OAuthEndpointError.INVALID_GRANT, rejected.getError());
            } else {
                assertLostAcknowledgement(() -> client.refreshResult(RefreshToken.fromValue("TEST-ONLY-old-refresh"),
                        TokenRequestOptions.builder().build()));
            }
            assertEquals(1, requests.get(), "one actual credential POST, with no retry-on-flag wrapper");
            assertEquals(1, committed.get(), "known simulated remote consumption happened before failure");
            assertEquals(1, server.getHitCount("/token"));
            var request = server.getRequests("/token").get(0);
            assertEquals("POST", request.getMethod());
            assertTrue(request.getBodyAsString().contains(mode.endsWith("code") ? "grant_type=authorization_code"
                    : mode.equals("client-credentials") ? "grant_type=client_credentials" : "grant_type=refresh_token"));
            assertTrue(request.getScriptFailure().isEmpty(), "fixture did not turn a failed oracle into HTTP500");
        }
    }

    private static void assertLostAcknowledgement(@NonNull Executable action) {
        RevetsecException failure = assertThrows(RevetsecException.class, action);
        assertTrue(failure.isTemporaryCondition());
        assertTrue(failure.getCategory() == ErrorCategory.TRANSPORT || failure.getCategory() == ErrorCategory.REMOTE_ERROR);
        assertFalse(java.util.Objects.requireNonNull(failure.getMessage()).contains("TEST-ONLY"));
        assertFalse(failure.toString().contains("TEST-ONLY"));
    }
}
