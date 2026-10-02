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

import org.jspecify.annotations.NonNull;

import com.revetsec.StateSealer;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

final class AuthorizationCompletionResultTests {
    private static final URI CALLBACK = URI.create("https://app.example/callback");

    @Test
    void successfulResultConsumesAtomicStateOnceAndReplayDoesNotPost() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            respond(server, 200, "{\"access_token\":\"TEST-ONLY-access\",\"token_type\":\"Bearer\"}");
            OAuthClient client = client(server);
            PendingAuthorization pending = client.beginAuthorization().getPendingAuthorization();
            InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().build();
            pending.saveTo(store, "browser");
            PendingAuthorizationSource source = PendingAuthorizationSource.fromStore(store, "browser");
            AuthorizationResponse response = AuthorizationResponse.fromQueryString("state=" + pending.state() + "&code=TEST-ONLY-code");
            AuthorizationCompletionResult.Succeeded success = assertInstanceOf(AuthorizationCompletionResult.Succeeded.class,
                    client.completeAuthorizationResult(response, source, CALLBACK));
            assertEquals("TEST-ONLY-access", success.getTokens().getAccessToken().getValue());
            assertFalse(success.toString().contains("TEST-ONLY-access"));
            AuthorizationCompletionResult.Rejected replay = assertInstanceOf(AuthorizationCompletionResult.Rejected.class,
                    client.completeAuthorizationResult(response, source, CALLBACK));
            assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_NOT_FOUND, replay.getReason());
            assertEquals(1, server.getRequests().size());
        }
    }

    @Test
    void checkedDenialDoesNotBypassStateIssuerOrRouteAndObserversFireOnce() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            AtomicInteger rejected = new AtomicInteger();
            OAuthClient client = builder(server).observer(new OAuthObserver() {
                @Override public void didRejectCallback(@NonNull OAuthValidationException failure) {
                    rejected.incrementAndGet(); throw new IllegalStateException("TEST-ONLY-hook");
                }
            }).build();
            PendingAuthorization pending = client.beginAuthorization().getPendingAuthorization();
            PendingAuthorizationSource source = sealed(pending);
            AuthorizationCompletionResult.Rejected wrongState = assertInstanceOf(AuthorizationCompletionResult.Rejected.class,
                    client.completeAuthorizationResult(AuthorizationResponse.fromQueryString("state=wrong&error=access_denied"), source, CALLBACK));
            assertEquals(OAuthException.Reason.STATE_MISMATCH, wrongState.getReason());
            assertEquals(1, rejected.get());
            AuthorizationResponse wrongIssuer = AuthorizationResponse.fromQueryString("state=" + pending.state()
                    + "&iss=https%3A%2F%2Fwrong.example&error=access_denied");
            assertEquals(OAuthException.Reason.ISSUER_MISMATCH, assertInstanceOf(AuthorizationCompletionResult.Rejected.class,
                    client.completeAuthorizationResult(wrongIssuer, source, CALLBACK)).getReason());
            AuthorizationResponse denied = AuthorizationResponse.fromQueryString("state=" + pending.state() + "&error=access_denied&error_description=TEST-ONLY-prose");
            assertEquals(OAuthException.Reason.CALLBACK_URI_MISMATCH, assertInstanceOf(AuthorizationCompletionResult.Rejected.class,
                    client.completeAuthorizationResult(denied, source, URI.create("https://app.example/other"))).getReason());
            AuthorizationCompletionResult result = client.completeAuthorizationResult(denied, source, CALLBACK);
            assertInstanceOf(AuthorizationCompletionResult.Denied.class, result);
            assertFalse(result.toString().contains("TEST-ONLY-prose"));
            assertEquals(3, rejected.get()); assertEquals(0, server.getRequests().size());
        }
    }

    @Test
    void providerFailuresAndMetadataDriftRemainExceptions() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            OAuthClient client = client(server);
            PendingAuthorization pending = client.beginAuthorization().getPendingAuthorization();
            PendingAuthorizationSource source = sealed(pending);
            for (String code : java.util.List.of("temporarily_unavailable", "server_error", "invalid_request")) {
                AuthorizationResponse response = AuthorizationResponse.fromQueryString("state=" + pending.state() + "&error=" + code);
                assertEquals(Optional.of(code), assertThrows(AuthorizationErrorException.class,
                        () -> client.completeAuthorizationResult(response, source, CALLBACK)).getErrorCode());
            }
            OAuthClient changed = OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
                    .authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/changed")).build())
                    .clientId("client").clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK).httpClient(TestTls.httpClient()).build();
            AuthorizationResponse response = AuthorizationResponse.fromQueryString("state=" + pending.state() + "&code=TEST-ONLY-code");
            assertEquals(OAuthException.Reason.METADATA_ENDPOINT_DRIFT, assertThrows(OAuthValidationException.class,
                    () -> changed.completeAuthorizationResult(response, source, CALLBACK)).getReason());
            assertEquals(0, server.getRequests().size());
            respond(server, 503, "{\"error\":\"temporarily_unavailable\"}");
            assertTrue(assertThrows(OAuthErrorResponseException.class,
                    () -> client.completeAuthorizationResult(response, source, CALLBACK)).isTransient());
            assertEquals(1, server.getRequests().size());
        }
    }

    private static @NonNull OAuthClient client(@NonNull TestHttpsServer server) { return builder(server).build(); }
    private static OAuthClient.@NonNull Builder builder(@NonNull TestHttpsServer server) {
        return OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
                .authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).build())
                .clientId("client").clientAuthentication(ClientAuthentication.noneInstance()).redirectUri(CALLBACK).httpClient(TestTls.httpClient());
    }
    private static @NonNull PendingAuthorizationSource sealed(@NonNull PendingAuthorization pending) {
        StateSealer sealer = TestSealers.fromFixedKey();
        return PendingAuthorizationSource.fromSealedForm(pending.toSealedForm(sealer, "result-api"), sealer, "result-api");
    }
    private static void respond(@NonNull TestHttpsServer server, int status, @NonNull String body) {
        server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(status)
                .header("Content-Type", "application/json").body(body.getBytes(StandardCharsets.UTF_8)).build()));
    }
}
