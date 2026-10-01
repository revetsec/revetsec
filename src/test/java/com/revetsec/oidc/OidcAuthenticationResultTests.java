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

import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.jose.*;
import com.revetsec.oauth.*;
import com.revetsec.testing.*;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws.Algorithm;
import com.revetsec.json.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import org.jspecify.annotations.Nullable;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OidcAuthenticationResultTests {
    private static final URI CALLBACK = URI.create("https://rp.example/callback");
    private static final Instant NOW = Instant.parse("2026-09-29T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final String ACCESS = "TEST-ONLY-access-sentinel";
    private static final String REFRESH = "TEST-ONLY-refresh-sentinel";
    private static final String CODE = "TEST-ONLY-code-sentinel";

    @Test
    void successRunsOnceAndAtomicReplayReleasesNoAuthentication() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            AtomicInteger completed = new AtomicInteger();
            OidcClient client = builder(server).observer(new OidcObserver() {
                @Override public void didCompleteAuthentication() { completed.incrementAndGet(); }
            }).build();
            AuthorizationRedirect redirect = client.beginAuthentication();
            String token = sign(claims(server, nonce(redirect)), false);
            respond(server, "/token", 200, "application/json", response(token, "Bearer"));
            InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.builder().clock(CLOCK).build();
            redirect.getPendingAuthorization().saveTo(store, "browser");
            PendingAuthorizationSource source = PendingAuthorizationSource.fromStore(store, "browser");
            OidcAuthenticationResult.Succeeded success = assertInstanceOf(OidcAuthenticationResult.Succeeded.class,
                    client.completeAuthenticationResult(callback(redirect), source, CALLBACK));
            assertEquals("subject", success.getAuthentication().getSubject());
            assertEquals(ACCESS, success.getAuthentication().getTokens().getAccessToken().getValue());
            assertRedacted(success.toString(), List.of(token, ACCESS, REFRESH, CODE, "subject"));
            OidcAuthenticationResult.RejectedAuthorization replay = assertInstanceOf(OidcAuthenticationResult.RejectedAuthorization.class,
                    client.completeAuthenticationResult(callback(redirect), source, CALLBACK));
            assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_NOT_FOUND, replay.getReason());
            assertEquals(1, server.getRequests().size()); assertEquals(1, completed.get());
        }
    }

    @TestFactory
    Stream<DynamicTest> rejectedIdTokensNeverReleaseEndpointTokensOrIdentity() {
        return Stream.of("expiry", "nonce", "signature").map(kind -> DynamicTest.dynamicTest(kind, () -> {
            try (TestHttpsServer server = TestHttpsServer.start()) {
                AtomicInteger rejected = new AtomicInteger();
                OidcClient client = builder(server).clockSkew(Duration.ZERO).observer(new OidcObserver() {
                    @Override public void didRejectIdToken(OidcValidationException failure) { rejected.incrementAndGet(); }
                }).build();
                AuthorizationRedirect redirect = client.beginAuthentication();
                Map<String, String> claims = claims(server, nonce(redirect));
                if (kind.equals("expiry")) claims.put("exp", Long.toString(NOW.getEpochSecond()));
                if (kind.equals("nonce")) claims.put("nonce", "\"TEST-ONLY-wrong-nonce\"");
                String token = sign(claims, kind.equals("signature"));
                respond(server, "/token", 200, "application/json", response(token, "Bearer"));
                OidcAuthenticationResult.RejectedIdToken failure = assertInstanceOf(OidcAuthenticationResult.RejectedIdToken.class,
                        client.completeAuthenticationResult(callback(redirect), sealed(redirect), CALLBACK));
                OidcValidationException.Reason expected = switch (kind) {
                    case "expiry" -> OidcValidationException.Reason.EXPIRED;
                    case "nonce" -> OidcValidationException.Reason.NONCE_MISMATCH;
                    default -> OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID;
                };
                assertEquals(expected, failure.getReason());
                if (kind.equals("nonce")) assertTrue(failure.getJoseReason().isEmpty());
                else assertTrue(failure.getJoseReason().isPresent());
                assertRedacted(failure.toString(), List.of(token, ACCESS, REFRESH, CODE, nonce(redirect), "subject"));
                assertEquals(1, rejected.get()); assertEquals(1, server.getRequests().size());
            }
        }));
    }

    @Test
    void denialStillRequiresBrowserBindingAndProviderFailuresRemainExceptions() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            OidcClient client = builder(server).build();
            AuthorizationRedirect redirect = client.beginAuthentication();
            String state = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
            PendingAuthorizationSource source = sealed(redirect);
            assertEquals(OAuthException.Reason.STATE_MISMATCH, assertInstanceOf(OidcAuthenticationResult.RejectedAuthorization.class,
                    client.completeAuthenticationResult(AuthorizationResponse.fromQueryString("state=wrong&error=access_denied"), source, CALLBACK)).getReason());
            assertInstanceOf(OidcAuthenticationResult.Denied.class,
                    client.completeAuthenticationResult(AuthorizationResponse.fromQueryString("state=" + state + "&error=access_denied"), source, CALLBACK));
            assertEquals(0, server.getRequests().size());
            assertThrows(AuthorizationErrorException.class, () -> client.completeAuthenticationResult(
                    AuthorizationResponse.fromQueryString("state=" + state + "&error=temporarily_unavailable"), source, CALLBACK));
            respond(server, "/token", 503, "application/json", "{\"error\":\"temporarily_unavailable\"}");
            assertThrows(OAuthErrorResponseException.class, () -> client.completeAuthenticationResult(callback(redirect), source, CALLBACK));
            assertEquals(1, server.getRequests().size());
        }
    }
	private static void respond(TestHttpsServer server, String path, int status, String mediaType, String body) { server.script(path, TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(status).header("Content-Type", mediaType).body(body.getBytes(StandardCharsets.UTF_8)).build())); }
	private static OidcClient.Builder builder(TestHttpsServer server) {
		return OidcClient.withProviderMetadata(metadata(server)).clientId("client").redirectUri(CALLBACK).clock(CLOCK).httpClient(TestTls.httpClient()).jsonWebKeySource(keys());
	}
	private static StaticJsonWebKeySource keys() { return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key").alg("RS256").toKeySetJson())); }
	private static OidcProviderMetadata metadata(TestHttpsServer server) { return OidcProviderMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).jwksUri(server.uri("/jwks")).build(); }
	private static PendingAuthorizationSource sealed(AuthorizationRedirect redirect) { StateSealer sealer = TestSealers.fromFixedKey(); return PendingAuthorizationSource.fromSealedForm(redirect.getPendingAuthorization().toSealedForm(sealer, "oidc"), sealer, "oidc"); }
	private static String nonce(AuthorizationRedirect redirect) throws Exception { return QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("nonce").get(0); }
	private static String callbackQuery(AuthorizationRedirect redirect) throws Exception { return "state=" + QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0) + "&code=" + CODE; }
	private static AuthorizationResponse callback(AuthorizationRedirect redirect) throws Exception { return AuthorizationResponse.fromQueryString(callbackQuery(redirect)); }
	private static Map<String, String> claims(TestHttpsServer server, String nonce) { Map<String, String> claims = new LinkedHashMap<>(); claims.put("iss", JsonText.string(server.getBaseUri().toString())); claims.put("sub", "\"subject\""); claims.put("aud", "\"client\""); claims.put("exp", Long.toString(NOW.plusSeconds(300).getEpochSecond())); claims.put("iat", Long.toString(NOW.getEpochSecond())); claims.put("nonce", JsonText.string(nonce)); return claims; }
	private static String sign(Map<String, String> claims, boolean forged) { return TestJws.withAlgorithm(Algorithm.RS256).kid("key").payload(JsonText.object(new ArrayList<>(claims.entrySet()))).sign(forged ? Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey() : Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()); }
	private static String response(@Nullable String token, String type) { return "{\"access_token\":" + JsonText.string(ACCESS) + ",\"refresh_token\":" + JsonText.string(REFRESH) + ",\"token_type\":" + JsonText.string(type) + (token == null ? "" : ",\"id_token\":" + JsonText.string(token)) + "}"; }
	private static void assertRedacted(String text, List<String> secrets) { for (String secret : secrets) assertFalse(text.contains(secret), "A string form disclosed a sentinel"); }
}
