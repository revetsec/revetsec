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

import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.internal.Limits;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** Limit and observer contracts found by the fresh RC-1 mutation inventory. */
final class OAuthRc1MutationTests {
    @Test
    void bearerHeaderAcceptsTheExactCredentialAndPrefixLimits() {
        assertInstanceOf(BearerTokenResult.Present.class,
                BearerToken.fromAuthorizationHeaderValuesResult(List.of("BEARER a"), 8192));
        assertInstanceOf(BearerTokenResult.Malformed.class,
                BearerToken.fromAuthorizationHeaderValuesResult(List.of("xxxxxx a"), 8192));
        String credential = "a".repeat(8192);
        String header = "Bearer" + " ".repeat(58) + credential;
        BearerTokenResult.Present result = assertInstanceOf(BearerTokenResult.Present.class,
                BearerToken.fromAuthorizationHeaderValuesResult(List.of(header), 8192));
        assertEquals(credential, result.getToken().value());
        assertInstanceOf(BearerTokenResult.Malformed.class,
                BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer" + " ".repeat(59) + credential), 8192));
        assertInstanceOf(BearerTokenResult.Malformed.class,
                BearerToken.fromAuthorizationHeaderValuesResult(List.of(header + "a"), 8192));
    }

    @Test
    void callbackAcceptsTheExactRawBodyAndQueryByteLimit() {
        int maximum = Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue();
        String query = "a=&".repeat(maximum / 3) + "b=";
        assertEquals(maximum, query.length());
        AuthorizationResponse encoded = AuthorizationResponse.fromQueryString(query);
        assertEquals(maximum / 3, java.util.Objects.requireNonNull(encoded.getParameters().get("a")).size());
        AuthorizationResponse posted = AuthorizationResponse.fromFormBody(query.getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8, null);
        assertEquals(encoded.getParameters(), posted.getParameters());
        assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, assertThrows(OAuthResponseException.class,
                () -> AuthorizationResponse.fromQueryString(query + "c")).getReason());
    }

    @Test
    void callbackCountsCombinedUtf8ParameterBytesAndAggregateAtTheirExactLimits() {
        int parameter = Limits.AUTHORIZATION_RESPONSE_PARAMETER_SIZE.getDefaultIntValue();
        int query = Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue();
        Map<String, List<String>> accepted = new LinkedHashMap<>();
        for (String name : List.of("a", "b", "c", "d")) accepted.put(name, List.of("x".repeat(parameter - 1)));
        AuthorizationResponse response = AuthorizationResponse.fromParameters(accepted, null, AuthorizationRequestOptions.ResponseMode.QUERY);
        assertEquals(4, response.getParameters().size());
        assertEquals(query, response.getParameters().entrySet().stream()
                .mapToInt(entry -> entry.getKey().length() + entry.getValue().get(0).length()).sum());
        accepted.put("e", List.of(""));
        assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, assertThrows(OAuthResponseException.class,
                () -> AuthorizationResponse.fromParameters(accepted, null, AuthorizationRequestOptions.ResponseMode.QUERY)).getReason());
        assertDoesNotThrow(() -> AuthorizationResponse.fromParameters(Map.of("a", List.of("é".repeat((parameter - 2) / 2) + "x")),
                null, AuthorizationRequestOptions.ResponseMode.QUERY));
        assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromParameters(
                Map.of("a", List.of("é".repeat(parameter / 2))), null, AuthorizationRequestOptions.ResponseMode.QUERY));
        assertDoesNotThrow(() -> AuthorizationResponse.fromParameters(Map.of("a".repeat(parameter), List.of("")),
                null, AuthorizationRequestOptions.ResponseMode.QUERY));
    }

    @Test
    void callbackParameterCountsIncludeFormAndQueryValues() {
        int maximum = Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue();
        List<String> values = new ArrayList<>(java.util.Collections.nCopies(maximum, ""));
        AuthorizationResponse response = AuthorizationResponse.fromParameters(Map.of("", values), null,
                AuthorizationRequestOptions.ResponseMode.FORM_POST);
        assertEquals(maximum, java.util.Objects.requireNonNull(response.getParameters().get("")).size());
        Map<String, List<String>> tooManyAcrossNames = new LinkedHashMap<>();
        tooManyAcrossNames.put("", values);
        tooManyAcrossNames.put("a", List.of(""));
        assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromParameters(tooManyAcrossNames, null,
                AuthorizationRequestOptions.ResponseMode.QUERY));
        List<String> nearlyFull = values.subList(0, maximum - 1);
        assertEquals(maximum - 1, java.util.Objects.requireNonNull(AuthorizationResponse.fromParameters(
                Map.of("", nearlyFull), "extra=", AuthorizationRequestOptions.ResponseMode.FORM_POST)
                .getParameters().get("")).size());
        assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromParameters(Map.of("", nearlyFull), "extra=&other=",
                AuthorizationRequestOptions.ResponseMode.FORM_POST));
        assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromParameters(Map.of("", values), "extra=",
                AuthorizationRequestOptions.ResponseMode.FORM_POST));
    }

    @Test
    void callbackLimitsAlsoBoundEmptyValueListsAndCombinedChannels() {
        int maximum = Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue();
        Map<String, List<String>> emptyValues = new LinkedHashMap<>();
        for (int index = 0; index < maximum; index++) emptyValues.put("extra" + index, List.of());
        assertEquals(maximum, AuthorizationResponse.fromParameters(emptyValues, null,
                AuthorizationRequestOptions.ResponseMode.QUERY).getParameters().size());
        emptyValues.put("one-more", List.of());
        assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromParameters(emptyValues, null,
                AuthorizationRequestOptions.ResponseMode.QUERY));
        Map<String, List<String>> body = Map.of("a", List.of("x".repeat(8191)), "b", List.of("x".repeat(8191)),
                "c", List.of("x".repeat(8191)));
        AuthorizationResponse accepted = AuthorizationResponse.fromParameters(body, "d=" + "x".repeat(8191),
                AuthorizationRequestOptions.ResponseMode.FORM_POST);
        assertEquals(4, accepted.getParameters().size());
        assertThrows(OAuthResponseException.class, () -> AuthorizationResponse.fromParameters(body,
                "d=" + "x".repeat(8191) + "&e=", AuthorizationRequestOptions.ResponseMode.FORM_POST));
    }

    @Test
    void authorizationPassesLoginHintAndTheRedactedBeginEvent() throws Exception {
        AtomicReference<URI> observed = new AtomicReference<>();
        AtomicInteger calls = new AtomicInteger();
        OAuthObserver observer = new OAuthObserver() {
            @Override public void didBeginAuthorization(@NonNull URI endpoint) {
                calls.incrementAndGet(); observed.set(endpoint);
            }
        };
        OAuthClient client = client().observer(observer).redirectUri(URI.create("https://app.example/callback")).build();
        AuthorizationRedirect redirect = client.beginAuthorization(AuthorizationRequestOptions.builder()
                .loginHint("TEST-ONLY-user@example.test").additionalParameters(Map.of("rc1-extra", "value")).build());
        assertEquals(List.of("TEST-ONLY-user@example.test"), QueryParameters.parse(redirect.getAuthorizationUri()
                .getRawQuery()).getValuesByName().get("login_hint"));
        assertEquals(List.of("value"), QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValuesByName().get("rc1-extra"));
        assertEquals(1, calls.get());
        assertEquals(URI.create("https://issuer.example/authorize"), observed.get());
    }

    @Test
    void builderEnforcesRelatedDurationsAndTheMaximumCallbackPort() {
        assertThrows(IllegalArgumentException.class, () -> client().requestTimeout(Duration.ofSeconds(5))
                .totalDeadline(Duration.ofSeconds(1)).build());
        assertThrows(IllegalArgumentException.class, () -> client().minimumTimeToLive(Duration.ofMinutes(2))
                .defaultTimeToLive(Duration.ofMinutes(1)).build());
        assertDoesNotThrow(() -> client().redirectUri(URI.create("https://app.example:65535/callback")).build());
        assertThrows(IllegalArgumentException.class, () -> client().redirectUri(URI.create("https://app.example:65536/callback")).build());
    }

    @Test
    void assertionDiscoveryFailureNotifiesOnlyPrivateKeyAuthentication() {
        AtomicInteger failures = new AtomicInteger();
        AtomicInteger audiences = new AtomicInteger();
        OAuthException failure = OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
        OAuthObserver observer = new OAuthObserver() {
            @Override public void didFailClientAssertionPreparation(@NonNull OAuthEndpoint endpoint, @NonNull OAuthException cause) {
                assertEquals(OAuthEndpoint.TOKEN, endpoint); assertSame(failure, cause); failures.incrementAndGet();
            }
            @Override public void didUseClientAssertionAudience(@NonNull ClientAssertionAudience audience) {
                assertEquals(ClientAssertionAudience.TOKEN_ENDPOINT, audience); audiences.incrementAndGet();
            }
        };
        client().build().assertionMetadataFailure(OAuthEndpoint.TOKEN, failure, observer);
        assertEquals(0, failures.get()); assertEquals(0, audiences.get());
        TestJsonWebKeys.Fixture key = TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
        ClientAuthentication authentication = ClientAuthentication.withPrivateKeyJwt(budget -> ClientAssertionSigningKey.withSigner(
                JwsSigner.fromRsaKeyPair(key.getPrivateKey(), key.getPublicKey(), JwsAlgorithm.RS256)).build())
                .audience(ClientAssertionAudience.TOKEN_ENDPOINT).build();
        client().clientAuthentication(authentication).build().assertionMetadataFailure(OAuthEndpoint.TOKEN, failure, observer);
        assertEquals(1, failures.get()); assertEquals(1, audiences.get());
    }

    @Test
    void allMetadataObserverUrisOmitUserInfoQueryAndFragment() {
        URI source = URI.create("https://user:secret@issuer.example/p%2Fath?TEST-ONLY-query#fragment");
        URI expected = URI.create("https://issuer.example/p%2Fath");
        assertEquals(expected, AuthorizationServerCache.reduced(source));
        assertEquals(expected, ResourceServerMetadataCache.reduced(source));
        assertEquals(URI.create("https://issuer.example/path"), AuthorizationServerCache.reduced(
                URI.create("https://@issuer.example/path")));
        assertEquals(URI.create("https://issuer.example/path"), ResourceServerMetadataCache.reduced(
                URI.create("https://@issuer.example/path")));
        assertThrows(IllegalArgumentException.class, () -> AuthorizationServerCache.reduced(URI.create("mailto:user@example.test")));
        assertThrows(IllegalArgumentException.class, () -> ResourceServerMetadataCache.reduced(URI.create("mailto:user@example.test")));
    }

    @Test
    void tokenPayloadKeepsVscharSpaceAndNineteenDigitLeadingZeroExpiry() {
        String json = "{\"access_token\":\" ~\",\"token_type\":\"Bearer\",\"expires_in\":\"0000000000000000001\"}";
        java.time.Instant now = java.time.Instant.parse("2026-10-14T12:00:00Z");
        TokenResponse response = TokenResponseParser.parse(raw(json), now, java.util.Set.of());
        assertEquals(" ~", response.getAccessToken().getValue());
        assertEquals("Bearer", response.getAccessToken().getTokenType());
        assertEquals(now.plusSeconds(1), response.getExpiresAt().orElseThrow());
        assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED, assertThrows(OAuthResponseException.class,
                () -> TokenResponseParser.parse(raw("{\"access_token\":\"value\",\"token_type\":\"Bearer\",\"scope\":\"\\u007f\"}"),
                        now, java.util.Set.of())).getReason());
    }

    @Test
    void protectedResourceAcceptsBothValidPortExtremesAndRejectsDelScope() {
        for (int port : List.of(1, 65535)) {
            URI resource = URI.create("https://resource.example:" + port + "/api");
            assertEquals(resource, ProtectedResourceMetadata.withResource(resource).build().getResource());
        }
        assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(
                URI.create("https://resource.example/api")).scopesSupported(List.of("\u007f")).build());
    }

    @Test
    void boundedSafeErrorCodeKeepsItsExactSixtyFourCharacterValue() {
        String code = "a".repeat(64);
        OAuthErrorResponseException failure = TokenResponseParser.error(
                new com.revetsec.internal.http.RawResponse(400,
                        java.net.http.HttpHeaders.of(Map.of(), (name, value) -> true),
                        ("{\"error\":\"" + code + "\"}").getBytes(StandardCharsets.UTF_8), null, false, Duration.ZERO),
                java.time.Instant.parse("2026-10-14T12:00:00Z"));
        assertEquals(code, failure.getErrorCode().orElseThrow());
    }

    @Test
    void allPublicScopeAndChallengeBoundariesUseTheirAsciiContract() {
        assertThrows(AccessTokenValidationException.class, () -> AccessTokenClaims.scopes(
                com.revetsec.json.JsonString.fromValue("\u007f"), false));
        assertThrows(IllegalArgumentException.class, () -> AuthorizationRequestOptions.builder().scopes(java.util.Set.of("\u007f")));
        assertEquals("Bearer realm=\" ~\"", BearerChallenge.builder().realm(" ~").build().getHeaderValue());
    }

    @Test
    void protectedMetadataBoundsSuppliedIssuerWorkBeforeDeduplicating() {
        String prefix = "https://issuer.example/";
        String issuer = prefix + "a".repeat(253 - prefix.length());
        ProtectedResourceMetadata accepted = ProtectedResourceMetadata.withResource(URI.create("https://resource.example/api"))
                .authorizationServers(java.util.Collections.nCopies(1024, issuer)).build();
        assertEquals(List.of(issuer), accepted.getAuthorizationServers());
        assertThrows(IllegalArgumentException.class, () -> ProtectedResourceMetadata.withResource(
                URI.create("https://resource.example/api")).authorizationServers(java.util.Collections.nCopies(1025, issuer)));
    }

    @Test
    void tokenSourceRelatedDurationsAndDiscoveredIntrospectionAuthenticationAreCheckedAtBuild() {
        OAuthClient confidential = client().clientAuthentication(ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret")).build();
        assertThrows(IllegalArgumentException.class, () -> ClientCredentialsTokenSource.withClient(confidential)
                .fallbackCacheDuration(Duration.ofMinutes(2)).maximumCacheDuration(Duration.ofMinutes(1)).renewBefore(Duration.ZERO).build());
        assertThrows(IllegalArgumentException.class, () -> ClientCredentialsTokenSource.withClient(confidential)
                .fallbackCacheDuration(Duration.ofSeconds(10)).maximumCacheDuration(Duration.ofMinutes(1))
                .renewBefore(Duration.ofMinutes(1)).build());
        OAuthClient publicDiscovery = OAuthClient.withIssuer("https://issuer.example").clientId("public")
                .clientAuthentication(ClientAuthentication.noneInstance()).build();
        assertThrows(IllegalArgumentException.class, () -> TokenIntrospectionClient.withOAuthClient(publicDiscovery)
                .expectedAudiences(java.util.Set.of("api")).build());
    }

    @Test
    void bearerChallengeAcceptsTheExactScopeInputBudgetBeforeRendering() {
        List<String> scopes = new ArrayList<>();
        for (int index = 0; index < 8; index++) scopes.add("s" + index + "a".repeat(8187));
        BearerChallenge challenge = BearerChallenge.builder().maximumHeaderLength(65536).scopes(scopes).build();
        assertEquals(65534, challenge.getHeaderValue().length());
    }

    @Test
    void transactionHandlesReleaseOnceAndRejectReinstallationAcrossCallerThreads() {
        TokenResponse tokens = TokenResponseParser.parse(raw("{\"access_token\":\"TEST-ONLY-value\",\"token_type\":\"Bearer\"}"),
                java.time.Instant.parse("2026-10-14T12:00:00Z"), java.util.Set.of());
        AtomicInteger releases = new AtomicInteger();
        java.util.function.Supplier<TokenResponse> release = () -> { releases.incrementAndGet(); return tokens; };
        com.revetsec.internal.oauth.OidcTransactionAccess.Completion completion = new com.revetsec.internal.oauth.OidcTransactionAccess.Completion(
                null, "TEST-ONLY-value", "Bearer", "TEST-ONLY-code", "TEST-ONLY-nonce", null, java.util.Set.of(), release);
        com.revetsec.internal.oauth.OidcTransactionAccess.RefreshCompletion refresh = new com.revetsec.internal.oauth.OidcTransactionAccess.RefreshCompletion(
                null, false, "TEST-ONLY-value", "Bearer", release, null);
        assertSame(tokens, onBridgeCaller(completion::releaseTokens));
        onBridgeCaller(() -> assertThrows(IllegalStateException.class, completion::releaseTokens));
        assertSame(tokens, onBridgeCaller(refresh::releaseTokens));
        onBridgeCaller(() -> assertThrows(IllegalStateException.class, refresh::releaseTokens));
        assertEquals(2, releases.get());
        com.revetsec.internal.oauth.OidcTransactionAccess.Operations installed = com.revetsec.internal.oauth.OidcTransactionAccess.get();
        onBridgeCaller(() -> assertThrowsExactly(IllegalStateException.class, () -> com.revetsec.internal.oauth.OidcTransactionAccess.set(installed)));
        onBridgeCaller(() -> assertThrowsExactly(IllegalStateException.class, () -> com.revetsec.internal.oauth.OidcTransactionAccess.set(installed)));
    }

    @Test
    void emptyRequestWriterAndEndpointFailureFactoriesKeepTheirComponentContracts() {
        URI endpoint = URI.create("https://issuer.example/endpoint?fixed=1");
        assertSame(endpoint, new OAuthRequestWriter().appendTo(endpoint));
        OAuthTransportException unavailable = OAuthTransportException.fromReason(OAuthException.Reason.HTTP_CLIENT_UNAVAILABLE, null);
        assertEquals(OAuthException.Reason.HTTP_CLIENT_UNAVAILABLE, unavailable.getReason());
        assertNull(unavailable.getCause());
        assertTrue(OAuthErrorResponseException.fromResponse(500, "", java.util.Optional.empty()).isTransient());
        assertFalse(OAuthErrorResponseException.fromResponse(499, "", java.util.Optional.empty()).isTransient());
    }

    @Test
    void pendingStoreReleasesBothSaveAndConsumeLocksAcrossFreshCallers() {
        InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.fromDefaults();
        java.time.Instant expiry = java.time.Instant.now().plusSeconds(60);
        onBridgeCaller(() -> { store.save("browser", "state-a", "TEST-ONLY-record-a", expiry, Duration.ofSeconds(1)); return true; });
        assertEquals(java.util.Optional.of("TEST-ONLY-record-a"), onBridgeCaller(() ->
                store.consume("browser", "state-a", Duration.ofSeconds(1))));
        onBridgeCaller(() -> { store.save("browser", "state-b", "TEST-ONLY-record-b", expiry, Duration.ofSeconds(1)); return true; });
        assertEquals(java.util.Optional.of("TEST-ONLY-record-b"), onBridgeCaller(() ->
                store.consume("browser", "state-b", Duration.ofSeconds(1))));
    }

    @Test
    void callbackWithoutCodeAndAbsentRevocationEndpointKeepTheirTypedFailures() {
        URI callback = URI.create("https://app.example/callback");
        OAuthClient client = client().redirectUri(callback).build();
        PendingAuthorization pending = client.beginAuthorization().getPendingAuthorization();
        InMemoryPendingAuthorizationStore store = InMemoryPendingAuthorizationStore.fromDefaults();
        pending.saveTo(store, "browser");
        AuthorizationResponse response = AuthorizationResponse.fromQueryString("state=" + pending.state());
        assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, assertThrows(OAuthResponseException.class, () ->
                client.completeAuthorization(response, PendingAuthorizationSource.fromStore(store, "browser"), callback)).getReason());
        assertThrowsExactly(IllegalStateException.class, () -> client.revoke("TEST-ONLY-token", TokenTypeHint.ACCESS_TOKEN));
    }

    @Test
    void distinctResourceAndClientObserversEachReceiveEndpointResults() {
        AtomicInteger clientSuccess = new AtomicInteger(); AtomicInteger clientFailure = new AtomicInteger();
        AtomicInteger resourceSuccess = new AtomicInteger(); AtomicInteger resourceFailure = new AtomicInteger();
        URI uri = URI.create("https://issuer.example/"); Duration elapsed = Duration.ofNanos(19);
        OAuthException failure = OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
        OAuthObserver observer = new OAuthObserver() {
            @Override public void didRequestEndpoint(@NonNull OAuthEndpoint role, @NonNull URI target, @NonNull Integer status, @NonNull Duration duration) {
                assertEquals(OAuthEndpoint.METADATA, role); assertEquals(uri, target); assertEquals(200, status); assertEquals(elapsed, duration); clientSuccess.incrementAndGet();
            }
            @Override public void didFailEndpoint(@NonNull OAuthEndpoint role, @NonNull URI target, @NonNull OAuthException error, @NonNull Duration duration) {
                assertEquals(OAuthEndpoint.METADATA, role); assertEquals(uri, target); assertSame(failure, error); assertEquals(elapsed, duration); clientFailure.incrementAndGet();
            }
        };
        AccessTokenObserver resource = new AccessTokenObserver() {
            @Override public void didRequestEndpoint(@NonNull OAuthEndpoint role, @NonNull URI target, @NonNull Integer status, @NonNull Duration duration) {
                assertEquals(OAuthEndpoint.METADATA, role); assertEquals(uri, target); assertEquals(200, status); assertEquals(elapsed, duration); resourceSuccess.incrementAndGet();
            }
            @Override public void didFailEndpoint(@NonNull OAuthEndpoint role, @NonNull URI target, @NonNull OAuthException error, @NonNull Duration duration) {
                assertEquals(OAuthEndpoint.METADATA, role); assertEquals(uri, target); assertSame(failure, error); assertEquals(elapsed, duration); resourceFailure.incrementAndGet();
            }
        };
        OAuthObserver fanout = client().observer(observer).build().resourceObserver(resource);
        fanout.didRequestEndpoint(OAuthEndpoint.METADATA, uri, 200, elapsed);
        fanout.didFailEndpoint(OAuthEndpoint.METADATA, uri, failure, elapsed);
        assertEquals(1, clientSuccess.get()); assertEquals(1, clientFailure.get());
        assertEquals(1, resourceSuccess.get()); assertEquals(1, resourceFailure.get());
    }

    @Test
    void scopeArrayRejectsAsciiSpaceAndTransportMappingRetainsOnlyTheIoCause() throws Exception {
        assertEquals(AccessTokenValidationException.Reason.SCOPE_INVALID, assertThrows(AccessTokenValidationException.class, () ->
                AccessTokenClaims.scopes(com.revetsec.json.JsonArray.fromElements(List.of(com.revetsec.json.JsonString.fromValue(" "))), true)).getReason());
        java.io.IOException cause = new java.io.IOException("TEST-ONLY-network-cause");
        java.lang.reflect.Constructor<com.revetsec.internal.http.HttpExchangeException> constructor =
                com.revetsec.internal.http.HttpExchangeException.class.getDeclaredConstructor(com.revetsec.internal.http.HttpExchangeException.Kind.class, java.io.IOException.class);
        constructor.setAccessible(true);
        OAuthException mapped = OAuthHttpErrors.fromExchange(constructor.newInstance(com.revetsec.internal.http.HttpExchangeException.Kind.IO, cause));
        assertEquals(OAuthException.Reason.NETWORK_FAILURE, mapped.getReason()); assertSame(cause, mapped.getCause());
    }

    private static <T> @NonNull T onBridgeCaller(java.util.function.@NonNull Supplier<@NonNull T> action) {
        java.util.concurrent.FutureTask<T> future = new java.util.concurrent.FutureTask<>(action::get);
        Thread thread = new Thread(future, "rc1-transaction-handle-caller"); thread.setDaemon(true); thread.start();
        try { return assertDoesNotThrow(() -> future.get(2, java.util.concurrent.TimeUnit.SECONDS)); }
        finally { future.cancel(true); }
    }

    private static com.revetsec.internal.http.@NonNull RawResponse raw(@NonNull String json) {
        return new com.revetsec.internal.http.RawResponse(200,
                java.net.http.HttpHeaders.of(Map.of("Content-Type", List.of("application/json")), (name, value) -> true),
                json.getBytes(StandardCharsets.UTF_8), com.revetsec.internal.http.MediaType.parse("application/json").orElseThrow(),
                false, Duration.ZERO);
    }

    private static OAuthClient.@NonNull Builder client() {
        return OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer("https://issuer.example")
                .authorizationEndpoint(URI.create("https://issuer.example/authorize"))
                .tokenEndpoint(URI.create("https://issuer.example/token")).build()).clientId("client")
                .clientAuthentication(ClientAuthentication.noneInstance());
    }
}
