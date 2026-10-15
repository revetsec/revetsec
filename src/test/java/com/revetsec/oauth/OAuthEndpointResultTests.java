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
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

final class OAuthEndpointResultTests {
  private static final URI CALLBACK = URI.create("https://app.example/callback");
  private static final String PRIVATE = "TEST-ONLY-private-endpoint-prose";

  @Test
  @SuppressWarnings("NullAway") // Deliberate required-argument misuse.
  void standardWireErrorsHaveFixedIdentityAndUntrustedExtensionsCannotEnterDiagnostics() {
    Map<String, OAuthEndpointError> standard = Map.ofEntries(
        Map.entry("invalid_request", OAuthEndpointError.INVALID_REQUEST),
        Map.entry("unauthorized_client", OAuthEndpointError.UNAUTHORIZED_CLIENT),
        Map.entry("access_denied", OAuthEndpointError.ACCESS_DENIED),
        Map.entry("unsupported_response_type", OAuthEndpointError.UNSUPPORTED_RESPONSE_TYPE),
        Map.entry("invalid_scope", OAuthEndpointError.INVALID_SCOPE),
        Map.entry("server_error", OAuthEndpointError.SERVER_ERROR),
        Map.entry("temporarily_unavailable", OAuthEndpointError.TEMPORARILY_UNAVAILABLE),
        Map.entry("invalid_client", OAuthEndpointError.INVALID_CLIENT),
        Map.entry("invalid_grant", OAuthEndpointError.INVALID_GRANT),
        Map.entry("unsupported_grant_type", OAuthEndpointError.UNSUPPORTED_GRANT_TYPE),
        Map.entry("unsupported_token_type", OAuthEndpointError.UNSUPPORTED_TOKEN_TYPE),
        Map.entry("invalid_token", OAuthEndpointError.INVALID_TOKEN),
        Map.entry("insufficient_scope", OAuthEndpointError.INSUFFICIENT_SCOPE),
        Map.entry("login_required", OAuthEndpointError.LOGIN_REQUIRED),
        Map.entry("interaction_required", OAuthEndpointError.INTERACTION_REQUIRED),
        Map.entry("account_selection_required", OAuthEndpointError.ACCOUNT_SELECTION_REQUIRED),
        Map.entry("consent_required", OAuthEndpointError.CONSENT_REQUIRED),
        Map.entry("invalid_request_uri", OAuthEndpointError.INVALID_REQUEST_URI),
        Map.entry("invalid_request_object", OAuthEndpointError.INVALID_REQUEST_OBJECT),
        Map.entry("request_not_supported", OAuthEndpointError.REQUEST_NOT_SUPPORTED),
        Map.entry("request_uri_not_supported", OAuthEndpointError.REQUEST_URI_NOT_SUPPORTED),
        Map.entry("registration_not_supported", OAuthEndpointError.REGISTRATION_NOT_SUPPORTED));
    standard.forEach((wire, expected) -> assertEquals(expected, OAuthEndpointError.fromWireValue(wire)));
    for (String unknown : List.of("", "INVALID_CLIENT", " invalid_client", "invalid_client ", "vendor_extension", PRIVATE,
        "invalid_client\nTEST-ONLY-header")) {
      OAuthEndpointError fixed = OAuthEndpointError.fromWireValue(unknown);
      assertEquals(OAuthEndpointError.UNRECOGNIZED, fixed);
      assertFalse(fixed.toString().contains(PRIVATE));
    }
    assertThrows(NullPointerException.class, () -> OAuthEndpointError.fromWireValue(null));
  }

  @Test
  void endpointDenialsExposeOnlyFixedCodesAndStatusWithoutRetry() throws Exception {
    try (TestHttpsServer server = TestHttpsServer.start()) {
      OAuthClient client = client(server).build();
      Map<String, OAuthEndpointError> errors = Map.of("invalid_client", OAuthEndpointError.INVALID_CLIENT,
          "invalid_grant", OAuthEndpointError.INVALID_GRANT, "invalid_scope", OAuthEndpointError.INVALID_SCOPE,
          "vendor_extension", OAuthEndpointError.UNRECOGNIZED, PRIVATE, OAuthEndpointError.UNRECOGNIZED);
      for (String code : errors.keySet()) {
        respond(server, 400, "{\"error\":\"" + code + "\",\"error_description\":\"" + PRIVATE + "\"}");
        OAuthTokenRequestResult.Rejected rejected = assertInstanceOf(OAuthTokenRequestResult.Rejected.class,
            client.requestClientCredentialsResult(TokenRequestOptions.builder().build()));
        assertEquals(errors.get(code), rejected.getError());
        assertEquals(400, rejected.getStatus());
        assertFalse(rejected.toString().contains(PRIVATE));
        assertFalse(rejected.toString().contains(code));
      }
      assertEquals(5, server.getHitCount("/token"));
      respond(server, 400, "{\"error\":\"invalid_grant\"}");
      OAuthTokenRequestResult.Rejected refresh = assertInstanceOf(OAuthTokenRequestResult.Rejected.class,
          client.refreshResult(RefreshToken.fromValue("TEST-ONLY-refresh"), TokenRequestOptions.builder().build()));
      assertEquals(OAuthEndpointError.INVALID_GRANT, refresh.getError());
      assertEquals(6, server.getHitCount("/token"));
    }
  }

  @Test
  void discoveryClientErrorsRemainInfrastructureFailuresBeforeAnyGrantEndpointRuns() throws Exception {
    for (int status : List.of(401, 404)) {
      try (TestHttpsServer server = TestHttpsServer.start()) {
        for (String path : List.of("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration")) {
          server.script(path, TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromStatus(status)));
        }
        OAuthClient lazy = OAuthClient.withIssuer(server.getBaseUri().toString()).clientId("client")
            .redirectUri(CALLBACK).clientAuthentication(ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret"))
            .httpClient(TestTls.httpClient()).build();
        assertEquals(status, assertThrows(OAuthErrorResponseException.class,
            () -> lazy.requestClientCredentialsResult(TokenRequestOptions.builder().build())).getStatus());
        assertEquals(status, assertThrows(OAuthErrorResponseException.class,
            () -> lazy.refreshResult(RefreshToken.fromValue("TEST-ONLY-refresh"),
                TokenRequestOptions.builder().build())).getStatus());
        assertEquals(status, assertThrows(OAuthErrorResponseException.class,
            () -> lazy.revokeResult("TEST-ONLY-token", TokenTypeHint.ACCESS_TOKEN)).getStatus());
        ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(lazy).build();
        assertEquals(status, assertThrows(OAuthErrorResponseException.class, source::getAccessTokenResult).getStatus());
        TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(lazy)
            .expectedAudiences(java.util.Set.of("resource")).build();
        BearerToken bearer = assertInstanceOf(BearerTokenResult.Present.class,
            BearerToken.fromAuthorizationHeaderValuesResult(List.of("Bearer TEST-ONLY-token"))).getToken();
        assertEquals(status, assertThrows(OAuthErrorResponseException.class,
            () -> introspection.validateResult(bearer)).getStatus());
        AuthorizationRedirect redirect = client(server).build().beginAuthorization();
        String state = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
        AuthorizationResponse response = assertInstanceOf(AuthorizationResponseParseResult.Succeeded.class,
            AuthorizationResponse.fromQueryStringResult("state=" + state + "&code=TEST-ONLY-code")).getResponse();
        var sealer = TestSealers.fromFixedKey();
        PendingAuthorizationSource pending = PendingAuthorizationSource.fromSealedForm(
            redirect.getPendingAuthorization().toSealedForm(sealer, "discovery-result"), sealer, "discovery-result");
        assertEquals(status, assertThrows(OAuthErrorResponseException.class,
            () -> lazy.completeAuthorizationResult(response, pending, CALLBACK)).getStatus());
        assertEquals(0, server.getHitCount("/token"));
        assertEquals(0, server.getHitCount("/revoke"));
        assertEquals(0, server.getHitCount("/inspect"));
      }
    }
  }

  @Test
  void transientAndMalformedProviderFailuresRemainExceptions() throws Exception {
    for (int status : List.of(429, 503, 200)) {
      try (TestHttpsServer server = TestHttpsServer.start()) {
        respond(server, status, "{\"error\":\"invalid_grant\"}");
        OAuthErrorResponseException failure = assertThrows(OAuthErrorResponseException.class,
            () -> client(server).build().requestClientCredentialsResult(TokenRequestOptions.builder().build()));
        assertEquals(status, failure.getStatus());
        assertEquals(1, server.getHitCount("/token"));
      }
    }
  }

  @Test
  void revocationAcknowledgementAndKnownDenialAreDistinctResults() throws Exception {
    try (TestHttpsServer server = TestHttpsServer.start()) {
      OAuthClient client = client(server).build();
      server.script("/revoke", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(200)
          .body(PRIVATE).build()));
      OAuthRevocationResult success = client.revokeResult("TEST-ONLY-unknown-token", TokenTypeHint.ACCESS_TOKEN);
      assertInstanceOf(OAuthRevocationResult.Succeeded.class, success);
      assertFalse(success.toString().contains(PRIVATE));
      server.script("/revoke", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(400,
          "{\"error\":\"unsupported_token_type\",\"error_description\":\"" + PRIVATE + "\"}")));
      OAuthRevocationResult.Rejected rejected = assertInstanceOf(OAuthRevocationResult.Rejected.class,
          client.revokeResult("TEST-ONLY-token", TokenTypeHint.ACCESS_TOKEN));
      assertEquals(OAuthEndpointError.UNSUPPORTED_TOKEN_TYPE, rejected.getError());
      assertEquals(400, rejected.getStatus());
      assertFalse(rejected.toString().contains(PRIVATE));
      assertEquals(2, server.getHitCount("/revoke"));
    }
  }

  @Test
  void checkedCallbackExtensionsNeverBypassBindingOrRetainSuppliedText() throws Exception {
    try (TestHttpsServer server = TestHttpsServer.start()) {
      OAuthClient client = client(server).build();
      Map<String, OAuthEndpointError> errors = Map.of("login_required", OAuthEndpointError.LOGIN_REQUIRED,
          "temporarily_unavailable", OAuthEndpointError.TEMPORARILY_UNAVAILABLE,
          "vendor_extension", OAuthEndpointError.UNRECOGNIZED);
      for (String error : errors.keySet()) {
        AuthorizationRedirect redirect = client.beginAuthorization();
        String state = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
        var sealer = TestSealers.fromFixedKey();
        PendingAuthorizationSource source = PendingAuthorizationSource.fromSealedForm(
            redirect.getPendingAuthorization().toSealedForm(sealer, "endpoint-results"), sealer, "endpoint-results");
        assertEquals(OAuthException.Reason.STATE_MISMATCH, assertInstanceOf(AuthorizationCompletionResult.Rejected.class,
            client.completeAuthorizationResult(callback("wrong", error), source, CALLBACK)).getReason());
        AuthorizationCompletionResult.RejectedAuthorizationError rejected = assertInstanceOf(
            AuthorizationCompletionResult.RejectedAuthorizationError.class,
            client.completeAuthorizationResult(callback(state, error), source, CALLBACK));
        assertEquals(errors.get(error), rejected.getError());
        assertFalse(rejected.toString().contains(PRIVATE));
      }
      assertEquals(0, server.getHitCount("/token"));
    }
  }

  @Test
  void cachedSourceKeepsEndpointRejectionExplicitDuringBackoff() throws Exception {
    try (TestHttpsServer server = TestHttpsServer.start()) {
      respond(server, 401, "{\"error\":\"invalid_client\"}");
      ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client(server).build()).build();
      for (int call = 0; call < 3; call++) {
        AccessTokenAcquisitionResult.Rejected rejected = assertInstanceOf(AccessTokenAcquisitionResult.Rejected.class,
            source.getAccessTokenResult());
        assertEquals(OAuthEndpointError.INVALID_CLIENT, rejected.getError());
        assertEquals(401, rejected.getStatus());
      }
      assertEquals(1, server.getHitCount("/token"));
    }
  }

  @Test
  void earlyRenewalDenialUsesOnlyStillValidCacheAndInvalidationReleasesTheDenial() throws Exception {
    try (TestHttpsServer server = TestHttpsServer.start()) {
      TestClock clock = TestClock.fromInstant(Instant.parse("2026-10-15T12:00:00Z"));
      respond(server, 200, "{\"access_token\":\"TEST-ONLY-access\",\"token_type\":\"Bearer\",\"expires_in\":60}");
      ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client(server).clock(clock).build())
          .renewBefore(Duration.ofSeconds(20)).build();
      AccessToken initial = assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class,
          source.getAccessTokenResult()).getAccessToken();
      clock.advance(Duration.ofSeconds(41));
      respond(server, 400, "{\"error\":\"invalid_client\"}");
      assertSame(initial, assertInstanceOf(AccessTokenAcquisitionResult.Succeeded.class,
          source.getAccessTokenResult()).getAccessToken());
      source.invalidate(initial);
      assertEquals(OAuthEndpointError.INVALID_CLIENT, assertInstanceOf(AccessTokenAcquisitionResult.Rejected.class,
          source.getAccessTokenResult()).getError());
      assertEquals(3, server.getHitCount("/token"));
    }
  }

  @Test
  void concurrentWaitersShareARejectedRenewalAsAnOrdinaryOutcome() throws Exception {
    try (TestHttpsServer server = TestHttpsServer.start()) {
      var held = TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromJson(400,
          "{\"error\":\"invalid_client\"}"));
      server.script("/token", held);
      ClientCredentialsTokenSource source = ClientCredentialsTokenSource.withClient(client(server).build()).build();
      var executor = Executors.newFixedThreadPool(8);
      try {
        List<Future<AccessTokenAcquisitionResult>> calls = new ArrayList<>();
        for (int caller = 0; caller < 8; caller++) calls.add(executor.submit(source::getAccessTokenResult));
        assertTrue(held.awaitHeldCount(1, Duration.ofSeconds(10)));
        held.release();
        for (Future<AccessTokenAcquisitionResult> call : calls) {
          assertEquals(OAuthEndpointError.INVALID_CLIENT, assertInstanceOf(AccessTokenAcquisitionResult.Rejected.class,
              call.get(15, TimeUnit.SECONDS)).getError());
        }
        assertEquals(1, server.getHitCount("/token"));
      } finally {
        held.release();
        executor.shutdownNow();
      }
    }
  }

  private static @NonNull AuthorizationResponse callback(@NonNull String state, @NonNull String error) {
    return assertInstanceOf(AuthorizationResponseParseResult.Succeeded.class,
        AuthorizationResponse.fromQueryStringResult("state=" + state + "&error=" + error
            + "&error_description=" + PRIVATE)).getResponse();
  }

  private static OAuthClient.@NonNull Builder client(@NonNull TestHttpsServer server) {
    AuthorizationServerMetadata metadata = AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
        .authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token"))
        .revocationEndpoint(server.uri("/revoke")).build();
    return OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client").redirectUri(CALLBACK)
        .clientAuthentication(ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret"))
        .httpClient(TestTls.httpClient());
  }

  private static void respond(@NonNull TestHttpsServer server, int status, @NonNull String body) {
    server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(status, body)));
  }
}
