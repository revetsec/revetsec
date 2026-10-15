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
import com.revetsec.jose.*;
import com.revetsec.oauth.*;
import com.revetsec.testing.*;
import com.revetsec.testing.TestJwk.Fixture;
import com.revetsec.testing.TestJws.Algorithm;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

final class OidcEndpointResultTests {
  private static final URI CALLBACK = URI.create("https://rp.example/callback");
  private static final Instant NOW = Instant.parse("2026-10-15T12:00:00Z");
  private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
  private static final String SUBJECT = "TEST-ONLY-result-subject";
  private static final String ACCESS = "TEST-ONLY-result-access";
  private static final String REFRESH = "TEST-ONLY-result-refresh";

  @Test
  void userInfoReturnsCheckedClaimsOrFixedDenialAndLeavesOutagesExceptional() throws Exception {
    try (TestHttpsServer server = TestHttpsServer.start()) {
      OidcClient client = client(server).build();
      OidcAuthentication authentication = authenticate(server, client);
      server.script("/userinfo", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
          "{\"sub\":" + JsonText.string(SUBJECT) + "}")));
      OidcUserInfoResult.Succeeded success = assertInstanceOf(OidcUserInfoResult.Succeeded.class,
          client.fetchUserInfoResult(authentication));
      assertEquals(SUBJECT, success.getUserInfo().getSubject());
      assertRedacted(success.toString());
      server.script("/userinfo", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(401,
          "{\"error\":\"invalid_token\",\"error_description\":" + JsonText.string(ACCESS) + "}")));
      OidcUserInfoResult.RejectedEndpoint denied = assertInstanceOf(OidcUserInfoResult.RejectedEndpoint.class,
          client.fetchUserInfoResult(authentication));
      assertEquals(401, denied.getStatus());
      assertEquals(OAuthEndpointError.UNRECOGNIZED, denied.getError());
      assertRedacted(denied.toString());
      server.script("/userinfo", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(503,
          "{\"error\":\"temporarily_unavailable\"}")));
      assertEquals(503, assertThrows(OAuthErrorResponseException.class,
          () -> client.fetchUserInfoResult(authentication)).getStatus());
      assertEquals(3, server.getHitCount("/userinfo"));
      assertEquals(0, server.getHitCount("/jwks"));
    }
  }

  @Test
  void discoveryClientErrorsCannotBecomeUserInfoRefreshOrCompletionRejections() throws Exception {
    for (int status : List.of(401, 404)) {
      try (TestHttpsServer server = TestHttpsServer.start()) {
        OidcClient configured = client(server).build();
        OidcAuthentication authentication = authenticate(server, configured);
        RefreshToken refresh = authentication.getTokens().getRefreshToken().orElseThrow();
        server.script("/.well-known/openid-configuration", TestHttpsServer.Script.fromResponse(
            TestHttpsServer.Response.fromStatus(status)));
        OidcClient lazy = OidcClient.withIssuer(server.getBaseUri().toString()).clientId("client")
            .redirectUri(CALLBACK).clock(CLOCK).httpClient(TestTls.httpClient()).build();
        assertEquals(status, assertThrows(OAuthErrorResponseException.class,
            () -> lazy.fetchUserInfoResult(authentication)).getStatus());
        assertEquals(status, assertThrows(OAuthErrorResponseException.class,
            () -> lazy.refreshResult(refresh, authentication.getSessionReference())).getStatus());
        assertEquals(status, assertThrows(OAuthErrorResponseException.class,
            () -> lazy.refreshResult(refresh, authentication.getSessionReference(),
                TokenRequestOptions.builder().build())).getStatus());
        AuthorizationRedirect redirect = configured.beginAuthentication();
        AuthorizationResponse response = callback("state=" + state(redirect) + "&code=TEST-ONLY-code");
        PendingAuthorizationSource pending = source(redirect);
        assertEquals(status, assertThrows(OAuthErrorResponseException.class,
            () -> lazy.completeAuthenticationResult(response, pending, CALLBACK)).getStatus());
        assertEquals(0, server.getHitCount("/userinfo"));
        assertEquals(1, server.getHitCount("/token"));
        assertEquals(0, server.getHitCount("/jwks"));
      }
    }
  }

  @Test
  void userInfoBindingAndSubjectFailuresNeverReleaseData() throws Exception {
    try (TestHttpsServer server = TestHttpsServer.start()) {
      OidcClient client = client(server).build();
      OidcAuthentication authentication = authenticate(server, client);
      OidcClient otherClient = client(server).clientId("other-client").build();
      assertEquals(OidcValidationException.Reason.USERINFO_AUTHENTICATION_MISMATCH,
          assertInstanceOf(OidcUserInfoResult.Rejected.class,
              otherClient.fetchUserInfoResult(authentication)).getReason());
      assertEquals(0, server.getHitCount("/userinfo"));
      server.script("/userinfo", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
          "{\"sub\":\"other\",\"private\":" + JsonText.string(ACCESS) + "}")));
      OidcUserInfoResult.Rejected rejected = assertInstanceOf(OidcUserInfoResult.Rejected.class,
          client.fetchUserInfoResult(authentication));
      assertEquals(OidcValidationException.Reason.USERINFO_SUBJECT_MISMATCH, rejected.getReason());
      assertTrue(rejected.getJoseReason().isEmpty());
      assertRedacted(rejected.toString());
      assertEquals(1, server.getHitCount("/userinfo"));
    }
  }

  @Test
  void refreshDenialCannotReleaseReturnedCredentialsAndSuccessRetainsOriginalIdentity() throws Exception {
    try (TestHttpsServer server = TestHttpsServer.start()) {
      OidcClient client = client(server).build();
      OidcAuthentication authentication = authenticate(server, client);
      RefreshToken refresh = authentication.getTokens().getRefreshToken().orElseThrow();
      server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(400,
          "{\"error\":\"invalid_grant\",\"access_token\":" + JsonText.string(ACCESS) + "}")));
      OidcRefreshOutcome.RejectedEndpoint denied = assertInstanceOf(OidcRefreshOutcome.RejectedEndpoint.class,
          client.refreshResult(refresh, authentication.getSessionReference()));
      assertEquals(OAuthEndpointError.INVALID_GRANT, denied.getError());
      assertEquals(400, denied.getStatus());
      assertRedacted(denied.toString());
      server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
          "{\"access_token\":" + JsonText.string(ACCESS) + ",\"token_type\":\"Bearer\"}")));
      OidcRefreshOutcome.Succeeded succeeded = assertInstanceOf(OidcRefreshOutcome.Succeeded.class,
          client.refreshResult(refresh, authentication.getSessionReference(), TokenRequestOptions.builder().build()));
      OidcRefreshResult refreshed = succeeded.getRefreshResult();
      assertEquals(ACCESS, refreshed.getTokens().getAccessToken().getValue());
      assertEquals(REFRESH, refreshed.getRefreshToken().getValue());
      assertTrue(refreshed.getIdToken().isEmpty());
      assertSame(authentication.getSessionReference(), refreshed.getSessionReference());
      assertRedacted(succeeded.toString());
      server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
          "{\"access_token\":" + JsonText.string(ACCESS) + ",\"token_type\":\"DPoP\"}")));
      assertEquals(OidcValidationException.Reason.TOKEN_TYPE_UNSUPPORTED,
          assertInstanceOf(OidcRefreshOutcome.Rejected.class,
              client.refreshResult(refresh, authentication.getSessionReference())).getReason());
      assertEquals(4, server.getHitCount("/token"));
    }
  }

  @Test
  void callbackErrorsAreCheckedOutcomesAndCodeEndpointRejectionReleasesNoAuthentication() throws Exception {
    try (TestHttpsServer server = TestHttpsServer.start()) {
      OidcClient client = client(server).build();
      Map<String, OAuthEndpointError> errors = Map.of("interaction_required", OAuthEndpointError.INTERACTION_REQUIRED,
          "temporarily_unavailable", OAuthEndpointError.TEMPORARILY_UNAVAILABLE,
          "vendor_extension", OAuthEndpointError.UNRECOGNIZED);
      for (String error : errors.keySet()) {
        AuthorizationRedirect redirect = client.beginAuthentication();
        String state = state(redirect);
        OidcAuthenticationResult.RejectedAuthorizationError rejected = assertInstanceOf(
            OidcAuthenticationResult.RejectedAuthorizationError.class,
            client.completeAuthenticationResult(callback("state=" + state + "&error=" + error), source(redirect), CALLBACK));
        assertEquals(errors.get(error), rejected.getError());
        assertRedacted(rejected.toString());
      }
      assertEquals(0, server.getHitCount("/token"));
      AuthorizationRedirect redirect = client.beginAuthentication();
      server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(400,
          "{\"error\":\"invalid_grant\",\"error_description\":" + JsonText.string(ACCESS) + "}")));
      OidcAuthenticationResult.RejectedEndpoint endpoint = assertInstanceOf(OidcAuthenticationResult.RejectedEndpoint.class,
          client.completeAuthenticationResult(callback("state=" + state(redirect) + "&code=TEST-ONLY-code"),
              source(redirect), CALLBACK));
      assertEquals(OAuthEndpointError.INVALID_GRANT, endpoint.getError());
      assertEquals(400, endpoint.getStatus());
      assertRedacted(endpoint.toString());
      assertEquals(1, server.getHitCount("/token"));
      assertEquals(0, server.getHitCount("/jwks"));
    }
  }

  private static @NonNull OidcAuthentication authenticate(@NonNull TestHttpsServer server, @NonNull OidcClient client)
      throws Exception {
    AuthorizationRedirect redirect = client.beginAuthentication();
    String nonce = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("nonce").get(0);
    String claims = "{\"iss\":" + JsonText.string(server.getBaseUri().toString()) + ",\"sub\":"
        + JsonText.string(SUBJECT) + ",\"aud\":\"client\",\"iat\":" + NOW.getEpochSecond()
        + ",\"exp\":" + NOW.plusSeconds(300).getEpochSecond() + ",\"nonce\":" + JsonText.string(nonce) + "}";
    String idToken = TestJws.withAlgorithm(Algorithm.RS256).kid("key").payload(claims)
        .sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
    server.script("/token", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
        "{\"access_token\":" + JsonText.string(ACCESS) + ",\"token_type\":\"Bearer\",\"expires_in\":300,"
            + "\"refresh_token\":" + JsonText.string(REFRESH) + ",\"id_token\":" + JsonText.string(idToken) + "}")));
    return assertInstanceOf(OidcAuthenticationResult.Succeeded.class,
        client.completeAuthenticationResult(callback("state=" + state(redirect) + "&code=TEST-ONLY-code"),
            source(redirect), CALLBACK)).getAuthentication();
  }

  private static @NonNull AuthorizationResponse callback(@NonNull String query) {
    return assertInstanceOf(AuthorizationResponseParseResult.Succeeded.class,
        AuthorizationResponse.fromQueryStringResult(query)).getResponse();
  }

  private static @NonNull String state(@NonNull AuthorizationRedirect redirect) throws Exception {
    return QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("state").get(0);
  }

  private static @NonNull PendingAuthorizationSource source(@NonNull AuthorizationRedirect redirect) {
    StateSealer sealer = TestSealers.fromFixedKey();
    return PendingAuthorizationSource.fromSealedForm(redirect.getPendingAuthorization().toSealedForm(sealer, "oidc-results"),
        sealer, "oidc-results");
  }

  private static OidcClient.@NonNull Builder client(@NonNull TestHttpsServer server) {
    Jwks keys = assertInstanceOf(JwksParseResult.Succeeded.class,
        Jwks.fromJsonResult(TestJwk.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("key")
            .alg("RS256").toKeySetJson())).getJwks();
    OidcProviderMetadata metadata = OidcProviderMetadata.withIssuer(server.getBaseUri().toString())
        .authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token"))
        .jwksUri(server.uri("/jwks")).userInfoEndpoint(server.uri("/userinfo")).build();
    return OidcClient.withProviderMetadata(metadata).clientId("client").redirectUri(CALLBACK).clock(CLOCK)
        .idTokenSigningAlgorithms(Set.of(JwsAlgorithm.RS256)).httpClient(TestTls.httpClient())
        .jwksSource(StaticJwksSource.fromJwks(keys));
  }

  private static void assertRedacted(@NonNull String diagnostic) {
    for (String secret : List.of(SUBJECT, ACCESS, REFRESH)) assertFalse(diagnostic.contains(secret));
  }
}
