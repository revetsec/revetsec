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

import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import com.revetsec.testing.*;
import com.revetsec.jose.*;
import com.revetsec.json.*;
import com.revetsec.internal.http.*;
import com.revetsec.internal.jose.*;
import com.revetsec.OutboundUriPolicy;
import org.jspecify.annotations.Nullable;
import java.net.*;
import java.net.http.*;
import java.time.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import java.util.stream.*;
import static com.revetsec.oauth.Phase2Fixtures.*;

/** RFC8414 sections3/5; exact issuer and role-only requirements. */
final class ResourceServerMetadataTests {
    @Test void roleRequirementsDoNotInventUnrelatedEndpointsOrUseIdTokenAlgorithms() {
        String json="{\"issuer\":\"https://issuer.example\",\"jwks_uri\":\"https://issuer.example/keys\",\"id_token_signing_alg_values_supported\":[\"HS256\"]}";
        ResourceServerMetadata m=ResourceServerMetadata.parse(ISSUER,json.getBytes(StandardCharsets.UTF_8),ResourceServerMetadata.Role.JWT);assertEquals(URI.create(ISSUER+"/keys"),m.endpoint());assertNull(m.authenticationMethods());redacted(m,ISSUER);
        assertThrows(OAuthResponseException.class,()->ResourceServerMetadata.parse(ISSUER,json.getBytes(StandardCharsets.UTF_8),ResourceServerMetadata.Role.INTROSPECTION));
        assertThrows(OAuthResponseException.class,()->AuthorizationServerMetadata.fromJson(ISSUER,json));
        ResourceServerMetadata parsed=ResourceServerMetadata.parse(ISSUER,"{\"issuer\":\"https://issuer.example\",\"introspection_endpoint\":\"https://issuer.example/inspect\",\"introspection_endpoint_auth_methods_supported\":[\"client_secret_post\"]}".getBytes(StandardCharsets.UTF_8),ResourceServerMetadata.Role.INTROSPECTION);
        assertEquals(Set.of("client_secret_post"),parsed.authenticationMethods());assertEquals(ISSUER,parsed.issuer());
    }
    @TestFactory Stream<DynamicTest> malformedKnownMembersFailClosed() {
        return Stream.of("[]","{}","{\"issuer\":null}","{\"issuer\":\"https://other.example\",\"jwks_uri\":\"https://issuer.example/key\"}","{\"issuer\":\"https://issuer.example\",\"jwks_uri\":null}","{\"issuer\":\"https://issuer.example\",\"jwks_uri\":\"%%%\"}","{\"issuer\":\"https://issuer.example\",\"jwks_uri\":\"https://issuer.example/key\",\"introspection_endpoint_auth_methods_supported\":[\"a\",\"a\"]}","{\"issuer\":\"https://issuer.example\",\"jwks_uri\":\"https://issuer.example/key\",\"introspection_endpoint_auth_methods_supported\":null}").map(v->DynamicTest.dynamicTest(v,()->assertThrows(OAuthException.class,()->ResourceServerMetadata.parse(ISSUER,v.getBytes(StandardCharsets.UTF_8),ResourceServerMetadata.Role.JWT))));
    }
    @Test void fallbackOnlyOnNotFoundAndIssuerPathsPreserveRawComponents() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            String issuer=server.uri("/tenant/").toString();String doc="{\"issuer\":"+JsonText.string(issuer)+",\"jwks_uri\":"+JsonText.string(server.uri("/jwks").toString())+"}";
            response(server,"/.well-known/oauth-authorization-server/tenant",404,"application/json","{}");response(server,"/.well-known/openid-configuration/tenant",404,"application/json","{}");response(server,"/tenant/.well-known/openid-configuration",200,"application/json",doc);response(server,"/jwks",200,"application/json",keyJson());
            JwtAccessTokenValidator validator=JwtAccessTokenValidator.withIssuer(issuer).expectedAudiences(Set.of(AUD)).clock(CLOCK).httpClient(TestTls.httpClient()).build();
            assertEquals(0,server.getRequests().size());validator.warmUp();assertEquals(4,server.getRequests().size());assertNotNull(validator.validate(bearer(token(claims(issuer),"at+jwt"))));assertEquals(4,server.getRequests().size());
        }
        try(TestHttpsServer server=TestHttpsServer.start()) {
            response(server,"/.well-known/oauth-authorization-server",200,"application/json","{}");JwtAccessTokenValidator validator=JwtAccessTokenValidator.withIssuer(server.getBaseUri().toString()).expectedAudiences(Set.of(AUD)).httpClient(TestTls.httpClient()).build();
            assertThrows(OAuthResponseException.class,validator::warmUp);assertEquals(1,server.getRequests().size());
        }
        assertEquals("https://issuer.example/.well-known/oauth-authorization-server/a%2Fb",AuthorizationServerCache.candidates(URI.create("https://issuer.example/a%2Fb/")).get(0).toString());
    }
    @Test void discoveredPrivateEndpointAndRedirectsAreRejected() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            response(server,"/.well-known/oauth-authorization-server",200,"application/json","{\"issuer\":"+JsonText.string(server.getBaseUri().toString())+",\"jwks_uri\":\"http://10.0.0.1/keys\"}");
            JwtAccessTokenValidator validator=JwtAccessTokenValidator.withIssuer(server.getBaseUri().toString()).expectedAudiences(Set.of(AUD)).httpClient(TestTls.httpClient()).build();assertThrows(OAuthValidationException.class,validator::warmUp);assertEquals(1,server.getRequests().size());
        }
    }
    @Test void roleDiscoveryRedirectIsNotFollowedOrFallbackAndTlsTrustIsNotWeakened() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            server.script("/.well-known/oauth-authorization-server",TestHttpsServer.Script.fromRedirect(302,server.uri("/target").toString()));
            JwtAccessTokenValidator validator=JwtAccessTokenValidator.withIssuer(server.getBaseUri().toString()).expectedAudiences(Set.of(AUD)).httpClient(TestTls.httpClient()).build();
            assertEquals(OAuthException.Reason.REDIRECT_NOT_FOLLOWED,assertThrows(OAuthResponseException.class,validator::warmUp).getReason());assertEquals(1,server.getRequests().size());assertEquals(0,server.getHitCount("/target"));assertEquals(0,server.getHitCount("/.well-known/openid-configuration"));
            JwtAccessTokenValidator untrusted=JwtAccessTokenValidator.withIssuer(server.getBaseUri().toString()).expectedAudiences(Set.of(AUD)).build();assertThrows(OAuthTransportException.class,untrusted::warmUp);assertEquals(1,server.getRequests().size());
        }
    }
    @Test void jwtUriRotationUsesNewKeysAndSameUriRefreshKeepsItsSource() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            String issuer=server.getBaseUri().toString();RewindableClock clock=RewindableClock.fromInstant(NOW);
            java.util.function.Function<String,String> doc=path->"{\"issuer\":"+JsonText.string(issuer)+",\"jwks_uri\":"+JsonText.string(server.uri(path).toString())+"}";
            response(server,"/.well-known/oauth-authorization-server",200,"application/json",doc.apply("/keys-a"));response(server,"/keys-a",200,"application/json",keyJson());
            String rotated=TestJsonWebKeys.withFixture(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_3072).kid("new-key").alg("RS256").toKeySetJson();response(server,"/keys-b",200,"application/json",rotated);
            JwtAccessTokenValidator v=JwtAccessTokenValidator.withIssuer(issuer).expectedAudiences(Set.of(AUD)).clock(clock).httpClient(TestTls.httpClient()).minimumTimeToLive(Duration.ofSeconds(30)).defaultTimeToLive(Duration.ofSeconds(30)).maximumTimeToLive(Duration.ofSeconds(60)).discoveryCooldown(Duration.ofSeconds(1)).build();
            assertNotNull(v.validate(bearer(token(claims(issuer),"at+jwt"))));assertEquals(1,server.getHitCount("/keys-a"));
            clock.advance(Duration.ofSeconds(31));assertNotNull(v.validate(bearer(token(claims(issuer),"at+jwt"))));assertEquals(1,server.getHitCount("/keys-a"));
            Thread.sleep(1050);clock.advance(Duration.ofSeconds(31));response(server,"/.well-known/oauth-authorization-server",200,"application/json",doc.apply("/keys-b"));
            String compact=TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("new-key").typ("at+jwt").payload(JsonText.object(new ArrayList<>(claims(issuer).entrySet()))).sign(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_3072.getPrivateKey());assertNotNull(v.validate(bearer(compact)));assertEquals(1,server.getHitCount("/keys-b"));assertEquals(3,server.getHitCount("/.well-known/oauth-authorization-server"));
            assertInstanceOf(AccessTokenValidationResult.Rejected.class,v.validateResult(bearer(token(claims(issuer),"at+jwt"))));assertEquals(1,server.getHitCount("/keys-a"));
        }
    }

}
