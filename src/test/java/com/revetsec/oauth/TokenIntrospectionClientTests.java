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

/** RFC7662 sections2.1/2.2; distinct endpoint authentication; uncached/replay/outage boundaries. */
final class TokenIntrospectionClientTests {
    @Test void everyHealthyOrInactiveCallPostsAgainIncludingTokensWithoutExpiry() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            response(server,"/inspect",200,"application/json",active());TokenIntrospectionClient client=inspect(server).build();BearerToken token=bearer("TEST-ONLY-opaque");
            assertNotNull(client.validate(token));assertInstanceOf(AccessTokenValidationResult.Succeeded.class,client.validateResult(token));assertEquals(2,server.getHitCount("/inspect"));
            response(server,"/inspect",200,"application/json","{\"active\":false}");
            for(int i=0;i<3;i++) assertEquals(AccessTokenValidationException.Reason.INACTIVE,assertInstanceOf(AccessTokenValidationResult.Rejected.class,client.validateResult(token)).getReason());
            assertEquals(5,server.getHitCount("/inspect"));
            TestHttpsServer.RecordedRequest request=server.getRequests("/inspect").get(0);assertEquals("POST",request.getMethod());assertEquals(Optional.of("application/json"),request.getHeader("Accept"));
            assertTrue(request.getHeader("Authorization").orElseThrow().startsWith("Basic "));assertEquals("token=TEST-ONLY-opaque&token_type_hint=access_token",request.getBodyAsString());
            redacted(client,"TEST-ONLY-opaque",SECRET);
        }
    }
    @Test void postAuthenticationSupplierReadOnceAndTokenMethodsDoNotAuthorizeIntrospection() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            AtomicInteger reads=new AtomicInteger();AuthorizationServerMetadata metadata=AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString())
                    .authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).introspectionEndpoint(server.uri("/inspect"))
                    .tokenEndpointAuthMethodsSupported(Set.of("client_secret_basic")).introspectionEndpointAuthMethodsSupported(Set.of("client_secret_post")).build();
            OAuthClient oauth=OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretPost(()->{reads.incrementAndGet();return SECRET;})).httpClient(TestTls.httpClient()).clock(CLOCK).build();
            TokenIntrospectionClient client=TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(AUD)).build();assertEquals(0,reads.get());
            response(server,"/inspect",200,"application/json",active());assertNotNull(client.validate(bearer("opaque")));assertEquals(1,reads.get());
            var request=server.getRequests("/inspect").get(0);assertTrue(request.getHeader("Authorization").isEmpty());assertTrue(request.getBodyAsString().contains("client_secret="+SECRET));assertTrue(request.getBodyAsString().contains("client_id=client"));
            OAuthClient basic=OAuthClient.withAuthorizationServerMetadata(metadata).clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic(SECRET)).build();
            assertThrows(OAuthValidationException.class,()->TokenIntrospectionClient.withOAuthClient(basic).expectedAudiences(Set.of(AUD)).build());assertEquals(1,server.getHitCount("/inspect"));
            assertThrows(IllegalArgumentException.class,()->TokenIntrospectionClient.withOAuthClient(oauth(server).clientAuthentication(ClientAuthentication.noneInstance()).build()).expectedAudiences(Set.of(AUD)).build());
        }
    }
    @TestFactory @NonNull Stream<@NonNull DynamicTest> providerFailuresNeverBecomeCredentialResultsAndDoNotRetry() {
        return Stream.of(401,429,500,503).map(status->DynamicTest.dynamicTest("status"+status,()-> {
            try(TestHttpsServer server=TestHttpsServer.start()) {
                response(server,"/inspect",status,"application/json","{\"error\":\"invalid_client\",\"error_description\":\"TEST-ONLY-prose\"}");TokenIntrospectionClient client=inspect(server).build();
                OAuthErrorResponseException first=assertThrows(OAuthErrorResponseException.class,()->client.validateResult(bearer("opaque")));
                assertSame(first,assertThrows(OAuthErrorResponseException.class,()->client.validateResult(bearer("other-opaque"))));assertEquals(1,server.getHitCount("/inspect"));redacted(first,"TEST-ONLY-prose",SECRET,"opaque");
            }
        }));
    }
    @TestFactory @NonNull Stream<@NonNull DynamicTest> jsonTransportAndMalformedProviderResponsesRemainExceptions() {
        return Stream.of(Map.entry("application/token-introspection+jwt","signed.jwt.bytes"),Map.entry("application/json","{\"active\":\"true\"}"),Map.entry("application/json","{\"active\":true,\"active\":false}"),Map.entry("application/json","{\"active\":true,\"aud\":42}"),Map.entry("application/json","{\"active\":true,\"aud\":\"resource\",\"exp\":1.5}")).map(e->DynamicTest.dynamicTest(e.toString(),()-> {
            try(TestHttpsServer server=TestHttpsServer.start()) {
                response(server,"/inspect",200,e.getKey(),e.getValue());TokenIntrospectionClient client=inspect(server).build();
                assertThrows(OAuthException.class,()->client.validateResult(bearer("opaque")));assertThrows(OAuthException.class,()->client.validateResult(bearer("different")));assertEquals(1,server.getHitCount("/inspect"));
            }
        }));
    }
    @Test void roleSpecificDiscoveryNeedsNoBrowserEndpointsAndManualEndpointBypassesIt() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            String issuer=server.getBaseUri().toString();response(server,"/.well-known/oauth-authorization-server",200,"application/json","{\"issuer\":"+JsonText.string(issuer)+",\"introspection_endpoint\":"+JsonText.string(server.uri("/inspect").toString())+"}");
            response(server,"/inspect",200,"application/json",active());OAuthClient oauth=OAuthClient.withIssuer(issuer).clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic(SECRET)).clock(CLOCK).httpClient(TestTls.httpClient()).build();
            TokenIntrospectionClient client=TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(AUD)).build();assertEquals(0,server.getRequests().size());client.warmUp();assertEquals(1,server.getRequests().size());assertNotNull(client.validate(bearer("opaque")));assertEquals(2,server.getRequests().size());
            TokenIntrospectionClient manual=TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(AUD)).introspectionEndpoint(server.uri("/inspect")).build();manual.warmUp();assertEquals(2,server.getRequests().size());assertNotNull(manual.validate(bearer("opaque")));assertEquals(3,server.getRequests().size());
            assertThrows(OAuthException.class,oauth::warmUp); // Browser client parser still requires authorization/token endpoints.
        }
    }
    @Test void providerFailureBackoffRecoversWithIndependentWaiterCredentials() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            OAuthClient oauth=oauth(server).discoveryCooldown(Duration.ofSeconds(1)).build();TokenIntrospectionClient client=TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(AUD)).build();
            response(server,"/inspect",503,"application/json","{}");assertThrows(OAuthErrorResponseException.class,()->client.validate(bearer("bad-health")));
            Thread.sleep(1050);TestHttpsServer.HeldScript held=TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromJson(200,active()));server.script("/inspect",held);
            ExecutorService pool=Executors.newFixedThreadPool(3);
            try {
                Future<VerifiedAccessToken> probe=pool.submit(()->client.validate(bearer("probe")));assertTrue(held.awaitHeldCount(1,Duration.ofSeconds(5)));
                Future<VerifiedAccessToken> waiter=pool.submit(()->client.validate(bearer("waiter")));
                // A later response is for a distinct call; no proof from the probe may be shared.
                response(server,"/inspect",200,"application/json","{\"active\":true,\"aud\":\"resource\",\"sub\":\"waiter-subject\"}");held.release();
                assertTrue(probe.get(5,TimeUnit.SECONDS).getSubject().isEmpty());assertEquals(Optional.of("waiter-subject"),waiter.get(5,TimeUnit.SECONDS).getSubject());
                assertEquals(3,server.getHitCount("/inspect"));assertTrue(server.getRequests("/inspect").stream().anyMatch(q->q.getBodyAsString().contains("token=waiter&")));
            } finally { held.release();pool.shutdownNow();assertTrue(pool.awaitTermination(5,TimeUnit.SECONDS)); }
        }
    }
    @Test void boundedEncodedTruncatedRedirectAndTimedOutResponsesAreProviderFailures() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            List<TestHttpsServer.Response> responses=List.of(TestHttpsServer.Response.withStatus(200).header("Content-Type","application/json").body("{\"active\":true").build(),TestHttpsServer.Response.withStatus(200).header("Content-Type","application/json").header("Content-Encoding","gzip").body(active()).build(),TestHttpsServer.Response.withStatus(200).header("Content-Type","application/json").body(" ".repeat(256*1024+1)).build(),TestHttpsServer.Response.withStatus(302).header("Location",server.uri("/target").toString()).build());
            for(TestHttpsServer.Response response:responses) {
                server.script("/inspect",TestHttpsServer.Script.fromResponse(response));TokenIntrospectionClient client=inspect(server).build();int before=server.getHitCount("/inspect");assertThrows(OAuthException.class,()->client.validateResult(bearer("bounded")));assertEquals(before+1,server.getHitCount("/inspect"));assertEquals(0,server.getHitCount("/target"));
            }
            TestHttpsServer.HeldScript held=TestHttpsServer.HeldScript.fromResponse(TestHttpsServer.Response.fromJson(200,active()));server.script("/inspect",held);
            TokenIntrospectionClient client=TokenIntrospectionClient.withOAuthClient(oauth(server).requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(1)).build()).expectedAudiences(Set.of(AUD)).build();
            try {assertThrows(OAuthTransportException.class,()->client.validateResult(bearer("timeout")));assertThrows(OAuthTransportException.class,()->client.validateResult(bearer("other-timeout")));}finally{held.release();}
        }
    }
    @Test void discoveredIntrospectionAuthenticationAndOutboundPolicyAreCheckedBeforePost() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            String issuer=server.getBaseUri().toString();String base="{\"issuer\":"+JsonText.string(issuer)+",\"introspection_endpoint\":"+JsonText.string(server.uri("/inspect").toString());
            for(String suffix:List.of(",\"introspection_endpoint_auth_methods_supported\":[\"client_secret_post\"]}",",\"introspection_endpoint_auth_methods_supported\":[]}")) {
                response(server,"/.well-known/oauth-authorization-server",200,"application/json",base+suffix);OAuthClient oauth=OAuthClient.withIssuer(issuer).clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic(SECRET)).httpClient(TestTls.httpClient()).build();TokenIntrospectionClient client=TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(AUD)).build();assertThrows(OAuthValidationException.class,()->client.validateResult(bearer("opaque")));assertEquals(0,server.getHitCount("/inspect"));
            }
            response(server,"/.well-known/oauth-authorization-server",200,"application/json","{\"issuer\":"+JsonText.string(issuer)+",\"introspection_endpoint\":\"http://10.0.0.1/inspect\"}");OAuthClient oauth=OAuthClient.withIssuer(issuer).clientId("client").clientAuthentication(ClientAuthentication.fromClientSecretBasic(SECRET)).httpClient(TestTls.httpClient()).build();assertThrows(OAuthValidationException.class,()->TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(AUD)).build().validateResult(bearer("opaque")));assertEquals(0,server.getHitCount("/inspect"));
        }
    }

}
