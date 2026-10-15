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

import com.revetsec.internal.http.Deadline;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.JwsSigner;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Preparation failures and endpoint failures keep their observer identity and bounded elapsed time. */
final class OAuthRc1ObserverMutationTests {
    private static final Instant NOW=Instant.parse("2026-10-14T12:00:00Z");

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> expiredPreparedAssertionsFailBeforeEveryCredentialedEndpoint() {
        return Stream.of(OAuthEndpoint.TOKEN,OAuthEndpoint.REVOCATION,OAuthEndpoint.INTROSPECTION).map(role ->
                DynamicTest.dynamicTest(role.name(),()->{
            try(TestHttpsServer server=TestHttpsServer.start()) {
                TestClock clock=TestClock.fromInstant(NOW);
                AtomicReference<OAuthException> observed=new AtomicReference<>();
                AtomicReference<Duration> elapsed=new AtomicReference<>();
                AtomicInteger events=new AtomicInteger();
                AccessTokenObserver observer=new AccessTokenObserver(){
                    @Override public void willRequestEndpoint(@NonNull OAuthEndpoint endpoint,@NonNull URI uri){
                        assertEquals(role,endpoint);clock.advance(Duration.ofSeconds(61));
                    }
                    @Override public void didFailEndpoint(@NonNull OAuthEndpoint endpoint,@NonNull URI uri,
                            @NonNull OAuthException failure,@NonNull Duration duration){
                        assertEquals(role,endpoint);observed.set(failure);elapsed.set(duration);events.incrementAndGet();
                    }
                };
                OAuthClient client=client(server,clock,observer,assertion());
                long started=System.nanoTime();
                OAuthException failure=assertThrows(OAuthException.class,()->invoke(client,server,role,observer));
                long total=System.nanoTime()-started;
                assertEquals(OAuthException.Reason.CLIENT_ASSERTION_SIGNING_FAILED,failure.getReason());
                assertSame(failure,observed.get());assertEquals(1,events.get());
                assertNotNull(elapsed.get());assertFalse(elapsed.get().isNegative());assertTrue(elapsed.get().toNanos()<=total);
                assertEquals(0,server.getHitCount(path(role)));
            }
        }));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> transportFailuresKeepTheirMappedObserverIdentity() {
        return Stream.of(OAuthEndpoint.TOKEN,OAuthEndpoint.INTROSPECTION).map(role -> DynamicTest.dynamicTest(role.name(),()->{
            try(TestHttpsServer server=TestHttpsServer.start()) {
                server.script(path(role),TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromStatus(302)));
                AtomicReference<OAuthException> observed=new AtomicReference<>();
                AtomicReference<Duration> elapsed=new AtomicReference<>();
                AtomicInteger events=new AtomicInteger();
                AccessTokenObserver observer=new AccessTokenObserver(){
                    @Override public void didFailEndpoint(@NonNull OAuthEndpoint endpoint,@NonNull URI uri,
                            @NonNull OAuthException failure,@NonNull Duration duration){
                        assertEquals(role,endpoint);observed.set(failure);elapsed.set(duration);events.incrementAndGet();
                    }
                };
                OAuthClient client=client(server,TestClock.fromInstant(NOW),observer,ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret"));
                long started=System.nanoTime();
                OAuthException failure=assertThrows(OAuthException.class,()->invoke(client,server,role,observer));
                long total=System.nanoTime()-started;
                assertEquals(OAuthException.Reason.REDIRECT_NOT_FOLLOWED,failure.getReason());
                assertSame(failure,observed.get());assertEquals(1,events.get());
                assertNotNull(elapsed.get());assertFalse(elapsed.get().isNegative());assertTrue(elapsed.get().toNanos()<=total);
                assertEquals(1,server.getHitCount(path(role)));
            }
        }));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> revocationCompatibilityEventsReflectTheActualBasicEncoding() {
        return Stream.of(ClientSecretBasicEncoding.FORM_URLENCODED,ClientSecretBasicEncoding.UNENCODED).map(encoding ->
                DynamicTest.dynamicTest(encoding.name(),()->{
            try(TestHttpsServer server=TestHttpsServer.start()) {
                server.script("/revoke",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromStatus(200)));
                AtomicInteger events=new AtomicInteger();
                AccessTokenObserver observer=new AccessTokenObserver(){
                    @Override public void didUseUnencodedBasic(){events.incrementAndGet();}
                };
                OAuthClient client=client(server,TestClock.fromInstant(NOW),observer,
                        ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret",encoding));
                events.set(0);
                client.revoke("TEST-ONLY-token",TokenTypeHint.ACCESS_TOKEN);
                assertEquals(encoding==ClientSecretBasicEncoding.UNENCODED?1:0,events.get());
                assertEquals(1,server.getHitCount("/revoke"));
            }
        }));
    }

    @Test
    void parsingFailureAfterIntrospectionReportsItsActualElapsedTime() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            server.script("/introspect",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,"not-json")));
            AtomicReference<Duration> elapsed=new AtomicReference<>();
            AtomicReference<OAuthException> observed=new AtomicReference<>();
            AccessTokenObserver observer=new AccessTokenObserver(){
                @Override public void didFailEndpoint(@NonNull OAuthEndpoint endpoint,@NonNull URI uri,
                        @NonNull OAuthException failure,@NonNull Duration duration){observed.set(failure);elapsed.set(duration);}
            };
            OAuthClient client=client(server,TestClock.fromInstant(NOW),observer,ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret"));
            TokenIntrospectionClient introspection=TokenIntrospectionClient.withOAuthClient(client).expectedAudiences(Set.of("api"))
                    .observer(observer).build();
            long started=System.nanoTime();
            OAuthException failure=assertThrows(OAuthException.class,()->introspection.validate(bearer()));
            long total=System.nanoTime()-started;
            assertSame(failure,observed.get());assertNotNull(elapsed.get());assertFalse(elapsed.get().isNegative());
            assertTrue(elapsed.get().toNanos()<=total);
        }
    }

    private static void invoke(@NonNull OAuthClient client,@NonNull TestHttpsServer server,@NonNull OAuthEndpoint role,
            @NonNull AccessTokenObserver observer){
        switch(role){
            case TOKEN -> client.requestClientCredentialsToken(TokenRequestOptions.builder().build());
            case REVOCATION -> client.revoke("TEST-ONLY-token",TokenTypeHint.ACCESS_TOKEN);
            case INTROSPECTION -> client.introspectionRequest(bearer(),new ResourceServerMetadata(server.uri("/tenant").toString(),
                    server.uri("/introspect"),Set.of("client_secret_basic","private_key_jwt"),Set.of("RS256"),server.uri("/token")),
                    Deadline.fromNow(Duration.ofSeconds(5)),observer);
            default -> throw new AssertionError(role);
        }
    }
    private static @NonNull BearerToken bearer(){return BearerToken.fromAuthorizationHeaderValues(java.util.List.of("Bearer TEST-ONLY-token")).orElseThrow();}
    private static @NonNull String path(@NonNull OAuthEndpoint role){return switch(role){
        case TOKEN -> "/token";case REVOCATION -> "/revoke";case INTROSPECTION -> "/introspect";default -> throw new AssertionError(role);};}
    private static @NonNull ClientAuthentication assertion(){
        TestJsonWebKeys.Fixture key=TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
        return ClientAuthentication.fromPrivateKeyJwt(budget->ClientAssertionSigningKey.withSigner(
                JwsSigner.fromRsaKeyPair(key.getPrivateKey(),key.getPublicKey(),JwsAlgorithm.RS256)).keyId("rc1-observer-key").build());
    }
    private static @NonNull OAuthClient client(@NonNull TestHttpsServer server,@NonNull TestClock clock,
            @NonNull OAuthObserver observer,@NonNull ClientAuthentication authentication){
        return OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer(server.uri("/tenant").toString())
                .authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token"))
                .revocationEndpoint(server.uri("/revoke")).introspectionEndpoint(server.uri("/introspect"))
                .tokenEndpointAuthMethodsSupported(Set.of("client_secret_basic","private_key_jwt"))
                .revocationEndpointAuthMethodsSupported(Set.of("client_secret_basic","private_key_jwt"))
                .introspectionEndpointAuthMethodsSupported(Set.of("client_secret_basic","private_key_jwt")).build())
                .clientId("client").clientAuthentication(authentication).clock(clock).httpClient(TestTls.httpClient()).observer(observer).build();
    }
}
