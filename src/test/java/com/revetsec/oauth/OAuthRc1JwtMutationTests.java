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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.http.Deadline;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import static org.junit.jupiter.api.Assertions.*;

/** Budget and ownership checks around the existing JWT verification engine. */
final class OAuthRc1JwtMutationTests {
    @Test
    void anExpiredBudgetRejectsBeforeAnyMalformedTokenParsing() {
        JwtAccessTokenValidator validator=Phase2Fixtures.jwt().build();
        OAuthException failure=assertThrows(OAuthException.class,()->validator.validate(
                Phase2Fixtures.bearer("malformed"),Deadline.fromNow(Duration.ZERO)));
        assertEquals(OAuthException.Reason.NETWORK_FAILURE,failure.getReason());
    }

    @Test
    void theFinalBudgetIncludesTheVerifiedJwtObserverCallback() {
        Deadline deadline=Deadline.fromNow(Duration.ofMillis(250));
        AccessTokenObserver observer=new AccessTokenObserver(){
            @Override public void didValidateJwt(@NonNull JwsAlgorithm algorithm,@NonNull Duration elapsed){
                long end=System.nanoTime()+Duration.ofSeconds(2).toNanos();
                while(!deadline.isExpired()){
                    if(System.nanoTime()-end>=0)throw new AssertionError("The deadline must make bounded progress.");
                    Thread.onSpinWait();
                }
            }
        };
        JwtAccessTokenValidator validator=Phase2Fixtures.jwt().observer(observer).build();
        BearerToken token=Phase2Fixtures.bearer(Phase2Fixtures.token(Phase2Fixtures.claims(Phase2Fixtures.ISSUER),"at+jwt"));
        assertEquals(OAuthException.Reason.NETWORK_FAILURE,assertThrows(OAuthException.class,
                ()->validator.validate(token,deadline)).getReason());
    }

    @Test
    void staticValidatorOwnershipIsReleasedBetweenCallerThreads() {
        JwtAccessTokenValidator validator=Phase2Fixtures.jwt().build();
        BearerToken token=Phase2Fixtures.bearer(Phase2Fixtures.token(Phase2Fixtures.claims(Phase2Fixtures.ISSUER),"at+jwt"));
        assertEquals("TEST-ONLY-subject",onCaller(()->validator.validate(token)).getSubject().orElseThrow());
        assertEquals("TEST-ONLY-subject",onCaller(()->validator.validate(token)).getSubject().orElseThrow());
    }

    @Test
    void discoveryRefreshCanPublishAgainFromAnotherCaller() throws Exception {
        try(TestHttpsServer server=TestHttpsServer.start()) {
            TestClock clock=TestClock.fromInstant(Phase2Fixtures.NOW);
            String path="/.well-known/oauth-authorization-server/tenant";
            server.script(path,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,
                    JsonObject.builder().put("issuer",server.uri("/tenant").toString()).put("jwks_uri",server.uri("/keys").toString()).build().toJson())));
            server.script("/keys",TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,Phase2Fixtures.keyJson())));
            JwtAccessTokenValidator validator=JwtAccessTokenValidator.withIssuer(server.uri("/tenant").toString())
                    .expectedAudiences(Set.of("api")).clock(clock).httpClient(TestTls.httpClient())
                    .minimumTimeToLive(Duration.ofSeconds(30)).defaultTimeToLive(Duration.ofSeconds(30))
                    .maximumTimeToLive(Duration.ofMinutes(1)).build();
            onCaller(()->{validator.warmUp();return true;});
            clock.advance(Duration.ofSeconds(31));
            onCaller(()->{validator.warmUp();return true;});
            assertEquals(2,server.getHitCount(path));
        }
    }

    @Test
    void theSelectedPublicAddressPolicyIsRetainedByTheBuilder() {
        assertThrows(IllegalArgumentException.class,()->JwtAccessTokenValidator.withIssuer("https://127.0.0.1/tenant")
                .expectedAudiences(Set.of("api")).outboundUriPolicy(OutboundUriPolicy.publicAddressesOnlyInstance()).build());
    }

    private static <T> @NonNull T onCaller(@NonNull Supplier<@NonNull T> action){
        FutureTask<T> future=new FutureTask<>(action::get);Thread thread=new Thread(future,"rc1-jwt-caller");thread.setDaemon(true);thread.start();
        try{return assertDoesNotThrow(()->future.get(2,TimeUnit.SECONDS));}finally{future.cancel(true);}
    }
}
