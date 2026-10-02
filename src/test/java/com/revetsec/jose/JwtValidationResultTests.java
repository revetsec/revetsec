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

package com.revetsec.jose;

import org.jspecify.annotations.NonNull;

import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws.Algorithm;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import com.revetsec.RevetsecException;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

final class JwtValidationResultTests {
    @Test
    void successKeepsTheValidatedJwtAndObserversRunOnceEvenWhenTheyThrow() {
        AtomicInteger successes = new AtomicInteger();
        AtomicInteger failures = new AtomicInteger();
        JoseObserver observer = new JoseObserver() {
            @Override public void didValidateJwt(@NonNull JwsAlgorithm algorithm, @NonNull Duration elapsed) {
                successes.incrementAndGet(); throw new IllegalStateException("TEST-ONLY-hook");
            }
            @Override public void didFailToValidateJwt(@NonNull RevetsecException exception, @NonNull Duration elapsed) {
                failures.incrementAndGet(); throw new IllegalStateException("TEST-ONLY-hook");
            }
        };
        JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048))
                .observer(observer).build();
        String token = JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256);
        JwtValidationResult.Succeeded success = assertInstanceOf(JwtValidationResult.Succeeded.class,
                validator.validateResult(token));
        assertEquals("subject-1", success.getJwt().getClaims().getSubject().orElseThrow());
        assertEquals(token, success.getJwt().toCompactSerialization());
        assertFalse(success.toString().contains(token));
        assertFalse(success.toString().contains("subject-1"));
        assertInstanceOf(JwtValidationResult.Rejected.class, validator.validateResult("bad.jwt"));
        assertEquals(1, successes.get()); assertEquals(1, failures.get());
    }

    @Test
    void expiryAtTheExactBoundaryAndAudienceMismatchNeverYieldSuccess() {
        JwtValidator validator = JwtFixtures.validator(JwtFixtures.source(Fixture.IDP_SIGNING_RSA_2048))
                .clockSkew(Duration.ZERO).build();
        String expired = JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256,
                JwtFixtures.claims().put("exp", JwtFixtures.NOW.getEpochSecond()));
        JwtValidationResult.Rejected failure = assertInstanceOf(JwtValidationResult.Rejected.class,
                validator.validateResult(expired));
        assertEquals(JoseException.Reason.EXPIRED, failure.getReason());
        assertEquals(JoseException.Reason.EXPIRED, assertThrows(JoseException.class,
                () -> validator.validate(expired)).getReason());
        String wrongAudience = JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256,
                JwtFixtures.claims().put("aud", "TEST-ONLY-wrong-audience"));
        assertEquals(JoseException.Reason.AUDIENCE_MISMATCH,
                assertInstanceOf(JwtValidationResult.Rejected.class, validator.validateResult(wrongAudience)).getReason());
        String forged = JwtFixtures.signed(Fixture.NEGATIVE_ATTACKER_RSA_2048, Algorithm.RS256,
                JwtFixtures.claims().put("exp", JwtFixtures.NOW.getEpochSecond()));
        assertEquals(JoseException.Reason.SIGNATURE_MISMATCH,
                assertInstanceOf(JwtValidationResult.Rejected.class, validator.validateResult(forged)).getReason());
        assertFalse(failure.toString().contains(expired));
    }

    @Test
    void malformedInputDoesNoKeyIoAndAProviderOutageStaysAnException() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            server.script("/jwks", TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.withStatus(503)
                    .header("Content-Type", "application/json").body("{}".getBytes(java.nio.charset.StandardCharsets.UTF_8)).build()));
            RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(server.uri("/jwks"))
                    .httpClient(TestTls.httpClient()).build();
            JwtValidator validator = JwtFixtures.validator(source).build();
            assertInstanceOf(JwtValidationResult.Rejected.class, validator.validateResult("bad.jwt"));
            assertEquals(0, server.getRequests().size());
            String token = JwtFixtures.signed(Fixture.IDP_SIGNING_RSA_2048, Algorithm.RS256);
            assertThrows(JsonWebKeySetUnavailableException.class, () -> validator.validateResult(token));
            assertEquals(1, server.getRequests().size());
        }
    }

    @SuppressWarnings("NullAway") // Deliberate required-argument misuse.
    @Test
    void nullRemainsProgrammerMisuse() {
        JwtValidator validator = JwtFixtures.validator(Fixture.IDP_SIGNING_RSA_2048, JwsAlgorithm.RS256);
        assertThrows(NullPointerException.class, () -> validator.validateResult(null));
    }
}
