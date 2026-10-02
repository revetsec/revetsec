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

import static com.revetsec.oauth.Phase2Fixtures.*;
import static org.junit.jupiter.api.Assertions.*;

import com.revetsec.jose.JoseException;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestTls;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import com.revetsec.testing.JsonText;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/** Behavior calibrations for the resource-server credential, provider-failure and replay boundaries. */
final class ResourceServerAssuranceTests {
    @Test
    void signedTokenForAnotherAudienceNeverReleasesProofOrSuccessEvent() {
        RecordingObserver<@NonNull AccessTokenObserver> events = RecordingObserver.fromInterface(AccessTokenObserver.class);
        JwtAccessTokenValidator validator = jwt().observer(events.getObserver()).build();
        Map<@NonNull String, @NonNull String> claims = claims(ISSUER);
        assertEquals(List.of(AUD), validator.validate(bearer(token(claims, "at+jwt"))).getAudiences());
        claims.put("aud", "\"other-resource\"");
        AccessTokenValidationResult.Rejected rejection = assertInstanceOf(AccessTokenValidationResult.Rejected.class,
                validator.validateResult(bearer(token(claims, "at+jwt"))));
        assertEquals(Optional.of(JoseException.Reason.AUDIENCE_MISMATCH), rejection.getJoseReason());
        assertEquals(BearerError.INVALID_TOKEN, rejection.getBearerError());
        assertEquals(1, eventCount(events, "didValidateAccessToken"));
        assertEquals(1, eventCount(events, "didRejectAccessToken"));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> untypedIdentityClaimPresenceCannotAuthorizeAnAccessToken() {
        return Stream.of("nonce", "at_hash", "c_hash", "auth_time").flatMap(name ->
                Stream.of("null", "\"\"", "false").map(value -> DynamicTest.dynamicTest(name + ":" + value, () -> {
                    Map<@NonNull String, @NonNull String> claims = claims(ISSUER);
                    claims.put("app", "true");
                    JwtAccessTokenValidator validator = jwt().compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS)
                            .requiredClaims(Set.of("app")).build();
                    assertNotNull(validator.validate(bearer(token(claims, "JWT"))));
                    claims.put(name, value);
                    AccessTokenValidationResult.Rejected rejection = assertInstanceOf(AccessTokenValidationResult.Rejected.class,
                            validator.validateResult(bearer(token(claims, "JWT"))));
                    assertEquals(AccessTokenValidationException.Reason.UNTYPED_IDENTITY_CLAIM_PRESENT, rejection.getReason());
                    assertEquals(BearerError.INVALID_TOKEN, rejection.getBearerError());
                })));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> confirmationPresenceIsRejectedForSignedAndIntrospectedTokens() {
        return Stream.of("null", "{}", "false", "\"\"", "{\"jkt\":\"TEST-ONLY-thumbprint\"}").map(value ->
                DynamicTest.dynamicTest("cnf=" + value, () -> {
                    Map<@NonNull String, @NonNull String> claims = claims(ISSUER);
                    claims.put("cnf", value);
                    AccessTokenValidationResult.Rejected signed = assertInstanceOf(AccessTokenValidationResult.Rejected.class,
                            jwt().build().validateResult(bearer(token(claims, "at+jwt"))));
                    assertEquals(Optional.of(JoseException.Reason.CONFIRMATION_NOT_VERIFIED), signed.getJoseReason());
                    AccessTokenValidationException opaque = assertThrows(AccessTokenValidationException.class, () ->
                            IntrospectionResponse.parse(raw(200, "{\"active\":true,\"aud\":\"resource\",\"cnf\":" + value + "}"), NOW)
                                    .validate(ISSUER, Set.of(AUD), Set.of(), NOW, Duration.ZERO));
                    assertEquals(AccessTokenValidationException.Reason.CONFIRMATION_NOT_VERIFIED, opaque.getReason());
                    assertEquals(BearerError.INVALID_TOKEN, opaque.getBearerError());
                }));
    }

    @Test
    void stringActiveIsAProviderFailureAndNeverACredentialVerdict() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            RecordingObserver<@NonNull AccessTokenObserver> events = RecordingObserver.fromInterface(AccessTokenObserver.class);
            TokenIntrospectionClient validator = inspect(server).observer(events.getObserver()).build();
            response(server, "/inspect", 200, "application/json", "{\"active\":\"true\",\"aud\":\"resource\"}");
            OAuthResponseException failure = assertThrows(OAuthResponseException.class,
                    () -> validator.validateResult(bearer("TEST-ONLY-string-active")));
            assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED, failure.getReason());
            assertEquals(0, eventCount(events, "didValidateAccessToken"));
            assertEquals(0, eventCount(events, "didRejectAccessToken"));
            assertEquals(1, server.getHitCount("/inspect"));
        }
    }

    @Test
    void identicalCredentialIsPostedAgainAndNewScopeSubjectAndInactiveVerdictsAreUsed() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            TokenIntrospectionClient validator = inspect(server).build();
            BearerToken credential = bearer("TEST-ONLY-repeated-credential");
            response(server, "/inspect", 200, "application/json", "{\"active\":true,\"aud\":\"resource\",\"scope\":\"read\",\"sub\":\"first\"}");
            VerifiedAccessToken first = validator.validate(credential);
            assertEquals(Set.of("read"), first.getScopes());
            assertEquals(Optional.of("first"), first.getSubject());
            response(server, "/inspect", 200, "application/json", "{\"active\":true,\"aud\":\"resource\",\"scope\":\"write\",\"sub\":\"second\"}");
            VerifiedAccessToken second = validator.validate(credential);
            assertNotSame(first, second);
            assertEquals(Set.of("write"), second.getScopes());
            assertEquals(Optional.of("second"), second.getSubject());
            assertEquals(Set.of("read"), first.getScopes());
            response(server, "/inspect", 200, "application/json", "{\"active\":false}");
            assertEquals(AccessTokenValidationException.Reason.INACTIVE,
                    assertInstanceOf(AccessTokenValidationResult.Rejected.class, validator.validateResult(credential)).getReason());
            response(server, "/inspect", 200, "application/json", active());
            assertEquals(Set.of("read", "write"), validator.validate(credential).getScopes());
            assertEquals(4, server.getHitCount("/inspect"));
            assertTrue(server.getRequests("/inspect").stream().allMatch(request ->
                    request.getBodyAsString().equals("token=TEST-ONLY-repeated-credential&token_type_hint=access_token")));
        }
    }

    @Test
    void unavailableIntrospectionIsAnExceptionWithoutInvalidTokenEventOrResult() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            RecordingObserver<@NonNull AccessTokenObserver> events = RecordingObserver.fromInterface(AccessTokenObserver.class);
            TokenIntrospectionClient validator = inspect(server).observer(events.getObserver()).build();
            response(server, "/inspect", 503, "application/json", "{}");
            OAuthErrorResponseException failure = assertThrows(OAuthErrorResponseException.class,
                    () -> validator.validateResult(bearer("TEST-ONLY-unavailable")));
            assertSame(failure, assertThrows(OAuthErrorResponseException.class,
                    () -> validator.validateResult(bearer("TEST-ONLY-different"))));
            assertEquals(0, eventCount(events, "didValidateAccessToken"));
            assertEquals(0, eventCount(events, "didRejectAccessToken"));
            assertEquals(1, eventCount(events, "didFailEndpoint"));
            assertEquals(1, server.getHitCount("/inspect"));
        }
    }

    @Test
    void metadataRequestsReportOneBoundedLifecycleAndWarmCacheDoesNotRequestAgain() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            RecordingObserver<@NonNull AccessTokenObserver> events = RecordingObserver.fromInterface(AccessTokenObserver.class);
            String issuer = server.getBaseUri().toString();
            response(server, "/.well-known/oauth-authorization-server", 200, "application/json",
                    "{\"issuer\":" + JsonText.string(issuer) + ",\"jwks_uri\":" + JsonText.string(server.uri("/keys").toString()) + "}");
            response(server, "/keys", 200, "application/json", keyJson());
            JwtAccessTokenValidator validator = JwtAccessTokenValidator.withIssuer(issuer).expectedAudiences(Set.of(AUD))
                    .clock(CLOCK).httpClient(TestTls.httpClient()).observer(events.getObserver()).build();
            validator.warmUp();
            validator.warmUp();
            assertEquals(1, server.getHitCount("/.well-known/oauth-authorization-server"));
            assertEquals(1, server.getHitCount("/keys"));
            assertEquals(1, eventCount(events, "willRequestEndpoint"));
            assertEquals(1, eventCount(events, "didRequestEndpoint"));
            assertEquals(0, eventCount(events, "didFailEndpoint"));
            RecordingObserver.Call before = events.getCalls("willRequestEndpoint").get(0);
            RecordingObserver.Call completed = events.getCalls("didRequestEndpoint").get(0);
            assertEquals(OAuthEndpoint.METADATA, before.getArguments().get(0));
            assertEquals(server.uri("/.well-known/oauth-authorization-server"), before.getArguments().get(1));
            assertEquals(before.getArguments().get(1), completed.getArguments().get(1));
            assertEquals(OAuthEndpoint.METADATA, completed.getArguments().get(0));
            assertEquals(200, completed.getArguments().get(2));
            assertBoundedElapsed(completed.getArguments().get(3));
            assertEquals(0, eventCount(events, "didValidateAccessToken"));
            assertEquals(0, eventCount(events, "didRejectAccessToken"));
        }
    }

    @Test
    void failedMetadataTlsRequestReportsTheSameInfrastructureExceptionOnce() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            RecordingObserver<@NonNull AccessTokenObserver> events = RecordingObserver.fromInterface(AccessTokenObserver.class);
            JwtAccessTokenValidator validator = JwtAccessTokenValidator.withIssuer(server.getBaseUri().toString())
                    .expectedAudiences(Set.of(AUD)).observer(events.getObserver()).build();
            OAuthTransportException failure = assertThrows(OAuthTransportException.class, validator::warmUp);
            assertEquals(1, eventCount(events, "willRequestEndpoint"));
            assertEquals(0, eventCount(events, "didRequestEndpoint"));
            assertEquals(1, eventCount(events, "didFailEndpoint"));
            RecordingObserver.Call failed = events.getCalls("didFailEndpoint").get(0);
            assertEquals(OAuthEndpoint.METADATA, failed.getArguments().get(0));
            assertEquals(server.uri("/.well-known/oauth-authorization-server"), failed.getArguments().get(1));
            assertSame(failure, failed.getArguments().get(2));
            assertBoundedElapsed(failed.getArguments().get(3));
            assertEquals(0, eventCount(events, "didValidateAccessToken"));
            assertEquals(0, eventCount(events, "didRejectAccessToken"));
        }
    }

    @Test
    void maximumSignedCredentialLengthIsInclusiveAndOneMoreCharacterRejectsBeforeKeyUse() {
        Map<@NonNull String, @NonNull String> claims = claims(ISSUER);
        claims.put("padding", "\"" + "a".repeat(6_500) + "\"");
        String credential = token(claims, "at+jwt");
        JwtAccessTokenValidator validator = jwt().maximumTokenLength(credential.length()).build();
        assertEquals(List.of(AUD), validator.validate(bearer(credential)).getAudiences());
        AccessTokenValidationResult.Rejected rejected = assertInstanceOf(AccessTokenValidationResult.Rejected.class,
                validator.validateResult(bearer(credential + "a")));
        assertEquals(AccessTokenValidationException.Reason.MALFORMED_REQUEST, rejected.getReason());
        assertEquals(BearerError.INVALID_REQUEST, rejected.getBearerError());
    }

    @Test
    void maximumOpaqueCredentialLengthIsInclusiveAndOneMoreCharacterDoesNotPost() throws Exception {
        try (TestHttpsServer server = TestHttpsServer.start()) {
            TokenIntrospectionClient validator = inspect(server).maximumTokenLength(8_192).build();
            response(server, "/inspect", 200, "application/json", active());
            assertEquals(List.of(AUD), validator.validate(bearer("a".repeat(8_192))).getAudiences());
            AccessTokenValidationResult.Rejected rejected = assertInstanceOf(AccessTokenValidationResult.Rejected.class,
                    validator.validateResult(bearer("a".repeat(8_193))));
            assertEquals(AccessTokenValidationException.Reason.MALFORMED_REQUEST, rejected.getReason());
            assertEquals(BearerError.INVALID_REQUEST, rejected.getBearerError());
            assertEquals(1, server.getHitCount("/inspect"));
        }
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> scopeGrammarAcceptsAdjacentLegalOctetsAndRejectsDelimiters() {
        return Stream.of(0x21, 0x23, 0x5b, 0x5d, 0x7e, 0x22, 0x5c, 0x7f).map(octet ->
                DynamicTest.dynamicTest("scope-octet=" + octet, () -> {
                    String scope = "read" + (char) octet.intValue();
                    Map<@NonNull String, @NonNull String> claims = claims(ISSUER);
                    claims.put("scope", JsonText.string(scope));
                    if (Set.of(0x22, 0x5c, 0x7f).contains(octet)) {
                        assertEquals(AccessTokenValidationException.Reason.SCOPE_INVALID,
                                assertInstanceOf(AccessTokenValidationResult.Rejected.class,
                                        jwt().build().validateResult(bearer(token(claims, "at+jwt")))).getReason());
                    } else {
                        assertEquals(Set.of(scope), jwt().build().validate(bearer(token(claims, "at+jwt"))).getScopes());
                    }
                }));
    }

    @Test
    void explicitAccessTokenTypeDoesNotReportUntypedCompatibilityUse() {
        RecordingObserver<@NonNull AccessTokenObserver> events = RecordingObserver.fromInterface(AccessTokenObserver.class);
        Map<@NonNull String, @NonNull String> claims = claims(ISSUER);
        claims.put("app", "true");
        JwtAccessTokenValidator validator = jwt().compatibility(AccessTokenCompatibilityMode.UNTYPED_ACCESS_TOKENS)
                .requiredClaims(Set.of("app")).observer(events.getObserver()).build();
        assertNotNull(validator.validate(bearer(token(claims, "at+jwt"))));
        assertEquals(1, eventCount(events, "didEnableCompatibilityMode"));
        assertEquals(0, eventCount(events, "didUseCompatibilityMode"));
        assertEquals(1, eventCount(events, "didValidateAccessToken"));
        assertEquals(0, eventCount(events, "didRejectAccessToken"));
    }

    private static void assertBoundedElapsed(@Nullable Object elapsed) {
        Duration actual = assertInstanceOf(Duration.class, elapsed);
        assertFalse(actual.isNegative());
        assertTrue(actual.compareTo(Duration.ofSeconds(10)) < 0);
    }

    private static long eventCount(@NonNull RecordingObserver<@NonNull AccessTokenObserver> events, @NonNull String name) {
        return events.getCalls().stream().filter(call -> call.getMethodName().equals(name)).count();
    }
}
