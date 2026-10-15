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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.jose.JoseObserver;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.oauth.AuthorizationRedirect;
import com.revetsec.oauth.AuthorizationRequestOptions;
import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.IssuerParameterPolicy;
import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Trusted configuration boundaries and documented complete-snapshot/null-reset contracts. */
final class OidcCloseoutConfigurationTests {
    private static final String ISSUER = "https://issuer.example";
    private static final URI CALLBACK = URI.create("https://rp.example/callback");
    private static final URI RESOURCE = URI.create("https://api.example/owned");

    @Test
    void clientNullResetsRemoveRequestDefaultsAndPreserveFreshAuthorizationProofs() throws Exception {
        OidcClient.Builder builder = client().scopes(Set.of("email")).resources(List.of(RESOURCE))
                .requiredAcrValues(Set.of("urn:mfa")).trustedAudiences(Set.of("other"))
                .trustedAuthorizedParties(Set.of("other"))
                .clientAuthentication(ClientAuthentication.fromClientSecretBasic("TEST-ONLY-secret"));
        builder = builder.scopes(null).resources(null).requiredAcrValues(null).trustedAudiences(null)
                .trustedAuthorizedParties(null).clientAuthentication(null);
        OidcClient client = builder.build();
        AuthorizationRedirect first = client.beginAuthentication();
        AuthorizationRedirect second = client.beginAuthentication();
        QueryParameters query = QueryParameters.parse(first.getAuthorizationUri().getRawQuery());
        assertEquals(List.of("openid"), query.getValues("scope"));
        assertTrue(query.getValues("resource").isEmpty());
        assertTrue(query.getValues("acr_values").isEmpty());
        assertEquals(CALLBACK.toString(), query.getValues("redirect_uri").get(0));
        assertNotEquals(query.getValues("state"), QueryParameters.parse(second.getAuthorizationUri().getRawQuery()).getValues("state"));
        assertTrue(first.getPendingAuthorization().getApplicationData().isEmpty());
    }

    @Test
    void resetTimingObserverAndOutboundConfigurationStillConstructsWithoutProviderIo() throws Exception {
        OidcClient.Builder builder = client().clock(Clock.fixed(Instant.EPOCH, ZoneOffset.UTC))
                .clockSkew(Duration.ZERO).maximumIdTokenAge(Duration.ofMinutes(1))
                .requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(2))
                .outboundUriPolicy(OutboundUriPolicy.defaultInstance()).observer(OidcObserver.disabledInstance())
                .issuerParameterPolicy(IssuerParameterPolicy.REQUIRED);
        builder = builder.clock(null).clockSkew(null).maximumIdTokenAge(null).requestTimeout(null).totalDeadline(null)
                .outboundUriPolicy(null).observer(null).issuerParameterPolicy(null)
                .minimumTimeToLive(null).defaultTimeToLive(null).maximumTimeToLive(null).discoveryCooldown(null);
        Instant before = Instant.now();
        AuthorizationRedirect redirect = builder.build().beginAuthentication();
        Instant after = Instant.now();
        Instant created = redirect.getPendingAuthorization().getCreatedAt();
        assertFalse(created.isBefore(before));
        assertFalse(created.isAfter(after));
        assertTrue(redirect.getPendingAuthorization().getExpiresAt().isAfter(created));
        assertEquals(List.of("code"), QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery()).getValues("response_type"));
    }

    @Test
    void perLoginNullRestoresClientDefaultsWhileClearingEphemeralHintsAndData() throws Exception {
        OidcClient client = client().scopes(Set.of("email")).resources(List.of(RESOURCE))
                .requiredAcrValues(Set.of("urn:default")).build();
        OidcAuthenticationOptions options = OidcAuthenticationOptions.builder()
                .scopes(Set.of("profile")).resources(List.of(URI.create("https://api.example/override")))
                .requiredAcrValues(Set.of("urn:override")).prompt("login").applicationData(Map.of("return", "/app"))
                .additionalParameters(Map.of("audience", "override"))
                .responseMode(AuthorizationRequestOptions.ResponseMode.FORM_POST)
                .scopes(null).resources(null).requiredAcrValues(null).prompt(null).applicationData(null)
                .additionalParameters(null).responseMode(null).build();
        assertTrue(options.getScopes().isEmpty());
        assertTrue(options.getResources().isEmpty());
        assertTrue(options.getRequiredAcrValues().isEmpty());
        assertTrue(options.getPrompt().isEmpty());
        assertTrue(options.getApplicationData().isEmpty());
        AuthorizationRedirect redirect = client.beginAuthentication(options);
        QueryParameters query = QueryParameters.parse(redirect.getAuthorizationUri().getRawQuery());
        assertEquals(List.of("email openid"), query.getValues("scope"));
        assertEquals(List.of(RESOURCE.toString()), query.getValues("resource"));
        assertEquals(List.of("urn:default"), query.getValues("acr_values"));
        assertTrue(query.getValues("prompt").isEmpty());
        assertTrue(query.getValues("audience").isEmpty());
        assertTrue(query.getValues("response_mode").isEmpty());
    }

    @Test
    void resourceOverridesSnapshotCallerListsAndExplicitEmptyDiffersFromNull() throws Exception {
        List<URI> values = new ArrayList<>(List.of(RESOURCE));
        OidcAuthenticationOptions populated = OidcAuthenticationOptions.builder().resources(values).build();
        values.clear();
        assertEquals(List.of(RESOURCE), populated.getResources().orElseThrow());
        assertThrows(UnsupportedOperationException.class, () -> populated.getResources().orElseThrow().clear());
        OidcClient client = client().resources(List.of(RESOURCE)).build();
        QueryParameters none = QueryParameters.parse(client.beginAuthentication(
                OidcAuthenticationOptions.builder().resources(List.of()).build()).getAuthorizationUri().getRawQuery());
        assertTrue(none.getValues("resource").isEmpty());
        QueryParameters inherited = QueryParameters.parse(client.beginAuthentication(
                OidcAuthenticationOptions.builder().resources(null).build()).getAuthorizationUri().getRawQuery());
        assertEquals(List.of(RESOURCE.toString()), inherited.getValues("resource"));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> incompleteOrEmptyTrustConfigurationCannotBuild() {
        return Stream.of(
                DynamicTest.dynamicTest("missing client ID", () -> assertThrows(IllegalStateException.class,
                        () -> OidcClient.withProviderMetadata(metadata()).redirectUri(CALLBACK).build())),
                DynamicTest.dynamicTest("missing callback", () -> assertThrows(IllegalStateException.class,
                        () -> OidcClient.withProviderMetadata(metadata()).clientId("client").build())),
                DynamicTest.dynamicTest("empty client ID", () -> assertThrows(IllegalArgumentException.class,
                        () -> client().clientId("").build())),
                DynamicTest.dynamicTest("empty algorithm allowlist", () -> assertThrows(IllegalArgumentException.class,
                        () -> client().idTokenSigningAlgorithms(Set.of()).build())),
                DynamicTest.dynamicTest("empty trusted audience", () -> assertThrows(IllegalArgumentException.class,
                        () -> client().trustedAudiences(Set.of("")).build())),
                DynamicTest.dynamicTest("empty trusted party", () -> assertThrows(IllegalArgumentException.class,
                        () -> client().trustedAuthorizedParties(Set.of("")).build())));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> directValidatorCannotBypassEmptyTrustChecks() {
        return Stream.of(
                DynamicTest.dynamicTest("empty issuer", () -> assertThrows(IllegalArgumentException.class,
                        () -> validator("", "client", Set.of(JwsAlgorithm.RS256), Set.of(), Set.of(), false))),
                DynamicTest.dynamicTest("empty client ID", () -> assertThrows(IllegalArgumentException.class,
                        () -> validator(ISSUER, "", Set.of(JwsAlgorithm.RS256), Set.of(), Set.of(), false))),
                DynamicTest.dynamicTest("empty algorithm allowlist", () -> assertThrows(IllegalArgumentException.class,
                        () -> validator(ISSUER, "client", Set.of(), Set.of(), Set.of(), false))),
                DynamicTest.dynamicTest("empty audience", () -> assertThrows(IllegalArgumentException.class,
                        () -> validator(ISSUER, "client", Set.of(JwsAlgorithm.RS256), Set.of(""), Set.of(), false))),
                DynamicTest.dynamicTest("empty authorized party", () -> assertThrows(IllegalArgumentException.class,
                        () -> validator(ISSUER, "client", Set.of(JwsAlgorithm.RS256), Set.of(), Set.of(""), false))),
                DynamicTest.dynamicTest("HMAC without opt-in", () -> assertThrows(IllegalArgumentException.class,
                        () -> validator(ISSUER, "client", Set.of(JwsAlgorithm.HS256), Set.of(), Set.of(), false))));
    }

    @Test
    void malformedAuthenticatedOptionsRejectBeforeAttemptingTokenParsing() {
        IdTokenValidator validator = validator(ISSUER, "client", Set.of(JwsAlgorithm.RS256), Set.of(), Set.of(), false);
        assertThrows(IllegalArgumentException.class, () -> validator.validate("invalid", "", "token", "code", null, Set.of()));
        assertThrows(IllegalArgumentException.class, () -> validator.validate("invalid", "nonce", "token", "code", null, Set.of("")));
        assertThrows(IllegalArgumentException.class, () -> validator.validate("invalid", "nonce", "token", "code", Duration.ofSeconds(-1), Set.of()));
        IdTokenValidator hmac = validator(ISSUER, "client", Set.of(JwsAlgorithm.HS256), Set.of(), Set.of(), true);
        OidcValidationException error = assertThrows(OidcValidationException.class,
                () -> hmac.validate("invalid", "nonce", "token", "code", null, Set.of()));
        assertEquals(OidcValidationException.Reason.HMAC_SECRET_INVALID, error.getReason());
    }

    @Test
    void tenantIssuerExtractionRequiresExactCloudSpellingAndLowercaseGuid() {
        String tenant = "01234567-89ab-cdef-0123-456789abcdef";
        assertEquals(tenant, OidcIssuerPolicy.tenantFromIssuer("https://login.microsoftonline.com/" + tenant + "/v2.0"));
        for (String issuer : List.of(
                "https://LOGIN.microsoftonline.com/01234567-89ab-cdef-0123-456789abcdef/v2.0",
                "https://login.microsoftonline.com/01234567-89ab-cdef-0123-456789abcdef/v2.1",
                "https://login.microsoftonline.com/01234567_89ab-cdef-0123-456789abcdef/v2.0",
                "https://login.microsoftonline.com//1234567-89ab-cdef-0123-456789abcdef/v2.0",
                "https://login.microsoftonline.com/:1234567-89ab-cdef-0123-456789abcdef/v2.0",
                "https://login.microsoftonline.com/`1234567-89ab-cdef-0123-456789abcdef/v2.0",
                "https://login.microsoftonline.com/g1234567-89ab-cdef-0123-456789abcdef/v2.0",
                "https://login.microsoftonline.com/01234567-89ab-cdef-0123-456789ABCDEF/v2.0")) {
            assertNull(OidcIssuerPolicy.tenantFromIssuer(issuer), issuer);
        }
    }

    @Test
    void entraValidatorRejectsHmacFlagAndHmacAllowlistIndependently() {
        OidcIssuerPolicy policy = OidcIssuerPolicy.fromMicrosoftEntraMultiTenant(tenant -> true);
        String issuer = "https://login.microsoftonline.com/common/v2.0";
        assertThrows(IllegalArgumentException.class, () -> new IdTokenValidator(issuer, "client", keys(),
                Set.of(JwsAlgorithm.RS256), Set.of(), Set.of(), Duration.ZERO, Duration.ofMinutes(5),
                Clock.systemUTC(), OidcObserver.disabledInstance(), true, policy));
        assertThrows(IllegalArgumentException.class, () -> new IdTokenValidator(issuer, "client", keys(),
                Set.of(JwsAlgorithm.HS256), Set.of(), Set.of(), Duration.ZERO, Duration.ofMinutes(5),
                Clock.systemUTC(), OidcObserver.disabledInstance(), false, policy));
        IdTokenValidator allowed = new IdTokenValidator(issuer, "client", keys(), Set.of(JwsAlgorithm.RS256),
                Set.of(), Set.of(), Duration.ZERO, Duration.ofMinutes(5), Clock.systemUTC(),
                OidcObserver.disabledInstance(), false, policy);
        assertTrue(allowed.needsPublicKeys());
    }

    private static @NonNull OidcProviderMetadata metadata() {
        return OidcProviderMetadata.withIssuer(ISSUER)
                .authorizationEndpoint(URI.create(ISSUER + "/authorize"))
                .tokenEndpoint(URI.create(ISSUER + "/token"))
                .jwksUri(URI.create(ISSUER + "/jwks"))
                .build();
    }
    private static OidcClient.@NonNull Builder client() {
        return OidcClient.withProviderMetadata(metadata()).clientId("client").redirectUri(CALLBACK)
                .jsonWebKeySource(keys());
    }
    private static @NonNull StaticJsonWebKeySource keys() {
        String json = TestJsonWebKeys.withFixture(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048)
                .kid("TEST-ONLY-closeout").alg("RS256").toKeySetJson();
        return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(json));
    }
    private static @NonNull IdTokenValidator validator(@NonNull String issuer, @NonNull String client,
            @NonNull Set<@NonNull JwsAlgorithm> algorithms, @NonNull Set<@NonNull String> audiences,
            @NonNull Set<@NonNull String> parties, boolean hmac) {
        return new IdTokenValidator(issuer, client, keys(), algorithms, audiences, parties,
                Duration.ZERO, Duration.ofMinutes(5), Clock.systemUTC(), JoseObserver.disabledInstance(), hmac);
    }
}
