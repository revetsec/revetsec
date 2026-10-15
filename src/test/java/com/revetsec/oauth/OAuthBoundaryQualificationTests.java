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

import com.revetsec.internal.Limits;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Boundary qualification for untrusted persisted records and endpoint/callback data. */
final class OAuthBoundaryQualificationTests {
    private static final Instant NOW = Instant.parse("2026-10-14T12:00:00Z");

    @Test
    void persistedRecordsRejectWrongVersionsTypesAndLifetimeBounds() {
        JsonObject valid = record("oauth");
        assertEquals("oauth", PendingAuthorizationCodec.decode(valid.toJson()).pending().kind());
        for (JsonValue version : List.of(JsonString.fromValue("1"), JsonNumber.fromValue(new java.math.BigDecimal("1.5")),
                JsonNumber.fromValue(new java.math.BigDecimal("0")), JsonNumber.fromValue(new java.math.BigDecimal("3")))) rejectRecord(valid, "v", version);
        rejectRecord(valid, "kind", JsonString.fromValue("saml"));
        for (String end : List.of(NOW.minusSeconds(1).toString(), NOW.toString(), NOW.plusSeconds(3601).toString()))
            rejectRecord(valid, "expires_at", JsonString.fromValue(end));
        rejectRecord(valid, "issuer", JsonString.fromValue(""));
        rejectRecord(valid, "client_id", JsonBoolean.trueInstance());
        rejectRecord(valid, "scopes", JsonBoolean.trueInstance());
        rejectRecord(valid, "scopes", JsonArray.fromElements(List.of(JsonBoolean.trueInstance())));
        rejectRecord(valid, "application_data", JsonBoolean.trueInstance());
        rejectRecord(valid, "application_data", JsonObject.builder().put("key", false).build());
        rejectRecord(valid, "issuer_required", JsonString.fromValue("true"));
        rejectRecord(valid, "v", JsonNumber.fromValue(new java.math.BigDecimal("2")));
        rejectRecord(valid, "max_age", JsonNumber.fromValue(new java.math.BigDecimal("0")));
        rejectRecord(valid, "acr_values", JsonArray.fromElements(List.of()));
        rejectRecord(valid, "prompt", JsonString.fromValue("login"));
        for (String text : List.of("[]", "{}", "a".repeat(65537)))
            assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID,
                    assertThrows(OAuthValidationException.class, () -> PendingAuthorizationCodec.decode(text)).getReason());
    }

    @Test
    void oidcRecordsRequireUnambiguousAcrAndPromptSemantics() {
        JsonObject valid = record("oidc");
        assertEquals("oidc", PendingAuthorizationCodec.decode(valid.toJson()).pending().kind());
        for (String acr : List.of("", "control\u001f", "nonascii\u0080"))
            rejectRecord(valid, "acr_values", JsonArray.fromElements(List.of(JsonString.fromValue(acr))));
        for (String prompt : List.of("login login", "none consent", "login ", "unknown"))
            rejectRecord(valid, "prompt", JsonString.fromValue(prompt));
        Map<String, JsonValue> missing = new LinkedHashMap<>(valid.getMembers());
        missing.remove("nonce");
        assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID,
                assertThrows(OAuthValidationException.class,
                        () -> PendingAuthorizationCodec.decode(JsonObject.fromMembers(missing).toJson())).getReason());
        JsonObject supplied = replaced(valid, "resources", JsonArray.fromElements(List.of(JsonString.fromValue("https://api.example"))));
        assertEquals(List.of(URI.create("https://api.example")), PendingAuthorizationCodec.decode(supplied.toJson()).pending().resources());
        assertThrows(IllegalArgumentException.class, () -> PendingAuthorizationCodec.bindingDigest(""));
        assertEquals(43, PendingAuthorizationCodec.bindingDigest("browser").length());
    }

    @Test
    void tokenDocumentsRequireBoundedIntegralExpiryAndScopeGrammar() {
        for (String expires : List.of("false", "null", "\"\"", "\"12345678901234567890\"", "\"9223372036854775808\"", "\"1/2\""))
            malformedToken("{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":" + expires + "}");
        for (String scope : List.of("a a", "a  b", "a\\t", "a\\\"", "a\\\\", "a\\u007f"))
            malformedToken("{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"scope\":\"" + scope + "\"}");
        for (String body : List.of("", "[]", "false", "{\"access_token\":\"\",\"token_type\":\"Bearer\"}",
                "{\"access_token\":false,\"token_type\":\"Bearer\"}",
                "{\"access_token\":\"a\",\"token_type\":\"\"}")) malformedToken(body);
        TokenResponse response = TokenResponseParser.parse(raw(200,
                "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":0,\"scope\":\"a b\"}"), NOW, null);
        assertEquals(NOW, response.getExpiresAt().orElseThrow());
        assertEquals(Set.of("a", "b"), response.getGrantedScopes().orElseThrow());
        assertThrows(IllegalArgumentException.class, () -> TokenResponseParser.error(raw(200, ""), NOW));
        for (String body : List.of("", "[]", "{\"error\":false}", "{\"error\":\"Invalid_Grant\"}")) {
            OAuthErrorResponseException failure = TokenResponseParser.error(raw(400, body), NOW);
            assertEquals(400, failure.getStatus());
            assertTrue(failure.getErrorCode().isEmpty());
        }
    }

    @Test
    void bearerHeaderGrammarAndSafeErrorCodesRejectInjection() {
        assertThrows(IllegalArgumentException.class, () -> new AccessToken("", "Bearer", null));
        assertThrows(IllegalArgumentException.class, () -> new AccessToken("a", "", null));
        for (String value : List.of("AZaz09-._~+/", "a=", "a=="))
            assertEquals("Bearer " + value, new AccessToken(value, "Bearer", null).getAuthorizationHeaderValue());
        for (String value : List.of("=", "a=b", "a!", "a:", "a[", "a`", "a{", "a ", "a\r\nHeader:x"))
            assertThrows(IllegalStateException.class, () -> new AccessToken(value, "Bearer", null).getAuthorizationHeaderValue());
        assertEquals("az09_", OAuthSafeErrorCode.fromValue("az09_"));
        for (String value : List.of("", "a".repeat(65), "A", "a/", "a:", "a`", "a{", "a\n"))
            assertNull(OAuthSafeErrorCode.fromValue(value));
        assertNull(OAuthSafeErrorCode.fromValue(null));
    }

    @Test
    void callbackLimitsAccountForEmptyListsMultiplicitiesAndUtf8Bytes() {
        int query = Limits.AUTHORIZATION_RESPONSE_QUERY_SIZE.getDefaultIntValue();
        int parameter = Limits.AUTHORIZATION_RESPONSE_PARAMETER_SIZE.getDefaultIntValue();
        Map<String, List<String>> manyNames = new LinkedHashMap<>();
        for (int i = 0; i <= query; i++) manyNames.put("p" + i, List.of());
        malformedCallback(manyNames, null);
        malformedCallback(Map.of("x", new ArrayList<>(java.util.Collections.nCopies(query + 1, ""))), null);
        malformedCallback(Map.of("x".repeat(parameter + 1), List.of()), null);
        malformedCallback(Map.of("x", List.of("a".repeat(parameter))), null);
        malformedCallback(Map.of("x", List.of("\u0800".repeat(parameter / 3 + 1))), null);
        Map<String, List<String>> aggregate = new LinkedHashMap<>();
        for (int i = 0; i < 5; i++) aggregate.put("p" + i, List.of("a".repeat(parameter - 2)));
        malformedCallback(aggregate, null);
        malformedCallback(Map.of("x", List.of("")), "x=");
        malformedCallback(Map.of("x", new ArrayList<>(java.util.Collections.nCopies(query, ""))), "y=");
        malformedCallback(Map.of("x", List.of("a".repeat(parameter - 1))), "y=" + "b".repeat(parameter - 2)
                + "&z=" + "c".repeat(parameter - 2) + "&q=" + "d".repeat(parameter - 2) + "&r=aaaaa");
        assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, assertThrows(OAuthResponseException.class,
                () -> AuthorizationResponse.fromQueryString("a".repeat(query + 1))).getReason());
        AuthorizationResponse empty = AuthorizationResponse.fromParameters(Map.of("code", List.of()), null,
                AuthorizationRequestOptions.ResponseMode.QUERY);
        assertTrue(empty.getCode().isEmpty());
    }

    @Test
    void callbackErrorProseIsBoundedAndUrisMustBeAbsolute() {
        String raw = " !\"#[\\]~\u007f\u0080";
        AuthorizationResponse response = AuthorizationResponse.fromParameters(Map.of("error_description", List.of(raw)), null,
                AuthorizationRequestOptions.ResponseMode.QUERY);
        assertEquals(" !?#[?]~??", response.getErrorDescription().orElseThrow());
        assertEquals(raw, response.getParameters().getOrDefault("error_description", List.of()).get(0));
        assertEquals(1024, AuthorizationResponse.fromParameters(Map.of("error_description", List.of("a".repeat(1025))), null,
                AuthorizationRequestOptions.ResponseMode.QUERY).getErrorDescription().orElseThrow().length());
        for (String uri : List.of("relative", "https://[invalid"))
            assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, assertThrows(OAuthResponseException.class,
                    () -> AuthorizationResponse.fromParameters(Map.of("error_uri", List.of(uri)), null,
                            AuthorizationRequestOptions.ResponseMode.QUERY).getErrorUri()).getReason());
        assertEquals(URI.create("https://issuer.example/error"), AuthorizationResponse.fromQueryString(
                "error_uri=https%3A%2F%2Fissuer.example%2Ferror").getErrorUri().orElseThrow());
    }

    @Test
    void tokenOptionsDistinguishInheritanceFromExplicitEmptyAndCopyCollections() {
        for (String scope : List.of("", "a b", "a\"", "a\\", "a\u007f"))
            assertThrows(IllegalArgumentException.class, () -> TokenRequestOptions.builder().scopes(Set.of(scope)));
        for (String resource : List.of("relative", "https://api.example#fragment"))
            assertThrows(IllegalArgumentException.class, () -> TokenRequestOptions.builder().resources(List.of(URI.create(resource))));
        assertThrows(IllegalArgumentException.class, () -> TokenRequestOptions.builder().additionalParameters(Map.of("", "value")));
        TokenRequestOptions empty = TokenRequestOptions.builder().resources(List.of()).scopes(Set.of()).build();
        assertTrue(empty.resourcesOverridden());
        assertEquals(Set.of(), empty.getScopes().orElseThrow());
        TokenRequestOptions inherited = TokenRequestOptions.builder().resources(List.of(URI.create("https://api.example")))
                .resources(null).scopes(null).additionalParameters(null).build();
        assertFalse(inherited.resourcesOverridden());
        assertTrue(inherited.getScopes().isEmpty());
        assertTrue(inherited.getResources().isEmpty());
    }

    @Test
    void introspectionAudienceAndTextFieldsCannotSmuggleWrongTypes() {
        for (String fields : List.of("\"aud\":\"\"", "\"aud\":false", "\"aud\":[false]", "\"aud\":[\"\"]", "\"sub\":\"\""))
            assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED, assertThrows(OAuthResponseException.class,
                    () -> IntrospectionResponse.parse(raw(200, "{\"active\":true," + fields + "}"), NOW)).getReason());
        IntrospectionResponse grace = IntrospectionResponse.parse(raw(200,
                "{\"active\":true,\"aud\":\"api\",\"exp\":" + NOW.minusSeconds(1).getEpochSecond() + "}"), NOW);
        assertEquals(List.of("api"), grace.validate("https://issuer.example", Set.of("api"), Set.of(), NOW,
                Duration.ofSeconds(2)).getAudiences());
    }

    @Test
    void endpointComparisonPreservesOriginAndRawQueryMeaning() {
        URI issuer = URI.create("https://issuer.example");
        for (String endpoint : List.of("relative", "urn:token", "https:/path", "http://issuer.example", "https://other.example", "https://issuer.example:444"))
            assertFalse(ClientAssertionPreparation.sameOrigin(issuer, URI.create(endpoint)));
        assertFalse(ClientAssertionPreparation.sameOrigin(URI.create("relative"), issuer));
        assertFalse(ClientAssertionPreparation.sameOrigin(URI.create("urn:issuer"), issuer));
        assertTrue(ClientAssertionPreparation.sameOrigin(issuer, URI.create("https://ISSUER.EXAMPLE:443/token")));
        assertFalse(ClientAssertionPreparation.sameEndpoint(URI.create("https://issuer.example/token?q=1"),
                URI.create("https://issuer.example/token?q=2")));
    }

    @Test
    void assertionSerializationPreservesUnicodeAndRejectsInvalidUtf16AndOversizeIds() throws Exception {
        com.revetsec.testing.TestJsonWebKeys.Fixture key = com.revetsec.testing.TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048;
        ClientAuthentication auth = ClientAuthentication.fromPrivateKeyJwt(budget -> ClientAssertionSigningKey.withSigner(
                com.revetsec.jose.JwsSigner.fromRsaKeyPair(key.getPrivateKey(), key.getPublicKey(), com.revetsec.jose.JwsAlgorithm.RS256)).keyId("qualification-key").build());
        OAuthClient client = OAuthClient.withAuthorizationServerMetadata(AuthorizationServerMetadata.withIssuer("https://issuer.example")
                .authorizationEndpoint(URI.create("https://issuer.example/authorize")).tokenEndpoint(URI.create("https://issuer.example/token")).build())
                .clientId("client").clientAuthentication(auth).clock(java.time.Clock.fixed(NOW, java.time.ZoneOffset.UTC)).build();
        ResourceServerMetadata target = new ResourceServerMetadata("https://issuer.example", URI.create("https://issuer.example/token"),
                Set.of("private_key_jwt"), Set.of("RS256"), null);
        for (String clientId : List.of("quote\"slash\\", "control\n", "latin-é", "bmp-\u0800", "pair-\ud83d\ude00")) {
            ClientAssertionPreparation.Prepared prepared = ClientAssertionPreparation.prepare(auth, clientId, target, OAuthEndpoint.TOKEN,
                    client.resourceSettings(), new java.security.SecureRandom(), com.revetsec.internal.http.Deadline.fromNow(Duration.ofSeconds(10)));
            String compact = prepared.value();
            int firstDot = compact.indexOf('.');
            int secondDot = compact.indexOf('.', firstDot + 1);
            assertTrue(firstDot > 0 && secondDot > firstDot + 1);
            assertEquals(secondDot, compact.lastIndexOf('.'));
            byte[] payload = java.util.Base64.getUrlDecoder().decode(compact.substring(firstDot + 1, secondDot));
            JsonObject claims = assertInstanceOf(JsonObject.class, com.revetsec.internal.json.JsonCodec.parse(payload,
                    com.revetsec.internal.json.JsonLimits.protocolDocument(32768)));
            assertEquals(clientId, claims.findString("iss").orElseThrow());
            assertEquals(clientId, claims.findString("sub").orElseThrow());
            assertEquals("https://issuer.example", claims.findString("aud").orElseThrow());
            assertEquals(NOW, prepared.issued());
            assertTrue(prepared.expires().isAfter(NOW));
        }
        for (String clientId : List.of("broken-\ud800", "broken-\ud800a", "broken-\udc00", "a".repeat(32769), "\u0800".repeat(6000)))
            assertEquals(OAuthException.Reason.CLIENT_ASSERTION_SIGNING_FAILED, assertThrows(OAuthConfigurationException.class,
                    () -> ClientAssertionPreparation.prepare(auth, clientId, target, OAuthEndpoint.TOKEN, client.resourceSettings(),
                            new java.security.SecureRandom(), com.revetsec.internal.http.Deadline.fromNow(Duration.ofSeconds(10)))).getReason());
    }

    private static @NonNull JsonObject record(@NonNull String kind) {
        JsonObject.Builder builder = JsonObject.builder().put("v", kind.equals("oidc") ? 2L : 1L)
                .put("kind", kind).put("issuer", "https://issuer.example").put("client_id", "client")
                .put("redirect_uri", "https://client.example/callback").put("state", "state").put("verifier", "verifier")
                .put("response_mode", "QUERY").put("created_at", NOW.toString()).put("expires_at", NOW.plusSeconds(300).toString())
                .put("issuer_required", true).put("authorization_endpoint", "https://issuer.example/authorize")
                .put("token_endpoint", "https://issuer.example/token").put("scopes", JsonArray.fromElements(List.of(JsonString.fromValue("openid"))))
                .put("resources", JsonArray.fromElements(List.of())).put("application_data", JsonObject.fromMembers(Map.of()));
        if (kind.equals("oidc")) builder.put("nonce", "nonce").put("acr_values", JsonArray.fromElements(List.of()));
        return builder.build();
    }

    private static @NonNull JsonObject replaced(@NonNull JsonObject source, @NonNull String field, @NonNull JsonValue value) {
        Map<String, JsonValue> changed = new LinkedHashMap<>(source.getMembers());
        changed.put(field, value);
        return JsonObject.fromMembers(changed);
    }

    private static void rejectRecord(@NonNull JsonObject source, @NonNull String field, @NonNull JsonValue value) {
        assertEquals(OAuthException.Reason.PENDING_AUTHORIZATION_INVALID, assertThrows(OAuthValidationException.class,
                () -> PendingAuthorizationCodec.decode(replaced(source, field, value).toJson())).getReason());
    }

    private static void malformedToken(@NonNull String body) {
        assertEquals(OAuthException.Reason.DOCUMENT_MALFORMED, assertThrows(OAuthResponseException.class,
                () -> TokenResponseParser.parse(raw(200, body), NOW, null)).getReason());
    }

    private static void malformedCallback(@NonNull Map<@NonNull String, @NonNull List<@NonNull String>> parameters,
            @org.jspecify.annotations.Nullable String query) {
        assertEquals(OAuthException.Reason.CALLBACK_MALFORMED, assertThrows(OAuthResponseException.class,
                () -> AuthorizationResponse.fromParameters(parameters, query, AuthorizationRequestOptions.ResponseMode.FORM_POST)).getReason());
    }

    private static @NonNull RawResponse raw(int status, @NonNull String body) {
        return new RawResponse(status, HttpHeaders.of(Map.of(), (name, value) -> true), body.getBytes(StandardCharsets.UTF_8),
                null, false, Duration.ZERO);
    }
}
