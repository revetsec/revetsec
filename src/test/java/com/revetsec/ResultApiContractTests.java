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

package com.revetsec;

import org.jspecify.annotations.NonNull;

import com.revetsec.jose.JwtValidationResult;
import com.revetsec.oauth.BearerTokenResult;
import com.revetsec.oauth.AuthorizationCompletionResult;
import com.revetsec.oidc.OidcAuthenticationResult;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Modifier;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

final class ResultApiContractTests {
    @Test
    void onlyTheOperationCanConstructAnOutcomeAndAllVariantsAreClosed() {
        for (Class<?> base : List.of(JwtValidationResult.class, StateUnsealResult.class, BearerTokenResult.class,
                AuthorizationCompletionResult.class, OidcAuthenticationResult.class,
                com.revetsec.oauth.AccessTokenValidationResult.class,
                com.revetsec.jose.JwksParseResult.class,
                com.revetsec.oauth.AuthorizationResponseParseResult.class,
                com.revetsec.oauth.AuthorizationServerMetadataParseResult.class,
                com.revetsec.oauth.OAuthTokenRequestResult.class,
                com.revetsec.oauth.OAuthRevocationResult.class,
                com.revetsec.oauth.AccessTokenAcquisitionResult.class,
                com.revetsec.oidc.OidcProviderMetadataParseResult.class,
                com.revetsec.oidc.OidcSessionReferenceParseResult.class,
                com.revetsec.oidc.OidcUserInfoResult.class,
                com.revetsec.oidc.OidcRefreshOutcome.class,
                com.revetsec.saml.SamlSessionReferenceParseResult.class)) {
            assertTrue(base.isSealed());
            assertRestrictedConstruction(base);
            for (Class<?> leaf : base.getPermittedSubclasses()) {
                assertTrue(Modifier.isFinal(leaf.getModifiers()));
                assertRestrictedConstruction(leaf);
                for (var field : leaf.getDeclaredFields()) {
                    assertTrue(Modifier.isPrivate(field.getModifiers()));
                    assertTrue(Modifier.isFinal(field.getModifiers()));
                    assertFalse(Throwable.class.isAssignableFrom(field.getType()));
                    if (!leaf.getSimpleName().equals("Succeeded") && !leaf.getSimpleName().equals("Present"))
                        assertTrue(field.getType().isEnum() || field.getName().equals("status") && field.getType() == int.class,
                                "Rejection data is a fixed enum or the bounded HTTP status only");
                }
            }
        }
    }

    @Test
    void eachOperationHasOnePublicResultContract() {
        java.util.Map<Class<?>, java.util.Set<String>> removed = java.util.Map.ofEntries(
                java.util.Map.entry(com.revetsec.oauth.PendingAuthorization.class, java.util.Set.of("saveTo")),
                java.util.Map.entry(com.revetsec.oauth.BearerToken.class, java.util.Set.of("fromAuthorizationHeaderValues")),
                java.util.Map.entry(com.revetsec.oauth.AccessTokenValidator.class, java.util.Set.of("validate")),
                java.util.Map.entry(com.revetsec.oauth.JwtAccessTokenValidator.class, java.util.Set.of("validate")),
                java.util.Map.entry(com.revetsec.oauth.TokenIntrospectionClient.class, java.util.Set.of("validate")),
                java.util.Map.entry(com.revetsec.jose.JwtValidator.class, java.util.Set.of("validate")),
                java.util.Map.entry(StateSealer.class, java.util.Set.of("unseal")),
                java.util.Map.entry(com.revetsec.oauth.OAuthClient.class, java.util.Set.of("completeAuthorization", "refresh", "requestClientCredentialsToken", "revoke")),
                java.util.Map.entry(com.revetsec.oidc.OidcClient.class, java.util.Set.of("completeAuthentication", "refresh", "fetchUserInfo")),
                java.util.Map.entry(com.revetsec.oauth.ClientCredentialsTokenSource.class, java.util.Set.of("getAccessToken")),
                java.util.Map.entry(com.revetsec.oauth.AuthorizationResponse.class, java.util.Set.of("fromQueryString", "fromFormBody", "fromParameters")),
                java.util.Map.entry(com.revetsec.jose.Jwks.class, java.util.Set.of("fromJson")),
                java.util.Map.entry(com.revetsec.oauth.AuthorizationServerMetadata.class, java.util.Set.of("fromJson")),
                java.util.Map.entry(com.revetsec.oidc.OidcProviderMetadata.class, java.util.Set.of("fromJson")),
                java.util.Map.entry(com.revetsec.oidc.OidcSessionReference.class, java.util.Set.of("fromSerializedForm", "fromSealedForm")),
                java.util.Map.entry(com.revetsec.saml.SamlSessionReference.class, java.util.Set.of("fromSerializedForm", "fromSealedForm")),
                java.util.Map.entry(com.revetsec.json.JsonObject.class, java.util.Set.of("findString", "findLong", "findBoolean", "findStringList")));
        removed.forEach((type, names) -> {
            for (var method : type.getMethods())
                assertFalse(names.contains(method.getName()), type.getName() + "." + method.getName());
        });
        for (var type : removed.keySet()) {
            for (var method : type.getDeclaredMethods()) {
                if (Modifier.isPublic(method.getModifiers()) && method.getName().endsWith("Result"))
                    assertTrue(method.getReturnType().isSealed() || method.getReturnType().isEnum(), type.getName() + "." + method.getName());
            }
        }
    }

    @Test
    void constructionGuardDetectsAPublicConstructorAndFactory() {
        assertNotNull(FactoryResult.fromValue());
        assertThrows(AssertionError.class, () -> assertRestrictedConstruction(ForgedResult.class));
        assertThrows(AssertionError.class, () -> assertRestrictedConstruction(FactoryResult.class));
    }

    private static void assertRestrictedConstruction(@NonNull Class<?> type) {
        for (var constructor : type.getDeclaredConstructors())
            assertFalse(Modifier.isPublic(constructor.getModifiers()) || Modifier.isProtected(constructor.getModifiers()));
        for (var method : type.getDeclaredMethods())
            assertFalse(Modifier.isStatic(method.getModifiers()) && Modifier.isPublic(method.getModifiers()));
    }
    private static final class ForgedResult { public ForgedResult() { } }
    private static final class FactoryResult {
        private FactoryResult() { }
        public static @NonNull FactoryResult fromValue() { return new FactoryResult(); }
    }
}
