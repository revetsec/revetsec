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

import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import static org.junit.jupiter.api.Assertions.*;

final class ResultApiContractTests {
    private static final Set<String> PROVIDER_CONSTRUCTIBLE_RESULTS = Set.of(
            "com.revetsec.oauth.server.OAuthStoreReadResult",
            "com.revetsec.password.PasswordPepperSnapshotResult",
            "com.revetsec.saml.SamlPendingConsumeResult",
            "com.revetsec.scim.ScimStringMatchResult",
            "com.revetsec.totp.TotpStoreReadResult",
            "com.revetsec.webauthn.WebAuthnStoreReadResult");

    @Test
    void exportedSealedResultsHaveClosedImmutableVariants() throws IOException {
        for (Class<?> base : exportedSealedResults()) {
            assertTrue(base.isSealed());
            assertRestrictedConstructors(base);
            for (Class<?> leaf : base.getPermittedSubclasses()) {
                assertTrue(Modifier.isFinal(leaf.getModifiers()));
                assertRestrictedConstructors(leaf);
                for (var field : leaf.getDeclaredFields()) {
                    if (field.isSynthetic() || Modifier.isStatic(field.getModifiers())) continue;
                    assertTrue(Modifier.isPrivate(field.getModifiers()));
                    assertTrue(Modifier.isFinal(field.getModifiers()));
                    assertFalse(Throwable.class.isAssignableFrom(field.getType()));
                }
            }
        }
    }

    @Test
    void onlyExplicitProviderResultsExposeFactories() throws IOException {
        Set<String> providerResults = new TreeSet<>();
        for (Class<?> base : exportedSealedResults()) {
            boolean hasFactory = hasPublicFactory(base);
            for (Class<?> leaf : base.getPermittedSubclasses())
                if (!leaf.isEnum()) hasFactory |= hasPublicFactory(leaf);
            if (hasFactory) providerResults.add(base.getName());
        }
        assertEquals(PROVIDER_CONSTRUCTIBLE_RESULTS, providerResults);
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
        assertThrows(AssertionError.class, () -> assertRestrictedConstructors(ForgedResult.class));
        assertTrue(hasPublicFactory(FactoryResult.class));
    }

    private static @NonNull List<@NonNull Class<?>> exportedSealedResults() throws IOException {
        List<String> names = ContractSupport.analyze(ContractSupport.repositoryRoot().resolve("src/main/java"), analysis ->
                ContractSupport.exportedTypes(analysis).stream()
                        .filter(type -> type.getModifiers().contains(javax.lang.model.element.Modifier.SEALED))
                        .filter(type -> type.getSimpleName().toString().endsWith("Result")
                                || type.getSimpleName().toString().endsWith("Outcome"))
                        .map(type -> analysis.getElements().getBinaryName(type).toString())
                        .toList());
        return names.stream().map(ResultApiContractTests::loadClass).toList();
    }

    private static @NonNull Class<?> loadClass(@NonNull String name) {
        try {
            return Class.forName(name);
        } catch (ClassNotFoundException e) {
            throw new AssertionError("Compiled result type is missing: " + name, e);
        }
    }

    private static void assertRestrictedConstructors(@NonNull Class<?> type) {
        for (var constructor : type.getDeclaredConstructors())
            assertFalse(Modifier.isPublic(constructor.getModifiers()) || Modifier.isProtected(constructor.getModifiers()));
    }

    private static boolean hasPublicFactory(@NonNull Class<?> type) {
        for (var method : type.getDeclaredMethods()) {
            int modifiers = method.getModifiers();
            if (Modifier.isStatic(modifiers) && (Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers)))
                return true;
        }
        return false;
    }
    private static final class ForgedResult { public ForgedResult() { } }
    private static final class FactoryResult {
        private FactoryResult() { }
        public static @NonNull FactoryResult fromValue() { return new FactoryResult(); }
    }
}
