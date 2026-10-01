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
                AuthorizationCompletionResult.class, OidcAuthenticationResult.class)) {
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
                        assertTrue(field.getType().isEnum(), "Rejection data is a fixed enum only");
                }
            }
        }
    }

    @Test
    void constructionGuardDetectsAPublicConstructorAndFactory() {
        assertNotNull(FactoryResult.fromValue());
        assertThrows(AssertionError.class, () -> assertRestrictedConstruction(ForgedResult.class));
        assertThrows(AssertionError.class, () -> assertRestrictedConstruction(FactoryResult.class));
    }

    private static void assertRestrictedConstruction(Class<?> type) {
        for (var constructor : type.getDeclaredConstructors())
            assertFalse(Modifier.isPublic(constructor.getModifiers()) || Modifier.isProtected(constructor.getModifiers()));
        for (var method : type.getDeclaredMethods())
            assertFalse(Modifier.isStatic(method.getModifiers()) && Modifier.isPublic(method.getModifiers()));
    }
    private static final class ForgedResult { public ForgedResult() { } }
    private static final class FactoryResult {
        private FactoryResult() { }
        public static FactoryResult fromValue() { return new FactoryResult(); }
    }
}
