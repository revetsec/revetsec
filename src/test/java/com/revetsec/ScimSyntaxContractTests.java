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

import com.revetsec.scim.ScimAttributePathParseResult;
import com.revetsec.scim.ScimError;
import com.revetsec.scim.ScimQueryParseResult;
import com.revetsec.scim.ScimResourceParseResult;
import com.revetsec.scim.ScimAttributeSelectionResult;
import com.revetsec.scim.ScimResponseResult;
import com.revetsec.scim.ScimContentTypeResult;
import com.revetsec.scim.ScimIfMatchResult;
import com.revetsec.scim.ScimIfNoneMatchResult;
import com.revetsec.scim.ScimQuery;
import com.revetsec.scim.ScimAttributeSelection;
import com.revetsec.scim.ScimResponse;
import com.revetsec.scim.ScimFilter;
import com.revetsec.scim.ScimFilterParseResult;
import com.revetsec.scim.ScimFilterValue;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Modifier;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Closed construction and rejection-payload guards for the approved SCIM result-first surface. */
final class ScimSyntaxContractTests {
    @Test
    void syntaxOutcomesHaveClosedConstructionAndImmutablePayloads() {
        for (Class<?> base : List.of(ScimFilterParseResult.class, ScimAttributePathParseResult.class,
                ScimQueryParseResult.class, ScimResourceParseResult.class, ScimAttributeSelectionResult.class,
                ScimResponseResult.class, ScimContentTypeResult.class, ScimIfMatchResult.class, ScimIfNoneMatchResult.class)) {
            assertTrue(base.isSealed());
            assertRestrictedConstruction(base);
            for (Class<?> leaf : base.getPermittedSubclasses()) {
                assertTrue(Modifier.isFinal(leaf.getModifiers()));
                assertRestrictedConstruction(leaf);
                for (var field : leaf.getDeclaredFields()) {
                    if (Modifier.isStatic(field.getModifiers())) continue;
                    assertTrue(Modifier.isPrivate(field.getModifiers()));
                    assertTrue(Modifier.isFinal(field.getModifiers()));
                    assertFalse(Throwable.class.isAssignableFrom(field.getType()));
                    if (leaf.getSimpleName().equals("Rejected"))
                        assertTrue(field.getType() == ScimError.class,
                                "A rejection retains only the reviewed fixed error carrier");
                }
            }
        }
    }

    @Test
    void boundQuerySelectionAndPreparedResponseCannotBeFabricatedByApplications() {
        for (Class<?> carrier : List.of(ScimQuery.class, ScimAttributeSelection.class, ScimResponse.class))
            assertRestrictedConstruction(carrier);
    }

    @Test
    void syntaxNodesAndLiteralsHaveNoApplicationConstructors() {
        for (Class<?> base : List.of(ScimFilter.class, ScimFilterValue.class)) {
            assertTrue(base.isSealed());
            for (Class<?> leaf : base.getPermittedSubclasses()) {
                assertTrue(Modifier.isFinal(leaf.getModifiers()));
                assertRestrictedConstruction(leaf);
            }
        }
    }

    @Test
    void publicErrorFactoriesCannotAcceptRequestText() {
        for (var constructor : ScimError.class.getDeclaredConstructors())
            assertFalse(Modifier.isPublic(constructor.getModifiers())
                    || Modifier.isProtected(constructor.getModifiers()));
        for (var method : ScimError.class.getDeclaredMethods()) {
            if (Modifier.isStatic(method.getModifiers()) && Modifier.isPublic(method.getModifiers()))
                assertTrue(method.getParameterCount() == 0 && method.getReturnType() == ScimError.class,
                        "Public SCIM errors are fixed, argument-free factories");
        }
    }

    @Test
    void constructionGuardIsCalibratedAgainstAnUnsafeFactory() {
        assertNotNull(UnsafeOutcome.fromInput());
        assertThrows(AssertionError.class, () -> assertRestrictedConstruction(UnsafeOutcome.class));
    }

    private static void assertRestrictedConstruction(@NonNull Class<?> type) {
        for (var constructor : type.getDeclaredConstructors())
            assertFalse(Modifier.isPublic(constructor.getModifiers())
                    || Modifier.isProtected(constructor.getModifiers()));
        for (var method : type.getDeclaredMethods())
            assertFalse(Modifier.isPublic(method.getModifiers()) && Modifier.isStatic(method.getModifiers()));
    }

    private static final class UnsafeOutcome {
        private UnsafeOutcome() { }
        public static @NonNull UnsafeOutcome fromInput() { return new UnsafeOutcome(); }
    }
}
