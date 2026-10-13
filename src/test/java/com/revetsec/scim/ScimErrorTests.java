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

package com.revetsec.scim;

import org.junit.jupiter.api.Test;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/** Independent factory/status/type inventory from approved SCIM-PLAN.md section 4.3. */
class ScimErrorTests {
    @Test
    void approvedFactoryInventoryHasExactStatusTypeAndNoOffset() {
        check(ScimError::invalidFilterInstance, 400, ScimErrorType.INVALID_FILTER);
        check(ScimError::tooManyInstance, 400, ScimErrorType.TOO_MANY);
        check(ScimError::invalidSyntaxInstance, 400, ScimErrorType.INVALID_SYNTAX);
        check(ScimError::invalidPathInstance, 400, ScimErrorType.INVALID_PATH);
        check(ScimError::noTargetInstance, 400, ScimErrorType.NO_TARGET);
        check(ScimError::invalidValueInstance, 400, ScimErrorType.INVALID_VALUE);
        check(ScimError::mutabilityInstance, 400, ScimErrorType.MUTABILITY);
        check(ScimError::invalidVersionInstance, 400, ScimErrorType.INVALID_VERSION);
        check(ScimError::invalidCursorInstance, 400, ScimErrorType.INVALID_CURSOR);
        check(ScimError::expiredCursorInstance, 400, ScimErrorType.EXPIRED_CURSOR);
        check(ScimError::invalidCountInstance, 400, ScimErrorType.INVALID_COUNT);
        check(ScimError::uniquenessInstance, 409, ScimErrorType.UNIQUENESS);
        check(ScimError::sensitiveInstance, 403, ScimErrorType.SENSITIVE);
        check(ScimError::unauthenticatedInstance, 401, null);
        check(ScimError::forbiddenInstance, 403, null);
        check(ScimError::notFoundInstance, 404, null);
        check(ScimError::preconditionFailedInstance, 412, null);
        check(ScimError::requestTooLargeInstance, 413, null);
        check(ScimError::unsupportedMediaTypeInstance, 415, null);
        check(ScimError::methodNotAllowedInstance, 405, null);
        check(ScimError::notImplementedInstance, 501, null);
        check(ScimError::internalErrorInstance, 500, null);
        check(ScimError::responseTooLargeInstance, 500, null);
        check(ScimError::unavailableInstance, 503, null);
    }

    @Test
    void approvedErrorTypesHaveExactWireSpellings() {
        assertEquals("invalidFilter", ScimErrorType.INVALID_FILTER.getValue());
        assertEquals("tooMany", ScimErrorType.TOO_MANY.getValue());
        assertEquals("uniqueness", ScimErrorType.UNIQUENESS.getValue());
        assertEquals("mutability", ScimErrorType.MUTABILITY.getValue());
        assertEquals("invalidSyntax", ScimErrorType.INVALID_SYNTAX.getValue());
        assertEquals("invalidPath", ScimErrorType.INVALID_PATH.getValue());
        assertEquals("noTarget", ScimErrorType.NO_TARGET.getValue());
        assertEquals("invalidValue", ScimErrorType.INVALID_VALUE.getValue());
        assertEquals("invalidVers", ScimErrorType.INVALID_VERSION.getValue());
        assertEquals("sensitive", ScimErrorType.SENSITIVE.getValue());
        assertEquals("invalidCursor", ScimErrorType.INVALID_CURSOR.getValue());
        assertEquals("expiredCursor", ScimErrorType.EXPIRED_CURSOR.getValue());
        assertEquals("invalidCount", ScimErrorType.INVALID_COUNT.getValue());
        assertEquals(13, ScimErrorType.values().length);
    }

    @Test
    void errorsAreImmutableWithOnlyTheApprovedPublicFactories() {
        assertTrue(Modifier.isFinal(ScimError.class.getModifiers()));
        Arrays.stream(ScimError.class.getDeclaredConstructors())
                .forEach(constructor -> assertTrue(Modifier.isPrivate(constructor.getModifiers())));
        Arrays.stream(ScimError.class.getDeclaredFields())
                .filter(field -> !Modifier.isStatic(field.getModifiers()))
                .forEach(field -> assertTrue(Modifier.isFinal(field.getModifiers())));
        Set<String> factories = Arrays.stream(ScimError.class.getDeclaredMethods())
                .filter(method -> Modifier.isPublic(method.getModifiers()) && Modifier.isStatic(method.getModifiers()))
                .map(method -> method.getName()).collect(Collectors.toSet());
        assertEquals(Set.of(
                "invalidFilterInstance", "tooManyInstance", "invalidSyntaxInstance", "invalidPathInstance",
                "noTargetInstance", "invalidValueInstance", "mutabilityInstance", "invalidVersionInstance",
                "invalidCursorInstance", "expiredCursorInstance", "invalidCountInstance", "uniquenessInstance",
                "sensitiveInstance", "unauthenticatedInstance", "forbiddenInstance", "notFoundInstance",
                "preconditionFailedInstance", "requestTooLargeInstance", "unsupportedMediaTypeInstance", "methodNotAllowedInstance",
                "notImplementedInstance", "internalErrorInstance", "responseTooLargeInstance", "unavailableInstance"
        ), factories);
    }

    @Test
    void filterSyntaxOffsetIsMetadataAndKeepsFixedRedactedDetail() {
        String secret = "SECURITY_MARKER_402953";
        String expression = "userName eq \"" + secret;
        ScimFilterParseResult result = ScimFilter.fromExpressionResult(expression);
        ScimFilterParseResult.Rejected rejected = assertInstanceOf(ScimFilterParseResult.Rejected.class, result);
        ScimError error = rejected.getError();
        assertEquals(Optional.of(expression.length()), error.getExpressionOffset());
        assertEquals(ScimError.invalidFilterInstance().getStatusCode(), error.getStatusCode());
        assertEquals(ScimError.invalidFilterInstance().getErrorType(), error.getErrorType());
        assertEquals(ScimError.invalidFilterInstance().getDetail(), error.getDetail());
        assertFalse(error.getDetail().contains(secret));
        assertFalse(error.toString().contains(secret));
        assertFalse(result.toString().contains(secret));
    }

    @Test
    void pathSyntaxOffsetIsMetadataAndKeepsFixedRedactedDetail() {
        String secret = "SECURITY_MARKER_402953";
        String expression = "userName." + secret + "!";
        ScimAttributePathParseResult result = ScimAttributePath.fromExpressionResult(expression);
        ScimAttributePathParseResult.Rejected rejected = assertInstanceOf(ScimAttributePathParseResult.Rejected.class, result);
        ScimError error = rejected.getError();
        assertEquals(Optional.of(expression.length() - 1), error.getExpressionOffset());
        assertEquals(ScimError.invalidPathInstance().getStatusCode(), error.getStatusCode());
        assertEquals(ScimError.invalidPathInstance().getErrorType(), error.getErrorType());
        assertEquals(ScimError.invalidPathInstance().getDetail(), error.getDetail());
        assertFalse(error.getDetail().contains(secret));
        assertFalse(error.toString().contains(secret));
        assertFalse(result.toString().contains(secret));
    }

    private static void check(@NonNull Supplier<@NonNull ScimError> factory, int expectedStatus,
            @Nullable ScimErrorType expectedType) {
        ScimError error = factory.get();
        assertSame(error, factory.get());
        assertEquals(expectedStatus, error.getStatusCode());
        assertEquals(Optional.ofNullable(expectedType), error.getErrorType());
        assertEquals(Optional.empty(), error.getExpressionOffset());
        assertFalse(error.getDetail().isBlank());
        assertEquals(error.getDetail(), factory.get().getDetail());
        assertTrue(error.toString().contains("<redacted>"));
    }
}
