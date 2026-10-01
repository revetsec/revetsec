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

import com.revetsec.ErrorCategory;
import com.revetsec.jose.JoseException;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Modifier;
import static org.junit.jupiter.api.Assertions.*;
final class AccessTokenValidationExceptionTests {
	@Test void verdictsAreFixedNontransientAndCannotRetainInput() {
		for (AccessTokenValidationException.Reason reason : AccessTokenValidationException.Reason.values()) {
			AccessTokenValidationException error = AccessTokenValidationException.fromReason(reason);
			assertSame(reason, error.getReason()); assertFalse(error.isTransient()); assertNull(error.getCause());
			assertTrue(error.getJoseReason().isEmpty()); assertTrue(java.util.Objects.requireNonNull(error.getMessage()).endsWith("."));
			assertEquals(reason == AccessTokenValidationException.Reason.MALFORMED_REQUEST ? ErrorCategory.MALFORMED_INPUT : ErrorCategory.VALIDATION_FAILURE, error.getCategory());
			assertEquals(reason == AccessTokenValidationException.Reason.MALFORMED_REQUEST ? BearerError.INVALID_REQUEST : BearerError.INVALID_TOKEN, error.getBearerError());
			error.addSuppressed(new IllegalArgumentException("sensitive")); assertEquals(0, error.getSuppressed().length);
			assertThrows(IllegalStateException.class, () -> error.initCause(new IllegalArgumentException("sensitive")));
		}
		for (var ctor : AccessTokenValidationException.class.getDeclaredConstructors())
			assertFalse(Modifier.isPublic(ctor.getModifiers()) || Modifier.isProtected(ctor.getModifiers()));
	}
	@Test void joseDetailRetainsOnlyAnEnumNotACause() {
		for (JoseException.Reason reason : JoseException.Reason.values()) {
			AccessTokenValidationException error = AccessTokenValidationException.fromJoseReason(reason);
			assertEquals(AccessTokenValidationException.Reason.JWT_REJECTED, error.getReason());
			assertEquals(reason, error.getJoseReason().orElseThrow()); assertNull(error.getCause());
			assertEquals(BearerError.INVALID_TOKEN, error.getBearerError());
		}
	}
	// Deliberate programmer misuse: these calls verify runtime rejection of required null inputs.
	@SuppressWarnings("NullAway")
	@Test void nullFactoryArgumentsAreProgrammingErrors() {
		assertThrows(NullPointerException.class, () -> AccessTokenValidationException.fromReason(null));
		assertThrows(NullPointerException.class, () -> AccessTokenValidationException.fromJoseReason(null));
	}

}
