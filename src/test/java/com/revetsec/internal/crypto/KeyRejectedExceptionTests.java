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

package com.revetsec.internal.crypto;

import org.jspecify.annotations.Nullable;

import org.jspecify.annotations.NonNull;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * {@link KeyRejectedException} and {@link VerifyResult}: each refusal kind has one fixed message, and the exception
 * carries no cause, no suppressed exceptions and no stack trace, so nothing about it depends on key material (R9).
 * The plan fixes both enums' constants (gate 8's internal type table).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class KeyRejectedExceptionTests {
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> eachKindHasAFixedMessageAndNoCauseOrStackTrace() {
		return Stream.of(KeyRejectedException.Kind.values()).map(kind -> DynamicTest.dynamicTest(kind.name(), () -> {
			KeyRejectedException exception = new KeyRejectedException(kind);
			exception.addSuppressed(new IllegalStateException("suppressed"));

			Assertions.assertSame(kind, exception.getKind());
			Assertions.assertEquals(kind.getMessage(), exception.getMessage());
			Assertions.assertNull(exception.getCause());
			Assertions.assertEquals(0, exception.getStackTrace().length);
			Assertions.assertEquals(0, exception.getSuppressed().length);
			Assertions.assertTrue(kind.getMessage().endsWith("."));
		}));
	}

	@Test
	void theKindsAndResultsAreThePlansConstants() {
		Assertions.assertEquals(List.of("MALFORMED", "RSA_KEY_SIZE", "RSA_EXPONENT", "NOT_ON_CURVE", "WEAK",
				"SECRET_TOO_SHORT"), Stream.of(KeyRejectedException.Kind.values()).map(Enum::name).toList());
		Assertions.assertEquals(List.of("VALID", "WRONG_LENGTH", "OUT_OF_RANGE", "MISMATCH", "PROVIDER_FAILURE"),
				Stream.of(VerifyResult.values()).map(Enum::name).toList());
		Assertions.assertEquals(KeyRejectedException.Kind.values().length, Stream.of(KeyRejectedException.Kind.values())
				.map(KeyRejectedException.Kind::getMessage).collect(Collectors.toSet()).size(), "messages are distinct");
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void rejectsANullKind() {
		Assertions.assertThrows(NullPointerException.class, () -> new KeyRejectedException(nullValue()));
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}
}
