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

package com.revetsec.internal.encoding;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.util.EnumSet;
import java.util.Objects;
import java.util.stream.Stream;

/**
 * The shape of {@link EncodingException} (M1 plan G6-1 and G6-2 applied to internal failures: checked, final, a
 * {@code Kind} with one fixed sentence each, no cause, suppression disabled, never echoes input).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class EncodingExceptionTests {
	@TestFactory
	Stream<DynamicTest> everyKindHasItsFixedOneSentenceMessageAndNoCause() {
		Assertions.assertEquals(EnumSet.allOf(EncodingException.Kind.class), EncodingFailures.MESSAGES.keySet(),
				"every kind has a spelled-out expected message");
		return Stream.of(EncodingException.Kind.values()).map(kind -> DynamicTest.dynamicTest(kind.name(), () -> {
			EncodingException exception = new EncodingException(kind);
			String message = Objects.requireNonNull(EncodingFailures.MESSAGES.get(kind));
			Assertions.assertEquals(message, kind.getMessage());
			Assertions.assertEquals(message, exception.getMessage());
			Assertions.assertEquals(kind, exception.getKind());
			Assertions.assertTrue(message.endsWith(".") && message.indexOf(". ") < 0, "one sentence");
			Assertions.assertNull(exception.getCause());
			Assertions.assertEquals(EncodingException.class.getName() + ": " + message, exception.toString());
		}));
	}

	// G6-1: suppression is disabled, and a cause can never be attached later.
	@TestFactory
	Stream<DynamicTest> suppressionIsDisabledAndTheCauseIsFixed() {
		return Stream.of(EncodingException.Kind.values()).map(kind -> DynamicTest.dynamicTest(kind.name(), () -> {
			EncodingException exception = new EncodingException(kind);
			exception.addSuppressed(new IllegalStateException(EncodingFailures.SENTINEL));
			Assertions.assertEquals(0, exception.getSuppressed().length);
			Assertions.assertThrows(IllegalStateException.class,
					() -> exception.initCause(new IllegalStateException(EncodingFailures.SENTINEL)));
			Assertions.assertNull(exception.getCause());
			EncodingFailures.assertNoEcho(exception, EncodingFailures.SENTINEL);
		}));
	}
}
