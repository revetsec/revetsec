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

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.ObjectStreamField;
import java.io.UncheckedIOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.http.HttpTimeoutException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * The exception root's construction rules (M1 plan G6-1 to G6-3, exit criterion 15; plan R9, R15, 7.8).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RevetsecExceptionTests {
	private static final String SENTINEL = "SENTINEL-6b1f0d6e-revetsec-exception";

	/**
	 * A stand-in for a Revetsec leaf exception, so the base class can be exercised in every category.
	 */
	private static final class TestLeafException extends RevetsecException {
		private static final long serialVersionUID = 1L;

		TestLeafException(@NonNull ErrorCategory category, @NonNull Boolean transientFailure, @NonNull String fixedMessage,
				@Nullable Throwable cause) {
			super(category, transientFailure, fixedMessage, cause);
		}
	}

	@Test
	void invalidSealedStateIsANonTransientValidationFailure() {
		// M1 plan, public types table: VALIDATION_FAILURE, not transient.
		InvalidSealedStateException exception = InvalidSealedStateException.fromAnyFailure();

		Assertions.assertEquals(ErrorCategory.VALIDATION_FAILURE, exception.getCategory());
		Assertions.assertFalse(exception.isTransient());
	}

	@Test
	void invalidSealedStateHasTheFixedMessageNoCauseAndNothingSuppressed() {
		// Exit criterion 8: every unseal failure is the identical exception (same message, null cause, no suppressed).
		InvalidSealedStateException first = InvalidSealedStateException.fromAnyFailure();
		InvalidSealedStateException second = InvalidSealedStateException.fromAnyFailure();

		for (InvalidSealedStateException exception : List.of(first, second)) {
			Assertions.assertEquals("Sealed state is invalid.", exception.getMessage());
			Assertions.assertEquals("Sealed state is invalid.", exception.getLocalizedMessage());
			Assertions.assertNull(exception.getCause());
			Assertions.assertEquals(0, exception.getSuppressed().length);
			Assertions.assertEquals(InvalidSealedStateException.class.getName() + ": Sealed state is invalid.",
					exception.toString());
		}

		// Each call returns a fresh instance, so no stack trace or state is shared between failures.
		Assertions.assertNotSame(first, second);
	}

	@Test
	void invalidSealedStateHasOnlyAPrivateConstructor() throws ReflectiveOperationException {
		// M1 plan G6-1: leaves are final, with private constructors and a package-private factory.
		Assertions.assertTrue(Modifier.isFinal(InvalidSealedStateException.class.getModifiers()));

		for (Constructor<?> constructor : InvalidSealedStateException.class.getDeclaredConstructors())
			Assertions.assertTrue(Modifier.isPrivate(constructor.getModifiers()), constructor::toString);

		Method factory = InvalidSealedStateException.class.getDeclaredMethod("fromAnyFailure");
		int modifiers = factory.getModifiers();
		Assertions.assertTrue(Modifier.isStatic(modifiers));
		Assertions.assertFalse(Modifier.isPublic(modifiers) || Modifier.isProtected(modifiers)
				|| Modifier.isPrivate(modifiers), "fromAnyFailure must be package-private");
	}

	@Test
	void addSuppressedIsANoOp() {
		// M1 plan G6-1: the one constructor calls super(message, cause, false, true), so suppression is disabled
		// and a later try-with-resources cannot attach an exception that carries secrets.
		List<RevetsecException> exceptions = List.of(InvalidSealedStateException.fromAnyFailure(),
				new TestLeafException(ErrorCategory.TRANSPORT, true, "The exchange failed.", new IOException()));

		for (RevetsecException exception : exceptions) {
			exception.addSuppressed(new IllegalStateException(SENTINEL));
			Assertions.assertEquals(0, exception.getSuppressed().length);
		}
	}

	@Test
	void initCauseThrowsOnAnExceptionBuiltWithoutACause() {
		// Exit criterion 15: the cause is fixed at construction, so nothing can attach a cause later.
		InvalidSealedStateException exception = InvalidSealedStateException.fromAnyFailure();

		Assertions.assertThrows(IllegalStateException.class,
				() -> exception.initCause(new IllegalStateException(SENTINEL)));
		Assertions.assertNull(exception.getCause());
	}

	@Test
	void initCauseThrowsOnAnExceptionBuiltWithACause() {
		IOException cause = new IOException("connection reset");
		TestLeafException exception = new TestLeafException(ErrorCategory.TRANSPORT, true, "The exchange failed.",
				cause);

		Assertions.assertThrows(IllegalStateException.class, () -> exception.initCause(new IOException()));
		Assertions.assertSame(cause, exception.getCause());
	}

	@Test
	void stackTracesAreWritable() {
		// M1 plan G6-1: super(message, cause, false, true) keeps stack traces.
		Assertions.assertTrue(InvalidSealedStateException.fromAnyFailure().getStackTrace().length > 0);
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> onlyTransportAndRemoteErrorMayBeTransient() {
		// M1 plan G6-3: transience is a function of category plus cause; MALFORMED_INPUT, VALIDATION_FAILURE,
		// CONFIGURATION and UNSUPPORTED are never transient.
		return Arrays.stream(ErrorCategory.values()).map(category -> DynamicTest.dynamicTest(category.name(), () -> {
			TestLeafException notTransient = new TestLeafException(category, false, "It failed.", null);
			Assertions.assertEquals(category, notTransient.getCategory());
			Assertions.assertFalse(notTransient.isTransient());

			if (category == ErrorCategory.TRANSPORT || category == ErrorCategory.REMOTE_ERROR) {
				TestLeafException transientFailure = new TestLeafException(category, true, "It failed.", null);
				Assertions.assertEquals(category, transientFailure.getCategory());
				Assertions.assertTrue(transientFailure.isTransient());
			} else {
				IllegalArgumentException rejection = Assertions.assertThrows(IllegalArgumentException.class,
						() -> new TestLeafException(category, true, "It failed.", null));
				Assertions.assertEquals("Only TRANSPORT and REMOTE_ERROR failures may be transient.",
						rejection.getMessage());
			}
		}));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> onlyATransportFailureMayKeepAnIoExceptionCause() {
		// M1 plan, layering: a cause is kept only on a TRANSPORT failure from Kind.IO, and it is the JDK IOException.
		return Arrays.stream(ErrorCategory.values()).map(category -> DynamicTest.dynamicTest(category.name(), () -> {
			if (category == ErrorCategory.TRANSPORT) {
				IOException cause = new IOException("connection reset");
				Assertions.assertSame(cause, new TestLeafException(category, true, "The exchange failed.", cause)
						.getCause());
				InterruptedIOException subclassCause = new InterruptedIOException();
				Assertions.assertSame(subclassCause, new TestLeafException(category, false, "The exchange failed.",
						subclassCause).getCause());
				HttpTimeoutException timeoutCause = new HttpTimeoutException("timed out");
				Assertions.assertSame(timeoutCause, new TestLeafException(category, true, "The exchange failed.",
						timeoutCause).getCause());
			} else {
				Assertions.assertThrows(IllegalArgumentException.class,
						() -> new TestLeafException(category, false, "It failed.", new IOException()));
			}

			for (Throwable notAnIoException : List.of(new IllegalStateException(SENTINEL),
					new UncheckedIOException(new IOException()), new Error()))
				Assertions.assertThrows(IllegalArgumentException.class,
						() -> new TestLeafException(category, false, "It failed.", notAnIoException));
		}));
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void nullArgumentsThrowNullPointerException() {
		// Plan R15: misuse throws NPE, never a RevetsecException.
		Assertions.assertThrows(NullPointerException.class, () -> new TestLeafException(nullValue(), false,
				"It failed.", null));
		Assertions.assertThrows(NullPointerException.class, () -> new TestLeafException(ErrorCategory.UNSUPPORTED,
				nullValue(), "It failed.", null));
		Assertions.assertThrows(NullPointerException.class, () -> new TestLeafException(ErrorCategory.UNSUPPORTED,
				false, nullValue(), null));
	}

	@Test
	void aBlankMessageIsRejected() {
		// M1 plan G6-1: every class or Reason has a fixed one-sentence message.
		for (String blank : List.of("", " ", "\t\n"))
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> new TestLeafException(ErrorCategory.UNSUPPORTED, false, blank, null));
	}

	@Test
	void categoryAndTransienceCannotBeOverridden() throws ReflectiveOperationException {
		// M1 plan G6-3: a subclass cannot make its own transience rule.
		Assertions.assertTrue(Modifier.isFinal(RevetsecException.class.getMethod("getCategory").getModifiers()));
		Assertions.assertTrue(Modifier.isFinal(RevetsecException.class.getMethod("isTransient").getModifiers()));
		Assertions.assertTrue(Modifier.isAbstract(RevetsecException.class.getModifiers()));
		Assertions.assertTrue(RuntimeException.class.isAssignableFrom(RevetsecException.class));
	}

	@Test
	void theRootHasOneProtectedConstructor() {
		// M1 plan G6-1: one protected constructor (ErrorCategory, Boolean, String, Throwable).
		Constructor<?>[] constructors = RevetsecException.class.getDeclaredConstructors();

		Assertions.assertEquals(1, constructors.length);
		Assertions.assertTrue(Modifier.isProtected(constructors[0].getModifiers()));
		Assertions.assertEquals(List.of(ErrorCategory.class, Boolean.class, String.class, Throwable.class),
				List.of(constructors[0].getParameterTypes()));
	}

	@Test
	void errorCategoriesAreTheSixApprovedCategoriesInOrder() {
		// Plan 7.1 and the M1 public types table.
		Assertions.assertEquals(List.of("MALFORMED_INPUT", "VALIDATION_FAILURE", "REMOTE_ERROR", "TRANSPORT",
						"CONFIGURATION", "UNSUPPORTED"),
				Arrays.stream(ErrorCategory.values()).map(Enum::name).toList());
	}

	@Test
	void serializedFormHoldsOnlyTheCategoryAndTransience() {
		// M1 plan: every exception declares serialVersionUID, and every serialized field is documented. This pins
		// the serialized shape, so a new field is a deliberate decision.
		ObjectStreamClass root = ObjectStreamClass.lookup(RevetsecException.class);
		Assertions.assertEquals(1L, root.getSerialVersionUID());
		Map<String, Class<?>> fields = Map.of("category", ErrorCategory.class, "transientFailure", Boolean.class);
		Assertions.assertEquals(fields.size(), root.getFields().length);
		for (ObjectStreamField field : root.getFields())
			Assertions.assertEquals(fields.get(field.getName()), field.getType(), field.getName());

		ObjectStreamClass leaf = ObjectStreamClass.lookup(InvalidSealedStateException.class);
		Assertions.assertEquals(1L, leaf.getSerialVersionUID());
		Assertions.assertEquals(0, leaf.getFields().length);
	}

	@Test
	void serializationRoundTripKeepsTheFixedShape() throws IOException, ClassNotFoundException {
		InvalidSealedStateException original = InvalidSealedStateException.fromAnyFailure();

		InvalidSealedStateException copy = (InvalidSealedStateException) roundTrip(original);

		Assertions.assertEquals(ErrorCategory.VALIDATION_FAILURE, copy.getCategory());
		Assertions.assertFalse(copy.isTransient());
		Assertions.assertEquals("Sealed state is invalid.", copy.getMessage());
		Assertions.assertNull(copy.getCause());
		// Suppression stays disabled after deserialization, and the cause stays fixed.
		copy.addSuppressed(new IllegalStateException(SENTINEL));
		Assertions.assertEquals(0, copy.getSuppressed().length);
		Assertions.assertThrows(IllegalStateException.class, () -> copy.initCause(new IllegalStateException()));

		TestLeafException transportCopy = (TestLeafException) roundTrip(new TestLeafException(ErrorCategory.TRANSPORT,
				true, "The exchange failed.", new IOException("connection reset")));
		Assertions.assertEquals(ErrorCategory.TRANSPORT, transportCopy.getCategory());
		Assertions.assertTrue(transportCopy.isTransient());
		Assertions.assertInstanceOf(IOException.class, transportCopy.getCause());
	}

	private static @NonNull Object roundTrip(@NonNull Object value) throws IOException, ClassNotFoundException {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();

		try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
			output.writeObject(value);
		}

		try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
			return input.readObject();
		}
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check the constructor's null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}
}
