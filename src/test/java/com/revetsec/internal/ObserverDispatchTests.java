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

package com.revetsec.internal;

import org.jspecify.annotations.NonNull;

import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.stream.Stream;

/**
 * Observer hooks can never break the operation they observe (M1 plan G6-4, exit criterion 15; plan R16).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class ObserverDispatchTests {
	private static final String SENTINEL = "SENTINEL-4f0c2a9e-observer-dispatch";

	/**
	 * A stand-in for an exported {@code *Observer} interface: default no-op hooks.
	 */
	private interface TestObserver {
		default void didSomething(@Nullable String argument) {
			// No-op by default, like every Revetsec observer hook.
		}
	}

	/**
	 * An observer whose hook throws whatever it is given.
	 */
	private static final class ThrowingObserver implements TestObserver {
		private final Throwable failure;

		private ThrowingObserver(@NonNull Throwable failure) {
			this.failure = failure;
		}

		@Override
		public void didSomething(@Nullable String argument) {
			ObserverDispatchTests.<RuntimeException>sneakyThrow(this.failure);
		}
	}

	/**
	 * Collects every record published on the {@code com.revetsec} logger during a test.
	 */
	private static final class RecordingHandler extends Handler {
		private final List<LogRecord> records = new CopyOnWriteArrayList<>();

		@Override
		public void publish(@NonNull LogRecord record) {
			this.records.add(record);
		}

		@Override
		public void flush() {
			// Nothing buffered.
		}

		@Override
		public void close() {
			// Nothing to release.
		}
	}

	/**
	 * A handler that throws from {@code publish}, counting its calls so a test can prove it was reached.
	 */
	private static final class ThrowingHandler extends Handler {
		private final Throwable failure;
		private final AtomicInteger publishCalls = new AtomicInteger();

		private ThrowingHandler(@NonNull Throwable failure) {
			this.failure = failure;
		}

		@Override
		public void publish(@NonNull LogRecord record) {
			this.publishCalls.incrementAndGet();
			ObserverDispatchTests.<RuntimeException>sneakyThrow(this.failure);
		}

		@Override
		public void flush() {
			// Nothing buffered.
		}

		@Override
		public void close() {
			// Nothing to release.
		}
	}

	/**
	 * Held strongly for the whole test, because the logging system keeps loggers only weakly.
	 */
	private final Logger logger = Logger.getLogger(ObserverDispatch.LOGGER_NAME);
	private final List<Handler> addedHandlers = new ArrayList<>();
	private @Nullable Level originalLevel;
	private boolean originalUseParentHandlers;

	@BeforeEach
	void captureLoggerState() {
		this.originalLevel = this.logger.getLevel();
		this.originalUseParentHandlers = this.logger.getUseParentHandlers();
		// Keep contained failures off the console while these tests run.
		this.logger.setUseParentHandlers(false);
	}

	@AfterEach
	void restoreLoggerState() {
		for (Handler handler : this.addedHandlers)
			this.logger.removeHandler(handler);
		this.logger.setLevel(this.originalLevel);
		this.logger.setUseParentHandlers(this.originalUseParentHandlers);
		Thread.interrupted();
	}

	@Test
	void theHookRunsOnTheCallersThread() {
		// M1 plan G6-4: hooks run on the caller's thread (R4: Revetsec starts no threads).
		List<Thread> threads = new ArrayList<>();
		List<@Nullable String> arguments = new ArrayList<>();
		TestObserver observer = new TestObserver() {
			@Override
			public void didSomething(@Nullable String argument) {
				threads.add(Thread.currentThread());
				arguments.add(argument);
			}
		};

		ObserverDispatch.dispatch(observer, recorded -> recorded.didSomething("value"));

		Assertions.assertEquals(List.of(Thread.currentThread()), threads);
		Assertions.assertEquals(List.of("value"), arguments);
	}

	@Test
	void aHookThatReturnsNormallyLogsNothing() {
		RecordingHandler handler = recordAtLevel(Level.ALL);

		ObserverDispatch.dispatch(new TestObserver() {
		}, observer -> observer.didSomething(null));

		Assertions.assertEquals(List.of(), handler.records);
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aThrowingHookIsContained() {
		// Exit criterion 15: a throwing observer and an Error are contained. Only VirtualMachineError escapes.
		List<Throwable> failures = List.of(new IllegalStateException(SENTINEL), new NullPointerException(SENTINEL),
				new AssertionError(SENTINEL), new LinkageError(SENTINEL), new ExceptionInInitializerError(SENTINEL),
				new NoClassDefFoundError(SENTINEL), new Error(SENTINEL), new Exception(SENTINEL), new Throwable(SENTINEL));

		return failures.stream().map(failure -> DynamicTest.dynamicTest(failure.getClass().getSimpleName(), () ->
				Assertions.assertDoesNotThrow(() -> ObserverDispatch.dispatch(new ThrowingObserver(failure),
						observer -> observer.didSomething(SENTINEL)))));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aVirtualMachineErrorFromTheHookIsRethrownUnchanged() {
		// M1 plan G6-4: VirtualMachineError is rethrown, because the JVM may not be able to continue.
		List<VirtualMachineError> errors = List.of(new OutOfMemoryError(SENTINEL), new StackOverflowError(SENTINEL),
				new InternalError(SENTINEL), new UnknownError(SENTINEL));

		return errors.stream().map(error -> DynamicTest.dynamicTest(error.getClass().getSimpleName(), () -> {
			VirtualMachineError thrown = Assertions.assertThrows(VirtualMachineError.class,
					() -> ObserverDispatch.dispatch(new ThrowingObserver(error), observer -> observer.didSomething(null)));
			Assertions.assertSame(error, thrown);
		}));
	}

	@Test
	void aContainedFailureIsLoggedAtFineWithClassNamesOnly() {
		// Plan R16 and M1 plan G6-4: last-resort reporting at FINE on the com.revetsec logger. The record carries
		// no throwable and no message from the failure, so RedactionTests' sentinels cannot leak through it (R9).
		RecordingHandler handler = recordAtLevel(Level.FINE);
		ThrowingObserver observer = new ThrowingObserver(new IllegalStateException(SENTINEL));

		ObserverDispatch.dispatch(observer, recorded -> recorded.didSomething(SENTINEL));

		Assertions.assertEquals(1, handler.records.size());
		LogRecord record = handler.records.get(0);
		Assertions.assertEquals(Level.FINE, record.getLevel());
		Assertions.assertEquals(ObserverDispatch.LOGGER_NAME, record.getLoggerName());
		Assertions.assertEquals(ObserverDispatch.FAILURE_MESSAGE, record.getMessage());
		Assertions.assertNull(record.getThrown());
		Object[] parameters = record.getParameters();
		Assertions.assertNotNull(parameters);
		Assertions.assertEquals(List.of(ThrowingObserver.class.getName(), IllegalStateException.class.getName()),
				Arrays.asList(parameters));

		String formatted = new SimpleFormatter().format(record);
		Assertions.assertFalse(formatted.contains(SENTINEL), formatted);
		Assertions.assertTrue(formatted.contains(ThrowingObserver.class.getName()), formatted);
	}

	@Test
	void nothingIsLoggedWhenFineIsDisabled() {
		RecordingHandler handler = recordAtLevel(Level.INFO);

		ObserverDispatch.dispatch(new ThrowingObserver(new IllegalStateException(SENTINEL)),
				observer -> observer.didSomething(null));

		Assertions.assertEquals(List.of(), handler.records);
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aThrowingLogHandlerIsContained() {
		// Exit criterion 15: a throwing java.util.logging handler is contained, so logging can never fail the call.
		List<Throwable> failures = List.of(new IllegalStateException(SENTINEL), new AssertionError(SENTINEL),
				new Error(SENTINEL), new Exception(SENTINEL));

		return failures.stream().map(failure -> DynamicTest.dynamicTest(failure.getClass().getSimpleName(), () -> {
			ThrowingHandler handler = new ThrowingHandler(failure);
			addHandlerAtLevel(handler, Level.FINE);
			try {
				Assertions.assertDoesNotThrow(() -> ObserverDispatch.dispatch(
						new ThrowingObserver(new IllegalStateException(SENTINEL)), observer -> observer.didSomething(null)));
				// The handler really ran and threw, so the containment above is what kept the call alive.
				Assertions.assertEquals(1, handler.publishCalls.get());
			} finally {
				removeAddedHandlers();
			}
		}));
	}

	@Test
	void aVirtualMachineErrorFromTheLogHandlerIsRethrown() {
		// M1 plan G6-4: the logging call is guarded, but a VirtualMachineError still escapes from it.
		StackOverflowError error = new StackOverflowError(SENTINEL);
		addHandlerAtLevel(new ThrowingHandler(error), Level.FINE);

		StackOverflowError thrown = Assertions.assertThrows(StackOverflowError.class, () -> ObserverDispatch.dispatch(
				new ThrowingObserver(new IllegalStateException(SENTINEL)), observer -> observer.didSomething(null)));

		Assertions.assertSame(error, thrown);
	}

	@Test
	void aHookThatThrowsInterruptedExceptionRestoresTheInterruptFlag() {
		Assertions.assertFalse(Thread.currentThread().isInterrupted());

		ObserverDispatch.dispatch(new ThrowingObserver(new InterruptedException()),
				observer -> observer.didSomething(null));

		Assertions.assertTrue(Thread.interrupted(), "the interrupt flag was not restored");
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void nullArgumentsThrowNullPointerException() {
		// Plan R15: misuse throws NPE; it is Revetsec's own bug, never contained.
		Consumer<TestObserver> hook = observer -> observer.didSomething(null);
		Assertions.assertThrows(NullPointerException.class, () -> ObserverDispatch.dispatch(nullValue(), hook));
		Assertions.assertThrows(NullPointerException.class, () -> ObserverDispatch.dispatch(new TestObserver() {
		}, nullValue()));
	}

	private @NonNull RecordingHandler recordAtLevel(@NonNull Level level) {
		RecordingHandler handler = new RecordingHandler();
		addHandlerAtLevel(handler, level);
		return handler;
	}

	private void addHandlerAtLevel(@NonNull Handler handler, @NonNull Level level) {
		handler.setLevel(Level.ALL);
		this.logger.setLevel(level);
		this.logger.addHandler(handler);
		this.addedHandlers.add(handler);
	}

	private void removeAddedHandlers() {
		for (Handler handler : this.addedHandlers)
			this.logger.removeHandler(handler);
		this.addedHandlers.clear();
	}

	@SuppressWarnings("unchecked")
	private static <T extends Throwable> void sneakyThrow(@NonNull Throwable throwable) throws T {
		throw (T) throwable;
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}
}
