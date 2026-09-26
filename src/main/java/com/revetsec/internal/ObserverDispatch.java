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

import javax.annotation.concurrent.ThreadSafe;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;

/**
 * Runs observer hooks so that an observer can never break the operation it observes (plan R16, D11; M1 plan G6-4).
 * <p>
 * Usage, with the observer a component was configured with:
 * <pre>{@code
 * ObserverDispatch.dispatch(this.observer, observer -> observer.didFailToRefreshJsonWebKeySet(jwksUri, exception));
 * }</pre>
 * The rules:
 * <ul>
 *   <li>The hook runs synchronously, on the calling thread. Revetsec creates no threads (R4).</li>
 *   <li>Callers dispatch outside any lock they hold, so a slow or reentrant observer cannot stall or deadlock
 *   other callers.</li>
 *   <li>Every {@link Throwable} the hook throws is contained, except a {@link VirtualMachineError} (such as
 *   {@link OutOfMemoryError} or {@link StackOverflowError}), which is rethrown unchanged because the JVM may no
 *   longer be able to continue. A hook that throws {@link InterruptedException} has the thread's interrupt flag
 *   restored.</li>
 *   <li>A contained failure is reported at {@link Level#FINE} on the {@code com.revetsec} {@link Logger}, as a last
 *   resort. The record holds a fixed message and two class names (the observer's and the failure's), never the
 *   failure itself or its message, which could carry application data. The logging call is itself guarded: a
 *   failing handler is contained the same way, so the observed operation never fails because of logging.</li>
 * </ul>
 * This is the only class in Revetsec that uses {@code java.util.logging}, and it touches the logging system only
 * when a hook fails.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class ObserverDispatch {
	/**
	 * The name of the logger that reports contained observer failures.
	 */
	public static final String LOGGER_NAME = "com.revetsec";

	/**
	 * The fixed {@link java.text.MessageFormat} pattern of the log record: {@code {0}} is the observer's class name
	 * and {@code {1}} the class name of what it threw.
	 */
	public static final String FAILURE_MESSAGE = "A Revetsec observer ({0}) threw {1} from a hook, and Revetsec "
			+ "ignored it.";

	private ObserverDispatch() {
		// Static helpers only.
	}

	/**
	 * Runs {@code hook} against {@code observer} on the calling thread, containing anything it throws except a
	 * {@link VirtualMachineError}.
	 *
	 * @param observer the observer; for components with no observer configured, its disabled instance
	 * @param hook     calls one hook method of {@code observer}
	 * @param <T>      the observer type
	 * @throws NullPointerException if {@code observer} or {@code hook} is {@code null}
	 * @throws VirtualMachineError  if the hook, or the logging of its failure, throws one
	 */
	public static <T> void dispatch(@NonNull T observer,
																	@NonNull Consumer<? super T> hook) {
		requireNonNull(observer);
		requireNonNull(hook);

		try {
			hook.accept(observer);
		} catch (Throwable failure) {
			if (failure instanceof VirtualMachineError virtualMachineError)
				throw virtualMachineError;

			// A hook can throw a checked exception only by cheating the compiler; keep the interrupt visible.
			if (failure instanceof InterruptedException)
				Thread.currentThread().interrupt();

			reportContainedFailure(observer, failure);
		}
	}

	private static void reportContainedFailure(@NonNull Object observer,
																						 @NonNull Throwable failure) {
		try {
			Logger logger = LoggerHolder.LOGGER;

			if (logger.isLoggable(Level.FINE))
				logger.log(Level.FINE, FAILURE_MESSAGE, new Object[]{observer.getClass().getName(),
						failure.getClass().getName()});
		} catch (Throwable loggingFailure) {
			// A failing handler, formatter or logging configuration is contained like the hook's own failure.
			if (loggingFailure instanceof VirtualMachineError virtualMachineError)
				throw virtualMachineError;
		}
	}

	/**
	 * Defers {@code java.util.logging} initialization, which reads the JDK's logging configuration, until a hook
	 * actually fails. A failure here surfaces inside the guarded logging call.
	 */
	private static final class LoggerHolder {
		private static final Logger LOGGER = Logger.getLogger(LOGGER_NAME);
	}
}
