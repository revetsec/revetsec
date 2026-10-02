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

package com.revetsec.testing;

import org.jspecify.annotations.NonNull;

import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

import static java.util.Objects.requireNonNull;

/**
 * A {@link Proxy} over any observer interface that records every hook call and its arguments (G6-4; exit criterion
 * 17), so a test can assert what Revetsec reported and {@link Sentinels} can walk it.
 * <p>
 * Arguments are kept by reference, never copied or rendered, so an exception passed to a failure hook is recorded
 * with its whole graph (cause chain and suppressed exceptions) and is the same instance the caller received.
 * <p>
 * Every interface method is recorded, default methods included. A {@code void} method returns after recording, and
 * its default body is not run, so a default hook that forwards to another hook is recorded once, as the call Revetsec
 * made. A method that returns a value runs its default body, if it has one, and otherwise returns {@code null},
 * {@code false} or zero. {@code equals}, {@code hashCode} and {@code toString} on the proxy use identity and are not
 * recorded.
 * <p>
 * A recorder made with {@link #fromInterface(Class, Supplier)} throws after recording each call, to exercise the
 * containment of throwing observers. A {@link RuntimeException} or {@link Error} reaches the caller as is; a checked
 * exception the hook does not declare reaches it wrapped in
 * {@link java.lang.reflect.UndeclaredThrowableException}.
 *
 * @param <T> the observer interface
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class RecordingObserver<T> {
	private final Class<T> observerInterface;
	private final T observer;
	private final List<Call> calls = new CopyOnWriteArrayList<>();
	private final @Nullable Supplier<? extends Throwable> failure;

	private RecordingObserver(@NonNull Class<@NonNull T> observerInterface, @Nullable Supplier<? extends @NonNull Throwable> failure) {
		this.observerInterface = observerInterface;
		this.failure = failure;
		@Nullable ClassLoader classLoader = observerInterface.getClassLoader();
		this.observer = observerInterface.cast(Proxy.newProxyInstance(
				classLoader == null ? RecordingObserver.class.getClassLoader() : classLoader,
				new Class<?>[]{observerInterface}, new Handler(this)));
	}

	/**
	 * A recorder whose hooks record and return.
	 *
	 * @param observerInterface the observer interface to implement
	 * @param <T> the observer interface
	 * @return a new recorder with no calls
	 * @throws IllegalArgumentException if {@code observerInterface} is not an interface
	 */
	public static <T> @NonNull RecordingObserver<@NonNull T> fromInterface(@NonNull Class<@NonNull T> observerInterface) {
		requireNonNull(observerInterface);
		requireInterface(observerInterface);
		return new RecordingObserver<>(observerInterface, null);
	}

	/**
	 * A recorder whose hooks record, then throw what {@code failure} supplies.
	 *
	 * @param observerInterface the observer interface to implement
	 * @param failure supplies the throwable for each call, for example {@code () -> new IllegalStateException()}
	 * @param <T> the observer interface
	 * @return a new recorder with no calls
	 * @throws IllegalArgumentException if {@code observerInterface} is not an interface
	 */
	public static <T> @NonNull RecordingObserver<@NonNull T> fromInterface(@NonNull Class<@NonNull T> observerInterface,
			@NonNull Supplier<? extends @NonNull Throwable> failure) {
		requireNonNull(observerInterface);
		requireNonNull(failure);
		requireInterface(observerInterface);
		return new RecordingObserver<>(observerInterface, failure);
	}

	/**
	 * The proxy to hand to the code under test.
	 *
	 * @return the observer; the same instance on every call
	 */
	public @NonNull T getObserver() {
		return this.observer;
	}

	/**
	 * The interface the proxy implements.
	 *
	 * @return the observer interface
	 */
	public @NonNull Class<@NonNull T> getObserverInterface() {
		return this.observerInterface;
	}

	/**
	 * Every recorded call, in the order the calls started.
	 *
	 * @return an immutable snapshot
	 */
	public @NonNull List<@NonNull Call> getCalls() {
		return List.copyOf(this.calls);
	}

	/**
	 * The recorded calls to hooks named {@code methodName}, in order.
	 *
	 * @param methodName the hook's name
	 * @return an immutable snapshot, empty if there were none
	 */
	public @NonNull List<@NonNull Call> getCalls(@NonNull String methodName) {
		requireNonNull(methodName);
		return this.calls.stream().filter(call -> call.getMethodName().equals(methodName)).toList();
	}

	@Override
	public @NonNull String toString() {
		return "RecordingObserver[" + this.observerInterface.getName() + ", " + this.calls.size() + " call(s)]";
	}

	private static void requireInterface(@NonNull Class<?> observerInterface) {
		if (!observerInterface.isInterface() || observerInterface.isAnnotation())
			throw new IllegalArgumentException(observerInterface.getName() + " is not an interface");
	}

	/**
	 * One recorded hook call. The call itself never changes; its arguments are the caller's own objects, held by
	 * reference, and are as thread-safe as those objects are.
	 */
	@ThreadSafe
	public static final class Call {
		private final Method method;
		private final List<@Nullable Object> arguments;
		private final Thread thread;

		private Call(@NonNull Method method, @NonNull List<@Nullable Object> arguments, @NonNull Thread thread) {
			this.method = method;
			this.arguments = arguments;
			this.thread = thread;
		}

		/**
		 * The interface method that was called.
		 *
		 * @return the method
		 */
		public @NonNull Method getMethod() {
			return this.method;
		}

		/**
		 * The name of the hook that was called.
		 *
		 * @return the method name
		 */
		public @NonNull String getMethodName() {
			return this.method.getName();
		}

		/**
		 * The arguments, in declaration order, as passed.
		 *
		 * @return an unmodifiable list that may contain {@code null}
		 */
		public @NonNull List<@Nullable Object> getArguments() {
			return this.arguments;
		}

		/**
		 * One argument.
		 *
		 * @param index the parameter's position
		 * @return the argument, which may be {@code null}
		 * @throws IndexOutOfBoundsException if the hook has no such parameter
		 */
		public @Nullable Object getArgument(int index) {
			return this.arguments.get(index);
		}

		/**
		 * The thread that made the call. ObserverDispatch runs hooks on the caller's thread (G6-4).
		 *
		 * @return the calling thread
		 */
		public @NonNull Thread getThread() {
			return this.thread;
		}

		@Override
		public @NonNull String toString() {
			// Names only: rendering arguments here could leak what a test asserts is never rendered.
			return "Call[" + this.method.getDeclaringClass().getSimpleName() + "." + getMethodName() + ", "
					+ this.arguments.size() + " argument(s)]";
		}
	}

	private static final class Handler implements InvocationHandler {
		private final RecordingObserver<?> recorder;

		private Handler(@NonNull RecordingObserver<?> recorder) {
			this.recorder = recorder;
		}

		@Override
		public @Nullable Object invoke(@NonNull Object proxy, @NonNull Method method, @Nullable Object @Nullable [] arguments)
				throws Throwable {
			if (method.getDeclaringClass() == Object.class)
				return objectMethod(proxy, method, arguments);

			List<@Nullable Object> argumentList = arguments == null ? List.of()
					: Collections.unmodifiableList(new ArrayList<>(Arrays.asList(arguments)));
			this.recorder.calls.add(new Call(method, argumentList, Thread.currentThread()));

			@Nullable Supplier<? extends Throwable> failure = this.recorder.failure;
			if (failure != null)
				throw requireNonNull(failure.get(), "The failure supplier returned null");
			if (method.getReturnType() == void.class)
				return null;
			if (method.isDefault())
				return InvocationHandler.invokeDefault(proxy, method, arguments);
			return zeroValue(method.getReturnType());
		}

		// A proxy is equal only to itself, as Object.equals would say.
		@SuppressWarnings("ReferenceEquality")
		private @NonNull Object objectMethod(@NonNull Object proxy, @NonNull Method method, @Nullable Object @Nullable [] arguments) {
			return switch (method.getName()) {
				case "equals" -> arguments != null && arguments.length == 1 && arguments[0] == proxy;
				case "hashCode" -> System.identityHashCode(proxy);
				case "toString" -> "RecordingObserver proxy for " + this.recorder.observerInterface.getName();
				default -> throw new IllegalStateException("Unexpected Object method " + method);
			};
		}

		private static @Nullable Object zeroValue(@NonNull Class<?> type) {
			if (!type.isPrimitive())
				return null;
			if (type == boolean.class)
				return false;
			if (type == char.class)
				return '\0';
			if (type == byte.class)
				return (byte) 0;
			if (type == short.class)
				return (short) 0;
			if (type == int.class)
				return 0;
			if (type == long.class)
				return 0L;
			if (type == float.class)
				return 0.0f;
			return 0.0d;
		}
	}
}
