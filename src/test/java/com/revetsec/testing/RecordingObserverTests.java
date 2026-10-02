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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Tests {@link RecordingObserver} through a test-only observer interface shaped like Revetsec's (G6-4: default
 * {@code void} hooks whose failure hooks receive the caller's exception instance), plus the less common shapes a
 * proxy over "any observer interface" must handle.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RecordingObserverTests {
	private static final URI ENDPOINT = URI.create("https://idp.example/token");

	@Test
	void recordsEveryHookCallWithItsArgumentsInOrder() {
		RecordingObserver<ExampleObserver> recorder = RecordingObserver.fromInterface(ExampleObserver.class);
		ExampleObserver observer = recorder.getObserver();
		IllegalStateException failure = new IllegalStateException("fixed message");

		observer.willFetch(ENDPOINT);
		observer.didFetch(ENDPOINT, Duration.ofMillis(12), 200);
		observer.didFailToFetch(ENDPOINT, Duration.ofMillis(34), failure);
		observer.didStop();

		List<RecordingObserver.Call> calls = recorder.getCalls();
		Assertions.assertEquals(List.of("willFetch", "didFetch", "didFailToFetch", "didStop"),
				calls.stream().map(RecordingObserver.Call::getMethodName).toList());
		Assertions.assertEquals(List.of(ENDPOINT), calls.get(0).getArguments());
		Assertions.assertEquals(Arrays.asList(ENDPOINT, Duration.ofMillis(12), 200), calls.get(1).getArguments());
		Assertions.assertEquals(List.of(), calls.get(3).getArguments());
		Assertions.assertEquals("didFailToFetch", calls.get(2).getMethod().getName());
		Assertions.assertEquals(ExampleObserver.class, recorder.getObserverInterface());
	}

	@Test
	void keepsTheCallersExceptionInstanceWithItsWholeGraph() {
		RecordingObserver<ExampleObserver> recorder = RecordingObserver.fromInterface(ExampleObserver.class);
		IOException cause = new IOException("connection reset");
		IllegalStateException failure = new IllegalStateException("fixed message", cause);
		failure.addSuppressed(new IllegalArgumentException("suppressed"));

		recorder.getObserver().didFailToFetch(ENDPOINT, Duration.ZERO, failure);

		Throwable recorded = Assertions.assertInstanceOf(Throwable.class,
				recorder.getCalls("didFailToFetch").get(0).getArgument(2));
		Assertions.assertSame(failure, recorded);
		Assertions.assertSame(cause, recorded.getCause());
		Assertions.assertEquals(1, recorded.getSuppressed().length);
	}

	@Test
	void exposesAHookArgumentsExceptionGraphToTheSentinelWalker() {
		// The positive control of exit criterion 17: a sentinel inside an exception passed to a recorded hook is found.
		RecordingObserver<ExampleObserver> leaking = RecordingObserver.fromInterface(ExampleObserver.class);
		leaking.getObserver().didFailToFetch(ENDPOINT, Duration.ZERO,
				new IllegalStateException("fixed", new IOException("upstream echoed " + Sentinels.CLIENT_SECRET)));
		List<String> locations = Sentinels.findIn(leaking);
		Assertions.assertTrue(locations.contains("$.getCalls()[0].getArguments()[2].getCause().getMessage()"),
				locations::toString);

		RecordingObserver<ExampleObserver> clean = RecordingObserver.fromInterface(ExampleObserver.class);
		clean.getObserver().didFailToFetch(ENDPOINT, Duration.ZERO,
				new IllegalStateException("fixed", new IOException("connection reset")));
		Sentinels.assertAbsent(clean);
	}

	@Test
	void recordsNullArguments() {
		RecordingObserver<ExampleObserver> recorder = RecordingObserver.fromInterface(ExampleObserver.class);

		recorder.getObserver().didFailToFetch(ENDPOINT, Duration.ZERO, null);

		RecordingObserver.Call call = recorder.getCalls().get(0);
		Assertions.assertEquals(3, call.getArguments().size());
		Assertions.assertNull(call.getArgument(2));
	}

	@Test
	void filtersCallsByHookName() {
		RecordingObserver<ExampleObserver> recorder = RecordingObserver.fromInterface(ExampleObserver.class);
		ExampleObserver observer = recorder.getObserver();

		observer.willFetch(ENDPOINT);
		observer.didStop();
		observer.willFetch(URI.create("https://idp.example/jwks"));

		Assertions.assertEquals(2, recorder.getCalls("willFetch").size());
		Assertions.assertEquals(1, recorder.getCalls("didStop").size());
		Assertions.assertEquals(List.of(), recorder.getCalls("didFetch"));
	}

	@Test
	void recordsTheThreadThatMadeEachCall() throws Exception {
		RecordingObserver<ExampleObserver> recorder = RecordingObserver.fromInterface(ExampleObserver.class);
		ExecutorService executor = Executors.newSingleThreadExecutor();
		try {
			Thread otherThread = executor.submit(() -> {
				recorder.getObserver().didStop();
				return Thread.currentThread();
			}).get(30, TimeUnit.SECONDS);
			recorder.getObserver().didStop();

			Assertions.assertSame(otherThread, recorder.getCalls().get(0).getThread());
			Assertions.assertSame(Thread.currentThread(), recorder.getCalls().get(1).getThread());
		} finally {
			executor.shutdownNow();
		}
	}

	@Test
	void recordsAVoidDefaultHookWithoutRunningItsBody() {
		RecordingObserver<ExampleObserver> recorder = RecordingObserver.fromInterface(ExampleObserver.class);

		recorder.getObserver().didStopForwarding();

		Assertions.assertEquals(List.of("didStopForwarding"),
				recorder.getCalls().stream().map(RecordingObserver.Call::getMethodName).toList());
	}

	@Test
	void runsDefaultBodiesOfValueMethodsAndReturnsZeroValuesForAbstractOnes() {
		RecordingObserver<ValueObserver> recorder = RecordingObserver.fromInterface(ValueObserver.class);
		ValueObserver observer = recorder.getObserver();

		Assertions.assertEquals("default description", observer.describe());
		Assertions.assertEquals(0, observer.count());
		Assertions.assertFalse(observer.isEnabled());
		Assertions.assertNull(observer.name());
		Assertions.assertEquals(List.of("describe", "count", "isEnabled", "name"),
				recorder.getCalls().stream().map(RecordingObserver.Call::getMethodName).toList());
	}

	@Test
	void objectMethodsUseIdentityAndAreNotRecorded() {
		RecordingObserver<ExampleObserver> recorder = RecordingObserver.fromInterface(ExampleObserver.class);
		ExampleObserver observer = recorder.getObserver();
		ExampleObserver other = RecordingObserver.fromInterface(ExampleObserver.class).getObserver();

		Assertions.assertEquals(observer, observer);
		Assertions.assertNotEquals(observer, other);
		Assertions.assertEquals(System.identityHashCode(observer), observer.hashCode());
		Assertions.assertTrue(observer.toString().contains(ExampleObserver.class.getName()), observer::toString);
		Assertions.assertEquals(List.of(), recorder.getCalls());
		Assertions.assertSame(observer, recorder.getObserver());
	}

	@Test
	void aFailingRecorderRecordsEachCallThenThrows() {
		RecordingObserver<ExampleObserver> runtime = RecordingObserver.fromInterface(ExampleObserver.class,
				() -> new IllegalStateException("observer failed"));
		Assertions.assertThrows(IllegalStateException.class, () -> runtime.getObserver().didStop());
		Assertions.assertEquals(1, runtime.getCalls().size());

		RecordingObserver<ExampleObserver> error = RecordingObserver.fromInterface(ExampleObserver.class,
				() -> new AssertionError("an Error, not an Exception"));
		Assertions.assertThrows(AssertionError.class, () -> error.getObserver().didStop());

		RecordingObserver<ExampleObserver> checked = RecordingObserver.fromInterface(ExampleObserver.class,
				() -> new IOException("undeclared"));
		UndeclaredThrowableException wrapped = Assertions.assertThrows(UndeclaredThrowableException.class,
				() -> checked.getObserver().didStop());
		Assertions.assertTrue(wrapped.getCause() instanceof IOException, () -> String.valueOf(wrapped.getCause()));
	}

	@Test
	void rejectsTypesThatAreNotInterfaces() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> RecordingObserver.fromInterface(String.class));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> RecordingObserver.fromInterface(Deprecated.class));
	}

	@Test
	void returnsSnapshotsThatCannotBeModified() {
		RecordingObserver<ExampleObserver> recorder = RecordingObserver.fromInterface(ExampleObserver.class);
		recorder.getObserver().willFetch(ENDPOINT);
		List<RecordingObserver.Call> calls = recorder.getCalls();

		recorder.getObserver().didStop();

		Assertions.assertEquals(1, calls.size(), "a snapshot does not grow");
		Assertions.assertThrows(UnsupportedOperationException.class, () -> calls.remove(0));
		Assertions.assertThrows(UnsupportedOperationException.class, () -> calls.get(0).getArguments().set(0, null));
		Assertions.assertFalse(calls.get(0).toString().contains(ENDPOINT.toString()), "Call#toString names only");
	}

	/**
	 * Shaped like a Revetsec observer: only default {@code void} hooks, {@code @Nullable} parameters instead of
	 * {@code Optional}, and a failure hook that receives the caller's exception.
	 */
	interface ExampleObserver {
		default void willFetch(@NonNull URI uri) {
		}

		default void didFetch(@NonNull URI uri, @NonNull Duration duration, @NonNull Integer status) {
		}

		default void didFailToFetch(@NonNull URI uri, @NonNull Duration duration, @Nullable RuntimeException exception) {
		}

		default void didStop() {
		}

		default void didStopForwarding() {
			didStop();
		}
	}

	/**
	 * Methods that return values, to cover the proxy's other paths.
	 */
	interface ValueObserver {
		default @NonNull String describe() {
			return "default description";
		}

		int count();

		boolean isEnabled();

		@Nullable String name();
	}
}
