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

package com.revetsec.internal.http;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.http.StandInNetworkedBuilder.StandInNetworkedComponent;
import com.revetsec.testing.ChildJvm;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Zero threads and one default client (R4, R5 and D36 as amended by G6-6; exit criterion 14), in a child JVM:
 * <ol>
 *   <li>1,000 {@link StandInNetworkedBuilder} builds (configuration checks, the runtime floor and the injected-client
 *   check; no I/O) start no thread, by {@link ThreadMXBean#getTotalStartedThreadCount()}, with the baseline taken
 *   after the injected clients exist, and load neither {@link DefaultHttpClientHolder} nor
 *   {@code jdk.internal.net.http.HttpClientImpl};</li>
 *   <li>then two components without an injected client make their first use against a refused {@code 127.0.0.1}
 *   port (so no trust store is needed), and the holder's test hook shows that both got the same client.</li>
 * </ol>
 * The child writes its own class-load log, in load order, and loads a marker class between the two phases, so the
 * test can tell what the builds loaded from what the first use loaded. No thread count is asserted after first use,
 * because the JDK's own threads differ by version (R4).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class ZeroThreadBuildTests {
	private static final String HOLDER = "com.revetsec.internal.http.DefaultHttpClientHolder";
	private static final String JDK_CLIENT = "jdk.internal.net.http.HttpClientImpl";
	private static final String MARKER = BuildsFinished.class.getName();
	private static final int BUILDS = 1_000;

	@Test
	void buildsStartNoThreadAndLoadNoClientAndFirstUsesShareOneDefaultClient(@TempDir Path directory)
			throws Exception {
		Path classLoadLog = directory.resolve("class-load.log");
		ChildJvm.Result result = ChildJvm.withMainClass(BuildChild.class)
				.jvmOptions(List.of("-Xlog:class+load=info:file=\"" + classLoadLog + "\":none:filecount=0"))
				.arguments(List.of(HttpExchangeDeadlineTests.refusedUri().toString()))
				.timeout(Duration.ofSeconds(60))
				.build()
				.run();

		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		Assertions.assertEquals(List.of(
				"built 625, refused 375",
				"threads started by the builds: 0",
				"threads started by the control thread: 1",
				"a call with no time left: TIMEOUT",
				"first component: IO",
				"second component: IO",
				"both components use the held client: true"), result.getStandardOutput().lines().toList(),
				result::toString);

		List<String> loaded = loadedInOrder(classLoadLog);
		int marker = loaded.indexOf(MARKER);
		Assertions.assertTrue(marker > 0, "the marker class was loaded");
		List<String> duringBuilds = loaded.subList(0, marker);
		List<String> afterBuilds = loaded.subList(marker, loaded.size());

		Assertions.assertFalse(duringBuilds.contains(HOLDER), "the builds loaded the default-client holder");
		Assertions.assertFalse(duringBuilds.contains(JDK_CLIENT), "the builds loaded the JDK client");
		// Controls: the builds did load the code under test, and the first use loaded what the builds did not.
		Assertions.assertTrue(duringBuilds.contains(StandInNetworkedBuilder.class.getName()));
		Assertions.assertTrue(duringBuilds.contains(HttpExchange.class.getName()));
		Assertions.assertTrue(duringBuilds.contains(HttpClient.class.getName()));
		Assertions.assertTrue(afterBuilds.contains(HOLDER));
		Assertions.assertTrue(afterBuilds.contains(JDK_CLIENT));
	}

	/**
	 * The binary names in a {@code -Xlog:class+load} log written with the {@code none} decorator, in load order.
	 */
	private static List<String> loadedInOrder(Path classLoadLog) throws Exception {
		List<String> names = new ArrayList<>();
		for (String line : Files.readAllLines(classLoadLog, StandardCharsets.UTF_8)) {
			int space = line.indexOf(' ');
			String name = space < 0 ? line.strip() : line.substring(0, space);
			if (!name.isEmpty())
				names.add(name);
		}
		return names;
	}

	/**
	 * Loaded (never initialized) between the builds and the first use; its line in the class-load log splits them.
	 */
	public static final class BuildsFinished {
		private BuildsFinished() {
			// Marker only.
		}
	}

	/**
	 * Runs in the child JVM and prints one line per result.
	 */
	public static final class BuildChild {
		private BuildChild() {
			// Entry point only.
		}

		/**
		 * The child's entry point.
		 *
		 * @param arguments one argument: a URI on 127.0.0.1 whose port refuses connections
		 * @throws Exception if the child itself fails, which the test sees as a non-zero exit
		 */
		// Identity is the point: both components must hold the very client the holder's test hook returns.
		@SuppressWarnings("ReferenceEquality")
		public static void main(String[] arguments) throws Exception {
			URI refused = URI.create(arguments[0]);
			ThreadMXBean threads = ManagementFactory.getThreadMXBean();
			// Injected clients are the application's; they exist before the baseline (exit criterion 14). These
			// stand-ins never touch the JDK's client implementation.
			HttpClient neverRedirects = new StandInHttpClient();
			HttpClient followsRedirects = new StandInHttpClient(HttpClient.Redirect.NORMAL);
			Runtime.Version belowFloor = Runtime.Version.parse("17.0.2");

			long baseline = threads.getTotalStartedThreadCount();
			int built = 0;
			int refusedBuilds = 0;
			for (int build = 0; build < BUILDS; ++build) {
				StandInNetworkedBuilder builder = StandInNetworkedBuilder
						.withIssuer(URI.create("https://issuer" + (build % 10) + ".example/tenant/" + build))
						.requestTimeout(Duration.ofSeconds(5))
						.totalDeadline(Duration.ofSeconds(8))
						.outboundUriPolicy(OutboundUriPolicy.defaultInstance());
				switch (build % 8) {
					case 0, 1 -> builder.httpClient(null);
					case 2, 3 -> builder.httpClient(neverRedirects);
					// Refused by the injected-client check (G6-5).
					case 4 -> builder.httpClient(followsRedirects);
					// Refused by the runtime floor, then accepted with the acknowledgment (section 9.6).
					case 5 -> builder.runtimeVersion(belowFloor);
					case 6 -> builder.runtimeVersion(belowFloor).acknowledgeUnpatchedRuntime(true);
					// Refused by configuration validation: the request timeout exceeds the total deadline (G5-5).
					default -> builder.requestTimeout(Duration.ofSeconds(9));
				}
				try {
					builder.build();
					++built;
				} catch (IllegalArgumentException | IllegalStateException e) {
					++refusedBuilds;
				}
			}
			long startedByBuilds = threads.getTotalStartedThreadCount() - baseline;

			// Control: the counter does see a thread this JVM starts.
			long beforeControl = threads.getTotalStartedThreadCount();
			Thread control = new Thread(() -> {
				// Nothing to do.
			}, "revetsec-control");
			control.start();
			control.join();
			long startedByControl = threads.getTotalStartedThreadCount() - beforeControl;

			System.out.println("built " + built + ", refused " + refusedBuilds);
			System.out.println("threads started by the builds: " + startedByBuilds);
			System.out.println("threads started by the control thread: " + startedByControl);

			// Exit criterion 11: a call with no time left fails before any request is built, so it does not create the
			// default client either (the holder must still be unloaded at the marker).
			StandInNetworkedComponent expired = StandInNetworkedBuilder.withIssuer(refused).build();
			System.out.println("a call with no time left: " + use(() -> expired.fetchMetadata(
					Deadline.fromNow(Duration.ZERO))));

			if (BuildsFinished.class.getName().isEmpty())
				throw new IllegalStateException("unreachable: the marker class has a name");

			StandInNetworkedComponent first = StandInNetworkedBuilder.withIssuer(refused).build();
			StandInNetworkedComponent second = StandInNetworkedBuilder.withIssuer(refused).build();
			System.out.println("first component: " + use(first::fetchMetadata));
			System.out.println("second component: " + use(second::fetchMetadata));

			@Nullable HttpClient held = DefaultHttpClientHolder.heldHttpClientForTests();
			System.out.println("both components use the held client: " + (held != null
					&& first.httpClientForTests() == held && second.httpClientForTests() == held));
		}

		private static String use(Call call) {
			try {
				return "status " + call.run().status();
			} catch (HttpExchangeException e) {
				return e.getKind().name();
			}
		}

		/**
		 * One public call on a component.
		 */
		@FunctionalInterface
		private interface Call {
			RawResponse run() throws HttpExchangeException;
		}
	}
}
