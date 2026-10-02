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

package com.revetsec.jose;

import org.jspecify.annotations.NonNull;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.http.DefaultHttpClientHolder;
import com.revetsec.internal.http.HttpExchange;
import com.revetsec.internal.http.HttpExchangeException;
import com.revetsec.testing.ChildJvm;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;

/**
 * Zero threads and one default client for key sources (G8-4, D36; exit criterion 17, which repeats M1's exit
 * criterion 14 for {@link RemoteJsonWebKeySource}), in a child JVM:
 * <ol>
 *   <li>1,000 {@link RemoteJsonWebKeySource} builds (settings, the runtime floor, the injected client and the URI;
 *   some refused) and a {@link JwtValidator} build over each source built start no thread, by
 *   {@link ThreadMXBean#getTotalStartedThreadCount()} with the baseline taken after the injected clients exist, and
 *   load neither {@link DefaultHttpClientHolder} nor {@code jdk.internal.net.http.HttpClientImpl};</li>
 *   <li>then two sources without an injected client make their first fetch against a refused {@code 127.0.0.1} port,
 *   over plain http with {@code allowInsecureLoopback(true)} so no trust store is needed: the holder is initialized
 *   once, and both sources got the client it holds.</li>
 * </ol>
 * The child writes its own class-load log, in load order, and loads a marker class between the two phases, so the
 * test can tell what the builds loaded from what the first fetches loaded. It uses the source's package-private
 * {@code build(Runtime.Version)} and {@code httpExchangeForTests()}, and {@code internal.http}'s two public test hooks.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RemoteJsonWebKeySourceZeroThreadTests {
	private static final String HOLDER = "com.revetsec.internal.http.DefaultHttpClientHolder";
	private static final String JDK_CLIENT = "jdk.internal.net.http.HttpClientImpl";
	private static final String MARKER = BuildsFinished.class.getName();
	private static final int BUILDS = 1_000;

	@Test
	void buildsStartNoThreadAndLoadNoClientAndFirstFetchesShareOneDefaultClient(@TempDir @NonNull Path directory)
			throws Exception {
		Path classLoadLog = directory.resolve("class-load.log");
		ChildJvm.Result result = ChildJvm.withMainClass(BuildChild.class)
				.jvmOptions(List.of("-Xlog:class+load=info:file=\"" + classLoadLog + "\":none:filecount=0"))
				.arguments(List.of(refusedUri().toString()))
				.timeout(Duration.ofSeconds(60))
				.build()
				.run();

		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		Assertions.assertEquals(List.of(
				"built 625, refused 375",
				"validators built: 1250",
				"threads started by the builds: 0",
				"threads started by the control thread: 1",
				"first source: TRANSPORT, transient",
				"second source: TRANSPORT, transient",
				"both sources use the held client: true"), result.getStandardOutput().lines().toList(),
				result::toString);

		List<String> loaded = loadedInOrder(classLoadLog);
		int marker = loaded.indexOf(MARKER);
		Assertions.assertTrue(marker > 0, "the marker class was loaded");
		List<String> duringBuilds = loaded.subList(0, marker);
		List<String> afterBuilds = loaded.subList(marker, loaded.size());

		Assertions.assertFalse(duringBuilds.contains(HOLDER), "the builds loaded the default-client holder");
		Assertions.assertFalse(duringBuilds.contains(JDK_CLIENT), "the builds loaded the JDK client");
		// Controls: the builds loaded the code under test, and the first fetches loaded what the builds did not.
		for (Class<?> type : List.of(RemoteJsonWebKeySource.class, JwksCache.class, JwksSettings.class,
				JwtValidator.class, HttpExchange.class, HttpClient.class))
			Assertions.assertTrue(duringBuilds.contains(type.getName()), type::getName);
		Assertions.assertTrue(afterBuilds.contains(HOLDER));
		Assertions.assertTrue(afterBuilds.contains(JDK_CLIENT));
	}

	/**
	 * An {@code http} URI on {@code 127.0.0.1} whose port was just released, so connecting to it is refused.
	 */
	private static @NonNull URI refusedUri() throws IOException {
		int port;
		try (ServerSocket serverSocket = new ServerSocket()) {
			serverSocket.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), 0));
			port = serverSocket.getLocalPort();
		}
		return URI.create("http://127.0.0.1:" + port + "/keys");
	}

	/**
	 * The binary names in a {@code -Xlog:class+load} log written with the {@code none} decorator, in load order.
	 */
	private static @NonNull List<@NonNull String> loadedInOrder(@NonNull Path classLoadLog) throws IOException {
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
	 * Loaded (never initialized) between the builds and the first fetches; its line in the class-load log splits them.
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
		 * @param arguments one argument: an {@code http} URI on 127.0.0.1 whose port refuses connections
		 * @throws Exception if the child itself fails, which the test sees as a non-zero exit
		 */
		// Identity is the point: both sources must hold the very client the holder's test hook returns.
		@SuppressWarnings("ReferenceEquality")
		public static void main(@NonNull String @NonNull [] arguments) throws Exception {
			URI refused = URI.create(arguments[0]);
			ThreadMXBean threads = ManagementFactory.getThreadMXBean();
			// Injected clients are the application's; they exist before the baseline. These stand-ins never touch the
			// JDK's client implementation.
			HttpClient neverRedirects = new StandInClient(HttpClient.Redirect.NEVER);
			HttpClient followsRedirects = new StandInClient(HttpClient.Redirect.NORMAL);
			Runtime.Version belowFloor = Runtime.Version.parse("17.0.2");
			Runtime.Version current = Runtime.version();

			long baseline = threads.getTotalStartedThreadCount();
			int built = 0;
			int refusedBuilds = 0;
			int validators = 0;
			for (int build = 0; build < BUILDS; ++build) {
				// Every eighth URI has a fragment, which the URI check refuses (G8-9).
				URI uri = URI.create("https://issuer" + (build % 10) + ".example.com/tenant/" + build + "/keys"
						+ (build % 8 == 7 ? "#fragment" : ""));
				RemoteJsonWebKeySource.Builder builder = RemoteJsonWebKeySource.withUri(uri)
						.outboundUriPolicy(build % 3 == 0 ? OutboundUriPolicy.publicAddressesOnlyInstance() : null)
						.requestTimeout(Duration.ofSeconds(5));
				Runtime.Version runtime = current;
				switch (build % 8) {
					case 0, 1, 7 -> builder = builder.httpClient(null);
					case 2, 3 -> builder = builder.httpClient(neverRedirects);
					// Refused by the injected-client check (G6-5).
					case 4 -> builder = builder.httpClient(followsRedirects);
					// Refused by the runtime floor, then accepted with the acknowledgment (section 9.6).
					case 5 -> runtime = belowFloor;
					default -> {
						runtime = belowFloor;
						builder = builder.acknowledgeUnpatchedRuntime(true);
					}
				}
				RemoteJsonWebKeySource source;
				try {
					source = builder.build(runtime);
					++built;
				} catch (IllegalArgumentException | IllegalStateException e) {
					++refusedBuilds;
					continue;
				}
				// A validator over the source builds without I/O too, with fixed or any audiences.
				validators += List.of(
						JwtValidator.withIssuer("https://issuer.example.com").jsonWebKeySource(source)
								.expectedAudiences(Set.of("api://" + build)).build(),
						JwtValidator.withIssuer("https://issuer.example.com").jsonWebKeySource(source)
								.acceptAnyAudience(true).build()).size();
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
			System.out.println("validators built: " + validators);
			System.out.println("threads started by the builds: " + startedByBuilds);
			System.out.println("threads started by the control thread: " + startedByControl);

			if (BuildsFinished.class.getName().isEmpty())
				throw new IllegalStateException("unreachable: the marker class has a name");

			RemoteJsonWebKeySource first = RemoteJsonWebKeySource.withUri(refused).allowInsecureLoopback(true).build();
			RemoteJsonWebKeySource second = RemoteJsonWebKeySource.withUri(refused).allowInsecureLoopback(true).build();
			System.out.println("first source: " + firstFetch(first));
			System.out.println("second source: " + firstFetch(second));

			@Nullable HttpClient held = DefaultHttpClientHolder.heldHttpClientForTests();
			System.out.println("both sources use the held client: " + (held != null
					&& resolved(first) == held && resolved(second) == held));
		}

		private static @NonNull String firstFetch(@NonNull RemoteJsonWebKeySource source) {
			try {
				source.warmUp();
				return "fetched";
			} catch (JsonWebKeySetUnavailableException e) {
				return e.getCategory() + (e.isTransient() ? ", transient" : ", not transient");
			}
		}

		private static @Nullable HttpClient resolved(@NonNull RemoteJsonWebKeySource source) {
			try {
				return source.httpExchangeForTests().resolvedHttpClientForTests();
			} catch (HttpExchangeException e) {
				return null;
			}
		}
	}

	/**
	 * A test-only client that only reports its redirect policy; nothing is ever sent through it here.
	 */
	@ThreadSafe
	static final class StandInClient extends HttpClient {
		private final HttpClient.Redirect redirect;

		StandInClient(HttpClient.@NonNull Redirect redirect) {
			this.redirect = redirect;
		}

		@Override
		public HttpClient.@NonNull Redirect followRedirects() {
			return this.redirect;
		}

		@Override
		public @NonNull Optional<@NonNull CookieHandler> cookieHandler() {
			return Optional.empty();
		}

		@Override
		public @NonNull Optional<@NonNull Duration> connectTimeout() {
			return Optional.empty();
		}

		@Override
		public @NonNull Optional<@NonNull ProxySelector> proxy() {
			return Optional.empty();
		}

		@Override
		public @NonNull SSLContext sslContext() {
			throw new UnsupportedOperationException("StandInClient has no TLS context");
		}

		@Override
		public @NonNull SSLParameters sslParameters() {
			return new SSLParameters();
		}

		@Override
		public @NonNull Optional<@NonNull Authenticator> authenticator() {
			return Optional.empty();
		}

		@Override
		public HttpClient.@NonNull Version version() {
			return HttpClient.Version.HTTP_1_1;
		}

		@Override
		public @NonNull Optional<@NonNull Executor> executor() {
			return Optional.empty();
		}

		@Override
		public <T> @NonNull HttpResponse<@NonNull T> send(@NonNull HttpRequest request, HttpResponse.@NonNull BodyHandler<@NonNull T> responseBodyHandler)
				throws IOException {
			throw new IOException("StandInClient sends nothing");
		}

		@Override
		public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(@NonNull HttpRequest request,
				HttpResponse.@NonNull BodyHandler<@NonNull T> responseBodyHandler) {
			return CompletableFuture.failedFuture(new IOException("StandInClient sends nothing"));
		}

		@Override
		public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(@NonNull HttpRequest request,
				HttpResponse.@NonNull BodyHandler<@NonNull T> responseBodyHandler, HttpResponse.@NonNull PushPromiseHandler<@NonNull T> pushPromiseHandler) {
			return sendAsync(request, responseBodyHandler);
		}
	}
}
