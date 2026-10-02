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

import org.jspecify.annotations.NonNull;

import com.revetsec.ErrorCategory;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.testing.ChildJvm;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

/**
 * The process-wide default client (D36 option (b) as amended by G6-6; exit criterion 13). Its settings are HTTP/1.1,
 * {@link HttpClient.Redirect#NEVER}, a 10-second connect timeout, no cookie handler or authenticator and the default
 * proxy selector. When it cannot be created, as with {@code -Djavax.net.ssl.keyStore=/nonexistent}, every call
 * reports {@link HttpExchangeException.Kind#DEFAULT_CLIENT_UNAVAILABLE} and no {@link Error} escapes; that case runs
 * in a child JVM, because a JVM initializes the holder once.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class DefaultHttpClientHolderTests {
	/**
	 * A child JVM normally takes about a second; this leaves room for a loaded machine.
	 */
	private static final Duration CHILD_TIMEOUT = Duration.ofSeconds(60);

	// Exit criterion 13: with the default SSLContext broken by a key store that does not exist, the holder's startup
	// fails, and every call, from any component, reports DEFAULT_CLIENT_UNAVAILABLE (CONFIGURATION, not transient),
	// never ExceptionInInitializerError or NoClassDefFoundError.
	@Test
	void aHolderStartupFailureGivesDefaultClientUnavailableOnEveryCallAndNoErrorEscapes() throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(HolderChild.class)
				.jvmOptions(List.of("-Djavax.net.ssl.keyStore=/nonexistent"))
				.arguments(List.of(HttpExchangeDeadlineTests.refusedUri().toString()))
				.timeout(CHILD_TIMEOUT)
				.build()
				.run();

		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		Assertions.assertEquals(List.of(
				"call 1: DEFAULT_CLIENT_UNAVAILABLE",
				"call 2: DEFAULT_CLIENT_UNAVAILABLE",
				"call 3: DEFAULT_CLIENT_UNAVAILABLE",
				"another component: DEFAULT_CLIENT_UNAVAILABLE",
				"holder: DEFAULT_CLIENT_UNAVAILABLE",
				"held client: none"), result.getStandardOutput().lines().toList(), result::toString);
		Assertions.assertEquals("", result.getStandardErrorWithoutJvmNotices(), result::toString);
		Assertions.assertEquals(ErrorCategory.CONFIGURATION,
				HttpExchangeException.Kind.DEFAULT_CLIENT_UNAVAILABLE.getCategory());
		Assertions.assertFalse(HttpExchangeException.Kind.DEFAULT_CLIENT_UNAVAILABLE.isTransient());
	}

	// Control for the test above: the same child without the broken key store gets a client, and a refused
	// connection is IO, so DEFAULT_CLIENT_UNAVAILABLE came from the startup failure alone.
	@Test
	void theSameChildWithoutTheBrokenKeyStoreGetsTheDefaultClient() throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(HolderChild.class)
				.arguments(List.of(HttpExchangeDeadlineTests.refusedUri().toString()))
				.timeout(CHILD_TIMEOUT)
				.build()
				.run();

		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		Assertions.assertEquals(List.of(
				"call 1: IO",
				"call 2: IO",
				"call 3: IO",
				"another component: IO",
				"holder: client",
				"held client: same"), result.getStandardOutput().lines().toList(), result::toString);
	}

	// D36 as amended by G6-6: HTTP/1.1, never follow redirects, a 10-second connect timeout, no cookie handler, no
	// authenticator, and the default proxy selector (an empty proxy() means the JDK's default).
	@Test
	void theDefaultClientHasTheD36Settings() throws Exception {
		HttpClient httpClient = DefaultHttpClientHolder.httpClient();

		Assertions.assertSame(httpClient, DefaultHttpClientHolder.heldHttpClientForTests());
		Assertions.assertSame(httpClient, DefaultHttpClientHolder.httpClient());
		Assertions.assertEquals(HttpClient.Version.HTTP_1_1, httpClient.version());
		Assertions.assertEquals(HttpClient.Redirect.NEVER, httpClient.followRedirects());
		Assertions.assertEquals(Duration.ofSeconds(10), httpClient.connectTimeout().orElseThrow());
		Assertions.assertTrue(httpClient.cookieHandler().isEmpty());
		Assertions.assertTrue(httpClient.authenticator().isEmpty());
		Assertions.assertTrue(httpClient.proxy().isEmpty());
		Assertions.assertTrue(httpClient.executor().isEmpty());
		Assertions.assertSame(httpClient, HttpExchange.fromHttpClient(null, OutboundUriPolicy.defaultInstance(), false)
				.resolveHttpClient());
	}

	// M2 plan G8-4 and exit criterion 17: the two test hooks are public, because the zero-thread test for the key-set
	// source lives in com.revetsec.jose. They are the only public members the holder adds: creating the client stays
	// package-private. The exchange's hook resolves exactly the client a request would use: the injected one, or the
	// holder's.
	@Test
	void theTwoTestHooksArePublicAndResolveTheClientARequestUses() throws Exception {
		Assertions.assertTrue(Modifier.isPublic(DefaultHttpClientHolder.class.getModifiers()));
		Method held = DefaultHttpClientHolder.class.getDeclaredMethod("heldHttpClientForTests");
		Assertions.assertTrue(Modifier.isPublic(held.getModifiers()) && Modifier.isStatic(held.getModifiers()));
		Assertions.assertEquals(List.of("heldHttpClientForTests"), Arrays.stream(
						DefaultHttpClientHolder.class.getDeclaredMethods())
				.filter(method -> Modifier.isPublic(method.getModifiers()))
				.map(Method::getName)
				.toList());
		Assertions.assertFalse(Modifier.isPublic(DefaultHttpClientHolder.class.getDeclaredMethod("httpClient")
				.getModifiers()));
		Method resolved = HttpExchange.class.getDeclaredMethod("resolvedHttpClientForTests");
		Assertions.assertTrue(Modifier.isPublic(resolved.getModifiers()));
		Assertions.assertFalse(Modifier.isPublic(HttpExchange.class.getDeclaredMethod("resolveHttpClient")
				.getModifiers()));

		HttpClient defaultClient = HttpExchange.fromHttpClient(null, OutboundUriPolicy.defaultInstance(), false)
				.resolvedHttpClientForTests();
		Assertions.assertSame(DefaultHttpClientHolder.heldHttpClientForTests(), defaultClient);
		Assertions.assertSame(defaultClient, HttpExchange.fromHttpClient(null, OutboundUriPolicy.defaultInstance(), true)
				.resolvedHttpClientForTests());
		StandInHttpClient injected = new StandInHttpClient();
		Assertions.assertSame(injected, HttpExchange.fromHttpClient(injected, OutboundUriPolicy.defaultInstance(), false)
				.resolvedHttpClientForTests());
		Assertions.assertEquals(0, injected.getSendCount());
	}

	/**
	 * Runs in the child JVM: three calls through one component, one through another, then the holder directly, each
	 * printed as one line; any {@link Throwable} other than {@link HttpExchangeException} is printed as escaping.
	 */
	public static final class HolderChild {
		private HolderChild() {
			// Entry point only.
		}

		/**
		 * The child's entry point.
		 *
		 * @param arguments one argument: a URI on 127.0.0.1 whose port refuses connections
		 */
		// Identity is the point: the hook must return the very client the holder hands out.
		@SuppressWarnings("ReferenceEquality")
		public static void main(@NonNull String @NonNull [] arguments) {
			URI refused = URI.create(arguments[0]);
			HttpExchange component = HttpExchange.fromHttpClient(null, OutboundUriPolicy.defaultInstance(), false);

			for (int call = 1; call <= 3; ++call)
				System.out.println("call " + call + ": " + outcome(component, refused));

			System.out.println("another component: " + outcome(HttpExchange.fromHttpClient(null,
					OutboundUriPolicy.defaultInstance(), false), refused));

			@Nullable HttpClient fromHolder = null;
			try {
				fromHolder = DefaultHttpClientHolder.httpClient();
				System.out.println("holder: client");
			} catch (HttpExchangeException e) {
				System.out.println("holder: " + e.getKind());
			} catch (Throwable t) {
				System.out.println("holder: escaped " + t.getClass().getName());
			}

			@Nullable HttpClient held = DefaultHttpClientHolder.heldHttpClientForTests();
			System.out.println("held client: " + (held == null ? "none" : held == fromHolder ? "same" : "different"));
		}

		private static @NonNull String outcome(@NonNull HttpExchange component, @NonNull URI uri) {
			try {
				RawResponse response = component.execute(HttpExchangeRequest.fromDefaults(uri, ResponseProfile.TOKEN),
						Deadline.fromNow(Duration.ofSeconds(20)));
				return "status " + response.status();
			} catch (HttpExchangeException e) {
				return e.getKind().name();
			} catch (Throwable t) {
				return "escaped " + t.getClass().getName();
			}
		}
	}
}
