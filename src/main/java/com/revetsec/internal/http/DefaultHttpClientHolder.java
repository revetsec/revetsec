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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.net.http.HttpClient;
import java.time.Duration;

/**
 * The process-wide default {@link HttpClient}, used when an application injects none (D36 option (b), as amended by
 * G6-6). This is the one class allowed to create it ({@code SourcePolicyTests.DEFAULT_HTTP_CLIENT_HOLDER}).
 * <p>
 * It is an initialization-on-demand holder: the JVM runs the static initializer, once, on the first network use of a
 * component without an injected client ({@link HttpExchange} calls {@link #httpClient()}), and never in
 * {@code build()}. The client is immutable, and it owns the JDK's own threads, the documented exception to R4's "no
 * threads": its selector thread and default executor on JDK 17 to 25, and the virtual-thread scheduler and pollers on
 * 26 and later. The JDK also completes {@code sendAsync} futures on the common pool, which {@link HttpExchange} never
 * waits on.
 * <p>
 * Its settings: HTTP/1.1, {@link HttpClient.Redirect#NEVER}, a 10-second connect timeout, no cookie handler, no
 * authenticator, the default proxy selector and the default {@code SSLContext}.
 * <p>
 * <strong>Startup failure.</strong> If the client cannot be created (for example, {@code javax.net.ssl.keyStore}
 * names a file that does not exist, so the default {@code SSLContext} fails), the initializer keeps the failure to
 * itself and every call reports {@link HttpExchangeException.Kind#DEFAULT_CLIENT_UNAVAILABLE}. Letting it escape
 * would throw {@link ExceptionInInitializerError} on first use and {@link NoClassDefFoundError} on every use after
 * that. Only a {@link VirtualMachineError} propagates; {@link HttpExchange} then maps the class's later
 * {@link LinkageError}s to the same kind. The failure itself is not kept: its message could name local paths.
 * <p>
 * The class is public only for its test hook, {@link #heldHttpClientForTests()} (M2 plan, G8-4; exit criterion 17):
 * a test in another package shows through it that components share the one default client. Everything else stays
 * package-private, and only {@link HttpExchange} obtains the client.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class DefaultHttpClientHolder {
	/**
	 * The default client's connect timeout (D36).
	 */
	static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);

	/**
	 * The default client, or {@code null} if it could not be created. Written once, by the static initializer.
	 */
	@Nullable
	private static final HttpClient HTTP_CLIENT = createHttpClient();

	private DefaultHttpClientHolder() {
		// Static holder only.
	}

	/**
	 * Returns the default client, creating it on the first call.
	 *
	 * @return the process-wide default client
	 * @throws HttpExchangeException with {@link HttpExchangeException.Kind#DEFAULT_CLIENT_UNAVAILABLE} if it could not
	 *                               be created in this runtime
	 */
	@NonNull
	static HttpClient httpClient() throws HttpExchangeException {
		@Nullable HttpClient httpClient = HTTP_CLIENT;

		if (httpClient == null)
			throw new HttpExchangeException(HttpExchangeException.Kind.DEFAULT_CLIENT_UNAVAILABLE);

		return httpClient;
	}

	/**
	 * Test hook, public by necessity (M1 exit criterion 14; M2 exit criterion 17): the held client, so a test can show
	 * that two components share one. Calling it initializes the holder, and so creates the default client, like a
	 * component's first request. Production code never calls it.
	 *
	 * @return the held client, or {@code null} if it could not be created
	 */
	@Nullable
	public static HttpClient heldHttpClientForTests() {
		return HTTP_CLIENT;
	}

	@Nullable
	private static HttpClient createHttpClient() {
		try {
			return HttpClient.newBuilder()
					.version(HttpClient.Version.HTTP_1_1)
					.followRedirects(HttpClient.Redirect.NEVER)
					.connectTimeout(CONNECT_TIMEOUT)
					.build();
		} catch (VirtualMachineError e) {
			throw e;
		} catch (Throwable t) {
			// Contained on purpose (see the class description): every call reports DEFAULT_CLIENT_UNAVAILABLE.
			return null;
		}
	}
}
