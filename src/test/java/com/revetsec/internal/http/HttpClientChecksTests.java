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

import com.revetsec.testing.TestTls;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.net.http.HttpClient;
import java.util.stream.Stream;

/**
 * The injected-client check (G6-5; exit criterion 13): a client that follows redirects, which would re-send a POST
 * body with {@code client_secret} to another origin on a 307, is refused with {@link IllegalArgumentException}; a
 * client with {@link HttpClient.Redirect#NEVER} is returned as given.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class HttpClientChecksTests {
	// G6-5: real JDK clients, built the way an application would.
	@TestFactory
	Stream<DynamicTest> refusesAClientThatFollowsRedirects() {
		return Stream.of(HttpClient.Redirect.NORMAL, HttpClient.Redirect.ALWAYS)
				.map(redirect -> DynamicTest.dynamicTest(redirect.name(), () -> {
					HttpClient httpClient = TestTls.httpClientBuilder().followRedirects(redirect).build();
					IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
							() -> HttpClientChecks.requireNeverRedirects(httpClient));
					Assertions.assertTrue(String.valueOf(exception.getMessage()).contains("NEVER"), exception::getMessage);
				}));
	}

	// G6-5: the application owns everything else about its client; NEVER passes unchanged.
	@Test
	void returnsAClientThatNeverFollowsRedirects() {
		HttpClient httpClient = TestTls.httpClient();
		Assertions.assertSame(httpClient, HttpClientChecks.requireNeverRedirects(httpClient));
		// The default JDK setting is NEVER, so a client built without a redirect setting passes too.
		HttpClient defaults = HttpClient.newBuilder().build();
		Assertions.assertSame(defaults, HttpClientChecks.requireNeverRedirects(defaults));
	}

	// The check reads only followRedirects(), so an application's own HttpClient subclass is judged the same way.
	@Test
	void judgesAnyHttpClientByItsRedirectPolicy() {
		Assertions.assertDoesNotThrow(() -> HttpClientChecks.requireNeverRedirects(new StandInHttpClient()));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> HttpClientChecks.requireNeverRedirects(new StandInHttpClient(HttpClient.Redirect.NORMAL)));
	}

	@Test
	void aNullClientThrowsNullPointerException() {
		Assertions.assertThrows(NullPointerException.class, () -> HttpClientChecks.requireNeverRedirects(nullValue()));
	}

	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> T nullValue() {
		@Nullable T value = null;
		return value;
	}
}
