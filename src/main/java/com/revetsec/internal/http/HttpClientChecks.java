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

import javax.annotation.concurrent.ThreadSafe;
import java.net.http.HttpClient;

import static java.util.Objects.requireNonNull;

/**
 * Build-time checks on an {@link HttpClient} the application injects (M1 plan, G6-5).
 * <p>
 * Every networked builder takes {@code httpClient(@Nullable HttpClient)} and calls
 * {@link #requireNeverRedirects(HttpClient)} on a non-null client in {@code build()}. The application owns the
 * injected client's TLS, proxy, authenticator and cookies; Revetsec only refuses one that follows redirects, because a
 * followed cross-origin 307 re-sends a POST body, and with it {@code client_secret}, to another origin (verified
 * against the JDK client with {@code Redirect.NORMAL}).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class HttpClientChecks {
	private HttpClientChecks() {
		// Static helpers only.
	}

	/**
	 * Requires that {@code httpClient} never follows redirects.
	 *
	 * @param httpClient the injected client
	 * @return {@code httpClient}
	 * @throws NullPointerException     if {@code httpClient} is {@code null}
	 * @throws IllegalArgumentException if {@code httpClient.followRedirects()} is not
	 *                                  {@link HttpClient.Redirect#NEVER}
	 */
	@NonNull
	public static HttpClient requireNeverRedirects(@NonNull HttpClient httpClient) {
		requireNonNull(httpClient);

		if (httpClient.followRedirects() != HttpClient.Redirect.NEVER)
			throw new IllegalArgumentException("An injected HttpClient must use followRedirects(HttpClient.Redirect.NEVER): "
					+ "a followed redirect can re-send credentials to another origin.");

		return httpClient;
	}
}
