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

import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Objects.requireNonNull;

/**
 * A test-only {@link HttpClient} that sends nothing: it counts {@code send} and {@code sendAsync} calls and fails each
 * with an {@link IOException}. It stands in for an application's injected client where a test must show that no
 * request was sent, or that building a component never touches the JDK's client implementation (exit criterion 14:
 * {@code jdk.internal.net.http.HttpClientImpl} is never loaded, and no thread starts).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
final class StandInHttpClient extends HttpClient {
	private final HttpClient.Redirect redirect;
	private final AtomicInteger sendCount = new AtomicInteger();

	StandInHttpClient() {
		this(HttpClient.Redirect.NEVER);
	}

	StandInHttpClient(HttpClient.Redirect redirect) {
		this.redirect = requireNonNull(redirect);
	}

	/**
	 * How many times {@code send} or {@code sendAsync} was called.
	 *
	 * @return the count
	 */
	int getSendCount() {
		return this.sendCount.get();
	}

	@Override
	public Optional<CookieHandler> cookieHandler() {
		return Optional.empty();
	}

	@Override
	public Optional<Duration> connectTimeout() {
		return Optional.empty();
	}

	@Override
	public HttpClient.Redirect followRedirects() {
		return this.redirect;
	}

	@Override
	public Optional<ProxySelector> proxy() {
		return Optional.empty();
	}

	@Override
	public SSLContext sslContext() {
		try {
			return SSLContext.getDefault();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public SSLParameters sslParameters() {
		return new SSLParameters();
	}

	@Override
	public Optional<Authenticator> authenticator() {
		return Optional.empty();
	}

	@Override
	public HttpClient.Version version() {
		return HttpClient.Version.HTTP_1_1;
	}

	@Override
	public Optional<Executor> executor() {
		return Optional.empty();
	}

	@Override
	public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
			throws IOException {
		this.sendCount.incrementAndGet();
		throw new IOException("StandInHttpClient sends nothing");
	}

	@Override
	public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
			HttpResponse.BodyHandler<T> responseBodyHandler) {
		this.sendCount.incrementAndGet();
		return CompletableFuture.failedFuture(new IOException("StandInHttpClient sends nothing"));
	}

	@Override
	public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
			HttpResponse.BodyHandler<T> responseBodyHandler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
		return sendAsync(request, responseBodyHandler);
	}
}
