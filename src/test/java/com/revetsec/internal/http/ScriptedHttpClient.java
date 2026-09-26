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

import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static java.util.Objects.requireNonNull;

/**
 * A test-only {@link HttpClient} that plays an application's injected client whose behavior the JDK's own client
 * never shows, so {@link HttpExchange}'s defensive paths can be exercised without a network. It records the last
 * request it was given ({@link #getLastRequest()}):
 * <ul>
 *   <li>{@link Behavior#THROW_FROM_SEND_ASYNC} and {@link Behavior#RETURN_NULL_FROM_SEND_ASYNC}: a broken client;</li>
 *   <li>{@link Behavior#RESPOND_AND_STALL}: the body handler is applied, on the calling thread, to a scripted status
 *   and headers (which may be {@code null}, or a status the JDK would never pass on), its subscriber is subscribed to a
 *   {@link #getSubscription() recording subscription} that never delivers a byte, and the returned future never
 *   completes and ignores {@code cancel}, like a decorating client that copies the JDK's result into a future of its
 *   own. Only a cancel of the subscription itself can end such an exchange's connection.</li>
 *   <li>{@link Behavior#NEVER_RESPOND} and {@link Behavior#FAIL_WITH_IO}: the handler is never applied, and the
 *   returned future never completes, or has already failed with an {@link IOException}.</li>
 * </ul>
 * {@link #withAFutureThatThrows(Behavior, int, HttpHeaders)} returns, for any behavior but the first two, a future
 * whose {@code isDone} and {@code cancel} throw, as {@link CompletableFuture#minimalCompletionStage()}'s do.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
final class ScriptedHttpClient extends HttpClient {
	/**
	 * What {@code sendAsync} does.
	 */
	@Immutable
	enum Behavior {
		/**
		 * Throws an {@link IllegalStateException}.
		 */
		THROW_FROM_SEND_ASYNC,
		/**
		 * Returns {@code null}.
		 */
		RETURN_NULL_FROM_SEND_ASYNC,
		/**
		 * Applies the handler, subscribes its subscriber and never delivers the body.
		 */
		RESPOND_AND_STALL,
		/**
		 * Returns a future that never completes, without applying the handler.
		 */
		NEVER_RESPOND,
		/**
		 * Returns a future that has already failed with an {@link IOException}, without applying the handler.
		 */
		FAIL_WITH_IO
	}

	private final Behavior behavior;
	private final int status;
	private final @Nullable HttpHeaders headers;
	private final boolean futureThrows;
	private final RecordingSubscription subscription = new RecordingSubscription();
	private final AtomicReference<@Nullable HttpRequest> lastRequest = new AtomicReference<>();

	private ScriptedHttpClient(Behavior behavior, int status, @Nullable HttpHeaders headers, boolean futureThrows) {
		this.behavior = requireNonNull(behavior);
		this.status = status;
		this.headers = headers;
		this.futureThrows = futureThrows;
	}

	/**
	 * A client whose {@code sendAsync} misbehaves before any response.
	 *
	 * @param behavior {@link Behavior#THROW_FROM_SEND_ASYNC} or {@link Behavior#RETURN_NULL_FROM_SEND_ASYNC}
	 * @return the client
	 */
	static ScriptedHttpClient failingBeforeAnyResponse(Behavior behavior) {
		if (behavior == Behavior.RESPOND_AND_STALL)
			throw new IllegalArgumentException("Use respondingAndStalling");
		return new ScriptedHttpClient(behavior, 200, null, false);
	}

	/**
	 * A client that answers every request with {@code status} and {@code headers}, then never sends the body.
	 *
	 * @param status  the status the body handler sees
	 * @param headers the headers the body handler sees, or {@code null} to make reading them fail
	 * @return the client
	 */
	static ScriptedHttpClient respondingAndStalling(int status, @Nullable HttpHeaders headers) {
		return new ScriptedHttpClient(Behavior.RESPOND_AND_STALL, status, headers, false);
	}

	/**
	 * A client whose {@code sendAsync} returns a future that throws {@link IllegalStateException} from {@code isDone}
	 * and {@code cancel}, like an application client that returns {@code minimalCompletionStage()} cast to
	 * {@link CompletableFuture}; its {@code whenComplete} still works.
	 *
	 * @param behavior {@link Behavior#RESPOND_AND_STALL}, {@link Behavior#NEVER_RESPOND} or
	 *                 {@link Behavior#FAIL_WITH_IO}
	 * @param status   the status the body handler sees, for {@link Behavior#RESPOND_AND_STALL}
	 * @param headers  the headers the body handler sees, for {@link Behavior#RESPOND_AND_STALL}
	 * @return the client
	 */
	static ScriptedHttpClient withAFutureThatThrows(Behavior behavior, int status, @Nullable HttpHeaders headers) {
		if (behavior == Behavior.THROW_FROM_SEND_ASYNC || behavior == Behavior.RETURN_NULL_FROM_SEND_ASYNC)
			throw new IllegalArgumentException("That behavior returns no future");
		return new ScriptedHttpClient(behavior, status, headers, true);
	}

	/**
	 * The request {@code sendAsync} was last given.
	 *
	 * @return the request
	 * @throws IllegalStateException if nothing was sent
	 */
	HttpRequest getLastRequest() {
		HttpRequest request = this.lastRequest.get();
		if (request == null)
			throw new IllegalStateException("Nothing was sent");
		return request;
	}

	/**
	 * The subscription the last body subscriber was given.
	 *
	 * @return the recording subscription
	 */
	RecordingSubscription getSubscription() {
		return this.subscription;
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
		return HttpClient.Redirect.NEVER;
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
		throw new IOException("ScriptedHttpClient only sends asynchronously");
	}

	@Override
	@SuppressWarnings("NullAway")
	public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
			HttpResponse.BodyHandler<T> responseBodyHandler) {
		this.lastRequest.set(request);
		switch (this.behavior) {
			case THROW_FROM_SEND_ASYNC -> throw new IllegalStateException("ScriptedHttpClient failed to send");
			case RETURN_NULL_FROM_SEND_ASYNC -> {
				return null;
			}
			case RESPOND_AND_STALL -> {
				HttpResponse.BodySubscriber<T> subscriber = responseBodyHandler.apply(new ScriptedResponseInfo(this.status,
						this.headers));
				subscriber.onSubscribe(this.subscription);
				// Never completed; cancelling it reaches nothing underneath.
				return newFuture();
			}
			case NEVER_RESPOND -> {
				return newFuture();
			}
			case FAIL_WITH_IO -> {
				CompletableFuture<HttpResponse<T>> failed = newFuture();
				failed.completeExceptionally(new IOException("ScriptedHttpClient failed the exchange"));
				return failed;
			}
		}
		throw new IllegalStateException("Unknown behavior " + this.behavior);
	}

	private <T> CompletableFuture<HttpResponse<T>> newFuture() {
		return this.futureThrows ? new ThrowingFuture<>() : new CompletableFuture<>();
	}

	/**
	 * A future whose {@code isDone} and {@code cancel} throw, as a minimal completion stage's do; completing it and
	 * {@code whenComplete} work as usual.
	 */
	@ThreadSafe
	private static final class ThrowingFuture<T> extends CompletableFuture<T> {
		@Override
		public boolean isDone() {
			throw new IllegalStateException("ThrowingFuture.isDone");
		}

		@Override
		public boolean cancel(boolean mayInterruptIfRunning) {
			throw new IllegalStateException("ThrowingFuture.cancel");
		}
	}

	@Override
	public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
			HttpResponse.BodyHandler<T> responseBodyHandler, HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
		return sendAsync(request, responseBodyHandler);
	}

	/**
	 * Records what the body subscriber asked for; it never delivers anything.
	 */
	@ThreadSafe
	static final class RecordingSubscription implements Flow.Subscription {
		private final AtomicLong requested = new AtomicLong();
		private final AtomicBoolean cancelled = new AtomicBoolean();

		@Override
		public void request(long n) {
			this.requested.addAndGet(n);
		}

		@Override
		public void cancel() {
			this.cancelled.set(true);
		}

		/**
		 * The total demand signalled.
		 *
		 * @return the sum of every {@code request(n)}
		 */
		long getRequested() {
			return this.requested.get();
		}

		/**
		 * Whether the subscriber cancelled.
		 *
		 * @return {@code true} once {@code cancel()} was called
		 */
		boolean isCancelled() {
			return this.cancelled.get();
		}
	}

	/**
	 * The status and headers a scripted body handler sees.
	 */
	@Immutable
	private static final class ScriptedResponseInfo implements HttpResponse.ResponseInfo {
		private final int status;
		private final @Nullable HttpHeaders headers;

		private ScriptedResponseInfo(int status, @Nullable HttpHeaders headers) {
			this.status = status;
			this.headers = headers;
		}

		@Override
		public int statusCode() {
			return this.status;
		}

		@Override
		@SuppressWarnings("NullAway")
		public HttpHeaders headers() {
			return this.headers;
		}

		@Override
		public HttpClient.Version version() {
			return HttpClient.Version.HTTP_1_1;
		}
	}
}
