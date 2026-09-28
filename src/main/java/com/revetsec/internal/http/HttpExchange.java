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
import com.revetsec.internal.http.HttpExchangeException.Kind;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.net.http.HttpResponse.BodySubscriber;
import java.net.http.HttpResponse.ResponseInfo;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow.Subscription;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * Performs one bounded HTTP exchange on the JDK {@link HttpClient} (plan R12, as amended by G6-5 to G6-7; M1 plan,
 * "HTTP helper").
 * <p>
 * An instance holds a component's transport settings: the injected client, or none for the process-wide default
 * ({@link DefaultHttpClientHolder}, created on first use and never here), the {@link OutboundUriPolicy}, and whether
 * loopback {@code http} is allowed. Creating one does no I/O, loads no client and starts no thread, so builders create
 * it in {@code build()}.
 * <p>
 * <strong>Algorithm</strong> ({@link #execute(HttpExchangeRequest, Deadline)}):
 * <ol>
 *   <li>The URI must pass {@link UriChecks}, the same check a builder runs at {@code build()} (G8-9): absolute and
 *   hierarchical, with a host, a port from 1 to 65535 if one is given, and no user information or fragment; its
 *   scheme {@code https}, or {@code http} when loopback is allowed and the host is a loopback literal the JDK
 *   connects to as loopback ({@code 127.0.0.0/8}, {@code [::1]} or {@code [::ffff:127.x.y.z]}) or exactly
 *   {@code localhost} (G8-7); and the {@link OutboundUriPolicy} must permit it. Otherwise {@link Kind#URI_REJECTED},
 *   before anything is sent. IPv4-compatible ({@code [::127.0.0.1]}) and NAT64 ({@code [64:ff9b::127.0.0.1]}) forms
 *   of a loopback address do not count, because the JDK connects to them as ordinary IPv6 addresses, off the host;
 *   nor do names under {@code .localhost} or {@code localhost.}, which the JDK hands to the platform resolver.</li>
 *   <li>If no time is left on the {@link Deadline}, {@link Kind#TIMEOUT} before a request is built. An interrupted
 *   thread fails with {@link Kind#INTERRUPTED} before a request is sent.</li>
 *   <li>The request gets {@code timeout(min(requestTimeout, remaining))}, {@code Accept} from the profile and
 *   {@code Accept-Encoding: identity}, and is sent with {@code sendAsync}. The {@code sendAsync} future only reports
 *   failures that happen before the response arrives ({@code whenComplete}).</li>
 *   <li>The caller waits, for that same min(requestTimeout, remaining), on an outcome future that this class's body
 *   handler and subscribers complete, never on the {@code sendAsync} future: the JDK completes that one on the common
 *   pool, so a busy pool would turn a finished exchange into a timeout (G6-6). Waiting that long bounds the body on
 *   every JDK, as {@link HttpRequest#timeout()} does itself from JDK 26. The wait ending gives {@link Kind#TIMEOUT};
 *   an interrupt gives {@link Kind#INTERRUPTED}, with the thread's interrupt flag set again; any other failure gives
 *   {@link Kind#TIMEOUT} if an {@link HttpTimeoutException} is in its cause chain (JDK 26 wraps it in an
 *   {@link IOException}) and {@link Kind#IO} otherwise.</li>
 *   <li>On failure only, a body subscriber that is still reading cancels its subscription, which closes the
 *   connection even when the {@code sendAsync} future cannot reach the exchange (an injected client's own future, or
 *   one that failing the body has already completed), and the {@code sendAsync} future is cancelled if it is not done;
 *   its {@code isCancelled()} is never consulted. A {@link RuntimeException} from an injected client's future (its
 *   {@code isDone} or {@code cancel}, as {@link CompletableFuture#minimalCompletionStage()} throws) is contained, so
 *   only {@link HttpExchangeException} leaves {@code execute}.</li>
 * </ol>
 * <strong>Checks on the response</strong>, in the body handler, in this order, before any body byte is read. They
 * apply to every response the JDK hands to the body handler: every status, except a 204 whose first
 * {@code Content-Length} is not zero or that has a {@code Transfer-Encoding} (see "204 responses" below):
 * <ol>
 *   <li>any 3xx: {@link Kind#REDIRECT} (nothing follows it);</li>
 *   <li>framing: more than one {@code Content-Length}, a {@code Content-Length} that is not {@code 1*DIGIT},
 *   {@code Content-Length} together with {@code Transfer-Encoding}, or any {@code Transfer-Encoding} other than one
 *   {@code chunked}; or a status outside 100 to 999: {@link Kind#FRAMING};</li>
 *   <li>a {@code Content-Encoding} with any coding other than {@code identity}: {@link Kind#CONTENT_ENCODING} on a 2xx,
 *   and otherwise the status is kept and the body dropped unread;</li>
 *   <li>a {@code Content-Length} over the limit for the status (the request's body limit on a 2xx, its error-body
 *   limit otherwise): {@link Kind#TOO_LARGE} on a 2xx, and otherwise the status is kept and the body dropped;</li>
 *   <li>on a 2xx under a checked {@link ResponseProfile}, exactly one {@code Content-Type} that the profile accepts:
 *   otherwise {@link Kind#MEDIA_TYPE}.</li>
 * </ol>
 * Every early outcome is delivered through a subscriber that cancels its subscription in {@code onSubscribe}: the
 * cancel is what makes the JDK close the connection instead of reading the rest or reusing it (a failed body future
 * alone does not, as JDK 27's {@code ResponseSubscribers} notes). Its body future fails too, so the response never
 * completes normally. The body handler also cancels the {@code sendAsync} future at once, while it is still pending:
 * the JDK may fail the exchange before it subscribes that subscriber (a {@code Content-Length} it cannot parse, such
 * as {@code 7, 7}, {@code 0x7} or twenty digits), and it then leaves the connection open.
 * <p>
 * That cancel reaches the connection only if the future the client returns passes {@code cancel} through to the
 * JDK's own future. The default client's does, and so does any client that returns the JDK's future. An injected
 * client that returns a future of its own (a decorating client that copies the JDK's result into a new future) does
 * not, and Revetsec has no other handle on the connection: after a rejection or a dropped error body caused by a
 * {@code Content-Length} the JDK cannot parse, that client's connection stays open until the server closes it on JDK
 * 17 to 25, and until {@link HttpRequest#timeout()} ends it on JDK 26; JDK 27 closes it. A body that is abandoned
 * later is not affected, because its subscriber cancels its own subscription.
 * <p>
 * <strong>Responses the JDK refuses itself</strong> fail as {@link Kind#IO}, which is transient, before any check
 * here runs, and Revetsec has no handle on their connection:
 * <ul>
 *   <li>A response head the JDK cannot parse (a header section over {@code jdk.http.maxHeaderSize}, an invalid status
 *   line, a header name that is not a token): the JDK leaves the connection open, on every JDK tested (17 to 27), for
 *   as long as the server keeps it.</li>
 *   <li><strong>204 responses.</strong> The JDK decides a 204's framing before it calls the body handler, so the
 *   early cancel above cannot reach it. A 204 whose first {@code Content-Length} is not zero, or that has any
 *   {@code Transfer-Encoding}, fails, and the JDK closes the connection. If the JDK cannot parse that first
 *   {@code Content-Length} ({@code 0x7}, {@code 7, 7}, twenty digits), JDK 17 to 26 leave the connection open until
 *   the server closes it; JDK 27 closes it. A 204 whose first {@code Content-Length} is zero reaches the body handler
 *   like any other response.</li>
 * </ul>
 * So a caller that retries transient failures against a hostile server can leave one connection open per attempt.
 * <p>
 * The body subscriber that reads requests one item at a time, and at the limit it cancels and completes:
 * {@link Kind#TOO_LARGE} on a 2xx, and a dropped body with the status kept otherwise. It zeroes its old buffer when it
 * grows and on every failure. {@code BodySubscribers.replacing} and {@code discarding} are never used, because they
 * read the whole body. The handler and the subscribers never throw: a callback that throws leaves the connection open
 * and unread.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class HttpExchange {
	private static final String ACCEPT = "Accept";
	private static final String ACCEPT_ENCODING = "Accept-Encoding";
	private static final String CONTENT_TYPE = "Content-Type";
	private static final String CONTENT_LENGTH = "Content-Length";
	private static final String CONTENT_ENCODING = "Content-Encoding";
	private static final String TRANSFER_ENCODING = "Transfer-Encoding";
	private static final String IDENTITY = "identity";
	private static final String CHUNKED = "chunked";
	private static final String FORM_MEDIA_TYPE = "application/x-www-form-urlencoded";

	/**
	 * The first allocation for a body of unknown length; the buffer then doubles, up to the limit.
	 */
	private static final int INITIAL_BUFFER_BYTES = 16 * 1024;

	/**
	 * How many causes the failure walk follows before it gives up (a cycle is stopped earlier).
	 */
	private static final int MAXIMUM_CAUSE_DEPTH = 64;

	@Nullable
	private final HttpClient injectedHttpClient;
	@NonNull
	private final OutboundUriPolicy outboundUriPolicy;
	private final boolean insecureLoopbackAllowed;

	private HttpExchange(@Nullable HttpClient injectedHttpClient,
											 @NonNull OutboundUriPolicy outboundUriPolicy,
											 boolean insecureLoopbackAllowed) {
		this.injectedHttpClient = injectedHttpClient;
		this.outboundUriPolicy = outboundUriPolicy;
		this.insecureLoopbackAllowed = insecureLoopbackAllowed;
	}

	/**
	 * Creates an exchange helper for one component. It does no I/O and never touches the default client.
	 *
	 * @param injectedHttpClient      the application's client, or {@code null} for the process-wide default
	 * @param outboundUriPolicy       the component's outbound URI policy
	 * @param insecureLoopbackAllowed whether {@code http} to a loopback host is allowed (tests only)
	 * @return the helper
	 * @throws NullPointerException     if {@code outboundUriPolicy} or {@code insecureLoopbackAllowed} is {@code null}
	 * @throws IllegalArgumentException if {@code injectedHttpClient} follows redirects (G6-5)
	 */
	@NonNull
	public static HttpExchange fromHttpClient(@Nullable HttpClient injectedHttpClient,
																						@NonNull OutboundUriPolicy outboundUriPolicy,
																						@NonNull Boolean insecureLoopbackAllowed) {
		requireNonNull(outboundUriPolicy);
		requireNonNull(insecureLoopbackAllowed);

		if (injectedHttpClient != null)
			HttpClientChecks.requireNeverRedirects(injectedHttpClient);

		return new HttpExchange(injectedHttpClient, outboundUriPolicy, insecureLoopbackAllowed);
	}

	/**
	 * Performs the exchange (see the class description).
	 *
	 * @param request  the request
	 * @param deadline the public call's total deadline, shared by every exchange in the call
	 * @return the response: a 2xx that met its profile, or a non-3xx, non-2xx status
	 * @throws NullPointerException  if an argument is {@code null}
	 * @throws HttpExchangeException if the exchange failed or the response was rejected; its {@link Kind} says why
	 */
	@NonNull
	public RawResponse execute(@NonNull HttpExchangeRequest request,
														 @NonNull Deadline deadline) throws HttpExchangeException {
		requireNonNull(request);
		requireNonNull(deadline);

		long startNanos = System.nanoTime();

		requirePermittedUri(request.uri());

		if (deadline.remainingNanos() <= 0)
			throw new HttpExchangeException(Kind.TIMEOUT);

		HttpClient httpClient = resolveHttpClient();

		// Resolving the default client the first time can take a moment, so the deadline is read again.
		long exchangeNanos = Math.min(deadline.remainingNanos(), requestTimeoutNanos(request));

		if (exchangeNanos <= 0)
			throw new HttpExchangeException(Kind.TIMEOUT);

		if (Thread.currentThread().isInterrupted())
			throw new HttpExchangeException(Kind.INTERRUPTED);

		HttpRequest httpRequest = buildRequest(request, Duration.ofNanos(exchangeNanos));
		Sink sink = new Sink(request, startNanos);
		@Nullable CompletableFuture<HttpResponse<Void>> sent = null;
		Outcome outcome;

		try {
			sent = httpClient.sendAsync(httpRequest, sink);
			sink.attach(sent);
			// Failures before the response (connect, TLS, header timeout) reach the sink only this way. The callback never
			// throws, so the future whenComplete returns carries nothing worth checking.
			CompletableFuture<HttpResponse<Void>> unused = sent.whenComplete((response, failure) -> {
				if (failure != null)
					sink.fail(failure);
			});
			outcome = sink.await(exchangeNanos);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			outcome = Outcome.fromKind(Kind.INTERRUPTED);
		} catch (TimeoutException e) {
			outcome = Outcome.fromKind(Kind.TIMEOUT);
		} catch (RuntimeException e) {
			// An injected client may throw from sendAsync, or return null.
			outcome = Outcome.fromFailure(e);
		}

		@Nullable RawResponse response = outcome.getResponse();

		if (response != null)
			return response;

		sink.abandon();
		// An injected client's future may throw from isDone or cancel; that is contained, so only HttpExchangeException
		// leaves execute.
		cancelIfPending(sent);

		throw outcome.toException();
	}

	/**
	 * Describes the transport settings: whether a client was injected, the policy and the loopback setting.
	 *
	 * @return the description
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{httpClient=" + (this.injectedHttpClient == null ? "default" : "injected")
				+ ", outboundUriPolicy=" + this.outboundUriPolicy + ", insecureLoopbackAllowed="
				+ this.insecureLoopbackAllowed + "}";
	}

	/**
	 * Test hook, public by necessity (M2 plan, G8-4; exit criterion 17): the client this component uses, as
	 * {@link #execute(HttpExchangeRequest, Deadline)} resolves it. A test in another package calls it to show that two
	 * components share the process-wide default client. The first call on a component without an injected client
	 * creates that default client, as a first request would. Production code never calls it.
	 *
	 * @return the injected client, or the process-wide default
	 * @throws HttpExchangeException with {@link Kind#DEFAULT_CLIENT_UNAVAILABLE} if no client was injected and the
	 *                               default client could not be created in this runtime
	 */
	@NonNull
	public HttpClient resolvedHttpClientForTests() throws HttpExchangeException {
		return resolveHttpClient();
	}

	/**
	 * The client this component uses: the injected one, or the process-wide default, created on the first call.
	 * Package-private so exit criterion 14's test can show that two components share the default;
	 * {@link #resolvedHttpClientForTests()} is the public form for tests in other packages.
	 */
	@NonNull
	HttpClient resolveHttpClient() throws HttpExchangeException {
		if (this.injectedHttpClient != null)
			return this.injectedHttpClient;

		try {
			return DefaultHttpClientHolder.httpClient();
		} catch (LinkageError e) {
			// The holder's initializer ended with a VirtualMachineError on an earlier call; see DefaultHttpClientHolder.
			throw new HttpExchangeException(Kind.DEFAULT_CLIENT_UNAVAILABLE);
		}
	}

	/**
	 * The fetch-time half of the shared URI check (G8-9): a URI that a builder accepted at {@code build()} with the same
	 * policy and loopback setting passes here too.
	 */
	private void requirePermittedUri(@NonNull URI uri) throws HttpExchangeException {
		if (!UriChecks.isPermitted(uri, this.outboundUriPolicy, this.insecureLoopbackAllowed))
			throw new HttpExchangeException(Kind.URI_REJECTED);
	}

	/**
	 * Cancels {@code future} if it is not done, which makes the JDK close the connection when the future is the JDK's
	 * own. A RuntimeException from an injected client's future (its {@code isDone} or {@code cancel}, as
	 * {@link CompletableFuture#minimalCompletionStage()} throws) is contained: the outcome is already decided.
	 */
	private static void cancelIfPending(@Nullable CompletableFuture<?> future) {
		try {
			if (future != null && !future.isDone())
				future.cancel(true);
		} catch (RuntimeException e) {
			// Contained; see above.
			return;
		}
	}

	private static long requestTimeoutNanos(@NonNull HttpExchangeRequest request) {
		try {
			return request.requestTimeout().toNanos();
		} catch (ArithmeticException e) {
			return Long.MAX_VALUE;
		}
	}

	@NonNull
	private static HttpRequest buildRequest(@NonNull HttpExchangeRequest request,
																					@NonNull Duration timeout) throws HttpExchangeException {
		try {
			HttpRequest.Builder builder = HttpRequest.newBuilder(request.uri())
					.timeout(timeout)
					.header(ACCEPT, request.profile().getAcceptHeaderValue())
					.header(ACCEPT_ENCODING, IDENTITY);

			for (Map.Entry<String, String> header : request.headers().entrySet())
				builder.header(header.getKey(), header.getValue());

			@Nullable String formBody = request.formBody();

			if (formBody == null)
				builder.GET();
			else
				builder.header(CONTENT_TYPE, FORM_MEDIA_TYPE)
						.POST(HttpRequest.BodyPublishers.ofByteArray(formBody.getBytes(StandardCharsets.US_ASCII)));

			return builder.build();
		} catch (IllegalArgumentException e) {
			// A backstop: requirePermittedUri admits only URIs the JDK accepts, and HttpExchangeRequest refuses every
			// header name the JDK restricts as of JDK 27. A name a later JDK starts to restrict would land here too.
			throw new HttpExchangeException(Kind.URI_REJECTED);
		}
	}

	/**
	 * The status is 3xx.
	 */
	private static boolean isRedirect(int status) {
		return status >= 300 && status <= 399;
	}

	/**
	 * Whether the framing is ambiguous or malformed (see the class description), for any status.
	 */
	static boolean hasFramingAnomaly(@NonNull HttpHeaders headers) {
		List<String> contentLengths = headers.allValues(CONTENT_LENGTH);
		List<String> transferEncodings = headers.allValues(TRANSFER_ENCODING);

		if (contentLengths.size() > 1 || transferEncodings.size() > 1)
			return true;

		if (!contentLengths.isEmpty() && (!transferEncodings.isEmpty() || !isDigits(contentLengths.get(0))))
			return true;

		return !transferEncodings.isEmpty() && !CHUNKED.equals(MediaType.asciiLowerCase(
				trimOws(transferEncodings.get(0))));
	}

	/**
	 * Whether any {@code Content-Encoding} field lists a coding other than {@code identity}; empty list elements are
	 * ignored (RFC 9110 section 5.6.1).
	 */
	static boolean hasNonIdentityContentEncoding(@NonNull HttpHeaders headers) {
		for (String fieldValue : headers.allValues(CONTENT_ENCODING)) {
			int start = 0;

			while (start <= fieldValue.length()) {
				int comma = fieldValue.indexOf(',', start);
				int end = comma < 0 ? fieldValue.length() : comma;
				String coding = trimOws(fieldValue.substring(start, end));

				if (!coding.isEmpty() && !IDENTITY.equals(MediaType.asciiLowerCase(coding)))
					return true;

				start = end + 1;
			}
		}

		return false;
	}

	/**
	 * The {@code Content-Length}, or -1 if there is none; a value too large for a {@code long} is
	 * {@link Long#MAX_VALUE}. Call only after {@link #hasFramingAnomaly(HttpHeaders)} returned {@code false}.
	 */
	private static long contentLength(@NonNull HttpHeaders headers) {
		List<String> contentLengths = headers.allValues(CONTENT_LENGTH);

		if (contentLengths.isEmpty())
			return -1;

		String digits = contentLengths.get(0);
		int start = 0;

		while (start < digits.length() - 1 && digits.charAt(start) == '0')
			++start;

		// 18 significant digits always fit in a long.
		if (digits.length() - start > 18)
			return Long.MAX_VALUE;

		return Long.parseLong(digits, start, digits.length(), 10);
	}

	/**
	 * The one {@code Content-Type}, parsed, or {@code null} if the field is absent, repeated or malformed.
	 */
	@Nullable
	private static MediaType singleMediaType(@NonNull HttpHeaders headers) {
		List<String> contentTypes = headers.allValues(CONTENT_TYPE);
		return contentTypes.size() == 1 ? MediaType.parse(contentTypes.get(0)).orElse(null) : null;
	}

	private static boolean isDigits(@NonNull String value) {
		if (value.isEmpty())
			return false;

		for (int i = 0; i < value.length(); ++i) {
			char c = value.charAt(i);

			if (c < '0' || c > '9')
				return false;
		}

		return true;
	}

	@NonNull
	private static String trimOws(@NonNull String value) {
		int start = 0;
		int end = value.length();

		while (start < end && MediaType.isOws(value.charAt(start)))
			++start;

		while (end > start && MediaType.isOws(value.charAt(end - 1)))
			--end;

		return value.substring(start, end);
	}

	/**
	 * The kind a transport failure maps to: {@link Kind#TIMEOUT} if an {@link HttpTimeoutException} is anywhere in
	 * its cause chain, {@link Kind#IO} otherwise, keeping the first {@link IOException} in the chain as the cause.
	 */
	@NonNull
	static HttpExchangeException fromTransportFailure(@NonNull Throwable failure) {
		Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
		@Nullable IOException firstIoException = null;
		int depth = 0;

		for (@Nullable Throwable current = failure; current != null && depth < MAXIMUM_CAUSE_DEPTH && seen.add(current);
				 current = current.getCause(), ++depth) {
			if (current instanceof HttpTimeoutException)
				return new HttpExchangeException(Kind.TIMEOUT);

			if (firstIoException == null && current instanceof IOException ioException)
				firstIoException = ioException;
		}

		return new HttpExchangeException(Kind.IO, firstIoException);
	}

	/**
	 * How an exchange ended: a response, a rejection kind, or a transport failure. Exceptions are created on the
	 * calling thread, from this.
	 */
	@Immutable
	private static final class Outcome {
		@Nullable
		private final RawResponse response;
		@Nullable
		private final Kind kind;
		@Nullable
		private final Throwable failure;

		private Outcome(@Nullable RawResponse response,
										@Nullable Kind kind,
										@Nullable Throwable failure) {
			this.response = response;
			this.kind = kind;
			this.failure = failure;
		}

		@NonNull
		static Outcome fromResponse(@NonNull RawResponse response) {
			return new Outcome(requireNonNull(response), null, null);
		}

		@NonNull
		static Outcome fromKind(@NonNull Kind kind) {
			return new Outcome(null, requireNonNull(kind), null);
		}

		@NonNull
		static Outcome fromFailure(@NonNull Throwable failure) {
			return new Outcome(null, null, requireNonNull(failure));
		}

		@Nullable
		RawResponse getResponse() {
			return this.response;
		}

		@NonNull
		HttpExchangeException toException() {
			if (this.kind != null)
				return new HttpExchangeException(this.kind);

			return fromTransportFailure(requireNonNull(this.failure));
		}
	}

	/**
	 * The body handler: it runs the response checks and hands out the subscriber, and it owns the outcome future the
	 * caller waits on. The first completion of that future wins.
	 */
	@ThreadSafe
	private static final class Sink implements BodyHandler<Void> {
		@NonNull
		private final HttpExchangeRequest request;
		private final long startNanos;
		@NonNull
		private final CompletableFuture<Outcome> outcome = new CompletableFuture<>();
		@NonNull
		private final AtomicReference<@Nullable BoundedSubscriber> boundedSubscriber = new AtomicReference<>();
		@NonNull
		private final AtomicReference<@Nullable CompletableFuture<?>> sent = new AtomicReference<>();
		private volatile boolean abandoned;
		private volatile boolean exchangeCancelRequested;

		private Sink(@NonNull HttpExchangeRequest request,
								 long startNanos) {
			this.request = request;
			this.startNanos = startNanos;
		}

		@Override
		@NonNull
		public BodySubscriber<Void> apply(@NonNull ResponseInfo responseInfo) {
			try {
				return subscriberFor(responseInfo.statusCode(), responseInfo.headers());
			} catch (Throwable t) {
				// Never throw from apply: the JDK would leave the connection open and unread.
				fail(t);
				cancelExchangeEarly();
				return new EarlyOutcomeSubscriber();
			}
		}

		@NonNull
		private BodySubscriber<Void> subscriberFor(int status,
																														 @NonNull HttpHeaders headers) {
			if (isRedirect(status))
				return reject(Kind.REDIRECT);

			if (status < 100 || status > 999 || hasFramingAnomaly(headers))
				return reject(Kind.FRAMING);

			boolean successful = RawResponse.isSuccessful(status);
			@Nullable MediaType mediaType = singleMediaType(headers);

			if (hasNonIdentityContentEncoding(headers))
				return successful ? reject(Kind.CONTENT_ENCODING) : dropErrorBody(status, headers, mediaType);

			int limit = successful ? this.request.maximumBodyBytes() : this.request.maximumErrorBodyBytes();
			long contentLength = contentLength(headers);

			if (contentLength > limit)
				return successful ? reject(Kind.TOO_LARGE) : dropErrorBody(status, headers, mediaType);

			if (successful && this.request.profile().isMediaTypeChecked()
					&& (mediaType == null || !this.request.profile().accepts(mediaType)))
				return reject(Kind.MEDIA_TYPE);

			BoundedSubscriber subscriber = new BoundedSubscriber(this, status, headers, mediaType, limit, contentLength);
			this.boundedSubscriber.set(subscriber);

			// The caller may have given up while the checks ran (see abandon()).
			if (this.abandoned)
				subscriber.abandon();

			return subscriber;
		}

		@NonNull
		private BodySubscriber<Void> reject(@NonNull Kind kind) {
			this.outcome.complete(Outcome.fromKind(kind));
			cancelExchangeEarly();
			return new EarlyOutcomeSubscriber();
		}

		@NonNull
		private BodySubscriber<Void> dropErrorBody(int status,
																														@NonNull HttpHeaders headers,
																														@Nullable MediaType mediaType) {
			complete(droppedErrorBody(status, headers, mediaType));
			cancelExchangeEarly();
			return new EarlyOutcomeSubscriber();
		}

		/**
		 * Records the {@code sendAsync} future once the caller has it; if an early outcome already asked for the
		 * exchange to be cancelled, cancels it now. Runs on the calling thread.
		 */
		void attach(@Nullable CompletableFuture<?> sentFuture) {
			if (sentFuture == null)
				return;

			this.sent.set(sentFuture);

			// Either this read sees the request, or cancelExchangeEarly's read of the future sees the write.
			if (this.exchangeCancelRequested)
				cancelExchange();
		}

		/**
		 * An early outcome was decided in {@code apply}: cancel the exchange now, while the {@code sendAsync} future is
		 * still pending. After {@code apply} returns, the JDK may fail the exchange itself before it subscribes the
		 * early subscriber (a {@code Content-Length} it cannot parse, such as {@code 7, 7}, {@code 0x7} or 20 digits),
		 * and then it leaves the connection open; once that failure has completed the future, cancelling it does
		 * nothing, so the caller's own cancel after the wait would race the JDK and sometimes lose.
		 */
		private void cancelExchangeEarly() {
			this.exchangeCancelRequested = true;
			cancelExchange();
		}

		/**
		 * Cancels the {@code sendAsync} future if it is known and not done, which makes the JDK close the connection.
		 * A RuntimeException from an injected client's future is contained: the outcome is already decided, and the
		 * early subscriber still cancels its subscription.
		 */
		private void cancelExchange() {
			cancelIfPending(this.sent.get());
		}

		@NonNull
		RawResponse droppedErrorBody(int status,
																 @NonNull HttpHeaders headers,
																 @Nullable MediaType mediaType) {
			return new RawResponse(status, headers, new byte[0], mediaType, true, elapsed());
		}

		@NonNull
		Duration elapsed() {
			return Duration.ofNanos(Math.max(0L, System.nanoTime() - this.startNanos));
		}

		void complete(@NonNull RawResponse response) {
			this.outcome.complete(Outcome.fromResponse(response));
		}

		void complete(@NonNull Kind kind) {
			this.outcome.complete(Outcome.fromKind(kind));
		}

		void fail(@NonNull Throwable failure) {
			this.outcome.complete(Outcome.fromFailure(failure));
		}

		@NonNull
		Outcome await(long timeoutNanos) throws InterruptedException, TimeoutException {
			try {
				return this.outcome.get(timeoutNanos, TimeUnit.NANOSECONDS);
			} catch (ExecutionException e) {
				// Never happens: the outcome future is only ever completed normally.
				return Outcome.fromFailure(e);
			}
		}

		/**
		 * The caller gave up: the subscriber, if any, stops, zeroes its buffer and cancels its subscription. Runs on the
		 * calling thread.
		 */
		void abandon() {
			// Either this read sees the subscriber, or subscriberFor's read of the flag sees the write: both are volatile.
			this.abandoned = true;

			@Nullable BoundedSubscriber subscriber = this.boundedSubscriber.get();

			if (subscriber != null)
				subscriber.abandon();
		}
	}

	/**
	 * Delivers an outcome decided in {@code apply}: it cancels its subscription at once, so the JDK closes the
	 * connection without reading the body, and its body future has already failed.
	 */
	@ThreadSafe
	private static final class EarlyOutcomeSubscriber implements BodySubscriber<Void> {
		@NonNull
		private final CompletableFuture<Void> body = new CompletableFuture<>();

		private EarlyOutcomeSubscriber() {
			this.body.completeExceptionally(new IOException("The response body was not read."));
		}

		@Override
		public void onSubscribe(@NonNull Subscription subscription) {
			try {
				subscription.cancel();
			} catch (Throwable t) {
				// Never throw from a subscriber callback; the failed body future still fails the exchange.
				return;
			}
		}

		@Override
		public void onNext(@NonNull List<@NonNull ByteBuffer> item) {
			// Nothing is read.
		}

		@Override
		public void onError(@NonNull Throwable throwable) {
			// The outcome was decided before the body.
		}

		@Override
		public void onComplete() {
			// The outcome was decided before the body.
		}

		@Override
		@NonNull
		public CompletionStage<Void> getBody() {
			return this.body.minimalCompletionStage();
		}
	}

	/**
	 * Reads a body up to its limit, one item at a time. The Flow callbacks arrive one at a time; {@link #abandon()}
	 * arrives from the calling thread, so the buffer is guarded by a lock that is never held while calling into the
	 * subscription.
	 */
	@ThreadSafe
	private static final class BoundedSubscriber implements BodySubscriber<Void> {
		private static final byte[] EMPTY = new byte[0];
		private static final String NOT_READ_TO_END = "The response body was not read to its end.";

		@NonNull
		private final Sink sink;
		private final int status;
		@NonNull
		private final HttpHeaders headers;
		@Nullable
		private final MediaType mediaType;
		private final int limit;
		private final long contentLength;
		@NonNull
		private final CompletableFuture<Void> body = new CompletableFuture<>();
		@NonNull
		private final ReentrantLock lock = new ReentrantLock();

		@GuardedBy("lock")
		private byte @NonNull [] buffer = EMPTY;
		@GuardedBy("lock")
		private int size;
		@GuardedBy("lock")
		private boolean done;
		@GuardedBy("lock")
		@Nullable
		private Subscription subscription;

		private BoundedSubscriber(@NonNull Sink sink,
															int status,
															@NonNull HttpHeaders headers,
															@Nullable MediaType mediaType,
															int limit,
															long contentLength) {
			this.sink = sink;
			this.status = status;
			this.headers = headers;
			this.mediaType = mediaType;
			this.limit = limit;
			this.contentLength = contentLength;
		}

		@Override
		public void onSubscribe(@NonNull Subscription subscription) {
			try {
				boolean accepted;

				this.lock.lock();

				try {
					accepted = this.subscription == null && !this.done;

					if (accepted)
						this.subscription = subscription;
				} finally {
					this.lock.unlock();
				}

				if (accepted)
					subscription.request(1);
				else
					subscription.cancel();
			} catch (Throwable t) {
				failInCallback(t, subscription);
			}
		}

		@Override
		public void onNext(@NonNull List<@NonNull ByteBuffer> item) {
			@Nullable Subscription currentSubscription = null;

			try {
				boolean overLimit = false;
				boolean wasDone;

				this.lock.lock();

				try {
					currentSubscription = this.subscription;
					wasDone = this.done;

					if (!wasDone) {
						long incoming = 0;

						for (ByteBuffer byteBuffer : item)
							incoming += byteBuffer.remaining();

						if (this.size + incoming > this.limit) {
							overLimit = true;
							this.done = true;
							zeroBuffer();
						} else {
							ensureCapacity((int) (this.size + incoming));

							for (ByteBuffer byteBuffer : item) {
								int length = byteBuffer.remaining();
								byteBuffer.get(this.buffer, this.size, length);
								this.size += length;
							}
						}
					}
				} finally {
					this.lock.unlock();
				}

				if (overLimit) {
					if (RawResponse.isSuccessful(this.status))
						this.sink.complete(Kind.TOO_LARGE);
					else
						this.sink.complete(this.sink.droppedErrorBody(this.status, this.headers, this.mediaType));

					stop(currentSubscription);
				} else if (wasDone) {
					stop(currentSubscription);
				} else if (currentSubscription != null) {
					currentSubscription.request(1);
				}
			} catch (Throwable t) {
				failInCallback(t, currentSubscription);
			}
		}

		@Override
		public void onError(@NonNull Throwable throwable) {
			try {
				if (markDone())
					this.sink.fail(throwable);
			} finally {
				this.body.completeExceptionally(throwable);
			}
		}

		@Override
		public void onComplete() {
			try {
				byte[] result;

				this.lock.lock();

				try {
					if (this.done) {
						// Stopped earlier (at the limit, on a failure or abandoned): the body never completes normally.
						this.body.completeExceptionally(new IOException(NOT_READ_TO_END));
						return;
					}

					this.done = true;

					if (this.size == this.buffer.length) {
						result = this.buffer;
					} else {
						result = Arrays.copyOf(this.buffer, this.size);
						zeroBuffer();
					}

					// This method zeroes the result once RawResponse has copied it.
					this.buffer = EMPTY;
					this.size = 0;
				} finally {
					this.lock.unlock();
				}

				try {
					this.sink.complete(new RawResponse(this.status, this.headers, result, this.mediaType, false,
							this.sink.elapsed()));
				} finally {
					// RawResponse keeps its own copy.
					Arrays.fill(result, (byte) 0);
				}

				this.body.complete(null);
			} catch (Throwable t) {
				failInCallback(t, null);
			}
		}

		@Override
		@NonNull
		public CompletionStage<Void> getBody() {
			return this.body.minimalCompletionStage();
		}

		/**
		 * The caller gave up: stop, zero, cancel the subscription and fail the body future. The cancel is what closes
		 * the connection; failing the body future alone leaves it open and unread, and the caller's cancel of the
		 * {@code sendAsync} future may not reach the exchange (an injected client's future, or one the failed body has
		 * already completed). {@code Subscription.cancel} is thread-safe (Reactive Streams rule 3.5), and the lock is
		 * not held while calling it. A RuntimeException from the cancel is contained, because this runs on the calling
		 * thread, which must see only the exchange's own outcome.
		 */
		void abandon() {
			@Nullable Subscription currentSubscription;

			this.lock.lock();

			try {
				currentSubscription = this.subscription;

				if (!this.done) {
					this.done = true;
					zeroBuffer();
				}
			} finally {
				this.lock.unlock();
			}

			try {
				if (currentSubscription != null)
					currentSubscription.cancel();
			} catch (RuntimeException e) {
				// The caller already has its outcome; the body future below still fails.
				this.body.completeExceptionally(e);
			} finally {
				this.body.completeExceptionally(new IOException(NOT_READ_TO_END));
			}
		}

		/**
		 * Marks the subscriber done and zeroes its buffer; returns whether it was not done before.
		 */
		private boolean markDone() {
			this.lock.lock();

			try {
				if (this.done)
					return false;

				this.done = true;
				zeroBuffer();
				return true;
			} finally {
				this.lock.unlock();
			}
		}

		/**
		 * Cancels the subscription, so the JDK closes the connection, and fails the body future.
		 */
		private void stop(@Nullable Subscription currentSubscription) {
			try {
				if (currentSubscription != null)
					currentSubscription.cancel();
			} finally {
				this.body.completeExceptionally(new IOException(NOT_READ_TO_END));
			}
		}

		private void failInCallback(@NonNull Throwable failure,
																@Nullable Subscription currentSubscription) {
			try {
				markDone();
				this.sink.fail(failure);
				stop(currentSubscription);
			} catch (Throwable t) {
				// Never throw from a subscriber callback.
				this.body.completeExceptionally(t);
			}
		}

		@GuardedBy("lock")
		private void ensureCapacity(int needed) {
			if (needed <= this.buffer.length)
				return;

			long initial = this.contentLength >= 0 ? this.contentLength : INITIAL_BUFFER_BYTES;
			long doubled = 2L * this.buffer.length;
			int capacity = (int) Math.min(this.limit, Math.max(needed, Math.max(initial, doubled)));
			byte[] grown = Arrays.copyOf(this.buffer, capacity);
			zeroBuffer();
			this.buffer = grown;
		}

		@GuardedBy("lock")
		private void zeroBuffer() {
			Arrays.fill(this.buffer, (byte) 0);
		}
	}
}
