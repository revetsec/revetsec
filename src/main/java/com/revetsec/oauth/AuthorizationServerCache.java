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

package com.revetsec.oauth;

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.http.CacheLifetime;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HttpExchange;
import com.revetsec.internal.http.HttpExchangeException;
import com.revetsec.internal.http.HttpExchangeRequest;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.internal.http.ResponseProfile;
import com.revetsec.internal.http.RetryAfter;
import com.revetsec.internal.http.UriChecks;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/** Lazy discovery with one in-flight candidate sequence, a failure backoff and a two-flight cooldown ceiling. */
@ThreadSafe
final class AuthorizationServerCache {
	private final ReentrantLock lock = new ReentrantLock();
	private final ArrayDeque<Long> attemptTimes = new ArrayDeque<>();
	private final URI issuer;
	private final HttpExchange exchange;
	private final OutboundUriPolicy outboundPolicy;
	private final boolean allowLoopback;
	private final Duration requestTimeout;
	private final Clock clock;
	private final OAuthObserver observer;
	private final Duration minimumTtl;
	private final Duration defaultTtl;
	private final Duration maximumTtl;
	private final Duration cooldown;
	private @Nullable MetadataSnapshot snapshot;
	private @Nullable Flight flight;
	private @Nullable OAuthException lastFailure;
	private long lastFailureNanos;
	private long failureBackoffNanos;
	private int consecutiveFailures;

	AuthorizationServerCache(@NonNull URI issuer, @NonNull HttpExchange exchange, @NonNull OutboundUriPolicy outboundPolicy,
			boolean allowLoopback, @NonNull Duration requestTimeout, @NonNull Clock clock, @NonNull OAuthObserver observer,
			@NonNull Duration minimumTtl, @NonNull Duration defaultTtl, @NonNull Duration maximumTtl, @NonNull Duration cooldown) {
		this.issuer = issuer;
		this.exchange = exchange;
		this.outboundPolicy = outboundPolicy;
		this.allowLoopback = allowLoopback;
		this.requestTimeout = requestTimeout;
		this.clock = clock;
		this.observer = observer;
		this.minimumTtl = minimumTtl;
		this.defaultTtl = defaultTtl;
		this.maximumTtl = maximumTtl;
		this.cooldown = cooldown;
	}

	@NonNull AuthorizationServerMetadata get(@NonNull Deadline deadline) {
		Flight mine = null;
		Flight waitFor = null;
		long nowNanos = System.nanoTime();
		this.lock.lock();
		try {
			if (this.snapshot != null && this.clock.instant().isBefore(this.snapshot.expiresAt))
				return this.snapshot.metadata;
			if (this.flight != null && nowNanos - this.flight.startedNanos > this.flight.overdueAfterNanos) {
				this.flight.future.completeExceptionally(OAuthTransportException.fromReason(
						OAuthException.Reason.NETWORK_FAILURE, null));
				this.flight = null;
			}
			if (this.flight != null) {
				waitFor = this.flight;
			} else {
				if (this.lastFailure != null && nowNanos - this.lastFailureNanos < this.failureBackoffNanos)
					throw this.lastFailure;
				while (!this.attemptTimes.isEmpty()
						&& nowNanos - this.attemptTimes.peekFirst() >= this.cooldown.toNanos())
					this.attemptTimes.removeFirst();
				if (this.attemptTimes.size() >= 2)
					throw OAuthTransportException.fromReason(OAuthException.Reason.ATTEMPT_LIMIT, null);
				this.attemptTimes.addLast(nowNanos);
				long leaderBudget = Math.min(Math.max(0, deadline.remainingNanos()), this.requestTimeout.toNanos());
				mine = new Flight(nowNanos, leaderBudget + this.requestTimeout.toNanos());
				this.flight = mine;
			}
		} finally {
			this.lock.unlock();
		}
		if (waitFor != null)
			return await(waitFor.future, deadline);
		Flight leader = requireNonNull(mine);
		try {
			MetadataSnapshot found = fetch(deadline);
			boolean current;
			this.lock.lock();
			try {
				current = this.flight == leader;
				if (current) {
					this.snapshot = found;
					this.lastFailure = null;
					this.consecutiveFailures = 0;
					this.flight = null;
				}
			} finally {
				this.lock.unlock();
			}
			if (!current)
				throw OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
			leader.future.complete(found.metadata);
			return found.metadata;
		} catch (OAuthException failure) {
			this.lock.lock();
			try {
				if (this.flight == leader) {
					this.lastFailure = failure;
					this.lastFailureNanos = System.nanoTime();
					this.consecutiveFailures = Math.min(5, this.consecutiveFailures + 1);
					this.failureBackoffNanos = Math.min(this.cooldown.toNanos() << (this.consecutiveFailures - 1),
							Math.min(this.cooldown.toNanos() * 10, Duration.ofMinutes(10).toNanos()));
					this.flight = null;
				}
			} finally {
				this.lock.unlock();
			}
			leader.future.completeExceptionally(failure);
			throw failure;
		} catch (RuntimeException failure) {
			OAuthException safe = OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
			this.lock.lock();
			try {
				if (this.flight == leader) {
					this.flight = null;
					this.lastFailure = safe;
					this.lastFailureNanos = System.nanoTime();
					this.failureBackoffNanos = this.cooldown.toNanos();
				}
			} finally {
				this.lock.unlock();
			}
			leader.future.completeExceptionally(safe);
			throw safe;
		}
	}

	private static @NonNull AuthorizationServerMetadata await(@NonNull CompletableFuture<@NonNull AuthorizationServerMetadata> future,
			@NonNull Deadline deadline) {
		try {
			long remaining = deadline.remainingNanos();
			if (remaining <= 0)
				throw OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
			return future.get(remaining, TimeUnit.NANOSECONDS);
		} catch (InterruptedException interrupted) {
			Thread.currentThread().interrupt();
			throw OAuthTransportException.fromReason(OAuthException.Reason.INTERRUPTED, null);
		} catch (TimeoutException timeout) {
			throw OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
		} catch (ExecutionException failure) {
			if (failure.getCause() instanceof OAuthException oauth) throw oauth;
			throw OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
		}
	}

	private @NonNull MetadataSnapshot fetch(@NonNull Deadline deadline) {
		for (URI candidate : candidates(this.issuer)) {
			try {
				UriChecks.requirePermitted(candidate, this.outboundPolicy, this.allowLoopback);
			} catch (IllegalArgumentException rejection) {
				throw OAuthValidationException.fromReason(OAuthException.Reason.METADATA_INVALID);
			}
			URI safe = reduced(candidate);
			ObserverDispatch.dispatch(this.observer, observer -> observer.willRequestEndpoint(OAuthEndpoint.METADATA, safe));
			long started = System.nanoTime();
			RawResponse response;
			try {
				response = this.exchange.execute(new HttpExchangeRequest(candidate, ResponseProfile.METADATA,
						null, Map.of(), 256 * 1_024, 16 * 1_024, this.requestTimeout), deadline);
			} catch (HttpExchangeException failure) {
				OAuthException mapped = OAuthHttpErrors.fromExchange(failure);
				Duration elapsed = Duration.ofNanos(System.nanoTime() - started);
				ObserverDispatch.dispatch(this.observer, observer -> observer.didFailEndpoint(
						OAuthEndpoint.METADATA, safe, mapped, elapsed));
				throw mapped;
			}
			Duration elapsed = Duration.ofNanos(System.nanoTime() - started);
			ObserverDispatch.dispatch(this.observer, observer -> observer.didRequestEndpoint(
					OAuthEndpoint.METADATA, safe, response.status(), elapsed));
			if (response.status() == 404 || response.status() == 405 || response.status() == 410)
				continue;
			if (response.status() != 200)
				throw OAuthErrorResponseException.fromResponse(response.status(), "",
						RetryAfter.parse(response.headers(), this.clock.instant()));
			byte[] bytes = response.body();
			try {
				AuthorizationServerMetadata metadata = AuthorizationServerMetadata.fromJson(this.issuer.toString(),
						StrictUtf8.decode(bytes));
				for (URI endpoint : allEndpoints(metadata))
					if (!UriChecks.isPermitted(endpoint, this.outboundPolicy, this.allowLoopback))
						throw OAuthValidationException.fromReason(OAuthException.Reason.METADATA_INVALID);
				Instant now = this.clock.instant();
				Duration lifetime = CacheLifetime.timeToLive(response.headers(), now, this.minimumTtl,
						this.defaultTtl, this.maximumTtl);
				return new MetadataSnapshot(metadata, now.plus(lifetime));
			} catch (EncodingException invalid) {
				throw OAuthResponseException.fromReason(OAuthException.Reason.DOCUMENT_MALFORMED);
			} finally {
				java.util.Arrays.fill(bytes, (byte) 0);
			}
		}
		throw OAuthErrorResponseException.fromResponse(404, "", java.util.Optional.empty());
	}

	static @NonNull List<@NonNull URI> candidates(@NonNull URI issuer) {
		String origin = issuer.getScheme() + "://" + issuer.getRawAuthority();
		String path = issuer.getRawPath() == null ? "" : issuer.getRawPath();
		String insertedPath = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
		LinkedHashSet<URI> candidates = new LinkedHashSet<>();
		candidates.add(URI.create(origin + "/.well-known/oauth-authorization-server" + insertedPath));
		candidates.add(URI.create(origin + "/.well-known/openid-configuration" + insertedPath));
		candidates.add(URI.create(issuer.toASCIIString() + (path.endsWith("/") ? "" : "/")
				+ ".well-known/openid-configuration"));
		return List.copyOf(candidates);
	}

	static @NonNull List<@NonNull URI> allEndpoints(@NonNull AuthorizationServerMetadata metadata) {
		List<URI> endpoints = new ArrayList<>();
		endpoints.add(metadata.getAuthorizationEndpoint());
		endpoints.add(metadata.getTokenEndpoint());
		metadata.getRevocationEndpoint().ifPresent(endpoints::add);
		metadata.getJwksUri().ifPresent(endpoints::add);
		metadata.getIntrospectionEndpoint().ifPresent(endpoints::add);
		return endpoints;
	}

	static @NonNull URI reduced(@NonNull URI uri) {
		String authority = uri.getRawAuthority();
		if (authority == null)
			throw new IllegalArgumentException("An endpoint URI needs an authority.");
		int userInfoEnd = authority.lastIndexOf('@');
		if (userInfoEnd >= 0)
			authority = authority.substring(userInfoEnd + 1);
		return URI.create(uri.getScheme() + "://" + authority
				+ (uri.getRawPath() == null ? "" : uri.getRawPath()));
	}

	private record MetadataSnapshot(@NonNull AuthorizationServerMetadata metadata, @NonNull Instant expiresAt) { }
	private static final class Flight {
		private final CompletableFuture<AuthorizationServerMetadata> future = new CompletableFuture<>();
		private final long startedNanos;
		private final long overdueAfterNanos;
		private Flight(long startedNanos, long overdueAfterNanos) {
			this.startedNanos = startedNanos;
			this.overdueAfterNanos = overdueAfterNanos;
		}
	}
}
