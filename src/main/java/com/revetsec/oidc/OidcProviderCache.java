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

package com.revetsec.oidc;

import com.revetsec.oauth.*;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import java.util.function.Function;
import java.util.function.LongSupplier;

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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/** Lazy discovery with one in-flight OIDC document fetch, a failure backoff and a two-flight cooldown ceiling. */
@ThreadSafe
final class OidcProviderCache<T> {
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
	private final Function<OidcProviderMetadata, T> validate;
	private final LongSupplier nanoTime;
	private @Nullable MetadataSnapshot<T> snapshot;
	private @Nullable Instant lastClock;
	private int waiters;
	private final java.util.concurrent.locks.Condition waiterChanged = this.lock.newCondition();
	private @Nullable Flight<T> flight;
	private @Nullable OAuthException lastFailure;
	private long lastFailureNanos;
	private long failureBackoffNanos;
	private int consecutiveFailures;

	OidcProviderCache(URI issuer, HttpExchange exchange, OutboundUriPolicy outboundPolicy,
			boolean allowLoopback, Duration requestTimeout, Clock clock, OAuthObserver observer,
			Duration minimumTtl, Duration defaultTtl, Duration maximumTtl, Duration cooldown,
			Function<OidcProviderMetadata, T> validate, LongSupplier nanoTime) {
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
		this.cooldown = cooldown; this.validate = validate; this.nanoTime = nanoTime;
	}

	T get(Deadline deadline) {
		Flight<T> mine = null;
		Flight<T> waitFor = null;
		long nowNanos = this.nanoTime.getAsLong();
		this.lock.lock();
		try {
			Instant now = this.clock.instant();
			boolean rollback = this.lastClock != null && now.isBefore(this.lastClock);
			this.lastClock = now;
			if (this.snapshot != null) {
				if (!rollback && !now.isBefore(this.snapshot.fetchedAt) && now.isBefore(this.snapshot.expiresAt)) return this.snapshot.metadata;
				// Once expired or invalidated by rollback, the old snapshot must never become fresh again.
				this.snapshot = null;
			}
			if (this.flight != null && nowNanos - this.flight.startedNanos > this.flight.overdueAfterNanos) {
				this.flight.future.completeExceptionally(failure(
						OAuthException.Reason.NETWORK_FAILURE));
				this.flight = null;
			}
			if (this.flight != null) {
				waitFor = this.flight;
				this.waiters++; this.waiterChanged.signalAll();
			} else {
				if (this.lastFailure != null && nowNanos - this.lastFailureNanos < this.failureBackoffNanos)
					throw this.lastFailure;
				while (!this.attemptTimes.isEmpty()
						&& nowNanos - this.attemptTimes.peekFirst() >= this.cooldown.toNanos())
					this.attemptTimes.removeFirst();
				if (this.attemptTimes.size() >= 2)
					throw failure(OAuthException.Reason.ATTEMPT_LIMIT);
				this.attemptTimes.addLast(nowNanos);
				long leaderBudget = Math.min(Math.max(0, deadline.remainingNanos()), this.requestTimeout.toNanos());
				mine = new Flight<>(nowNanos, leaderBudget + this.requestTimeout.toNanos());
				this.flight = mine;
			}
		} finally {
			this.lock.unlock();
		}
		if (waitFor != null) {
			try { return await(waitFor.future, deadline); }
			finally {
				this.lock.lock();
				try { this.waiters--; this.waiterChanged.signalAll(); } finally { this.lock.unlock(); }
			}
		}
		Flight<T> leader = requireNonNull(mine);
		try {
			MetadataSnapshot<T> found = fetch(deadline);
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
				throw failure(OAuthException.Reason.NETWORK_FAILURE);
			leader.future.complete(found.metadata);
			return found.metadata;
		} catch (OAuthException failure) {
			this.lock.lock();
			try {
				if (this.flight == leader) {
					this.lastFailure = failure;
					this.lastFailureNanos = this.nanoTime.getAsLong();
					this.consecutiveFailures = Math.min(5, this.consecutiveFailures + 1);
					this.failureBackoffNanos = Math.min(this.cooldown.toNanos() << (this.consecutiveFailures - 1),
							Math.min(this.cooldown.toNanos() * 10, Duration.ofMinutes(10).toNanos()));
					if (failure instanceof OAuthErrorResponseException error) {
						Duration delay = error.getRetryAfter().orElse(Duration.ZERO);
						long retryNanos = delay.compareTo(Duration.ofMinutes(10)) >= 0 ? Duration.ofMinutes(10).toNanos() : delay.toNanos();
						this.failureBackoffNanos = Math.max(this.failureBackoffNanos, retryNanos);
					}
					this.flight = null;
				}
			} finally {
				this.lock.unlock();
			}
			leader.future.completeExceptionally(failure);
			throw failure;
		} catch (RuntimeException failure) {
			OAuthException safe = failure(OAuthException.Reason.NETWORK_FAILURE);
			this.lock.lock();
			try {
				if (this.flight == leader) {
					this.flight = null;
					this.lastFailure = safe;
					this.lastFailureNanos = this.nanoTime.getAsLong();
					this.failureBackoffNanos = this.cooldown.toNanos();
				}
			} finally {
				this.lock.unlock();
			}
			leader.future.completeExceptionally(safe);
			throw safe;
		}
	}

	boolean awaitWaitersForTests(int expected, Duration timeout) throws InterruptedException {
		long remaining = timeout.toNanos(); this.lock.lock();
		try {
			while (this.waiters < expected && remaining > 0) remaining = this.waiterChanged.awaitNanos(remaining);
			return this.waiters >= expected;
		} finally { this.lock.unlock(); }
	}
	private static <T> T await(CompletableFuture<T> future,
			Deadline deadline) {
		try {
			long remaining = deadline.remainingNanos();
			if (remaining <= 0)
				throw failure(OAuthException.Reason.NETWORK_FAILURE);
			return future.get(remaining, TimeUnit.NANOSECONDS);
		} catch (InterruptedException interrupted) {
			Thread.currentThread().interrupt();
			throw failure(OAuthException.Reason.INTERRUPTED);
		} catch (TimeoutException timeout) {
			throw failure(OAuthException.Reason.NETWORK_FAILURE);
		} catch (ExecutionException failure) {
			if (failure.getCause() instanceof OAuthException oauth) throw oauth;
			throw failure(OAuthException.Reason.NETWORK_FAILURE);
		}
	}

	private MetadataSnapshot<T> fetch(Deadline deadline) {
		URI candidate = discoveryUri(this.issuer);
		if (!UriChecks.isPermitted(candidate, this.outboundPolicy, this.allowLoopback))
			throw failure(OAuthException.Reason.METADATA_INVALID);
		URI safe = reduced(candidate);
		ObserverDispatch.dispatch(this.observer, observer -> observer.willRequestEndpoint(OAuthEndpoint.METADATA, safe));
		long started = this.nanoTime.getAsLong();
		RawResponse response;
		try {
			response = this.exchange.execute(new HttpExchangeRequest(candidate, ResponseProfile.METADATA,
					null, Map.of(), 256 * 1_024, 16 * 1_024, this.requestTimeout), deadline);
		} catch (HttpExchangeException cause) {
			OAuthException mapped = OidcTransactionAccess.get().endpointExchangeFailure(cause);
			Duration elapsed = Duration.ofNanos(this.nanoTime.getAsLong() - started);
			ObserverDispatch.dispatch(this.observer, observer -> observer.didFailEndpoint(OAuthEndpoint.METADATA, safe, mapped, elapsed));
			throw mapped;
		}
		Duration elapsed = Duration.ofNanos(this.nanoTime.getAsLong() - started);
		ObserverDispatch.dispatch(this.observer, observer -> observer.didRequestEndpoint(OAuthEndpoint.METADATA, safe, response.status(), elapsed));
		byte[] bytes = response.body();
		try {
			if (response.status() != 200)
				throw OidcTransactionAccess.get().endpointStatusFailure(response.status(), RetryAfter.parse(response.headers(), this.clock.instant()).orElse(null));
			OidcProviderMetadata metadata = OidcProviderMetadata.fromJson(this.issuer.toString(), StrictUtf8.decode(bytes));
			T checked = this.validate.apply(metadata);
			Instant now = this.clock.instant();
			Duration lifetime = CacheLifetime.timeToLive(response.headers(), now, this.minimumTtl, this.defaultTtl, this.maximumTtl);
			return new MetadataSnapshot<>(checked, now, now.plus(lifetime));
		} catch (EncodingException invalid) {
			throw failure(OAuthException.Reason.DOCUMENT_MALFORMED);
		} finally { java.util.Arrays.fill(bytes, (byte) 0); }
	}
	static URI discoveryUri(URI issuer) {
		String value = issuer.toString();
		return URI.create((value.endsWith("/") ? value.substring(0, value.length() - 1) : value) + "/.well-known/openid-configuration");
	}
	private static OAuthException failure(OAuthException.Reason reason) { return OidcTransactionAccess.get().endpointFailure(reason); }

	static URI reduced(URI uri) {
		String authority = uri.getRawAuthority();
		if (authority == null)
			throw new IllegalArgumentException("An endpoint URI needs an authority.");
		int userInfoEnd = authority.lastIndexOf('@');
		if (userInfoEnd >= 0)
			authority = authority.substring(userInfoEnd + 1);
		return URI.create(uri.getScheme() + "://" + authority
				+ (uri.getRawPath() == null ? "" : uri.getRawPath()));
	}

	private record MetadataSnapshot<T>(T metadata, Instant fetchedAt, Instant expiresAt) { }
	private static final class Flight<T> {
		private final CompletableFuture<T> future = new CompletableFuture<>();
		private final long startedNanos;
		private final long overdueAfterNanos;
		private Flight(long startedNanos, long overdueAfterNanos) {
			this.startedNanos = startedNanos;
			this.overdueAfterNanos = overdueAfterNanos;
		}
	}
}
