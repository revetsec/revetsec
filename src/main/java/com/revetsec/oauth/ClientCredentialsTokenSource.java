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

import com.revetsec.internal.Limits;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * A bounded caller-thread cache for client-credentials access tokens. One caller renews while waiters share its
 * result. A rejected cached token is cleared only when {@link #invalidate(AccessToken)} receives that exact instance.
 * No expired or rejected token is returned.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class ClientCredentialsTokenSource {
	private final @NonNull OAuthClient client;
	private final @NonNull TokenRequestOptions options;
	private final @NonNull Duration fallbackCacheDuration;
	private final @NonNull Duration maximumCacheDuration;
	private final @NonNull Duration renewBefore;
	private final @NonNull Clock clock;
	private final ReentrantLock lock = new ReentrantLock();
	private @Nullable Cached cached;
	private @Nullable CompletableFuture<@NonNull AccessToken> flight;
	private @Nullable OAuthException lastFailure;
	private long lastFailureNanos;
	private int failureCount;

	private ClientCredentialsTokenSource(@NonNull Builder builder) {
		this.client = builder.client;
		TokenRequestOptions.Builder optionsBuilder = TokenRequestOptions.builder().scopes(builder.scopes);
		if (builder.resourcesOverridden) optionsBuilder.resources(builder.resources);
		this.options = optionsBuilder.build();
		this.fallbackCacheDuration = builder.fallbackCacheDuration;
		this.maximumCacheDuration = builder.maximumCacheDuration;
		this.renewBefore = builder.renewBefore;
		this.clock = builder.client.clock();
	}

	/**
	 * Starts a source using the client's configured token endpoint and deadline.
	 *
	 * @param client a confidential OAuth client
	 * @return the builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder withClient(@NonNull OAuthClient client) {
		return new Builder(requireNonNull(client));
	}

	/**
	 * Gets a valid access token, renewing in the calling thread when needed. An early renewal failure may serve the
	 * still-valid previous token, except after it was invalidated.
	 *
	 * @return a valid token
	 * @since 1.0.0
	 */
	public @NonNull AccessToken getAccessToken() {
		for (;;) {
			AccessToken token = getAccessTokenOnce();
			if (token != null) return token;
		}
	}

	// Only the caller that installed this exact future may publish or clear its flight.
	@SuppressWarnings("ReferenceEquality")
	private @Nullable AccessToken getAccessTokenOnce() {
		CompletableFuture<AccessToken> mine = null;
		CompletableFuture<AccessToken> waitFor = null;
		Cached old;
		this.lock.lock();
		try {
			Instant now = this.clock.instant();
			old = this.cached;
			if (old != null && now.isBefore(old.renewAt) && now.isBefore(old.expiresAt))
				return old.token;
			if (this.flight != null) {
				waitFor = this.flight;
			} else {
				long base = Duration.ofSeconds(30).toNanos();
				long backoff = Math.min(base << Math.min(4, Math.max(0, this.failureCount - 1)),
						Duration.ofMinutes(5).toNanos());
				if (this.lastFailure != null && System.nanoTime() - this.lastFailureNanos < backoff) {
					if (old != null && now.isBefore(old.expiresAt)) return old.token;
					throw this.lastFailure;
				}
				mine = new CompletableFuture<>();
				this.flight = mine;
			}
		} finally {
			this.lock.unlock();
		}
		if (waitFor != null) {
			AccessToken shared = await(waitFor, this.client.totalDeadline());
			this.lock.lock();
			try {
				Cached current = this.cached;
				if (current != null && current.token == shared
						&& this.clock.instant().isBefore(current.expiresAt)) return shared;
			} finally {
				this.lock.unlock();
			}
			return null;
		}
		CompletableFuture<AccessToken> leader = requireNonNull(mine);
		try {
			TokenResponse response = this.client.requestClientCredentialsToken(this.options);
			Instant now = this.clock.instant();
			Instant explicit = response.getExpiresAt().orElse(null);
			Duration lifetime = explicit == null ? this.fallbackCacheDuration
					: Duration.between(now, explicit);
			if (lifetime.isNegative() || lifetime.isZero())
				throw OAuthValidationException.fromReason(OAuthException.Reason.TOKEN_EXPIRED);
			if (lifetime.compareTo(this.maximumCacheDuration) > 0) lifetime = this.maximumCacheDuration;
			Duration lead = Limits.clientCredentialsRenewalLeadTime(this.renewBefore, lifetime);
			AccessToken token = response.getAccessToken();
			Cached fresh = new Cached(token, now.plus(lifetime), now.plus(lifetime).minus(lead));
			this.lock.lock();
			try {
				if (this.flight == leader) {
					this.cached = fresh;
					this.flight = null;
					this.lastFailure = null;
					this.failureCount = 0;
				}
			} finally {
				this.lock.unlock();
			}
			leader.complete(token);
			return token;
		} catch (OAuthException failure) {
			AccessToken fallback = null;
			this.lock.lock();
			try {
				if (this.flight == leader) {
					this.flight = null;
					this.lastFailure = failure;
					this.lastFailureNanos = System.nanoTime();
					this.failureCount = Math.min(5, this.failureCount + 1);
					Cached current = this.cached;
					if (current != null && this.clock.instant().isBefore(current.expiresAt))
						fallback = current.token;
				}
			} finally {
				this.lock.unlock();
			}
			if (fallback != null) {
				leader.complete(fallback);
				return fallback;
			}
			leader.completeExceptionally(failure);
			throw failure;
		} catch (RuntimeException failure) {
			OAuthException safe = OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
			this.lock.lock();
			try {
				if (this.flight == leader) {
					this.flight = null;
					this.lastFailure = safe;
					this.lastFailureNanos = System.nanoTime();
					this.failureCount = Math.min(5, this.failureCount + 1);
				}
			} finally {
				this.lock.unlock();
			}
			leader.completeExceptionally(safe);
			throw safe;
		}
	}

	/**
	 * Clears a rejected cached instance. An old 401 cannot evict a replacement token.
	 *
	 * @param rejectedToken the exact instance rejected by a resource server
	 * @since 1.0.0
	 */
	public void invalidate(@NonNull AccessToken rejectedToken) {
		requireNonNull(rejectedToken);
		this.lock.lock();
		try {
			if (this.cached != null && this.cached.token == rejectedToken) {
				this.cached = null;
				this.lastFailure = null;
				this.failureCount = 0;
			}
	} finally {
			this.lock.unlock();
		}
	}

	private static AccessToken await(CompletableFuture<AccessToken> future, Duration deadline) {
		try {
			return future.get(deadline.toNanos(), TimeUnit.NANOSECONDS);
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

	private record Cached(AccessToken token, Instant expiresAt, Instant renewAt) { }

	/**
	 * Configures a source without network I/O.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	public static final class Builder {
		private final @NonNull OAuthClient client;
		private @Nullable Set<@NonNull String> scopes;
		private @NonNull List<@NonNull URI> resources = List.of();
		private boolean resourcesOverridden;
		private @NonNull Duration fallbackCacheDuration = Limits.CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION.getDefaultDuration();
		private @NonNull Duration maximumCacheDuration = Limits.CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION.getDefaultDuration();
		private @NonNull Duration renewBefore = Limits.CLIENT_CREDENTIALS_RENEW_BEFORE.getDefaultDuration();

		private Builder(@NonNull OAuthClient client) { this.client = client; }

		/**
		 * Replaces the complete scope set; null uses the client's default.
		 *
		 * @param value scopes or null
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder scopes(@Nullable Set<@NonNull String> value) {
			this.scopes = value == null ? null : TokenRequestOptions.builder().scopes(value).build().getScopes().orElseThrow();
			return this;
		}

		/**
		 * Replaces the complete resource list.
		 *
		 * @param value resources
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder resources(@NonNull List<@NonNull URI> value) {
			this.resources = TokenRequestOptions.builder().resources(value).build().getResources();
			this.resourcesOverridden = true;
			return this;
		}

		/**
		 * Sets the fallback cache lifetime when expires_in is absent.
		 *
		 * @param value fallback duration
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder fallbackCacheDuration(@NonNull Duration value) {
			this.fallbackCacheDuration = Limits.CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION.require(value);
			return this;
		}

		/**
		 * Sets the maximum cache lifetime.
		 *
		 * @param value maximum duration
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder maximumCacheDuration(@NonNull Duration value) {
			this.maximumCacheDuration = Limits.CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION.require(value);
			return this;
		}

		/**
		 * Sets the renewal lead time, clipped to half the actual lifetime.
		 *
		 * @param value lead time
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder renewBefore(@NonNull Duration value) {
			this.renewBefore = Limits.CLIENT_CREDENTIALS_RENEW_BEFORE.require(value);
			return this;
		}

		/**
		 * Builds the source without I/O or a worker thread.
		 *
		 * @return the source
		 * @since 1.0.0
		 */
		public @NonNull ClientCredentialsTokenSource build() {
			Limits.requireFallbackWithinMaximumCacheDuration(this.fallbackCacheDuration, this.maximumCacheDuration);
			Limits.requireRenewBeforeBelowMaximumCacheDuration(this.renewBefore, this.maximumCacheDuration);
			return new ClientCredentialsTokenSource(this);
		}
	}
}
