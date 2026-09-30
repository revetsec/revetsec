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

package com.revetsec.jose;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.Limits;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HttpClientChecks;
import com.revetsec.internal.http.HttpExchange;
import com.revetsec.internal.http.RuntimeFloor;
import com.revetsec.internal.http.UriChecks;
import com.revetsec.internal.jose.KeyQuery;
import com.revetsec.internal.jose.KeySelection;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;

import static java.util.Objects.requireNonNull;

/**
 * A JSON Web Key Set fetched from a URI and cached, such as an OpenID provider's {@code jwks_uri}.
 * <p>
 * <strong>Lazy, on the caller's thread.</strong> {@link Builder#build()} does no I/O, creates no HTTP client and starts
 * no thread. The first call that needs a key, or {@link #warmUp()}, fetches the key set on the calling thread, and
 * concurrent callers wait for that one fetch, each within its own deadline: a validation's is this source's request
 * timeout. Revetsec starts no thread of its own; the JDK's HTTP client runs its own, as it always does.
 * <p>
 * <strong>Caching.</strong> A fetched key set stays fresh for a time to live taken from the response's
 * {@code Cache-Control} ({@code max-age}; {@code no-store} and {@code no-cache} mean the minimum) or {@code Expires},
 * clamped to the minimum and maximum time to live, or for the default time to live when the response has neither.
 * There are no conditional requests. After it expires, the next call that needs a key fetches it again. A key set in
 * which every key was skipped is still a key set, so an identity provider can withdraw all its keys; each skipped key
 * is reported to {@link JoseObserver#didSkipJsonWebKey(URI, Integer, JsonWebKeySkipReason)} on every fetch.
 * <p>
 * <strong>Unknown keys.</strong> A token whose key is not in a fresh key set (an unknown {@code kid}, or no key that
 * fits a token without one) refreshes the key set early, at most once per unknown-key refresh cooldown. The cooldown
 * holds back only these refreshes: the first fetch, {@link #warmUp()} and refreshes after expiry neither wait for it
 * nor start it, so a key an identity provider starts using just after a scheduled fetch is fetched at once. A request
 * sent for an unknown key keeps its cooldown whatever its outcome. A key named by the token's {@code kid} that does not
 * fit the token's algorithm, or two keys that fit, never cause a refresh.
 * <p>
 * <strong>Failures.</strong> A failed fetch, a timeout included, starts a backoff that every fetch respects,
 * {@link #warmUp()} included: the unknown-key cooldown, doubled after each further failure up to ten cooldowns (at
 * most 10 minutes), which is 30, 60, 120, 240 and then 300 seconds at the default cooldown. A {@code Retry-After} on a
 * 429 or 503 may lengthen a step, up to that cap. A successful fetch does not reset the backoff: the failure count
 * falls by one for each full cap interval without a failure. During a backoff no request is sent, and each call that
 * would have fetched is reported to {@link JoseObserver#didSuppressJsonWebKeySetFetch(URI, Duration)}. At the
 * defaults, one endpoint that keeps failing gets at most 15 requests in its first hour, and 12 an hour after that.
 * <p>
 * <strong>Request limit.</strong> No more than two requests of any kind start within one cooldown.
 * {@link Builder#build()} refuses a cooldown longer than the minimum time to live, so each successful fetch leaves a
 * key set fresh for at least one cooldown, and each failed one starts a backoff of at least one cooldown. The
 * unknown-key cooldown, the backoff and the time to live therefore keep requests within this limit on their own, and
 * it holds back no call, a refresh after expiry included, unless fetches were cut short: by an interrupt, by an
 * {@link Error}, or by a leader held past the longest a fetch may take, as a slow observer can hold it. A call the
 * limit holds back sends nothing and is reported to
 * {@link JoseObserver#didSuppressJsonWebKeySetFetch(URI, Duration)}: an expired key set answers it for the keys it
 * holds, a call for an unknown key gets no key, and any other call throws a transient
 * {@link JsonWebKeySetUnavailableException} of category {@link com.revetsec.ErrorCategory#TRANSPORT} with no cause.
 * <p>
 * <strong>Stale keys.</strong> While refreshes fail or are held back, an expired key set still answers, for the keys
 * it holds, until the maximum staleness after its expiry; other calls throw {@link JsonWebKeySetUnavailableException}.
 * <p>
 * <strong>Time.</strong> The time to live, cooldown, backoff and staleness follow the configured {@link Clock}. An
 * instant recorded in the future of the clock's current time counts as passed, so a clock set back makes the key set
 * expired and never extends anything. Deadlines and elapsed times use {@link System#nanoTime()}.
 * <p>
 * <strong>Bound to one URI, not to an issuer.</strong> Share an instance only among validators that expect the same
 * issuer, because every key in it is trusted for any token they check. Sources compare by reference.
 * {@link #toString()} shows the URI cut to its scheme, host, port and path, and the settings.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class RemoteJsonWebKeySource implements JsonWebKeySource {
	@NonNull
	private final URI uri;
	@NonNull
	private final HttpExchange httpExchange;
	@NonNull
	private final JwksSettings settings;
	@NonNull
	private final JwksCache cache;

	/**
	 * Creates a source from settings and a URI that were already checked: the form {@link Builder#build()} uses, and
	 * a later milestone's component that embeds a key source. It does no I/O and does not check the URI again; a URI
	 * the exchange refuses fails each fetch with {@link com.revetsec.ErrorCategory#CONFIGURATION}.
	 *
	 * @param uri          the key set's URI
	 * @param httpExchange the component's exchange helper
	 * @param settings     the checked settings
	 */
	RemoteJsonWebKeySource(@NonNull URI uri,
												 @NonNull HttpExchange httpExchange,
												 @NonNull JwksSettings settings) {
		this.uri = requireNonNull(uri);
		this.httpExchange = requireNonNull(httpExchange);
		this.settings = requireNonNull(settings);
		this.cache = new JwksCache(uri, httpExchange, settings);
	}

	/**
	 * Starts building a source for the key set at {@code uri}.
	 *
	 * @param uri the key set's URI: absolute, {@code https} (or {@code http} to a loopback host where allowed), with no
	 *            user information and no fragment, and permitted by the outbound URI policy; a query is allowed.
	 *            {@link Builder#build()} checks it
	 * @return a new builder
	 * @throws NullPointerException if {@code uri} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public static Builder withUri(@NonNull URI uri) {
		return new Builder(uri);
	}

	void warmUp(java.util.function.LongSupplier remainingNanos) {
		this.cache.warmUp(Deadline.fromNow(Duration.ofNanos(Math.max(0, remainingNanos.getAsLong()))));
	}

	/**
	 * Fetches the key set now, unless a fresh one is cached (even one with no usable key), so the first validation
	 * does not wait for it. It waits for a fetch another caller already started instead of starting its own. It
	 * follows the backoff after a failure, throwing that failure without sending a request, and the limit of two
	 * requests per cooldown, but not the unknown-key cooldown, which it neither waits for nor starts. It waits at most
	 * the request timeout.
	 *
	 * @throws JsonWebKeySetUnavailableException if the fetch failed, a recent failure or the request limit held it
	 *                                           back, or the wait ended, even when an expired key set is still cached
	 * @since 1.0.0
	 */
	public void warmUp() {
		this.cache.warmUp(Deadline.fromNow(this.settings.requestTimeout()));
	}

	/**
	 * Returns the key set's URI.
	 *
	 * @return the URI, as configured
	 * @since 1.0.0
	 */
	@NonNull
	public URI getUri() {
		return this.uri;
	}

	/**
	 * Selects the key for {@code query} within this source's request timeout: the standalone form a validator uses.
	 *
	 * @param query the token's algorithm, key ID and effective algorithm set
	 * @return the selection, after at most one completed fetch
	 * @throws JsonWebKeySetUnavailableException if no usable key set is available for this call
	 */
	@NonNull
	KeySelection select(@NonNull KeyQuery query) {
		return select(query, Deadline.fromNow(this.settings.requestTimeout()));
	}

	/**
	 * Selects the key for {@code query} within {@code deadline}: the form a caller with its own budget uses. A fetch
	 * this call leads that its deadline ends counts as a failed fetch, like any other timeout.
	 *
	 * @param query    the token's algorithm, key ID and effective algorithm set
	 * @param deadline the caller's deadline, which bounds any fetch or wait
	 * @return the selection, after at most one completed fetch
	 * @throws JsonWebKeySetUnavailableException if no usable key set is available for this call
	 */
	@NonNull
	KeySelection select(@NonNull KeyQuery query,
											@NonNull Deadline deadline) {
		return this.cache.select(query, deadline);
	}

	/**
	 * Test seam (plan A-2): this source's key-set cache, whose
	 * {@link JwksCache#awaitWaitersForTests(Integer, Duration)} waits until callers have joined a fetch another caller
	 * leads.
	 *
	 * @return this source's key-set cache
	 */
	@NonNull
	JwksCache cacheForTests() {
		return this.cache;
	}

	/**
	 * The exchange helper, for the zero-thread and single-client checks.
	 */
	@NonNull
	HttpExchange httpExchangeForTests() {
		return this.httpExchange;
	}

	/**
	 * Describes the source by its URI, cut to its scheme, host, port and path, and its settings.
	 *
	 * @return the description
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{uri=" + this.cache.getReportedUri() + ", " + this.settings + "}";
	}

	/**
	 * Builds a {@link RemoteJsonWebKeySource}.
	 * <p>
	 * Each setter stores its value, and {@link #build()} checks them all, in this order: each setting against its
	 * range, then the time-to-live order, then the unknown-key refresh cooldown against the minimum time to live; the
	 * minimum Java runtime; an injected client's redirect policy; then the URI.
	 * {@code null} restores a setting's default. Nothing here does I/O.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		@NonNull
		private final URI uri;
		@Nullable
		private HttpClient httpClient;
		@Nullable
		private OutboundUriPolicy outboundUriPolicy;
		@Nullable
		private Boolean allowInsecureLoopback;
		@Nullable
		private Clock clock;
		@Nullable
		private Duration requestTimeout;
		@Nullable
		private Duration minimumTimeToLive;
		@Nullable
		private Duration defaultTimeToLive;
		@Nullable
		private Duration maximumTimeToLive;
		@Nullable
		private Duration unknownKeyRefreshCooldown;
		@Nullable
		private Duration maximumStaleness;
		@Nullable
		private Integer maximumResponseBytes;
		@Nullable
		private Integer maximumKeys;
		@Nullable
		private JoseObserver observer;
		@Nullable
		private Boolean acknowledgeUnpatchedRuntime;

		private Builder(@NonNull URI uri) {
			this.uri = requireNonNull(uri);
		}

		/**
		 * Sets the HTTP client to fetch with.
		 *
		 * @param httpClient a client that never follows redirects; {@code null} restores the default, a process-wide
		 *                   client Revetsec creates on the first fetch
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder httpClient(@Nullable HttpClient httpClient) {
			this.httpClient = httpClient;
			return this;
		}

		/**
		 * Sets the policy the URI must pass.
		 *
		 * @param outboundUriPolicy the policy; {@code null} restores the default,
		 *                          {@link OutboundUriPolicy#defaultInstance()}
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder outboundUriPolicy(@Nullable OutboundUriPolicy outboundUriPolicy) {
			this.outboundUriPolicy = outboundUriPolicy;
			return this;
		}

		/**
		 * Sets whether plain {@code http} is allowed to a loopback address or to exactly {@code localhost}, for tests.
		 * A request to {@code localhost} reaches loopback only as the host's name resolution decides, which usually
		 * means its hosts file.
		 *
		 * @param allowInsecureLoopback whether to allow it; {@code null} restores the default, {@code false}
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder allowInsecureLoopback(@Nullable Boolean allowInsecureLoopback) {
			this.allowInsecureLoopback = allowInsecureLoopback;
			return this;
		}

		/**
		 * Sets the clock for the time to live, cooldown, backoff and staleness. Outside tests, keep the default: a
		 * clock that stands still never lets the key set expire.
		 *
		 * @param clock the clock; {@code null} restores the default, {@link Clock#systemUTC()}
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder clock(@Nullable Clock clock) {
			this.clock = clock;
			return this;
		}

		/**
		 * Sets how long one fetch may take, which is also the deadline of a standalone call.
		 *
		 * @param requestTimeout from 1 to 60 seconds; {@code null} restores the default, 10 seconds
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder requestTimeout(@Nullable Duration requestTimeout) {
			this.requestTimeout = requestTimeout;
			return this;
		}

		/**
		 * Sets the shortest time a fetched key set is cached, whatever its cache headers say. It must be at least the
		 * unknown-key refresh cooldown, so that the limit of two requests per cooldown holds back no refresh after
		 * expiry unless fetches were cut short; {@link #build()} checks that.
		 *
		 * @param minimumTimeToLive from 30 seconds to 1 hour, and no shorter than the unknown-key refresh cooldown;
		 *                          {@code null} restores the default, 1 minute
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder minimumTimeToLive(@Nullable Duration minimumTimeToLive) {
			this.minimumTimeToLive = minimumTimeToLive;
			return this;
		}

		/**
		 * Sets the time a fetched key set is cached when its response has neither {@code max-age} nor {@code Expires}.
		 *
		 * @param defaultTimeToLive from 30 seconds to 24 hours; {@code null} restores the default, 10 minutes
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder defaultTimeToLive(@Nullable Duration defaultTimeToLive) {
			this.defaultTimeToLive = defaultTimeToLive;
			return this;
		}

		/**
		 * Sets the longest time a fetched key set is cached, whatever its cache headers say.
		 *
		 * @param maximumTimeToLive from 1 minute to 24 hours; {@code null} restores the default, 6 hours
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder maximumTimeToLive(@Nullable Duration maximumTimeToLive) {
			this.maximumTimeToLive = maximumTimeToLive;
			return this;
		}

		/**
		 * Sets the shortest time between two refreshes that tokens with unknown key IDs trigger. It is also the first
		 * step of the backoff after a failed fetch, and the window of the limit of two requests of any kind. It must be
		 * no longer than the minimum time to live, so that this limit holds back no refresh after expiry unless fetches
		 * were cut short; {@link #build()} checks that.
		 *
		 * @param unknownKeyRefreshCooldown from 1 second to 10 minutes, and no longer than the minimum time to live;
		 *                                  {@code null} restores the default, 30 seconds
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder unknownKeyRefreshCooldown(@Nullable Duration unknownKeyRefreshCooldown) {
			this.unknownKeyRefreshCooldown = unknownKeyRefreshCooldown;
			return this;
		}

		/**
		 * Sets how long after it expires a key set may still answer for the keys it holds, while refreshes fail or are
		 * held back.
		 *
		 * @param maximumStaleness from zero, which never serves an expired key set, to 24 hours; {@code null} restores
		 *                         the default, 12 hours
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder maximumStaleness(@Nullable Duration maximumStaleness) {
			this.maximumStaleness = maximumStaleness;
			return this;
		}

		/**
		 * Sets the largest key set response body accepted, in bytes.
		 *
		 * @param maximumResponseBytes from 16 KiB to 4 MiB; {@code null} restores the default, 256 KiB
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder maximumResponseBytes(@Nullable Integer maximumResponseBytes) {
			this.maximumResponseBytes = maximumResponseBytes;
			return this;
		}

		/**
		 * Sets the most keys a key set may hold, counting every element of its {@code keys} array, usable or not.
		 *
		 * @param maximumKeys from 1 to 1,000; {@code null} restores the default, 100
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder maximumKeys(@Nullable Integer maximumKeys) {
			this.maximumKeys = maximumKeys;
			return this;
		}

		/**
		 * Sets the observer that receives this source's events.
		 *
		 * @param observer the observer; {@code null} restores the default, {@link JoseObserver#disabledInstance()}
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder observer(@Nullable JoseObserver observer) {
			this.observer = observer;
			return this;
		}

		/**
		 * Sets whether to allow a Java runtime below Revetsec's minimum for network I/O (17.0.3, or 18.0.1 on Java 18),
		 * whose TLS and certificate checks are exposed to CVE-2022-21449. The choice is reported to
		 * {@link JoseObserver#didUseUnpatchedRuntime(String)} when the source is built and on every fetch.
		 *
		 * @param acknowledgeUnpatchedRuntime whether to accept the risk; {@code null} restores the default,
		 *                                    {@code false}
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder acknowledgeUnpatchedRuntime(@Nullable Boolean acknowledgeUnpatchedRuntime) {
			this.acknowledgeUnpatchedRuntime = acknowledgeUnpatchedRuntime;
			return this;
		}

		/**
		 * Builds the source, with no I/O.
		 *
		 * @return a new source
		 * @throws IllegalArgumentException if a setting is out of range, the time-to-live settings are not ordered
		 *                                  minimum, default, maximum, the unknown-key refresh cooldown is longer than
		 *                                  the minimum time to live, the injected client follows redirects, or the URI
		 *                                  is not permitted
		 * @throws IllegalStateException    if the Java runtime is below Revetsec's minimum for network I/O and that was
		 *                                  not acknowledged
		 * @since 1.0.0
		 */
		@NonNull
		public RemoteJsonWebKeySource build() {
			return build(Runtime.version());
		}

		/**
		 * {@link #build()} for a given runtime version, so tests can check the runtime floor.
		 */
		@NonNull
		RemoteJsonWebKeySource build(Runtime.@NonNull Version runtimeVersion) {
			requireNonNull(runtimeVersion);

			Duration timeout = Limits.REQUEST_TIMEOUT.require(orDefault(this.requestTimeout,
					Limits.REQUEST_TIMEOUT.getDefaultDuration()));
			Duration minimum = Limits.JWKS_MINIMUM_TIME_TO_LIVE.require(orDefault(this.minimumTimeToLive,
					Limits.JWKS_MINIMUM_TIME_TO_LIVE.getDefaultDuration()));
			Duration standard = Limits.JWKS_DEFAULT_TIME_TO_LIVE.require(orDefault(this.defaultTimeToLive,
					Limits.JWKS_DEFAULT_TIME_TO_LIVE.getDefaultDuration()));
			Duration maximum = Limits.JWKS_MAXIMUM_TIME_TO_LIVE.require(orDefault(this.maximumTimeToLive,
					Limits.JWKS_MAXIMUM_TIME_TO_LIVE.getDefaultDuration()));
			Duration cooldown = Limits.JWKS_UNKNOWN_KEY_ID_COOLDOWN.require(orDefault(this.unknownKeyRefreshCooldown,
					Limits.JWKS_UNKNOWN_KEY_ID_COOLDOWN.getDefaultDuration()));
			Duration staleness = Limits.JWKS_MAXIMUM_STALENESS.require(orDefault(this.maximumStaleness,
					Limits.JWKS_MAXIMUM_STALENESS.getDefaultDuration()));
			int responseBytes = this.maximumResponseBytes == null ? Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue()
					: Limits.JWKS_RESPONSE_BODY_SIZE.require(this.maximumResponseBytes.intValue());
			int keys = this.maximumKeys == null ? Limits.JWKS_KEY_COUNT.getDefaultIntValue()
					: Limits.JWKS_KEY_COUNT.require(this.maximumKeys.intValue());
			Limits.requireJwksTimeToLiveOrder(minimum, standard, maximum);
			Limits.requireJwksCooldownWithinMinimumTimeToLive(cooldown, minimum);

			boolean acknowledged = this.acknowledgeUnpatchedRuntime != null && this.acknowledgeUnpatchedRuntime;
			RuntimeFloor.require(runtimeVersion, acknowledged);

			OutboundUriPolicy policy = this.outboundUriPolicy == null ? OutboundUriPolicy.defaultInstance()
					: this.outboundUriPolicy;
			boolean insecureLoopback = this.allowInsecureLoopback != null && this.allowInsecureLoopback;
			if (this.httpClient != null)
				HttpClientChecks.requireNeverRedirects(this.httpClient);
			UriChecks.requirePermitted(this.uri, policy, insecureLoopback);
			HttpExchange exchange = HttpExchange.fromHttpClient(this.httpClient, policy, insecureLoopback);

			JoseObserver sourceObserver = this.observer == null ? JoseObserver.disabledInstance() : this.observer;
			@Nullable String unpatchedRuntimeVersion = RuntimeFloor.isBelowFloor(runtimeVersion) ? runtimeVersion.toString()
					: null;

			if (unpatchedRuntimeVersion != null)
				ObserverDispatch.dispatch(sourceObserver, observer -> observer.didUseUnpatchedRuntime(unpatchedRuntimeVersion));

			JwksSettings settings = new JwksSettings(this.clock == null ? Clock.systemUTC() : this.clock, timeout, minimum,
					standard, maximum, cooldown, staleness, responseBytes, keys, sourceObserver, unpatchedRuntimeVersion);

			return new RemoteJsonWebKeySource(this.uri, exchange, settings);
		}

		@NonNull
		private static Duration orDefault(@Nullable Duration value,
																			@NonNull Duration defaultValue) {
			return value == null ? defaultValue : value;
		}
	}
}
