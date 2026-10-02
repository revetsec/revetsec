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

import com.revetsec.OutboundUriPolicy;
import com.revetsec.internal.Limits;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * A test-only stand-in for the networked builders M2 to M4 add ({@code RemoteJsonWebKeySet}, {@code OAuthClient},
 * {@code OidcClient}), shaped the way the plan requires them to be (R5, R6, R8, G6-5, section 9.6): {@link #build()}
 * validates the configuration against {@link Limits}, applies the {@link RuntimeFloor}, checks an injected client with
 * {@link HttpClientChecks}, and creates the component's {@link HttpExchange}, all with no I/O, no default client and
 * no thread. The first network use happens in {@link StandInNetworkedComponent#fetchMetadata()}.
 * <p>
 * Exit criterion 14 builds it 1,000 times in a child JVM; M2, M3 and M4 re-point that test at the real builders.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
final class StandInNetworkedBuilder {
	private final URI issuer;
	private @Nullable HttpClient httpClient;
	private @Nullable OutboundUriPolicy outboundUriPolicy;
	private @Nullable Duration requestTimeout;
	private @Nullable Duration totalDeadline;
	private @Nullable Boolean allowInsecureLoopback;
	private @Nullable Boolean acknowledgeUnpatchedRuntime;
	private Runtime.Version runtimeVersion = Runtime.version();

	private StandInNetworkedBuilder(@NonNull URI issuer) {
		this.issuer = requireNonNull(issuer);
	}

	/**
	 * Starts a builder for a component that talks to {@code issuer}.
	 *
	 * @param issuer the issuer, an absolute {@code https} URI
	 * @return a new builder
	 */
	static @NonNull StandInNetworkedBuilder withIssuer(@NonNull URI issuer) {
		return new StandInNetworkedBuilder(issuer);
	}

	@NonNull StandInNetworkedBuilder httpClient(@Nullable HttpClient httpClient) {
		this.httpClient = httpClient;
		return this;
	}

	@NonNull StandInNetworkedBuilder outboundUriPolicy(@Nullable OutboundUriPolicy outboundUriPolicy) {
		this.outboundUriPolicy = outboundUriPolicy;
		return this;
	}

	@NonNull StandInNetworkedBuilder requestTimeout(@Nullable Duration requestTimeout) {
		this.requestTimeout = requestTimeout;
		return this;
	}

	@NonNull StandInNetworkedBuilder totalDeadline(@Nullable Duration totalDeadline) {
		this.totalDeadline = totalDeadline;
		return this;
	}

	@NonNull StandInNetworkedBuilder allowInsecureLoopback(@Nullable Boolean allowInsecureLoopback) {
		this.allowInsecureLoopback = allowInsecureLoopback;
		return this;
	}

	@NonNull StandInNetworkedBuilder acknowledgeUnpatchedRuntime(@Nullable Boolean acknowledgeUnpatchedRuntime) {
		this.acknowledgeUnpatchedRuntime = acknowledgeUnpatchedRuntime;
		return this;
	}

	/**
	 * The internal version seam for the runtime floor (plan M1: "behind an internal version seam so it can be
	 * tested").
	 */
	@NonNull StandInNetworkedBuilder runtimeVersion(Runtime.@NonNull Version runtimeVersion) {
		this.runtimeVersion = requireNonNull(runtimeVersion);
		return this;
	}

	/**
	 * Validates everything and creates the component, with no I/O.
	 *
	 * @return the component
	 * @throws IllegalArgumentException if a setting is outside its limits, the issuer is not permitted, or the
	 *                                  injected client follows redirects
	 * @throws IllegalStateException    if the runtime is below the floor and the risk was not acknowledged
	 */
	@NonNull StandInNetworkedComponent build() {
		Duration requestTimeoutValue = Limits.REQUEST_TIMEOUT.require(this.requestTimeout == null
				? Limits.REQUEST_TIMEOUT.getDefaultDuration() : this.requestTimeout);
		Duration totalDeadlineValue = Limits.TOTAL_DEADLINE.require(this.totalDeadline == null
				? Limits.TOTAL_DEADLINE.getDefaultDuration() : this.totalDeadline);
		Limits.requireRequestTimeoutWithinTotalDeadline(requestTimeoutValue, totalDeadlineValue);

		RuntimeFloor.require(this.runtimeVersion, this.acknowledgeUnpatchedRuntime != null
				&& this.acknowledgeUnpatchedRuntime);

		if (this.httpClient != null)
			HttpClientChecks.requireNeverRedirects(this.httpClient);

		OutboundUriPolicy policy = this.outboundUriPolicy == null ? OutboundUriPolicy.defaultInstance()
				: this.outboundUriPolicy;

		if (!policy.permits(this.issuer))
			throw new IllegalArgumentException("The issuer is not permitted by the outbound URI policy.");

		boolean insecureLoopbackAllowed = this.allowInsecureLoopback != null && this.allowInsecureLoopback;
		HttpExchange exchange = HttpExchange.fromHttpClient(this.httpClient, policy, insecureLoopbackAllowed);
		return new StandInNetworkedComponent(this.issuer, exchange, requestTimeoutValue, totalDeadlineValue);
	}

	/**
	 * What {@link #build()} returns: a component whose first network use creates the default client if none was
	 * injected.
	 */
	@ThreadSafe
	static final class StandInNetworkedComponent {
		private final URI issuer;
		private final HttpExchange exchange;
		private final Duration requestTimeout;
		private final Duration totalDeadline;

		private StandInNetworkedComponent(@NonNull URI issuer, @NonNull HttpExchange exchange, @NonNull Duration requestTimeout,
				@NonNull Duration totalDeadline) {
			this.issuer = issuer;
			this.exchange = exchange;
			this.requestTimeout = requestTimeout;
			this.totalDeadline = totalDeadline;
		}

		/**
		 * One public call: fetches the issuer's metadata under a fresh total deadline.
		 *
		 * @return the response
		 * @throws HttpExchangeException if the exchange failed
		 */
		@NonNull RawResponse fetchMetadata() throws HttpExchangeException {
			return fetchMetadata(Deadline.fromNow(this.totalDeadline));
		}

		/**
		 * {@link #fetchMetadata()} under a given deadline, so a test can start the call with no time left.
		 *
		 * @param deadline the call's deadline
		 * @return the response
		 * @throws HttpExchangeException if the exchange failed
		 */
		@NonNull RawResponse fetchMetadata(@NonNull Deadline deadline) throws HttpExchangeException {
			HttpExchangeRequest request = new HttpExchangeRequest(this.issuer, ResponseProfile.METADATA, null, Map.of(),
					Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue(), Limits.HTTP_ERROR_BODY_SIZE.getDefaultIntValue(),
					this.requestTimeout);
			return this.exchange.execute(request, deadline);
		}

		/**
		 * The client this component uses (exit criterion 14's test hook, through {@link HttpExchange}).
		 *
		 * @return the client
		 * @throws HttpExchangeException if the default client is unavailable
		 */
		@NonNull HttpClient httpClientForTests() throws HttpExchangeException {
			return this.exchange.resolveHttpClient();
		}
	}
}
