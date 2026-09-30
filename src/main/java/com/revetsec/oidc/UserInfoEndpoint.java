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

import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.http.*;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.oauth.*;
import com.revetsec.jose.*;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

/** One credentialed GET, followed by strict format and subject-bound validation. */
@ThreadSafe
final class UserInfoEndpoint {
	private final HttpExchange exchange;
	private final Duration requestTimeout;
	private final Clock clock;
	private final OidcObserver observer;
	private final UserInfoAttemptGate attempts;
	UserInfoEndpoint(HttpExchange exchange, Duration requestTimeout, Clock clock, OidcObserver observer, UserInfoAttemptGate attempts) {
		this.exchange = exchange; this.requestTimeout = requestTimeout; this.clock = clock; this.observer = observer; this.attempts = attempts;
	}
	static String authorization(AccessToken token, Clock clock) {
		if (token.getExpiresAt().isPresent() && !clock.instant().isBefore(token.getExpiresAt().orElseThrow()))
			throw OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_ACCESS_TOKEN_EXPIRED);
		try { return token.getAuthorizationHeaderValue(); }
		catch (IllegalStateException invalid) { throw OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_ACCESS_TOKEN_INVALID); }
	}
	OidcUserInfo fetch(OidcProviderMetadata metadata, JsonWebKeySource keys, OidcAuthentication authentication,
			String clientId, @Nullable JwsAlgorithm signedAlgorithm, Duration skew, Set<String> trustedAudiences, Deadline deadline) {
		URI uri = metadata.getUserInfoEndpoint().orElseThrow(() -> OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_ENDPOINT_UNAVAILABLE));
		String header = authorization(authentication.getTokens().getAccessToken(), this.clock);
		UserInfoAttemptGate.Attempt attempt = this.attempts.acquire(deadline, this.requestTimeout);
		URI safe = OidcProviderCache.reduced(uri);
		ObserverDispatch.dispatch(this.observer, observer -> observer.willRequestEndpoint(OAuthEndpoint.USERINFO, safe));
		long started = System.nanoTime(); RawResponse response;
		try {
			response = this.exchange.execute(new HttpExchangeRequest(uri, ResponseProfile.USERINFO, null,
					Map.of("Authorization", header), 256 * 1_024, 16 * 1_024, this.requestTimeout), deadline);
		} catch (HttpExchangeException cause) {
			OAuthException mapped = OidcTransactionAccess.get().endpointExchangeFailure(cause);
			this.attempts.failed(attempt, mapped);
			Duration elapsed = Duration.ofNanos(System.nanoTime() - started);
			ObserverDispatch.dispatch(this.observer, observer -> observer.didFailEndpoint(OAuthEndpoint.USERINFO, safe, mapped, elapsed));
			throw mapped;
		}
		byte[] body = response.body();
		try {
			OAuthException statusFailure = response.status() == 200 ? null : OidcTransactionAccess.get().endpointStatusFailure(response.status(), RetryAfter.parse(response.headers(), this.clock.instant()).orElse(null));
			if (statusFailure != null && statusFailure.isTransient()) this.attempts.failed(attempt, statusFailure);
			else this.attempts.healthy(attempt);
			Duration elapsed = Duration.ofNanos(System.nanoTime() - started);
			ObserverDispatch.dispatch(this.observer, observer -> observer.didRequestEndpoint(OAuthEndpoint.USERINFO, safe, response.status(), elapsed));
			if (statusFailure != null) throw statusFailure;
			String essence = java.util.Objects.requireNonNull(response.mediaType()).getEssence();
			if (!essence.equals(signedAlgorithm == null ? "application/json" : "application/jwt"))
				throw OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_FORMAT_MISMATCH);
			JsonObject claims = signedAlgorithm == null ? UserInfoValidator.json(body, authentication.getSubject())
					: UserInfoValidator.signed(StrictUtf8.decode(body), metadata.getIssuer(), clientId, authentication.getSubject(),
						signedAlgorithm, keys, skew, this.clock, this.observer, trustedAudiences, deadline);
			return new OidcUserInfo(metadata.getIssuer(), claims, signedAlgorithm != null);
		} catch (EncodingException invalid) { throw OidcValidationException.fromReason(OidcValidationException.Reason.USERINFO_MALFORMED); }
		finally { Arrays.fill(body, (byte) 0); }
	}
}
