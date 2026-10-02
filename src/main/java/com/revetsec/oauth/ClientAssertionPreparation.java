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

import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.UriChecks;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.jose.JwsSigningException;
import com.revetsec.json.JsonObject;
import java.net.URI;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Caller-thread preparation under the original operation deadline; no assertion is cached or retried. */
@ThreadSafe
final class ClientAssertionPreparation {
	private ClientAssertionPreparation() { }

	@Immutable
	record Prepared(@NonNull String value, @NonNull Instant issued, @NonNull Instant expires) {
		@Override public @NonNull String toString() { return "Prepared{assertion=<redacted>}"; }
	}

	static @NonNull Prepared prepare(@NonNull ClientAuthentication authentication, @NonNull String clientId,
			@NonNull ResourceServerMetadata target, @NonNull OAuthEndpoint role, OAuthClient.@NonNull ResourceSettings settings,
			@NonNull SecureRandom random, @NonNull Deadline deadline) {
		checkActive(deadline);
		try {
			URI issuer = URI.create(settings.issuer());
			if (!UriChecks.isPermitted(target.endpoint(), settings.policy(), settings.allowLoopback())
					|| !sameOrigin(issuer, target.endpoint())
					|| (target.tokenEndpoint() != null && !sameOrigin(issuer, target.tokenEndpoint()))) throw endpointMismatch();
		} catch (IllegalArgumentException invalid) { throw endpointMismatch(); }
		Set<String> methods = target.authenticationMethods();
		if (methods == null ? role != OAuthEndpoint.INTROSPECTION : !methods.contains("private_key_jwt")) throw endpointMismatch();
		// A present empty algorithm list cannot permit any selected signer. Reject before consulting the provider.
		Set<String> algorithms = target.signingAlgorithms();
		if (algorithms != null && algorithms.isEmpty()) throw endpointMismatch();
		checkActive(deadline);
		ClientAssertionSigningKey key;
		try {
			key = authentication.keyProvider().getSigningKey(deadline.remaining());
			if (key == null) throw OAuthConfigurationException.fromReason(OAuthException.Reason.CLIENT_ASSERTION_KEY_UNAVAILABLE);
		} catch (VirtualMachineError fatal) { throw fatal; }
		catch (Throwable unavailable) {
			checkActive(deadline);
			throw OAuthConfigurationException.fromReason(OAuthException.Reason.CLIENT_ASSERTION_KEY_UNAVAILABLE);
		}
		checkActive(deadline);
		if (algorithms != null && !algorithms.contains(key.signer().getAlgorithm().getWireValue())) throw endpointMismatch();
		String audience = authentication.assertionAudience() == ClientAssertionAudience.ISSUER
				? settings.issuer() : target.endpoint().toString();
		byte @Nullable [] claims = null;
		byte[] nonce = new byte[32];
		try {
			Instant now = settings.clock().instant();
			long issuedSecond = now.getEpochSecond();
			long expirySecond = Math.addExact(issuedSecond, authentication.assertionLifetime().toSeconds());
			// Same NumericDate range as the existing strict JOSE reader: [-9999, 10000).
			if (issuedSecond < -377_705_116_800L || expirySecond >= 253_402_300_800L) throw signingFailed();
						Instant expires = Instant.ofEpochSecond(expirySecond);
			// Count JSON string bytes before serialization. Signer's fixed 32KiB claims cap is not a new tunable limit.
			if (2L * jsonStringLength(clientId) + jsonStringLength(audience) + 256L > 32L * 1024L) throw signingFailed();
			random.nextBytes(nonce);
			String jti = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
			claims = JsonCodec.toUtf8Bytes(JsonObject.builder().put("iss", clientId).put("sub", clientId)
					.put("aud", audience).put("iat", issuedSecond).put("nbf", issuedSecond).put("exp", expirySecond).put("jti", jti).build());
			checkActive(deadline);
			String type = authentication.assertionAudience() == ClientAssertionAudience.ISSUER ? "client-authentication+jwt" : "JWT";
			String compact = key.signer().toCompactSerialization(type, key.getKeyId().orElse(null),
					key.getCertificateSha256Thumbprint().orElse(null), claims, deadline.remaining());
			Prepared prepared = new Prepared(compact, now, expires);
			checkReady(prepared, settings.clock(), deadline);
			return prepared;
		} catch (JwsSigningException failure) {
			checkActive(deadline);
			throw switch (failure.getReason()) {
				case KEY_PAIR_MISMATCH -> OAuthConfigurationException.fromReason(OAuthException.Reason.CLIENT_ASSERTION_KEY_PAIR_MISMATCH);
				case BUDGET_EXHAUSTED -> OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
				case SIGNING_UNAVAILABLE -> signingFailed();
			};
		} catch (OAuthException failure) { throw failure; }
		catch (RuntimeException invalid) { throw signingFailed(); }
		finally { if (claims != null) Arrays.fill(claims, (byte) 0); Arrays.fill(nonce, (byte) 0); }
	}

	static void checkReady(@Nullable Prepared prepared, @NonNull Clock clock, @NonNull Deadline deadline) {
		if (prepared == null) return;
		checkActive(deadline);
		Instant now;
		try { now = java.util.Objects.requireNonNull(clock.instant()); }
		catch (RuntimeException invalid) { throw signingFailed(); }
		if (now.isBefore(prepared.issued()) || !now.isBefore(prepared.expires())) throw signingFailed();
	}
	private static void checkActive(@NonNull Deadline deadline) {
		if (Thread.currentThread().isInterrupted()) throw OAuthTransportException.fromReason(OAuthException.Reason.INTERRUPTED, null);
		if (deadline.isExpired()) throw OAuthTransportException.fromReason(OAuthException.Reason.NETWORK_FAILURE, null);
	}
	static boolean sameOrigin(@NonNull URI issuer, @NonNull URI endpoint) {
		return issuer.getScheme() != null && endpoint.getScheme() != null && issuer.getHost() != null && endpoint.getHost() != null
				&& issuer.getScheme().equalsIgnoreCase(endpoint.getScheme()) && issuer.getHost().equalsIgnoreCase(endpoint.getHost())
				&& effectivePort(issuer) == effectivePort(endpoint);
	}
	static boolean sameEndpoint(@NonNull URI first, @NonNull URI second) {
		return sameOrigin(first, second) && route(first).equals(route(second));
	}
	private static @NonNull URI route(@NonNull URI uri) {
		// URI equality compares escape hex case while retaining exact path and query meaning. A fixed authority
		// prevents a path beginning with two slashes from becoming an authority during this local comparison.
		return URI.create("https://route.invalid" + java.util.Objects.requireNonNull(uri.getRawPath())
				+ (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery()));
	}
	private static int effectivePort(@NonNull URI uri) {
		return uri.getPort() != -1 ? uri.getPort() : "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
	}
	private static long jsonStringLength(@NonNull String value) {
		if (value.length() > 32 * 1024) throw signingFailed();
		long length = 2;
		for (int i = 0; i < value.length(); i++) {
			char c = value.charAt(i);
			if (c < 32) length += 6;
			else if (c == '"' || c == '\\') length += 2;
			else if (c < 128) length++;
			else if (c < 2048) length += 2;
			else if (Character.isHighSurrogate(c)) {
				if (++i == value.length() || !Character.isLowSurrogate(value.charAt(i))) throw signingFailed();
				length += 4;
			} else if (Character.isLowSurrogate(c)) throw signingFailed();
			else length += 3;
		}
		return length;
	}
	private static @NonNull OAuthConfigurationException endpointMismatch() {
		return OAuthConfigurationException.fromReason(OAuthException.Reason.CLIENT_ASSERTION_ENDPOINT_MISMATCH);
	}
	private static @NonNull OAuthConfigurationException signingFailed() {
		return OAuthConfigurationException.fromReason(OAuthException.Reason.CLIENT_ASSERTION_SIGNING_FAILED);
	}
}
