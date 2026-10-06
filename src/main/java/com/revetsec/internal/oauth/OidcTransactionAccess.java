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

package com.revetsec.internal.oauth;

import com.revetsec.oauth.*;
import com.revetsec.jose.JwsAlgorithm;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import java.util.function.Function;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HttpExchangeException;
import static java.util.Objects.requireNonNull;

/**
 * Set-once access to OAuthClient's shared transaction path. Only its nestmates can install operations. The bridge
 * accepts checked OIDC metadata supplied by the OIDC layer; completion consults it only after local callback checks.
 * No exported signature mentions this class or a completion handle.
 */
@ThreadSafe
public final class OidcTransactionAccess {
	private static final ReentrantLock SET_LOCK = new ReentrantLock();
	private static volatile @Nullable Operations operations;
	private OidcTransactionAccess() { }

	@ThreadSafe
	public interface Operations {
  /** Existing OAuth proof validation under the caller's original shrinking transaction deadline. */
  @NonNull VerifiedAccessToken validateAccessToken(@NonNull JwtAccessTokenValidator validator,@NonNull BearerToken token,@NonNull Deadline deadline);
  /** Credential extraction stays in the nonexported protocol bridge, never in the public holder API. */
  @NonNull String bearerValue(@NonNull BearerToken token);
		void checkHmacAuthentication(@NonNull ClientAuthentication authentication, @NonNull Set<@NonNull JwsAlgorithm> algorithms);
		@NonNull OAuthException endpointFailure(OAuthException.@NonNull Reason reason);
		@NonNull OAuthException endpointExchangeFailure(@NonNull HttpExchangeException failure);
		@NonNull OAuthException endpointStatusFailure(int status, @Nullable Duration retryAfter);
		@NonNull AuthorizationRedirect begin(@NonNull OAuthClient client, @NonNull AuthorizationRequestOptions options,
				@NonNull AuthorizationServerMetadata metadata, @Nullable Duration maxAge, @NonNull Set<@NonNull String> acrValues);
		@NonNull RefreshCompletion refresh(@NonNull OAuthClient client, @NonNull RefreshToken token, @NonNull TokenRequestOptions options,
				@NonNull AuthorizationServerMetadata metadata, @NonNull Deadline deadline, @NonNull Set<@NonNull JwsAlgorithm> hmacAlgorithms);
		@NonNull Completion complete(@NonNull OAuthClient client, @NonNull AuthorizationResponse response, @NonNull PendingAuthorizationSource source,
				@NonNull URI callback, @NonNull Function<@NonNull Deadline, @NonNull AuthorizationServerMetadata> metadata, @NonNull Deadline deadline, @NonNull Set<@NonNull JwsAlgorithm> hmacAlgorithms);
	}

	public static void set(@NonNull Operations value) {
		requireNonNull(value);
		if (value.getClass().getNestHost() != OAuthClient.class)
			throw new IllegalArgumentException("Only OAuthClient installs the OIDC transaction operations.");
		SET_LOCK.lock();
		try {
			if (operations != null) throw new IllegalStateException("The OIDC transaction operations are installed.");
			operations = value;
		} finally { SET_LOCK.unlock(); }
	}

	public static @NonNull Operations get() {
		try { MethodHandles.lookup().ensureInitialized(OAuthClient.class); }
		catch (IllegalAccessException impossible) { throw new IllegalStateException("OAuthClient cannot be initialized."); }
		Operations installed = operations;
		if (installed == null) throw new IllegalStateException("The OIDC transaction operations are not installed.");
		return installed;
	}

	/** Credential-bearing, per-call internal handle. Only OIDC validation's successful path releases public tokens. */
	@ThreadSafe
	public static final class Completion {
		private final @Nullable String idToken;
		private final @Nullable String clientSecret;
		private final String accessToken;
		private final String tokenType;
		private final String code;
		private final String nonce;
		private final @Nullable Duration maxAge;
		private final Set<String> acrValues;
		private final Supplier<TokenResponse> release;
		private final ReentrantLock lock = new ReentrantLock();
		private boolean released;

		public Completion(@Nullable String idToken, @NonNull String accessToken, @NonNull String tokenType, @NonNull String code, @NonNull String nonce,
				@Nullable Duration maxAge, @NonNull Set<@NonNull String> acrValues, @NonNull Supplier<@NonNull TokenResponse> release) {
			this(idToken, accessToken, tokenType, code, nonce, maxAge, acrValues, release, null);
		}
		public Completion(@Nullable String idToken, @NonNull String accessToken, @NonNull String tokenType, @NonNull String code, @NonNull String nonce,
				@Nullable Duration maxAge, @NonNull Set<@NonNull String> acrValues, @NonNull Supplier<@NonNull TokenResponse> release, @Nullable String clientSecret) {
			this.clientSecret = clientSecret;
			this.idToken = idToken; this.accessToken = requireNonNull(accessToken);
			this.tokenType = requireNonNull(tokenType); this.code = requireNonNull(code);
			this.nonce = requireNonNull(nonce); this.maxAge = maxAge; this.acrValues = Set.copyOf(acrValues);
			this.release = requireNonNull(release);
		}
		public @Nullable String clientSecret() { return this.clientSecret; }
		public @Nullable String idToken() { return this.idToken; }
		public @NonNull String accessToken() { return this.accessToken; }
		public @NonNull String tokenType() { return this.tokenType; }
		public @NonNull String code() { return this.code; }
		public @NonNull String nonce() { return this.nonce; }
		public @Nullable Duration maxAge() { return this.maxAge; }
		public @NonNull Set<@NonNull String> acrValues() { return this.acrValues; }
		public @NonNull TokenResponse releaseTokens() {
			this.lock.lock();
			try {
				if (this.released) throw new IllegalStateException("The OIDC tokens were already released.");
				this.released = true;
				return this.release.get();
			} finally { this.lock.unlock(); }
		}
		@Override public @NonNull String toString() { return "Completion{credentials=<redacted>}"; }
	}
	/** Credential-bearing refresh handle; public tokens are released only after optional ID-token validation. */
	@ThreadSafe
	public static final class RefreshCompletion {
		private final @Nullable String idToken;
		private final @Nullable String clientSecret;
		private final boolean idTokenPresent;
		private final String accessToken;
		private final String tokenType;
		private final Supplier<TokenResponse> release;
		private final ReentrantLock lock = new ReentrantLock();
		private boolean released;
		public RefreshCompletion(@Nullable String idToken, boolean idTokenPresent, @NonNull String accessToken, @NonNull String tokenType, @NonNull Supplier<@NonNull TokenResponse> release) {
			this(idToken, idTokenPresent, accessToken, tokenType, release, null);
		}
		public RefreshCompletion(@Nullable String idToken, boolean idTokenPresent, @NonNull String accessToken, @NonNull String tokenType,
				@NonNull Supplier<@NonNull TokenResponse> release, @Nullable String clientSecret) {
			this.clientSecret = clientSecret;
			this.idToken = idToken; this.idTokenPresent = idTokenPresent; this.accessToken = requireNonNull(accessToken);
			this.tokenType = requireNonNull(tokenType); this.release = requireNonNull(release);
		}
		public @Nullable String clientSecret() { return this.clientSecret; }
		public @Nullable String idToken() { return this.idToken; }
		public boolean idTokenPresent() { return this.idTokenPresent; }
		public @NonNull String accessToken() { return this.accessToken; }
		public @NonNull String tokenType() { return this.tokenType; }
		public @NonNull TokenResponse releaseTokens() {
			this.lock.lock();
			try {
				if (this.released) throw new IllegalStateException("The OIDC refresh tokens were already released.");
				this.released = true; return this.release.get();
			} finally { this.lock.unlock(); }
		}
		@Override public @NonNull String toString() { return "RefreshCompletion{credentials=<redacted>}"; }
	}

}
