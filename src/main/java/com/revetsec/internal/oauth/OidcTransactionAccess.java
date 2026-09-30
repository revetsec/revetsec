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
		OAuthException endpointFailure(OAuthException.Reason reason);
		OAuthException endpointExchangeFailure(HttpExchangeException failure);
		OAuthException endpointStatusFailure(int status, @Nullable Duration retryAfter);
		AuthorizationRedirect begin(OAuthClient client, AuthorizationRequestOptions options,
				AuthorizationServerMetadata metadata, @Nullable Duration maxAge, Set<String> acrValues);
		Completion complete(OAuthClient client, AuthorizationResponse response, PendingAuthorizationSource source,
				URI callback, Function<Deadline, AuthorizationServerMetadata> metadata, Deadline deadline);
	}

	public static void set(Operations value) {
		requireNonNull(value);
		if (value.getClass().getNestHost() != OAuthClient.class)
			throw new IllegalArgumentException("Only OAuthClient installs the OIDC transaction operations.");
		SET_LOCK.lock();
		try {
			if (operations != null) throw new IllegalStateException("The OIDC transaction operations are installed.");
			operations = value;
		} finally { SET_LOCK.unlock(); }
	}

	public static Operations get() {
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
		private final String accessToken;
		private final String tokenType;
		private final String code;
		private final String nonce;
		private final @Nullable Duration maxAge;
		private final Set<String> acrValues;
		private final Supplier<TokenResponse> release;
		private final ReentrantLock lock = new ReentrantLock();
		private boolean released;

		public Completion(@Nullable String idToken, String accessToken, String tokenType, String code, String nonce,
				@Nullable Duration maxAge, Set<String> acrValues, Supplier<TokenResponse> release) {
			this.idToken = idToken; this.accessToken = requireNonNull(accessToken);
			this.tokenType = requireNonNull(tokenType); this.code = requireNonNull(code);
			this.nonce = requireNonNull(nonce); this.maxAge = maxAge; this.acrValues = Set.copyOf(acrValues);
			this.release = requireNonNull(release);
		}
		public @Nullable String idToken() { return this.idToken; }
		public String accessToken() { return this.accessToken; }
		public String tokenType() { return this.tokenType; }
		public String code() { return this.code; }
		public String nonce() { return this.nonce; }
		public @Nullable Duration maxAge() { return this.maxAge; }
		public Set<String> acrValues() { return this.acrValues; }
		public TokenResponse releaseTokens() {
			this.lock.lock();
			try {
				if (this.released) throw new IllegalStateException("The OIDC tokens were already released.");
				this.released = true;
				return this.release.get();
			} finally { this.lock.unlock(); }
		}
		@Override public String toString() { return "Completion{credentials=<redacted>}"; }
	}
}
