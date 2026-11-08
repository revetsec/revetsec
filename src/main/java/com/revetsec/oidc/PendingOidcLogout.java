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

import com.revetsec.BrowserBinding;
import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.http.Deadline;
import com.revetsec.oauth.PendingAuthorizationSaveResult;
import com.revetsec.oauth.PendingAuthorizationStore;
import com.google.errorprone.annotations.CheckReturnValue;
import org.jspecify.annotations.NonNull;
import javax.annotation.concurrent.Immutable;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import static java.util.Objects.requireNonNull;

/**
 * One bounded pending logout correlation record, separate from login. It holds no ID token, nonce, PKCE verifier,
 * access/refresh credential or authentication proof. Browser delivery requires SAVED on the store path. A sealed
 * cookie must be cleared on every callback and supplies no atomic concurrent single-use guarantee.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class PendingOidcLogout {
	private final @NonNull String issuer, clientId, state;
	private final @NonNull URI callbackUri;
	private final @NonNull Instant createdAt, expiresAt;
	PendingOidcLogout(@NonNull String issuer, @NonNull String clientId, @NonNull URI callbackUri, @NonNull String state, @NonNull Instant createdAt, @NonNull Instant expiresAt) {
		OidcLogoutSupport.text(requireNonNull(issuer), OidcLogoutSupport.FIELD_LIMIT); if (issuer.isEmpty()) throw OidcLogoutSupport.invalid();
		OidcLogoutSupport.client(requireNonNull(clientId)); OidcLogoutSupport.text(requireNonNull(callbackUri).toString(), OidcLogoutSupport.FIELD_LIMIT); OidcLogoutSupport.state(requireNonNull(state));
		OidcLogoutPendingCodec.interval(requireNonNull(createdAt), requireNonNull(expiresAt));
		this.issuer = issuer; this.clientId = clientId; this.callbackUri = callbackUri; this.state = state; this.createdAt = createdAt; this.expiresAt = expiresAt;
	}
	@NonNull String state() { return this.state; }
	/** Returns the configured issuer, not authenticated identity.
	 * @return issuer
	 * @since 1.0.0
	 */
	public @NonNull String getIssuer() { return this.issuer; }
	/** Returns the configured client identifier.
	 * @return client identifier
	 * @since 1.0.0
	 */
	public @NonNull String getClientId() { return this.clientId; }
	/** Returns the fixed registered logout callback.
	 * @return callback URI
	 * @since 1.0.0
	 */
	public @NonNull URI getCallbackUri() { return this.callbackUri; }
	/** Returns when correlation state was created.
	 * @return creation instant
	 * @since 1.0.0
	 */
	public @NonNull Instant getCreatedAt() { return this.createdAt; }
	/** Returns exact expiry; equality is expired.
	 * @return expiry instant
	 * @since 1.0.0
	 */
	public @NonNull Instant getExpiresAt() { return this.expiresAt; }
	/**
	 * Seals under the dedicated pending-logout type and exact expiry. Cookie size is limited by the existing sealer
	 * profile; no cap is raised. Clear the browser cookie on every callback, including failure/exception paths.
	 * @param sealer application-owned sealer
	 * @param context fixed browser-cookie context
	 * @return typed sealed pending cookie
	 * @throws NullPointerException if a required argument is null
	 * @throws OidcLogoutException if the storage profile, interruption or provider prevents sealing
	 * @since 1.0.0
	 */
	public @NonNull String toSealedForm(@NonNull StateSealer sealer, @NonNull String context) {
		requireNonNull(sealer); requireNonNull(context); OidcLogoutSupport.interrupted();
		try { String sealed = SealedStateAccess.get().seal(sealer, SealedStateType.PENDING_OIDC_LOGOUT, OidcLogoutPendingCodec.encode(this, null), context, this.expiresAt); OidcLogoutSupport.interrupted(); return sealed; }
		catch (OidcLogoutException failure) { throw failure; }
		catch (IllegalArgumentException invalid) { throw OidcLogoutSupport.failure(OidcLogoutException.Reason.STORAGE_PROFILE_UNSUPPORTED); }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (RuntimeException | Error unavailable) { OidcLogoutSupport.interrupted(); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE); }
	}
	/**
	 * Saves using a five-second convenience budget. Only SAVED permits browser delivery; uncertain writes are never retried.
	 * @param store trusted opaque atomic store
	 * @param browserBinding nonempty browser-specific secret, at most512UTF8bytes
	 * @return fixed save outcome
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull PendingAuthorizationSaveResult saveToResult(@NonNull PendingAuthorizationStore store, @NonNull BrowserBinding browserBinding) { return saveToResult(store, requireNonNull(browserBinding), Duration.ofSeconds(5)); }
	@CheckReturnValue
	@NonNull PendingAuthorizationSaveResult saveToResult(@NonNull PendingAuthorizationStore store, @NonNull String browserBinding) { return saveToResult(store, browserBinding, Duration.ofSeconds(5)); }
	/**
	 * Saves the complete browser-bound record under one shrinking caller budget. UNAVAILABLE before provider entry
	 * has no save effect. A late/null/throwing/possibly completed store call returns INDETERMINATE, never safe retry.
	 * Existing store capacities apply and may refuse this record without evicting live state.
	 * @param store trusted opaque atomic store
	 * @param browserBinding nonempty browser-specific secret, at most512UTF8bytes
	 * @param remaining the caller's remaining operation budget
	 * @return fixed save outcome; only SAVED permits browser delivery
	 * @throws NullPointerException if a required argument is null
	 * @throws IllegalArgumentException if browser binding is outside the profile
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull PendingAuthorizationSaveResult saveToResult(@NonNull PendingAuthorizationStore store, @NonNull BrowserBinding browserBinding, @NonNull Duration remaining) {
		return saveToResult(store, requireNonNull(browserBinding).toSecretString(), remaining);
	}
	@CheckReturnValue
	@NonNull PendingAuthorizationSaveResult saveToResult(@NonNull PendingAuthorizationStore store, @NonNull String browserBinding, @NonNull Duration remaining) {
		requireNonNull(store); requireNonNull(browserBinding); requireNonNull(remaining); OidcLogoutSupport.binding(browserBinding);
		if (remaining.isZero() || remaining.isNegative() || Thread.currentThread().isInterrupted()) return PendingAuthorizationSaveResult.UNAVAILABLE;
		Deadline deadline = Deadline.fromNow(remaining); String record; Duration allowance;
		try { record = OidcLogoutPendingCodec.encode(this, OidcLogoutPendingCodec.digest(browserBinding)); allowance = OidcLogoutSupport.remaining(deadline); }
		catch (RuntimeException unavailable) { return PendingAuthorizationSaveResult.UNAVAILABLE; }
		try {
			PendingAuthorizationSaveResult result = store.save(browserBinding, this.state, record, this.expiresAt, allowance);
			return result == null || deadline.isExpired() || Thread.currentThread().isInterrupted() ? PendingAuthorizationSaveResult.INDETERMINATE : result;
		} catch (VirtualMachineError fatal) { throw fatal; }
		catch (Throwable failure) { if (failure instanceof InterruptedException) Thread.currentThread().interrupt(); return PendingAuthorizationSaveResult.INDETERMINATE; }
	}
	/** Redacts state and browser data.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "PendingOidcLogout{correlation=<redacted>}"; }
}
