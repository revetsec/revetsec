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
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.http.Deadline;
import com.revetsec.oauth.PendingAuthorizationStore;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import static java.util.Objects.requireNonNull;

/**
 * A typed browser-bound source for logout return correlation. The application clears a sealed cookie on every
 * callback, including failures/exceptions; that cookie cannot promise atomic concurrent single use. A qualified
 * shared store must consume atomically across participating nodes/restarts. No state-only source exists.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class PendingOidcLogoutSource {
	private final @Nullable String sealed, context, binding;
	private final @Nullable StateSealer sealer;
	private final @Nullable PendingAuthorizationStore store;
	private PendingOidcLogoutSource(@Nullable String sealed, @Nullable StateSealer sealer, @Nullable String context, @Nullable PendingAuthorizationStore store, @Nullable String binding) {
		this.sealed = sealed; this.sealer = sealer; this.context = context; this.store = store; this.binding = binding;
	}
	/**
	 * Selects only a typed pending-logout cookie supplied by that browser. Clear it on every callback.
	 * @param sealedForm received browser cookie
	 * @param sealer application-owned sealer
	 * @param context fixed application cookie context
	 * @return source with no atomic-single-use guarantee
	 * @throws NullPointerException if a required argument is null
	 * @throws IllegalArgumentException if the trusted context is outside the sealer profile
	 * @since 1.0.0
	 */
	public static @NonNull PendingOidcLogoutSource fromSealedForm(@NonNull String sealedForm, @NonNull StateSealer sealer, @NonNull String context) {
		requireNonNull(sealedForm); requireNonNull(sealer); com.revetsec.internal.crypto.SealerV1.requireContext(requireNonNull(context));
		return new PendingOidcLogoutSource(sealedForm, sealer, context, null, null);
	}
	/**
	 * Selects a trusted opaque atomic store and this browser's separately generated binding.
	 * @param store shared store whose consume must be atomic
	 * @param browserBinding nonempty browser-specific secret, at most512UTF8bytes
	 * @return source
	 * @throws NullPointerException if a required argument is null
	 * @throws IllegalArgumentException if browser binding is outside the fixed profile
	 * @since 1.0.0
	 */
	public static @NonNull PendingOidcLogoutSource fromStore(@NonNull PendingAuthorizationStore store, @NonNull BrowserBinding browserBinding) {
		return fromStore(requireNonNull(store), requireNonNull(browserBinding).toSecretString());
	}
	static @NonNull PendingOidcLogoutSource fromStore(@NonNull PendingAuthorizationStore store, @NonNull String browserBinding) {
		OidcLogoutSupport.binding(requireNonNull(browserBinding));
		return new PendingOidcLogoutSource(null, null, null, requireNonNull(store), browserBinding);
	}

	@NonNull OidcLogoutResult complete(@NonNull String state, @NonNull String issuer, @NonNull String clientId, @NonNull URI callback, @NonNull Clock clock, @NonNull Deadline deadline) {
		OidcLogoutSupport.active(deadline); Instant before = readClock(clock, false, deadline); OidcLogoutSupport.active(deadline);
		String record; boolean entered = false;
		try {
			if (this.store != null) {
				java.time.Duration allowance = OidcLogoutSupport.remaining(deadline); entered = true;
				Optional<String> consumed = this.store.consume(requireNonNull(this.binding), state, allowance);
				if (consumed == null || deadline.isExpired() || Thread.currentThread().isInterrupted()) throw indeterminate();
				if (consumed.isEmpty()) return rejected(OidcLogoutResult.Reason.PENDING_NOT_FOUND, entered, deadline);
				record = consumed.get();
			} else {
				if (requireNonNull(this.sealed).length() > 16_384) return rejected(OidcLogoutResult.Reason.PENDING_INVALID, entered, deadline);
				record = SealedStateAccess.get().unseal(requireNonNull(this.sealer), SealedStateType.PENDING_OIDC_LOGOUT, this.sealed, requireNonNull(this.context), Clock.fixed(before, ZoneOffset.UTC));
				OidcLogoutSupport.active(deadline);
			}
			OidcLogoutPendingCodec.Decoded decoded;
			try { decoded = OidcLogoutPendingCodec.decode(record); }
			catch (IllegalArgumentException invalid) { return rejected(OidcLogoutResult.Reason.PENDING_INVALID, entered, deadline); }
			PendingOidcLogout pending = decoded.pending();
			if (!pending.getIssuer().equals(issuer) || !pending.getClientId().equals(clientId) || !pending.getCallbackUri().toString().equals(callback.toString()))
				return rejected(OidcLogoutResult.Reason.CLIENT_MISMATCH, entered, deadline);
			if (!OidcLogoutSupport.same(pending.state(), state)) return rejected(OidcLogoutResult.Reason.STATE_MISMATCH, entered, deadline);
			String digest = decoded.bindingDigest();
			if (this.store == null ? digest != null : digest == null) return rejected(OidcLogoutResult.Reason.PENDING_INVALID, entered, deadline);
			if (this.store != null && !OidcLogoutSupport.same(requireNonNull(digest), OidcLogoutPendingCodec.digest(requireNonNull(this.binding))))
				return rejected(OidcLogoutResult.Reason.BROWSER_BINDING_MISMATCH, entered, deadline);
			Instant now = readClock(clock, entered, deadline);
			if (now.isBefore(before)) throw entered ? indeterminate() : OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE);
			if (now.isBefore(pending.getCreatedAt())) return rejected(OidcLogoutResult.Reason.PENDING_INVALID, entered, deadline);
			if (!now.isBefore(pending.getExpiresAt())) return rejected(OidcLogoutResult.Reason.PENDING_EXPIRED, entered, deadline);
			if (entered && (deadline.isExpired() || Thread.currentThread().isInterrupted())) throw indeterminate();
			OidcLogoutSupport.active(deadline); return OidcLogoutResult.returned();
		} catch (UnsealException invalid) {
			return rejected(invalid.getKind() == UnsealException.Kind.EXPIRED ? OidcLogoutResult.Reason.PENDING_EXPIRED : OidcLogoutResult.Reason.PENDING_INVALID, entered, deadline);
		} catch (VirtualMachineError fatal) { throw fatal; }
		catch (OidcLogoutException failure) {
			if (entered) throw indeterminate();
			throw failure;
		} catch (Throwable unavailable) {
			if (unavailable instanceof InterruptedException) Thread.currentThread().interrupt();
			if (entered) throw indeterminate();
			OidcLogoutSupport.active(deadline); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE);
		}
	}
	private static @NonNull Instant readClock(@NonNull Clock clock, boolean entered, @NonNull Deadline deadline) {
		try { return requireNonNull(clock.instant()); }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (RuntimeException | Error unavailable) { if (entered) throw indeterminate(); OidcLogoutSupport.active(deadline); throw OidcLogoutSupport.failure(OidcLogoutException.Reason.PROVIDER_UNAVAILABLE); }
	}
	private static @NonNull OidcLogoutResult rejected(OidcLogoutResult.@NonNull Reason reason, boolean entered, @NonNull Deadline deadline) {
		if (entered && (deadline.isExpired() || Thread.currentThread().isInterrupted())) throw indeterminate();
		OidcLogoutSupport.active(deadline); return OidcLogoutResult.rejected(reason);
	}
	private static @NonNull OidcLogoutException indeterminate() { return OidcLogoutSupport.failure(OidcLogoutException.Reason.STORE_INDETERMINATE); }
	/** Redacts source state and browser binding.
	 * @return redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "PendingOidcLogoutSource{correlation=<redacted>}"; }
}
