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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.oauth.OidcTransactionAccess;
import com.revetsec.jose.JwtClaims;
import com.revetsec.oauth.OAuthException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Predicate;
import static java.util.Objects.requireNonNull;

/**
 * Exact issuer validation or the fixed Microsoft Entra common/organizations v2.0 trust policy.
 * The application predicate sees only signature-authenticated lowercase tenant GUIDs. It must be fast,
 * thread-safe and cooperative: it runs synchronously on the caller's thread and cannot be preempted.
 * Sharing keys across Entra clients requires the same policy instance; distinct predicates are not equivalent.
 * Consumer tenants use the same rule; deny them unless consumer accounts are intended. Hosted behavior is unproven.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
@CheckReturnValue
public final class OidcIssuerPolicy {
	static final String PREFIX = "https://login.microsoftonline.com/";
	static final String SUFFIX = "/v2.0";
	static final String TEMPLATE = PREFIX + "{tenantid}" + SUFFIX;
	private static final OidcIssuerPolicy EXACT = new OidcIssuerPolicy(null);
	private final @Nullable Predicate<@NonNull String> allowedTenant;
	private OidcIssuerPolicy(@Nullable Predicate<@NonNull String> allowedTenant) { this.allowedTenant = allowedTenant; }
	/**
	 * Returns the default exact issuer policy, with no tenant callback.
	 * @return exact issuer policy
	 * @since 1.0.0
	 */
	public static @NonNull OidcIssuerPolicy exactInstance() { return EXACT; }
	/**
	 * Selects only the fixed public-cloud common/organizations v2.0 issuer template.
	 * The callback is never called by build, metadata parsing or restored session references.
	 * False rejects the tenant; a throwing callback produces a fixed configuration failure without its cause.
	 * @param allowedTenant trusted application decision for a verified lowercase tenant GUID
	 * @return selected policy; share this same instance when sharing common keys
	 * @throws NullPointerException if the predicate is null
	 * @since 1.0.0
	 */
	public static @NonNull OidcIssuerPolicy fromMicrosoftEntraMultiTenant(@NonNull Predicate<@NonNull String> allowedTenant) {
		return new OidcIssuerPolicy(requireNonNull(allowedTenant));
	}
	boolean isMicrosoftEntra() { return this.allowedTenant != null; }
	void checkConfiguredIssuer(@NonNull String issuer) {
		if (isMicrosoftEntra() && !issuer.equals(PREFIX + "common" + SUFFIX) && !issuer.equals(PREFIX + "organizations" + SUFFIX))
			throw new IllegalArgumentException("The Entra policy requires a fixed common or organizations v2.0 issuer.");
	}
	void checkMetadata(@NonNull OidcProviderMetadata metadata) {
		checkConfiguredIssuer(metadata.getIssuer());
		if (!metadata.getIssuer().equals(metadata.getAdvertisedIssuer()) && (!isMicrosoftEntra() || !TEMPLATE.equals(metadata.getAdvertisedIssuer())))
			throw new IllegalArgumentException("The provider metadata requires the selected Entra issuer policy.");
	}
	static @Nullable String tenantFromIssuer(@NonNull String issuer) {
		if (issuer.length() != PREFIX.length() + 36 + SUFFIX.length() || !issuer.startsWith(PREFIX) || !issuer.endsWith(SUFFIX)) return null;
		String value = issuer.substring(PREFIX.length(), issuer.length() - SUFFIX.length());
		if (value.length() != 36) return null;
		for (int index = 0; index < value.length(); index++) {
			char character = value.charAt(index);
			boolean dash = index == 8 || index == 13 || index == 18 || index == 23;
			if (dash ? character != '-' : !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'))) return null;
		}
		return value;
	}
	void checkTenant(@NonNull String tenant, @Nullable Deadline deadline) {
		checkDeadline(deadline);
		if (Thread.currentThread().isInterrupted()) throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.INTERRUPTED);
		boolean allowed;
		try { allowed = requireNonNull(this.allowedTenant).test(tenant); }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (RuntimeException | Error unavailable) { throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.ISSUER_POLICY_UNAVAILABLE); }
		checkDeadline(deadline);
		if (Thread.currentThread().isInterrupted()) throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.INTERRUPTED);
		if (!allowed) throw OidcValidationException.fromReason(OidcValidationException.Reason.TENANT_NOT_ALLOWED);
	}
	static void checkDeadline(@Nullable Deadline deadline) {
		if (deadline != null && deadline.remainingNanos() <= 0)
			throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.NETWORK_FAILURE);
	}
	static @NonNull Instant readClock(@NonNull Clock clock) {
		try { return requireNonNull(clock.instant()); }
		catch (VirtualMachineError fatal) { throw fatal; }
		catch (RuntimeException | Error invalid) { throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.ISSUER_POLICY_UNAVAILABLE); }
	}
	static void checkTime(@NonNull JwtClaims claims, @NonNull Instant now, @NonNull Instant verifiedAt, @NonNull Duration skew) {
		if (now.isBefore(verifiedAt)) throw OidcTransactionAccess.get().endpointFailure(OAuthException.Reason.ISSUER_POLICY_UNAVAILABLE);
		if (!now.isBefore(claims.getExpiresAt().orElseThrow().plus(skew)))
			throw OidcValidationException.fromReason(OidcValidationException.Reason.EXPIRED);
	}
	/**
	 * Redacts the application predicate and tenant policy contents.
	 * @return redacted policy description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "OidcIssuerPolicy{configuration=<redacted>}"; }
}
