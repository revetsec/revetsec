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

package com.revetsec.internal.jose;

import com.revetsec.jose.JoseException;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import static java.util.Objects.requireNonNull;

/**
 * The claim checks a verified JWT must pass (plan "JOSE semantics", steps 10 to 14), parameterized so that the
 * generic validator and later profiles share them: the exact issuer, the expected audiences or any audience, the
 * required claims, and the clock skew.
 * <p>
 * {@code iss} is always required, and so is {@code aud} unless any audience is accepted. The default profile
 * also requires {@code exp}; the internal signed-UserInfo profile validates expiration only when present. The
 * required-claims setting adds names to those.
 * <p>
 * {@link #check(RegisteredClaims, VerificationKey, Instant)} runs the checks in order, and the first failure names the
 * reason:
 * <ol>
 *   <li><strong>Issuer</strong> (step 10). {@code iss} absent is {@link JoseException.Reason#MISSING_CLAIM}; not equal
 *   to the configured issuer, code point by code point with no normalization, is
 *   {@link JoseException.Reason#ISSUER_MISMATCH} (RFC 7519 section 4.1.1). Then the verifying key's JWK {@code issuer}
 *   member, when it has one, must equal {@code iss}, else {@link JoseException.Reason#KEY_ISSUER_MISMATCH} (INV-C6):
 *   a key published for one issuer never verifies another's tokens. The one exception is Microsoft Entra ID's
 *   template (M2-11): a member exactly equal to {@value #ENTRA_ISSUER_TEMPLATE} is bound to {@code iss} only when the
 *   token's {@code tid} claim is a lowercase GUID string and {@code iss} is exactly
 *   {@value #ENTRA_ISSUER_PREFIX}{@code <tid>}{@value #ENTRA_ISSUER_SUFFIX}; it is never compared literally, so an
 *   {@code iss} that is the template itself matches no such key. Any other spelling, host or placeholder is compared
 *   literally. Since {@code iss} already equals the configured issuer, the template never admits a token for another
 *   issuer.</li>
 *   <li><strong>Audience</strong> (step 11). Unless any audience is accepted, {@code aud} absent is
 *   {@link JoseException.Reason#MISSING_CLAIM}, and one with no expected audience, compared exactly, is
 *   {@link JoseException.Reason#AUDIENCE_MISMATCH}. Other audiences beside an expected one are allowed (RFC 7519
 *   section 4.1.3).</li>
 *   <li><strong>Time</strong> (step 12), with the clock skew {@code s}: {@code exp} absent in the default profile is
 *   {@link JoseException.Reason#MISSING_CLAIM}; {@code now >= exp + s} is {@link JoseException.Reason#EXPIRED}
 *   (RFC 7519 section 4.1.4); {@code iat > now + s} is {@link JoseException.Reason#ISSUED_IN_FUTURE}; and
 *   {@code now < nbf - s} is {@link JoseException.Reason#NOT_YET_VALID} (section 4.1.5).</li>
 *   <li><strong>Required claims</strong> (step 13): each is present and not JSON {@code null}, else
 *   {@link JoseException.Reason#MISSING_CLAIM}.</li>
 *   <li><strong>Confirmation</strong> (step 14): a {@code cnf} member (RFC 7800) is
 *   {@link JoseException.Reason#CONFIRMATION_NOT_VERIFIED}, because this policy proves no possession of a key, so a
 *   proof-of-possession token is never accepted as a bearer token (INV-G6).</li>
 * </ol>
 * An unexpected {@link RuntimeException} in a step is that step's first reason (INV-G1).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public final class JwtClaimsPolicy {
	/**
	 * The JWK {@code issuer} member Microsoft Entra ID publishes on its shared v2 keys (M2-11).
	 */
	public static final String ENTRA_ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0";

	/**
	 * What precedes the tenant ID in an Entra v2 issuer.
	 */
	public static final String ENTRA_ISSUER_PREFIX = "https://login.microsoftonline.com/";

	/**
	 * What follows the tenant ID in an Entra v2 issuer.
	 */
	public static final String ENTRA_ISSUER_SUFFIX = "/v2.0";

	private static final String TENANT_ID_CLAIM = "tid";
	private static final String CONFIRMATION_CLAIM = "cnf";
	private static final int GUID_LENGTH = 36;

	@NonNull
	private final String issuer;
	@Nullable
	private final Set<@NonNull String> expectedAudiences;
	@NonNull
	private final Set<@NonNull String> requiredClaims;
	@NonNull
	private final Duration clockSkew;
	private final boolean expirationRequired;
	private final boolean timeAdmission;
	private final boolean microsoftEntra;
	private final @Nullable String boundTenantIssuer;

	private JwtClaimsPolicy(@NonNull String issuer,
													@Nullable Set<@NonNull String> expectedAudiences,
													@NonNull Set<@NonNull String> requiredClaims,
													@NonNull Duration clockSkew, boolean expirationRequired) {
		this(issuer, expectedAudiences, requiredClaims, clockSkew, expirationRequired, false, null);
	}
	private JwtClaimsPolicy(@NonNull String issuer, @Nullable Set<@NonNull String> expectedAudiences,
			@NonNull Set<@NonNull String> requiredClaims, @NonNull Duration clockSkew, boolean expirationRequired,
			boolean microsoftEntra, @Nullable String boundTenantIssuer) {
		this(issuer, expectedAudiences, requiredClaims, clockSkew, expirationRequired, microsoftEntra, boundTenantIssuer, true);
	}
	private JwtClaimsPolicy(@NonNull String issuer, @Nullable Set<@NonNull String> expectedAudiences,
			@NonNull Set<@NonNull String> requiredClaims, @NonNull Duration clockSkew, boolean expirationRequired,
			boolean microsoftEntra, @Nullable String boundTenantIssuer, boolean timeAdmission) {
		this.timeAdmission = timeAdmission;
		this.microsoftEntra = microsoftEntra; this.boundTenantIssuer = boundTenantIssuer;
		this.expirationRequired = expirationRequired;
		this.issuer = issuer;
		this.expectedAudiences = expectedAudiences == null ? null : Set.copyOf(expectedAudiences);
		this.requiredClaims = Set.copyOf(requiredClaims);
		this.clockSkew = clockSkew;
	}

	/**
	 * Returns a policy from settings the caller has already range-checked against its own limits.
	 *
	 * @param issuer            the expected {@code iss}, compared exactly by code point; not empty
	 * @param expectedAudiences the audiences a token may name, compared exactly, or {@code null} to accept any
	 *                          audience; not empty, and no element empty
	 * @param requiredClaims    claim names that must be present and not JSON {@code null}, besides the ones always
	 *                          required; no element empty
	 * @param clockSkew         the allowance for clock differences in the time checks; not negative
	 * @return the policy
	 * @throws NullPointerException     if a required argument or an element is {@code null}
	 * @throws IllegalArgumentException if a value is empty or the skew is negative
	 */
	@NonNull
	public static JwtClaimsPolicy fromSettings(@NonNull String issuer,
																						 @Nullable Set<@NonNull String> expectedAudiences,
																						 @NonNull Set<@NonNull String> requiredClaims,
																						 @NonNull Duration clockSkew) {
		requireNonNull(issuer);
		requireNonNull(clockSkew);

		if (issuer.isEmpty())
			throw new IllegalArgumentException("The issuer must not be empty.");

		Set<String> audiences = expectedAudiences == null ? null : Set.copyOf(expectedAudiences);
		if (audiences != null && (audiences.isEmpty() || audiences.contains("")))
			throw new IllegalArgumentException("Expected audiences must not be empty, and no audience may be empty.");

		Set<String> claims = Set.copyOf(requiredClaims);
		if (claims.contains(""))
			throw new IllegalArgumentException("A required claim name must not be empty.");

		if (clockSkew.isNegative())
			throw new IllegalArgumentException("The clock skew must not be negative.");

		return new JwtClaimsPolicy(issuer, audiences, claims, clockSkew, true);
	}

	/**
	 * Returns the signed-UserInfo profile: expiry is optional, but validated when present. Only the internal OIDC
	 * validation bridge selects this profile; exported JWT validation always requires expiry.
	 * @return the same issuer, audience and claim policy with optional expiration
	 */
	public @NonNull JwtClaimsPolicy withOptionalExpiration() {
		return new JwtClaimsPolicy(this.issuer, this.expectedAudiences, this.requiredClaims, this.clockSkew, false);
	}

	/**
	 * Internal issuer revocation only: recognize a retained credential without granting time admission.
	 * Signature, claim types, issuer/key issuer, audience, required claims and confirmation checks remain.
	 * The issuer must separately prove exact persisted issuance, ownership and current revocation fences.
	 * @return the revocation recognition policy
	 */
	public @NonNull JwtClaimsPolicy forIssuerRevocation() {
		return new JwtClaimsPolicy(this.issuer, this.expectedAudiences, this.requiredClaims, this.clockSkew,
			this.expirationRequired, false, null, false);
	}

	/**
	 * Checks a verified token's claims (steps 10 to 14 in the class documentation).
	 *
	 * @param claims the claims, with their registered claims read
	 * @param key    the key that verified the signature, or {@code null} for a configured secret, which has no JWK
	 *               {@code issuer} member
	 * @param now    the current time, from the caller's clock
	 * @throws NullPointerException if {@code claims} or {@code now} is {@code null}
	 * @throws JoseFailure          with the reason of the first check that failed
	 */
	public void check(@NonNull RegisteredClaims claims,
										@Nullable VerificationKey key,
										@NonNull Instant now) throws JoseFailure {
		requireNonNull(claims);
		requireNonNull(now);
		// The reason an unexpected RuntimeException in the running step becomes (INV-G1).
		JoseException.Reason step = JoseException.Reason.ISSUER_MISMATCH;

		try {
			checkIssuer(claims, key == null ? null : key.issuer());
			step = JoseException.Reason.AUDIENCE_MISMATCH;
			checkAudience(claims);
			step = JoseException.Reason.EXPIRED;
			if (this.timeAdmission) checkTime(claims, now);
			step = JoseException.Reason.MISSING_CLAIM;
			checkRequiredClaims(claims);
			step = JoseException.Reason.CONFIRMATION_NOT_VERIFIED;
			if (claims.claims().getMembers().containsKey(CONFIRMATION_CLAIM))
				throw new JoseFailure(JoseException.Reason.CONFIRMATION_NOT_VERIFIED);
		} catch (RuntimeException e) {
			throw new JoseFailure(step);
		}
	}

	/** Dedicated fixed Entra profile selected only by the existing OIDC validation bridge. */
	public @NonNull JwtClaimsPolicy withMicrosoftEntraIssuer(@Nullable String trustedTenantIssuer) {
		if (trustedTenantIssuer == null) {
			if (!this.issuer.equals(ENTRA_ISSUER_PREFIX + "common" + ENTRA_ISSUER_SUFFIX)
					&& !this.issuer.equals(ENTRA_ISSUER_PREFIX + "organizations" + ENTRA_ISSUER_SUFFIX)) throw new IllegalArgumentException("Invalid Entra trust issuer.");
		} else if (trustedTenantIssuer.length() != ENTRA_ISSUER_PREFIX.length() + GUID_LENGTH + ENTRA_ISSUER_SUFFIX.length()
				|| !trustedTenantIssuer.equals(this.issuer) || !trustedTenantIssuer.startsWith(ENTRA_ISSUER_PREFIX)
				|| !trustedTenantIssuer.endsWith(ENTRA_ISSUER_SUFFIX)
				|| !isLowercaseGuid(trustedTenantIssuer.substring(ENTRA_ISSUER_PREFIX.length(), trustedTenantIssuer.length() - ENTRA_ISSUER_SUFFIX.length())))
			throw new IllegalArgumentException("Invalid verified tenant issuer.");
		return new JwtClaimsPolicy(this.issuer, this.expectedAudiences, this.requiredClaims, this.clockSkew, this.expirationRequired, true, trustedTenantIssuer);
	}
	private void checkMicrosoftEntraIssuer(@NonNull RegisteredClaims claims, @Nullable String keyIssuer) throws JoseFailure {
		String actual = claims.issuer();
		JsonValue tidValue = claims.claims().getMembers().get(TENANT_ID_CLAIM);
		if (this.boundTenantIssuer == null) {
			if (!(tidValue instanceof JsonString tid) || !isLowercaseGuid(tid.getValue())
					|| !(ENTRA_ISSUER_PREFIX + tid.getValue() + ENTRA_ISSUER_SUFFIX).equals(actual)) throw new JoseFailure(JoseException.Reason.ISSUER_MISMATCH);
		} else {
			if (!this.boundTenantIssuer.equals(actual)) throw new JoseFailure(JoseException.Reason.ISSUER_MISMATCH);
			if (tidValue != null && (!(tidValue instanceof JsonString tid) || !isLowercaseGuid(tid.getValue())
					|| !(ENTRA_ISSUER_PREFIX + tid.getValue() + ENTRA_ISSUER_SUFFIX).equals(actual))) throw new JoseFailure(JoseException.Reason.ISSUER_MISMATCH);
		}
		if (keyIssuer == null || !(keyIssuer.equals(actual) || keyIssuer.equals(ENTRA_ISSUER_TEMPLATE)))
			throw new JoseFailure(JoseException.Reason.KEY_ISSUER_MISMATCH);
	}
	private void checkIssuer(@NonNull RegisteredClaims claims,
													 @Nullable String keyIssuer) throws JoseFailure {
		if (this.microsoftEntra) { checkMicrosoftEntraIssuer(claims, keyIssuer); return; }
		String issuer = claims.issuer();

		if (issuer == null)
			throw new JoseFailure(JoseException.Reason.MISSING_CLAIM);
		if (!issuer.equals(this.issuer))
			throw new JoseFailure(JoseException.Reason.ISSUER_MISMATCH);
		if (keyIssuer == null)
			return;

		// The template is never compared literally: an iss that is the template itself names no tenant, so it matches
		// only through a valid tid, which it can never equal (M2-11).
		boolean bound = keyIssuer.equals(ENTRA_ISSUER_TEMPLATE)
				? isEntraTemplateMatch(issuer, claims.claims().getMembers())
				: keyIssuer.equals(issuer);

		if (!bound)
			throw new JoseFailure(JoseException.Reason.KEY_ISSUER_MISMATCH);
	}

	/**
	 * Whether the token's {@code tid} substitutes into Entra's template to give exactly {@code issuer} (M2-11).
	 */
	private static boolean isEntraTemplateMatch(@NonNull String issuer,
																							@NonNull Map<@NonNull String, @NonNull JsonValue> claims) {
		if (!(claims.get(TENANT_ID_CLAIM) instanceof JsonString tid) || !isLowercaseGuid(tid.getValue()))
			return false;

		return issuer.equals(ENTRA_ISSUER_PREFIX + tid.getValue() + ENTRA_ISSUER_SUFFIX);
	}

	/**
	 * Whether {@code value} is a whole lowercase GUID, the pattern
	 * {@code [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}}.
	 */
	static boolean isLowercaseGuid(@NonNull String value) {
		if (value.length() != GUID_LENGTH)
			return false;

		for (int index = 0; index < GUID_LENGTH; ++index) {
			char character = value.charAt(index);
			boolean dash = index == 8 || index == 13 || index == 18 || index == 23;

			if (dash ? character != '-' : !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')))
				return false;
		}

		return true;
	}

	private void checkAudience(@NonNull RegisteredClaims claims) throws JoseFailure {
		Set<String> audiences = this.expectedAudiences;

		if (audiences == null)
			return;
		if (claims.audiences().isEmpty())
			throw new JoseFailure(JoseException.Reason.MISSING_CLAIM);

		for (String audience : claims.audiences())
			if (audiences.contains(audience))
				return;

		throw new JoseFailure(JoseException.Reason.AUDIENCE_MISMATCH);
	}

	private void checkTime(@NonNull RegisteredClaims claims,
												 @NonNull Instant now) throws JoseFailure {
		Instant expiresAt = claims.expiresAt();

		if (expiresAt == null && this.expirationRequired)
			throw new JoseFailure(JoseException.Reason.MISSING_CLAIM);
		if (expiresAt != null && !now.isBefore(expiresAt.plus(this.clockSkew)))
			throw new JoseFailure(JoseException.Reason.EXPIRED);

		Instant issuedAt = claims.issuedAt();
		if (issuedAt != null && issuedAt.isAfter(now.plus(this.clockSkew)))
			throw new JoseFailure(JoseException.Reason.ISSUED_IN_FUTURE);

		Instant notBefore = claims.notBefore();
		if (notBefore != null && now.isBefore(notBefore.minus(this.clockSkew)))
			throw new JoseFailure(JoseException.Reason.NOT_YET_VALID);
	}

	private void checkRequiredClaims(@NonNull RegisteredClaims claims) throws JoseFailure {
		Map<@NonNull String, @NonNull JsonValue> members = claims.claims().getMembers();

		for (String name : this.requiredClaims) {
			JsonValue value = members.get(name);
			if (value == null || value instanceof JsonNull)
				throw new JoseFailure(JoseException.Reason.MISSING_CLAIM);
		}
	}

	/**
	 * Returns the expected issuer.
	 *
	 * @return the issuer, compared exactly
	 */
	@NonNull
	public String getIssuer() {
		return this.issuer;
	}

	/**
	 * Returns the expected audiences.
	 *
	 * @return an unmodifiable set, or empty if any audience is accepted
	 */
	@NonNull
	public Optional<@NonNull Set<@NonNull String>> findExpectedAudiences() {
		return Optional.ofNullable(this.expectedAudiences);
	}

	/**
	 * Returns the claim names required besides {@code iss}, {@code exp} and, unless any audience is accepted,
	 * {@code aud}.
	 *
	 * @return an unmodifiable set
	 */
	@NonNull
	public Set<@NonNull String> getRequiredClaims() {
		return this.requiredClaims;
	}

	/**
	 * Returns the clock skew the time checks allow.
	 *
	 * @return the skew, zero or positive
	 */
	@NonNull
	public Duration getClockSkew() {
		return this.clockSkew;
	}

	/**
	 * Describes the policy. The issuer and audiences are configuration, not token content.
	 *
	 * @return the settings
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{issuer=" + this.issuer + ", expectedAudiences="
				+ (this.expectedAudiences == null ? "any" : new TreeSet<>(this.expectedAudiences)) + ", requiredClaims="
				+ new TreeSet<>(this.requiredClaims) + ", clockSkew=" + this.clockSkew + "}";
	}
}
