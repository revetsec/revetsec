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

package com.revetsec.internal;

import com.revetsec.internal.Limit.Unit;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.time.Duration;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * The R8 limits registry: one {@link Limit} per row, with the values approved at gate 5 (M1 plan, "Limits
 * registry") and the two rows added at gate 8 (G8-10). {@code FrozenLimitsTests} pins every row.
 * <p>
 * Every row is here, including rows whose consumers arrive in later milestones. A builder checks each setting with
 * the row's {@code require} method, and takes its default from the row.
 * <p>
 * <strong>Units.</strong> Sizes are bytes ({@link Unit#BYTES}; KiB = 1,024 and MiB = 1,048,576), lengths of Java
 * strings are UTF-16 code units ({@link Unit#CHARACTERS}), counts and nesting depths are {@link Unit#COUNT}, and
 * times are {@link Duration}s ({@link Unit#DURATION}). The JSON rows use the codec's conventions: depth counts a
 * scalar or empty container as 1 and each enclosing container as one more (M1 plan G7-6), and the exponent row
 * bounds the magnitude of the adjusted decimal exponent.
 * <p>
 * <strong>Zero</strong> is permitted only by three rows: {@link #JWKS_MAXIMUM_STALENESS} (never serve a stale key
 * set), {@link #CLIENT_CREDENTIALS_RENEW_BEFORE} (renew only at expiry) and {@link #JOSE_CLOCK_SKEW} (compare times
 * exactly). Every other row rejects zero and negative values.
 * <p>
 * <strong>Internal rows.</strong> The JSON structural rows other than {@link #SCIM_JSON_NODES} are fixed in 1.0.0:
 * the codec's profiles use their defaults, and their floors bind only if a row is ever made configurable.
 * <p>
 * <strong>Cross-field rules</strong>, checked at {@code build()} after each row's own check:
 * <ul>
 *   <li>requestTimeout &le; totalDeadline ({@link #requireRequestTimeoutWithinTotalDeadline});</li>
 *   <li>JWKS minimum TTL &le; default TTL &le; maximum TTL ({@link #requireJwksTimeToLiveOrder});</li>
 *   <li>JWKS unknown-kid cooldown &le; minimum TTL ({@link #requireJwksCooldownWithinMinimumTimeToLive}; M2-8, the
 *   owner's decision of 2026-09-28), so the limit of two key-set requests per cooldown holds back no refresh after
 *   expiry unless fetches were cut short;</li>
 *   <li>renewBefore &lt; maximumCacheDuration ({@link #requireRenewBeforeBelowMaximumCacheDuration});</li>
 *   <li>fallbackCacheDuration &le; maximumCacheDuration ({@link #requireFallbackWithinMaximumCacheDuration}).</li>
 * </ul>
 * <strong>Runtime rule for client-credentials tokens</strong> (gate 5, G5-3): a cached token's lifetime is its
 * {@code expires_in} capped at maximumCacheDuration, or fallbackCacheDuration when {@code expires_in} is absent
 * ({@link #clientCredentialsCacheLifetime}), so with the cross-field rule above no lifetime exceeds
 * maximumCacheDuration. The token is renewed min(renewBefore, lifetime / 2) before it expires
 * ({@link #clientCredentialsRenewalLeadTime}). So a 30-second token under the 60-second default is renewed after
 * 15 seconds, not re-fetched on every call.
 * <p>
 * The total deadline covers every exchange in one public call, and the per-request timeout each exchange (G5-5).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class Limits {
	private static final long KIB = 1_024L;
	private static final long MIB = 1_024L * KIB;

	// HTTP (R12)

	/**
	 * Response body of a token, metadata (discovery), UserInfo or introspection request: 256 KiB [16 KiB, 4 MiB].
	 */
	public static final Limit HTTP_RESPONSE_BODY_SIZE = Limit.fromAmounts("HTTP response body size", Unit.BYTES,
			256 * KIB, 16 * KIB, 4 * MIB);

	/**
	 * Response body of a JWKS request: 256 KiB [16 KiB, 4 MiB].
	 */
	public static final Limit JWKS_RESPONSE_BODY_SIZE = Limit.fromAmounts("JWKS response body size", Unit.BYTES,
			256 * KIB, 16 * KIB, 4 * MIB);

	/**
	 * Keys in one JWKS: 100 [1, 1,000].
	 */
	public static final Limit JWKS_KEY_COUNT = Limit.fromAmounts("JWKS key count", Unit.COUNT, 100, 1, 1_000);

	/**
	 * Body of a non-2xx response: 16 KiB [1 KiB, 64 KiB]. A larger or encoded error body is dropped unread and the
	 * status is kept.
	 */
	public static final Limit HTTP_ERROR_BODY_SIZE = Limit.fromAmounts("HTTP error body size", Unit.BYTES, 16 * KIB,
			KIB, 64 * KIB);

	/**
	 * One HTTP exchange: 10 s [1 s, 60 s]. Must not exceed {@link #TOTAL_DEADLINE}'s setting.
	 */
	public static final Limit REQUEST_TIMEOUT = Limit.fromDurations("Request timeout", Duration.ofSeconds(10),
			Duration.ofSeconds(1), Duration.ofSeconds(60));

	/**
	 * Every exchange in one public call together: 15 s [1 s, 120 s].
	 */
	public static final Limit TOTAL_DEADLINE = Limit.fromDurations("Total deadline", Duration.ofSeconds(15),
			Duration.ofSeconds(1), Duration.ofSeconds(120));

	// JOSE

	/**
	 * A compact JWS or JWT serialization: 64 KiB [8 KiB, 1 MiB]. The compact form is ASCII, so its length in
	 * characters equals its size in bytes.
	 */
	public static final Limit COMPACT_JWT_SIZE = Limit.fromAmounts("Compact JWT size", Unit.BYTES, 64 * KIB, 8 * KIB,
			MIB);

	/**
	 * Clock skew allowed when a JWT's {@code exp}, {@code nbf} and {@code iat} are compared with the current time:
	 * 60 s [0, 5 min] (G8-10). Zero compares the times exactly.
	 */
	public static final Limit JOSE_CLOCK_SKEW = Limit.fromDurations("JOSE clock skew", Duration.ofSeconds(60),
			Duration.ZERO, Duration.ofMinutes(5));

	/**
	 * Oldest ID token accepted, measured from its {@code iat}: 5 min [1 min, 1 h] (G8-10). The age rule includes the
	 * clock skew: a token is too old when now - iat &gt; maximum age + skew.
	 */
	public static final Limit ID_TOKEN_MAXIMUM_AGE = Limit.fromDurations("ID token maximum age", Duration.ofMinutes(5),
			Duration.ofMinutes(1), Duration.ofHours(1));

	// JSON (internal in 1.0.0, except SCIM_JSON_NODES)

	/**
	 * JSON nesting depth for protocol documents (metadata, JWKS, token responses, JOSE): 32 [8, 64]. Internal.
	 */
	public static final Limit JSON_DEPTH_PROTOCOL = Limit.fromAmounts("JSON depth for protocol documents",
			Unit.COUNT, 32, 8, 64);

	/**
	 * JSON nesting depth for SCIM documents: 64 [8, 64]. Internal.
	 */
	public static final Limit JSON_DEPTH_SCIM = Limit.fromAmounts("JSON depth for SCIM documents", Unit.COUNT, 64, 8,
			64);

	/**
	 * JSON values in one protocol document: 100,000 [1,000, 1,000,000]. Internal.
	 */
	public static final Limit JSON_NODES = Limit.fromAmounts("JSON node count", Unit.COUNT, 100_000, 1_000,
			1_000_000);

	/**
	 * One JSON string, after unescaping: 1 Mi characters [16 Ki, 4 Mi]. Internal. The floor leaves room for
	 * {@code x5c} certificate chains.
	 */
	public static final Limit JSON_STRING_LENGTH = Limit.fromAmounts("JSON string length", Unit.CHARACTERS, MIB,
			16 * KIB, 4 * MIB);

	/**
	 * One JSON number's text: 1,024 characters [32, 4,096]. Internal.
	 */
	public static final Limit JSON_NUMBER_LENGTH = Limit.fromAmounts("JSON number length", Unit.CHARACTERS, 1_024,
			32, 4_096);

	/**
	 * Magnitude of a JSON number's adjusted decimal exponent: 10,000 [32, 100,000]. Internal. A floor of 32 keeps
	 * ordinary values such as {@code 123456789012} parseable.
	 */
	public static final Limit JSON_NUMBER_EXPONENT_MAGNITUDE = Limit.fromAmounts("JSON number exponent magnitude",
			Unit.COUNT, 10_000, 32, 100_000);

	// OAuth authorization response (R7)

	/**
	 * One authorization-response parameter: 8 KiB [2 KiB, 32 KiB].
	 */
	public static final Limit AUTHORIZATION_RESPONSE_PARAMETER_SIZE = Limit.fromAmounts(
			"Authorization-response parameter size", Unit.BYTES, 8 * KIB, 2 * KIB, 32 * KIB);

	/**
	 * A whole authorization-response query or form body: 32 KiB [4 KiB, 128 KiB].
	 */
	public static final Limit AUTHORIZATION_RESPONSE_QUERY_SIZE = Limit.fromAmounts(
			"Authorization-response query size", Unit.BYTES, 32 * KIB, 4 * KIB, 128 * KIB);

	// Bearer presentation and challenges

	/** Maximum bearer credential size, independent of the fixed header prefix allowance. */
	public static final Limit BEARER_CREDENTIAL_SIZE = Limit.fromAmounts("Bearer credential size", Unit.BYTES,
			64 * KIB, 8 * KIB, MIB);

	/** Maximum rendered WWW-Authenticate Bearer field size, including escaping. */
	public static final Limit BEARER_CHALLENGE_SIZE = Limit.fromAmounts("Bearer challenge size", Unit.BYTES,
			8 * KIB, KIB, 64 * KIB);

	// SAML and XML

	/**
	 * A decoded {@code SAMLResponse}: 256 KiB [16 KiB, 4 MiB]. The raw parameter is bounded at 4 * ceil(cap / 3)
	 * plus a whitespace allowance before decoding (G5-5).
	 */
	public static final Limit SAML_RESPONSE_DECODED_SIZE = Limit.fromAmounts("Decoded SAMLResponse size", Unit.BYTES,
			256 * KIB, 16 * KIB, 4 * MIB);

	/**
	 * XML element nesting depth: 64 [16, 256].
	 */
	public static final Limit XML_DEPTH = Limit.fromAmounts("XML depth", Unit.COUNT, 64, 16, 256);

	/**
	 * Attributes on one XML element: 64 [16, 256].
	 */
	public static final Limit XML_ATTRIBUTES_PER_ELEMENT = Limit.fromAmounts("XML attributes per element",
			Unit.COUNT, 64, 16, 256);

	/**
	 * XML elements in one document, counted by Revetsec during the parse: 10,000 [1,000, 100,000].
	 */
	public static final Limit XML_ELEMENTS = Limit.fromAmounts("XML element count", Unit.COUNT, 10_000, 1_000,
			100_000);

	/**
	 * One XML name: 1,000 characters [64, 10,000].
	 */
	public static final Limit XML_NAME_LENGTH = Limit.fromAmounts("XML name length", Unit.CHARACTERS, 1_000, 64,
			10_000);

	/**
	 * A SAML metadata document: 1 MiB [64 KiB, 8 MiB].
	 */
	public static final Limit SAML_METADATA_SIZE = Limit.fromAmounts("SAML metadata size", Unit.BYTES, MIB, 64 * KIB,
			8 * MIB);

	/**
	 * An inflated Redirect-binding payload (SLO, M8b; gate 15): 64 KiB [4 KiB, 256 KiB].
	 */
	public static final Limit SAML_REDIRECT_INFLATED_SIZE = Limit.fromAmounts("Inflated Redirect-binding payload size",
			Unit.BYTES, 64 * KIB, 4 * KIB, 256 * KIB);

	/**
	 * A Redirect-binding {@code SAMLRequest} or {@code SAMLResponse} parameter before Base64 decoding (SLO, M8b;
	 * gate 15): 16 KiB [2 KiB, 64 KiB].
	 */
	public static final Limit SAML_REDIRECT_PARAMETER_SIZE = Limit.fromAmounts("Redirect-binding parameter size",
			Unit.BYTES, 16 * KIB, 2 * KIB, 64 * KIB);

	// SCIM

	/**
	 * A SCIM request body: 1 MiB [16 KiB, 10 MiB].
	 */
	public static final Limit SCIM_BODY_SIZE = Limit.fromAmounts("SCIM body size", Unit.BYTES, MIB, 16 * KIB,
			10 * MIB);

	/**
	 * Operations in one SCIM PATCH: 1,000 [1, 10,000].
	 */
	public static final Limit SCIM_PATCH_OPERATIONS = Limit.fromAmounts("SCIM PATCH operation count", Unit.COUNT,
			1_000, 1, 10_000);

	/**
	 * JSON values in one SCIM document: 100,000 [1,000, 1,000,000]. The one public JSON row (G5-4).
	 */
	public static final Limit SCIM_JSON_NODES = Limit.fromAmounts("SCIM JSON node count", Unit.COUNT, 100_000, 1_000,
			1_000_000);

	/**
	 * A SCIM filter expression: 4,096 characters [256, 65,536].
	 */
	public static final Limit SCIM_FILTER_LENGTH = Limit.fromAmounts("SCIM filter length", Unit.CHARACTERS, 4_096,
			256, 65_536);

	/**
	 * Nesting depth of a SCIM filter's syntax tree: 16 [4, 64].
	 */
	public static final Limit SCIM_FILTER_DEPTH = Limit.fromAmounts("SCIM filter depth", Unit.COUNT, 16, 4, 64);

	/**
	 * Nodes in a SCIM filter's syntax tree: 128 [8, 4,096].
	 */
	public static final Limit SCIM_FILTER_NODES = Limit.fromAmounts("SCIM filter node count", Unit.COUNT, 128, 8,
			4_096);

	// Pending state and sealing (D8)

	/**
	 * How long a pending authorization or authentication stays valid: 15 min [1 min, 60 min] (G5-6).
	 */
	public static final Limit PENDING_STATE_LIFETIME = Limit.fromDurations("Pending-state lifetime",
			Duration.ofMinutes(15), Duration.ofMinutes(1), Duration.ofMinutes(60));

	/** Live entries in the one-node pending-authorization store: 1,024 [16, 65,536]. */
	public static final Limit PENDING_AUTHORIZATION_STORE_ENTRIES = Limit.fromAmounts(
			"Pending-authorization store entries", Unit.COUNT, 1_024, 16, 65_536);

	/** Charged UTF-8 bytes in the one-node pending-authorization store: 4 MiB [64 KiB, 64 MiB]. */
	public static final Limit PENDING_AUTHORIZATION_STORE_BYTES = Limit.fromAmounts(
			"Pending-authorization store bytes", Unit.BYTES, 4L * 1_024 * 1_024,
			64L * 1_024, 64L * 1_024 * 1_024);

	/** UTF-8 bytes in one opaque pending record: 8 KiB [1 KiB, 64 KiB]. */
	public static final Limit PENDING_AUTHORIZATION_RECORD_BYTES = Limit.fromAmounts(
			"Pending-authorization record bytes", Unit.BYTES, 8 * 1_024, 1_024, 64 * 1_024);

	/**
	 * StateSealer's maximumSealedLength: 3,800 characters [1,024, 16,384]. Checked before any decoding.
	 */
	public static final Limit STATE_SEALER_MAXIMUM_SEALED_LENGTH = Limit.fromAmounts(
			"StateSealer maximum sealed length", Unit.CHARACTERS, 3_800, 1_024, 16_384);

	/**
	 * The lifetime argument of one {@code seal} call: no default [1 s, 400 days].
	 */
	public static final Limit SEAL_LIFETIME = Limit.fromDurations("Seal lifetime", null, Duration.ofSeconds(1),
			Duration.ofDays(400));

	// JWKS caching

	/**
	 * Minimum time between refetches triggered by an unknown {@code kid}: 30 s [1 s, 10 min].
	 */
	public static final Limit JWKS_UNKNOWN_KEY_ID_COOLDOWN = Limit.fromDurations("JWKS unknown-kid cooldown",
			Duration.ofSeconds(30), Duration.ofSeconds(1), Duration.ofMinutes(10));

	/**
	 * Shortest time a fetched key set is cached, whatever the response's cache headers say: 1 min [30 s, 1 h].
	 */
	public static final Limit JWKS_MINIMUM_TIME_TO_LIVE = Limit.fromDurations("JWKS minimum time to live",
			Duration.ofMinutes(1), Duration.ofSeconds(30), Duration.ofHours(1));

	/**
	 * Time a fetched key set is cached when the response carries neither {@code max-age} nor {@code Expires}: 10 min
	 * [30 s, 24 h] (G5-4). A malformed or conflicting {@code Cache-Control}, {@code no-store}, {@code no-cache}, or an
	 * invalid or repeated {@code Expires} gives {@link #JWKS_MINIMUM_TIME_TO_LIVE} instead.
	 */
	public static final Limit JWKS_DEFAULT_TIME_TO_LIVE = Limit.fromDurations("JWKS default time to live",
			Duration.ofMinutes(10), Duration.ofSeconds(30), Duration.ofHours(24));

	/**
	 * Longest time a fetched key set is cached, whatever the response's cache headers say: 6 h [1 min, 24 h].
	 */
	public static final Limit JWKS_MAXIMUM_TIME_TO_LIVE = Limit.fromDurations("JWKS maximum time to live",
			Duration.ofHours(6), Duration.ofMinutes(1), Duration.ofHours(24));

	/**
	 * How long an expired key set may still be served while refreshes fail: 12 h [0, 24 h]. Zero never serves a
	 * stale key set.
	 */
	public static final Limit JWKS_MAXIMUM_STALENESS = Limit.fromDurations("JWKS maximum staleness",
			Duration.ofHours(12), Duration.ZERO, Duration.ofHours(24));

	// OAuth authorization-server discovery (M3)

	/** Minimum metadata cache lifetime: 1 min [30 s, 1 h]. */
	public static final Limit DISCOVERY_MINIMUM_TIME_TO_LIVE = Limit.fromDurations(
			"Discovery minimum time to live", Duration.ofMinutes(1), Duration.ofSeconds(30), Duration.ofHours(1));

	/** Metadata cache lifetime without usable freshness headers: 10 min [30 s, 24 h]. */
	public static final Limit DISCOVERY_DEFAULT_TIME_TO_LIVE = Limit.fromDurations(
			"Discovery default time to live", Duration.ofMinutes(10), Duration.ofSeconds(30), Duration.ofHours(24));

	/** Maximum metadata cache lifetime: 6 h [1 min, 24 h]. */
	public static final Limit DISCOVERY_MAXIMUM_TIME_TO_LIVE = Limit.fromDurations(
			"Discovery maximum time to live", Duration.ofHours(6), Duration.ofMinutes(1), Duration.ofHours(24));

	/** Window for the outcome-independent two-flight discovery ceiling: 30 s [1 s, 10 min]. */
	public static final Limit DISCOVERY_COOLDOWN = Limit.fromDurations(
			"Discovery cooldown", Duration.ofSeconds(30), Duration.ofSeconds(1), Duration.ofMinutes(10));

	// Client credentials (G5-3)

	/**
	 * Cache lifetime of a client-credentials token whose response has no {@code expires_in}: 5 min [10 s, 1 h], and
	 * at most {@link #CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION} ({@link #requireFallbackWithinMaximumCacheDuration}).
	 */
	public static final Limit CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION = Limit.fromDurations(
			"Client-credentials fallback cache duration", Duration.ofMinutes(5), Duration.ofSeconds(10),
			Duration.ofHours(1));

	/**
	 * Upper bound on the cache lifetime of a client-credentials token: 24 h [1 min, 24 h]. A longer
	 * {@code expires_in} is capped at it, and {@code build()} rejects a
	 * {@link #CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION} longer than it
	 * ({@link #requireFallbackWithinMaximumCacheDuration}).
	 */
	public static final Limit CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION = Limit.fromDurations(
			"Client-credentials maximum cache duration", Duration.ofHours(24), Duration.ofMinutes(1),
			Duration.ofHours(24));

	/**
	 * How long before expiry a cached client-credentials token is renewed, before the lifetime / 2 bound: 60 s
	 * [0, 10 min]. Zero renews only at expiry.
	 */
	public static final Limit CLIENT_CREDENTIALS_RENEW_BEFORE = Limit.fromDurations("Client-credentials renewBefore",
			Duration.ofSeconds(60), Duration.ZERO, Duration.ofMinutes(10));

	/** OAuth client assertion lifetime: 60 s [1 s, 300 s], with exact whole seconds. */
	public static final Limit CLIENT_ASSERTION_LIFETIME = Limit.fromDurations("Client assertion lifetime",
			Duration.ofSeconds(60), Duration.ofSeconds(1), Duration.ofSeconds(300));

	private static final List<Limit> ALL = List.of(
			HTTP_RESPONSE_BODY_SIZE,
			JWKS_RESPONSE_BODY_SIZE,
			JWKS_KEY_COUNT,
			HTTP_ERROR_BODY_SIZE,
			REQUEST_TIMEOUT,
			TOTAL_DEADLINE,
			COMPACT_JWT_SIZE,
			JOSE_CLOCK_SKEW,
			ID_TOKEN_MAXIMUM_AGE,
			JSON_DEPTH_PROTOCOL,
			JSON_DEPTH_SCIM,
			JSON_NODES,
			JSON_STRING_LENGTH,
			JSON_NUMBER_LENGTH,
			JSON_NUMBER_EXPONENT_MAGNITUDE,
			AUTHORIZATION_RESPONSE_PARAMETER_SIZE,
			AUTHORIZATION_RESPONSE_QUERY_SIZE,
			BEARER_CREDENTIAL_SIZE,
			BEARER_CHALLENGE_SIZE,
			SAML_RESPONSE_DECODED_SIZE,
			XML_DEPTH,
			XML_ATTRIBUTES_PER_ELEMENT,
			XML_ELEMENTS,
			XML_NAME_LENGTH,
			SAML_METADATA_SIZE,
			SAML_REDIRECT_INFLATED_SIZE,
			SAML_REDIRECT_PARAMETER_SIZE,
			SCIM_BODY_SIZE,
			SCIM_PATCH_OPERATIONS,
			SCIM_JSON_NODES,
			SCIM_FILTER_LENGTH,
			SCIM_FILTER_DEPTH,
			SCIM_FILTER_NODES,
			PENDING_STATE_LIFETIME,
			PENDING_AUTHORIZATION_STORE_ENTRIES,
			PENDING_AUTHORIZATION_STORE_BYTES,
			PENDING_AUTHORIZATION_RECORD_BYTES,
			STATE_SEALER_MAXIMUM_SEALED_LENGTH,
			SEAL_LIFETIME,
			JWKS_UNKNOWN_KEY_ID_COOLDOWN,
			JWKS_MINIMUM_TIME_TO_LIVE,
			JWKS_DEFAULT_TIME_TO_LIVE,
			JWKS_MAXIMUM_TIME_TO_LIVE,
			JWKS_MAXIMUM_STALENESS,
			DISCOVERY_MINIMUM_TIME_TO_LIVE,
			DISCOVERY_DEFAULT_TIME_TO_LIVE,
			DISCOVERY_MAXIMUM_TIME_TO_LIVE,
			DISCOVERY_COOLDOWN,
			CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION,
			CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION,
			CLIENT_CREDENTIALS_RENEW_BEFORE,
			CLIENT_ASSERTION_LIFETIME);

	private Limits() {
		// Constants and static helpers only.
	}

	/**
	 * Returns every row, in registry order.
	 *
	 * @return an unmodifiable list of every row
	 */
	@NonNull
	public static List<@NonNull Limit> all() {
		return ALL;
	}

	/**
	 * Checks that the per-request timeout does not exceed the total deadline. Call it after each value's own check.
	 *
	 * @param requestTimeout the per-request timeout setting
	 * @param totalDeadline  the total deadline setting
	 * @throws IllegalArgumentException if {@code requestTimeout > totalDeadline}
	 */
	public static void requireRequestTimeoutWithinTotalDeadline(@NonNull Duration requestTimeout,
																															@NonNull Duration totalDeadline) {
		requireNonNull(requestTimeout);
		requireNonNull(totalDeadline);

		if (requestTimeout.compareTo(totalDeadline) > 0)
			throw new IllegalArgumentException("Request timeout must not exceed the total deadline.");
	}

	/**
	 * Checks that the JWKS time-to-live settings are ordered. Call it after each value's own check.
	 *
	 * @param minimumTimeToLive the minimum TTL setting
	 * @param defaultTimeToLive the default TTL setting
	 * @param maximumTimeToLive the maximum TTL setting
	 * @throws IllegalArgumentException unless {@code minimum <= default <= maximum}
	 */
	public static void requireJwksTimeToLiveOrder(@NonNull Duration minimumTimeToLive,
																								@NonNull Duration defaultTimeToLive,
																								@NonNull Duration maximumTimeToLive) {
		requireNonNull(minimumTimeToLive);
		requireNonNull(defaultTimeToLive);
		requireNonNull(maximumTimeToLive);

		if (minimumTimeToLive.compareTo(defaultTimeToLive) > 0 || defaultTimeToLive.compareTo(maximumTimeToLive) > 0)
			throw new IllegalArgumentException("JWKS time to live must satisfy minimum <= default <= maximum.");
	}

	/**
	 * Checks that the JWKS unknown-kid cooldown is no longer than the minimum TTL. The cooldown is also the window of
	 * the limit of two key-set requests of any kind; with it no longer than the minimum TTL, every successful fetch
	 * leaves a key set fresh for at least one cooldown, so that limit holds back no refresh after expiry unless fetches
	 * were cut short. Call it after each value's own check.
	 *
	 * @param unknownKeyIdCooldown the unknown-kid cooldown setting
	 * @param minimumTimeToLive    the minimum TTL setting
	 * @throws IllegalArgumentException if {@code unknownKeyIdCooldown > minimumTimeToLive}
	 */
	public static void requireJwksCooldownWithinMinimumTimeToLive(@NonNull Duration unknownKeyIdCooldown,
																												@NonNull Duration minimumTimeToLive) {
		requireNonNull(unknownKeyIdCooldown);
		requireNonNull(minimumTimeToLive);

		if (unknownKeyIdCooldown.compareTo(minimumTimeToLive) > 0)
			throw new IllegalArgumentException("JWKS unknown-kid cooldown must not exceed the JWKS minimum time to live.");
	}

	/**
	 * Checks the discovery cache lifetime order and its two-attempt cooldown window.
	 *
	 * @param minimumTimeToLive the minimum cache lifetime
	 * @param defaultTimeToLive the fallback cache lifetime
	 * @param maximumTimeToLive the maximum cache lifetime
	 * @param cooldown the discovery attempt window
	 * @throws IllegalArgumentException unless minimum is at most default and maximum, and cooldown is at most minimum
	 */
	public static void requireDiscoveryTimeToLiveOrder(@NonNull Duration minimumTimeToLive,
			@NonNull Duration defaultTimeToLive, @NonNull Duration maximumTimeToLive,
			@NonNull Duration cooldown) {
		requireNonNull(minimumTimeToLive);
		requireNonNull(defaultTimeToLive);
		requireNonNull(maximumTimeToLive);
		requireNonNull(cooldown);
		if (minimumTimeToLive.compareTo(defaultTimeToLive) > 0
				|| defaultTimeToLive.compareTo(maximumTimeToLive) > 0)
			throw new IllegalArgumentException("Discovery time to live must satisfy minimum <= default <= maximum.");
		if (cooldown.compareTo(minimumTimeToLive) > 0)
			throw new IllegalArgumentException("Discovery cooldown must not exceed minimum time to live.");
	}

	/**
	 * Checks that renewBefore is shorter than the maximum cache duration. Call it after each value's own check.
	 *
	 * @param renewBefore          the renewBefore setting
	 * @param maximumCacheDuration the maximumCacheDuration setting
	 * @throws IllegalArgumentException unless {@code renewBefore < maximumCacheDuration}
	 */
	public static void requireRenewBeforeBelowMaximumCacheDuration(@NonNull Duration renewBefore,
																																 @NonNull Duration maximumCacheDuration) {
		requireNonNull(renewBefore);
		requireNonNull(maximumCacheDuration);

		if (renewBefore.compareTo(maximumCacheDuration) >= 0)
			throw new IllegalArgumentException("Client-credentials renewBefore must be shorter than the maximum cache "
					+ "duration.");
	}

	/**
	 * Checks that the fallback cache duration does not exceed the maximum cache duration, so a token without
	 * {@code expires_in} is never cached longer than the maximum. Call it after each value's own check.
	 *
	 * @param fallbackCacheDuration the fallbackCacheDuration setting
	 * @param maximumCacheDuration  the maximumCacheDuration setting
	 * @throws IllegalArgumentException if {@code fallbackCacheDuration > maximumCacheDuration}
	 */
	public static void requireFallbackWithinMaximumCacheDuration(@NonNull Duration fallbackCacheDuration,
																															 @NonNull Duration maximumCacheDuration) {
		requireNonNull(fallbackCacheDuration);
		requireNonNull(maximumCacheDuration);

		if (fallbackCacheDuration.compareTo(maximumCacheDuration) > 0)
			throw new IllegalArgumentException("Client-credentials fallback cache duration must not exceed the maximum "
					+ "cache duration.");
	}

	/**
	 * Returns how long a client-credentials token is cached: its {@code expires_in} capped at the maximum cache
	 * duration, or the fallback cache duration when the response has no {@code expires_in}. {@code build()} has
	 * already checked the fallback against the maximum ({@link #requireFallbackWithinMaximumCacheDuration}), so the
	 * result never exceeds the maximum cache duration.
	 *
	 * @param expiresIn            the token response's {@code expires_in}, already validated as non-negative, or
	 *                             {@code null} if absent
	 * @param fallbackCacheDuration the fallbackCacheDuration setting
	 * @param maximumCacheDuration  the maximumCacheDuration setting
	 * @return the token's cache lifetime
	 * @throws IllegalArgumentException if {@code expiresIn} is negative
	 */
	@NonNull
	public static Duration clientCredentialsCacheLifetime(@Nullable Duration expiresIn,
																												@NonNull Duration fallbackCacheDuration,
																												@NonNull Duration maximumCacheDuration) {
		requireNonNull(fallbackCacheDuration);
		requireNonNull(maximumCacheDuration);

		if (expiresIn == null)
			return fallbackCacheDuration;

		if (expiresIn.isNegative())
			throw new IllegalArgumentException("A token lifetime must not be negative.");

		return expiresIn.compareTo(maximumCacheDuration) > 0 ? maximumCacheDuration : expiresIn;
	}

	/**
	 * Returns how long before its expiry a cached client-credentials token is renewed: min(renewBefore,
	 * lifetime / 2).
	 *
	 * @param renewBefore   the renewBefore setting
	 * @param tokenLifetime the token's cache lifetime ({@link #clientCredentialsCacheLifetime})
	 * @return the renewal lead time; never longer than half the token's lifetime
	 * @throws IllegalArgumentException if either argument is negative
	 */
	@NonNull
	public static Duration clientCredentialsRenewalLeadTime(@NonNull Duration renewBefore,
																												 @NonNull Duration tokenLifetime) {
		requireNonNull(renewBefore);
		requireNonNull(tokenLifetime);

		if (renewBefore.isNegative() || tokenLifetime.isNegative())
			throw new IllegalArgumentException("Durations must not be negative.");

		Duration halfLifetime = tokenLifetime.dividedBy(2);
		return renewBefore.compareTo(halfLifetime) < 0 ? renewBefore : halfLifetime;
	}
}
