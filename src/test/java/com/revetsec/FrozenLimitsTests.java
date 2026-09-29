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

package com.revetsec;

import com.revetsec.internal.Limit;
import com.revetsec.internal.Limit.Unit;
import com.revetsec.internal.Limits;
import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.Ed25519PublicKeys;
import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.internal.crypto.Hmac;
import com.revetsec.internal.crypto.KeyRejectedException;
import com.revetsec.internal.crypto.RsaPublicKeys;
import com.revetsec.internal.http.HttpExchangeRequest;
import com.revetsec.internal.http.ResponseProfile;
import com.revetsec.internal.jose.JwkParser;
import com.revetsec.internal.jose.JwtClaimsPolicy;
import com.revetsec.internal.jose.TestClaims;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JoseObserver;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JsonWebKeySetUnavailableException;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.Jwt;
import com.revetsec.jose.JwtValidator;
import com.revetsec.jose.RemoteJsonWebKeySource;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.testing.JsonText;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestHttpsServer.Response;
import com.revetsec.testing.TestHttpsServer.Script;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;
import java.util.function.IntFunction;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * Freezes the R8 limits registry as approved at gate 5 (M1 plan, "Limits registry", G5-1 to G5-6, and the
 * cross-field rule added under "Results"; exit criterion 16) and extended at gate 8 (G8-10: the JOSE clock skew and
 * ID token maximum age rows; M2 exit criterion 19).
 * <p>
 * {@link #APPROVED_ROWS} is a literal transcription of the plan's table, row by row, in {@link Limits#all()} order
 * (which lists the two StateSealer rows before the JWKS rows, where the plan lists them last): the constant, the name
 * rejection messages print, the unit, the default, the floor, the cap and whether zero is permitted. Every
 * test here reads its numbers from that table, never from {@link Limit}'s own getters, so a change to any row, an
 * added or removed row, or a consumer that stops enforcing a row fails loudly. Changing a value is a change to an
 * approved gate item: update the plan first, then this table.
 * <p>
 * The tests also pin what the M1 consumers do with the rows: the JSON profiles stay within the public model's caps
 * (G7-6) and take the registry's defaults, {@link JsonLimits}, {@link StateSealer.Builder#maximumSealedLength(Integer)}
 * and {@link StateSealer#seal(String, String, Duration)} reject every out-of-range setting, the HTTP helper's defaults
 * come from the registry, and the five cross-field rules (M2-8's cooldown rule among them) and the G5-3 runtime rule
 * hold at their boundaries.
 * <p>
 * <strong>JOSE (M2 exit criterion 19).</strong> The M2 consumers reject every out-of-range value: the
 * {@link JwtValidator.Builder}'s clock skew and token length, and every limit of the
 * {@link RemoteJsonWebKeySource.Builder}, each with its own row's message, and each accepted value takes effect.
 * Beside the rows, the plan fixes policy constants that are not rows ("Limits registry additions"), transcribed here
 * as the secure-defaults block and the JOSE constants:
 * <ul>
 *   <li>the {@link JwtValidator} defaults: RS256 alone, a {@code typ} of JWT or none, {@code iss}, {@code exp} and
 *   {@code aud} always required, and the skew and token length of their rows. They are private, so they are pinned
 *   through {@link JwtValidator#validate(String)};</li>
 *   <li>the key and signature shapes: RSA moduli of 2,048 to 16,384 bits, odd and minimal, with an odd exponent from
 *   65,537 to below 2^32; the ROCA primes 3 to 167; key IDs of 1 to 256 characters; EC coordinates of 32, 48 and 66
 *   octets; Ed25519 keys of 32 octets; ECDSA signatures of 64, 96 and 132 octets, Ed25519 signatures of 64, and RS* and
 *   PS* signatures of 256 to 2,048 octets, all checked before a key is selected; HMAC secrets at least as long as the
 *   hash; and at most one candidate key per token. The public constants of {@code internal.crypto} and
 *   {@code internal.jose} are compared with the transcription, and each shape is also pinned through
 *   {@link JsonWebKeySet#fromJson(String)} or {@link JwtValidator#validate(String)};</li>
 *   <li>the key set's failure backoff, {@code min(cooldown * 2^(n-1), cap)} with
 *   {@code cap = max(cooldown, min(10 * cooldown, 10 min))}, the decay of the failure count by one per full cap
 *   interval without a failure, and the ceiling of two fetches per cooldown (M2-8). They live in a package-private
 *   class, so they are pinned through {@link RemoteJsonWebKeySource#warmUp()} and
 *   {@link JoseObserver#didSuppressJsonWebKeySetFetch(URI, Duration)}, against a local HTTPS server and a
 *   {@link TestClock}.</li>
 * </ul>
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class FrozenLimitsTests {
	private static final long KIB = 1_024L;
	private static final long MIB = 1_024L * KIB;
	private static final boolean ZERO_ALLOWED = true;
	private static final boolean ZERO_REJECTED = false;

	/**
	 * The secure defaults of {@link JwtValidator} (M2 plan, "Limits registry additions"; M2-4): the algorithms it
	 * allows, the {@code typ} values it accepts when none is configured (an absent {@code typ} included, because
	 * {@code typeRequired} defaults to false), and the claims it always requires. Its clock skew and maximum token
	 * length are the defaults of the JOSE_CLOCK_SKEW and COMPACT_JWT_SIZE rows.
	 */
	private static final Set<JwsAlgorithm> DEFAULT_ALLOWED_ALGORITHMS = Set.of(JwsAlgorithm.RS256);
	private static final List<String> DEFAULT_ACCEPTED_TYPES = List.of("JWT", "jwt", "application/jwt",
			"Application/JWT");
	private static final List<String> ALWAYS_REQUIRED_CLAIMS = List.of("iss", "exp", "aud");

	/**
	 * The JOSE policy constants (M2 plan, "Limits registry additions"; M2-6, M2-7, M2-8 and M2-11), which are not
	 * rows.
	 */
	private static final int RSA_MINIMUM_MODULUS_BITS = 2_048;
	private static final int RSA_MAXIMUM_MODULUS_BITS = 16_384;
	private static final int RSA_MINIMUM_SIGNATURE_OCTETS = 256;
	private static final int RSA_MAXIMUM_SIGNATURE_OCTETS = 2_048;
	private static final BigInteger RSA_MINIMUM_PUBLIC_EXPONENT = BigInteger.valueOf(65_537);
	private static final BigInteger RSA_PUBLIC_EXPONENT_LIMIT = BigInteger.TWO.pow(32);
	private static final int ROCA_LARGEST_PRIME = 167;
	private static final int ROCA_PRIME_COUNT = 38;
	private static final int MAXIMUM_KEY_ID_LENGTH = 256;
	/**
	 * Each EC curve's coordinate length and ECDSA signature length, in octets.
	 */
	private static final Map<String, List<Integer>> EC_CURVE_OCTETS = Map.of("P-256", List.of(32, 64), "P-384",
			List.of(48, 96), "P-521", List.of(66, 132));
	private static final int ED25519_KEY_OCTETS = 32;
	private static final int ED25519_SIGNATURE_OCTETS = 64;
	/**
	 * The shortest HMAC secret for each HS* algorithm, in octets: the hash length (RFC 7518 section 3.2).
	 */
	private static final Map<String, Integer> HMAC_MINIMUM_SECRET_OCTETS = Map.of("HS256", 32, "HS384", 48, "HS512",
			64);
	private static final int CANDIDATE_KEYS_PER_TOKEN = 1;
	private static final int BACKOFF_CAP_COOLDOWNS = 10;
	private static final Duration BACKOFF_CAP_LIMIT = Duration.ofMinutes(10);
	private static final int ATTEMPTS_PER_COOLDOWN = 2;
	private static final String ENTRA_ISSUER_TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0";

	private static final String ISSUER = "https://issuer.example.com";
	private static final String AUDIENCE = "https://api.example.com";
	private static final String KEY_ID = "key-1";
	private static final String UNKNOWN_KEY_ID = "unknown-key";
	private static final Instant NOW = Instant.parse("2026-09-27T12:00:00Z");
	private static final URI JWKS_URI = URI.create("https://issuer.example.com/jwks");
	private static final AtomicInteger NEXT_PATH = new AtomicInteger();

	private static @Nullable TestHttpsServer server;
	private static @Nullable HttpClient client;

	@BeforeAll
	static void startServer() throws IOException {
		server = TestHttpsServer.start();
		client = TestTls.httpClient();
	}

	@AfterAll
	static void stopServer() {
		if (server != null)
			server.close();
	}

	/**
	 * The approved registry (M1 plan, "Limits registry", and G8-10), in {@link Limits#all()} order. Changes from plan
	 * v3 made at gates 5 and 8 are marked with their gate item.
	 */
	private static final List<Row> APPROVED_ROWS = List.of(
			// HTTP body: token, metadata, UserInfo, introspection (G5-1: floor 4 -> 16 KiB).
			amounts("HTTP_RESPONSE_BODY_SIZE", "HTTP response body size", Unit.BYTES, 256 * KIB, 16 * KIB, 4 * MIB),
			// HTTP body: JWKS / key count (G5-1: floor 4 -> 16 KiB).
			amounts("JWKS_RESPONSE_BODY_SIZE", "JWKS response body size", Unit.BYTES, 256 * KIB, 16 * KIB, 4 * MIB),
			amounts("JWKS_KEY_COUNT", "JWKS key count", Unit.COUNT, 100, 1, 1_000),
			// HTTP error body (overflow or encoding keeps the status).
			amounts("HTTP_ERROR_BODY_SIZE", "HTTP error body size", Unit.BYTES, 16 * KIB, KIB, 64 * KIB),
			// Per-request timeout / total deadline (G5-5: per public call; timeout <= deadline).
			durations("REQUEST_TIMEOUT", "Request timeout", Duration.ofSeconds(10), Duration.ofSeconds(1),
					Duration.ofSeconds(60), ZERO_REJECTED),
			durations("TOTAL_DEADLINE", "Total deadline", Duration.ofSeconds(15), Duration.ofSeconds(1),
					Duration.ofSeconds(120), ZERO_REJECTED),
			// Compact JWT (G5-1: floor 1 -> 8 KiB).
			amounts("COMPACT_JWT_SIZE", "Compact JWT size", Unit.BYTES, 64 * KIB, 8 * KIB, MIB),
			// JOSE clock skew, zero allowed (G8-10: new row; R11's "configurable 0-5 min").
			durations("JOSE_CLOCK_SKEW", "JOSE clock skew", Duration.ofSeconds(60), Duration.ZERO, Duration.ofMinutes(5),
					ZERO_ALLOWED),
			// ID token maximum age, for M4; the age rule adds the skew (G8-10: new row).
			durations("ID_TOKEN_MAXIMUM_AGE", "ID token maximum age", Duration.ofMinutes(5), Duration.ofMinutes(1),
					Duration.ofHours(1), ZERO_REJECTED),
			// JSON depth, protocol / SCIM; internal (G5-2: cap 256 -> 64).
			amounts("JSON_DEPTH_PROTOCOL", "JSON depth for protocol documents", Unit.COUNT, 32, 8, 64),
			amounts("JSON_DEPTH_SCIM", "JSON depth for SCIM documents", Unit.COUNT, 64, 8, 64),
			// JSON nodes / string length / number length; internal (G5-1: string floor 1 -> 16 KiB).
			amounts("JSON_NODES", "JSON node count", Unit.COUNT, 100_000, 1_000, 1_000_000),
			amounts("JSON_STRING_LENGTH", "JSON string length", Unit.CHARACTERS, MIB, 16 * KIB, 4 * MIB),
			amounts("JSON_NUMBER_LENGTH", "JSON number length", Unit.CHARACTERS, 1_024, 32, 4_096),
			// JSON number magnitude, adjusted decimal exponent; internal (new row; G5-1: floor 32).
			amounts("JSON_NUMBER_EXPONENT_MAGNITUDE", "JSON number exponent magnitude", Unit.COUNT, 10_000, 32,
					100_000),
			// Authorization-response parameter / query (G5-1: floors 256 B / 1 KiB -> 2 / 4 KiB).
			amounts("AUTHORIZATION_RESPONSE_PARAMETER_SIZE", "Authorization-response parameter size", Unit.BYTES,
					8 * KIB, 2 * KIB, 32 * KIB),
			amounts("AUTHORIZATION_RESPONSE_QUERY_SIZE", "Authorization-response query size", Unit.BYTES, 32 * KIB,
					4 * KIB, 128 * KIB),
			// SAMLResponse decoded.
			amounts("SAML_RESPONSE_DECODED_SIZE", "Decoded SAMLResponse size", Unit.BYTES, 256 * KIB, 16 * KIB,
					4 * MIB),
			// XML depth / attributes / elements / name length (G5-1: attribute and element floors raised).
			amounts("XML_DEPTH", "XML depth", Unit.COUNT, 64, 16, 256),
			amounts("XML_ATTRIBUTES_PER_ELEMENT", "XML attributes per element", Unit.COUNT, 64, 16, 256),
			amounts("XML_ELEMENTS", "XML element count", Unit.COUNT, 10_000, 1_000, 100_000),
			amounts("XML_NAME_LENGTH", "XML name length", Unit.CHARACTERS, 1_000, 64, 10_000),
			// SAML metadata (G5-1: floor 16 -> 64 KiB; G5-2: cap 32 -> 8 MiB).
			amounts("SAML_METADATA_SIZE", "SAML metadata size", Unit.BYTES, MIB, 64 * KIB, 8 * MIB),
			// Redirect inflate / Redirect parameter (M8b, gate 15).
			amounts("SAML_REDIRECT_INFLATED_SIZE", "Inflated Redirect-binding payload size", Unit.BYTES, 64 * KIB,
					4 * KIB, 256 * KIB),
			amounts("SAML_REDIRECT_PARAMETER_SIZE", "Redirect-binding parameter size", Unit.BYTES, 16 * KIB, 2 * KIB,
					64 * KIB),
			// SCIM body / PATCH operations / JSON nodes, public (G5-4: new node row).
			amounts("SCIM_BODY_SIZE", "SCIM body size", Unit.BYTES, MIB, 16 * KIB, 10 * MIB),
			amounts("SCIM_PATCH_OPERATIONS", "SCIM PATCH operation count", Unit.COUNT, 1_000, 1, 10_000),
			amounts("SCIM_JSON_NODES", "SCIM JSON node count", Unit.COUNT, 100_000, 1_000, 1_000_000),
			// SCIM filter length / AST depth / nodes (G5-1: floors 64 / 2 / 4 -> 256 / 4 / 8).
			amounts("SCIM_FILTER_LENGTH", "SCIM filter length", Unit.CHARACTERS, 4_096, 256, 65_536),
			amounts("SCIM_FILTER_DEPTH", "SCIM filter depth", Unit.COUNT, 16, 4, 64),
			amounts("SCIM_FILTER_NODES", "SCIM filter node count", Unit.COUNT, 128, 8, 4_096),
			// Pending-state lifetime (G5-6: default 10 -> 15 min).
			durations("PENDING_STATE_LIFETIME", "Pending-state lifetime", Duration.ofMinutes(15), Duration.ofMinutes(1),
					Duration.ofMinutes(60), ZERO_REJECTED),
			amounts("PENDING_AUTHORIZATION_STORE_ENTRIES", "Pending-authorization store entries", Unit.COUNT,
					1_024, 16, 65_536),
			amounts("PENDING_AUTHORIZATION_STORE_BYTES", "Pending-authorization store bytes", Unit.BYTES,
					4 * MIB, 64 * KIB, 64 * MIB),
			amounts("PENDING_AUTHORIZATION_RECORD_BYTES", "Pending-authorization record bytes", Unit.BYTES,
					8 * KIB, KIB, 64 * KIB),
			// StateSealer maximum sealed length, in characters (G5-4: new row).
			amounts("STATE_SEALER_MAXIMUM_SEALED_LENGTH", "StateSealer maximum sealed length", Unit.CHARACTERS, 3_800,
					1_024, 16_384),
			// Seal lifetime, a per-call argument with no default (G5-4: new row).
			durations("SEAL_LIFETIME", "Seal lifetime", null, Duration.ofSeconds(1), Duration.ofDays(400),
					ZERO_REJECTED),
			// JWKS cooldown / min TTL / default TTL / max TTL / max staleness (G5-4: new default-TTL row).
			durations("JWKS_UNKNOWN_KEY_ID_COOLDOWN", "JWKS unknown-kid cooldown", Duration.ofSeconds(30),
					Duration.ofSeconds(1), Duration.ofMinutes(10), ZERO_REJECTED),
			durations("JWKS_MINIMUM_TIME_TO_LIVE", "JWKS minimum time to live", Duration.ofMinutes(1),
					Duration.ofSeconds(30), Duration.ofHours(1), ZERO_REJECTED),
			durations("JWKS_DEFAULT_TIME_TO_LIVE", "JWKS default time to live", Duration.ofMinutes(10),
					Duration.ofSeconds(30), Duration.ofHours(24), ZERO_REJECTED),
			durations("JWKS_MAXIMUM_TIME_TO_LIVE", "JWKS maximum time to live", Duration.ofHours(6),
					Duration.ofMinutes(1), Duration.ofHours(24), ZERO_REJECTED),
			durations("JWKS_MAXIMUM_STALENESS", "JWKS maximum staleness", Duration.ofHours(12), Duration.ZERO,
					Duration.ofHours(24), ZERO_ALLOWED),
			// M3 gate 9/10: metadata discovery cache and attempt bounds.
			durations("DISCOVERY_MINIMUM_TIME_TO_LIVE", "Discovery minimum time to live", Duration.ofMinutes(1),
					Duration.ofSeconds(30), Duration.ofHours(1), ZERO_REJECTED),
			durations("DISCOVERY_DEFAULT_TIME_TO_LIVE", "Discovery default time to live", Duration.ofMinutes(10),
					Duration.ofSeconds(30), Duration.ofHours(24), ZERO_REJECTED),
			durations("DISCOVERY_MAXIMUM_TIME_TO_LIVE", "Discovery maximum time to live", Duration.ofHours(6),
					Duration.ofMinutes(1), Duration.ofHours(24), ZERO_REJECTED),
			durations("DISCOVERY_COOLDOWN", "Discovery cooldown", Duration.ofSeconds(30),
					Duration.ofSeconds(1), Duration.ofMinutes(10), ZERO_REJECTED),
			// Client credentials fallback / maximum cache duration / renewBefore (G5-3: new rows).
			durations("CLIENT_CREDENTIALS_FALLBACK_CACHE_DURATION", "Client-credentials fallback cache duration",
					Duration.ofMinutes(5), Duration.ofSeconds(10), Duration.ofHours(1), ZERO_REJECTED),
			durations("CLIENT_CREDENTIALS_MAXIMUM_CACHE_DURATION", "Client-credentials maximum cache duration",
					Duration.ofHours(24), Duration.ofMinutes(1), Duration.ofHours(24), ZERO_REJECTED),
			durations("CLIENT_CREDENTIALS_RENEW_BEFORE", "Client-credentials renewBefore", Duration.ofSeconds(60),
					Duration.ZERO, Duration.ofMinutes(10), ZERO_ALLOWED));

	/**
	 * The three rows that permit zero (M1 plan, "Limits registry": "Zero is allowed only for maximum staleness and
	 * renewBefore"; G8-10 adds the JOSE clock skew as the third).
	 */
	private static final Set<String> ZERO_ROWS = Set.of("JWKS_MAXIMUM_STALENESS", "CLIENT_CREDENTIALS_RENEW_BEFORE",
			"JOSE_CLOCK_SKEW");

	// Gates 5 and 8: the registry holds exactly the approved rows, as public constants, in the transcribed order.
	@Test
	void theRegistryHoldsExactlyTheApprovedRowsInOrder() throws IllegalAccessException {
		List<String> approved = APPROVED_ROWS.stream().map(Row::getConstant).toList();
		Assertions.assertEquals(49, approved.size(), "M3 adds seven rows to the previous 42");

		Map<String, Limit> constants = constants();
		IdentityHashMap<Limit, String> names = new IdentityHashMap<>();
		constants.forEach((name, limit) -> names.put(limit, name));
		Assertions.assertEquals(approved, Limits.all().stream().map(names::get).toList(),
				"Limits.all() holds every approved row, in order, and nothing else");
		Assertions.assertEquals(approved.stream().sorted().toList(), constants.keySet().stream().sorted().toList(),
				"every Limit constant is an approved row");
		for (Field field : Limits.class.getDeclaredFields())
			if (field.getType() == Limit.class)
				Assertions.assertTrue(Modifier.isPublic(field.getModifiers()) && Modifier.isStatic(field.getModifiers())
						&& Modifier.isFinal(field.getModifiers()), field::getName);

		Assertions.assertThrows(UnsupportedOperationException.class,
				() -> Limits.all().add(Limits.HTTP_RESPONSE_BODY_SIZE));
	}

	// G8-10: zero is allowed for exactly three rows, the JWKS maximum staleness, renewBefore and the JOSE clock skew,
	// and no other constant permits it.
	@Test
	void zeroIsAllowedForExactlyTheThreeZeroRows() throws IllegalAccessException {
		Assertions.assertEquals(3, ZERO_ROWS.size());
		Assertions.assertEquals(ZERO_ROWS, APPROVED_ROWS.stream().filter(Row::isZeroAllowed).map(Row::getConstant)
				.collect(Collectors.toSet()));
		Assertions.assertEquals(ZERO_ROWS, constants().entrySet().stream()
				.filter(entry -> entry.getValue().isZeroAllowed())
				.map(Map.Entry::getKey)
				.collect(Collectors.toSet()));
	}

	// Gate 5 and exit criterion 16: every row keeps its approved name, unit, default, floor, cap and zero rule.
	@TestFactory
	Stream<DynamicTest> everyApprovedRowIsPinned() {
		return APPROVED_ROWS.stream().map(row -> DynamicTest.dynamicTest(row.getConstant(), () -> {
			Limit limit = limit(row);

			Assertions.assertEquals(row.getName(), limit.getName());
			Assertions.assertEquals(row.getUnit(), limit.getUnit());
			Assertions.assertEquals(row.isZeroAllowed(), limit.isZeroAllowed());
			Assertions.assertEquals(row.isZeroAllowed(), ZERO_ROWS.contains(row.getConstant()));

			if (row.getUnit() == Unit.DURATION) {
				Assertions.assertEquals(row.getFloorDuration(), limit.getFloorDuration());
				Assertions.assertEquals(row.getCapDuration(), limit.getCapDuration());
				@Nullable Duration defaultDuration = row.getDefaultDuration();
				Assertions.assertEquals(defaultDuration != null, limit.hasDefault());
				if (defaultDuration == null)
					Assertions.assertThrows(IllegalStateException.class, limit::getDefaultDuration);
				else
					Assertions.assertEquals(defaultDuration, limit.getDefaultDuration());
			} else {
				Assertions.assertTrue(limit.hasDefault());
				Assertions.assertEquals(row.getDefaultAmount(), limit.getDefaultValue());
				Assertions.assertEquals(row.getFloorAmount(), limit.getFloor());
				Assertions.assertEquals(row.getCapAmount(), limit.getCap());
			}
		}));
	}

	// Plan R8 and exit criterion 16: Limit.require rejects zero outside the three zero rows, and every value outside
	// the approved [floor, cap], through each overload; it accepts the approved floor, default and cap.
	@TestFactory
	Stream<DynamicTest> requireRejectsZeroAndEveryValueOutsideTheApprovedRange() {
		return APPROVED_ROWS.stream().map(row -> DynamicTest.dynamicTest(row.getConstant(), () -> {
			Limit limit = limit(row);

			if (row.getUnit() == Unit.DURATION) {
				Duration floor = row.getFloorDuration();
				Duration cap = row.getCapDuration();

				Assertions.assertEquals(floor, limit.require(floor));
				Assertions.assertEquals(cap, limit.require(cap));
				@Nullable Duration defaultDuration = row.getDefaultDuration();
				if (defaultDuration != null)
					Assertions.assertEquals(defaultDuration, limit.require(defaultDuration));

				if (row.isZeroAllowed())
					Assertions.assertEquals(Duration.ZERO, limit.require(Duration.ZERO));
				else
					assertRejected(() -> limit.require(Duration.ZERO));

				for (Duration outside : List.of(floor.minusNanos(1), cap.plusNanos(1), Duration.ofNanos(-1),
						Duration.ofSeconds(Long.MIN_VALUE), Duration.ofSeconds(Long.MAX_VALUE, 999_999_999)))
					assertRejected(() -> limit.require(outside));

				// A duration row is never read as a count.
				Assertions.assertThrows(IllegalStateException.class, () -> limit.require(1L));
			} else {
				long floor = row.getFloorAmount();
				long cap = row.getCapAmount();

				Assertions.assertEquals(floor, limit.require(floor));
				Assertions.assertEquals(cap, limit.require(cap));
				Assertions.assertEquals(row.getDefaultAmount(), limit.require(row.getDefaultAmount()));
				Assertions.assertEquals((int) cap, limit.require((int) cap));
				Assertions.assertEquals((int) floor, limit.require((int) floor));

				// No amount row permits zero: every floor is positive.
				assertRejected(() -> limit.require(0));
				assertRejected(() -> limit.require(0L));

				for (long outside : new long[]{floor - 1, cap + 1, -1, Long.MIN_VALUE, Long.MAX_VALUE,
						Integer.MAX_VALUE + 1L})
					assertRejected(() -> limit.require(outside));
				for (int outside : new int[]{(int) floor - 1, (int) cap + 1, -1, Integer.MIN_VALUE, Integer.MAX_VALUE})
					assertRejected(() -> limit.require(outside));

				// A count row is never read as a duration.
				Assertions.assertThrows(IllegalStateException.class, () -> limit.require(Duration.ofSeconds(1)));
			}
		}));
	}

	// G7-6 and exit criterion 16: the public model's caps are 64 levels, 4,096 digits and an adjusted exponent of
	// 100,000, and no JSON row's cap, and so no profile, exceeds them.
	@Test
	void noJsonProfileExceedsAModelCap() throws ReflectiveOperationException {
		Assertions.assertEquals(64, JsonLimits.MODEL_MAXIMUM_DEPTH);
		Assertions.assertEquals(4_096, JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS);
		Assertions.assertEquals(100_000, JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE);

		Assertions.assertTrue(row("JSON_DEPTH_PROTOCOL").getCapAmount() <= JsonLimits.MODEL_MAXIMUM_DEPTH);
		Assertions.assertTrue(row("JSON_DEPTH_SCIM").getCapAmount() <= JsonLimits.MODEL_MAXIMUM_DEPTH);
		Assertions.assertTrue(row("JSON_NUMBER_LENGTH").getCapAmount() <= JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS);
		Assertions.assertTrue(row("JSON_NUMBER_EXPONENT_MAGNITUDE").getCapAmount()
				<= JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE);

		List<JsonLimits> profiles = new ArrayList<>(List.of(
				JsonLimits.protocolDocument(1), JsonLimits.protocolDocument((int) (4 * MIB)),
				JsonLimits.jose(1), JsonLimits.jose((int) MIB),
				JsonLimits.scim(1, 1_000), JsonLimits.scim((int) (10 * MIB), 1_000_000)));
		profiles.add(maximumCaps());

		for (JsonLimits profile : profiles) {
			Assertions.assertTrue(profile.getMaxDepth() <= JsonLimits.MODEL_MAXIMUM_DEPTH, profile::toString);
			Assertions.assertTrue(profile.getMaxNumberLength() <= JsonLimits.MODEL_MAXIMUM_NUMBER_DIGITS,
					profile::toString);
			Assertions.assertTrue(profile.getMaxExponentMagnitude() <= JsonLimits.MODEL_MAXIMUM_EXPONENT_MAGNITUDE,
					profile::toString);
		}
	}

	// G5-5 and G7-6: the JSON structural rows are internal in 1.0.0, so each profile uses their approved defaults,
	// except SCIM's node count, the one public JSON row; the test-only maximum-cap profile uses every cap.
	@Test
	void theJsonProfilesUseTheApprovedRows() throws ReflectiveOperationException {
		for (JsonLimits profile : List.of(JsonLimits.protocolDocument(1_000), JsonLimits.jose(1_000))) {
			assertJsonProfile(profile, 1_000, row("JSON_DEPTH_PROTOCOL").getDefaultAmount(),
					row("JSON_NODES").getDefaultAmount(), false);
		}
		assertJsonProfile(JsonLimits.scim(1_000, 2_000), 1_000, row("JSON_DEPTH_SCIM").getDefaultAmount(), 2_000,
				true);

		JsonLimits maximumCaps = maximumCaps();
		Assertions.assertEquals(Integer.MAX_VALUE, maximumCaps.getMaxInputBytes());
		Assertions.assertEquals(row("JSON_DEPTH_SCIM").getCapAmount(), maximumCaps.getMaxDepth());
		Assertions.assertEquals(row("SCIM_JSON_NODES").getCapAmount(), maximumCaps.getMaxNodes());
		Assertions.assertEquals(row("JSON_STRING_LENGTH").getCapAmount(), maximumCaps.getMaxStringLength());
		Assertions.assertEquals(row("JSON_NUMBER_LENGTH").getCapAmount(), maximumCaps.getMaxNumberLength());
		Assertions.assertEquals(row("JSON_NUMBER_EXPONENT_MAGNITUDE").getCapAmount(),
				maximumCaps.getMaxExponentMagnitude());
		Assertions.assertFalse(maximumCaps.isAsciiCaseVariantNamesRejected());
	}

	// G5-5 and exit criterion 16: each JSON profile's input size is the owning row's setting, from 1 byte to the
	// largest cap of the rows it serves, and SCIM's node count is the SCIM_JSON_NODES row.
	@TestFactory
	Stream<DynamicTest> theJsonProfilesRejectOutOfRangeSettings() {
		int protocolDocumentCap = (int) Math.max(row("HTTP_RESPONSE_BODY_SIZE").getCapAmount(),
				Math.max(row("JWKS_RESPONSE_BODY_SIZE").getCapAmount(), row("HTTP_ERROR_BODY_SIZE").getCapAmount()));
		int joseCap = (int) row("COMPACT_JWT_SIZE").getCapAmount();
		int scimCap = (int) row("SCIM_BODY_SIZE").getCapAmount();
		Row scimNodes = row("SCIM_JSON_NODES");

		return Stream.of(
				DynamicTest.dynamicTest("protocolDocument input bytes", () -> {
					Assertions.assertEquals((int) (4 * MIB), protocolDocumentCap);
					assertIntRange(value -> JsonLimits.protocolDocument(value).getMaxInputBytes(), 1,
							protocolDocumentCap);
				}),
				DynamicTest.dynamicTest("jose input bytes", () -> {
					Assertions.assertEquals((int) MIB, joseCap);
					assertIntRange(value -> JsonLimits.jose(value).getMaxInputBytes(), 1, joseCap);
				}),
				DynamicTest.dynamicTest("scim input bytes", () -> {
					Assertions.assertEquals((int) (10 * MIB), scimCap);
					assertIntRange(value -> JsonLimits.scim(value, 1_000).getMaxInputBytes(), 1, scimCap);
				}),
				DynamicTest.dynamicTest("scim nodes", () -> assertIntRange(
						value -> JsonLimits.scim(1_000, value).getMaxNodes(), (int) scimNodes.getFloorAmount(),
						(int) scimNodes.getCapAmount())));
	}

	// G5-4 and exit criterion 16: build() rejects a maximumSealedLength outside [1,024, 16,384], and null means
	// 3,800. The sealed length is ceil(4 * (54 + keyIdLength + plaintextBytes) / 3) (M1 plan, "StateSealer v1"), so
	// with the 4-character key ID "test" a plaintext of 2,792 bytes seals to exactly 3,800 characters.
	@Test
	void theSealerRejectsAMaximumSealedLengthOutsideTheApprovedRange() {
		Row row = row("STATE_SEALER_MAXIMUM_SEALED_LENGTH");
		assertIntRange(value -> sealerWithMaximum(value).toString(), (int) row.getFloorAmount(),
				(int) row.getCapAmount());

		assertSealsExactlyUpTo(sealerWithMaximum(null), (int) row.getDefaultAmount());
		assertSealsExactlyUpTo(StateSealer.withActiveKey(TestSealers.fixedKey(TestSealers.FIXED_KEY_ID)).build(),
				(int) row.getDefaultAmount());
		assertSealsExactlyUpTo(sealerWithMaximum((int) row.getFloorAmount()), (int) row.getFloorAmount());
		assertSealsExactlyUpTo(sealerWithMaximum((int) row.getCapAmount()), (int) row.getCapAmount());
	}

	// G5-4 and exit criterion 16: seal rejects a lifetime outside [1 s, 400 days].
	@Test
	void theSealerRejectsALifetimeOutsideTheApprovedRange() {
		Row row = row("SEAL_LIFETIME");
		StateSealer sealer = TestSealers.fromFixedKey();

		Assertions.assertFalse(sealer.seal("x", "context", row.getFloorDuration()).isEmpty());
		Assertions.assertFalse(sealer.seal("x", "context", row.getCapDuration()).isEmpty());
		for (Duration outside : List.of(row.getFloorDuration().minusNanos(1), row.getCapDuration().plusNanos(1),
				Duration.ZERO, Duration.ofSeconds(-1), Duration.ofSeconds(Long.MAX_VALUE)))
			assertRejected(() -> sealer.seal("x", "context", outside));
	}

	// Plan R8 and R12: the HTTP helper's defaults are the registry's, and a JWKS body is bounded by its own row.
	@Test
	void theHttpDefaultsComeFromTheApprovedRows() throws IllegalAccessException {
		URI uri = URI.create("https://example.com/");
		for (ResponseProfile profile : ResponseProfile.values()) {
			String bodyRow = profile == ResponseProfile.JWKS ? "JWKS_RESPONSE_BODY_SIZE" : "HTTP_RESPONSE_BODY_SIZE";
			Assertions.assertSame(limit(row(bodyRow)), profile.getBodySizeLimit(), profile::name);

			HttpExchangeRequest request = HttpExchangeRequest.fromDefaults(uri, profile);
			Assertions.assertEquals(row(bodyRow).getDefaultAmount(), request.maximumBodyBytes(), profile::name);
			Assertions.assertEquals(row("HTTP_ERROR_BODY_SIZE").getDefaultAmount(), request.maximumErrorBodyBytes(),
					profile::name);
			Assertions.assertEquals(row("REQUEST_TIMEOUT").getDefaultDuration(), request.requestTimeout(),
					profile::name);
		}
	}

	// G5-5: requestTimeout <= totalDeadline; equal passes, one nanosecond more fails, whatever the rows allow.
	@Test
	void theRequestTimeoutMayNotExceedTheTotalDeadline() {
		Limits.requireRequestTimeoutWithinTotalDeadline(Duration.ofSeconds(10), Duration.ofSeconds(15));
		Limits.requireRequestTimeoutWithinTotalDeadline(Duration.ofSeconds(15), Duration.ofSeconds(15));
		assertRejected(() -> Limits.requireRequestTimeoutWithinTotalDeadline(Duration.ofSeconds(15).plusNanos(1),
				Duration.ofSeconds(15)));
		assertRejected(() -> Limits.requireRequestTimeoutWithinTotalDeadline(Duration.ofSeconds(60),
				Duration.ofSeconds(1)));
	}

	// G5-4: JWKS minimum TTL <= default TTL <= maximum TTL; equal passes.
	@Test
	void theJwksTimesToLiveMustBeOrdered() {
		Limits.requireJwksTimeToLiveOrder(Duration.ofMinutes(1), Duration.ofMinutes(10), Duration.ofHours(6));
		Limits.requireJwksTimeToLiveOrder(Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ofMinutes(1));
		assertRejected(() -> Limits.requireJwksTimeToLiveOrder(Duration.ofMinutes(10).plusNanos(1),
				Duration.ofMinutes(10), Duration.ofHours(6)));
		assertRejected(() -> Limits.requireJwksTimeToLiveOrder(Duration.ofMinutes(1), Duration.ofHours(6).plusNanos(1),
				Duration.ofHours(6)));
		assertRejected(() -> Limits.requireJwksTimeToLiveOrder(Duration.ofHours(1), Duration.ofSeconds(30),
				Duration.ofMinutes(1)));
	}

	// M2-8, the owner's decision of 2026-09-28: the JWKS unknown-kid cooldown <= the minimum TTL, so the limit of two
	// requests per cooldown holds back no refresh after expiry unless fetches were cut short; equal passes, one
	// nanosecond more fails, and the defaults (30 s and 1 min) and the floors (1 s and 30 s) pass.
	@Test
	void theJwksCooldownMayNotExceedTheMinimumTimeToLive() {
		Row cooldown = row("JWKS_UNKNOWN_KEY_ID_COOLDOWN");
		Row minimum = row("JWKS_MINIMUM_TIME_TO_LIVE");
		Limits.requireJwksCooldownWithinMinimumTimeToLive(Objects.requireNonNull(cooldown.getDefaultDuration()),
				Objects.requireNonNull(minimum.getDefaultDuration()));
		Limits.requireJwksCooldownWithinMinimumTimeToLive(cooldown.getFloorDuration(), minimum.getFloorDuration());
		Limits.requireJwksCooldownWithinMinimumTimeToLive(Duration.ofMinutes(10), Duration.ofMinutes(10));
		assertRejected(() -> Limits.requireJwksCooldownWithinMinimumTimeToLive(Duration.ofMinutes(10).plusNanos(1),
				Duration.ofMinutes(10)));
		assertRejected(() -> Limits.requireJwksCooldownWithinMinimumTimeToLive(cooldown.getCapDuration(),
				Objects.requireNonNull(minimum.getDefaultDuration())));
	}

	// G5-3: renewBefore < maximumCacheDuration, strictly; zero renewBefore passes with the smallest maximum.
	@Test
	void renewBeforeMustBeShorterThanTheMaximumCacheDuration() {
		Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ofSeconds(60), Duration.ofHours(24));
		Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ZERO, Duration.ofMinutes(1));
		Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ofMinutes(1).minusNanos(1), Duration.ofMinutes(1));
		assertRejected(() -> Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ofMinutes(1),
				Duration.ofMinutes(1)));
		assertRejected(() -> Limits.requireRenewBeforeBelowMaximumCacheDuration(Duration.ofMinutes(10),
				Duration.ofMinutes(1)));
	}

	// M1 plan, Results (phase 1, "Calls made within approved scope"): fallbackCacheDuration <= maximumCacheDuration;
	// equal passes, one nanosecond more fails.
	@Test
	void theFallbackCacheDurationMayNotExceedTheMaximumCacheDuration() {
		Limits.requireFallbackWithinMaximumCacheDuration(Duration.ofMinutes(5), Duration.ofHours(24));
		Limits.requireFallbackWithinMaximumCacheDuration(Duration.ofMinutes(1), Duration.ofMinutes(1));
		Limits.requireFallbackWithinMaximumCacheDuration(Duration.ofHours(1), Duration.ofHours(1));
		assertRejected(() -> Limits.requireFallbackWithinMaximumCacheDuration(Duration.ofMinutes(1).plusNanos(1),
				Duration.ofMinutes(1)));
		assertRejected(() -> Limits.requireFallbackWithinMaximumCacheDuration(Duration.ofHours(1),
				Duration.ofMinutes(1)));
	}

	// G5-3 runtime rule: a token's lifetime is expires_in capped at maximumCacheDuration, or the fallback without one,
	// and it is renewed min(renewBefore, lifetime / 2) before expiry, so a 30 s token under the 60 s default is renewed
	// after 15 s.
	@Test
	void clientCredentialsTokensFollowTheApprovedRuntimeRule() {
		Assertions.assertEquals(Duration.ofMinutes(5),
				Limits.clientCredentialsCacheLifetime(null, Duration.ofMinutes(5), Duration.ofHours(24)));
		Assertions.assertEquals(Duration.ofHours(24),
				Limits.clientCredentialsCacheLifetime(Duration.ofHours(48), Duration.ofMinutes(5), Duration.ofHours(24)));
		Assertions.assertEquals(Duration.ofHours(1),
				Limits.clientCredentialsCacheLifetime(Duration.ofHours(1), Duration.ofMinutes(5), Duration.ofHours(24)));

		Assertions.assertEquals(Duration.ofSeconds(15),
				Limits.clientCredentialsRenewalLeadTime(Duration.ofSeconds(60), Duration.ofSeconds(30)));
		Assertions.assertEquals(Duration.ofSeconds(60),
				Limits.clientCredentialsRenewalLeadTime(Duration.ofSeconds(60), Duration.ofHours(24)));
		Assertions.assertEquals(Duration.ZERO,
				Limits.clientCredentialsRenewalLeadTime(Duration.ZERO, Duration.ofHours(1)));
	}

	// M2 plan, "Limits registry additions": the JOSE policy constants that are not rows. The public constants of
	// internal.crypto and internal.jose carry exactly the transcribed values.
	@TestFactory
	Stream<DynamicTest> everyJosePolicyConstantIsPinned() {
		return Stream.of(
				DynamicTest.dynamicTest("RSA modulus bits (M2-7)", () -> {
					Assertions.assertEquals(RSA_MINIMUM_MODULUS_BITS, RsaPublicKeys.MINIMUM_MODULUS_BITS);
					Assertions.assertEquals(RSA_MAXIMUM_MODULUS_BITS, RsaPublicKeys.MAXIMUM_MODULUS_BITS);
				}),
				DynamicTest.dynamicTest("RS* and PS* signature octets before key selection (M2-6)", () -> {
					// The bound is the lengths of the moduli the key policy allows.
					Assertions.assertEquals(RSA_MINIMUM_MODULUS_BITS / Byte.SIZE, RSA_MINIMUM_SIGNATURE_OCTETS);
					Assertions.assertEquals(RSA_MAXIMUM_MODULUS_BITS / Byte.SIZE, RSA_MAXIMUM_SIGNATURE_OCTETS);
					Assertions.assertEquals(RSA_MINIMUM_SIGNATURE_OCTETS, RsaPublicKeys.MINIMUM_SIGNATURE_LENGTH);
					Assertions.assertEquals(RSA_MAXIMUM_SIGNATURE_OCTETS, RsaPublicKeys.MAXIMUM_SIGNATURE_LENGTH);
					for (int octets : new int[]{RSA_MINIMUM_SIGNATURE_OCTETS, RSA_MAXIMUM_SIGNATURE_OCTETS})
						Assertions.assertTrue(RsaPublicKeys.isWithinSignatureLengthBounds(octets));
					for (int octets : new int[]{0, RSA_MINIMUM_SIGNATURE_OCTETS - 1, RSA_MAXIMUM_SIGNATURE_OCTETS + 1})
						Assertions.assertFalse(RsaPublicKeys.isWithinSignatureLengthBounds(octets));
				}),
				DynamicTest.dynamicTest("RSA public exponent (M2-7)", () -> {
					Assertions.assertEquals(RSA_MINIMUM_PUBLIC_EXPONENT, RsaPublicKeys.MINIMUM_PUBLIC_EXPONENT);
					Assertions.assertEquals(RSA_PUBLIC_EXPONENT_LIMIT, RsaPublicKeys.PUBLIC_EXPONENT_LIMIT);
				}),
				DynamicTest.dynamicTest("ROCA primes (M2-7)", () -> {
					List<Integer> oddPrimes = IntStream.rangeClosed(3, ROCA_LARGEST_PRIME)
							.filter(candidate -> BigInteger.valueOf(candidate).isProbablePrime(64))
							.boxed()
							.toList();
					Assertions.assertEquals(ROCA_PRIME_COUNT, oddPrimes.size());
					Assertions.assertEquals(oddPrimes, RsaPublicKeys.ROCA_PRIMES);
					Assertions.assertEquals(ROCA_PRIME_COUNT, RsaPublicKeys.ROCA_PRIME_COUNT);
				}),
				DynamicTest.dynamicTest("EC coordinate and signature octets (G8-3, M2-7)", () -> {
					Assertions.assertEquals(EC_CURVE_OCTETS.keySet(), Arrays.stream(EcCurve.values()).map(EcCurve::getName)
							.collect(Collectors.toSet()));
					for (EcCurve curve : EcCurve.values())
						Assertions.assertEquals(EC_CURVE_OCTETS.get(curve.getName()), List.of(curve.getCoordinateLength(),
								curve.getSignatureLength()), curve::getName);
				}),
				DynamicTest.dynamicTest("Ed25519 key and signature octets (M2-7)", () -> {
					Assertions.assertEquals(ED25519_KEY_OCTETS, Ed25519PublicKeys.KEY_LENGTH);
					Assertions.assertEquals(ED25519_SIGNATURE_OCTETS, Ed25519PublicKeys.SIGNATURE_LENGTH);
				}),
				DynamicTest.dynamicTest("HMAC secret octets (RFC 7518 section 3.2)", () -> {
					Map<HashAlgorithm, String> algorithms = Map.of(HashAlgorithm.SHA_256, "HS256", HashAlgorithm.SHA_384,
							"HS384", HashAlgorithm.SHA_512, "HS512");
					Assertions.assertEquals(Set.of(HashAlgorithm.values()), algorithms.keySet());
					for (Map.Entry<HashAlgorithm, String> algorithm : algorithms.entrySet()) {
						int minimum = Objects.requireNonNull(HMAC_MINIMUM_SECRET_OCTETS.get(algorithm.getValue()));
						Assertions.assertEquals(minimum, algorithm.getKey().getLength());
						Hmac.checkSecretLength(algorithm.getKey(), new byte[minimum]);
						KeyRejectedException shortSecret = Assertions.assertThrows(KeyRejectedException.class,
								() -> Hmac.checkSecretLength(algorithm.getKey(), new byte[minimum - 1]));
						Assertions.assertEquals(KeyRejectedException.Kind.SECRET_TOO_SHORT, shortSecret.getKind());
					}
				}),
				DynamicTest.dynamicTest("key ID characters (JOSE semantics, step 4; key check 7)", () ->
						Assertions.assertEquals(MAXIMUM_KEY_ID_LENGTH, JwkParser.MAXIMUM_KEY_ID_LENGTH)),
				DynamicTest.dynamicTest("the Entra key-issuer template (M2-11)", () -> {
					Assertions.assertEquals(ENTRA_ISSUER_TEMPLATE, JwtClaimsPolicy.ENTRA_ISSUER_TEMPLATE);
					Assertions.assertEquals(ENTRA_ISSUER_TEMPLATE, JwtClaimsPolicy.ENTRA_ISSUER_PREFIX + "{tenantid}"
							+ JwtClaimsPolicy.ENTRA_ISSUER_SUFFIX);
				}));
	}

	// M2-4 and G8-2 (D14): a validator allows RS256 alone unless configured otherwise, so every other algorithm, and
	// none in any spelling, is ALGORITHM_NOT_ALLOWED before its signature is examined, while RS256 reaches it.
	@Test
	void theValidatorAllowsOnlyRs256ByDefault() {
		JwtValidator validator = defaultValidator();
		assertAccepted(validator, signed(claims()));

		for (JwsAlgorithm algorithm : JwsAlgorithm.values()) {
			String token = TestJws.builder().alg(algorithm.getWireValue()).kid(KEY_ID).payload(claims().toJson())
					.withSignature(new byte[RSA_MINIMUM_SIGNATURE_OCTETS]);
			assertRejected(DEFAULT_ALLOWED_ALGORITHMS.contains(algorithm) ? JoseException.Reason.SIGNATURE_MISMATCH
					: JoseException.Reason.ALGORITHM_NOT_ALLOWED, validator, token);
		}
		for (String none : List.of("none", "None", "NONE"))
			assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, validator,
					TestJws.builder().alg(none).payload(claims().toJson()).unsigned());
	}

	// M2-4 and P7: by default a typ is optional, and when present it must be JWT as a media type (ASCII
	// case-insensitive, with application/ implied); the types of other profiles are INVALID_TYPE.
	@Test
	void theValidatorAcceptsTypeJwtOrNoTypeByDefault() {
		JwtValidator validator = defaultValidator();
		assertAccepted(validator, signed(claims()));
		for (String type : DEFAULT_ACCEPTED_TYPES)
			assertAccepted(validator, rs256(claims()).typ(type).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
		for (String type : List.of("at+jwt", "application/at+jwt", "logout+jwt", "application/secevent+jwt", "JOSE"))
			assertRejected(JoseException.Reason.INVALID_TYPE, validator, rs256(claims()).typ(type)
					.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
	}

	// M2-4: iss, exp and aud are always required (aud unless any audience is accepted), and nothing else is by
	// default.
	@Test
	void theValidatorAlwaysRequiresIssExpAndAud() {
		JwtValidator validator = defaultValidator();
		for (String claim : ALWAYS_REQUIRED_CLAIMS)
			assertRejected(JoseException.Reason.MISSING_CLAIM, validator, signed(claims().remove(claim)));

		TestClaims onlyRequired = TestClaims.empty().put("iss", ISSUER).put("aud", AUDIENCE)
				.put("exp", NOW.plus(Duration.ofMinutes(5)).getEpochSecond());
		Jwt jwt = validator.validate(signed(onlyRequired));
		Assertions.assertEquals(Set.copyOf(ALWAYS_REQUIRED_CLAIMS), jwt.getClaims().getClaimNames());
	}

	// G8-10 and M2-4: the default clock skew and maximum token length are the JOSE_CLOCK_SKEW and COMPACT_JWT_SIZE
	// rows' defaults, at their exact boundaries.
	@Test
	void theValidatorDefaultsToTheSkewAndTokenLengthRows() {
		assertSkew(defaultValidator(), Objects.requireNonNull(row("JOSE_CLOCK_SKEW").getDefaultDuration()));
		assertMaximumLength(defaultValidator(), (int) row("COMPACT_JWT_SIZE").getDefaultAmount());
	}

	// G8-2 and M2-4: no validator allows an HMAC algorithm, or no algorithm; and one without expected audiences is
	// refused unless it accepts any audience.
	@Test
	void theValidatorBuilderRefusesHmacAndAMissingAudience() {
		for (JwsAlgorithm hmac : List.of(JwsAlgorithm.HS256, JwsAlgorithm.HS384, JwsAlgorithm.HS512)) {
			assertRejected(() -> Assertions.assertNotNull(validatorBuilder(rsaKey()).allowedAlgorithms(Set.of(hmac))
					.build()));
			assertRejected(() -> Assertions.assertNotNull(validatorBuilder(rsaKey()).allowedAlgorithms(
					Set.of(JwsAlgorithm.RS256, hmac)).build()));
		}
		assertRejected(() -> Assertions.assertNotNull(validatorBuilder(rsaKey()).allowedAlgorithms(Set.of()).build()));
		Assertions.assertThrows(IllegalStateException.class, () -> Assertions.assertNotNull(JwtValidator
				.withIssuer(ISSUER).jsonWebKeySource(source(rsaKey())).build()));
	}

	// Exit criterion 19 (G8-10): the validator's clock skew and maximum token length are checked against their rows
	// at build(), with the row's message, zero skew included; and each accepted value, null for the default included,
	// takes effect at its exact boundary.
	@TestFactory
	Stream<DynamicTest> theValidatorBuilderChecksItsSettingsAgainstTheirRows() {
		Row skew = row("JOSE_CLOCK_SKEW");
		Row length = row("COMPACT_JWT_SIZE");
		Duration defaultSkew = Objects.requireNonNull(skew.getDefaultDuration());
		int defaultLength = (int) length.getDefaultAmount();

		return Stream.of(
				DynamicTest.dynamicTest("clockSkew", () -> {
					Assertions.assertTrue(skew.isZeroAllowed() && skew.getFloorDuration().isZero());
					for (Duration accepted : List.of(skew.getFloorDuration(), defaultSkew, skew.getCapDuration()))
						assertSkew(validatorBuilder(rsaKey()).clockSkew(accepted).build(), accepted);
					assertSkew(validatorBuilder(rsaKey()).clockSkew(null).build(), defaultSkew);
					for (Duration outside : List.of(skew.getCapDuration().plusNanos(1), Duration.ofNanos(-1),
							Duration.ofSeconds(Long.MIN_VALUE), Duration.ofSeconds(Long.MAX_VALUE, 999_999_999)))
						assertRowRejected(skew, () -> Assertions.assertNotNull(validatorBuilder(rsaKey()).clockSkew(outside)
								.build()));
				}),
				DynamicTest.dynamicTest("maximumTokenLength", () -> {
					int floor = (int) length.getFloorAmount();
					int cap = (int) length.getCapAmount();
					for (int accepted : new int[]{floor, defaultLength, cap})
						assertMaximumLength(validatorBuilder(rsaKey()).maximumTokenLength(accepted).build(), accepted);
					assertMaximumLength(validatorBuilder(rsaKey()).maximumTokenLength(null).build(), defaultLength);
					for (int outside : new int[]{floor - 1, cap + 1, 0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE})
						assertRowRejected(length, () -> Assertions.assertNotNull(validatorBuilder(rsaKey())
								.maximumTokenLength(outside).build()));
				}));
	}

	// Exit criterion 19 (G5-4, G8-4, M2-8): RemoteJsonWebKeySource.Builder checks each limit against its row at build(),
	// with that row's message and before its other checks, so a builder whose URI it would refuse (plain http to a
	// name that is not localhost, G8-7) still fails on the limit; it accepts the floor, the default and the cap (zero
	// staleness included); null restores the row's default; and the built source carries the value it was given. It
	// also applies the time-to-live order and keeps the unknown-key cooldown within the minimum time to live.
	@TestFactory
	Stream<DynamicTest> theRemoteKeySourceBuilderChecksEverySettingAgainstItsRow() {
		Duration shortest = row("JWKS_MINIMUM_TIME_TO_LIVE").getFloorDuration();
		Duration longest = row("JWKS_MAXIMUM_TIME_TO_LIVE").getCapDuration();
		Duration longestCooldown = row("JWKS_UNKNOWN_KEY_ID_COOLDOWN").getCapDuration();
		List<DurationSetting> durationSettings = List.of(
				new DurationSetting("requestTimeout", "REQUEST_TIMEOUT", RemoteJsonWebKeySource.Builder::requestTimeout,
						UnaryOperator.identity()),
				new DurationSetting("minimumTimeToLive", "JWKS_MINIMUM_TIME_TO_LIVE",
						RemoteJsonWebKeySource.Builder::minimumTimeToLive,
						builder -> builder.defaultTimeToLive(longest).maximumTimeToLive(longest)),
				new DurationSetting("defaultTimeToLive", "JWKS_DEFAULT_TIME_TO_LIVE",
						RemoteJsonWebKeySource.Builder::defaultTimeToLive,
						builder -> builder.minimumTimeToLive(shortest).maximumTimeToLive(longest)),
				new DurationSetting("maximumTimeToLive", "JWKS_MAXIMUM_TIME_TO_LIVE",
						RemoteJsonWebKeySource.Builder::maximumTimeToLive,
						builder -> builder.minimumTimeToLive(shortest).defaultTimeToLive(shortest)),
				new DurationSetting("unknownKeyRefreshCooldown", "JWKS_UNKNOWN_KEY_ID_COOLDOWN",
						RemoteJsonWebKeySource.Builder::unknownKeyRefreshCooldown,
						builder -> builder.minimumTimeToLive(longestCooldown)),
				new DurationSetting("maximumStaleness", "JWKS_MAXIMUM_STALENESS",
						RemoteJsonWebKeySource.Builder::maximumStaleness, UnaryOperator.identity()));
		List<AmountSetting> amountSettings = List.of(
				new AmountSetting("maximumResponseBytes", "JWKS_RESPONSE_BODY_SIZE",
						RemoteJsonWebKeySource.Builder::maximumResponseBytes),
				new AmountSetting("maximumKeys", "JWKS_KEY_COUNT", RemoteJsonWebKeySource.Builder::maximumKeys));

		Stream<DynamicTest> durations = durationSettings.stream().map(setting -> DynamicTest.dynamicTest(
				setting.getName(), () -> {
					Row row = row(setting.getRow());
					Duration defaultValue = Objects.requireNonNull(row.getDefaultDuration());
					for (Duration accepted : List.of(row.getFloorDuration(), defaultValue, row.getCapDuration()))
						assertCarries(setting.configure(remoteBuilder(), accepted).build(), setting.getName(), accepted);
					assertCarries(setting.apply(remoteBuilder(), null).build(), setting.getName(), defaultValue);

					List<Duration> outside = new ArrayList<>(List.of(row.getFloorDuration().minusNanos(1),
							row.getCapDuration().plusNanos(1), Duration.ofNanos(-1), Duration.ofSeconds(Long.MIN_VALUE),
							Duration.ofSeconds(Long.MAX_VALUE, 999_999_999)));
					if (row.isZeroAllowed())
						assertCarries(setting.configure(remoteBuilder(), Duration.ZERO).build(), setting.getName(),
								Duration.ZERO);
					else
						outside.add(Duration.ZERO);
					for (Duration value : outside) {
						assertRowRejected(row, () -> Assertions.assertNotNull(setting.configure(remoteBuilder(), value)
								.build()));
						assertRowRejected(row, () -> Assertions.assertNotNull(setting.configure(refusedUriBuilder(), value)
								.build()));
					}
				}));
		Stream<DynamicTest> amounts = amountSettings.stream().map(setting -> DynamicTest.dynamicTest(setting.getName(),
				() -> {
					Row row = row(setting.getRow());
					for (long accepted : new long[]{row.getFloorAmount(), row.getDefaultAmount(), row.getCapAmount()})
						assertCarries(setting.apply(remoteBuilder(), (int) accepted).build(), setting.getName(), accepted);
					assertCarries(setting.apply(remoteBuilder(), null).build(), setting.getName(), row.getDefaultAmount());
					for (long outside : new long[]{row.getFloorAmount() - 1, row.getCapAmount() + 1, 0, -1,
							Integer.MIN_VALUE, Integer.MAX_VALUE}) {
						assertRowRejected(row, () -> Assertions.assertNotNull(setting.apply(remoteBuilder(), (int) outside)
								.build()));
						assertRowRejected(row, () -> Assertions.assertNotNull(setting.apply(refusedUriBuilder(),
								(int) outside).build()));
					}
				}));
		Stream<DynamicTest> refused = Stream.of(DynamicTest.dynamicTest("the refused URI, with every limit in range", () -> {
			IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class,
					() -> Assertions.assertNotNull(refusedUriBuilder().build()));
			for (Row row : APPROVED_ROWS)
				Assertions.assertFalse(String.valueOf(exception.getMessage()).startsWith(row.getName()),
						() -> "the URI check, not " + row.getConstant() + ", refuses it: " + exception.getMessage());
		}));
		Stream<DynamicTest> order = Stream.of(DynamicTest.dynamicTest("the time-to-live order (G5-4)", () -> {
			Duration defaultTimeToLive = Objects.requireNonNull(row("JWKS_DEFAULT_TIME_TO_LIVE").getDefaultDuration());
			Duration maximumTimeToLive = Objects.requireNonNull(row("JWKS_MAXIMUM_TIME_TO_LIVE").getDefaultDuration());
			assertCarries(remoteBuilder().minimumTimeToLive(defaultTimeToLive).build(), "minimumTimeToLive",
					defaultTimeToLive);
			assertRejected(() -> Assertions.assertNotNull(remoteBuilder().minimumTimeToLive(defaultTimeToLive
					.plusNanos(1)).build()));
			assertCarries(remoteBuilder().defaultTimeToLive(maximumTimeToLive).build(), "defaultTimeToLive",
					maximumTimeToLive);
			assertRejected(() -> Assertions.assertNotNull(remoteBuilder().defaultTimeToLive(maximumTimeToLive
					.plusNanos(1)).build()));
		}));
		Stream<DynamicTest> cooldown = Stream.of(DynamicTest.dynamicTest(
				"the unknown-key cooldown within the minimum time to live (M2-8)", () -> {
					Duration minimumTimeToLive = Objects.requireNonNull(row("JWKS_MINIMUM_TIME_TO_LIVE").getDefaultDuration());
					assertCarries(remoteBuilder().unknownKeyRefreshCooldown(minimumTimeToLive).build(),
							"unknownKeyRefreshCooldown", minimumTimeToLive);
					assertRejected(() -> Assertions.assertNotNull(remoteBuilder().unknownKeyRefreshCooldown(minimumTimeToLive
							.plusNanos(1)).build()));
					assertCarries(remoteBuilder().minimumTimeToLive(shortest).unknownKeyRefreshCooldown(shortest).build(),
							"minimumTimeToLive", shortest);
					assertRejected(() -> Assertions.assertNotNull(remoteBuilder().minimumTimeToLive(shortest)
							.unknownKeyRefreshCooldown(shortest.plusNanos(1)).build()));
				}));
		return Stream.of(durations, amounts, refused, order, cooldown).flatMap(tests -> tests);
	}

	// M2-7 and plan 9.3: an RSA key is usable only with a modulus of 2,048 to 16,384 bits that is odd and written
	// minimally; any other key is skipped, and never fails its key set.
	@Test
	void rsaKeysNeedAnOddMinimalModulusOf2048To16384Bits() {
		Random random = new Random(20_260_927L);
		assertUsable(true, "the smallest modulus", rsaWithModulus(oddModulus(random, RSA_MINIMUM_MODULUS_BITS)));
		assertUsable(true, "the largest modulus", rsaWithModulus(oddModulus(random, RSA_MAXIMUM_MODULUS_BITS)));
		assertUsable(false, "one bit short", rsaWithModulus(oddModulus(random, RSA_MINIMUM_MODULUS_BITS - 1)));
		assertUsable(false, "one bit long", rsaWithModulus(oddModulus(random, RSA_MAXIMUM_MODULUS_BITS + 1)));
		assertUsable(false, "an even modulus", rsaWithModulus(oddModulus(random, RSA_MINIMUM_MODULUS_BITS).clearBit(0)));
		assertUsable(true, "the fixture", rsaKey());
		assertUsable(false, "a leading zero octet", TestJsonWebKeys.rsaWithLeadingZeroModulus().kid(KEY_ID).toJson());
		assertUsable(false, "RSA-1024", TestJsonWebKeys.withFixture(Fixture.NEGATIVE_RSA_1024).kid(KEY_ID).toJson());
	}

	// M2-7: an RSA key's exponent must be odd, at least 65,537 and below 2^32.
	@Test
	void rsaExponentsMustBeOddFrom65537ToBelowTwoToThe32() {
		BigInteger two = BigInteger.TWO;
		for (BigInteger exponent : List.of(BigInteger.ONE, BigInteger.valueOf(3),
				RSA_MINIMUM_PUBLIC_EXPONENT.subtract(two), RSA_MINIMUM_PUBLIC_EXPONENT.subtract(BigInteger.ONE),
				RSA_MINIMUM_PUBLIC_EXPONENT, RSA_MINIMUM_PUBLIC_EXPONENT.add(BigInteger.ONE),
				RSA_MINIMUM_PUBLIC_EXPONENT.add(two), RSA_PUBLIC_EXPONENT_LIMIT.subtract(BigInteger.ONE),
				RSA_PUBLIC_EXPONENT_LIMIT, RSA_PUBLIC_EXPONENT_LIMIT.add(BigInteger.ONE))) {
			boolean usable = exponent.testBit(0) && exponent.compareTo(RSA_MINIMUM_PUBLIC_EXPONENT) >= 0
					&& exponent.compareTo(RSA_PUBLIC_EXPONENT_LIMIT) < 0;
			assertUsable(usable, "e = " + exponent, TestJsonWebKeys.rsaWithExponent(exponent).kid(KEY_ID).toJson());
		}
	}

	// M2-7 and G8-3: an EC key's coordinates are exactly its curve's length (32, 48 or 66 octets) and an Ed25519 key's
	// x exactly 32 octets; a longer or shorter encoding of the same key is skipped.
	@Test
	void keyCoordinatesHaveTheirCurvesExactLengths() {
		Map<Fixture, String> curves = Map.of(Fixture.IDP_SIGNING_EC_P256, "P-256", Fixture.IDP_SIGNING_EC_P384, "P-384",
				Fixture.IDP_SIGNING_EC_P521, "P-521");
		for (Map.Entry<Fixture, String> curve : curves.entrySet()) {
			int octets = Objects.requireNonNull(EC_CURVE_OCTETS.get(curve.getValue())).get(0);
			ECPoint point = ((ECPublicKey) curve.getKey().getPublicKey()).getW();
			assertUsable(true, curve.getValue(), TestJsonWebKeys.withFixture(curve.getKey()).kid(KEY_ID).toJson());
			assertUsable(false, curve.getValue() + " x one octet long", TestJsonWebKeys.withFixture(curve.getKey())
					.kid(KEY_ID).member("x", JsonText.string(TestJsonWebKeys.base64UrlFixedLength(point.getAffineX(),
							octets + 1))).toJson());
			assertUsable(false, curve.getValue() + " y one octet long", TestJsonWebKeys.withFixture(curve.getKey())
					.kid(KEY_ID).member("y", JsonText.string(TestJsonWebKeys.base64UrlFixedLength(point.getAffineY(),
							octets + 1))).toJson());
		}
		assertUsable(false, "P-256 x one octet short", TestJsonWebKeys.ecWithShortX().kid(KEY_ID).toJson());

		byte[] encoded = Fixture.ED25519.getPublicKey().getEncoded();
		byte[] x = Arrays.copyOfRange(encoded, encoded.length - ED25519_KEY_OCTETS, encoded.length);
		assertUsable(true, "Ed25519", TestJsonWebKeys.ed25519WithX(TestJws.base64Url(x)).kid(KEY_ID).toJson());
		assertUsable(false, "Ed25519 x one octet short", TestJsonWebKeys.ed25519WithX(TestJws.base64Url(
				Arrays.copyOf(x, ED25519_KEY_OCTETS - 1))).kid(KEY_ID).toJson());
		assertUsable(false, "Ed25519 x one octet long", TestJsonWebKeys.ed25519WithX(TestJws.base64Url(
				Arrays.copyOf(x, ED25519_KEY_OCTETS + 1))).kid(KEY_ID).toJson());
	}

	// M2-2 and M2-7: a key ID is 1 to 256 characters, in a key set (a key with another is skipped) and in a token's
	// header (another is HEADER, before any key is looked up).
	@Test
	void keyIdsAreOneTo256Characters() {
		String longest = "k".repeat(MAXIMUM_KEY_ID_LENGTH);
		assertUsable(true, "the longest kid", TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid(longest)
				.toJson());
		assertUsable(false, "a kid one character long", TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048)
				.kid(longest + "k").toJson());
		assertUsable(false, "an empty kid", TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("").toJson());

		JwtValidator validator = validatorBuilder(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid(longest)
				.toJson()).build();
		assertAccepted(validator, rs256(claims()).kid(longest).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
		assertRejected(JoseException.Reason.HEADER, validator, rs256(claims()).kid(longest + "k")
				.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
		assertRejected(JoseException.Reason.HEADER, validator, rs256(claims()).kid("")
				.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
	}

	// M2-6 and INV-J5: each algorithm's signature length is checked before a key is looked up: ECDSA 64, 96 or 132
	// octets, Ed25519 64, and RS* or PS* 256 to 2,048. A signature of the right shape reaches key selection (an
	// unknown kid, so UNKNOWN_KEY), and any other length is SIGNATURE_MALFORMED.
	@TestFactory
	Stream<DynamicTest> signatureLengthsAreCheckedBeforeKeySelection() {
		Map<JwsAlgorithm, String> ecdsaCurves = Map.of(JwsAlgorithm.ES256, "P-256", JwsAlgorithm.ES384, "P-384",
				JwsAlgorithm.ES512, "P-521");
		return Arrays.stream(JwsAlgorithm.values())
				.filter(algorithm -> !algorithm.getWireValue().startsWith("HS"))
				.map(algorithm -> DynamicTest.dynamicTest(algorithm.getWireValue(), () -> {
					List<byte[]> wellShaped = new ArrayList<>();
					List<byte[]> malformed = new ArrayList<>();
					@Nullable String curve = ecdsaCurves.get(algorithm);
					if (curve != null) {
						int coordinate = Objects.requireNonNull(EC_CURVE_OCTETS.get(curve)).get(0);
						int signature = Objects.requireNonNull(EC_CURVE_OCTETS.get(curve)).get(1);
						Assertions.assertEquals(2 * coordinate, signature);
						wellShaped.add(TestJws.ecdsaSignature(BigInteger.ONE, BigInteger.ONE, coordinate));
						malformed.add(new byte[signature - 1]);
						malformed.add(new byte[signature + 1]);
					} else if (algorithm == JwsAlgorithm.ED25519 || algorithm == JwsAlgorithm.EDDSA) {
						wellShaped.add(new byte[ED25519_SIGNATURE_OCTETS]);
						malformed.add(new byte[ED25519_SIGNATURE_OCTETS - 1]);
						malformed.add(new byte[ED25519_SIGNATURE_OCTETS + 1]);
					} else {
						wellShaped.add(new byte[RSA_MINIMUM_SIGNATURE_OCTETS]);
						wellShaped.add(new byte[RSA_MAXIMUM_SIGNATURE_OCTETS]);
						malformed.add(new byte[0]);
						malformed.add(new byte[RSA_MINIMUM_SIGNATURE_OCTETS - 1]);
						malformed.add(new byte[RSA_MAXIMUM_SIGNATURE_OCTETS + 1]);
					}

					JwtValidator validator = validatorBuilder(rsaKey()).allowedAlgorithms(Set.of(algorithm)).build();
					TestJws.Builder token = TestJws.builder().alg(algorithm.getWireValue()).kid(UNKNOWN_KEY_ID)
							.payload(claims().toJson());
					for (byte[] signature : wellShaped)
						assertRejected(JoseException.Reason.UNKNOWN_KEY, validator, token.withSignature(signature));
					for (byte[] signature : malformed)
						assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, validator, token.withSignature(signature));
				}));
	}

	// M2-7 and INV-J9: a token is checked against at most one candidate key. With more than one key that fits its kid, or
	// a token without kid and more than one key that fits it, it is AMBIGUOUS_KEY, even when one of those keys signed it.
	@Test
	void aTokenIsCheckedAgainstAtMostOneCandidateKey() {
		List<Fixture> rsaKeys = List.of(Fixture.IDP_SIGNING_RSA_2048, Fixture.NEGATIVE_ATTACKER_RSA_2048,
				Fixture.SP_SIGNING_RSA_2048);
		String withKid = signed(claims());
		String withoutKid = TestJws.withAlgorithm(TestJws.Algorithm.RS256).payload(claims().toJson())
				.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());

		for (int candidates = 1; candidates <= rsaKeys.size(); ++candidates) {
			List<String> keysWithKid = new ArrayList<>();
			List<String> keysWithoutKid = new ArrayList<>();
			for (Fixture fixture : rsaKeys.subList(0, candidates)) {
				keysWithKid.add(TestJsonWebKeys.withFixture(fixture).kid(KEY_ID).toJson());
				keysWithoutKid.add(TestJsonWebKeys.withFixture(fixture).toJson());
			}
			JwtValidator byKid = validatorBuilder(keysWithKid.toArray(String[]::new)).build();
			JwtValidator byFit = validatorBuilder(keysWithoutKid.toArray(String[]::new)).build();

			if (candidates <= CANDIDATE_KEYS_PER_TOKEN) {
				assertAccepted(byKid, withKid);
				assertAccepted(byFit, withoutKid);
			} else {
				assertRejected(JoseException.Reason.AMBIGUOUS_KEY, byKid, withKid);
				assertRejected(JoseException.Reason.AMBIGUOUS_KEY, byFit, withoutKid);
			}
		}
	}

	// M2-8 and G8-8: after the n-th consecutive failure no fetch of any kind starts, warmUp() included, for
	// min(cooldown * 2^(n-1), cap), with cap = max(cooldown, min(10 * cooldown, 10 min)): 30, 60, 120, 240 and then
	// 300 s at the default cooldown; 1, 2, 4, 8 and then 10 s at the row's 1 s floor; and at most 10 min, from 90 s and
	// at the row's 10 min cap. A held-back call gets the remembered failure with no request, and is reported with the
	// time left; one nanosecond later the next fetch starts.
	@TestFactory
	Stream<DynamicTest> theKeySetBackoffDoublesFromTheCooldownUpToItsCap() {
		Row cooldown = row("JWKS_UNKNOWN_KEY_ID_COOLDOWN");
		return Stream.of(
				backoffSchedule(cooldown.getFloorDuration(), List.of(1, 2, 4, 8, 10, 10)),
				backoffSchedule(Objects.requireNonNull(cooldown.getDefaultDuration()), List.of(30, 60, 120, 240, 300, 300)),
				backoffSchedule(Duration.ofSeconds(90), List.of(90, 180, 360, 600, 600)),
				backoffSchedule(cooldown.getCapDuration(), List.of(600, 600)));
	}

	// M2-8 and G8-8, decay and no reset: before a failure counts, the failure count falls by one for each full cap
	// interval since the previous failure (5 min at the default cooldown), and a successful fetch leaves it as it
	// was, so a failure after a success resumes the schedule where it stood.
	@Test
	void theFailureCountDecaysOneStepPerCapIntervalAndASuccessKeepsIt() {
		Duration cooldown = Objects.requireNonNull(row("JWKS_UNKNOWN_KEY_ID_COOLDOWN").getDefaultDuration());
		Duration cap = backoffCap(cooldown);
		Assertions.assertEquals(Duration.ofMinutes(5), cap);
		Response failure = Response.fromStatus(500);
		String path = path();
		server().script(path, Script.fromSequence(List.of(failure, failure, failure, failure, failure, failure,
				Response.fromJsonWebKeySet(TestJsonWebKeys.keySet(List.of(rsaKey())), "no-store"), failure)));
		TestClock clock = TestClock.fromInstant(NOW);
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = remoteSource(path, clock, observer).build();

		assertFailureHeldBackFor(source, observer, backoffStep(cooldown, 1));
		clock.advance(backoffStep(cooldown, 1));
		assertFailureHeldBackFor(source, observer, backoffStep(cooldown, 2));
		clock.advance(backoffStep(cooldown, 2));
		assertFailureHeldBackFor(source, observer, backoffStep(cooldown, 3));
		Assertions.assertEquals(Duration.ofMinutes(2), backoffStep(cooldown, 3));

		// One nanosecond short of a full cap interval: no decay, so the fourth failure is n = 4.
		clock.advance(cap.minusNanos(1));
		assertFailureHeldBackFor(source, observer, Duration.ofMinutes(4));
		// Exactly one full cap interval: n falls to 3, and this failure makes it 4 again, not 5 (the cap).
		clock.advance(cap);
		assertFailureHeldBackFor(source, observer, Duration.ofMinutes(4));
		// Three full cap intervals: n falls to 1, and this failure makes it 2.
		clock.advance(cap.multipliedBy(3));
		assertFailureHeldBackFor(source, observer, Duration.ofSeconds(60));
		Assertions.assertEquals(6, server().getHitCount(path));

		// A success leaves n at 2...
		clock.advance(Duration.ofSeconds(60));
		source.warmUp();
		Assertions.assertEquals(7, server().getHitCount(path));
		Assertions.assertEquals(1, observer.getCalls("didFetchJsonWebKeySet").size());
		// ...so when the key set expires (no-store: the minimum time to live) and the next fetch fails, n is 3, where a
		// reset would have made it 1 (30 s).
		clock.advance(Objects.requireNonNull(row("JWKS_MINIMUM_TIME_TO_LIVE").getDefaultDuration()));
		assertFailureHeldBackFor(source, observer, Duration.ofMinutes(2));
		Assertions.assertEquals(8, server().getHitCount(path));
	}

	// M2-8: no more than two fetches of any kind start within one cooldown. At the row's 10 min cooldown, with the 10 min
	// minimum time to live that build() then requires, the time to live and the backoff never let a third fetch come that
	// close, so only fetches cut short bring the limit into play: two fetches 30 s apart, each cut short because the
	// application interrupts the leading thread once its request has reached the server, leave the next call with no
	// request and a transient TRANSPORT failure without a cause until the older fetch leaves the window, one nanosecond
	// after which a fetch starts again.
	@Test
	void noMoreThanTwoKeySetFetchesStartWithinOneCooldown() {
		Duration cooldown = row("JWKS_UNKNOWN_KEY_ID_COOLDOWN").getCapDuration();
		Duration spacing = Duration.ofSeconds(30);
		String path = path();
		Thread leader = Thread.currentThread();
		server().script(path, exchange -> {
			leader.interrupt();
			exchange.awaitServerClose();
		});
		TestClock clock = TestClock.fromInstant(NOW);
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = remoteSource(path, clock, observer).unknownKeyRefreshCooldown(cooldown)
				.minimumTimeToLive(cooldown).build();

		for (int attempt = 1; attempt <= ATTEMPTS_PER_COOLDOWN; ++attempt) {
			boolean interrupted;
			try {
				assertUnavailable(ErrorCategory.TRANSPORT, false, source::warmUp);
			} finally {
				interrupted = Thread.interrupted();
			}
			Assertions.assertTrue(interrupted, "the cut-short leader's interrupt flag is set again");
			Assertions.assertEquals(attempt, server().getHitCount(path));
			clock.advance(spacing);
		}

		server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(TestJsonWebKeys.keySet(List.of(rsaKey())))));
		JsonWebKeySetUnavailableException heldBack = assertUnavailable(ErrorCategory.TRANSPORT, true, source::warmUp);
		Assertions.assertNull(heldBack.getCause());
		Assertions.assertEquals(cooldown.minus(spacing.multipliedBy(ATTEMPTS_PER_COOLDOWN)), lastSuppression(observer));
		clock.set(NOW.plus(cooldown).minusNanos(1));
		assertUnavailable(ErrorCategory.TRANSPORT, true, source::warmUp);
		Assertions.assertEquals(Duration.ofNanos(1), lastSuppression(observer));
		Assertions.assertEquals(ATTEMPTS_PER_COOLDOWN, server().getHitCount(path));

		clock.set(NOW.plus(cooldown));
		source.warmUp();
		Assertions.assertEquals(ATTEMPTS_PER_COOLDOWN + 1, server().getHitCount(path));
	}

	private static DynamicTest backoffSchedule(Duration cooldown, List<Integer> expectedSeconds) {
		return DynamicTest.dynamicTest("cooldown " + cooldown, () -> {
			List<Duration> expected = expectedSeconds.stream().map(Duration::ofSeconds).toList();
			for (int failures = 1; failures <= expected.size(); ++failures)
				Assertions.assertEquals(expected.get(failures - 1), backoffStep(cooldown, failures),
						"the transcribed formula gives the plan's schedule");

			String path = path();
			server().script(path, Script.fromResponse(Response.fromStatus(500)));
			TestClock clock = TestClock.fromInstant(NOW);
			RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
			// build() requires a minimum time to live at least as long as the cooldown, so a longer cooldown raises it.
			Duration minimumTimeToLive = Objects.requireNonNull(row("JWKS_MINIMUM_TIME_TO_LIVE").getDefaultDuration());
			RemoteJsonWebKeySource source = remoteSource(path, clock, observer).unknownKeyRefreshCooldown(cooldown)
					.minimumTimeToLive(cooldown.compareTo(minimumTimeToLive) > 0 ? cooldown : minimumTimeToLive).build();

			for (int index = 0; index < expected.size(); ++index) {
				Duration step = expected.get(index);
				assertFailureHeldBackFor(source, observer, step);
				Assertions.assertEquals(index + 1, server().getHitCount(path));

				clock.advance(step.minusNanos(1));
				JsonWebKeySetUnavailableException heldBack = assertUnavailable(ErrorCategory.REMOTE_ERROR, true,
						source::warmUp);
				Assertions.assertNull(heldBack.getCause());
				Assertions.assertEquals(Duration.ofNanos(1), lastSuppression(observer));
				Assertions.assertEquals(index + 1, server().getHitCount(path), "no request inside the backoff");
				clock.advance(Duration.ofNanos(1));
			}

			assertUnavailable(ErrorCategory.REMOTE_ERROR, true, source::warmUp);
			Assertions.assertEquals(expected.size() + 1, server().getHitCount(path));
		});
	}

	/**
	 * {@code warmUp()} fetches and fails with the server's 500, and the next call, at the same instant, is held back
	 * without a request for exactly {@code step}.
	 */
	private static void assertFailureHeldBackFor(RemoteJsonWebKeySource source, RecordingObserver<JoseObserver> observer,
			Duration step) {
		int suppressedBefore = observer.getCalls("didSuppressJsonWebKeySetFetch").size();
		assertUnavailable(ErrorCategory.REMOTE_ERROR, true, source::warmUp);
		Assertions.assertEquals(suppressedBefore, observer.getCalls("didSuppressJsonWebKeySetFetch").size(),
				"the first call fetched");
		JsonWebKeySetUnavailableException heldBack = assertUnavailable(ErrorCategory.REMOTE_ERROR, true, source::warmUp);
		Assertions.assertNull(heldBack.getCause(), "a held-back call gets the remembered failure without its cause");
		Assertions.assertEquals(suppressedBefore + 1, observer.getCalls("didSuppressJsonWebKeySetFetch").size());
		Assertions.assertEquals(step, lastSuppression(observer));
	}

	/**
	 * The backoff cap from the transcribed formula: {@code max(cooldown, min(10 * cooldown, 10 min))}.
	 */
	private static Duration backoffCap(Duration cooldown) {
		Duration tenCooldowns = cooldown.multipliedBy(BACKOFF_CAP_COOLDOWNS);
		Duration limited = tenCooldowns.compareTo(BACKOFF_CAP_LIMIT) < 0 ? tenCooldowns : BACKOFF_CAP_LIMIT;
		return limited.compareTo(cooldown) < 0 ? cooldown : limited;
	}

	/**
	 * The backoff after the {@code failures}-th consecutive failure, from the transcribed formula:
	 * {@code min(cooldown * 2^(failures - 1), cap)}.
	 */
	private static Duration backoffStep(Duration cooldown, int failures) {
		Duration cap = backoffCap(cooldown);
		Duration step = cooldown;
		for (int doubling = 1; doubling < failures && step.compareTo(cap) < 0; ++doubling)
			step = step.multipliedBy(2);
		return step.compareTo(cap) < 0 ? step : cap;
	}

	private static Duration lastSuppression(RecordingObserver<JoseObserver> observer) {
		List<RecordingObserver.Call> calls = observer.getCalls("didSuppressJsonWebKeySetFetch");
		Assertions.assertFalse(calls.isEmpty(), "a call was held back");
		return (Duration) Objects.requireNonNull(calls.get(calls.size() - 1).getArgument(1));
	}

	private static JsonWebKeySetUnavailableException assertUnavailable(ErrorCategory category, boolean transientFailure,
			Executable call) {
		JsonWebKeySetUnavailableException exception = Assertions.assertThrows(JsonWebKeySetUnavailableException.class,
				call);
		Assertions.assertEquals(category, exception.getCategory());
		Assertions.assertEquals(transientFailure, exception.isTransient());
		return exception;
	}

	private static void assertSkew(JwtValidator validator, Duration skew) {
		long expired = NOW.minus(skew).getEpochSecond();
		assertAccepted(validator, signed(claims().put("exp", expired + 1)));
		assertRejected(JoseException.Reason.EXPIRED, validator, signed(claims().put("exp", expired)));
	}

	/**
	 * A token of exactly {@code maximumLength} characters is examined (and, with no dots, is TOKEN_SYNTAX), and one
	 * character more is TOKEN_TOO_LARGE.
	 */
	private static void assertMaximumLength(JwtValidator validator, int maximumLength) {
		assertRejected(JoseException.Reason.TOKEN_SYNTAX, validator, "a".repeat(maximumLength));
		assertRejected(JoseException.Reason.TOKEN_TOO_LARGE, validator, "a".repeat(maximumLength + 1));
	}

	private static void assertRowRejected(Row row, Executable executable) {
		IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, executable);
		Assertions.assertTrue(String.valueOf(exception.getMessage()).startsWith(row.getName() + " must be"),
				() -> row.getConstant() + " did not reject the value: " + exception.getMessage());
	}

	private static void assertCarries(RemoteJsonWebKeySource source, String setting, Object value) {
		Assertions.assertTrue(source.toString().contains(setting + "=" + value + ", "),
				() -> setting + "=" + value + " in " + source);
	}

	private static void assertUsable(boolean usable, String name, String jwk) {
		JsonWebKeySet keySet = JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(jwk)));
		Assertions.assertEquals(usable ? 1 : 0, keySet.getKeys().size(), () -> name + (usable ? " is usable"
				: " is skipped"));
	}

	private static void assertAccepted(JwtValidator validator, String token) {
		try {
			Assertions.assertNotNull(validator.validate(token));
		} catch (JoseException exception) {
			throw new AssertionError("expected acceptance, got " + exception.getReason(), exception);
		}
	}

	private static void assertRejected(JoseException.Reason reason, JwtValidator validator, String token) {
		JoseException exception = Assertions.assertThrows(JoseException.class, () -> validator.validate(token));
		Assertions.assertEquals(reason, exception.getReason());
	}

	/**
	 * A random odd modulus of exactly {@code bits} bits, which the ROCA check does not flag.
	 */
	private static BigInteger oddModulus(Random random, int bits) {
		BigInteger modulus = new BigInteger(bits, random).setBit(bits - 1).setBit(0);
		Assertions.assertFalse(RsaPublicKeys.isRocaFingerprinted(modulus), "a random modulus is not ROCA-structured");
		return modulus;
	}

	/**
	 * The RSA fixture's JWK with another modulus; the key is parsed, never used.
	 */
	private static String rsaWithModulus(BigInteger modulus) {
		return TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid(KEY_ID)
				.member("n", JsonText.string(TestJsonWebKeys.base64UrlUInt(modulus))).toJson();
	}

	private static String rsaKey() {
		return TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid(KEY_ID).toJson();
	}

	private static StaticJsonWebKeySource source(String... jwks) {
		return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(jwks))));
	}

	/**
	 * A validator builder with only its required settings, over a static source of {@code jwks}, at {@link #NOW}.
	 */
	private static JwtValidator.Builder validatorBuilder(String... jwks) {
		return JwtValidator.withIssuer(ISSUER).jsonWebKeySource(source(jwks)).expectedAudiences(Set.of(AUDIENCE))
				.clock(TestClock.fromInstant(NOW));
	}

	private static JwtValidator defaultValidator() {
		return validatorBuilder(rsaKey()).build();
	}

	/**
	 * Valid claims at {@link #NOW}: {@code iss}, {@code aud}, {@code sub}, {@code iat} now and {@code exp} in 5 min.
	 */
	private static TestClaims claims() {
		return TestClaims.empty().put("iss", ISSUER).put("aud", AUDIENCE).put("sub", "subject-1")
				.put("iat", NOW.getEpochSecond()).put("exp", NOW.plus(Duration.ofMinutes(5)).getEpochSecond());
	}

	private static TestJws.Builder rs256(TestClaims claims) {
		return TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid(KEY_ID).payload(claims.toJson());
	}

	private static String signed(TestClaims claims) {
		return rs256(claims).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
	}

	private static RemoteJsonWebKeySource.Builder remoteBuilder() {
		return RemoteJsonWebKeySource.withUri(JWKS_URI);
	}

	/**
	 * A builder whose URI {@code build()} refuses once every limit has passed: plain http to a name that is not
	 * {@code localhost} (G8-7).
	 */
	private static RemoteJsonWebKeySource.Builder refusedUriBuilder() {
		return RemoteJsonWebKeySource.withUri(URI.create("http://issuer.example.com/jwks"));
	}

	private static RemoteJsonWebKeySource.Builder remoteSource(String path, TestClock clock,
			RecordingObserver<JoseObserver> observer) {
		return RemoteJsonWebKeySource.withUri(server().uri(path)).httpClient(client()).clock(clock)
				.observer(observer.getObserver());
	}

	private static String path() {
		return "/frozen-limits/" + NEXT_PATH.incrementAndGet();
	}

	private static TestHttpsServer server() {
		return Objects.requireNonNull(server, "the server did not start");
	}

	private static HttpClient client() {
		return Objects.requireNonNull(client, "the client was not created");
	}

	private static void assertJsonProfile(JsonLimits profile, int maxInputBytes, long depth, long nodes,
			boolean asciiCaseVariantNamesRejected) {
		Assertions.assertEquals(maxInputBytes, profile.getMaxInputBytes(), profile::toString);
		Assertions.assertEquals(depth, profile.getMaxDepth(), profile::toString);
		Assertions.assertEquals(nodes, profile.getMaxNodes(), profile::toString);
		Assertions.assertEquals(row("JSON_STRING_LENGTH").getDefaultAmount(), profile.getMaxStringLength(),
				profile::toString);
		Assertions.assertEquals(row("JSON_NUMBER_LENGTH").getDefaultAmount(), profile.getMaxNumberLength(),
				profile::toString);
		Assertions.assertEquals(row("JSON_NUMBER_EXPONENT_MAGNITUDE").getDefaultAmount(),
				profile.getMaxExponentMagnitude(), profile::toString);
		Assertions.assertEquals(asciiCaseVariantNamesRejected, profile.isAsciiCaseVariantNamesRejected(),
				profile::toString);
	}

	/**
	 * {@code consumer} accepts {@code floor} and {@code cap} and rejects, with {@link IllegalArgumentException}, the
	 * values just outside them, zero, a negative value and both {@code int} extremes.
	 */
	private static void assertIntRange(IntFunction<Object> consumer, int floor, int cap) {
		Assertions.assertNotNull(consumer.apply(floor));
		Assertions.assertNotNull(consumer.apply(cap));
		for (int outside : new int[]{floor - 1, cap + 1, 0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE})
			assertRejected(() -> consumer.apply(outside));
	}

	/**
	 * {@code sealer} seals a value of exactly {@code maximumSealedLength} characters and refuses one byte more.
	 */
	private static void assertSealsExactlyUpTo(StateSealer sealer, int maximumSealedLength) {
		int overhead = 54 + TestSealers.FIXED_KEY_ID.length();
		Assertions.assertEquals(0, maximumSealedLength % 4, "the boundary is exact only for multiples of 4");
		int largestPlaintext = maximumSealedLength / 4 * 3 - overhead;

		Assertions.assertEquals(maximumSealedLength,
				sealer.seal("a".repeat(largestPlaintext), "context", Duration.ofMinutes(1)).length());
		assertRejected(() -> sealer.seal("a".repeat(largestPlaintext + 1), "context", Duration.ofMinutes(1)));
	}

	private static StateSealer sealerWithMaximum(@Nullable Integer maximumSealedLength) {
		return StateSealer.withActiveKey(TestSealers.fixedKey(TestSealers.FIXED_KEY_ID))
				.maximumSealedLength(maximumSealedLength)
				.build();
	}

	private static void assertRejected(Executable executable) {
		Assertions.assertThrows(IllegalArgumentException.class, executable);
	}

	/**
	 * The package-private, test-only profile that sets every JSON row at its cap, read reflectively because it is
	 * deliberately not part of the internal API.
	 */
	private static JsonLimits maximumCaps() throws ReflectiveOperationException {
		Method maximumCaps = JsonLimits.class.getDeclaredMethod("maximumCaps");
		maximumCaps.setAccessible(true);
		return (JsonLimits) maximumCaps.invoke(null);
	}

	/**
	 * Every public {@link Limit} constant of {@link Limits}, by name, in declaration order.
	 */
	private static Map<String, Limit> constants() throws IllegalAccessException {
		Map<String, Limit> constants = new LinkedHashMap<>();
		for (Field field : Limits.class.getFields())
			if (field.getType() == Limit.class)
				constants.put(field.getName(), (Limit) field.get(null));
		return constants;
	}

	private static Limit limit(Row row) throws IllegalAccessException {
		return Objects.requireNonNull(constants().get(row.getConstant()),
				() -> "Limits has no public constant " + row.getConstant());
	}

	private static Row row(String constant) {
		return APPROVED_ROWS.stream()
				.filter(row -> row.getConstant().equals(constant))
				.findFirst()
				.orElseThrow(() -> new AssertionError("No approved row " + constant));
	}

	private static Row amounts(String constant, String name, Unit unit, long defaultValue, long floor, long cap) {
		return new Row(constant, name, unit, defaultValue, floor, cap, null, Duration.ZERO, Duration.ZERO,
				ZERO_REJECTED);
	}

	private static Row durations(String constant, String name, @Nullable Duration defaultValue, Duration floor,
			Duration cap, boolean zeroAllowed) {
		return new Row(constant, name, Unit.DURATION, 0, 0, 0, defaultValue, floor, cap, zeroAllowed);
	}

	/**
	 * A duration setting of {@link RemoteJsonWebKeySource.Builder}: its name, as the source's {@code toString()}
	 * shows it, its row, its setter, and the other settings that keep the time-to-live order for any value of it in
	 * range.
	 */
	private static final class DurationSetting {
		private final String name;
		private final String row;
		private final BiFunction<RemoteJsonWebKeySource.Builder, @Nullable Duration, RemoteJsonWebKeySource.Builder> setter;
		private final UnaryOperator<RemoteJsonWebKeySource.Builder> neighbors;

		private DurationSetting(String name, String row,
				BiFunction<RemoteJsonWebKeySource.Builder, @Nullable Duration, RemoteJsonWebKeySource.Builder> setter,
				UnaryOperator<RemoteJsonWebKeySource.Builder> neighbors) {
			this.name = name;
			this.row = row;
			this.setter = setter;
			this.neighbors = neighbors;
		}

		String getName() {
			return this.name;
		}

		String getRow() {
			return this.row;
		}

		RemoteJsonWebKeySource.Builder apply(RemoteJsonWebKeySource.Builder builder, @Nullable Duration value) {
			return this.setter.apply(builder, value);
		}

		RemoteJsonWebKeySource.Builder configure(RemoteJsonWebKeySource.Builder builder, Duration value) {
			return apply(this.neighbors.apply(builder), value);
		}
	}

	/**
	 * A count or size setting of {@link RemoteJsonWebKeySource.Builder}: its name, its row and its setter.
	 */
	private static final class AmountSetting {
		private final String name;
		private final String row;
		private final BiFunction<RemoteJsonWebKeySource.Builder, @Nullable Integer, RemoteJsonWebKeySource.Builder> setter;

		private AmountSetting(String name, String row,
				BiFunction<RemoteJsonWebKeySource.Builder, @Nullable Integer, RemoteJsonWebKeySource.Builder> setter) {
			this.name = name;
			this.row = row;
			this.setter = setter;
		}

		String getName() {
			return this.name;
		}

		String getRow() {
			return this.row;
		}

		RemoteJsonWebKeySource.Builder apply(RemoteJsonWebKeySource.Builder builder, @Nullable Integer value) {
			return this.setter.apply(builder, value);
		}
	}

	/**
	 * One transcribed row: a count, size or length row uses the amounts, and a duration row the durations.
	 */
	private static final class Row {
		private final String constant;
		private final String name;
		private final Unit unit;
		private final long defaultAmount;
		private final long floorAmount;
		private final long capAmount;
		private final @Nullable Duration defaultDuration;
		private final Duration floorDuration;
		private final Duration capDuration;
		private final boolean zeroAllowed;

		private Row(String constant, String name, Unit unit, long defaultAmount, long floorAmount, long capAmount,
				@Nullable Duration defaultDuration, Duration floorDuration, Duration capDuration, boolean zeroAllowed) {
			this.constant = constant;
			this.name = name;
			this.unit = unit;
			this.defaultAmount = defaultAmount;
			this.floorAmount = floorAmount;
			this.capAmount = capAmount;
			this.defaultDuration = defaultDuration;
			this.floorDuration = floorDuration;
			this.capDuration = capDuration;
			this.zeroAllowed = zeroAllowed;
		}

		String getConstant() {
			return this.constant;
		}

		String getName() {
			return this.name;
		}

		Unit getUnit() {
			return this.unit;
		}

		long getDefaultAmount() {
			return this.defaultAmount;
		}

		long getFloorAmount() {
			return this.floorAmount;
		}

		long getCapAmount() {
			return this.capAmount;
		}

		@Nullable Duration getDefaultDuration() {
			return this.defaultDuration;
		}

		Duration getFloorDuration() {
			return this.floorDuration;
		}

		Duration getCapDuration() {
			return this.capDuration;
		}

		boolean isZeroAllowed() {
			return this.zeroAllowed;
		}
	}
}
