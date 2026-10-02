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

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.Limit;
import com.revetsec.internal.Limits;
import com.revetsec.internal.ObserverDispatch;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.SealerV1;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.FormUrlEncoding;
import com.revetsec.internal.encoding.PercentDecoding;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.internal.encoding.SamlBase64;
import com.revetsec.internal.encoding.StandardBase64;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.http.HttpExchange;
import com.revetsec.internal.http.HttpExchangeException;
import com.revetsec.internal.http.HttpExchangeRequest;
import com.revetsec.internal.http.MediaType;
import com.revetsec.internal.http.RawResponse;
import com.revetsec.internal.http.ResponseProfile;
import com.revetsec.internal.jose.TestClaims;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonFieldException;
import com.revetsec.internal.json.JsonFields;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.internal.json.Rfc7638;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.pem.PemException;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JoseObserver;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JsonWebKeySetUnavailableException;
import com.revetsec.jose.JsonWebKeySkipReason;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.Jwt;
import com.revetsec.jose.JwtValidator;
import com.revetsec.jose.RemoteJsonWebKeySource;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.JsonText;
import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.Sentinels;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.function.ThrowingSupplier;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Deque;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * No rendering shows a secret (plan R9 and R16; M1 plan G6-1, G6-2 and G6-4; M1 exit criterion 17; M2 exit criterion
 * 20).
 * <p>
 * Every test plants {@link Sentinels} in the input of one surface and walks what Revetsec renders from it with
 * {@link Sentinels#findIn(Object)}: {@code toString()}, a JSON value's {@code toJson()}, an exception's message,
 * {@code toString()}, cause and suppressed chain and printed stack trace, and every argument recorded by a
 * {@link RecordingObserver}. The walker matches a sentinel's base64url, standard-base64 and hex forms too, so a token,
 * key or body echoed in encoded form is found. Suppression is disabled on every Revetsec exception, so a secret cannot
 * be attached to one later.
 * <p>
 * <strong>Observers.</strong> Every public failure (a {@link RevetsecException}) is also handed to the real
 * {@link JoseObserver} through {@link ObserverDispatch}: to {@code didFailToValidateJwt}, and a key-set failure to
 * {@code didFailToFetchJsonWebKeySet} too. It goes once to a recorded observer, which must record the same instance
 * (G6-4), and once to an observer that throws, whose contained failure's {@code com.revetsec} log record is walked
 * as well. An internal failure never reaches a hook, because Revetsec translates it first, so it is walked but not
 * dispatched. The JOSE components are run with recorded and throwing observers of their own, so every argument they
 * pass to a hook, and every log record of a hook that throws, is walked too.
 * <p>
 * <strong>The M1 surfaces:</strong> the JSON model and {@link JsonObject.Builder}; codec and field failures;
 * {@link SealingKey}, {@link StateSealer}, the internal sealer and their failures; encoding and PEM failures;
 * {@link OutboundUriPolicy}; {@link Limit}; and the internal HTTP helper's requests (the ones it refuses included),
 * responses and failures.
 * <p>
 * <strong>The JOSE surfaces</strong>, each group built once and walked by its own test:
 * <ul>
 *   <li>{@link JwtValidator#validate(String)} refusing tokens that carry sentinels in the header ({@code kid},
 *   {@code alg}, {@code typ}, {@code crit}, {@code zip}, {@code cty}, {@code jku}, {@code jwk} and duplicate members),
 *   in the claims (ones that fail each claim check included), in the signature segment and in the text around them,
 *   so that every {@link JoseException.Reason} is reached with a sentinel in its input: the exceptions, every hook
 *   argument, and the log records of a throwing observer;</li>
 *   <li>{@link JsonWebKeySet#fromJson(String)} over a key set with sentinels in private and symmetric members, in the
 *   {@code kid}, {@code use}, {@code alg}, {@code kty}, {@code issuer} and {@code x5c} of skipped keys, and in the
 *   {@code issuer} and an unknown member of a usable key; its refusals of documents that carry sentinels; and the key
 *   set, its keys, a {@link StaticJsonWebKeySource} and a {@link JwtValidator} over it;</li>
 *   <li>{@link RemoteJsonWebKeySource}, whose URI has a sentinel in its query, fetching that key set and failing on
 *   error, redirect, media-type, framing, malformed and oversized responses with sentinels in their bodies and
 *   headers, through {@link RemoteJsonWebKeySource#warmUp()} and through a validator; holding back a fetch, inside the
 *   backoff after each of those failures and inside the unknown-key cooldown; and a fetch whose leader is interrupted
 *   after its request was sent: the sources, the validators, the failures, every hook argument and every log
 *   record;</li>
 *   <li>accepted tokens whose claims, or {@code kid}, carry a sentinel: {@link Jwt} and its claims render none of
 *   them;</li>
 *   <li>the builders' refusals of settings that carry a sentinel, the builders themselves, and the enums.</li>
 * </ul>
 * {@link Jwt#toCompactSerialization()} and {@link com.revetsec.jose.JwtClaims#toJsonObject()} are explicit
 * emissions: an application calls them to get the token and its claims, so they are not walked, and positive
 * controls show that they do carry the sentinels. The claim getters likewise return what they are asked for. A usable
 * key's {@code kid} and a validator's issuer and audiences are configuration, which their {@code toString()} shows by
 * design, so no sentinel is planted there.
 * {@link #everyExportedConcreteJoseClassIsWalked()} checks that the surfaces hold an instance of every exported
 * concrete class of {@code com.revetsec.jose}, so a type added later cannot be forgotten;
 * {@link #everyJoseObserverHookIsWalked()} that the components fire every {@link JoseObserver} hook, with one
 * documented exception, to an observer whose recorded arguments are walked; and
 * {@link #everyJoseReasonIsReachedWithASentinelInItsInput()} that every reason is reached.
 * <p>
 * <strong>One documented exception.</strong> An I/O failure keeps the JDK's {@link IOException} as its cause
 * ({@link HttpExchangeException.Kind#IO} internally, and a transient {@link ErrorCategory#TRANSPORT}
 * {@link JsonWebKeySetUnavailableException} for the caller whose fetch failed; G6-2), and the JDK may copy
 * server-controlled text into that cause's message, for example a status line it rejects. That is the server's own
 * text echoed by the JDK, not something Revetsec rendered, so for I/O failures the server's sentinel may appear
 * inside the cause (and in the "Caused by" part of the printed stack trace), and nowhere else. The request's own
 * secrets, a key set URI's query included, appear nowhere, not even in the cause
 * ({@link #anIoFailureCarriesServerTextOnlyInsideTheJdkCause()}, and the key-set fetch surfaces).
 * <p>
 * Positive controls show the walker reaches what these tests rely on: a sentinel in a {@link JsonString} is found in
 * {@code toJson()} and not in {@code toString()}; a sentinel inside an exception passed to a recorded
 * {@link JoseObserver} hook is found; a sentinel in a log record's parameters is found; a sentinel claim that appears
 * only base64url-encoded, at payload offsets 0, 1 and 2 mod 3, is found in the token and in any rendering that echoes
 * it; and every planted token and key set document does carry its sentinel.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RedactionTests {
	private static final String SECRET = Sentinels.secret("redaction");
	private static final String HOOK_SECRET = Sentinels.secret("observer-failure");
	private static final String SUPPRESSED_SECRET = Sentinels.secret("suppressed");
	/**
	 * Server-controlled text in the IO cases, distinct from every secret a request carries, so the IO allowance can
	 * tell the server's echo from a request secret.
	 */
	private static final String SERVER_ECHO = Sentinels.secret("server-echo");
	/**
	 * A secret in a key set URI's query, such as an application ID: a source never renders its URI's query.
	 */
	private static final String URI_SECRET = Sentinels.secret("jwks-query");
	private static final String CONTEXT = "redaction-context";
	private static final JsonLimits PROTOCOL = JsonLimits.protocolDocument(4 * 1_024 * 1_024);
	private static final Instant START = Instant.parse("2026-09-24T12:00:00Z");
	private static final Instant NOW = Instant.parse("2026-09-27T12:00:00Z");
	private static final String ISSUER = "https://issuer.example.com";
	private static final String AUDIENCE = "https://api.example.com";
	private static final String KEY_ID = "key-1";
	private static final URI REPORTED_URI = URI.create("https://issuer.example.com/jwks");
	private static final Duration ELAPSED = Duration.ofMillis(3);
	private static final String JOSE_PACKAGE = "com.revetsec.jose";
	/**
	 * The {@link JoseObserver} hooks no surface fires. {@code didUseUnpatchedRuntime} fires only below the plan 9.6
	 * runtime floor, which a test can simulate only through a package-private seam of {@code com.revetsec.jose}, and
	 * its one argument is the running JDK's own version, which no token, key set or server chooses.
	 */
	private static final Set<String> UNWALKED_HOOKS = Set.of("didUseUnpatchedRuntime");
	/**
	 * The longest a surface waits for the server or a thread; each wait ends as soon as its condition holds.
	 */
	private static final Duration WAIT = Duration.ofSeconds(30);
	private static final Pattern HOOK_ARGUMENT = Pattern.compile(
			"\\$\\.getCalls\\(\\)\\[\\d+]\\.getArguments\\(\\)\\[\\d+]");
	private static final AtomicInteger NEXT_PATH = new AtomicInteger();

	private static @Nullable TestHttpsServer jdkServer;
	private static @Nullable RawTlsServer rawServer;
	private static @Nullable HttpExchange exchange;
	private static @Nullable HttpClient httpClient;
	/**
	 * The JOSE surfaces, built once for the class by the first test that needs them, because building them fetches
	 * key sets.
	 */
	private static @Nullable Map<Group, List<Surface>> builtJoseSurfaces;

	/**
	 * Held strongly for the whole test, because the logging system keeps loggers only weakly.
	 */
	private final Logger logger = Logger.getLogger(ObserverDispatch.LOGGER_NAME);
	private final RecordingHandler logRecords = new RecordingHandler();
	private @Nullable Level originalLevel;
	private boolean originalUseParentHandlers;

	@BeforeAll
	static void startServers() throws IOException {
		jdkServer = TestHttpsServer.start();
		rawServer = RawTlsServer.start();
		httpClient = TestTls.httpClient();
		exchange = HttpExchange.fromHttpClient(httpClient, OutboundUriPolicy.defaultInstance(), false);
	}

	@AfterAll
	static void stopServers() {
		builtJoseSurfaces = null;
		if (jdkServer != null)
			jdkServer.close();
		if (rawServer != null)
			rawServer.close();
	}

	@BeforeEach
	void recordObserverDispatchLogRecords() {
		this.originalLevel = this.logger.getLevel();
		this.originalUseParentHandlers = this.logger.getUseParentHandlers();
		// ObserverDispatch logs contained failures at FINE; record them here and keep them off the console.
		this.logger.setUseParentHandlers(false);
		this.logger.setLevel(Level.ALL);
		this.logger.addHandler(this.logRecords);
	}

	@AfterEach
	void restoreLogger() {
		this.logger.removeHandler(this.logRecords);
		this.logger.setLevel(this.originalLevel);
		this.logger.setUseParentHandlers(this.originalUseParentHandlers);
	}

	// Exit criterion 17, positive control: the walker reads toJson(), so a sentinel in a JsonString is found there, and
	// only there, because toString() is redacted.
	@Test
	void theWalkerFindsASentinelInAJsonStringsToJsonButNotInItsToString() {
		JsonString value = JsonString.fromValue(SECRET);

		Assertions.assertEquals(List.of("$.toJson()"), Sentinels.findIn(value));
		Assertions.assertEquals("JsonString{value=<redacted>}", value.toString());
		Assertions.assertTrue(value.toJson().contains(SECRET));
	}

	// Exit criteria 17 and 20, positive control: the walker reads the arguments a real JoseObserver hook recorded,
	// exception graphs included.
	@Test
	void theWalkerFindsASentinelInsideAnExceptionPassedToARecordedHook() {
		RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
		EchoingFailure failure = new EchoingFailure(new IOException("echoed " + SECRET));

		ObserverDispatch.dispatch(recorder.getObserver(), observer -> observer.didFailToValidateJwt(failure, ELAPSED));

		List<String> locations = Sentinels.findIn(recorder);
		Assertions.assertTrue(locations.contains("$.getCalls()[0].getArguments()[0].getCause().getMessage()"),
				locations::toString);
	}

	// Exit criterion 17, positive control: the walker reads a log record's parameters, so the checks on
	// ObserverDispatch's records below are not vacuous.
	@Test
	void theWalkerFindsASentinelInALogRecordsParameters() {
		LogRecord record = new LogRecord(Level.FINE, ObserverDispatch.FAILURE_MESSAGE);
		record.setParameters(new Object[]{SECRET, "java.lang.IllegalStateException"});

		List<String> locations = Sentinels.findIn(record);
		Assertions.assertTrue(locations.contains("$.getParameters()[0]"), locations::toString);
		Assertions.assertTrue(locations.contains("$ (formatted message)"), locations::toString);
	}

	// Exit criterion 20, positive control (the sentinel blind spot): a token whose only sentinel is a claim, so the
	// marker appears only base64url-encoded, at each payload alignment. The walker finds it in the token and in every
	// rendering that would echo the token; the validator that refuses it echoes nothing.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theWalkerFindsABase64UrlSentinelClaimAtEachAlignment() {
		JwtValidator validator = validator(rsaJwk(KEY_ID)).build();
		return IntStream.range(0, 3).mapToObj(alignment -> DynamicTest.dynamicTest("alignment " + alignment, () -> {
			String token = Sentinels.compactJwtWithSentinelClaim(alignment);
			String payload = new String(Base64Url.decode(token.substring(token.indexOf('.') + 1, token.lastIndexOf('.'))),
					StandardCharsets.UTF_8);
			Assertions.assertTrue(payload.contains(Sentinels.MARKER), "the claim carries the marker");
			Assertions.assertFalse(token.toLowerCase(Locale.ROOT).contains(Sentinels.MARKER),
					"the token carries it only base64url-encoded");

			Assertions.assertEquals(List.of("$"), Sentinels.findIn(token));
			Assertions.assertTrue(Sentinels.findIn(new IllegalStateException("echoed " + token))
					.contains("$.getMessage()"));
			Assertions.assertEquals(List.of("$.toJson()"), Sentinels.findIn(JsonString.fromValue(token)));
			RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
			ObserverDispatch.dispatch(recorder.getObserver(), observer -> observer.didFailToValidateJwt(
					new EchoingFailure(new IOException(token)), ELAPSED));
			Assertions.assertFalse(Sentinels.findIn(recorder).isEmpty());

			JoseException refused = Assertions.assertThrows(JoseException.class, () -> validator.validate(token));
			Assertions.assertEquals(JoseException.Reason.SIGNATURE_MISMATCH, refused.getReason());
			assertRedacted(refused);
		}));
	}

	// R9 and exit criterion 5: every JSON value's toString() is redacted, so a secret it holds appears only in
	// toJson(); the builder has no toJson() and renders nothing it holds.
	@Test
	void jsonValuesRenderTheirContentsOnlyThroughToJson() throws JsonParseException {
		JsonObject built = JsonObject.builder()
				.put(SECRET, SECRET)
				.put("count", 1L)
				.put("amount", new BigDecimal("1.5"))
				.put("enabled", Boolean.TRUE)
				.putNull("nothing")
				.build();
		List<JsonValue> withSecrets = List.of(
				JsonString.fromValue(SECRET),
				built,
				JsonObject.fromMembers(Map.of(SECRET, JsonString.fromValue("value"))),
				JsonObject.fromMembers(Map.of("name", JsonString.fromValue(SECRET))),
				JsonArray.fromElements(List.of(JsonString.fromValue(SECRET), built)),
				JsonCodec.parse(("{\"" + SECRET + "\":[\"" + SECRET + "\",{\"a\":\"" + SECRET + "\"}]}")
						.getBytes(StandardCharsets.UTF_8), PROTOCOL));

		for (JsonValue value : withSecrets)
			Assertions.assertEquals(List.of("$.toJson()"), Sentinels.findIn(value), value::toString);

		for (JsonValue value : List.of(JsonNumber.fromValue(12L), JsonBoolean.trueInstance(), JsonNull.defaultInstance(),
				JsonObject.emptyInstance(), JsonArray.emptyInstance()))
			Sentinels.assertAbsent(value);

		JsonObject.Builder builder = JsonObject.builder().put(SECRET, SECRET).put("other", JsonString.fromValue(SECRET));
		Assertions.assertEquals("JsonObject.Builder{members=<redacted>}", builder.toString());
		Sentinels.assertAbsent(builder);
	}

	// G7-6 and R15: the model's factories reject invalid input with a fixed message that never repeats it.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> jsonModelFailuresDoNotEchoTheirInput() {
		return Stream.of(
				failure("an unpaired surrogate in a string", IllegalArgumentException.class,
						() -> JsonString.fromValue(SECRET + "\uD800")),
				failure("an unpaired surrogate in a member name", IllegalArgumentException.class,
						() -> JsonObject.builder().put(SECRET + "\uDC00", SECRET)),
				failure("an unpaired surrogate in a map key", IllegalArgumentException.class,
						() -> JsonObject.fromMembers(Map.of(SECRET + "\uDC00", JsonString.fromValue(SECRET)))),
				failure("a repeated member name", IllegalArgumentException.class,
						() -> JsonObject.builder().put(SECRET, SECRET).put(SECRET, "second")),
				failure("depth 65", IllegalArgumentException.class, () -> {
					JsonValue value = JsonString.fromValue(SECRET);
					// A scalar is depth 1 and each array adds one (G7-6): 63 arrays reach the cap of 64, and one more fails.
					for (int depth = 1; depth < JsonLimits.MODEL_MAXIMUM_DEPTH; ++depth)
						value = JsonArray.fromElements(List.of(value));
					JsonArray.fromElements(List.of(value));
				}));
	}

	// G7-3 and exit criterion 2: every codec failure has a fixed message, a Kind and an offset, never the input.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> jsonParseFailuresDoNotEchoTheirInput() {
		String sentinelString = "\"" + SECRET + "\"";
		return Stream.of(
				parseFailure(JsonParseException.Kind.SYNTAX, PROTOCOL, utf8("{\"a\":" + sentinelString + " x}")),
				parseFailure(JsonParseException.Kind.INVALID_UTF8, PROTOCOL,
						concat(utf8("[" + sentinelString + ",\""), new byte[]{(byte) 0xFF}, utf8("\"]"))),
				parseFailure(JsonParseException.Kind.BOM, PROTOCOL,
						concat(new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF}, utf8(sentinelString))),
				parseFailure(JsonParseException.Kind.UNPAIRED_SURROGATE, PROTOCOL, utf8("\"" + SECRET + "\\uD800\"")),
				parseFailure(JsonParseException.Kind.DUPLICATE_MEMBER, PROTOCOL,
						utf8("{" + sentinelString + ":1," + sentinelString + ":2}")),
				parseFailure(JsonParseException.Kind.DUPLICATE_MEMBER, JsonLimits.scim(1_024, 1_000),
						utf8("{" + sentinelString + ":1,\"" + SECRET.toUpperCase(Locale.ROOT) + "\":2}")),
				parseFailure(JsonParseException.Kind.DEPTH, PROTOCOL,
						utf8("[".repeat(40) + sentinelString + "]".repeat(40))),
				parseFailure(JsonParseException.Kind.NODES, JsonLimits.scim(1_024 * 1_024, 1_000),
						utf8("[" + (sentinelString + ",").repeat(1_000) + sentinelString + "]")),
				parseFailure(JsonParseException.Kind.STRING_LENGTH, PROTOCOL,
						utf8("\"" + SECRET + "a".repeat(1_024 * 1_024) + "\"")),
				parseFailure(JsonParseException.Kind.NUMBER_LENGTH, PROTOCOL,
						utf8("{" + sentinelString + ":1" + "0".repeat(1_100) + "}")),
				parseFailure(JsonParseException.Kind.EXPONENT, PROTOCOL, utf8("{" + sentinelString + ":1e10001}")),
				parseFailure(JsonParseException.Kind.INPUT_SIZE, JsonLimits.protocolDocument(16),
						utf8("{\"a\":" + sentinelString + "}")));
	}

	// G6-2: field and thumbprint failures carry a Kind and a fixed message, never the member's name or value.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> jsonFieldFailuresDoNotEchoTheirInput() {
		JsonObject object = JsonObject.builder()
				.put(SECRET, JsonNumber.fromValue(1L))
				.put("aud", JsonArray.fromElements(List.of(JsonString.fromValue(SECRET), JsonNumber.fromValue(2L))))
				.put("exp", JsonNumber.fromValue(new BigDecimal("1E+300")))
				.build();
		return Stream.of(
				failure("a string field of the wrong type", JsonFieldException.class,
						() -> JsonFields.string(object, SECRET)),
				failure("a string-array field with a number", JsonFieldException.class,
						() -> JsonFields.stringOrStringArray(object, "aud")),
				failure("a NumericDate out of range", JsonFieldException.class,
						() -> JsonFields.numericDate(object, "exp")),
				failure("an unsupported kty", JsonFieldException.class,
						() -> Rfc7638.canonicalJwk(JsonObject.builder().put("kty", SECRET).build())),
				failure("a JWK member JSON must escape", JsonFieldException.class,
						() -> Rfc7638.canonicalJwk(JsonObject.builder().put("kty", "oct").put("k", SECRET + "\"").build())),
				failure("a missing JWK member", JsonFieldException.class,
						() -> Rfc7638.canonicalJwk(JsonObject.builder().put("kty", "RSA").put("n", SECRET).build())));
	}

	// R9, G6-8 and G6-9: keys and sealers never render key material, and sealed values never show their plaintext.
	@Test
	void keysAndSealersNeverRenderKeyMaterialOrPlaintext() throws Exception {
		String keyWithMarker = Sentinels.MARKER + "A".repeat(29) + "=";
		SealingKey key = SealingKey.fromBase64("2026-09", keyWithMarker);
		StateSealer sealer = StateSealer.withActiveKey(key)
				.verificationKeys(List.of(TestSealers.fixedKey("2026-06")))
				.build();
		String sealed = sealer.seal(Sentinels.SEALED_PLAINTEXT, CONTEXT, Duration.ofHours(1));
		String pending = SealedStateAccess.get().seal(sealer, SealedStateType.PENDING_AUTHORIZATION,
				Sentinels.SEALED_PLAINTEXT, CONTEXT, START.plusSeconds(3_600));
		byte[] masterKey = Sentinels.secret("master-key").substring(0, SealerV1.MASTER_KEY_LENGTH)
				.getBytes(StandardCharsets.US_ASCII);

		Assertions.assertEquals("SealingKey{keyId=2026-09, key=<redacted>}", key.toString());
		Sentinels.assertAbsent(List.of(key, StateSealer.withActiveKey(key), sealer, sealed, pending,
				SealerV1.Key.fromMasterKey("k", masterKey)));
		Assertions.assertEquals(Sentinels.SEALED_PLAINTEXT, sealer.unseal(sealed, CONTEXT));
	}

	// G6-8, G6-9 and exit criteria 8 and 9: every sealing, opening and key failure is fixed text, whatever the input
	// carried, and every failure to open is the one InvalidSealedStateException.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> sealerFailuresDoNotEchoTheirInput() {
		TestClock clock = TestClock.fromInstant(START);
		StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey(TestSealers.FIXED_KEY_ID)).clock(clock)
				.build();
		StateSealer otherSealer = StateSealer.withActiveKey(TestSealers.fixedKey("other")).clock(clock).build();
		String sealed = sealer.seal(Sentinels.SEALED_PLAINTEXT, CONTEXT, Duration.ofSeconds(1));
		String sealedByOther = otherSealer.seal(Sentinels.SEALED_PLAINTEXT, CONTEXT, Duration.ofHours(1));
		String tampered = sealed.substring(0, sealed.length() / 2)
				+ (sealed.charAt(sealed.length() / 2) == 'A' ? 'B' : 'A') + sealed.substring(sealed.length() / 2 + 1);
		String pending = SealedStateAccess.get().seal(sealer, SealedStateType.PENDING_AUTHORIZATION,
				Sentinels.SEALED_PLAINTEXT, CONTEXT, START.plusSeconds(60));
		String keyWithMarker = Sentinels.MARKER + "A".repeat(29) + "=";

		return Stream.of(
				failure("unseal garbage", InvalidSealedStateException.class, () -> sealer.unseal(SECRET, CONTEXT)),
				failure("unseal an over-length value", InvalidSealedStateException.class,
						() -> sealer.unseal(SECRET.repeat(200), CONTEXT)),
				failure("unseal a tampered value", InvalidSealedStateException.class, () -> sealer.unseal(tampered, CONTEXT)),
				failure("unseal under another context", InvalidSealedStateException.class,
						() -> sealer.unseal(sealed, SECRET)),
				failure("unseal under an unknown key ID", InvalidSealedStateException.class,
						() -> sealer.unseal(sealedByOther, CONTEXT)),
				failure("unseal an expired value", InvalidSealedStateException.class, () -> {
					clock.set(START.plusSeconds(2));
					sealer.unseal(sealed, CONTEXT);
				}),
				failure("unseal pending state under another type", UnsealException.class,
						() -> SealedStateAccess.get().unseal(sealer, SealedStateType.PENDING_SAML, pending, CONTEXT, clock)),
				failure("unseal garbage as pending state", UnsealException.class,
						() -> SealedStateAccess.get().unseal(sealer, SealedStateType.PENDING_AUTHORIZATION, SECRET, CONTEXT,
								clock)),
				failure("seal a plaintext with an unpaired surrogate", IllegalArgumentException.class,
						() -> sealer.seal(Sentinels.SEALED_PLAINTEXT + "\uD800", CONTEXT, Duration.ofHours(1))),
				failure("seal an oversized plaintext", IllegalArgumentException.class,
						() -> sealer.seal(Sentinels.SEALED_PLAINTEXT.repeat(100), CONTEXT, Duration.ofHours(1))),
				failure("seal under a context with an unpaired surrogate", IllegalArgumentException.class,
						() -> sealer.seal("x", SECRET + "\uDC00", Duration.ofHours(1))),
				failure("seal under an over-length context", IllegalArgumentException.class,
						() -> sealer.seal("x", SECRET.repeat(10), Duration.ofHours(1))),
				failure("a key ID outside the alphabet", IllegalArgumentException.class,
						() -> SealingKey.fromBase64(SECRET + "!", keyWithMarker)),
				failure("key text of the wrong length", IllegalArgumentException.class,
						() -> SealingKey.fromBase64("k", Sentinels.MARKER + "A".repeat(30))),
				failure("key text outside the alphabet", IllegalArgumentException.class,
						() -> SealingKey.fromBase64("k", SECRET + "!!!!!!")),
				failure("two keys with the same bytes", IllegalArgumentException.class,
						() -> Assertions.assertNotNull(StateSealer.withActiveKey(SealingKey.fromBase64("one", keyWithMarker))
								.verificationKeys(List.of(SealingKey.fromBase64("two", keyWithMarker)))
								.build())),
				failure("two keys with the same key ID", IllegalArgumentException.class,
						() -> Assertions.assertNotNull(StateSealer.withActiveKey(SealingKey.fromBase64("same", keyWithMarker))
								.verificationKeys(List.of(TestSealers.fixedKey("same")))
								.build())));
	}

	// G6-2 and exit criterion 6: encoding failures carry a Kind and a fixed message, never the input; parsed query
	// parameters render redacted.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> encodingFailuresDoNotEchoTheirInput() throws EncodingException {
		QueryParameters parameters = QueryParameters.parse("code=" + SECRET + "&" + SECRET + "=state");
		Assertions.assertEquals(List.of(SECRET), parameters.getValues("code"), "the control: the value is there");
		Sentinels.assertAbsent(parameters);
		Sentinels.assertAbsent(parameters.getParameters());

		return Stream.of(
				failure("base64url outside the alphabet", EncodingException.class, () -> Base64Url.decode(SECRET + "!")),
				failure("base64url with padding", EncodingException.class, () -> Base64Url.decode(SECRET + "==")),
				failure("standard base64 outside the alphabet", EncodingException.class,
						() -> StandardBase64.decode(SECRET)),
				failure("SAML base64 outside the alphabet", EncodingException.class, () -> SamlBase64.decode(SECRET)),
				failure("form encoding with a malformed escape", EncodingException.class,
						() -> FormUrlEncoding.decode(SECRET + "%zz")),
				failure("form encoding of an unpaired surrogate", EncodingException.class,
						() -> FormUrlEncoding.encode(SECRET + "\uD800")),
				failure("percent-encoded invalid UTF-8", EncodingException.class,
						() -> PercentDecoding.decode(SECRET + "%C3%28")),
				failure("a query with a malformed escape", EncodingException.class,
						() -> QueryParameters.parse("code=" + SECRET + "&state=%GG")),
				failure("strict UTF-8 decoding", EncodingException.class,
						() -> StrictUtf8.decode(concat(utf8(SECRET), new byte[]{(byte) 0xFF}))),
				failure("strict UTF-8 encoding", EncodingException.class, () -> StrictUtf8.encode(SECRET + "\uDC00")));
	}

	// G6-2 and exit criterion 6: PEM failures carry a Kind and a fixed message, never the text, the label or the DER.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> pemFailuresDoNotEchoTheirInput() throws Exception {
		String certificatePem = resource("/fixtures/keys/idp-signing-rsa-2048-cert.pem");
		String privateKeyPem = resource("/fixtures/keys/idp-signing-rsa-2048-key.pem");
		byte[] certificateDer = Pem.parseCertificate(certificatePem).getEncoded();
		byte[] derWithSentinel = concat(certificateDer, utf8(SECRET));

		return Stream.of(
				failure("text after the certificate block", PemException.class,
						() -> Pem.parseCertificate(certificatePem + SECRET + "\n")),
				failure("a body outside the base64 alphabet", PemException.class,
						() -> Pem.parseCertificate(pem("CERTIFICATE", SECRET))),
				failure("a body that is not DER", PemException.class,
						() -> Pem.parseCertificate(pem("CERTIFICATE", base64(utf8(SECRET))))),
				failure("DER bytes after the certificate", PemException.class,
						() -> Pem.parseCertificate(pem("CERTIFICATE", base64(derWithSentinel)))),
				failure("DER bytes after the certificate, as DER", PemException.class,
						() -> Pem.parseCertificateDer(derWithSentinel)),
				failure("an unknown label", PemException.class,
						() -> Pem.parsePublicKey(pem(SECRET.toUpperCase(Locale.ROOT), base64(certificateDer)))),
				failure("a private key that is not DER", PemException.class,
						() -> Pem.parsePrivateKey(pem("PRIVATE KEY", base64(utf8(SECRET))))),
				failure("a SEC1 key", PemException.class,
						() -> Pem.parsePrivateKey(pem("EC PRIVATE KEY", base64(utf8(SECRET))))),
				failure("an encrypted key", PemException.class,
						() -> Pem.parsePrivateKey(pem("ENCRYPTED PRIVATE KEY", base64(utf8(SECRET))))),
				failure("text after the private key block", PemException.class,
						() -> Pem.parsePrivateKey(privateKeyPem + SECRET)));
	}

	// A-1 and R8: the outbound policy and the limits registry render no input, and a rejected setting repeats only
	// the number.
	@Test
	void theOutboundPolicyAndTheLimitsRenderNoInput() {
		OutboundUriPolicy policy = OutboundUriPolicy.defaultInstance();
		Assertions.assertFalse(policy.permits(URI.create("https://user:" + SECRET + "@169.254.169.254/" + SECRET
				+ "?token=" + SECRET)));
		Assertions.assertTrue(policy.permits(URI.create("https://idp.example/" + SECRET + "?token=" + SECRET)));
		Sentinels.assertAbsent(policy);

		for (Limit limit : Limits.all()) {
			Sentinels.assertAbsent(limit);
			Executable outOfRange = limit.getUnit() == Limit.Unit.DURATION
					? () -> limit.require(Duration.ofSeconds(-1))
					: () -> limit.require(-1L);
			assertRedacted(Assertions.assertThrows(IllegalArgumentException.class, outOfRange, limit::getName));
		}
		for (JsonLimits profile : List.of(PROTOCOL, JsonLimits.jose(1_024), JsonLimits.scim(1_024, 1_000)))
			Sentinels.assertAbsent(profile);
	}

	// R9 and G6-4: requests render their method, their URI cut to scheme, host, port and path, their profile, limits
	// and header names; responses their status, media type, header names and body length. Never a query, a header
	// value, a form body, a media-type parameter value or a body byte.
	@Test
	void httpRequestsAndResponsesRenderNoSecrets() throws Exception {
		HttpExchangeRequest request = requestWithSecrets(URI.create("https://user:" + SECRET + "@example.com/token"),
				ResponseProfile.TOKEN, 1_024);
		Assertions.assertTrue(request.toString().contains("https://example.com/token"), request::toString);
		Sentinels.assertAbsent(request);
		Sentinels.assertAbsent(MediaType.parse("application/json; charset=utf-8; token=" + SECRET).orElseThrow());
		Sentinels.assertAbsent(List.of(exchange(), Deadline.fromNow(Duration.ofSeconds(1))));

		String success = scriptJdk(TestHttpsServer.Response.withStatus(200)
				.header("Content-Type", "application/json")
				.header("X-Echo", SECRET)
				.body("{\"access_token\":\"" + SECRET + "\"}")
				.build());
		RawResponse successResponse = exchange().execute(requestWithSecrets(jdk().uri(success), ResponseProfile.TOKEN,
				1_024), deadline());
		Assertions.assertEquals(200, successResponse.status());
		Sentinels.assertPresent(successResponse.body());
		Sentinels.assertAbsent(successResponse);

		String kept = scriptJdk(TestHttpsServer.Response.withStatus(400)
				.header("Content-Type", "application/json")
				.header("WWW-Authenticate", "Bearer error_description=\"" + SECRET + "\"")
				.body("{\"error\":\"invalid_grant\",\"error_description\":\"" + SECRET + "\"}")
				.build());
		RawResponse keptResponse = exchange().execute(requestWithSecrets(jdk().uri(kept), ResponseProfile.TOKEN, 1_024),
				deadline());
		Assertions.assertEquals(400, keptResponse.status());
		Sentinels.assertPresent(keptResponse.body());
		Sentinels.assertAbsent(keptResponse);

		String dropped = scriptJdk(TestHttpsServer.Response.withStatus(503)
				.header("Content-Type", "application/json")
				.header("Content-Encoding", "gzip")
				.body(SECRET)
				.build());
		RawResponse droppedResponse = exchange().execute(requestWithSecrets(jdk().uri(dropped), ResponseProfile.TOKEN,
				1_024), deadline());
		Assertions.assertTrue(droppedResponse.errorBodyDropped());
		Sentinels.assertAbsent(List.of(droppedResponse, droppedResponse.body()));
	}

	// R9 and R15: a request the helper refuses fails with a fixed message, never the credential it carried in a header
	// value, a header name or the form body.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> httpRequestMisuseDoesNotEchoCredentials() {
		URI uri = URI.create("https://idp.example/token");
		Duration timeout = Duration.ofSeconds(10);
		return Stream.of(
				failure("a header value with a line break", IllegalArgumentException.class,
						() -> new HttpExchangeRequest(uri, ResponseProfile.TOKEN, null,
								Map.of("Authorization", "Bearer " + Sentinels.ACCESS_TOKEN + "\r\nX-Injected: " + SECRET), 1_024,
								1_024, timeout)),
				failure("a header name that is not a token", IllegalArgumentException.class,
						() -> new HttpExchangeRequest(uri, ResponseProfile.TOKEN, null, Map.of(SECRET + " name", "value"),
								1_024, 1_024, timeout)),
				failure("a reserved header name", IllegalArgumentException.class,
						() -> new HttpExchangeRequest(uri, ResponseProfile.TOKEN, null,
								Map.of("Content-Type", "application/json; token=" + SECRET), 1_024, 1_024, timeout)),
				failure("a form body that is not US-ASCII", IllegalArgumentException.class,
						() -> new HttpExchangeRequest(uri, ResponseProfile.TOKEN, "client_secret=" + Sentinels.CLIENT_SECRET
								+ "\u00E9", Map.of(), 1_024, 1_024, timeout)));
	}

	// G6-2, G6-7 and exit criterion 12: every HTTP failure is its Kind's fixed sentence, with no cause except IO's,
	// whatever secrets the request or the response carried.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> httpFailuresDoNotEchoTheRequestOrTheResponse() {
		String jsonWithSecret = "{\"token\":\"" + SECRET + "\"}";
		return Stream.of(
				httpFailure("plain http", HttpExchangeException.Kind.URI_REJECTED,
						() -> execute(URI.create("http://idp.example/" + SECRET))),
				httpFailure("a link-local address", HttpExchangeException.Kind.URI_REJECTED,
						() -> execute(URI.create("https://169.254.169.254/" + SECRET))),
				httpFailure("user information", HttpExchangeException.Kind.URI_REJECTED,
						() -> execute(URI.create("https://user:" + SECRET + "@idp.example/"))),
				httpFailure("no time left", HttpExchangeException.Kind.TIMEOUT,
						() -> exchange().execute(requestWithSecrets(jdk().uri("/never-requested"), ResponseProfile.TOKEN,
								1_024), Deadline.fromNow(Duration.ZERO))),
				httpFailure("an interrupted thread", HttpExchangeException.Kind.INTERRUPTED, () -> {
					Thread.currentThread().interrupt();
					try {
						execute(jdk().uri("/never-requested"));
					} finally {
						Assertions.assertTrue(Thread.interrupted(), "the interrupt flag stays set");
					}
				}),
				httpFailure("a redirect", HttpExchangeException.Kind.REDIRECT,
						() -> execute(jdk().uri(scriptJdk(TestHttpsServer.Response.withStatus(302)
								.header("Location", "https://idp.example/callback?token=" + SECRET)
								.header("Content-Type", "application/json")
								.body(jsonWithSecret)
								.build())))),
				httpFailure("an unknown content encoding", HttpExchangeException.Kind.CONTENT_ENCODING,
						() -> execute(jdk().uri(scriptJdk(TestHttpsServer.Response.withStatus(200)
								.header("Content-Type", "application/json")
								.header("Content-Encoding", SECRET)
								.body(jsonWithSecret)
								.build())))),
				httpFailure("a charset other than utf-8", HttpExchangeException.Kind.MEDIA_TYPE,
						() -> execute(jdk().uri(scriptJdk(TestHttpsServer.Response.withStatus(200)
								.header("Content-Type", "application/json; charset=" + SECRET)
								.body(jsonWithSecret)
								.build())))),
				httpFailure("an unlisted media type", HttpExchangeException.Kind.MEDIA_TYPE,
						() -> execute(jdk().uri(scriptJdk(TestHttpsServer.Response.withStatus(200)
								.header("Content-Type", "text/" + SECRET)
								.body(SECRET)
								.build())))),
				httpFailure("a body over the limit", HttpExchangeException.Kind.TOO_LARGE,
						() -> exchange().execute(requestWithSecrets(jdk().uri(scriptJdk(
								TestHttpsServer.Response.withStatus(200)
										.header("Content-Type", "application/json")
										.body(jsonWithSecret.repeat(10))
										.build())), ResponseProfile.TOKEN, 64), deadline())),
				httpFailure("an unknown transfer coding", HttpExchangeException.Kind.FRAMING,
						() -> execute(raw().uri(scriptRaw(RawTlsServer.Script.fromString("HTTP/1.1 200 OK\r\n"
								+ "Content-Type: application/json\r\n"
								+ "Transfer-Encoding: " + SECRET + "\r\n"
								+ "\r\n"
								+ jsonWithSecret))))));
	}

	// G6-2: an IO failure keeps the JDK's IOException as its cause, and the JDK may copy server text into that cause's
	// message. For the status line below, JDK 17 and 27 throw ProtocolException 'Invalid status line: "HTTP/1.1 099
	// <reason phrase>"'; for the short body, an IOException that names only the byte counts. That is server echo, not a
	// Revetsec rendering, so the server's sentinel may appear inside the cause and nowhere else: not in Revetsec's
	// message, toString or stack frames. The request's secrets appear nowhere at all, so an IOException Revetsec made
	// itself cannot carry them. This internal failure never reaches a hook; the key-set fetch surfaces check the public
	// exception that carries such a cause to the real JoseObserver hooks.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> anIoFailureCarriesServerTextOnlyInsideTheJdkCause() {
		return Stream.of(
				DynamicTest.dynamicTest("a status line the JDK rejects", () -> assertServerEchoOnlyInCause(
						raw().uri(scriptRaw(statusLineTheJdkRejects())))),
				DynamicTest.dynamicTest("a body the server cuts short", () -> assertServerEchoOnlyInCause(
						raw().uri(scriptRaw(bodyTheServerCutsShort("application/json"))))));
	}

	// G6-4 and exit criteria 17 and 20: a public failure reaches the real JoseObserver's failure hook as the same
	// instance, and neither the recorded arguments nor the contained hook failure's log record carries a sentinel.
	@Test
	void aPublicFailureReachesTheRealObserverAsTheSameInstanceWithoutASentinel() {
		StateSealer sealer = TestSealers.fromFixedKey();
		InvalidSealedStateException failure = Assertions.assertThrows(InvalidSealedStateException.class,
				() -> sealer.unseal(SECRET, CONTEXT));

		RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
		ObserverDispatch.dispatch(recorder.getObserver(), observer -> observer.didFailToValidateJwt(failure, ELAPSED));
		Assertions.assertSame(failure, recorder.getCalls("didFailToValidateJwt").get(0).getArgument(0));
		Sentinels.assertAbsent(recorder);

		RecordingObserver<JoseObserver> throwing = RecordingObserver.fromInterface(JoseObserver.class,
				() -> new IllegalStateException(HOOK_SECRET));
		ObserverDispatch.dispatch(throwing.getObserver(), observer -> observer.didFailToValidateJwt(failure, ELAPSED));
		Assertions.assertEquals(1, this.logRecords.getRecords().size(), "the contained hook failure was logged");
		Sentinels.assertAbsent(List.of(throwing, this.logRecords.getRecords()));
	}

	// R9, INV-G9 and exit criterion 20: JwtValidator.validate refuses tokens that carry sentinels in every part a token
	// has, one or more for every JoseException.Reason, and neither the exception nor any hook argument nor the log
	// record of a throwing observer carries one.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectedTokensRevealNothing() {
		return dynamicTests(Group.REJECTED_TOKENS);
	}

	// R9, INV-G9, M2-7 and exit criterion 20: a key set whose skipped keys carry sentinels in their private, symmetric
	// and other members, and whose usable key carries them in members it never renders, shows none of them, nor does
	// anything built over it; a document that fails with a sentinel in it echoes nothing.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> keySetDocumentsRevealNothing() {
		return dynamicTests(Group.KEY_SETS);
	}

	// R9, R12, INV-G9, M2-3 and exit criterion 20: a remote key source whose URI has a secret in its query, fetching
	// key sets and error responses that carry sentinels in their bodies and headers, renders none of them in its
	// toString, its failures, any hook argument (the skipped keys are named by index) or any log record. The one
	// allowance is a JDK IOException cause, which may echo the server's text, never the request's.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> keySetFetchesRevealNothing() {
		return dynamicTests(Group.KEY_SET_FETCHES);
	}

	// R9, R17 and exit criterion 20: an accepted token's Jwt and claims render nothing of the token, its kid or its
	// claims, nor does any hook argument; the explicit emissions, toCompactSerialization() and toJsonObject(), do carry
	// them, which shows the sentinels were there.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> acceptedTokensShowTheirContentOnlyOnRequest() {
		return dynamicTests(Group.ACCEPTED_TOKENS);
	}

	// R9, R15 and exit criterion 20: the builders refuse settings that carry a sentinel with fixed messages, the
	// builders themselves render nothing they hold, and the enums render their names.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> joseConfigurationAndItsRefusalsRevealNothing() {
		return dynamicTests(Group.CONFIGURATION);
	}

	// Exit criterion 20 (plan M2, contract-list change 5): the JOSE surfaces hold, among the objects they walk, an
	// instance of every exported concrete class of com.revetsec.jose (public top-level classes and enums, and their
	// public nested ones), read from the sources, so a class added later fails here until a surface walks it.
	@Test
	void everyExportedConcreteJoseClassIsWalked() throws IOException, ClassNotFoundException {
		List<Class<?>> exported = exportedConcreteJoseClasses();
		for (Class<?> expected : List.of(Jwt.class, com.revetsec.jose.JwtClaims.class, JwtValidator.Builder.class,
				RemoteJsonWebKeySource.Builder.class, JoseException.Reason.class, JsonWebKeySkipReason.class))
			Assertions.assertTrue(exported.contains(expected), () -> "the source scan finds " + expected.getName());
		for (Class<?> notConcrete : List.of(JoseException.class, JoseObserver.class,
				com.revetsec.jose.JsonWebKeySource.class))
			Assertions.assertFalse(exported.contains(notConcrete), notConcrete::getName);

		List<Object> walked = new ArrayList<>();
		for (List<Surface> surfaces : joseSurfaces().values())
			for (Surface surface : surfaces)
				if (surface.getCheck().isWalk())
					collectRendered(surface.getValue(), walked);

		List<String> missing = new ArrayList<>();
		for (Class<?> type : exported)
			if (walked.stream().noneMatch(type::isInstance))
				missing.add(type.getName());
		ContractSupport.assertNoViolations("Exported concrete JOSE classes that no redaction surface walks", missing);
	}

	// Exit criterion 20 (M2-3): the components fire every JoseObserver hook, didUseUnpatchedRuntime aside (see
	// UNWALKED_HOOKS), to a recorded observer whose arguments a surface walks, so a hook added later, or one no surface
	// reaches, such as a held-back fetch's, fails here until a redaction case fires it.
	@Test
	void everyJoseObserverHookIsWalked() {
		Set<String> hooks = new TreeSet<>();
		for (Method method : JoseObserver.class.getDeclaredMethods())
			if (Modifier.isPublic(method.getModifiers()) && !Modifier.isStatic(method.getModifiers())
					&& !method.isSynthetic())
				hooks.add(method.getName());
		Assertions.assertTrue(hooks.containsAll(UNWALKED_HOOKS), () -> "stale unwalked hooks: " + UNWALKED_HOOKS);
		hooks.removeAll(UNWALKED_HOOKS);

		Set<String> walked = new TreeSet<>();
		for (List<Surface> surfaces : joseSurfaces().values())
			for (Surface surface : surfaces)
				if (surface.getCheck() == Check.HOOK_ARGUMENTS)
					for (RecordingObserver.Call call : ((RecordingObserver<?>) surface.getValue()).getCalls())
						walked.add(call.getMethodName());
		Assertions.assertEquals(hooks, walked, "the hooks whose recorded arguments are walked");
	}

	// Exit criterion 20: every JoseException.Reason is reached by a surface whose input carries a sentinel, so a
	// reason added later fails here until a redaction case covers it.
	@Test
	void everyJoseReasonIsReachedWithASentinelInItsInput() {
		Set<JoseException.Reason> reached = EnumSet.noneOf(JoseException.Reason.class);
		for (List<Surface> surfaces : joseSurfaces().values())
			for (Surface surface : surfaces)
				if (surface.getCheck() == Check.FAILURE && surface.getExpected() instanceof JoseException.Reason reason)
					reached.add(reason);
		Assertions.assertEquals(EnumSet.allOf(JoseException.Reason.class), reached);
	}

	/**
	 * A dynamic test that expects {@code executable} to throw {@code type} and asserts the failure is redacted.
	 */
	private <T extends Throwable> @NonNull DynamicTest failure(@NonNull String name, @NonNull Class<@NonNull T> type, @NonNull Executable executable) {
		return DynamicTest.dynamicTest(name, () -> assertRedacted(Assertions.assertThrows(type, executable)));
	}

	private @NonNull DynamicTest parseFailure(JsonParseException.@NonNull Kind kind, @NonNull JsonLimits limits, byte @NonNull [] input) {
		String name = kind.name() + (limits.isAsciiCaseVariantNamesRejected() ? " (SCIM profile)" : "");
		return DynamicTest.dynamicTest(name, () -> {
			Sentinels.assertPresent(input);
			JsonParseException failure = Assertions.assertThrows(JsonParseException.class,
					() -> JsonCodec.parse(input, limits));
			Assertions.assertEquals(kind, failure.getKind());
			assertRedacted(failure);
		});
	}

	private @NonNull DynamicTest httpFailure(@NonNull String name, HttpExchangeException.@NonNull Kind kind, @NonNull Executable executable) {
		return DynamicTest.dynamicTest(kind.name() + ": " + name, () -> {
			HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class, executable);
			Assertions.assertEquals(kind, failure.getKind());
			Assertions.assertNull(failure.getCause(), "only IO keeps a cause");
			assertRedacted(failure);
		});
	}

	private @NonNull Stream<@NonNull DynamicTest> dynamicTests(@NonNull Group group) {
		return Objects.requireNonNull(joseSurfaces().get(group)).stream()
				.map(surface -> DynamicTest.dynamicTest(surface.getName(), () -> verify(surface)));
	}

	/**
	 * Checks one JOSE surface as its {@link Check} says.
	 */
	private void verify(@NonNull Surface surface) {
		Object value = surface.getValue();
		switch (surface.getCheck()) {
			case PRESENT -> Sentinels.assertPresent(value);
			case ENCODED_ONLY -> {
				String text = (String) value;
				Assertions.assertFalse(text.toLowerCase(Locale.ROOT).contains(Sentinels.MARKER), "only encoded");
				Sentinels.assertPresent(text);
			}
			case RENDERING -> Sentinels.assertAbsent(value);
			case FAILURE -> {
				Throwable failure = (Throwable) value;
				assertExpected(surface.getExpected(), failure);
				assertRedacted(failure);
			}
			case SERVER_ECHO_IN_CAUSE -> {
				Throwable failure = (Throwable) value;
				assertExpected(surface.getExpected(), failure);
				assertRedactedExceptInsideTheJdkCause(failure);
			}
			case HOOK_ARGUMENTS -> {
				RecordingObserver<?> recorder = (RecordingObserver<?>) value;
				Assertions.assertFalse(recorder.getCalls().isEmpty(), "the component reported to its observer");
				assertHookArgumentsRedacted(recorder);
			}
			case LOG_RECORDS -> {
				List<?> records = (List<?>) value;
				Assertions.assertFalse(records.isEmpty(), "the throwing observer's failures were logged");
				Sentinels.assertAbsent(records);
			}
		}
	}

	private static void assertExpected(@Nullable Object expected, @NonNull Throwable failure) {
		if (expected instanceof JoseException.Reason reason) {
			JoseException exception = Assertions.assertInstanceOf(JoseException.class, failure);
			Assertions.assertEquals(reason, exception.getReason());
		} else if (expected instanceof ErrorCategory category) {
			JsonWebKeySetUnavailableException exception = Assertions.assertInstanceOf(
					JsonWebKeySetUnavailableException.class, failure);
			Assertions.assertEquals(category, exception.getCategory());
		} else if (expected instanceof Class<?> type) {
			Assertions.assertInstanceOf(type, failure);
		} else {
			Assertions.fail("A failure surface names what it expects");
		}
	}

	/**
	 * No rendering of {@code failure} carries a sentinel; nothing can be attached to a Revetsec exception later; and a
	 * public failure, handed to the real {@link JoseObserver} hooks through {@link ObserverDispatch}, is recorded as
	 * the same instance with no sentinel, while the log record of a hook that throws carries none either.
	 */
	private void assertRedacted(@NonNull Throwable failure) {
		Sentinels.assertAbsent(failure);
		assertSuppressionDisabledOnRevetsecExceptions(failure);
		Sentinels.assertAbsent(failure);

		if (failure instanceof RevetsecException exception)
			Sentinels.assertAbsent(dispatchToObservers(exception));
	}

	/**
	 * {@link #assertRedacted(Throwable)} with the documented IO allowance (see the class description): the server's
	 * text may appear inside the JDK cause, and only there, in the failure and in the hook arguments that carry it.
	 */
	private void assertRedactedExceptInsideTheJdkCause(@NonNull Throwable failure) {
		assertEchoOnlyInsideTheJdkCause(failure);
		assertSuppressionDisabledOnRevetsecExceptions(failure);
		assertEchoOnlyInsideTheJdkCause(failure);

		if (failure instanceof RevetsecException exception)
			assertHookArgumentsRedacted(dispatchToObservers(exception));
	}

	/**
	 * The documented IO allowance for {@link HttpExchangeException}, which never reaches a hook.
	 */
	private static void assertServerEchoOnlyInCause(@NonNull URI uri) {
		HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class, () -> execute(uri));
		Assertions.assertEquals(HttpExchangeException.Kind.IO, failure.getKind());
		assertEchoOnlyInsideTheJdkCause(failure);
	}

	/**
	 * The documented IO allowance (see the class description): the failure's cause is the JDK's {@link IOException},
	 * every place the walker finds a sentinel is inside that cause, and the only sentinel there is the server's
	 * {@link #SERVER_ECHO}, never a secret the request carried.
	 */
	private static void assertEchoOnlyInsideTheJdkCause(@NonNull Throwable failure) {
		IOException cause = Assertions.assertInstanceOf(IOException.class, failure.getCause());
		for (@Nullable Throwable link = cause; link != null; link = link.getCause()) {
			String name = link.getClass().getName();
			Assertions.assertTrue(isJdkClassName(name), "a JDK exception, not " + name);
			// A JDK exception class does not prove the JDK wrote the text: Revetsec may create an IOException too.
			String message = String.valueOf(link.getMessage());
			Assertions.assertFalse(Sentinels.containsSentinel(message.replace(SERVER_ECHO, "")),
					() -> "a request secret in the cause chain: " + message);
		}

		Sentinels.assertAbsent(List.of(String.valueOf(failure.getMessage()), String.valueOf(failure.getLocalizedMessage()),
				failure.toString()));
		String printed = printedStackTrace(failure);
		int causedBy = printed.indexOf("Caused by: ");
		Assertions.assertTrue(causedBy > 0, printed);
		Sentinels.assertAbsent(printed.substring(0, causedBy));
		Assertions.assertFalse(Sentinels.containsSentinel(printed.replace(SERVER_ECHO, "")),
				() -> "a request secret in the printed stack trace: " + printed);
		assertOnlyInCause(Sentinels.findIn(failure), "$");
	}

	/**
	 * Every argument a hook recorded is free of sentinels, except that a failure whose cause is the JDK's
	 * {@link IOException} gets the IO allowance.
	 */
	private static void assertHookArgumentsRedacted(@NonNull RecordingObserver<?> recorder) {
		for (RecordingObserver.Call call : recorder.getCalls()) {
			Assertions.assertFalse(Sentinels.containsSentinel(call.getMethodName()));
			for (@Nullable Object argument : call.getArguments()) {
				if (argument instanceof Throwable throwable && throwable.getCause() instanceof IOException)
					assertEchoOnlyInsideTheJdkCause(throwable);
				else
					Sentinels.assertAbsent(argument);
			}
		}
		for (String location : Sentinels.findIn(recorder))
			Assertions.assertTrue(HOOK_ARGUMENT.matcher(location).lookingAt()
					&& (location.contains(".getCause()") || location.endsWith(" (printed stack trace)")),
					() -> "outside a JDK cause: " + location);
	}

	/**
	 * Hands {@code failure} to the real {@link JoseObserver} failure hooks through {@link ObserverDispatch}, recorded,
	 * and then again to hooks that throw an exception carrying a sentinel, and checks that ObserverDispatch logged each
	 * contained failure without a sentinel.
	 */
	private @NonNull RecordingObserver<@NonNull JoseObserver> dispatchToObservers(@NonNull RevetsecException failure) {
		RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
		dispatchFailureHooks(recorder.getObserver(), failure);
		for (RecordingObserver.Call call : recorder.getCalls())
			Assertions.assertTrue(call.getArguments().contains(failure), "hooks receive the caller's exception instance "
					+ "(G6-4)");
		int hooks = recorder.getCalls().size();
		Assertions.assertEquals(failure instanceof JsonWebKeySetUnavailableException ? 2 : 1, hooks);

		RecordingObserver<JoseObserver> throwing = RecordingObserver.fromInterface(JoseObserver.class,
				() -> new IllegalStateException(HOOK_SECRET));
		int recordsBefore = this.logRecords.getRecords().size();
		dispatchFailureHooks(throwing.getObserver(), failure);
		List<LogRecord> records = this.logRecords.getRecords();
		Assertions.assertEquals(recordsBefore + hooks, records.size(), "each contained hook failure was logged");
		Sentinels.assertAbsent(records);
		return recorder;
	}

	private static void dispatchFailureHooks(@NonNull JoseObserver observer, @NonNull RevetsecException failure) {
		ObserverDispatch.dispatch(observer, hook -> hook.didFailToValidateJwt(failure, ELAPSED));
		if (failure instanceof JsonWebKeySetUnavailableException unavailable)
			ObserverDispatch.dispatch(observer, hook -> hook.didFailToFetchJsonWebKeySet(REPORTED_URI, unavailable,
					false, ELAPSED));
	}

	/**
	 * A Revetsec exception has suppression disabled (G6-1), so a secret added as a suppressed exception is dropped.
	 * JDK exceptions thrown for misuse (R15) are left alone.
	 */
	private static void assertSuppressionDisabledOnRevetsecExceptions(@NonNull Throwable failure) {
		if (!failure.getClass().getName().startsWith("com.revetsec."))
			return;
		failure.addSuppressed(new IllegalStateException(SUPPRESSED_SECRET));
		Assertions.assertEquals(0, failure.getSuppressed().length, failure.getClass()::getName);
	}

	private static void assertOnlyInCause(@NonNull List<@NonNull String> locations, @NonNull String root) {
		for (String location : locations)
			Assertions.assertTrue(location.equals(root + " (printed stack trace)")
					|| location.startsWith(root + ".getCause()"), () -> "outside the JDK cause: " + location);
	}

	private static boolean isJdkClassName(@NonNull String name) {
		return name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("jdk.")
				|| name.startsWith("sun.");
	}

	private static @NonNull String printedStackTrace(@NonNull Throwable throwable) {
		StringWriter stringWriter = new StringWriter();
		try (PrintWriter printWriter = new PrintWriter(stringWriter)) {
			throwable.printStackTrace(printWriter);
		}
		return stringWriter.toString();
	}

	/**
	 * Every exported concrete class of {@code com.revetsec.jose}: the public top-level classes and enums declared in
	 * its sources, and their public or protected nested classes and enums, without interfaces and abstract classes.
	 */
	private static @NonNull List<@NonNull Class<?>> exportedConcreteJoseClasses() throws IOException, ClassNotFoundException {
		Assertions.assertTrue(ContractSupport.EXPORTED_PACKAGES.contains(JOSE_PACKAGE));
		Path sources = ContractSupport.repositoryRoot().resolve("src/main/java").resolve(JOSE_PACKAGE.replace('.', '/'));
		List<Class<?>> exported = new ArrayList<>();
		for (Path source : ContractSupport.javaSources(sources)) {
			String simpleName = ContractSupport.fileName(source).replaceFirst("\\.java$", "");
			if (simpleName.equals("package-info") || !sources.equals(source.getParent()))
				continue;
			Class<?> type = Class.forName(JOSE_PACKAGE + "." + simpleName);
			if (Modifier.isPublic(type.getModifiers()))
				addExported(type, exported);
		}
		return exported.stream()
				.filter(type -> type.isEnum() || !(type.isInterface() || Modifier.isAbstract(type.getModifiers())))
				.toList();
	}

	private static void addExported(@NonNull Class<?> type, @NonNull List<@NonNull Class<?>> exported) {
		exported.add(type);
		for (Class<?> nested : type.getDeclaredClasses())
			if (Modifier.isPublic(nested.getModifiers()) || Modifier.isProtected(nested.getModifiers()))
				addExported(nested, exported);
	}

	/**
	 * Every object the walker renders from {@code root} by itself, reached through the same containers the walker
	 * follows: collections, maps, arrays, optionals, recorded observers and their calls, and exception causes.
	 */
	private static void collectRendered(@NonNull Object root, @NonNull List<@NonNull Object> rendered) {
		Set<Object> visited = Collections.newSetFromMap(new IdentityHashMap<>());
		Deque<Object> pending = new ArrayDeque<>(List.of(root));
		while (!pending.isEmpty()) {
			Object value = pending.removeFirst();
			if (!visited.add(value))
				continue;
			if (value instanceof RecordingObserver<?> observer) {
				pending.addAll(observer.getCalls());
			} else if (value instanceof RecordingObserver.Call call) {
				call.getArguments().stream().filter(Objects::nonNull).forEach(pending::add);
			} else if (value instanceof Collection<?> collection) {
				collection.stream().filter(Objects::nonNull).forEach(pending::add);
			} else if (value instanceof Map<?, ?> map) {
				map.forEach((key, element) -> {
					pending.add(key);
					if (element != null)
						pending.add(element);
				});
			} else if (value instanceof Object[] array) {
				for (@Nullable Object element : array)
					if (element != null)
						pending.add(element);
			} else if (value instanceof Optional<?> optional) {
				optional.ifPresent(pending::add);
			} else {
				rendered.add(value);
				if (value instanceof Throwable throwable && throwable.getCause() != null)
					pending.add(Objects.requireNonNull(throwable.getCause()));
			}
		}
	}

	/**
	 * Executes a {@link ResponseProfile#TOKEN} request that carries secrets ({@link #requestWithSecrets}).
	 */
	private static @NonNull RawResponse execute(@NonNull URI uri) throws HttpExchangeException {
		return exchange().execute(requestWithSecrets(uri, ResponseProfile.TOKEN, 1_024), deadline());
	}

	/**
	 * A POST that carries a secret in its query, its form body and two header values.
	 */
	private static @NonNull HttpExchangeRequest requestWithSecrets(@NonNull URI uri, @NonNull ResponseProfile profile, int maximumBodyBytes) {
		URI withQuery = URI.create(uri + (uri.getRawQuery() == null ? "?" : "&") + "code=" + SECRET);
		return new HttpExchangeRequest(withQuery, profile, "client_secret=" + Sentinels.CLIENT_SECRET,
				Map.of("Authorization", "Bearer " + Sentinels.ACCESS_TOKEN, "X-Api-Key", SECRET), maximumBodyBytes,
				1_024, Duration.ofSeconds(10));
	}

	/**
	 * A status line the JDK refuses, whose reason phrase is the server's {@link #SERVER_ECHO}.
	 */
	private static RawTlsServer.@NonNull Script statusLineTheJdkRejects() {
		return RawTlsServer.Script.fromString("HTTP/1.1 099 " + SERVER_ECHO + "\r\nContent-Length: 0\r\n\r\n");
	}

	/**
	 * A 200 of {@code contentType} whose body, which starts with the server's {@link #SERVER_ECHO}, the server cuts
	 * short.
	 */
	private static RawTlsServer.@NonNull Script bodyTheServerCutsShort(@NonNull String contentType) {
		return RawTlsServer.Script.builder()
				.write("HTTP/1.1 200 OK\r\nContent-Type: " + contentType + "\r\nContent-Length: 1000\r\n\r\n"
						+ "{\"keys\":[{\"kid\":\"" + SERVER_ECHO)
				.closeConnection()
				.build();
	}

	private static @NonNull String scriptJdk(TestHttpsServer.@NonNull Response response) {
		String path = "/redaction-" + NEXT_PATH.incrementAndGet();
		jdk().script(path, TestHttpsServer.Script.fromResponse(response));
		return path;
	}

	private static @NonNull String scriptRaw(RawTlsServer.@NonNull Script script) {
		String path = "/redaction-" + NEXT_PATH.incrementAndGet();
		raw().script(path, script);
		return path;
	}

	private static @NonNull Deadline deadline() {
		return Deadline.fromNow(Duration.ofSeconds(30));
	}

	private static @NonNull TestHttpsServer jdk() {
		return Objects.requireNonNull(jdkServer);
	}

	private static @NonNull RawTlsServer raw() {
		return Objects.requireNonNull(rawServer);
	}

	private static @NonNull HttpExchange exchange() {
		return Objects.requireNonNull(exchange);
	}

	private static @NonNull HttpClient client() {
		return Objects.requireNonNull(httpClient);
	}

	private static @NonNull String pem(@NonNull String label, @NonNull String body) {
		return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
	}

	private static @NonNull String base64(byte @NonNull [] bytes) {
		return Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes);
	}

	private static @NonNull String resource(@NonNull String path) throws IOException {
		try (InputStream inputStream = Objects.requireNonNull(RedactionTests.class.getResourceAsStream(path), path)) {
			return new String(inputStream.readAllBytes(), StandardCharsets.US_ASCII);
		}
	}

	private static byte @NonNull [] utf8(@NonNull String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	private static byte @NonNull [] concat(byte @NonNull [] @NonNull ... parts) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		for (byte[] part : parts)
			outputStream.writeBytes(part);
		return outputStream.toByteArray();
	}

	// ---- JOSE fixtures ----

	/**
	 * The JOSE surfaces, building them on first use.
	 */
	private static @NonNull Map<@NonNull Group, @NonNull List<@NonNull Surface>> joseSurfaces() {
		@Nullable Map<Group, List<Surface>> surfaces = builtJoseSurfaces;
		if (surfaces == null) {
			surfaces = new JoseSurfaces(jdk(), raw(), client()).build();
			builtJoseSurfaces = surfaces;
		}
		return surfaces;
	}

	/**
	 * A JWK for the RSA 2048 fixture key with {@code kid}.
	 */
	private static @NonNull String rsaJwk(@NonNull String kid) {
		return TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid(kid).toJson();
	}

	/**
	 * A validator builder for {@link #ISSUER} and {@link #AUDIENCE} at {@link #NOW}, over a static source of
	 * {@code jwks}.
	 */
	private static JwtValidator.@NonNull Builder validator(@NonNull String @NonNull ... jwks) {
		return JwtValidator.withIssuer(ISSUER)
				.jsonWebKeySource(StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(
						TestJsonWebKeys.keySet(List.of(jwks)))))
				.expectedAudiences(Set.of(AUDIENCE))
				.clock(TestClock.fromInstant(NOW));
	}

	/**
	 * Valid claims at {@link #NOW}, without a sentinel.
	 */
	private static @NonNull TestClaims claims() {
		return TestClaims.empty().put("iss", ISSUER).put("aud", AUDIENCE).put("sub", "subject-1")
				.put("iat", NOW.getEpochSecond()).put("exp", NOW.plus(Duration.ofMinutes(5)).getEpochSecond());
	}

	/**
	 * An RS256 token builder with {@code kid} {@link #KEY_ID} and {@code claims}.
	 */
	private static TestJws.@NonNull Builder rs256(@NonNull TestClaims claims) {
		return TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid(KEY_ID).payload(claims.toJson());
	}

	/**
	 * {@link #rs256(TestClaims)}, signed by the RSA 2048 fixture key.
	 */
	private static @NonNull String signed(@NonNull TestClaims claims) {
		return rs256(claims).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
	}

	/**
	 * How a {@link Surface} is checked.
	 */
	private enum Check {
		/**
		 * A positive control: the input carries a sentinel.
		 */
		PRESENT,
		/**
		 * A positive control: the text carries a sentinel only in encoded form.
		 */
		ENCODED_ONLY,
		/**
		 * No rendering carries a sentinel.
		 */
		RENDERING,
		/**
		 * A failure with the expected reason, category or class, redacted ({@link #assertRedacted(Throwable)}).
		 */
		FAILURE,
		/**
		 * A failure whose cause is the JDK's {@link IOException}, redacted except for the server's text inside that
		 * cause.
		 */
		SERVER_ECHO_IN_CAUSE,
		/**
		 * A component's recorded observer: it recorded calls, and no argument carries a sentinel, the IO allowance
		 * aside.
		 */
		HOOK_ARGUMENTS,
		/**
		 * The log records of a component's throwing observer: at least one, and none carries a sentinel.
		 */
		LOG_RECORDS;

		/**
		 * Whether the surface's value is walked for sentinels that must be absent, as opposed to a positive control.
		 */
		boolean isWalk() {
			return this != PRESENT && this != ENCODED_ONLY;
		}
	}

	/**
	 * The groups of JOSE surfaces, one test each.
	 */
	private enum Group {
		REJECTED_TOKENS,
		KEY_SETS,
		KEY_SET_FETCHES,
		ACCEPTED_TOKENS,
		CONFIGURATION
	}

	/**
	 * One JOSE surface: what it is, the object walked, how it is checked, and, for a failure, the
	 * {@link JoseException.Reason}, {@link ErrorCategory} or class it must have.
	 */
	private static final class Surface {
		private final String name;
		private final Object value;
		private final Check check;
		private final @Nullable Object expected;

		private Surface(@NonNull String name, @NonNull Object value, @NonNull Check check, @Nullable Object expected) {
			this.name = name;
			this.value = value;
			this.check = check;
			this.expected = expected;
		}

		@NonNull String getName() {
			return this.name;
		}

		@NonNull Object getValue() {
			return this.value;
		}

		@NonNull Check getCheck() {
			return this.check;
		}

		@Nullable Object getExpected() {
			return this.expected;
		}
	}

	/**
	 * A {@link RevetsecException} whose cause carries a sentinel, for the positive controls; Revetsec never makes one.
	 */
	private static final class EchoingFailure extends RevetsecException {
		private static final long serialVersionUID = 1L;

		private EchoingFailure(@NonNull IOException cause) {
			super(ErrorCategory.TRANSPORT, true, "A test failure whose cause echoes input.", cause);
		}
	}

	/**
	 * Builds the JOSE surfaces: runs every scenario, with recorded and throwing observers, and records what it
	 * rendered, while its own handler captures the {@code com.revetsec} log records each throwing observer causes.
	 */
	private static final class JoseSurfaces {
		private final TestHttpsServer jdkServer;
		private final RawTlsServer rawServer;
		private final HttpClient client;
		private final Logger logger = Logger.getLogger(ObserverDispatch.LOGGER_NAME);
		private final RecordingHandler records = new RecordingHandler();
		private final Map<Group, List<Surface>> surfaces = new EnumMap<>(Group.class);

		private JoseSurfaces(@NonNull TestHttpsServer jdkServer, @NonNull RawTlsServer rawServer, @NonNull HttpClient client) {
			this.jdkServer = jdkServer;
			this.rawServer = rawServer;
			this.client = client;
		}

		@NonNull Map<@NonNull Group, @NonNull List<@NonNull Surface>> build() {
			@Nullable Level level = this.logger.getLevel();
			boolean useParentHandlers = this.logger.getUseParentHandlers();
			this.logger.setUseParentHandlers(false);
			this.logger.setLevel(Level.ALL);
			this.logger.addHandler(this.records);

			try {
				rejectedTokens();
				keySets();
				keySetFetches();
				acceptedTokens();
				configuration();
			} finally {
				this.logger.removeHandler(this.records);
				this.logger.setLevel(level);
				this.logger.setUseParentHandlers(useParentHandlers);
			}

			Map<Group, List<Surface>> built = new EnumMap<>(Group.class);
			this.surfaces.forEach((group, list) -> built.put(group, List.copyOf(list)));
			return Collections.unmodifiableMap(built);
		}

		private void add(@NonNull Group group, @NonNull String name, @NonNull Object value, @NonNull Check check) {
			add(group, name, value, check, null);
		}

		private void add(@NonNull Group group, @NonNull String name, @NonNull Object value, @NonNull Check check, @Nullable Object expected) {
			this.surfaces.computeIfAbsent(group, key -> new ArrayList<>()).add(new Surface(name, value, check, expected));
		}

		// -- Rejected tokens --

		private void rejectedTokens() {
			String rsa = rsaJwk(KEY_ID);
			Function<JoseObserver, JwtValidator> standard = observer -> validator(rsa).observer(observer).build();
			Function<JoseObserver, JwtValidator> ambiguous = observer -> validator(rsa,
					TestJsonWebKeys.withFixture(Fixture.NEGATIVE_ATTACKER_RSA_2048).kid(KEY_ID).toJson())
					.observer(observer).build();
			Function<JoseObserver, JwtValidator> withEcdsa = observer -> validator(rsa)
					.allowedAlgorithms(Set.of(JwsAlgorithm.RS256, JwsAlgorithm.ES256)).observer(observer).build();
			Function<JoseObserver, JwtValidator> issuerBound = observer -> validator(TestJsonWebKeys.withFixture(
					Fixture.IDP_SIGNING_RSA_2048).kid(KEY_ID).issuer(Sentinels.secret("jwk-issuer")).toJson())
					.observer(observer).build();
			byte[] rsaSignature = new byte[256];
			TestClaims withSecretSubject = claims().put("sub", SECRET);

			rejected("an oversized token of sentinels", JoseException.Reason.TOKEN_TOO_LARGE, standard,
					Sentinels.JWT_CLAIM.repeat(65_536 / Sentinels.JWT_CLAIM.length() + 1));
			rejected("sentinels around one dot", JoseException.Reason.TOKEN_SYNTAX, standard, SECRET + "." + SECRET);
			rejected("a JSON serialization", JoseException.Reason.JSON_SERIALIZATION, standard,
					"{\"payload\":" + JsonText.string(SECRET) + ",\"signature\":" + JsonText.string(SECRET) + "}");
			rejected("five segments", JoseException.Reason.ENCRYPTED_TOKEN, standard, String.join(".",
					TestJws.base64Url("{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}"), SECRET, SECRET, SECRET, SECRET));
			rejected("a duplicate kid, one of them a sentinel", JoseException.Reason.HEADER, standard, TestJws.builder()
					.header("{\"alg\":\"RS256\",\"kid\":" + JsonText.string(Sentinels.JWT_KEY_ID) + ",\"kid\":\"x\"}")
					.payload(claims().toJson()).withSignature(rsaSignature));
			rejected("a kid too long, of sentinels", JoseException.Reason.HEADER, standard, rs256(claims())
					.kid(SECRET.repeat(10)).withSignature(rsaSignature));
			rejected("alg none, with sentinels in the kid, claims and signature",
					JoseException.Reason.ALGORITHM_NOT_ALLOWED, standard, Sentinels.compactJwt("none", 11));
			rejected("a sentinel alg", JoseException.Reason.ALGORITHM_NOT_ALLOWED, standard, rs256(claims()).alg(SECRET)
					.withSignature(rsaSignature));
			rejected("a critical sentinel member", JoseException.Reason.CRITICAL_HEADER, standard, rs256(claims())
					.headerMember("crit", JsonText.stringArray(List.of(SECRET))).headerMember(SECRET, "true")
					.withSignature(rsaSignature));
			rejected("an unencoded payload with a sentinel claim", JoseException.Reason.UNENCODED_PAYLOAD, standard,
					rs256(withSecretSubject).headerMember("b64", "false").withSignature(rsaSignature));
			rejected("a sentinel zip", JoseException.Reason.COMPRESSED_PAYLOAD, standard, rs256(claims())
					.headerMember("zip", JsonText.string(SECRET)).withSignature(rsaSignature));
			rejected("a jku with a sentinel", JoseException.Reason.UNTRUSTED_KEY_REFERENCE, standard, rs256(claims())
					.headerMember("jku", JsonText.string("https://keys.example.com/" + SECRET)).withSignature(rsaSignature));
			rejected("an embedded jwk with sentinel members", JoseException.Reason.UNTRUSTED_KEY_REFERENCE, standard,
					rs256(claims()).headerMember("jwk", TestJsonWebKeys.withFixture(Fixture.NEGATIVE_ATTACKER_RSA_2048)
							.kid(SECRET).member("d", JsonText.string(Sentinels.PRIVATE_KEY_MEMBER)).toJson())
							.withSignature(rsaSignature));
			rejected("a sentinel typ", JoseException.Reason.INVALID_TYPE, standard, rs256(claims()).typ(SECRET)
					.withSignature(rsaSignature));
			rejected("a sentinel cty", JoseException.Reason.NESTED_TOKEN, standard, rs256(claims())
					.headerMember("cty", JsonText.string(SECRET)).withSignature(rsaSignature));
			rejected("a short sentinel signature", JoseException.Reason.SIGNATURE_MALFORMED, standard,
					Sentinels.compactJwt("RS256", 11));
			rejected("a sentinel kid no key has", JoseException.Reason.UNKNOWN_KEY, standard,
					Sentinels.compactJwt("RS256", 256));
			for (int alignment = 0; alignment < 3; ++alignment)
				rejected("a base64url sentinel claim at alignment " + alignment, JoseException.Reason.SIGNATURE_MISMATCH,
						standard, Sentinels.compactJwtWithSentinelClaim(alignment));
			rejected("sentinel claims signed by another key", JoseException.Reason.SIGNATURE_MISMATCH, standard,
					rs256(withSecretSubject).sign(Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey()));
			rejected("sentinel claims under an ambiguous kid", JoseException.Reason.AMBIGUOUS_KEY, ambiguous,
					signed(withSecretSubject));
			rejected("sentinel claims for a key of another type", JoseException.Reason.KEY_ALGORITHM_MISMATCH, withEcdsa,
					TestJws.withAlgorithm(TestJws.Algorithm.ES256).kid(KEY_ID).payload(withSecretSubject.toJson())
							.sign(Fixture.IDP_SIGNING_EC_P256.getPrivateKey()));
			rejected("sentinel claims for a key bound to another issuer", JoseException.Reason.KEY_ISSUER_MISMATCH,
					issuerBound, signed(withSecretSubject));
			rejected("a sentinel payload that is not JSON", JoseException.Reason.CLAIMS, standard,
					rs256(claims()).payload(SECRET).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey()));
			rejected("a sentinel exp", JoseException.Reason.CLAIMS, standard, signed(claims().put("exp", SECRET)));
			rejected("a sentinel iss", JoseException.Reason.ISSUER_MISMATCH, standard, signed(claims().put("iss",
					SECRET)));
			rejected("a sentinel aud", JoseException.Reason.AUDIENCE_MISMATCH, standard, signed(claims().put("aud",
					SECRET)));
			rejected("sentinel claims without exp", JoseException.Reason.MISSING_CLAIM, standard,
					signed(withSecretSubject.copy().remove("exp")));
			rejected("expired sentinel claims", JoseException.Reason.EXPIRED, standard, signed(withSecretSubject.copy()
					.put("exp", NOW.minus(Duration.ofHours(1)).getEpochSecond())));
			rejected("sentinel claims not yet valid", JoseException.Reason.NOT_YET_VALID, standard,
					signed(withSecretSubject.copy().put("nbf", NOW.plus(Duration.ofHours(1)).getEpochSecond())));
			rejected("sentinel claims issued in the future", JoseException.Reason.ISSUED_IN_FUTURE, standard,
					signed(withSecretSubject.copy().put("iat", NOW.plus(Duration.ofHours(1)).getEpochSecond())));
			rejected("a sentinel confirmation", JoseException.Reason.CONFIRMATION_NOT_VERIFIED, standard,
					signed(claims().raw("cnf", "{\"jkt\":" + JsonText.string(SECRET) + "}")));
		}

		/**
		 * Validates {@code token} with a recorded observer and with a throwing one, and adds the token (a positive
		 * control), both failures, the hook arguments and the throwing observer's log records.
		 */
		private void rejected(@NonNull String name, JoseException.@NonNull Reason reason, @NonNull Function<@NonNull JoseObserver, @NonNull JwtValidator> validator,
				@NonNull String token) {
			String surface = reason + ", " + name;
			add(Group.REJECTED_TOKENS, surface + ": the token carries a sentinel", token, Check.PRESENT);

			RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
			JwtValidator recorded = validator.apply(recorder.getObserver());
			add(Group.REJECTED_TOKENS, surface + ": the exception", thrownBy(surface, () -> recorded.validate(token)),
					Check.FAILURE, reason);
			add(Group.REJECTED_TOKENS, surface + ": the hook arguments", recorder, Check.HOOK_ARGUMENTS);
			com.revetsec.jose.JwtValidationResult result = validator.apply(JoseObserver.disabledInstance()).validateResult(token);
			Assertions.assertEquals(reason, Assertions.assertInstanceOf(com.revetsec.jose.JwtValidationResult.Rejected.class, result).getReason());
			add(Group.REJECTED_TOKENS, surface + ": the result", result, Check.RENDERING);

			RecordingObserver<JoseObserver> throwing = RecordingObserver.fromInterface(JoseObserver.class,
					() -> new IllegalStateException(HOOK_SECRET));
			JwtValidator throwingValidator = validator.apply(throwing.getObserver());
			this.records.clear();
			add(Group.REJECTED_TOKENS, surface + ": the exception, with a throwing observer",
					thrownBy(surface, () -> throwingValidator.validate(token)), Check.FAILURE, reason);
			add(Group.REJECTED_TOKENS, surface + ": the throwing observer's log records", this.records.getRecords(),
					Check.LOG_RECORDS);
		}

		// -- Key sets --

		private void keySets() {
			String document = sentinelKeySet();
			add(Group.KEY_SETS, "the key set document carries sentinels", document, Check.PRESENT);
			JsonWebKeySet keySet = JsonWebKeySet.fromJson(document);
			add(Group.KEY_SETS, "the key set", keySet, Check.RENDERING);
			add(Group.KEY_SETS, "its one usable key", keySet.getKeys(), Check.RENDERING);
			StaticJsonWebKeySource source = StaticJsonWebKeySource.fromJsonWebKeySet(keySet);
			add(Group.KEY_SETS, "a static source over it", source, Check.RENDERING);
			JwtValidator.Builder builder = JwtValidator.withIssuer(ISSUER).jsonWebKeySource(source)
					.expectedAudiences(Set.of(AUDIENCE)).clock(TestClock.fromInstant(NOW));
			add(Group.KEY_SETS, "a validator builder over it", builder, Check.RENDERING);
			add(Group.KEY_SETS, "a validator over it", builder.build(), Check.RENDERING);

			String onlySkipped = TestJsonWebKeys.keySet(List.of(
					TestJsonWebKeys.octWithK(Sentinels.SYMMETRIC_KEY).kid(SECRET).toJson(),
					TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid(SECRET)
							.member("d", JsonText.string(Sentinels.PRIVATE_KEY_MEMBER)).toJson()));
			add(Group.KEY_SETS, "a static source refused over sentinel keys that are all skipped",
					thrownBy("a static source", () -> StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(
							onlySkipped))), Check.FAILURE, IllegalArgumentException.class);

			Map<String, String> malformed = new LinkedHashMap<>();
			malformed.put("keys is a sentinel string", "{\"keys\":" + JsonText.string(SECRET) + "}");
			malformed.put("a key that is a sentinel string", "{\"keys\":[" + JsonText.string(SECRET) + "]}");
			malformed.put("an array of sentinels", "[" + JsonText.string(SECRET) + "]");
			malformed.put("a duplicate sentinel member", "{\"keys\":[]," + JsonText.string(SECRET) + ":1,"
					+ JsonText.string(SECRET) + ":2}");
			malformed.put("text that is not JSON", "{" + JsonText.string(SECRET) + ":");
			malformed.put("a sentinel with an unpaired surrogate", "{\"keys\":[],\"note\":\"" + SECRET + "\uD800\"}");
			malformed.put("more keys than the limit", TestJsonWebKeys.keySet(Collections.nCopies(101,
					TestJsonWebKeys.octWithK(Sentinels.SYMMETRIC_KEY).kid(SECRET).toJson())));
			malformed.put("a document over the size limit", "{\"keys\":[],\"note\":"
					+ JsonText.string(SECRET.repeat(256 * 1_024 / SECRET.length() + 1)) + "}");
			malformed.forEach((name, text) -> {
				add(Group.KEY_SETS, "KEY_SET, " + name + ": the document carries a sentinel", text, Check.PRESENT);
				add(Group.KEY_SETS, "KEY_SET, " + name + ": the exception", thrownBy(name,
						() -> JsonWebKeySet.fromJson(text)), Check.FAILURE, JoseException.Reason.KEY_SET);
			});
		}

		// -- Remote key sets --

		private void keySetFetches() {
			String document = sentinelKeySet();
			TestHttpsServer.Response keySet = TestHttpsServer.Response.withStatus(200)
					.header("Content-Type", TestHttpsServer.JWK_SET_MEDIA_TYPE)
					.header("Cache-Control", "private, " + SECRET)
					.header("X-Echo", SECRET)
					.body(document)
					.build();

			RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
			RemoteJsonWebKeySource.Builder builder = RemoteJsonWebKeySource.withUri(jdkTarget(keySet))
					.httpClient(this.client).clock(TestClock.fromInstant(NOW)).observer(recorder.getObserver());
			add(Group.KEY_SET_FETCHES, "a source builder whose URI has a sentinel query", builder, Check.RENDERING);
			RemoteJsonWebKeySource source = builder.build();
			add(Group.KEY_SET_FETCHES, "the source before its first fetch", source, Check.RENDERING);
			source.warmUp();
			add(Group.KEY_SET_FETCHES, "the source after fetching the sentinel key set", source, Check.RENDERING);
			JwtValidator validator = remoteValidator(source, recorder.getObserver());
			add(Group.KEY_SET_FETCHES, "a validator over it", validator, Check.RENDERING);
			add(Group.KEY_SET_FETCHES, "UNKNOWN_KEY after a refetch, for a sentinel kid",
					thrownBy("an unknown kid", () -> validator.validate(Sentinels.compactJwt("RS256", 256))),
					Check.FAILURE, JoseException.Reason.UNKNOWN_KEY);
			add(Group.KEY_SET_FETCHES, "UNKNOWN_KEY inside the unknown-key cooldown, for a sentinel kid",
					thrownBy("an unknown kid inside the cooldown", () -> validator.validate(Sentinels.compactJwt("RS256",
							256))), Check.FAILURE, JoseException.Reason.UNKNOWN_KEY);
			Assertions.assertEquals(1, recorder.getCalls("didSuppressJsonWebKeySetFetch").size(),
					"the cooldown held back the second unknown kid's refetch");
			add(Group.KEY_SET_FETCHES, "the fetch, skip, suppression and validation hook arguments", recorder,
					Check.HOOK_ARGUMENTS);

			RecordingObserver<JoseObserver> throwing = RecordingObserver.fromInterface(JoseObserver.class,
					() -> new IllegalStateException(HOOK_SECRET));
			RemoteJsonWebKeySource throwingSource = remoteSource(jdkTarget(keySet), throwing.getObserver());
			this.records.clear();
			throwingSource.warmUp();
			add(Group.KEY_SET_FETCHES, "a successful fetch's throwing observer: its log records",
					this.records.getRecords(), Check.LOG_RECORDS);

			fetchFailure("an error status with sentinels", ErrorCategory.REMOTE_ERROR,
					() -> jdkTarget(TestHttpsServer.Response.withStatus(500)
							.header("Content-Type", "application/json")
							.header("X-Echo", SECRET)
							.body("{\"error\":" + JsonText.string(SECRET) + "}")
							.build()));
			fetchFailure("a 429 with a sentinel Retry-After", ErrorCategory.REMOTE_ERROR,
					() -> jdkTarget(TestHttpsServer.Response.withStatus(429)
							.header("Retry-After", SECRET)
							.body(SECRET)
							.build()));
			fetchFailure("a redirect to a sentinel URI", ErrorCategory.REMOTE_ERROR,
					() -> jdkTarget(TestHttpsServer.Response.withStatus(302)
							.header("Location", "https://keys.example.com/" + SECRET + "?token=" + SECRET)
							.body(document)
							.build()));
			fetchFailure("a malformed key set of sentinels", ErrorCategory.MALFORMED_INPUT,
					() -> jdkTarget(TestHttpsServer.Response.withStatus(200)
							.header("Content-Type", TestHttpsServer.JWK_SET_MEDIA_TYPE)
							.body("{\"keys\":" + JsonText.string(SECRET) + "}")
							.build()));
			fetchFailure("more keys than the limit", ErrorCategory.MALFORMED_INPUT,
					() -> jdkTarget(TestHttpsServer.Response.fromJsonWebKeySet(TestJsonWebKeys.keySet(Collections.nCopies(
							101, TestJsonWebKeys.octWithK(Sentinels.SYMMETRIC_KEY).kid(SECRET).toJson())))));
			fetchFailure("a body over the limit", ErrorCategory.MALFORMED_INPUT,
					() -> jdkTarget(TestHttpsServer.Response.fromJsonWebKeySet("{\"keys\":[],\"note\":"
							+ JsonText.string(SECRET.repeat(300 * 1_024 / SECRET.length())) + "}")));
			fetchFailure("a sentinel media type", ErrorCategory.MALFORMED_INPUT,
					() -> jdkTarget(TestHttpsServer.Response.withStatus(200)
							.header("Content-Type", "text/" + SECRET)
							.body(document)
							.build()));
			fetchFailure("a sentinel charset", ErrorCategory.MALFORMED_INPUT,
					() -> jdkTarget(TestHttpsServer.Response.withStatus(200)
							.header("Content-Type", "application/json; charset=" + SECRET)
							.body(document)
							.build()));
			fetchFailure("a sentinel content encoding", ErrorCategory.MALFORMED_INPUT,
					() -> jdkTarget(TestHttpsServer.Response.withStatus(200)
							.header("Content-Type", TestHttpsServer.JWK_SET_MEDIA_TYPE)
							.header("Content-Encoding", SECRET)
							.body(document)
							.build()));
			fetchFailure("a sentinel transfer coding", ErrorCategory.MALFORMED_INPUT,
					() -> rawTarget(RawTlsServer.Script.fromString("HTTP/1.1 200 OK\r\n"
							+ "Content-Type: " + TestHttpsServer.JWK_SET_MEDIA_TYPE + "\r\n"
							+ "Transfer-Encoding: " + SECRET + "\r\n"
							+ "\r\n"
							+ document)));
			fetchFailure("a status line the JDK rejects", ErrorCategory.TRANSPORT,
					() -> rawTarget(statusLineTheJdkRejects()));
			fetchFailure("a body the server cuts short", ErrorCategory.TRANSPORT,
					() -> rawTarget(bodyTheServerCutsShort(TestHttpsServer.JWK_SET_MEDIA_TYPE)));
			interruptedLeader();
		}

		/**
		 * One failing key set endpoint, met three times on fresh sources: through {@code warmUp()}, as the leader,
		 * and then again inside the backoff that failure started, which sends nothing and throws the remembered
		 * failure without a cause; through a validator that shares the source's recorded observer; and through a
		 * validator whose observer throws. A {@link ErrorCategory#TRANSPORT} failure here keeps the JDK's cause, so it
		 * gets the IO allowance.
		 */
		private void fetchFailure(@NonNull String name, @NonNull ErrorCategory category, @NonNull Supplier<@NonNull URI> target) {
			Check failureCheck = category == ErrorCategory.TRANSPORT ? Check.SERVER_ECHO_IN_CAUSE : Check.FAILURE;
			String surface = category + ", " + name;

			RecordingObserver<JoseObserver> leader = RecordingObserver.fromInterface(JoseObserver.class);
			RemoteJsonWebKeySource warmed = remoteSource(target.get(), leader.getObserver());
			add(Group.KEY_SET_FETCHES, surface + ": warmUp()'s exception", thrownBy(surface, () -> {
				warmed.warmUp();
				return warmed;
			}), failureCheck, category);
			add(Group.KEY_SET_FETCHES, surface + ": warmUp()'s exception inside the backoff", thrownBy(surface, () -> {
				warmed.warmUp();
				return warmed;
			}), Check.FAILURE, category);
			Assertions.assertEquals(1, leader.getCalls("didSuppressJsonWebKeySetFetch").size(),
					() -> surface + ": the backoff held back the second warmUp()");
			add(Group.KEY_SET_FETCHES, surface + ": the fetch and suppression hook arguments", leader,
					Check.HOOK_ARGUMENTS);
			add(Group.KEY_SET_FETCHES, surface + ": the source", warmed, Check.RENDERING);

			RecordingObserver<JoseObserver> validation = RecordingObserver.fromInterface(JoseObserver.class);
			JwtValidator validator = remoteValidator(remoteSource(target.get(), validation.getObserver()),
					validation.getObserver());
			add(Group.KEY_SET_FETCHES, surface + ": validate()'s exception", thrownBy(surface,
					() -> validator.validate(Sentinels.compactJwt("RS256", 256))), failureCheck, category);
			add(Group.KEY_SET_FETCHES, surface + ": the fetch and validation hook arguments", validation,
					Check.HOOK_ARGUMENTS);

			RecordingObserver<JoseObserver> throwing = RecordingObserver.fromInterface(JoseObserver.class,
					() -> new IllegalStateException(HOOK_SECRET));
			JwtValidator throwingValidator = remoteValidator(remoteSource(target.get(), throwing.getObserver()),
					throwing.getObserver());
			this.records.clear();
			add(Group.KEY_SET_FETCHES, surface + ": validate()'s exception, with a throwing observer", thrownBy(surface,
					() -> throwingValidator.validate(Sentinels.compactJwt("RS256", 256))), failureCheck, category);
			add(Group.KEY_SET_FETCHES, surface + ": the throwing observer's log records", this.records.getRecords(),
					Check.LOG_RECORDS);
		}

		/**
		 * A leader interrupted after its request reached the server, which holds the request: its failure (TRANSPORT,
		 * not transient, with no cause) and the arguments of the hooks it fired, over a URI with a sentinel query. The
		 * waits end on the server's held count and on the leader's failure, never on a sleep.
		 */
		private void interruptedLeader() {
			TestHttpsServer.HeldScript held = TestHttpsServer.HeldScript.fromResponse(
					TestHttpsServer.Response.fromJsonWebKeySet(sentinelKeySet()));
			String path = "/redaction-jwks-" + NEXT_PATH.incrementAndGet();
			this.jdkServer.script(path, held);
			RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
			RemoteJsonWebKeySource source = remoteSource(withSecretQuery(this.jdkServer.uri(path)), recorder.getObserver());
			CompletableFuture<Throwable> failure = new CompletableFuture<>();
			Thread leader = new Thread(() -> {
				try {
					failure.complete(thrownBy("an interrupted leader", () -> {
						source.warmUp();
						return source;
					}));
				} catch (AssertionError error) {
					failure.completeExceptionally(error);
				}
			}, "redaction-interrupted-leader");
			leader.setDaemon(true);
			String surface = ErrorCategory.TRANSPORT + ", a leader interrupted after its request was sent";

			try {
				leader.start();
				Assertions.assertTrue(held.awaitHeldCount(1, WAIT), "the leader's request reached the server");
				leader.interrupt();
				JsonWebKeySetUnavailableException exception = Assertions.assertInstanceOf(
						JsonWebKeySetUnavailableException.class, failure.get(WAIT.toNanos(), TimeUnit.NANOSECONDS));
				Assertions.assertFalse(exception.isTransient(), () -> surface + ": not transient");
				Assertions.assertNull(exception.getCause(), () -> surface + ": no cause");
				add(Group.KEY_SET_FETCHES, surface + ": the exception", exception, Check.FAILURE, ErrorCategory.TRANSPORT);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new AssertionError(surface, e);
			} catch (ExecutionException | TimeoutException e) {
				throw new AssertionError(surface, e);
			} finally {
				held.release();
			}

			Assertions.assertEquals(1, recorder.getCalls("didFailToFetchJsonWebKeySet").size(),
					() -> surface + ": the leader reported its interrupted fetch");
			add(Group.KEY_SET_FETCHES, surface + ": the fetch hook arguments", recorder, Check.HOOK_ARGUMENTS);
		}

		private @NonNull URI jdkTarget(TestHttpsServer.@NonNull Response response) {
			String path = "/redaction-jwks-" + NEXT_PATH.incrementAndGet();
			this.jdkServer.script(path, TestHttpsServer.Script.fromResponse(response));
			return withSecretQuery(this.jdkServer.uri(path));
		}

		private @NonNull URI rawTarget(RawTlsServer.@NonNull Script script) {
			String path = "/redaction-jwks-" + NEXT_PATH.incrementAndGet();
			this.rawServer.script(path, script);
			return withSecretQuery(this.rawServer.uri(path));
		}

		private static @NonNull URI withSecretQuery(@NonNull URI uri) {
			return URI.create(uri + "?appid=" + URI_SECRET);
		}

		private @NonNull RemoteJsonWebKeySource remoteSource(@NonNull URI uri, @NonNull JoseObserver observer) {
			return RemoteJsonWebKeySource.withUri(uri).httpClient(this.client).clock(TestClock.fromInstant(NOW))
					.observer(observer).build();
		}

		private static @NonNull JwtValidator remoteValidator(@NonNull RemoteJsonWebKeySource source, @NonNull JoseObserver observer) {
			return JwtValidator.withIssuer(ISSUER).jsonWebKeySource(source).expectedAudiences(Set.of(AUDIENCE))
					.clock(TestClock.fromInstant(NOW)).observer(observer).build();
		}

		// -- Accepted tokens --

		private void acceptedTokens() {
			for (int alignment = 0; alignment < 3; ++alignment) {
				String token = TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid(KEY_ID)
						.payload(claimsWithMarker(alignment)).sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
				accepted("a marker claim at alignment " + alignment, validator(rsaJwk(KEY_ID)), token, true);
			}

			String sentinelKeyId = Sentinels.JWT_KEY_ID;
			String token = TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid(sentinelKeyId)
					.payload(claims().put("sub", Sentinels.JWT_CLAIM).put("jti", SECRET).put("email", SECRET)
							.raw("roles", JsonText.stringArray(List.of(SECRET, SECRET))).toJson())
					.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
			// The validator itself is not walked here: its key's kid is key set metadata, which its toString shows.
			accepted("a sentinel kid, sub, jti and custom claims", validator(rsaJwk(sentinelKeyId)), token, false);

			String anyAudience = signed(claims().put("aud", SECRET).put("sub", SECRET));
			accepted("any audience, and a sentinel aud and sub", JwtValidator.withIssuer(ISSUER)
					.jsonWebKeySource(StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(
							TestJsonWebKeys.keySet(List.of(rsaJwk(KEY_ID))))))
					.acceptAnyAudience(true).clock(TestClock.fromInstant(NOW)), anyAudience, false);
		}

		/**
		 * Validates {@code token} with a recorded observer and adds the Jwt, its claims, the hook arguments and, as
		 * positive controls, the explicit emissions.
		 */
		private void accepted(@NonNull String name, JwtValidator.@NonNull Builder builder, @NonNull String token, boolean encodedOnly) {
			add(Group.ACCEPTED_TOKENS, name + ": the token carries a sentinel", token,
					encodedOnly ? Check.ENCODED_ONLY : Check.PRESENT);
			RecordingObserver<JoseObserver> recorder = RecordingObserver.fromInterface(JoseObserver.class);
			Jwt jwt = builder.observer(recorder.getObserver()).build().validate(token);
			add(Group.ACCEPTED_TOKENS, name + ": the Jwt", jwt, Check.RENDERING);
			com.revetsec.jose.JwtValidationResult result = builder.observer(JoseObserver.disabledInstance()).build().validateResult(token);
			Assertions.assertEquals(token, Assertions.assertInstanceOf(com.revetsec.jose.JwtValidationResult.Succeeded.class, result).getJwt().toCompactSerialization());
			add(Group.ACCEPTED_TOKENS, name + ": the result", result, Check.RENDERING);
			add(Group.ACCEPTED_TOKENS, name + ": its claims", jwt.getClaims(), Check.RENDERING);
			add(Group.ACCEPTED_TOKENS, name + ": the hook arguments", recorder, Check.HOOK_ARGUMENTS);
			add(Group.ACCEPTED_TOKENS, name + ": toCompactSerialization() is an explicit emission",
					jwt.toCompactSerialization(), Check.PRESENT);
			add(Group.ACCEPTED_TOKENS, name + ": toJsonObject() is an explicit emission", jwt.getClaims().toJsonObject(),
					Check.PRESENT);
		}

		/**
		 * Valid claims whose only sentinel is the bare {@link Sentinels#MARKER}, as a claim's value, starting at a UTF-8
		 * byte offset of {@code alignment} mod 3.
		 */
		private static @NonNull String claimsWithMarker(int alignment) {
			for (int extra = 0; ; ++extra) {
				String prefix = "{\"iss\":" + JsonText.string(ISSUER) + ",\"aud\":" + JsonText.string(AUDIENCE)
						+ ",\"exp\":" + NOW.plus(Duration.ofMinutes(5)).getEpochSecond() + ",\"claim" + "x".repeat(extra)
						+ "\":\"";
				if (prefix.getBytes(StandardCharsets.UTF_8).length % 3 == alignment)
					return prefix + Sentinels.MARKER + "\"}";
			}
		}

		// -- Configuration --

		private void configuration() {
			add(Group.CONFIGURATION, "every JwsAlgorithm", List.of(JwsAlgorithm.values()), Check.RENDERING);
			add(Group.CONFIGURATION, "every JsonWebKeySkipReason", List.of(JsonWebKeySkipReason.values()),
					Check.RENDERING);
			add(Group.CONFIGURATION, "every JoseException.Reason", List.of(JoseException.Reason.values()),
					Check.RENDERING);
			add(Group.CONFIGURATION, "the disabled observer", JoseObserver.disabledInstance(), Check.RENDERING);

			Map<String, ThrowingSupplier<?>> refusals = new LinkedHashMap<>();
			refusals.put("an empty audience beside a sentinel one", () -> validator(rsaJwk(KEY_ID))
					.expectedAudiences(Set.of("", SECRET)).build());
			refusals.put("any audience beside a sentinel audience", () -> validator(rsaJwk(KEY_ID))
					.expectedAudiences(Set.of(SECRET)).acceptAnyAudience(true).build());
			refusals.put("an empty required claim beside a sentinel one", () -> validator(rsaJwk(KEY_ID))
					.requiredClaims(Set.of("", SECRET)).build());
			refusals.put("an allowed type with a sentinel parameter", () -> validator(rsaJwk(KEY_ID))
					.allowedTypes(Set.of("application/jwt; profile=" + SECRET)).build());
			refusals.put("an HMAC algorithm", () -> validator(rsaJwk(KEY_ID))
					.allowedAlgorithms(Set.of(JwsAlgorithm.HS256)).build());
			refusals.put("a key set URI with sentinel user information", () -> RemoteJsonWebKeySource
					.withUri(URI.create("https://user:" + SECRET + "@issuer.example.com/jwks")).build());
			refusals.put("a key set URI with a sentinel fragment", () -> RemoteJsonWebKeySource
					.withUri(URI.create("https://issuer.example.com/jwks#" + SECRET)).build());
			refusals.put("a plain-http key set URI with a sentinel path", () -> RemoteJsonWebKeySource
					.withUri(URI.create("http://issuer.example.com/" + SECRET + "?appid=" + URI_SECRET)).build());
			refusals.put("a metadata-address key set URI with a sentinel path", () -> RemoteJsonWebKeySource
					.withUri(URI.create("https://169.254.169.254/" + SECRET + "?appid=" + URI_SECRET)).build());
			refusals.forEach((name, refusal) -> add(Group.CONFIGURATION, name + ": the refusal", thrownBy(name, refusal),
					Check.FAILURE, IllegalArgumentException.class));

			add(Group.CONFIGURATION, "a validator builder", validator(rsaJwk(KEY_ID)).requiredClaims(Set.of(SECRET)),
					Check.RENDERING);
			add(Group.CONFIGURATION, "a source builder whose URI has a sentinel query", RemoteJsonWebKeySource.withUri(
					withSecretQuery(REPORTED_URI)), Check.RENDERING);
			add(Group.CONFIGURATION, "a source whose URI has a sentinel query", RemoteJsonWebKeySource.withUri(
					withSecretQuery(REPORTED_URI)).build(), Check.RENDERING);
		}

		/**
		 * A key set whose one usable key carries sentinels in members it never renders (its {@code issuer} and an
		 * unknown member), and whose other keys, each skipped, carry them in private and symmetric members and in the
		 * members that get them skipped.
		 */
		private static @NonNull String sentinelKeySet() {
			return TestJsonWebKeys.keySet(List.of(
					TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid(KEY_ID)
							.issuer(Sentinels.secret("jwk-issuer")).member("x-note", JsonText.string(SECRET)).toJson(),
					TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_3072).kid(Sentinels.secret("private-rsa"))
							.member("d", JsonText.string(Sentinels.PRIVATE_KEY_MEMBER))
							.member("p", JsonText.string(Sentinels.PRIVATE_KEY_MEMBER)).toJson(),
					TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P256).kid(Sentinels.secret("private-ec"))
							.member("d", JsonText.string(Sentinels.PRIVATE_KEY_MEMBER)).toJson(),
					TestJsonWebKeys.withFixture(Fixture.ED25519).kid(Sentinels.secret("private-okp"))
							.member("d", JsonText.string(Sentinels.PRIVATE_KEY_MEMBER)).toJson(),
					TestJsonWebKeys.octWithK(Sentinels.SYMMETRIC_KEY).kid(Sentinels.secret("oct")).toJson(),
					TestJsonWebKeys.octWithK(Sentinels.HMAC_SECRET).alg("HS256").toJson(),
					TestJsonWebKeys.withFixture(Fixture.SP_ENCRYPTION_RSA_2048).kid(Sentinels.secret("encryption"))
							.use("enc").toJson(),
					TestJsonWebKeys.withFixture(Fixture.NEGATIVE_ATTACKER_RSA_2048).alg(SECRET).toJson(),
					JsonText.object(List.of(Map.entry("kty", JsonText.string(SECRET)),
							Map.entry("kid", JsonText.string(SECRET)))),
					TestJsonWebKeys.withFixture(Fixture.SP_SIGNING_RSA_2048).member("x5c",
							JsonText.stringArray(List.of(SECRET))).toJson(),
					TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P384).member("issuer",
							JsonText.stringArray(List.of(SECRET))).toJson(),
					TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_EC_P521).kid(SECRET.repeat(10)).toJson(),
					TestJsonWebKeys.ecOffCurve().kid(Sentinels.secret("off-curve")).toJson()));
		}

		/**
		 * What {@code call} throws, which it must.
		 */
		private static @NonNull Throwable thrownBy(@NonNull String name, @NonNull ThrowingSupplier<?> call) {
			try {
				call.get();
				throw new AssertionError(name + ": expected a failure");
			} catch (AssertionError error) {
				throw error;
			} catch (Throwable throwable) {
				return throwable;
			}
		}
	}

	/**
	 * Collects every record published on the {@code com.revetsec} logger while it is attached.
	 */
	private static final class RecordingHandler extends Handler {
		private final List<LogRecord> records = new CopyOnWriteArrayList<>();

		@NonNull List<@NonNull LogRecord> getRecords() {
			return List.copyOf(this.records);
		}

		void clear() {
			this.records.clear();
		}

		@Override
		public void publish(@NonNull LogRecord record) {
			this.records.add(record);
		}

		@Override
		public void flush() {
			// Nothing buffered.
		}

		@Override
		public void close() {
			// Nothing to release.
		}
	}
    @Test void resourceProofResultsFailuresAndActualObserverArgumentsAreRedacted() throws Exception {
        Clock clock=Clock.fixed(NOW,java.time.ZoneOffset.UTC);
        RecordingObserver<com.revetsec.oauth.AccessTokenObserver> observer=RecordingObserver.fromInterface(com.revetsec.oauth.AccessTokenObserver.class,()->new IllegalStateException(HOOK_SECRET));
        JsonObject claims=JsonObject.builder().put("iss",ISSUER).put("aud",AUDIENCE).put("sub",SECRET).put("client_id",SECRET).put("jti",SECRET).put("scope","read").put("iat",NOW.getEpochSecond()).put("exp",NOW.plusSeconds(60).getEpochSecond()).put("custom",SECRET).build();
        String compact=TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid(KEY_ID).typ("at+jwt").payload(claims.toJson()).sign(TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());Sentinels.assertPresent(compact);
        com.revetsec.oauth.JwtAccessTokenValidator.Builder builder=com.revetsec.oauth.JwtAccessTokenValidator.withIssuer(ISSUER).expectedAudiences(Set.of(AUDIENCE)).jsonWebKeySource(StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(TestJsonWebKeys.keySet(List.of(rsaJwk(KEY_ID)))))).clock(clock).observer(observer.getObserver());
        com.revetsec.oauth.JwtAccessTokenValidator validator=builder.build();com.revetsec.oauth.BearerToken bearer=com.revetsec.oauth.BearerToken.fromAuthorizationHeaderValues(List.of("Bearer "+compact)).orElseThrow();
        com.revetsec.oauth.AccessTokenValidationResult result=validator.validateResult(bearer);com.revetsec.oauth.VerifiedAccessToken proof=Assertions.assertInstanceOf(com.revetsec.oauth.AccessTokenValidationResult.Succeeded.class,result).getAccessToken();
        Sentinels.assertPresent(proof.getClaims());Sentinels.assertAbsent(List.of(builder,validator,bearer,result,proof,observer));
        com.revetsec.oauth.BearerToken invalid=com.revetsec.oauth.BearerToken.fromAuthorizationHeaderValues(List.of("Bearer "+SECRET)).orElseThrow();Sentinels.assertAbsent(validator.validateResult(invalid));assertRedacted(Assertions.assertThrows(com.revetsec.oauth.AccessTokenValidationException.class,()->validator.validate(invalid)));
        try(TestHttpsServer server=TestHttpsServer.start()) {
            String path="/inspect";server.script(path,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,"{\"active\":true,\"aud\":"+JsonText.string(AUDIENCE)+",\"sub\":"+JsonText.string(SECRET)+",\"scope\":\"read\",\"custom\":"+JsonText.string(SECRET)+"}")));
            com.revetsec.oauth.OAuthClient oauth=com.revetsec.oauth.OAuthClient.withAuthorizationServerMetadata(com.revetsec.oauth.AuthorizationServerMetadata.withIssuer(server.getBaseUri().toString()).authorizationEndpoint(server.uri("/authorize")).tokenEndpoint(server.uri("/token")).introspectionEndpoint(server.uri(path+"?secret="+URI_SECRET)).build()).clientId("client").clientAuthentication(com.revetsec.oauth.ClientAuthentication.fromClientSecretBasic(SECRET)).httpClient(TestTls.httpClient()).clock(clock).observer(observer.getObserver()).build();
            com.revetsec.oauth.TokenIntrospectionClient.Builder ib=com.revetsec.oauth.TokenIntrospectionClient.withOAuthClient(oauth).expectedAudiences(Set.of(AUDIENCE)).observer(observer.getObserver());com.revetsec.oauth.TokenIntrospectionClient client=ib.build();
            com.revetsec.oauth.AccessTokenValidationResult ir=client.validateResult(invalid);com.revetsec.oauth.VerifiedAccessToken ip=Assertions.assertInstanceOf(com.revetsec.oauth.AccessTokenValidationResult.Succeeded.class,ir).getAccessToken();Sentinels.assertPresent(ip.getClaims());Sentinels.assertAbsent(List.of(ib,client,ir,ip,observer));
            server.script(path,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(200,"{\"active\":false,\"sub\":"+JsonText.string(SECRET)+"}")));Sentinels.assertAbsent(client.validateResult(invalid));
            server.script(path,TestHttpsServer.Script.fromResponse(TestHttpsServer.Response.fromJson(401,"{\"error\":\"invalid_client\",\"error_description\":"+JsonText.string(SECRET)+"}")));assertRedacted(Assertions.assertThrows(com.revetsec.oauth.OAuthException.class,()->client.validateResult(invalid)));Sentinels.assertAbsent(observer);
        }
        Assertions.assertFalse(this.logRecords.getRecords().isEmpty());Sentinels.assertAbsent(this.logRecords.getRecords());
    }

}
