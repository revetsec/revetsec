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
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonFieldException;
import com.revetsec.internal.json.JsonFields;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.internal.json.Rfc7638;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.pem.PemException;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.Sentinels;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * No M1 rendering shows a secret (plan R9 and R16; M1 plan G6-1, G6-2 and G6-4; exit criterion 17).
 * <p>
 * Every test plants {@link Sentinels} in the input of one M1 surface and walks what Revetsec renders from it with
 * {@link Sentinels#findIn(Object)}: {@code toString()}, a JSON value's {@code toJson()}, an exception's message,
 * {@code toString()}, cause and suppressed chain and printed stack trace, and every argument recorded by a
 * {@link RecordingObserver}. Each failure is also handed to a recorded observer hook through
 * {@link ObserverDispatch}, once to a hook that returns and once to a hook that throws, and the {@code com.revetsec}
 * log records that the contained failure produces are walked too. Suppression is disabled on every Revetsec
 * exception, so a secret cannot be attached to one later.
 * <p>
 * The surfaces: the JSON model and {@link JsonObject.Builder}; codec and field failures; {@link SealingKey},
 * {@link StateSealer}, the internal sealer and their failures; encoding and PEM failures; {@link OutboundUriPolicy};
 * {@link Limit}; and the internal HTTP helper's requests (the ones it refuses included), responses and failures.
 * <p>
 * <strong>One documented exception.</strong> An {@link HttpExchangeException.Kind#IO} failure keeps the JDK's
 * {@link IOException} as its cause (G6-2), and the JDK may copy server-controlled text into that cause's message,
 * for example a status line it rejects. That is the server's own text echoed by the JDK, not something Revetsec
 * rendered, so for IO failures the server's sentinel may appear inside the cause (and in the "Caused by" part of the
 * printed stack trace), and nowhere else. The request's own secrets appear nowhere, not even in the cause
 * ({@link #anIoFailureCarriesServerTextOnlyInsideTheJdkCause()}).
 * <p>
 * Positive controls show the walker reaches what these tests rely on: a sentinel in a {@link JsonString} is found in
 * {@code toJson()} and not in {@code toString()}, a sentinel inside an exception passed to a recorded hook is found,
 * and a sentinel in a log record's parameters is found.
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
	private static final String CONTEXT = "redaction-context";
	private static final JsonLimits PROTOCOL = JsonLimits.protocolDocument(4 * 1_024 * 1_024);
	private static final Instant START = Instant.parse("2026-09-24T12:00:00Z");
	private static final AtomicInteger NEXT_PATH = new AtomicInteger();

	private static @Nullable TestHttpsServer jdkServer;
	private static @Nullable RawTlsServer rawServer;
	private static @Nullable HttpExchange exchange;

	/**
	 * Held strongly for the whole test, because the logging system keeps loggers only weakly.
	 */
	private final Logger logger = Logger.getLogger(ObserverDispatch.LOGGER_NAME);
	private final RecordingHandler logRecords = new RecordingHandler();
	private @Nullable Level originalLevel;
	private boolean originalUseParentHandlers;

	/**
	 * A test-only observer shaped like Revetsec's (G6-4): default {@code void} hooks that do nothing. M1 exports no
	 * observer yet, so failures reach a {@link RecordingObserver} through this interface and {@link ObserverDispatch},
	 * as M2's hooks will. {@code didFailToUnseal} takes only allowlisted parameter types; {@code didFail} also takes
	 * the internal checked failures, which M2 translates before any public hook sees them.
	 */
	interface RedactionObserver {
		default void didFail(@Nullable Throwable failure) {
			// No-op by default, like every Revetsec hook.
		}

		default void didFailToUnseal(@Nullable String context, @Nullable Duration elapsed,
				@Nullable RevetsecException exception) {
			// No-op by default, like every Revetsec hook.
		}
	}

	@BeforeAll
	static void startServers() throws IOException {
		jdkServer = TestHttpsServer.start();
		rawServer = RawTlsServer.start();
		exchange = HttpExchange.fromHttpClient(TestTls.httpClient(), OutboundUriPolicy.defaultInstance(), false);
	}

	@AfterAll
	static void stopServers() {
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

	// Exit criterion 17, positive control: the walker reads recorded hook arguments, exception graphs included.
	@Test
	void theWalkerFindsASentinelInsideAnExceptionPassedToARecordedHook() {
		RecordingObserver<RedactionObserver> recorder = RecordingObserver.fromInterface(RedactionObserver.class);
		IllegalStateException failure = new IllegalStateException("fixed", new IOException("echoed " + SECRET));

		ObserverDispatch.dispatch(recorder.getObserver(), observer -> observer.didFail(failure));

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
	Stream<DynamicTest> jsonModelFailuresDoNotEchoTheirInput() {
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
	Stream<DynamicTest> jsonParseFailuresDoNotEchoTheirInput() {
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
	Stream<DynamicTest> jsonFieldFailuresDoNotEchoTheirInput() {
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
	Stream<DynamicTest> sealerFailuresDoNotEchoTheirInput() {
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
	Stream<DynamicTest> encodingFailuresDoNotEchoTheirInput() throws EncodingException {
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
	Stream<DynamicTest> pemFailuresDoNotEchoTheirInput() throws Exception {
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
	Stream<DynamicTest> httpRequestMisuseDoesNotEchoCredentials() {
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
	Stream<DynamicTest> httpFailuresDoNotEchoTheRequestOrTheResponse() {
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
	// message, toString or stack frames, not in a log record, and in a recorded hook argument only through the cause.
	// The request's secrets appear nowhere at all, so an IOException Revetsec made itself cannot carry them.
	@TestFactory
	Stream<DynamicTest> anIoFailureCarriesServerTextOnlyInsideTheJdkCause() {
		return Stream.of(
				DynamicTest.dynamicTest("a status line the JDK rejects", () -> assertServerEchoOnlyInCause(
						raw().uri(scriptRaw(RawTlsServer.Script.fromString("HTTP/1.1 099 " + SERVER_ECHO + "\r\n"
								+ "Content-Length: 0\r\n\r\n"))))),
				DynamicTest.dynamicTest("a body the server cuts short", () -> assertServerEchoOnlyInCause(
						raw().uri(scriptRaw(RawTlsServer.Script.builder()
								.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n"
										+ "{\"token\":\"" + SERVER_ECHO)
								.closeConnection()
								.build())))));
	}

	// G6-4 and exit criterion 17: the public exception reaches a hook shaped like Revetsec's as the same instance, and
	// neither the recorded arguments nor the contained hook failure's log record carries a sentinel.
	@Test
	void anUnsealFailureReachesAnAllowlistShapedHookWithoutASentinel() {
		StateSealer sealer = TestSealers.fromFixedKey();
		InvalidSealedStateException failure = Assertions.assertThrows(InvalidSealedStateException.class,
				() -> sealer.unseal(SECRET, CONTEXT));

		RecordingObserver<RedactionObserver> recorder = RecordingObserver.fromInterface(RedactionObserver.class);
		ObserverDispatch.dispatch(recorder.getObserver(),
				observer -> observer.didFailToUnseal(CONTEXT, Duration.ofMillis(3), failure));
		Assertions.assertSame(failure, recorder.getCalls("didFailToUnseal").get(0).getArgument(2));
		Sentinels.assertAbsent(recorder);

		RecordingObserver<RedactionObserver> throwing = RecordingObserver.fromInterface(RedactionObserver.class,
				() -> new IllegalStateException(HOOK_SECRET));
		ObserverDispatch.dispatch(throwing.getObserver(),
				observer -> observer.didFailToUnseal(CONTEXT, Duration.ofMillis(3), failure));
		Assertions.assertEquals(1, this.logRecords.getRecords().size(), "the contained hook failure was logged");
		Sentinels.assertAbsent(List.of(throwing, this.logRecords.getRecords()));
	}

	/**
	 * A dynamic test that expects {@code executable} to throw {@code type} and asserts the failure is redacted.
	 */
	private <T extends Throwable> DynamicTest failure(String name, Class<T> type, Executable executable) {
		return DynamicTest.dynamicTest(name, () -> assertRedacted(Assertions.assertThrows(type, executable)));
	}

	private DynamicTest parseFailure(JsonParseException.Kind kind, JsonLimits limits, byte[] input) {
		String name = kind.name() + (limits.isAsciiCaseVariantNamesRejected() ? " (SCIM profile)" : "");
		return DynamicTest.dynamicTest(name, () -> {
			Sentinels.assertPresent(input);
			JsonParseException failure = Assertions.assertThrows(JsonParseException.class,
					() -> JsonCodec.parse(input, limits));
			Assertions.assertEquals(kind, failure.getKind());
			assertRedacted(failure);
		});
	}

	private DynamicTest httpFailure(String name, HttpExchangeException.Kind kind, Executable executable) {
		return DynamicTest.dynamicTest(kind.name() + ": " + name, () -> {
			HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class, executable);
			Assertions.assertEquals(kind, failure.getKind());
			Assertions.assertNull(failure.getCause(), "only IO keeps a cause");
			assertRedacted(failure);
		});
	}

	/**
	 * No rendering of {@code failure} carries a sentinel; nothing can be attached to a Revetsec exception later; and
	 * {@code failure}, handed to a recorded hook through {@link ObserverDispatch}, is recorded as the same instance
	 * with no sentinel, while the log record of a hook that throws carries none either.
	 */
	private void assertRedacted(Throwable failure) {
		Sentinels.assertAbsent(failure);
		assertSuppressionDisabledOnRevetsecExceptions(failure);
		Sentinels.assertAbsent(failure);

		RecordingObserver<RedactionObserver> recorder = dispatchToRecorder(failure);
		Sentinels.assertAbsent(recorder);
	}

	/**
	 * The documented IO allowance (see the class description): the failure is IO, its cause is the JDK's
	 * {@link IOException}, every place the walker finds a sentinel is inside that cause, and the only sentinel there
	 * is the server's {@link #SERVER_ECHO}, never a secret the request carried.
	 */
	private void assertServerEchoOnlyInCause(URI uri) {
		HttpExchangeException failure = Assertions.assertThrows(HttpExchangeException.class, () -> execute(uri));
		Assertions.assertEquals(HttpExchangeException.Kind.IO, failure.getKind());
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
		assertSuppressionDisabledOnRevetsecExceptions(failure);

		RecordingObserver<RedactionObserver> recorder = dispatchToRecorder(failure);
		assertOnlyInCause(Sentinels.findIn(recorder), "$.getCalls()[0].getArguments()[0]");
	}

	/**
	 * Hands {@code failure} to a recorded hook through {@link ObserverDispatch}, then to a recorded hook that throws
	 * an exception carrying a sentinel, and checks that ObserverDispatch logged the contained failure without one.
	 */
	private RecordingObserver<RedactionObserver> dispatchToRecorder(Throwable failure) {
		RecordingObserver<RedactionObserver> recorder = RecordingObserver.fromInterface(RedactionObserver.class);
		ObserverDispatch.dispatch(recorder.getObserver(), observer -> observer.didFail(failure));
		Assertions.assertSame(failure, recorder.getCalls("didFail").get(0).getArgument(0),
				"hooks receive the caller's exception instance (G6-4)");

		RecordingObserver<RedactionObserver> throwing = RecordingObserver.fromInterface(RedactionObserver.class,
				() -> new IllegalStateException(HOOK_SECRET));
		int recordsBefore = this.logRecords.getRecords().size();
		ObserverDispatch.dispatch(throwing.getObserver(), observer -> observer.didFail(failure));
		List<LogRecord> records = this.logRecords.getRecords();
		Assertions.assertEquals(recordsBefore + 1, records.size(), "the contained hook failure was logged");
		Sentinels.assertAbsent(records);
		return recorder;
	}

	/**
	 * A Revetsec exception has suppression disabled (G6-1), so a secret added as a suppressed exception is dropped.
	 * JDK exceptions thrown for misuse (R15) are left alone.
	 */
	private static void assertSuppressionDisabledOnRevetsecExceptions(Throwable failure) {
		if (!failure.getClass().getName().startsWith("com.revetsec."))
			return;
		failure.addSuppressed(new IllegalStateException(SUPPRESSED_SECRET));
		Assertions.assertEquals(0, failure.getSuppressed().length, failure.getClass()::getName);
	}

	private static void assertOnlyInCause(List<String> locations, String root) {
		for (String location : locations)
			Assertions.assertTrue(location.equals(root + " (printed stack trace)")
					|| location.startsWith(root + ".getCause()"), () -> "outside the JDK cause: " + location);
	}

	private static boolean isJdkClassName(String name) {
		return name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("jdk.")
				|| name.startsWith("sun.");
	}

	private static String printedStackTrace(Throwable throwable) {
		StringWriter stringWriter = new StringWriter();
		try (PrintWriter printWriter = new PrintWriter(stringWriter)) {
			throwable.printStackTrace(printWriter);
		}
		return stringWriter.toString();
	}

	/**
	 * Executes a {@link ResponseProfile#TOKEN} request that carries secrets ({@link #requestWithSecrets}).
	 */
	private static RawResponse execute(URI uri) throws HttpExchangeException {
		return exchange().execute(requestWithSecrets(uri, ResponseProfile.TOKEN, 1_024), deadline());
	}

	/**
	 * A POST that carries a secret in its query, its form body and two header values.
	 */
	private static HttpExchangeRequest requestWithSecrets(URI uri, ResponseProfile profile, int maximumBodyBytes) {
		URI withQuery = URI.create(uri + (uri.getRawQuery() == null ? "?" : "&") + "code=" + SECRET);
		return new HttpExchangeRequest(withQuery, profile, "client_secret=" + Sentinels.CLIENT_SECRET,
				Map.of("Authorization", "Bearer " + Sentinels.ACCESS_TOKEN, "X-Api-Key", SECRET), maximumBodyBytes,
				1_024, Duration.ofSeconds(10));
	}

	private static String scriptJdk(TestHttpsServer.Response response) {
		String path = "/redaction-" + NEXT_PATH.incrementAndGet();
		jdk().script(path, TestHttpsServer.Script.fromResponse(response));
		return path;
	}

	private static String scriptRaw(RawTlsServer.Script script) {
		String path = "/redaction-" + NEXT_PATH.incrementAndGet();
		raw().script(path, script);
		return path;
	}

	private static Deadline deadline() {
		return Deadline.fromNow(Duration.ofSeconds(30));
	}

	private static TestHttpsServer jdk() {
		return Objects.requireNonNull(jdkServer);
	}

	private static RawTlsServer raw() {
		return Objects.requireNonNull(rawServer);
	}

	private static HttpExchange exchange() {
		return Objects.requireNonNull(exchange);
	}

	private static String pem(String label, String body) {
		return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
	}

	private static String base64(byte[] bytes) {
		return Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(bytes);
	}

	private static String resource(String path) throws IOException {
		try (InputStream inputStream = Objects.requireNonNull(RedactionTests.class.getResourceAsStream(path), path)) {
			return new String(inputStream.readAllBytes(), StandardCharsets.US_ASCII);
		}
	}

	private static byte[] utf8(String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	private static byte[] concat(byte[]... parts) {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		for (byte[] part : parts)
			outputStream.writeBytes(part);
		return outputStream.toByteArray();
	}

	/**
	 * Collects every record published on the {@code com.revetsec} logger during a test.
	 */
	private static final class RecordingHandler extends Handler {
		private final List<LogRecord> records = new CopyOnWriteArrayList<>();

		List<LogRecord> getRecords() {
			return List.copyOf(this.records);
		}

		@Override
		public void publish(LogRecord record) {
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
}
