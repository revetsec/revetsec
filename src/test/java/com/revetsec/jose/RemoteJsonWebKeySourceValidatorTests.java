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

package com.revetsec.jose;

import com.revetsec.ErrorCategory;
import com.revetsec.jose.RemoteJsonWebKeySourceConcurrencyTests.Call;
import com.revetsec.testing.JsonText;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestHttpsServer;
import com.revetsec.testing.TestHttpsServer.HeldScript;
import com.revetsec.testing.TestHttpsServer.Response;
import com.revetsec.testing.TestHttpsServer.Script;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
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
import java.math.BigInteger;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static com.revetsec.jose.JwksCacheTests.START;
import static com.revetsec.jose.JwksCacheTests.WAIT;

/**
 * The key-set exits through the public {@link JwtValidator} over a {@link RemoteJsonWebKeySource} and the in-process
 * {@link TestHttpsServer} (M2 plan, "Order and integration"): the remote halves of exit criteria 5 and 6 (header key
 * references and malformed signatures are refused before any key is looked up, so the key-set server and a
 * {@code jku} target see zero requests, with a positive control that a well-formed unknown key makes exactly one),
 * exit criterion 11's public-API variant, exit criteria 12 and 15 and OpenID Connect Core section 10.1 through
 * {@code validate}, the unchanged propagation of {@link JsonWebKeySetUnavailableException}, and the selections that
 * never refresh (INV-J3, INV-C6, M2-11).
 * <p>
 * These run green only against the full validation pipeline; they are written against the published signatures and
 * first run at the phase-2 integration.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class RemoteJsonWebKeySourceValidatorTests {
	private static final String ISSUER = "https://issuer.example.com/tenant";
	private static final String AUDIENCE = "api://resource";
	private static final Instant EXPIRES_AT = START.plus(Duration.ofHours(1));
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

	// Exit criterion 5 (INV-J4, RFC 8725 section 3.10): a token that carries jwk, jku or x5u, including a jku equal to
	// the configured key-set URI, is UNTRUSTED_KEY_REFERENCE on a cold remote source, and neither the key-set server
	// nor the jku target sees a request. Positive control: the same source and server, given a well-formed token with
	// an unknown kid, record exactly one request.
	@TestFactory
	Stream<DynamicTest> headerKeyReferencesAreRefusedBeforeAnyRequest() {
		String attackerJwk = TestJsonWebKeys.withFixture(Fixture.NEGATIVE_ATTACKER_RSA_2048).toJson();
		return Stream.of("jwk", "jku to another path", "jku to the key-set URI itself", "x5u").map(member ->
				DynamicTest.dynamicTest(member, () -> {
					String path = path();
					String target = path + "-target";
					server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(keySet(Map.of("a",
							Fixture.IDP_SIGNING_RSA_2048)))));
					server().script(target, Script.fromResponse(Response.fromJsonWebKeySet(keySet(Map.of("attacker",
							Fixture.NEGATIVE_ATTACKER_RSA_2048)))));
					RemoteJsonWebKeySource source = source(path, TestClock.fromInstant(START)).build();
					JwtValidator validator = validator(source, TestClock.fromInstant(START), Set.of(JwsAlgorithm.RS256));

					TestJws.Builder token = TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("attacker").payload(claims());
					switch (member) {
						case "jwk" -> token.headerMember("jwk", attackerJwk);
						case "jku to another path" -> token.headerMember("jku", JsonText.string(server().uri(target)
								.toString()));
						case "jku to the key-set URI itself" -> token.headerMember("jku", JsonText.string(server().uri(path)
								.toString()));
						default -> token.headerMember("x5u", JsonText.string(server().uri(target).toString()));
					}
					String compact = token.sign(Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey());

					assertRejected(JoseException.Reason.UNTRUSTED_KEY_REFERENCE, () -> validator.validate(compact));
					Assertions.assertEquals(0, server().getHitCount(path));
					Assertions.assertEquals(0, server().getHitCount(target));

					String unknownKey = TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid("attacker").payload(claims())
							.sign(Fixture.NEGATIVE_ATTACKER_RSA_2048.getPrivateKey());
					assertRejected(JoseException.Reason.UNKNOWN_KEY, () -> validator.validate(unknownKey));
					Assertions.assertEquals(1, server().getHitCount(path));
					Assertions.assertEquals(0, server().getHitCount(target));
				}));
	}

	// Exit criterion 6 (INV-J5, CVE-2022-21449, M2-6): r = 0, r = n, s = n, r = n + 1 and 64 zero octets for ES256,
	// and RS256 and PS256 signatures of 0, 1 and 2,049 octets, are SIGNATURE_MALFORMED before key resolution: with an
	// unknown kid against a cold remote source, the key-set server sees zero requests for every one. Positive control:
	// the well-formed token with the same kid makes exactly one.
	@TestFactory
	Stream<DynamicTest> malformedSignaturesAreRefusedBeforeAnyRequest() {
		List<DynamicTest> tests = new ArrayList<>();
		TestJws.Signed es256 = TestJws.withAlgorithm(TestJws.Algorithm.ES256).kid("unknown").payload(claims())
				.signed(Fixture.IDP_SIGNING_EC_P256.getPrivateKey());
		for (TestJws.Variant variant : List.of(TestJws.Variant.R_ZERO, TestJws.Variant.R_EQUALS_ORDER,
				TestJws.Variant.S_EQUALS_ORDER, TestJws.Variant.R_ORDER_PLUS_ONE, TestJws.Variant.ZERO_SIGNATURE,
				TestJws.Variant.EMPTY_SIGNATURE, TestJws.Variant.ONE_OCTET_LONG, TestJws.Variant.DER_SIGNATURE))
			tests.add(malformedSignatureTest("ES256 " + variant, es256.withVariant(variant),
					es256.toCompactSerialization()));
		for (TestJws.Algorithm algorithm : List.of(TestJws.Algorithm.RS256, TestJws.Algorithm.PS256)) {
			TestJws.Builder builder = TestJws.withAlgorithm(algorithm).kid("unknown").payload(claims());
			String wellFormed = builder.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
			for (int octets : List.of(0, 1, 255, 2_049))
				tests.add(malformedSignatureTest(algorithm + " with " + octets + " octets",
						builder.withSignature(new byte[octets]), wellFormed));
		}
		return tests.stream();
	}

	// Exit criterion 11, the public-API variant: 100 threads released together by a barrier
	// validate a token whose kid is not in the cached key set; the server holds the one refetch until the other 99 are
	// waiting for it, then every token validates, after exactly one refetch.
	@Test
	void oneHundredConcurrentValidationsOfARotatedInKeyMakeOneRefetch() throws Exception {
		String path = path();
		server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(keySet(Map.of("a",
				Fixture.IDP_SIGNING_RSA_2048)))));
		TestClock clock = TestClock.fromInstant(START);
		RemoteJsonWebKeySource source = source(path, clock).requestTimeout(Duration.ofSeconds(60)).build();
		JwtValidator validator = validator(source, clock, Set.of(JwsAlgorithm.RS256));
		Assertions.assertEquals(JwsAlgorithm.RS256, validator.validate(token("a", Fixture.IDP_SIGNING_RSA_2048))
				.getAlgorithm());

		HeldScript held = HeldScript.fromResponse(Response.fromJsonWebKeySet(keySet(Map.of("a",
				Fixture.IDP_SIGNING_RSA_2048, "b", Fixture.IDP_SIGNING_RSA_3072))));
		server().script(path, held);
		String rotatedIn = token("b", Fixture.IDP_SIGNING_RSA_3072);
		CyclicBarrier barrier = new CyclicBarrier(100);
		List<Call<Jwt>> calls = new ArrayList<>();
		for (int caller = 0; caller < 100; ++caller)
			calls.add(Call.start("validator-" + caller, () -> {
				barrier.await(WAIT.toNanos(), TimeUnit.NANOSECONDS);
				return validator.validate(rotatedIn);
			}));

		Assertions.assertTrue(held.awaitHeldCount(1, WAIT));
		Assertions.assertTrue(source.cacheForTests().awaitWaitersForTests(99, WAIT));
		held.release();
		for (Call<Jwt> call : calls)
			Assertions.assertEquals(ISSUER, call.await().getClaims().getIssuer().orElseThrow());
		Assertions.assertEquals(2, server().getHitCount(path));
	}

	// Exit criterion 12: a key removed from the key set stops verifying at the first
	// successful refresh after the time to live, and the key that stayed keeps verifying. Validations after the one that
	// led the refresh read the stored key set, which lacks the removed key too: one unknown-key refetch, then nothing
	// inside its cooldown.
	@Test
	void aRemovedKeyStopsVerifyingAtTheFirstRefreshAfterTheTimeToLive() {
		String path = path();
		server().script(path, Script.fromSequence(List.of(
				Response.fromJsonWebKeySet(keySet(Map.of("a", Fixture.IDP_SIGNING_RSA_2048, "b",
						Fixture.IDP_SIGNING_RSA_3072)), "max-age=60"),
				Response.fromJsonWebKeySet(keySet(Map.of("a", Fixture.IDP_SIGNING_RSA_2048)), "max-age=60"))));
		TestClock clock = TestClock.fromInstant(START);
		JwtValidator validator = validator(source(path, clock).build(), clock, Set.of(JwsAlgorithm.RS256));
		String removed = token("b", Fixture.IDP_SIGNING_RSA_3072);
		String kept = token("a", Fixture.IDP_SIGNING_RSA_2048);

		Assertions.assertEquals("b", validator.validate(removed).getKeyId().orElseThrow());
		clock.advance(Duration.ofSeconds(60).minusNanos(1));
		Assertions.assertEquals("b", validator.validate(removed).getKeyId().orElseThrow());
		clock.advance(Duration.ofNanos(1));
		assertRejected(JoseException.Reason.UNKNOWN_KEY, () -> validator.validate(removed));
		Assertions.assertEquals("a", validator.validate(kept).getKeyId().orElseThrow());
		Assertions.assertEquals(2, server().getHitCount(path));

		clock.advance(Duration.ofSeconds(1));
		assertRejected(JoseException.Reason.UNKNOWN_KEY, () -> validator.validate(removed));
		Assertions.assertEquals(3, server().getHitCount(path));
		clock.advance(Duration.ofSeconds(1));
		assertRejected(JoseException.Reason.UNKNOWN_KEY, () -> validator.validate(removed));
		Assertions.assertEquals(3, server().getHitCount(path));
	}

	// Exit criterion 15 through validate (RFC 9111 section 5.2): max-age=5 keeps the key set for the 1 min minimum, so
	// a validation at 59 s sends nothing and one at 60 s refetches.
	@Test
	void theTimeToLiveGovernsRefetchesDuringValidation() {
		String path = path();
		server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(keySet(Map.of("a",
				Fixture.IDP_SIGNING_RSA_2048)), "max-age=5")));
		TestClock clock = TestClock.fromInstant(START);
		JwtValidator validator = validator(source(path, clock).build(), clock, Set.of(JwsAlgorithm.RS256));
		String compact = token("a", Fixture.IDP_SIGNING_RSA_2048);

		Assertions.assertEquals("a", validator.validate(compact).getKeyId().orElseThrow());
		clock.advance(Duration.ofSeconds(59));
		Assertions.assertEquals("a", validator.validate(compact).getKeyId().orElseThrow());
		Assertions.assertEquals(1, server().getHitCount(path));
		clock.advance(Duration.ofSeconds(1));
		Assertions.assertEquals("a", validator.validate(compact).getKeyId().orElseThrow());
		Assertions.assertEquals(2, server().getHitCount(path));
	}

	// Exit criterion 15 and G6-2: a refresh with 101 keys, or a 300 KiB body with no Content-Length, makes
	// validate throw JsonWebKeySetUnavailableException, MALFORMED_INPUT and not transient, unchanged: the same instance
	// reaches the source's didFailToFetchJsonWebKeySet and the validator's didFailToValidateJwt. The previous key set
	// stays in use.
	@TestFactory
	Stream<DynamicTest> aMalformedRefreshPropagatesUnchangedAndThePreviousKeySetStays() {
		Response tooManyKeys = Response.fromJsonWebKeySet(JwksCacheTests.keySetJson(JwksCacheTests.keyIds(101)));
		Response oversized = Response.withStatus(200).header("Content-Type", TestHttpsServer.JWK_SET_MEDIA_TYPE)
				.body(new byte[300 * 1024]).framing(TestHttpsServer.Framing.CHUNKED).build();
		return Stream.of(Map.entry("101 keys", tooManyKeys), Map.entry("300 KiB with no Content-Length", oversized))
				.map(row -> DynamicTest.dynamicTest(row.getKey(), () -> {
					String path = path();
					server().script(path, Script.fromSequence(List.of(Response.fromJsonWebKeySet(keySet(Map.of("a",
							Fixture.IDP_SIGNING_RSA_2048))), row.getValue())));
					TestClock clock = TestClock.fromInstant(START);
					RecordingObserver<JoseObserver> sourceObserver = RecordingObserver.fromInterface(JoseObserver.class);
					RecordingObserver<JoseObserver> validatorObserver = RecordingObserver.fromInterface(JoseObserver.class);
					RemoteJsonWebKeySource source = source(path, clock).observer(sourceObserver.getObserver()).build();
					JwtValidator validator = JwtValidator.withIssuer(ISSUER).jsonWebKeySource(source)
							.expectedAudiences(Set.of(AUDIENCE)).clock(clock).observer(validatorObserver.getObserver())
							.build();
					String kept = token("a", Fixture.IDP_SIGNING_RSA_2048);
					Assertions.assertEquals("a", validator.validate(kept).getKeyId().orElseThrow());

					String unknown = token("b", Fixture.IDP_SIGNING_RSA_3072);
					JsonWebKeySetUnavailableException exception = Assertions.assertThrows(
							JsonWebKeySetUnavailableException.class, () -> validator.validate(unknown));
					Assertions.assertEquals(ErrorCategory.MALFORMED_INPUT, exception.getCategory());
					Assertions.assertFalse(exception.isTransient());
					Assertions.assertSame(exception, sourceObserver.getCalls("didFailToFetchJsonWebKeySet").get(0)
							.getArgument(1));
					Assertions.assertSame(exception, validatorObserver.getCalls("didFailToValidateJwt").get(0)
							.getArgument(0));

					Assertions.assertEquals("a", validator.validate(kept).getKeyId().orElseThrow());
					Assertions.assertEquals(2, server().getHitCount(path));
				}));
	}

	// Plan "Key selection" and OpenID Connect Core section 10.1: a kid-less token with one compatible key validates;
	// with two it is AMBIGUOUS_KEY, as is a duplicate kid; none of them refreshes the key set.
	@Test
	void ambiguousSelectionsNeverRefresh() {
		String path = path();
		String keySet = TestJsonWebKeys.keySet(List.of(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("twice").toJson(),
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_3072).kid("twice").toJson()));
		server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(keySet)));
		TestClock clock = TestClock.fromInstant(START);
		JwtValidator validator = validator(source(path, clock).build(), clock, Set.of(JwsAlgorithm.RS256));

		assertRejected(JoseException.Reason.AMBIGUOUS_KEY, () -> validator.validate(token("twice",
				Fixture.IDP_SIGNING_RSA_2048)));
		assertRejected(JoseException.Reason.AMBIGUOUS_KEY, () -> validator.validate(token(null,
				Fixture.IDP_SIGNING_RSA_2048)));
		Assertions.assertEquals(1, server().getHitCount(path));

		String single = path();
		server().script(single, Script.fromResponse(Response.fromJsonWebKeySet(keySet(Map.of("only",
				Fixture.IDP_SIGNING_RSA_2048)))));
		JwtValidator singleValidator = validator(source(single, clock).build(), clock, Set.of(JwsAlgorithm.RS256));
		Assertions.assertEquals(JwsAlgorithm.RS256, singleValidator.validate(token(null, Fixture.IDP_SIGNING_RSA_2048))
				.getAlgorithm());
	}

	// INV-J3 (G8-2) and M2-11 over a remote source: an RSA key without alg verifies RS256 under {RS256}; under
	// {RS256, PS256} it fits neither, so RS256 and PS256 tokens with its kid are KEY_ALGORITHM_MISMATCH, with no
	// refresh.
	@Test
	void anRsaKeyWithoutAlgorithmFitsOnlyASoleRsaAlgorithmAndNeverRefreshes() {
		String path = path();
		server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(keySet(Map.of("entra-like",
				Fixture.IDP_SIGNING_RSA_2048)))));
		TestClock clock = TestClock.fromInstant(START);
		RemoteJsonWebKeySource source = source(path, clock).build();

		JwtValidator rs256Only = validator(source, clock, Set.of(JwsAlgorithm.RS256));
		Assertions.assertEquals(JwsAlgorithm.RS256, rs256Only.validate(token("entra-like",
				Fixture.IDP_SIGNING_RSA_2048)).getAlgorithm());

		JwtValidator twoRsa = validator(source, clock, Set.of(JwsAlgorithm.RS256, JwsAlgorithm.PS256));
		assertRejected(JoseException.Reason.KEY_ALGORITHM_MISMATCH, () -> twoRsa.validate(token("entra-like",
				Fixture.IDP_SIGNING_RSA_2048)));
		String ps256 = TestJws.withAlgorithm(TestJws.Algorithm.PS256).kid("entra-like").payload(claims())
				.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());
		assertRejected(JoseException.Reason.KEY_ALGORITHM_MISMATCH, () -> twoRsa.validate(ps256));
		Assertions.assertEquals(1, server().getHitCount(path));
	}

	// Plan "Key selection" and INV-G11: a token without kid that no key fits counts as an unknown key, not as a key
	// that does not fit its algorithm. With an RSA key without alg under {RS256, PS256}, a kid-less RS256 token is
	// UNKNOWN_KEY: once after the first fetch, then after one unknown-key refetch, then with no request inside that
	// refetch's cooldown, and after one more refetch once the cooldown has passed.
	@Test
	void aTokenWithoutKidThatNoKeyFitsRefreshesAtMostOncePerCooldown() {
		String path = path();
		server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(keySet(Map.of("entra-like",
				Fixture.IDP_SIGNING_RSA_2048)))));
		TestClock clock = TestClock.fromInstant(START);
		JwtValidator twoRsa = validator(source(path, clock).build(), clock, Set.of(JwsAlgorithm.RS256,
				JwsAlgorithm.PS256));
		String kidless = token(null, Fixture.IDP_SIGNING_RSA_2048);

		assertRejected(JoseException.Reason.UNKNOWN_KEY, () -> twoRsa.validate(kidless));
		Assertions.assertEquals(1, server().getHitCount(path), "the first fetch");
		clock.advance(Duration.ofSeconds(1));
		assertRejected(JoseException.Reason.UNKNOWN_KEY, () -> twoRsa.validate(kidless));
		Assertions.assertEquals(2, server().getHitCount(path), "one unknown-key refetch");
		clock.advance(Duration.ofSeconds(29));
		assertRejected(JoseException.Reason.UNKNOWN_KEY, () -> twoRsa.validate(kidless));
		Assertions.assertEquals(2, server().getHitCount(path), "inside the cooldown");
		clock.advance(Duration.ofSeconds(1));
		assertRejected(JoseException.Reason.UNKNOWN_KEY, () -> twoRsa.validate(kidless));
		Assertions.assertEquals(3, server().getHitCount(path), "after the cooldown");
	}

	// INV-C6 and M2-11 over a remote source: a key whose JWK issuer member names another issuer gives
	// KEY_ISSUER_MISMATCH, which never refreshes the key set; a signature that does not verify never refreshes it either.
	@Test
	void keyIssuerAndSignatureMismatchesNeverRefresh() {
		String path = path();
		String keySet = TestJsonWebKeys.keySet(List.of(
				TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("other-issuer")
						.issuer("https://other.example.com/tenant").toJson(),
				TestJsonWebKeys.withFixture(Fixture.SP_SIGNING_RSA_2048).kid("b").toJson()));
		server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(keySet)));
		TestClock clock = TestClock.fromInstant(START);
		JwtValidator validator = validator(source(path, clock).build(), clock, Set.of(JwsAlgorithm.RS256));

		assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, () -> validator.validate(token("other-issuer",
				Fixture.IDP_SIGNING_RSA_2048)));
		assertRejected(JoseException.Reason.SIGNATURE_MISMATCH, () -> validator.validate(token("b",
				Fixture.IDP_SIGNING_RSA_2048)));
		Assertions.assertEquals(1, server().getHitCount(path));
	}

	// M2-11 and exit criterion 10 over a remote source: a key set shaped like Entra's (RSA keys with use sig, an x5c and
	// no alg) with the captured JWK issuer members. The {tenantid} template verifies a token whose lowercase GUID tid
	// substitutes into the configured tenant issuer; an exact-tenant key and a consumer-tenant key verify their own
	// issuers. Every M2-11 negative fails with its reason and never refreshes the key set: tid absent, not a string,
	// uppercase, braced or not a GUID; another tenant's tid; another iss (ISSUER_MISMATCH, first); a look-alike template;
	// a consumer key for an enterprise token; and {RS256, PS256}. The positive control, a well-formed unknown kid,
	// refreshes it once.
	@Test
	void entraShapedKeySetsVerifyTheirTenantsAndNoNegativeRefreshes() {
		String template = "https://login.microsoftonline.com/{tenantid}/v2.0";
		String tenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47";
		String consumerId = "9188040d-6c67-4c5b-b112-36a304b66dad";
		String tenantIssuer = "https://login.microsoftonline.com/" + tenantId + "/v2.0";
		String consumerIssuer = "https://login.microsoftonline.com/" + consumerId + "/v2.0";
		Map<String, String> lookAlikes = Map.of(
				"us-cloud", "https://login.microsoftonline.us/{tenantid}/v2.0",
				"uppercase-placeholder", "https://login.microsoftonline.com/{TENANTID}/v2.0",
				"doubled-placeholder", "https://login.microsoftonline.com/{tenantid}{tenantid}/v2.0",
				"trailing-slash", "https://login.microsoftonline.com/{tenantid}/v2.0/");
		List<String> keys = new ArrayList<>(List.of(entraKey(Fixture.IDP_SIGNING_RSA_2048, "templated", template),
				entraKey(Fixture.IDP_SIGNING_RSA_3072, "tenant", tenantIssuer),
				entraKey(Fixture.SP_SIGNING_RSA_2048, "consumer", consumerIssuer)));
		lookAlikes.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> keys.add(entraKey(
				Fixture.IDP_SIGNING_RSA_2048, entry.getKey(), entry.getValue())));
		String path = path();
		server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(TestJsonWebKeys.keySet(keys))));
		TestClock clock = TestClock.fromInstant(START);
		RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
		RemoteJsonWebKeySource source = source(path, clock).observer(observer.getObserver()).build();
		JwtValidator tenant = entraValidator(source, clock, tenantIssuer, Set.of(JwsAlgorithm.RS256));
		JwtValidator consumer = entraValidator(source, clock, consumerIssuer, Set.of(JwsAlgorithm.RS256));
		String tid = JsonText.string(tenantId);

		Assertions.assertEquals("templated", tenant.validate(entraToken(TestJws.Algorithm.RS256, "templated",
				Fixture.IDP_SIGNING_RSA_2048, tenantIssuer, tid)).getKeyId().orElseThrow());
		Assertions.assertEquals("tenant", tenant.validate(entraToken(TestJws.Algorithm.RS256, "tenant",
				Fixture.IDP_SIGNING_RSA_3072, tenantIssuer, tid)).getKeyId().orElseThrow());
		Assertions.assertEquals("consumer", consumer.validate(entraToken(TestJws.Algorithm.RS256, "consumer",
				Fixture.SP_SIGNING_RSA_2048, consumerIssuer, JsonText.string(consumerId))).getKeyId().orElseThrow());
		Assertions.assertEquals(List.of(), observer.getCalls("didSkipJsonWebKey"), "no Entra-shaped key is skipped");
		Assertions.assertEquals(1, server().getHitCount(path));

		List<@Nullable String> badTids = new ArrayList<>(List.of("72988", "null",
				JsonText.string(tenantId.toUpperCase(Locale.ROOT)), JsonText.string("{" + tenantId + "}"),
				JsonText.string("contoso.onmicrosoft.com"), JsonText.string(tenantId.replace("-", "")),
				JsonText.string(consumerId)));
		badTids.add(null);
		for (@Nullable String badTid : badTids)
			assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, () -> tenant.validate(entraToken(
					TestJws.Algorithm.RS256, "templated", Fixture.IDP_SIGNING_RSA_2048, tenantIssuer, badTid)));
		assertRejected(JoseException.Reason.ISSUER_MISMATCH, () -> tenant.validate(entraToken(TestJws.Algorithm.RS256,
				"templated", Fixture.IDP_SIGNING_RSA_2048, consumerIssuer, JsonText.string(consumerId))));
		for (String lookAlike : lookAlikes.keySet())
			assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, () -> tenant.validate(entraToken(
					TestJws.Algorithm.RS256, lookAlike, Fixture.IDP_SIGNING_RSA_2048, tenantIssuer, tid)));
		assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, () -> tenant.validate(entraToken(
				TestJws.Algorithm.RS256, "consumer", Fixture.SP_SIGNING_RSA_2048, tenantIssuer, tid)));
		JwtValidator widened = entraValidator(source, clock, tenantIssuer, Set.of(JwsAlgorithm.RS256,
				JwsAlgorithm.PS256));
		for (TestJws.Algorithm algorithm : List.of(TestJws.Algorithm.RS256, TestJws.Algorithm.PS256))
			assertRejected(JoseException.Reason.KEY_ALGORITHM_MISMATCH, () -> widened.validate(entraToken(algorithm,
					"templated", Fixture.IDP_SIGNING_RSA_2048, tenantIssuer, tid)));
		Assertions.assertEquals(1, server().getHitCount(path), "no negative refreshed the key set");

		assertRejected(JoseException.Reason.UNKNOWN_KEY, () -> tenant.validate(entraToken(TestJws.Algorithm.RS256,
				"rotated", Fixture.IDP_SIGNING_RSA_2048, tenantIssuer, tid)));
		Assertions.assertEquals(2, server().getHitCount(path));
	}

	private static DynamicTest malformedSignatureTest(String name, String malformed, String wellFormed) {
		return DynamicTest.dynamicTest(name, () -> {
			String path = path();
			server().script(path, Script.fromResponse(Response.fromJsonWebKeySet(keySet(Map.of("a",
					Fixture.IDP_SIGNING_RSA_2048)))));
			TestClock clock = TestClock.fromInstant(START);
			JwtValidator validator = validator(source(path, clock).build(), clock, Set.of(JwsAlgorithm.RS256,
					JwsAlgorithm.PS256, JwsAlgorithm.ES256));

			assertRejected(JoseException.Reason.SIGNATURE_MALFORMED, () -> validator.validate(malformed));
			Assertions.assertEquals(0, server().getHitCount(path));

			assertRejected(JoseException.Reason.UNKNOWN_KEY, () -> validator.validate(wellFormed));
			Assertions.assertEquals(1, server().getHitCount(path));
		});
	}

	private static void assertRejected(JoseException.Reason reason, Executable executable) {
		JoseException exception = Assertions.assertThrows(JoseException.class, executable);
		Assertions.assertEquals(reason, exception.getReason(), exception::toString);
	}

	private static JwtValidator validator(RemoteJsonWebKeySource source, TestClock clock,
			Set<JwsAlgorithm> allowedAlgorithms) {
		return JwtValidator.withIssuer(ISSUER).jsonWebKeySource(source).expectedAudiences(Set.of(AUDIENCE))
				.allowedAlgorithms(allowedAlgorithms).clock(clock).build();
	}

	private static JwtValidator entraValidator(RemoteJsonWebKeySource source, TestClock clock, String issuer,
			Set<JwsAlgorithm> allowedAlgorithms) {
		return JwtValidator.withIssuer(issuer).jsonWebKeySource(source).expectedAudiences(Set.of(AUDIENCE))
				.allowedAlgorithms(allowedAlgorithms).clock(clock).build();
	}

	/**
	 * An Entra-shaped key: the fixture's public key with {@code use} {@code sig}, its certificate as the {@code x5c},
	 * the given JWK {@code issuer} member, and no {@code alg}.
	 */
	private static String entraKey(Fixture fixture, String keyId, String issuer) {
		return TestJsonWebKeys.withFixture(fixture).kid(keyId).use("sig").x5c(List.of(fixture.getCertificate()
				.orElseThrow())).issuer(issuer).toJson();
	}

	/**
	 * A token for {@code issuer} and the validator's audience, valid for an hour from {@link JwksCacheTests#START}, with
	 * {@code rawTid} as the raw JSON of its {@code tid} claim, or no {@code tid} when it is {@code null}.
	 */
	private static String entraToken(TestJws.Algorithm algorithm, String keyId, Fixture key, String issuer,
			@Nullable String rawTid) {
		List<Map.Entry<String, String>> claims = new ArrayList<>(List.of(
				Map.entry("iss", JsonText.string(issuer)),
				Map.entry("sub", JsonText.string("subject")),
				Map.entry("aud", JsonText.string(AUDIENCE)),
				Map.entry("iat", BigInteger.valueOf(START.getEpochSecond()).toString()),
				Map.entry("exp", BigInteger.valueOf(EXPIRES_AT.getEpochSecond()).toString()),
				Map.entry("ver", JsonText.string("2.0"))));
		if (rawTid != null)
			claims.add(Map.entry("tid", rawTid));
		return TestJws.withAlgorithm(algorithm).kid(keyId).payload(JsonText.object(claims)).sign(key.getPrivateKey());
	}

	private static RemoteJsonWebKeySource.Builder source(String path, TestClock clock) {
		return RemoteJsonWebKeySource.withUri(server().uri(path)).httpClient(client()).clock(clock);
	}

	/**
	 * An RS256 token for the validator's issuer and audience, valid for an hour from {@link JwksCacheTests#START}.
	 */
	private static String token(@Nullable String keyId, Fixture key) {
		return TestJws.withAlgorithm(TestJws.Algorithm.RS256).kid(keyId).payload(claims()).sign(key.getPrivateKey());
	}

	private static String claims() {
		return JsonText.object(List.of(
				Map.entry("iss", JsonText.string(ISSUER)),
				Map.entry("sub", JsonText.string("subject")),
				Map.entry("aud", JsonText.string(AUDIENCE)),
				Map.entry("iat", BigInteger.valueOf(START.getEpochSecond()).toString()),
				Map.entry("exp", BigInteger.valueOf(EXPIRES_AT.getEpochSecond()).toString())));
	}

	/**
	 * A key set with each fixture's public key under its kid, in kid order, with no {@code alg}.
	 */
	private static String keySet(Map<String, Fixture> keys) {
		List<String> jwks = new ArrayList<>();
		keys.entrySet().stream().sorted(Map.Entry.comparingByKey()).forEach(entry -> jwks.add(TestJsonWebKeys
				.withFixture(entry.getValue()).kid(entry.getKey()).toJson()));
		return TestJsonWebKeys.keySet(jwks);
	}

	private static String path() {
		return "/validator-jwks/" + NEXT_PATH.incrementAndGet();
	}

	private static TestHttpsServer server() {
		TestHttpsServer current = server;
		if (current == null)
			throw new IllegalStateException("The server did not start");
		return current;
	}

	private static HttpClient client() {
		HttpClient current = client;
		if (current == null)
			throw new IllegalStateException("The client was not created");
		return current;
	}
}
