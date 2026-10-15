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

import com.revetsec.internal.crypto.RsaPublicKeys;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.TestJwk.Fixture;
import com.revetsec.testing.TestJws;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Standalone public-key publication, including its bounded HTTP and conditional-request contract. */
final class JwksPublisherTests {

	@Test
	void builderSnapshotsKeysAndPublishesThemInDocumentOrder() {
		PublishedJwk first = key(Fixture.IDP_SIGNING_RSA_2048, "first", JwsAlgorithm.RS384);
		PublishedJwk second = key(Fixture.IDP_SIGNING_EC_P256, "second", JwsAlgorithm.ES256);
		List<PublishedJwk> keys = new ArrayList<>(List.of(first, second));
		JwksPublisher.Builder builder = JwksPublisher.withKeys(keys);
		keys.clear();
		JwksPublisher publisher = builder.build();

		assertEquals(List.of(first, second), publisher.getKeys());
		assertThrows(UnsupportedOperationException.class, () -> publisher.getKeys().clear());
		assertEquals(List.of(first.toJsonObject(), second.toJsonObject()),
				assertInstanceOf(JsonArray.class, publisher.toJsonObject().getMembers().get("keys")).getElements());
		assertEquals(publisher.toJsonObject().toJson(), publisher.toJson());
		Jwks parsed = JwtFixtures.assertParsedJwks(publisher.toJson());
		assertEquals(List.of(Optional.of("first"), Optional.of("second")),
				parsed.getKeys().stream().map(Jwk::getKeyId).toList());
		assertEquals(publisher.toJson(), text(publisher.responseFor("GET")));

		builder.cacheLifetime(Duration.ofHours(1));
		assertEquals(Duration.ofSeconds(60), publisher.getCacheLifetime());
		assertEquals(Duration.ofHours(1), builder.build().getCacheLifetime());
	}

	@Test
	void emptySetCanWithdrawEveryPublishedKey() {
		JwksPublisher publisher = JwksPublisher.fromKeys(List.of());
		assertEquals(List.of(), publisher.getKeys());
		assertEquals("{\"keys\":[]}", publisher.toJson());
		assertEquals(200, publisher.responseFor("GET").getStatusCode());
		assertEquals(List.of(), JwtFixtures.assertParsedJwks(text(publisher.responseFor("GET"))).getKeys());
		assertEquals(Optional.of(publisher.toJsonObject()), publisher.responseFor("GET").getDocument());
		assertEquals(List.of(), assertInstanceOf(JsonArray.class,
				publisher.responseFor("GET").getDocument().orElseThrow().getMembers().get("keys")).getElements());
	}

	@Test
	void getResponseExposesTheStructuredPublicKeysAndCompleteCertificateChains() throws Exception {
		X509Certificate leaf = certificate("publisher-leaf.pem");
		X509Certificate root = certificate("publisher-root.pem");
		PublishedJwk prod = PublishedJwk.withPublicKey(leaf.getPublicKey()).keyId("epic-prod")
				.algorithm(JwsAlgorithm.RS384).certificateChain(List.of(leaf, root)).build();
		X509Certificate nonprodCertificate = Fixture.IDP_SIGNING_RSA_2048.getCertificate().orElseThrow();
		PublishedJwk nonprod = PublishedJwk.withPublicKey(nonprodCertificate.getPublicKey()).keyId("epic-nonprod")
				.algorithm(JwsAlgorithm.RS384).certificateChain(List.of(nonprodCertificate)).build();
		JwksPublisher publisher = JwksPublisher.fromKeys(List.of(prod, nonprod));
		JwksResponse response = publisher.responseFor("GET");
		JsonObject document = response.getDocument().orElseThrow();

		assertEquals(publisher.toJsonObject(), document);
		List<JsonValue> keys = assertInstanceOf(JsonArray.class,
				document.getMembers().get("keys")).getElements();
		assertEquals(List.of(prod.toJsonObject(), nonprod.toJsonObject()), keys);
		JsonObject prodJson = assertInstanceOf(JsonObject.class, keys.get(0));
		assertEquals(JsonString.fromValue("epic-prod"), prodJson.getMembers().get("kid"));
		assertEquals(JsonString.fromValue("RS384"), prodJson.getMembers().get("alg"));
		assertEquals(List.of(
				JsonString.fromValue(Base64.getEncoder().encodeToString(leaf.getEncoded())),
				JsonString.fromValue(Base64.getEncoder().encodeToString(root.getEncoded()))),
				assertInstanceOf(JsonArray.class, prodJson.getMembers().get("x5c")).getElements());
		assertEquals(document.toJson(), text(response));
	}

	@Test
	void duplicateKeyIdsAreRejectedButUnidentifiedKeysAreAllowed() {
		PublishedJwk first = key(Fixture.IDP_SIGNING_RSA_2048, "shared", JwsAlgorithm.RS384);
		PublishedJwk second = key(Fixture.SP_SIGNING_RSA_2048, "shared", JwsAlgorithm.RS384);
		assertThrows(IllegalArgumentException.class,
				() -> JwksPublisher.fromKeys(List.of(first, second)));
		assertThrows(IllegalArgumentException.class,
				() -> JwksPublisher.fromKeys(List.of(first, first)));

		PublishedJwk unidentified = PublishedJwk.withPublicKey(Fixture.IDP_SIGNING_RSA_2048.getPublicKey())
				.build();
		assertEquals(2, JwksPublisher.fromKeys(List.of(unidentified, unidentified)).getKeys().size());
		assertEquals(2, JwksPublisher.fromKeys(List.of(first,
				key(Fixture.SP_SIGNING_RSA_2048, "SHARED", JwsAlgorithm.RS384))).getKeys().size());
	}

	@Test
	void publisherAppliesTheSame100KeyAnd256KiBLimitsAsTheParser() throws Exception {
		PublishedJwk ordinary = PublishedJwk.withPublicKey(Fixture.IDP_SIGNING_RSA_2048.getPublicKey()).build();
		assertEquals(100, JwksPublisher.fromKeys(Collections.nCopies(100, ordinary)).getKeys().size());
		assertThrows(IllegalArgumentException.class,
				() -> JwksPublisher.fromKeys(Collections.nCopies(101, ordinary)));

		// A structurally valid public RSA key at the supported bit limit makes the body cap independently reachable.
		BigInteger modulus = BigInteger.ONE.shiftLeft(16383).add(BigInteger.valueOf(173));
		while (RsaPublicKeys.isRocaFingerprinted(modulus))
			modulus = modulus.add(BigInteger.TWO);
		PublicKey largePublicKey = KeyFactory.getInstance("RSA").generatePublic(
				new RSAPublicKeySpec(modulus, BigInteger.valueOf(65537)));
		PublishedJwk large = PublishedJwk.withPublicKey(largePublicKey).build();
		assertThrows(IllegalArgumentException.class,
				() -> JwksPublisher.fromKeys(Collections.nCopies(100, large)));
	}

	@Test
	void freshnessDefaultsTo60SecondsAndSupportsZeroThrough24Hours() {
		JwksPublisher.Builder builder = JwksPublisher.withKeys(List.of());
		assertEquals(Duration.ofSeconds(60), builder.build().getCacheLifetime());
		for (Duration freshness : List.of(Duration.ZERO, Duration.ofSeconds(1), Duration.ofHours(1), Duration.ofDays(1))) {
			JwksPublisher publisher = builder.cacheLifetime(freshness).build();
			assertEquals(freshness, publisher.getCacheLifetime());
			assertEquals("public, max-age=" + freshness.toSeconds() + ", must-revalidate",
					header(publisher.responseFor("GET"), "Cache-Control"));
		}
		assertEquals(Duration.ofSeconds(60), builder.cacheLifetime(null).build().getCacheLifetime());
		for (Duration invalid : List.of(Duration.ofSeconds(-1), Duration.ofNanos(1), Duration.ofSeconds(1, 1),
				Duration.ofDays(1).plusSeconds(1), Duration.ofSeconds(Long.MAX_VALUE)))
			assertThrows(IllegalArgumentException.class,
					() -> JwksPublisher.withKeys(List.of()).cacheLifetime(invalid).build());
	}

	@Test
	@SuppressWarnings("NullAway")
	void requiredCollectionsElementsAndHttpMethodsRejectNull() {
		assertThrows(NullPointerException.class, () -> JwksPublisher.withKeys(null));
		assertThrows(NullPointerException.class, () -> JwksPublisher.fromKeys(null));
		List<PublishedJwk> nullElement = new ArrayList<>();
		nullElement.add(null);
		assertThrows(NullPointerException.class, () -> JwksPublisher.fromKeys(nullElement));
		JwksPublisher publisher = publisher();
		assertThrows(NullPointerException.class, () -> publisher.responseFor(null));
		assertThrows(NullPointerException.class, () -> publisher.responseFor(null, null));
		assertEquals(200, publisher.responseFor("GET", null).getStatusCode());
	}

	@Test
	void getAndHeadHaveIdenticalRepresentationHeadersAndHeadHasNoBody() throws Exception {
		JwksPublisher publisher = publisher();
		JwksResponse get = publisher.responseFor("GET");
		JwksResponse head = publisher.responseFor("HEAD");
		assertEquals(200, get.getStatusCode());
		assertEquals(200, head.getStatusCode());
		assertEquals(get.getHeaders(), head.getHeaders());
		assertArrayEquals(new byte[0], head.toHttpBody());
		assertEquals(Optional.of(publisher.toJsonObject()), get.getDocument());
		assertEquals(Optional.empty(), head.getDocument());
		assertEquals(Map.of(
				"Content-Type", List.of("application/jwk-set+json"),
				"Cache-Control", List.of("public, max-age=60, must-revalidate"),
				"Referrer-Policy", List.of("no-referrer"),
				"ETag", List.of(header(get, "ETag")),
				"Content-Length", List.of(Integer.toString(get.toHttpBody().length))), get.getHeaders());
		assertTrue(header(get, "ETag").matches("\"[^\"]+\""), "A strong, quoted entity tag is required.");
		assertEquals("\"" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(get.toHttpBody())) + "\"",
				header(get, "ETag"));
		assertEquals(publisher.toJson(), text(get));
	}

	@Test
	void entityTagTracksTheExactOrderedRepresentationAndIgnoresFreshness() {
		PublishedJwk first = key(Fixture.IDP_SIGNING_RSA_2048, "first", JwsAlgorithm.RS384);
		PublishedJwk second = key(Fixture.SP_SIGNING_RSA_2048, "second", JwsAlgorithm.RS384);
		String original = header(JwksPublisher.fromKeys(List.of(first, second)).responseFor("GET"), "ETag");
		assertEquals(original, header(JwksPublisher.withKeys(List.of(first, second))
				.cacheLifetime(Duration.ofDays(1)).build().responseFor("GET"), "ETag"));
		assertNotEquals(original,
				header(JwksPublisher.fromKeys(List.of(second, first)).responseFor("GET"), "ETag"));
		assertNotEquals(original, header(JwksPublisher.fromKeys(List.of(first)).responseFor("GET"), "ETag"));
		assertNotEquals(header(publisher().responseFor("GET"), "ETag"), header(JwksPublisher.fromKeys(List.of(
				key(Fixture.IDP_SIGNING_RSA_2048, "epic-prod", JwsAlgorithm.RS256))).responseFor("GET"), "ETag"));
	}

	@Test
	void matchingConditionalRequestsUseWeakComparisonAndReturn304WithoutContentLength() {
		JwksPublisher publisher = publisher();
		JwksResponse get = publisher.responseFor("GET");
		String tag = header(get, "ETag");
		for (String method : List.of("GET", "HEAD")) {
			for (String condition : List.of(tag, "W/" + tag, "*", " \t" + tag + "\t ",
					"\"other\", W/" + tag, "W/\"other\", " + tag + ", \"last\"", ", " + tag, tag + ",",
					", , W/" + tag + ", ,", "\"other\", , " + tag)) {
				JwksResponse response = publisher.responseFor(method, condition);
				assertEquals(304, response.getStatusCode(), method + ": " + condition);
				assertArrayEquals(new byte[0], response.toHttpBody());
				assertEquals(Optional.empty(), response.getDocument());
				assertFalse(response.getHeaders().containsKey("Content-Length"));
				assertEquals(tag, header(response, "ETag"));
				assertEquals(header(get, "Cache-Control"), header(response, "Cache-Control"));
			}
		}
	}

	@Test
	void absentUnmatchedOrMalformedConditionsLeaveTheFullResponse() {
		JwksPublisher publisher = publisher();
		String tag = header(publisher.responseFor("GET"), "ETag");
		for (String condition : List.of("", "\"different\"", "W/\"different\"", "unquoted", "\"unterminated",
				"w/" + tag, tag + ", malformed", "*, " + tag, "\"bad\nvalue\"")) {
			JwksResponse response = publisher.responseFor("GET", condition);
			assertEquals(200, response.getStatusCode(), condition);
			assertEquals(publisher.toJson(), text(response));
			assertEquals(Optional.of(publisher.toJsonObject()), response.getDocument());
		}
	}

	@Test
	void oversizedConditionalHeadersAreRejectedAtThe8192CharacterBoundary() {
		JwksPublisher publisher = publisher();
		String maximum = "\"" + "a".repeat(8190) + "\"";
		assertEquals(200, publisher.responseFor("GET", maximum).getStatusCode());
		for (String method : List.of("GET", "HEAD")) {
			JwksResponse response = publisher.responseFor(method, maximum + " ");
			assertEquals(400, response.getStatusCode());
			assertEquals("no-store", header(response, "Cache-Control"));
			assertArrayEquals(new byte[0], response.toHttpBody());
			assertEquals(Optional.empty(), response.getDocument());
			assertFalse(response.getHeaders().containsKey("ETag"));
		}
	}

	@Test
	void otherMethodsReturn405WithoutPublishingARepresentation() {
		JwksPublisher publisher = publisher();
		for (String method : List.of("POST", "PUT", "DELETE", "OPTIONS", "get", "head", "")) {
			JwksResponse response = publisher.responseFor(method, "*");
			assertEquals(405, response.getStatusCode(), method);
			assertEquals("GET, HEAD", header(response, "Allow"));
			assertEquals("no-store", header(response, "Cache-Control"));
			assertArrayEquals(new byte[0], response.toHttpBody());
			assertEquals(Optional.empty(), response.getDocument());
			assertFalse(response.getHeaders().containsKey("ETag"));
		}
	}

	@Test
	void responsesDefendTheirBodyAndBothLevelsOfHeadersFromMutation() {
		JwksPublisher publisher = publisher();
		JwksResponse response = publisher.responseFor("GET");
		byte[] expected = response.toHttpBody();
		byte[] changed = response.toHttpBody();
		changed[0] = '!';
		assertArrayEquals(expected, response.toHttpBody());
		assertArrayEquals(expected, publisher.responseFor("GET").toHttpBody());
		assertThrows(UnsupportedOperationException.class,
				() -> response.getHeaders().put("ETag", List.of("changed")));
		assertThrows(UnsupportedOperationException.class,
				() -> requireNonNull(response.getHeaders().get("ETag")).add("changed"));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> publishedKeysCanVerifyTokensForEverySupportedAsymmetricAlgorithm() {
		return Stream.of(JwsAlgorithm.RS256, JwsAlgorithm.RS384, JwsAlgorithm.RS512,
				JwsAlgorithm.PS256, JwsAlgorithm.PS384, JwsAlgorithm.PS512,
				JwsAlgorithm.ES256, JwsAlgorithm.ES384, JwsAlgorithm.ES512,
				JwsAlgorithm.ED25519, JwsAlgorithm.EDDSA).map(algorithm -> DynamicTest.dynamicTest(
				algorithm.getWireValue(), () -> {
					Fixture fixture = fixture(algorithm);
					PublishedJwk.Builder builder = PublishedJwk.withPublicKey(fixture.getPublicKey())
							.keyId(JwtFixtures.KID).algorithm(algorithm);
					if (algorithm == JwsAlgorithm.RS384)
						builder.certificateChain(List.of(fixture.getCertificate().orElseThrow()));
					JwksPublisher publisher = JwksPublisher.fromKeys(List.of(builder.build()));
					Jwks parsed = JwtFixtures.assertParsedJwks(text(publisher.responseFor("GET")));
					assertEquals(1, parsed.getKeys().size());
					assertEquals(Optional.of(algorithm), parsed.getKeys().get(0).getAlgorithm());
					JwtValidator validator = JwtFixtures.validator(StaticJwksSource.fromJwks(parsed))
							.allowedAlgorithms(Set.of(algorithm)).build();
					JwtFixtures.assertAccepted(validator, JwtFixtures.signed(fixture, TestJws.Algorithm.valueOf(algorithm.name())));
				}));
	}

	private static @NonNull Fixture fixture(@NonNull JwsAlgorithm algorithm) {
		return switch (algorithm) {
			case RS256, RS384, RS512, PS256, PS384, PS512 -> Fixture.IDP_SIGNING_RSA_2048;
			case ES256 -> Fixture.IDP_SIGNING_EC_P256;
			case ES384 -> Fixture.IDP_SIGNING_EC_P384;
			case ES512 -> Fixture.IDP_SIGNING_EC_P521;
			case ED25519, EDDSA -> Fixture.ED25519;
			default -> throw new IllegalArgumentException("An asymmetric test algorithm is required.");
		};
	}

	private static @NonNull X509Certificate certificate(@NonNull String name) throws Exception {
		try (InputStream stream = requireNonNull(JwksPublisherTests.class.getResourceAsStream("/fixtures/jwks/" + name))) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(stream);
		}
	}

	private static @NonNull JwksPublisher publisher() {
		return JwksPublisher.fromKeys(List.of(key(Fixture.IDP_SIGNING_RSA_2048, "epic-prod", JwsAlgorithm.RS384)));
	}

	private static @NonNull PublishedJwk key(@NonNull Fixture fixture, @NonNull String kid,
			@NonNull JwsAlgorithm algorithm) {
		return PublishedJwk.withPublicKey(fixture.getPublicKey()).keyId(kid).algorithm(algorithm).build();
	}

	private static @NonNull String header(@NonNull JwksResponse response, @NonNull String name) {
		return requireNonNull(response.getHeaders().get(name)).get(0);
	}

	private static @NonNull String text(@NonNull JwksResponse response) {
		return new String(response.toHttpBody(), StandardCharsets.UTF_8);
	}
}
