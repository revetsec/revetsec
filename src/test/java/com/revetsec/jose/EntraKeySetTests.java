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

import com.revetsec.internal.Limits;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.jose.JwkSetParser;
import com.revetsec.internal.jose.KeyQuery;
import com.revetsec.internal.jose.KeySelection;
import com.revetsec.internal.jose.KeySelector;
import com.revetsec.internal.jose.ParsedKeySet;
import com.revetsec.internal.jose.TestClaims;
import com.revetsec.internal.jose.VerificationKey;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.TestJsonWebKeys;
import com.revetsec.testing.TestJsonWebKeys.Fixture;
import com.revetsec.testing.TestJws;
import com.revetsec.testing.TestJws.Algorithm;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Microsoft Entra ID's published key sets, captured on 2026-09-27 (plan M2-11): every key loads with nothing skipped,
 * with the JWK {@code issuer} members Microsoft publishes, and the discovery documents' {@code issuer} and
 * {@code jwks_uri} are pinned. Entra's keys carry no {@code alg}, so they fit only while one RSA algorithm is allowed
 * (G8-2, RFC 8725 section 3.1, read 2026-09-28).
 * <p>
 * Synthetic Entra-shaped key sets, test keys with the captured {@code issuer} members, {@code use} {@code sig}, an
 * {@code x5c} and no {@code alg}, then show the key-issuer rule (INV-C6 with M2-11's template) through
 * {@link JwtValidator}: a templated key verifies a token for the configured tenant issuer whose {@code tid}
 * substitutes into the template, and every other combination fails with its stated reason.
 * <p>
 * The captures sit beside {@code SOURCE.txt}, which records how and when they were taken, and {@code MANIFEST.sha256}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class EntraKeySetTests {
	private static final String DIRECTORY = "/com/revetsec/jose/entra/2026-09-27/";
	private static final String TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0";
	private static final String TENANT_ISSUER = "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47"
			+ "/v2.0";
	private static final String CONSUMER_ISSUER = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad"
			+ "/v2.0";
	private static final String TENANT_ID = "72f988bf-86f1-41af-91ab-2d7cd011db47";
	private static final String CONSUMER_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad";
	private static final String APPLICATION = "6e74172b-be56-4843-9ff4-e66a39bb12e3";
	private static final String VERSION_ONE_TENANT_ISSUER = "https://sts.windows.net/" + TENANT_ID + "/";

	/**
	 * Each captured key set, with its key count and the multiset of its keys' {@code issuer} members ({@code null} for
	 * none).
	 */
	private static final List<Capture> KEY_SETS = List.of(
			new Capture("tenant-v2-keys.json", 5, Map.of(TENANT_ISSUER, 5)),
			new Capture("common-v2-keys.json", 8, Map.of(TEMPLATE, 5, CONSUMER_ISSUER, 3)),
			new Capture("orgs-v2-keys.json", 5, Map.of(TEMPLATE, 5)),
			new Capture("common-v1-keys.json", 5, Map.of()),
			new Capture("tenant-v1-keys.json", 5, Map.of()));

	// The captures are exactly the files MANIFEST.sha256 lists, with the listed SHA-256 values, in both directions.
	@Test
	void theCapturesMatchTheirManifestInBothDirections() throws Exception {
		Map<String, String> manifest = new TreeMap<>();
		for (String line : resource("MANIFEST.sha256").lines().toList()) {
			String[] fields = line.split(" {2}", 2);
			Assertions.assertEquals(2, fields.length, line);
			Assertions.assertNull(manifest.put(fields[1], fields[0]), line);
		}

		Set<String> captures;
		try (Stream<Path> files = Files.list(directory())) {
			captures = files.map(path -> path.getFileName().toString()).filter(name -> name.endsWith(".json"))
					.collect(Collectors.toCollection(TreeSet::new));
		}
		Assertions.assertEquals(manifest.keySet(), captures);
		try (Stream<Path> files = Files.list(directory())) {
			Assertions.assertEquals(new TreeSet<>(Set.of("MANIFEST.sha256", "SOURCE.txt")), files.map(path ->
					path.getFileName().toString()).filter(name -> !name.endsWith(".json")).collect(Collectors.toCollection(
					TreeSet::new)), "no headers or other files beside the captures");
		}

		for (Map.Entry<String, String> entry : manifest.entrySet())
			Assertions.assertEquals(entry.getValue(), HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
					.digest(bytes(entry.getKey()))), entry.getKey());

		Assertions.assertTrue(resource("SOURCE.txt").contains("read-only GET"));
	}

	// M2-11: all five captured key sets load with zero skipped keys (so rule 12's x5c check passes on every key), and
	// every key is an RSA-2048 signing key with e = 65537, a kid and no alg, with the issuer members of the table.
	@TestFactory
	Stream<DynamicTest> everyCapturedKeySetLoadsWithNoKeySkipped() {
		return KEY_SETS.stream().map(capture -> DynamicTest.dynamicTest(capture.file(), () -> {
			ParsedKeySet parsed = JwkSetParser.parse(bytes(capture.file()),
					Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue(), Limits.JWKS_KEY_COUNT.getDefaultIntValue());
			JsonWebKeySet keySet = JsonWebKeySet.fromJson(resource(capture.file()));

			Assertions.assertEquals(List.of(), parsed.skips());
			Assertions.assertEquals(capture.keyCount(), parsed.keys().size());
			Assertions.assertEquals(capture.keyCount(), keySet.getKeys().size());
			Assertions.assertEquals(capture.keyCount(), keySet.getKeys().stream().map(JsonWebKey::getThumbprintSha256)
					.distinct().count(), "distinct keys");

			Map<String, Integer> issuers = new TreeMap<>();
			for (VerificationKey key : keySet.verificationKeys()) {
				Assertions.assertEquals("RSA", key.keyType());
				Assertions.assertNull(key.algorithm());
				Assertions.assertEquals("sig", key.use());
				Assertions.assertNotNull(key.keyId());
				RSAPublicKey rsa = (RSAPublicKey) key.publicKey();
				Assertions.assertEquals(2048, rsa.getModulus().bitLength());
				Assertions.assertEquals(BigInteger.valueOf(65_537), rsa.getPublicExponent());
				String issuer = key.issuer();
				if (issuer != null)
					issuers.merge(issuer, 1, Integer::sum);
			}
			Assertions.assertEquals(new TreeMap<>(capture.issuers()), issuers);
		}));
	}

	// M2-11: the common discovery document's issuer is the template itself, and each document names its own key set.
	@Test
	void theDiscoveryDocumentsPinTheIssuerAndKeySetUri() throws Exception {
		JsonObject common = json("common-v2-openid.json");
		JsonObject tenant = json("tenant-v2-openid.json");

		Assertions.assertEquals(TEMPLATE, common.findString("issuer").orElseThrow());
		Assertions.assertEquals("https://login.microsoftonline.com/common/discovery/v2.0/keys",
				common.findString("jwks_uri").orElseThrow());
		Assertions.assertEquals(TENANT_ISSUER, tenant.findString("issuer").orElseThrow());
		Assertions.assertEquals("https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/discovery/v2.0"
				+ "/keys",
				tenant.findString("jwks_uri").orElseThrow());
	}

	// G8-2 and M2-11: Entra's keys carry no alg, so each fits RS256 under the default {RS256}, and none fits once a
	// second RSA algorithm is allowed; a token with the key's kid then gets KEY_ALGORITHM_MISMATCH, never a refresh.
	@TestFactory
	Stream<DynamicTest> entraKeysFitOnlyWhileOneRsaAlgorithmIsAllowed() {
		return KEY_SETS.stream().map(capture -> DynamicTest.dynamicTest(capture.file(), () -> {
			List<VerificationKey> keys = JsonWebKeySet.fromJson(resource(capture.file())).verificationKeys();

			for (VerificationKey key : keys) {
				String kid = key.keyId();
				KeySelection alone = KeySelector.select(keys, new KeyQuery(JwsAlgorithm.RS256, kid,
						Set.of(JwsAlgorithm.RS256)));
				Assertions.assertSame(key, alone.findKey().orElseThrow());

				for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.RS256, JwsAlgorithm.PS256))
					Assertions.assertEquals(KeySelection.Kind.ALGORITHM_MISMATCH, KeySelector.select(keys, new KeyQuery(
							algorithm, kid, Set.of(JwsAlgorithm.RS256, JwsAlgorithm.PS256))).getKind());
			}
		}));
	}

	// M2-11 positives: in a common-v2-shaped set, the templated key verifies a token for the configured tenant issuer
	// whose tid substitutes into the template; the exact-tenant key verifies its tenant's token; and the consumer
	// tenant's key verifies a consumer-tenant token for a validator configured with the consumer issuer.
	@Test
	void entraShapedKeysVerifyTokensForTheirIssuer() {
		JwtFixtures.assertAccepted(validator(TENANT_ISSUER, Set.of(JwsAlgorithm.RS256)), token("templated",
				Fixture.IDP_SIGNING_RSA_2048, TENANT_ISSUER, "\"" + TENANT_ID + "\""));
		JwtFixtures.assertAccepted(validator(TENANT_ISSUER, Set.of(JwsAlgorithm.RS256)), token("tenant",
				Fixture.IDP_SIGNING_RSA_3072, TENANT_ISSUER, "\"" + TENANT_ID + "\""));
		JwtFixtures.assertAccepted(validator(TENANT_ISSUER, Set.of(JwsAlgorithm.RS256)), token("tenant",
				Fixture.IDP_SIGNING_RSA_3072, TENANT_ISSUER, null));
		JwtFixtures.assertAccepted(validator(CONSUMER_ISSUER, Set.of(JwsAlgorithm.RS256)), token("consumer",
				Fixture.SP_SIGNING_RSA_2048, CONSUMER_ISSUER, "\"" + CONSUMER_TENANT_ID + "\""));
		JwtFixtures.assertAccepted(validator(CONSUMER_ISSUER, Set.of(JwsAlgorithm.RS256)), token("templated",
				Fixture.IDP_SIGNING_RSA_2048, CONSUMER_ISSUER, "\"" + CONSUMER_TENANT_ID + "\""));
	}

	// M2-11 negatives on the templated key: a tid that is absent, not a string, uppercase, braced or not a GUID, and
	// another tenant's tid while iss is the configured issuer, are KEY_ISSUER_MISMATCH, after the signature verified.
	@TestFactory
	Stream<DynamicTest> theTemplatedKeyNeedsTheTokensOwnLowercaseTenantId() {
		Map<String, @Nullable String> tids = new LinkedHashMap<>();
		tids.put("tid absent", null);
		tids.put("tid a number", "72988");
		tids.put("tid null", "null");
		tids.put("tid uppercase", "\"" + TENANT_ID.toUpperCase(Locale.ROOT) + "\"");
		tids.put("tid braced", "\"{" + TENANT_ID + "}\"");
		tids.put("tid not a GUID", "\"contoso.onmicrosoft.com\"");
		tids.put("another tenant's tid", "\"" + CONSUMER_TENANT_ID + "\"");

		return tids.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				JwtFixtures.assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, validator(TENANT_ISSUER,
						Set.of(JwsAlgorithm.RS256)), token("templated", Fixture.IDP_SIGNING_RSA_2048, TENANT_ISSUER,
						entry.getValue()))));
	}

	// M2-11: a configured issuer whose tenant segment is not a lowercase GUID (a domain name, an uppercase GUID, or
	// 36 hexadecimal digits without the GUID's dashes) never matches the template, even with a tid that substitutes to
	// that issuer exactly.
	@Test
	void theTemplateNeedsAGuidTenantEvenWhenTheIssuerMatches() {
		for (String tid : List.of("contoso.onmicrosoft.com", TENANT_ID.toUpperCase(Locale.ROOT),
				TENANT_ID.replace('-', '0'))) {
			String issuer = "https://login.microsoftonline.com/" + tid + "/v2.0";
			JwtFixtures.assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, validator(issuer,
					Set.of(JwsAlgorithm.RS256)), token("templated", Fixture.IDP_SIGNING_RSA_2048, issuer, "\"" + tid + "\""));
		}
	}

	// M2-11: an iss other than the configured issuer is ISSUER_MISMATCH first, even when the tid substitutes into the
	// template to give that iss; and a consumer-tenant key never verifies an enterprise tenant's token.
	@Test
	void theTemplateNeverWidensTheConfiguredIssuer() {
		JwtFixtures.assertRejected(JoseException.Reason.ISSUER_MISMATCH, validator(TENANT_ISSUER,
				Set.of(JwsAlgorithm.RS256)), token("templated", Fixture.IDP_SIGNING_RSA_2048, CONSUMER_ISSUER,
				"\"" + CONSUMER_TENANT_ID + "\""));
		JwtFixtures.assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, validator(TENANT_ISSUER,
				Set.of(JwsAlgorithm.RS256)), token("consumer", Fixture.SP_SIGNING_RSA_2048, TENANT_ISSUER,
				"\"" + TENANT_ID + "\""));
		JwtFixtures.assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, validator(CONSUMER_ISSUER,
				Set.of(JwsAlgorithm.RS256)), token("tenant", Fixture.IDP_SIGNING_RSA_3072, CONSUMER_ISSUER,
				"\"" + CONSUMER_TENANT_ID + "\""));
	}

	// M2-11: only the exact template bytes are a template. A key whose issuer member is the template on
	// login.microsoftonline.us, spelled {TENANTID}, with the placeholder doubled, or with a trailing slash, is compared
	// literally, so it is KEY_ISSUER_MISMATCH.
	@TestFactory
	Stream<DynamicTest> lookAlikeTemplatesAreLiteral() {
		return Stream.of("https://login.microsoftonline.us/{tenantid}/v2.0",
				"https://login.microsoftonline.com/{TENANTID}/v2.0",
				"https://login.microsoftonline.com/{tenantid}{tenantid}/v2.0",
				"https://login.microsoftonline.com/{tenantid}/v2.0/").map(template -> DynamicTest.dynamicTest(template, () -> {
			String keySet = JwtFixtures.keySet(entraKey(Fixture.IDP_SIGNING_RSA_2048, "templated", template));
			JwtValidator validator = JwtValidator.withIssuer(TENANT_ISSUER).jsonWebKeySource(
					StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(keySet))).expectedAudiences(
					Set.of(APPLICATION)).clock(JwtFixtures.clock()).build();
			JwtFixtures.assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, validator, token("templated",
					Fixture.IDP_SIGNING_RSA_2048, TENANT_ISSUER, "\"" + TENANT_ID + "\""));
		}));
	}

	// M2-11: the template is never a literal issuer. A validator configured with the template itself, as the common
	// discovery document publishes it, never lets the templated key verify a token whose iss is the template, whatever
	// its tid.
	@TestFactory
	Stream<DynamicTest> theTemplateItselfIsNeverALiteralIssuer() {
		Map<String, @Nullable String> tids = new LinkedHashMap<>();
		tids.put("tid absent", null);
		tids.put("tid not a GUID", "\"NOT-A-GUID\"");
		tids.put("tid a lowercase GUID", "\"" + TENANT_ID + "\"");
		tids.put("tid the placeholder", "\"{tenantid}\"");

		return tids.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () ->
				JwtFixtures.assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, validator(TEMPLATE,
						Set.of(JwsAlgorithm.RS256)), token("templated", Fixture.IDP_SIGNING_RSA_2048, TEMPLATE,
						entry.getValue()))));
	}

	// Open question 16: a v1.0 token (iss https://sts.windows.net/<tid>/, ver 1.0) verifies with the tenant's v1.0 key
	// set, whose keys carry no issuer member. The v2.0 key sets hold the same keys (the captures share every kid), but
	// with v2.0 issuer members, the tenant's exact issuer or the template, and neither ever equals a v1.0 iss. So such a
	// token finds its key, passes its signature check, and then fails with KEY_ISSUER_MISMATCH: each token version
	// needs its own key set, and an application that accepts both needs one validator for each.
	@TestFactory
	Stream<DynamicTest> aVersionOneTokenVerifiesOnlyWithTheVersionOneKeySet() throws Exception {
		Assertions.assertEquals(keyIds("tenant-v1-keys.json"), keyIds("tenant-v2-keys.json"), "the same keys");
		Map<String, @Nullable String> keyIssuers = new LinkedHashMap<>();
		keyIssuers.put("a v1.0 key, with no issuer member", null);
		keyIssuers.put("the tenant's v2.0 key", TENANT_ISSUER);
		keyIssuers.put("a common or organizations v2.0 key", TEMPLATE);

		return keyIssuers.entrySet().stream().map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			String keySet = JwtFixtures.keySet(TestJsonWebKeys.withFixture(Fixture.IDP_SIGNING_RSA_2048).kid("k")
					.use("sig").x5c(List.of(Fixture.IDP_SIGNING_RSA_2048.getCertificate().orElseThrow()))
					.issuer(entry.getValue()));
			JwtValidator validator = JwtValidator.withIssuer(VERSION_ONE_TENANT_ISSUER).jsonWebKeySource(
					StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(keySet))).expectedAudiences(
					Set.of(APPLICATION)).clock(JwtFixtures.clock()).build();
			String token = TestJws.withAlgorithm(Algorithm.RS256).kid("k").typ("JWT").payload(TestClaims.empty()
					.put("aud", APPLICATION).put("iss", VERSION_ONE_TENANT_ISSUER).put("iat", JwtFixtures.NOW.getEpochSecond())
					.put("exp", JwtFixtures.NOW.getEpochSecond() + 3_600).put("ver", "1.0").put("tid", TENANT_ID).toJson())
					.sign(Fixture.IDP_SIGNING_RSA_2048.getPrivateKey());

			if (entry.getValue() == null)
				JwtFixtures.assertAccepted(validator, token);
			else
				JwtFixtures.assertRejected(JoseException.Reason.KEY_ISSUER_MISMATCH, validator, token);
		}));
	}

	// G8-2 and M2-11: Entra's keys carry no alg, so under {RS256, PS256} a token naming any of them is
	// KEY_ALGORITHM_MISMATCH, whether it is signed RS256 or PS256; a key-selection outcome that never refreshes.
	@Test
	void widenedRsaAlgorithmsMakeEntraKeysUnusable() {
		JwtValidator widened = validator(TENANT_ISSUER, Set.of(JwsAlgorithm.RS256, JwsAlgorithm.PS256));
		for (Map.Entry<String, Fixture> key : Map.of("templated", Fixture.IDP_SIGNING_RSA_2048, "tenant",
				Fixture.IDP_SIGNING_RSA_3072).entrySet())
			for (Algorithm algorithm : List.of(Algorithm.RS256, Algorithm.PS256))
				JwtFixtures.assertRejected(JoseException.Reason.KEY_ALGORITHM_MISMATCH, widened, TestJws.withAlgorithm(
						algorithm).kid(key.getKey()).payload(claims(TENANT_ISSUER, "\"" + TENANT_ID + "\"")).sign(
						key.getValue().getPrivateKey()));
	}

	/**
	 * A validator for {@code issuer} over a key set shaped like Entra's common v2 set: a templated key, the enterprise
	 * tenant's key and the consumer tenant's key, all RSA with {@code use} {@code sig}, an {@code x5c} and no
	 * {@code alg}.
	 */
	private static JwtValidator validator(String issuer,
																				Set<JwsAlgorithm> algorithms) {
		String keySet = JwtFixtures.keySet(entraKey(Fixture.IDP_SIGNING_RSA_2048, "templated", TEMPLATE),
				entraKey(Fixture.IDP_SIGNING_RSA_3072, "tenant", TENANT_ISSUER),
				entraKey(Fixture.SP_SIGNING_RSA_2048, "consumer", CONSUMER_ISSUER));
		Assertions.assertEquals(3, JsonWebKeySet.fromJson(keySet).getKeys().size());
		return JwtValidator.withIssuer(issuer).jsonWebKeySource(StaticJsonWebKeySource.fromJsonWebKeySet(
				JsonWebKeySet.fromJson(keySet))).expectedAudiences(Set.of(APPLICATION)).allowedAlgorithms(algorithms)
				.clock(JwtFixtures.clock()).build();
	}

	private static TestJsonWebKeys.Builder entraKey(Fixture fixture,
																									String kid,
																									String issuer) {
		return TestJsonWebKeys.withFixture(fixture).kid(kid).use("sig").x5c(List.of(fixture.getCertificate()
				.orElseThrow())).issuer(issuer);
	}

	private static String token(String kid,
															Fixture fixture,
															String issuer,
															@Nullable String tid) {
		return TestJws.withAlgorithm(Algorithm.RS256).kid(kid).typ("JWT").payload(claims(issuer, tid)).sign(
				fixture.getPrivateKey());
	}

	private static String claims(String issuer,
															 @Nullable String tid) {
		TestClaims claims = TestClaims.empty().put("aud", APPLICATION).put("iss", issuer).put("iat",
				JwtFixtures.NOW.getEpochSecond()).put("exp", JwtFixtures.NOW.getEpochSecond() + 3_600).put("ver", "2.0");
		if (tid != null)
			claims.raw("tid", tid);
		return claims.toJson();
	}

	private static Set<String> keyIds(String capture) throws IOException {
		return JsonWebKeySet.fromJson(resource(capture)).getKeys().stream().map(key -> key.getKeyId().orElseThrow())
				.collect(Collectors.toCollection(TreeSet::new));
	}

	private static Path directory() throws URISyntaxException {
		URL url = EntraKeySetTests.class.getResource(DIRECTORY);
		Assertions.assertNotNull(url, DIRECTORY);
		return Path.of(url.toURI());
	}

	private static byte[] bytes(String name) throws IOException {
		try (@Nullable InputStream stream = EntraKeySetTests.class.getResourceAsStream(DIRECTORY + name)) {
			if (stream == null)
				throw new IllegalStateException("Missing capture " + name);
			return stream.readAllBytes();
		}
	}

	private static String resource(String name) throws IOException {
		return new String(bytes(name), StandardCharsets.UTF_8);
	}

	private static JsonObject json(String name) throws Exception {
		return (JsonObject) JsonCodec.parse(bytes(name), JsonLimits.protocolDocument(
				Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue()));
	}

	private record Capture(String file, int keyCount, Map<String, Integer> issuers) {
	}
}
