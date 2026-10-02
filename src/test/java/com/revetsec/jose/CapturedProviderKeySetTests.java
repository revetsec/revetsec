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

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.Limits;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.jose.JwkSetParser;
import com.revetsec.internal.jose.ParsedKeySet;
import com.revetsec.internal.jose.VerificationKey;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.RawTlsServer;
import com.revetsec.testing.RecordingObserver;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestTls;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

/**
 * Key sets, discovery documents and signed tokens captured on 2026-09-28 from the local Keycloak 26.7.4 and
 * node-oidc-provider 9.12.2 test containers (plan A-5), replayed offline through {@link JsonWebKeySet},
 * {@link StaticJsonWebKeySource} and {@link JwtValidator} with a fixed clock, and through a
 * {@link RemoteJsonWebKeySource} that fetches each key set from a loopback server sending the provider's captured
 * {@code Content-Type} and {@code Cache-Control}.
 * <p>
 * Each provider was captured in its committed interop configuration ({@code default-*} files) and with one signing
 * key and one test client per algorithm it offers ({@code algorithms-*} files). Every token verifies at its capture
 * time, fails once the clock reaches {@code exp} plus the skew, and fails with another key set, a changed byte or
 * another issuer; relabelled to the other RSA padding, an RSA token no longer fits its key. The key sets also answer
 * what real producers publish: both providers encode every RSA modulus and exponent minimally and every EC coordinate
 * at its fixed length, so M2-7 skips none of their RSA, EC or Ed25519 keys; Keycloak's default key set carries an
 * RSA-OAEP encryption key and node-oidc-provider's may carry an ML-DSA-44 signing key, and both are skipped with their
 * reason; and both put {@code alg} on every RSA key, so their keys stay usable when several RSA algorithms are allowed
 * (G8-2), unlike Microsoft Entra ID's.
 * <p>
 * The captures sit beside {@code SOURCE.txt}, which records how and when they were taken, and {@code MANIFEST.sha256}.
 * The keys that signed them were generated inside the containers and destroyed with them.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class CapturedProviderKeySetTests {
	private static final Capture KEYCLOAK = new Capture("keycloak", "/fixtures/keycloak/2026-09-28/",
			Instant.parse("2026-09-28T03:34:14Z"), Instant.parse("2026-09-28T03:34:15Z"), Duration.ofMinutes(5),
			"Content-Type: application/json\r\nCache-Control: no-cache\r\n", Duration.ofMinutes(1));
	private static final Capture NODE_OIDC_PROVIDER = new Capture("node-oidc-provider",
			"/fixtures/node-oidc-provider/2026-09-28/", Instant.parse("2026-09-28T03:33:53Z"),
			Instant.parse("2026-09-28T03:33:55Z"), Duration.ofHours(1),
			"Content-Type: application/jwk-set+json; charset=utf-8\r\n", Duration.ofMinutes(10));
	private static final List<Capture> CAPTURES = List.of(KEYCLOAK, NODE_OIDC_PROVIDER);

	private static final String KEYCLOAK_DEFAULT_ISSUER = "https://localhost:8443/realms/revetsec-test";
	private static final String KEYCLOAK_ALGORITHMS_ISSUER = "https://localhost:8443/realms/revetsec-test-algorithms";
	private static final String NODE_OIDC_PROVIDER_ISSUER = "https://localhost:3000";
	private static final String TEST_CLIENT = "revetsec-test-client";
	private static final String TEST_USER = "test-user";
	private static final String ML_DSA_TOKEN = "algorithms-ml-dsa-44-id-token.jwt";

	/**
	 * The only names a capture may have: a scenario's discovery document and key set, and its ID and access tokens.
	 * Refresh tokens, cookies and response headers were never kept.
	 */
	private static final Pattern CAPTURE_NAME = Pattern.compile(
			"(default|algorithms)-(openid-configuration\\.json|jwks\\.json|[a-z0-9-]+-(id|access)-token\\.jwt)");
	private static final Pattern SUBJECT_UUID = Pattern.compile(
			"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
	private static final List<String> PRIVATE_MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv");
	private static final Set<JwsAlgorithm> RSA_ALGORITHMS = Set.of(JwsAlgorithm.RS256, JwsAlgorithm.RS384,
			JwsAlgorithm.RS512, JwsAlgorithm.PS256, JwsAlgorithm.PS384, JwsAlgorithm.PS512);

	private static final Set<String> KEYCLOAK_ID_TOKEN_CLAIMS = Set.of("iss", "sub", "aud", "exp", "iat", "auth_time",
			"jti", "typ", "azp", "nonce", "sid", "at_hash", "acr", "email_verified", "name", "preferred_username",
			"given_name", "family_name", "email");
	private static final Set<String> KEYCLOAK_ACCESS_TOKEN_CLAIMS = Set.of("iss", "sub", "exp", "iat", "auth_time", "jti",
			"typ", "azp", "sid", "acr", "scope", "email_verified", "name", "preferred_username", "given_name",
			"family_name", "email");
	private static final Set<String> NODE_OIDC_PROVIDER_ID_TOKEN_CLAIMS = Set.of("iss", "sub", "aud", "exp", "iat",
			"nonce");

	/**
	 * Each captured key set: its usable keys in document order (key type, modulus bits or curve, and {@code alg}), its
	 * skipped keys, and how many of its elements carry an {@code x5c} chain.
	 */
	private static final List<KeySetCase> KEY_SETS = List.of(
			new KeySetCase(KEYCLOAK, "default-jwks.json", List.of("RSA 2048 RS256"),
					List.of(new ParsedKeySet.Skip(0, JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY)), 2),
			new KeySetCase(KEYCLOAK, "algorithms-jwks.json", List.of("OKP Ed25519 EdDSA", "RSA 4096 RS512",
					"EC P-256 ES256", "RSA 2048 RS256", "RSA 3072 PS384", "RSA 2048 PS256", "EC P-521 ES512", "RSA 4096 PS512",
					"EC P-384 ES384", "RSA 3072 RS384"), List.of(), 6),
			new KeySetCase(NODE_OIDC_PROVIDER, "default-jwks.json", List.of("RSA 2048 RS256", "EC P-256 ES256"), List.of(),
					0),
			new KeySetCase(NODE_OIDC_PROVIDER, "algorithms-jwks.json", List.of("RSA 2048 RS256", "RSA 3072 RS384",
					"RSA 4096 RS512", "RSA 2048 PS256", "RSA 3072 PS384", "RSA 4096 PS512", "EC P-256 ES256", "EC P-384 ES384",
					"EC P-521 ES512", "OKP Ed25519 (no alg)"),
					List.of(new ParsedKeySet.Skip(10, JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE)), 0));

	/**
	 * Each captured discovery document: its {@code issuer}, its {@code jwks_uri} and the ID token signing algorithms it
	 * advertises.
	 */
	private static final List<DiscoveryCase> DISCOVERY_DOCUMENTS = List.of(
			new DiscoveryCase(KEYCLOAK, "default-openid-configuration.json", KEYCLOAK_DEFAULT_ISSUER,
					KEYCLOAK_DEFAULT_ISSUER + "/protocol/openid-connect/certs", keycloakAdvertisedAlgorithms()),
			new DiscoveryCase(KEYCLOAK, "algorithms-openid-configuration.json", KEYCLOAK_ALGORITHMS_ISSUER,
					KEYCLOAK_ALGORITHMS_ISSUER + "/protocol/openid-connect/certs", keycloakAdvertisedAlgorithms()),
			new DiscoveryCase(NODE_OIDC_PROVIDER, "default-openid-configuration.json", NODE_OIDC_PROVIDER_ISSUER,
					NODE_OIDC_PROVIDER_ISSUER + "/jwks", Set.of("RS256", "ES256")),
			new DiscoveryCase(NODE_OIDC_PROVIDER, "algorithms-openid-configuration.json", NODE_OIDC_PROVIDER_ISSUER,
					NODE_OIDC_PROVIDER_ISSUER + "/jwks", Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
					"ES384", "ES512", "Ed25519", "EdDSA", "ML-DSA-44")));

	/**
	 * Every captured token Revetsec can verify. The ML-DSA-44 token is not among them.
	 */
	private static final List<TokenCase> TOKENS = tokens();

	// The captures are exactly the files MANIFEST.sha256 lists, with the listed SHA-256 values, in both directions;
	// each is a discovery document, a key set, or an ID or access token; and every one is replayed by a test below.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theCapturesMatchTheirManifestsAndAreEachReplayed() {
		return CAPTURES.stream().map(capture -> DynamicTest.dynamicTest(capture.name(), () -> {
			Map<String, String> manifest = new TreeMap<>();
			for (String line : text(capture, "MANIFEST.sha256").lines().toList()) {
				String[] fields = line.split(" {2}", 2);
				Assertions.assertEquals(2, fields.length, line);
				Assertions.assertNull(manifest.put(fields[1], fields[0]), line);
			}

			Set<String> files;
			try (Stream<Path> listing = Files.list(directory(capture))) {
				files = listing.map(path -> path.getFileName().toString()).collect(Collectors.toCollection(TreeSet::new));
			}
			Assertions.assertTrue(files.remove("MANIFEST.sha256"));
			Assertions.assertTrue(files.remove("SOURCE.txt"));
			Assertions.assertEquals(manifest.keySet(), files, "no headers, logs or other files beside the captures");

			for (Map.Entry<String, String> entry : manifest.entrySet()) {
				Assertions.assertTrue(CAPTURE_NAME.matcher(entry.getKey()).matches(), entry.getKey());
				Assertions.assertEquals(entry.getValue(), HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
						.digest(bytes(capture, entry.getKey()))), entry.getKey());
			}

			Set<String> replayed = new TreeSet<>();
			KEY_SETS.stream().filter(keySet -> keySet.capture().equals(capture)).forEach(keySet ->
					replayed.add(keySet.file()));
			DISCOVERY_DOCUMENTS.stream().filter(document -> document.capture().equals(capture)).forEach(document ->
					replayed.add(document.file()));
			TOKENS.stream().filter(token -> token.capture().equals(capture)).forEach(token -> replayed.add(token.file()));
			if (capture.equals(NODE_OIDC_PROVIDER))
				replayed.add(ML_DSA_TOKEN);
			Assertions.assertEquals(manifest.keySet(), replayed);

			String source = text(capture, "SOURCE.txt");
			Assertions.assertTrue(source.contains("--network none"), "SOURCE.txt records the isolated capture");
			Assertions.assertTrue(source.contains("--pull never"), "SOURCE.txt records the local image");
		}));
	}

	// M2-7: each captured key set loads with exactly its pinned usable keys, in document order, and its pinned skips.
	// The public JsonWebKeySet holds the same keys, each a signing key (use sig) with a kid, and a static source takes
	// the set.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyCapturedKeySetLoadsWithItsPinnedKeysAndSkips() {
		return KEY_SETS.stream().map(keySet -> DynamicTest.dynamicTest(keySet.toString(), () -> {
			ParsedKeySet parsed = JwkSetParser.parse(bytes(keySet.capture(), keySet.file()),
					Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue(), Limits.JWKS_KEY_COUNT.getDefaultIntValue());
			Assertions.assertEquals(keySet.skips(), parsed.skips());
			Assertions.assertEquals(keySet.keys(), parsed.keys().stream().map(CapturedProviderKeySetTests::describe)
					.toList());

			JsonWebKeySet jsonWebKeySet = JsonWebKeySet.fromJson(text(keySet.capture(), keySet.file()));
			Assertions.assertEquals(parsed.keys().stream().map(VerificationKey::thumbprintSha256).toList(),
					jsonWebKeySet.getKeys().stream().map(JsonWebKey::getThumbprintSha256).toList());
			Assertions.assertEquals(jsonWebKeySet.getKeys().size(), jsonWebKeySet.getKeys().stream()
					.map(JsonWebKey::getThumbprintSha256).distinct().count(), "distinct keys");
			for (JsonWebKey key : jsonWebKeySet.getKeys()) {
				Assertions.assertEquals(Optional.of("sig"), key.getUse());
				Assertions.assertTrue(key.getKeyId().isPresent());
			}
			Assertions.assertSame(jsonWebKeySet, StaticJsonWebKeySource.fromJsonWebKeySet(jsonWebKeySet)
					.getJsonWebKeySet());
		}));
	}

	// M2-7 and plan open question 11, read from the raw JSON, independently of the parser: no published key carries a
	// private member; every RSA modulus and exponent is a minimal Base64urlUInt (no leading zero octet, RFC 7518
	// section 6.3.1) with e = 65537; every EC coordinate has its curve's full length (RFC 7518 section 6.2.1.2); every
	// Ed25519 x is 32 octets (RFC 8037 section 2). Keycloak also sends an x5c chain with each RSA key; none of its
	// signing keys was skipped, so check 12 found each chain's first certificate to hold the same key.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> publishedKeysUseMinimalOrFixedLengthEncodingsAndNoPrivateMembers() {
		return KEY_SETS.stream().map(keySet -> DynamicTest.dynamicTest(keySet.toString(), () -> {
			int certificates = 0;
			for (JsonObject key : rawKeys(keySet)) {
				for (String member : PRIVATE_MEMBERS)
					Assertions.assertEquals(Optional.empty(), key.find(member), member);

				String keyType = key.findString("kty").orElseThrow();
				switch (keyType) {
					case "RSA" -> {
						byte[] modulus = decoded(key, "n");
						byte[] exponent = decoded(key, "e");
						Assertions.assertNotEquals(0, modulus[0], "minimal n");
						Assertions.assertNotEquals(0, exponent[0], "minimal e");
						Assertions.assertEquals(BigInteger.valueOf(65_537), new BigInteger(1, exponent));
					}
					case "EC" -> {
						int length = switch (key.findString("crv").orElseThrow()) {
							case "P-256" -> 32;
							case "P-384" -> 48;
							case "P-521" -> 66;
							default -> throw new AssertionError("unexpected curve");
						};
						Assertions.assertEquals(length, decoded(key, "x").length);
						Assertions.assertEquals(length, decoded(key, "y").length);
					}
					case "OKP" -> {
						Assertions.assertEquals(Optional.of("Ed25519"), key.findString("crv"));
						Assertions.assertEquals(32, decoded(key, "x").length);
					}
					default -> Assertions.assertEquals("AKP", keyType);
				}

				if (key.find("x5c").isPresent())
					certificates++;
			}
			Assertions.assertEquals(keySet.certificates(), certificates);
		}));
	}

	// Plan A-5: Keycloak's default key set carries an RSA-OAEP encryption key (use enc) beside its RS256 signing key,
	// and M2-7 check 4 skips it as NOT_A_VERIFICATION_KEY, never failing the set; node-oidc-provider's default key set
	// carries signing keys only.
	@Test
	void keycloaksDefaultKeySetCarriesAnEncryptionKeyThatIsSkipped() throws Exception {
		List<JsonObject> keycloak = rawKeys(keySet(KEYCLOAK, "default-jwks.json"));
		Assertions.assertEquals(Optional.of("enc"), keycloak.get(0).findString("use"));
		Assertions.assertEquals(Optional.of("RSA-OAEP"), keycloak.get(0).findString("alg"));
		Assertions.assertEquals(List.of(new ParsedKeySet.Skip(0, JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY)),
				JwkSetParser.parse(bytes(KEYCLOAK, "default-jwks.json"), Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue(),
						Limits.JWKS_KEY_COUNT.getDefaultIntValue()).skips());
		Assertions.assertEquals(1, JsonWebKeySet.fromJson(text(KEYCLOAK, "default-jwks.json")).getKeys().size());

		for (JsonObject key : rawKeys(keySet(NODE_OIDC_PROVIDER, "default-jwks.json")))
			Assertions.assertEquals(Optional.of("sig"), key.findString("use"));
	}

	// Each captured token verifies at its capture time against its own key set with its own algorithm allowed: the
	// algorithm, kid and typ are the producer's, the compact serialization is the received string, and iss, aud, iat
	// and exp are as captured (iat inside the capture run; Keycloak's tokens live 5 minutes, node-oidc-provider's 1
	// hour; neither sends nbf).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyCapturedTokenVerifiesAtItsCaptureTime() {
		return TOKENS.stream().map(token -> DynamicTest.dynamicTest(token.toString(), () -> {
			String compact = text(token.capture(), token.file());
			StaticJsonWebKeySource source = source(token.capture(), token.keySet());
			Jwt jwt = JwtFixtures.assertAccepted(validator(token, source, token.capture().finishedAt()).allowedAlgorithms(
					Set.of(token.algorithm())).build(), compact);

			Assertions.assertEquals(token.algorithm(), jwt.getAlgorithm());
			Assertions.assertEquals(Optional.ofNullable(token.type()), jwt.getType());
			Assertions.assertEquals(compact, jwt.toCompactSerialization());
			String kid = jwt.getKeyId().orElseThrow();
			Assertions.assertEquals(1, source.getJsonWebKeySet().getKeys().stream().filter(key ->
					key.getKeyId().equals(Optional.of(kid))).count(), "one key with the token's kid");

			JwtClaims claims = jwt.getClaims();
			Assertions.assertEquals(Optional.of(token.issuer()), claims.getIssuer());
			String audience = token.audience();
			Assertions.assertEquals(audience == null ? List.of() : List.of(audience), claims.getAudiences());
			Instant issuedAt = claims.getIssuedAt().orElseThrow();
			Assertions.assertFalse(issuedAt.isBefore(token.capture().startedAt()), "issued during the capture");
			Assertions.assertFalse(issuedAt.isAfter(token.capture().finishedAt()), "issued during the capture");
			Assertions.assertEquals(token.capture().lifetime(), Duration.between(issuedAt, claims.getExpiresAt()
					.orElseThrow()));
			Assertions.assertEquals(Optional.empty(), claims.getNotBefore());
		}));
	}

	// Time checks at each captured token's own exp (plan "JOSE semantics" step 12): at the default 60 s skew the token
	// is accepted at exp + 59 s and EXPIRED from exp + 60 s; with no skew it is accepted at exp - 1 s and EXPIRED at exp.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyCapturedTokenExpiresOnceTheClockReachesExpPlusTheSkew() {
		return TOKENS.stream().map(token -> DynamicTest.dynamicTest(token.toString(), () -> {
			String compact = text(token.capture(), token.file());
			StaticJsonWebKeySource source = source(token.capture(), token.keySet());
			Instant expiresAt = claimsAtCapture(token, source).getExpiresAt().orElseThrow();

			JwtFixtures.assertAccepted(atTime(token, source, expiresAt.plusSeconds(59), null), compact);
			JwtFixtures.assertRejected(JoseException.Reason.EXPIRED, atTime(token, source, expiresAt.plusSeconds(60),
					null), compact);
			JwtFixtures.assertAccepted(atTime(token, source, expiresAt.minusSeconds(1), Duration.ZERO), compact);
			JwtFixtures.assertRejected(JoseException.Reason.EXPIRED, atTime(token, source, expiresAt, Duration.ZERO),
					compact);
		}));
	}

	// Time checks at each captured token's own iat (plan "JOSE semantics" step 12): at the default 60 s skew a clock
	// 60 s behind the producer's still accepts the token, and one 61 s behind gives ISSUED_IN_FUTURE.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyCapturedTokenIsIssuedInTheFutureForAClockMoreThanTheSkewBehind() {
		return TOKENS.stream().map(token -> DynamicTest.dynamicTest(token.toString(), () -> {
			String compact = text(token.capture(), token.file());
			StaticJsonWebKeySource source = source(token.capture(), token.keySet());
			Instant issuedAt = claimsAtCapture(token, source).getIssuedAt().orElseThrow();

			JwtFixtures.assertAccepted(atTime(token, source, issuedAt.minusSeconds(60), null), compact);
			JwtFixtures.assertRejected(JoseException.Reason.ISSUED_IN_FUTURE, atTime(token, source,
					issuedAt.minusSeconds(61), null), compact);
		}));
	}

	// A captured token fails with the other provider's key set of the same scenario (UNKNOWN_KEY: no key has its kid,
	// and a static source never refreshes), with the lowest bit of its signature flipped, or with one space appended to
	// its payload JSON, which leaves the claims unchanged but not the signed bytes (SIGNATURE_MISMATCH, plan M2-6), and
	// for a validator configured with the issuer plus a trailing slash (ISSUER_MISMATCH, exact comparison).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyCapturedTokenFailsWithAnotherKeySetAChangedByteOrAnotherIssuer() {
		return TOKENS.stream().map(token -> DynamicTest.dynamicTest(token.toString(), () -> {
			String compact = text(token.capture(), token.file());
			StaticJsonWebKeySource source = source(token.capture(), token.keySet());
			Instant now = token.capture().finishedAt();
			String[] segments = compact.split("\\.", -1);
			Assertions.assertEquals(3, segments.length);

			Capture other = token.capture().equals(KEYCLOAK) ? NODE_OIDC_PROVIDER : KEYCLOAK;
			JwtFixtures.assertRejected(JoseException.Reason.UNKNOWN_KEY, validator(token, source(other, token.keySet()),
					now).allowedAlgorithms(Set.of(token.algorithm())).build(), compact);

			byte[] signature = Base64Url.decode(segments[2]);
			signature[signature.length - 1] ^= 1;
			JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MISMATCH, atTime(token, source, now, null),
					segments[0] + "." + segments[1] + "." + Base64Url.encode(signature));

			byte[] payload = Base64Url.decode(segments[1]);
			byte[] padded = new byte[payload.length + 1];
			System.arraycopy(payload, 0, padded, 0, payload.length);
			padded[payload.length] = ' ';
			JwtFixtures.assertRejected(JoseException.Reason.SIGNATURE_MISMATCH, atTime(token, source, now, null),
					segments[0] + "." + Base64Url.encode(padded) + "." + segments[2]);

			TokenCase slashed = new TokenCase(token.capture(), token.file(), token.issuer() + "/", token.algorithm(),
					token.audience(), token.type(), token.claimNames());
			JwtFixtures.assertRejected(JoseException.Reason.ISSUER_MISMATCH, validator(slashed, source, now)
					.allowedAlgorithms(Set.of(token.algorithm())).build(), compact);
		}));
	}

	// G8-2 and M2-4: both providers' default ID tokens validate under JwtValidator's defaults alone ({RS256}, typ JWT
	// or absent, 60 s skew), which is how an application configures a validator for either one.
	@Test
	void theDefaultValidatorAcceptsEachProvidersDefaultIdToken() throws Exception {
		for (Capture capture : CAPTURES) {
			String issuer = capture.equals(KEYCLOAK) ? KEYCLOAK_DEFAULT_ISSUER : NODE_OIDC_PROVIDER_ISSUER;
			Jwt jwt = JwtFixtures.assertAccepted(JwtValidator.withIssuer(issuer).jsonWebKeySource(source(capture,
					"default-jwks.json")).expectedAudiences(Set.of(TEST_CLIENT)).clock(TestClock.fromInstant(
					capture.finishedAt())).build(), text(capture, "default-rs256-id-token.jwt"));
			Assertions.assertEquals(JwsAlgorithm.RS256, jwt.getAlgorithm());
			Assertions.assertEquals(List.of(TEST_CLIENT), jwt.getClaims().getAudiences());
		}
	}

	// M2-4: Keycloak's access token for the test client, with no audience mapper, carries no aud, so a validator that
	// expects an audience gives MISSING_CLAIM, whichever audience it expects, and only acceptAnyAudience(true) validates
	// it, which didAcceptAnyAudience reports at build() and on the validation; azp names the client.
	@Test
	void keycloaksAccessTokenHasNoAudienceSoOnlyAcceptingAnyAudienceValidatesIt() throws Exception {
		String compact = text(KEYCLOAK, "default-rs256-access-token.jwt");
		StaticJsonWebKeySource source = source(KEYCLOAK, "default-jwks.json");

		for (String audience : List.of(TEST_CLIENT, "account"))
			JwtFixtures.assertRejected(JoseException.Reason.MISSING_CLAIM, JwtValidator.withIssuer(KEYCLOAK_DEFAULT_ISSUER)
					.jsonWebKeySource(source).expectedAudiences(Set.of(audience)).clock(TestClock.fromInstant(
					KEYCLOAK.finishedAt())).build(), compact);

		List<String> acceptedAnyAudience = new ArrayList<>();
		JoseObserver observer = new JoseObserver() {
			@Override
			public void didAcceptAnyAudience(@NonNull String issuer) {
				acceptedAnyAudience.add(issuer);
			}
		};
		Jwt jwt = JwtFixtures.assertAccepted(JwtValidator.withIssuer(KEYCLOAK_DEFAULT_ISSUER).jsonWebKeySource(source)
				.acceptAnyAudience(true).observer(observer).clock(TestClock.fromInstant(KEYCLOAK.finishedAt())).build(),
				compact);
		Assertions.assertEquals(List.of(KEYCLOAK_DEFAULT_ISSUER, KEYCLOAK_DEFAULT_ISSUER), acceptedAnyAudience);
		Assertions.assertEquals(List.of(), jwt.getClaims().getAudiences());
		Assertions.assertEquals(Optional.of(TEST_CLIENT), jwt.getClaims().toJsonObject().findString("azp"));
		Assertions.assertEquals(Optional.of("Bearer"), jwt.getClaims().toJsonObject().findString("typ"));
	}

	// G8-2 and INV-J3: both providers put alg on every RSA key, so each RSA-signed token still verifies when all six RSA
	// algorithms are allowed; an alg-less RSA key, as Microsoft Entra ID publishes, would then fit none of them.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rsaKeysThatCarryAlgStayUsableWhenEveryRsaAlgorithmIsAllowed() {
		return TOKENS.stream().filter(token -> RSA_ALGORITHMS.contains(token.algorithm())).map(token ->
				DynamicTest.dynamicTest(token.toString(), () -> {
					StaticJsonWebKeySource source = source(token.capture(), token.keySet());
					Jwt jwt = JwtFixtures.assertAccepted(validator(token, source, token.capture().finishedAt())
							.allowedAlgorithms(RSA_ALGORITHMS).build(), text(token.capture(), token.file()));
					Assertions.assertEquals(token.algorithm(), jwt.getAlgorithm());
				}));
	}

	// INV-J3 and RFC 8725 section 3.1 (read 2026-09-28): a key that carries alg verifies only that algorithm. A captured
	// RSA token whose header is relabelled to the other RSA padding with the same hash (RS256 to PS256, PS384 to RS384,
	// and so on) keeps its signature's length, so it passes the shape check, and its key then does not fit:
	// KEY_ALGORITHM_MISMATCH, with no signature check under the wrong padding.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> anRsaTokenRelabelledToTheOtherRsaPaddingIsAKeyAlgorithmMismatch() {
		return TOKENS.stream().filter(token -> RSA_ALGORITHMS.contains(token.algorithm())).map(token ->
				DynamicTest.dynamicTest(token.toString(), () -> {
					String wireValue = token.algorithm().getWireValue();
					JwsAlgorithm relabelled = JwsAlgorithm.findByWireValue((wireValue.startsWith("RS") ? "PS" : "RS")
							+ wireValue.substring(2)).orElseThrow();
					String[] segments = text(token.capture(), token.file()).split("\\.", -1);
					String header = new String(Base64Url.decode(segments[0]), StandardCharsets.UTF_8);
					String quoted = "\"" + wireValue + "\"";
					Assertions.assertEquals(header.indexOf(quoted), header.lastIndexOf(quoted), "alg appears once");
					String relabelledHeader = header.replace(quoted, "\"" + relabelled.getWireValue() + "\"");

					JwtFixtures.assertRejected(JoseException.Reason.KEY_ALGORITHM_MISMATCH, validator(token, source(
							token.capture(), token.keySet()), token.capture().finishedAt()).allowedAlgorithms(Set.of(relabelled))
							.build(), Base64Url.encode(relabelledHeader.getBytes(StandardCharsets.UTF_8)) + "." + segments[1] + "."
							+ segments[2]);
				}));
	}

	// Plan "Key selection" and G8-2: node-oidc-provider publishes its Ed25519 key without alg and signs with it under
	// both names, so the one key verifies an Ed25519 token and an EdDSA token; Keycloak's Ed25519 key says EdDSA. The
	// allowlist itself stays exact: an EdDSA token is ALGORITHM_NOT_ALLOWED under {Ed25519}, and the reverse.
	@Test
	void theEd25519KeyWithoutAlgVerifiesBothNamesWhileTheAllowlistStaysExact() throws Exception {
		Set<JwsAlgorithm> both = Set.of(JwsAlgorithm.ED25519, JwsAlgorithm.EDDSA);
		for (TokenCase token : TOKENS) {
			if (!both.contains(token.algorithm()))
				continue;
			String compact = text(token.capture(), token.file());
			StaticJsonWebKeySource source = source(token.capture(), token.keySet());
			Instant now = token.capture().finishedAt();

			Assertions.assertEquals(token.algorithm(), JwtFixtures.assertAccepted(validator(token, source, now)
					.allowedAlgorithms(both).build(), compact).getAlgorithm());
			JwsAlgorithm other = token.algorithm() == JwsAlgorithm.EDDSA ? JwsAlgorithm.ED25519 : JwsAlgorithm.EDDSA;
			JwtFixtures.assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, validator(token, source, now)
					.allowedAlgorithms(Set.of(other)).build(), compact);
		}
		Assertions.assertEquals(3, TOKENS.stream().filter(token -> both.contains(token.algorithm())).count());
	}

	// P4: node-oidc-provider's ML-DSA-44 ID token names an algorithm that is no JwsAlgorithm, so it is
	// ALGORITHM_NOT_ALLOWED at the header check under every allowlist a validator can hold; and its key (kty AKP) is
	// skipped as UNSUPPORTED_KEY_TYPE, never failing the key set.
	@Test
	void aPostQuantumTokenIsNeverAllowedAndItsKeyIsSkipped() throws Exception {
		Assertions.assertEquals(Optional.empty(), JwsAlgorithm.findByWireValue("ML-DSA-44"));
		Set<JwsAlgorithm> asymmetric = Stream.of(JwsAlgorithm.values()).filter(algorithm ->
				!algorithm.getWireValue().startsWith("HS")).collect(Collectors.toUnmodifiableSet());
		JwtFixtures.assertRejected(JoseException.Reason.ALGORITHM_NOT_ALLOWED, JwtValidator.withIssuer(
				NODE_OIDC_PROVIDER_ISSUER).jsonWebKeySource(source(NODE_OIDC_PROVIDER, "algorithms-jwks.json"))
				.expectedAudiences(Set.of(TEST_CLIENT + "-ml-dsa-44")).allowedAlgorithms(asymmetric).clock(
				TestClock.fromInstant(NODE_OIDC_PROVIDER.finishedAt())).build(), text(NODE_OIDC_PROVIDER, ML_DSA_TOKEN));

		Assertions.assertEquals("AKP", rawKeys(keySet(NODE_OIDC_PROVIDER, "algorithms-jwks.json")).get(10).findString(
				"kty").orElseThrow());
		Assertions.assertEquals(List.of(new ParsedKeySet.Skip(10, JsonWebKeySkipReason.UNSUPPORTED_KEY_TYPE)),
				JwkSetParser.parse(bytes(NODE_OIDC_PROVIDER, "algorithms-jwks.json"),
						Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue(), Limits.JWKS_KEY_COUNT.getDefaultIntValue()).skips());
	}

	// Plan A-5 and M2-8 through RemoteJsonWebKeySource: each captured key set, fetched from a loopback TLS server that
	// sends it byte for byte with its provider's captured Content-Type and Cache-Control, passes the key-set media-type
	// check (Keycloak's application/json; node-oidc-provider's application/jwk-set+json with charset=utf-8) and loads
	// with its pinned usable and skipped counts. Its lifetime follows those headers (M2-8's TTL rules): Keycloak's
	// no-cache gives the 1 min minimum, and node-oidc-provider's missing Cache-Control the 10 min default. Keycloak sent
	// no Date, and node-oidc-provider's Date changes nothing without Expires, so none is sent. The scenario's first token
	// validates with no further request until the lifetime ends, and didSkipJsonWebKey reports each skipped key by its
	// index on every fetch (plan "Exceptions, transience and observers").
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyCapturedKeySetFetchedWithItsCapturedHeadersLoadsAndLivesAsTheyDirect() throws IOException {
		RawTlsServer server = RawTlsServer.start();
		HttpClient client = TestTls.httpClient();
		return KEY_SETS.stream().map(keySet -> DynamicTest.dynamicTest(keySet.toString(), () -> {
			Capture capture = keySet.capture();
			String path = "/" + capture.name() + "/" + keySet.file();
			byte[] body = bytes(capture, keySet.file());
			server.script(path, RawTlsServer.Script.builder().write("HTTP/1.1 200 OK\r\n" + capture.keySetHeaders()
					+ "Content-Length: " + body.length + "\r\n\r\n").write(body).build());
			URI uri = server.uri(path);

			TestClock clock = TestClock.fromInstant(capture.finishedAt());
			RecordingObserver<JoseObserver> observer = RecordingObserver.fromInterface(JoseObserver.class);
			RemoteJsonWebKeySource source = RemoteJsonWebKeySource.withUri(uri).httpClient(client).clock(clock)
					.observer(observer.getObserver()).build();
			TokenCase token = TOKENS.stream().filter(candidate -> candidate.capture().equals(capture)
					&& candidate.keySet().equals(keySet.file())).findFirst().orElseThrow();
			JwtValidator validator = validator(token, source, capture.finishedAt()).allowedAlgorithms(Set.of(
					token.algorithm())).clock(clock).build();
			String compact = text(capture, token.file());
			List<List<Object>> skips = keySet.skips().stream().map(skip -> List.<Object>of(uri, skip.index(),
					skip.reason())).toList();

			JwtFixtures.assertAccepted(validator, compact);
			Assertions.assertEquals(1, server.getHitCount(path));
			Assertions.assertEquals(List.of(uri, keySet.keys().size(), keySet.skips().size(), capture.keySetTimeToLive()),
					observer.getCalls("didFetchJsonWebKeySet").get(0).getArguments().subList(0, 4));
			Assertions.assertEquals(skips, arguments(observer, "didSkipJsonWebKey"));

			clock.advance(capture.keySetTimeToLive().minusNanos(1));
			JwtFixtures.assertAccepted(validator, compact);
			Assertions.assertEquals(1, server.getHitCount(path));

			clock.advance(Duration.ofNanos(1));
			JwtFixtures.assertAccepted(validator, compact);
			Assertions.assertEquals(2, server.getHitCount(path));
			Assertions.assertEquals(2, observer.getCalls("didFetchJsonWebKeySet").size());
			Assertions.assertEquals(Stream.concat(skips.stream(), skips.stream()).toList(),
					arguments(observer, "didSkipJsonWebKey"));
			Assertions.assertEquals(List.of(), observer.getCalls("didFailToFetchJsonWebKeySet"));
		})).onClose(server::close);
	}

	// Each discovery document names its issuer and key set, and advertises every algorithm its captured tokens use.
	// Keycloak also advertises HS256, HS384 and HS512, which JwtValidator never allows (G8-2).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theDiscoveryDocumentsNameTheIssuerKeySetAndAdvertisedAlgorithms() {
		return DISCOVERY_DOCUMENTS.stream().map(document -> DynamicTest.dynamicTest(document.toString(), () -> {
			JsonObject json = (JsonObject) JsonCodec.parse(bytes(document.capture(), document.file()),
					JsonLimits.protocolDocument(Limits.HTTP_RESPONSE_BODY_SIZE.getDefaultIntValue()));
			Assertions.assertEquals(Optional.of(document.issuer()), json.findString("issuer"));
			Assertions.assertEquals(Optional.of(document.jwksUri()), json.findString("jwks_uri"));
			List<String> advertised = json.findStringList("id_token_signing_alg_values_supported").orElseThrow();
			Assertions.assertEquals(document.advertised(), Set.copyOf(advertised));
			Assertions.assertEquals(advertised.size(), document.advertised().size(), "no duplicates");

			String scenario = document.file().substring(0, document.file().indexOf('-'));
			for (TokenCase token : TOKENS)
				if (token.capture().equals(document.capture()) && token.keySet().startsWith(scenario))
					Assertions.assertTrue(advertised.contains(token.algorithm().getWireValue()), token.toString());
		}));
	}

	// The tokens name only the test realm's synthetic user, and carry only the pinned claims: node-oidc-provider's say
	// sub test-user and nothing else about the user; Keycloak's give a random subject UUID with the user's fixed test
	// name and address.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theTokensNameOnlyTheSyntheticTestUser() {
		return TOKENS.stream().map(token -> DynamicTest.dynamicTest(token.toString(), () -> {
			StaticJsonWebKeySource source = source(token.capture(), token.keySet());
			JsonObject claims = JwtFixtures.assertAccepted(validator(token, source, token.capture().finishedAt())
					.allowedAlgorithms(Set.of(token.algorithm())).build(), text(token.capture(), token.file())).getClaims()
					.toJsonObject();
			Assertions.assertEquals(token.claimNames(), claims.getMembers().keySet());

			if (token.capture().equals(NODE_OIDC_PROVIDER)) {
				Assertions.assertEquals(Optional.of(TEST_USER), claims.findString("sub"));
			} else {
				Assertions.assertTrue(SUBJECT_UUID.matcher(claims.findString("sub").orElseThrow()).matches());
				Assertions.assertEquals(Optional.of(TEST_USER), claims.findString("preferred_username"));
				Assertions.assertEquals(Optional.of("test-user@example.test"), claims.findString("email"));
				Assertions.assertEquals(Optional.of(true), claims.findBoolean("email_verified"));
				Assertions.assertEquals(Optional.of("Test User"), claims.findString("name"));
				Assertions.assertEquals(Optional.of("Test"), claims.findString("given_name"));
				Assertions.assertEquals(Optional.of("User"), claims.findString("family_name"));
			}
		}));
	}

	private static @NonNull List<@NonNull TokenCase> tokens() {
		List<TokenCase> tokens = new ArrayList<>();
		tokens.add(new TokenCase(KEYCLOAK, "default-rs256-id-token.jwt", KEYCLOAK_DEFAULT_ISSUER, JwsAlgorithm.RS256,
				TEST_CLIENT, "JWT", KEYCLOAK_ID_TOKEN_CLAIMS));
		tokens.add(new TokenCase(KEYCLOAK, "default-rs256-access-token.jwt", KEYCLOAK_DEFAULT_ISSUER, JwsAlgorithm.RS256,
				null, "JWT", KEYCLOAK_ACCESS_TOKEN_CLAIMS));
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.RS256, JwsAlgorithm.RS384, JwsAlgorithm.RS512,
				JwsAlgorithm.PS256, JwsAlgorithm.PS384, JwsAlgorithm.PS512, JwsAlgorithm.ES256, JwsAlgorithm.ES384,
				JwsAlgorithm.ES512, JwsAlgorithm.EDDSA)) {
			String name = algorithm.getWireValue().toLowerCase(Locale.ROOT);
			tokens.add(new TokenCase(KEYCLOAK, "algorithms-" + name + "-id-token.jwt", KEYCLOAK_ALGORITHMS_ISSUER,
					algorithm, TEST_CLIENT + "-" + name, "JWT", KEYCLOAK_ID_TOKEN_CLAIMS));
		}

		tokens.add(new TokenCase(NODE_OIDC_PROVIDER, "default-rs256-id-token.jwt", NODE_OIDC_PROVIDER_ISSUER,
				JwsAlgorithm.RS256, TEST_CLIENT, null, NODE_OIDC_PROVIDER_ID_TOKEN_CLAIMS));
		for (JwsAlgorithm algorithm : List.of(JwsAlgorithm.RS256, JwsAlgorithm.RS384, JwsAlgorithm.RS512,
				JwsAlgorithm.PS256, JwsAlgorithm.PS384, JwsAlgorithm.PS512, JwsAlgorithm.ES256, JwsAlgorithm.ES384,
				JwsAlgorithm.ES512, JwsAlgorithm.ED25519, JwsAlgorithm.EDDSA)) {
			String name = algorithm.getWireValue().toLowerCase(Locale.ROOT);
			tokens.add(new TokenCase(NODE_OIDC_PROVIDER, "algorithms-" + name + "-id-token.jwt", NODE_OIDC_PROVIDER_ISSUER,
					algorithm, TEST_CLIENT + "-" + name, null, NODE_OIDC_PROVIDER_ID_TOKEN_CLAIMS));
		}
		return List.copyOf(tokens);
	}

	private static @NonNull Set<@NonNull String> keycloakAdvertisedAlgorithms() {
		return Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA", "HS256",
				"HS384", "HS512");
	}

	/**
	 * A validator builder for the token's issuer and audience (any audience when the token has none) over
	 * {@code source}, with a clock stopped at {@code now}.
	 */
	private static JwtValidator.@NonNull Builder validator(@NonNull TokenCase token,
																								@NonNull JsonWebKeySource source,
																								@NonNull Instant now) {
		JwtValidator.Builder builder = JwtValidator.withIssuer(token.issuer()).jsonWebKeySource(source).clock(
				TestClock.fromInstant(now));
		String audience = token.audience();
		return audience == null ? builder.acceptAnyAudience(true) : builder.expectedAudiences(Set.of(audience));
	}

	/**
	 * A validator for the token's own algorithm at {@code now}, with {@code clockSkew} ({@code null} for the default).
	 */
	private static @NonNull JwtValidator atTime(@NonNull TokenCase token,
																		 @NonNull StaticJsonWebKeySource source,
																		 @NonNull Instant now,
																		 @Nullable Duration clockSkew) {
		return validator(token, source, now).allowedAlgorithms(Set.of(token.algorithm())).clockSkew(clockSkew).build();
	}

	/**
	 * The token's claims, as validated at its capture time.
	 */
	private static @NonNull JwtClaims claimsAtCapture(@NonNull TokenCase token,
																					 @NonNull StaticJsonWebKeySource source) throws IOException {
		return JwtFixtures.assertAccepted(atTime(token, source, token.capture().finishedAt(), null), text(token.capture(),
				token.file())).getClaims();
	}

	/**
	 * The arguments of each recorded call to {@code hook}, in call order.
	 */
	private static @NonNull List<@NonNull List<@Nullable Object>> arguments(@NonNull RecordingObserver<@NonNull JoseObserver> observer,
																												@NonNull String hook) {
		return observer.getCalls(hook).stream().map(RecordingObserver.Call::getArguments).toList();
	}

	private static @NonNull StaticJsonWebKeySource source(@NonNull Capture capture,
																							 @NonNull String keySet) throws IOException {
		return StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(text(capture, keySet)));
	}

	/**
	 * Describes a usable key by its type, its modulus size or curve, and its {@code alg}.
	 */
	private static @NonNull String describe(@NonNull VerificationKey key) {
		String size = key.publicKey() instanceof RSAPublicKey rsa ? String.valueOf(rsa.getModulus().bitLength())
				: requireNonNull(key.curve());
		JwsAlgorithm algorithm = key.algorithm();
		return key.keyType() + " " + size + " " + (algorithm == null ? "(no alg)" : algorithm.getWireValue());
	}

	private static @NonNull KeySetCase keySet(@NonNull Capture capture,
																	 @NonNull String file) {
		return KEY_SETS.stream().filter(keySet -> keySet.capture().equals(capture) && keySet.file().equals(file))
				.findFirst().orElseThrow();
	}

	private static @NonNull List<@NonNull JsonObject> rawKeys(@NonNull KeySetCase keySet) throws Exception {
		JsonObject document = (JsonObject) JsonCodec.parse(bytes(keySet.capture(), keySet.file()),
				JsonLimits.protocolDocument(Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue()));
		List<JsonObject> keys = new ArrayList<>();
		for (JsonValue element : ((JsonArray) document.find("keys").orElseThrow()).getElements())
			keys.add((JsonObject) element);
		return keys;
	}

	private static byte @NonNull [] decoded(@NonNull JsonObject key,
																@NonNull String member) throws Exception {
		return Base64Url.decode(key.findString(member).orElseThrow());
	}

	private static @NonNull Path directory(@NonNull Capture capture) throws URISyntaxException {
		URL url = CapturedProviderKeySetTests.class.getResource(capture.directory());
		Assertions.assertNotNull(url, capture.directory());
		return Path.of(url.toURI());
	}

	private static byte @NonNull [] bytes(@NonNull Capture capture,
															@NonNull String name) throws IOException {
		try (@Nullable InputStream stream = CapturedProviderKeySetTests.class.getResourceAsStream(capture.directory()
				+ name)) {
			if (stream == null)
				throw new IllegalStateException("Missing capture " + name);
			return stream.readAllBytes();
		}
	}

	private static @NonNull String text(@NonNull Capture capture,
														 @NonNull String name) throws IOException {
		return new String(bytes(capture, name), StandardCharsets.UTF_8);
	}

	/**
	 * One provider's capture directory, the capture run's first and last second, the provider's token lifetime, the
	 * {@code Content-Type} and {@code Cache-Control} header lines its key-set responses carried (SOURCE.txt), and the
	 * lifetime those headers give a remote source.
	 */
	private record Capture(@NonNull String name, @NonNull String directory, @NonNull Instant startedAt, @NonNull Instant finishedAt, @NonNull Duration lifetime,
												 @NonNull String keySetHeaders, @NonNull Duration keySetTimeToLive) {
		@Override
		public @NonNull String toString() {
			return this.name;
		}
	}

	private record KeySetCase(@NonNull Capture capture, @NonNull String file, @NonNull List<@NonNull String> keys, @NonNull List<ParsedKeySet.@NonNull Skip> skips,
														int certificates) {
		@Override
		public @NonNull String toString() {
			return this.capture.name() + " " + this.file;
		}
	}

	private record DiscoveryCase(@NonNull Capture capture, @NonNull String file, @NonNull String issuer, @NonNull String jwksUri, @NonNull Set<@NonNull String> advertised) {
		@Override
		public @NonNull String toString() {
			return this.capture.name() + " " + this.file;
		}
	}

	/**
	 * One captured token: its issuer, algorithm, audience ({@code null} for none), {@code typ} header ({@code null} for
	 * none) and claim names; its key set is its scenario's.
	 */
	private record TokenCase(@NonNull Capture capture, @NonNull String file, @NonNull String issuer, @NonNull JwsAlgorithm algorithm,
													 @Nullable String audience, @Nullable String type, @NonNull Set<@NonNull String> claimNames) {
		@NonNull String keySet() {
			return this.file.substring(0, this.file.indexOf('-')) + "-jwks.json";
		}

		@Override
		public @NonNull String toString() {
			return this.capture.name() + " " + this.file;
		}
	}
}
