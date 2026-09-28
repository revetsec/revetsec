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

import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.pem.PemException;
import com.revetsec.jose.JwtValidatorFuzzSupport;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EdECPoint;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.stream.IntStream;

/**
 * Writes the fuzz module's generated seeds: the {@code generated-*} and {@code wycheproof-*} files in the JOSE and
 * ECDSA targets' inputs directories, and {@code com/revetsec/jose/fixture-key-set.json}, which
 * {@code JwtValidatorFuzzTests} verifies with. It is not a test and has no {@code FuzzTests} suffix, so neither
 * Surefire nor {@code .clusterfuzzlite/build.sh} runs it. Like the targets, it uses only the main sources and the JDK.
 * <p>
 * <strong>Inputs.</strong> The TEST ONLY fixture keys ({@code src/test/resources/fixtures/keys/} and
 * {@code src/test/resources/fixtures/pem/ed25519-*.pem}) and the vendored Wycheproof files
 * ({@code src/test/resources/vectors/wycheproof/testvectors_v1/}), both read from the core checkout.
 * <ul>
 *   <li>{@code generated-*} tokens are signed with the fixture private keys over fixed headers and claims, relative to
 *   {@link JwtValidatorFuzzSupport#NOW}. RSASSA-PKCS1-v1_5, Ed25519 and HMAC signatures are deterministic, so those
 *   seeds are reproduced byte for byte. RSASSA-PSS and ECDSA signing draw from a {@code SHA1PRNG} seeded with 1, which
 *   makes a run repeatable on one JDK but not across JDKs; {@code FuzzSeedProvenanceTests} therefore checks those
 *   seeds'
 *   signing input and, for an undamaged one, that its signature verifies.</li>
 *   <li>{@code generated-*} key sets hold the fixture keys' public halves, their certificates, and damaged copies
 *   (a leading zero octet, a coordinate one octet short, a point moved off the curve, and so on), and keys computed
 *   here at the key rules' bounds: moduli of 2,047, 16,384 and 16,385 bits drawn from SHA-256, moduli built to carry
 *   the ROCA fingerprint for every prime or for all but the first or the last, points whose {@code x} is a curve's
 *   field prime, and Ed25519's points of order 1, 2, 4 and 8. No private key member is ever copied: a seed that needs
 *   a private member carries a placeholder value.</li>
 *   <li>{@code wycheproof-<file>-tc<tcId>-<field>} seeds copy one field out of a vendored file: a test's {@code jws}
 *   string, a test's {@code sig} octets (from its hex), or its group's {@code public} or {@code private} key or key
 *   set (as canonical JSON). {@code FuzzSeedProvenanceTests} re-derives each from its name.</li>
 * </ul>
 * <strong>Running it</strong> (from the repository root, after {@code mvn -f fuzz/pom.xml test-compile}):
 * <pre>
 * java -cp "fuzz/target/test-classes:fuzz/target/classes" com.revetsec.FuzzSeedGenerator .
 * </pre>
 * The seeds in the tree were written on 2026-09-28 with Corretto 21.0.11.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class FuzzSeedGenerator {
	/**
	 * Where the seeds live, relative to the core checkout.
	 */
	public static final String FUZZ_RESOURCES = "fuzz/src/test/resources";

	/**
	 * Where the vendored Wycheproof files live, relative to the core checkout.
	 */
	public static final String WYCHEPROOF_VECTORS = "src/test/resources/vectors/wycheproof/testvectors_v1";

	private static final String VALIDATOR_SEEDS =
			"com/revetsec/jose/JwtValidatorFuzzTestsInputs/validateAcceptsOnlyWhatTheJdkVerifiersAccept/";
	private static final String COMPACT_SEEDS = "com/revetsec/internal/jose/CompactJwsFuzzTestsInputs/"
			+ "compactSerializationsSplitIntoThreeCanonicalSegmentsOrFailInStepOrder/";
	private static final String KEY_SET_SEEDS = "com/revetsec/internal/jose/JsonWebKeyFuzzTestsInputs/"
			+ "keySetDocumentsSkipExactlyTheKeysAnIndependentOracleRefuses/";
	private static final String ECDSA_SEEDS = "com/revetsec/internal/crypto/EcdsaFuzzTestsInputs/"
			+ "shapeCheckAndDerEncodingAgreeWithTheRangeRuleAndAnX690Reader/";
	private static final String KEY_SET_RESOURCE = "com/revetsec/jose/"
			+ JwtValidatorFuzzSupport.FIXTURE_KEY_SET_RESOURCE;

	private static final long NOW = JwtValidatorFuzzSupport.NOW.getEpochSecond();
	private static final String TOKEN_ID = "\"jti\":\"generated\"";
	private static final String CLIENT = "\"client_id\":\"fuzz-client\"";

	/**
	 * The JWS strings copied into the token targets: every HMAC and ES256 test of the JWS file, a spread of its RS256
	 * padding tests, the other RSA groups' first tests, the RFC 7520 examples, the base64 canonicality tests and the
	 * special-case ES256 tests.
	 */
	private static final List<Integer> JWS_TEST_IDS = concat(IntStream.rangeClosed(1, 36).boxed().toList(),
			List.of(60, 100, 150, 200, 258, 259, 264, 268, 272, 290, 320, 321, 325, 330),
			IntStream.rangeClosed(345, 401).boxed().toList());

	/**
	 * The JWS file's key-carrying groups, by a tcId in each, whose {@code public} or {@code private} member is copied.
	 */
	private static final List<Integer> JWS_KEY_GROUP_TEST_IDS = List.of(1, 18, 33, 272, 320, 325, 345, 346, 347, 348,
			349, 350, 351, 352, 353, 354, 355, 356, 357, 378);

	/**
	 * The JWK file's groups, by a tcId in each.
	 */
	private static final List<Integer> JWK_GROUP_TEST_IDS = List.of(1, 2, 4, 5, 6, 7, 8, 9, 10, 13, 16, 19, 20, 21, 22,
			23, 24, 25, 26);

	/**
	 * The fixed-length ECDSA signatures copied into the shape target: the signature-malleability vector, r or s pushed
	 * past n or 2^256, every special r/s pair's first rows, a two-octet signature, and each file's first valid
	 * edge-case vectors.
	 */
	private static final Map<String, List<Integer>> ECDSA_TEST_IDS = Map.of(
			"ecdsa_secp256r1_sha256_p1363", List.of(1, 2, 4, 6, 9, 11, 14, 19, 27, 35, 40, 46, 115, 121, 136, 137, 152, 153,
					257, 262),
			"ecdsa_secp384r1_sha384_p1363", List.of(1, 2, 4, 11, 14, 19, 27, 35, 40, 46, 147, 153, 164, 165, 180, 181, 280),
			"ecdsa_secp521r1_sha512_p1363", List.of(1, 2, 4, 11, 14, 19, 27, 35, 40, 46, 184, 190, 201, 202, 217, 218, 318));

	/**
	 * The odd primes from 3 to 167, whose residues the ROCA fingerprint constrains (M2-7).
	 */
	private static final List<Integer> ROCA_PRIMES = IntStream.rangeClosed(3, 167)
			.filter(candidate -> candidate % 2 == 1 && IntStream.rangeClosed(2, (int) Math.sqrt(candidate))
					.noneMatch(divisor -> candidate % divisor == 0))
			.boxed().toList();

	private FuzzSeedGenerator() {
	}

	/**
	 * Writes every generated seed under {@code <core>/fuzz/src/test/resources}.
	 *
	 * @param arguments the core checkout's path, {@code .} by default
	 * @throws Exception if a fixture or vector cannot be read, or a seed cannot be written
	 */
	public static void main(String[] arguments) throws Exception {
		Path core = Path.of(arguments.length > 0 ? arguments[0] : ".").toAbsolutePath().normalize();
		Path resources = core.resolve(FUZZ_RESOURCES);

		List<Seed> seeds = seeds(core);

		for (Seed seed : seeds) {
			Path file = resources.resolve(seed.getPath());
			Files.createDirectories(file.getParent());
			Files.write(file, seed.getBytes());
		}

		System.out.println("Wrote " + seeds.size() + " generated seeds under " + resources);
	}

	/**
	 * Every generated seed, in a fixed order.
	 *
	 * @param core the core checkout
	 * @return the seeds
	 * @throws IOException              if a fixture or vector cannot be read
	 * @throws GeneralSecurityException if the JDK cannot sign
	 * @throws PemException             if a fixture does not parse
	 * @throws JsonParseException       if a vector file does not parse
	 */
	public static List<Seed> seeds(Path core) throws IOException, GeneralSecurityException, PemException,
			JsonParseException {
		Fixtures fixtures = new Fixtures(core);
		List<Seed> seeds = new ArrayList<>();

		seeds.add(Seed.exact(KEY_SET_RESOURCE, utf8(fixtureKeySet(fixtures))));
		tokenSeeds(fixtures, seeds);
		keySetSeeds(fixtures, seeds);
		wycheproofSeeds(core, seeds);

		return List.copyOf(seeds);
	}

	/**
	 * {@link JwtValidatorFuzzSupport#KEY_SLOTS} over the fixtures' public keys.
	 *
	 * @param fixtures the fixtures
	 * @return the key set's JSON text
	 */
	private static String fixtureKeySet(Fixtures fixtures) {
		return JwtValidatorFuzzSupport.keySetJson(JwtValidatorFuzzSupport.KEY_SLOTS, fixtures::publicKey,
				fixtures::certificate);
	}

	private static void tokenSeeds(Fixtures fixtures, List<Seed> seeds) throws GeneralSecurityException {
		String claims = claims("\"iss\":\"" + JwtValidatorFuzzSupport.ISSUER + "\"", "\"sub\":\"fuzz-subject\"",
				"\"aud\":\"" + JwtValidatorFuzzSupport.AUDIENCE + "\"", CLIENT, "\"iat\":" + (NOW - 60),
				"\"nbf\":" + (NOW - 60), "\"exp\":" + (NOW + 3_600), TOKEN_ID);
		TokenFactory tokens = new TokenFactory(fixtures, seeds);

		// Every algorithm, with the key its kid names; the first also go to the compact target.
		tokens.both("accepted-rs256", header("RS256", "rsa-2048-rs256", "JWT"), claims, "idp-signing-rsa-2048");
		tokens.one("accepted-rs384", header("RS384", "rsa-2048-rs384", null), claims, "idp-signing-rsa-2048");
		tokens.one("accepted-rs512", header("RS512", "rsa-2048-rs512", null), claims, "idp-signing-rsa-2048");
		tokens.both("accepted-ps256", header("PS256", "rsa-2048-ps256", "JWT"), claims, "idp-signing-rsa-2048");
		tokens.one("accepted-ps384", header("PS384", "rsa-2048-ps384", null), claims, "idp-signing-rsa-2048");
		tokens.one("accepted-ps512", header("PS512", "rsa-2048-ps512", null), claims, "idp-signing-rsa-2048");
		tokens.both("accepted-es256", header("ES256", "ec-p256", "jwt"), claims, "idp-signing-ec-p256");
		tokens.both("accepted-es384", header("ES384", "ec-p384", null), claims, "idp-signing-ec-p384");
		tokens.both("accepted-es512", header("ES512", "ec-p521", "application/JWT"), claims, "idp-signing-ec-p521");
		tokens.both("accepted-ed25519", header("Ed25519", "ed25519", null), claims, "ed25519");
		tokens.both("accepted-eddsa", header("EdDSA", "ed25519", "JWT"), claims, "ed25519");

		// Selection (INV-J3, INV-J9, INV-C6).
		tokens.one("accepted-es384-without-kid", header("ES384", null, null), claims, "idp-signing-ec-p384");
		tokens.one("rejected-eddsa-without-kid-is-ambiguous", header("EdDSA", null, null), claims, "ed25519");
		tokens.one("accepted-ps256-without-kid", header("PS256", null, null), claims, "idp-signing-rsa-2048");
		tokens.one("rejected-rs256-without-kid-is-ambiguous", header("RS256", null, null), claims, "idp-signing-rsa-2048");
		tokens.one("accepted-ed25519-with-an-eddsa-key", header("Ed25519", "ed25519-eddsa", null), claims, "ed25519");
		tokens.one("accepted-eddsa-with-an-ed25519-key", header("EdDSA", "ed25519-ed25519", null), claims, "ed25519");
		tokens.one("rejected-shared-kid-with-two-fitting-keys-is-ambiguous", header("ES512", "shared-kid", null), claims,
				"idp-signing-ec-p521");
		tokens.one("accepted-shared-kid-with-one-fitting-key", header("RS384", "shared-kid", null), claims,
				"idp-signing-rsa-2048");
		tokens.one("accepted-key-bound-to-this-issuer", header("ES256", "ec-p256-issuer-bound", null), claims,
				"idp-signing-ec-p256");
		tokens.one("rejected-key-bound-to-another-issuer", header("RS256", "rsa-2048-other-issuer", null), claims,
				"sp-signing-rsa-2048");
		tokens.one("rejected-rsa-key-without-alg-while-several-rsa-algorithms-are-allowed", header("RS256", "rsa-3072",
				null), claims, "idp-signing-rsa-3072");
		tokens.one("rejected-unknown-kid", header("RS256", "no-such-key", null), claims, "idp-signing-rsa-2048");
		tokens.one("rejected-es256-kid-names-an-rsa-key", header("ES256", "rsa-2048-rs256", null), claims,
				"idp-signing-ec-p256");

		// Time, with 60 seconds of skew (exit criterion 9).
		String base = "\"iss\":\"" + JwtValidatorFuzzSupport.ISSUER + "\",\"sub\":\"s\",\"aud\":\""
				+ JwtValidatorFuzzSupport.AUDIENCE + "\"," + CLIENT;
		String es256 = header("ES256", "ec-p256", null);
		tokens.one("rejected-expired-at-exp-plus-skew", es256, claims(base, "\"exp\":" + (NOW - 60)),
				"idp-signing-ec-p256");
		tokens.one("accepted-expired-less-than-skew-ago", es256, claims(base, "\"exp\":" + (NOW - 59)),
				"idp-signing-ec-p256");
		tokens.one("rejected-not-yet-valid", es256, claims(base, "\"exp\":" + (NOW + 600), "\"nbf\":" + (NOW + 61)),
				"idp-signing-ec-p256");
		tokens.one("accepted-not-before-within-skew", es256, claims(base, "\"exp\":" + (NOW + 600),
				"\"nbf\":" + (NOW + 60)), "idp-signing-ec-p256");
		tokens.one("rejected-issued-in-future", es256, claims(base, "\"exp\":" + (NOW + 600), "\"iat\":" + (NOW + 61)),
				"idp-signing-ec-p256");
		tokens.one("accepted-issued-at-within-skew", es256, claims(base, "\"exp\":" + (NOW + 600), "\"iat\":" + (NOW + 60)),
				"idp-signing-ec-p256");
		tokens.one("accepted-fractional-exp", es256, claims(base, "\"exp\":" + (NOW + 600) + ".25"), "idp-signing-ec-p256");
		tokens.one("rejected-exp-as-string", es256, claims(base, "\"exp\":\"" + (NOW + 600) + "\""), "idp-signing-ec-p256");
		tokens.one("rejected-exp-past-year-9999", es256, claims(base, "\"exp\":1e20"), "idp-signing-ec-p256");
		tokens.one("rejected-missing-exp", es256, claims(base), "idp-signing-ec-p256");

		// Issuer, audience, required claims and cnf (exit criterion 10).
		String rs256 = header("RS256", "rsa-2048-rs256", null);
		String times = "\"exp\":" + (NOW + 600);
		String audience = "\"aud\":\"" + JwtValidatorFuzzSupport.AUDIENCE + "\"";
		String issuer = "\"iss\":\"" + JwtValidatorFuzzSupport.ISSUER + "\"";
		tokens.one("rejected-other-issuer", rs256, claims("\"iss\":\"https://attacker.example.com\"", "\"sub\":\"s\"",
				audience, CLIENT, times), "idp-signing-rsa-2048");
		tokens.one("rejected-issuer-in-other-case", rs256, claims("\"iss\":\"https://ISSUER.example.com\"",
				"\"sub\":\"s\"", audience, CLIENT, times), "idp-signing-rsa-2048");
		tokens.one("rejected-issuer-with-trailing-slash", rs256, claims("\"iss\":\"" + JwtValidatorFuzzSupport.ISSUER
				+ "/\"", "\"sub\":\"s\"", audience, CLIENT, times), "idp-signing-rsa-2048");
		tokens.one("rejected-missing-issuer", rs256, claims("\"sub\":\"s\"", audience, CLIENT, times),
				"idp-signing-rsa-2048");
		tokens.one("rejected-missing-client-id", rs256, claims(issuer, "\"sub\":\"s\"", audience, times),
				"idp-signing-rsa-2048");
		tokens.one("rejected-null-client-id", rs256, claims(issuer, "\"sub\":\"s\"", audience, "\"client_id\":null",
				times), "idp-signing-rsa-2048");
		tokens.one("rejected-null-sub-is-malformed", rs256, claims(issuer, "\"sub\":null", audience, CLIENT, times),
				"idp-signing-rsa-2048");
		tokens.one("rejected-other-audience", rs256, claims(issuer, "\"sub\":\"s\"",
				"\"aud\":\"https://other.example.com\"", CLIENT, times), "idp-signing-rsa-2048");
		tokens.one("accepted-audience-array-with-others", rs256, claims(issuer, "\"sub\":\"s\"", "\"aud\":[\"x\",\""
				+ JwtValidatorFuzzSupport.AUDIENCE + "\"]", CLIENT, times), "idp-signing-rsa-2048");
		tokens.one("rejected-empty-audience-array", rs256, claims(issuer, "\"sub\":\"s\"", "\"aud\":[]", CLIENT, times),
				"idp-signing-rsa-2048");
		tokens.one("rejected-audience-array-with-a-number", rs256, claims(issuer, "\"sub\":\"s\"", "\"aud\":[123]", CLIENT,
				times), "idp-signing-rsa-2048");
		tokens.one("rejected-confirmation-claim", rs256, claims(issuer, "\"sub\":\"s\"", audience, CLIENT, times,
				"\"cnf\":{\"jkt\":\"fuzz-generated-key-thumbprint\"}"), "idp-signing-rsa-2048");
		tokens.one("rejected-null-confirmation-claim", rs256, claims(issuer, "\"sub\":\"s\"", audience, CLIENT, times,
				"\"cnf\":null"), "idp-signing-rsa-2048");
		tokens.one("rejected-jti-not-a-string", rs256, claims(issuer, "\"sub\":\"s\"", audience, CLIENT, times,
				"\"jti\":5"), "idp-signing-rsa-2048");
		tokens.one("rejected-typ-of-another-profile", header("RS256", "rsa-2048-rs256", "at+jwt"), claims,
				"idp-signing-rsa-2048");
		tokens.one("rejected-claims-not-an-object", rs256, "[\"" + JwtValidatorFuzzSupport.ISSUER + "\"]",
				"idp-signing-rsa-2048");
		tokens.one("rejected-empty-payload", rs256, "", "idp-signing-rsa-2048");
		tokens.one("rejected-duplicate-claim", rs256, claims(issuer, issuer, "\"sub\":\"s\"", audience, CLIENT, times),
				"idp-signing-rsa-2048");

		// Signatures (exit criteria 4 to 6; CVE-2022-21449, CVE-2015-9235).
		tokens.both("rejected-es256-der-signature", es256, claims, "idp-signing-ec-p256", Damage.DER);
		tokens.both("rejected-es256-r-zero", es256, claims, "idp-signing-ec-p256", Damage.R_ZERO);
		tokens.one("rejected-es256-r-equals-order", es256, claims, "idp-signing-ec-p256", Damage.R_ORDER);
		tokens.one("accepted-es256-high-s", es256, claims, "idp-signing-ec-p256", Damage.HIGH_S);
		tokens.one("rejected-es256-63-octets", es256, claims, "idp-signing-ec-p256", Damage.TRUNCATE);
		tokens.one("rejected-es256-65-octets", es256, claims, "idp-signing-ec-p256", Damage.EXTEND);
		tokens.both("rejected-rs256-255-octets", rs256, claims, "idp-signing-rsa-2048", Damage.TRUNCATE);
		tokens.one("rejected-rs256-257-octets", rs256, claims, "idp-signing-rsa-2048", Damage.EXTEND);
		tokens.one("rejected-rs256-empty-signature", rs256, claims, "idp-signing-rsa-2048", Damage.EMPTY);
		tokens.one("rejected-rs256-3072-bit-signature-for-a-2048-bit-key", rs256, claims, "idp-signing-rsa-3072");
		tokens.one("rejected-rs256-signed-by-an-untrusted-key", rs256, claims, "negative-attacker-rsa-2048");
		tokens.one("rejected-rs256-payload-changed-after-signing", rs256, claims, "idp-signing-rsa-2048",
				Damage.PAYLOAD_CHANGED);
		tokens.both("rejected-rs256-padded-signature-segment", rs256, claims, "idp-signing-rsa-2048", Damage.PADDED);
		tokens.one("rejected-ps256-flipped-bit", header("PS256", "rsa-2048-ps256", null), claims, "idp-signing-rsa-2048",
				Damage.FLIP_BIT);
		tokens.one("rejected-ed25519-65-octets", header("Ed25519", "ed25519", null), claims, "ed25519", Damage.EXTEND);
		tokens.one("rejected-ed25519-flipped-bit", header("Ed25519", "ed25519", null), claims, "ed25519", Damage.FLIP_BIT);
		tokens.both("rejected-hs256-keyed-with-the-rsa-public-key", header("HS256", "rsa-2048-rs256", null), claims,
				"idp-signing-rsa-2048");

		// The Entra validator (M2-11): template, exact and alg-less keys, and the tid negatives.
		String entra = "\"iss\":\"" + JwtValidatorFuzzSupport.ENTRA_ISSUER
				+ "\",\"sub\":\"s\",\"aud\":\"api://fuzz\",\"exp\":" + (NOW + 600);
		String tid = "\"tid\":\"" + JwtValidatorFuzzSupport.ENTRA_TENANT + "\"";
		tokens.one("entra-accepted-template-key", header("RS256", "entra-template", "JWT"), claims(entra, tid),
				"idp-signing-rsa-3072");
		tokens.one("entra-accepted-exact-key", header("RS256", "entra-exact", "JWT"), claims(entra, tid),
				"sp-signing-rsa-2048");
		tokens.one("entra-accepted-rsa-key-without-alg", header("RS256", "rsa-3072", "at+jwt"), claims(entra),
				"idp-signing-rsa-3072");
		tokens.one("entra-accepted-es256", header("ES256", "ec-p256", "JWT"), claims(entra), "idp-signing-ec-p256");
		tokens.one("entra-rejected-uppercase-tid", header("RS256", "entra-template", "JWT"), claims(entra, "\"tid\":\""
				+ JwtValidatorFuzzSupport.ENTRA_TENANT.toUpperCase(Locale.ROOT) + "\""), "idp-signing-rsa-3072");
		tokens.one("entra-rejected-braced-tid", header("RS256", "entra-template", "JWT"), claims(entra, "\"tid\":\"{"
				+ JwtValidatorFuzzSupport.ENTRA_TENANT + "}\""), "idp-signing-rsa-3072");
		tokens.one("entra-rejected-missing-tid", header("RS256", "entra-template", "JWT"), claims(entra),
				"idp-signing-rsa-3072");
		tokens.one("entra-rejected-other-tenant-tid", header("RS256", "entra-template", "JWT"), claims(entra,
				"\"tid\":\"00000000-1111-4222-8333-444444444444\""), "idp-signing-rsa-3072");
		tokens.one("entra-rejected-template-key-for-an-uppercase-tenant", header("RS256", "entra-template", "JWT"),
				claims("\"iss\":\"" + JwtValidatorFuzzSupport.UPPERCASE_ENTRA_ISSUER + "\"", "\"tid\":\""
						+ JwtValidatorFuzzSupport.ENTRA_TENANT.toUpperCase(Locale.ROOT) + "\"", "\"exp\":" + (NOW + 600)),
				"idp-signing-rsa-3072");
		tokens.one("entra-accepted-key-without-issuer-for-an-uppercase-tenant", header("RS256", "rsa-3072", "JWT"), claims(
				"\"iss\":\"" + JwtValidatorFuzzSupport.UPPERCASE_ENTRA_ISSUER + "\"", "\"exp\":" + (NOW + 600)),
				"idp-signing-rsa-3072");
		tokens.one("entra-rejected-missing-typ", header("RS256", "entra-exact", null), claims(entra, tid),
				"sp-signing-rsa-2048");
		tokens.one("entra-rejected-ps256-not-allowed", header("PS256", "rsa-2048-ps256", "JWT"), claims(entra),
				"idp-signing-rsa-2048");

		// Step 1 at the Entra validator's 8,192-character cap, which fuzzing alone seldom reaches (libFuzzer's inputs
		// stay below 4,096 bytes unless a seed is longer): a valid token of exactly that length, and one character more.
		int signatureLength = base64Url(new byte[(((RSAPublicKey) fixtures.publicKey("sp-signing-rsa-2048")).getModulus()
				.bitLength() + 7) / 8]).length();

		for (int length : List.of(8_192, 8_193)) {
			String header = null;
			String padded = null;

			// A space after the first comma moves the header's length when no padding gives the exact total.
			for (int spaces = 0; padded == null; ++spaces) {
				header = "{\"alg\":\"RS256\"," + " ".repeat(spaces) + "\"kid\":\"entra-exact\",\"typ\":\"JWT\"}";
				padded = paddedClaims(length - base64Url(utf8(header)).length() - 2 - signatureLength, entra, tid);
			}

			tokens.one("entra-" + (length == 8_192 ? "accepted" : "rejected") + "-" + length + "-characters", header, padded,
					"sp-signing-rsa-2048");
		}
	}

	/**
	 * The claims {@code members} plus a {@code pad} claim, as long as makes their unpadded base64url encoding exactly
	 * {@code segmentLength} characters, or {@code null} if no length does: n octets encode to 4n/3 characters rounded
	 * up, which is never 1 more than a multiple of 4.
	 */
	private static String paddedClaims(int segmentLength, String... members) {
		if (segmentLength % 4 == 1)
			return null;

		int octets = segmentLength / 4 * 3 + (segmentLength % 4 == 0 ? 0 : segmentLength % 4 - 1);
		String others = String.join(",", members);
		int padding = octets - utf8(claims(others, "\"pad\":\"\"")).length;

		if (padding < 0)
			return null;

		String claims = claims(others, "\"pad\":\"" + "p".repeat(padding) + "\"");

		if (base64Url(utf8(claims)).length() != segmentLength)
			throw new IllegalStateException("The padded claims encode to the wrong length");

		return claims;
	}

	private static void keySetSeeds(Fixtures fixtures, List<Seed> seeds) throws GeneralSecurityException {
		seeds.add(Seed.exact(KEY_SET_SEEDS + "generated-fixture-key-set.json", utf8(fixtureKeySet(fixtures))));

		List<String> withCertificates = new ArrayList<>();

		for (String name : Fixtures.WITH_CERTIFICATES)
			withCertificates.add(jwk(fixtures.publicKey(name), "\"kid\":\"" + name + "\",\"x5c\":[\""
					+ base64(fixtures.certificate(name).getEncoded()) + "\"]"));

		seeds.add(Seed.exact(KEY_SET_SEEDS + "generated-fixture-keys-with-their-certificates.json",
				utf8(keySet(withCertificates))));
		seeds.add(Seed.exact(KEY_SET_SEEDS + "generated-certificates-of-other-keys.json", utf8(keySet(List.of(
				jwk(fixtures.publicKey("idp-signing-rsa-2048"), "\"x5c\":[\""
						+ base64(fixtures.certificate("sp-signing-rsa-2048").getEncoded()) + "\"]"),
				jwk(fixtures.publicKey("idp-signing-ec-p256"), "\"x5c\":[\""
						+ base64(fixtures.certificate("negative-unconfigured-ec-p256").getEncoded()) + "\"]"))))));

		RSAPublicKey rsa = (RSAPublicKey) fixtures.publicKey("idp-signing-rsa-2048");
		String n = base64Url(unsigned(rsa.getModulus()));
		seeds.add(Seed.exact(KEY_SET_SEEDS + "generated-rsa-key-policy.json", utf8(keySet(List.of(
				"{\"kty\":\"RSA\",\"kid\":\"leading-zero-n\",\"n\":\"" + base64Url(concat(new byte[1],
						unsigned(rsa.getModulus()))) + "\",\"e\":\"AQAB\"}",
				"{\"kty\":\"RSA\",\"kid\":\"leading-zero-e\",\"n\":\"" + n + "\",\"e\":\"AAEAAQ\"}",
				"{\"kty\":\"RSA\",\"kid\":\"even-n\",\"n\":\"" + base64Url(unsigned(rsa.getModulus().add(BigInteger.ONE)))
						+ "\",\"e\":\"AQAB\"}",
				"{\"kty\":\"RSA\",\"kid\":\"e-3\",\"n\":\"" + n + "\",\"e\":\"Aw\"}",
				"{\"kty\":\"RSA\",\"kid\":\"e-65535\",\"n\":\"" + n + "\",\"e\":\"__8\"}",
				"{\"kty\":\"RSA\",\"kid\":\"e-65536\",\"n\":\"" + n + "\",\"e\":\"AQAA\"}",
				"{\"kty\":\"RSA\",\"kid\":\"e-2-to-the-32-plus-1\",\"n\":\"" + n + "\",\"e\":\"AQAAAAE\"}",
				jwk(fixtures.publicKey("negative-rsa-1024"), "\"kid\":\"rsa-1024\""),
				"{\"kty\":\"RSA\",\"kid\":\"padded-n\",\"n\":\"" + n + "==\",\"e\":\"AQAB\"}")))));

		// The key policy's bounds (M2-7): the modulus sizes on each side of 2,048 and 16,384 bits, and the ROCA
		// fingerprint for every prime, or for all but the first or the last (n divisible by that prime).
		seeds.add(Seed.exact(KEY_SET_SEEDS + "generated-rsa-moduli-at-the-policy-bounds.json", utf8(keySet(List.of(
				rsaJwk("n-2047-bits", oddModulus("n-2047-bits", 2_047)),
				rsaJwk("n-16384-bits", oddModulus("n-16384-bits", 16_384)),
				rsaJwk("n-16385-bits", oddModulus("n-16385-bits", 16_385)),
				rsaJwk("roca-every-prime", rocaModulus(-1)),
				rsaJwk("roca-all-but-the-first-prime", rocaModulus(0)),
				rsaJwk("roca-all-but-the-last-prime", rocaModulus(ROCA_PRIMES.size() - 1)))))));

		ECPublicKey ec = (ECPublicKey) fixtures.publicKey("idp-signing-ec-p256");
		BigInteger p = ((ECFieldFp) ec.getParams().getCurve().getField()).getP();
		BigInteger x = ec.getW().getAffineX();
		BigInteger y = ec.getW().getAffineY();
		seeds.add(Seed.exact(KEY_SET_SEEDS + "generated-ec-points.json", utf8(keySet(List.of(
				ecJwk("x-one-octet-short", Arrays.copyOfRange(fixed(x, 32), 1, 32), fixed(y, 32)),
				ecJwk("y-plus-one", fixed(x, 32), fixed(y.add(BigInteger.ONE).mod(p), 32)),
				ecJwk("other-root", fixed(x, 32), fixed(p.subtract(y), 32)),
				ecJwk("x-equal-to-field-prime", fixed(p, 32), fixed(y, 32)),
				ecJwk("y-plus-field-prime", fixed(x, 32), fixed(y.add(p), 33)),
				"{\"kty\":\"EC\",\"kid\":\"wrong-curve-name\",\"crv\":\"P-384\",\"x\":\"" + base64Url(fixed(x, 32))
						+ "\",\"y\":\"" + base64Url(fixed(y, 32)) + "\"}",
				"{\"kty\":\"EC\",\"kid\":\"es384-on-p-256\",\"alg\":\"ES384\",\"crv\":\"P-256\",\"x\":\""
						+ base64Url(fixed(x, 32)) + "\",\"y\":\"" + base64Url(fixed(y, 32)) + "\"}",
				pointWithTheFieldPrimeForX(fixtures.publicKey("idp-signing-ec-p256")),
				pointWithTheFieldPrimeForX(fixtures.publicKey("idp-signing-ec-p384")),
				pointWithTheFieldPrimeForX(fixtures.publicKey("idp-signing-ec-p521")))))));

		BigInteger edwardsPrime = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
		seeds.add(Seed.exact(KEY_SET_SEEDS + "generated-ed25519-encodings.json", utf8(keySet(List.of(
				okpJwk("identity", BigInteger.ONE, false),
				okpJwk("order-two", edwardsPrime.subtract(BigInteger.ONE), false),
				okpJwk("order-four", BigInteger.ZERO, false),
				okpJwk("order-four-negated", BigInteger.ZERO, true),
				okpJwk("x-zero-with-sign-bit", BigInteger.ONE, true),
				okpJwk("minus-one-with-sign-bit", edwardsPrime.subtract(BigInteger.ONE), true),
				okpJwk("y-two-does-not-decode", BigInteger.TWO, false),
				okpJwk("y-equal-to-field-prime", edwardsPrime, false),
				okpJwk("y-all-ones", BigInteger.ONE.shiftLeft(255).subtract(BigInteger.ONE), false),
				okpJwk("order-eight-first-y", orderEightY(edwardsPrime).get(0), false),
				okpJwk("order-eight-first-y-negated-x", orderEightY(edwardsPrime).get(0), true),
				okpJwk("order-eight-second-y", orderEightY(edwardsPrime).get(1), false),
				okpJwk("order-eight-second-y-negated-x", orderEightY(edwardsPrime).get(1), true),
				jwk(fixtures.publicKey("ed25519"), "\"kid\":\"fixture\""))))));

		String fixtureEc = "\"crv\":\"P-256\",\"x\":\"" + base64Url(fixed(x, 32)) + "\",\"y\":\"" + base64Url(fixed(y, 32))
				+ "\"";
		seeds.add(Seed.exact(KEY_SET_SEEDS + "generated-optional-members.json", utf8(keySet(List.of(
				"{\"kty\":\"EC\",\"kid\":\"issuer-null\",\"issuer\":null," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"issuer-number\",\"issuer\":123," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"issuer-array\",\"issuer\":[]," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"issuer-empty\",\"issuer\":\"\"," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"issuer\",\"issuer\":\"" + JwtValidatorFuzzSupport.ISSUER + "\"," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"use-enc\",\"use\":\"enc\"," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"key-ops-encrypt\",\"key_ops\":[\"encrypt\"]," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"use-and-key-ops-disagree\",\"use\":\"sig\",\"key_ops\":[\"verify\",\"encrypt\"],"
						+ fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"key-ops-without-use\",\"key_ops\":[\"verify\",\"encrypt\"]," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"private-member-placeholder\",\"d\":\"AQAB\"," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"\"," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"" + "k".repeat(256) + "\"," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"kid\":\"" + "k".repeat(257) + "\"," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"alg\":\"ES521\"," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"alg\":\"HS256\"," + fixtureEc + "}",
				"{\"kty\":\"EC\",\"x5c\":[\"not base64\"]," + fixtureEc + "}")))));
	}

	/**
	 * Copies the listed fields out of the vendored Wycheproof files.
	 */
	private static void wycheproofSeeds(Path core, List<Seed> seeds) throws IOException, JsonParseException {
		Vectors jws = Vectors.read(core, "json_web_signature");

		for (int testId : JWS_TEST_IDS) {
			byte[] token = utf8(jws.testString(testId, "jws"));
			String name = "wycheproof-json_web_signature-tc" + testId + "-jws.txt";
			seeds.add(Seed.exact(VALIDATOR_SEEDS + name, token));

			if (testId <= 32 || testId >= 345)
				seeds.add(Seed.exact(COMPACT_SEEDS + name, token));
		}

		for (int testId : JWS_KEY_GROUP_TEST_IDS)
			for (String field : List.of("public", "private"))
				jws.groupMember(testId, field).ifPresent(value -> seeds.add(Seed.exact(KEY_SET_SEEDS
						+ "wycheproof-json_web_signature-tc" + testId + "-" + field + ".json", JsonCodec.toUtf8Bytes(value))));

		Vectors jwk = Vectors.read(core, "json_web_key");

		for (int testId : JWK_GROUP_TEST_IDS)
			for (String field : List.of("public", "private"))
				jwk.groupMember(testId, field).ifPresent(value -> seeds.add(Seed.exact(KEY_SET_SEEDS
						+ "wycheproof-json_web_key-tc" + testId + "-" + field + ".json", JsonCodec.toUtf8Bytes(value))));

		for (Map.Entry<String, List<Integer>> file : new TreeMap<>(ECDSA_TEST_IDS).entrySet()) {
			Vectors vectors = Vectors.read(core, file.getKey());

			for (int testId : file.getValue())
				seeds.add(Seed.exact(ECDSA_SEEDS + "wycheproof-" + file.getKey() + "-tc" + testId + "-sig.bin",
						HexFormat.of().parseHex(vectors.testString(testId, "sig"))));
		}
	}

	private static String header(String algorithm, String keyId, String type) {
		StringBuilder header = new StringBuilder("{\"alg\":\"").append(algorithm).append('"');

		if (keyId != null)
			header.append(",\"kid\":\"").append(keyId).append('"');

		if (type != null)
			header.append(",\"typ\":\"").append(type).append('"');

		return header.append('}').toString();
	}

	private static String claims(String... members) {
		return "{" + String.join(",", members) + "}";
	}

	private static String keySet(List<String> keys) {
		return "{\"keys\":[" + String.join(",", keys) + "]}";
	}

	/**
	 * A public key as a JWK, with {@code extra} members before its key members.
	 */
	private static String jwk(PublicKey key, String extra) {
		String prefix = extra.isEmpty() ? "" : extra + ",";

		if (key instanceof RSAPublicKey rsa)
			return "{\"kty\":\"RSA\"," + prefix + "\"n\":\"" + base64Url(unsigned(rsa.getModulus())) + "\",\"e\":\""
					+ base64Url(unsigned(rsa.getPublicExponent())) + "\"}";

		if (key instanceof ECPublicKey ec) {
			int length = (((ECFieldFp) ec.getParams().getCurve().getField()).getP().bitLength() + 7) / 8;
			return "{\"kty\":\"EC\"," + prefix + "\"crv\":\"" + (length == 32 ? "P-256" : length == 48 ? "P-384" : "P-521")
					+ "\",\"x\":\"" + base64Url(fixed(ec.getW().getAffineX(), length)) + "\",\"y\":\""
					+ base64Url(fixed(ec.getW().getAffineY(), length)) + "\"}";
		}

		EdECPoint point = ((EdECPublicKey) key).getPoint();
		return okpJwkWithMembers(prefix, point.getY(), point.isXOdd());
	}

	private static String ecJwk(String keyId, byte[] x, byte[] y) {
		return "{\"kty\":\"EC\",\"kid\":\"" + keyId + "\",\"crv\":\"P-256\",\"x\":\"" + base64Url(x) + "\",\"y\":\""
				+ base64Url(y) + "\"}";
	}

	/**
	 * An Ed25519 JWK whose {@code x} is the RFC 8032 section 5.1.2 encoding of {@code y} (its low 255 bits) and the
	 * sign bit.
	 */
	private static String okpJwk(String keyId, BigInteger y, boolean xOdd) {
		return okpJwkWithMembers("\"kid\":\"" + keyId + "\",", y, xOdd);
	}

	private static String okpJwkWithMembers(String prefix, BigInteger y, boolean xOdd) {
		byte[] bigEndian = fixed(y, 32);
		byte[] encoded = new byte[32];

		for (int index = 0; index < 32; ++index)
			encoded[index] = bigEndian[31 - index];

		encoded[31] = (byte) ((encoded[31] & 0x7F) | (xOdd ? 0x80 : 0));
		return "{\"kty\":\"OKP\"," + prefix + "\"crv\":\"Ed25519\",\"x\":\"" + base64Url(encoded) + "\"}";
	}

	private static String rsaJwk(String keyId, BigInteger modulus) {
		return "{\"kty\":\"RSA\",\"kid\":\"" + keyId + "\",\"n\":\"" + base64Url(unsigned(modulus)) + "\",\"e\":\"AQAB\"}";
	}

	/**
	 * An odd modulus of exactly {@code bits} bits, from SHA-256 over {@code label} and a block counter, so that it is
	 * the same in every run.
	 */
	private static BigInteger oddModulus(String label, int bits) throws GeneralSecurityException {
		byte[] octets = new byte[(bits + 7) / 8];

		for (int block = 0; block * 32 < octets.length; ++block) {
			byte[] digest = MessageDigest.getInstance("SHA-256").digest(utf8(label + "/" + block));
			System.arraycopy(digest, 0, octets, block * 32, Math.min(32, octets.length - block * 32));
		}

		return new BigInteger(1, octets).mod(BigInteger.ONE.shiftLeft(bits)).setBit(bits - 1).setBit(0);
	}

	/**
	 * An odd 2,048-bit modulus whose residue modulo every ROCA prime lies in the subgroup that 65,537 generates (a power
	 * of 65,537), built by the Chinese remainder theorem, except that the prime at {@code broken} divides it.
	 */
	private static BigInteger rocaModulus(int broken) {
		BigInteger product = BigInteger.ONE;

		for (int prime : ROCA_PRIMES)
			product = product.multiply(BigInteger.valueOf(prime));

		BigInteger residue = BigInteger.ZERO;

		for (int index = 0; index < ROCA_PRIMES.size(); ++index) {
			BigInteger prime = BigInteger.valueOf(ROCA_PRIMES.get(index));
			BigInteger value = index == broken ? BigInteger.ZERO
					: BigInteger.valueOf(65_537).modPow(BigInteger.valueOf(index + 1L), prime);
			BigInteger cofactor = product.divide(prime);
			residue = residue.add(value.multiply(cofactor).multiply(cofactor.modInverse(prime)));
		}

		// The product is odd, so adding it once more makes the modulus odd and keeps every residue.
		BigInteger modulus = residue.mod(product).add(product.shiftLeft(2_048 - product.bitLength()));
		modulus = modulus.testBit(0) ? modulus : modulus.add(product);

		if (modulus.bitLength() != 2_048)
			throw new IllegalStateException("The ROCA-shaped modulus is not 2,048 bits long");

		return modulus;
	}

	/**
	 * An EC JWK whose {@code x} is the curve's field prime, which is 0 modulo that prime, and whose {@code y} is a square
	 * root of the curve's {@code b}: the point {@code (0, y)} is on the curve, but its {@code x} is not below the prime
	 * (SEC 1 section 2.3.5). Every NIST prime is 3 modulo 4, so the root is {@code b^((p + 1) / 4)}.
	 */
	private static String pointWithTheFieldPrimeForX(PublicKey fixture) {
		ECParameterSpec parameters = ((ECPublicKey) fixture).getParams();
		BigInteger p = ((ECFieldFp) parameters.getCurve().getField()).getP();
		BigInteger b = parameters.getCurve().getB();
		BigInteger y = b.modPow(p.add(BigInteger.ONE).shiftRight(2), p);

		if (!y.multiply(y).mod(p).equals(b.mod(p)))
			throw new IllegalStateException("The curve's b is not a square");

		int length = (p.bitLength() + 7) / 8;
		String curve = length == 32 ? "P-256" : length == 48 ? "P-384" : "P-521";
		return "{\"kty\":\"EC\",\"kid\":\"" + curve.toLowerCase(Locale.ROOT) + "-x-equal-to-the-field-prime\",\"crv\":\""
				+ curve + "\",\"x\":\"" + base64Url(fixed(p, length)) + "\",\"y\":\"" + base64Url(fixed(y, length)) + "\"}";
	}

	/**
	 * The two {@code y} coordinates of Ed25519's four points of order 8, in ascending order. Such a point doubles to one
	 * with {@code y = 0}, so {@code x^2 = -y^2}, which with the curve equation gives {@code d y^4 + 2 y^2 - 1 = 0}
	 * (RFC 8032 section 5.1).
	 */
	private static List<BigInteger> orderEightY(BigInteger p) {
		BigInteger d = p.subtract(BigInteger.valueOf(121_665)).multiply(BigInteger.valueOf(121_666).modInverse(p)).mod(p);
		BigInteger root = squareRoot(BigInteger.ONE.add(d).mod(p), p);

		for (BigInteger sign : List.of(BigInteger.ONE, p.subtract(BigInteger.ONE))) {
			BigInteger y = squareRoot(sign.multiply(root).subtract(BigInteger.ONE).multiply(d.modInverse(p)).mod(p), p);

			if (y != null)
				return List.of(y.min(p.subtract(y)), y.max(p.subtract(y)));
		}

		throw new IllegalStateException("Ed25519 has no point of order 8");
	}

	/**
	 * A square root modulo a prime {@code p = 5 mod 8} by Atkin's method, or {@code null} if {@code a} is not a square.
	 */
	private static BigInteger squareRoot(BigInteger a, BigInteger p) {
		if (!a.modPow(p.subtract(BigInteger.ONE).shiftRight(1), p).equals(BigInteger.ONE))
			return a.signum() == 0 ? BigInteger.ZERO : null;

		BigInteger twiceA = a.shiftLeft(1).mod(p);
		BigInteger v = twiceA.modPow(p.subtract(BigInteger.valueOf(5)).shiftRight(3), p);
		BigInteger i = twiceA.multiply(v).multiply(v).mod(p);
		return a.multiply(v).multiply(i.subtract(BigInteger.ONE)).mod(p);
	}

	private static byte[] unsigned(BigInteger value) {
		byte[] bytes = value.toByteArray();
		return bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
	}

	private static byte[] fixed(BigInteger value, int length) {
		byte[] bytes = value.toByteArray();
		byte[] fixed = new byte[length];

		for (int index = 0; index < length && index < bytes.length; ++index)
			fixed[length - 1 - index] = bytes[bytes.length - 1 - index];

		return fixed;
	}

	private static byte[] concat(byte[] first, byte[] second) {
		byte[] joined = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, joined, first.length, second.length);
		return joined;
	}

	@SafeVarargs
	private static List<Integer> concat(List<Integer>... lists) {
		List<Integer> joined = new ArrayList<>();

		for (List<Integer> list : lists)
			joined.addAll(list);

		return List.copyOf(joined);
	}

	private static String base64Url(byte[] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private static String base64(byte[] bytes) {
		return Base64.getEncoder().encodeToString(bytes);
	}

	private static byte[] utf8(String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Verifies a generated token's signature with the JDK engine its algorithm names, as the provenance check does for
	 * a randomized signature.
	 *
	 * @param token     the token
	 * @param algorithm the JWS algorithm it was signed with
	 * @param key       the fixture's public key
	 * @return whether the signature verifies
	 */
	public static boolean verifies(String token, String algorithm, PublicKey key) {
		try {
			String signingInput = token.substring(0, token.lastIndexOf('.'));
			Signature verifier = engine(algorithm);
			verifier.initVerify(key);
			parameters(verifier, algorithm);
			verifier.update(signingInput.getBytes(StandardCharsets.US_ASCII));
			return verifier.verify(Base64.getUrlDecoder().decode(token.substring(token.lastIndexOf('.') + 1)));
		} catch (GeneralSecurityException | RuntimeException e) {
			return false;
		}
	}

	private static Signature engine(String algorithm) throws GeneralSecurityException {
		return switch (algorithm) {
			case "RS256" -> Signature.getInstance("SHA256withRSA");
			case "RS384" -> Signature.getInstance("SHA384withRSA");
			case "RS512" -> Signature.getInstance("SHA512withRSA");
			case "PS256", "PS384", "PS512" -> Signature.getInstance("RSASSA-PSS");
			case "ES256" -> Signature.getInstance("SHA256withECDSAinP1363Format");
			case "ES384" -> Signature.getInstance("SHA384withECDSAinP1363Format");
			case "ES512" -> Signature.getInstance("SHA512withECDSAinP1363Format");
			default -> Signature.getInstance("Ed25519");
		};
	}

	private static void parameters(Signature engine, String algorithm) throws GeneralSecurityException {
		switch (algorithm) {
			case "PS256" -> engine.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
			case "PS384" -> engine.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1));
			case "PS512" -> engine.setParameter(new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1));
			default -> {
				// No parameters.
			}
		}
	}

	/**
	 * How a generated token's signature is damaged after signing.
	 */
	private enum Damage {
		NONE, DER, R_ZERO, R_ORDER, HIGH_S, TRUNCATE, EXTEND, EMPTY, FLIP_BIT, PAYLOAD_CHANGED, PADDED
	}

	/**
	 * Signs the token seeds and files them.
	 */
	@Immutable
	private static final class TokenFactory {
		private final Fixtures fixtures;
		private final List<Seed> seeds;

		private TokenFactory(Fixtures fixtures, List<Seed> seeds) {
			this.fixtures = fixtures;
			this.seeds = seeds;
		}

		private void one(String name, String header, String claims, String signer) throws GeneralSecurityException {
			add(name, header, claims, signer, Damage.NONE, false);
		}

		private void one(String name, String header, String claims, String signer, Damage damage)
				throws GeneralSecurityException {
			add(name, header, claims, signer, damage, false);
		}

		private void both(String name, String header, String claims, String signer) throws GeneralSecurityException {
			add(name, header, claims, signer, Damage.NONE, true);
		}

		private void both(String name, String header, String claims, String signer, Damage damage)
				throws GeneralSecurityException {
			add(name, header, claims, signer, damage, true);
		}

		private void add(String name, String header, String claims, String signer, Damage damage, boolean compactToo)
				throws GeneralSecurityException {
			String algorithm = header.substring(8, header.indexOf('"', 8));
			String headerSegment = base64Url(utf8(header));
			String payloadSegment = base64Url(utf8(claims));
			String signingInput = headerSegment + "." + payloadSegment;
			byte[] signature = sign(algorithm, signer, signingInput);
			boolean randomized = algorithm.startsWith("PS") || algorithm.startsWith("ES");
			String signatureSegment;

			switch (damage) {
				case DER -> signature = der(signature);
				case R_ZERO -> Arrays.fill(signature, 0, signature.length / 2, (byte) 0);
				case R_ORDER -> System.arraycopy(fixed(((ECPublicKey) this.fixtures.publicKey(signer)).getParams().getOrder(),
						signature.length / 2), 0, signature, 0, signature.length / 2);
				case HIGH_S -> {
					int half = signature.length / 2;
					BigInteger order = ((ECPublicKey) this.fixtures.publicKey(signer)).getParams().getOrder();
					BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, half, signature.length));
					System.arraycopy(fixed(order.subtract(s), half), 0, signature, half, half);
				}
				case TRUNCATE -> signature = Arrays.copyOf(signature, signature.length - 1);
				case EXTEND -> signature = Arrays.copyOf(signature, signature.length + 1);
				case EMPTY -> signature = new byte[0];
				case FLIP_BIT -> signature[signature.length / 2] ^= 0x01;
				case PAYLOAD_CHANGED -> payloadSegment = base64Url(utf8(claims.replace("fuzz-subject", "fuzz-attacker")));
				default -> {
					// Signed as is.
				}
			}

			signatureSegment = base64Url(signature) + (damage == Damage.PADDED ? "=" : "");
			byte[] token = utf8(headerSegment + "." + payloadSegment + "." + signatureSegment);
			Seed seed;

			if (!randomized)
				seed = Seed.exact(VALIDATOR_SEEDS + "generated-" + name + ".txt", token);
			else if (damage == Damage.NONE || damage == Damage.HIGH_S)
				seed = Seed.signed(VALIDATOR_SEEDS + "generated-" + name + ".txt", token, algorithm,
						this.fixtures.publicKey(signer));
			else
				seed = Seed.sameSigningInput(VALIDATOR_SEEDS + "generated-" + name + ".txt", token);

			this.seeds.add(seed);

			if (compactToo)
				this.seeds.add(seed.at(COMPACT_SEEDS + "generated-" + name + ".txt"));
		}

		private byte[] sign(String algorithm, String signer, String signingInput) throws GeneralSecurityException {
			byte[] input = signingInput.getBytes(StandardCharsets.US_ASCII);

			if (algorithm.equals("HS256")) {
				// CVE-2015-9235: a MAC keyed with the RSA public key's DER encoding.
				Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(new SecretKeySpec(this.fixtures.publicKey(signer).getEncoded(), "HmacSHA256"));
				return mac.doFinal(input);
			}

			Signature engine = engine(algorithm);
			PrivateKey key = this.fixtures.privateKey(signer);

			if (algorithm.startsWith("PS") || algorithm.startsWith("ES")) {
				SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
				random.setSeed(1L);
				engine.initSign(key, random);
			} else {
				engine.initSign(key);
			}

			parameters(engine, algorithm);
			engine.update(input);
			return engine.sign();
		}

		/**
		 * The minimal DER form of a fixed-length ECDSA signature (X.690), which JOSE forbids.
		 */
		private static byte[] der(byte[] signature) {
			int half = signature.length / 2;
			byte[] r = new BigInteger(1, Arrays.copyOfRange(signature, 0, half)).toByteArray();
			byte[] s = new BigInteger(1, Arrays.copyOfRange(signature, half, signature.length)).toByteArray();
			int content = 2 + r.length + 2 + s.length;
			byte[] der = new byte[2 + content];
			der[0] = 0x30;
			der[1] = (byte) content;
			der[2] = 0x02;
			der[3] = (byte) r.length;
			System.arraycopy(r, 0, der, 4, r.length);
			der[4 + r.length] = 0x02;
			der[5 + r.length] = (byte) s.length;
			System.arraycopy(s, 0, der, 6 + r.length, s.length);
			return der;
		}
	}

	/**
	 * The TEST ONLY fixture keys and certificates, by name.
	 */
	@Immutable
	private static final class Fixtures {
		private static final List<String> WITH_CERTIFICATES = List.of("idp-signing-rsa-2048", "idp-signing-rsa-3072",
				"idp-signing-ec-p256", "idp-signing-ec-p384", "idp-signing-ec-p521", "negative-attacker-rsa-2048",
				"negative-rsa-1024", "negative-unconfigured-ec-p256", "sp-signing-rsa-2048", "sp-encryption-rsa-2048");

		private final Map<String, PrivateKey> privateKeys = new LinkedHashMap<>();
		private final Map<String, PublicKey> publicKeys = new LinkedHashMap<>();
		private final Map<String, X509Certificate> certificates = new LinkedHashMap<>();

		private Fixtures(Path core) throws IOException, PemException {
			Path keys = core.resolve("src/test/resources/fixtures/keys");

			for (String name : WITH_CERTIFICATES) {
				this.privateKeys.put(name, Pem.parsePrivateKey(Files.readString(keys.resolve(name + "-key.pem"))));
				X509Certificate certificate = Pem.parseCertificate(Files.readString(keys.resolve(name + "-cert.pem")));
				this.certificates.put(name, certificate);
				this.publicKeys.put(name, certificate.getPublicKey());
			}

			Path pem = core.resolve("src/test/resources/fixtures/pem");
			this.privateKeys.put("ed25519", Pem.parsePrivateKey(Files.readString(pem.resolve("ed25519-key.pem"))));
			this.publicKeys.put("ed25519", Pem.parsePublicKey(Files.readString(pem.resolve("ed25519-public.pem"))));
		}

		private PrivateKey privateKey(String name) {
			return require(this.privateKeys, name);
		}

		private PublicKey publicKey(String name) {
			return require(this.publicKeys, name);
		}

		private X509Certificate certificate(String name) {
			return this.certificates.get(name);
		}

		private static <T> T require(Map<String, T> values, String name) {
			T value = values.get(name);

			if (value == null)
				throw new IllegalArgumentException("No fixture named " + name);

			return value;
		}
	}

	/**
	 * One vendored Wycheproof file, parsed.
	 */
	@Immutable
	public static final class Vectors {
		private final JsonObject document;

		private Vectors(JsonObject document) {
			this.document = document;
		}

		/**
		 * Reads {@code <stem>_test.json} from the vendored directory.
		 *
		 * @param core the core checkout
		 * @param stem the file name without {@code _test.json}
		 * @return the parsed file
		 * @throws IOException        if it cannot be read
		 * @throws JsonParseException if it does not parse
		 */
		public static Vectors read(Path core, String stem) throws IOException, JsonParseException {
			byte[] bytes = Files.readAllBytes(core.resolve(WYCHEPROOF_VECTORS).resolve(stem + "_test.json"));
			return new Vectors((JsonObject) JsonCodec.parse(bytes, JsonLimits.protocolDocument(4 * 1024 * 1024)));
		}

		/**
		 * The string member {@code field} of test {@code testId}.
		 *
		 * @param testId the tcId
		 * @param field  the member name
		 * @return the value
		 */
		public String testString(int testId, String field) {
			return ((JsonString) test(testId).getMembers().get(field)).getValue();
		}

		/**
		 * The member {@code field} of the group that holds test {@code testId}, if it has one.
		 *
		 * @param testId the tcId
		 * @param field  the member name
		 * @return the value, or empty
		 */
		public Optional<JsonValue> groupMember(int testId, String field) {
			return Optional.ofNullable(group(testId).getMembers().get(field));
		}

		/**
		 * The member {@code field} of test {@code testId}, or else of its group.
		 *
		 * @param testId the tcId
		 * @param field  the member name
		 * @return the value, or empty if neither has it
		 */
		public Optional<JsonValue> field(int testId, String field) {
			JsonValue value = test(testId).getMembers().get(field);
			return value != null ? Optional.of(value) : groupMember(testId, field);
		}

		private JsonObject test(int testId) {
			for (JsonValue group : groups())
				for (JsonValue test : ((JsonArray) ((JsonObject) group).getMembers().get("tests")).getElements())
					if (tcId((JsonObject) test) == testId)
						return (JsonObject) test;

			throw new IllegalArgumentException("No tcId " + testId);
		}

		private JsonObject group(int testId) {
			for (JsonValue group : groups())
				for (JsonValue test : ((JsonArray) ((JsonObject) group).getMembers().get("tests")).getElements())
					if (tcId((JsonObject) test) == testId)
						return (JsonObject) group;

			throw new IllegalArgumentException("No tcId " + testId);
		}

		private List<JsonValue> groups() {
			return ((JsonArray) this.document.getMembers().get("testGroups")).getElements();
		}

		private static int tcId(JsonObject test) {
			return ((JsonNumber) test.getMembers().get("tcId")).getValue().intValueExact();
		}
	}

	/**
	 * One generated seed and how its provenance is checked.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public static final class Seed {
		private final String path;
		private final byte[] bytes;
		private final Check check;
		private final String algorithm;
		private final PublicKey key;

		private Seed(String path, byte[] bytes, Check check, String algorithm, PublicKey key) {
			this.path = path;
			this.bytes = bytes.clone();
			this.check = check;
			this.algorithm = algorithm;
			this.key = key;
		}

		private static Seed exact(String path, byte[] bytes) {
			return new Seed(path, bytes, Check.EXACT, null, null);
		}

		private static Seed signed(String path, byte[] bytes, String algorithm, PublicKey key) {
			return new Seed(path, bytes, Check.SIGNATURE_VERIFIES, algorithm, key);
		}

		private static Seed sameSigningInput(String path, byte[] bytes) {
			return new Seed(path, bytes, Check.SAME_SIGNING_INPUT, null, null);
		}

		private Seed at(String otherPath) {
			return new Seed(otherPath, this.bytes, this.check, this.algorithm, this.key);
		}

		/**
		 * The seed's path under {@code fuzz/src/test/resources}.
		 *
		 * @return the relative path
		 */
		public String getPath() {
			return this.path;
		}

		/**
		 * The seed's content.
		 *
		 * @return a new array
		 */
		public byte[] getBytes() {
			return this.bytes.clone();
		}

		/**
		 * How the committed file must match what the generator makes now.
		 *
		 * @return the check
		 */
		public Check getCheck() {
			return this.check;
		}

		/**
		 * For {@link Check#SIGNATURE_VERIFIES}: whether a committed token's signature verifies with the fixture key.
		 *
		 * @param token the committed token
		 * @return whether it verifies
		 */
		public boolean verifies(String token) {
			return FuzzSeedGenerator.verifies(token, this.algorithm, this.key);
		}

		/**
		 * How a committed generated seed is compared with the generator's output.
		 */
		public enum Check {
			/**
			 * Byte for byte.
			 */
			EXACT,
			/**
			 * The same signing input, and a signature that verifies (a randomized signature).
			 */
			SIGNATURE_VERIFIES,
			/**
			 * The same signing input and signature length (a damaged randomized signature).
			 */
			SAME_SIGNING_INPUT
		}
	}
}
