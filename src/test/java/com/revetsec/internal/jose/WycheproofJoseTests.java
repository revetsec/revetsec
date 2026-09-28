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

import com.revetsec.internal.Limits;
import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.internal.crypto.Hmac;
import com.revetsec.internal.crypto.KeyRejectedException;
import com.revetsec.internal.crypto.WycheproofSignatureTests.Expectations;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.jose.JoseException;
import com.revetsec.jose.JsonWebKey;
import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JsonWebKeySkipReason;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.WycheproofVectors;
import com.revetsec.testing.WycheproofVectors.Result;
import com.revetsec.testing.WycheproofVectors.TestGroup;
import com.revetsec.testing.WycheproofVectors.TestVector;
import com.revetsec.testing.WycheproofVectors.VectorFile;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Project Wycheproof's JSON Web Signature and JSON Web Key files through the internal JWS layer (plan M2-9 and M2 exit
 * criterion 3): every vector runs through {@link JwtProcessor} with no JWT claims check, because Wycheproof's payloads
 * are opaque bytes, and every vector runs a second time through the key-set-only path.
 * <p>
 * <strong>The JWS layer.</strong> Each token is prepared under a {@link JoseHeaderPolicy} whose effective algorithm
 * set is the token's own {@code alg} when that names a {@link JwsAlgorithm}, and every {@link JwsAlgorithm} otherwise
 * (M2-9). P4 then decides exactly as it would under the full set, and INV-J3's one-algorithm rule binds an RSA key
 * without {@code alg} to that algorithm (G8-2). The token length and the {@code typ} settings are
 * {@code JwtValidator}'s defaults.
 * <p>
 * <strong>Keys.</strong> Public keys come from the real key set parser, {@link JwkSetParser}, at the default limits of
 * {@link JsonWebKeySet#fromJson(String)}, and {@code JsonWebKeySet.fromJson} must find the same keys: the group's
 * {@code public} JWK or JWK Set, or, for a group without one, its {@code private} keys with their private and
 * symmetric members dropped. An {@code HS*} token goes to the internal HMAC engine
 * ({@link JwtProcessor#verifyWithSecret}), with the {@code k} of the group's one {@code kty: oct} key with the token's
 * {@code kid} as the configured secret, after INV-J3's checks on that JWK: {@code use} and {@code key_ops} must allow
 * verification (RFC 7517 sections 4.2 and 4.3), and an {@code alg} must name an HMAC algorithm. A key that fails
 * them, or a secret shorter than the hash, which the engine refuses (RFC 7518 section 3.2), is never configured, so
 * the token has no key ({@code UNKNOWN_KEY}). A key whose {@code alg} names another HMAC algorithm is a key for that
 * algorithm, as in key selection ({@code KEY_ALGORITHM_MISMATCH}). A key set that mixes symmetric and asymmetric keys,
 * or that holds two secrets for one token, is key-set semantics that one configured secret cannot express:
 * {@code n/a}.
 * <p>
 * <strong>The key-set-only path.</strong> Every vector also runs against a key set that holds the group's
 * {@code public} keys followed by its {@code private} keys exactly as Wycheproof writes them, secrets included. Every
 * key with a private or symmetric member is skipped, never used for its public half (INV-J3), so the usable keys are
 * those of the first path, and so is every outcome, except that every {@code HS*} token the first path sent to the
 * HMAC engine is rejected here, whatever its outcome there: no key in a key set is ever an HMAC key (INV-J2).
 * <p>
 * <strong>Expectations.</strong> Each outcome is {@code accept}, {@code reject:<code>} with a
 * {@link JoseException.Reason} name, or {@code n/a}, and it must be the one the expectation manifest
 * {@code EXPECTATIONS.tsv} (in this package's {@code wycheproof} test resources) records, in the format and under the
 * staleness checks of {@link Expectations}, which the primitive runner in {@code internal.crypto} shares. Each group's
 * skipped keys are pinned here, so JWK tcId 7 is shown rejected through the {@code WEAK_KEY} skip, not merely
 * rejected.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class WycheproofJoseTests {
	/**
	 * The manifest, relative to the module root.
	 */
	private static final String MANIFEST = "src/test/resources/com/revetsec/internal/jose/wycheproof/EXPECTATIONS.tsv";

	/**
	 * The vendored files this runner runs; the primitive runner runs the rest.
	 */
	private static final Set<String> FILES = Set.of("json_web_key_test.json", "json_web_signature_test.json");

	/**
	 * The reason codes this runner reports.
	 */
	private static final Set<String> CODES = Arrays.stream(JoseException.Reason.values()).map(Enum::name)
			.collect(Collectors.toUnmodifiableSet());

	/**
	 * {@code JwtValidator}'s default maximum token length.
	 */
	private static final int MAXIMUM_TOKEN_LENGTH = Limits.COMPACT_JWT_SIZE.getDefaultIntValue();

	/**
	 * Every {@link JwsAlgorithm}: the effective set of a token whose {@code alg} names none.
	 */
	private static final Set<JwsAlgorithm> ALL_ALGORITHMS = Set.copyOf(EnumSet.allOf(JwsAlgorithm.class));

	/**
	 * The members that hold private or symmetric key material (RFC 7518 sections 6.2.2, 6.3.2 and 6.4.1).
	 */
	private static final List<String> PRIVATE_MEMBERS = List.of("d", "p", "q", "dp", "dq", "qi", "oth", "k");

	/**
	 * The keys each group's verification key set skips, as {@code <index> <reason>}, by the group's file and tcIds; a
	 * group not listed skips none (INV-J3, M2-7, and exit criterion 3's JWK tcIds 7, 8, 9 and 22).
	 */
	private static final Map<String, List<String>> SKIPS = Map.ofEntries(
			Map.entry("json_web_signature_test.json tcIds 1-17", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_signature_test.json tcIds 347-347", List.of("0 UNSUPPORTED_ALGORITHM")),
			Map.entry("json_web_signature_test.json tcIds 348-348", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_signature_test.json tcIds 351-351", List.of("0 UNSUPPORTED_ALGORITHM")),
			Map.entry("json_web_signature_test.json tcIds 352-352", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_signature_test.json tcIds 353-353", List.of("0 NOT_A_VERIFICATION_KEY")),
			Map.entry("json_web_signature_test.json tcIds 354-354", List.of("0 NOT_A_VERIFICATION_KEY")),
			Map.entry("json_web_signature_test.json tcIds 355-355", List.of("0 NOT_A_VERIFICATION_KEY")),
			Map.entry("json_web_signature_test.json tcIds 356-356", List.of("0 NOT_A_VERIFICATION_KEY")),
			Map.entry("json_web_signature_test.json tcIds 357-377", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 1-1", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 2-3", List.of("0 SYMMETRIC_KEY", "1 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 4-4", List.of("0 SYMMETRIC_KEY", "1 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 6-6", List.of("0 NOT_A_VERIFICATION_KEY")),
			Map.entry("json_web_key_test.json tcIds 7-7", List.of("0 WEAK_KEY")),
			Map.entry("json_web_key_test.json tcIds 8-8", List.of("0 RSA_KEY_SIZE")),
			Map.entry("json_web_key_test.json tcIds 9-9", List.of("0 RSA_EXPONENT")),
			Map.entry("json_web_key_test.json tcIds 10-10", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 11-11", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 12-12", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 13-13", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 14-14", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 15-15", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 16-16", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 17-17", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 18-18", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 19-19", List.of("0 UNSUPPORTED_ALGORITHM")),
			Map.entry("json_web_key_test.json tcIds 20-20", List.of("0 UNSUPPORTED_ALGORITHM")),
			Map.entry("json_web_key_test.json tcIds 21-21", List.of("0 NOT_A_VERIFICATION_KEY")),
			Map.entry("json_web_key_test.json tcIds 22-22", List.of("0 EC_POINT_NOT_ON_CURVE")),
			Map.entry("json_web_key_test.json tcIds 23-23", List.of("0 ALGORITHM_MISMATCH")),
			Map.entry("json_web_key_test.json tcIds 24-24", List.of("0 ALGORITHM_MISMATCH")),
			Map.entry("json_web_key_test.json tcIds 25-25", List.of("0 SYMMETRIC_KEY")),
			Map.entry("json_web_key_test.json tcIds 26-26", List.of("0 SYMMETRIC_KEY")));

	/**
	 * How many keys the key-set-only path skips in each file, by reason, over every group's key set: the skips among
	 * the group's {@code public} keys, plus its {@code private} keys as Wycheproof writes them, each skipped for its
	 * private or symmetric member where it has one.
	 */
	private static final Map<String, Map<JsonWebKeySkipReason, Integer>> KEY_SET_ONLY_SKIPS = Map.of(
			"json_web_key_test.json", Map.of(
					JsonWebKeySkipReason.SYMMETRIC_KEY, 16,
					JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS, 11,
					JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY, 2,
					JsonWebKeySkipReason.UNSUPPORTED_ALGORITHM, 2,
					JsonWebKeySkipReason.ALGORITHM_MISMATCH, 2,
					JsonWebKeySkipReason.RSA_KEY_SIZE, 1,
					JsonWebKeySkipReason.RSA_EXPONENT, 1,
					JsonWebKeySkipReason.EC_POINT_NOT_ON_CURVE, 1,
					JsonWebKeySkipReason.WEAK_KEY, 1),
			"json_web_signature_test.json", Map.of(
					JsonWebKeySkipReason.SYMMETRIC_KEY, 4,
					JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS, 19,
					JsonWebKeySkipReason.NOT_A_VERIFICATION_KEY, 4,
					JsonWebKeySkipReason.UNSUPPORTED_ALGORITHM, 2));

	/**
	 * Each file's outcome counts through the key-set-only path, on every JDK.
	 */
	private static final Map<String, Map<String, Integer>> KEY_SET_ONLY_COUNTS = Map.of(
			"json_web_key_test.json", Map.of(
					"accept", 1,
					"reject:SIGNATURE_MALFORMED", 1,
					"reject:UNKNOWN_KEY", 24),
			"json_web_signature_test.json", Map.of(
					"accept", 32,
					"reject:ALGORITHM_NOT_ALLOWED", 5,
					"reject:JSON_SERIALIZATION", 1,
					"reject:KEY_ALGORITHM_MISMATCH", 8,
					"reject:SIGNATURE_MALFORMED", 26,
					"reject:SIGNATURE_MISMATCH", 269,
					"reject:TOKEN_SYNTAX", 37,
					"reject:UNKNOWN_KEY", 22,
					"reject:UNTRUSTED_KEY_REFERENCE", 1));

	// ---------------------------------------------------------------------------------------------------------------
	// The vendored files and the manifest
	// ---------------------------------------------------------------------------------------------------------------

	// Plan M2-9: the vendored tree passes its own checks (the manifest first), and the expectation manifest passes
	// every staleness check, before any vector runs. Each factory below loads both the same way first.
	@Test
	void checksTheVendoredFilesAndTheManifestBeforeAnyVectorRuns() {
		Run run = Run.load();

		Assertions.assertEquals(FILES, run.files.stream().map(VectorFile::getName).collect(Collectors.toSet()));
		Assertions.assertEquals(427, run.files.stream().mapToInt(VectorFile::getNumberOfTests).sum());
	}

	// Plan M2-9 and exit criterion 3: each vector's outcome through the JWS layer is the one the manifest records.
	// Every invalid vector is rejected except JWS tcIds 367 and 370 (upstream defects); every valid one is accepted
	// except JWS 346 and 350 (KEY_ALGORITHM_MISMATCH), 347 and 351 (UNKNOWN_KEY; the key's alg ES521 is no JWS
	// algorithm, so the key is skipped) under INV-J3, and 372 and 373 (TOKEN_SYNTAX; INV-J7); JWK tcIds 1 and 4 are
	// n/a on the HMAC route.
	@TestFactory
	Stream<DynamicContainer> runsEveryVectorAsTheManifestExpects() {
		Run run = Run.load();
		int feature = Runtime.version().feature();

		return run.files.stream().map(file -> DynamicContainer.dynamicContainer(file.getName(),
				file.getGroups().stream().flatMap(group -> {
					GroupKeys keys = GroupKeys.of(group);
					return group.getTests().stream().map(vector -> DynamicTest.dynamicTest(vector.toString(), () -> {
						String expected = run.expectations.outcomeFor(file.getName(), vector.getTcId(), feature);
						String observed = observe(vector, keys);

						Assertions.assertTrue(Expectations.satisfies(expected, observed), () -> vector + ": the manifest "
								+ "expects " + expected + " on JDK " + feature + ", but the outcome is " + observed);
					}));
				})));
	}

	// Plan M2-9 and exit criterion 3 (INV-J2, INV-J3): through a key set that also holds every private and symmetric
	// key as Wycheproof writes it, each vector has the outcome of the JWS-layer run, except that every token the HMAC
	// engine took is rejected, JWK tcIds 1 and 4 included.
	@TestFactory
	Stream<DynamicContainer> everyVectorAlsoRunsThroughTheKeySetOnlyPath() {
		Run run = Run.load();

		return run.files.stream().map(file -> DynamicContainer.dynamicContainer(file.getName(),
				file.getGroups().stream().flatMap(group -> {
					GroupKeys keys = GroupKeys.of(group);
					return group.getTests().stream().map(vector -> DynamicTest.dynamicTest(vector.toString(), () -> {
						String observed = observe(vector, keys);
						String keySetOnly = observeKeySetOnly(vector, keys);

						if (usesTheHmacEngine(vector))
							Assertions.assertTrue(keySetOnly.startsWith(Expectations.REJECT), () -> vector + ": a key set never "
									+ "verifies an HS* token, but the outcome is " + keySetOnly);
						else
							Assertions.assertEquals(observed, keySetOnly, () -> vector + ": the private and symmetric keys "
									+ "change nothing");
					}));
				})));
	}

	// Plan M2-9: the per-file outcome counts in the manifest's #count lines hold on this JDK, reason by reason, and so
	// do the key-set-only path's counts pinned here.
	@Test
	void eachFilesOutcomeCountsAreTheManifestsOnThisJdk() {
		Run run = Run.load();
		int feature = Runtime.version().feature();
		List<String> mismatches = new ArrayList<>();
		Map<String, Map<String, Integer>> keySetOnlyCounts = new TreeMap<>();

		for (VectorFile file : run.files) {
			SortedMap<String, Integer> counts = new TreeMap<>();
			SortedMap<String, Integer> keySetOnly = new TreeMap<>();

			for (TestGroup group : file.getGroups()) {
				GroupKeys keys = GroupKeys.of(group);

				for (TestVector vector : group.getTests()) {
					counts.merge(observe(vector, keys), 1, Integer::sum);
					keySetOnly.merge(observeKeySetOnly(vector, keys), 1, Integer::sum);
				}
			}

			if (!counts.equals(run.expectations.pinnedCounts(file.getName(), feature)))
				mismatches.add(Expectations.countLine(file.getName(), feature, counts));

			keySetOnlyCounts.put(file.getName(), keySetOnly);
		}

		Assertions.assertEquals(List.of(), mismatches, "the observed counts on JDK " + feature + ", as #count lines");
		Assertions.assertEquals(new TreeMap<>(KEY_SET_ONLY_COUNTS), keySetOnlyCounts, "the key-set-only path's counts");
	}

	// INV-J3, M2-7 and exit criterion 3: each group's verification key set skips exactly its pinned keys, with their
	// reasons (JWK tcId 7 through WEAK_KEY, 8 RSA_KEY_SIZE, 9 RSA_EXPONENT, 22 EC_POINT_NOT_ON_CURVE), and the public
	// JsonWebKeySet.fromJson keeps the same keys. The key-set-only path skips every key with a private or symmetric
	// member (INV-J2, INV-J3), for that reason, and keeps the same usable keys; its skips per file are pinned too.
	@Test
	void eachGroupsKeySetSkipsExactlyItsPinnedKeys() {
		Map<String, List<String>> skips = new TreeMap<>();
		Map<String, Map<JsonWebKeySkipReason, Integer>> keySetOnlySkips = new TreeMap<>();

		for (VectorFile file : Run.load().files)
			for (TestGroup group : file.getGroups()) {
				GroupKeys keys = GroupKeys.of(group);
				String name = groupName(group);

				for (ParsedKeySet.Skip skip : keys.keySetOnly.skips())
					keySetOnlySkips.computeIfAbsent(file.getName(), fileName -> new TreeMap<>()).merge(skip.reason(), 1,
							Integer::sum);

				if (!keys.verification.skips().isEmpty())
					skips.put(name, skips(keys.verification));

				List<JsonWebKey> publicKeys = JsonWebKeySet.fromJson(keys.verificationJson).getKeys();
				Assertions.assertEquals(thumbprints(keys.verification.keys()), publicKeys.stream()
						.map(key -> key.getKeyId().orElse("") + " " + key.getThumbprintSha256()).toList(),
						() -> name + ": JsonWebKeySet.fromJson keeps the same keys");

				Assertions.assertEquals(thumbprints(keys.verification.keys()), thumbprints(keys.keySetOnly.keys()),
						() -> name + ": the key-set-only path keeps the same usable keys");

				Map<Integer, JsonWebKeySkipReason> skipped = keys.keySetOnly.skips().stream()
						.collect(Collectors.toMap(ParsedKeySet.Skip::index, ParsedKeySet.Skip::reason));

				for (int index = 0; index < keys.keySetOnlyKeys.size(); ++index) {
					JsonObject jwk = keys.keySetOnlyKeys.get(index);
					int keyIndex = index;

					if (PRIVATE_MEMBERS.stream().anyMatch(member -> jwk.find(member).isPresent()))
						Assertions.assertEquals(isSymmetric(jwk) ? JsonWebKeySkipReason.SYMMETRIC_KEY
										: JsonWebKeySkipReason.PRIVATE_KEY_MEMBERS, skipped.get(index),
								() -> name + ": the key-set-only path's key " + keyIndex);
				}
			}

		Assertions.assertEquals(new TreeMap<>(SKIPS), skips);
		Assertions.assertEquals(new TreeMap<>(KEY_SET_ONLY_SKIPS), keySetOnlySkips);
	}

	// Plan M2-9: JWS tcIds 367 and 370 are marked invalid (padding), but an upstream format change lost the padding,
	// so each is byte-identical to the valid tcId 357. The manifest accepts them as upstream defects.
	@Test
	void theTwoUpstreamDefectsAreByteIdenticalToAValidVector() {
		VectorFile file = Run.load().file("json_web_signature_test.json");
		String valid = file.getTest(357).getString("jws");

		Assertions.assertEquals(Result.VALID, file.getTest(357).getResult());

		for (int tcId : new int[]{367, 370}) {
			Assertions.assertEquals(Result.INVALID, file.getTest(tcId).getResult());
			Assertions.assertEquals(valid, file.getTest(tcId).getString("jws"), () -> "tcId " + tcId);
		}
	}

	// M2-9 and G8-2: the effective set is the token's own alg when it names a JwsAlgorithm, and every algorithm
	// otherwise, including a header that does not decode. So an RSA key without alg would serve each RSA token's own
	// algorithm, one at a time, while P4 decides as it would under the full set.
	@Test
	void theEffectiveAlgorithmSetIsTheTokensOwnAlgorithm() {
		VectorFile file = Run.load().file("json_web_signature_test.json");

		Assertions.assertEquals(Set.of(JwsAlgorithm.RS256), effectiveAlgorithms(file.getTest(345).getString("jws")));
		Assertions.assertEquals(Set.of(JwsAlgorithm.PS384), effectiveAlgorithms(file.getTest(346).getString("jws")));
		Assertions.assertEquals(ALL_ALGORITHMS, effectiveAlgorithms(Base64Url.encode(utf8("{\"alg\":\"none\"}"))
				+ ".e30."));
		Assertions.assertEquals(ALL_ALGORITHMS, effectiveAlgorithms(Base64Url.encode(utf8("{\"alg\":\"rs256\"}"))
				+ ".e30."));
		Assertions.assertEquals(ALL_ALGORITHMS, effectiveAlgorithms(Base64Url.encode(utf8("{\"alg\":256}")) + ".e30."));
		Assertions.assertEquals(ALL_ALGORITHMS, effectiveAlgorithms("e?J.e30."));
		Assertions.assertEquals(ALL_ALGORITHMS, effectiveAlgorithms("{\"payload\":\"e30\"}"));
		Assertions.assertEquals(14, ALL_ALGORITHMS.size());
	}

	// INV-J3 and RFC 7518 section 3.2 on the HMAC route, which the vendored keys decide only in part (each has use sig
	// and an HS* or AES alg): the secret is configured only from the one symmetric key with the token's kid whose use,
	// key_ops and alg allow the token's algorithm, and only when it is long enough. Two secrets for one token, or a
	// key set that mixes key types, are not applicable. JWS tcId 357 (HS256, kid hs256-key) is the token.
	@Test
	void theHmacRouteConfiguresOnlyASecretThatInvJ3Allows() throws Exception {
		TestVector vector = Run.load().file("json_web_signature_test.json").getTest(357);
		PreparedJws prepared = prepare(vector.getString("jws"));
		JsonObject key = vector.getGroup().getObject("private");
		String k = key.findString("k").orElseThrow();

		Assertions.assertEquals(Expectations.ACCEPT, verifyWithSecret(prepared, List.of(key)));
		Assertions.assertEquals(Expectations.ACCEPT, verifyWithSecret(prepared, List.of(without(key, "alg"))));
		Assertions.assertEquals(Expectations.ACCEPT, verifyWithSecret(prepared, List.of(without(key, "use"))));
		Assertions.assertEquals(Expectations.ACCEPT, verifyWithSecret(prepared, List.of(with(key, "key_ops",
				"[\"verify\"]"))));
		Assertions.assertEquals(Expectations.ACCEPT, verifyWithSecret(prepared, List.of(with(key, "key_ops",
				"[\"sign\",\"verify\"]"))));
		Assertions.assertEquals(Expectations.ACCEPT, verifyWithSecret(prepared, List.of(with(key, "kid", "\"other\""),
				key)));

		String unknownKey = reject(JoseException.Reason.UNKNOWN_KEY);
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of()));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "kid", "\"other\""))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(without(key, "kid"))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "use", "\"enc\""))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "use", "[\"sig\"]"))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "key_ops", "[\"sign\"]"))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "key_ops", "\"verify\""))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "key_ops", "[\"verify\",1]"))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "key_ops",
				"[\"verify\",\"encrypt\"]"))));
		Assertions.assertEquals(Expectations.ACCEPT, verifyWithSecret(prepared, List.of(without(with(key, "key_ops",
				"[\"verify\",\"encrypt\"]"), "use"))), "only alongside use are other operations refused");
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "alg", "\"A256GCM\""))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "alg", "\"RS256\""))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "alg", "256"))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "k", "\"" + k + "=\""))));
		Assertions.assertEquals(unknownKey, verifyWithSecret(prepared, List.of(with(key, "k", "\""
				+ Base64Url.encode(Arrays.copyOf(Base64Url.decode(k), 31)) + "\""))), "a 31-octet secret");
		Assertions.assertEquals(reject(JoseException.Reason.KEY_ALGORITHM_MISMATCH), verifyWithSecret(prepared,
				List.of(with(key, "alg", "\"HS384\""))));
		byte[] otherSecret = Base64Url.decode(k);
		otherSecret[0] ^= 1;
		Assertions.assertEquals(reject(JoseException.Reason.SIGNATURE_MISMATCH), verifyWithSecret(prepared,
				List.of(with(key, "k", "\"" + Base64Url.encode(otherSecret) + "\""))), "another secret");

		Assertions.assertEquals(Expectations.NOT_APPLICABLE, verifyWithSecret(prepared, List.of(key, key)));
		Assertions.assertEquals(Expectations.NOT_APPLICABLE, verifyWithSecret(prepared, List.of(key,
				Run.load().file("json_web_signature_test.json").getTest(18).getGroup().getObject("public"))));
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Running a vector
	// ---------------------------------------------------------------------------------------------------------------

	/**
	 * A vector's outcome through the JWS layer: {@code accept}, {@code reject:<Reason>} or {@code n/a}.
	 */
	private static String observe(TestVector vector,
																GroupKeys keys) {
		return run(vector, prepared -> isHmac(prepared) ? verifyWithSecret(prepared, keys.privateKeys)
				: verify(prepared, keys.verification));
	}

	/**
	 * A vector's outcome through the key-set-only path: public, private and symmetric keys, and no secret.
	 */
	private static String observeKeySetOnly(TestVector vector,
																					GroupKeys keys) {
		return run(vector, prepared -> verify(prepared, keys.keySetOnly));
	}

	/**
	 * Steps 1 to 5, then the rest of a path. Anything but a {@link JoseFailure} thrown fails the test (INV-G1).
	 */
	private static String run(TestVector vector,
														Function<PreparedJws, String> path) {
		try {
			PreparedJws prepared;

			try {
				prepared = prepare(vector.getString("jws"));
			} catch (JoseFailure failure) {
				return reject(failure.getReason());
			}

			return path.apply(prepared);
		} catch (RuntimeException exception) {
			throw new AssertionError(vector + ": the JWS layer threw " + exception.getClass().getName() + " (INV-G1)",
					exception);
		}
	}

	/**
	 * Whether the JWS-layer run sends the vector to the HMAC engine: steps 1 to 5 pass, and its algorithm is
	 * {@code HS*}.
	 */
	private static boolean usesTheHmacEngine(TestVector vector) {
		try {
			return isHmac(prepare(vector.getString("jws")));
		} catch (JoseFailure failure) {
			return false;
		}
	}

	/**
	 * Steps 1 to 5 under the token's effective algorithm set and {@code JwtValidator}'s default length and types.
	 */
	private static PreparedJws prepare(String jws) throws JoseFailure {
		return JwtProcessor.prepare(jws, JoseHeaderPolicy.fromSettings(MAXIMUM_TOKEN_LENGTH, effectiveAlgorithms(jws),
				Set.of("JWT"), false));
	}

	private static boolean isHmac(PreparedJws prepared) {
		return Algorithms.familyOf(prepared.getAlgorithm()) == Algorithms.Family.HMAC;
	}

	/**
	 * Steps 6 and 7 with a key selected from a parsed key set.
	 */
	private static String verify(PreparedJws prepared,
															 ParsedKeySet keySet) {
		try {
			JwtProcessor.verify(prepared, KeySelector.select(keySet.keys(), prepared.getKeyQuery()));
			return Expectations.ACCEPT;
		} catch (JoseFailure failure) {
			return reject(failure.getReason());
		}
	}

	/**
	 * Step 7 over a configured HMAC secret: the {@code k} of the group's one symmetric key for the token, once INV-J3's
	 * checks pass (see the class documentation).
	 */
	private static String verifyWithSecret(PreparedJws prepared,
																				 List<JsonObject> privateKeys) {
		List<JsonObject> symmetric = privateKeys.stream().filter(WycheproofJoseTests::isSymmetric).toList();

		// A key set of symmetric and asymmetric keys together is no single configured secret.
		if (!symmetric.isEmpty() && symmetric.size() < privateKeys.size())
			return Expectations.NOT_APPLICABLE;

		Optional<String> keyId = prepared.findKeyId();
		List<JsonObject> candidates = symmetric.stream()
				.filter(jwk -> keyId.isEmpty() || jwk.findString("kid").equals(keyId)).toList();

		// Two secrets for one token: which one is configured is key-set semantics.
		if (candidates.size() > 1)
			return Expectations.NOT_APPLICABLE;
		if (candidates.isEmpty() || !allowsVerification(candidates.get(0)))
			return reject(JoseException.Reason.UNKNOWN_KEY);

		JsonObject jwk = candidates.get(0);
		Optional<JsonValue> alg = jwk.find("alg");

		if (alg.isPresent()) {
			Optional<JwsAlgorithm> algorithm = alg.get() instanceof JsonString string
					? JwsAlgorithm.findByWireValue(string.getValue()) : Optional.empty();

			// Like the key set parser: an alg that names no HMAC algorithm makes the key unusable, and another HMAC
			// algorithm is a key for another algorithm.
			if (algorithm.isEmpty() || Algorithms.familyOf(algorithm.get()) != Algorithms.Family.HMAC)
				return reject(JoseException.Reason.UNKNOWN_KEY);
			if (algorithm.get() != prepared.getAlgorithm())
				return reject(JoseException.Reason.KEY_ALGORITHM_MISMATCH);
		}

		byte[] secret;

		try {
			secret = Base64Url.decode(jwk.findString("k").orElse("?"));
		} catch (EncodingException exception) {
			return reject(JoseException.Reason.UNKNOWN_KEY);
		}

		try {
			JwtProcessor.verifyWithSecret(prepared, secret);
			return Expectations.ACCEPT;
		} catch (JoseFailure failure) {
			return reject(failure.getReason());
		} catch (IllegalArgumentException exception) {
			// The engine refuses a secret shorter than the hash output (RFC 7518 section 3.2), and for no other reason
			// here, so the secret is never configured and the token has no key.
			HashAlgorithm hash = Algorithms.findHash(prepared.getAlgorithm()).orElseThrow();
			Assertions.assertThrows(KeyRejectedException.class, () -> Hmac.checkSecretLength(hash, secret));
			return reject(JoseException.Reason.UNKNOWN_KEY);
		}
	}

	/**
	 * INV-J3's use checks on a JWK, as the key set parser applies them (RFC 7517 sections 4.2 and 4.3): {@code use},
	 * when present, is {@code sig}; {@code key_ops}, when present, is an array of strings with {@code verify} and,
	 * alongside {@code use}, nothing but {@code sign} and {@code verify}.
	 */
	private static boolean allowsVerification(JsonObject jwk) {
		Optional<JsonValue> use = jwk.find("use");

		if (use.isPresent() && !use.get().equals(JsonString.fromValue("sig")))
			return false;

		Optional<JsonValue> keyOperations = jwk.find("key_ops");

		if (keyOperations.isEmpty())
			return true;
		if (!(keyOperations.get() instanceof JsonArray operations)
				|| !operations.getElements().stream().allMatch(element -> element instanceof JsonString))
			return false;

		List<String> names = operations.getElements().stream().map(element -> ((JsonString) element).getValue()).toList();
		return names.contains("verify") && (use.isEmpty() || names.stream().allMatch(name -> name.equals("sign")
				|| name.equals("verify")));
	}

	/**
	 * The token's own {@code alg} when it names a {@link JwsAlgorithm}, and every algorithm otherwise (M2-9). A header
	 * that does not decode leaves the full set, which is then never consulted: the parser refuses the token first.
	 */
	private static Set<JwsAlgorithm> effectiveAlgorithms(String jws) {
		int dot = jws.indexOf('.');

		try {
			JsonValue header = JsonCodec.parse(Base64Url.decode(dot < 0 ? jws : jws.substring(0, dot)),
					JsonLimits.jose(MAXIMUM_TOKEN_LENGTH));

			if (header instanceof JsonObject object && object.getMembers().get("alg") instanceof JsonString alg)
				return JwsAlgorithm.findByWireValue(alg.getValue()).map(Set::of).orElse(ALL_ALGORITHMS);
		} catch (EncodingException | JsonParseException exception) {
			// The full set.
		}

		return ALL_ALGORITHMS;
	}

	private static String reject(JoseException.Reason reason) {
		return Expectations.REJECT + reason.name();
	}

	private static boolean isSymmetric(JsonObject jwk) {
		return jwk.findString("kty").equals(Optional.of(Algorithms.OCT_KEY_TYPE));
	}

	private static List<String> skips(ParsedKeySet keySet) {
		return keySet.skips().stream().map(skip -> skip.index() + " " + skip.reason().name()).toList();
	}

	private static List<String> thumbprints(List<VerificationKey> keys) {
		return keys.stream().map(key -> Optional.ofNullable(key.keyId()).orElse("") + " " + key.thumbprintSha256())
				.toList();
	}

	/**
	 * A group's name in pins and messages: its file and the tcIds of its tests.
	 */
	private static String groupName(TestGroup group) {
		List<TestVector> tests = group.getTests();
		return group.getFile().getName() + " tcIds " + tests.get(0).getTcId() + "-" + tests.get(tests.size() - 1)
				.getTcId();
	}

	/**
	 * A JWK with one member set to a JSON value, replacing any it had.
	 */
	private static JsonObject with(JsonObject jwk,
																 String name,
																 String json) throws JsonParseException {
		Map<String, JsonValue> members = new LinkedHashMap<>(jwk.getMembers());
		members.put(name, JsonCodec.parse(utf8(json), JsonLimits.jose(MAXIMUM_TOKEN_LENGTH)));
		return JsonObject.fromMembers(members);
	}

	/**
	 * A JWK without one member.
	 */
	private static JsonObject without(JsonObject jwk,
																		String name) {
		Map<String, JsonValue> members = new LinkedHashMap<>(jwk.getMembers());
		Assertions.assertNotNull(members.remove(name), name);
		return JsonObject.fromMembers(members);
	}

	private static byte[] utf8(String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * A group's keys: the verification key set of the JWS-layer run, the key-set-only path's key set, and the
	 * {@code private} keys the HMAC engine takes its secret from.
	 */
	private static final class GroupKeys {
		private final List<JsonObject> privateKeys;
		private final String verificationJson;
		private final ParsedKeySet verification;
		private final List<JsonObject> keySetOnlyKeys;
		private final ParsedKeySet keySetOnly;

		private GroupKeys(List<JsonObject> privateKeys,
											String verificationJson,
											ParsedKeySet verification,
											List<JsonObject> keySetOnlyKeys,
											ParsedKeySet keySetOnly) {
			this.privateKeys = privateKeys;
			this.verificationJson = verificationJson;
			this.verification = verification;
			this.keySetOnlyKeys = keySetOnlyKeys;
			this.keySetOnly = keySetOnly;
		}

		static GroupKeys of(TestGroup group) {
			List<JsonObject> privateKeys = keys(group.getObject("private"));
			List<JsonObject> publicKeys = group.findObject("public").map(GroupKeys::keys).orElse(List.of());
			List<JsonObject> verificationKeys = group.findObject("public").isPresent() ? publicKeys
					: privateKeys.stream().map(GroupKeys::withoutPrivateMembers).toList();
			List<JsonObject> keySetOnlyKeys = Stream.concat(publicKeys.stream(), privateKeys.stream()).toList();
			String verificationJson = keySet(verificationKeys);

			return new GroupKeys(privateKeys, verificationJson, parse(group, verificationJson), keySetOnlyKeys,
					parse(group, keySet(keySetOnlyKeys)));
		}

		/**
		 * The keys of a {@code public} or {@code private} member: a JWK Set's {@code keys}, or one JWK.
		 */
		private static List<JsonObject> keys(JsonObject member) {
			if (!(member.find("keys").orElse(null) instanceof JsonArray keys))
				return List.of(member);

			return keys.getElements().stream().map(key -> (JsonObject) key).toList();
		}

		private static JsonObject withoutPrivateMembers(JsonObject jwk) {
			JsonObject.Builder builder = JsonObject.builder();
			jwk.getMembers().forEach((name, value) -> {
				if (!PRIVATE_MEMBERS.contains(name))
					builder.put(name, value);
			});
			return builder.build();
		}

		private static String keySet(List<JsonObject> keys) {
			return JsonObject.builder().put("keys", JsonArray.fromElements(keys)).build().toJson();
		}

		/**
		 * The real key set parser, at {@code JsonWebKeySet.fromJson}'s limits; no vendored key set is a document
		 * failure.
		 */
		private static ParsedKeySet parse(TestGroup group,
																			String keySet) {
			try {
				return JwkSetParser.parse(keySet, Limits.JWKS_RESPONSE_BODY_SIZE.getDefaultIntValue(),
						Limits.JWKS_KEY_COUNT.getDefaultIntValue());
			} catch (JoseFailure failure) {
				throw new AssertionError(group + ": the key set is a document failure, " + failure.getReason(), failure);
			}
		}
	}

	/**
	 * The vendored files this runner runs and the manifest, both checked.
	 */
	private static final class Run {
		private final List<VectorFile> files;
		private final Expectations expectations;

		private Run(List<VectorFile> files,
								Expectations expectations) {
			this.files = files;
			this.expectations = expectations;
		}

		static Run load() {
			List<VectorFile> files = WycheproofVectors.fromVendoredFiles().getFiles().stream()
					.filter(file -> FILES.contains(file.getName())).toList();
			SortedMap<String, List<Expectations.Vector>> vectors = new TreeMap<>();

			for (VectorFile file : files)
				vectors.put(file.getName(), file.getTests().stream().map(vector -> new Expectations.Vector(vector.getTcId(),
						vector.getResult(), Set.of())).toList());

			return new Run(files, Expectations.fromManifest(MANIFEST, Expectations.read(WycheproofJoseTests.class,
					MANIFEST), vectors, CODES, Set.of()));
		}

		VectorFile file(String name) {
			return this.files.stream().filter(file -> file.getName().equals(name)).findFirst().orElseThrow();
		}
	}
}
