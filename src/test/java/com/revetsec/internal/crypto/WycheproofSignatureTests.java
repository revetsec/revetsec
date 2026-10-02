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

package com.revetsec.internal.crypto;

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.json.JsonObject;
import com.revetsec.testing.WycheproofVectors;
import com.revetsec.testing.WycheproofVectors.Result;
import com.revetsec.testing.WycheproofVectors.TestGroup;
import com.revetsec.testing.WycheproofVectors.TestVector;
import com.revetsec.testing.WycheproofVectors.VectorFile;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;

/**
 * Project Wycheproof through the signature and MAC primitives (plan M2-9 and M2 exit criterion 3): every vector of the
 * 26 vendored ECDSA (IEEE P1363, the curve with the hash JOSE pairs it with), RSASSA-PKCS1-v1_5, RSASSA-PSS, Ed25519
 * and HMAC files, run through {@link SignatureVerifier} and {@link Hmac#verifyTag}. Keys are built by
 * {@link EcPublicKeys}, {@link RsaPublicKeys} and {@link Ed25519PublicKeys}, so the key policy applies as it does to
 * every key Revetsec loads: a group whose key the policy refuses rejects each of its vectors with that
 * {@link KeyRejectedException.Kind}. The two JOSE files run in {@code internal.jose.WycheproofJoseTests}, so every
 * vendored file runs in exactly one runner.
 * <p>
 * <strong>What each vector runs.</strong> ECDSA verifies {@code r || s} on the group's curve with its hash, after the
 * exact length and the range of {@code r} and {@code s} (G8-3). RSASSA-PSS runs with the parameters RFC 7518
 * section 3.5 fixes for the group's hash (MGF1 with the same hash, a salt as long as the hash output), never the
 * file's {@code mgfSha} or {@code sLen}, and a group whose hash JOSE does not use is not applicable. HMAC verifies the
 * full-length tag under the RFC 7518 section 3.2 secret rule. The runner reads each key from the group's
 * {@code publicKey} and checks that the group's JWK, where it has one, holds the same key. It also names the JCA
 * provider that serves each algorithm, so a run on another provider describes itself.
 * <p>
 * <strong>Expectations.</strong> Each vector's outcome is {@code accept}, {@code reject:<code>} with a
 * {@link VerifyResult} or {@link KeyRejectedException.Kind} name, or {@code n/a}, and it must be the one the
 * expectation manifest {@code EXPECTATIONS.tsv} (in this package's {@code wycheproof} test resources) records for this
 * JDK: by default {@code accept} for a {@code valid} vector and any rejection for an {@code invalid} one, with a line
 * for every exception and every {@code acceptable} vector. {@link Expectations} documents the format and the staleness
 * checks, which fail the build before any vector runs; the JOSE runner shares them. The per-file outcome counts are
 * pinned in the manifest's {@code #count} lines, so a vector rejected for another reason than before fails the build
 * even where no line names it.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
public final class WycheproofSignatureTests {
	/**
	 * The manifest, relative to the module root.
	 */
	private static final String MANIFEST = "src/test/resources/com/revetsec/internal/crypto/wycheproof/EXPECTATIONS.tsv";

	/**
	 * The vendored files the JOSE runner runs instead of this one.
	 */
	private static final Set<String> JOSE_FILES = Set.of("json_web_key_test.json", "json_web_signature_test.json");

	/**
	 * The reason codes this runner reports: every {@link VerifyResult} but {@code VALID}, and every
	 * {@link KeyRejectedException.Kind}.
	 */
	private static final Set<String> CODES = Stream.concat(
					Arrays.stream(VerifyResult.values()).filter(result -> result != VerifyResult.VALID).map(Enum::name),
					Arrays.stream(KeyRejectedException.Kind.values()).map(Enum::name))
			.collect(Collectors.toUnmodifiableSet());

	/**
	 * The hashes JOSE uses, by the name the vector files give them.
	 */
	private static final Map<String, HashAlgorithm> JOSE_HASHES = Arrays.stream(HashAlgorithm.values())
			.collect(Collectors.toUnmodifiableMap(HashAlgorithm::getDigestName, hash -> hash));

	/**
	 * M2-7's floor for an RSA public exponent. It is written here rather than read from {@link RsaPublicKeys}, so the
	 * {@code small-public-exponent} rule stays independent of the code under test: a lowered floor shows as those
	 * vectors accepted, not as a rule that selects nothing.
	 */
	private static final BigInteger MINIMUM_PUBLIC_EXPONENT = BigInteger.valueOf(65_537);

	/**
	 * The closed rule set (plan M2-9): each rule is a predicate over a group, and it selects every vector of the groups
	 * it matches.
	 */
	private static final Map<String, Predicate<TestGroup>> RULES = Map.of(
			// RFC 7518 section 3.5: PS* fixes MGF1 with the same hash and a salt as long as the hash output.
			"pss-params-not-jose", group -> isPss(group) && JOSE_HASHES.containsKey(group.getString("sha"))
					&& !(group.getString("mgf").equals("MGF1") && group.getString("mgfSha").equals(group.getString("sha"))
					&& group.getInteger("sLen") == hash(group).getLength()),
			// SHA-1 and SHA-224 have no JOSE signature algorithm.
			"hash-not-jose", group -> group.findString("sha").filter(sha -> !JOSE_HASHES.containsKey(sha)).isPresent(),
			// RFC 7518 section 3.2: an HS* secret is at least as long as the hash output.
			"key-shorter-than-hash", group -> isMac(group) && group.getInteger("keySize") < macHash(group).getLength() * 8,
			// RFC 7518 section 3.2: an HS* tag is the full hash output (a secret long enough, so only the tag decides).
			"truncated-tag", group -> isMac(group) && group.getInteger("tagSize") < macHash(group).getLength() * 8
					&& group.getInteger("keySize") >= macHash(group).getLength() * 8,
			// M2-7: the public exponent is at least 65537, so e = 3 keys are refused.
			"small-public-exponent", group -> group.findObject("publicKey").flatMap(key -> key.findString("publicExponent"))
					.filter(exponent -> positive(exponent).compareTo(MINIMUM_PUBLIC_EXPONENT) < 0).isPresent());

	/**
	 * How many vectors each rule selects in each file, and how many of those are {@code valid}: the rules' predicates
	 * pinned against the vendored files (plan M2-9 and exit criterion 3).
	 */
	private static final Map<String, List<Integer>> RULE_SELECTIONS = Map.ofEntries(
			Map.entry("rsa_pss_misc_test.json pss-params-not-jose", List.of(87, 87)),
			Map.entry("rsa_pss_misc_test.json hash-not-jose", List.of(60, 60)),
			Map.entry("hmac_sha256_test.json key-shorter-than-hash", List.of(6, 6)),
			Map.entry("hmac_sha384_test.json key-shorter-than-hash", List.of(6, 6)),
			Map.entry("hmac_sha512_test.json key-shorter-than-hash", List.of(6, 6)),
			Map.entry("hmac_sha256_test.json truncated-tag", List.of(84, 30)),
			Map.entry("hmac_sha384_test.json truncated-tag", List.of(84, 30)),
			Map.entry("hmac_sha512_test.json truncated-tag", List.of(84, 30)),
			Map.entry("rsa_signature_2048_sha256_test.json small-public-exponent", List.of(2, 2)),
			Map.entry("rsa_signature_2048_sha512_test.json small-public-exponent", List.of(1, 1)),
			Map.entry("rsa_signature_3072_sha256_test.json small-public-exponent", List.of(1, 1)),
			Map.entry("rsa_signature_3072_sha512_test.json small-public-exponent", List.of(1, 1)));

	// ---------------------------------------------------------------------------------------------------------------
	// The vendored files and the manifest
	// ---------------------------------------------------------------------------------------------------------------

	// Plan M2-9: the vendored tree passes its own checks (the manifest first), and the expectation manifest passes
	// every staleness check, before any vector runs. Each factory below loads both the same way first.
	@Test
	void checksTheVendoredFilesAndTheManifestBeforeAnyVectorRuns() {
		Run run = Run.load();

		Assertions.assertEquals(26, run.files.size());
		Assertions.assertEquals(5_574, run.files.stream().mapToInt(VectorFile::getNumberOfTests).sum());
		Assertions.assertEquals(RULES.keySet(), Set.of("pss-params-not-jose", "hash-not-jose", "key-shorter-than-hash",
				"truncated-tag", "small-public-exponent"), "the closed rule set");
	}

	// Plan M2-9: every vendored file runs in exactly one runner, this one or the JOSE runner.
	@Test
	void everyVendoredFileRunsInExactlyOneRunner() {
		WycheproofVectors vectors = WycheproofVectors.fromVendoredFiles();
		Set<String> vendored = vectors.getFiles().stream().map(VectorFile::getName).collect(Collectors.toSet());
		Set<String> here = Run.load().files.stream().map(VectorFile::getName).collect(Collectors.toSet());

		Assertions.assertEquals(28, vendored.size());
		Assertions.assertTrue(vendored.containsAll(JOSE_FILES));
		Assertions.assertEquals(Collections.emptySet(), intersection(here, JOSE_FILES));

		Set<String> union = new HashSet<>(here);
		union.addAll(JOSE_FILES);
		Assertions.assertEquals(vendored, union);
	}

	// Plan M2-9 and exit criterion 3: each vector's outcome is the one the manifest records for this JDK. That covers
	// every invalid vector rejected, every valid one accepted except the listed exceptions (the JDK 17 ECDSA
	// x(R) >= n lines, the HMAC key-shorter-than-hash and truncated-tag groups of RFC 7518 section 3.2, the PSS-misc
	// parameters JOSE does not use, and the e = 3 keys of M2-7), and every acceptable vector (PKCS#1 MissingNull).
	@TestFactory
	@NonNull Stream<@NonNull DynamicContainer> runsEveryVectorAsTheManifestExpects() {
		Run run = Run.load();
		int feature = Runtime.version().feature();

		return run.files.stream().map(file -> DynamicContainer.dynamicContainer(file.getName(),
				file.getGroups().stream().flatMap(group -> {
					Setup setup = Setup.of(group);
					return group.getTests().stream().map(vector -> DynamicTest.dynamicTest(vector.toString(), () -> {
						String expected = run.expectations.outcomeFor(file.getName(), vector.getTcId(), feature);
						String observed = observe(setup, vector);

						Assertions.assertTrue(Expectations.satisfies(expected, observed), () -> vector + ": the manifest "
								+ "expects " + expected + " on JDK " + feature + ", but the outcome is " + observed);
					}));
				})));
	}

	// Plan M2-9: the per-file outcome counts in the manifest's #count lines hold on this JDK, reason by reason.
	@Test
	void eachFilesOutcomeCountsAreTheManifestsOnThisJdk() {
		Run run = Run.load();
		int feature = Runtime.version().feature();
		List<String> mismatches = new ArrayList<>();

		for (VectorFile file : run.files) {
			SortedMap<String, Integer> counts = new TreeMap<>();

			for (TestGroup group : file.getGroups()) {
				Setup setup = Setup.of(group);

				for (TestVector vector : group.getTests())
					counts.merge(observe(setup, vector), 1, Integer::sum);
			}

			if (!counts.equals(run.expectations.pinnedCounts(file.getName(), feature)))
				mismatches.add(Expectations.countLine(file.getName(), feature, counts));
		}

		Assertions.assertEquals(List.of(), mismatches, "the observed counts on JDK " + feature + ", as #count lines");
	}

	// Plan M2-9: each rule selects exactly its groups' vectors in exactly the files pinned here, so a predicate that
	// drifts (or a re-vendored file) fails even where the outcome would not change.
	@Test
	void eachRuleSelectsExactlyItsPinnedVectors() {
		Map<String, List<Integer>> selections = new TreeMap<>();

		for (VectorFile file : Run.load().files)
			for (Map.Entry<String, Predicate<TestGroup>> rule : RULES.entrySet()) {
				int selected = 0;
				int valid = 0;

				for (TestGroup group : file.getGroups())
					if (rule.getValue().test(group)) {
						selected += group.getTests().size();
						valid += (int) group.getTests().stream().filter(test -> test.getResult() == Result.VALID).count();
					}

				if (selected > 0)
					selections.put(file.getName() + " " + rule.getKey(), List.of(selected, valid));
			}

		Assertions.assertEquals(new TreeMap<>(RULE_SELECTIONS), selections);
	}

	// Plan M2-9 and exit criterion 3: Ed25519 tcId 37 is a valid signature with a zero octet appended, which JDK 17's
	// own verifier accepts (plan section 9.6). Revetsec refuses it on every JDK before the JCA sees it.
	@Test
	void anEd25519SignatureWithAnAppendedOctetIsTheWrongLengthOnEveryJdk() {
		VectorFile file = Run.load().file("ed25519_test.json");
		TestVector vector = file.getTest(37);
		Setup setup = Setup.of(vector.getGroup());
		byte[] signature = vector.getHexBytes("sig");

		Assertions.assertEquals(Result.INVALID, vector.getResult());
		Assertions.assertEquals(65, signature.length);
		Assertions.assertEquals(0, signature[64]);
		Assertions.assertEquals(Expectations.REJECT + VerifyResult.WRONG_LENGTH.name(), observe(setup, vector));
		Assertions.assertEquals(VerifyResult.VALID, SignatureVerifier.verifyEd25519(setup.requireKey(),
				vector.getHexBytes("msg"), Arrays.copyOf(signature, 64)), "without the appended octet it verifies");
	}

	// Plan M2-9 (the runner prints the provider that served each algorithm) and the risks section: the JCA provider
	// behind every algorithm the runner uses is named, so a run on another provider describes itself. Each test's
	// display name carries the provider, and each is printed.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> namesTheProviderThatServesEachAlgorithm() {
		Map<String, Provider> providers = new LinkedHashMap<>();

		for (VectorFile file : Run.load().files) {
			for (TestGroup group : file.getGroups()) {
				Setup setup = Setup.of(group);

				if (setup.applicable && setup.key != null)
					providers.computeIfAbsent(setup.algorithmName(), name -> provider(setup));
				else if (setup.family == Family.HMAC)
					providers.computeIfAbsent(setup.algorithmName(), name -> macProvider(setup, group));
			}
		}

		Assertions.assertEquals(Set.of("SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA", "SHA256withRSA",
				"SHA384withRSA", "SHA512withRSA", "RSASSA-PSS", "Ed25519", "HmacSHA256", "HmacSHA384", "HmacSHA512"),
				providers.keySet());

		return providers.entrySet().stream().map(entry -> {
			String served = entry.getKey() + " served by " + entry.getValue().getName() + " "
					+ entry.getValue().getVersionStr();
			return DynamicTest.dynamicTest(served, () -> {
				Assertions.assertFalse(entry.getValue().getName().isEmpty());
				System.out.println("Wycheproof: " + served);
			});
		});
	}

	// ---------------------------------------------------------------------------------------------------------------
	// The manifest checks themselves: each kind of stale or malformed line is reported, so each one fails the build
	// ---------------------------------------------------------------------------------------------------------------

	// Plan M2-9: a well-formed, current manifest gives each vector its line's outcome on the JDKs the line covers and
	// the default elsewhere (valid: accept; invalid: any rejection), and pins each file's counts by JDK.
	@Test
	void aCurrentManifestDecidesEachVectorByItsLineOrTheDefault() {
		Expectations expectations = Expectations.fromManifest("M.tsv", ExpectationsCase.utf8(ExpectationsCase.CURRENT),
				ExpectationsCase.FILES, ExpectationsCase.CODES, ExpectationsCase.RULE_NAMES);

		Assertions.assertEquals(Expectations.ACCEPT, expectations.outcomeFor("a.json", 1, 17));
		Assertions.assertEquals(Expectations.ANY_REJECTION, expectations.outcomeFor("a.json", 2, 17));
		Assertions.assertEquals(Expectations.ACCEPT, expectations.outcomeFor("a.json", 3, 27));
		Assertions.assertEquals("reject:MISMATCH", expectations.outcomeFor("a.json", 4, 17));
		Assertions.assertEquals(Expectations.ACCEPT, expectations.outcomeFor("a.json", 4, 18));
		Assertions.assertEquals("reject:WRONG_LENGTH", expectations.outcomeFor("a.json", 5, 21));
		Assertions.assertEquals(Expectations.NOT_APPLICABLE, expectations.outcomeFor("b.json", 1, 99));
		Assertions.assertEquals(new TreeMap<>(Map.of("accept", 2, "reject:MISMATCH", 2, "reject:WRONG_LENGTH", 1)),
				expectations.pinnedCounts("a.json", 17));
		Assertions.assertEquals(new TreeMap<>(Map.of("accept", 3, "reject:MISMATCH", 1, "reject:WRONG_LENGTH", 1)),
				expectations.pinnedCounts("a.json", 18));
		Assertions.assertEquals("#count\ta.json\t21\taccept=3\treject:MISMATCH=1\treject:WRONG_LENGTH=1",
				Expectations.countLine("a.json", 21, expectations.pinnedCounts("a.json", 21)));

		Assertions.assertTrue(Expectations.satisfies(Expectations.ANY_REJECTION, "reject:MISMATCH"));
		Assertions.assertTrue(Expectations.satisfies("reject:MISMATCH", "reject:MISMATCH"));
		Assertions.assertTrue(Expectations.satisfies(Expectations.NOT_APPLICABLE, Expectations.NOT_APPLICABLE));
		Assertions.assertFalse(Expectations.satisfies(Expectations.ANY_REJECTION, Expectations.ACCEPT));
		Assertions.assertFalse(Expectations.satisfies(Expectations.ANY_REJECTION, Expectations.NOT_APPLICABLE));
		Assertions.assertFalse(Expectations.satisfies("reject:MISMATCH", "reject:WRONG_LENGTH"));
		Assertions.assertFalse(Expectations.satisfies(Expectations.ACCEPT, "reject:MISMATCH"));

		AssertionError failure = Assertions.assertThrows(AssertionError.class, () -> Expectations.fromManifest("M.tsv",
				null, ExpectationsCase.FILES, ExpectationsCase.CODES, ExpectationsCase.RULE_NAMES));
		String message = requireNonNull(failure.getMessage());
		Assertions.assertTrue(message.contains("M.tsv is missing"), message);
	}

	// Plan M2-9's staleness list: an unknown file or tcId, a duplicate or overlapping line, a line that repeats the
	// default, a rule that changes no outcome, an unlisted acceptable vector and a count that disagrees with the file
	// are each reported, and so are malformed lines, reasons the runner does not report and rules outside the closed
	// set. Each problem names its line.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> reportsEveryStaleOrMalformedManifestLine() {
		String a = ExpectationsCase.COUNT_A;
		String b = ExpectationsCase.COUNT_B;
		String acceptable = "a.json\ttcId=3\tall\taccept\tn";

		return Stream.of(
				ExpectationsCase.of("a current manifest", ExpectationsCase.CURRENT),
				ExpectationsCase.of("a line with four fields", lines(a, b, "a.json\ttcId=3\tall\taccept"), malformed(3),
						unlisted(3, 17)),
				ExpectationsCase.of("a blank note", lines(a, b, "a.json\ttcId=3\tall\taccept\t "), malformed(3),
						unlisted(3, 17)),
				ExpectationsCase.of("a selector in the wrong case", lines(a, b, "a.json\ttcid=3\tall\taccept\tn"),
						malformed(3), unlisted(3, 17)),
				ExpectationsCase.of("a tcId with a leading zero", lines(a, b, "a.json\ttcId=03\tall\taccept\tn"),
						malformed(3), unlisted(3, 17)),
				ExpectationsCase.of("a JDK below 17", lines(a, b, "a.json\ttcId=3\t11+\taccept\tn"), malformed(3),
						unlisted(3, 17)),
				ExpectationsCase.of("a JDK range written backwards", lines(a, b, "a.json\ttcId=3\t21-17\taccept\tn"),
						malformed(3), unlisted(3, 17)),
				ExpectationsCase.of("a JDK range of one release", lines(a, b, "a.json\ttcId=3\t17-17\taccept\tn"),
						malformed(3), unlisted(3, 17)),
				ExpectationsCase.of("an outcome in the wrong case", lines(a, b, "a.json\ttcId=3\tall\tAccept\tn"),
						malformed(3), unlisted(3, 17)),
				ExpectationsCase.of("a rejection without a reason", lines(a, b, "a.json\ttcId=3\tall\treject:\tn"),
						malformed(3), unlisted(3, 17)),
				ExpectationsCase.of("a reason this runner does not report",
						lines(a, b, "a.json\ttcId=3\tall\treject:OVERFLOW\tn"),
						"M.tsv line 3 names a reason code this runner does not report: OVERFLOW", unlisted(3, 17)),
				ExpectationsCase.of("a file this runner does not run",
						lines(a, b, acceptable, "c.json\ttcId=1\tall\taccept\tn"),
						"M.tsv line 4 names a file this runner does not run: c.json"),
				ExpectationsCase.of("a tcId the file does not have",
						lines(a, b, acceptable, "a.json\ttcId=9\tall\treject:MISMATCH\tn"),
						"M.tsv line 4 names a tcId that a.json does not have: 9"),
				ExpectationsCase.of("a rule outside the closed set",
						lines(a, b, acceptable, "a.json\trule:other\tall\treject:MISMATCH\tn"),
						"M.tsv line 4 names a rule outside the closed set: other"),
				ExpectationsCase.of("a rule that selects nothing in its file",
						lines(a, b, acceptable, "b.json\trule:r\tall\treject:MISMATCH\tn"),
						"M.tsv line 4 selects no vector: rule:r matches nothing in b.json"),
				ExpectationsCase.of("a line that repeats the default",
						lines(a, b, acceptable, "a.json\ttcId=1\t21+\taccept\tn"),
						"M.tsv line 4 repeats the default: a.json tcId 1 is valid"),
				ExpectationsCase.of("a rule that changes no outcome", lines(a, b, acceptable, "a.json\trule:s\tall\taccept\tn"),
						"M.tsv line 4 changes no outcome: every vector that rule:s selects in a.json already has it by default"),
				ExpectationsCase.of("a repeated line", lines(a, b, acceptable, acceptable),
						"M.tsv lines 3 and 4 both decide a.json tcId 3 on JDK 17"),
				ExpectationsCase.of("overlapping JDK ranges",
						lines(a, b, "a.json\ttcId=3\t17-21\taccept\tn", "a.json\ttcId=3\t21+\treject:MISMATCH\tn"),
						"M.tsv lines 3 and 4 both decide a.json tcId 3 on JDK 21"),
				ExpectationsCase.of("a tcId line and a rule line for one vector", lines(a, b, acceptable,
								"a.json\trule:r\t18+\treject:MISMATCH\tn", "a.json\ttcId=2\t21\treject:WRONG_LENGTH\tn"),
						"M.tsv lines 4 and 5 both decide a.json tcId 2 on JDK 21"),
				ExpectationsCase.of("an acceptable vector with no line", lines(a, b), unlisted(3, 17)),
				ExpectationsCase.of("an acceptable vector with a line for one JDK",
						lines(a, b, "a.json\ttcId=3\t17\taccept\tn"), unlisted(3, 18)),
				ExpectationsCase.of("an acceptable vector with a gap between its lines",
						lines(a, b, "a.json\ttcId=3\t17-20\taccept\tn", "a.json\ttcId=3\t22+\treject:MISMATCH\tn"),
						unlisted(3, 21)),
				ExpectationsCase.of("a count line without counts", lines("#count\ta.json\tall", b, acceptable),
						malformedCount(1), "M.tsv has no count line for a.json on JDK 17"),
				ExpectationsCase.of("counts out of order", lines("#count\ta.json\tall\treject:MISMATCH=2\taccept=3", b,
						acceptable), malformedCount(1), "M.tsv has no count line for a.json on JDK 17"),
				ExpectationsCase.of("a count of zero", lines(a + "\treject:X=0", b, acceptable), malformedCount(1),
						"M.tsv has no count line for a.json on JDK 17"),
				ExpectationsCase.of("a count of a reason this runner does not report",
						lines("#count\ta.json\tall\taccept=3\treject:OVERFLOW=2", b, acceptable),
						"M.tsv line 1 names a reason code this runner does not report: OVERFLOW"),
				ExpectationsCase.of("a count line for a file this runner does not run",
						lines(a, b, "#count\tc.json\tall\taccept=1", acceptable),
						"M.tsv line 3 names a file this runner does not run: c.json"),
				ExpectationsCase.of("counts that disagree with the file", lines("#count\ta.json\tall\taccept=3", b, acceptable),
						"M.tsv line 1 counts 3 tests, but a.json has 5"),
				ExpectationsCase.of("two count lines for one JDK", lines(a, b, "#count\tb.json\t27+\taccept=1", acceptable),
						"M.tsv lines 2 and 3 both count b.json on JDK 27"),
				ExpectationsCase.of("a file with count lines for some JDKs only",
						lines(a, "#count\tb.json\t17-20\taccept=1", acceptable), "M.tsv has no count line for b.json on JDK 21"),
				ExpectationsCase.of("a CRLF line ending", lines(a, b).replace("\n", "\r\n") + lines(acceptable),
						"M.tsv contains a carriage return (lines end with LF only)", malformedCount(1), malformedCount(2),
						"M.tsv has no count line for a.json on JDK 17", "M.tsv has no count line for b.json on JDK 17"),
				ExpectationsCase.of("no final line feed", lines(a, b) + acceptable, "M.tsv does not end with a line feed"),
				ExpectationsCase.ofBytes("ill-formed UTF-8", new byte[]{'#', (byte) 0xC0, (byte) 0x80, '\n'},
						"M.tsv is not well-formed UTF-8", unlisted(3, 17), "M.tsv has no count line for a.json on JDK 17",
						"M.tsv has no count line for b.json on JDK 17"),
				ExpectationsCase.ofBytes("a missing manifest", null, "M.tsv is missing", unlisted(3, 17),
						"M.tsv has no count line for a.json on JDK 17", "M.tsv has no count line for b.json on JDK 17"));
	}

	/**
	 * A manifest of the given lines, each ended with a line feed.
	 */
	private static @NonNull String lines(@NonNull String @NonNull ... lines) {
		return Stream.of(lines).map(line -> line + "\n").collect(Collectors.joining());
	}

	private static @NonNull String malformed(int number) {
		return "M.tsv line " + number + " is malformed (expected <file><TAB><tcId=n or rule:name><TAB><jdk><TAB>"
				+ "<outcome><TAB><note>)";
	}

	private static @NonNull String malformedCount(int number) {
		return "M.tsv line " + number + " is malformed (expected #count<TAB><file><TAB><jdk><TAB><outcome>=<count>..., "
				+ "one or more, sorted and distinct)";
	}

	private static @NonNull String unlisted(int tcId, int feature) {
		return "M.tsv has no line for a.json tcId " + tcId + ", which is acceptable, on JDK " + feature;
	}

	/**
	 * The synthetic files and manifests of the manifest checks' own tests.
	 */
	private static final class ExpectationsCase {
		/**
		 * {@code a.json}: tcId 1 valid (rule r), 2 invalid (rule r), 3 acceptable, 4 valid (rule s), 5 invalid;
		 * {@code b.json}: tcId 1 valid.
		 */
		private static final SortedMap<String, List<Expectations.Vector>> FILES = new TreeMap<>(Map.of(
				"a.json", List.of(new Expectations.Vector(1, Result.VALID, Set.of("r")),
						new Expectations.Vector(2, Result.INVALID, Set.of("r")),
						new Expectations.Vector(3, Result.ACCEPTABLE, Set.of()),
						new Expectations.Vector(4, Result.VALID, Set.of("s")),
						new Expectations.Vector(5, Result.INVALID, Set.of())),
				"b.json", List.of(new Expectations.Vector(1, Result.VALID, Set.of()))));
		private static final Set<String> CODES = Set.of("MISMATCH", "WRONG_LENGTH");
		private static final Set<String> RULE_NAMES = Set.of("r", "s");

		/**
		 * Count lines that fit {@link #FILES} when only tcId 3 has a line ({@code accept}).
		 */
		private static final String COUNT_A = "#count\ta.json\tall\taccept=3\treject:MISMATCH=2";
		private static final String COUNT_B = "#count\tb.json\tall\taccept=1";

		private static final String CURRENT = lines("# A comment, then the count lines and the expectations.", "",
				"#count\ta.json\t17\taccept=2\treject:MISMATCH=2\treject:WRONG_LENGTH=1",
				"#count\ta.json\t18+\taccept=3\treject:MISMATCH=1\treject:WRONG_LENGTH=1",
				"#count\tb.json\tall\tn/a=1",
				"a.json\ttcId=3\tall\taccept\tacceptable, and accepted",
				"a.json\ttcId=4\t17\treject:MISMATCH\ta JDK-conditional exception",
				"a.json\ttcId=5\tall\treject:WRONG_LENGTH\ta pinned reason",
				"b.json\ttcId=1\tall\tn/a\tnot applicable");

		private static @NonNull DynamicTest of(@NonNull String name, @NonNull String manifest, @NonNull String @NonNull ... expected) {
			return ofBytes(name, utf8(manifest), expected);
		}

		private static @NonNull DynamicTest ofBytes(@NonNull String name, byte @Nullable [] manifest, @NonNull String @NonNull ... expected) {
			return DynamicTest.dynamicTest(name, () -> Assertions.assertEquals(List.of(expected),
					Expectations.findProblems("M.tsv", manifest, FILES, CODES, RULE_NAMES)));
		}

		private static byte @NonNull [] utf8(@NonNull String text) {
			return text.getBytes(StandardCharsets.UTF_8);
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Running a vector
	// ---------------------------------------------------------------------------------------------------------------

	/**
	 * A vector's outcome: {@code accept}, {@code reject:<code>} or {@code n/a}. Anything thrown fails the test (INV-G1:
	 * the verifiers never throw on untrusted input).
	 */
	private static @NonNull String observe(@NonNull Setup setup, @NonNull TestVector vector) {
		if (!setup.applicable)
			return Expectations.NOT_APPLICABLE;

		KeyRejectedException.Kind refusal = setup.refusal;

		if (refusal != null)
			return Expectations.REJECT + refusal.name();

		VerifyResult result;

		try {
			result = switch (setup.family) {
				case ECDSA -> SignatureVerifier.verifyEcdsa(requireNonNull(setup.curve), setup.requireHash(),
						setup.requireKey(), vector.getHexBytes("msg"), vector.getHexBytes("sig"));
				case RSA_PKCS1 -> SignatureVerifier.verifyRsaPkcs1(setup.requireHash(), setup.requireKey(),
						vector.getHexBytes("msg"), vector.getHexBytes("sig"));
				case RSA_PSS -> SignatureVerifier.verifyRsaPss(setup.requireHash(), setup.requireKey(),
						vector.getHexBytes("msg"), vector.getHexBytes("sig"));
				case EDDSA -> SignatureVerifier.verifyEd25519(setup.requireKey(), vector.getHexBytes("msg"),
						vector.getHexBytes("sig"));
				case HMAC -> Hmac.verifyTag(setup.requireHash(), vector.getHexBytes("key"), vector.getHexBytes("msg"),
						vector.getHexBytes("tag"));
			};
		} catch (KeyRejectedException exception) {
			return Expectations.REJECT + exception.getKind().name();
		} catch (RuntimeException exception) {
			throw new AssertionError(vector + ": the primitive threw " + exception.getClass().getName() + " (INV-G1)",
					exception);
		}

		return result == VerifyResult.VALID ? Expectations.ACCEPT : Expectations.REJECT + result.name();
	}

	/**
	 * The JCA provider that serves a group's signature algorithm for its key, chosen the way {@link SignatureVerifier}'s
	 * own {@link Signature} chooses it: at {@code initVerify}.
	 */
	private static @NonNull Provider provider(@NonNull Setup setup) {
		try {
			Signature signature = Signature.getInstance(setup.algorithmName());
			signature.initVerify(setup.requireKey());

			if (setup.family == Family.RSA_PSS)
				signature.setParameter(setup.requireHash().getPssParameterSpec());

			return signature.getProvider();
		} catch (GeneralSecurityException exception) {
			throw new AssertionError(setup.algorithmName() + " has no provider for the vendored key", exception);
		}
	}

	/**
	 * The JCA provider that serves a MAC group's algorithm, for the key of its first test.
	 */
	private static @NonNull Provider macProvider(@NonNull Setup setup, @NonNull TestGroup group) {
		try {
			Mac mac = Mac.getInstance(setup.algorithmName());
			mac.init(new SecretKeySpec(group.getTests().get(0).getHexBytes("key"), setup.algorithmName()));
			return mac.getProvider();
		} catch (GeneralSecurityException exception) {
			throw new AssertionError(setup.algorithmName() + " has no provider", exception);
		}
	}

	private static boolean isPss(@NonNull TestGroup group) {
		return group.getType().equals("RsassaPssVerify");
	}

	private static boolean isMac(@NonNull TestGroup group) {
		return group.getType().equals("MacTest");
	}

	/**
	 * The hash a group names in {@code sha}, which must be one JOSE uses.
	 */
	private static @NonNull HashAlgorithm hash(@NonNull TestGroup group) {
		String sha = group.getString("sha");
		return Optional.ofNullable(JOSE_HASHES.get(sha)).orElseThrow(() -> new AssertionError(group + ": no JOSE hash "
				+ sha));
	}

	/**
	 * The hash of a MAC file, from its {@code algorithm} ({@code HMACSHA256} and so on).
	 */
	private static @NonNull HashAlgorithm macHash(@NonNull TestGroup group) {
		String algorithm = group.getFile().findAlgorithm().orElse("");

		return switch (algorithm) {
			case "HMACSHA256" -> HashAlgorithm.SHA_256;
			case "HMACSHA384" -> HashAlgorithm.SHA_384;
			case "HMACSHA512" -> HashAlgorithm.SHA_512;
			default -> throw new AssertionError(group + ": no JOSE HMAC hash for " + algorithm);
		};
	}

	/**
	 * A vector file's {@code BigInt}: hex two's complement (Wycheproof's {@code doc/formats.md}), which must be
	 * positive here.
	 */
	private static @NonNull BigInteger positive(@NonNull String hex) {
		BigInteger value = new BigInteger(HexFormat.of().parseHex(hex));

		if (value.signum() <= 0)
			throw new AssertionError("not a positive BigInt: " + hex);

		return value;
	}

	/**
	 * The minimal unsigned big-endian bytes of a positive integer: no leading zero octet.
	 */
	private static byte @NonNull [] unsigned(@NonNull BigInteger value) {
		byte[] bytes = value.toByteArray();
		return bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes;
	}

	private static byte @NonNull [] base64Url(@NonNull TestGroup group, @NonNull JsonObject jwk, @NonNull String member) {
		try {
			return Base64Url.decode(jwk.findString(member).orElseThrow(() -> new AssertionError(group + ": the JWK "
					+ "has no " + member)));
		} catch (EncodingException exception) {
			throw new AssertionError(group + ": the JWK's " + member + " is not canonical base64url", exception);
		}
	}

	private static @NonNull Set<@NonNull String> intersection(@NonNull Set<@NonNull String> first, @NonNull Set<@NonNull String> second) {
		Set<String> intersection = new HashSet<>(first);
		intersection.retainAll(second);
		return intersection;
	}

	/**
	 * The signature or MAC family a group's type names.
	 */
	private enum Family {
		ECDSA, RSA_PKCS1, RSA_PSS, EDDSA, HMAC
	}

	/**
	 * What every vector of one group shares: its family, curve and hash, and its key or the key policy's refusal. A
	 * group whose hash JOSE does not use is not applicable, and gets no key.
	 */
	private static final class Setup {
		private final Family family;
		private final @Nullable EcCurve curve;
		private final @Nullable HashAlgorithm hash;
		private final @Nullable PublicKey key;
		private final KeyRejectedException.@Nullable Kind refusal;
		private final boolean applicable;

		private Setup(@NonNull Family family,
									@Nullable EcCurve curve,
									@Nullable HashAlgorithm hash,
									@Nullable PublicKey key,
									KeyRejectedException.@Nullable Kind refusal,
									boolean applicable) {
			this.family = family;
			this.curve = curve;
			this.hash = hash;
			this.key = key;
			this.refusal = refusal;
			this.applicable = applicable;
		}

		static @NonNull Setup of(@NonNull TestGroup group) {
			return switch (group.getType()) {
				case "EcdsaP1363Verify" -> ecdsa(group);
				case "RsassaPkcs1Verify" -> rsa(group, Family.RSA_PKCS1);
				case "RsassaPssVerify" -> JOSE_HASHES.containsKey(group.getString("sha")) ? rsa(group, Family.RSA_PSS)
						: new Setup(Family.RSA_PSS, null, null, null, null, false);
				case "EddsaVerify" -> ed25519(group);
				case "MacTest" -> new Setup(Family.HMAC, null, macHash(group), null, null, true);
				default -> throw new AssertionError(group + ": this runner does not run " + group.getType());
			};
		}

		/**
		 * ECDSA: {@code publicKey.uncompressed} is {@code 04 || x || y} with fixed-length coordinates; the JWK, where
		 * the group has one, holds the same point on the same curve.
		 */
		private static @NonNull Setup ecdsa(@NonNull TestGroup group) {
			JsonObject publicKey = group.getObject("publicKey");
			String curveName = publicKey.findString("curve").orElse("");
			EcCurve curve = Arrays.stream(EcCurve.values()).filter(value -> value.getStandardName().equals(curveName))
					.findFirst().orElseThrow(() -> new AssertionError(group + ": no curve " + curveName));
			HashAlgorithm hash = hash(group);

			// JOSE pairs each curve with one hash (RFC 7518 section 3.4), and the vendored files are exactly those.
			HashAlgorithm joseHash = switch (curve) {
				case P_256 -> HashAlgorithm.SHA_256;
				case P_384 -> HashAlgorithm.SHA_384;
				case P_521 -> HashAlgorithm.SHA_512;
			};
			Assertions.assertEquals(joseHash, hash, () -> group + ": the hash JOSE pairs with " + curve.getName());

			byte[] point = HexFormat.of().parseHex(publicKey.findString("uncompressed").orElse(""));
			int length = curve.getCoordinateLength();
			Assertions.assertEquals(1 + 2 * length, point.length, () -> group + ": an uncompressed point");
			Assertions.assertEquals(4, point[0], () -> group + ": an uncompressed point");
			byte[] x = Arrays.copyOfRange(point, 1, 1 + length);
			byte[] y = Arrays.copyOfRange(point, 1 + length, point.length);

			group.findObject("publicKeyJwk").ifPresent(jwk -> {
				Assertions.assertEquals(Optional.of(curve.getName()), jwk.findString("crv"), () -> group + ": crv");
				Assertions.assertArrayEquals(x, base64Url(group, jwk, "x"), () -> group + ": the JWK's x");
				Assertions.assertArrayEquals(y, base64Url(group, jwk, "y"), () -> group + ": the JWK's y");
			});

			try {
				return new Setup(Family.ECDSA, curve, hash, EcPublicKeys.fromCoordinates(curve, x, y), null, true);
			} catch (KeyRejectedException exception) {
				return new Setup(Family.ECDSA, curve, hash, null, exception.getKind(), true);
			}
		}

		/**
		 * RSA: {@code publicKey.modulus} and {@code publicExponent} as minimal unsigned integers; the JWK, where the
		 * group has one, holds the same ones.
		 */
		private static @NonNull Setup rsa(@NonNull TestGroup group,
														 @NonNull Family family) {
			JsonObject publicKey = group.getObject("publicKey");
			byte[] modulus = unsigned(positive(publicKey.findString("modulus").orElse("")));
			byte[] exponent = unsigned(positive(publicKey.findString("publicExponent").orElse("")));
			HashAlgorithm hash = hash(group);

			Stream.of("keyJwk", "publicKeyJwk").map(group::findObject).flatMap(Optional::stream).forEach(jwk -> {
				Assertions.assertArrayEquals(modulus, base64Url(group, jwk, "n"), () -> group + ": the JWK's n");
				Assertions.assertArrayEquals(exponent, base64Url(group, jwk, "e"), () -> group + ": the JWK's e");
			});

			try {
				return new Setup(family, null, hash, RsaPublicKeys.fromComponents(modulus, exponent), null, true);
			} catch (KeyRejectedException exception) {
				return new Setup(family, null, hash, null, exception.getKind(), true);
			}
		}

		/**
		 * Ed25519: {@code publicKey.pk} is the 32-octet encoding; the JWK, where the group has one, holds the same.
		 */
		private static @NonNull Setup ed25519(@NonNull TestGroup group) {
			JsonObject publicKey = group.getObject("publicKey");
			Assertions.assertEquals(Optional.of("edwards25519"), publicKey.findString("curve"), () -> group + ": curve");
			byte[] encoded = HexFormat.of().parseHex(publicKey.findString("pk").orElse(""));

			group.findObject("publicKeyJwk").ifPresent(jwk -> {
				Assertions.assertEquals(Optional.of("Ed25519"), jwk.findString("crv"), () -> group + ": crv");
				Assertions.assertArrayEquals(encoded, base64Url(group, jwk, "x"), () -> group + ": the JWK's x");
			});

			try {
				return new Setup(Family.EDDSA, null, null, Ed25519PublicKeys.fromEncoded(encoded), null, true);
			} catch (KeyRejectedException exception) {
				return new Setup(Family.EDDSA, null, null, null, exception.getKind(), true);
			}
		}

		@NonNull PublicKey requireKey() {
			return requireNonNull(this.key, "no key");
		}

		@NonNull HashAlgorithm requireHash() {
			return requireNonNull(this.hash, "no hash");
		}

		/**
		 * The JCA name the primitive uses for this group.
		 */
		@NonNull String algorithmName() {
			return switch (this.family) {
				case ECDSA -> requireHash().getEcdsaSignatureName();
				case RSA_PKCS1 -> requireHash().getRsaSignatureName();
				case RSA_PSS -> "RSASSA-PSS";
				case EDDSA -> Ed25519PublicKeys.ALGORITHM;
				case HMAC -> requireHash().getHmacName();
			};
		}
	}

	/**
	 * The vendored files this runner runs and the manifest, both checked.
	 */
	private static final class Run {
		private final List<VectorFile> files;
		private final Expectations expectations;

		private Run(@NonNull List<@NonNull VectorFile> files,
								@NonNull Expectations expectations) {
			this.files = files;
			this.expectations = expectations;
		}

		static @NonNull Run load() {
			List<VectorFile> files = WycheproofVectors.fromVendoredFiles().getFiles().stream()
					.filter(file -> !JOSE_FILES.contains(file.getName())).toList();
			SortedMap<String, List<Expectations.Vector>> vectors = new TreeMap<>();

			for (VectorFile file : files) {
				List<Expectations.Vector> fileVectors = new ArrayList<>();

				for (TestGroup group : file.getGroups()) {
					Set<String> rules = RULES.entrySet().stream().filter(rule -> rule.getValue().test(group))
							.map(Map.Entry::getKey).collect(Collectors.toSet());

					for (TestVector vector : group.getTests())
						fileVectors.add(new Expectations.Vector(vector.getTcId(), vector.getResult(), rules));
				}

				vectors.put(file.getName(), fileVectors);
			}

			return new Run(files, Expectations.fromManifest(MANIFEST, Expectations.read(WycheproofSignatureTests.class,
					MANIFEST), vectors, CODES, RULES.keySet()));
		}

		@NonNull VectorFile file(@NonNull String name) {
			return this.files.stream().filter(file -> file.getName().equals(name)).findFirst().orElseThrow();
		}
	}

	// ---------------------------------------------------------------------------------------------------------------
	// The expectation manifest, shared with the JOSE runner
	// ---------------------------------------------------------------------------------------------------------------

	/**
	 * A Wycheproof runner's expectation manifest (plan M2-9), checked in full before any vector runs. Both runners use
	 * this class, each with its own manifest, files, reason codes and rules.
	 * <p>
	 * <strong>Format.</strong> UTF-8 text with LF line endings, ending with a line feed. Blank lines and lines starting
	 * with {@code #} are comments, except count lines. Every other line is an expectation of five TAB-separated fields:
	 * <pre>
	 * file &lt;TAB&gt; selector &lt;TAB&gt; jdk &lt;TAB&gt; outcome &lt;TAB&gt; note
	 * </pre>
	 * <ul>
	 *   <li>{@code file}: a vector file the runner runs, by its name in {@code testvectors_v1/};</li>
	 *   <li>{@code selector}: {@code tcId=<n>}, one vector, or {@code rule:<name>}, every vector of the groups the rule
	 *   (from the runner's closed set) matches in that file;</li>
	 *   <li>{@code jdk}: the Java feature releases the line covers: {@code all}, {@code <n>}, {@code <n>+} or
	 *   {@code <n>-<m>} with {@code n < m}, each at least {@value #MINIMUM_FEATURE}. A line is inert on other
	 *   releases;</li>
	 *   <li>{@code outcome}: {@code accept}, {@code reject:<code>} with a reason code the runner reports, or
	 *   {@code n/a};</li>
	 *   <li>{@code note}: why, never blank.</li>
	 * </ul>
	 * A <strong>count line</strong> pins a file's outcomes on some releases: {@code #count}, the file, the releases,
	 * then one or more {@code <outcome>=<count>} fields, sorted and distinct, with positive counts that add up to the
	 * file's number of tests. Each file has exactly one count line for every release from
	 * {@value #MINIMUM_FEATURE} up.
	 * <p>
	 * <strong>Defaults.</strong> A vector no line covers on a release expects {@code accept} if it is {@code valid} and
	 * any rejection if it is {@code invalid}; an {@code acceptable} vector has no default, so it needs a line on every
	 * release.
	 * <p>
	 * <strong>Staleness.</strong> Each of these is a problem, and any problem fails the build before a vector runs:
	 * a malformed line; a file the runner does not run, or a tcId its file does not have; a rule outside the closed
	 * set, or one that matches nothing in its file; a reason code the runner does not report; two lines that decide
	 * one vector on one release (a repeated line included); a {@code tcId=} line that repeats the default
	 * ({@code accept} for a {@code valid} vector); a {@code rule:} line that changes no outcome, because every vector it
	 * selects already has it by default; an {@code acceptable} vector without a line on some release; and a count line
	 * that is malformed, names another file, overlaps another for its file, or does not add up to the file's number of
	 * tests, or a release on which a file has no count line. A {@code tcId=} line may name the reason of an
	 * {@code invalid} vector's rejection, which pins it. On the release under test, each runner then checks every
	 * vector against {@link #outcomeFor(String, int, int)} and each file's counts against
	 * {@link #pinnedCounts(String, int)}.
	 */
	public static final class Expectations {
		/**
		 * The outcome of a vector that verified.
		 */
		public static final String ACCEPT = "accept";

		/**
		 * The prefix of a rejection's outcome, which ends in its reason code.
		 */
		public static final String REJECT = "reject:";

		/**
		 * The outcome of a vector the runner cannot express.
		 */
		public static final String NOT_APPLICABLE = "n/a";

		/**
		 * What an {@code invalid} vector expects by default: a rejection for any reason.
		 */
		public static final String ANY_REJECTION = "reject:*";

		/**
		 * The oldest Java feature release Revetsec runs on, and so the lowest a {@code jdk} field names.
		 */
		public static final int MINIMUM_FEATURE = 17;

		private static final String COUNT_PREFIX = "#count\t";
		private static final String RULE_PREFIX = "rule:";
		private static final Pattern TC_ID = Pattern.compile("tcId=([1-9][0-9]{0,8})");
		private static final Pattern RULE = Pattern.compile("rule:([a-z0-9]+(?:-[a-z0-9]+)*)");
		private static final Pattern JDK = Pattern.compile("all|([1-9][0-9]{1,3})(?:(\\+)|-([1-9][0-9]{1,3}))?");
		private static final Pattern OUTCOME = Pattern.compile("accept|n/a|reject:([A-Z][A-Z0-9_]*)");
		private static final Pattern COUNT = Pattern.compile("(accept|n/a|reject:([A-Z][A-Z0-9_]*))=([1-9][0-9]{0,8})");

		private final Map<String, Map<Integer, Vector>> vectors;
		private final Map<String, Map<Integer, List<Line>>> linesByVector;
		private final List<CountLine> countLines;

		private Expectations(@NonNull Map<@NonNull String, @NonNull Map<@NonNull Integer, @NonNull Vector>> vectors,
												 @NonNull Map<@NonNull String, @NonNull Map<@NonNull Integer, @NonNull List<@NonNull Line>>> linesByVector,
												 @NonNull List<@NonNull CountLine> countLines) {
			this.vectors = vectors;
			this.linesByVector = linesByVector;
			this.countLines = countLines;
		}

		/**
		 * One vector as the manifest sees it.
		 *
		 * @param tcId   its tcId
		 * @param result its upstream verdict
		 * @param rules  the rules of the runner's closed set that select it
		 */
		public record Vector(int tcId, @NonNull Result result, @NonNull Set<@NonNull String> rules) {
			/**
			 * Copies the rules.
			 */
			public Vector {
				requireNonNull(result);
				rules = Set.copyOf(rules);
			}
		}

		/**
		 * Checks a manifest against a runner's files, reason codes and rules.
		 *
		 * @param name    the manifest's name in problem messages
		 * @param content the manifest's bytes, or {@code null} if it is missing
		 * @param files   the runner's files by name, each with its vectors
		 * @param codes   the reason codes the runner reports
		 * @param rules   the runner's closed rule set
		 * @return the checked manifest
		 * @throws AssertionError if any check fails; its message lists every problem
		 */
		public static @NonNull Expectations fromManifest(@NonNull String name,
																						byte @Nullable [] content,
																						@NonNull SortedMap<@NonNull String, @NonNull List<@NonNull Vector>> files,
																						@NonNull Set<@NonNull String> codes,
																						@NonNull Set<@NonNull String> rules) {
			Check check = new Check(name, content, files, codes, rules);

			if (!check.problems.isEmpty())
				throw new AssertionError(name + " fails its checks (plan M2-9):\n  " + String.join("\n  ", check.problems));

			return new Expectations(check.vectors, check.linesByVector, check.countLines);
		}

		/**
		 * Every problem the checks find in a manifest, in line order and then by file; empty if there is none.
		 *
		 * @param name    the manifest's name in problem messages
		 * @param content the manifest's bytes, or {@code null} if it is missing
		 * @param files   the runner's files by name, each with its vectors
		 * @param codes   the reason codes the runner reports
		 * @param rules   the runner's closed rule set
		 * @return the problems
		 */
		public static @NonNull List<@NonNull String> findProblems(@NonNull String name,
																						byte @Nullable [] content,
																						@NonNull SortedMap<@NonNull String, @NonNull List<@NonNull Vector>> files,
																						@NonNull Set<@NonNull String> codes,
																						@NonNull Set<@NonNull String> rules) {
			return List.copyOf(new Check(name, content, files, codes, rules).problems);
		}

		/**
		 * Reads a manifest. Tests read the source file when they run from a checkout, so the checks cover exactly what
		 * is committed; otherwise they read the copy on the test class path.
		 *
		 * @param anchor         a test class of the module
		 * @param relativeSource the manifest's path relative to the module root, under {@code src/test/resources/}
		 * @return its bytes, or {@code null} if there is no such file
		 */
		public static byte @Nullable [] read(@NonNull Class<?> anchor,
																				 @NonNull String relativeSource) {
			try {
				// target/test-classes -> target -> the module root.
				Path testClasses = Path.of(anchor.getProtectionDomain().getCodeSource().getLocation().toURI());
				Path target = testClasses.getParent();
				Path moduleRoot = target == null ? null : target.getParent();

				if (moduleRoot != null && Files.isRegularFile(moduleRoot.resolve(relativeSource)))
					return Files.readAllBytes(moduleRoot.resolve(relativeSource));

				try (InputStream input = anchor.getResourceAsStream("/" + relativeSource.substring(
						"src/test/resources/".length()))) {
					return input == null ? null : input.readAllBytes();
				}
			} catch (IOException exception) {
				throw new UncheckedIOException(exception);
			} catch (URISyntaxException exception) {
				throw new IllegalStateException(exception);
			}
		}

		/**
		 * The outcome a vector expects on a release: its line's, or the default.
		 *
		 * @param file    the vector's file
		 * @param tcId    its tcId
		 * @param feature the Java feature release
		 * @return {@code accept}, {@code reject:<code>}, {@code n/a}, or {@link #ANY_REJECTION}
		 */
		public @NonNull String outcomeFor(@NonNull String file,
														 int tcId,
														 int feature) {
			Vector vector = requireNonNull(requireNonNull(this.vectors.get(file), file).get(tcId), () -> file + " tcId "
					+ tcId);

			for (Line line : this.linesByVector.getOrDefault(file, Map.of()).getOrDefault(tcId, List.of()))
				if (line.jdk.contains(feature))
					return line.outcome;

			return switch (vector.result()) {
				case VALID -> ACCEPT;
				case INVALID -> ANY_REJECTION;
				// The checks give every acceptable vector a line on every release.
				case ACCEPTABLE -> throw new IllegalStateException(file + " tcId " + tcId + " has no line on JDK " + feature);
			};
		}

		/**
		 * The outcome counts a file's count line pins for a release.
		 *
		 * @param file    the file
		 * @param feature the Java feature release, at least {@value #MINIMUM_FEATURE}
		 * @return the counts, by outcome
		 */
		public @NonNull SortedMap<@NonNull String, @NonNull Integer> pinnedCounts(@NonNull String file,
																									 int feature) {
			return this.countLines.stream().filter(line -> line.file.equals(file) && line.jdk.contains(feature))
					.findFirst().map(line -> line.counts)
					.orElseThrow(() -> new IllegalStateException(file + " has no count line on JDK " + feature));
		}

		/**
		 * Whether an observed outcome is the expected one; any rejection satisfies {@link #ANY_REJECTION}.
		 *
		 * @param expected the expected outcome
		 * @param observed the observed outcome
		 * @return whether it is satisfied
		 */
		public static boolean satisfies(@NonNull String expected,
																		@NonNull String observed) {
			return expected.equals(observed) || (expected.equals(ANY_REJECTION) && observed.startsWith(REJECT));
		}

		/**
		 * A count line for observed counts, as a failure message shows them so they can be reviewed and pasted.
		 *
		 * @param file    the file
		 * @param feature the release they were observed on
		 * @param counts  the counts, by outcome
		 * @return the line, without a line feed
		 */
		public static @NonNull String countLine(@NonNull String file,
																	 int feature,
																	 @NonNull SortedMap<@NonNull String, @NonNull Integer> counts) {
			return "#count\t" + file + "\t" + feature + "\t" + counts.entrySet().stream()
					.map(entry -> entry.getKey() + "=" + entry.getValue()).collect(Collectors.joining("\t"));
		}

		/**
		 * The releases a line covers: {@code from} to {@code to}, inclusive.
		 */
		private record Range(int from, int to) {
			boolean contains(int feature) {
				return this.from <= feature && feature <= this.to;
			}

			/**
			 * The first release both ranges cover, if any.
			 */
			@NonNull Optional<@NonNull Integer> firstShared(@NonNull Range other) {
				int from = Math.max(this.from, other.from);
				return from <= Math.min(this.to, other.to) ? Optional.of(from) : Optional.empty();
			}

			static @Nullable Range parse(@NonNull String field) {
				Matcher matcher = JDK.matcher(field);

				if (!matcher.matches())
					return null;
				if (matcher.group(1) == null)
					return new Range(MINIMUM_FEATURE, Integer.MAX_VALUE);

				int from = Integer.parseInt(matcher.group(1));
				String upper = matcher.group(3);
				int to = matcher.group(2) != null ? Integer.MAX_VALUE : upper == null ? from : Integer.parseInt(upper);

				return from < MINIMUM_FEATURE || (upper != null && to <= from) ? null : new Range(from, to);
			}

			/**
			 * The first release from {@value #MINIMUM_FEATURE} up that no range covers, if any.
			 */
			static @NonNull Optional<@NonNull Integer> firstUncovered(@NonNull List<@NonNull Range> ranges) {
				List<Range> sorted = new ArrayList<>(ranges);
				sorted.sort(Comparator.comparingInt(Range::from));
				long next = MINIMUM_FEATURE;

				for (Range range : sorted) {
					if (range.from > next)
						break;
					next = Math.max(next, (long) range.to + 1);
				}

				return next > Integer.MAX_VALUE ? Optional.empty() : Optional.of((int) next);
			}
		}

		/**
		 * An expectation line; exactly one of {@code tcId} and {@code rule} is set.
		 */
		private record Line(int number, @NonNull String file, @Nullable Integer tcId, @Nullable String rule, @NonNull Range jdk,
												@NonNull String outcome) {
		}

		/**
		 * A count line.
		 */
		private record CountLine(int number, @NonNull String file, @NonNull Range jdk, @NonNull SortedMap<@NonNull String, @NonNull Integer> counts) {
		}

		/**
		 * One run of every check over a manifest.
		 */
		private static final class Check {
			private final String name;
			private final Map<String, Map<Integer, Vector>> vectors = new TreeMap<>();
			private final Map<String, Map<Integer, List<Line>>> linesByVector = new TreeMap<>();
			private final List<CountLine> countLines = new ArrayList<>();
			private final List<String> problems = new ArrayList<>();

			private Check(@NonNull String name,
										byte @Nullable [] content,
										@NonNull SortedMap<@NonNull String, @NonNull List<@NonNull Vector>> files,
										@NonNull Set<@NonNull String> codes,
										@NonNull Set<@NonNull String> rules) {
				this.name = name;

				for (Map.Entry<String, List<Vector>> file : files.entrySet()) {
					Map<Integer, Vector> byTcId = new TreeMap<>();

					for (Vector vector : file.getValue())
						byTcId.put(vector.tcId(), vector);

					this.vectors.put(file.getKey(), byTcId);
				}

				List<Line> lines = new ArrayList<>();

				for (Map.Entry<Integer, String> line : lines(content).entrySet()) {
					if (line.getValue().startsWith(COUNT_PREFIX))
						countLine(line.getKey(), line.getValue(), codes);
					else if (!line.getValue().startsWith("#") && !line.getValue().isBlank())
						expectationLine(line.getKey(), line.getValue(), codes, rules).ifPresent(lines::add);
				}

				for (Line line : lines)
					select(line);

				checkOverlaps();
				checkAcceptableVectors();
				checkCountLines();
			}

			/**
			 * The manifest's lines by 1-based number, after the file-level checks: present, well-formed UTF-8, LF line
			 * endings only, and a final line feed.
			 */
			private @NonNull SortedMap<@NonNull Integer, @NonNull String> lines(byte @Nullable [] content) {
				SortedMap<Integer, String> lines = new TreeMap<>();

				if (content == null) {
					this.problems.add(this.name + " is missing");
					return lines;
				}

				String text;

				try {
					text = StandardCharsets.UTF_8.newDecoder()
							.onMalformedInput(CodingErrorAction.REPORT)
							.onUnmappableCharacter(CodingErrorAction.REPORT)
							.decode(ByteBuffer.wrap(content))
							.toString();
				} catch (CharacterCodingException exception) {
					this.problems.add(this.name + " is not well-formed UTF-8");
					return lines;
				}

				if (text.indexOf('\r') >= 0)
					this.problems.add(this.name + " contains a carriage return (lines end with LF only)");
				if (!text.isEmpty() && !text.endsWith("\n"))
					this.problems.add(this.name + " does not end with a line feed");

				String[] raw = (text.endsWith("\n") ? text.substring(0, text.length() - 1) : text).split("\n", -1);

				for (int index = 0; index < raw.length; ++index)
					lines.put(index + 1, raw[index]);

				return lines;
			}

			private @NonNull Optional<@NonNull Line> expectationLine(int number,
																						 @NonNull String text,
																						 @NonNull Set<@NonNull String> codes,
																						 @NonNull Set<@NonNull String> rules) {
				String[] fields = text.split("\t", -1);
				Matcher tcId = TC_ID.matcher(fields.length == 5 ? fields[1] : "");
				Matcher rule = RULE.matcher(fields.length == 5 ? fields[1] : "");
				Matcher outcome = OUTCOME.matcher(fields.length == 5 ? fields[3] : "");
				boolean tcIdSelector = tcId.matches();
				boolean ruleSelector = rule.matches();
				Range range = fields.length == 5 ? Range.parse(fields[2]) : null;

				if (!(tcIdSelector || ruleSelector) || range == null || !outcome.matches() || fields[4].isBlank()) {
					this.problems.add(prefix(number) + " is malformed (expected <file><TAB><tcId=n or rule:name><TAB><jdk>"
							+ "<TAB><outcome><TAB><note>)");
					return Optional.empty();
				}

				String file = fields[0];
				Map<Integer, Vector> fileVectors = this.vectors.get(file);
				String code = outcome.group(1);

				if (fileVectors == null) {
					this.problems.add(prefix(number) + " names a file this runner does not run: " + file);
				} else if (code != null && !codes.contains(code)) {
					this.problems.add(prefix(number) + " names a reason code this runner does not report: " + code);
				} else if (tcIdSelector) {
					int id = Integer.parseInt(tcId.group(1));

					if (fileVectors.containsKey(id))
						return Optional.of(new Line(number, file, id, null, range, fields[3]));

					this.problems.add(prefix(number) + " names a tcId that " + file + " does not have: " + id);
				} else if (!rules.contains(rule.group(1))) {
					this.problems.add(prefix(number) + " names a rule outside the closed set: " + rule.group(1));
				} else {
					return Optional.of(new Line(number, file, null, rule.group(1), range, fields[3]));
				}

				return Optional.empty();
			}

			private void countLine(int number,
														 @NonNull String text,
														 @NonNull Set<@NonNull String> codes) {
				String[] fields = text.split("\t", -1);
				Range range = fields.length >= 4 ? Range.parse(fields[2]) : null;
				SortedMap<String, Integer> counts = new TreeMap<>();
				String previous = "";
				boolean wellFormed = range != null;

				for (int index = 3; wellFormed && index < fields.length; ++index) {
					Matcher count = COUNT.matcher(fields[index]);
					wellFormed = count.matches() && count.group(1).compareTo(previous) > 0;

					if (wellFormed) {
						previous = count.group(1);
						counts.put(count.group(1), Integer.parseInt(count.group(3)));
					}
				}

				if (!wellFormed || range == null) {
					this.problems.add(prefix(number) + " is malformed (expected #count<TAB><file><TAB><jdk><TAB><outcome>="
							+ "<count>..., one or more, sorted and distinct)");
					return;
				}

				Map<Integer, Vector> fileVectors = this.vectors.get(fields[1]);

				if (fileVectors == null) {
					this.problems.add(prefix(number) + " names a file this runner does not run: " + fields[1]);
					return;
				}

				counts.keySet().stream().filter(outcome -> outcome.startsWith(REJECT))
						.map(outcome -> outcome.substring(REJECT.length())).filter(code -> !codes.contains(code))
						.forEach(code -> this.problems.add(prefix(number) + " names a reason code this runner does not "
								+ "report: " + code));

				int total = counts.values().stream().mapToInt(Integer::intValue).sum();

				if (total != fileVectors.size())
					this.problems.add(prefix(number) + " counts " + total + " tests, but " + fields[1] + " has "
							+ fileVectors.size());

				// Kept even with a problem, so that the coverage check does not report its releases again.
				this.countLines.add(new CountLine(number, fields[1], range, Collections.unmodifiableSortedMap(counts)));
			}

			/**
			 * Records the vectors a line selects, and reports a rule that selects nothing, a line that repeats the
			 * default, and a rule that changes no outcome.
			 */
			private void select(@NonNull Line line) {
				Map<Integer, Vector> fileVectors = requireNonNull(this.vectors.get(line.file));
				Integer tcId = line.tcId;
				String rule = line.rule;
				List<Vector> selected = tcId != null ? List.of(requireNonNull(fileVectors.get(tcId)))
						: fileVectors.values().stream().filter(vector -> vector.rules().contains(rule)).toList();

				if (selected.isEmpty()) {
					this.problems.add(prefix(line.number) + " selects no vector: " + RULE_PREFIX + rule + " matches nothing in "
							+ line.file);
					return;
				}

				if (tcId != null && selected.get(0).result() == Result.VALID && line.outcome.equals(ACCEPT))
					this.problems.add(prefix(line.number) + " repeats the default: " + line.file + " tcId " + tcId
							+ " is valid");
				else if (rule != null && selected.stream().noneMatch(vector -> changes(vector, line.outcome)))
					this.problems.add(prefix(line.number) + " changes no outcome: every vector that " + RULE_PREFIX + rule
							+ " selects in " + line.file + " already has it by default");

				for (Vector vector : selected)
					this.linesByVector.computeIfAbsent(line.file, file -> new TreeMap<>())
							.computeIfAbsent(vector.tcId(), id -> new ArrayList<>()).add(line);
			}

			/**
			 * Whether an outcome differs from a vector's default: {@code accept} for a valid vector, any rejection for an
			 * invalid one, and nothing for an acceptable one.
			 */
			private static boolean changes(@NonNull Vector vector,
																		 @NonNull String outcome) {
				return switch (vector.result()) {
					case VALID -> !outcome.equals(ACCEPT);
					case INVALID -> !outcome.startsWith(REJECT);
					case ACCEPTABLE -> true;
				};
			}

			/**
			 * Reports each pair of lines that decide one vector on one release, once per pair.
			 */
			private void checkOverlaps() {
				Set<String> reported = new LinkedHashSet<>();
				List<String> overlaps = new ArrayList<>();

				this.linesByVector.forEach((file, byTcId) -> byTcId.forEach((tcId, lines) -> {
					for (int first = 0; first < lines.size(); ++first)
						for (int second = first + 1; second < lines.size(); ++second) {
							Line a = lines.get(first);
							Line b = lines.get(second);
							Optional<Integer> shared = a.jdk.firstShared(b.jdk);

							if (shared.isPresent() && reported.add(a.number + " " + b.number))
								overlaps.add(this.name + " lines " + a.number + " and " + b.number + " both decide " + file
										+ " tcId " + tcId + " on JDK " + shared.get());
						}
				}));

				this.problems.addAll(overlaps);
			}

			/**
			 * Reports each acceptable vector without a line on some release.
			 */
			private void checkAcceptableVectors() {
				this.vectors.forEach((file, byTcId) -> byTcId.values().stream()
						.filter(vector -> vector.result() == Result.ACCEPTABLE).forEach(vector -> {
							List<Range> ranges = this.linesByVector.getOrDefault(file, Map.of())
									.getOrDefault(vector.tcId(), List.of()).stream().map(Line::jdk).toList();
							Range.firstUncovered(ranges).ifPresent(feature -> this.problems.add(this.name + " has no line for "
									+ file + " tcId " + vector.tcId() + ", which is acceptable, on JDK " + feature));
						}));
			}

			/**
			 * Reports two count lines for one file on one release, and a release on which a file has none.
			 */
			private void checkCountLines() {
				for (String file : this.vectors.keySet()) {
					List<CountLine> lines = this.countLines.stream().filter(line -> line.file.equals(file)).toList();

					for (int first = 0; first < lines.size(); ++first)
						for (int second = first + 1; second < lines.size(); ++second) {
							CountLine a = lines.get(first);
							CountLine b = lines.get(second);
							a.jdk.firstShared(b.jdk).ifPresent(feature -> this.problems.add(this.name + " lines " + a.number
									+ " and " + b.number + " both count " + file + " on JDK " + feature));
						}

					Range.firstUncovered(lines.stream().map(CountLine::jdk).toList()).ifPresent(feature -> this.problems
							.add(this.name + " has no count line for " + file + " on JDK " + feature));
				}
			}

			private @NonNull String prefix(int number) {
				return this.name + " line " + number;
			}
		}
	}
}
