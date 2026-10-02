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

import com.revetsec.testing.WycheproofVectors;
import com.revetsec.testing.WycheproofVectors.Result;
import com.revetsec.testing.WycheproofVectors.TestGroup;
import com.revetsec.testing.WycheproofVectors.TestVector;
import com.revetsec.testing.WycheproofVectors.VectorFile;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.Map.entry;
import static java.util.Objects.requireNonNull;

/**
 * The vendored Project Wycheproof files (M2 plan M2-9, the "Pins" section and exit criterion 3; plan 14.3): 28
 * unmodified files of {@code C2SP/wycheproof}'s {@code testvectors_v1/} at
 * {@code 3fa63dd0344abb611f1fb1d77e119938603ea230}, under {@code src/test/resources/vectors/wycheproof/} with the
 * upstream {@code LICENSE}, {@code SOURCE.txt} and {@code MANIFEST.sha256}.
 * <p>
 * {@link WycheproofVectors} checks the manifest in both directions and recomputes the {@code SOURCE.txt} table before
 * it hands out a vector. These tests load the real files through it and pin what the checks alone cannot: the commit,
 * the 28 file names, each file's size and counts, the totals (6,001 tests in 7,171,129 bytes), each file's git blob
 * SHA-1 upstream, the upstream {@code LICENSE}, the files left out, and the {@code NOTICE} attributions (Wycheproof,
 * and the IETF examples with their copyright notices and the Revised BSD License text). So a silent re-vendor, an
 * emptied directory, or an edited file whose manifest and {@code SOURCE.txt} were regenerated with it fails here even
 * when the files agree with each other. Every problem the checks report is also exercised on a small synthetic tree,
 * one kind at a time, so each check is known to fire.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class WycheproofManifestTests {
	private static final String COMMIT = "3fa63dd0344abb611f1fb1d77e119938603ea230";
	private static final String ARCHIVE_SHA_256 = "3e3ec73e31525d4b99a3023a28f008e812f6e3f5ec20b7ffb6a0027aef0958e3";

	/**
	 * The SHA-256 of the upstream {@code LICENSE} at the commit: the Apache License 2.0 text, which differs byte-wise
	 * from Revetsec's own {@code LICENSE} (a leading blank line, and no final line feed).
	 */
	private static final String LICENSE_SHA_256 = "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd";

	private static final String IETF_HEADING = "Examples from IETF RFCs";

	/**
	 * The Revised BSD License text as section 4.c of the IETF Trust's Legal Provisions Relating to IETF Documents,
	 * version 5.0 ({@code https://trustee.ietf.org/license-info}), sets it out and section 4.e lets a Code Component
	 * carry it, word for word with its {@code <insert year>} placeholder, as NOTICE must reproduce it. It is written in
	 * ASCII, with hyphens for the bullets and straight quotation marks, and with a space after "All rights reserved.",
	 * which the provisions' own text runs into the next sentence. Only the words are compared: line breaks and
	 * indentation may differ.
	 */
	private static final String IETF_REVISED_BSD_LICENSE = """
			Copyright (c) <insert year> IETF Trust and the persons identified as authors of the code. All rights reserved.

			Redistribution and use in source and binary forms, with or without modification, are permitted provided that \
			the following conditions are met:

			- Redistributions of source code must retain the above copyright notice, this list of conditions and the \
			following disclaimer.

			- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the \
			following disclaimer in the documentation and/or other materials provided with the distribution.

			- Neither the name of Internet Society, IETF or IETF Trust, nor the names of specific contributors, may be \
			used to endorse or promote products derived from this software without specific prior written permission.

			THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED \
			WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A \
			PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY \
			DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, \
			PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) \
			HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING \
			NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE \
			POSSIBILITY OF SUCH DAMAGE.
			""";

	/**
	 * Each vendored file's size in bytes, number of tests, and how many upstream marks valid, invalid and acceptable,
	 * at the commit (counted with Python's json module when the files were vendored; the totals match the M2 plan's
	 * "Pins").
	 */
	private static final Map<String, List<Integer>> COUNTS = Map.ofEntries(
			entry("ecdsa_secp256r1_sha256_p1363_test.json", List.of(242_550, 262, 173, 89, 0)),
			entry("ecdsa_secp384r1_sha384_p1363_test.json", List.of(283_550, 280, 193, 87, 0)),
			entry("ecdsa_secp521r1_sha512_p1363_test.json", List.of(360_316, 318, 231, 87, 0)),
			entry("ed25519_test.json", List.of(126_699, 151, 88, 63, 0)),
			entry("hmac_sha256_test.json", List.of(69_111, 174, 66, 108, 0)),
			entry("hmac_sha384_test.json", List.of(78_567, 174, 66, 108, 0)),
			entry("hmac_sha512_test.json", List.of(88_023, 174, 66, 108, 0)),
			entry("json_web_key_test.json", List.of(33_730, 26, 5, 21, 0)),
			entry("json_web_signature_test.json", List.of(252_527, 401, 46, 355, 0)),
			entry("rsa_pss_2048_sha256_mgf1_32_test.json", List.of(85_280, 108, 63, 45, 0)),
			entry("rsa_pss_2048_sha384_mgf1_48_test.json", List.of(110_184, 141, 95, 46, 0)),
			entry("rsa_pss_3072_sha256_mgf1_32_test.json", List.of(113_786, 108, 63, 45, 0)),
			entry("rsa_pss_4096_sha256_mgf1_32_test.json", List.of(142_295, 108, 63, 45, 0)),
			entry("rsa_pss_4096_sha384_mgf1_48_test.json", List.of(184_095, 141, 95, 46, 0)),
			entry("rsa_pss_4096_sha512_mgf1_64_test.json", List.of(232_338, 179, 132, 47, 0)),
			entry("rsa_pss_misc_test.json", List.of(496_116, 150, 150, 0, 0)),
			entry("rsa_signature_2048_sha256_test.json", List.of(211_075, 259, 9, 249, 1)),
			entry("rsa_signature_2048_sha384_test.json", List.of(203_297, 258, 7, 250, 1)),
			entry("rsa_signature_2048_sha512_test.json", List.of(207_663, 259, 8, 250, 1)),
			entry("rsa_signature_3072_sha256_test.json", List.of(275_722, 259, 8, 250, 1)),
			entry("rsa_signature_3072_sha384_test.json", List.of(270_950, 259, 7, 251, 1)),
			entry("rsa_signature_3072_sha512_test.json", List.of(276_682, 260, 8, 251, 1)),
			entry("rsa_signature_4096_sha256_test.json", List.of(336_643, 258, 7, 250, 1)),
			entry("rsa_signature_4096_sha384_test.json", List.of(337_859, 259, 7, 251, 1)),
			entry("rsa_signature_4096_sha512_test.json", List.of(337_859, 259, 7, 251, 1)),
			entry("rsa_signature_8192_sha256_test.json", List.of(603_244, 258, 7, 250, 1)),
			entry("rsa_signature_8192_sha384_test.json", List.of(605_484, 259, 7, 251, 1)),
			entry("rsa_signature_8192_sha512_test.json", List.of(605_484, 259, 7, 251, 1)));

	/**
	 * The git blob SHA-1 of every file taken from upstream, by its path in the vendored directory: each file's identity
	 * in the upstream tree at the commit, as the GitHub tree API listed it when the files were vendored ({@code
	 * SOURCE.txt} records the same values). Unlike sizes and counts, these change with any edit to a file's content.
	 */
	private static final Map<String, String> GIT_BLOB_SHA_1 = Map.ofEntries(
			entry("LICENSE", "7a4a3ea2424c09fbe48d455aed1eaa94d9124835"),
			entry("testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json", "d5c41c1d498a69f81e9ddf49bc217217e1ccc2b8"),
			entry("testvectors_v1/ecdsa_secp384r1_sha384_p1363_test.json", "be2d9c2856075274ce58b795a917304c706f79fb"),
			entry("testvectors_v1/ecdsa_secp521r1_sha512_p1363_test.json", "f0494e9f6cac4cfcb0a84da0357312b68952e00d"),
			entry("testvectors_v1/ed25519_test.json", "42d44cd7eca6003c7de611b6487c9cc57a124b38"),
			entry("testvectors_v1/hmac_sha256_test.json", "19181195d1bfa01ded2ca5620f0aedd0e50dc31f"),
			entry("testvectors_v1/hmac_sha384_test.json", "3ba4fbac6744df6ef62c6d0a205cc7466a8a7cbc"),
			entry("testvectors_v1/hmac_sha512_test.json", "a56fe183738b5bb19d09eb8c36c5f3f7c6218fc7"),
			entry("testvectors_v1/json_web_key_test.json", "61a0f721c388ca3c7ee769c113eea0f84f64f7a7"),
			entry("testvectors_v1/json_web_signature_test.json", "cdb1c77a770b72e340d6c1e2ed502b86628e9438"),
			entry("testvectors_v1/rsa_pss_2048_sha256_mgf1_32_test.json", "bdb7694c4b44e8f0a3569bc2a9c56c33e9d24cec"),
			entry("testvectors_v1/rsa_pss_2048_sha384_mgf1_48_test.json", "2626470be2712e92e001fa3cf21695e48b1ca78e"),
			entry("testvectors_v1/rsa_pss_3072_sha256_mgf1_32_test.json", "ae66ed7a7b1b8ff8ab1bbe277a034af49f8823bc"),
			entry("testvectors_v1/rsa_pss_4096_sha256_mgf1_32_test.json", "bc269c8ad5be25bc45a60a214ead990e27db44ff"),
			entry("testvectors_v1/rsa_pss_4096_sha384_mgf1_48_test.json", "1104795da826412538ea8fb0849f45ce6f296c29"),
			entry("testvectors_v1/rsa_pss_4096_sha512_mgf1_64_test.json", "7c6b44626473f71f6ac94694a9edc3d253976b93"),
			entry("testvectors_v1/rsa_pss_misc_test.json", "8e4d8b2ae4a91851f0c73c508203e9f734747402"),
			entry("testvectors_v1/rsa_signature_2048_sha256_test.json", "26f8d2c5b5c50bcba47653ee54d7b81e97f2ea0a"),
			entry("testvectors_v1/rsa_signature_2048_sha384_test.json", "4f46227342d74e456ddb91fb0f0ff99f4dfecbc1"),
			entry("testvectors_v1/rsa_signature_2048_sha512_test.json", "83f0083b48ad67a5faee5e2d68ac534496a2210f"),
			entry("testvectors_v1/rsa_signature_3072_sha256_test.json", "eadbe046ce232284e522b0bab426fd98669f2f1e"),
			entry("testvectors_v1/rsa_signature_3072_sha384_test.json", "78fc1d1dbea93d36e1c98bfae728795a1a9eaa9c"),
			entry("testvectors_v1/rsa_signature_3072_sha512_test.json", "a07b4380dc9cce6264d8f6bbbeb7e6d59a4cd2c2"),
			entry("testvectors_v1/rsa_signature_4096_sha256_test.json", "06f58684beabb55c28cbdd1fdcec81b83d085e5a"),
			entry("testvectors_v1/rsa_signature_4096_sha384_test.json", "492e3321c99dfcb71564038c4ae33c984f84d113"),
			entry("testvectors_v1/rsa_signature_4096_sha512_test.json", "5dcb85df9bd300c0f573bcad7070c4998073ceb5"),
			entry("testvectors_v1/rsa_signature_8192_sha256_test.json", "a6d6a96190416223337a752558f1a618899d3202"),
			entry("testvectors_v1/rsa_signature_8192_sha384_test.json", "4f1a4d74e928291c00a207853a8b190be281ecea"),
			entry("testvectors_v1/rsa_signature_8192_sha512_test.json", "a9f4cb7d43d38c0ab83d70dd8f809a7a97e64ab6"));

	private static final String MANIFEST = "MANIFEST.sha256";
	private static final String SOURCE = "SOURCE.txt";
	private static final String LICENSE = "LICENSE";

	// The synthetic tree the checks are exercised on: a LICENSE, one vector file, and the SOURCE.txt and manifest
	// that this class computes for them without the loader's help.
	private static final String SAMPLE_COMMIT = "0123456789abcdef0123456789abcdef01234567";
	private static final String SAMPLE_PATH = "testvectors_v1/sample_test.json";
	private static final String SAMPLE_LICENSE = "license text\n";
	private static final String SAMPLE = """
			{"algorithm":"SAMPLE","schema":"sample_verify_schema_v1.json","numberOfTests":3,"header":["A sample file."],\
			"notes":{"Edge":{"bugType":"EDGE_CASE","description":"An edge case."},"Legacy":{"bugType":"LEGACY",\
			"description":"A legacy case."}},"testGroups":[{"type":"SampleVerify","keySize":256,"sha":"SHA-256",\
			"publicKey":{"uncompressed":"04ab"},"tests":[{"tcId":1,"comment":"a valid case","flags":[],"msg":"",\
			"sig":"00ff","result":"valid"},{"tcId":2,"comment":"an invalid case","flags":["Edge"],"msg":"6869",\
			"sig":"zz","result":"invalid"}]},{"type":"SampleVerify","tests":[{"tcId":3,\
			"comment":"an acceptable case","flags":["Legacy","Edge"],"msg":"00","sig":"0","result":"acceptable"}]}]}
			""";

	// ---------------------------------------------------------------------------------------------------------------
	// The vendored files
	// ---------------------------------------------------------------------------------------------------------------

	// M2-9 and exit criterion 3: the loader accepts the vendored tree only after the manifest matches every other file
	// in both directions and the SOURCE.txt table matches the files, and the tree it accepts is the pinned commit's.
	@Test
	void loadsTheVendoredFilesOnlyAfterTheManifestAndTheSourceTableMatchThem() throws IOException {
		WycheproofVectors vectors = WycheproofVectors.fromVendoredFiles();

		Assertions.assertEquals(COMMIT, vectors.getCommit());
		Assertions.assertEquals(30, vectors.getCheckedFileCount(), "the manifest covers every file but itself");
		Assertions.assertEquals(List.of(), WycheproofVectors.findProblems(readTree(vendoredDirectory())));
	}

	// M2-9 ("Pins"): exactly the 28 files, each with its size and counts at the commit, and the totals, so an
	// emptied, partial or re-vendored directory cannot pass even when its manifest and SOURCE.txt agree with it.
	@Test
	void pinsTheTwentyEightFilesAndEveryCountAtThePinnedCommit() {
		WycheproofVectors vectors = WycheproofVectors.fromVendoredFiles();
		Map<String, List<Integer>> counts = new TreeMap<>();

		for (VectorFile file : vectors.getFiles())
			counts.put(file.getName(), List.of(file.getSize(), file.getTests().size(),
					file.getTests(Result.VALID).size(), file.getTests(Result.INVALID).size(),
					file.getTests(Result.ACCEPTABLE).size()));

		Assertions.assertEquals(new TreeMap<>(COUNTS), counts);
		Assertions.assertEquals(28, vectors.getFiles().size());
		Assertions.assertEquals(7_171_129, vectors.getFiles().stream().mapToInt(VectorFile::getSize).sum());
		Assertions.assertEquals(6_001, vectors.getFiles().stream().mapToInt(file -> file.getTests().size()).sum());

		int largest = vectors.getFiles().stream().mapToInt(VectorFile::getSize).max().orElseThrow();

		Assertions.assertEquals(605_484, largest);
		Assertions.assertTrue(largest <= WycheproofVectors.MAXIMUM_FILE_BYTES, "the loader's limit fits every file");

		for (VectorFile file : vectors.getFiles())
			Assertions.assertEquals(file.getNumberOfTests(), file.getJson().findLong("numberOfTests").orElseThrow()
					.intValue(), file.getName());
	}

	// M2-9 ("Pins": the per-file blob SHA-1 check) and plan 14.3 ("unmodified"): every file taken from upstream is,
	// byte for byte, the upstream blob at the commit, and the loader hands out exactly those bytes. Sizes and counts
	// alone would pass a same-size edit whose manifest and SOURCE.txt were regenerated with it; these pins would not.
	@Test
	void everyUpstreamFileIsTheUpstreamBlobAtThePinnedCommitByteForByte() throws IOException {
		Map<String, String> blobs = new TreeMap<>();

		for (Map.Entry<String, byte[]> file : readTree(vendoredDirectory()).entrySet())
			if (!file.getKey().equals(SOURCE) && !file.getKey().equals(MANIFEST))
				blobs.put(file.getKey(), gitBlobSha1(file.getValue()));

		Assertions.assertEquals(new TreeMap<>(GIT_BLOB_SHA_1), blobs);

		for (VectorFile file : WycheproofVectors.fromVendoredFiles().getFiles())
			Assertions.assertEquals(GIT_BLOB_SHA_1.get(file.getPath()), gitBlobSha1(file.getContent()), file.getPath());
	}

	// M2-9 ("Pins", and exit criterion 3's acceptable line): the only acceptable tests in the set are PKCS#1
	// MissingNull, tcId 8 in each of the twelve rsa_signature_* files; the JOSE files have none.
	@Test
	void theOnlyAcceptableTestsAreTheTwelvePkcs1MissingNullVectors() {
		WycheproofVectors vectors = WycheproofVectors.fromVendoredFiles();
		Set<String> acceptable = new TreeSet<>();

		for (VectorFile file : vectors.getFiles())
			for (TestVector test : file.getTests(Result.ACCEPTABLE)) {
				Assertions.assertEquals(List.of("MissingNull"), test.getFlags(), test::toString);
				acceptable.add(file.getName() + " " + test.getTcId());
			}

		Set<String> expected = new TreeSet<>();

		for (String file : COUNTS.keySet())
			if (file.startsWith("rsa_signature_"))
				expected.add(file + " 8");

		Assertions.assertEquals(12, expected.size());
		Assertions.assertEquals(expected, acceptable);
	}

	// M2-9 and plan 14.3: the directory holds the 28 files, the upstream LICENSE verbatim, SOURCE.txt and the
	// manifest, and nothing else: no README or other Markdown, which plan 19's claims lint would scan.
	@Test
	void vendorsTheUpstreamLicenseVerbatimAndNoMarkdownOrOtherUpstreamFiles() throws IOException {
		SortedMap<String, byte[]> tree = readTree(vendoredDirectory());
		Set<String> expected = new TreeSet<>(Set.of(LICENSE, SOURCE, MANIFEST));

		for (String file : COUNTS.keySet())
			expected.add("testvectors_v1/" + file);

		Assertions.assertEquals(expected, tree.keySet());

		byte[] license = requireNonNull(tree.get(LICENSE));
		String licenseText = new String(license, StandardCharsets.UTF_8);

		Assertions.assertEquals(LICENSE_SHA_256, sha256(license));
		Assertions.assertTrue(licenseText.contains("Apache License") && licenseText.contains("Version 2.0, January 2004"));
		Assertions.assertFalse(Arrays.equals(license, Files.readAllBytes(ContractSupport.repositoryRoot()
				.resolve(LICENSE))), "the upstream LICENSE, not a copy of Revetsec's");
	}

	// M2-9 ("Pins" and "Not vendored"): SOURCE.txt records the repository, the commit's date, the archive and its
	// SHA-256, and every upstream file the plan leaves out, with its reason: Ed448, the legacy combined JOSE file,
	// JWE, the RSAES-PKCS1-v1_5 files and the PSS files whose keys carry parameters; and that no README is vendored.
	@Test
	void sourceRecordsTheArchiveAndEveryUpstreamFileLeftOut() throws IOException {
		String source = normalizedWhitespace(Files.readString(vendoredDirectory().resolve(SOURCE),
				StandardCharsets.UTF_8));

		for (String expected : List.of("https://github.com/C2SP/wycheproof", "2026-09-02T15:59:32Z",
				"https://codeload.github.com/C2SP/wycheproof/tar.gz/" + COMMIT, ARCHIVE_SHA_256,
				"ed448_test.json Ed448 is not a supported curve", "json_web_crypto_test.json a legacy combined file",
				"json_web_encryption_test.json JWE is not supported", "rsa_pkcs1_*_test.json RSAES-PKCS1-v1_5",
				"rsa_pss_*_params_test.json keys that carry RSASSA-PSS parameters", "no README.md"))
			Assertions.assertTrue(source.contains(expected), () -> "SOURCE.txt must record " + expected);
	}

	// Plan 14.3 and A-3: NOTICE attributes the vendored files (and the fuzz seeds derived from them) at the same
	// commit as SOURCE.txt, with the upstream copyright line and license, in place of M1's placeholder, and points to
	// the SOURCE.txt beside them.
	@Test
	void noticeAttributesTheVendoredFilesAtThePinnedCommit() throws IOException {
		String notice = normalizedWhitespace(Files.readString(ContractSupport.repositoryRoot().resolve("NOTICE"),
				StandardCharsets.UTF_8));

		for (String expected : List.of("Project Wycheproof", "src/test/resources/vectors/wycheproof/testvectors_v1/",
				COMMIT, "https://github.com/C2SP/wycheproof", "Copyright 2016-2026 The Wycheproof Authors",
				"Apache License, Version 2.0", "SOURCE.txt in src/test/resources/vectors/wycheproof/ records",
				"fuzz/src/test/resources/", "\"wycheproof-\""))
			Assertions.assertTrue(notice.contains(expected), () -> "NOTICE must mention " + expected);

		Assertions.assertFalse(notice.contains("are planned but are not in the repository yet"),
				"M1's placeholder is replaced");
	}

	// A-3 and plan 14.3 ("attributed in NOTICE"): one NOTICE paragraph covers every IETF RFC example transcribed into
	// test sources, test data or fuzz seeds, M2's JOSE examples (RFC 7515, 7517, 7520 and 8037) and primitive test
	// vectors (RFC 4231 and 8032) included, under BCP 78 and the IETF Trust's Legal Provisions.
	@Test
	void noticeAttributesTheTranscribedIetfRfcExamples() throws IOException {
		String notice = normalizedWhitespace(Files.readString(ContractSupport.repositoryRoot().resolve("NOTICE"),
				StandardCharsets.UTF_8));

		for (String expected : List.of("Examples from IETF RFCs", "RFC 4231 section 4", "RFC 4648 section 10",
				"RFC 5869 appendix A", "RFC 6749 section 4.1.2 and appendix B", "RFC 7515 appendix A",
				"RFC 7517 appendix A", "RFC 7520 sections 3 and 4", "RFC 7638 section 3.1", "RFC 8032 section 7.1",
				"RFC 8037 appendix A", "RFC 9110 section 5.6.7", "BCP 78", "https://trustee.ietf.org/license-info"))
			Assertions.assertTrue(notice.contains(expected), () -> "NOTICE must mention " + expected);
	}

	// A-3, as the owner decided on 2026-09-27: the IETF paragraph reproduces the Revised BSD License text word for
	// word from the IETF Trust's Legal Provisions, version 5.0 (section 4.c's text, which section 4.e lets a Code
	// Component carry), the way the MIT paragraphs reproduce theirs. The text must sit in that paragraph, whole and in
	// order, with the provisions' own <insert year> placeholder, and the paragraph must say what it stands for.
	@Test
	void noticeReproducesTheRevisedBsdLicenseTextForTheIetfExamples() throws IOException {
		String notice = normalizedWhitespace(Files.readString(ContractSupport.repositoryRoot().resolve("NOTICE"),
				StandardCharsets.UTF_8));
		int heading = notice.indexOf(IETF_HEADING);
		Assertions.assertTrue(heading >= 0, "NOTICE must have the IETF examples paragraph");
		String ietfSection = notice.substring(heading);

		for (String expected : List.of("used under the Revised BSD License",
				"Section 4.e of the Legal Provisions, version 5.0, permits a Code Component to carry the full text of "
						+ "that license as their section 4.c sets it out, so the text is reproduced here word for word, "
						+ "with <insert year> standing for the year in which the RFC the material comes from was "
						+ "published.",
				"Versions of the Legal Provisions before the IETF Trust's correction of September 21, 2021 call the "
						+ "same license text the \"Simplified BSD License\".",
				normalizedWhitespace(IETF_REVISED_BSD_LICENSE).strip()))
			Assertions.assertTrue(ietfSection.contains(expected), () -> "NOTICE's IETF paragraph must contain "
					+ expected);

		Assertions.assertEquals(1L, occurrences(notice, "IETF Trust and the persons identified as authors of the code"),
				"the license text appears once");
		Assertions.assertFalse(notice.contains("<year>"), "the placeholder is the provisions' own, <insert year>");
	}

	// A-3, as the owner decided on 2026-09-27: RFC 4231 (2005) and RFC 4648 (2006) were published under the Internet
	// Society's notice, "Copyright (C) The Internet Society", so NOTICE names that notice for them and gives the IETF
	// Trust notice only to the other RFCs, and applies the Revised BSD License only to those RFCs' Code Components.
	// The paragraph lists exactly the RFCs whose notices and streams were checked, so an RFC added to the list without
	// a look at its notice (one published under the Internet Society's, say) fails here instead of taking the IETF
	// Trust's. The stream matters too: section 4 of the Legal Provisions, and so the Revised BSD License, does not
	// apply to the IAB, Independent or IRTF streams (version 5.0, sections 8.e to 8.g), so NOTICE says which license
	// the IRTF-stream RFC 8032's vectors are used under, and gives the Revised BSD License only to the IETF-stream
	// ones. The notices and streams were read from the RFC texts on 2026-09-28 (each RFC's "Copyright Notice" and the
	// stream line of its header), except for RFC 6749 and RFC 7638, IETF-stream RFCs with an IETF Trust notice whose
	// texts were not part of that read.
	@Test
	void noticeGivesEachIetfRfcTheCopyrightNoticeItCarries() throws IOException {
		String notice = normalizedWhitespace(Files.readString(ContractSupport.repositoryRoot().resolve("NOTICE"),
				StandardCharsets.UTF_8));
		String ietfSection = notice.substring(notice.indexOf(IETF_HEADING));
		String listedRfcs = ietfSection.substring(0, ietfSection.indexOf("None of them is in the published JAR."));

		Assertions.assertEquals(new TreeSet<>(List.of("4231", "4648", "5869", "6749", "7515", "7517", "7520", "7638",
						"8032", "8037", "9110")),
				Pattern.compile("RFC (\\d+)").matcher(listedRfcs).results().map(result -> result.group(1))
						.collect(Collectors.toCollection(TreeSet::new)),
				"each RFC in NOTICE's list has had its copyright notice and its stream checked: add a new one here, to "
						+ "the Internet Society sentence if it carries that notice, and to a stream sentence if it is not "
						+ "an IETF-stream RFC");

		for (String expected : List.of("RFC 4231 (2005) and RFC 4648 (2006) carry an Internet Society copyright "
						+ "notice, \"Copyright (C) The Internet Society\", rather than an IETF Trust one, and are subject "
						+ "to BCP 78 as it stood when each was published.",
				"The other RFCs are Copyright (c) the IETF Trust and the persons identified as the document authors, all "
						+ "rights reserved, and are subject to BCP 78 and the IETF Trust's Legal Provisions Relating to "
						+ "IETF Documents (https://trustee.ietf.org/license-info) in effect on the date each was "
						+ "published.",
				"RFC 8032 was published in the Internet Research Task Force (IRTF) stream, and section 4 of the Legal "
						+ "Provisions, which covers Code Components and the Revised BSD License, does not apply to IRTF "
						+ "documents (version 5.0, section 8.g).",
				"Its section 7.1 test vectors are copied unmodified, with attribution, under the license of section "
						+ "3.a, which section 8.c applies to IRTF documents without its limit to the IETF Standards "
						+ "Process.",
				"The rest of the RFCs with an IETF Trust notice were published in the IETF stream, and to the extent "
						+ "that material from them consists of Code Components under those provisions, it is used under "
						+ "the Revised BSD License that they describe."))
			Assertions.assertTrue(ietfSection.contains(expected), () -> "NOTICE's IETF paragraph must contain "
					+ expected);

		Assertions.assertFalse(notice.contains("The RFCs are Copyright (c) the IETF Trust"),
				"not every RFC carries an IETF Trust notice");
		Assertions.assertFalse(ietfSection.contains("from those other RFCs"),
				"the Revised BSD License covers the IETF-stream RFCs only, not RFC 8032");
	}

	// ---------------------------------------------------------------------------------------------------------------
	// The checks: each kind of problem is reported, on a synthetic tree
	// ---------------------------------------------------------------------------------------------------------------

	// The synthetic tree passes, and the views expose every checked member and the typed lookups the runners use:
	// strings, whole numbers, objects and hex, with getX failing and findX empty for an absent member.
	@Test
	void theViewsExposeTheCheckedStructureAndTypedLookups() {
		SortedMap<String, byte[]> tree = sampleTree();

		Assertions.assertEquals(List.of(), WycheproofVectors.findProblems(tree));

		WycheproofVectors vectors = WycheproofVectors.fromFiles(tree);
		VectorFile file = vectors.getFile("sample_test.json");

		Assertions.assertEquals(SAMPLE_COMMIT, vectors.getCommit());
		Assertions.assertEquals(3, vectors.getCheckedFileCount());
		Assertions.assertEquals(List.of(file), vectors.getFiles());
		Assertions.assertEquals(Optional.empty(), vectors.findFile("other_test.json"));
		Assertions.assertThrows(NoSuchElementException.class, () -> vectors.getFile("other_test.json"));

		Assertions.assertEquals("sample_test.json", file.getName());
		Assertions.assertEquals(SAMPLE_PATH, file.getPath());
		Assertions.assertEquals(utf8(SAMPLE).length, file.getSize());
		Assertions.assertArrayEquals(utf8(SAMPLE), file.getContent());
		Assertions.assertEquals("sample_verify_schema_v1.json", file.getSchema());
		Assertions.assertEquals(Optional.of("SAMPLE"), file.findAlgorithm());
		Assertions.assertEquals(3, file.getNumberOfTests());
		Assertions.assertEquals(List.of("A sample file."), file.getHeader());
		Assertions.assertEquals(Set.of("Edge", "Legacy"), file.getNotes().getMembers().keySet());
		Assertions.assertEquals(List.of(1, 2, 3), file.getTests().stream().map(TestVector::getTcId).toList());
		Assertions.assertEquals(List.of(1), file.getTests(Result.VALID).stream().map(TestVector::getTcId).toList());
		Assertions.assertEquals(List.of(2), file.getTests(Result.INVALID).stream().map(TestVector::getTcId).toList());
		Assertions.assertEquals(List.of(3), file.getTests(Result.ACCEPTABLE).stream().map(TestVector::getTcId).toList());
		Assertions.assertEquals(Optional.empty(), file.findTest(4));
		Assertions.assertThrows(NoSuchElementException.class, () -> file.getTest(4));

		TestGroup group = file.getGroups().get(0);

		Assertions.assertEquals(2, file.getGroups().size());
		Assertions.assertSame(file, group.getFile());
		Assertions.assertEquals(0, group.getIndex());
		Assertions.assertEquals("SampleVerify", group.getType());
		Assertions.assertEquals("SHA-256", group.getString("sha"));
		Assertions.assertEquals(Optional.empty(), group.findString("keySize"), "a number is not a string");
		Assertions.assertEquals(256, group.getInteger("keySize"));
		Assertions.assertEquals(Optional.empty(), group.findInteger("sha"), "a string is not a number");
		Assertions.assertEquals(Optional.of("04ab"), group.getObject("publicKey").findString("uncompressed"));
		Assertions.assertEquals(Optional.empty(), group.findObject("sha"), "a string is not an object");
		Assertions.assertEquals(List.of(1, 2), group.getTests().stream().map(TestVector::getTcId).toList());
		Assertions.assertTrue(group.getJson().find("tests").isPresent(), "the whole group object");
		Assertions.assertEquals("sample_test.json testGroups[0]", group.toString());
		assertAbsentMember("sample_test.json testGroups[1] has no string member sha",
				() -> file.getGroups().get(1).getString("sha"));
		assertAbsentMember("sample_test.json testGroups[1] has no whole-number member keySize",
				() -> file.getGroups().get(1).getInteger("keySize"));
		assertAbsentMember("sample_test.json testGroups[1] has no object member publicKey",
				() -> file.getGroups().get(1).getObject("publicKey"));

		TestVector valid = file.getTest(1);
		TestVector invalid = file.getTest(2);
		TestVector acceptable = file.getTest(3);

		Assertions.assertSame(group, valid.getGroup());
		Assertions.assertSame(file, acceptable.getFile());
		Assertions.assertSame(file.getGroups().get(1), acceptable.getGroup());
		Assertions.assertEquals(Result.VALID, valid.getResult());
		Assertions.assertEquals(Result.INVALID, invalid.getResult());
		Assertions.assertEquals(Result.ACCEPTABLE, acceptable.getResult());
		Assertions.assertEquals("an acceptable case", acceptable.getComment());
		Assertions.assertEquals(List.of(), valid.getFlags());
		Assertions.assertEquals(List.of("Legacy", "Edge"), acceptable.getFlags());
		Assertions.assertArrayEquals(new byte[]{0x00, (byte) 0xFF}, valid.getHexBytes("sig"));
		Assertions.assertArrayEquals(new byte[0], valid.getHexBytes("msg"));
		Assertions.assertArrayEquals(new byte[]{'h', 'i'}, invalid.getHexBytes("msg"));
		Assertions.assertEquals("6869", invalid.getString("msg"));
		Assertions.assertEquals(Optional.empty(), invalid.findString("jws"));
		Assertions.assertEquals(3L, acceptable.getJson().findLong("tcId").orElseThrow());
		Assertions.assertEquals("sample_test.json tcId 3 (acceptable) [Legacy, Edge]: an acceptable case",
				acceptable.toString());
		assertAbsentMember("sample_test.json tcId 2 has no string member jws", () -> invalid.getString("jws"));

		IllegalArgumentException notHex = Assertions.assertThrows(IllegalArgumentException.class,
				() -> invalid.getHexBytes("sig"));
		Assertions.assertEquals("sample_test.json tcId 2 member sig is not an even-length hex string",
				notHex.getMessage());
		Assertions.assertThrows(IllegalArgumentException.class, () -> acceptable.getHexBytes("sig"),
				"an odd-length hex string");
		Assertions.assertThrows(IllegalArgumentException.class, () -> group.getHexBytes("sha"));

		Assertions.assertEquals(Optional.of(Result.ACCEPTABLE), Result.findByWireValue("acceptable"));
		Assertions.assertEquals(Optional.empty(), Result.findByWireValue("Valid"));
		Assertions.assertEquals("valid", Result.VALID.getWireValue());

		AssertionError failure = Assertions.assertThrows(AssertionError.class, () -> WycheproofVectors.fromFiles(
				without(tree, SOURCE)));
		Assertions.assertTrue(requireNonNull(failure.getMessage()).endsWith("\n  " + MANIFEST + " line 2 lists a file "
				+ "that does not exist: " + SOURCE + "\n  " + SOURCE + " is missing"), failure::getMessage);
	}

	// M2-9 ("a manifest mismatch, which is checked first"): the manifest is sha256sum output for every other file,
	// sorted by the paths' UTF-8 bytes, with LF line endings. A changed, missing, unlisted or repeated file, a
	// malformed or misordered line, and a line for the manifest itself are each reported, and manifest problems come
	// before every other problem.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> reportsEveryStaleOrMalformedManifestLine() {
		SortedMap<String, byte[]> tree = sampleTree();
		String licenseLine = sha256(utf8(SAMPLE_LICENSE)) + "  " + LICENSE;
		byte[] changedLicense = utf8("license TEXT\n");

		return Stream.of(
				treeCase("a manifest that lists every file with its digest, in order", tree),
				treeCase("a changed file", with(tree, LICENSE, changedLicense),
						MANIFEST + " line 1 does not match the SHA-256 of " + LICENSE,
						SOURCE + " line 5 says the git blob SHA-1 of " + LICENSE + " is " + gitBlobSha1(utf8(SAMPLE_LICENSE))
								+ ", but it is " + gitBlobSha1(changedLicense)),
				treeCase("a listed file that is missing", without(tree, LICENSE),
						MANIFEST + " line 1 lists a file that does not exist: " + LICENSE, LICENSE + " is missing",
						SOURCE + " line 5 lists a file that does not exist: " + LICENSE),
				treeCase("a file that is not listed", editManifest(tree, lines -> lines.remove(1)),
						MANIFEST + " does not list " + SOURCE),
				treeCase("an uppercase digest", editManifest(tree, lines -> lines.set(0, "A" + lines.get(0).substring(1))),
						malformedManifestLine(1), MANIFEST + " does not list " + LICENSE),
				treeCase("one space before the path",
						editManifest(tree, lines -> lines.set(0, lines.get(0).replace("  ", " "))),
						malformedManifestLine(1), MANIFEST + " does not list " + LICENSE),
				treeCase("a CRLF line ending", editManifest(tree, lines -> lines.set(0, lines.get(0) + "\r")),
						malformedManifestLine(1), MANIFEST + " does not list " + LICENSE),
				treeCase("a path that leaves the directory",
						editManifest(tree, lines -> lines.add(1, sha256(utf8(SAMPLE_LICENSE)) + "  ../" + LICENSE)),
						malformedManifestLine(2)),
				treeCase("a path below testvectors_v1/",
						editManifest(tree, lines -> lines.add(sha256(utf8(SAMPLE)) + "  testvectors_v1/sub/a.json")),
						malformedManifestLine(4)),
				treeCase("no final line feed", with(tree, MANIFEST, Arrays.copyOf(requireNonNull(tree.get(MANIFEST)),
						requireNonNull(tree.get(MANIFEST)).length - 1)), MANIFEST + " does not end with a line feed"),
				treeCase("lines out of order", editManifest(tree, lines -> lines.add(0, lines.remove(1))),
						MANIFEST + " line 2 is out of order: " + LICENSE),
				treeCase("a repeated line", editManifest(tree, lines -> lines.add(0, licenseLine)),
						MANIFEST + " line 2 repeats " + LICENSE),
				treeCase("a line for the manifest itself",
						editManifest(tree, lines -> lines.add(1, sha256(utf8("")) + "  " + MANIFEST)),
						MANIFEST + " line 2 lists " + MANIFEST + " itself"),
				treeCase("an empty manifest", with(tree, MANIFEST, new byte[0]), MANIFEST + " is empty",
						MANIFEST + " does not list " + LICENSE, MANIFEST + " does not list " + SOURCE,
						MANIFEST + " does not list " + SAMPLE_PATH),
				treeCase("no manifest", without(tree, MANIFEST), MANIFEST + " is missing"));
	}

	// M2-9 and plan 14.3: only LICENSE, SOURCE.txt, the manifest and testvectors_v1/<name>.json belong in the tree.
	// A README or other Markdown (which plan 19's claims lint would scan), a file of another kind, a name outside
	// the upstream naming, a missing LICENSE and a tree with no vector file are each reported.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> reportsEveryFileThatDoesNotBelongAndEveryMissingOne() {
		SortedMap<String, byte[]> sampleOnly = new TreeMap<>(Map.of(SAMPLE_PATH, utf8(SAMPLE)));
		SortedMap<String, byte[]> licenseOnly = new TreeMap<>(Map.of(LICENSE, utf8(SAMPLE_LICENSE)));

		return Stream.of(
				treeCase("a README.md", withManifest(with(sampleTree(), "README.md", utf8("# Wycheproof\n"))),
						doesNotBelong("README.md")),
				treeCase("a text file in testvectors_v1/",
						withManifest(with(sampleTree(), "testvectors_v1/notes.txt", utf8("notes\n"))),
						doesNotBelong("testvectors_v1/notes.txt")),
				treeCase("a vector file name with an uppercase letter",
						withManifest(with(sampleTree(), "testvectors_v1/Sample_test.json", utf8(SAMPLE))),
						doesNotBelong("testvectors_v1/Sample_test.json")),
				treeCase("no LICENSE", consistent(sampleOnly), LICENSE + " is missing"),
				treeCase("no vector file", consistent(licenseOnly), "testvectors_v1/ holds no vector files"));
	}

	// M2-9 ("a count that disagrees with SOURCE.txt"): SOURCE.txt is UTF-8 with LF line endings and one Commit: line,
	// and its table has one row per file in path order, then a total row. A malformed, repeated, misordered, missing
	// or extra row, and every column that differs from the files, are each reported.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> reportsEveryStaleOrMalformedSourceLine() {
		SortedMap<String, byte[]> tree = sampleTree();
		byte[] sample = utf8(SAMPLE);
		String licenseRow = "  LICENSE  13  -  -  -  -  " + gitBlobSha1(utf8(SAMPLE_LICENSE));
		String sampleRow = "  " + SAMPLE_PATH + "  " + sample.length + "  3  1  1  1  " + gitBlobSha1(sample);
		String totalRow = "  total  " + sample.length + "  3  1  1  1  -";
		String zeros = "0".repeat(40);

		Assertions.assertEquals(List.of("Sample provenance", "", "Commit:  " + SAMPLE_COMMIT, "", licenseRow, sampleRow,
				totalRow), sourceLines(tree), "the layout the cases below edit");

		return Stream.of(
				treeCase("no SOURCE.txt", withManifest(without(tree, SOURCE)), SOURCE + " is missing"),
				treeCase("ill-formed UTF-8", withSourceBytes(tree, new byte[]{'#', (byte) 0xC0, (byte) 0x80, '\n'}),
						SOURCE + " is not well-formed UTF-8"),
				treeCase("a CRLF line ending", editSource(tree, lines -> lines.set(4, licenseRow + "\r")),
						SOURCE + " contains a carriage return (lines end with LF only)"),
				treeCase("no final line feed", withSourceBytes(tree, utf8(String.join("\n", sourceLines(tree)))),
						SOURCE + " does not end with a line feed"),
				treeCase("no Commit: line", editSource(tree, lines -> lines.remove(2)), SOURCE + " has no Commit: line"),
				treeCase("a repeated Commit: line", editSource(tree, lines -> lines.add(2, lines.get(2))),
						SOURCE + " line 4 repeats the Commit: line"),
				treeCase("an uppercase commit",
						editSource(tree, lines -> lines.set(2, "Commit:  " + SAMPLE_COMMIT.toUpperCase(Locale.ROOT))),
						malformedCommitLine(3), SOURCE + " has no Commit: line"),
				treeCase("a short commit", editSource(tree, lines -> lines.set(2, "Commit:  " + SAMPLE_COMMIT.substring(1))),
						malformedCommitLine(3), SOURCE + " has no Commit: line"),
				treeCase("a count for LICENSE",
						editSource(tree, lines -> lines.set(4, licenseRow.replace("13  -", "13  0"))),
						malformedRow(5), SOURCE + " has no row for " + LICENSE),
				treeCase("a vector file row without counts",
						editSource(tree, lines -> lines.set(5, sampleRow.replace("  3  1  1  1  ", "  -  -  -  -  "))),
						malformedRow(6), SOURCE + " has no row for " + SAMPLE_PATH),
				treeCase("a count with a leading zero",
						editSource(tree, lines -> lines.set(5, sampleRow.replace("  3  1  1  1  ", "  03  1  1  1  "))),
						malformedRow(6), SOURCE + " has no row for " + SAMPLE_PATH),
				treeCase("a total row with a git blob SHA-1", editSource(tree, lines -> lines.set(6, totalRow.replace("  -",
						"  " + zeros))), malformedRow(7), SOURCE + " has no total row"),
				treeCase("a row for a file that does not exist",
						editSource(tree, lines -> lines.add(6, "  testvectors_v1/zzz_test.json  1  1  1  0  0  " + zeros)),
						SOURCE + " line 7 lists a file that does not exist: testvectors_v1/zzz_test.json"),
				treeCase("a file with no row", editSource(tree, lines -> lines.remove(4)),
						SOURCE + " has no row for " + LICENSE),
				treeCase("a repeated row", editSource(tree, lines -> lines.add(4, licenseRow)),
						SOURCE + " line 6 repeats " + LICENSE),
				treeCase("rows out of order", editSource(tree, lines -> lines.add(5, lines.remove(4))),
						SOURCE + " line 6 is out of order: " + LICENSE),
				treeCase("a row after the total row", editSource(tree, lines -> lines.add(lines.remove(4))),
						SOURCE + " line 7 comes after the total row: " + LICENSE),
				treeCase("a wrong size", editSource(tree, lines -> lines.set(4, licenseRow.replace("  13  ", "  14  "))),
						SOURCE + " line 5 says " + LICENSE + " has 14 bytes, but the files give 13"),
				treeCase("a wrong git blob SHA-1",
						editSource(tree, lines -> lines.set(4, licenseRow.replace(gitBlobSha1(utf8(SAMPLE_LICENSE)), zeros))),
						SOURCE + " line 5 says the git blob SHA-1 of " + LICENSE + " is " + zeros + ", but it is "
								+ gitBlobSha1(utf8(SAMPLE_LICENSE))),
				treeCase("a wrong number of tests",
						editSource(tree, lines -> lines.set(5, sampleCounts(sampleRow, "4  1  1  1"))),
						SOURCE + " line 6 says " + SAMPLE_PATH + " has 4 tests, but the files give 3"),
				treeCase("a wrong number of valid tests",
						editSource(tree, lines -> lines.set(5, sampleCounts(sampleRow, "3  2  1  1"))),
						SOURCE + " line 6 says " + SAMPLE_PATH + " has 2 valid tests, but the files give 1"),
				treeCase("a wrong number of invalid tests",
						editSource(tree, lines -> lines.set(5, sampleCounts(sampleRow, "3  1  0  1"))),
						SOURCE + " line 6 says " + SAMPLE_PATH + " has 0 invalid tests, but the files give 1"),
				treeCase("a wrong number of acceptable tests",
						editSource(tree, lines -> lines.set(5, sampleCounts(sampleRow, "3  1  1  2"))),
						SOURCE + " line 6 says " + SAMPLE_PATH + " has 2 acceptable tests, but the files give 1"),
				treeCase("no total row", editSource(tree, lines -> lines.remove(6)), SOURCE + " has no total row"),
				treeCase("a repeated total row", editSource(tree, lines -> lines.add(totalRow)),
						SOURCE + " line 8 repeats the total row"),
				treeCase("a wrong total size",
						editSource(tree, lines -> lines.set(6, totalRow.replace("  " + sample.length + "  ",
								"  " + (sample.length + 1) + "  "))),
						SOURCE + " line 7 says the vector files total " + (sample.length + 1) + " bytes, but the files give "
								+ sample.length),
				treeCase("wrong total counts", editSource(tree, lines -> lines.set(6, totalRow.replace("  3  1  1  1  ",
								"  4  0  2  0  "))),
						SOURCE + " line 7 says the vector files total 4 tests, but the files give 3",
						SOURCE + " line 7 says the vector files total 0 valid tests, but the files give 1",
						SOURCE + " line 7 says the vector files total 2 invalid tests, but the files give 1",
						SOURCE + " line 7 says the vector files total 0 acceptable tests, but the files give 1"),
				treeCase("no counts compared for a vector file with a structure problem",
						editSource(consistent(new TreeMap<>(Map.of(LICENSE, utf8(SAMPLE_LICENSE), SAMPLE_PATH,
								utf8(replaceOnce(SAMPLE, "\"numberOfTests\":3", "\"numberOfTests\":4"))))), lines -> {
							lines.set(5, replaceOnce(lines.get(5), "  3  1  1  1  ", "  9  9  9  9  "));
							lines.set(6, replaceOnce(lines.get(6), "  3  1  1  1  ", "  9  9  9  9  "));
						}),
						SAMPLE_PATH + " has 3 tests, but its numberOfTests is 4"));
	}

	// M2-9 (the codec-misread and re-vendor guard): each vector file is strict JSON under the protocol-document
	// profile and has the structure the views rely on, down to every test's tcId, comment, flags and result; the
	// tcIds run from 1 to numberOfTests, each once. Every departure is reported with the file and where in it.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> reportsEveryVectorFileThatIsNotWellFormed() {
		String at = SAMPLE_PATH + " testGroups[1]";
		String test = at + ".tests[0]";
		byte[] bom = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
		byte[] withBom = Arrays.copyOf(bom, bom.length + utf8(SAMPLE).length);
		System.arraycopy(utf8(SAMPLE), 0, withBom, bom.length, utf8(SAMPLE).length);

		return Stream.of(
				vectorCase("a byte order mark", withBom, SAMPLE_PATH + " does not parse as strict JSON under the "
						+ "protocol-document profile: BOM at byte 0"),
				vectorCase("a file over the loader's limit",
						utf8(SAMPLE + " ".repeat(WycheproofVectors.MAXIMUM_FILE_BYTES + 1 - utf8(SAMPLE).length)),
						SAMPLE_PATH + " does not parse as strict JSON under the protocol-document profile: INPUT_SIZE "
								+ "at byte " + WycheproofVectors.MAXIMUM_FILE_BYTES),
				vectorCase("an array", utf8("[]\n"), SAMPLE_PATH + " is not a JSON object"),
				vectorCase("no schema", "\"schema\":\"sample_verify_schema_v1.json\",", "",
						SAMPLE_PATH + " has no string member schema"),
				vectorCase("an algorithm that is a number", "\"algorithm\":\"SAMPLE\"", "\"algorithm\":1",
						SAMPLE_PATH + " has a member algorithm that is not a string"),
				vectorCase("numberOfTests as a string", "\"numberOfTests\":3", "\"numberOfTests\":\"3\"",
						SAMPLE_PATH + " has no whole-number member numberOfTests"),
				vectorCase("a header that is not strings", "[\"A sample file.\"]", "[1]",
						SAMPLE_PATH + " has no member header that is an array of strings"),
				vectorCase("notes that are not an object", "\"notes\":{\"Edge\":{\"bugType\":\"EDGE_CASE\","
								+ "\"description\":\"An edge case.\"},\"Legacy\":{\"bugType\":\"LEGACY\","
								+ "\"description\":\"A legacy case.\"}}", "\"notes\":[]",
						SAMPLE_PATH + " has no object member notes",
						SAMPLE_PATH + " testGroups[0].tests[1] has a flag that notes does not define: Edge",
						test + " has a flag that notes does not define: Legacy",
						test + " has a flag that notes does not define: Edge"),
				vectorCase("no testGroups", "\"testGroups\":", "\"groups\":", SAMPLE_PATH + " has no array member testGroups"),
				vectorCase("a group that is not an object", "{\"type\":\"SampleVerify\",\"tests\":[{\"tcId\":3,"
								+ "\"comment\":\"an acceptable case\",\"flags\":[\"Legacy\",\"Edge\"],\"msg\":\"00\","
								+ "\"sig\":\"0\",\"result\":\"acceptable\"}]}", "1",
						at + " is not an object", SAMPLE_PATH + " has 2 tests, but its numberOfTests is 3"),
				vectorCase("a group with no type", "{\"type\":\"SampleVerify\",\"tests\"", "{\"tests\"",
						at + " has no string member type"),
				vectorCase("a group with no tests", "\"tests\":[{\"tcId\":3", "\"cases\":[{\"tcId\":3",
						at + " has no array member tests", SAMPLE_PATH + " has 2 tests, but its numberOfTests is 3"),
				vectorCase("a test that is not an object", "{\"tcId\":3,\"comment\":\"an acceptable case\","
								+ "\"flags\":[\"Legacy\",\"Edge\"],\"msg\":\"00\",\"sig\":\"0\",\"result\":\"acceptable\"}", "3",
						test + " is not an object"),
				vectorCase("a tcId of 0", "\"tcId\":3", "\"tcId\":0", test + " has no positive whole-number member tcId"),
				vectorCase("a fractional tcId", "\"tcId\":3", "\"tcId\":3.5",
						test + " has no positive whole-number member tcId"),
				vectorCase("a test with no comment", "\"comment\":\"an acceptable case\",", "",
						test + " has no string member comment"),
				vectorCase("flags that are not strings", "\"flags\":[\"Legacy\",\"Edge\"]", "\"flags\":[1]",
						test + " has no member flags that is an array of strings"),
				vectorCase("a flag that notes does not define", "\"flags\":[\"Legacy\",\"Edge\"]",
						"\"flags\":[\"Legacy\",\"Other\"]", test + " has a flag that notes does not define: Other"),
				vectorCase("a result in the wrong case", "\"result\":\"acceptable\"", "\"result\":\"Acceptable\"",
						test + " has no member result that is valid, invalid or acceptable"),
				vectorCase("a numberOfTests that differs", "\"numberOfTests\":3", "\"numberOfTests\":4",
						SAMPLE_PATH + " has 3 tests, but its numberOfTests is 4"),
				vectorCase("a repeated tcId", "\"tcId\":3", "\"tcId\":2", SAMPLE_PATH + " repeats tcId 2"),
				vectorCase("tcIds that skip a number", "\"tcId\":3", "\"tcId\":4",
						SAMPLE_PATH + "'s tcIds do not run from 1 to 3"));
	}

	// ---------------------------------------------------------------------------------------------------------------
	// Helpers
	// ---------------------------------------------------------------------------------------------------------------

	/**
	 * A case that expects exactly these problems, in this order, from {@code findProblems}; and from {@code fromFiles}
	 * an {@link AssertionError} that lists exactly them, so a tree with even one problem hands out no vector, or the
	 * views when there is none.
	 */
	private static @NonNull DynamicTest treeCase(@NonNull String name, @NonNull SortedMap<@NonNull String, byte @NonNull []> tree, @NonNull String @NonNull ... expected) {
		return DynamicTest.dynamicTest(name, () -> {
			Assertions.assertEquals(List.of(expected), WycheproofVectors.findProblems(tree));

			if (expected.length == 0) {
				Assertions.assertFalse(WycheproofVectors.fromFiles(tree).getFiles().isEmpty());
				return;
			}

			AssertionError failure = Assertions.assertThrows(AssertionError.class,
					() -> WycheproofVectors.fromFiles(tree));
			String message = requireNonNull(failure.getMessage());

			Assertions.assertEquals(List.of(expected), List.of(message.substring(message.indexOf(":\n  ") + 4)
					.split("\n  ", -1)), message);
		});
	}

	/**
	 * A case whose vector file is {@code SAMPLE} with one substring replaced, in a tree that is otherwise consistent.
	 */
	private static @NonNull DynamicTest vectorCase(@NonNull String name, @NonNull String from, @NonNull String to, @NonNull String @NonNull ... expected) {
		return vectorCase(name, utf8(replaceOnce(SAMPLE, from, to)), expected);
	}

	/**
	 * A case whose vector file has the given content, in a tree that is otherwise consistent.
	 */
	private static @NonNull DynamicTest vectorCase(@NonNull String name, byte @NonNull [] content, @NonNull String @NonNull ... expected) {
		return treeCase(name, consistent(new TreeMap<>(Map.of(LICENSE, utf8(SAMPLE_LICENSE), SAMPLE_PATH, content))),
				expected);
	}

	private static void assertAbsentMember(@NonNull String expectedMessage, @NonNull Executable lookup) {
		NoSuchElementException exception = Assertions.assertThrows(NoSuchElementException.class, lookup);
		Assertions.assertEquals(expectedMessage, exception.getMessage());
	}

	/**
	 * The consistent synthetic tree: {@code SAMPLE_LICENSE}, {@code SAMPLE}, and their SOURCE.txt and manifest.
	 */
	private static @NonNull SortedMap<@NonNull String, byte @NonNull []> sampleTree() {
		return consistent(new TreeMap<>(Map.of(LICENSE, utf8(SAMPLE_LICENSE), SAMPLE_PATH, utf8(SAMPLE))));
	}

	/**
	 * A tree the checks accept for well-formed files: the given files, a SOURCE.txt with a Commit: line and a row for
	 * each of them computed here (independently of the loader: counts come from the JSON text), and a manifest.
	 */
	private static @NonNull SortedMap<@NonNull String, byte @NonNull []> consistent(@NonNull SortedMap<@NonNull String, byte @NonNull []> files) {
		StringBuilder source = new StringBuilder("Sample provenance\n\nCommit:  " + SAMPLE_COMMIT + "\n\n");
		long bytes = 0;
		long[] totals = new long[4];

		for (Map.Entry<String, byte[]> file : files.entrySet()) {
			byte[] content = file.getValue();

			if (file.getKey().equals(LICENSE)) {
				source.append("  LICENSE  ").append(content.length).append("  -  -  -  -  ").append(gitBlobSha1(content))
						.append('\n');
				continue;
			}

			String json = new String(content, StandardCharsets.UTF_8);
			long[] counts = {occurrences(json, "\"tcId\":"), occurrences(json, "\"result\":\"valid\""),
					occurrences(json, "\"result\":\"invalid\""), occurrences(json, "\"result\":\"acceptable\"")};

			source.append("  ").append(file.getKey()).append("  ").append(content.length);

			for (int index = 0; index < counts.length; ++index) {
				source.append("  ").append(counts[index]);
				totals[index] += counts[index];
			}

			source.append("  ").append(gitBlobSha1(content)).append('\n');
			bytes += content.length;
		}

		source.append("  total  ").append(bytes);

		for (long total : totals)
			source.append("  ").append(total);

		source.append("  -\n");

		SortedMap<String, byte[]> tree = new TreeMap<>(files);
		tree.put(SOURCE, utf8(source.toString()));
		return withManifest(tree);
	}

	/**
	 * The tree with its manifest replaced by one for every other file, sorted by path, in sha256sum format.
	 */
	private static @NonNull SortedMap<@NonNull String, byte @NonNull []> withManifest(@NonNull SortedMap<@NonNull String, byte @NonNull []> files) {
		SortedMap<String, byte[]> tree = new TreeMap<>(files);
		tree.remove(MANIFEST);
		StringBuilder manifest = new StringBuilder();

		for (Map.Entry<String, byte[]> file : tree.entrySet())
			manifest.append(sha256(file.getValue())).append("  ").append(file.getKey()).append('\n');

		tree.put(MANIFEST, utf8(manifest.toString()));
		return tree;
	}

	private static @NonNull SortedMap<@NonNull String, byte @NonNull []> with(@NonNull SortedMap<@NonNull String, byte @NonNull []> files, @NonNull String path, byte @NonNull [] content) {
		SortedMap<String, byte[]> tree = new TreeMap<>(files);
		tree.put(path, content);
		return tree;
	}

	private static @NonNull SortedMap<@NonNull String, byte @NonNull []> without(@NonNull SortedMap<@NonNull String, byte @NonNull []> files, @NonNull String path) {
		SortedMap<String, byte[]> tree = new TreeMap<>(files);
		Assertions.assertNotNull(tree.remove(path), path);
		return tree;
	}

	/**
	 * The tree with its manifest's lines edited and nothing else changed.
	 */
	private static @NonNull SortedMap<@NonNull String, byte @NonNull []> editManifest(@NonNull SortedMap<@NonNull String, byte @NonNull []> files, @NonNull Consumer<@NonNull List<@NonNull String>> edit) {
		return with(files, MANIFEST, utf8(editLines(new String(requireNonNull(files.get(MANIFEST)),
				StandardCharsets.UTF_8), edit)));
	}

	/**
	 * The tree with SOURCE.txt's lines edited and the manifest regenerated, so only the edit is a problem.
	 */
	private static @NonNull SortedMap<@NonNull String, byte @NonNull []> editSource(@NonNull SortedMap<@NonNull String, byte @NonNull []> files, @NonNull Consumer<@NonNull List<@NonNull String>> edit) {
		return withSourceBytes(files, utf8(editLines(String.join("\n", sourceLines(files)) + "\n", edit)));
	}

	private static @NonNull SortedMap<@NonNull String, byte @NonNull []> withSourceBytes(@NonNull SortedMap<@NonNull String, byte @NonNull []> files, byte @NonNull [] source) {
		return withManifest(with(files, SOURCE, source));
	}

	private static @NonNull List<@NonNull String> sourceLines(@NonNull SortedMap<@NonNull String, byte @NonNull []> files) {
		String text = new String(requireNonNull(files.get(SOURCE)), StandardCharsets.UTF_8);
		return List.of(text.substring(0, text.length() - 1).split("\n", -1));
	}

	/**
	 * Applies an edit to the lines of an LF-terminated text and joins them again with a final LF.
	 */
	private static @NonNull String editLines(@NonNull String text, @NonNull Consumer<@NonNull List<@NonNull String>> edit) {
		List<String> lines = new ArrayList<>(List.of(text.substring(0, text.length() - 1).split("\n", -1)));
		edit.accept(lines);
		return lines.stream().map(line -> line + "\n").collect(Collectors.joining());
	}

	/**
	 * A sample row with its four counts replaced.
	 */
	private static @NonNull String sampleCounts(@NonNull String sampleRow, @NonNull String counts) {
		return replaceOnce(sampleRow, "  3  1  1  1  ", "  " + counts + "  ");
	}

	private static @NonNull String replaceOnce(@NonNull String text, @NonNull String from, @NonNull String to) {
		int index = text.indexOf(from);
		Assertions.assertTrue(index >= 0 && text.indexOf(from, index + 1) < 0, () -> "exactly one occurrence of " + from);
		return text.substring(0, index) + to + text.substring(index + from.length());
	}

	private static long occurrences(@NonNull String text, @NonNull String substring) {
		long count = 0;

		for (int index = text.indexOf(substring); index >= 0; index = text.indexOf(substring, index + 1))
			++count;

		return count;
	}

	/**
	 * The text with every run of whitespace, line breaks included, replaced by one space, so a phrase matches across
	 * line wrapping and table padding.
	 */
	private static @NonNull String normalizedWhitespace(@NonNull String text) {
		return text.replaceAll("\\s+", " ");
	}

	private static @NonNull String doesNotBelong(@NonNull String path) {
		return path + " does not belong here: only LICENSE, SOURCE.txt, MANIFEST.sha256 and testvectors_v1/<name>.json "
				+ "are vendored";
	}

	private static @NonNull String malformedManifestLine(int number) {
		return MANIFEST + " line " + number + " is malformed (expected <64 lowercase hex digits><two spaces><path>)";
	}

	private static @NonNull String malformedCommitLine(int number) {
		return SOURCE + " line " + number + " is malformed (expected Commit: and 40 lowercase hex digits)";
	}

	private static @NonNull String malformedRow(int number) {
		return SOURCE + " line " + number + " is malformed (expected a file table row: <path> <bytes> <tests> <valid> "
				+ "<invalid> <acceptable> <git blob SHA-1>, with - for each count of LICENSE, or the total row)";
	}

	private static @NonNull Path vendoredDirectory() {
		return ContractSupport.repositoryRoot().resolve(WycheproofVectors.RELATIVE_SOURCE);
	}

	/**
	 * Every regular file under {@code root}, by its path relative to {@code root} with {@code /} separators, read here
	 * rather than through the loader.
	 */
	private static @NonNull SortedMap<@NonNull String, byte @NonNull []> readTree(@NonNull Path root) throws IOException {
		SortedMap<String, byte[]> files = new TreeMap<>();

		try (Stream<Path> paths = Files.walk(root)) {
			for (Path path : paths.filter(Files::isRegularFile).toList())
				files.put(root.relativize(path).toString().replace('\\', '/'), Files.readAllBytes(path));
		}

		return files;
	}

	private static byte @NonNull [] utf8(@NonNull String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	private static @NonNull String sha256(byte @NonNull [] content) {
		return HexFormat.of().formatHex(digest("SHA-256", content));
	}

	/**
	 * How git names a blob: the SHA-1 of {@code "blob <size>\0"} followed by the content.
	 */
	private static @NonNull String gitBlobSha1(byte @NonNull [] content) {
		byte[] header = ("blob " + content.length + "\0").getBytes(StandardCharsets.US_ASCII);
		byte[] blob = Arrays.copyOf(header, header.length + content.length);
		System.arraycopy(content, 0, blob, header.length, content.length);
		return HexFormat.of().formatHex(digest("SHA-1", blob));
	}

	private static byte @NonNull [] digest(@NonNull String algorithm, byte @NonNull [] content) {
		try {
			return MessageDigest.getInstance(algorithm).digest(content);
		} catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException(exception);
		}
	}
}
