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

package com.revetsec.internal.json;

import org.jspecify.annotations.NonNull;

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The core JSON corpus and its SHA-256 manifest (M1 plan G7-1 and WP-1): Soklet's 25 files at {@code 38786326},
 * byte-for-byte, plus Revetsec's protocol-shaped seeds.
 * <p>
 * The manifest is checked in both directions: every line matches its file, and every file is listed. Its format is
 * WP-7's: {@code <64 lowercase hex><two spaces><path>}, LF line endings, sorted by the paths' UTF-8 bytes.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JsonCorpusManifestTests {
	private static final Pattern LINE = Pattern.compile("([0-9a-f]{64})  ((?:parse|round-trip)/[A-Za-z0-9._-]+)");

	/**
	 * The protocol-shaped seeds Revetsec adds, and the profile that must accept each.
	 */
	private static final Map<String, JsonLimits> SEEDS = Map.of(
			"parse/jwks-rsa-ec-okp.json", JsonLimits.protocolDocument(256 * 1_024),
			"parse/discovery-document.json", JsonLimits.protocolDocument(256 * 1_024),
			"parse/token-response.json", JsonLimits.protocolDocument(256 * 1_024),
			"parse/scim-user.json", JsonLimits.scim(1_024 * 1_024, 100_000),
			"parse/scim-patch-request.json", JsonLimits.scim(1_024 * 1_024, 100_000));

	// Soklet: retainedJsonCorpusMatchesItsSha256Manifest. Every manifest line matches its file, no path repeats, and
	// every corpus file is listed: 25 from Soklet plus 5 seeds.
	@Test
	void everyFileMatchesItsManifestLineAndEveryFileIsListed() throws NoSuchAlgorithmException {
		byte[] manifest = JsonCorpus.read(JsonCorpus.MANIFEST);
		String text = new String(manifest, StandardCharsets.US_ASCII);

		Assertions.assertArrayEquals(manifest, text.getBytes(StandardCharsets.US_ASCII), "the manifest is ASCII");
		Assertions.assertTrue(text.endsWith("\n"), "the manifest ends with a line feed");
		Assertions.assertFalse(text.contains("\r"), "the manifest uses LF line endings");

		List<String> listed = new ArrayList<>();
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

		for (String line : text.substring(0, text.length() - 1).split("\n", -1)) {
			var matcher = LINE.matcher(line);
			Assertions.assertTrue(matcher.matches(), () -> "malformed manifest line: " + line);
			String path = matcher.group(2);
			Assertions.assertFalse(listed.contains(path), () -> "repeated path: " + path);
			listed.add(path);
			Assertions.assertEquals(matcher.group(1), HexFormat.of().formatHex(sha256.digest(JsonCorpus.read(path))),
					path);
		}

		List<String> sorted = new ArrayList<>(listed);
		sorted.sort(JsonCorpusManifestTests::compareUtf8);
		Assertions.assertEquals(sorted, listed, "the manifest is sorted by the paths' UTF-8 bytes");
		Assertions.assertEquals(JsonCorpus.files(), sorted, "the manifest lists exactly the corpus files");
		Assertions.assertEquals(30, listed.size());
		Assertions.assertTrue(listed.containsAll(SEEDS.keySet()));
	}

	// G7-1: Soklet's 25 files are unchanged. Their digests are the ones in Soklet's own manifest at 38786326.
	@Test
	void keepsSoklets25FilesByteForByte() {
		String manifest = new String(JsonCorpus.read(JsonCorpus.MANIFEST), StandardCharsets.US_ASCII);

		for (String line : List.of(
				"7e5fe45923b8b0497b7d1c3789e0cf619066b4bd4c41d01ffec621dcc6a868be  parse/array.json",
				"85059b4e4a02e25bfb4e588ed7f9ccd5fa6c899ae4c6390820c5fc23c91064ae  parse/canonical-exponent-overflow.json",
				"48794cab193a01fa265f3f82ac02796a5336cd1e039ecef9760c1a812b27c598  parse/canonical-length-overflow.json",
				"2c2614d17b6a58910157e2869fa5514793f576f1965a8df17931cefb09c077b7  parse/deep-array.json",
				"d8e3ca834eb476cf1c6b23a2da362bc58d053e0c4e96edf8db122b5ae5814009  parse/duplicate-keys.json",
				"41c6e3d30a364be60722fc6f62dddbb8a8fdf76c4633040d79ff7ccbf0c76a6e  parse/exponent-limit.json",
				"275d7bfbea7193887de16a8482fc81e849d640a1d8873680836f4d78be6178bd  parse/incomplete-object.json",
				"43fd56f56bb9bb18bc9c33966325732b2d7e58bfe2504a2c5c164b071c1b8653  parse/invalid-number.json",
				"b28d127662f1659ca347d9b6620d7db6935a3d372aeb40ca398428eee54a9ee5  "
						+ "parse/invalid-utf8-large-truncated-envelope.bin",
				"13a02861a08985aeb224ec7bc6587751a6f458ce730552babb354fce0e1ed29b  parse/invalid-utf8-nested-object.bin",
				"b6ecf13cbcf9bb6039c6c397cf4f36c5af3dffb583e94c1e484712d1716b6d37  "
						+ "parse/invalid-utf8-property-name-truncated-id.bin",
				"ec2f00596f643c3181e6f3c6bfb64bb07cf8994f019df013681c886bee0d8b6a  parse/leading-bom.json",
				"efbdab350f2485e5ebfaca5aa26b420135fbd138fd55a0db63db9a7479290244  parse/lone-low-surrogate.json",
				"4ecc05d454e86f8daf17eaa4ca98d2a08396bfe0fe62f86432916151452aa78e  parse/object.json",
				"f790468db3fef19927f6f71fc64ed545d7c9d625f2f3dfe2249b6ed12e15faf7  parse/string-escapes.json",
				"b547356b03a5e66105c754f6c987ff53be2ee165ca993edc875a85ec5fc97eac  parse/surrogate-pair.json",
				"87705cac8d4f3285dd90fa2cf6c5fbb42d1797fb16dfaa254bcca68f69a25799  "
						+ "parse/truncated-array-object-with-whitespace.json",
				"b299963e153441d1d40e98b79f21d6661d38433e1f80e91873b21263246be13d  parse/truncated-deep-array-object.json",
				"f52f6988ba056b5810ee162eeccd3c45cf75c82c42cb48df9996f4b5892e4689  "
						+ "parse/truncated-nested-array-object.json",
				"021fb596db81e6d02bf3d2586ee3981fe519f275c0ac9ca76bbcf2ebb4097d96  parse/truncated-object-minimal.json",
				"f47e2242c4492d73b6cccf02d5f9741a9917f62919ab51bb13634b5821ebf606  round-trip/exponent-scale.json",
				"3e2ca1f05d26b02c504a0c1968779b50ee9a74f2765262f2f347a1158202a404  round-trip/large-exponent.json",
				"91b7ece59022d1fe34fbe714efa8a7e97ab3d0eae7e1222a3654b6f58a09cd1a  round-trip/line-separators.json",
				"0137589ebf5955c70b5f855fede3a82087df98f895aba169c7997bc50fd50806  round-trip/nested.json",
				"7a0c50b92434b015545fe93ab723db2d4b2cdd14a441405624a9ce8be29f1d5a  round-trip/surrogate-pair.json"))
			Assertions.assertTrue(manifest.contains(line + "\n"), line);
	}

	// WP-1: each protocol-shaped seed parses under the profile it stands for (and the other default profile), and
	// round-trips through the maximum-cap profile.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> protocolShapedSeedsParseUnderTheirProfileAndRoundTrip() {
		return SEEDS.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(seed -> DynamicTest.dynamicTest(
				seed.getKey(), () -> {
					byte[] input = JsonCorpus.read(seed.getKey());
					JsonValue value = JsonCodec.parse(input, seed.getValue());

					Assertions.assertInstanceOf(JsonObject.class, value);
					Assertions.assertEquals(value, JsonCodec.parse(input, JsonLimits.protocolDocument(256 * 1_024)));
					Assertions.assertEquals(value, JsonCodec.parse(input, JsonLimits.scim(1_024 * 1_024, 100_000)));
					Assertions.assertEquals(value, JsonCodec.parse(JsonCodec.toUtf8Bytes(value), JsonLimits.maximumCaps()));
				}));
	}

	// RFC 7517 section 5 and RFC 8037: the JWKS seed holds one RSA, one EC and one OKP public key, and no private
	// member.
	@Test
	void theJwksSeedHoldsRsaEcAndOkpPublicKeys() throws JsonParseException {
		JsonObject jwks = (JsonObject) JsonCodec.parse(JsonCorpus.read("parse/jwks-rsa-ec-okp.json"),
				JsonLimits.protocolDocument(256 * 1_024));
		List<String> keyTypes = new ArrayList<>();

		for (JsonValue key : ((JsonArray) jwks.find("keys").orElseThrow()).getElements()) {
			JsonObject jwk = (JsonObject) key;
			keyTypes.add(jwk.findString("kty").orElseThrow());

			for (String privateMember : List.of("d", "p", "q", "dp", "dq", "qi", "k"))
				Assertions.assertFalse(jwk.getMembers().containsKey(privateMember), privateMember);
		}

		Assertions.assertEquals(List.of("RSA", "EC", "OKP"), keyTypes);
	}

	private static int compareUtf8(@NonNull String first, @NonNull String second) {
		return Arrays.compareUnsigned(first.getBytes(StandardCharsets.UTF_8), second.getBytes(StandardCharsets.UTF_8));
	}
}
