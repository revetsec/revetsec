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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.stream.Stream;

/**
 * {@link Hmac}: the RFC 4231 test cases for HMAC-SHA-256, -384 and -512, and the signature-MAC policy of
 * {@link Hmac#verifyTag} (RFC 7518 section 3.2): a secret at least as long as the hash output, checked before the JCA
 * sees it, and the full-length tag, checked before the constant-time comparison (INV-G1, INV-G8).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class HmacTests {
	private static final HexFormat HEX = HexFormat.of();

	// RFC 4231 section 4: test cases 1 to 4, 6 and 7 (case 5 truncates its output; see the next test).
	@TestFactory
	Stream<DynamicTest> computesTheRfc4231TestCases() {
		byte[] largeKey = filled(0xaa, 131);

		return Stream.of(
						new Case("4.2 test case 1", filled(0x0b, 20), ascii("Hi There"),
								"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
								"afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
								"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4"
										+ "be9d914eeb61f1702e696c203a126854"),
						new Case("4.3 test case 2 (a key shorter than the output)", ascii("Jefe"),
								ascii("what do ya want for nothing?"),
								"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
								"af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
								"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fd"
										+ "caeab1a34d4a6b4b636e070a38bce737"),
						new Case("4.4 test case 3", filled(0xaa, 20), filled(0xdd, 50),
								"773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
								"88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
								"fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807"
										+ "b946a337bee8942674278859e13292fb"),
						new Case("4.5 test case 4", HEX.parseHex("0102030405060708090a0b0c0d0e0f10111213141516171819"),
								filled(0xcd, 50),
								"82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
								"3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
								"b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063"
										+ "a5f19741120c4f2de2adebeb10a298dd"),
						new Case("4.7 test case 6 (a key longer than the block)", largeKey,
								ascii("Test Using Larger Than Block-Size Key - Hash Key First"),
								"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
								"4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
								"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e52"
										+ "95e64f73f63f0aec8b915a985d786598"),
						new Case("4.8 test case 7 (a key and data longer than the block)", largeKey,
								ascii("This is a test using a larger than block-size key and a larger than block-size data. The key "
										+ "needs to be hashed before being used by the HMAC algorithm."),
								"9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
								"6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
								"e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15"
										+ "134676fb6de0446065c97440fa8c6a58"))
				.map(testCase -> DynamicTest.dynamicTest(testCase.name, () -> {
					for (HashAlgorithm hash : HashAlgorithm.values()) {
						byte[] mac = Hmac.compute(hash, testCase.key, testCase.data);

						Assertions.assertEquals(testCase.expected(hash), HEX.formatHex(mac), hash::name);
						Assertions.assertEquals(hash.getLength(), mac.length, hash::name);

						Mac parts = Hmac.mac(hash, testCase.key);
						int middle = testCase.data.length / 2;
						parts.update(testCase.data, 0, middle);
						parts.update(testCase.data, middle, testCase.data.length - middle);
						Assertions.assertEquals(testCase.expected(hash), HEX.formatHex(parts.doFinal()), hash::name);
					}

					Assertions.assertEquals(testCase.sha256, HEX.formatHex(Hmac.sha256(testCase.key, testCase.data)));
					Assertions.assertEquals(testCase.sha256, HEX.formatHex(Hmac.sha256Mac(testCase.key).doFinal(testCase.data)));
				}));
	}

	// RFC 4231 section 4.6, test case 5: the RFC's 128-bit truncation is a prefix of the full MAC, and the signature
	// policy refuses it twice over: its 20-byte key is too short, and a 16-byte tag is not a full-length tag.
	@Test
	void theRfc4231TruncatedOutputIsNeverAcceptedAsASignatureTag() throws Exception {
		byte[] key = filled(0x0c, 20);
		byte[] data = ascii("Test With Truncation");
		Map<HashAlgorithm, String> truncated = Map.of(HashAlgorithm.SHA_256, "a3b6167473100ee06e0c796c2955552b",
				HashAlgorithm.SHA_384, "3abf34c3503b2a23a46efc619baef897", HashAlgorithm.SHA_512,
				"415fad6271580a531d4179bc891d87a6");

		for (HashAlgorithm hash : HashAlgorithm.values()) {
			byte[] tag = HEX.parseHex(truncated.get(hash));

			Assertions.assertArrayEquals(tag, Arrays.copyOf(Hmac.compute(hash, key, data), 16), hash::name);
			Assertions.assertEquals(KeyRejectedException.Kind.SECRET_TOO_SHORT,
					Assertions.assertThrows(KeyRejectedException.class, () -> Hmac.verifyTag(hash, key, data, tag)).getKind());

			byte[] longKey = filled(0x0c, hash.getLength());
			byte[] fullTag = Hmac.compute(hash, longKey, data);
			Assertions.assertEquals(VerifyResult.VALID, Hmac.verifyTag(hash, longKey, data, fullTag), hash::name);
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH,
					Hmac.verifyTag(hash, longKey, data, Arrays.copyOf(fullTag, 16)), hash::name);
		}
	}

	// RFC 7518 section 3.2: "A key of the same size as the hash output ... or larger MUST be used", counted in octets.
	@TestFactory
	Stream<DynamicTest> secretsShorterThanTheHashOutputAreRefusedBeforeTheJca() {
		return Stream.of(HashAlgorithm.values()).map(hash -> DynamicTest.dynamicTest(hash.name(), () -> {
			byte[] message = ascii("message");

			for (int length : new int[]{0, 1, hash.getLength() - 1}) {
				byte[] secret = filled(0x42, length);

				// An empty secret would make SecretKeySpec throw IllegalArgumentException (INV-G1); it never gets there.
				Assertions.assertEquals(KeyRejectedException.Kind.SECRET_TOO_SHORT, Assertions.assertThrows(
						KeyRejectedException.class, () -> Hmac.checkSecretLength(hash, secret)).getKind(), () -> "" + length);
				Assertions.assertEquals(KeyRejectedException.Kind.SECRET_TOO_SHORT, Assertions.assertThrows(
						KeyRejectedException.class, () -> Hmac.verifyTag(hash, secret, message, new byte[hash.getLength()]))
						.getKind(), () -> "" + length);
			}

			for (int length : new int[]{hash.getLength(), hash.getLength() + 1, 131}) {
				byte[] secret = filled(0x42, length);

				Hmac.checkSecretLength(hash, secret);
				Assertions.assertEquals(VerifyResult.VALID,
						Hmac.verifyTag(hash, secret, message, Hmac.compute(hash, secret, message)), () -> "" + length);
			}

			// The multi-byte UTF-8 secret "é" x 16 is 32 octets but 16 characters: octets are what count.
			byte[] accented = "é".repeat(hash.getLength() / 2).getBytes(StandardCharsets.UTF_8);
			Assertions.assertEquals(hash.getLength(), accented.length);
			Hmac.checkSecretLength(hash, accented);
		}));
	}

	// RFC 7518 section 3.2 forbids truncated tags; MessageDigest.isEqual calls two empty arrays equal, so the length
	// check must come first (INV-G8).
	@TestFactory
	Stream<DynamicTest> onlyTheExactFullLengthTagVerifies() {
		return Stream.of(HashAlgorithm.values()).map(hash -> DynamicTest.dynamicTest(hash.name(), () -> {
			byte[] secret = filled(0x5a, hash.getLength());
			byte[] message = ascii("eyJhbGciOiJIUzI1NiJ9.e30");
			byte[] tag = Hmac.compute(hash, secret, message);
			byte[] secretCopy = secret.clone();
			byte[] messageCopy = message.clone();
			byte[] tagCopy = tag.clone();

			Assertions.assertEquals(VerifyResult.VALID, Hmac.verifyTag(hash, secret, message, tag));
			Assertions.assertArrayEquals(secretCopy, secret, "the secret is not modified");
			Assertions.assertArrayEquals(messageCopy, message, "the message is not modified");
			Assertions.assertArrayEquals(tagCopy, tag, "the tag is not modified");

			Assertions.assertEquals(VerifyResult.WRONG_LENGTH, Hmac.verifyTag(hash, secret, message, new byte[0]));
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH,
					Hmac.verifyTag(hash, secret, message, Arrays.copyOf(tag, hash.getLength() / 2)));
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH,
					Hmac.verifyTag(hash, secret, message, Arrays.copyOf(tag, hash.getLength() - 1)));
			Assertions.assertEquals(VerifyResult.WRONG_LENGTH,
					Hmac.verifyTag(hash, secret, message, Arrays.copyOf(tag, hash.getLength() + 1)));

			for (int index : new int[]{0, hash.getLength() / 2, hash.getLength() - 1}) {
				byte[] flipped = tag.clone();
				flipped[index] ^= 0x01;
				Assertions.assertEquals(VerifyResult.MISMATCH, Hmac.verifyTag(hash, secret, message, flipped),
						() -> "bit flipped at " + index);
			}

			byte[] otherMessage = ascii("eyJhbGciOiJIUzI1NiJ9.e31");
			Assertions.assertEquals(VerifyResult.MISMATCH, Hmac.verifyTag(hash, secret, otherMessage, tag));
			Assertions.assertEquals(VerifyResult.MISMATCH, Hmac.verifyTag(hash, filled(0x5b, hash.getLength()), message,
					tag));
		}));
	}

	// A tag made under one hash never verifies under another, even when lengths agree after truncation.
	@Test
	void tagsDoNotCrossHashFunctions() throws Exception {
		byte[] secret = filled(0x33, 64);
		byte[] message = ascii("message");
		byte[] sha512 = Hmac.compute(HashAlgorithm.SHA_512, secret, message);

		Assertions.assertEquals(VerifyResult.WRONG_LENGTH, Hmac.verifyTag(HashAlgorithm.SHA_256, secret, message, sha512));
		Assertions.assertEquals(VerifyResult.MISMATCH,
				Hmac.verifyTag(HashAlgorithm.SHA_256, secret, message, Arrays.copyOf(sha512, 32)));
		Assertions.assertEquals(VerifyResult.MISMATCH,
				Hmac.verifyTag(HashAlgorithm.SHA_384, secret, message, Arrays.copyOf(sha512, 48)));
	}

	// INV-G1 inventory: the JCA's SecretKeySpec throws an unchecked IllegalArgumentException for an empty key. The
	// plain MAC helpers keep M1's documented IllegalArgumentException; the signature path refuses the secret first.
	@Test
	void anEmptyKeyIsAnIllegalArgumentOnlyOutsideTheSignaturePath() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> new SecretKeySpec(new byte[0], "HmacSHA256"));

		for (HashAlgorithm hash : HashAlgorithm.values()) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> Hmac.compute(hash, new byte[0], new byte[1]));
			Assertions.assertThrows(IllegalArgumentException.class, () -> Hmac.mac(hash, new byte[0]));
			Assertions.assertEquals(KeyRejectedException.Kind.SECRET_TOO_SHORT, Assertions.assertThrows(
					KeyRejectedException.class, () -> Hmac.verifyTag(hash, new byte[0], new byte[1], new byte[0])).getKind());
		}

		Assertions.assertThrows(IllegalArgumentException.class, () -> Hmac.sha256(new byte[0], new byte[1]));
		Assertions.assertThrows(IllegalArgumentException.class, () -> Hmac.sha256Mac(new byte[0]));
	}

	@Test
	void rejectsNullArguments() {
		byte[] secret = new byte[64];

		for (HashAlgorithm hash : HashAlgorithm.values()) {
			Assertions.assertThrows(NullPointerException.class, () -> Hmac.compute(hash, nullValue(), new byte[1]));
			Assertions.assertThrows(NullPointerException.class, () -> Hmac.compute(hash, secret, nullValue()));
			Assertions.assertThrows(NullPointerException.class, () -> Hmac.mac(hash, nullValue()));
			Assertions.assertThrows(NullPointerException.class, () -> Hmac.checkSecretLength(hash, nullValue()));
			Assertions.assertThrows(NullPointerException.class,
					() -> Hmac.verifyTag(hash, nullValue(), new byte[1], new byte[1]));
			Assertions.assertThrows(NullPointerException.class,
					() -> Hmac.verifyTag(hash, secret, nullValue(), new byte[1]));
			Assertions.assertThrows(NullPointerException.class,
					() -> Hmac.verifyTag(hash, secret, new byte[1], nullValue()));
		}

		Assertions.assertThrows(NullPointerException.class, () -> Hmac.compute(nullValue(), secret, new byte[1]));
		Assertions.assertThrows(NullPointerException.class, () -> Hmac.mac(nullValue(), secret));
		Assertions.assertThrows(NullPointerException.class, () -> Hmac.checkSecretLength(nullValue(), secret));
		Assertions.assertThrows(NullPointerException.class,
				() -> Hmac.verifyTag(nullValue(), secret, new byte[1], new byte[1]));
	}

	// M1's HMAC-SHA256 constants are unchanged, and agree with HashAlgorithm.SHA_256.
	@Test
	void theSha256ConstantsAgreeWithTheHashAlgorithm() throws GeneralSecurityException {
		Assertions.assertEquals(Hmac.HMAC_SHA256, HashAlgorithm.SHA_256.getHmacName());
		Assertions.assertEquals(Hmac.SHA256_LENGTH, HashAlgorithm.SHA_256.getLength());
		Assertions.assertEquals(Hmac.HMAC_SHA256, Hmac.sha256Mac(new byte[1]).getAlgorithm());
	}

	private static byte[] filled(int value, int length) {
		byte[] bytes = new byte[length];
		Arrays.fill(bytes, (byte) value);
		return bytes;
	}

	private static byte[] ascii(String value) {
		return value.getBytes(StandardCharsets.US_ASCII);
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> T nullValue() {
		return null;
	}

	/**
	 * One RFC 4231 test case: key, data, and the three MACs in hex.
	 */
	private static final class Case {
		private final String name;
		private final byte[] key;
		private final byte[] data;
		private final String sha256;
		private final String sha384;
		private final String sha512;

		private Case(String name,
								 byte[] key,
								 byte[] data,
								 String sha256,
								 String sha384,
								 String sha512) {
			this.name = name;
			this.key = key;
			this.data = data;
			this.sha256 = sha256;
			this.sha384 = sha384;
			this.sha512 = sha512;
		}

		private String expected(HashAlgorithm hash) {
			return switch (hash) {
				case SHA_256 -> this.sha256;
				case SHA_384 -> this.sha384;
				case SHA_512 -> this.sha512;
			};
		}
	}
}
