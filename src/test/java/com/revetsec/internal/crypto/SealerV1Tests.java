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

import org.jspecify.annotations.Nullable;

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.encoding.Base64Url;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * The StateSealer v1 format as pure functions (M1 plan, "StateSealer v1"; G6-8 and exit criterion 7).
 * <p>
 * The known-answer vectors below are normative. They were generated once on JDK 17.0.20.1 with
 * {@link SealerV1#seal}, found byte-identical on 21, 25 and 27, and matched by an independent implementation of the
 * plan's formulas on pyca/cryptography 50.0.1 (OpenSSL). Every JDK in CI must reproduce them byte for byte. A second,
 * in-test transcription of the formulas with raw JCA calls checks them again on every run. Changing a vector breaks
 * every value sealed in the field; that needs a new version byte, not an edit here.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class SealerV1Tests {
	private static final String KEY_ID_64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567._~-";
	private static final String JSON_PLAINTEXT = "{\"state\":\"af0ifjsldkj\",\"nonce\":\"n-0S6_WzA2Mj\"}";

	/**
	 * The normative KAT: master key, key ID, type, context, notAfter, plaintext, salt, IV and the sealed value.
	 */
	private static final List<Vector> VECTORS = List.of(
			new Vector("app label, JSON plaintext", sequence(0x00, 32, 1), "2026-09", SealedStateType.APP, "google",
					1_790_000_000L, JSON_PLAINTEXT, sequence(0xa0, 16, 1), sequence(0xc0, 12, 1),
					"AQcyMDI2LTA5oKGio6SlpqeoqaqrrK2ur8DBwsPExcbHyMnKy7EizVtmzlLqMWaKKmBEcOfHoVajofVUDPZrAYtD3gZT8JxKJ-Dyy-"
							+ "OB9e_mBk8S3ytnKAA46gzdn-Kp9chD3OZi3HjQuHE"),
			new Vector("pending-authorization label, empty plaintext, one-character key ID", sequence(0x20, 32, 1), "a",
					SealedStateType.PENDING_AUTHORIZATION, "c", 1L, "", new byte[16], new byte[12],
					"AQFhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGYKmIORZTyxzG-eiLU4k9_0JFjlFCvM7Q"),
			new Vector("pending-saml label, non-ASCII plaintext and context, 64-character key ID", sequence(0xff, 32, -1),
					KEY_ID_64, SealedStateType.PENDING_SAML, "tenant/\u00e9/\ud834\udd1e", 4_102_444_800L,
					"h\u00e9llo w\u00f6rld \u2713 \ud834\udd1e", filled(0xff, 16), filled(0xff, 12),
					"AUBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1NjcuX34t__________________"
							+ "___________________43ZD9BhUhsVpUtKvzjGReGMKK0oo_psmLjz-jZOAEY6IC8Aj_eBuWHCV5A4VjI"),
			new Vector("oidc-session label, otherwise the first vector's inputs", sequence(0x00, 32, 1), "2026-09",
					SealedStateType.OIDC_SESSION, "google", 1_790_000_000L, JSON_PLAINTEXT, sequence(0xa0, 16, 1),
					sequence(0xc0, 12, 1),
					"AQcyMDI2LTA5oKGio6SlpqeoqaqrrK2ur8DBwsPExcbHyMnKywP9TFt1T2bOidrLHcU80yEL-JPDAjMAQ2nGj7YO94W-CnauWcRSckAQ"
							+ "M315CDoDTwUiQAYqjn8q4Toqwy6fEKqBjh_nO6M"));

	// Exit criterion 7: the StateSealer v1 KAT is byte-identical on every JDK.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> sealsTheNormativeKnownAnswerVectorsByteForByte() {
		return VECTORS.stream().map(vector -> DynamicTest.dynamicTest(vector.name, () -> {
			SealerV1.Key key = SealerV1.Key.fromMasterKey(vector.keyId, vector.masterKey);
			String sealed = SealerV1.seal(key, vector.type, vector.context, vector.notAfter,
					vector.plaintext.getBytes(StandardCharsets.UTF_8), vector.salt, vector.iv);

			Assertions.assertEquals(vector.sealed, sealed);
			Assertions.assertEquals(vector.sealed, referenceSeal(vector), "the in-test transcription of the formulas");
		}));
	}

	// The build() self-test seals the second vector's input and compares the bytes, so a provider that drops or alters
	// the additional authenticated data, ignores the IV or truncates the tag fails at build(). Its embedded answer must
	// stay the vector's.
	@Test
	void theSelfTestsKnownAnswerIsTheSecondKnownAnswerVector() throws Exception {
		Vector vector = VECTORS.get(1);

		Assertions.assertEquals(vector.sealed, SealerV1.SELF_TEST_KNOWN_ANSWER);
		Assertions.assertEquals("a", vector.keyId);
		Assertions.assertEquals(SealedStateType.PENDING_AUTHORIZATION, vector.type);
		Assertions.assertEquals("c", vector.context);
		Assertions.assertEquals(1L, vector.notAfter);
		Assertions.assertEquals("", vector.plaintext);
		Assertions.assertArrayEquals(sequence(0x20, 32, 1), vector.masterKey);
		Assertions.assertArrayEquals(new byte[16], vector.salt);
		Assertions.assertArrayEquals(new byte[12], vector.iv);
		Assertions.assertTrue(SealerV1.passesSelfTest(SealerV1.Key.fromMasterKey(vector.keyId, vector.masterKey),
				new byte[16], new byte[12]));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> opensTheKnownAnswerVectorsUntilTheirNotAfter() {
		return VECTORS.stream().map(vector -> DynamicTest.dynamicTest(vector.name, () -> {
			Map<String, SealerV1.Key> keys = Map.of(vector.keyId, SealerV1.Key.fromMasterKey(vector.keyId,
					vector.masterKey));
			Instant notAfter = Instant.ofEpochSecond(vector.notAfter);

			Assertions.assertEquals(vector.plaintext, SealerV1.open(vector.sealed, 16_384, keys, vector.type,
					vector.context, notAfter.minusNanos(1)));
			Assertions.assertEquals(UnsealException.Kind.EXPIRED, kindOf(() -> SealerV1.open(vector.sealed, 16_384, keys,
					vector.type, vector.context, notAfter)));
		}));
	}

	// G6-8: the overhead is 54 + kidLen bytes; the header is 0x01 || kidLen || kid || S(16) || IV(12).
	@Test
	void laysOutTheHeaderAndAddsFiftyFourBytesPlusTheKeyId() throws Exception {
		Vector vector = VECTORS.get(0);
		byte[] bytes = Base64Url.decode(vector.sealed);
		int keyIdLength = vector.keyId.length();

		Assertions.assertEquals(54, SealerV1.FIXED_OVERHEAD);
		Assertions.assertEquals(SealerV1.FIXED_OVERHEAD + keyIdLength + vector.plaintext.length(), bytes.length);
		Assertions.assertEquals(SealerV1.VERSION, bytes[0]);
		Assertions.assertEquals(keyIdLength, bytes[1]);
		Assertions.assertEquals(vector.keyId, new String(bytes, 2, keyIdLength, StandardCharsets.US_ASCII));
		Assertions.assertArrayEquals(vector.salt, Arrays.copyOfRange(bytes, 2 + keyIdLength, 18 + keyIdLength));
		Assertions.assertArrayEquals(vector.iv, Arrays.copyOfRange(bytes, 18 + keyIdLength, 30 + keyIdLength));
	}

	// M1 plan "Size": a 700 B payload with kid 2026-09 seals to about 1,015 characters; the formula is exact.
	@Test
	void predictsTheSealedLengthExactly() throws Exception {
		Assertions.assertEquals(1_015, SealerV1.sealedLength(7, 700));

		for (int keyIdLength : new int[]{1, 2, 3, 7, 63, 64}) {
			SealerV1.Key key = SealerV1.Key.fromMasterKey("k".repeat(keyIdLength), sequence(1, 32, 3));

			for (int plaintextLength = 0; plaintextLength <= 40; ++plaintextLength) {
				String sealed = SealerV1.seal(key, SealedStateType.APP, "c", 0, new byte[plaintextLength], new byte[16],
						new byte[12]);
				Assertions.assertEquals(SealerV1.sealedLength(keyIdLength, plaintextLength), sealed.length());
			}
		}

		Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.sealedLength(0, 0));
		Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.sealedLength(65, 0));
		Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.sealedLength(1, -1));
		// ceil(4 * (54 + 64 + 2,147,483,647) / 3), computed without overflow.
		Assertions.assertEquals(2_863_311_687L, SealerV1.sealedLength(64, Integer.MAX_VALUE));
	}

	// G6-8 and G6-10: the type label is bound into both the key and the AAD, so no label opens another's value.
	@Test
	void aValueOpensOnlyUnderTheTypeItWasSealedUnder() throws Exception {
		SealerV1.Key key = SealerV1.Key.fromMasterKey("k", sequence(7, 32, 5));
		Map<String, SealerV1.Key> keys = Map.of("k", key);
		Set<String> labels = new HashSet<>();

		for (SealedStateType sealedType : SealedStateType.values()) {
			labels.add(sealedType.getLabel());
			String sealed = SealerV1.seal(key, sealedType, "ctx", Long.MAX_VALUE, bytes("x"), new byte[16], new byte[12]);

			for (SealedStateType openedType : SealedStateType.values()) {
				if (openedType == sealedType)
					Assertions.assertEquals("x", SealerV1.open(sealed, 4_096, keys, openedType, "ctx", Instant.EPOCH));
				else
					Assertions.assertEquals(UnsealException.Kind.INVALID, kindOf(() -> SealerV1.open(sealed, 4_096, keys,
							openedType, "ctx", Instant.EPOCH)), sealedType + " opened as " + openedType);
			}
		}

		Assertions.assertEquals(Set.of("revetsec/pending-authorization/v1", "revetsec/pending-saml/v1",
				"revetsec/oidc-session/v1", "revetsec/app/v1", "revetsec/as-record/v1"), labels);
	}

	// The unseal order (M1 plan): each step's failure is INVALID, with the same fixed message and no cause.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsEachMalformedValueAsInvalid() throws Exception {
		Vector vector = VECTORS.get(0);
		byte[] authentic = Base64Url.decode(vector.sealed);
		Map<String, SealerV1.Key> keys = Map.of(vector.keyId, SealerV1.Key.fromMasterKey(vector.keyId,
				vector.masterKey));
		Instant now = Instant.ofEpochSecond(vector.notAfter - 1);

		return Stream.of(
				// 1. length before decoding
				Map.entry("longer than the maximum", vector.sealed + "A".repeat(4_096)),
				// 2. alphabet
				Map.entry("a standard-Base64 character", vector.sealed.replace('-', '+')),
				Map.entry("a space", vector.sealed.substring(0, 10) + " " + vector.sealed.substring(11)),
				Map.entry("a non-ASCII letter", "\u00c1" + vector.sealed.substring(1)),
				// 3. canonical form
				Map.entry("padding", vector.sealed + "="),
				Map.entry("non-zero trailing bits", nonCanonical(vector.sealed)),
				Map.entry("an impossible length", vector.sealed + "A"),
				Map.entry("empty", ""),
				// 4. minimum length, version, key ID length and characters
				Map.entry("54 bytes", encode(Arrays.copyOf(authentic, 54))),
				Map.entry("version 0x00", encode(with(authentic, 0, 0x00))),
				Map.entry("version 0x02", encode(with(authentic, 0, 0x02))),
				Map.entry("version 0x81", encode(with(authentic, 0, 0x81))),
				Map.entry("key ID length 0", encode(with(authentic, 1, 0))),
				Map.entry("key ID length 65", encode(with(authentic, 1, 65))),
				Map.entry("key ID length 255", encode(with(authentic, 1, 255))),
				Map.entry("key ID longer than the value allows", encode(with(Arrays.copyOf(authentic, 60), 1, 7))),
				Map.entry("a slash in the key ID", encode(with(authentic, 6, '/'))),
				Map.entry("a NUL in the key ID", encode(with(authentic, 6, 0))),
				Map.entry("a non-ASCII byte in the key ID", encode(with(authentic, 6, 0xC3))),
				// 5. exact key ID lookup
				Map.entry("an unknown key ID", encode(with(authentic, 8, '8'))),
				Map.entry("an unknown key ID with a letter", encode(with(authentic, 2, 'X'))),
				// 7. authentication
				Map.entry("a flipped salt bit", encode(with(authentic, 9, authentic[9] ^ 0x01))),
				Map.entry("a flipped IV bit", encode(with(authentic, 25, authentic[25] ^ 0x80))),
				Map.entry("a flipped ciphertext bit", encode(with(authentic, 40, authentic[40] ^ 0x10))),
				Map.entry("a flipped tag bit", encode(with(authentic, authentic.length - 1,
						authentic[authentic.length - 1] ^ 0x01))),
				Map.entry("an appended byte", encode(Arrays.copyOf(authentic, authentic.length + 1))),
				Map.entry("a removed byte", encode(Arrays.copyOf(authentic, authentic.length - 1)))
		).map(entry -> DynamicTest.dynamicTest(entry.getKey(), () -> {
			UnsealException e = Assertions.assertThrows(UnsealException.class,
					() -> SealerV1.open(entry.getValue(), 4_096, keys, vector.type, vector.context, now));
			assertInvalid(e);
		}));
	}

	// Step 6: the context is bound into the AAD, compared as UTF-8 bytes.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsAnyOtherContext() {
		Vector vector = VECTORS.get(0);

		return Stream.of("Google", "google ", " google", "googl", "google\u0000", "g\u043e\u043egle", "microsoft")
				.map(context -> DynamicTest.dynamicTest(context, () -> {
					Map<String, SealerV1.Key> keys = Map.of(vector.keyId, SealerV1.Key.fromMasterKey(vector.keyId,
							vector.masterKey));
					assertInvalid(Assertions.assertThrows(UnsealException.class, () -> SealerV1.open(vector.sealed, 4_096,
							keys, vector.type, context, Instant.EPOCH)));
				}));
	}

	// Step 5: lookup is by exact key ID; another key under the same ID fails authentication (no trial decryption).
	@Test
	void neverTriesAKeyOtherThanTheOneTheKeyIdNames() throws Exception {
		Vector vector = VECTORS.get(0);
		SealerV1.Key right = SealerV1.Key.fromMasterKey(vector.keyId, vector.masterKey);
		SealerV1.Key wrong = SealerV1.Key.fromMasterKey(vector.keyId, sequence(0x01, 32, 1));
		SealerV1.Key other = SealerV1.Key.fromMasterKey("other", vector.masterKey);

		assertInvalid(Assertions.assertThrows(UnsealException.class, () -> SealerV1.open(vector.sealed, 4_096,
				Map.of(vector.keyId, wrong, "other", right), vector.type, vector.context, Instant.EPOCH)));
		assertInvalid(Assertions.assertThrows(UnsealException.class, () -> SealerV1.open(vector.sealed, 4_096,
				Map.of("other", other), vector.type, vector.context, Instant.EPOCH)));
		assertInvalid(Assertions.assertThrows(UnsealException.class, () -> SealerV1.open(vector.sealed, 4_096,
				Map.of(), vector.type, vector.context, Instant.EPOCH)));

		// Key IDs are compared exactly, case included.
		SealerV1.Key upper = SealerV1.Key.fromMasterKey("Key", vector.masterKey);
		String sealed = SealerV1.seal(upper, SealedStateType.APP, "c", Long.MAX_VALUE, bytes("x"), new byte[16],
				new byte[12]);
		assertInvalid(Assertions.assertThrows(UnsealException.class, () -> SealerV1.open(sealed, 4_096,
				Map.of("key", SealerV1.Key.fromMasterKey("key", vector.masterKey)), SealedStateType.APP, "c",
				Instant.EPOCH)));
		Assertions.assertEquals("x", SealerV1.open(sealed, 4_096, Map.of("Key", upper), SealedStateType.APP, "c",
				Instant.EPOCH));
	}

	// JDK 17 note: a ciphertext shorter than the tag makes 17.0.20's provider throw ProviderException. Step 4 stops
	// every such value first, so the outcome is INVALID on every JDK.
	@Test
	void rejectsCiphertextsShorterThanNotAfterPlusTagBeforeTheProviderSeesThem() throws Exception {
		Vector vector = VECTORS.get(0);
		byte[] authentic = Base64Url.decode(vector.sealed);
		Map<String, SealerV1.Key> keys = Map.of(vector.keyId, SealerV1.Key.fromMasterKey(vector.keyId,
				vector.masterKey));
		int headerLength = 2 + vector.keyId.length() + SealerV1.SALT_LENGTH + SealerV1.IV_LENGTH;

		for (int ciphertextLength = 0; ciphertextLength < SealerV1.NOT_AFTER_LENGTH + AesGcm.TAG_LENGTH;
				 ++ciphertextLength) {
			String truncated = encode(Arrays.copyOf(authentic, headerLength + ciphertextLength));
			assertInvalid(Assertions.assertThrows(UnsealException.class, () -> SealerV1.open(truncated, 4_096, keys,
					vector.type, vector.context, Instant.EPOCH)));
		}
	}

	// Step 8 comes after authentication: a forged value never learns whether it would have expired.
	@Test
	void reportsExpiryOnlyForAuthenticValues() throws Exception {
		Vector vector = VECTORS.get(0);
		byte[] tampered = Base64Url.decode(vector.sealed);
		tampered[tampered.length - 1] ^= 0x01;
		Map<String, SealerV1.Key> keys = Map.of(vector.keyId, SealerV1.Key.fromMasterKey(vector.keyId,
				vector.masterKey));
		Instant expired = Instant.ofEpochSecond(vector.notAfter).plusSeconds(3_600);

		Assertions.assertEquals(UnsealException.Kind.EXPIRED, kindOf(() -> SealerV1.open(vector.sealed, 4_096, keys,
				vector.type, vector.context, expired)));
		Assertions.assertEquals(UnsealException.Kind.INVALID, kindOf(() -> SealerV1.open(encode(tampered), 4_096, keys,
				vector.type, vector.context, expired)));
	}

	// Step 9: an authentic plaintext that is not well-formed UTF-8 is INVALID, never decoded with U+FFFD.
	@Test
	void rejectsAnAuthenticPlaintextThatIsNotWellFormedUtf8() throws Exception {
		SealerV1.Key key = SealerV1.Key.fromMasterKey("k", sequence(9, 32, 1));

		for (byte[] plaintext : List.of(new byte[]{(byte) 0xFF}, new byte[]{(byte) 0xC0, (byte) 0x80},
				new byte[]{(byte) 0xED, (byte) 0xA0, (byte) 0x80}, new byte[]{'o', 'k', (byte) 0xE2, (byte) 0x82})) {
			String sealed = SealerV1.seal(key, SealedStateType.APP, "c", Long.MAX_VALUE, plaintext, new byte[16],
					new byte[12]);
			assertInvalid(Assertions.assertThrows(UnsealException.class, () -> SealerV1.open(sealed, 4_096,
					Map.of("k", key), SealedStateType.APP, "c", Instant.EPOCH)));
		}
	}

	// INV-G1: a runtime failure anywhere in the steps is one more INVALID, never an escaped RuntimeException.
	@Test
	void turnsAnUnexpectedRuntimeExceptionIntoInvalid() {
		Map<String, SealerV1.Key> throwingKeys = new AbstractMap<>() {
			@Override
			public @NonNull Set<@NonNull Entry<@NonNull String, SealerV1.@NonNull Key>> entrySet() {
				throw new IllegalStateException("lookup failed");
			}
		};

		assertInvalid(Assertions.assertThrows(UnsealException.class, () -> SealerV1.open(VECTORS.get(0).sealed, 4_096,
				throwingKeys, SealedStateType.APP, "google", Instant.EPOCH)));
	}

	// Arguments are checked first: NullPointerException or IllegalArgumentException, never UnsealException.
	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void checksArgumentsBeforeAnyStep() throws Exception {
		SealerV1.Key key = SealerV1.Key.fromMasterKey("k", sequence(1, 32, 1));
		Map<String, SealerV1.Key> keys = Map.of("k", key);
		byte[] salt = new byte[16];
		byte[] iv = new byte[12];

		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.open(nullValue(), 1, keys,
				SealedStateType.APP, "c", Instant.EPOCH));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.open("", 1, nullValue(), SealedStateType.APP,
				"c", Instant.EPOCH));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.open("", 1, keys, nullValue(), "c",
				Instant.EPOCH));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.open("", 1, keys, SealedStateType.APP,
				nullValue(), Instant.EPOCH));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.open("", 1, keys, SealedStateType.APP, "c",
				nullValue()));
		Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.open("", 0, keys, SealedStateType.APP,
				"c", Instant.EPOCH));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.seal(nullValue(), SealedStateType.APP, "c",
				0, new byte[0], salt, iv));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.seal(key, nullValue(), "c", 0, new byte[0],
				salt, iv));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.seal(key, SealedStateType.APP, nullValue(), 0,
				new byte[0], salt, iv));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.seal(key, SealedStateType.APP, "c", 0,
				nullValue(), salt, iv));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.seal(key, SealedStateType.APP, "c", 0,
				new byte[0], nullValue(), iv));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.seal(key, SealedStateType.APP, "c", 0,
				new byte[0], salt, nullValue()));
		Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.seal(key, SealedStateType.APP, "c", 0,
				new byte[0], new byte[15], iv));
		Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.seal(key, SealedStateType.APP, "c", 0,
				new byte[0], salt, new byte[16]));

		for (String context : List.of("", "x".repeat(257), "\ud800", "a\udc00b", "\ud800\ud800")) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.requireContext(context));
			Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.open("", 1, keys,
					SealedStateType.APP, context, Instant.EPOCH));
			Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.seal(key, SealedStateType.APP,
					context, 0, new byte[0], salt, iv));
		}

		SealerV1.requireContext("x");
		SealerV1.requireContext("x".repeat(256));
		SealerV1.requireContext("\ud834\udd1e".repeat(128));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.requireContext(nullValue()));
	}

	// G6-9: key IDs are 1-64 characters of [A-Za-z0-9._~-]; master keys are exactly 32 bytes.
	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void acceptsOnlyValidKeyIdsAndThirtyTwoByteMasterKeys() throws GeneralSecurityException {
		for (String keyId : List.of("a", "2026-09", KEY_ID_64, "._~-", "Z9"))
			Assertions.assertTrue(SealerV1.isKeyId(keyId), keyId);

		for (String keyId : List.of("", KEY_ID_64 + "a", "a b", "a/b", "a+b", "a=b", "a:b", "\u00e9", "a\u0000",
				"\uff21", "a\n"))
			Assertions.assertFalse(SealerV1.isKeyId(keyId), keyId);

		Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.Key.fromMasterKey("a b", new byte[32]));
		Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.Key.fromMasterKey("a", new byte[31]));
		Assertions.assertThrows(IllegalArgumentException.class, () -> SealerV1.Key.fromMasterKey("a", new byte[33]));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.Key.fromMasterKey(nullValue(), new byte[32]));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.Key.fromMasterKey("a", nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> SealerV1.isKeyId(nullValue()));
	}

	// R9: a key renders its key ID only.
	@Test
	void aKeyRendersItsKeyIdButNeverItsBytes() throws GeneralSecurityException {
		byte[] masterKey = sequence(0x41, 32, 0);
		masterKey[0] = 0x42;
		SealerV1.Key key = SealerV1.Key.fromMasterKey("2026-09", masterKey);

		Assertions.assertEquals("Key{keyId=2026-09, key=<redacted>}", key.toString());
		Assertions.assertEquals("2026-09", key.getKeyId());
	}

	@Test
	void theSelfTestPassesOnThisJdksProvider() throws GeneralSecurityException {
		Assertions.assertTrue(SealerV1.passesSelfTest(SealerV1.Key.fromMasterKey("k", sequence(3, 32, 7)),
				new byte[16], new byte[12]));
	}

	// UnsealException carries a fixed message per kind, no cause, nothing suppressed and no stack trace.
	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void unsealExceptionsHaveFixedMessagesAndNoCauseSuppressionOrStackTrace() {
		UnsealException invalid = new UnsealException(UnsealException.Kind.INVALID);
		UnsealException expired = new UnsealException(UnsealException.Kind.EXPIRED);
		invalid.addSuppressed(new IllegalStateException("x"));

		Assertions.assertEquals("The sealed state is invalid.", invalid.getMessage());
		Assertions.assertEquals("The sealed state has expired.", expired.getMessage());
		Assertions.assertEquals(UnsealException.Kind.EXPIRED, expired.getKind());
		Assertions.assertNull(invalid.getCause());
		Assertions.assertEquals(0, invalid.getSuppressed().length);
		Assertions.assertEquals(0, invalid.getStackTrace().length);
		Assertions.assertThrows(NullPointerException.class, () -> new UnsealException(nullValue()));
	}

	/**
	 * The plan's formulas transcribed with raw JCA calls, independent of {@link SealerV1} and {@link Hkdf}.
	 */
	private static @NonNull String referenceSeal(@NonNull Vector vector) throws GeneralSecurityException {
		byte[] keyId = vector.keyId.getBytes(StandardCharsets.US_ASCII);
		byte[] label = vector.type.getLabel().getBytes(StandardCharsets.US_ASCII);
		byte[] context = vector.context.getBytes(StandardCharsets.UTF_8);
		byte[] header = concatenate(new byte[]{1, (byte) keyId.length}, keyId, vector.salt, vector.iv);

		Mac extract = Mac.getInstance("HmacSHA256");
		extract.init(new SecretKeySpec(bytes("revetsec/state-sealer/v1/extract"), "HmacSHA256"));
		byte[] pseudorandomKey = extract.doFinal(vector.masterKey);

		// HKDF-Expand with L = 32 is one block: T(1) = HMAC(PRK, info || 0x01).
		Mac expand = Mac.getInstance("HmacSHA256");
		expand.init(new SecretKeySpec(pseudorandomKey, "HmacSHA256"));
		byte[] messageKey = expand.doFinal(concatenate(bytes("revetsec/state-sealer/v1/aes-256-gcm-key"),
				new byte[]{0}, label, new byte[]{0}, vector.salt, new byte[]{1}));

		byte[] additionalData = concatenate(bytes("revetsec/state-sealer/v1/aad"), u32(header.length), header,
				u32(label.length), label, u32(context.length), context);
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(messageKey, "AES"), new GCMParameterSpec(128, vector.iv));
		cipher.updateAAD(additionalData);
		byte[] ciphertext = cipher.doFinal(concatenate(ByteBuffer.allocate(8).putLong(vector.notAfter).array(),
				vector.plaintext.getBytes(StandardCharsets.UTF_8)));

		return Base64.getUrlEncoder().withoutPadding().encodeToString(concatenate(header, ciphertext));
	}

	private static void assertInvalid(@NonNull UnsealException e) {
		Assertions.assertEquals(UnsealException.Kind.INVALID, e.getKind());
		Assertions.assertEquals("The sealed state is invalid.", e.getMessage());
		Assertions.assertNull(e.getCause());
		Assertions.assertEquals(0, e.getSuppressed().length);
	}

	private static UnsealException.@NonNull Kind kindOf(@NonNull Opening opening) {
		return Assertions.assertThrows(UnsealException.class, opening::open).getKind();
	}

	/**
	 * Changes the last character of an unpadded base64url value so that its unused trailing bits are not zero.
	 */
	private static @NonNull String nonCanonical(@NonNull String sealed) {
		Assertions.assertNotEquals(0, sealed.length() % 4, "the vector must have unused trailing bits");
		char last = sealed.charAt(sealed.length() - 1);
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		return sealed.substring(0, sealed.length() - 1) + alphabet.charAt(alphabet.indexOf(last) ^ 1);
	}

	private static @NonNull String encode(byte @NonNull [] bytes) {
		return Base64Url.encode(bytes);
	}

	private static byte @NonNull [] with(byte @NonNull [] bytes,
														 int index,
														 int value) {
		byte[] copy = bytes.clone();
		copy[index] = (byte) value;
		return copy;
	}

	private static byte @NonNull [] sequence(int start,
																 int count,
																 int step) {
		byte[] bytes = new byte[count];

		for (int index = 0; index < count; ++index)
			bytes[index] = (byte) (start + index * step);

		return bytes;
	}

	private static byte @NonNull [] filled(int value,
															 int count) {
		byte[] bytes = new byte[count];
		Arrays.fill(bytes, (byte) value);
		return bytes;
	}

	private static byte @NonNull [] bytes(@NonNull String ascii) {
		return ascii.getBytes(StandardCharsets.US_ASCII);
	}

	private static byte @NonNull [] u32(int value) {
		return ByteBuffer.allocate(4).putInt(value).array();
	}

	private static byte @NonNull [] concatenate(byte @NonNull [] @NonNull ... parts) {
		ByteArrayOutputStream output = new ByteArrayOutputStream();

		for (byte[] part : parts)
			output.writeBytes(part);

		return output.toByteArray();
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}

	/**
	 * One call to {@link SealerV1#open} that must fail.
	 */
	@FunctionalInterface
	private interface Opening {
		void open() throws UnsealException;
	}

	/**
	 * One known-answer vector.
	 */
	private static final class Vector {
		private final String name;
		private final byte[] masterKey;
		private final String keyId;
		private final SealedStateType type;
		private final String context;
		private final long notAfter;
		private final String plaintext;
		private final byte[] salt;
		private final byte[] iv;
		private final String sealed;

		private Vector(@NonNull String name,
									 byte @NonNull [] masterKey,
									 @NonNull String keyId,
									 @NonNull SealedStateType type,
									 @NonNull String context,
									 long notAfter,
									 @NonNull String plaintext,
									 byte @NonNull [] salt,
									 byte @NonNull [] iv,
									 @NonNull String sealed) {
			this.name = name;
			this.masterKey = masterKey;
			this.keyId = keyId;
			this.type = type;
			this.context = context;
			this.notAfter = notAfter;
			this.plaintext = plaintext;
			this.salt = salt;
			this.iv = iv;
			this.sealed = sealed;
		}
	}
}
