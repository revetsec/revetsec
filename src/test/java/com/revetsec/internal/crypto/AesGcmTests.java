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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * AES-256-GCM with its parameters fixed (M1 plan G6-8: 12-byte IV, 128-bit tag): a published vector, tamper
 * rejection, and the JDK 17 note, which makes every input shorter than the tag an {@link AEADBadTagException} on every
 * JDK instead of 17's unchecked {@code ProviderException}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class AesGcmTests {
	private static final HexFormat HEX = HexFormat.of();

	// McGrew and Viega, "The Galois/Counter Mode of Operation (GCM)", test case 16: AES-256, 96-bit IV, with AAD.
	@Test
	void encryptsAndDecryptsGcmSpecificationTestCase16() throws GeneralSecurityException {
		byte[] key = HEX.parseHex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
		byte[] iv = HEX.parseHex("cafebabefacedbaddecaf888");
		byte[] plaintext = HEX.parseHex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
				+ "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
		byte[] additionalData = HEX.parseHex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
		String expected = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
				+ "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662" + "76fc6ece0f4e1768cddf8853bb2d551b";

		byte[] ciphertextAndTag = AesGcm.encrypt(key, iv, additionalData, plaintext);

		Assertions.assertEquals(expected, HEX.formatHex(ciphertextAndTag));
		Assertions.assertArrayEquals(plaintext, AesGcm.decrypt(key, iv, additionalData, ciphertextAndTag));
	}

	// Test case 13: AES-256 with an all-zero key and IV, and no plaintext or AAD, is the tag alone.
	@Test
	void encryptsAnEmptyPlaintextToTheTagAlone() throws GeneralSecurityException {
		byte[] ciphertextAndTag = AesGcm.encrypt(new byte[32], new byte[12], new byte[0], new byte[0]);

		Assertions.assertEquals("530f8afbc74536b9a963b4f1c4cb738b", HEX.formatHex(ciphertextAndTag));
		Assertions.assertEquals(0, AesGcm.decrypt(new byte[32], new byte[12], new byte[0], ciphertextAndTag).length);
	}

	@Test
	void rejectsAnyChangeToTheCiphertextTagIvKeyOrAdditionalData() throws GeneralSecurityException {
		byte[] key = new byte[32];
		byte[] iv = new byte[12];
		byte[] additionalData = {1, 2, 3};
		byte[] ciphertextAndTag = AesGcm.encrypt(key, iv, additionalData, new byte[]{4, 5, 6, 7});

		for (int index = 0; index < ciphertextAndTag.length; ++index) {
			byte[] altered = ciphertextAndTag.clone();
			altered[index] ^= 0x01;
			Assertions.assertThrows(AEADBadTagException.class, () -> AesGcm.decrypt(key, iv, additionalData, altered));
		}

		byte[] otherKey = key.clone();
		otherKey[31] = 1;
		byte[] otherIv = iv.clone();
		otherIv[11] = 1;

		Assertions.assertThrows(AEADBadTagException.class, () -> AesGcm.decrypt(otherKey, iv, additionalData,
				ciphertextAndTag));
		Assertions.assertThrows(AEADBadTagException.class, () -> AesGcm.decrypt(key, otherIv, additionalData,
				ciphertextAndTag));
		Assertions.assertThrows(AEADBadTagException.class, () -> AesGcm.decrypt(key, iv, new byte[]{1, 2},
				ciphertextAndTag));
		Assertions.assertThrows(AEADBadTagException.class, () -> AesGcm.decrypt(key, iv, additionalData,
				Arrays.copyOf(ciphertextAndTag, ciphertextAndTag.length + 1)));
	}

	// M1 plan, JDK 17 note: 17.0.20's provider throws ProviderException for 0 to 15 bytes; Revetsec never lets it.
	@Test
	void rejectsInputShorterThanTheTagWithAeadBadTagExceptionOnEveryJdk() {
		for (int length = 0; length < AesGcm.TAG_LENGTH; ++length) {
			byte[] input = new byte[length];
			Assertions.assertThrows(AEADBadTagException.class, () -> AesGcm.decrypt(new byte[32], new byte[12],
					new byte[0], input), () -> input.length + " bytes");
		}
	}

	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void rejectsKeysAndIvsOfAnyOtherLength() {
		for (int length : new int[]{0, 16, 24, 31, 33})
			Assertions.assertThrows(IllegalArgumentException.class, () -> AesGcm.encrypt(new byte[length], new byte[12],
					new byte[0], new byte[0]));

		for (int length : new int[]{0, 8, 11, 13, 16})
			Assertions.assertThrows(IllegalArgumentException.class, () -> AesGcm.decrypt(new byte[32], new byte[length],
					new byte[0], new byte[16]));

		Assertions.assertThrows(NullPointerException.class, () -> AesGcm.encrypt(new byte[32], new byte[12],
				new byte[0], nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> AesGcm.decrypt(new byte[32], new byte[12],
				nullValue(), new byte[16]));
		Assertions.assertThrows(NullPointerException.class, () -> AesGcm.decrypt(nullValue(), new byte[12],
				new byte[0], new byte[16]));
		Assertions.assertThrows(NullPointerException.class, () -> AesGcm.decrypt(new byte[32], nullValue(),
				new byte[0], new byte[16]));
		Assertions.assertThrows(NullPointerException.class, () -> AesGcm.decrypt(new byte[32], new byte[12],
				new byte[0], nullValue()));
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}
}
