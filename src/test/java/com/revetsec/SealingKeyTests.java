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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Stream;

/**
 * Sealing keys (M1 plan G6-9, plan R9): exactly 32 bytes as canonical 44-character standard Base64, placeholder keys
 * rejected, key IDs of 1 to 64 characters of {@code [A-Za-z0-9._~-]}, reference equality, and a redacted
 * {@code toString}. No message ever repeats either argument.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class SealingKeyTests {
	/**
	 * 32 distinct bytes, 0x00 to 0x1f.
	 */
	private static final String KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

	@Test
	void acceptsThirtyTwoBytesInCanonicalStandardBase64() {
		SealingKey key = SealingKey.fromBase64("2026-09", KEY);
		byte[] bytes = key.copyKeyBytes();

		Assertions.assertEquals("2026-09", key.getKeyId());
		Assertions.assertEquals(32, bytes.length);
		Assertions.assertArrayEquals(Base64.getDecoder().decode(KEY), bytes);
	}

	// R9: the key is never rendered, whatever its bytes.
	@Test
	void rendersTheKeyIdButNeverTheKey() {
		SealingKey key = SealingKey.fromBase64("2026-09", KEY);

		Assertions.assertEquals("SealingKey{keyId=2026-09, key=<redacted>}", key.toString());
		Assertions.assertFalse(key.toString().contains(KEY));
		Assertions.assertFalse(key.toString().contains("AAECAwQF"));
	}

	// R9: secret holders use reference identity for equals.
	@Test
	void keysAreEqualOnlyToThemselves() {
		SealingKey first = SealingKey.fromBase64("2026-09", KEY);
		SealingKey second = SealingKey.fromBase64("2026-09", KEY);

		Assertions.assertEquals(first, first);
		Assertions.assertNotEquals(first, second);
		Assertions.assertEquals(System.identityHashCode(first), first.hashCode());
		Assertions.assertTrue(first.hasSameKeyBytes(second));
		Assertions.assertFalse(first.hasSameKeyBytes(SealingKey.fromBase64("2026-09",
				"AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")));
	}

	@Test
	void handsOutCopiesOfTheKeyBytes() {
		SealingKey key = SealingKey.fromBase64("2026-09", KEY);
		byte[] copy = key.copyKeyBytes();
		Arrays.fill(copy, (byte) 0);

		Assertions.assertArrayEquals(Base64.getDecoder().decode(KEY), key.copyKeyBytes());
	}

	// G6-9: a kid is 1-64 characters of [A-Za-z0-9._~-].
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> acceptsKeyIdsOfOneToSixtyFourUnreservedCharacters() {
		return Stream.of("a", "Z", "0", "2026-09", "prod.v2_rotated~1", "-", "._~-",
						"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", "x".repeat(64))
				.map(keyId -> DynamicTest.dynamicTest(keyId, () -> Assertions.assertEquals(keyId,
						SealingKey.fromBase64(keyId, KEY).getKeyId())));
	}

	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsEveryOtherKeyIdWithoutEchoingIt() {
		return Stream.of("", "x".repeat(65), "a b", " a", "a\t", "a/b", "a+b", "a=b", "a:b", "a@b", "a%20", "a\"b",
						"\u00e9", "\uff21", "\u212a", "a\u0000", "a\n", "\ud800", KEY)
				.map(keyId -> DynamicTest.dynamicTest("\"" + escape(keyId) + "\"", () -> {
					IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
							() -> SealingKey.fromBase64(keyId, KEY));
					assertNoEcho(e, keyId);
					assertNoEcho(e, KEY);
				}));
	}

	// G6-9: exactly 32 bytes as canonical 44-character standard Base64; anything else is rejected, never repaired.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsEveryOtherKeyEncodingWithoutEchoingIt() {
		return Stream.of(
				"",
				KEY.substring(0, 43),
				KEY + "=",
				"=" + KEY.substring(1),
				// 44 characters that decode to 31 or 33 bytes
				"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==",
				"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g",
				// non-zero trailing bits before the padding
				"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=",
				// the base64url alphabet
				"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh-=",
				"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh_=",
				// whitespace and line breaks
				" AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
				"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n",
				"AAECAwQFBgcICQoLDA0O\nDxAREhMUFRYXGBkaGxwdHh8=",
				"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
				// padding in the middle
				"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd=h8=",
				// non-ASCII
				"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh\u00e9=",
				// a hex key, a common mistake
				"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				"x".repeat(100_000)
		).map(encoded -> DynamicTest.dynamicTest("\"" + escape(encoded.length() > 70 ? encoded.substring(0, 70) + "..."
				: encoded) + "\"",
				() -> {
					IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
							() -> SealingKey.fromBase64("2026-09", encoded));
					assertNoEcho(e, encoded);
				}));
	}

	// G6-9: a key whose 32 bytes are all the same is a placeholder, such as all zeros.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> rejectsKeysWhoseThirtyTwoBytesAreAllTheSame() {
		return Stream.of(0x00, 0x01, 0x41, 0x7f, 0x80, 0xff).map(value -> DynamicTest.dynamicTest(
				String.format(java.util.Locale.ROOT, "0x%02x", value), () -> {
					byte[] bytes = new byte[32];
					Arrays.fill(bytes, (byte) (int) value);
					String encoded = Base64.getEncoder().encodeToString(bytes);
					IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
							() -> SealingKey.fromBase64("2026-09", encoded));
					assertNoEcho(e, encoded);

					// One different byte, anywhere, makes it a key.
					for (int index : new int[]{0, 15, 31}) {
						byte[] almost = bytes.clone();
						almost[index] ^= 0x01;
						SealingKey.fromBase64("2026-09", Base64.getEncoder().encodeToString(almost));
					}
				}));
	}

	@Test
	@SuppressWarnings("NullAway")
	void rejectsNullArguments() {
		Assertions.assertThrows(NullPointerException.class, () -> SealingKey.fromBase64(null, KEY));
		Assertions.assertThrows(NullPointerException.class, () -> SealingKey.fromBase64("2026-09", null));
		Assertions.assertThrows(NullPointerException.class,
				() -> SealingKey.fromBase64("2026-09", KEY).hasSameKeyBytes(null));
	}

	private static void assertNoEcho(@NonNull Throwable e,
																	 @NonNull String argument) {
		if (argument.length() < 4)
			return;

		String message = String.valueOf(e.getMessage());
		Assertions.assertFalse(message.contains(argument), () -> "the message repeats an argument: " + message);
		Assertions.assertFalse(e.toString().contains(argument));
	}

	private static @NonNull String escape(@NonNull String value) {
		StringBuilder escaped = new StringBuilder();

		for (char character : value.toCharArray())
			escaped.append(character >= 0x20 && character < 0x7f ? String.valueOf(character)
					: String.format(java.util.Locale.ROOT, "\\u%04x", (int) character));

		return escaped.toString();
	}
}
