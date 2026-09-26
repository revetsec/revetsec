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
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.TestReporter;

import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;
import java.util.stream.IntStream;
import java.util.stream.Stream;

/**
 * HKDF-SHA256 (RFC 5869; M1 plan A-3 and exit criterion 7): the RFC's appendix A.1 to A.3 vectors, the absent-salt
 * rule, the output-length bound {@code L <= 255 * HashLen = 8,160}, and, on JDK 25 and later, a differential
 * against the JDK's own {@code javax.crypto.KDF}, called reflectively because the tests compile with
 * {@code --release 17}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class HkdfTests {
	private static final HexFormat HEX = HexFormat.of();

	/**
	 * How many random cases the {@code javax.crypto.KDF} differential runs.
	 */
	private static final int DIFFERENTIAL_CASES = 400;

	// RFC 5869 appendix A.1 to A.3, the SHA-256 cases: IKM, salt, info, L, PRK and OKM, in hex.
	@TestFactory
	Stream<DynamicTest> derivesTheRfc5869AppendixASha256Vectors() {
		return Stream.of(new Vector("A.1 basic", "0b".repeat(22), "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
						42, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
						"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
				new Vector("A.2 longer inputs and outputs", range(0x00, 0x50), range(0x60, 0xb0), range(0xb0, 0x100), 82,
						"06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
						"b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09"
								+ "da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
				new Vector("A.3 zero-length salt and info", "0b".repeat(22), "", "", 42,
						"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
						"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"))
				.map(vector -> DynamicTest.dynamicTest(vector.name, () -> {
					byte[] inputKeyingMaterial = HEX.parseHex(vector.inputKeyingMaterial);
					byte[] salt = HEX.parseHex(vector.salt);
					byte[] info = HEX.parseHex(vector.info);
					byte[] pseudorandomKey = Hkdf.extract(salt, inputKeyingMaterial);

					Assertions.assertEquals(vector.pseudorandomKey, HEX.formatHex(pseudorandomKey));
					Assertions.assertEquals(vector.outputKeyingMaterial,
							HEX.formatHex(Hkdf.expand(pseudorandomKey, info, vector.length)));
					Assertions.assertEquals(vector.outputKeyingMaterial,
							HEX.formatHex(Hkdf.derive(salt, inputKeyingMaterial, info, vector.length)));
				}));
	}

	// RFC 5869 section 2.2: "if not provided, [salt] is set to a string of HashLen zeros" (A.3 is the empty case).
	@Test
	void treatsAnAbsentOrEmptySaltAsThirtyTwoZeroBytes() throws GeneralSecurityException {
		byte[] inputKeyingMaterial = HEX.parseHex("0b".repeat(22));
		String expected = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04";

		Assertions.assertEquals(expected, HEX.formatHex(Hkdf.extract(null, inputKeyingMaterial)));
		Assertions.assertEquals(expected, HEX.formatHex(Hkdf.extract(new byte[0], inputKeyingMaterial)));
		Assertions.assertEquals(expected, HEX.formatHex(Hkdf.extract(new byte[Hkdf.HASH_LENGTH], inputKeyingMaterial)));
		Assertions.assertEquals(HEX.formatHex(Hkdf.derive(null, inputKeyingMaterial, new byte[0], 42)),
				HEX.formatHex(Hkdf.derive(new byte[0], inputKeyingMaterial, new byte[0], 42)));
	}

	// RFC 5869 section 2.3: L <= 255 * HashLen. Anything else is a programming error, never a truncated key.
	@TestFactory
	Stream<DynamicTest> rejectsOutputLengthsOutsideOneTo8160() {
		byte[] pseudorandomKey = new byte[Hkdf.HASH_LENGTH];

		return IntStream.of(Hkdf.MAXIMUM_OUTPUT_LENGTH + 1, 8_192, Integer.MAX_VALUE, 0, -1, Integer.MIN_VALUE)
				.mapToObj(length -> DynamicTest.dynamicTest("L = " + length, () -> {
					Assertions.assertThrows(IllegalArgumentException.class,
							() -> Hkdf.expand(pseudorandomKey, new byte[0], length));
					Assertions.assertThrows(IllegalArgumentException.class,
							() -> Hkdf.derive(null, new byte[1], new byte[0], length));
				}));
	}

	// RFC 5869 section 2.3: T(1) || ... || T(255), and each shorter output is a prefix of a longer one.
	@Test
	void expandsTheMaximumOf8160BytesAndEveryShorterOutputIsAPrefix() throws GeneralSecurityException {
		byte[] pseudorandomKey = HEX.parseHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
		byte[] info = HEX.parseHex("f0f1f2f3f4f5f6f7f8f9");
		byte[] maximum = Hkdf.expand(pseudorandomKey, info, Hkdf.MAXIMUM_OUTPUT_LENGTH);

		Assertions.assertEquals(8_160, Hkdf.MAXIMUM_OUTPUT_LENGTH);
		Assertions.assertEquals(Hkdf.MAXIMUM_OUTPUT_LENGTH, maximum.length);

		for (int length : new int[]{1, 31, 32, 33, 42, 64, 65, 8_127, 8_128, 8_129, 8_159})
			Assertions.assertArrayEquals(Arrays.copyOf(maximum, length), Hkdf.expand(pseudorandomKey, info, length),
					() -> "L = " + length);
	}

	// RFC 5869 section 2.3: PRK is "a pseudorandom key of at least HashLen octets".
	@Test
	void rejectsAPseudorandomKeyShorterThanThirtyTwoBytes() throws GeneralSecurityException {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> Hkdf.expand(new byte[Hkdf.HASH_LENGTH - 1], new byte[0], 32));
		Assertions.assertEquals(32, Hkdf.expand(new byte[Hkdf.HASH_LENGTH + 1], new byte[0], 32).length);
	}

	@Test
	void rejectsNullArgumentsAndAnEmptyHmacKey() {
		Assertions.assertThrows(NullPointerException.class, () -> Hkdf.extract(null, nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> Hkdf.expand(nullValue(), new byte[0], 32));
		Assertions.assertThrows(NullPointerException.class, () -> Hkdf.expand(new byte[32], nullValue(), 32));
		Assertions.assertThrows(NullPointerException.class, () -> Hkdf.derive(null, nullValue(), new byte[0], 32));
		Assertions.assertThrows(NullPointerException.class, () -> Hkdf.derive(null, new byte[0], nullValue(), 32));
		Assertions.assertThrows(NullPointerException.class, () -> Hmac.sha256(new byte[1], nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> Hmac.sha256Mac(nullValue()));
		// SecretKeySpec cannot hold an empty key; a zero-length HMAC key is never silently replaced.
		Assertions.assertThrows(IllegalArgumentException.class, () -> Hmac.sha256(new byte[0], new byte[1]));
	}

	// M1 plan A-3 and exit criterion 7: 0 mismatches against javax.crypto.KDF on JDK 25 and later, where it is final
	// (JEP 510). JDK 17 to 23 lack the class, which is why Hkdf exists; JDK 24 has it only as a preview API (JEP 478),
	// so the differential skips 24 without asserting anything about it.
	@Test
	void matchesJavaxCryptoKdfOnRandomInputsFromJdk25(TestReporter testReporter) throws Exception {
		int feature = Runtime.version().feature();

		if (feature < 25) {
			if (feature <= 23)
				Assertions.assertThrows(ClassNotFoundException.class, () -> Class.forName("javax.crypto.KDF"));

			testReporter.publishEntry("kdfDifferential", "javax.crypto.KDF is not final API on " + Runtime.version());
			return;
		}

		JdkHkdf jdkHkdf = new JdkHkdf();
		long seed = new Random().nextLong();
		Random random = new Random(seed);
		int mismatches = 0;

		for (int index = 0; index < DIFFERENTIAL_CASES; ++index) {
			byte[] inputKeyingMaterial = bytes(random, random.nextInt(97));
			// A null salt is left out of the JDK's builder, which then uses HashLen zeros too.
			byte @Nullable [] salt = random.nextInt(4) == 0 ? null : bytes(random, random.nextInt(97));
			byte[] info = bytes(random, random.nextInt(97));
			int length = index % 50 == 0 ? 1 + random.nextInt(Hkdf.MAXIMUM_OUTPUT_LENGTH) : 1 + random.nextInt(200);
			byte[] pseudorandomKey = bytes(random, Hkdf.HASH_LENGTH + random.nextInt(33));

			if (!Arrays.equals(jdkHkdf.derive(salt, inputKeyingMaterial, info, length),
					Hkdf.derive(salt, inputKeyingMaterial, info, length)))
				++mismatches;
			if (!Arrays.equals(jdkHkdf.expandOnly(pseudorandomKey, info, length),
					Hkdf.expand(pseudorandomKey, info, length)))
				++mismatches;
		}

		testReporter.publishEntry("kdfDifferential", DIFFERENTIAL_CASES + " cases x 2 on " + Runtime.version()
				+ ", seed " + seed);
		Assertions.assertEquals(0, mismatches, "seed " + seed);
		// The maximum length matches too.
		byte[] pseudorandomKey = bytes(random, Hkdf.HASH_LENGTH);
		Assertions.assertArrayEquals(jdkHkdf.expandOnly(pseudorandomKey, new byte[0], Hkdf.MAXIMUM_OUTPUT_LENGTH),
				Hkdf.expand(pseudorandomKey, new byte[0], Hkdf.MAXIMUM_OUTPUT_LENGTH));
	}

	private static byte[] bytes(Random random,
															int length) {
		byte[] bytes = new byte[length];
		random.nextBytes(bytes);
		return bytes;
	}

	private static String range(int fromInclusive,
															int toExclusive) {
		StringBuilder hex = new StringBuilder();

		for (int value = fromInclusive; value < toExclusive; ++value)
			hex.append(HEX.toHexDigits((byte) value));

		return hex.toString();
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> T nullValue() {
		return null;
	}

	/**
	 * One RFC 5869 appendix A case, in hex.
	 */
	private static final class Vector {
		private final String name;
		private final String inputKeyingMaterial;
		private final String salt;
		private final String info;
		private final int length;
		private final String pseudorandomKey;
		private final String outputKeyingMaterial;

		private Vector(String name,
									 String inputKeyingMaterial,
									 String salt,
									 String info,
									 int length,
									 String pseudorandomKey,
									 String outputKeyingMaterial) {
			this.name = name;
			this.inputKeyingMaterial = inputKeyingMaterial;
			this.salt = salt;
			this.info = info;
			this.length = length;
			this.pseudorandomKey = pseudorandomKey;
			this.outputKeyingMaterial = outputKeyingMaterial;
		}
	}

	/**
	 * The JDK 25+ {@code javax.crypto.KDF} HKDF-SHA256, reached by reflection so this class compiles with
	 * {@code --release 17}.
	 */
	private static final class JdkHkdf {
		private final Object kdf;
		private final Method deriveData;
		private final Method ofExtract;
		private final Method expandOnly;
		private final Method addInputKeyingMaterial;
		private final Method addSalt;
		private final Method thenExpand;

		private JdkHkdf() throws ReflectiveOperationException {
			Class<?> kdfClass = Class.forName("javax.crypto.KDF");
			Class<?> specClass = Class.forName("javax.crypto.spec.HKDFParameterSpec");
			Class<?> builderClass = Class.forName("javax.crypto.spec.HKDFParameterSpec$Builder");

			this.kdf = kdfClass.getMethod("getInstance", String.class).invoke(null, "HKDF-SHA256");
			this.deriveData = kdfClass.getMethod("deriveData", AlgorithmParameterSpec.class);
			this.ofExtract = specClass.getMethod("ofExtract");
			this.expandOnly = specClass.getMethod("expandOnly", javax.crypto.SecretKey.class, byte[].class, int.class);
			this.addInputKeyingMaterial = builderClass.getMethod("addIKM", byte[].class);
			this.addSalt = builderClass.getMethod("addSalt", byte[].class);
			this.thenExpand = builderClass.getMethod("thenExpand", byte[].class, int.class);
		}

		private byte[] derive(byte @Nullable [] salt,
													byte[] inputKeyingMaterial,
													byte[] info,
													int length) throws ReflectiveOperationException {
			Object builder = this.ofExtract.invoke(null);
			this.addInputKeyingMaterial.invoke(builder, (Object) inputKeyingMaterial);

			// With no salt added, the JDK uses HashLen zeros (RFC 5869 section 2.2); an empty salt is passed through.
			if (salt != null)
				this.addSalt.invoke(builder, (Object) salt);

			return derive(this.thenExpand.invoke(builder, info, length));
		}

		private byte[] expandOnly(byte[] pseudorandomKey,
															byte[] info,
															int length) throws ReflectiveOperationException {
			return derive(this.expandOnly.invoke(null, new SecretKeySpec(pseudorandomKey, "Generic"), info, length));
		}

		private byte[] derive(Object parameters) throws ReflectiveOperationException {
			try {
				return (byte[]) this.deriveData.invoke(this.kdf, parameters);
			} catch (InvocationTargetException e) {
				throw new AssertionError("javax.crypto.KDF failed", e.getCause());
			}
		}
	}
}
