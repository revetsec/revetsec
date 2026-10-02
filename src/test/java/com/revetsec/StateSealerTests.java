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

import org.jspecify.annotations.Nullable;

import org.jspecify.annotations.NonNull;

import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.testing.ChildJvm;
import com.revetsec.testing.Sentinels;
import com.revetsec.testing.TestClock;
import com.revetsec.testing.TestSealers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.function.Executable;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The public sealer (M1 plan, "StateSealer v1"; G6-8 to G6-10; exit criteria 8 and 9).
 * <p>
 * Exit criterion 8: every way a value can fail to open gives the identical {@link InvalidSealedStateException}: the
 * same class, message, category and transience, no cause, nothing suppressed, and the same stack trace down to the
 * test's own call, because it is thrown from one place. Exit criterion 9: rotation, removed keys, label separation
 * through {@link SealedStateAccess}, the size limit and the argument and builder checks.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class StateSealerTests {
	private static final Instant START = Instant.parse("2026-09-24T12:00:00Z");
	private static final Duration HOUR = Duration.ofHours(1);
	private static final String PLAINTEXT = "{\"issuer\":\"https://accounts.example\",\"nonce\":\"n-0S6_WzA2Mj\"}";
	private static final String CONTEXT = "__Host-revetsec-pending";
	private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+");

	// Exit criterion 8: a bit flip at every bit of every byte.
	@Test
	void aFlippedBitAnywhereGivesTheIdenticalFailure() throws Exception {
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = sealer.seal(PLAINTEXT, CONTEXT, HOUR);
		byte[] bytes = Base64Url.decode(sealed);

		for (int index = 0; index < bytes.length; ++index) {
			for (int bit = 0; bit < 8; ++bit) {
				byte[] altered = bytes.clone();
				altered[index] = (byte) (altered[index] ^ (1 << bit));
				assertUniformFailure(sealer, Base64Url.encode(altered), CONTEXT);
			}
		}

		Assertions.assertEquals(PLAINTEXT, sealer.unseal(sealed, CONTEXT));
	}

	// Exit criterion 8: truncation at every length, of the text and of the decoded bytes.
	@Test
	void truncationAtEveryLengthGivesTheIdenticalFailure() throws Exception {
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = sealer.seal(PLAINTEXT, CONTEXT, HOUR);
		byte[] bytes = Base64Url.decode(sealed);

		for (int length = 0; length < sealed.length(); ++length)
			assertUniformFailure(sealer, sealed.substring(0, length), CONTEXT);

		for (int length = 0; length < bytes.length; ++length)
			assertUniformFailure(sealer, Base64Url.encode(Arrays.copyOf(bytes, length)), CONTEXT);
	}

	// Exit criterion 8: an appended byte, or appended characters.
	@Test
	void anAppendedByteGivesTheIdenticalFailure() throws Exception {
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = sealer.seal(PLAINTEXT, CONTEXT, HOUR);
		byte[] bytes = Base64Url.decode(sealed);

		for (int value : new int[]{0x00, 0x01, 0x7f, 0x80, 0xff}) {
			byte[] longer = Arrays.copyOf(bytes, bytes.length + 1);
			longer[bytes.length] = (byte) value;
			assertUniformFailure(sealer, Base64Url.encode(longer), CONTEXT);
		}

		for (String suffix : List.of("A", "AA", "AAA", "AAAA", "_"))
			assertUniformFailure(sealer, sealed + suffix, CONTEXT);
	}

	// Exit criterion 8: an unknown key ID, or the right key ID with other key bytes (never trial decryption).
	@Test
	void anUnknownKeyGivesTheIdenticalFailure() {
		StateSealer sealer = TestSealers.fromFixedKey();
		StateSealer otherKeyId = TestSealers.fromFixedKeys("other", List.of());
		StateSealer sameKeyIdOtherBytes = StateSealer.withActiveKey(SealingKey.fromBase64(TestSealers.FIXED_KEY_ID,
				"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")).build();
		// Holds the right key bytes under another key ID only.
		StateSealer sameBytesOtherKeyId = StateSealer.withActiveKey(TestSealers.fixedKey("other"))
				.verificationKeys(List.of(SealingKey.fromBase64("renamed", Base64.getEncoder().encodeToString(
						TestSealers.fixedKeyBytes(TestSealers.FIXED_KEY_ID)))))
				.build();

		String sealed = sealer.seal(PLAINTEXT, CONTEXT, HOUR);

		assertUniformFailure(otherKeyId, sealed, CONTEXT);
		assertUniformFailure(sameKeyIdOtherBytes, sealed, CONTEXT);
		assertUniformFailure(sameBytesOtherKeyId, sealed, CONTEXT);
		assertUniformFailure(sealer, otherKeyId.seal(PLAINTEXT, CONTEXT, HOUR), CONTEXT);
	}

	// Exit criterion 8: the wrong context. Contexts compare exactly, as UTF-8 bytes.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> theWrongContextGivesTheIdenticalFailure() {
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = sealer.seal(PLAINTEXT, "google", HOUR);

		return Stream.of("Google", "GOOGLE", "google ", " google", "googl", "googlee", "google\u0000", "g\u043e\u043egle",
						"google\u200b", "microsoft", "x".repeat(256))
				.map(context -> DynamicTest.dynamicTest(escape(context), () -> assertUniformFailure(sealer, sealed,
						context)));
	}

	// Exit criterion 8: garbage of every kind.
	@Test
	void garbageGivesTheIdenticalFailure() {
		StateSealer sealer = TestSealers.fromFixedKey();
		Random random = new Random(20260924L);
		List<String> garbage = new ArrayList<>(List.of("", "A", "AA", "AAAA", "garbage", "!!!!", "%%%%", "\u0000",
				"\ud800", "\ud834\udd1e", " ", "\n", "null", "{}", "AQ", "AQE", "AQEA", "A".repeat(3_800),
				"_".repeat(100), "-".repeat(3_800)));

		for (int length = 0; length < 400; length += 7) {
			byte[] bytes = new byte[length];
			random.nextBytes(bytes);
			garbage.add(Base64Url.encode(bytes));

			// A plausible header: version 1, the right key ID, then random bytes.
			byte[] header = ("\u0001\u0004" + TestSealers.FIXED_KEY_ID).getBytes(StandardCharsets.US_ASCII);
			garbage.add(Base64Url.encode(concatenate(header, bytes)));
		}

		for (String value : garbage)
			assertUniformFailure(sealer, value, CONTEXT);
	}

	// Exit criterion 8: non-canonical base64url, padding, the standard alphabet and over-length values.
	@Test
	void nonCanonicalPaddedOrOverLengthValuesGiveTheIdenticalFailure() throws Exception {
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = sealWithAUrlSafeCharacter(sealer);
		byte[] bytes = Base64Url.decode(sealed);
		String padded = Base64.getUrlEncoder().encodeToString(bytes);
		String standard = Base64.getEncoder().withoutPadding().encodeToString(bytes);

		Assertions.assertNotEquals(sealed, padded, "the value must need padding for this test");
		Assertions.assertNotEquals(sealed, standard, "the value must use '-' or '_' for this test");
		assertUniformFailure(sealer, padded, CONTEXT);
		assertUniformFailure(sealer, sealed + "=", CONTEXT);
		assertUniformFailure(sealer, sealed + "==", CONTEXT);
		assertUniformFailure(sealer, standard, CONTEXT);
		assertUniformFailure(sealer, nonCanonical(sealed), CONTEXT);
		assertUniformFailure(sealer, " " + sealed, CONTEXT);
		assertUniformFailure(sealer, sealed + "\n", CONTEXT);

		// Over-length: rejected before decoding, even when authentic.
		StateSealer roomy = StateSealer.withActiveKey(TestSealers.fixedKey(TestSealers.FIXED_KEY_ID))
				.maximumSealedLength(16_384)
				.build();
		// Key ID "test": 2,793 bytes seal to 3,802 characters, just over the default maximum of 3,800.
		String justTooLong = roomy.seal("x".repeat(2_793), CONTEXT, HOUR);

		Assertions.assertEquals(3_802, justTooLong.length());
		Assertions.assertEquals("x".repeat(2_793), roomy.unseal(justTooLong, CONTEXT));
		assertUniformFailure(sealer, justTooLong, CONTEXT);
		assertUniformFailure(sealer, "A".repeat(3_801), CONTEXT);
		assertUniformFailure(sealer, "A".repeat(10_000_000), CONTEXT);
	}

	// Exit criterion 8 and the JDK 17 note: a ciphertext shorter than notAfter plus the tag never reaches the
	// provider, which throws ProviderException on 17.0.20. The outcome is identical on every JDK.
	@Test
	void theShortCiphertextCaseGivesTheIdenticalFailureOnEveryJdk() throws Exception {
		StateSealer sealer = TestSealers.fromFixedKey();
		byte[] bytes = Base64Url.decode(sealer.seal(PLAINTEXT, CONTEXT, HOUR));
		int headerLength = 2 + TestSealers.FIXED_KEY_ID.length() + 16 + 12;

		for (int ciphertextLength = 0; ciphertextLength < 8 + 16; ++ciphertextLength)
			assertUniformFailure(sealer, Base64Url.encode(Arrays.copyOf(bytes, headerLength + ciphertextLength)),
					CONTEXT);
	}

	// Exit criterion 8: expiry at the boundary now == notAfter, sealing at .000, .001 and .999 s. notAfter is the
	// sealing time rounded up to a whole second plus the lifetime's whole seconds.
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> aValueExpiresExactlyAtNotAfter() {
		List<Duration> offsets = List.of(Duration.ZERO, Duration.ofMillis(1), Duration.ofMillis(999));
		List<Duration> lifetimes = List.of(Duration.ofSeconds(1), Duration.ofSeconds(60), Duration.ofMillis(60_999),
				Duration.ofMinutes(15), Duration.ofDays(400));

		return offsets.stream().flatMap(offset -> lifetimes.stream().map(lifetime -> DynamicTest.dynamicTest(
				"sealed at +" + offset.toMillis() + " ms for " + lifetime, () -> {
					TestClock clock = TestClock.fromInstant(START.plus(offset));
					StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("k")).clock(clock).build();
					String sealed = sealer.seal("x", CONTEXT, lifetime);
					Instant notAfter = (offset.isZero() ? START : START.plusSeconds(1)).plusSeconds(lifetime.toSeconds());

					// Never shorter than the lifetime's whole seconds, and at most one second longer.
					Assertions.assertTrue(Duration.between(START.plus(offset), notAfter).compareTo(
							Duration.ofSeconds(lifetime.toSeconds())) >= 0);
					Assertions.assertTrue(Duration.between(START.plus(offset), notAfter).compareTo(
							Duration.ofSeconds(lifetime.toSeconds() + 1)) < 0);

					clock.set(notAfter.minusNanos(1));
					Assertions.assertEquals("x", sealer.unseal(sealed, CONTEXT));
					clock.set(notAfter);
					assertUniformFailure(sealer, sealed, CONTEXT);
					clock.advance(Duration.ofDays(1_000));
					assertUniformFailure(sealer, sealed, CONTEXT);
				})));
	}

	// Exit criterion 9: rotation in three phases; a value sealed under a rotated key still opens, a removed key fails.
	@Test
	void aRotatedKeyStillOpensAndARemovedKeyFails() {
		StateSealer before = TestSealers.fromFixedKeys("2026-06", List.of());
		StateSealer added = TestSealers.fromFixedKeys("2026-06", List.of("2026-09"));
		StateSealer promoted = TestSealers.fromFixedKeys("2026-09", List.of("2026-06"));
		StateSealer retired = TestSealers.fromFixedKeys("2026-09", List.of());

		String old = before.seal("old", CONTEXT, HOUR);
		String fresh = promoted.seal("new", CONTEXT, HOUR);

		Assertions.assertEquals("old", added.unseal(old, CONTEXT));
		Assertions.assertEquals("old", promoted.unseal(old, CONTEXT));
		assertUniformFailure(retired, old, CONTEXT);

		// Instances still in phase 1 already open what promoted instances seal.
		Assertions.assertEquals("new", added.unseal(fresh, CONTEXT));
		Assertions.assertEquals("new", promoted.unseal(fresh, CONTEXT));
		Assertions.assertEquals("new", retired.unseal(fresh, CONTEXT));
		assertUniformFailure(before, fresh, CONTEXT);

		// Verification keys only open: what a sealer seals names its active key.
		Assertions.assertEquals("2026-09", keyIdOf(promoted.seal("x", CONTEXT, HOUR)));
		Assertions.assertEquals("2026-06", keyIdOf(added.seal("x", CONTEXT, HOUR)));
	}

	// Exit criterion 9 and G6-10: an app value never opens as pending authorization state, through the same internal
	// path M3 uses. SealedStateAccessTests shows in a fresh JVM that get() works before any StateSealer is built.
	@Test
	void anAppValueNeverOpensUnderPendingAuthorizationAndViceVersa() throws UnsealException {
		StateSealer sealer = TestSealers.fromFixedKey();
		TestClock clock = TestClock.fromInstant(Instant.now());
		String app = sealer.seal("x", "google", HOUR);
		String pending = SealedStateAccess.get().seal(sealer, SealedStateType.PENDING_AUTHORIZATION, "x", "google",
				clock.instant().plus(HOUR));

		UnsealException e = Assertions.assertThrows(UnsealException.class, () -> SealedStateAccess.get().unseal(sealer,
				SealedStateType.PENDING_AUTHORIZATION, app, "google", clock));
		Assertions.assertEquals(UnsealException.Kind.INVALID, e.getKind());
		Assertions.assertEquals("x", SealedStateAccess.get().unseal(sealer, SealedStateType.APP, app, "google", clock));
		Assertions.assertEquals("x", SealedStateAccess.get().unseal(sealer, SealedStateType.PENDING_AUTHORIZATION,
				pending, "google", clock));

		assertUniformFailure(sealer, pending, "google");

		for (SealedStateType type : List.of(SealedStateType.PENDING_SAML, SealedStateType.OIDC_SESSION))
			assertUniformFailure(sealer, SealedStateAccess.get().seal(sealer, type, "x", "google",
					clock.instant().plus(HOUR)), "google");
	}

	// Exit criterion 9: an oversized seal throws IllegalArgumentException; the limit counts UTF-8 bytes exactly.
	@Test
	void anOversizedSealThrowsIllegalArgumentException() {
		StateSealer sealer = StateSealer.withActiveKey(TestSealers.fixedKey("test"))
				.maximumSealedLength(1_024)
				.build();

		// Key ID "test": ceil(4 * (54 + 4 + p) / 3) <= 1,024 exactly when p <= 710.
		String largest = sealer.seal("x".repeat(710), CONTEXT, HOUR);
		Assertions.assertEquals(1_024, largest.length());
		Assertions.assertEquals("x".repeat(710), sealer.unseal(largest, CONTEXT));
		Assertions.assertThrows(IllegalArgumentException.class, () -> sealer.seal("x".repeat(711), CONTEXT, HOUR));

		// 236 euro signs are 708 UTF-8 bytes and fit; 237 are 711 bytes and do not, although they are 237 characters.
		Assertions.assertEquals("\u20ac".repeat(236), sealer.unseal(sealer.seal("\u20ac".repeat(236), CONTEXT, HOUR),
				CONTEXT));
		Assertions.assertThrows(IllegalArgumentException.class, () -> sealer.seal("\u20ac".repeat(237), CONTEXT,
				HOUR));
		// 178 supplementary characters are 712 bytes in 356 UTF-16 code units.
		Assertions.assertThrows(IllegalArgumentException.class, () -> sealer.seal("\ud834\udd1e".repeat(178), CONTEXT,
				HOUR));
		// Refused before encoding, however long.
		Assertions.assertThrows(IllegalArgumentException.class, () -> sealer.seal("x".repeat(20_000_000), CONTEXT,
				HOUR));

		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
				() -> sealer.seal(Sentinels.SEALED_PLAINTEXT.repeat(100), CONTEXT, HOUR));
		Sentinels.assertAbsent(e);
	}

	// Exit criterion 9: null or out-of-range arguments throw NullPointerException or IllegalArgumentException, never
	// InvalidSealedStateException.
	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void nullOrOutOfRangeArgumentsThrowNullPointerOrIllegalArgumentException() {
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = sealer.seal("x", CONTEXT, HOUR);

		Assertions.assertThrows(NullPointerException.class, () -> sealer.seal(nullValue(), CONTEXT, HOUR));
		Assertions.assertThrows(NullPointerException.class, () -> sealer.seal("x", nullValue(), HOUR));
		Assertions.assertThrows(NullPointerException.class, () -> sealer.seal("x", CONTEXT, nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> sealer.unseal(nullValue(), CONTEXT));
		Assertions.assertThrows(NullPointerException.class, () -> sealer.unseal(sealed, nullValue()));

		// A context is 1 to 256 characters of well-formed UTF-16.
		for (String context : List.of("", "x".repeat(257), "\ud800", "\udc00", "a\ud800b", "\udc00\ud800",
				"\ud834\udd1e".repeat(128) + "x")) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> sealer.seal("x", context, HOUR),
					() -> escape(context));
			Assertions.assertThrows(IllegalArgumentException.class, () -> sealer.unseal(sealed, context),
					() -> escape(context));
		}

		Assertions.assertEquals("x", sealer.unseal(sealer.seal("x", "x".repeat(256), HOUR), "x".repeat(256)));
		Assertions.assertEquals("x", sealer.unseal(sealer.seal("x", "\ud834\udd1e".repeat(128), HOUR),
				"\ud834\udd1e".repeat(128)));

		// A plaintext is well-formed UTF-16.
		for (String plaintext : List.of("\ud800", "x\udc00", "\udc00\ud800"))
			Assertions.assertThrows(IllegalArgumentException.class, () -> sealer.seal(plaintext, CONTEXT, HOUR));

		// A lifetime is from 1 second to 400 days (Limits.SEAL_LIFETIME).
		for (Duration lifetime : List.of(Duration.ZERO, Duration.ofMillis(999), Duration.ofNanos(999_999_999),
				Duration.ofSeconds(-1), Duration.ofDays(400).plusNanos(1), Duration.ofDays(401),
				Duration.ofSeconds(Long.MAX_VALUE), Duration.ofSeconds(Long.MIN_VALUE)))
			Assertions.assertThrows(IllegalArgumentException.class, () -> sealer.seal("x", CONTEXT, lifetime),
					lifetime::toString);

		Assertions.assertEquals("x", sealer.unseal(sealer.seal("x", CONTEXT, Duration.ofSeconds(1)), CONTEXT));
		Assertions.assertEquals("x", sealer.unseal(sealer.seal("x", CONTEXT, Duration.ofDays(400)), CONTEXT));
	}

	// Exit criterion 9 and G6-9: the builder rejects duplicate key IDs or key bytes and more than 16 verification keys.
	// Deliberate null inputs verify runtime rejection.
	@SuppressWarnings("NullAway")
	@Test
	void theBuilderRejectsKeyViolations() {
		SealingKey active = TestSealers.fixedKey("active");
		List<SealingKey> sixteen = new ArrayList<>();

		for (int index = 0; index < 16; ++index)
			sixteen.add(TestSealers.fixedKey("v" + index));

		Assertions.assertNotNull(StateSealer.withActiveKey(active).verificationKeys(sixteen).build());

		List<SealingKey> seventeen = new ArrayList<>(sixteen);
		seventeen.add(TestSealers.fixedKey("v16"));
		String activeBytes = Base64.getEncoder().encodeToString(TestSealers.fixedKeyBytes("active"));

		List<List<SealingKey>> violations = List.of(
				seventeen,
				List.of(active),
				List.of(TestSealers.fixedKey("active")),
				List.of(SealingKey.fromBase64("active", Base64.getEncoder().encodeToString(TestSealers.fixedKeyBytes("x")))),
				List.of(SealingKey.fromBase64("same-bytes", activeBytes)),
				List.of(TestSealers.fixedKey("v1"), TestSealers.fixedKey("v1")),
				List.of(TestSealers.fixedKey("v1"), SealingKey.fromBase64("v2", Base64.getEncoder().encodeToString(
						TestSealers.fixedKeyBytes("v1")))),
				List.of(TestSealers.fixedKey("v1"), TestSealers.fixedKey("v2"), TestSealers.fixedKey("v1")));

		for (List<SealingKey> verificationKeys : violations) {
			IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class,
					() -> StateSealer.withActiveKey(active).verificationKeys(verificationKeys).build(),
					verificationKeys::toString);
			Assertions.assertFalse(String.valueOf(e.getMessage()).contains(activeBytes));
		}

		Assertions.assertThrows(NullPointerException.class, () -> StateSealer.withActiveKey(nullValue()));
		Assertions.assertThrows(NullPointerException.class, () -> StateSealer.withActiveKey(active)
				.verificationKeys(Arrays.asList(TestSealers.fixedKey("v1"), nullValue())));

		// null restores the default, no verification keys.
		StateSealer reset = StateSealer.withActiveKey(active).verificationKeys(seventeen).verificationKeys(null).build();
		Assertions.assertEquals("StateSealer{activeKeyId=active, verificationKeyIds=[], maximumSealedLength=3800}",
				reset.toString());
	}

	// R8 and G5-4: maximumSealedLength is 3,800 [1,024, 16,384], checked at build(); null restores the default.
	@Test
	void theMaximumSealedLengthDefaultsTo3800AndBuildRejectsValuesOutsideItsRange() {
		SealingKey key = TestSealers.fixedKey("test");

		for (int length : new int[]{1_023, 16_385, 0, -1, Integer.MIN_VALUE, Integer.MAX_VALUE})
			Assertions.assertThrows(IllegalArgumentException.class, () -> StateSealer.withActiveKey(key)
					.maximumSealedLength(length).build(), () -> String.valueOf(length));

		Assertions.assertEquals("StateSealer{activeKeyId=test, verificationKeyIds=[], maximumSealedLength=1024}",
				StateSealer.withActiveKey(key).maximumSealedLength(1_024).build().toString());
		Assertions.assertEquals("StateSealer{activeKeyId=test, verificationKeyIds=[], maximumSealedLength=16384}",
				StateSealer.withActiveKey(key).maximumSealedLength(16_384).build().toString());

		StateSealer sealer = StateSealer.withActiveKey(key).maximumSealedLength(1_024).maximumSealedLength(null).build();
		// Key ID "test": 2,792 bytes seal to exactly 3,800 characters; 2,793 would take 3,802.
		String largest = sealer.seal("x".repeat(2_792), CONTEXT, HOUR);

		Assertions.assertEquals(3_800, largest.length());
		Assertions.assertEquals("x".repeat(2_792), sealer.unseal(largest, CONTEXT));
		Assertions.assertThrows(IllegalArgumentException.class, () -> sealer.seal("x".repeat(2_793), CONTEXT, HOUR));
	}

	@Test
	void roundTripsEmptyNonAsciiAndMaximumLengthInputs() {
		StateSealer sealer = TestSealers.fromFixedKey();

		for (String plaintext : List.of("", " ", "\u0000", "h\u00e9llo w\u00f6rld \u2713 \ud834\udd1e", PLAINTEXT,
				"\ufffd\ufeff")) {
			for (String context : List.of("c", "tenant/\u00e9/\ud834\udd1e", "x".repeat(256), "\u0000"))
				Assertions.assertEquals(plaintext, sealer.unseal(sealer.seal(plaintext, context, HOUR), context));
		}
	}

	// G6-8: each seal draws its own random 16-byte salt S, so every value gets its own AES key, and its own random
	// 12-byte IV. Both are checked separately: a fixed salt would put every value under one message key, back under
	// GCM's random-IV bound, and a fixed IV would leave only the salt varying. Values are base64url.
	@Test
	void everySealDrawsAFreshSaltAndIvAndIsBase64url() throws EncodingException {
		StateSealer sealer = TestSealers.fromFixedKey();
		int saltOffset = 2 + TestSealers.FIXED_KEY_ID.length();
		int ivOffset = saltOffset + 16;
		Set<String> values = new HashSet<>();
		Set<String> salts = new HashSet<>();
		Set<String> ivs = new HashSet<>();

		for (int index = 0; index < 200; ++index) {
			String sealed = sealer.seal(PLAINTEXT, CONTEXT, HOUR);
			byte[] bytes = Base64Url.decode(sealed);

			Assertions.assertTrue(BASE64URL.matcher(sealed).matches(), sealed);
			Assertions.assertTrue(values.add(sealed));
			Assertions.assertTrue(salts.add(Base64Url.encode(Arrays.copyOfRange(bytes, saltOffset, ivOffset))),
					"a salt repeated");
			Assertions.assertTrue(ivs.add(Base64Url.encode(Arrays.copyOfRange(bytes, ivOffset, ivOffset + 12))),
					"an IV repeated");
		}
	}

	// The default clock is the system clock.
	@Test
	void theDefaultClockIsTheSystemClock() {
		StateSealer sealer = TestSealers.fromFixedKey();
		StateSealer future = StateSealer.withActiveKey(TestSealers.fixedKey(TestSealers.FIXED_KEY_ID))
				.clock(TestClock.fromInstant(Instant.now().plus(Duration.ofDays(2))))
				.build();
		String sealed = sealer.seal("x", CONTEXT, Duration.ofDays(1));

		Assertions.assertEquals("x", sealer.unseal(sealed, CONTEXT));
		assertUniformFailure(future, sealed, CONTEXT);
		Assertions.assertEquals("x", StateSealer.withActiveKey(TestSealers.fixedKey(TestSealers.FIXED_KEY_ID))
				.clock(TestClock.fromInstant(START))
				.clock(null)
				.build()
				.unseal(sealed, CONTEXT));
	}

	// R9: no secret or input appears in any rendering or failure.
	@Test
	void neverRendersKeysPlaintextsOrContexts() {
		String keyWithMarker = Sentinels.MARKER + "A".repeat(29) + "=";
		SealingKey key = SealingKey.fromBase64("2026-09", keyWithMarker);
		StateSealer sealer = StateSealer.withActiveKey(key)
				.verificationKeys(List.of(TestSealers.fixedKey("2026-06")))
				.build();
		String context = Sentinels.secret("context");
		String sealed = sealer.seal(Sentinels.SEALED_PLAINTEXT, context, HOUR);

		Assertions.assertEquals("StateSealer{activeKeyId=2026-09, verificationKeyIds=[2026-06], "
				+ "maximumSealedLength=3800}", sealer.toString());
		Sentinels.assertAbsent(List.of(key, sealer, sealed));
		Sentinels.assertAbsent(Assertions.assertThrows(InvalidSealedStateException.class,
				() -> sealer.unseal(sealed, context + "x")));
		Sentinels.assertAbsent(Assertions.assertThrows(InvalidSealedStateException.class,
				() -> sealer.unseal(sealed.substring(1), context)));
		Sentinels.assertAbsent(Assertions.assertThrows(IllegalArgumentException.class,
				() -> StateSealer.withActiveKey(key).verificationKeys(List.of(SealingKey.fromBase64("copy",
						keyWithMarker))).build()));
		Assertions.assertEquals(Sentinels.SEALED_PLAINTEXT, sealer.unseal(sealed, context));
	}

	// G6-9: build() runs a self-test, and throws IllegalStateException if the JCA provider refuses or misbehaves: if it
	// refuses AES-GCM, never verifies the tag, drops the additional authenticated data (which would silently unbind the
	// context) or ignores the IV. A sealer built earlier then fails closed. The provider is JVM-global, so this runs in a
	// child JVM.
	//
	// The test providers are unsigned. OpenJDK builds (Corretto, on every CI leg) accept unsigned JCE providers, but a
	// JDK that requires signed ones, such as Oracle JDK, skips them and keeps using its own AES-GCM. The child checks
	// which provider it got. Only on a runtime that is not an OpenJDK build is the test then aborted; on an OpenJDK
	// build an ignored provider is a failure, so the test is never silently skipped there.
	@Test
	void buildThrowsIllegalStateExceptionWhenTheProviderRefusesAndBuiltSealersFailClosed() throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(ProviderFailureMain.class).build().run();

		Assertions.assertFalse(result.isTimedOut(), result::toString);
		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		String output = result.getStandardOutput();
		boolean providerIgnored = output.contains(ProviderFailureMain.PROVIDER_IGNORED);
		Assertions.assertFalse(providerIgnored && isOpenJdkRuntime(),
				() -> "an OpenJDK build must select the unsigned test provider: " + result);
		Assumptions.assumeFalse(providerIgnored, () -> "This JDK (" + System.getProperty("java.runtime.name")
				+ ") did not select the unsigned test JCE provider, as a JDK that requires signed JCE providers"
				+ " (Oracle JDK) does, so the provider-failure paths cannot be exercised here: " + output.strip());
		Assertions.assertTrue(output.contains(ProviderFailureMain.SUCCESS), result::toString);
	}

	// Section 9.6 and seal's contract: a SecureRandom that fails, at construction or at any later draw, surfaces as the
	// documented IllegalStateException from build() and from both seal paths, never as a raw ProviderException. The
	// provider is JVM-global, so this runs in a child JVM. SecureRandom is JCA, not JCE, so no JDK ignores an unsigned
	// provider of it.
	@Test
	void secureRandomFailuresThrowIllegalStateExceptionFromBuildAndSeal() throws Exception {
		ChildJvm.Result result = ChildJvm.withMainClass(EntropyFailureMain.class).build().run();

		Assertions.assertFalse(result.isTimedOut(), result::toString);
		Assertions.assertEquals(0, result.getExitCode(), result::toString);
		Assertions.assertTrue(result.getStandardOutput().contains(EntropyFailureMain.SUCCESS), result::toString);
	}

	private static boolean isOpenJdkRuntime() {
		return System.getProperty("java.runtime.name", "").startsWith("OpenJDK");
	}

	/**
	 * Asserts that {@code sealed} fails to open with the identical exception every failure gives: the same class,
	 * message, category and transience, no cause, nothing suppressed, the same stack trace down to this class's own
	 * call, and no echo of the input.
	 */
	private static void assertUniformFailure(@NonNull StateSealer sealer,
																					 @NonNull String sealed,
																					 @NonNull String context) {
		InvalidSealedStateException e = failureOf(sealer, sealed, context);
		InvalidSealedStateException reference = failureOf(sealer, "", CONTEXT);

		Assertions.assertEquals(InvalidSealedStateException.class, e.getClass());
		Assertions.assertEquals("Sealed state is invalid.", e.getMessage());
		Assertions.assertEquals(ErrorCategory.VALIDATION_FAILURE, e.getCategory());
		Assertions.assertFalse(e.isTransient());
		Assertions.assertNull(e.getCause());
		Assertions.assertEquals(0, e.getSuppressed().length);
		Assertions.assertEquals(throwSite(reference), throwSite(e));

		if (sealed.length() >= 8)
			Assertions.assertFalse(e.toString().contains(sealed));
	}

	/**
	 * The one call site every failure in this class goes through, so their stack traces can be compared.
	 */
	private static @NonNull InvalidSealedStateException failureOf(@NonNull StateSealer sealer,
																											 @NonNull String sealed,
																											 @NonNull String context) {
		return Assertions.assertThrows(InvalidSealedStateException.class, () -> sealer.unseal(sealed, context));
	}

	/**
	 * The frames from where the exception was created down to {@link #failureOf}.
	 */
	private static @NonNull List<@NonNull StackTraceElement> throwSite(@NonNull Throwable e) {
		StackTraceElement[] trace = e.getStackTrace();

		for (int index = 0; index < trace.length; ++index)
			if (trace[index].getMethodName().equals("failureOf"))
				return List.of(Arrays.copyOf(trace, index + 1));

		throw new AssertionError("No failureOf frame in " + Arrays.toString(trace));
	}

	/**
	 * Seals {@link #PLAINTEXT} until the value holds a {@code -} or {@code _}, so its standard-alphabet encoding
	 * differs from it. A single seal of this length lacks both about once in 110 tries (measured: 0.89% of 200,000),
	 * which made a test that sealed once fail at random; 64 tries all lacking both has a probability below 10^-130.
	 */
	private static @NonNull String sealWithAUrlSafeCharacter(@NonNull StateSealer sealer) {
		for (int attempt = 0; attempt < 64; ++attempt) {
			String sealed = sealer.seal(PLAINTEXT, CONTEXT, HOUR);

			if (sealed.indexOf('-') >= 0 || sealed.indexOf('_') >= 0)
				return sealed;
		}

		throw new AssertionError("64 sealed values in a row had neither '-' nor '_'");
	}

	private static @NonNull String keyIdOf(@NonNull String sealed) {
		try {
			byte[] bytes = Base64Url.decode(sealed);
			return new String(bytes, 2, bytes[1], StandardCharsets.US_ASCII);
		} catch (EncodingException e) {
			throw new AssertionError("not base64url", e);
		}
	}

	/**
	 * Changes the last character of an unpadded base64url value so that its unused trailing bits are not zero.
	 */
	private static @NonNull String nonCanonical(@NonNull String sealed) {
		Assertions.assertNotEquals(0, sealed.length() % 4, "the value must have unused trailing bits");
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		char last = sealed.charAt(sealed.length() - 1);
		return sealed.substring(0, sealed.length() - 1) + alphabet.charAt(alphabet.indexOf(last) ^ 1);
	}

	private static byte @NonNull [] concatenate(byte @NonNull [] first,
																		byte @NonNull [] second) {
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		output.writeBytes(first);
		output.writeBytes(second);
		return output.toByteArray();
	}

	private static @NonNull String escape(@NonNull String value) {
		StringBuilder escaped = new StringBuilder();

		for (char character : value.toCharArray())
			escaped.append(character >= 0x20 && character < 0x7f ? String.valueOf(character)
					: String.format(java.util.Locale.ROOT, "\\u%04x", (int) character));

		return escaped.toString();
	}

	/**
	 * Hides a {@code null} from NullAway, for the tests that check null handling.
	 */
	@SuppressWarnings({"NullAway", "TypeParameterUnusedInFormals"})
	private static <T> @Nullable T nullValue() {
		return null;
	}

	/**
	 * Runs in a child JVM: installs a cipher provider that refuses AES-GCM, then one that never verifies the tag, then
	 * one that drops the additional authenticated data, then one that ignores the IV, and exits 0 only if
	 * {@code build()} throws IllegalStateException for each and a sealer built earlier fails closed. If the JDK does not
	 * select an installed test provider (a JDK that requires signed JCE providers), it prints {@link #PROVIDER_IGNORED}
	 * with the provider it got instead, and exits 0 without {@link #SUCCESS}.
	 */
	public static final class ProviderFailureMain {
		static final String SUCCESS = "provider-failure-ok";
		static final String PROVIDER_IGNORED = "provider-ignored";

		private ProviderFailureMain() {
			// Only main runs.
		}

		public static void main(@NonNull String @NonNull [] arguments) throws GeneralSecurityException {
			StateSealer earlier = TestSealers.fromFixedKey();
			String sealed = earlier.seal("x", CONTEXT, HOUR);

			// A provider that refuses: build() fails, and the earlier sealer throws IllegalStateException from seal and
			// the uniform exception from unseal, whose GCM step catches the provider's RuntimeException.
			Security.insertProviderAt(new TestProvider("RevetsecRefusing", RefusingGcm.class), 1);
			if (!selects("RevetsecRefusing"))
				return;
			IllegalStateException refused = Assertions.assertThrows(IllegalStateException.class,
					TestSealers::fromFixedKey);
			Assertions.assertInstanceOf(ProviderException.class, refused.getCause());
			Assertions.assertThrows(IllegalStateException.class, () -> earlier.seal("x", CONTEXT, HOUR));
			InvalidSealedStateException unsealed = Assertions.assertThrows(InvalidSealedStateException.class,
					() -> earlier.unseal(sealed, CONTEXT));
			Assertions.assertNull(unsealed.getCause());
			Security.removeProvider("RevetsecRefusing");
			Assertions.assertEquals("x", earlier.unseal(sealed, CONTEXT));

			// A provider that never verifies the tag: the self-test's altered value opens, so build() fails.
			Security.insertProviderAt(new TestProvider("RevetsecNonVerifying", NonVerifyingGcm.class), 1);
			if (!selects("RevetsecNonVerifying"))
				return;
			IllegalStateException failed = Assertions.assertThrows(IllegalStateException.class,
					TestSealers::fromFixedKey);
			Assertions.assertEquals("The cryptographic provider failed StateSealer's self-test.", failed.getMessage());
			Security.removeProvider("RevetsecNonVerifying");

			// A provider that is real AES-GCM but ignores the additional authenticated data: every value it seals opens
			// under any context, so the self-test's other-context open and its known answer both fail.
			Security.insertProviderAt(new TestProvider("RevetsecAadDropping", AadDroppingGcm.class), 1);
			if (!selects("RevetsecAadDropping"))
				return;
			IllegalStateException unbound = Assertions.assertThrows(IllegalStateException.class,
					TestSealers::fromFixedKey);
			Assertions.assertEquals("The cryptographic provider failed StateSealer's self-test.", unbound.getMessage());
			Security.removeProvider("RevetsecAadDropping");

			// A provider that is real AES-GCM but uses its own IV: values seal, open and stay bound to their context, so
			// only the self-test's known answer finds it.
			Security.insertProviderAt(new TestProvider("RevetsecIvIgnoring", IvIgnoringGcm.class), 1);
			if (!selects("RevetsecIvIgnoring"))
				return;
			IllegalStateException ivIgnored = Assertions.assertThrows(IllegalStateException.class,
					TestSealers::fromFixedKey);
			Assertions.assertEquals("The cryptographic provider failed StateSealer's self-test.", ivIgnored.getMessage());
			Security.removeProvider("RevetsecIvIgnoring");
			Assertions.assertEquals("x", TestSealers.fromFixedKey().unseal(sealed, CONTEXT));

			System.out.println(SUCCESS);
			System.out.flush();
		}

		/**
		 * Whether a new AES/GCM/NoPadding cipher, obtained the way {@code AesGcm} obtains one, comes from the named
		 * provider. If not, prints {@link #PROVIDER_IGNORED} and the provider the JDK chose.
		 */
		private static boolean selects(@NonNull String providerName) throws GeneralSecurityException {
			String selected = Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName();

			if (selected.equals(providerName))
				return true;

			System.out.println(PROVIDER_IGNORED + ": " + providerName + " was installed first, but AES/GCM/NoPadding"
					+ " came from " + selected);
			System.out.flush();
			return false;
		}
	}

	/**
	 * Runs in a child JVM: installs a SecureRandom provider first, then makes its draws fail, and exits 0 with
	 * {@link #SUCCESS} only if every failure is the documented IllegalStateException with the provider's exception
	 * underneath: a failing salt draw and a failing IV draw, from {@code seal} and from the internal seal of
	 * {@link SealedStateAccess}, and a SecureRandom that cannot be constructed, from {@code build()}.
	 */
	public static final class EntropyFailureMain {
		static final String SUCCESS = "entropy-failure-ok";

		private EntropyFailureMain() {
			// Only main runs.
		}

		public static void main(@NonNull String @NonNull [] arguments) {
			Security.insertProviderAt(new FailingRandomProvider(), 1);
			Assertions.assertEquals(FailingRandomProvider.NAME, new SecureRandom().getProvider().getName());

			// build() draws the self-test's salt and IV; every draw succeeds until the budget is set.
			StateSealer sealer = TestSealers.fromFixedKey();
			Assertions.assertEquals("x", sealer.unseal(sealer.seal("x", CONTEXT, HOUR), CONTEXT));

			// The salt draw fails, then only the IV draw.
			for (int successfulDraws = 0; successfulDraws < 2; ++successfulDraws) {
				FailingRandom.REMAINING_DRAWS.set(successfulDraws);
				assertRefused(() -> sealer.seal("x", CONTEXT, HOUR));
				FailingRandom.REMAINING_DRAWS.set(successfulDraws);
				assertRefused(() -> SealedStateAccess.get().seal(sealer, SealedStateType.APP, "x", CONTEXT,
						Instant.now().plus(HOUR)));
			}

			// With draws working again, the same sealer seals again.
			FailingRandom.REMAINING_DRAWS.set(Integer.MAX_VALUE);
			Assertions.assertEquals("x", sealer.unseal(sealer.seal("x", CONTEXT, HOUR), CONTEXT));

			// A SecureRandom that cannot be constructed fails build(), a JVM-environment failure (section 9.6).
			FailingRandom.FAIL_CONSTRUCTION.set(true);
			IllegalStateException unavailable = Assertions.assertThrows(IllegalStateException.class,
					TestSealers::fromFixedKey);
			Assertions.assertTrue(hasCause(unavailable, FailingRandom.CONSTRUCTION_FAILURE), unavailable::toString);
			FailingRandom.FAIL_CONSTRUCTION.set(false);

			Security.removeProvider(FailingRandomProvider.NAME);
			Assertions.assertNotEquals(FailingRandomProvider.NAME, new SecureRandom().getProvider().getName());
			System.out.println(SUCCESS);
			System.out.flush();
		}

		private static void assertRefused(@NonNull Executable seal) {
			IllegalStateException refused = Assertions.assertThrows(IllegalStateException.class, seal);
			Assertions.assertEquals("The cryptographic provider refused to seal.", refused.getMessage());
			ProviderException cause = Assertions.assertInstanceOf(ProviderException.class, refused.getCause());
			Assertions.assertEquals(FailingRandom.DRAW_FAILURE, cause.getMessage());
		}

		private static boolean hasCause(@NonNull Throwable throwable,
																		@NonNull String message) {
			for (Throwable cause = throwable.getCause(); cause != null; cause = cause.getCause())
				if (cause instanceof ProviderException && message.equals(cause.getMessage()))
					return true;

			return false;
		}
	}

	/**
	 * A provider whose only service is {@link FailingRandom}.
	 */
	public static final class FailingRandomProvider extends Provider {
		static final String NAME = "RevetsecFailingRandom";
		private static final long serialVersionUID = 1L;

		FailingRandomProvider() {
			super(NAME, "1.0", "Revetsec test provider");
			put("SecureRandom.RevetsecFailing", FailingRandom.class.getName());
			put("SecureRandom.RevetsecFailing ThreadSafe", "true");
		}
	}

	/**
	 * A SecureRandom over the JDK's SHA1PRNG that throws ProviderException once its draw budget is spent, or from its
	 * constructor when told to, as a PKCS#11 or native SecureRandom does on a device or I/O failure.
	 */
	public static final class FailingRandom extends SecureRandomSpi {
		static final String DRAW_FAILURE = "test SecureRandom draw failed";
		static final String CONSTRUCTION_FAILURE = "test SecureRandom construction failed";
		static final AtomicInteger REMAINING_DRAWS = new AtomicInteger(Integer.MAX_VALUE);
		static final AtomicBoolean FAIL_CONSTRUCTION = new AtomicBoolean();
		private static final long serialVersionUID = 1L;
		private final SecureRandom delegate;

		public FailingRandom() throws GeneralSecurityException {
			if (FAIL_CONSTRUCTION.get())
				throw new ProviderException(CONSTRUCTION_FAILURE);

			this.delegate = SecureRandom.getInstance("SHA1PRNG", "SUN");
		}

		@Override
		protected void engineSetSeed(byte @NonNull [] seed) {
			this.delegate.setSeed(seed);
		}

		@Override
		protected void engineNextBytes(byte @NonNull [] bytes) {
			if (REMAINING_DRAWS.getAndDecrement() <= 0)
				throw new ProviderException(DRAW_FAILURE);

			this.delegate.nextBytes(bytes);
		}

		@Override
		protected byte @NonNull [] engineGenerateSeed(int length) {
			return this.delegate.generateSeed(length);
		}
	}

	/**
	 * A provider with one AES/GCM/NoPadding implementation.
	 */
	public static final class TestProvider extends Provider {
		private static final long serialVersionUID = 1L;

		TestProvider(@NonNull String name,
								 @NonNull Class<? extends @NonNull CipherSpi> implementation) {
			super(name, "1.0", "Revetsec test provider");
			put("Cipher.AES/GCM/NoPadding", implementation.getName());
		}
	}

	/**
	 * AES-GCM that accepts every setup call and then refuses the operation with an unchecked ProviderException.
	 */
	public static class RefusingGcm extends CipherSpi {
		public RefusingGcm() {
			// The JCA instantiates it reflectively.
		}

		@Override
		protected void engineSetMode(@NonNull String mode) {
			// Accepted.
		}

		@Override
		protected void engineSetPadding(@NonNull String padding) {
			// Accepted.
		}

		@Override
		protected int engineGetBlockSize() {
			return 16;
		}

		@Override
		protected int engineGetOutputSize(int inputLength) {
			return inputLength + 16;
		}

		@Override
		protected byte @NonNull [] engineGetIV() {
			return new byte[12];
		}

		@Override
		protected @NonNull AlgorithmParameters engineGetParameters() {
			throw new UnsupportedOperationException();
		}

		@Override
		protected void engineInit(int mode,
															@NonNull Key key,
															@NonNull SecureRandom random) {
			// Accepted.
		}

		@Override
		protected void engineInit(int mode,
															@NonNull Key key,
															@NonNull AlgorithmParameterSpec parameters,
															@NonNull SecureRandom random) {
			// Accepted.
		}

		@Override
		protected void engineInit(int mode,
															@NonNull Key key,
															@NonNull AlgorithmParameters parameters,
															@NonNull SecureRandom random) {
			// Accepted.
		}

		@Override
		protected void engineUpdateAAD(byte @NonNull [] input,
																	 int offset,
																	 int length) {
			// Accepted.
		}

		@Override
		protected byte @NonNull [] engineUpdate(byte @NonNull [] input,
																	int offset,
																	int length) {
			throw new ProviderException("refused");
		}

		@Override
		protected int engineUpdate(byte @NonNull [] input,
															 int offset,
															 int length,
															 byte @NonNull [] output,
															 int outputOffset) {
			throw new ProviderException("refused");
		}

		@Override
		protected byte @NonNull [] engineDoFinal(byte @NonNull [] input,
																	 int offset,
																	 int length) throws AEADBadTagException {
			throw new ProviderException("refused");
		}

		@Override
		protected int engineDoFinal(byte @NonNull [] input,
																int offset,
																int length,
																byte @NonNull [] output,
																int outputOffset) {
			throw new ProviderException("refused");
		}
	}

	/**
	 * The JDK's own AES-GCM (SunJCE), behind a provider of its own, for the misbehaving variants below.
	 */
	public static class DelegatingGcm extends CipherSpi {
		private final Cipher delegate;

		public DelegatingGcm() throws GeneralSecurityException {
			this.delegate = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
		}

		@Override
		protected void engineSetMode(@NonNull String mode) {
			// Only GCM is registered.
		}

		@Override
		protected void engineSetPadding(@NonNull String padding) {
			// Only NoPadding is registered.
		}

		@Override
		protected int engineGetBlockSize() {
			return this.delegate.getBlockSize();
		}

		@Override
		protected int engineGetOutputSize(int inputLength) {
			return this.delegate.getOutputSize(inputLength);
		}

		@Override
		protected byte @NonNull [] engineGetIV() {
			return this.delegate.getIV();
		}

		@Override
		protected @NonNull AlgorithmParameters engineGetParameters() {
			return this.delegate.getParameters();
		}

		@Override
		protected void engineInit(int mode,
															@NonNull Key key,
															@NonNull SecureRandom random) throws InvalidKeyException {
			this.delegate.init(mode, key, random);
		}

		@Override
		protected void engineInit(int mode,
															@NonNull Key key,
															@NonNull AlgorithmParameterSpec parameters,
															@NonNull SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
			this.delegate.init(mode, key, parameters, random);
		}

		@Override
		protected void engineInit(int mode,
															@NonNull Key key,
															@NonNull AlgorithmParameters parameters,
															@NonNull SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
			this.delegate.init(mode, key, parameters, random);
		}

		@Override
		protected void engineUpdateAAD(byte @NonNull [] input,
																	 int offset,
																	 int length) {
			this.delegate.updateAAD(input, offset, length);
		}

		@Override
		protected void engineUpdateAAD(@NonNull ByteBuffer input) {
			this.delegate.updateAAD(input);
		}

		@Override
		protected byte @NonNull [] engineUpdate(byte @NonNull [] input,
																	int offset,
																	int length) {
			return this.delegate.update(input, offset, length);
		}

		@Override
		protected int engineUpdate(byte @NonNull [] input,
															 int offset,
															 int length,
															 byte @NonNull [] output,
															 int outputOffset) throws ShortBufferException {
			return this.delegate.update(input, offset, length, output, outputOffset);
		}

		@Override
		protected byte @NonNull [] engineDoFinal(byte @NonNull [] input,
																	 int offset,
																	 int length) throws IllegalBlockSizeException, BadPaddingException {
			return this.delegate.doFinal(input, offset, length);
		}

		@Override
		protected int engineDoFinal(byte @NonNull [] input,
																int offset,
																int length,
																byte @NonNull [] output,
																int outputOffset)
				throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
			return this.delegate.doFinal(input, offset, length, output, outputOffset);
		}
	}

	/**
	 * The JDK's own AES-GCM, except that additional authenticated data is silently discarded, which leaves every value
	 * sealed and opened correctly but bound to no context.
	 */
	public static final class AadDroppingGcm extends DelegatingGcm {
		public AadDroppingGcm() throws GeneralSecurityException {
			// The JCA instantiates it reflectively.
		}

		@Override
		protected void engineUpdateAAD(byte @NonNull [] input,
																	 int offset,
																	 int length) {
			// The defect under test: the additional authenticated data is dropped.
		}

		@Override
		protected void engineUpdateAAD(@NonNull ByteBuffer input) {
			// The defect under test: the additional authenticated data is dropped.
			input.position(input.limit());
		}
	}

	/**
	 * The JDK's own AES-GCM, except that it always uses an IV of its own in place of the caller's. Every value still
	 * seals, opens and stays bound to its context, so only a known answer shows the defect.
	 */
	public static final class IvIgnoringGcm extends DelegatingGcm {
		private static final byte[] OWN_IV = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

		public IvIgnoringGcm() throws GeneralSecurityException {
			// The JCA instantiates it reflectively.
		}

		@Override
		protected void engineInit(int mode,
															@NonNull Key key,
															@NonNull AlgorithmParameterSpec parameters,
															@NonNull SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
			// The defect under test: the caller's IV is replaced.
			super.engineInit(mode, key, parameters instanceof GCMParameterSpec gcm
					? new GCMParameterSpec(gcm.getTLen(), OWN_IV) : parameters, random);
		}
	}

	/**
	 * "AES-GCM" that copies the plaintext and appends a zero tag, and on decryption drops the tag unchecked.
	 */
	public static final class NonVerifyingGcm extends RefusingGcm {
		private boolean encrypting;

		public NonVerifyingGcm() {
			// The JCA instantiates it reflectively.
		}

		@Override
		protected void engineInit(int mode,
															@NonNull Key key,
															@NonNull AlgorithmParameterSpec parameters,
															@NonNull SecureRandom random) {
			this.encrypting = mode == Cipher.ENCRYPT_MODE;
		}

		@Override
		protected byte @NonNull [] engineDoFinal(byte @NonNull [] input,
																	 int offset,
																	 int length) throws AEADBadTagException {
			if (this.encrypting)
				return Arrays.copyOfRange(input, offset, offset + length + 16);
			if (length < 16)
				throw new AEADBadTagException("short");
			return Arrays.copyOfRange(input, offset, offset + length - 16);
		}
	}
}
