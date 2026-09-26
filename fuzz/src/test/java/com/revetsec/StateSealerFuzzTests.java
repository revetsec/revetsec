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

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import com.revetsec.internal.Limits;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.UnsealException;
import org.junit.jupiter.api.Assertions;

import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Coverage-guided checks for {@link StateSealer} and the internal {@link SealedStateAccess} path (M1 plan, "StateSealer
 * v1", G6-8 to G6-10; exit criteria 8, 9 and 18; INV-G1).
 * <p>
 * The keys are fuzz-only constants (32 consecutive byte values each, never used anywhere else), and every sealer runs
 * on a fixed clock at 2026-09-24T00:00:00Z, so a checked-in sealed value stays authentic and unexpired for as long as
 * the fuzz target exists. The sealer's active key is {@code fuzz-2026}, with {@code fuzz-2025} as a verification key;
 * two more sealers stand for the next rotation step, one with {@code fuzz-2026} demoted to a verification key and one
 * with it retired.
 * <p>
 * Every value that opens is also opened by an implementation of the v1 construction written here from the M1 plan
 * ("StateSealer v1") on the JDK's HMAC-SHA256 and AES-GCM alone, so the label in the key derivation and the header,
 * label and context in the additional authenticated data are checked for every fuzzed plaintext, context and label,
 * not only for the known-answer vectors in {@code SealerV1Tests}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public class StateSealerFuzzTests {
	private static final Instant NOW = Instant.parse("2026-09-24T00:00:00Z");
	private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
	private static final Clock EARLIEST = Clock.fixed(Instant.MIN, ZoneOffset.UTC);
	private static final Clock LATEST = Clock.fixed(Instant.MAX, ZoneOffset.UTC);
	private static final String CONTEXT = "fuzz-context";
	private static final SealingKey KEY_2025 = fuzzOnlyKey("fuzz-2025", 0x10);
	private static final SealingKey KEY_2026 = fuzzOnlyKey("fuzz-2026", 0x30);
	private static final SealingKey KEY_2027 = fuzzOnlyKey("fuzz-2027", 0x50);
	/**
	 * The master keys {@link #SEALER} holds, for the independent implementation.
	 */
	private static final Map<String, byte[]> MASTER_KEYS = Map.of("fuzz-2025", fuzzOnlyKeyBytes(0x10),
			"fuzz-2026", fuzzOnlyKeyBytes(0x30));
	private static final StateSealer SEALER = StateSealer.withActiveKey(KEY_2026)
			.verificationKeys(List.of(KEY_2025))
			.clock(CLOCK)
			.build();
	private static final StateSealer PROMOTED = StateSealer.withActiveKey(KEY_2027)
			.verificationKeys(List.of(KEY_2026))
			.clock(CLOCK)
			.build();
	private static final StateSealer RETIRED = StateSealer.withActiveKey(KEY_2027).clock(CLOCK).build();
	private static final SealedStateAccess.Operations ACCESS = SealedStateAccess.get();
	private static final int MAXIMUM_SEALED_LENGTH = Limits.STATE_SEALER_MAXIMUM_SEALED_LENGTH.getDefaultIntValue();
	private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

	/**
	 * The one public failure: its message, and its stack trace down to {@code StateSealer.unseal}, which every failure
	 * must share, whichever of the nine unseal steps failed.
	 */
	private static final InvalidSealedStateException REFERENCE_FAILURE = referenceFailure();
	private static final String CONTEXT_MESSAGE = sealMessage("x", "", Duration.ofHours(1));
	private static final String ILL_FORMED_MESSAGE = sealMessage("\uD800", CONTEXT, Duration.ofHours(1));
	private static final String TOO_LONG_MESSAGE = sealMessage("x".repeat(MAXIMUM_SEALED_LENGTH), CONTEXT,
			Duration.ofHours(1));

	/**
	 * Any text given to {@link StateSealer#unseal(String, String)} either opens, or fails with the one
	 * {@link InvalidSealedStateException}: the fixed message, no cause, nothing suppressed, VALIDATION_FAILURE, not
	 * transient, and the same stack trace whichever step failed (exit 8). Through {@link SealedStateAccess} the same
	 * text fails with {@link UnsealException.Kind#INVALID}, and with {@link UnsealException.Kind#EXPIRED} only for a
	 * value that opens at an earlier time. Nothing longer than the maximum sealed length opens, not even an authentic
	 * value sealed under a larger maximum (the {@code over-maximum-length} seed; unseal step 1). A value that opens is
	 * authentic, and then: the internal path and the independent implementation return the same plaintext; any other
	 * label or context fails; it has expired at the latest instant; changing any one character makes it fail; and it
	 * opens after the next rotation step only if its key is still held (exit 9). Nothing else is thrown (INV-G1).
	 *
	 * @param input the fuzzed sealed value, read as ISO-8859-1 so every byte is one character
	 */
	@FuzzTest(maxDuration = "5m")
	public void unsealRejectsEverythingButAuthenticValuesWithOneFixedException(byte[] input) throws UnsealException {
		String sealed = new String(input, StandardCharsets.ISO_8859_1);
		String opened;

		try {
			opened = SEALER.unseal(sealed, CONTEXT);
		} catch (InvalidSealedStateException e) {
			requireUniformFailure(e);
			requireInternalFailure(sealed, SealedStateType.APP, CONTEXT, CLOCK, false);

			for (SealedStateType type : SealedStateType.values())
				if (type != SealedStateType.APP)
					requireOpensOnlyUnderItsOwnLabel(sealed, type);

			return;
		}

		// Unseal step 1 bounds the value before decoding, so nothing longer opens, however authentic.
		Assertions.assertTrue(sealed.length() <= MAXIMUM_SEALED_LENGTH,
				"a value longer than the maximum sealed length opened");
		Assertions.assertEquals(opened, ACCESS.unseal(SEALER, SealedStateType.APP, sealed, CONTEXT, CLOCK),
				"the public and internal paths opened a value differently");
		requireAuthenticValueIsBound(sealed, SealedStateType.APP, CONTEXT, opened, NOW.getEpochSecond() + 1);
		requireExpired(sealed, SealedStateType.APP, CONTEXT, LATEST);
	}

	/**
	 * Every value sealed through the public API or {@link SealedStateAccess} opens with the same plaintext, under its
	 * own label and context, up to the last nanosecond before its notAfter (the ceiling of its expiry in whole seconds)
	 * and never at or after it, where the internal path reports {@link UnsealException.Kind#EXPIRED}. Its length is
	 * exactly what the v1 format gives (54 bytes plus the key ID, in unpadded base64url), and the independent
	 * implementation opens it to the same plaintext and notAfter. Any other label, a longer context, another context of
	 * the same length, and any change to the value, fail; it opens after the next rotation step only while its key is
	 * still held. A seal that must fail (a context outside 1 to 256 well-formed characters, a lifetime outside
	 * [1 s, 400 days], an unpaired surrogate, a value longer than the maximum sealed length) throws
	 * {@link IllegalArgumentException} with the message of the first failed check, which never holds the plaintext or
	 * the context (R9, exit 9).
	 *
	 * @param data the fuzzed plaintext, context, label, lifetime and edit
	 */
	@FuzzTest(maxDuration = "5m")
	public void sealedValuesOpenOnlyUnchangedUnderTheirOwnLabelContextAndTime(FuzzedDataProvider data)
			throws UnsealException {
		String plaintext = data.consumeBoolean() ? data.consumeString(3_000) : characters(data, 16);
		String context = data.consumeBoolean() ? CONTEXT : characters(data, 260);
		boolean publicApi = data.consumeBoolean();
		SealedStateType type = publicApi ? SealedStateType.APP : data.pickValue(SealedStateType.values());
		String sealed;
		long notAfter;

		if (publicApi) {
			Duration lifetime = Duration.ofSeconds(data.consumeLong(-1, Duration.ofDays(400).toSeconds() + 1),
					data.consumeInt(0, 999_999_999));
			String expected = expectedSealFailure(plaintext, context, lifetime);

			try {
				sealed = SEALER.seal(plaintext, context, lifetime);
			} catch (IllegalArgumentException e) {
				requireSealFailure(e, expected);
				return;
			}

			Assertions.assertNull(expected, () -> "seal succeeded where it must fail with: " + expected);
			notAfter = NOW.getEpochSecond() + lifetime.toSeconds();
		} else {
			Instant expiresAt = Instant.ofEpochSecond(data.consumeLong(NOW.getEpochSecond() - 100_000_000L,
					NOW.getEpochSecond() + 100_000_000L), data.consumeInt(0, 999_999_999));
			String expected = expectedSealFailure(plaintext, context, null);

			try {
				sealed = ACCESS.seal(SEALER, type, plaintext, context, expiresAt);
			} catch (IllegalArgumentException e) {
				requireSealFailure(e, expected);
				return;
			}

			Assertions.assertNull(expected, () -> "seal succeeded where it must fail with: " + expected);
			notAfter = expiresAt.getNano() == 0 ? expiresAt.getEpochSecond() : expiresAt.getEpochSecond() + 1;
		}

		Assertions.assertEquals(expectedSealedLength(plaintext), sealed.length(), "the sealed length is not v1's");

		for (int index = 0; index < sealed.length(); ++index)
			Assertions.assertTrue(ALPHABET.indexOf(sealed.charAt(index)) >= 0, "a sealed value left the alphabet");

		Assertions.assertEquals(notAfter, requireAuthenticValueIsBound(sealed, type, context, plaintext, notAfter),
				"the value holds another notAfter");
		requireExpired(sealed, type, context, Clock.fixed(Instant.ofEpochSecond(notAfter), ZoneOffset.UTC));

		if (type == SealedStateType.APP && notAfter > NOW.getEpochSecond())
			Assertions.assertEquals(plaintext, SEALER.unseal(sealed, context), "the public path did not open the value");

		String edited = edited(sealed, data);

		if (!edited.equals(sealed)) {
			requireInternalFailure(edited, type, context, beforeNotAfter(notAfter), true);

			if (type == SealedStateType.APP)
				requirePublicFailure(edited, context);
		}
	}

	/**
	 * An authentic value opens only under its own label and context, before its notAfter, and with a changed character
	 * never; after the next rotation step it opens only while its key is still held. The independent implementation
	 * opens it to the same plaintext, with a notAfter no earlier than {@code notAfter}.
	 *
	 * @return the notAfter the value holds
	 */
	private static long requireAuthenticValueIsBound(String sealed, SealedStateType type, String context,
																									 String plaintext, long notAfter) throws UnsealException {
		Clock beforeNotAfter = beforeNotAfter(notAfter);
		Assertions.assertEquals(plaintext, ACCESS.unseal(SEALER, type, sealed, context, beforeNotAfter),
				"an authentic value did not open before its notAfter");
		long heldNotAfter = independentlyOpened(sealed, type, context, plaintext);
		Assertions.assertTrue(heldNotAfter >= notAfter, "a value opened after the notAfter it holds");

		for (SealedStateType other : SealedStateType.values())
			if (other != type)
				requireInternalFailure(sealed, other, context, beforeNotAfter, true);

		// A longer context, and one of the same length in UTF-16 and UTF-8, so that the context's bytes are bound, and
		// not only its length.
		for (String otherContext : List.of(otherContext(context), sameLengthOtherContext(context))) {
			requireInternalFailure(sealed, type, otherContext, beforeNotAfter, true);

			if (type == SealedStateType.APP)
				requirePublicFailure(sealed, otherContext);
		}

		int position = Math.floorMod(plaintext.hashCode(), sealed.length());
		char original = sealed.charAt(position);
		char replacement = ALPHABET.charAt((ALPHABET.indexOf(original) + 1) % ALPHABET.length());
		String changed = sealed.substring(0, position) + replacement + sealed.substring(position + 1);
		requireInternalFailure(changed, type, context, beforeNotAfter, true);

		boolean activeKey = keyIdOf(sealed).equals(KEY_2026.getKeyId());
		boolean opensAfterPromotion = opens(PROMOTED, sealed, type, context, beforeNotAfter);
		boolean opensAfterRetirement = opens(RETIRED, sealed, type, context, beforeNotAfter);
		Assertions.assertEquals(activeKey, opensAfterPromotion, "a demoted key did not verify, or a removed one did");
		Assertions.assertFalse(opensAfterRetirement, "a value opened after its key was retired");
		return heldNotAfter;
	}

	/**
	 * Opens an authentic value with the v1 construction as the M1 plan states it, on the JDK's HMAC-SHA256 and
	 * AES-GCM, apart from Revetsec's own {@code Hkdf} and {@code AesGcm}: PRK = HMAC-SHA256(key = the extract string,
	 * message = the master key); K = HKDF-Expand(PRK, the key string || 0x00 || label || 0x00 || salt, 32), one HMAC
	 * block; AAD = the AAD string || u32 || header || u32 || label || u32 || UTF-8(context); and the body is notAfter
	 * (int64, big-endian) || UTF-8(plaintext).
	 *
	 * @return the notAfter the value holds, in epoch seconds
	 */
	private static long independentlyOpened(String sealed, SealedStateType type, String context, String plaintext) {
		byte[] bytes = Base64.getUrlDecoder().decode(sealed);
		int keyIdLength = bytes[1] & 0xFF;
		byte[] masterKey = MASTER_KEYS.get(new String(bytes, 2, keyIdLength, StandardCharsets.US_ASCII));
		Assertions.assertNotNull(masterKey, "a value opened under a key the sealer does not hold");
		int saltStart = 2 + keyIdLength;
		int ivStart = saltStart + 16;
		int headerLength = ivStart + 12;
		byte[] header = Arrays.copyOfRange(bytes, 0, headerLength);
		byte[] label = type.getLabel().getBytes(StandardCharsets.US_ASCII);
		byte[] contextBytes = context.getBytes(StandardCharsets.UTF_8);

		try {
			byte[] pseudorandomKey = hmacSha256(ascii("revetsec/state-sealer/v1/extract"), masterKey);
			byte[] keyInfo = concatenated(ascii("revetsec/state-sealer/v1/aes-256-gcm-key"), new byte[]{0}, label,
					new byte[]{0}, Arrays.copyOfRange(bytes, saltStart, ivStart));
			// HKDF-Expand to 32 bytes is the first block alone: T(1) = HMAC(PRK, info || 0x01) (RFC 5869 section 2.3).
			byte[] messageKey = hmacSha256(pseudorandomKey, concatenated(keyInfo, new byte[]{1}));
			byte[] additionalData = concatenated(ascii("revetsec/state-sealer/v1/aad"), u32(header.length), header,
					u32(label.length), label, u32(contextBytes.length), contextBytes);
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(messageKey, "AES"),
					new GCMParameterSpec(128, Arrays.copyOfRange(bytes, ivStart, headerLength)));
			cipher.updateAAD(additionalData);
			byte[] body = cipher.doFinal(bytes, headerLength, bytes.length - headerLength);
			Assertions.assertEquals(plaintext, new String(body, 8, body.length - 8, StandardCharsets.UTF_8),
					"the independent implementation opened another plaintext");
			return ByteBuffer.wrap(body, 0, 8).getLong();
		} catch (GeneralSecurityException e) {
			return Assertions.fail("the independent implementation of v1 did not open an authentic value", e);
		}
	}

	private static byte[] hmacSha256(byte[] key, byte[] message) throws GeneralSecurityException {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(key, "HmacSHA256"));
		return mac.doFinal(message);
	}

	private static byte[] concatenated(byte[]... parts) {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();

		for (byte[] part : parts)
			bytes.writeBytes(part);

		return bytes.toByteArray();
	}

	private static byte[] u32(int value) {
		return ByteBuffer.allocate(Integer.BYTES).putInt(value).array();
	}

	private static byte[] ascii(String value) {
		return value.getBytes(StandardCharsets.US_ASCII);
	}

	/**
	 * A value that some label opens is opened by that label only; one that no label opens stays closed.
	 */
	private static void requireOpensOnlyUnderItsOwnLabel(String sealed, SealedStateType type) throws UnsealException {
		String opened;

		try {
			opened = ACCESS.unseal(SEALER, type, sealed, CONTEXT, CLOCK);
		} catch (UnsealException e) {
			requireFixedShape(e);

			if (e.getKind() == UnsealException.Kind.EXPIRED)
				Assertions.assertNotNull(ACCESS.unseal(SEALER, type, sealed, CONTEXT, EARLIEST),
						"EXPIRED for a value that is not authentic");

			return;
		}

		requireAuthenticValueIsBound(sealed, type, CONTEXT, opened, NOW.getEpochSecond() + 1);
	}

	/**
	 * Requires the internal path to fail: {@link UnsealException.Kind#INVALID} when {@code invalid} is set, otherwise
	 * INVALID or EXPIRED, where EXPIRED is allowed only for a value that opens at an earlier time.
	 */
	private static void requireInternalFailure(String sealed, SealedStateType type, String context, Clock clock,
																						 boolean invalid) throws UnsealException {
		try {
			ACCESS.unseal(SEALER, type, sealed, context, clock);
		} catch (UnsealException e) {
			requireFixedShape(e);

			if (invalid)
				Assertions.assertEquals(UnsealException.Kind.INVALID, e.getKind(), "expected INVALID");
			else if (e.getKind() == UnsealException.Kind.EXPIRED)
				Assertions.assertNotNull(ACCESS.unseal(SEALER, type, sealed, context, EARLIEST),
						"EXPIRED for a value that is not authentic");

			return;
		}

		Assertions.fail("the internal path opened a value it must reject");
	}

	/**
	 * Requires an authentic value to have expired at {@code clock}: {@link UnsealException.Kind#EXPIRED}, which the
	 * internal path reports only after authentication.
	 */
	private static void requireExpired(String sealed, SealedStateType type, String context, Clock clock) {
		try {
			ACCESS.unseal(SEALER, type, sealed, context, clock);
		} catch (UnsealException e) {
			requireFixedShape(e);
			Assertions.assertEquals(UnsealException.Kind.EXPIRED, e.getKind(), "an authentic value was not EXPIRED");
			return;
		}

		Assertions.fail("a value opened at or after its notAfter");
	}

	private static void requirePublicFailure(String sealed, String context) {
		try {
			SEALER.unseal(sealed, context);
		} catch (InvalidSealedStateException e) {
			requireUniformFailure(e);
			return;
		}

		Assertions.fail("the public path opened a value it must reject");
	}

	private static void requireUniformFailure(InvalidSealedStateException exception) {
		Assertions.assertEquals(REFERENCE_FAILURE.getMessage(), exception.getMessage(), "not the fixed message");
		Assertions.assertNull(exception.getCause(), "the failure has a cause");
		Assertions.assertEquals(0, exception.getSuppressed().length, "the failure has suppressed exceptions");
		Assertions.assertEquals(ErrorCategory.VALIDATION_FAILURE, exception.getCategory(), "wrong category");
		Assertions.assertFalse(exception.isTransient(), "the failure is transient");
		Assertions.assertArrayEquals(sealerFrames(REFERENCE_FAILURE), sealerFrames(exception),
				"the failure's stack trace depends on which step failed");
	}

	private static void requireFixedShape(UnsealException exception) {
		Assertions.assertEquals(exception.getKind().getMessage(), exception.getMessage(), "not the Kind's message");
		Assertions.assertNull(exception.getCause(), "an UnsealException has a cause");
		Assertions.assertEquals(0, exception.getSuppressed().length, "an UnsealException has suppressed exceptions");
	}

	private static void requireSealFailure(IllegalArgumentException exception, String expectedMessage) {
		Assertions.assertNotNull(expectedMessage, () -> "seal rejected valid arguments: " + exception.getMessage());
		Assertions.assertEquals(expectedMessage, exception.getMessage(), "not the first failed check's message");
	}

	/**
	 * The message of the first check {@code seal} must fail, in its documented order, or {@code null}. A {@code null}
	 * lifetime means the internal path, which takes an expiry instead.
	 */
	private static String expectedSealFailure(String plaintext, String context, Duration lifetime) {
		if (context.isEmpty() || context.length() > 256 || !isWellFormed(context))
			return CONTEXT_MESSAGE;

		if (lifetime != null) {
			try {
				Limits.SEAL_LIFETIME.require(lifetime);
			} catch (IllegalArgumentException e) {
				return e.getMessage();
			}
		}

		// UTF-8 is never shorter than UTF-16, so seal refuses on the UTF-16 length before it encodes.
		if (sealedLength(plaintext.length()) > MAXIMUM_SEALED_LENGTH)
			return TOO_LONG_MESSAGE;

		if (!isWellFormed(plaintext))
			return ILL_FORMED_MESSAGE;

		if (expectedSealedLength(plaintext) > MAXIMUM_SEALED_LENGTH)
			return TOO_LONG_MESSAGE;

		return null;
	}

	private static long expectedSealedLength(String plaintext) {
		return sealedLength(plaintext.getBytes(StandardCharsets.UTF_8).length);
	}

	/**
	 * The v1 length, computed here from the format: 54 fixed bytes plus the key ID and the plaintext, in unpadded
	 * base64url.
	 */
	private static long sealedLength(long plaintextBytes) {
		long bytes = 54 + KEY_2026.getKeyId().length() + plaintextBytes;
		return bytes / 3 * 4 + (bytes % 3 == 0 ? 0 : bytes % 3 + 1);
	}

	/**
	 * A different valid context: one more character, or, at the 256-character limit, another first code point. Cutting
	 * a code unit off the front could leave an unpaired surrogate, which is an invalid context, not another one (found
	 * by this target).
	 */
	private static String otherContext(String context) {
		if (context.length() < 256)
			return context + "x";

		int first = context.codePointAt(0);
		return (first == 'x' ? "y" : "x") + context.substring(Character.charCount(first));
	}

	/**
	 * A different valid context with the same length in UTF-16 code units and in UTF-8 bytes: the first code point with
	 * its lowest bit flipped. The flip never crosses a boundary of the UTF-8 length classes (U+0080, U+0800, U+10000)
	 * or the surrogate range, which all start at even code points, and U+10FFFF becomes U+10FFFE.
	 */
	private static String sameLengthOtherContext(String context) {
		int first = context.codePointAt(0);
		return new StringBuilder(context.length()).appendCodePoint(first ^ 1)
				.append(context, Character.charCount(first), context.length()).toString();
	}

	private static boolean opens(StateSealer sealer, String sealed, SealedStateType type, String context, Clock clock) {
		try {
			ACCESS.unseal(sealer, type, sealed, context, clock);
			return true;
		} catch (UnsealException e) {
			requireFixedShape(e);
			Assertions.assertEquals(UnsealException.Kind.INVALID, e.getKind(), "a rotation failure was not INVALID");
			return false;
		}
	}

	/**
	 * The key ID in an authentic value's header: version byte, key ID length, key ID.
	 */
	private static String keyIdOf(String sealed) {
		byte[] bytes = Base64.getUrlDecoder().decode(sealed);
		return new String(bytes, 2, bytes[1] & 0xFF, StandardCharsets.US_ASCII);
	}

	private static Clock beforeNotAfter(long notAfter) {
		return Clock.fixed(Instant.ofEpochSecond(notAfter - 1, 999_999_999), ZoneOffset.UTC);
	}

	/**
	 * One fuzzed edit: replace, insert or delete a character, truncate, or append.
	 */
	private static String edited(String sealed, FuzzedDataProvider data) {
		int position = data.consumeInt(0, sealed.length() - 1);
		char character = data.consumeBoolean() ? data.consumeChar() : ALPHABET.charAt(data.consumeInt(0, 63));

		return switch (data.consumeInt(0, 4)) {
			case 0 -> sealed.substring(0, position) + character + sealed.substring(position + 1);
			case 1 -> sealed.substring(0, position) + character + sealed.substring(position);
			case 2 -> sealed.substring(0, position) + sealed.substring(position + 1);
			case 3 -> sealed.substring(0, position);
			default -> sealed + character;
		};
	}

	/**
	 * Up to {@code maximum} characters from {@link FuzzedDataProvider#consumeChar()}, which can be any UTF-16 code unit,
	 * unpaired surrogates included.
	 */
	private static String characters(FuzzedDataProvider data, int maximum) {
		char[] characters = new char[data.consumeInt(0, maximum)];

		for (int index = 0; index < characters.length; ++index)
			characters[index] = data.consumeChar();

		return new String(characters);
	}

	private static boolean isWellFormed(String value) {
		for (int index = 0; index < value.length(); ++index) {
			char character = value.charAt(index);

			if (Character.isHighSurrogate(character) && index + 1 < value.length()
					&& Character.isLowSurrogate(value.charAt(index + 1)))
				++index;
			else if (Character.isSurrogate(character))
				return false;
		}

		return true;
	}

	/**
	 * The frames from the top of the stack down to {@code StateSealer.unseal}, which the caller does not affect.
	 */
	private static StackTraceElement[] sealerFrames(Throwable throwable) {
		StackTraceElement[] frames = throwable.getStackTrace();

		for (int index = 0; index < frames.length; ++index)
			if (frames[index].getClassName().equals(StateSealer.class.getName())
					&& frames[index].getMethodName().equals("unseal"))
				return Arrays.copyOf(frames, index + 1);

		return frames;
	}

	private static InvalidSealedStateException referenceFailure() {
		try {
			SEALER.unseal("", CONTEXT);
		} catch (InvalidSealedStateException e) {
			return e;
		}

		throw new IllegalStateException("The empty string opened.");
	}

	private static String sealMessage(String plaintext, String context, Duration lifetime) {
		try {
			SEALER.seal(plaintext, context, lifetime);
		} catch (IllegalArgumentException e) {
			return e.getMessage();
		}

		throw new IllegalStateException("A known-bad seal succeeded.");
	}

	private static SealingKey fuzzOnlyKey(String keyId, int firstByte) {
		return SealingKey.fromBase64(keyId, Base64.getEncoder().encodeToString(fuzzOnlyKeyBytes(firstByte)));
	}

	private static byte[] fuzzOnlyKeyBytes(int firstByte) {
		byte[] key = new byte[32];

		for (int index = 0; index < key.length; ++index)
			key[index] = (byte) (firstByte + index);

		return key;
	}
}
