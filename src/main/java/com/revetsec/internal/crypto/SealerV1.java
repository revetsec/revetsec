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

import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * The StateSealer v1 wire format as pure functions: the salt and IV are arguments, so a known-answer test pins every
 * byte (M1 plan, "StateSealer v1"; G6-8).
 * <pre>
 * sealed = base64url-nopad( header || C || T )    header = 0x01 || kidLen(1) || kid || S(16) || IV(12)
 * PRK    = HMAC-SHA256(key = "revetsec/state-sealer/v1/extract", msg = masterKey)     (once per key)
 * K      = HKDF-Expand(PRK, "revetsec/state-sealer/v1/aes-256-gcm-key" || 0x00 || label || 0x00 || S, 32)
 * AAD    = "revetsec/state-sealer/v1/aad" || u32 len || header || u32 len || label || u32 len || UTF-8(context)
 * C || T = AES-256-GCM(K, IV, AAD, notAfter(int64 big-endian epoch seconds) || UTF-8(plaintext)),  |T| = 16
 * </pre>
 * {@code u32 len} is the length of the field that follows, as four big-endian bytes, and {@code label} is the
 * {@link SealedStateType}'s ASCII label. {@code PRK} is HKDF-Extract (RFC 5869) with the fixed string as the salt and
 * the master key as the input keying material, and {@code K} costs one HMAC. Every message gets its own AES key from
 * its random 16-byte salt {@code S}, so the number of messages one master key can seal is not limited by GCM's
 * random-IV bound. v1 has no key-commitment block; the version byte leaves room for one. The overhead is
 * {@value #FIXED_OVERHEAD} bytes plus the key ID, before base64url.
 * <p>
 * <strong>Opening</strong> ({@link #open(String, int, Map, SealedStateType, String, Instant)}) checks its arguments
 * first, which throws {@link NullPointerException} or {@link IllegalArgumentException} and never
 * {@link UnsealException}. Then it runs these steps in order, and every failure is the same
 * {@link UnsealException.Kind#INVALID}, except step 8:
 * <ol>
 *   <li>the length is at most the caller's maximum, before any decoding;</li>
 *   <li>the characters are in the base64url alphabet;</li>
 *   <li>decode, then confirm that the encoding is canonical (no padding, zero trailing bits);</li>
 *   <li>the minimum length, the version, the key ID's length and its characters. The minimum leaves room for a
 *   notAfter and a whole tag, so a ciphertext shorter than the tag never reaches JDK 17's provider, which would throw
 *   an unchecked {@code ProviderException};</li>
 *   <li>an exact lookup of the key ID, with no fallback to other keys (never trial decryption);</li>
 *   <li>the context, bound into the additional authenticated data;</li>
 *   <li>derive the message key and run GCM, which authenticates everything above; any
 *   {@link GeneralSecurityException} or {@link RuntimeException} from the JCA is a failure;</li>
 *   <li>notAfter: the value has expired ({@link UnsealException.Kind#EXPIRED}) when {@code now >= notAfter}. This is
 *   checked only after authentication;</li>
 *   <li>a strict UTF-8 decode of the plaintext.</li>
 * </ol>
 * Any other {@link RuntimeException} after the argument checks is also {@link UnsealException.Kind#INVALID}
 * (INV-G1).
 * <p>
 * Revetsec zeroes its own copies of derived keys and plaintext on every path before a method returns. The JCA's
 * copies (in {@code SecretKeySpec} and the {@code Cipher} and {@code Mac} key state) cannot be zeroed, and stay until
 * they are garbage-collected.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class SealerV1 {
	/**
	 * The version byte that starts every v1 value.
	 */
	public static final int VERSION = 0x01;

	/**
	 * The length of a master key, in bytes.
	 */
	public static final int MASTER_KEY_LENGTH = 32;

	/**
	 * The length of the per-message salt {@code S}, in bytes.
	 */
	public static final int SALT_LENGTH = 16;

	/**
	 * The length of the GCM IV, in bytes.
	 */
	public static final int IV_LENGTH = AesGcm.IV_LENGTH;

	/**
	 * The length of the encrypted notAfter, in bytes.
	 */
	public static final int NOT_AFTER_LENGTH = Long.BYTES;

	/**
	 * The longest key ID, in characters (the shortest is one).
	 */
	public static final int MAXIMUM_KEY_ID_LENGTH = 64;

	/**
	 * The longest context, in UTF-16 code units (the shortest is one).
	 */
	public static final int MAXIMUM_CONTEXT_LENGTH = 256;

	/**
	 * The bytes every sealed value has besides its key ID and plaintext: the version, the key ID's length, the salt,
	 * the IV, notAfter and the tag.
	 */
	public static final int FIXED_OVERHEAD = 2 + SALT_LENGTH + IV_LENGTH + NOT_AFTER_LENGTH + AesGcm.TAG_LENGTH;

	/**
	 * The HKDF-Extract salt, in ASCII.
	 */
	static final String EXTRACT_SALT = "revetsec/state-sealer/v1/extract";

	/**
	 * The start of the HKDF-Expand info, in ASCII.
	 */
	static final String KEY_INFO_PREFIX = "revetsec/state-sealer/v1/aes-256-gcm-key";

	/**
	 * The start of the additional authenticated data, in ASCII.
	 */
	static final String ADDITIONAL_DATA_PREFIX = "revetsec/state-sealer/v1/aad";

	private static final String SELF_TEST_CONTEXT = "revetsec/state-sealer/self-test";

	/**
	 * A context of the same length as {@link #SELF_TEST_CONTEXT} that differs only in its last character. The context
	 * is the last field of the additional authenticated data, so a provider that drops or truncates it opens the
	 * self-test value under this context too.
	 */
	private static final String SELF_TEST_OTHER_CONTEXT = "revetsec/state-sealer/self-tesu";
	private static final String SELF_TEST_PLAINTEXT = "Revetsec StateSealer v1 self-test";

	/**
	 * The known answer the self-test seals: SealerV1Tests' second KAT vector, which is the master key 0x20 to 0x3f
	 * under key ID {@code a}, the {@link SealedStateType#PENDING_AUTHORIZATION} label, context {@code c}, notAfter 1,
	 * an empty plaintext, and an all-zero salt and IV.
	 */
	static final String SELF_TEST_KNOWN_ANSWER = "AQFhAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGYKmIORZTyxzG-eiLU4k9_0JFjlFCvM7Q";
	private static final String SELF_TEST_KNOWN_ANSWER_KEY_ID = "a";
	private static final String SELF_TEST_KNOWN_ANSWER_CONTEXT = "c";
	private static final int SELF_TEST_KNOWN_ANSWER_FIRST_KEY_BYTE = 0x20;

	private SealerV1() {
		// Static functions only.
	}

	/**
	 * A master key after HKDF-Extract, with its key ID: what sealing and opening need.
	 * <p>
	 * It keeps the pseudorandom key to itself and never returns it, and its {@code equals} is reference identity.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public static final class Key {
		@NonNull
		private final String keyId;
		private final byte @NonNull [] keyIdBytes;
		private final byte @NonNull [] pseudorandomKey;

		private Key(@NonNull String keyId,
								byte @NonNull [] pseudorandomKey) {
			this.keyId = keyId;
			this.keyIdBytes = keyId.getBytes(StandardCharsets.US_ASCII);
			this.pseudorandomKey = pseudorandomKey;
		}

		/**
		 * Derives the pseudorandom key of {@code masterKey}.
		 *
		 * @param keyId     the key ID, as {@link #isKeyId(String)} requires
		 * @param masterKey the {@value #MASTER_KEY_LENGTH}-byte master key; not modified, and not kept
		 * @return a new key
		 * @throws IllegalArgumentException if the key ID or the master key's length is invalid
		 * @throws GeneralSecurityException if the JCA provider refuses HMAC-SHA256
		 */
		@NonNull
		public static Key fromMasterKey(@NonNull String keyId,
																		byte @NonNull [] masterKey) throws GeneralSecurityException {
			requireNonNull(keyId);
			requireNonNull(masterKey);

			if (!isKeyId(keyId))
				throw new IllegalArgumentException("A key ID must be 1 to " + MAXIMUM_KEY_ID_LENGTH + " characters of "
						+ "A-Z, a-z, 0-9, '.', '_', '~' and '-'.");
			if (masterKey.length != MASTER_KEY_LENGTH)
				throw new IllegalArgumentException("A master key must be " + MASTER_KEY_LENGTH + " bytes.");

			return new Key(keyId, Hkdf.extract(ascii(EXTRACT_SALT), masterKey));
		}

		/**
		 * Returns the key ID.
		 *
		 * @return the key ID
		 */
		@NonNull
		public String getKeyId() {
			return this.keyId;
		}

		/**
		 * Returns {@code Key{keyId=..., key=<redacted>}}; the key's bytes are never rendered.
		 *
		 * @return a description of this key without its secret
		 */
		@Override
		@NonNull
		public String toString() {
			return getClass().getSimpleName() + "{keyId=" + this.keyId + ", key=<redacted>}";
		}
	}

	/**
	 * Returns whether {@code keyId} is a valid key ID: 1 to {@value #MAXIMUM_KEY_ID_LENGTH} characters, each an ASCII
	 * letter or digit, {@code .}, {@code _}, {@code ~} or {@code -} (RFC 3986's unreserved set, safe in cookies and
	 * URLs).
	 *
	 * @param keyId the candidate key ID
	 * @return {@code true} if it is valid
	 */
	public static boolean isKeyId(@NonNull String keyId) {
		requireNonNull(keyId);

		int length = keyId.length();

		if (length < 1 || length > MAXIMUM_KEY_ID_LENGTH)
			return false;

		for (int index = 0; index < length; ++index)
			if (!isKeyIdCharacter(keyId.charAt(index)))
				return false;

		return true;
	}

	/**
	 * Checks a context: 1 to {@value #MAXIMUM_CONTEXT_LENGTH} UTF-16 code units of well-formed UTF-16, with no
	 * unpaired surrogate.
	 *
	 * @param context the context
	 * @throws NullPointerException     if {@code context} is {@code null}
	 * @throws IllegalArgumentException if {@code context} is not valid
	 */
	public static void requireContext(@NonNull String context) {
		contextBytes(context);
	}

	/**
	 * Returns the length, in characters, of every value {@link #seal} returns for a key ID and plaintext of these
	 * lengths.
	 *
	 * @param keyIdLength     the key ID's length, 1 to {@value #MAXIMUM_KEY_ID_LENGTH}
	 * @param plaintextLength the plaintext's length in UTF-8 bytes, zero or more
	 * @return the sealed value's length
	 * @throws IllegalArgumentException if either length is out of range
	 */
	public static long sealedLength(int keyIdLength,
																	int plaintextLength) {
		if (keyIdLength < 1 || keyIdLength > MAXIMUM_KEY_ID_LENGTH)
			throw new IllegalArgumentException("A key ID must be 1 to " + MAXIMUM_KEY_ID_LENGTH + " characters.");
		if (plaintextLength < 0)
			throw new IllegalArgumentException("A plaintext length must not be negative.");

		long bytes = (long) FIXED_OVERHEAD + keyIdLength + plaintextLength;
		// Unpadded base64url: four characters per three bytes, rounded up.
		return (bytes * 4 + 2) / 3;
	}

	/**
	 * Seals a plaintext.
	 *
	 * @param key       the sealing key
	 * @param type      the type label to bind
	 * @param context   the context to bind, as {@link #requireContext(String)} requires
	 * @param notAfter  the first epoch second at which the value no longer opens
	 * @param plaintext the plaintext's UTF-8 bytes; not modified
	 * @param salt      the {@value #SALT_LENGTH}-byte random salt, never reused; not modified
	 * @param iv        the {@value #IV_LENGTH}-byte random IV; not modified
	 * @return the sealed value, in unpadded base64url
	 * @throws IllegalArgumentException if the context, salt or IV is invalid
	 * @throws GeneralSecurityException if the JCA provider refuses HMAC-SHA256 or AES-GCM
	 */
	@NonNull
	public static String seal(@NonNull Key key,
														@NonNull SealedStateType type,
														@NonNull String context,
														long notAfter,
														byte @NonNull [] plaintext,
														byte @NonNull [] salt,
														byte @NonNull [] iv) throws GeneralSecurityException {
		return Base64Url.encode(sealToBytes(key, type, context, notAfter, plaintext, salt, iv));
	}

	/**
	 * Opens a sealed value, in the order the class description gives.
	 *
	 * @param sealed              the sealed value, untrusted
	 * @param maximumSealedLength the longest value to decode, in characters, at least 1
	 * @param keys                the keys that may open it, by key ID
	 * @param type                the type label the value must have been sealed under
	 * @param context             the context it must have been sealed for, as {@link #requireContext(String)}
	 *                            requires
	 * @param now                 the current time
	 * @return the plaintext
	 * @throws IllegalArgumentException if the context or the maximum length is invalid
	 * @throws UnsealException          with {@link UnsealException.Kind#EXPIRED} if the value is authentic but has
	 *                                  expired, and with {@link UnsealException.Kind#INVALID} for every other failure
	 */
	@NonNull
	public static String open(@NonNull String sealed,
														int maximumSealedLength,
														@NonNull Map<@NonNull String, @NonNull Key> keys,
														@NonNull SealedStateType type,
														@NonNull String context,
														@NonNull Instant now) throws UnsealException {
		requireNonNull(sealed);
		requireNonNull(keys);
		requireNonNull(type);
		requireNonNull(now);

		byte[] contextBytes = contextBytes(context);

		if (maximumSealedLength < 1)
			throw new IllegalArgumentException("A maximum sealed length must be positive.");

		try {
			return openChecked(sealed, maximumSealedLength, keys, type, contextBytes, now);
		} catch (RuntimeException e) {
			// INV-G1: whatever else goes wrong on untrusted input is one more failure of the same kind.
			throw invalid();
		}
	}

	/**
	 * Checks that the JCA provider seals and opens correctly before {@code key} is used, so a provider that refuses or
	 * misbehaves in any of these ways is found:
	 * <ul>
	 *   <li>a fixed plaintext sealed under {@code key} with the given salt and IV opens again to the same
	 *   plaintext;</li>
	 *   <li>the same value with one tag bit flipped does not open;</li>
	 *   <li>the same value does not open under another context of the same length, so a provider that drops or
	 *   truncates the additional authenticated data is found;</li>
	 *   <li>a fixed input seals to its known bytes ({@link #SELF_TEST_KNOWN_ANSWER}), which also finds an altered
	 *   additional authenticated data, an ignored IV and a wrong tag length.</li>
	 * </ul>
	 *
	 * @param key  the key to test
	 * @param salt the {@value #SALT_LENGTH}-byte random salt; not modified
	 * @param iv   the {@value #IV_LENGTH}-byte random IV; not modified
	 * @return {@code true} if every check passed
	 * @throws IllegalArgumentException if the salt or IV has the wrong length
	 * @throws GeneralSecurityException if the JCA provider refuses HMAC-SHA256 or AES-GCM
	 */
	public static boolean passesSelfTest(@NonNull Key key,
																			 byte @NonNull [] salt,
																			 byte @NonNull [] iv) throws GeneralSecurityException {
		byte[] bytes = sealToBytes(key, SealedStateType.APP, SELF_TEST_CONTEXT, Long.MAX_VALUE,
				ascii(SELF_TEST_PLAINTEXT), salt, iv);
		String sealed = Base64Url.encode(bytes);
		bytes[bytes.length - 1] = (byte) (bytes[bytes.length - 1] ^ 0x01);
		String altered = Base64Url.encode(bytes);
		Map<String, Key> keys = Map.of(key.keyId, key);
		boolean opens;

		try {
			opens = ConstantTime.isEqual(SELF_TEST_PLAINTEXT,
					open(sealed, Integer.MAX_VALUE, keys, SealedStateType.APP, SELF_TEST_CONTEXT, Instant.EPOCH));
		} catch (UnsealException e) {
			opens = false;
		}

		boolean rejectsAltered = isRejected(altered, keys, SELF_TEST_CONTEXT);
		boolean rejectsOtherContext = isRejected(sealed, keys, SELF_TEST_OTHER_CONTEXT);
		boolean matchesKnownAnswer = ConstantTime.isEqual(SELF_TEST_KNOWN_ANSWER, sealKnownAnswer());

		// Every check has run; any one that failed fails the self-test.
		return Boolean.logicalAnd(Boolean.logicalAnd(opens, rejectsAltered),
				Boolean.logicalAnd(rejectsOtherContext, matchesKnownAnswer));
	}

	/**
	 * Whether the self-test's {@code sealed} value fails to open under {@code context} as
	 * {@link UnsealException.Kind#INVALID}. It never expires, so any other outcome means the provider misbehaved.
	 */
	private static boolean isRejected(@NonNull String sealed,
																		@NonNull Map<@NonNull String, @NonNull Key> keys,
																		@NonNull String context) {
		try {
			open(sealed, Integer.MAX_VALUE, keys, SealedStateType.APP, context, Instant.EPOCH);
			return false;
		} catch (UnsealException e) {
			return e.getKind() == UnsealException.Kind.INVALID;
		}
	}

	/**
	 * Seals the known-answer input that {@link #SELF_TEST_KNOWN_ANSWER} documents.
	 */
	@NonNull
	private static String sealKnownAnswer() throws GeneralSecurityException {
		byte[] masterKey = new byte[MASTER_KEY_LENGTH];

		for (int index = 0; index < masterKey.length; ++index)
			masterKey[index] = (byte) (SELF_TEST_KNOWN_ANSWER_FIRST_KEY_BYTE + index);

		Key key = Key.fromMasterKey(SELF_TEST_KNOWN_ANSWER_KEY_ID, masterKey);

		return seal(key, SealedStateType.PENDING_AUTHORIZATION, SELF_TEST_KNOWN_ANSWER_CONTEXT, 1L, new byte[0],
				new byte[SALT_LENGTH], new byte[IV_LENGTH]);
	}

	/**
	 * {@link #seal} before base64url: {@code header || C || T}.
	 */
	private static byte @NonNull [] sealToBytes(@NonNull Key key,
																							@NonNull SealedStateType type,
																							@NonNull String context,
																							long notAfter,
																							byte @NonNull [] plaintext,
																							byte @NonNull [] salt,
																							byte @NonNull [] iv) throws GeneralSecurityException {
		requireNonNull(key);
		requireNonNull(type);
		requireNonNull(plaintext);
		requireNonNull(salt);
		requireNonNull(iv);

		byte[] contextBytes = contextBytes(context);

		if (salt.length != SALT_LENGTH)
			throw new IllegalArgumentException("A salt must be " + SALT_LENGTH + " bytes.");
		if (iv.length != IV_LENGTH)
			throw new IllegalArgumentException("An IV must be " + IV_LENGTH + " bytes.");

		byte[] header = ByteBuffer.allocate(2 + key.keyIdBytes.length + SALT_LENGTH + IV_LENGTH)
				.put((byte) VERSION)
				.put((byte) key.keyIdBytes.length)
				.put(key.keyIdBytes)
				.put(salt)
				.put(iv)
				.array();
		byte[] additionalData = additionalData(header, type, contextBytes);
		byte[] body = ByteBuffer.allocate(NOT_AFTER_LENGTH + plaintext.length).putLong(notAfter).put(plaintext).array();
		byte[] messageKey = new byte[0];

		// The key is derived inside the try, so a provider failure there still zeroes the plaintext copy in body.
		try {
			messageKey = messageKey(key, type, salt);
			byte[] ciphertextAndTag = AesGcm.encrypt(messageKey, iv, additionalData, body);
			return ByteBuffer.allocate(header.length + ciphertextAndTag.length)
					.put(header)
					.put(ciphertextAndTag)
					.array();
		} finally {
			Arrays.fill(messageKey, (byte) 0);
			Arrays.fill(body, (byte) 0);
		}
	}

	@NonNull
	private static String openChecked(@NonNull String sealed,
																		int maximumSealedLength,
																		@NonNull Map<@NonNull String, @NonNull Key> keys,
																		@NonNull SealedStateType type,
																		byte @NonNull [] contextBytes,
																		@NonNull Instant now) throws UnsealException {
		// 1. The length, before any decoding.
		if (sealed.length() > maximumSealedLength)
			throw invalid();

		// 2 and 3. The alphabet, then decode and confirm the canonical form.
		byte[] bytes;

		try {
			bytes = Base64Url.decode(sealed);
		} catch (EncodingException e) {
			throw invalid();
		}

		// 4. The minimum length, the version, the key ID's length and characters. The length comes first, so a
		// ciphertext shorter than the tag never reaches the provider (JDK 17 note).
		if (bytes.length < FIXED_OVERHEAD + 1 || (bytes[0] & 0xFF) != VERSION)
			throw invalid();

		int keyIdLength = bytes[1] & 0xFF;

		if (keyIdLength < 1 || keyIdLength > MAXIMUM_KEY_ID_LENGTH || bytes.length < FIXED_OVERHEAD + keyIdLength)
			throw invalid();

		for (int index = 2; index < 2 + keyIdLength; ++index)
			if (!isKeyIdCharacter((char) (bytes[index] & 0xFF)))
				throw invalid();

		// 5. An exact lookup of the key ID, with no fallback to any other key.
		@Nullable Key key = keys.get(new String(bytes, 2, keyIdLength, StandardCharsets.US_ASCII));

		if (key == null)
			throw invalid();

		// 6. The context, bound into the additional authenticated data with the header and the type label.
		int saltOffset = 2 + keyIdLength;
		int ivOffset = saltOffset + SALT_LENGTH;
		int headerLength = ivOffset + IV_LENGTH;
		byte[] additionalData = additionalData(Arrays.copyOfRange(bytes, 0, headerLength), type, contextBytes);

		// 7. Derive the message key and run GCM, which authenticates everything above.
		byte[] salt = Arrays.copyOfRange(bytes, saltOffset, ivOffset);
		byte[] iv = Arrays.copyOfRange(bytes, ivOffset, headerLength);
		byte[] ciphertextAndTag = Arrays.copyOfRange(bytes, headerLength, bytes.length);
		byte[] messageKey = new byte[0];
		byte[] body;

		try {
			messageKey = messageKey(key, type, salt);
			body = AesGcm.decrypt(messageKey, iv, additionalData, ciphertextAndTag);
		} catch (GeneralSecurityException | RuntimeException e) {
			throw invalid();
		} finally {
			Arrays.fill(messageKey, (byte) 0);
		}

		try {
			// 8. notAfter, only now that the value is known to be authentic. Step 4's minimum length guarantees the
			// body holds one.
			long notAfter = ByteBuffer.wrap(body, 0, NOT_AFTER_LENGTH).getLong();

			if (now.getEpochSecond() >= notAfter)
				throw new UnsealException(UnsealException.Kind.EXPIRED);

			// 9. A strict UTF-8 decode.
			try {
				return StrictUtf8.decode(body, NOT_AFTER_LENGTH, body.length - NOT_AFTER_LENGTH);
			} catch (EncodingException e) {
				throw invalid();
			}
		} finally {
			Arrays.fill(body, (byte) 0);
		}
	}

	/**
	 * The message key {@code K} for one value.
	 */
	static byte @NonNull [] messageKey(@NonNull Key key,
																		 @NonNull SealedStateType type,
																		 byte @NonNull [] salt) throws GeneralSecurityException {
		byte[] prefix = ascii(KEY_INFO_PREFIX);
		byte[] label = type.getLabelBytes();
		byte[] info = ByteBuffer.allocate(prefix.length + 1 + label.length + 1 + salt.length)
				.put(prefix)
				.put((byte) 0)
				.put(label)
				.put((byte) 0)
				.put(salt)
				.array();

		return Hkdf.expand(key.pseudorandomKey, info, AesGcm.KEY_LENGTH);
	}

	/**
	 * The additional authenticated data for one value.
	 */
	static byte @NonNull [] additionalData(byte @NonNull [] header,
																				 @NonNull SealedStateType type,
																				 byte @NonNull [] contextBytes) {
		byte[] prefix = ascii(ADDITIONAL_DATA_PREFIX);
		byte[] label = type.getLabelBytes();

		return ByteBuffer.allocate(prefix.length + Integer.BYTES + header.length + Integer.BYTES + label.length
						+ Integer.BYTES + contextBytes.length)
				.put(prefix)
				.putInt(header.length)
				.put(header)
				.putInt(label.length)
				.put(label)
				.putInt(contextBytes.length)
				.put(contextBytes)
				.array();
	}

	/**
	 * Whether {@code character} may appear in a key ID.
	 */
	static boolean isKeyIdCharacter(char character) {
		return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')
				|| (character >= '0' && character <= '9') || character == '.' || character == '_' || character == '~'
				|| character == '-';
	}

	/**
	 * The UTF-8 bytes of a valid context.
	 *
	 * @throws IllegalArgumentException if the context is empty, too long or not well-formed UTF-16
	 */
	private static byte @NonNull [] contextBytes(@NonNull String context) {
		requireNonNull(context);

		if (context.isEmpty() || context.length() > MAXIMUM_CONTEXT_LENGTH)
			throw invalidContext();

		try {
			return StrictUtf8.encode(context);
		} catch (EncodingException e) {
			throw invalidContext();
		}
	}

	@NonNull
	private static IllegalArgumentException invalidContext() {
		return new IllegalArgumentException("A context must be 1 to " + MAXIMUM_CONTEXT_LENGTH + " characters of "
				+ "well-formed UTF-16.");
	}

	private static byte @NonNull [] ascii(@NonNull String value) {
		return value.getBytes(StandardCharsets.US_ASCII);
	}

	@NonNull
	private static UnsealException invalid() {
		return new UnsealException(UnsealException.Kind.INVALID);
	}
}
