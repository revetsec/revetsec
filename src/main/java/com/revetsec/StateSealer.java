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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.Limits;
import com.revetsec.internal.crypto.ConstantTime;
import com.revetsec.internal.crypto.EntropySource;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.SealerV1;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/**
 * Seals short strings into opaque, URL- and cookie-safe values that only a holder of the same keys can open, and
 * only for the same context before they expire.
 * <p>
 * Revetsec uses sealed values to carry pending sign-in state through the browser, and applications can seal their
 * own data with {@link #seal(String, String, Duration)} and {@link #unseal(String, String)}. A sealed value is
 * encrypted and authenticated with AES-256-GCM under a key derived with HKDF-SHA256 from the sealing key and a fresh
 * random salt, so every value gets its own encryption key, and it is written in unpadded base64url. It carries, in
 * the clear, the ID of the key that sealed it; everything else is encrypted, authenticated or both. Values sealed
 * here are application data: Revetsec seals its own pending state under other type labels, bound into both the key
 * derivation and the authenticated data, so a value of one kind does not open as the other.
 * <p>
 * <strong>Context.</strong> Every value is bound to a context string, such as the name of the cookie that carries
 * it or the identity provider it concerns, and opens only for the same context. A context is 1 to 256 characters of
 * well-formed UTF-16 (no unpaired surrogate). It is not secret and is not stored in the value.
 * <p>
 * <strong>Lifetime.</strong> {@code seal} takes a lifetime from 1 second to 400 days. The value's expiry, which it
 * carries encrypted, is the current time from the builder's {@link Clock} rounded up to a whole second, plus the
 * lifetime rounded down to whole seconds. So a value opens for at least the lifetime's whole seconds and at most one
 * second more, and it stops opening at the first instant at or after its expiry.
 * <p>
 * <strong>Failures.</strong> Arguments are checked first: a {@code null} throws {@link NullPointerException}, and an
 * invalid context, plaintext or lifetime, or a plaintext too long to seal, throws {@link IllegalArgumentException}.
 * Every failure to open a value throws the one {@link InvalidSealedStateException}, with the same message, no cause
 * and nothing suppressed, whether the value was tampered with, truncated, malformed, too long, sealed for another
 * context, sealed under a key this sealer does not hold, or expired. Opening never tries more than one key: the key
 * ID in the value selects exactly one.
 * <p>
 * <strong>Keys and rotation.</strong> The {@linkplain Builder#build() built} sealer seals with its active key and
 * opens values sealed under its active key or any of its verification keys (at most 16). To rotate:
 * <ol>
 *   <li>add the new key as a verification key on every instance, so each can open values the new key seals;</li>
 *   <li>promote it: make it the active key and the old key a verification key;</li>
 *   <li>once every value sealed under the old key has expired, retire the old key.</li>
 * </ol>
 * Rotate at once if a key may have been disclosed: whoever holds a key can seal values that every sealer holding it
 * accepts. Use one key per application.
 * <p>
 * <strong>Size.</strong> A sealed value is {@code ceil(4 * (54 + k + p) / 3)} characters long for a key ID of
 * {@code k} characters and a plaintext of {@code p} UTF-8 bytes; a 700-byte plaintext under key ID {@code 2026-09}
 * seals to 1,015 characters. {@code seal} refuses, and {@code unseal} rejects before decoding, any value longer than
 * {@link Builder#maximumSealedLength(Integer)}: 3,800 characters by default, which leaves room for a cookie's name
 * and attributes within the 4,096 bytes per cookie that RFC 6265 section 6.1 asks browsers to support.
 * <p>
 * Instances are immutable and safe for concurrent use.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class StateSealer {
	/**
	 * The most verification keys a sealer holds besides its active key (G6-9).
	 */
	private static final int MAXIMUM_VERIFICATION_KEYS = 16;

	static {
		// G6-10: the protocol packages reach the internal type labels through this accessor, never through the public
		// API. SealedStateAccess.get() forces this initialization first.
		SealedStateAccess.set(new SealedStateOperations());
	}

	private final SealerV1.@NonNull Key activeKey;
	/**
	 * The active key and every verification key, by key ID.
	 */
	@NonNull
	private final Map<@NonNull String, SealerV1.@NonNull Key> keysByKeyId;
	@NonNull
	private final List<@NonNull String> verificationKeyIds;
	@NonNull
	private final Clock clock;
	private final int maximumSealedLength;
	@NonNull
	private final EntropySource entropySource;

	private StateSealer(SealerV1.@NonNull Key activeKey,
											@NonNull Map<@NonNull String, SealerV1.@NonNull Key> keysByKeyId,
											@NonNull List<@NonNull String> verificationKeyIds,
											@NonNull Clock clock,
											int maximumSealedLength,
											@NonNull EntropySource entropySource) {
		this.activeKey = activeKey;
		this.keysByKeyId = keysByKeyId;
		this.verificationKeyIds = verificationKeyIds;
		this.clock = clock;
		this.maximumSealedLength = maximumSealedLength;
		this.entropySource = entropySource;
	}

	/**
	 * Starts building a sealer that seals with {@code activeKey}.
	 *
	 * @param activeKey the key that seals new values; it also opens them
	 * @return a new builder
	 * @throws NullPointerException if {@code activeKey} is {@code null}
	 * @since 1.0.0
	 */
	@NonNull
	public static Builder withActiveKey(@NonNull SealingKey activeKey) {
		return new Builder(activeKey);
	}

	/**
	 * Seals {@code plaintext} for {@code context}, to open until {@code lifetime} from now.
	 * <p>
	 * Every call returns a different value, even for the same arguments, because each draws a fresh random salt and
	 * IV.
	 *
	 * @param plaintext the text to seal, well-formed UTF-16; it may be empty
	 * @param context   the context to bind: 1 to 256 characters of well-formed UTF-16
	 * @param lifetime  how long the value opens, from 1 second to 400 days; only whole seconds count
	 * @return the sealed value, in unpadded base64url
	 * @throws NullPointerException     if an argument is {@code null}
	 * @throws IllegalArgumentException if the context or lifetime is out of range, the plaintext or context contains an
	 *                                  unpaired surrogate, or the sealed value would be longer than
	 *                                  {@link Builder#maximumSealedLength(Integer)}
	 * @throws IllegalStateException    if the platform's cryptographic provider refuses to seal or cannot supply
	 *                                  random bytes
	 * @since 1.0.0
	 */
	@NonNull
	public String seal(@NonNull String plaintext,
										 @NonNull String context,
										 @NonNull Duration lifetime) {
		requireNonNull(plaintext);
		requireNonNull(context);
		requireNonNull(lifetime);
		SealerV1.requireContext(context);
		Limits.SEAL_LIFETIME.require(lifetime);

		// Neither sum can overflow: the largest Instant is about 3.2E16 seconds and the lifetime at most 400 days.
		long notAfter = ceilingEpochSecond(this.clock.instant()) + lifetime.toSeconds();
		return sealUntil(SealedStateType.APP, plaintext, context, notAfter);
	}

	/**
	 * Opens a value that {@link #seal(String, String, Duration)} sealed for {@code context} under one of this
	 * sealer's keys, if it has not expired.
	 *
	 * @param sealed  the sealed value, untrusted
	 * @param context the context it was sealed for: 1 to 256 characters of well-formed UTF-16
	 * @return the plaintext
	 * @throws NullPointerException         if an argument is {@code null}
	 * @throws IllegalArgumentException     if the context is out of range or contains an unpaired surrogate
	 * @throws InvalidSealedStateException  if the value does not open, for whatever reason
	 * @since 1.0.0
	 */
	@NonNull
	public String unseal(@NonNull String sealed,
											 @NonNull String context) {
		requireNonNull(sealed);
		requireNonNull(context);
		SealerV1.requireContext(context);

		Instant now = this.clock.instant();

		try {
			return SealerV1.open(sealed, this.maximumSealedLength, this.keysByKeyId, SealedStateType.APP, context, now);
		} catch (UnsealException e) {
			// Every failure, expiry included, is this one exception, thrown from this one place, so neither the type,
			// the message nor the stack trace says which step failed.
			throw InvalidSealedStateException.fromAnyFailure();
		}
	}

	/**
	 * Returns a description of this sealer's configuration, which names its key IDs but never renders a key.
	 *
	 * @return a description of this sealer without its secrets
	 * @since 1.0.0
	 */
	@Override
	@NonNull
	public String toString() {
		return getClass().getSimpleName() + "{activeKeyId=" + this.activeKey.getKeyId() + ", verificationKeyIds="
				+ this.verificationKeyIds + ", maximumSealedLength=" + this.maximumSealedLength + "}";
	}

	/**
	 * Seals under {@code type} with the active key. The context has been checked.
	 */
	@NonNull
	private String sealUntil(@NonNull SealedStateType type,
													 @NonNull String plaintext,
													 @NonNull String context,
													 long notAfter) {
		int keyIdLength = this.activeKey.getKeyId().length();

		// UTF-8 never has fewer bytes than UTF-16 has code units, so an oversized plaintext is refused before it is
		// encoded.
		if (SealerV1.sealedLength(keyIdLength, plaintext.length()) > this.maximumSealedLength)
			throw tooLong();

		byte[] plaintextBytes;

		try {
			plaintextBytes = StrictUtf8.encode(plaintext);
		} catch (EncodingException e) {
			throw new IllegalArgumentException("A plaintext must be well-formed UTF-16.");
		}

		try {
			// Checked outside sealWithProvider, so this IllegalArgumentException is never mistaken for a provider failure.
			if (SealerV1.sealedLength(keyIdLength, plaintextBytes.length) > this.maximumSealedLength)
				throw tooLong();

			return sealWithProvider(type, context, notAfter, plaintextBytes);
		} finally {
			Arrays.fill(plaintextBytes, (byte) 0);
		}
	}

	@NonNull
	private String sealWithProvider(@NonNull SealedStateType type,
																	@NonNull String context,
																	long notAfter,
																	byte @NonNull [] plaintextBytes) {
		try {
			// The salt and IV are drawn here, because the SecureRandom is a JCA provider too: a PKCS#11 or native one
			// can throw ProviderException at any draw.
			byte[] salt = this.entropySource.nextBytes(SealerV1.SALT_LENGTH);
			byte[] iv = this.entropySource.nextBytes(SealerV1.IV_LENGTH);

			return SealerV1.seal(this.activeKey, type, context, notAfter, plaintextBytes, salt, iv);
		} catch (GeneralSecurityException | RuntimeException e) {
			// Every argument has been checked, so only the provider or the SecureRandom can fail here.
			throw new IllegalStateException("The cryptographic provider refused to seal.", e);
		}
	}

	/**
	 * The first epoch second at or after {@code instant}.
	 */
	private static long ceilingEpochSecond(@NonNull Instant instant) {
		return instant.getNano() == 0 ? instant.getEpochSecond() : instant.getEpochSecond() + 1;
	}

	@NonNull
	private IllegalArgumentException tooLong() {
		return new IllegalArgumentException("The sealed value would be longer than the maximum sealed length of "
				+ this.maximumSealedLength + " characters.");
	}

	/**
	 * Builds a {@link StateSealer}.
	 * <p>
	 * {@link #build()} checks the keys together and runs a self-test: it seals and opens a fixed value with the active
	 * key, checks that an altered copy does not open and that the value does not open under another context, and
	 * checks that a fixed input seals to its known bytes.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		@NonNull
		private final SealingKey activeKey;
		@NonNull
		private List<@NonNull SealingKey> verificationKeys;
		@Nullable
		private Clock clock;
		@Nullable
		private Integer maximumSealedLength;

		private Builder(@NonNull SealingKey activeKey) {
			this.activeKey = requireNonNull(activeKey);
			this.verificationKeys = List.of();
		}

		/**
		 * Sets the keys that open values sealed earlier under other keys, such as the previous active key during a
		 * rotation. They never seal.
		 *
		 * @param verificationKeys at most 16 keys, each with its own key ID and its own key bytes, none of them the
		 *                         active key; {@code null} restores the default, none. The list is copied
		 * @return this builder
		 * @throws NullPointerException if the list contains {@code null}
		 * @since 1.0.0
		 */
		@NonNull
		public Builder verificationKeys(@Nullable List<@NonNull SealingKey> verificationKeys) {
			this.verificationKeys = verificationKeys == null ? List.of() : List.copyOf(verificationKeys);
			return this;
		}

		/**
		 * Sets the clock that supplies the current time for sealing and opening.
		 *
		 * @param clock the clock; {@code null} restores the default, {@link Clock#systemUTC()}
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder clock(@Nullable Clock clock) {
			this.clock = clock;
			return this;
		}

		/**
		 * Sets the longest sealed value, in characters, that {@code seal} returns and {@code unseal} decodes.
		 *
		 * @param maximumSealedLength from 1,024 to 16,384; {@code null} restores the default, 3,800. {@link #build()}
		 *                            checks the range
		 * @return this builder
		 * @since 1.0.0
		 */
		@NonNull
		public Builder maximumSealedLength(@Nullable Integer maximumSealedLength) {
			this.maximumSealedLength = maximumSealedLength;
			return this;
		}

		/**
		 * Builds the sealer.
		 *
		 * @return a new sealer
		 * @throws IllegalArgumentException if the maximum sealed length is out of range, there are more than 16
		 *                                  verification keys, or two keys share a key ID or key bytes
		 * @throws IllegalStateException    if the platform's cryptographic provider refuses HMAC-SHA256 or AES-GCM,
		 *                                  cannot supply random bytes, or fails the self-test
		 * @since 1.0.0
		 */
		@NonNull
		public StateSealer build() {
			int maximum = this.maximumSealedLength == null
					? Limits.STATE_SEALER_MAXIMUM_SEALED_LENGTH.getDefaultIntValue()
					: Limits.STATE_SEALER_MAXIMUM_SEALED_LENGTH.require(this.maximumSealedLength);

			if (this.verificationKeys.size() > MAXIMUM_VERIFICATION_KEYS)
				throw new IllegalArgumentException("A StateSealer holds at most " + MAXIMUM_VERIFICATION_KEYS
						+ " verification keys.");

			List<SealingKey> keys = new ArrayList<>(1 + this.verificationKeys.size());
			keys.add(this.activeKey);
			keys.addAll(this.verificationKeys);
			requireDistinct(keys);

			Map<String, SealerV1.Key> keysByKeyId = new LinkedHashMap<>();
			List<String> verificationKeyIds = new ArrayList<>(this.verificationKeys.size());
			EntropySource entropySource;
			SealerV1.Key derivedActiveKey;
			boolean passesSelfTest;

			try {
				// Inside the try: the platform's SecureRandom can fail to construct (a JVM-environment failure, section
				// 9.6), which must be the same IllegalStateException as a refusing cipher.
				entropySource = EntropySource.fromDefaults();
				derivedActiveKey = derive(this.activeKey);
				keysByKeyId.put(derivedActiveKey.getKeyId(), derivedActiveKey);

				for (SealingKey key : this.verificationKeys) {
					keysByKeyId.put(key.getKeyId(), derive(key));
					verificationKeyIds.add(key.getKeyId());
				}

				passesSelfTest = SealerV1.passesSelfTest(derivedActiveKey, entropySource.nextBytes(SealerV1.SALT_LENGTH),
						entropySource.nextBytes(SealerV1.IV_LENGTH));
			} catch (GeneralSecurityException | RuntimeException e) {
				throw new IllegalStateException("The cryptographic provider refused StateSealer's self-test.", e);
			}

			if (!passesSelfTest)
				throw new IllegalStateException("The cryptographic provider failed StateSealer's self-test.");

			return new StateSealer(derivedActiveKey, Map.copyOf(keysByKeyId), List.copyOf(verificationKeyIds),
					this.clock == null ? Clock.systemUTC() : this.clock, maximum, entropySource);
		}

		/**
		 * Rejects two keys with the same key ID or the same key bytes, both compared in constant time.
		 */
		private static void requireDistinct(@NonNull List<@NonNull SealingKey> keys) {
			for (int first = 0; first < keys.size(); ++first) {
				for (int second = first + 1; second < keys.size(); ++second) {
					if (ConstantTime.isEqual(keys.get(first).getKeyId(), keys.get(second).getKeyId()))
						throw new IllegalArgumentException("Every sealing key needs its own key ID.");
					if (keys.get(first).hasSameKeyBytes(keys.get(second)))
						throw new IllegalArgumentException("Every sealing key needs its own key bytes.");
				}
			}
		}

		private static SealerV1.@NonNull Key derive(@NonNull SealingKey key) throws GeneralSecurityException {
			byte[] keyBytes = key.copyKeyBytes();

			try {
				return SealerV1.Key.fromMasterKey(key.getKeyId(), keyBytes);
			} finally {
				Arrays.fill(keyBytes, (byte) 0);
			}
		}
	}

	/**
	 * The internal, label-aware sealing and opening that {@link SealedStateAccess} hands to the protocol packages.
	 */
	@ThreadSafe
	private static final class SealedStateOperations implements SealedStateAccess.Operations {
		@Override
		@NonNull
		public String seal(@NonNull StateSealer sealer,
											 @NonNull SealedStateType type,
											 @NonNull String plaintext,
											 @NonNull String context,
											 @NonNull Instant expiresAt) {
			requireNonNull(sealer);
			requireNonNull(type);
			requireNonNull(plaintext);
			requireNonNull(context);
			requireNonNull(expiresAt);
			SealerV1.requireContext(context);

			return sealer.sealUntil(type, plaintext, context, ceilingEpochSecond(expiresAt));
		}

		@Override
		@NonNull
		public String unseal(@NonNull StateSealer sealer,
												 @NonNull SealedStateType type,
												 @NonNull String sealed,
												 @NonNull String context,
												 @NonNull Clock clock) throws UnsealException {
			requireNonNull(sealer);
			requireNonNull(type);
			requireNonNull(sealed);
			requireNonNull(context);
			requireNonNull(clock);
			SealerV1.requireContext(context);

			return SealerV1.open(sealed, sealer.maximumSealedLength, sealer.keysByKeyId, type, context, clock.instant());
		}
	}
}
