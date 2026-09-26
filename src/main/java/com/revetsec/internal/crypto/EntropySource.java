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

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.security.SecureRandom;

/**
 * The one source of randomness for a Revetsec object (plan R6).
 * <p>
 * Each owner, such as a {@code StateSealer}, creates its own instance, and each instance holds its own
 * {@link SecureRandom} from the platform's default constructor. It never uses {@link SecureRandom#getInstanceStrong()},
 * whose algorithm may block waiting for entropy (on Linux it can read {@code /dev/random}), so no Revetsec call can
 * hang on the kernel. The seam is internal, so tests assert the format and uniqueness of random values, never the
 * values themselves.
 * <p>
 * {@link SecureRandom} is safe for concurrent use, so one instance serves every thread of its owner.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class EntropySource {
	@NonNull
	private final SecureRandom secureRandom;

	private EntropySource(@NonNull SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}

	/**
	 * Returns a new source backed by a new {@link SecureRandom} from the platform's default constructor.
	 *
	 * @return a new source, for one owner only
	 */
	@NonNull
	public static EntropySource fromDefaults() {
		return new EntropySource(new SecureRandom());
	}

	/**
	 * Returns fresh random bytes.
	 *
	 * @param length how many bytes to return, zero or more
	 * @return a new array of {@code length} random bytes
	 * @throws IllegalArgumentException if {@code length} is negative
	 */
	public byte @NonNull [] nextBytes(int length) {
		if (length < 0)
			throw new IllegalArgumentException("A random byte count must not be negative.");

		byte[] bytes = new byte[length];
		this.secureRandom.nextBytes(bytes);
		return bytes;
	}
}
