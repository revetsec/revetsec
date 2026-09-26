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
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Comparisons whose running time does not depend on where two values first differ (plan R10).
 * <p>
 * {@code String.equals} and {@code Arrays.equals} return at the first difference, so their timing tells an attacker
 * how much of a guessed secret was right. Revetsec compares state, nonces, MACs, tags, key material and the other
 * values it must keep secret through this class instead, and the {@code constant-time-comparison} source rule bans
 * the early-exit comparisons in {@code internal.crypto}, {@code StateSealer} and {@code SealingKey}.
 * <p>
 * Both methods delegate to {@link MessageDigest#isEqual(byte[], byte[])}, whose running time depends only on the
 * lengths of its arguments, so the length of a value is not hidden, only its content. Both are null-guarded: a
 * {@code null} is never equal to anything, not even another {@code null}, so a missing value can never match a
 * missing value.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class ConstantTime {
	private ConstantTime() {
		// Static helpers only.
	}

	/**
	 * Returns whether two byte arrays hold the same bytes, in time that depends only on their lengths.
	 *
	 * @param first  the first value, or {@code null}; not modified
	 * @param second the second value, or {@code null}; not modified
	 * @return {@code true} if neither is {@code null} and both hold the same bytes; {@code false} otherwise, including
	 * when both are {@code null}
	 */
	public static boolean isEqual(byte @Nullable [] first,
																byte @Nullable [] second) {
		if (first == null || second == null)
			return false;

		return MessageDigest.isEqual(first, second);
	}

	/**
	 * Returns whether two strings hold the same UTF-16 code units, in time that depends only on their lengths.
	 * <p>
	 * The strings are compared as UTF-16 code units, not as encoded text, so an unpaired surrogate is compared like any
	 * other code unit and never makes two different strings equal.
	 *
	 * @param first  the first value, or {@code null}
	 * @param second the second value, or {@code null}
	 * @return {@code true} if neither is {@code null} and both hold the same code units; {@code false} otherwise,
	 * including when both are {@code null}
	 */
	public static boolean isEqual(@Nullable String first,
																@Nullable String second) {
		if (first == null || second == null)
			return false;

		byte[] firstUnits = codeUnits(first);
		byte[] secondUnits = codeUnits(second);

		try {
			return MessageDigest.isEqual(firstUnits, secondUnits);
		} finally {
			Arrays.fill(firstUnits, (byte) 0);
			Arrays.fill(secondUnits, (byte) 0);
		}
	}

	/**
	 * The UTF-16BE code units of {@code value}, two bytes per {@code char}, with no validation or replacement.
	 */
	private static byte @NonNull [] codeUnits(@NonNull String value) {
		int length = value.length();
		// Only a string of about a billion characters overflows; fail rather than wrap.
		byte[] units = new byte[Math.multiplyExact(length, 2)];

		for (int index = 0; index < length; ++index) {
			char unit = value.charAt(index);
			units[index * 2] = (byte) (unit >>> 8);
			units[index * 2 + 1] = (byte) unit;
		}

		return units;
	}
}
