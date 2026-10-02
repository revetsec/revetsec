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

package com.revetsec.internal.encoding;

import org.jspecify.annotations.NonNull;

/**
 * An independent oracle for UTF-8 well-formedness, written from the Unicode Standard's Table 3-7 ("Well-Formed UTF-8
 * Byte Sequences", chapter 3.9) rather than from any JDK code, so the strict decoders can be checked against
 * something other than the decoder they wrap.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class Utf8Reference {
	private Utf8Reference() {
	}

	/**
	 * Whether {@code bytes} is a sequence of well-formed UTF-8 code unit sequences.
	 */
	static boolean isWellFormed(byte @NonNull [] bytes) {
		int index = 0;
		while (index < bytes.length) {
			int first = bytes[index] & 0xFF;
			int length;
			int secondLow = 0x80;
			int secondHigh = 0xBF;
			if (first <= 0x7F) {
				length = 1;
			} else if (first >= 0xC2 && first <= 0xDF) {
				length = 2;
			} else if (first == 0xE0) {
				length = 3;
				secondLow = 0xA0;
			} else if ((first >= 0xE1 && first <= 0xEC) || first == 0xEE || first == 0xEF) {
				length = 3;
			} else if (first == 0xED) {
				length = 3;
				secondHigh = 0x9F;
			} else if (first == 0xF0) {
				length = 4;
				secondLow = 0x90;
			} else if (first >= 0xF1 && first <= 0xF3) {
				length = 4;
			} else if (first == 0xF4) {
				length = 4;
				secondHigh = 0x8F;
			} else {
				return false;
			}
			if (index + length > bytes.length)
				return false;
			for (int offset = 1; offset < length; ++offset) {
				int next = bytes[index + offset] & 0xFF;
				int low = offset == 1 ? secondLow : 0x80;
				int high = offset == 1 ? secondHigh : 0xBF;
				if (next < low || next > high)
					return false;
			}
			index += length;
		}
		return true;
	}
}
