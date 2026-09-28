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

package com.revetsec.internal.jose;

/**
 * Seeded violations: early-exit byte comparisons in internal.jose (byte-comparison, R10, M2-10), through Arrays (the
 * range overload and a method reference included), ByteBuffer and a MappedByteBuffer that inherits from it, and
 * Objects.deepEquals, and MessageDigest.isEqual called directly instead of through ConstantTime. In controls(), String
 * equality on public values, which constant-time-comparison would report in internal.crypto, and the Arrays and
 * ByteBuffer methods that compare nothing, are not reported.
 */
final class ByteComparisonFixture {
	boolean seeded(byte[] first, byte[] second, byte[][] firstGroup, byte[][] secondGroup, java.nio.ByteBuffer buffer,
			java.nio.ByteBuffer other, java.nio.MappedByteBuffer mapped) {
		boolean equal = java.util.Arrays.equals(first, second);
		equal &= java.util.Arrays.equals(first, 0, 16, second, 0, 16);
		equal &= java.util.Arrays.deepEquals(firstGroup, secondGroup);
		equal &= java.util.Arrays.mismatch(first, second) < 0;
		equal &= java.util.Arrays.compare(first, second) == 0;
		equal &= java.util.Arrays.compareUnsigned(first, second) == 0;
		equal &= buffer.equals(other);
		equal &= buffer.compareTo(other) == 0;
		equal &= buffer.mismatch(other) < 0;
		equal &= mapped.equals(other);
		equal &= java.util.Objects.deepEquals(first, second);
		equal &= java.security.MessageDigest.isEqual(first, second);
		java.util.function.BiPredicate<byte[], byte[]> comparison = java.util.Arrays::equals;
		return equal && comparison.test(first, second);
	}

	boolean controls(String algorithm, String keyId, byte[] value) {
		boolean equal = algorithm.equals("RS256") && keyId.contentEquals("key-1");
		equal &= java.util.Arrays.hashCode(value) != 0 && java.util.Arrays.copyOf(value, 2).length == 2;
		return equal && java.nio.ByteBuffer.wrap(value).remaining() == value.length;
	}
}
