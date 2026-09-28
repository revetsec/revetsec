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

package com.revetsec.json;

/**
 * Controls: constant-time-comparison covers only internal.crypto, StateSealer.java and SealingKey.java,
 * byte-comparison only internal.jose, ascii-case-fold only scim, internal.json and internal.jose, and
 * jca-provider-argument only internal.jose and internal.crypto, so nothing in the public JSON model's package is
 * reported.
 */
final class ScopeControlFixture {
	boolean controls(String name, String other, byte[] first, byte[] second) {
		boolean equal = name.equals(other) && name.contentEquals(other) && java.util.Arrays.equals(first, second);
		equal |= name.equalsIgnoreCase(other) || name.regionMatches(true, 0, other, 0, 2);
		equal |= name.toLowerCase(java.util.Locale.ROOT).equals(other) || Character.toUpperCase('k') == 'K';
		return equal || String.CASE_INSENSITIVE_ORDER.compare(name, other) == 0;
	}

	boolean m2Controls(byte[] first, byte[] second, java.nio.ByteBuffer buffer, java.security.Provider provider)
			throws java.security.GeneralSecurityException {
		boolean equal = java.util.Arrays.mismatch(first, second) < 0 && buffer.compareTo(buffer) == 0;
		equal &= java.security.MessageDigest.isEqual(first, second);
		java.security.Signature.getInstance("SHA256withRSA", "SunRsaSign");
		java.security.KeyFactory.getInstance("RSA", provider);
		return equal;
	}
}
