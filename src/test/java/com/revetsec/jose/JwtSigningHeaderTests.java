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

package com.revetsec.jose;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class JwtSigningHeaderTests {
	@Test
	void typesHaveTheSupportedExactWireValues() {
		assertEquals("JWT", JwtType.JWT.getWireValue());
		assertEquals("at+jwt", JwtType.ACCESS_TOKEN.getWireValue());
		assertEquals("client-authentication+jwt", JwtType.CLIENT_AUTHENTICATION.getWireValue());
	}

	@SuppressWarnings("NullAway") // Deliberately verifies rejection of null required inputs.
	@Test
	void typeIsRequiredAndOptionalMetadataDefaultsToAbsent() {
		assertThrows(NullPointerException.class, () -> JwtSigningHeader.withType(null));
		assertThrows(NullPointerException.class, () -> JwtSigningHeader.fromType(null));
		for (JwtType type : JwtType.values()) {
			JwtSigningHeader header = JwtSigningHeader.fromType(type);
			assertSame(type, header.getType());
			assertTrue(header.getKeyId().isEmpty());
			assertTrue(header.getCertificateSha256Thumbprint().isEmpty());
		}
	}

	@Test
	void keyIdentifierUsesExistingLengthAndUnicodeBounds() {
		for (String invalid : List.of("", "x".repeat(257), "\ud800", "\udc00", "x\ud800y"))
			assertThrows(IllegalArgumentException.class, () -> JwtSigningHeader.withType(JwtType.JWT).keyId(invalid));
		for (String valid : List.of("key-1", "x".repeat(256), "\"é😀", "😀".repeat(128), "\u0000"))
			assertEquals(valid, JwtSigningHeader.withType(JwtType.JWT).keyId(valid).build().getKeyId().orElseThrow());
	}

	@Test
	void optionalMetadataCanBeReplacedAndClearedWithoutChangingEarlierSnapshots() {
		byte[] firstDigest = new byte[32];
		firstDigest[0] = 7;
		JwtSigningHeader.Builder builder = JwtSigningHeader.withType(JwtType.ACCESS_TOKEN)
				.keyId("first").certificateSha256Thumbprint(firstDigest);
		JwtSigningHeader first = builder.build();
		byte[] replacementDigest = new byte[32];
		replacementDigest[0] = 11;
		JwtSigningHeader second = builder.keyId("second").certificateSha256Thumbprint(replacementDigest).build();
		JwtSigningHeader cleared = builder.keyId(null).certificateSha256Thumbprint(null).build();
		assertEquals("first", first.getKeyId().orElseThrow());
		assertArrayEquals(firstDigest, first.getCertificateSha256Thumbprint().orElseThrow());
		assertEquals("second", second.getKeyId().orElseThrow());
		assertArrayEquals(replacementDigest, second.getCertificateSha256Thumbprint().orElseThrow());
		assertTrue(cleared.getKeyId().isEmpty());
		assertTrue(cleared.getCertificateSha256Thumbprint().isEmpty());
		assertSame(JwtType.ACCESS_TOKEN, cleared.getType());
	}

	@Test
	void certificateDigestIsLengthCheckedAndCopiedAtEveryBoundary() {
		for (int length : List.of(0, 31, 33))
			assertThrows(IllegalArgumentException.class, () -> JwtSigningHeader.withType(JwtType.JWT)
					.certificateSha256Thumbprint(new byte[length]));
		byte[] digest = new byte[32];
		digest[0] = 7;
		JwtSigningHeader.Builder builder = JwtSigningHeader.withType(JwtType.JWT).certificateSha256Thumbprint(digest);
		digest[0] = 9;
		JwtSigningHeader first = builder.build();
		assertEquals(7, first.getCertificateSha256Thumbprint().orElseThrow()[0]);
		byte[] returned = first.getCertificateSha256Thumbprint().orElseThrow();
		returned[0] = 11;
		assertEquals(7, first.getCertificateSha256Thumbprint().orElseThrow()[0]);
		assertEquals(7, builder.build().getCertificateSha256Thumbprint().orElseThrow()[0]);
	}

	@Test
	void stringRenderingRedactsIdentifiersAndDigests() {
		JwtSigningHeader.Builder builder = JwtSigningHeader.withType(JwtType.JWT)
				.keyId("TEST-ONLY-secret-header-identifier").certificateSha256Thumbprint(new byte[32]);
		for (Object value : List.of(builder, builder.build())) {
			assertTrue(value.toString().contains("<redacted>"));
			assertFalse(value.toString().contains("TEST-ONLY-secret-header-identifier"));
			assertFalse(value.toString().contains("AAAAAAAA"));
		}
	}
}
