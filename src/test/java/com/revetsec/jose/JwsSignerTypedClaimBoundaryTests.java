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

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNull;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonValue;
import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Pins typed scalar preservation and the expanded claims byte boundary at credential emission. */
final class JwsSignerTypedClaimBoundaryTests {

	@Test
	void typedScalarClaimsPreserveFalseAndExplicitNullInTheActualSignedPayload() throws Exception {
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.claim("enabled", true)
				.claim("disabled", false)
				.claim("nothing", JsonNull.defaultInstance())
				.claim("amount", new BigDecimal("123.50"))
				.claim("nested", JsonArray.fromElements(List.of(JsonObject.builder().build(),
						JsonArray.fromElements(List.of()), JsonBoolean.trueInstance(),
						JsonBoolean.falseInstance(), JsonNull.defaultInstance())))
				.build();
		String expected = "{\"enabled\":true,\"disabled\":false,\"nothing\":null,\"amount\":123.50,"
				+ "\"nested\":[{},[],true,false,null]}";
		String compact = signer().fromHeaderAndClaims(JwtSigningHeader.fromType(JwtType.JWT), claims);
		assertArrayEquals(expected.getBytes(StandardCharsets.UTF_8), verifiedPayload(compact));
	}

	@Test
	void booleanAndNullValuesRespectTheExactSerializedClaimsBoundary() throws Exception {
		JwsSigner signer = signer();
		JwtSigningHeader header = JwtSigningHeader.fromType(JwtType.JWT);
		for (JsonValue scalar : List.of(JsonBoolean.trueInstance(), JsonBoolean.falseInstance(),
				JsonNull.defaultInstance())) {
			String prefix = "{\"value\":" + scalar.toJson() + ",\"padding\":\"";
			String suffix = "\"}";
			int paddingLength = 32768 - prefix.length() - suffix.length();
			String padding = "a".repeat(paddingLength);
			JwtClaimsSet atLimit = JwtClaimsSet.builder().claim("value", scalar).claim("padding", padding).build();
			byte[] payload = verifiedPayload(signer.fromHeaderAndClaims(header, atLimit));
			assertEquals(32768, payload.length);
			assertArrayEquals((prefix + padding + suffix).getBytes(StandardCharsets.UTF_8), payload);

			JwtClaimsSet tooLarge = JwtClaimsSet.builder().claim("value", scalar)
					.claim("padding", padding + "a").build();
			assertThrows(IllegalArgumentException.class, () -> signer.fromHeaderAndClaims(header, tooLarge));
		}
	}

	@Test
	void anIndividuallyOversizedTypedStringCannotEmitACredential() {
		JwtClaimsSet claims = JwtClaimsSet.builder().claim("padding", "a".repeat(32769)).build();
		JwsSigner.Builder operation = signer().withHeaderAndClaims(JwtSigningHeader.fromType(JwtType.JWT), claims);
		IllegalArgumentException failure = assertThrows(IllegalArgumentException.class, operation::build);
		assertEquals("The JWS signing input is invalid.", failure.getMessage());
	}

	private static @NonNull JwsSigner signer() {
		var key = TestJwk.Fixture.IDP_SIGNING_RSA_2048;
		return JwsSigner.fromRsaKeyPair(key.getPrivateKey(), key.getPublicKey(), JwsAlgorithm.RS256);
	}

	private static byte @NonNull [] verifiedPayload(@NonNull String compact) throws Exception {
		String[] parts = compact.split("\\.", -1);
		assertEquals(3, parts.length);
		Signature verifier = Signature.getInstance("SHA256withRSA");
		verifier.initVerify(TestJwk.Fixture.IDP_SIGNING_RSA_2048.getPublicKey());
		verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
		assertTrue(verifier.verify(Base64.getUrlDecoder().decode(parts[2])));
		return Base64.getUrlDecoder().decode(parts[1]);
	}
}
