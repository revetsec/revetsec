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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

/**
 * {@link JwsAlgorithm}: the wire values of RFC 7518 section 3.1, RFC 8037 section 3.1 and RFC 9864, looked up exactly
 * and case-sensitively (RFC 7515 section 4.1.1), with no {@code none}.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class JwsAlgorithmTests {
	// Every constant's wire value is the registered alg name, and it finds its constant again.
	@Test
	void wireValuesAreTheRegisteredNamesAndRoundTrip() {
		Assertions.assertEquals(List.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512",
				"Ed25519", "EdDSA", "HS256", "HS384", "HS512"), List.of(JwsAlgorithm.values()).stream()
				.map(JwsAlgorithm::getWireValue).toList());
		for (JwsAlgorithm algorithm : JwsAlgorithm.values())
			Assertions.assertEquals(Optional.of(algorithm), JwsAlgorithm.findByWireValue(algorithm.getWireValue()));
	}

	// Lookup is exact: none in any case, other cases of real names, whitespace and unregistered names find nothing.
	@Test
	@SuppressWarnings("NullAway")
	void lookupIsExactAndKnowsNoNone() {
		for (String unknown : List.of("none", "None", "NONE", "nOnE", "rs256", "Rs256", "RS256 ", " RS256", "ed25519",
				"EDDSA", "eddsa", "ES256K", "ES521", "Ed448", "RSA-OAEP", "dir", "PBES2-HS256+A128KW", ""))
			Assertions.assertEquals(Optional.empty(), JwsAlgorithm.findByWireValue(unknown), unknown);
		Assertions.assertThrows(NullPointerException.class, () -> JwsAlgorithm.findByWireValue(null));
	}
}
