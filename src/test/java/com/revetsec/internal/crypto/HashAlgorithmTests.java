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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.List;
import java.util.stream.Stream;

/**
 * {@link HashAlgorithm}: the pinned JCA names resolve on the running JDK (INV-G10: names are pinned, providers are
 * not), the output lengths are the digests' own, and the RSASSA-PSS parameters are RFC 7518 section 3.5's.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
final class HashAlgorithmTests {
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> everyPinnedJcaNameResolvesWithTheDigestsLength() {
		return Stream.of(HashAlgorithm.values()).map(hash -> DynamicTest.dynamicTest(hash.name(), () -> {
			Assertions.assertEquals(hash.getLength(), MessageDigest.getInstance(hash.getDigestName()).getDigestLength());
			Assertions.assertEquals(hash.getLength(), Mac.getInstance(hash.getHmacName()).getMacLength());
			Assertions.assertNotNull(Signature.getInstance(hash.getRsaSignatureName()));
			Assertions.assertNotNull(Signature.getInstance(hash.getEcdsaSignatureName()));
		}));
	}

	@Test
	void theNamesAndLengthsArePinned() {
		Assertions.assertEquals(List.of("SHA-256", "SHA-384", "SHA-512"),
				Stream.of(HashAlgorithm.values()).map(HashAlgorithm::getDigestName).toList());
		Assertions.assertEquals(List.of(32, 48, 64), Stream.of(HashAlgorithm.values()).map(HashAlgorithm::getLength)
				.toList());
		Assertions.assertEquals(List.of("SHA256withRSA", "SHA384withRSA", "SHA512withRSA"),
				Stream.of(HashAlgorithm.values()).map(HashAlgorithm::getRsaSignatureName).toList());
		Assertions.assertEquals(List.of("SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"),
				Stream.of(HashAlgorithm.values()).map(HashAlgorithm::getEcdsaSignatureName).toList());
		Assertions.assertEquals(List.of("HmacSHA256", "HmacSHA384", "HmacSHA512"),
				Stream.of(HashAlgorithm.values()).map(HashAlgorithm::getHmacName).toList());
	}

	// RFC 7518 section 3.5: MGF1 with the same hash, and "the size of the salt value is the same size as the hash
	// function output"; the trailer field is 1 (RFC 8017 section 9.1).
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> pssParametersAreFixedByTheHash() {
		return Stream.of(HashAlgorithm.values()).map(hash -> DynamicTest.dynamicTest(hash.name(), () -> {
			PSSParameterSpec parameters = hash.getPssParameterSpec();

			Assertions.assertEquals(hash.getDigestName(), parameters.getDigestAlgorithm());
			Assertions.assertEquals("MGF1", parameters.getMGFAlgorithm());
			Assertions.assertEquals(hash.getDigestName(),
					((MGF1ParameterSpec) parameters.getMGFParameters()).getDigestAlgorithm());
			Assertions.assertEquals(hash.getLength(), parameters.getSaltLength());
			Assertions.assertEquals(PSSParameterSpec.TRAILER_FIELD_BC, parameters.getTrailerField());
			Assertions.assertNotSame(parameters, hash.getPssParameterSpec());

			Signature verifier = Signature.getInstance("RSASSA-PSS");
			verifier.setParameter(parameters);
		}));
	}
}
