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
package example.pending;

import org.jspecify.annotations.NonNull;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

/** Test-only signer: the generated private key never leaves this process. */
public final class RsaFixtureSigner {
	private RsaFixtureSigner() { }

	private static @NonNull String encoded(byte @NonNull [] value) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
	}

	private static @NonNull String unsigned(@NonNull BigInteger value) {
		byte[] bytes = value.toByteArray();
		return encoded(bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);
	}

	private static @NonNull String sign(@NonNull PrivateKey key, @NonNull String payload)
			throws GeneralSecurityException {
		String header = encoded("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"fixture-rsa\"}"
				.getBytes(StandardCharsets.US_ASCII));
		String input = header + "." + encoded(payload.getBytes(StandardCharsets.UTF_8));
		Signature signer = Signature.getInstance("SHA256withRSA");
		signer.initSign(key);
		signer.update(input.getBytes(StandardCharsets.US_ASCII));
		return input + "." + encoded(signer.sign());
	}

	public static void main(@NonNull String @NonNull [] args) throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair pair = generator.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
		System.out.println(unsigned(publicKey.getModulus()) + "\t" + unsigned(publicKey.getPublicExponent()));
		System.out.flush();
		try (BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8))) {
			String payload;
			while ((payload = input.readLine()) != null) {
				if (payload.length() > 4096) throw new IllegalArgumentException("Fixture payload is too long.");
				System.out.println(sign(pair.getPrivate(), payload));
				System.out.flush();
			}
		}
	}
}
