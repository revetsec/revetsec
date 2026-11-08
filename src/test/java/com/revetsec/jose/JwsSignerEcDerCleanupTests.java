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

import com.revetsec.testing.TestJwk;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** In-process observations of provider-owned EC DER buffers on both exits from DER conversion. */
@ResourceLock("java.security.Security")
final class JwsSignerEcDerCleanupTests {
	private static final @NonNull String PROVIDER_NAME = "RevetsecEcDerCleanupProbe";
	private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);
	private static final byte @NonNull [] INVALID_DER = {0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01};

	@Test
	void p256ProviderDerIsClearedAfterSuccessfulSigning() throws Exception {
		assertSuccessfulCleanup(JwsAlgorithm.ES256, TestJwk.Fixture.IDP_SIGNING_EC_P256);
	}

	@Test
	void p384ProviderDerIsClearedAfterSuccessfulSigning() throws Exception {
		assertSuccessfulCleanup(JwsAlgorithm.ES384, TestJwk.Fixture.IDP_SIGNING_EC_P384);
	}

	@Test
	void p256ProviderDerIsClearedWhenMalformedDerIsRefused() throws Exception {
		assertRefusalCleanup(JwsAlgorithm.ES256, TestJwk.Fixture.IDP_SIGNING_EC_P256);
	}

	@Test
	void p384ProviderDerIsClearedWhenMalformedDerIsRefused() throws Exception {
		assertRefusalCleanup(JwsAlgorithm.ES384, TestJwk.Fixture.IDP_SIGNING_EC_P384);
	}

	private static void assertSuccessfulCleanup(@NonNull JwsAlgorithm algorithm, TestJwk.@NonNull Fixture fixture)
			throws Exception {
		withProvider(false, state -> {
			JwsSigner signer = JwsSigner.fromEcKeyPair(fixture.getPrivateKey(), fixture.getPublicKey(), algorithm);
			String compact = signer.toCompactSerialization("JWT", null, null,
					"{}".getBytes(StandardCharsets.UTF_8), BUDGET);

			assertEquals(3, compact.split("\\.", -1).length);
			assertEquals(1, state.signCalls);
			assertEquals(1, state.verifyCalls);
			assertClearedProviderResult(state);
		});
	}

	private static void assertRefusalCleanup(@NonNull JwsAlgorithm algorithm, TestJwk.@NonNull Fixture fixture)
			throws Exception {
		withProvider(true, state -> {
			JwsSigner signer = JwsSigner.fromEcKeyPair(fixture.getPrivateKey(), fixture.getPublicKey(), algorithm);
			JwsSigningException failure = assertThrows(JwsSigningException.class,
					() -> signer.toCompactSerialization("JWT", null, null,
							"{}".getBytes(StandardCharsets.UTF_8), BUDGET));

			assertEquals(JwsSigningException.Reason.SIGNING_UNAVAILABLE, failure.getReason());
			assertNull(failure.getCause());
			assertEquals(1, state.signCalls);
			assertEquals(0, state.verifyCalls);
			assertClearedProviderResult(state);
		});
	}

	private static void assertClearedProviderResult(@NonNull State state) {
		assertTrue(state.returnedContainedNonZero, "The provider result must contain data before JwsSigner receives it.");
		byte[] exactProviderResult = requireNonNull(state.returnedDer);
		assertArrayEquals(new byte[exactProviderResult.length], exactProviderResult,
				"JwsSigner must clear the exact array returned by the provider.");
	}

	private static void withProvider(boolean invalidDer, @NonNull Scenario scenario) throws Exception {
		// Resolve fixtures and the delegate before the probe becomes the highest-priority provider.
		assertNotNull(TestJwk.Fixture.IDP_SIGNING_EC_P256.getPrivateKey());
		assertNotNull(TestJwk.Fixture.IDP_SIGNING_EC_P384.getPrivateKey());
		State state = new State(requireNonNull(Security.getProvider("SunEC")), invalidDer);
		assertNull(Security.getProvider(PROVIDER_NAME));
		assertEquals(1, Security.insertProviderAt(new FixtureProvider(state), 1));
		try {
			scenario.run(state);
		} finally {
			Security.removeProvider(PROVIDER_NAME);
		}
		assertNull(Security.getProvider(PROVIDER_NAME));
	}

	@FunctionalInterface
	private interface Scenario {
		void run(@NonNull State state) throws Exception;
	}

	private static final class State {
		private final @NonNull Provider delegateProvider;
		private final @NonNull Thread owner = Thread.currentThread();
		private final boolean invalidDer;
		private int signCalls;
		private int verifyCalls;
		private boolean returnedContainedNonZero;
		private byte @Nullable [] returnedDer;

		private State(@NonNull Provider delegateProvider, boolean invalidDer) {
			this.delegateProvider = delegateProvider;
			this.invalidDer = invalidDer;
		}
	}

	private static final class FixtureProvider extends Provider {
		private static final long serialVersionUID = 1L;

		private FixtureProvider(@NonNull State state) {
			super(PROVIDER_NAME, "1", "Scoped EC DER cleanup fixture");
			for (String algorithm : List.of("SHA256withECDSA", "SHA384withECDSA")) {
				putService(new Service(this, "Signature", algorithm, Engine.class.getName(), List.of(), null) {
					@Override
					public @NonNull Object newInstance(@Nullable Object ignored)
							throws java.security.NoSuchAlgorithmException {
						return new Engine(algorithm, state);
					}
				});
			}
		}
	}

	private static final class Engine extends SignatureSpi {
		private final @NonNull State state;
		private final @NonNull Signature delegate;
		private boolean trackedSign;
		private boolean trackedVerification;

		private Engine(@NonNull String algorithm, @NonNull State state)
				throws java.security.NoSuchAlgorithmException {
			this.state = state;
			this.delegate = Signature.getInstance(algorithm, state.delegateProvider);
		}

		@Override
		protected void engineInitSign(@NonNull PrivateKey key) throws InvalidKeyException {
			this.trackedSign = Thread.currentThread().equals(this.state.owner);
			this.trackedVerification = false;
			this.delegate.initSign(key);
		}

		@Override
		protected void engineInitVerify(@NonNull PublicKey key) throws InvalidKeyException {
			this.trackedSign = false;
			this.trackedVerification = Thread.currentThread().equals(this.state.owner);
			this.delegate.initVerify(key);
		}

		@Override
		protected void engineUpdate(byte value) throws SignatureException {
			this.delegate.update(value);
		}

		@Override
		protected void engineUpdate(byte @NonNull [] bytes, int offset, int length) throws SignatureException {
			this.delegate.update(bytes, offset, length);
		}

		@Override
		protected byte @NonNull [] engineSign() throws SignatureException {
			byte[] result = this.delegate.sign();
			if (this.trackedSign && Thread.currentThread().equals(this.state.owner)) {
				if (this.state.invalidDer) {
					Arrays.fill(result, (byte) 0);
					result = INVALID_DER.clone();
				}
				this.state.signCalls++;
				this.state.returnedContainedNonZero = containsNonZero(result);
				this.state.returnedDer = result;
			}
			return result;
		}

		@Override
		protected boolean engineVerify(byte @NonNull [] signature) throws SignatureException {
			boolean valid = this.delegate.verify(signature);
			if (this.trackedVerification && Thread.currentThread().equals(this.state.owner))
				this.state.verifyCalls++;
			return valid;
		}

		@Override
		protected void engineSetParameter(@NonNull AlgorithmParameterSpec parameters)
				throws InvalidAlgorithmParameterException {
			this.delegate.setParameter(parameters);
		}

		@Override
		@SuppressWarnings("deprecation")
		protected void engineSetParameter(@NonNull String name, @NonNull Object value) {
			throw new UnsupportedOperationException();
		}

		@Override
		@SuppressWarnings("deprecation")
		protected @Nullable Object engineGetParameter(@NonNull String name) {
			throw new UnsupportedOperationException();
		}
	}

	private static boolean containsNonZero(byte @NonNull [] bytes) {
		for (byte value : bytes) if (value != 0) return true;
		return false;
	}
}
