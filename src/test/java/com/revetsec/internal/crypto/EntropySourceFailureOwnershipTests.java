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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.security.Provider;
import java.security.ProviderException;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** Isolated scripted-provider memory ownership calibration, not an entropy quality/provider qualification. */
final class EntropySourceFailureOwnershipTests {
	private static byte @Nullable [] observed;
	private static @Nullable Error error;
	private static @Nullable RuntimeException runtime;
	@TestFactory
	@NonNull Stream<@NonNull DynamicTest> failedProviderFillErasesTheOwnedBufferAndRethrowsTheSameFailure() {
		return List.of("runtime", "error", "virtual-machine-error").stream().map(mode -> DynamicTest.dynamicTest(mode, () -> {
			Provider provider = new ScriptedProvider(); observed = null;
			runtime = mode.equals("runtime") ? new ProviderException("TEST-ONLY-entropy-sensitive-failure") : null;
			error = mode.equals("error") ? new AssertionError("TEST-ONLY-entropy-sensitive-failure") : mode.equals("virtual-machine-error") ? new ScriptedVirtualMachineError() : null;
			Security.insertProviderAt(provider, 1);
			try {
				EntropySource source = EntropySource.fromDefaults(); Throwable failure = assertThrows(Throwable.class, () -> source.nextBytes(32));
				assertSame(runtime == null ? error : runtime, failure, "failure identity remains caller/provider owned");
				assertNotNull(observed); byte[] buffer = java.util.Objects.requireNonNull(observed); assertEquals(32, buffer.length); assertTrue(Arrays.equals(buffer, new byte[32]), "failed entropy buffer must be erased");
			} finally { Security.removeProvider(provider.getName()); runtime = null; error = null; observed = null; }
		}));
	}
	@Test
	void successTransfersTheSameBufferWithoutErasingCallerOwnedBytes() {
		Provider provider = new ScriptedProvider(); runtime = null; error = null; observed = null; Security.insertProviderAt(provider, 1);
		try {
			byte[] result = EntropySource.fromDefaults().nextBytes(32); assertSame(observed, result); byte[] expected = new byte[32]; Arrays.fill(expected, (byte) 0x5a);
			assertTrue(Arrays.equals(expected, result), "successful ownership transfer must preserve filled bytes"); Arrays.fill(result, (byte) 0);
		} finally { Security.removeProvider(provider.getName()); observed = null; }
	}
	public static final class ScriptedProvider extends Provider {
		private static final long serialVersionUID = 1L;
		public ScriptedProvider() { super("RevetsecEntropyOwnership", "1.0", "scripted ownership test only"); put("SecureRandom.RevetsecOwnership", ScriptedRandom.class.getName()); }
	}
	public static final class ScriptedRandom extends SecureRandomSpi {
		private static final long serialVersionUID = 1L;
		@Override protected void engineSetSeed(byte @NonNull [] seed) { }
		@Override protected void engineNextBytes(byte @NonNull [] bytes) { observed = bytes; Arrays.fill(bytes, (byte) 0x5a); if (runtime != null) throw runtime; if (error != null) throw error; }
		@Override protected byte @NonNull [] engineGenerateSeed(int length) { byte[] bytes = new byte[length]; engineNextBytes(bytes); return bytes; }
	}
	private static final class ScriptedVirtualMachineError extends VirtualMachineError { private static final long serialVersionUID = 1L; }
}
