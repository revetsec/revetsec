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

import com.revetsec.testing.TestJsonWebKeys;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
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
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.nio.charset.StandardCharsets;
import static java.util.Objects.requireNonNull;

/** Isolated child-JVM provider probes. Never installed into the test suite's JVM. */
public final class JwsSignerTestProvider extends Provider {
	private static final long serialVersionUID = 1L;
	private static @Nullable Provider original;
	private static @NonNull String mode = "opaque";
	private static int signCalls;
	private static int verifyCalls;
	private static int encodedCalls;
	private static int signatureInstances;
	private static int initializedSignEngines;
	private static int initializedVerifyEngines;
	private static byte @Nullable [] mutatingClaims;
	private static byte @Nullable [] mutatingDigest;
	private static final @NonNull String SECRET = "sentinel7f3a9c-provider-sentinel7f3a9c";

	public JwsSignerTestProvider() {
		super("RevetsecSignerProbe", "1", "Isolated signer test provider");
		putService(new Service(this, "Signature", "SHA256withRSA", Engine.class.getName(), List.of(), null));
		putService(new Service(this, "Signature", "SHA384withRSA", Engine.class.getName(), List.of(), null));
		putService(new Service(this, "Signature", "RSASSA-PSS", Engine.class.getName(), List.of(), null));
	}

	public static void main(@NonNull String @NonNull [] arguments) throws Exception {
		mode = arguments[0];
		original = requireNonNull(Security.getProvider("SunRsaSign"));
		Provider installed = new JwsSignerTestProvider();
		Security.insertProviderAt(installed, 1);
		try { exercise(); }
		finally { Security.removeProvider(installed.getName()); }
		System.out.println("scenario=" + mode + " passed");
	}

	private static void exercise() throws Exception {
		PrivateKey real = TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPrivateKey();
		PublicKey publicKey = TestJsonWebKeys.Fixture.IDP_SIGNING_RSA_2048.getPublicKey();
		OpaqueKey opaque = new OpaqueKey(real, mode.equals("restricted") ? "RSASSA-PSS" : "RSA");
		int beforeThreads = Thread.getAllStackTraces().size();
		JwsSigner signer = JwsSigner.fromRsaKeyPair(opaque, publicKey, JwsAlgorithm.PS256);
		check(signCalls == 0 && verifyCalls == 0 && signatureInstances == 0 && encodedCalls == 0,
				"Factory performed provider work.");
		if (mode.equals("vm-error")) {
			try { signer.warmUp(Duration.ofSeconds(5)); throw new AssertionError("VM error did not escape."); }
			catch (ProbeVmError expected) { check(SECRET.equals(expected.getMessage()), "Wrong VM error."); }
		} else if (mode.equals("interrupt")) {
			Thread.currentThread().interrupt();
			try { expectFailure(signer, JwsSigningException.Reason.SIGNING_UNAVAILABLE, Duration.ofSeconds(5));
				check(Thread.currentThread().isInterrupted(), "Interruption was cleared."); }
			finally { Thread.interrupted(); }
		} else if (mode.equals("restricted")) {
			expectFailure(signer, JwsSigningException.Reason.SIGNING_UNAVAILABLE, Duration.ofSeconds(5));
		} else if (mode.equals("late-init") || mode.equals("late-update") || mode.equals("late-sign") || mode.equals("late-verify")) {
			expectFailure(signer, JwsSigningException.Reason.BUDGET_EXHAUSTED, Duration.ofMillis(80));
		} else if (mode.equals("malformed") || mode.equals("oversized-output") || mode.equals("wrong-modulus-length")
				|| mode.equals("null-output") || mode.equals("throwing")) {
			expectFailure(signer, JwsSigningException.Reason.SIGNING_UNAVAILABLE, Duration.ofSeconds(5));
			if (!mode.equals("throwing")) check(verifyCalls == 0, "Malformed signature reached the verification provider.");
		} else if (mode.equals("mismatch")) {
			expectFailure(signer, JwsSigningException.Reason.KEY_PAIR_MISMATCH, Duration.ofSeconds(5));
		} else if (mode.equals("throwing-verifier")) {
			expectFailure(signer, JwsSigningException.Reason.SIGNING_UNAVAILABLE, Duration.ofSeconds(5));
		} else {
			byte[] claims = " { \"marker\": 1e+0 } ".getBytes(StandardCharsets.UTF_8);
			byte[] digest = new byte[32]; Arrays.fill(digest, (byte) 42);
			byte[] accepted = claims.clone(); byte[] acceptedDigest = digest.clone();
			mutatingClaims = claims; mutatingDigest = digest;
			String compact = signer.toCompactSerialization("JWT", "key", digest, claims, Duration.ofSeconds(5));
			String[] pieces = compact.split("\\.", -1);
			check(Arrays.equals(accepted, java.util.Base64.getUrlDecoder().decode(pieces[1])), "Claims copy changed.");
			String header = new String(java.util.Base64.getUrlDecoder().decode(pieces[0]), StandardCharsets.UTF_8);
			check(header.contains(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(acceptedDigest)),
					"Digest copy changed.");
			Signature verifier = Signature.getInstance("RSASSA-PSS", requireNonNull(original));
			verifier.initVerify(publicKey);
			verifier.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
			verifier.update((pieces[0] + "." + pieces[1]).getBytes(StandardCharsets.US_ASCII));
			check(verifier.verify(java.util.Base64.getUrlDecoder().decode(pieces[2])), "Opaque provider output failed.");
			signer.warmUp(Duration.ofSeconds(5));
			check(signCalls == 2 && verifyCalls == 2 && initializedSignEngines == 2 && initializedVerifyEngines == 2
					&& signatureInstances >= 4, "Fresh sign/verify per operation.");
		}
		check(encodedCalls == 0, "Opaque key was encoded.");
		check(Thread.getAllStackTraces().size() <= beforeThreads, "Signer created a thread.");
	}

	private static void expectFailure(@NonNull JwsSigner signer, JwsSigningException.@NonNull Reason reason,
			@NonNull Duration budget) {
		try { var unused = signer.toCompactSerialization("JWT", SECRET, null,
				("{\"marker\":\"" + SECRET + "\"}").getBytes(StandardCharsets.UTF_8), budget);
			throw new AssertionError("A credential was released.");
		} catch (JwsSigningException failure) {
			check(failure.getReason() == reason, "Unexpected reason: " + failure.getReason());
			if (mode.equals("late-init") || mode.equals("late-update")) check(signCalls == 0, "Signing started after exhaustion.");
			check(failure.getCause() == null && !failure.toString().contains(SECRET), "Provider details escaped.");
		}
	}

	private static void check(boolean condition, @NonNull String message) { if (!condition) throw new AssertionError(message); }

	private static final class OpaqueKey implements PrivateKey {
		private static final long serialVersionUID = 1L;
		private final @NonNull PrivateKey delegate;
		private final @NonNull String algorithm;
		private OpaqueKey(@NonNull PrivateKey delegate, @NonNull String algorithm) {
			this.delegate = delegate; this.algorithm = algorithm;
		}
		@Override public @NonNull String getAlgorithm() { return this.algorithm; }
		@Override public @Nullable String getFormat() { return null; }
		@Override public byte @Nullable [] getEncoded() { ++encodedCalls; throw new AssertionError("Opaque key encoded."); }
		@Override public @NonNull String toString() { return SECRET; }
	}

	private static final class ProbeVmError extends VirtualMachineError {
		private static final long serialVersionUID = 1L;
		private ProbeVmError() { super(SECRET); }
	}

	/** JCA reflectively constructs this public fixture only in the child JVM. */
	public static final class Engine extends SignatureSpi {
		private @Nullable Signature delegate;
		private boolean signing;
		private boolean initialized;
		private @NonNull String algorithm = "RSASSA-PSS";
		public Engine() { ++signatureInstances; }

		@Override protected void engineInitVerify(@NonNull PublicKey publicKey) throws InvalidKeyException {
			check(!this.initialized, "A verification engine was reused.");
			this.initialized = true; ++initializedVerifyEngines;
			this.signing = false;
			try {
				this.delegate = Signature.getInstance(this.algorithm, requireNonNull(original));
				this.delegate.initVerify(publicKey);
			} catch (java.security.GeneralSecurityException failure) { throw new InvalidKeyException(SECRET); }
		}
		@Override protected void engineInitSign(@NonNull PrivateKey privateKey) throws InvalidKeyException {
			if (!(privateKey instanceof OpaqueKey opaque)) throw new InvalidKeyException(SECRET);
			check(!this.initialized, "A signing engine was reused.");
			this.initialized = true; ++initializedSignEngines;
			this.signing = true;
			if (mode.equals("late-init")) delay();
			try {
				this.delegate = Signature.getInstance(this.algorithm, requireNonNull(original));
				this.delegate.initSign(opaque.delegate);
			} catch (java.security.GeneralSecurityException failure) { throw new InvalidKeyException(SECRET); }
		}
		@Override protected void engineUpdate(byte value) throws SignatureException { requireNonNull(this.delegate).update(value); }
		@Override protected void engineUpdate(byte @NonNull [] values, int offset, int length) throws SignatureException {
			if (this.signing && mode.equals("late-update")) delay();
			requireNonNull(this.delegate).update(values, offset, length);
		}
		@Override protected byte @NonNull [] engineSign() throws SignatureException {
			++signCalls;
			if (mutatingClaims != null) Arrays.fill(mutatingClaims, (byte) 0);
			if (mutatingDigest != null) Arrays.fill(mutatingDigest, (byte) 0);
			if (mode.equals("vm-error")) throw new ProbeVmError();
			if (mode.equals("throwing") || mode.equals("interrupt")) throw new IllegalStateException(SECRET);
			if (mode.equals("late-sign")) delay();
			if (mode.equals("malformed")) return new byte[17];
			if (mode.equals("oversized-output")) return new byte[2049];
			if (mode.equals("wrong-modulus-length")) return new byte[257];
			if (mode.equals("mismatch")) return new byte[256];
			if (mode.equals("null-output")) return nullOutput();
			return requireNonNull(this.delegate).sign();
		}
		@Override protected boolean engineVerify(byte @NonNull [] signature) throws SignatureException {
			++verifyCalls;
			if (mode.equals("late-verify")) delay();
			if (mode.equals("throwing-verifier")) throw new IllegalStateException(SECRET);
			return requireNonNull(this.delegate).verify(signature);
		}
		@Override protected void engineSetParameter(@NonNull AlgorithmParameterSpec parameters)
				throws InvalidAlgorithmParameterException {
			if (this.signing && mode.equals("restricted")) throw new InvalidAlgorithmParameterException(SECRET);
			requireNonNull(this.delegate).setParameter(parameters);
		}
		@Override @SuppressWarnings("deprecation") protected void engineSetParameter(@NonNull String name,
				@NonNull Object value) { throw new UnsupportedOperationException(); }
		@Override @SuppressWarnings("deprecation") protected @Nullable Object engineGetParameter(@NonNull String name) {
			throw new UnsupportedOperationException();
		}
		private static void delay() {
			try { Thread.sleep(180); }
			catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new IllegalStateException(SECRET); }
		}
		@SuppressWarnings("NullAway") private static byte @NonNull [] nullOutput() { return null; }
	}
}
