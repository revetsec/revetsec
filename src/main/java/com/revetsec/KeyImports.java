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

package com.revetsec;

import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.EcPublicKeys;
import com.revetsec.internal.crypto.EcdsaSignatures;
import com.revetsec.internal.crypto.Ed25519PublicKeys;
import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.internal.crypto.KeyRejectedException;
import com.revetsec.internal.crypto.RsaPublicKeys;
import com.revetsec.internal.crypto.SignatureVerifier;
import com.revetsec.internal.crypto.VerifyResult;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.pem.PemException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.ThreadSafe;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Arrays;
import static java.util.Objects.requireNonNull;

/**
 * Bounded imports of ordinary JCA key material: RSA (2048 through 16384 bits, the existing exponent/ROCA policy),
 * EC P-256/P-384 and canonical, non-small-order Ed25519 public points. DER is at most 65536 bytes and PEM at most
 * 98304 characters, checked before copying/decoding; PEM's decoded DER is also bounded before allocation.
 * <p>
 * One exact PEM block is accepted, with canonical padded Base64 and matching labels. Public DER is SPKI.
 * Private material is unencrypted PKCS#8 version 0 without attributes/outer public fields, or two-prime RSA
 * PKCS#1 version 0. SEC1 armor, encrypted keys, RFC5958 version 1/attributes, P-521, Ed448, XDH and RSA-PSS
 * containers are outside this profile. EC's inner named parameters must agree with its outer parameters; an
 * embedded public hint must be a well-formed on-curve point but remains untrusted metadata. Import does not
 * establish scalar-to-hint or key-pair agreement; use the separate explicit pair check.
 * <p>
 * Certificate parsing checks the embedded key profile, not certificate signatures, trust, chains, hostname,
 * time, revocation or complete inner DER canonicality. Caller input remains unchanged. Owned private DER and
 * pair-check challenge/signature buffers are erased; provider-owned keys, copies and immutable values remain
 * under JCA/provider ownership. No method exports private key material or implicitly signs during import.
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class KeyImports {
	private static final int MAXIMUM_DER_BYTES = 65_536;
	private static final int MAXIMUM_PEM_CHARACTERS = 98_304;
	private KeyImports() { }

	/**
	 * Imports one CERTIFICATE PEM block and checks its embedded key profile, without establishing certificate trust.
	 * @param pem at most 98304 characters
	 * @return the caller-owned parsed certificate
	 * @throws NullPointerException if pem is null
	 * @throws KeyImportException if parsing, size or the selected key profile fails
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull X509Certificate certificateFromPem(@NonNull String pem) {
		checkPem(pem);
		return load(() -> checkedCertificate(Pem.parseCertificate(pem, MAXIMUM_DER_BYTES)));
	}

	/**
	 * Imports one DER certificate and checks its embedded key profile, without establishing certificate trust.
	 * @param der at most 65536 bytes; not modified
	 * @return the caller-owned parsed certificate
	 * @throws NullPointerException if der is null
	 * @throws KeyImportException if parsing, size or the selected key profile fails
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull X509Certificate certificateFromDer(byte @NonNull [] der) {
		byte[] owned = snapshot(der);
		try { return load(() -> checkedCertificate(Pem.parseCertificateDer(owned))); }
		finally { clear(owned); }
	}

	/**
	 * Imports one PUBLIC KEY PEM block under the selected public-key profile.
	 * @param pem at most 98304 characters
	 * @return the caller-owned checked JCA key
	 * @throws NullPointerException if pem is null
	 * @throws KeyImportException if parsing, size or the selected key profile fails
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull PublicKey publicKeyFromPem(@NonNull String pem) {
		checkPem(pem); return load(() -> checkedPublic(Pem.parsePublicKey(pem, MAXIMUM_DER_BYTES)));
	}

	/**
	 * Imports one canonical SubjectPublicKeyInfo DER value under the selected public-key profile.
	 * @param der at most 65536 bytes; not modified
	 * @return the caller-owned checked JCA key
	 * @throws NullPointerException if der is null
	 * @throws KeyImportException if parsing, size or the selected key profile fails
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull PublicKey publicKeyFromSpkiDer(byte @NonNull [] der) {
		byte[] owned = snapshot(der);
		try { return load(() -> checkedPublic(Pem.parsePublicKeyDer(owned))); }
		finally { clear(owned); }
	}

	/**
	 * Imports one PRIVATE KEY or RSA PRIVATE KEY PEM block in the selected unencrypted private-container profile.
	 * @param pem at most 98304 characters
	 * @return the caller-owned decoded JCA key; pair agreement is not established
	 * @throws NullPointerException if pem is null
	 * @throws KeyImportException if parsing, size or the selected key profile fails
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull PrivateKey privateKeyFromPem(@NonNull String pem) {
		checkPem(pem); return load(() -> checkedPrivate(Pem.parsePrivateKey(pem, MAXIMUM_DER_BYTES)));
	}

	/**
	 * Imports one unencrypted PKCS#8 version 0 key without attributes or an outer public-key field.
	 * @param der at most 65536 bytes; not modified
	 * @return the caller-owned decoded JCA key; pair agreement is not established
	 * @throws NullPointerException if der is null
	 * @throws KeyImportException if parsing, size or the selected key profile fails
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull PrivateKey privateKeyFromPkcs8Der(byte @NonNull [] der) {
		return privateDer(der, false);
	}

	/**
	 * Imports one two-prime RSA PKCS#1 version 0 private key.
	 * @param der at most 65536 bytes; not modified
	 * @return the caller-owned decoded RSA key; pair agreement is not established
	 * @throws NullPointerException if der is null
	 * @throws KeyImportException if parsing, size or the selected key profile fails
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull PrivateKey rsaPrivateKeyFromPkcs1Der(byte @NonNull [] der) {
		return privateDer(der, true);
	}

	private static @NonNull PrivateKey privateDer(byte @NonNull [] der, boolean pkcs1) {
		byte[] owned = snapshot(der);
		try { return load(() -> checkedPrivate(pkcs1 ? Pem.parseRsaPrivateKeyDer(owned) : Pem.parsePrivateKeyDer(owned))); }
		finally { clear(owned); }
	}

	/**
	 * Checks agreement with a fresh 32-byte noncredential challenge, a fresh JCA signer and the independent verifier.
	 * The public key must provide a bounded canonical SPKI encoding; it is reparsed to a checked stable projection.
	 * The private key may remain opaque; its encoding is never requested. No signature or challenge is returned.
	 * One original monotonic budget covers public snapshot, provider/random initialization, signing and verification.
	 * Trusted synchronous providers must cooperate; these checks cannot preempt a blocked provider. No retry occurs.
	 * @param privateKey the caller-owned private key
	 * @param publicKey the caller-owned encodable public key
	 * @param remainingBudget the original remaining budget; nonpositive values are exhausted
	 * @throws NullPointerException if a required argument is null
	 * @throws KeyImportException if the profile, pair, provider, interruption or budget check fails
	 * @since 1.0.0
	 */
	public static void checkKeyPair(@NonNull PrivateKey privateKey, @NonNull PublicKey publicKey, @NonNull Duration remainingBudget) {
		requireNonNull(privateKey); requireNonNull(publicKey); requireNonNull(remainingBudget);
		if (Thread.currentThread().isInterrupted()) throw failure(KeyImportException.Reason.CANCELLED);
		if (remainingBudget.isNegative() || remainingBudget.isZero()) throw failure(KeyImportException.Reason.BUDGET_EXHAUSTED);
		Budget deadline = new Budget(remainingBudget);
		byte[] challenge = new byte[32]; byte @Nullable [] signature = null; byte @Nullable [] jose = null;
		try {
			active(deadline);
			PublicKey stable = publicKeyFromSpkiDer(requireNonNull(publicKey.getEncoded()));
			active(deadline);
			String privateAlgorithm = requireNonNull(privateKey.getAlgorithm());
			@Nullable EcCurve curve = stable instanceof ECPublicKey ec ? selectedCurve(ec.getParams()) : null;
			if (privateKey instanceof RSAPrivateCrtKey || privateKey instanceof ECPrivateKey || privateKey instanceof EdECPrivateKey)
				checkedPrivate(privateKey);
			active(deadline);
			if (privateKey instanceof ECPrivateKey ec && curve != null && selectedCurve(ec.getParams()) != curve)
				throw failure(KeyImportException.Reason.KEY_PAIR_MISMATCH);
			if (!(privateAlgorithm.equals("RSA") || privateAlgorithm.equals("EC") || privateAlgorithm.equals("Ed25519") || privateAlgorithm.equals("EdDSA")))
				throw failure(KeyImportException.Reason.UNSUPPORTED_KEY);
			String algorithm = stable instanceof RSAPublicKey ? "SHA256withRSA" : curve != null
					? (curve == EcCurve.P_256 ? "SHA256withECDSA" : "SHA384withECDSA") : "Ed25519";
			if (!(stable instanceof RSAPublicKey ? privateAlgorithm.equals("RSA") : curve != null
					? privateAlgorithm.equals("EC") : privateAlgorithm.equals("Ed25519") || privateAlgorithm.equals("EdDSA")))
				throw failure(KeyImportException.Reason.KEY_PAIR_MISMATCH);
			active(deadline);
			SecureRandom random = pairRandom();
			active(deadline); random.nextBytes(challenge); active(deadline);
			Signature signer = Signature.getInstance(algorithm);
			active(deadline); signer.initSign(privateKey, random); active(deadline);
			signer.update(challenge); active(deadline);
			signature = requireNonNull(signer.sign()); active(deadline);
			if (signature.length > RsaPublicKeys.MAXIMUM_SIGNATURE_LENGTH) throw failure(KeyImportException.Reason.OPERATION_UNAVAILABLE);
			VerifyResult result;
			if (curve != null) {
				jose = EcdsaSignatures.toJose(curve, signature); active(deadline);
				result = SignatureVerifier.verifyEcdsa(curve, curve == EcCurve.P_256 ? HashAlgorithm.SHA_256 : HashAlgorithm.SHA_384, stable, challenge, jose);
			} else if (stable instanceof RSAPublicKey) result = SignatureVerifier.verifyRsaPkcs1(HashAlgorithm.SHA_256, stable, challenge, signature);
			else result = SignatureVerifier.verifyEd25519(stable, challenge, signature);
			active(deadline);
			if (result != VerifyResult.VALID) throw failure(result == VerifyResult.MISMATCH
					? KeyImportException.Reason.KEY_PAIR_MISMATCH : KeyImportException.Reason.OPERATION_UNAVAILABLE);
		} catch (KeyImportException failure) { active(deadline); throw failure; }
		catch (KeyRejectedException rejected) { active(deadline); throw failure(KeyImportException.Reason.KEY_REJECTED); }
		catch (GeneralSecurityException | RuntimeException providerFailure) {
			active(deadline); throw failure(KeyImportException.Reason.OPERATION_UNAVAILABLE);
		} finally { clear(challenge); clear(signature); clear(jose); }
	}

	private static @NonNull X509Certificate checkedCertificate(@NonNull X509Certificate certificate) throws KeyRejectedException, GeneralSecurityException {
		checkedPublic(certificate.getPublicKey()); return certificate;
	}

	private static @NonNull PublicKey checkedPublic(@NonNull PublicKey key) throws KeyRejectedException {
		if (key instanceof RSAPublicKey rsa) {
			if (rsa.getParams() != null) throw failure(KeyImportException.Reason.UNSUPPORTED_KEY);
			RsaPublicKeys.checkPublicKey(rsa);
		} else if (key instanceof ECPublicKey ec) EcPublicKeys.checkPublicKey(selectedCurve(ec.getParams()), ec);
		else if (key instanceof EdECPublicKey ed) {
			if (!NamedParameterSpec.ED25519.getName().equals(ed.getParams().getName())) throw failure(KeyImportException.Reason.UNSUPPORTED_KEY);
			Ed25519PublicKeys.checkPublicKey(ed);
		} else throw failure(KeyImportException.Reason.UNSUPPORTED_KEY);
		return key;
	}

	private static @NonNull PrivateKey checkedPrivate(@NonNull PrivateKey key) throws GeneralSecurityException, KeyRejectedException {
		if (key instanceof RSAPrivateCrtKey rsa) {
			if (rsa.getParams() != null) throw failure(KeyImportException.Reason.UNSUPPORTED_KEY);
			checkedPublic(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent())));
		} else if (key instanceof ECPrivateKey ec) selectedCurve(ec.getParams());
		else if (!(key instanceof EdECPrivateKey ed) || !NamedParameterSpec.ED25519.getName().equals(ed.getParams().getName()))
			throw failure(KeyImportException.Reason.UNSUPPORTED_KEY);
		return key;
	}

	private static @NonNull EcCurve selectedCurve(java.security.spec.@NonNull ECParameterSpec parameters) {
		EcCurve curve = EcCurve.findByParameterSpec(parameters).orElseThrow(() -> failure(KeyImportException.Reason.UNSUPPORTED_KEY));
		if (curve == EcCurve.P_521) throw failure(KeyImportException.Reason.UNSUPPORTED_KEY);
		return curve;
	}

	private static byte @NonNull [] snapshot(byte @NonNull [] der) {
		requireNonNull(der);
		if (der.length > MAXIMUM_DER_BYTES) throw failure(KeyImportException.Reason.INPUT_TOO_LARGE);
		return der.clone();
	}

	private static void checkPem(@NonNull String pem) {
		requireNonNull(pem);
		if (pem.length() > MAXIMUM_PEM_CHARACTERS) throw failure(KeyImportException.Reason.INPUT_TOO_LARGE);
	}

	@FunctionalInterface private interface Loader<T> { @NonNull T load() throws PemException, GeneralSecurityException, KeyRejectedException; }
	private static <T> @NonNull T load(@NonNull Loader<@NonNull T> loader) {
		try { return loader.load(); }
		catch (KeyImportException failure) { throw failure; }
		catch (PemException failure) {
			throw failure(switch (failure.getKind()) {
				case UNSUPPORTED_ALGORITHM, UNSUPPORTED_LABEL, ENCRYPTED_PRIVATE_KEY, SEC1_PRIVATE_KEY -> KeyImportException.Reason.UNSUPPORTED_KEY;
				case INVALID_KEY -> KeyImportException.Reason.KEY_REJECTED;
				default -> KeyImportException.Reason.MALFORMED_INPUT;
			});
		} catch (KeyRejectedException failure) { throw failure(KeyImportException.Reason.KEY_REJECTED); }
		catch (IllegalArgumentException tooLarge) { throw failure(KeyImportException.Reason.INPUT_TOO_LARGE); }
		catch (GeneralSecurityException | RuntimeException providerFailure) { throw failure(KeyImportException.Reason.OPERATION_UNAVAILABLE); }
	}

	/** Pure monotonic budget: no dependency on the protocol-restricted HTTP package. */
	private static final class Budget {
		private final long start = System.nanoTime();
		private final long total;
		private Budget(@NonNull Duration duration) {
			long nanos;
			try { nanos = duration.toNanos(); } catch (ArithmeticException excessive) { nanos = Long.MAX_VALUE; }
			this.total = nanos;
		}
		private boolean isExpired() { return System.nanoTime() - this.start >= this.total; }
	}

	private static void active(@NonNull Budget deadline) {
		if (Thread.currentThread().isInterrupted()) throw failure(KeyImportException.Reason.CANCELLED);
		if (deadline.isExpired()) throw failure(KeyImportException.Reason.BUDGET_EXHAUSTED);
	}
	/** One trusted provider initialization boundary, entered and exited under the original budget. */
	private static @NonNull SecureRandom pairRandom() { return new SecureRandom(); }
	private static void clear(byte @Nullable [] bytes) { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
	private static @NonNull KeyImportException failure(KeyImportException.@NonNull Reason reason) { return KeyImportException.fromReason(reason); }
}
