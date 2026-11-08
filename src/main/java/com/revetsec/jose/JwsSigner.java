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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.Limits;
import com.revetsec.internal.crypto.HashAlgorithm;
import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.EcPublicKeys;
import com.revetsec.internal.crypto.EcdsaSignatures;
import com.revetsec.internal.crypto.Ed25519PublicKeys;
import com.revetsec.internal.crypto.KeyRejectedException;
import com.revetsec.internal.crypto.RsaPublicKeys;
import com.revetsec.internal.crypto.SignatureVerifier;
import com.revetsec.internal.crypto.VerifyResult;
import com.revetsec.internal.encoding.Base64Url;
import com.revetsec.internal.http.Deadline;
import com.revetsec.internal.jose.Algorithms;
import com.revetsec.internal.jose.JwkParser;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonBoolean;
import com.revetsec.json.JsonNumber;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.util.Arrays;
import static java.util.Objects.requireNonNull;

/**
 * Signs compact JWS credentials with one application-owned key pair and one fixed algorithm.
 * PS256, PS384, PS512, RS256, RS384, RS512, ES256, ES384 and Ed25519 are supported. Each operation uses fresh JCA engines and verifies its actual signature
 * against the checked public projection before releasing any credential. Provider selection is left to JCA;
 * no fallback or provider configuration change is made.
 * <p>
 * The private key is retained by reference, may be opaque or nonexportable, and is never encoded or returned.
 * Applications own its persistent storage, registration and rotation. Construction makes structural checks only:
 * it never signs, probes the pair or invokes a JCA provider. Explicit {@link #warmUp(Duration)} probes the pair
 * without creating a credential.
 * <p>
 * Operations run on the caller thread and measure their remaining budget with monotonic time. They discard late
 * output but cannot preempt a trusted provider that hangs: bounded completion requires cooperative providers.
 * Callers also check their original deadline after this operation. No thread or executor is owned by the signer.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class JwsSigner {
	private static final @NonNull Duration DEFAULT_REMAINING_BUDGET = Duration.ofSeconds(2);
	private static final int MAXIMUM_COMPACT_LENGTH = Limits.COMPACT_JWT_SIZE.getDefaultIntValue();
	private static final int MAXIMUM_CLAIMS_LENGTH = MAXIMUM_COMPACT_LENGTH / 2;
	private static final int MAXIMUM_HEADER_LENGTH = MAXIMUM_COMPACT_LENGTH / 16;
	private static final int CERTIFICATE_DIGEST_LENGTH = 32;
	private static final String PROBE = "Revetsec RSA signing key pair noncredential probe v1";
	private static final @NonNull JsonLimits CLAIM_LIMITS = JsonLimits.jose(MAXIMUM_CLAIMS_LENGTH);

	private final @NonNull PrivateKey privateKey;
	private final @NonNull PublicKey publicKey;
	private final int signatureLength;
	private final @Nullable EcCurve ecCurve;
	private final @NonNull JwsAlgorithm algorithm;
	// Ed25519 is a pure JCA operation with no caller-supplied digest/prehash parameter.
	private final @Nullable HashAlgorithm hash;

	private JwsSigner(@NonNull PrivateKey privateKey, @NonNull PublicProjection publicKey,
			@NonNull JwsAlgorithm algorithm) {
		this(privateKey, publicKey, algorithm, publicKey.signatureLength(), null);
	}

	private JwsSigner(@NonNull PrivateKey privateKey, @NonNull PublicKey publicKey,
			@NonNull JwsAlgorithm algorithm, int signatureLength, @Nullable EcCurve ecCurve) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.signatureLength = signatureLength;
		this.ecCurve = ecCurve;
		this.algorithm = algorithm;
		this.hash = Algorithms.findHash(algorithm).orElse(null);
	}

	/**
	 * Returns a signer after bounded structural checks of its algorithm and inspectable RSA public projection.
	 * Public keys must satisfy the existing 2048–16384-bit, exponent and ROCA policy. RSA-PSS key restrictions are
	 * preserved; a PSS-only key cannot be selected for RS256, RS384 or RS512. This factory does not test pair agreement.
	 *
	 * @param privateKey the application-owned private key, retained by reference without encoding
	 * @param publicKey the inspectable RSA public key, snapshotted without encoding
	 * @param algorithm exactly PS256, PS384, PS512, RS256, RS384 or RS512
	 * @return the signer
	 * @throws NullPointerException if a required argument is null
	 * @throws IllegalArgumentException if a supplied algorithm or key is structurally invalid or unsupported
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull JwsSigner fromRsaKeyPair(@NonNull PrivateKey privateKey, @NonNull PublicKey publicKey,
			@NonNull JwsAlgorithm algorithm) {
		requireNonNull(privateKey);
		requireNonNull(publicKey);
		requireNonNull(algorithm);
		if (algorithm != JwsAlgorithm.PS256 && algorithm != JwsAlgorithm.PS384 && algorithm != JwsAlgorithm.PS512
				&& algorithm != JwsAlgorithm.RS256 && algorithm != JwsAlgorithm.RS384 && algorithm != JwsAlgorithm.RS512)
			throw invalidKey();
		try {
			if (!(publicKey instanceof RSAPublicKey rsaKey)) throw invalidKey();
			String privateAlgorithm = requireNonNull(privateKey.getAlgorithm());
			String publicAlgorithm = requireNonNull(publicKey.getAlgorithm());
			if (!rsaAlgorithm(privateAlgorithm) || !rsaAlgorithm(publicAlgorithm)) throw invalidKey();
			@Nullable AlgorithmParameterSpec parameters = rsaKey.getParams();
			if (!isRsaPss(algorithm) && (isPss(privateAlgorithm) || isPss(publicAlgorithm)
					|| parameters != null)) throw invalidKey();
			PublicProjection projection = new PublicProjection(snapshotInteger(requireNonNull(rsaKey.getModulus()), 16384, 2049),
					snapshotInteger(requireNonNull(rsaKey.getPublicExponent()), 32, 5), publicAlgorithm, snapshotParameters(parameters, Algorithms.findHash(algorithm).orElseThrow()));
			RsaPublicKeys.checkPublicKey(projection);
			return new JwsSigner(privateKey, projection, algorithm);
		} catch (KeyRejectedException | RuntimeException failure) {
			throw invalidKey();
		}
	}

	/**
	 * Returns a signer after bounded structural checks of an EC public point and its complete domain parameters.
	 * ES256 requires exactly P-256; ES384 requires exactly P-384. The optional domain seed is not significant.
	 * The private key must report EC and may remain opaque. This factory does not invoke JCA or test pair agreement;
	 * each signing operation verifies its actual signature against the independent public snapshot before release.
	 *
	 * @param privateKey the application-owned EC private key, retained by reference without encoding
	 * @param publicKey the inspectable EC public key, snapshotted without encoding
	 * @param algorithm exactly ES256 or ES384
	 * @return the signer
	 * @throws NullPointerException if a required argument is null
	 * @throws IllegalArgumentException if the algorithm, public point or domain parameters are unsupported or invalid
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull JwsSigner fromEcKeyPair(@NonNull PrivateKey privateKey, @NonNull PublicKey publicKey,
			@NonNull JwsAlgorithm algorithm) {
		requireNonNull(privateKey); requireNonNull(publicKey); requireNonNull(algorithm);
		EcCurve curve = switch (algorithm) {
			case ES256 -> EcCurve.P_256;
			case ES384 -> EcCurve.P_384;
			default -> throw invalidEcKey();
		};
		try {
			if (!(publicKey instanceof ECPublicKey ecKey)
					|| !"EC".equalsIgnoreCase(privateKey.getAlgorithm())
					|| !"EC".equalsIgnoreCase(publicKey.getAlgorithm())) throw invalidEcKey();
			ECParameterSpec parameters = snapshotEcParameters(requireNonNull(ecKey.getParams()), curve);
			if (!curve.isDescribedBy(parameters)) throw invalidEcKey();
			ECPoint point = requireNonNull(ecKey.getW());
			EcPublicProjection projection = new EcPublicProjection(curve,
					snapshotEcInteger(requireNonNull(point.getAffineX()), curve),
					snapshotEcInteger(requireNonNull(point.getAffineY()), curve));
			EcPublicKeys.checkPublicKey(curve, projection);
			return new JwsSigner(privateKey, projection, algorithm, curve.getSignatureLength(), curve);
		} catch (KeyRejectedException | RuntimeException failure) { throw invalidEcKey(); }
	}

	/**
	 * Returns a signer for pure Ed25519 with the fully specified {@code Ed25519} JWS algorithm identifier.
	 * The public key must name Ed25519 and its bounded point must decode canonically and not have small order.
	 * Its point and parameters are snapshotted without encoding. The private key may remain opaque and must report
	 * Ed25519 or EdDSA; if it exposes {@link EdECKey} parameters, those must name Ed25519. Private key bytes are never
	 * read. Construction invokes no JCA provider or signing probe; every actual operation verifies
	 * its signature against the checked public snapshot before release. Legacy {@code EdDSA} is not emitted.
	 *
	 * @param privateKey the application-owned private key, retained by reference without encoding
	 * @param publicKey the inspectable Ed25519 public key, snapshotted without encoding
	 * @return the signer using {@link JwsAlgorithm#ED25519}
	 * @throws NullPointerException if a required argument is null
	 * @throws IllegalArgumentException if a supplied key or inspectable parameter is structurally invalid or unsupported
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull JwsSigner fromEd25519KeyPair(@NonNull PrivateKey privateKey, @NonNull PublicKey publicKey) {
		requireNonNull(privateKey); requireNonNull(publicKey);
		try {
			if (!(publicKey instanceof EdECPublicKey edKey) || !ed25519Algorithm(privateKey.getAlgorithm())
					|| !ed25519Algorithm(publicKey.getAlgorithm())) throw invalidEd25519Key();
			if (privateKey instanceof EdECKey inspectable
					&& !"Ed25519".equals(requireNonNull(inspectable.getParams()).getName())) throw invalidEd25519Key();
			if (!"Ed25519".equals(requireNonNull(edKey.getParams()).getName())) throw invalidEd25519Key();
			EdECPoint point = requireNonNull(edKey.getPoint());
			Ed25519PublicProjection projection = new Ed25519PublicProjection(snapshotEd25519Y(requireNonNull(point.getY())),
					point.isXOdd());
			Ed25519PublicKeys.checkPublicKey(projection);
			return new JwsSigner(privateKey, projection, JwsAlgorithm.ED25519, Ed25519PublicKeys.SIGNATURE_LENGTH, null);
		} catch (KeyRejectedException | RuntimeException failure) { throw invalidEd25519Key(); }
	}

	/**
	 * Returns the one selected signing algorithm.
	 * @return the selected signing algorithm
	 * @since 1.0.0
	 */
	public @NonNull JwsAlgorithm getAlgorithm() { return this.algorithm; }

	/**
	 * Returns the stable, inspectable checked public projection. It does not expose private material, and its
	 * encoding and format are absent; applications retain their original public key when an encoded key is needed.
	 * @return the checked public key
	 * @since 1.0.0
	 */
	public @NonNull PublicKey getPublicKey() { return this.publicKey; }

	/**
	 * Starts a signing builder with the required protected-header metadata and outbound claims. Construction does
	 * not serialize claims or invoke a provider. The builder's {@link Builder#build()} signs and returns a compact
	 * JWT, using a two-second operation budget unless overridden. The algorithm always comes from this signer.
	 *
	 * @param header the required header metadata
	 * @param claims the required outbound claims; construction does not establish that they are trusted or valid
	 * @return a new signing builder
	 * @throws NullPointerException if a required argument is null
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull Builder withHeaderAndClaims(@NonNull JwtSigningHeader header, @NonNull JwtClaimsSet claims) {
		return new Builder(this, header, claims);
	}

	/**
	 * Signs the header metadata and outbound claims with the default two-second operation budget, returning a
	 * compact JWT credential. Equivalent to {@code withHeaderAndClaims(header, claims).build()}. The algorithm
	 * comes from this signer, and the claims' application meaning remains the caller's responsibility.
	 *
	 * @param header the required header metadata
	 * @param claims the required outbound claims
	 * @return the verified compact JWT credential; keep it out of logs
	 * @throws NullPointerException if a required argument is null
	 * @throws IllegalArgumentException if the serialized claims exceed the signing JSON profile or size limits
	 * @throws JwsSigningException if signing, pair verification or the operation budget fails
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull String fromHeaderAndClaims(@NonNull JwtSigningHeader header, @NonNull JwtClaimsSet claims) {
		return withHeaderAndClaims(header, claims).build();
	}

	/**
	 * Signs the exact accepted UTF-8 claims bytes and returns a compact JWS credential, an explicit secret emission.
	 * Claims are one strict JSON object under the existing JOSE defaults, limited to 32 KiB; their semantics belong
	 * to the caller. Arrays are snapshotted after length checks. The fixed protected header holds only alg, typ and
	 * optional kid/x5t#S256, is limited to 4 KiB encoded, and the final compact credential to 64 KiB.
	 *
	 * @param type exactly client-authentication+jwt, JWT or at+jwt
	 * @param keyId a nonempty key identifier of at most 256 characters, or null for none
	 * @param certificateSha256Thumbprint exactly 32 bytes, SHA-256 of a DER certificate, or null for none
	 * @param claimsUtf8 strict UTF-8 JSON object bytes; the accepted bytes are signed without reserialization
	 * @param remainingBudget the caller's remaining monotonic budget; nonpositive values are exhausted
	 * @return the verified compact JWS credential; keep it out of logs
	 * @throws NullPointerException if a required argument is null
	 * @throws IllegalArgumentException if a supplied type, identifier, digest or claims input is invalid
	 * @throws JwsSigningException if signing, pair verification or the remaining budget fails
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public @NonNull String toCompactSerialization(@NonNull String type, @Nullable String keyId,
			byte @Nullable [] certificateSha256Thumbprint, byte @NonNull [] claimsUtf8,
			@NonNull Duration remainingBudget) {
		requireNonNull(type);
		requireNonNull(claimsUtf8);
		requireNonNull(remainingBudget);
		return toCompactSerialization(type, keyId, certificateSha256Thumbprint, claimsUtf8, deadline(remainingBudget));
	}

	private @NonNull String toCompactSerialization(@NonNull String type, @Nullable String keyId,
			byte @Nullable [] certificateSha256Thumbprint, byte @NonNull [] claimsUtf8, @NonNull Deadline deadline) {
		if (!(type.equals("client-authentication+jwt") || type.equals("JWT") || type.equals("at+jwt")))
			throw invalidInput();
		if (keyId != null && (keyId.isEmpty() || keyId.length() > JwkParser.MAXIMUM_KEY_ID_LENGTH))
			throw invalidInput();
		if (certificateSha256Thumbprint != null && certificateSha256Thumbprint.length != CERTIFICATE_DIGEST_LENGTH)
			throw invalidInput();
		if (claimsUtf8.length > MAXIMUM_CLAIMS_LENGTH) throw invalidInput();
		byte[] claims = claimsUtf8.clone();
		byte @Nullable [] digest = certificateSha256Thumbprint == null ? null : certificateSha256Thumbprint.clone();
		byte @Nullable [] header = null;
		byte @Nullable [] input = null;
		byte @Nullable [] signature = null;
		try {
			checkBudget(deadline);
			try {
				if (!(JsonCodec.parse(claims, CLAIM_LIMITS) instanceof JsonObject)) throw invalidInput();
			} catch (JsonParseException failure) { throw invalidInput(); }
			checkBudget(deadline);
			String wireAlgorithm = this.algorithm.getWireValue();
			@Nullable String thumbprint = digest == null ? null : Base64Url.encode(digest);
			long headerBytes = 15L + jsonStringBytes(wireAlgorithm) + jsonStringBytes(type);
			if (keyId != null) headerBytes += 7L + jsonStringBytes(keyId);
			if (thumbprint != null) headerBytes += 12L + jsonStringBytes(thumbprint);
			if (encodedLength(headerBytes) > MAXIMUM_HEADER_LENGTH) throw invalidInput();
			JsonObject.Builder builder = JsonObject.builder().put("alg", wireAlgorithm).put("typ", type);
			if (keyId != null) builder.put("kid", keyId);
			if (thumbprint != null) builder.put("x5t#S256", thumbprint);
			header = JsonCodec.toUtf8Bytes(builder.build());
			long headerLength = encodedLength(header.length);
			long claimsLength = encodedLength(claims.length);
			if (headerLength > MAXIMUM_HEADER_LENGTH || headerLength + claimsLength + 2L
					+ encodedLength(this.signatureLength) > MAXIMUM_COMPACT_LENGTH) throw invalidInput();
			checkBudget(deadline);
			String signingInput = Base64Url.encode(header) + "." + Base64Url.encode(claims);
			input = signingInput.getBytes(StandardCharsets.US_ASCII);
			signature = signAndVerify(input, deadline);
			String compact = signingInput + "." + Base64Url.encode(signature);
			if (compact.length() > MAXIMUM_COMPACT_LENGTH) throw invalidInput();
			checkBudget(deadline);
			return compact;
		} finally {
			Arrays.fill(claims, (byte) 0);
			clear(digest); clear(header); clear(input); clear(signature);
		}
	}

	/**
	 * Explicitly signs and verifies a fixed internal noncredential probe without returning a credential.
	 * It runs on the caller thread; trusted providers must cooperate with the budget (see the class description).
	 * @param remainingBudget the caller's remaining monotonic budget
	 * @throws NullPointerException if remainingBudget is null
	 * @throws JwsSigningException if signing, pair verification or the budget fails
	 * @since 1.0.0
	 */
	public void warmUp(@NonNull Duration remainingBudget) {
		Deadline deadline = deadline(requireNonNull(remainingBudget));
		byte[] input = PROBE.getBytes(StandardCharsets.US_ASCII);
		byte @Nullable [] signature = null;
		try { signature = signAndVerify(input, deadline); checkBudget(deadline); }
		finally { clear(input); clear(signature); }
	}

	/**
	 * Returns a description without key or credential contents.
	 * @return the redacted description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() { return "JwsSigner{key=<redacted>}"; }

	/**
	 * Configures one signing operation. Header and claims are immutable snapshots; the builder owns no credential.
	 * Each {@link #build()} starts a fresh budget, serializes the claims and signs on the caller thread. A trusted
	 * JCA provider must cooperate with the budget; it cannot be forcibly interrupted. Callers enforcing an original
	 * deadline must also recheck it after the operation.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private final @NonNull JwsSigner signer;
		private final @NonNull JwtSigningHeader header;
		private final @NonNull JwtClaimsSet claims;
		private @NonNull Duration remainingBudget = DEFAULT_REMAINING_BUDGET;

		private Builder(@NonNull JwsSigner signer, @NonNull JwtSigningHeader header, @NonNull JwtClaimsSet claims) {
			this.signer = requireNonNull(signer);
			this.header = requireNonNull(header);
			this.claims = requireNonNull(claims);
		}

		/**
		 * Sets the budget measured from entry to {@link #build()}, including claims serialization and signing.
		 * Nonpositive values are exhausted and cause {@code build()} to fail without signing.
		 *
		 * @param remainingBudget the remaining operation allowance, or null to restore the two-second default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder remainingBudget(@Nullable Duration remainingBudget) {
			this.remainingBudget = remainingBudget == null ? DEFAULT_REMAINING_BUDGET : remainingBudget;
			return this;
		}

		/**
		 * Serializes the outbound claims, signs them and verifies the signature before returning the compact JWT.
		 * This is an explicit credential emission; it does not validate the application meaning of the claims.
		 *
		 * @return the verified compact JWT credential; keep it out of logs
		 * @throws IllegalArgumentException if the claims exceed the signing JSON profile or size limits
		 * @throws JwsSigningException if signing, pair verification or the operation budget fails
		 * @since 1.0.0
		 */
		public @NonNull String build() {
			Deadline deadline = deadline(this.remainingBudget);
			JsonObject json = this.claims.toJsonObject();
			// Bound the expanded tree before the general JSON writer allocates its output. Shared subtrees can
			// otherwise expand exponentially despite the immutable JSON model's depth limit.
			claimsLength(json, deadline);
			byte[] claimsUtf8 = JsonCodec.toUtf8Bytes(json);
			byte @Nullable [] digest = this.header.getCertificateSha256Thumbprint().orElse(null);
			try {
				checkBudget(deadline);
				return this.signer.toCompactSerialization(this.header.getType().getWireValue(),
						this.header.getKeyId().orElse(null), digest, claimsUtf8, deadline);
			} finally { clear(claimsUtf8); clear(digest); }
		}

		/**
		 * Returns a description without the header, claims, key or credential.
		 * @return the redacted description
		 * @since 1.0.0
		 */
		@Override
		public @NonNull String toString() { return "JwsSigner.Builder{input=<redacted>}"; }
	}

	private static int claimsLength(@NonNull JsonValue value, @NonNull Deadline deadline) {
		checkBudget(deadline);
		int length;
		if (value instanceof JsonObject object) {
			length = 2;
			boolean first = true;
			for (var member : object.getMembers().entrySet()) {
				length = addClaimsLength(length, claimsStringLength(member.getKey()) + (first ? 1 : 2));
				length = addClaimsLength(length, claimsLength(member.getValue(), deadline));
				first = false;
			}
		} else if (value instanceof JsonArray array) {
			length = 2;
			boolean first = true;
			for (JsonValue element : array.getElements()) {
				length = addClaimsLength(length, (first ? 0 : 1) + claimsLength(element, deadline));
				first = false;
			}
		} else if (value instanceof JsonString string) length = claimsStringLength(string.getValue());
		else if (value instanceof JsonNumber number) length = number.getValue().toString().length();
		else if (value instanceof JsonBoolean bool) length = bool.getValue() ? 4 : 5;
		else length = 4;
		return addClaimsLength(0, length);
	}

	private static int claimsStringLength(@NonNull String value) {
		if (value.length() > MAXIMUM_CLAIMS_LENGTH) throw invalidInput();
		return jsonStringBytes(value);
	}

	private static int addClaimsLength(int length, int additional) {
		if (additional > MAXIMUM_CLAIMS_LENGTH - length) throw invalidInput();
		return length + additional;
	}

	private byte @NonNull [] signAndVerify(byte @NonNull [] input, @NonNull Deadline deadline) {
		checkBudget(deadline);
		byte[] signature;
		try {
			Signature engine = Signature.getInstance(this.algorithm == JwsAlgorithm.ED25519 ? "Ed25519"
					: this.ecCurve != null ? hash().getEcdsaSignatureName()
					: isRsaPss(this.algorithm) ? "RSASSA-PSS" : hash().getRsaSignatureName());
			engine.initSign(this.privateKey);
			checkBudget(deadline);
			if (isRsaPss(this.algorithm)) engine.setParameter(hash().getPssParameterSpec());
			checkBudget(deadline);
			engine.update(input);
			checkBudget(deadline);
			signature = requireNonNull(engine.sign());
			if (this.ecCurve != null) {
				byte[] der = signature;
				try {
					checkBudget(deadline);
					signature = EcdsaSignatures.toJose(this.ecCurve, der);
				} finally { clear(der); }
			}
		} catch (GeneralSecurityException | RuntimeException failure) {
			checkBudget(deadline);
			throw JwsSigningException.fromReason(JwsSigningException.Reason.SIGNING_UNAVAILABLE);
		}
		try {
			checkBudget(deadline);
			VerifyResult result = this.algorithm == JwsAlgorithm.ED25519
					? SignatureVerifier.verifyEd25519(this.publicKey, input, signature)
					: this.ecCurve != null
					? SignatureVerifier.verifyEcdsa(this.ecCurve, hash(), this.publicKey, input, signature)
					: isRsaPss(this.algorithm) ? SignatureVerifier.verifyRsaPss(hash(), this.publicKey, input, signature)
					: SignatureVerifier.verifyRsaPkcs1(hash(), this.publicKey, input, signature);
			checkBudget(deadline);
			if (result != VerifyResult.VALID)
				throw JwsSigningException.fromReason(result == VerifyResult.MISMATCH
						? JwsSigningException.Reason.KEY_PAIR_MISMATCH : JwsSigningException.Reason.SIGNING_UNAVAILABLE);
			return signature;
		} catch (RuntimeException | Error failure) {
			clear(signature);
			throw failure;
		}
	}

	private @NonNull HashAlgorithm hash() { return requireNonNull(this.hash); }

	private static boolean ed25519Algorithm(@Nullable String algorithm) {
		return "Ed25519".equalsIgnoreCase(algorithm) || "EdDSA".equalsIgnoreCase(algorithm);
	}

	private static @NonNull BigInteger snapshotEd25519Y(@NonNull BigInteger value) {
		if (value.bitLength() < 0 || value.bitLength() > 255) throw invalidEd25519Key();
		byte[] bytes = value.toByteArray();
		if (bytes.length == 0 || bytes.length > Ed25519PublicKeys.KEY_LENGTH) throw invalidEd25519Key();
		BigInteger snapshot = new BigInteger(bytes);
		if (snapshot.signum() < 0 || snapshot.bitLength() > 255) throw invalidEd25519Key();
		return snapshot;
	}

	private static @NonNull Deadline deadline(@NonNull Duration remainingBudget) {
		if (remainingBudget.isNegative() || remainingBudget.isZero())
			throw JwsSigningException.fromReason(JwsSigningException.Reason.BUDGET_EXHAUSTED);
		return Deadline.fromNow(remainingBudget);
	}

	private static void checkBudget(@NonNull Deadline deadline) {
		if (deadline.isExpired()) throw JwsSigningException.fromReason(JwsSigningException.Reason.BUDGET_EXHAUSTED);
	}

	private static boolean rsaAlgorithm(@NonNull String algorithm) {
		return algorithm.equalsIgnoreCase("RSA") || isPss(algorithm);
	}

	private static boolean isPss(@NonNull String algorithm) { return algorithm.equalsIgnoreCase("RSASSA-PSS"); }

	private static @NonNull BigInteger snapshotInteger(@NonNull BigInteger value, int maximumBits, int maximumBytes) {
		if (value.bitLength() < 1 || value.bitLength() > maximumBits) throw invalidKey();
		byte[] bytes = value.toByteArray();
		if (bytes.length == 0 || bytes.length > maximumBytes) throw invalidKey();
		return new BigInteger(bytes);
	}

	private static @NonNull ECParameterSpec snapshotEcParameters(@NonNull ECParameterSpec parameters,
			@NonNull EcCurve curve) {
		EllipticCurve domain = requireNonNull(parameters.getCurve());
		if (!(domain.getField() instanceof ECFieldFp field)) throw invalidEcKey();
		ECPoint generator = requireNonNull(parameters.getGenerator());
		return new ECParameterSpec(new EllipticCurve(new ECFieldFp(snapshotEcInteger(field.getP(), curve)),
				snapshotEcInteger(domain.getA(), curve), snapshotEcInteger(domain.getB(), curve)),
				new ECPoint(snapshotEcInteger(requireNonNull(generator.getAffineX()), curve),
						snapshotEcInteger(requireNonNull(generator.getAffineY()), curve)),
				snapshotEcInteger(parameters.getOrder(), curve), parameters.getCofactor());
	}

	private static @NonNull BigInteger snapshotEcInteger(@NonNull BigInteger value, @NonNull EcCurve curve) {
		int bits = curve.getCoordinateLength() * Byte.SIZE;
		if (value.bitLength() < 0 || value.bitLength() > bits) throw invalidEcKey();
		byte[] bytes = value.toByteArray();
		if (bytes.length == 0 || bytes.length > curve.getCoordinateLength() + 1) throw invalidEcKey();
		BigInteger snapshot = new BigInteger(bytes);
		if (snapshot.signum() < 0 || snapshot.bitLength() > bits) throw invalidEcKey();
		return snapshot;
	}

	private static boolean isRsaPss(@NonNull JwsAlgorithm algorithm) {
		return algorithm == JwsAlgorithm.PS256 || algorithm == JwsAlgorithm.PS384 || algorithm == JwsAlgorithm.PS512;
	}

	private static @Nullable PSSParameterSpec snapshotParameters(@Nullable AlgorithmParameterSpec parameters,
			@NonNull HashAlgorithm hash) {
		if (parameters == null) return null;
		if (!(parameters instanceof PSSParameterSpec pss) || !(pss.getMGFParameters() instanceof MGF1ParameterSpec mgf))
			throw invalidKey();
		// Public restrictions must permit this fixed JWS digest/MGF1 pair and digest-sized salt. Private-provider
		// restrictions remain provider-owned and must succeed with those exact parameters during each operation.
		if (!pss.getDigestAlgorithm().equalsIgnoreCase(hash.getDigestName()) || !pss.getMGFAlgorithm().equalsIgnoreCase("MGF1")
				|| !mgf.getDigestAlgorithm().equalsIgnoreCase(hash.getDigestName())) throw invalidKey();
		int saltLength = pss.getSaltLength();
		if (saltLength < 0 || saltLength > hash.getLength() || pss.getTrailerField() != 1) throw invalidKey();
		return new PSSParameterSpec(hash.getDigestName(), "MGF1", new MGF1ParameterSpec(hash.getDigestName()), saltLength, 1);
	}

	private static long encodedLength(long bytes) { return 4L * (bytes / 3L) + (bytes % 3L == 0 ? 0 : bytes % 3L + 1L); }

	private static int jsonStringBytes(@NonNull String value) {
		int bytes = 2;
		for (int index = 0; index < value.length(); ++index) {
			char character = value.charAt(index);
			if (character == '"' || character == '\\' || character == '\b' || character == '\f'
					|| character == '\n' || character == '\r' || character == '\t') bytes += 2;
			else if (character < 0x20) bytes += 6;
			else if (character < 0x80) ++bytes;
			else if (character < 0x800) bytes += 2;
			else if (Character.isHighSurrogate(character)) {
				if (++index >= value.length() || !Character.isLowSurrogate(value.charAt(index))) throw invalidInput();
				bytes += 4;
			} else if (Character.isLowSurrogate(character)) throw invalidInput();
			else bytes += 3;
		}
		return bytes;
	}

	private static void clear(byte @Nullable [] bytes) { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
	private static @NonNull IllegalArgumentException invalidKey() {
		return new IllegalArgumentException("The RSA signing key or algorithm is invalid.");
	}
	private static @NonNull IllegalArgumentException invalidEcKey() {
		return new IllegalArgumentException("The EC signing key or algorithm is invalid.");
	}
	private static @NonNull IllegalArgumentException invalidEd25519Key() {
		return new IllegalArgumentException("The Ed25519 signing key is invalid.");
	}
	private static @NonNull IllegalArgumentException invalidInput() {
		return new IllegalArgumentException("The JWS signing input is invalid.");
	}

	@Immutable
	private static final class Ed25519PublicProjection implements EdECPublicKey {
		private static final long serialVersionUID = 1L;
		private final @NonNull BigInteger y;
		private final boolean xOdd;
		private Ed25519PublicProjection(@NonNull BigInteger y, boolean xOdd) { this.y = y; this.xOdd = xOdd; }
		@Override public @NonNull EdECPoint getPoint() { return new EdECPoint(this.xOdd, this.y); }
		@Override public @NonNull NamedParameterSpec getParams() { return new NamedParameterSpec("Ed25519"); }
		@Override public @NonNull String getAlgorithm() { return "Ed25519"; }
		@Override public @Nullable String getFormat() { return null; }
		@Override public byte @Nullable [] getEncoded() { return null; }
		@Override public @NonNull String toString() { return "Ed25519PublicKey{material=<redacted>}"; }
	}

	@Immutable
	private static final class EcPublicProjection implements ECPublicKey {
		private static final long serialVersionUID = 1L;
		private final @NonNull EcCurve curve;
		private final @NonNull BigInteger x;
		private final @NonNull BigInteger y;
		private EcPublicProjection(@NonNull EcCurve curve, @NonNull BigInteger x, @NonNull BigInteger y) {
			this.curve = curve; this.x = x; this.y = y;
		}
		@Override public @NonNull ECPoint getW() { return new ECPoint(this.x, this.y); }
		@Override public @NonNull ECParameterSpec getParams() { return this.curve.getParameterSpec(); }
		@Override public @NonNull String getAlgorithm() { return "EC"; }
		@Override public @Nullable String getFormat() { return null; }
		@Override public byte @Nullable [] getEncoded() { return null; }
		@Override public @NonNull String toString() { return "EcPublicKey{material=<redacted>}"; }
	}

	@Immutable
	private static final class PublicProjection implements RSAPublicKey {
		private static final long serialVersionUID = 1L;
		private final @NonNull BigInteger modulus;
		private final @NonNull BigInteger exponent;
		private final @NonNull String algorithm;
		// Canonical PSS facts retain restrictions even when the inherited RSA key serialization contract is used.
		private final boolean hasPssParameters;
		private final int minimumSaltLength;
		private final @NonNull String pssDigestName;
		private PublicProjection(@NonNull BigInteger modulus, @NonNull BigInteger exponent, @NonNull String algorithm,
				@Nullable PSSParameterSpec parameters) {
			this.modulus = modulus; this.exponent = exponent; this.algorithm = algorithm;
			this.hasPssParameters = parameters != null;
			this.minimumSaltLength = parameters == null ? 0 : parameters.getSaltLength();
			this.pssDigestName = parameters == null ? "SHA-256" : parameters.getDigestAlgorithm();
		}
		private int signatureLength() { return (this.modulus.bitLength() + 7) / 8; }
		@Override public @NonNull BigInteger getModulus() { return this.modulus; }
		@Override public @NonNull BigInteger getPublicExponent() { return this.exponent; }
		@Override public @NonNull String getAlgorithm() { return this.algorithm; }
		@Override public @Nullable AlgorithmParameterSpec getParams() {
			return this.hasPssParameters ? new PSSParameterSpec(this.pssDigestName, "MGF1", new MGF1ParameterSpec(this.pssDigestName),
					this.minimumSaltLength, 1) : null;
		}
		@Override public @Nullable String getFormat() { return null; }
		@Override public byte @Nullable [] getEncoded() { return null; }
		@Override public @NonNull String toString() { return "RsaPublicKey{material=<redacted>}"; }
	}
}
