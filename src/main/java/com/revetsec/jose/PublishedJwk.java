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

import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.internal.crypto.EcCurve;
import com.revetsec.internal.crypto.EcPublicKeys;
import com.revetsec.internal.crypto.Ed25519PublicKeys;
import com.revetsec.internal.crypto.KeyRejectedException;
import com.revetsec.internal.crypto.RsaPublicKeys;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.jose.JwkParser;
import com.revetsec.internal.pem.Pem;
import com.revetsec.internal.pem.PemException;
import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.EdECPoint;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * An immutable public signing key for publication in a JSON Web Key Set (RFC 7517). RSA, EC on P-256, P-384 or
 * P-521, and Ed25519 public keys are supported; shared secrets and private keys cannot be published here.
 * <p>
 * Only the public key is required. The key identifier, algorithm and certificate chain are optional. No algorithm
 * is inferred when it is absent. Every key advertises {@code use=sig}.
 * <p>
 * Public parameters are copied when the builder starts, and certificate DER is copied and checked when its setter
 * is called. Neither the builder nor the built key retains caller-owned key or certificate objects. A certificate
 * chain supplies {@code x5c}, {@code x5t} and {@code x5t#S256}; certificate trust and validity periods are the
 * application's responsibility.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@Immutable
public final class PublishedJwk {
	private static final int MAXIMUM_CERTIFICATES = 16;
	private static final int MAXIMUM_CERTIFICATE_BYTES = 65_536;
	private static final int MAXIMUM_CHAIN_BYTES = 131_072;
	private final @Nullable String keyId;
	private final @Nullable JwsAlgorithm algorithm;
	private final @NonNull JsonObject json;

	private PublishedJwk(@NonNull Builder builder) {
		this.keyId = builder.keyId;
		this.algorithm = builder.algorithm;
		Map<String, JsonValue> members = new LinkedHashMap<>(builder.material.getMembers());
		members.put("use", JsonString.fromValue("sig"));
		if (this.keyId != null)
			members.put("kid", JsonString.fromValue(this.keyId));
		if (this.algorithm != null)
			members.put("alg", JsonString.fromValue(this.algorithm.getWireValue()));
		members.putAll(builder.certificates.getMembers());
		this.json = JsonObject.fromMembers(members);
	}

	/**
	 * Starts a builder with a checked snapshot of a public key.
	 *
	 * @param publicKey the public signing key
	 * @return the builder
	 * @throws NullPointerException if {@code publicKey} is {@code null}
	 * @throws IllegalArgumentException if the key is unsupported, malformed or refused by Revetsec's key policy
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull Builder withPublicKey(@NonNull PublicKey publicKey) {
		return new Builder(publicKey);
	}

	/**
	 * Returns a public signing key without optional metadata; equivalent to {@code withPublicKey(publicKey).build()}.
	 *
	 * @param publicKey the public signing key
	 * @return the immutable published key
	 * @throws NullPointerException if {@code publicKey} is {@code null}
	 * @throws IllegalArgumentException if the key is unsupported, malformed or refused by Revetsec's key policy
	 * @since 1.0.0
	 */
	@CheckReturnValue
	public static @NonNull PublishedJwk fromPublicKey(@NonNull PublicKey publicKey) {
		return withPublicKey(publicKey).build();
	}

	/**
	 * Returns the optional JWK {@code kid} value.
	 *
	 * @return the configured key identifier, or empty
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull String> getKeyId() {
		return Optional.ofNullable(this.keyId);
	}

	/**
	 * Returns the optional JWK {@code alg} value. No algorithm is inferred from the public key.
	 *
	 * @return the configured algorithm, or empty
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull JwsAlgorithm> getAlgorithm() {
		return Optional.ofNullable(this.algorithm);
	}

	/**
	 * Serializes this key's public JWK representation, including optional certificate metadata, to JSON text.
	 *
	 * @return the JWK JSON text; no private or symmetric key parameters are included
	 * @since 1.0.0
	 */
	public @NonNull String toJson() {
		return this.json.toJson();
	}

	/**
	 * Returns this key's immutable public JWK representation, including optional certificate metadata.
	 *
	 * @return the JWK; no private or symmetric key parameters are included
	 * @since 1.0.0
	 */
	public @NonNull JsonObject toJsonObject() {
		return this.json;
	}

	/**
	 * Describes this object without configured key identifiers, key parameters or certificate material.
	 *
	 * @return the description
	 * @since 1.0.0
	 */
	@Override
	public @NonNull String toString() {
		return "PublishedJwk{publicKey=<redacted>}";
	}

	private static @NonNull IllegalArgumentException invalidKey() {
		return new IllegalArgumentException("The published public key is unsupported, malformed or weak.");
	}

	/** Reads only public components, then validates independent, bounded copies of those components. */
	private static @NonNull JsonObject snapshot(@NonNull PublicKey key) {
		try {
			if (key instanceof RSAPublicKey rsa) {
				if (!"RSA".equalsIgnoreCase(rsa.getAlgorithm()) || rsa.getParams() != null)
					throw invalidKey();
				byte[] modulus = unsigned(rsa.getModulus(), RsaPublicKeys.MAXIMUM_MODULUS_BITS / Byte.SIZE);
				byte[] exponent = unsigned(rsa.getPublicExponent(), 4);
				RsaPublicKeys.fromComponents(modulus, exponent);
				return JsonObject.builder().put("kty", "RSA").put("n", base64Url(modulus))
						.put("e", base64Url(exponent)).build();
			}
			if (key instanceof ECPublicKey ec) {
				EcCurve curve = EcCurve.findByParameterSpec(requireNonNull(ec.getParams())).orElseThrow(
						PublishedJwk::invalidKey);
				ECPoint point = requireNonNull(ec.getW());
				byte[] x = coordinate(point.getAffineX(), curve.getCoordinateLength());
				byte[] y = coordinate(point.getAffineY(), curve.getCoordinateLength());
				EcPublicKeys.fromCoordinates(curve, x, y);
				return JsonObject.builder().put("kty", "EC").put("crv", curve.getName())
						.put("x", base64Url(x)).put("y", base64Url(y)).build();
			}
			if (key instanceof EdECPublicKey ed) {
				if (!NamedParameterSpec.ED25519.getName().equals(ed.getParams().getName()))
					throw invalidKey();
				EdECPoint point = requireNonNull(ed.getPoint());
				byte[] bigEndian = coordinate(point.getY(), Ed25519PublicKeys.KEY_LENGTH);
				byte[] encoded = new byte[Ed25519PublicKeys.KEY_LENGTH];
				for (int index = 0; index < encoded.length; index++)
					encoded[index] = bigEndian[encoded.length - index - 1];
				// The high bit belongs to x's sign, so y must fit in the remaining 255 bits.
				if ((encoded[encoded.length - 1] & 0x80) != 0)
					throw invalidKey();
				if (point.isXOdd())
					encoded[encoded.length - 1] |= (byte) 0x80;
				Ed25519PublicKeys.fromEncoded(encoded);
				return JsonObject.builder().put("kty", "OKP").put("crv", "Ed25519")
						.put("x", base64Url(encoded)).build();
			}
			throw invalidKey();
		} catch (KeyRejectedException | RuntimeException invalid) {
			throw invalidKey();
		}
	}

	private static byte @NonNull [] unsigned(@NonNull BigInteger value, int maximumBytes) {
		if (value.signum() < 0 || value.bitLength() > maximumBytes * Byte.SIZE)
			throw invalidKey();
		byte[] bytes = value.toByteArray();
		if (bytes.length == 0 || bytes.length > maximumBytes + 1)
			throw invalidKey();
		byte[] result = bytes.length > 1 && bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes.clone();
		if (result.length > maximumBytes || new BigInteger(1, result).compareTo(value) != 0)
			throw invalidKey();
		return result;
	}

	private static byte @NonNull [] coordinate(@NonNull BigInteger value, int length) {
		byte[] minimal = unsigned(value, length);
		byte[] padded = new byte[length];
		System.arraycopy(minimal, 0, padded, length - minimal.length, minimal.length);
		return padded;
	}

	private static @NonNull String base64Url(byte @NonNull [] bytes) {
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private static @NonNull String string(@NonNull JsonObject json, @NonNull String member) {
		return ((JsonString) requireNonNull(json.getMembers().get(member))).getValue();
	}

	private static void checkAlgorithm(@NonNull JsonObject material, @Nullable JwsAlgorithm algorithm) {
		if (algorithm == null)
			return;
		boolean compatible = switch (algorithm) {
			case RS256, RS384, RS512, PS256, PS384, PS512 -> string(material, "kty").equals("RSA");
			case ES256 -> "P-256".equals(material.getMembers().containsKey("crv") ? string(material, "crv") : null);
			case ES384 -> "P-384".equals(material.getMembers().containsKey("crv") ? string(material, "crv") : null);
			case ES512 -> "P-521".equals(material.getMembers().containsKey("crv") ? string(material, "crv") : null);
			case ED25519, EDDSA -> string(material, "kty").equals("OKP");
			default -> false;
		};
		if (!compatible)
			throw new IllegalArgumentException("The published algorithm is incompatible with the public key.");
	}

	private static @NonNull JsonObject snapshotCertificates(@NonNull JsonObject material,
			@Nullable List<@NonNull X509Certificate> chain) {
		if (chain == null || chain.isEmpty())
			return JsonObject.emptyInstance();
		if (chain.size() > MAXIMUM_CERTIFICATES)
			throw new IllegalArgumentException("The published certificate chain is too large.");
		List<X509Certificate> parsed = new ArrayList<>();
		List<JsonValue> encoded = new ArrayList<>();
		Set<String> unique = new HashSet<>();
		byte[] leaf = new byte[0];
		int total = 0;
		try {
			for (X509Certificate certificate : List.copyOf(chain)) {
				byte[] supplied = requireNonNull(certificate.getEncoded());
				if (supplied.length == 0 || supplied.length > MAXIMUM_CERTIFICATE_BYTES || supplied.length > MAXIMUM_CHAIN_BYTES - total)
					throw new IllegalArgumentException("The published certificate chain is too large.");
				byte[] der = supplied.clone();
				total += der.length;
				String text = Base64.getEncoder().encodeToString(der);
				if (!unique.add(text))
					throw new IllegalArgumentException("The published certificate chain contains a duplicate certificate.");
				parsed.add(Pem.parseCertificateDer(der));
				encoded.add(JsonString.fromValue(text));
				if (parsed.size() == 1)
					leaf = der;
			}
			X509Certificate first = parsed.get(0);
			if (!material.equals(snapshot(requireNonNull(first.getPublicKey()))))
				throw new IllegalArgumentException("The leaf certificate does not match the published public key.");
			boolean[] leafUsage = first.getKeyUsage();
			if (leafUsage != null && (leafUsage.length == 0 || !leafUsage[0]))
				throw new IllegalArgumentException("The leaf certificate does not permit digital signatures.");
			for (int index = 1; index < parsed.size(); index++) {
				X509Certificate child = parsed.get(index - 1);
				X509Certificate issuer = parsed.get(index);
				boolean[] usage = issuer.getKeyUsage();
				if (!child.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())
						|| issuer.getBasicConstraints() < 0 || (usage != null && (usage.length <= 5 || !usage[5])))
					throw new IllegalArgumentException("The published certificate chain is not in issuer order.");
				child.verify(issuer.getPublicKey());
			}
			return JsonObject.builder().put("x5c", JsonArray.fromElements(encoded))
					.put("x5t", base64Url(MessageDigest.getInstance("SHA-1").digest(leaf)))
					.put("x5t#S256", base64Url(MessageDigest.getInstance("SHA-256").digest(leaf))).build();
		} catch (GeneralSecurityException | PemException | RuntimeException invalid) {
			throw new IllegalArgumentException("The published certificate chain is malformed or inconsistent.");
		}
	}

	/**
	 * Configures an immutable published public key. Optional setters replace prior values; {@code null} clears them.
	 * Key parameters and certificate encodings are snapshotted before assignment.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private final @NonNull JsonObject material;
		private @Nullable String keyId;
		private @Nullable JwsAlgorithm algorithm;
		private @NonNull JsonObject certificates = JsonObject.emptyInstance();

		private Builder(@NonNull PublicKey publicKey) {
			this.material = snapshot(requireNonNull(publicKey));
		}

		/**
		 * Replaces the optional key identifier. It must contain 1–256 UTF-16 code units and valid Unicode.
		 *
		 * @param keyId the JWK {@code kid}, or {@code null} to clear it
		 * @return this builder
		 * @throws IllegalArgumentException if the identifier is empty, too long or invalid Unicode
		 * @since 1.0.0
		 */
		@CanIgnoreReturnValue
		public @NonNull Builder keyId(@Nullable String keyId) {
			if (keyId != null) {
				if (keyId.isEmpty() || keyId.length() > JwkParser.MAXIMUM_KEY_ID_LENGTH)
					throw new IllegalArgumentException("The published key identifier is invalid.");
				try {
					Arrays.fill(StrictUtf8.encode(keyId), (byte) 0);
				} catch (EncodingException invalid) {
					throw new IllegalArgumentException("The published key identifier is invalid.");
				}
			}
			this.keyId = keyId;
			return this;
		}

		/**
		 * Replaces the optional algorithm restriction. RSA supports RS256/384/512 and PS256/384/512; EC supports
		 * ES256, ES384 or ES512 on its corresponding curve; Ed25519 supports ED25519 and the legacy EDDSA name.
		 *
		 * @param algorithm the JWK {@code alg}, or {@code null} to omit it
		 * @return this builder
		 * @throws IllegalArgumentException if the algorithm does not match the key, including every HMAC algorithm
		 * @since 1.0.0
		 */
		@CanIgnoreReturnValue
		public @NonNull Builder algorithm(@Nullable JwsAlgorithm algorithm) {
			checkAlgorithm(this.material, algorithm);
			this.algorithm = algorithm;
			return this;
		}

		/**
		 * Replaces the certificate chain with a checked snapshot, leaf first. The leaf must match the public key and
		 * permit digital signatures when key usage is present. Each following certificate must be its predecessor's
		 * signing CA, with a matching issuer name and valid certificate signature. Duplicate certificates are refused.
		 * The chain need not end at a root; trust, validity periods and revocation are not evaluated.
		 * <p>
		 * At most 16 certificates, 64 KiB per DER certificate and 128 KiB of total DER are accepted. The leaf's SHA-1
		 * and SHA-256 thumbprints are derived for {@code x5t} and {@code x5t#S256}; SHA-1 is only a certificate identifier.
		 *
		 * @param certificateChain the leaf-first chain, or {@code null} or an empty list to clear certificate metadata
		 * @return this builder
		 * @throws IllegalArgumentException if the chain is oversized, malformed, inconsistent or mismatched
		 * @since 1.0.0
		 */
		@CanIgnoreReturnValue
		public @NonNull Builder certificateChain(@Nullable List<@NonNull X509Certificate> certificateChain) {
			this.certificates = snapshotCertificates(this.material, certificateChain);
			return this;
		}

		/**
		 * Returns a published key with the builder's current public parameters and metadata.
		 *
		 * @return the immutable public signing key
		 * @since 1.0.0
		 */
		public @NonNull PublishedJwk build() {
			return new PublishedJwk(this);
		}
	}
}
