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

import javax.annotation.concurrent.Immutable;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * The hash functions of the signature and MAC algorithms Revetsec verifies, with the JCA names each one pins.
 * <p>
 * The helpers in this package are written in hash and curve terms, never in protocol terms, so that JOSE and XML
 * signature processing share them. Mapping a protocol's algorithm identifier to a hash, a curve and a family is the
 * protocol package's job. Algorithm names are pinned; JCA providers are not.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public enum HashAlgorithm {
	/**
	 * SHA-256, with a 32-byte output.
	 */
	SHA_256("SHA-256", 32, "SHA256withRSA", "SHA256withECDSA", "HmacSHA256"),
	/**
	 * SHA-384, with a 48-byte output.
	 */
	SHA_384("SHA-384", 48, "SHA384withRSA", "SHA384withECDSA", "HmacSHA384"),
	/**
	 * SHA-512, with a 64-byte output.
	 */
	SHA_512("SHA-512", 64, "SHA512withRSA", "SHA512withECDSA", "HmacSHA512");

	@NonNull
	private final String digestName;
	private final int length;
	@NonNull
	private final String rsaSignatureName;
	@NonNull
	private final String ecdsaSignatureName;
	@NonNull
	private final String hmacName;

	HashAlgorithm(@NonNull String digestName,
								int length,
								@NonNull String rsaSignatureName,
								@NonNull String ecdsaSignatureName,
								@NonNull String hmacName) {
		this.digestName = digestName;
		this.length = length;
		this.rsaSignatureName = rsaSignatureName;
		this.ecdsaSignatureName = ecdsaSignatureName;
		this.hmacName = hmacName;
	}

	/**
	 * Returns the JCA {@code MessageDigest} name, such as {@code SHA-256}.
	 *
	 * @return the digest name
	 */
	@NonNull
	public String getDigestName() {
		return this.digestName;
	}

	/**
	 * Returns the length of the hash output, in bytes.
	 *
	 * @return 32, 48 or 64
	 */
	public int getLength() {
		return this.length;
	}

	/**
	 * Returns the JCA name of RSASSA-PKCS1-v1_5 with this hash, such as {@code SHA256withRSA}.
	 *
	 * @return the signature algorithm name
	 */
	@NonNull
	public String getRsaSignatureName() {
		return this.rsaSignatureName;
	}

	/**
	 * Returns the JCA name of ECDSA with this hash over a DER-encoded signature, such as {@code SHA256withECDSA}.
	 * Revetsec re-encodes fixed-length {@code r || s} signatures as DER itself (see {@link EcdsaSignatures}), because
	 * the DER form works with any JCA provider, including hardware-backed and approved-mode ones.
	 *
	 * @return the signature algorithm name
	 */
	@NonNull
	public String getEcdsaSignatureName() {
		return this.ecdsaSignatureName;
	}

	/**
	 * Returns the JCA {@code Mac} name of HMAC with this hash, such as {@code HmacSHA256}.
	 *
	 * @return the MAC algorithm name
	 */
	@NonNull
	public String getHmacName() {
		return this.hmacName;
	}

	/**
	 * Returns the fixed RSASSA-PSS parameters for this hash: MGF1 with the same hash, a salt as long as the hash
	 * output, and the trailer field 1 (RFC 7518 section 3.5; RFC 8017 section 9.1). They never come from the message.
	 *
	 * @return new parameters for {@code Signature.setParameter}
	 */
	@NonNull
	public PSSParameterSpec getPssParameterSpec() {
		return new PSSParameterSpec(this.digestName, "MGF1", new MGF1ParameterSpec(this.digestName), this.length,
				PSSParameterSpec.TRAILER_FIELD_BC);
	}
}
