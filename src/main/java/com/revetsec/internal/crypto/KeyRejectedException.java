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
import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * A checked refusal of public key material or an HMAC secret by the key policy of {@link RsaPublicKeys},
 * {@link EcPublicKeys}, {@link Ed25519PublicKeys} or {@link Hmac}.
 * <p>
 * The protocol packages translate the {@link Kind} into their own terms: a JSON Web Key is skipped with a reason, and
 * a configured key fails configuration. The message is the fixed sentence of its kind. The exception has no cause,
 * suppression is disabled, and it records no stack trace, so nothing about it depends on the key material or on the
 * JCA provider. It never leaves Revetsec.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
public final class KeyRejectedException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Why the key was refused.
	 */
	@NonNull
	private final Kind kind;

	/**
	 * Why key material was refused, in the order the checks run for each key type.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum Kind {
		/**
		 * The encoding is wrong: a component of the wrong length, a non-minimal RSA integer, an even RSA modulus, an
		 * Ed25519 encoding that does not decode to a curve point (RFC 8032 section 5.1.3), a key whose parameters are
		 * not the expected curve, or key material the JCA provider refused after every check passed.
		 */
		MALFORMED("The key is malformed."),
		/**
		 * The RSA modulus is shorter than {@value RsaPublicKeys#MINIMUM_MODULUS_BITS} or longer than
		 * {@value RsaPublicKeys#MAXIMUM_MODULUS_BITS} bits.
		 */
		RSA_KEY_SIZE("The RSA modulus size is not allowed."),
		/**
		 * The RSA public exponent is even, below 65537, or at least 2^32.
		 */
		RSA_EXPONENT("The RSA public exponent is not allowed."),
		/**
		 * An EC coordinate is not below the field prime, the point is not on the curve, or it is the point at
		 * infinity.
		 */
		NOT_ON_CURVE("The EC point is not on the curve."),
		/**
		 * The key is structurally valid but known to be weak: an RSA modulus with the ROCA fingerprint, or an Ed25519
		 * point of small order.
		 */
		WEAK("The key is weak."),
		/**
		 * An HMAC secret is shorter than the output of its hash function.
		 */
		SECRET_TOO_SHORT("The HMAC secret is shorter than the hash output.");

		@NonNull
		private final String message;

		Kind(@NonNull String message) {
			this.message = message;
		}

		/**
		 * Returns the fixed message for this kind.
		 *
		 * @return the message, which never contains input
		 */
		@NonNull
		public String getMessage() {
			return this.message;
		}
	}

	KeyRejectedException(@NonNull Kind kind) {
		super(requireNonNull(kind).getMessage(), null, false, false);
		this.kind = kind;
	}

	/**
	 * Returns why the key was refused.
	 *
	 * @return the kind of refusal
	 */
	@NonNull
	public Kind getKind() {
		return this.kind;
	}
}
