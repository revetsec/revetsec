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

package com.revetsec.internal.pem;

import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * Checked failure of {@link Pem} (M1 plan, G6-2).
 * <p>
 * The message is the fixed sentence of its {@link Kind} and never contains any part of the input: not the label,
 * not the Base64 text and not the JDK's own parser message. The JDK's exception is dropped rather than kept as the
 * cause, since its message can quote the input. Suppression is disabled.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@NotThreadSafe
public final class PemException extends Exception {
	private static final long serialVersionUID = 1L;

	/**
	 * Why the input was rejected.
	 */
	private final @NonNull Kind kind;

	/**
	 * What was wrong with the input. Each kind has one fixed message.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 */
	@Immutable
	public enum Kind {
		/**
		 * The text is not exactly one PEM block: a missing or malformed boundary line, an END label that differs from
		 * the BEGIN label, text before or after the block, a second block, or an encapsulated header.
		 */
		MALFORMED_ARMOR("The PEM text is not exactly one well-formed block."),
		/**
		 * The label is not one the operation accepts.
		 */
		UNSUPPORTED_LABEL("The PEM label is not supported by this operation."),
		/**
		 * A SEC1 {@code EC PRIVATE KEY} block (RFC 5915), which Revetsec does not read.
		 */
		SEC1_PRIVATE_KEY("SEC1 EC PRIVATE KEY blocks are not supported; convert the key with "
				+ "openssl pkcs8 -topk8 -nocrypt, or load it from a PKCS#12 KeyStore."),
		/**
		 * An encrypted private key: an {@code ENCRYPTED PRIVATE KEY} block, or a legacy block with a
		 * {@code Proc-Type} header.
		 */
		ENCRYPTED_PRIVATE_KEY("Encrypted private keys are not supported; decrypt the key with "
				+ "openssl pkcs8 -topk8 -nocrypt, or load it from a PKCS#12 KeyStore."),
		/**
		 * The body is not canonical padded Base64.
		 */
		INVALID_BASE64("The PEM body is not canonical Base64."),
		/**
		 * The body is not one well-formed DER structure of the expected shape (for example BER indefinite or
		 * non-minimal lengths, a truncated element, or a missing field).
		 */
		MALFORMED_DER("The PEM body is not a well-formed DER structure of the expected type."),
		/**
		 * Bytes follow the outer DER structure, or the one element inside a PKCS#8 {@code privateKey}. JDK 17 key
		 * factories and every JDK's certificate factory ignore bytes after the outer structure, and JDK key factories
		 * ignore bytes after an EdDSA key (and, before JDK 27, an EC key) inside {@code privateKey}.
		 */
		TRAILING_DATA("The DER structure is followed by trailing bytes."),
		/**
		 * The public key parses, but the input is not the one DER encoding of it: its {@code subjectPublicKey} BIT
		 * STRING has unused bits, or the JDK's encoding of the key, or of a key rebuilt from its values (an RSA
		 * modulus and exponent, an EC point and curve), differs from the input. Or a certificate's
		 * {@code getEncoded()} differs from the input.
		 */
		NON_CANONICAL("The DER encoding does not round-trip."),
		/**
		 * The key's algorithm, or its algorithm parameters, are not supported (for example X25519, RSASSA-PSS, or EC
		 * with explicit curve parameters).
		 */
		UNSUPPORTED_ALGORITHM("The key algorithm or its parameters are not supported."),
		/**
		 * The JDK rejected the key material, or an EdDSA public key's y-coordinate is not below the field prime
		 * (RFC 8032 sections 5.1.3 and 5.2.3).
		 */
		INVALID_KEY("The key could not be decoded."),
		/**
		 * The JDK rejected the certificate.
		 */
		INVALID_CERTIFICATE("The certificate could not be decoded.");

		private final @NonNull String message;

		Kind(@NonNull String message) {
			this.message = message;
		}

		/**
		 * The fixed message for this kind.
		 *
		 * @return the message, which never contains input
		 */
		public @NonNull String getMessage() {
			return this.message;
		}
	}

	PemException(@NonNull Kind kind) {
		super(requireNonNull(kind).getMessage(), null, false, true);
		this.kind = kind;
	}

	/**
	 * Why the input was rejected.
	 *
	 * @return the kind of failure
	 */
	public @NonNull Kind getKind() {
		return this.kind;
	}
}
