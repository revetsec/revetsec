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

import com.revetsec.ErrorCategory;
import com.revetsec.RevetsecException;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;

import static java.util.Objects.requireNonNull;

/**
 * A rejected JOSE input: a token that {@link JwtValidator} refused, or a JSON Web Key Set document that
 * {@link JsonWebKeySet#fromJson(String)} refused.
 * <p>
 * Every instance has a {@link Reason}, which also fixes its class and {@link ErrorCategory}:
 * <ul>
 *   <li>{@link MalformedJoseInputException}: {@link ErrorCategory#MALFORMED_INPUT}, for input that could not be
 *   parsed or exceeded a limit;</li>
 *   <li>{@link UnsupportedJoseFeatureException}: {@link ErrorCategory#UNSUPPORTED}, for a JOSE feature Revetsec does
 *   not support, such as encryption;</li>
 *   <li>{@link JwtValidationException}: {@link ErrorCategory#VALIDATION_FAILURE}, for a well-formed token that failed a
 *   check.</li>
 * </ul>
 * The message is the reason's fixed sentence and never contains the token, a claim, a key or a key ID. A JOSE
 * exception has no cause and is never transient. Applications catch these exceptions; only Revetsec creates them.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@NotThreadSafe
public abstract sealed class JoseException extends RevetsecException
		permits MalformedJoseInputException, UnsupportedJoseFeatureException, JwtValidationException {
	/**
	 * The serialized form's version.
	 */
	private static final long serialVersionUID = 1L;

	/**
	 * Why the input was rejected; never {@code null}.
	 *
	 * @serial
	 */
	@NonNull
	private final Reason reason;

	/**
	 * Creates an exception for {@code reason}, with the reason's category and fixed message, no cause, and not
	 * transient. Only the three permitted subclasses call it, from their factories.
	 *
	 * @param reason the reason, whose category the subclass has checked
	 */
	JoseException(@NonNull Reason reason) {
		// The checks run inside the super(...) arguments, so a failed construction leaves no partial instance.
		super(requireNonNull(reason).category(), false, reason.message(), null);
		this.reason = reason;
	}

	/**
	 * Returns a new exception of the class that {@code reason} belongs to. Only Revetsec calls this.
	 *
	 * @param reason the reason
	 * @return a new {@link MalformedJoseInputException}, {@link UnsupportedJoseFeatureException} or
	 * {@link JwtValidationException}
	 */
	@NonNull
	static JoseException fromReason(@NonNull Reason reason) {
		requireNonNull(reason);

		return switch (reason.category()) {
			case MALFORMED_INPUT -> MalformedJoseInputException.fromReason(reason);
			case UNSUPPORTED -> UnsupportedJoseFeatureException.fromReason(reason);
			case VALIDATION_FAILURE -> JwtValidationException.fromReason(reason);
			default -> throw new IllegalArgumentException("A JOSE reason must be MALFORMED_INPUT, UNSUPPORTED or "
					+ "VALIDATION_FAILURE.");
		};
	}

	/**
	 * Returns why the input was rejected.
	 *
	 * @return the reason
	 * @since 1.0.0
	 */
	@NonNull
	public final Reason getReason() {
		return this.reason;
	}

	/**
	 * Why a JOSE input was rejected. Each reason belongs to exactly one exception class and category, and has one fixed
	 * message.
	 * <p>
	 * This enum is not switch-stable: a later release may add constants, so a {@code switch} over it needs a default
	 * branch.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@Immutable
	public enum Reason {
		/**
		 * The token is longer than the validator's maximum token length. Nothing else about it was examined.
		 * {@link MalformedJoseInputException}.
		 */
		TOKEN_TOO_LARGE(ErrorCategory.MALFORMED_INPUT, "The token is longer than the maximum token length."),
		/**
		 * The token is not a JWS compact serialization: a character outside the base64url alphabet and {@code .}, a
		 * number of dots other than two or four, an empty header, or a segment that is not canonical unpadded
		 * base64url (RFC 7515 sections 2 and 7.1). Four dots are {@link #ENCRYPTED_TOKEN}, and a leading left curly
		 * bracket is {@link #JSON_SERIALIZATION}. {@link MalformedJoseInputException}.
		 */
		TOKEN_SYNTAX(ErrorCategory.MALFORMED_INPUT, "The token is not a well-formed JWS compact serialization."),
		/**
		 * The JOSE header is not a strict UTF-8 JSON object within the limits, has duplicate members, has no string
		 * {@code alg}, or has a {@code kid} that is not a string of 1 to 256 characters.
		 * {@link MalformedJoseInputException}.
		 */
		HEADER(ErrorCategory.MALFORMED_INPUT, "The token's JOSE header is malformed."),
		/**
		 * The payload is not a strict UTF-8 JSON object within the limits, has duplicate members, is empty, or holds a
		 * registered claim of the wrong type or out of range, such as an {@code exp} that is not a number or an empty
		 * {@code aud} array (RFC 7519 section 4.1). {@link MalformedJoseInputException}.
		 */
		CLAIMS(ErrorCategory.MALFORMED_INPUT, "The token's claims are malformed."),
		/**
		 * The JSON Web Key Set document is not a strict JSON object with a {@code keys} array of objects within the
		 * size and key-count limits (RFC 7517 section 5). {@link MalformedJoseInputException}.
		 */
		KEY_SET(ErrorCategory.MALFORMED_INPUT, "The JSON Web Key Set document is malformed."),
		/**
		 * The token is a JWE compact serialization, with four dots (RFC 7516), which Revetsec does not decrypt.
		 * {@link UnsupportedJoseFeatureException}.
		 */
		ENCRYPTED_TOKEN(ErrorCategory.UNSUPPORTED, "Encrypted tokens are not supported."),
		/**
		 * The token starts with a left curly bracket, as a JWS JSON serialization does (RFC 7515 section 7.2), which
		 * Revetsec does not accept. {@link UnsupportedJoseFeatureException}.
		 */
		JSON_SERIALIZATION(ErrorCategory.UNSUPPORTED, "The JWS JSON serialization is not supported."),
		/**
		 * The header has a {@code crit} member (RFC 7515 section 4.1.11). Revetsec understands no extension, so it
		 * rejects every critical one. {@link UnsupportedJoseFeatureException}.
		 */
		CRITICAL_HEADER(ErrorCategory.UNSUPPORTED, "Critical header parameters are not supported."),
		/**
		 * The header has a {@code b64} member (RFC 7797). {@link UnsupportedJoseFeatureException}.
		 */
		UNENCODED_PAYLOAD(ErrorCategory.UNSUPPORTED, "Unencoded payloads are not supported."),
		/**
		 * The header has a {@code zip} member. {@link UnsupportedJoseFeatureException}.
		 */
		COMPRESSED_PAYLOAD(ErrorCategory.UNSUPPORTED, "Compressed payloads are not supported."),
		/**
		 * The header has a {@code cty} member, as a nested token does (RFC 7519 section 5.2).
		 * {@link UnsupportedJoseFeatureException}.
		 */
		NESTED_TOKEN(ErrorCategory.UNSUPPORTED, "Nested tokens are not supported."),
		/**
		 * The header's {@code alg} is not one of the allowed algorithms, compared exactly; {@code none} in any case
		 * lands here. {@link JwtValidationException}.
		 */
		ALGORITHM_NOT_ALLOWED(ErrorCategory.VALIDATION_FAILURE, "The token's algorithm is not allowed."),
		/**
		 * The header carries its own key or a key location ({@code jwk}, {@code jku} or {@code x5u}), which Revetsec
		 * never trusts or fetches. {@link JwtValidationException}.
		 */
		UNTRUSTED_KEY_REFERENCE(ErrorCategory.VALIDATION_FAILURE, "The token's header refers to a key that is not "
				+ "trusted."),
		/**
		 * The signature has the wrong length for its algorithm or key, or an ECDSA signature's r or s is outside
		 * [1, n &minus; 1]. Decided before any cryptographic verification and, for the key-independent part, before any
		 * key is looked up. {@link JwtValidationException}.
		 */
		SIGNATURE_MALFORMED(ErrorCategory.VALIDATION_FAILURE, "The token's signature is malformed."),
		/**
		 * No trusted key matches the token's {@code kid}, or, without a {@code kid}, no trusted key fits its
		 * algorithm. {@link JwtValidationException}.
		 */
		UNKNOWN_KEY(ErrorCategory.VALIDATION_FAILURE, "No trusted key matches the token."),
		/**
		 * More than one trusted key fits the token: two usable keys share its {@code kid}, or, without a {@code kid},
		 * more than one key fits its algorithm. {@link JwtValidationException}.
		 */
		AMBIGUOUS_KEY(ErrorCategory.VALIDATION_FAILURE, "More than one trusted key matches the token."),
		/**
		 * Trusted keys with the token's {@code kid} exist, but none fits its algorithm: another key type or curve,
		 * another {@code alg}, or an RSA key without {@code alg} while more than one RSA algorithm is allowed.
		 * {@link JwtValidationException}.
		 */
		KEY_ALGORITHM_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The token's key does not fit its algorithm."),
		/**
		 * The key's JWK {@code issuer} member does not match the token's {@code iss}. {@link JwtValidationException}.
		 */
		KEY_ISSUER_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The token's key is not bound to its issuer."),
		/**
		 * The signature did not verify. {@link JwtValidationException}.
		 */
		SIGNATURE_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The token's signature does not verify."),
		/**
		 * The header's {@code typ} is not one of the allowed types, or it is absent where a type is required.
		 * {@link JwtValidationException}.
		 */
		INVALID_TYPE(ErrorCategory.VALIDATION_FAILURE, "The token's type is not allowed."),
		/**
		 * The token's {@code iss} is not the expected issuer, compared exactly. {@link JwtValidationException}.
		 */
		ISSUER_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The token's issuer is not the expected issuer."),
		/**
		 * None of the token's audiences is an expected audience. {@link JwtValidationException}.
		 */
		AUDIENCE_MISMATCH(ErrorCategory.VALIDATION_FAILURE, "The token's audience is not an expected audience."),
		/**
		 * A required claim is absent or JSON {@code null}. {@link JwtValidationException}.
		 */
		MISSING_CLAIM(ErrorCategory.VALIDATION_FAILURE, "A required claim is missing from the token."),
		/**
		 * The token's {@code exp} has passed, allowing for clock skew. {@link JwtValidationException}.
		 */
		EXPIRED(ErrorCategory.VALIDATION_FAILURE, "The token has expired."),
		/**
		 * The token's {@code nbf} has not yet been reached, allowing for clock skew. {@link JwtValidationException}.
		 */
		NOT_YET_VALID(ErrorCategory.VALIDATION_FAILURE, "The token is not yet valid."),
		/**
		 * The token's {@code iat} is in the future, allowing for clock skew. {@link JwtValidationException}.
		 */
		ISSUED_IN_FUTURE(ErrorCategory.VALIDATION_FAILURE, "The token was issued in the future."),
		/**
		 * The token has a {@code cnf} claim (RFC 7800): it is bound to a key whose possession this validator does not
		 * check, so it is never accepted as a bearer token. {@link JwtValidationException}.
		 */
		CONFIRMATION_NOT_VERIFIED(ErrorCategory.VALIDATION_FAILURE, "The token is bound to a key whose possession was "
				+ "not proven.");

		@NonNull
		private final ErrorCategory category;
		@NonNull
		private final String message;

		Reason(@NonNull ErrorCategory category,
					 @NonNull String message) {
			this.category = category;
			this.message = message;
		}

		/**
		 * The category, which also fixes the exception class.
		 */
		@NonNull
		ErrorCategory category() {
			return this.category;
		}

		/**
		 * The fixed message.
		 */
		@NonNull
		String message() {
			return this.message;
		}
	}
}
