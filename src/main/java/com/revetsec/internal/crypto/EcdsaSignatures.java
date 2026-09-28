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

import javax.annotation.concurrent.ThreadSafe;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * The shape check and DER encoding for fixed-length ECDSA signatures {@code r || s}, the form JOSE (RFC 7518
 * section 3.4) and XML Signature 1.1 both use.
 * <p>
 * Verification runs in this order (plan D15, gate 8's G8-3), and {@link SignatureVerifier#verifyEcdsa} follows it:
 * <ol>
 *   <li>the signature is exactly twice the curve's coordinate length (64, 96 or 132 bytes), else
 *   {@link VerifyResult#WRONG_LENGTH};</li>
 *   <li>{@code 1 <= r <= n - 1} and {@code 1 <= s <= n - 1}, else {@link VerifyResult#OUT_OF_RANGE};</li>
 *   <li>{@code r} and {@code s} are re-encoded as the minimal DER {@code SEQUENCE { INTEGER r, INTEGER s }};</li>
 *   <li>the JCA's {@code SHAxxxwithECDSA} verifies the DER form.</li>
 * </ol>
 * The DER form works with any JCA provider, including hardware-backed and approved-mode ones. The exact-length check
 * is needed whichever form reaches the JCA: a provider's fixed-length form has accepted too-short signatures, and a
 * DER path without the check accepts halves padded with leading zeros. The range check is the defense against
 * CVE-2022-21449 on runtimes and providers that lack their own. High-S signatures ({@code s > n / 2}) are valid ECDSA
 * and pass, so one signed message has more than one valid signature, and signature bytes never serve as a replay or
 * cache key (ECDSA is malleable).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class EcdsaSignatures {
	private static final int DER_INTEGER = 0x02;
	private static final int DER_SEQUENCE = 0x30;
	private static final int DER_LONG_FORM_ONE_OCTET = 0x81;
	private static final int DER_SHORT_FORM_LIMIT = 0x80;

	private EcdsaSignatures() {
		// Static helpers only.
	}

	/**
	 * Checks the shape of a fixed-length signature {@code r || s} on {@code curve}, without any JCA call and without a
	 * key: its length first, then the range of {@code r} and {@code s}.
	 *
	 * @param curve     the curve of the verifying key
	 * @param signature the signature; not modified
	 * @return {@link VerifyResult#WRONG_LENGTH} or {@link VerifyResult#OUT_OF_RANGE} for a signature no key can
	 * verify, or empty if the shape allows verification (which proves nothing about the signature)
	 */
	@NonNull
	public static Optional<VerifyResult> findShapeFailure(@NonNull EcCurve curve,
																												byte @NonNull [] signature) {
		requireNonNull(curve);
		requireNonNull(signature);

		if (signature.length != curve.getSignatureLength())
			return Optional.of(VerifyResult.WRONG_LENGTH);

		int length = curve.getCoordinateLength();
		BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, length));
		BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, length, 2 * length));

		if (!isInRange(r, curve.getOrder()) || !isInRange(s, curve.getOrder()))
			return Optional.of(VerifyResult.OUT_OF_RANGE);

		return Optional.empty();
	}

	/**
	 * Re-encodes a fixed-length signature {@code r || s} on {@code curve} as the minimal DER encoding of
	 * {@code SEQUENCE { INTEGER r, INTEGER s }} (X.690 sections 8.3 and 10.1): each integer in the fewest octets, with a
	 * leading zero octet only where the high bit would otherwise make it negative, and definite lengths in the
	 * shortest form.
	 * <p>
	 * Call {@link #findShapeFailure(EcCurve, byte[])} first. This method checks only the length, so a value outside
	 * {@code [1, n - 1]} is encoded as it is.
	 *
	 * @param curve     the curve of the verifying key
	 * @param signature the signature, exactly {@link EcCurve#getSignatureLength()} bytes; not modified
	 * @return a new array holding the DER encoding
	 * @throws IllegalArgumentException if the signature does not have the curve's signature length
	 */
	public static byte @NonNull [] toDer(@NonNull EcCurve curve,
																			 byte @NonNull [] signature) {
		requireNonNull(curve);
		requireNonNull(signature);

		if (signature.length != curve.getSignatureLength())
			throw new IllegalArgumentException("The ECDSA signature does not have the curve's signature length.");

		int length = curve.getCoordinateLength();
		// BigInteger.toByteArray is the minimal two's-complement form, which is exactly DER's INTEGER content.
		byte[] r = new BigInteger(1, Arrays.copyOfRange(signature, 0, length)).toByteArray();
		byte[] s = new BigInteger(1, Arrays.copyOfRange(signature, length, 2 * length)).toByteArray();

		// Each INTEGER holds at most 67 content octets (P-521), so its length always takes the short form. The
		// SEQUENCE content reaches 138 octets on P-521, which needs the one-octet long form.
		int contentLength = 2 + r.length + 2 + s.length;
		boolean longForm = contentLength >= DER_SHORT_FORM_LIMIT;
		byte[] der = new byte[(longForm ? 3 : 2) + contentLength];
		int position = 0;

		der[position++] = (byte) DER_SEQUENCE;
		if (longForm)
			der[position++] = (byte) DER_LONG_FORM_ONE_OCTET;
		der[position++] = (byte) contentLength;
		position = putInteger(der, position, r);
		putInteger(der, position, s);

		return der;
	}

	private static boolean isInRange(@NonNull BigInteger value,
																	 @NonNull BigInteger order) {
		return value.signum() > 0 && value.compareTo(order) < 0;
	}

	private static int putInteger(byte @NonNull [] der,
																int position,
																byte @NonNull [] content) {
		int next = position;
		der[next++] = (byte) DER_INTEGER;
		der[next++] = (byte) content.length;
		System.arraycopy(content, 0, der, next, content.length);
		return next + content.length;
	}
}
