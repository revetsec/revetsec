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

package com.revetsec.internal.jose;

import com.revetsec.internal.crypto.VerifyResult;
import com.revetsec.jose.JoseException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * The JWS and JWT pipeline that {@code jose.JwtValidator}, the later ID token and access token validators, and the
 * vector runners share (plan "JOSE semantics", steps 1 to 14). It does no I/O: the caller resolves the key between
 * the two halves, so a remote key source can fetch with the caller's own deadline.
 * <ol>
 *   <li>{@link #prepare(String, JoseHeaderPolicy)} runs every check that needs no key: size, serialization, canonical
 *   base64url ({@link CompactJwsParser}), the header policy (P3 to P8; {@link JoseHeaderPolicy#check(byte[])}) and the
 *   key-independent signature shape ({@link JwsVerifier#findShapeFailure}). A malformed signature therefore never
 *   causes a key lookup or a fetch.</li>
 *   <li>The caller selects a key with {@link PreparedJws#getKeyQuery()}: {@link KeySelector} over a static key list,
 *   or a remote source.</li>
 *   <li>{@link #verify(PreparedJws, KeySelection)} turns a selection without a key into its reason, checks the exact
 *   signature length for the key, and verifies the signature over the received ASCII {@code header.payload}
 *   ({@link JwsVerifier#verify}). A key that does not fit the token's query is refused even if a source selected it.
 *   That is where the JWS layer ends.</li>
 *   <li>{@link #complete(PreparedJws, KeySelection, JwtClaimsPolicy, Instant)} also parses the payload as JWT claims,
 *   only after the signature verified ({@link JwtClaimsReader}), and checks them against the policy
 *   ({@link JwtClaimsPolicy#check}).</li>
 * </ol>
 * The {@code WithSecret} variants verify over a configured HMAC secret instead of a selected key; they are reachable
 * only internally, for the later ID token profile and the vector runners.
 * <p>
 * Every failure is a {@link JoseFailure} whose reason the entry point reports. An unexpected
 * {@link RuntimeException} inside a step becomes that step's reason (INV-G1).
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@ThreadSafe
public final class JwtProcessor {
	private JwtProcessor() {
		// Static helpers only.
	}

	/**
	 * Runs steps 1 to 5 on a compact serialization.
	 *
	 * @param compactSerialization the token, untrusted
	 * @param headerPolicy         the length, algorithm and type settings
	 * @return the checked JWS, ready for key selection
	 * @throws NullPointerException if an argument is {@code null}
	 * @throws JoseFailure          with the reason of the first check that failed
	 */
	@NonNull
	public static PreparedJws prepare(@NonNull String compactSerialization,
																		@NonNull JoseHeaderPolicy headerPolicy) throws JoseFailure {
		requireNonNull(compactSerialization);
		requireNonNull(headerPolicy);

		// Steps 1 to 3.
		CompactJws jws = CompactJwsParser.parse(compactSerialization, headerPolicy.getMaximumTokenLength());
		// Step 4.
		JoseHeader header = headerPolicy.check(jws.getHeader());
		byte[] signature = jws.getSignature();

		// Step 5, before any key is looked up.
		Optional<VerifyResult> shapeFailure;
		try {
			shapeFailure = JwsVerifier.findShapeFailure(header.algorithm(), signature);
		} catch (RuntimeException e) {
			throw new JoseFailure(JoseException.Reason.SIGNATURE_MALFORMED);
		}
		if (shapeFailure.isPresent())
			throw new JoseFailure(JoseException.Reason.SIGNATURE_MALFORMED);

		return new PreparedJws(compactSerialization, header.algorithm(), header.keyId(), header.type(),
				jws.getSigningInput(), jws.getPayload(), signature, new KeyQuery(header.algorithm(), header.keyId(),
				headerPolicy.getAllowedAlgorithms()), headerPolicy.getJsonLimits());
	}

	/**
	 * Runs steps 6 and 7: the selection's outcome, then the signature.
	 *
	 * @param prepared  the output of {@link #prepare(String, JoseHeaderPolicy)}
	 * @param selection the key selected for {@link PreparedJws#getKeyQuery()}
	 * @return the verified JWS, its payload not parsed
	 * @throws NullPointerException if an argument is {@code null}
	 * @throws JoseFailure          {@link JoseException.Reason#UNKNOWN_KEY}, {@link JoseException.Reason#AMBIGUOUS_KEY}
	 *                              or {@link JoseException.Reason#KEY_ALGORITHM_MISMATCH} for a selection without a
	 *                              key, {@link JoseException.Reason#SIGNATURE_MALFORMED} for a signature of the wrong
	 *                              length for the key, and {@link JoseException.Reason#SIGNATURE_MISMATCH} if it does
	 *                              not verify
	 */
	@NonNull
	public static VerifiedJws verify(@NonNull PreparedJws prepared,
																	 @NonNull KeySelection selection) throws JoseFailure {
		requireNonNull(prepared);
		requireNonNull(selection);

		// Step 6.
		VerificationKey key = requireKey(prepared, selection);

		// Step 7.
		VerifyResult result;
		try {
			result = JwsVerifier.verify(prepared.getAlgorithm(), key.publicKey(), prepared.signingInput(),
					prepared.signature());
		} catch (RuntimeException e) {
			throw new JoseFailure(JoseException.Reason.SIGNATURE_MISMATCH);
		}
		requireValid(result);

		return verified(prepared, key);
	}

	/**
	 * Runs steps 6 to 14: the signature, then the claims.
	 *
	 * @param prepared     the output of {@link #prepare(String, JoseHeaderPolicy)}
	 * @param selection    the key selected for {@link PreparedJws#getKeyQuery()}
	 * @param claimsPolicy the claim checks
	 * @param now          the current time, from the caller's clock
	 * @return the verified JWT
	 * @throws NullPointerException if an argument is {@code null}
	 * @throws JoseFailure          with the reason of the first check that failed
	 */
	@NonNull
	public static VerifiedJwt complete(@NonNull PreparedJws prepared,
																		 @NonNull KeySelection selection,
																		 @NonNull JwtClaimsPolicy claimsPolicy,
																		 @NonNull Instant now) throws JoseFailure {
		requireNonNull(prepared);
		requireNonNull(selection);
		requireNonNull(claimsPolicy);
		requireNonNull(now);

		VerifiedJws jws = verify(prepared, selection);
		return claims(prepared, jws, claimsPolicy, now);
	}

	/**
	 * Runs step 7 over a configured HMAC secret instead of a selected key. Internal only.
	 *
	 * @param prepared the output of {@link #prepare(String, JoseHeaderPolicy)}, with an {@code HS*} algorithm
	 * @param secret   the secret, at least as long as the algorithm's hash; not modified
	 * @return the verified JWS, its payload not parsed
	 * @throws NullPointerException     if an argument is {@code null}
	 * @throws IllegalArgumentException if the algorithm is not an HMAC algorithm, or the secret is too short
	 * @throws JoseFailure              {@link JoseException.Reason#SIGNATURE_MISMATCH} if the tag does not verify
	 */
	@NonNull
	public static VerifiedJws verifyWithSecret(@NonNull PreparedJws prepared,
																						 byte @NonNull [] secret) throws JoseFailure {
		requireNonNull(prepared);
		requireNonNull(secret);

		// Step 7. JwsVerifier refuses a non-HMAC algorithm before it reads the secret, and a short secret is a
		// configuration error, so both stay IllegalArgumentExceptions.
		VerifyResult result = JwsVerifier.verifyWithSecret(prepared.getAlgorithm(), secret, prepared.signingInput(),
				prepared.signature());
		requireValid(result);

		return verified(prepared, null);
	}

	/**
	 * Runs steps 7 to 14 over a configured HMAC secret instead of a selected key. Internal only.
	 *
	 * @param prepared     the output of {@link #prepare(String, JoseHeaderPolicy)}, with an {@code HS*} algorithm
	 * @param secret       the secret, at least as long as the algorithm's hash; not modified
	 * @param claimsPolicy the claim checks
	 * @param now          the current time, from the caller's clock
	 * @return the verified JWT
	 * @throws NullPointerException     if an argument is {@code null}
	 * @throws IllegalArgumentException if the algorithm is not an HMAC algorithm, or the secret is too short
	 * @throws JoseFailure              with the reason of the first check that failed
	 */
	@NonNull
	public static VerifiedJwt completeWithSecret(@NonNull PreparedJws prepared,
																							 byte @NonNull [] secret,
																							 @NonNull JwtClaimsPolicy claimsPolicy,
																							 @NonNull Instant now) throws JoseFailure {
		requireNonNull(prepared);
		requireNonNull(secret);
		requireNonNull(claimsPolicy);
		requireNonNull(now);

		VerifiedJws jws = verifyWithSecret(prepared, secret);
		return claims(prepared, jws, claimsPolicy, now);
	}

	/**
	 * Step 6: the selected key, or the reason there is none. A selected key that does not fit the token's query is
	 * refused too, so a faulty key source can never make a key verify an algorithm or {@code kid} it was not selected
	 * for.
	 */
	@NonNull
	private static VerificationKey requireKey(@NonNull PreparedJws prepared,
																						@NonNull KeySelection selection) throws JoseFailure {
		// A FOUND selection always holds its key (KeySelection's invariant).
		VerificationKey key = switch (selection.getKind()) {
			case FOUND -> selection.findKey().orElseThrow();
			case UNKNOWN -> throw new JoseFailure(JoseException.Reason.UNKNOWN_KEY);
			case AMBIGUOUS -> throw new JoseFailure(JoseException.Reason.AMBIGUOUS_KEY);
			case ALGORITHM_MISMATCH -> throw new JoseFailure(JoseException.Reason.KEY_ALGORITHM_MISMATCH);
		};

		String keyId = prepared.findKeyId().orElse(null);
		if (keyId != null && !keyId.equals(key.keyId()))
			throw new JoseFailure(JoseException.Reason.UNKNOWN_KEY);
		if (!KeySelector.fits(key, prepared.getKeyQuery()))
			throw new JoseFailure(JoseException.Reason.KEY_ALGORITHM_MISMATCH);

		return key;
	}

	/**
	 * Step 7's outcome: only {@link VerifyResult#VALID} passes. A malformed signature is
	 * {@link JoseException.Reason#SIGNATURE_MALFORMED}; a signature that does not verify, or a provider failure, is
	 * {@link JoseException.Reason#SIGNATURE_MISMATCH}, and so is any other result, so the check fails closed.
	 */
	private static void requireValid(@NonNull VerifyResult result) throws JoseFailure {
		if (result == VerifyResult.VALID)
			return;
		if (result == VerifyResult.WRONG_LENGTH || result == VerifyResult.OUT_OF_RANGE)
			throw new JoseFailure(JoseException.Reason.SIGNATURE_MALFORMED);
		throw new JoseFailure(JoseException.Reason.SIGNATURE_MISMATCH);
	}

	@NonNull
	private static VerifiedJws verified(@NonNull PreparedJws prepared,
																			@Nullable VerificationKey key) {
		return new VerifiedJws(prepared.getAlgorithm(), prepared.findKeyId().orElse(null),
				prepared.findType().orElse(null), prepared.payload(), key);
	}

	/**
	 * Steps 8 to 14: the payload, parsed only now that the signature verified, and the claim checks.
	 */
	@NonNull
	private static VerifiedJwt claims(@NonNull PreparedJws prepared,
																		@NonNull VerifiedJws jws,
																		@NonNull JwtClaimsPolicy claimsPolicy,
																		@NonNull Instant now) throws JoseFailure {
		RegisteredClaims claims = JwtClaimsReader.read(jws.getPayload(), prepared.jsonLimits());
		VerificationKey key = jws.findKey().orElse(null);
		claimsPolicy.check(claims, key, now);

		return new VerifiedJwt(prepared.getAlgorithm(), prepared.findKeyId().orElse(null),
				prepared.findType().orElse(null), claims, prepared.compactSerialization(), key);
	}
}
