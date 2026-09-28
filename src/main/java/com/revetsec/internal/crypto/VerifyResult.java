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

import javax.annotation.concurrent.Immutable;

/**
 * The outcome of a signature or MAC verification by {@link SignatureVerifier} or {@link Hmac}.
 * <p>
 * Only {@link #VALID} means the signature verified. {@link #WRONG_LENGTH} and {@link #OUT_OF_RANGE} are decided from
 * the signature's shape before any JCA call. {@link #MISMATCH} and {@link #PROVIDER_FAILURE} come from the JCA, or
 * from a key that does not fit the algorithm. The protocol packages report the first two as a malformed signature
 * and the last two as a signature mismatch; tests and vector runners assert these finer results.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 */
@Immutable
public enum VerifyResult {
	/**
	 * The signature or MAC verified.
	 */
	VALID,
	/**
	 * The signature or MAC does not have a length that the algorithm, curve or key allows. Decided before any JCA
	 * call.
	 */
	WRONG_LENGTH,
	/**
	 * An ECDSA {@code r} or {@code s} is outside {@code [1, n - 1]}, where {@code n} is the order of the curve's base
	 * point. Decided before any JCA call, so a provider without its own range check (CVE-2022-21449) never sees it.
	 */
	OUT_OF_RANGE,
	/**
	 * The JCA reported the signature as invalid, the MAC differs, or the key does not fit the algorithm or curve.
	 */
	MISMATCH,
	/**
	 * The JCA provider threw instead of answering. Never treated as valid.
	 */
	PROVIDER_FAILURE
}
