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

package com.revetsec.webauthn;

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.StoreCommitTiming;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Objects;
import java.util.Optional;

/**
 * Immutable factual acknowledgement of an atomic WebAuthn write or predicate barrier.
 * A known commitment retains its required validation timing even when completion acquisition or
 * later service admission fails. It is not a credential, current-readiness assertion or retry token.
 *
 * @since 1.0.0
 */
@javax.annotation.concurrent.Immutable
@CheckReturnValue
public final class WebAuthnStoreCommitReceipt {
	private final @NonNull WebAuthnStoreCommitResult status;
	private final @Nullable StoreCommitTiming timing;

	private WebAuthnStoreCommitReceipt(@NonNull WebAuthnStoreCommitResult status, @Nullable StoreCommitTiming timing) {
		this.status = Objects.requireNonNull(status);
		this.timing = timing;
	}

	/**
	 * Records a known committed timed write, including a successful condition-only barrier.
	 * @param timing the fresh final-validation sample and optional post-acknowledgement sample
	 * @return the committed factual receipt
	 * @throws NullPointerException if timing is null
	 * @since 1.0.0
	 */
	public static @NonNull WebAuthnStoreCommitReceipt fromCommittedTiming(@NonNull StoreCommitTiming timing) {
		return new WebAuthnStoreCommitReceipt(WebAuthnStoreCommitResult.COMMITTED, Objects.requireNonNull(timing));
	}

	/**
	 * Records a definitive no-effect refusal, without fabricating validation timing.
	 * @param status a refusal status other than COMMITTED or UNKNOWN
	 * @return the no-effect receipt
	 * @throws NullPointerException if status is null
	 * @throws IllegalArgumentException if status is COMMITTED or UNKNOWN
	 * @since 1.0.0
	 */
	public static @NonNull WebAuthnStoreCommitReceipt fromRefusal(@NonNull WebAuthnStoreCommitResult status) {
		Objects.requireNonNull(status);
		if (status == WebAuthnStoreCommitResult.COMMITTED || status == WebAuthnStoreCommitResult.UNKNOWN)
			throw new IllegalArgumentException("Invalid WebAuthn refusal status");
		return new WebAuthnStoreCommitReceipt(status, null);
	}

	/**
	 * Records an uncertain possible commitment, without claimed timing.
	 * @return the unknown factual receipt
	 * @since 1.0.0
	 */
	public static @NonNull WebAuthnStoreCommitReceipt unknownInstance() {
		return new WebAuthnStoreCommitReceipt(WebAuthnStoreCommitResult.UNKNOWN, null);
	}

	/**
	 * Returns factual commitment, a definite no-effect refusal or uncertainty.
	 * @return the status
	 * @since 1.0.0
	 */
	public @NonNull WebAuthnStoreCommitResult getStatus() { return this.status; }

	/**
	 * Returns required timing only for COMMITTED.
	 * @return the optional validation/completion metadata
	 * @since 1.0.0
	 */
	public @NonNull Optional<@NonNull StoreCommitTiming> getTiming() { return Optional.ofNullable(this.timing); }

	/**
	 * Returns a fixed description without timing, identities or state.
	 * @return the redacted description
	 * @since 1.0.0
	 */
	@Override public @NonNull String toString() { return "WebAuthnStoreCommitReceipt{receipt=<redacted>}"; }
}
