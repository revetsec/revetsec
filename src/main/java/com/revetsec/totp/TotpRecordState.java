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

package com.revetsec.totp;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Mutable, thread-confined working state for the active TTR3 codec and engine. */
@NotThreadSafe
final class TotpRecordState {
	private TotpRecordState() {}

	@NotThreadSafe
	static final class Account {
		final @NonNull String accountId;
		@NonNull String fence;
		@NonNull Instant observedAt;
		@Nullable Active active;
		@Nullable Pending pending;
		@Nullable String batchId;
		final @NonNull List<byte @NonNull []> recoveryHashes = new ArrayList<>();
		final @NonNull List<@NonNull Charge> charges = new ArrayList<>();
		final @NonNull List<@NonNull Charge> totpCharges = new ArrayList<>();

		Account(@NonNull String accountId, @NonNull String fence, @NonNull Instant observedAt) {
			this.accountId = accountId;
			this.fence = fence;
			this.observedAt = observedAt;
		}

		void erase() {
			Active current = this.active;
			if (current != null) Arrays.fill(current.secret, (byte) 0);
			Pending preparation = this.pending;
			if (preparation != null) {
				Arrays.fill(preparation.secret, (byte) 0);
				Arrays.fill(preparation.browserHash, (byte) 0);
			}
			for (byte[] hash : this.recoveryHashes) Arrays.fill(hash, (byte) 0);
		}
	}

	@NotThreadSafe
	static final class Active {
		final @NonNull String factorId;
		final byte @NonNull [] secret;
		final @NonNull Instant enrolledAt;
		long usedStep;

		Active(@NonNull String factorId, byte @NonNull [] secret, @NonNull Instant enrolledAt, long usedStep) {
			this.factorId = factorId;
			this.secret = secret;
			this.enrolledAt = enrolledAt;
			this.usedStep = usedStep;
		}
	}

	@NotThreadSafe
	static final class Pending {
		final @NonNull String enrollmentId;
		final @NonNull String factorId;
		final byte @NonNull [] secret;
		final byte @NonNull [] browserHash;
		final @NonNull Instant expiresAt;
		final @Nullable String expectedFactorId;

		Pending(@NonNull String enrollmentId, @NonNull String factorId, byte @NonNull [] secret,
				byte @NonNull [] browserHash, @NonNull Instant expiresAt, @Nullable String expectedFactorId) {
			this.enrollmentId = enrollmentId;
			this.factorId = factorId;
			this.secret = secret;
			this.browserHash = browserHash;
			this.expiresAt = expiresAt;
			this.expectedFactorId = expectedFactorId;
		}
	}

	@NotThreadSafe
	static final class Charge {
		final @NonNull String id;
		final @NonNull Instant at;

		Charge(@NonNull String id, @NonNull Instant at) {
			this.id = id;
			this.at = at;
		}
	}
}
