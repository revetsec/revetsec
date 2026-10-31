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

import com.revetsec.StateSealer;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.ThreadSafe;
import java.io.IOException;

import static java.util.Objects.requireNonNull;

/**
 * Inactive, bounded TTR1/TTR2 transformation for an already verified external CLOSED migration intent.
 * <p>
 * This component neither establishes writer exclusion nor activates a namespace. Its caller must recheck the
 * current external intent, inventory, writer/recovery fences and exact row predicates for each later bounded
 * administrative transaction. The old codec and old account/root invariant are retained without modification.
 */
@ThreadSafe
final class TotpMigrationV3 {
	private final @NonNull TotpRecords legacy;
	private final @NonNull TotpRecordsV3 target;

	TotpMigrationV3(@NonNull StateSealer sealer) {
		requireNonNull(sealer);
		this.legacy = new TotpRecords(sealer);
		this.target = new TotpRecordsV3(sealer);
	}

	@NonNull TotpStoreRecord migrateNamespace(@NonNull TotpStoreRecord oldRoot,
			@NonNull ClosedMigrationIntent intent) throws IOException {
		requireNonNull(oldRoot);
		requireNonNull(intent).requireFormat(ClosedMigrationIntent.Format.TOTP_TTR3);
		if (oldRoot.getKey().getKind() != TotpStoreKey.Kind.NAMESPACE_STATE)
			throw invalid();
		try (TotpRecords.Decoded decoded = this.legacy.open(oldRoot)) {
			return requireFreshReplacement(oldRoot, this.target.sealNamespace(oldRoot.getKey(), new TotpRecordsV3.Namespace(
					intent.getTargetAdmission().getAuthorityId(), decoded.namespace.observedAt)));
		}
	}

	@NonNull TotpStoreRecord migrateAccount(@NonNull TotpStoreRecord oldAccount,
			@NonNull TotpStoreRecord oldRoot, @NonNull ClosedMigrationIntent intent) throws IOException {
		requireNonNull(oldAccount);
		requireNonNull(oldRoot);
		requireNonNull(intent).requireFormat(ClosedMigrationIntent.Format.TOTP_TTR3);
		TotpStoreKey key = oldAccount.getKey();
		if (key.getKind() != TotpStoreKey.Kind.ACCOUNT_STATE || !oldRoot.getKey().equals(
				TotpStoreKey.forNamespace(key.getCredentialNamespace(), key.getRecoveryEpoch())))
			throw invalid();
		try (TotpRecords.Decoded root = this.legacy.open(oldRoot);
				TotpRecords.Decoded decoded = this.legacy.open(oldAccount)) {
			TotpRecords.Account account = requireNonNull(decoded.account);
			if (account.observedAt.isAfter(root.namespace.observedAt))
				throw invalid();
			return requireFreshReplacement(oldAccount, this.target.sealAccount(key, account));
		}
	}

	/** Validates a prepared replacement before any caller can conditionally submit it to storage. */
	static @NonNull TotpStoreRecord requireFreshReplacement(@NonNull TotpStoreRecord previous,
			@NonNull TotpStoreRecord replacement) throws IOException {
		requireNonNull(previous);
		requireNonNull(replacement);
		if (!previous.getKey().equals(replacement.getKey()) || previous.getVersion().equals(replacement.getVersion()))
			throw invalid();
		return replacement;
	}

	private static @NonNull IOException invalid() {
		return new IOException("Invalid legacy TOTP migration state");
	}
}
