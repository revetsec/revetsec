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

import com.google.errorprone.annotations.CheckReturnValue;
import com.revetsec.StoreAdmission;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Internal immutable binding to an application's already-verified external closed migration intent.
 * This is metadata, not a capability or proof that SQL writers are fenced. The administrative controller must
 * establish and recheck current external CLOSED intent, recovery admission, ownership and writer fencing before
 * each bounded use. No normal engine accepts this carrier, and construction performs no I/O or time admission.
 */
@Immutable
@CheckReturnValue
public final class ClosedMigrationIntent {
	/** The exact selected target format families, independent of sealing-type labels. */
	@Immutable
	public enum Format {
		/** TTR3 durable TOTP records. */
		TOTP_TTR3,
		/** WAR2 WebAuthn records. */
		WEBAUTHN_WAR2,
		/** Issuer outer schema 2 records. */
		ISSUER_SCHEMA2
	}

	private final @NonNull String migrationId;
	private final @NonNull StoreAdmission targetAdmission;
	private final @NonNull Set<@NonNull Format> formats;

	private ClosedMigrationIntent(@NonNull String migrationId, @NonNull StoreAdmission targetAdmission,
			@NonNull Set<@NonNull Format> formats) {
		// Reuse the exact canonical 32-byte identity grammar without generating or admitting an identity.
		this.migrationId = StoreAdmission.fromIdentifiers(migrationId, migrationId).getAuthorityId();
		this.targetAdmission = requireNonNull(targetAdmission);
		this.formats = Set.copyOf(requireNonNull(formats));
		if (this.formats.isEmpty())
			throw new IllegalArgumentException("No target migration format selected.");
	}

	/** Retains the identities/formats of externally verified closed intent; does not verify operational state. */
	public static @NonNull ClosedMigrationIntent fromExternalIntent(@NonNull String migrationId,
			@NonNull StoreAdmission targetAdmission, @NonNull Set<@NonNull Format> formats) {
		return new ClosedMigrationIntent(migrationId, targetAdmission, formats);
	}

	/** Returns the exact migration identity, for protected administrative binding only. */
	public @NonNull String getMigrationId() {
		return this.migrationId;
	}

	/** Returns the externally selected target authority/recovery identities. */
	public @NonNull StoreAdmission getTargetAdmission() {
		return this.targetAdmission;
	}

	/** Refuses a transform outside the externally selected target family set. */
	public void requireFormat(@NonNull Format format) {
		if (!this.formats.contains(requireNonNull(format)))
			throw new IllegalArgumentException("Migration format is not selected.");
	}

	@Override
	public @NonNull String toString() {
		return "ClosedMigrationIntent{intent=<redacted>}";
	}
}
