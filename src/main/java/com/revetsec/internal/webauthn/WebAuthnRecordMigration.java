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

package com.revetsec.internal.webauthn;

import com.revetsec.StateSealer;
import com.revetsec.internal.StoreTimeRules;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.internal.crypto.EntropySource;
import com.revetsec.webauthn.WebAuthnStoreKey;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.ThreadSafe;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;

import static java.util.Objects.requireNonNull;

/**
 * Inactive, bounded WAR1-to-WAR2 transformations for an externally verified closed migration intent.
 * This component performs no inventory, writer fencing, store write, phase transition or activation.
 * Its caller must revalidate the external closed intent and exact row CAS immediately around the administrative write.
 */
@ThreadSafe
final class WebAuthnRecordMigration {
	private final @NonNull WebAuthnRecordCodecV2 records;
	private final @NonNull EntropySource entropy;

	WebAuthnRecordMigration(@NonNull StateSealer sealer) {
		this(sealer, EntropySource.fromDefaults());
	}

	WebAuthnRecordMigration(@NonNull StateSealer sealer, @NonNull EntropySource entropy) {
		this.entropy = requireNonNull(entropy);
		this.records = new WebAuthnRecordCodecV2(requireNonNull(sealer), entropy);
	}

	@NonNull LegacyRoot authenticateRoot(@NonNull ClosedMigrationIntent intent,
			@NonNull String storageKey, byte @NonNull [] sealedBytes) throws WebAuthnRecordException {
		requireNonNull(intent).requireFormat(ClosedMigrationIntent.Format.WEBAUTHN_WAR2);
		requireNonNull(sealedBytes);
		try (WebAuthnRecordCodecV2.Opened opened = this.records.openLegacyForMigration(storageKey, sealedBytes, intent)) {
			byte[] plaintext = opened.plaintext();
			try {
				Instant minimum = WebAuthnRecordPayloadV2.legacyMinimum(storageKey, plaintext, opened.notAfter());
				return new LegacyRoot(intent, WebAuthnRecordPayloadV2.namespaceKeyForAddress(storageKey), minimum, sealedBytes);
			} finally { Arrays.fill(plaintext, (byte) 0); }
		}
	}

	@NonNull Prepared prepare(@NonNull ClosedMigrationIntent intent, @NonNull LegacyRoot root,
			@NonNull String storageKey, byte @NonNull [] expectedVersion, byte @NonNull [] sealedBytes)
			throws WebAuthnRecordException {
		requireNonNull(intent).requireFormat(ClosedMigrationIntent.Format.WEBAUTHN_WAR2);
		requireNonNull(root);
		requireNonNull(expectedVersion);
		requireNonNull(sealedBytes);
		if (expectedVersion.length < 1 || expectedVersion.length > 128) throw new IllegalArgumentException("Invalid old WebAuthn version.");
		root.requireIntent(intent);
		WebAuthnStoreKey scope = WebAuthnRecordPayloadV2.namespaceKeyForAddress(storageKey);
		if (!scope.equals(root.key)) throw new WebAuthnRecordException();
		byte[] payload;
		WebAuthnStoreKey key;
		Instant expiresAt;
		Instant floor;
		try (WebAuthnRecordCodecV2.Opened opened = this.records.openLegacyForMigration(storageKey, sealedBytes, intent)) {
			byte[] oldPlaintext = opened.plaintext();
			try {
				if (storageKey.equals(root.key.getStorageKey())) {
					if (!MessageDigest.isEqual(root.sourceBytes, sealedBytes)
							|| !root.minimum.equals(WebAuthnRecordPayloadV2.legacyMinimum(storageKey, oldPlaintext, opened.notAfter())))
						throw new WebAuthnRecordException();
					key = root.key;
					floor = root.minimum;
					expiresAt = WebAuthnRecordPayloadV2.PERMANENT;
					payload = WebAuthnRecordPayloadV2.namespace(key, intent.getTargetAdmission().getAuthorityId(), floor);
				} else {
					try (WebAuthnRecordPayloadV2.Decoded decoded = WebAuthnRecordPayloadV2.legacyEntity(
							storageKey, oldPlaintext, opened.notAfter(), root.minimum)) {
						key = decoded.key();
						floor = decoded.floor();
						expiresAt = decoded.expiresAt();
						payload = WebAuthnRecordPayloadV2.entity(key, floor, oldPlaintext);
					}
				}
			} finally { Arrays.fill(oldPlaintext, (byte) 0); }
		}
		try {
			byte[] replacement = this.records.seal(key, payload, expiresAt);
			byte[] version = this.entropy.nextBytes(32);
			try {
				if (version.length != 32 || MessageDigest.isEqual(version, expectedVersion))
					throw new IllegalStateException("WebAuthn migration version was not fresh.");
				return new Prepared(key, expectedVersion, sealedBytes, version, replacement, floor, expiresAt);
			} finally { Arrays.fill(version, (byte) 0); Arrays.fill(replacement, (byte) 0); }
		} finally { Arrays.fill(payload, (byte) 0); }
	}

	/** Authenticated stable legacy root bound to the closed intent, never a mutable namespace clock. */
	@Immutable
	static final class LegacyRoot {
		private final @NonNull ClosedMigrationIntent intent;
		private final @NonNull WebAuthnStoreKey key;
		private final @NonNull Instant minimum;
		private final byte @NonNull [] sourceBytes;
		private LegacyRoot(@NonNull ClosedMigrationIntent intent, @NonNull WebAuthnStoreKey key,
				@NonNull Instant minimum, byte @NonNull [] sourceBytes) {
			this.intent = intent; this.key = key; this.minimum = minimum; this.sourceBytes = sourceBytes.clone();
		}
		@NonNull Instant minimum() { return this.minimum; }
		private void requireIntent(@NonNull ClosedMigrationIntent actual) {
			if (!this.intent.getMigrationId().equals(actual.getMigrationId())
					|| !StoreTimeRules.sameAdmission(this.intent.getTargetAdmission(), actual.getTargetAdmission()))
				throw new IllegalArgumentException("Mismatched closed WebAuthn migration intent.");
		}
		@Override public @NonNull String toString() { return "LegacyRoot{root=<redacted>, no admission}"; }
	}

	/** Ciphertext-only bounded replacement plan; the administrative controller still owns exact atomic CAS. */
	@Immutable
	static final class Prepared {
		private final @NonNull WebAuthnStoreKey key;
		private final byte @NonNull [] expectedVersion;
		private final byte @NonNull [] expectedBytes;
		private final byte @NonNull [] version;
		private final byte @NonNull [] sealedBytes;
		private final @NonNull Instant floor;
		private final @NonNull Instant expiresAt;
		private Prepared(@NonNull WebAuthnStoreKey key, byte @NonNull [] expectedVersion, byte @NonNull [] expectedBytes,
				byte @NonNull [] version, byte @NonNull [] sealedBytes, @NonNull Instant floor, @NonNull Instant expiresAt) {
			this.key = key; this.expectedVersion = expectedVersion.clone(); this.expectedBytes = expectedBytes.clone();
			this.version = version.clone(); this.sealedBytes = sealedBytes.clone(); this.floor = floor; this.expiresAt = expiresAt;
		}
		@NonNull WebAuthnStoreKey key() { return this.key; }
		byte @NonNull [] expectedVersion() { return this.expectedVersion.clone(); }
		byte @NonNull [] expectedBytes() { return this.expectedBytes.clone(); }
		byte @NonNull [] version() { return this.version.clone(); }
		byte @NonNull [] sealedBytes() { return this.sealedBytes.clone(); }
		@NonNull Instant floor() { return this.floor; }
		@NonNull Instant expiresAt() { return this.expiresAt; }
		@Override public @NonNull String toString() { return "Prepared{replacement=<redacted>, no admission}"; }
	}
}
