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

package com.revetsec.oauth.server;

import com.revetsec.internal.crypto.AuthenticatedRecord;
import com.revetsec.internal.crypto.ClosedMigrationIntent;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;

import java.time.Instant;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Inactive bounded old-envelope transformer, usable only with externally verified CLOSED intent metadata.
 * This performs no inventory, writer fencing, row replacement or activation; the later administrative controller
 * must recheck those operational prerequisites for every exact bounded batch.
 */
final class OAuthStoreMigrationCodec {
	private static final @NonNull Set<@NonNull String> LEGACY_FIELDS =
			Set.of("schema", "issuer", "key", "version", "retainUntil", "payload");
	private final @NonNull OAuthStoreRecordCodecV2 target;
	private final @NonNull ClosedMigrationIntent intent;
	private final int legacyMaximumRecordBytes;
	private final int legacyMaximumPlaintextBytes;

	OAuthStoreMigrationCodec(@NonNull OAuthStoreRecordCodecV2 target, int legacyMaximumRecordBytes,
			@NonNull ClosedMigrationIntent intent) {
		this.target = requireNonNull(target);
		this.intent = requireNonNull(intent);
		this.intent.requireFormat(ClosedMigrationIntent.Format.ISSUER_SCHEMA2);
		if (legacyMaximumRecordBytes < 1024 || legacyMaximumRecordBytes > 16384)
			throw OAuthStoreFormat.invalid();
		this.legacyMaximumRecordBytes = legacyMaximumRecordBytes;
		this.legacyMaximumPlaintextBytes = legacyMaximumRecordBytes * 3 / 4 - 55;
	}

	/** L comes only from an authenticated old issuer root, never a migration-time wall-clock argument. */
	@NonNull LegacyRoot openRoot(@NonNull OAuthStoreEntry entry) {
		if (!entry.getKey().equals(this.target.issuerKey())) throw OAuthStoreFormat.invalid();
		JsonObject payload = openLegacy(entry);
		OAuthStoreFence old = OAuthStoreFence.decode(payload, OAuthStoreKey.Kind.ISSUER_STATE);
		OAuthIssuerRootV2 root = OAuthIssuerRootV2.fromLegacy(old, this.intent.getTargetAdmission().getAuthorityId());
		return new LegacyRoot(this, entry, root);
	}

	/** Preserves all authenticated payload facts; output is a prepared replacement, not an administrative write. */
	@NonNull OAuthStoreEntry convert(@NonNull OAuthStoreEntry entry, @NonNull LegacyRoot root) {
		requireNonNull(entry);
		requireNonNull(root);
		if (root.owner != this) throw OAuthStoreFormat.invalid();
		JsonObject payload = openLegacy(entry);
		Instant floor = root.root.minimum();
		String newPayload;
		if (entry.getKey().getKind() == OAuthStoreKey.Kind.ISSUER_STATE) {
			if (!entry.getKey().equals(root.entry.getKey()) || !entry.getVersion().equals(root.entry.getVersion())
					|| !entry.toSealedForm().equals(root.entry.toSealedForm())) throw OAuthStoreFormat.invalid();
			// Recheck the source root before reusing the pinned authenticated semantic minimum.
			OAuthStoreFence legacy = OAuthStoreFence.decode(payload, OAuthStoreKey.Kind.ISSUER_STATE);
			if (!legacy.highWater().equals(root.root.minimum()) || legacy.epoch() != root.root.epoch()
					|| !legacy.incarnation().equals(root.root.incarnation())) throw OAuthStoreFormat.invalid();
			newPayload = root.root.toPayload();
		} else if (entry.getKey().getKind() == OAuthStoreKey.Kind.SUBJECT_STATE) {
			OAuthStoreFence.decode(payload, OAuthStoreKey.Kind.SUBJECT_STATE);
			newPayload = payload.toJson();
		} else {
			OAuthAuthorizationRecord record = OAuthAuthorizationRecord.decode(entry.getKey().getKind(),
					OAuthStoreRecordCodecV2.identifier(entry.getKey()), payload, this.target.ingress(), this.target.subjectLimit());
			if (!record.retention().equals(entry.getRetainUntil())) throw OAuthStoreFormat.invalid();
			if (entry.getKey().getKind() == OAuthStoreKey.Kind.ACCESS_TOKEN) {
				Instant issued = Instant.ofEpochSecond(record.number("issued"));
				if (issued.isAfter(floor)) floor = issued;
			}
			// Historical epoch mismatches and consumed states intentionally remain unchanged.
			newPayload = payload.toJson();
		}
		String version = freshDifferentVersion(entry.getVersion());
		return this.target.sealVersion(entry.getKey(), version, entry.getRetainUntil(), floor, newPayload);
	}

	private @NonNull String freshDifferentVersion(@NonNull String oldVersion) {
		for (int attempt = 0; attempt < 3; attempt++) {
			String version = this.target.freshVersion();
			if (!version.equals(oldVersion)) return version;
		}
		throw OAuthStoreFormat.invalid();
	}

	private @NonNull JsonObject openLegacy(@NonNull OAuthStoreEntry entry) {
		requireNonNull(entry);
		this.target.namespace(entry.getKey());
		OAuthStoreFormat.sealed(entry.toSealedForm(), this.legacyMaximumRecordBytes);
		OAuthStoreFormat.retention(entry.getKey().getKind(), entry.getRetainUntil());
		try (AuthenticatedRecord opened = SealedStateAccess.get().openForMigration(this.target.sealer(),
				SealedStateType.AS_RECORD, entry.toSealedForm(), legacyContext(entry.getKey()), this.intent)) {
			if (!opened.getNotAfter().equals(entry.getRetainUntil())) throw OAuthStoreFormat.invalid();
			JsonObject object = OAuthStoreRecordCodecV2.parse(opened.getPlaintext(), this.legacyMaximumPlaintextBytes);
			if (!object.getMembers().keySet().equals(LEGACY_FIELDS)
					|| OAuthStoreFormat.longMember(object, "schema").orElse(-1L) != 1L
					|| !OAuthStoreFormat.stringMember(object, "issuer").orElse("").equals(this.target.issuer())
					|| !OAuthStoreFormat.stringMember(object, "key").orElse("").equals(entry.getKey().getStorageKey())
					|| !OAuthStoreFormat.stringMember(object, "version").orElse("").equals(entry.getVersion())
					|| OAuthStoreFormat.longMember(object, "retainUntil").orElse(Long.MIN_VALUE) != entry.getRetainUntil().getEpochSecond()
					|| !(object.find("payload").orElseThrow(OAuthStoreFormat::invalid) instanceof JsonObject payload))
				throw OAuthStoreFormat.invalid();
			return payload;
		} catch (UnsealException | IllegalArgumentException failure) { throw OAuthStoreFormat.invalid(); }
	}

	private static @NonNull String legacyContext(@NonNull OAuthStoreKey key) {
		return "revetsec/as-record/v1:" + key.getStorageKey();
	}

	/** Owner-bound pinned root from this transformer's closed intent and authenticated old envelope. */
	static final class LegacyRoot {
		private final @NonNull OAuthStoreMigrationCodec owner;
		private final @NonNull OAuthStoreEntry entry;
		private final @NonNull OAuthIssuerRootV2 root;
		private LegacyRoot(@NonNull OAuthStoreMigrationCodec owner, @NonNull OAuthStoreEntry entry,
				@NonNull OAuthIssuerRootV2 root) { this.owner = owner; this.entry = entry; this.root = root; }
		@NonNull Instant minimum() { return this.root.minimum(); }
		@NonNull String authorityId() { return this.root.authorityId(); }
		@Override public @NonNull String toString() { return "OAuthStoreMigrationCodec.LegacyRoot{state=<redacted>}"; }
	}
}
