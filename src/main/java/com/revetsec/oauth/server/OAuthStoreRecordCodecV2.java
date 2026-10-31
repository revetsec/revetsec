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

import com.revetsec.StateSealer;
import com.revetsec.StoreAdmission;
import com.revetsec.internal.crypto.AuthenticatedRecord;
import com.revetsec.internal.crypto.SealedStateAccess;
import com.revetsec.internal.crypto.SealedStateType;
import com.revetsec.internal.crypto.UnsealException;
import com.revetsec.internal.encoding.StrictUtf8;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.internal.json.JsonParseException;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.json.JsonValue;
import org.jspecify.annotations.NonNull;

import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Active schema-two issuer envelope; schema-one opening remains restricted to closed migration.
 * Exact payload parsers remain separate from temporal/epoch admission and current external recovery evidence.
 */
final class OAuthStoreRecordCodecV2 {
	private static final @NonNull Set<@NonNull String> FIELDS = Set.of("schema", "issuer", "key", "version",
			"retainUntil", "floorSeconds", "floorNanos", "payload");
	private final @NonNull OAuthStoreRecordCodec legacyAddresses;
	private final @NonNull StateSealer sealer;
	private final @NonNull OAuthServerIngressLimits ingress;
	private final int subjectLimit;
	private final int maximumRecordBytes;
	private final int maximumPlaintextBytes;

	OAuthStoreRecordCodecV2(@NonNull String issuer, @NonNull StateSealer sealer, int maximumRecordBytes,
			@NonNull OAuthServerIngressLimits ingress, int subjectLimit) {
		this.sealer = requireNonNull(sealer);
		this.ingress = requireNonNull(ingress);
		if (maximumRecordBytes < 1024 || maximumRecordBytes > 16384
				|| maximumRecordBytes > SealedStateAccess.get().getMaximumSealedLength(sealer)
				|| subjectLimit < 16 || subjectLimit > 1024) throw OAuthStoreFormat.invalid();
		this.legacyAddresses = new OAuthStoreRecordCodec(issuer, sealer, maximumRecordBytes);
		this.maximumRecordBytes = maximumRecordBytes;
		this.maximumPlaintextBytes = maximumRecordBytes * 3 / 4 - 118;
		this.subjectLimit = subjectLimit;
	}

	@NonNull String issuer() { return this.legacyAddresses.issuer(); }
	@NonNull OAuthStoreKey issuerKey() { return this.legacyAddresses.issuerKey(); }
	@NonNull OAuthStoreKey subjectKey(@NonNull String subject) { return this.legacyAddresses.subjectKey(subject); }
	@NonNull OAuthStoreKey key(OAuthStoreKey.@NonNull Kind kind, @NonNull String identifier) {
		return this.legacyAddresses.key(kind, identifier);
	}
	@NonNull StateSealer sealer() { return this.sealer; }
	int maximumRecordBytes() { return this.maximumRecordBytes; }
	int maximumPlaintextBytes() { return this.maximumPlaintextBytes; }
	@NonNull OAuthServerIngressLimits ingress() { return this.ingress; }
	int subjectLimit() { return this.subjectLimit; }
	@NonNull String freshVersion() { return this.legacyAddresses.freshVersion(); }

	@NonNull OAuthStoreEntry seal(@NonNull OAuthStoreKey key, @NonNull Instant retainUntil,
			@NonNull Instant floor, @NonNull String payloadJson) {
		return sealVersion(key, freshVersion(), retainUntil, floor, payloadJson);
	}

	/** Explicit version is package-private for fixed vectors; migration always supplies a fresh generated version. */
	@NonNull OAuthStoreEntry sealVersion(@NonNull OAuthStoreKey key, @NonNull String version,
			@NonNull Instant retainUntil, @NonNull Instant floor, @NonNull String payloadJson) {
		namespace(key);
		OAuthStoreFormat.nonce(version);
		OAuthStoreFormat.retention(key.getKind(), retainUntil);
		validFloor(floor);
		JsonObject payload = parse(payloadJson, this.maximumPlaintextBytes);
		validatePayload(key, retainUntil, floor, payload);
		String text = envelope(key, version, retainUntil, floor, payload.toJson());
		byte[] bytes = boundedUtf8(text, this.maximumPlaintextBytes);
		try {
			String sealed = SealedStateAccess.get().seal(this.sealer, SealedStateType.AS_RECORD,
					text, context(key), retainUntil);
			OAuthStoreFormat.sealed(sealed, this.maximumRecordBytes);
			return OAuthStoreEntry.fromStoredForm(key, version, retainUntil, sealed);
		} finally { Arrays.fill(bytes, (byte) 0); }
	}

	@NonNull Opened open(@NonNull OAuthStoreEntry entry, @NonNull Clock authorityClock) {
		requireNonNull(entry);
		requireNonNull(authorityClock);
		checkCarrier(entry);
		try (AuthenticatedRecord opened = SealedStateAccess.get().openRecord(this.sealer, SealedStateType.AS_RECORD,
				entry.toSealedForm(), context(entry.getKey()), authorityClock)) {
			return decode(entry, opened.getPlaintext(), opened.getNotAfter());
		} catch (UnsealException | IllegalArgumentException failure) { throw OAuthStoreFormat.invalid(); }
	}

	/** Permanent authentication only; the supplied issuer root is separately authenticated under the same context. */
	@NonNull Opened openPermanentFence(@NonNull OAuthStoreEntry entry, @NonNull StoreAdmission admission,
			@NonNull OAuthStoreEntry issuerRootEntry) {
		requireNonNull(admission);
		checkCarrier(issuerRootEntry);
		if (!issuerRootEntry.getKey().equals(issuerKey())) throw OAuthStoreFormat.invalid();
		Opened rootOpened = openPermanent(issuerRootEntry);
		OAuthIssuerRootV2 root = OAuthIssuerRootV2.decode(rootOpened.payload());
		if (!root.authorityId().equals(admission.getAuthorityId())) throw OAuthStoreFormat.invalid();
		checkCarrier(entry);
		if (entry.getKey().getKind() == OAuthStoreKey.Kind.ISSUER_STATE) {
			if (!entry.getVersion().equals(issuerRootEntry.getVersion())
					|| !entry.toSealedForm().equals(issuerRootEntry.toSealedForm())) throw OAuthStoreFormat.invalid();
			return rootOpened;
		}
		if (entry.getKey().getKind() != OAuthStoreKey.Kind.SUBJECT_STATE) throw OAuthStoreFormat.invalid();
		return openPermanent(entry);
	}

	private @NonNull Opened openPermanent(@NonNull OAuthStoreEntry entry) {
		if (!entry.getRetainUntil().equals(OAuthStoreFormat.PERMANENT)) throw OAuthStoreFormat.invalid();
		try (AuthenticatedRecord opened = SealedStateAccess.get().openPermanentFence(this.sealer,
				entry.toSealedForm(), context(entry.getKey()))) {
			return decode(entry, opened.getPlaintext(), opened.getNotAfter());
		} catch (UnsealException | IllegalArgumentException failure) { throw OAuthStoreFormat.invalid(); }
	}

	@NonNull Opened decode(@NonNull OAuthStoreEntry entry, @NonNull String plaintext, @NonNull Instant notAfter) {
		checkCarrier(entry);
		if (!entry.getRetainUntil().equals(notAfter)) throw OAuthStoreFormat.invalid();
		JsonObject object = parse(plaintext, this.maximumPlaintextBytes);
		if (!object.getMembers().keySet().equals(FIELDS)
				|| OAuthStoreFormat.longMember(object, "schema").orElse(-1L) != 2L
				|| !OAuthStoreFormat.stringMember(object, "issuer").orElse("").equals(issuer())
				|| !OAuthStoreFormat.stringMember(object, "key").orElse("").equals(entry.getKey().getStorageKey())
				|| !OAuthStoreFormat.stringMember(object, "version").orElse("").equals(entry.getVersion())
				|| OAuthStoreFormat.longMember(object, "retainUntil").orElse(Long.MIN_VALUE) != entry.getRetainUntil().getEpochSecond()
				|| !(object.find("payload").orElseThrow(OAuthStoreFormat::invalid) instanceof JsonObject payload))
			throw OAuthStoreFormat.invalid();
		long seconds = OAuthStoreFormat.longMember(object, "floorSeconds").orElseThrow(OAuthStoreFormat::invalid);
		long nanos = OAuthStoreFormat.longMember(object, "floorNanos").orElseThrow(OAuthStoreFormat::invalid);
		Instant floor = OAuthIssuerRootV2.instant(seconds, nanos);
		validatePayload(entry.getKey(), entry.getRetainUntil(), floor, payload);
		return new Opened(floor, payload);
	}

	private void validatePayload(@NonNull OAuthStoreKey key, @NonNull Instant retainUntil,
			@NonNull Instant floor, @NonNull JsonObject payload) {
		if (key.getKind() == OAuthStoreKey.Kind.ISSUER_STATE) {
			OAuthIssuerRootV2 root = OAuthIssuerRootV2.decode(payload);
			if (!root.minimum().equals(floor)) throw OAuthStoreFormat.invalid();
		} else if (key.getKind() == OAuthStoreKey.Kind.SUBJECT_STATE) {
			OAuthStoreFence.decode(payload, key.getKind());
		} else {
			OAuthAuthorizationRecord record = OAuthAuthorizationRecord.decode(key.getKind(), identifier(key), payload,
					this.ingress, this.subjectLimit);
			if (!record.retention().equals(retainUntil)) throw OAuthStoreFormat.invalid();
			if (key.getKind() == OAuthStoreKey.Kind.ACCESS_TOKEN
					&& floor.isBefore(Instant.ofEpochSecond(record.number("issued")))) throw OAuthStoreFormat.invalid();
		}
	}

	void namespace(@NonNull OAuthStoreKey key) {
		requireNonNull(key);
		if (!OAuthStoreFormat.namespace(key).equals(OAuthStoreFormat.namespace(issuerKey()))) throw OAuthStoreFormat.invalid();
	}

	void checkCarrier(@NonNull OAuthStoreEntry entry) {
		requireNonNull(entry);
		namespace(entry.getKey());
		OAuthStoreFormat.retention(entry.getKey().getKind(), entry.getRetainUntil());
		OAuthStoreFormat.sealed(entry.toSealedForm(), this.maximumRecordBytes);
	}

	static @NonNull String identifier(@NonNull OAuthStoreKey key) {
		String address = key.getStorageKey();
		return address.substring(address.lastIndexOf(':') + 1);
	}

	static @NonNull String context(@NonNull OAuthStoreKey key) { return "revetsec/as-record/v2:" + key.getStorageKey(); }

	static void validFloor(@NonNull Instant floor) {
		requireNonNull(floor);
		if (!floor.isBefore(OAuthStoreFormat.PERMANENT)) throw OAuthStoreFormat.invalid();
	}

	@SuppressWarnings("JavaInstantGetSecondsGetNano") // Exact encoded components; no normalization or rounding.
	private @NonNull String envelope(@NonNull OAuthStoreKey key, @NonNull String version,
			@NonNull Instant retainUntil, @NonNull Instant floor, @NonNull String payload) {
		return "{\"schema\":2,\"issuer\":" + JsonString.fromValue(issuer()).toJson()
				+ ",\"key\":" + JsonString.fromValue(key.getStorageKey()).toJson()
				+ ",\"version\":" + JsonString.fromValue(version).toJson()
				+ ",\"retainUntil\":" + retainUntil.getEpochSecond()
				+ ",\"floorSeconds\":" + floor.getEpochSecond() + ",\"floorNanos\":" + floor.getNano()
				+ ",\"payload\":" + payload + "}";
	}

	static @NonNull JsonObject parse(@NonNull String text, int cap) {
		byte[] bytes = boundedUtf8(text, cap);
		try {
			JsonValue value = JsonCodec.parse(bytes, JsonLimits.protocolDocument(cap));
			if (!(value instanceof JsonObject object)) throw OAuthStoreFormat.invalid();
			return object;
		} catch (JsonParseException failure) { throw OAuthStoreFormat.invalid(); }
		finally { Arrays.fill(bytes, (byte) 0); }
	}

	static byte @NonNull [] boundedUtf8(@NonNull String text, int cap) {
		requireNonNull(text);
		if (text.length() > cap) throw OAuthStoreFormat.invalid();
		try {
			byte[] bytes = StrictUtf8.encode(text);
			if (bytes.length <= cap) return bytes;
			Arrays.fill(bytes, (byte) 0);
			throw OAuthStoreFormat.invalid();
		} catch (EncodingException failure) { throw OAuthStoreFormat.invalid(); }
	}

	/** Internal decoded operational state only; never returned by public stores, receipts or results. */
	static final class Opened {
		private final @NonNull Instant floor;
		private final @NonNull JsonObject payload;
		private Opened(@NonNull Instant floor, @NonNull JsonObject payload) { this.floor = floor; this.payload = payload; }
		@NonNull Instant floor() { return this.floor; }
		@NonNull JsonObject payload() { return this.payload; }
		@Override public @NonNull String toString() { return "OAuthStoreRecordCodecV2.Opened{state=<redacted>}"; }
	}
}
