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

import com.revetsec.json.JsonObject;
import org.jspecify.annotations.NonNull;

import java.time.DateTimeException;
import java.time.Instant;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/** Immutable issuer root: authority binding and minimum never advance with ordinary time passage. */
final class OAuthIssuerRootV2 {
	private static final @NonNull Set<@NonNull String> FIELDS = Set.of("schema", "incarnation", "epoch",
			"authorityId", "minimumSeconds", "minimumNanos");
	private final @NonNull String incarnation;
	private final long epoch;
	private final @NonNull String authorityId;
	private final @NonNull Instant minimum;

	private OAuthIssuerRootV2(@NonNull String incarnation, long epoch, @NonNull String authorityId,
			@NonNull Instant minimum) {
		OAuthStoreFormat.nonce(incarnation);
		// Syntax only: independently current external admission still has to bind this authority.
		OAuthStoreFormat.nonce(authorityId);
		requireNonNull(minimum);
		if (epoch < 0 || !minimum.isBefore(OAuthStoreFormat.PERMANENT)) throw OAuthStoreFormat.invalid();
		this.incarnation = incarnation;
		this.epoch = epoch;
		this.authorityId = authorityId;
		this.minimum = minimum;
	}

	static @NonNull OAuthIssuerRootV2 fromLegacy(@NonNull OAuthStoreFence legacy, @NonNull String authorityId) {
		requireNonNull(legacy);
		OAuthStoreFence issuer = OAuthStoreFence.decode(
				OAuthStoreRecordCodecV2.parse(legacy.toPayload(), 512), OAuthStoreKey.Kind.ISSUER_STATE);
		return new OAuthIssuerRootV2(issuer.incarnation(), issuer.epoch(), authorityId, issuer.highWater());
	}

	static @NonNull OAuthIssuerRootV2 initial(@NonNull String incarnation, @NonNull String authorityId,
			@NonNull Instant minimum) {
		return new OAuthIssuerRootV2(incarnation, 0, authorityId, minimum);
	}

	@NonNull OAuthIssuerRootV2 advance() {
		try { return new OAuthIssuerRootV2(this.incarnation, Math.addExact(this.epoch, 1), this.authorityId, this.minimum); }
		catch (ArithmeticException failure) { throw OAuthStoreFormat.invalid(); }
	}

	static @NonNull OAuthIssuerRootV2 decode(@NonNull JsonObject payload) {
		requireNonNull(payload);
		if (!payload.getMembers().keySet().equals(FIELDS)
				|| OAuthStoreFormat.longMember(payload, "schema").orElse(-1L) != 2L) throw OAuthStoreFormat.invalid();
		String incarnation = OAuthStoreFormat.stringMember(payload, "incarnation").orElseThrow(OAuthStoreFormat::invalid);
		long epoch = OAuthStoreFormat.longMember(payload, "epoch").orElseThrow(OAuthStoreFormat::invalid);
		String authority = OAuthStoreFormat.stringMember(payload, "authorityId").orElseThrow(OAuthStoreFormat::invalid);
		long seconds = OAuthStoreFormat.longMember(payload, "minimumSeconds").orElseThrow(OAuthStoreFormat::invalid);
		long nanos = OAuthStoreFormat.longMember(payload, "minimumNanos").orElseThrow(OAuthStoreFormat::invalid);
		return new OAuthIssuerRootV2(incarnation, epoch, authority, instant(seconds, nanos));
	}

	static @NonNull Instant instant(long seconds, long nanos) {
		if (nanos < 0 || nanos > 999999999) throw OAuthStoreFormat.invalid();
		try {
			Instant result = Instant.ofEpochSecond(seconds, nanos);
			if (!result.isBefore(OAuthStoreFormat.PERMANENT)) throw OAuthStoreFormat.invalid();
			return result;
		} catch (DateTimeException failure) { throw OAuthStoreFormat.invalid(); }
	}

	@NonNull String incarnation() { return this.incarnation; }
	long epoch() { return this.epoch; }
	@NonNull String authorityId() { return this.authorityId; }
	@NonNull Instant minimum() { return this.minimum; }

	@SuppressWarnings("JavaInstantGetSecondsGetNano") // Exact persisted components, never rounded.
	@NonNull String toPayload() {
		return "{\"schema\":2,\"incarnation\":\"" + this.incarnation + "\",\"epoch\":" + this.epoch
				+ ",\"authorityId\":\"" + this.authorityId + "\",\"minimumSeconds\":" + this.minimum.getEpochSecond()
				+ ",\"minimumNanos\":" + this.minimum.getNano() + "}";
	}

	@Override public @NonNull String toString() { return "OAuthIssuerRootV2{state=<redacted>}"; }
}
