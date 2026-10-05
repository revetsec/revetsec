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

/** Typed permanent records. A later grant binds incarnation AND epoch for both issuer and subject. */
final class OAuthStoreFence {
	private static final @NonNull Set<@NonNull String> SUBJECT_FIELDS = Set.of("schema", "incarnation", "epoch");
	private static final @NonNull Set<@NonNull String> ISSUER_FIELDS =
		Set.of("schema", "incarnation", "epoch", "highWaterSeconds", "highWaterNanos");
	private final @NonNull String incarnation;
	private final long epoch;
	private final @NonNull Instant highWater;
	private final boolean issuer;
	private OAuthStoreFence(@NonNull String incarnation, long epoch, @NonNull Instant highWater, boolean issuer) {
		OAuthStoreFormat.nonce(incarnation); requireNonNull(highWater);
		if (epoch < 0 || !highWater.isBefore(OAuthStoreFormat.PERMANENT)) throw OAuthStoreFormat.invalid();
		this.incarnation = incarnation; this.epoch = epoch; this.highWater = highWater; this.issuer = issuer;
	}
	static @NonNull OAuthStoreFence initialIssuer(@NonNull String incarnation, @NonNull Instant now) {
		return new OAuthStoreFence(incarnation, 0, now, true);
	}
	static @NonNull OAuthStoreFence initialSubject(@NonNull String incarnation) {
		return new OAuthStoreFence(incarnation, 0, Instant.EPOCH, false);
	}
	static @NonNull OAuthStoreFence decode(@NonNull JsonObject payload, OAuthStoreKey.@NonNull Kind kind) {
		requireNonNull(payload); requireNonNull(kind);
		boolean issuer = kind == OAuthStoreKey.Kind.ISSUER_STATE;
		if ((!issuer && kind != OAuthStoreKey.Kind.SUBJECT_STATE)
			|| !payload.getMembers().keySet().equals(issuer ? ISSUER_FIELDS : SUBJECT_FIELDS)
			|| payload.findLong("schema").orElse(-1L) != 1L) throw OAuthStoreFormat.invalid();
		String incarnation = payload.findString("incarnation").orElseThrow(OAuthStoreFormat::invalid);
		long epoch = payload.findLong("epoch").orElseThrow(OAuthStoreFormat::invalid);
		Instant highWater = Instant.EPOCH;
		if (issuer) {
			long seconds = payload.findLong("highWaterSeconds").orElseThrow(OAuthStoreFormat::invalid);
			long nanos = payload.findLong("highWaterNanos").orElseThrow(OAuthStoreFormat::invalid);
			if (nanos < 0 || nanos > 999999999) throw OAuthStoreFormat.invalid();
			try { highWater = Instant.ofEpochSecond(seconds, nanos); }
			catch (DateTimeException failure) { throw OAuthStoreFormat.invalid(); }
		}
		return new OAuthStoreFence(incarnation, epoch, highWater, issuer);
	}
	@NonNull OAuthStoreFence advance(@NonNull Instant now) {
		try { return new OAuthStoreFence(this.incarnation, Math.addExact(this.epoch, 1),
			this.issuer ? checkedTime(now) : this.highWater, this.issuer); }
		catch (ArithmeticException failure) { throw OAuthStoreFormat.invalid(); }
	}
	@NonNull OAuthStoreFence atTime(@NonNull Instant now) {
		if (!this.issuer) throw OAuthStoreFormat.invalid();
		return new OAuthStoreFence(this.incarnation, this.epoch, checkedTime(now), true);
	}
	private @NonNull Instant checkedTime(@NonNull Instant now) {
		requireNonNull(now);
		if (now.isBefore(this.highWater)) throw OAuthStoreFormat.invalid();
		return now;
	}
	@NonNull String incarnation() { return this.incarnation; }
	long epoch() { return this.epoch; }
	@NonNull Instant highWater() { return this.highWater; }
	// The persisted clock fence preserves the complete Instant; both components are required.
	@SuppressWarnings("JavaInstantGetSecondsGetNano")
	@NonNull String toPayload() {
		return "{\"schema\":1,\"incarnation\":\"" + this.incarnation + "\",\"epoch\":" + this.epoch
			+ (this.issuer ? ",\"highWaterSeconds\":" + this.highWater.getEpochSecond()
				+ ",\"highWaterNanos\":" + this.highWater.getNano() : "") + "}";
	}
	@Override public @NonNull String toString() { return "OAuthStoreFence{state=<redacted>}"; }
}
