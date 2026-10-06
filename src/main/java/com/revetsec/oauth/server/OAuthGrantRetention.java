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

import org.jspecify.annotations.NonNull;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import static java.util.Objects.requireNonNull;

/** Checked retention arithmetic. Retention never grants credential validity or extends a pinned lifetime. */
final class OAuthGrantRetention {
	private final @NonNull Duration maximumAccessLifetime;
	private final @NonNull Duration margin;
	OAuthGrantRetention(@NonNull Duration maximumAccessLifetime, @NonNull Duration skew,
			@NonNull Duration totalDeadline, @NonNull Duration metadataFreshness) {
		this.maximumAccessLifetime = duration(maximumAccessLifetime, Duration.ofSeconds(30), Duration.ofMinutes(15));
		duration(skew, Duration.ZERO, Duration.ofSeconds(60));
		duration(totalDeadline, Duration.ofSeconds(1), Duration.ofSeconds(60));
		duration(metadataFreshness, Duration.ZERO, Duration.ofMinutes(5));
		if (skew.compareTo(maximumAccessLifetime.dividedBy(2)) > 0) throw OAuthStoreFormat.invalid();
		this.margin = skew.plus(totalDeadline).plus(metadataFreshness);
	}
	/** Called at first redemption: the caller persists this H and the maximum lifetime in the same issuance commit. */
	@NonNull Instant horizon(@NonNull Instant lastFamilyOrFirstTokenExpiry) {
		return add(lastFamilyOrFirstTokenExpiry, this.maximumAccessLifetime.plus(this.margin), true);
	}
	@NonNull Instant accessRetention(@NonNull Instant accessExpiry) { return add(accessExpiry, this.margin, true); }
	@NonNull Duration maximumAccessLifetime() { return this.maximumAccessLifetime; }
	void requireAccessLifetime(@NonNull Duration value) {
		if (requireNonNull(value).isZero() || value.isNegative() || value.compareTo(this.maximumAccessLifetime) > 0)
			throw OAuthStoreFormat.invalid();
	}
	/** Validity rounds down; physical retention rounds up. Neither uses unchecked epoch-second addition. */
	static @NonNull Instant expiry(@NonNull Instant now, @NonNull Duration lifetime) {
		if (requireNonNull(lifetime).isZero() || lifetime.isNegative()) throw OAuthStoreFormat.invalid();
		Instant expiry = add(now, lifetime, false);
		if (!expiry.isAfter(now)) throw OAuthStoreFormat.invalid();
		return expiry;
	}
	static @NonNull Instant retain(@NonNull Instant expiry) { return add(expiry, Duration.ZERO, true); }
	static @NonNull Duration duration(@NonNull Duration value, @NonNull Duration minimum, @NonNull Duration maximum) {
		if (requireNonNull(value).compareTo(minimum) < 0 || value.compareTo(maximum) > 0) throw OAuthStoreFormat.invalid();
		return value;
	}
	private static @NonNull Instant add(@NonNull Instant instant, @NonNull Duration amount, boolean ceiling) {
		try {
			Instant exact = requireNonNull(instant).plus(amount), whole = exact.truncatedTo(ChronoUnit.SECONDS);
			Instant result = ceiling && !exact.equals(whole) ? whole.plusSeconds(1) : whole;
			if (!result.isBefore(OAuthStoreFormat.PERMANENT)) throw OAuthStoreFormat.invalid();
			return result;
		} catch (ArithmeticException | DateTimeException failure) { throw OAuthStoreFormat.invalid(); }
	}
	@Override public @NonNull String toString() { return "OAuthGrantRetention{<redacted>}"; }
}
