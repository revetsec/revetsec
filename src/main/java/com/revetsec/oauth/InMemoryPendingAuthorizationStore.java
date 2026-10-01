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

package com.revetsec.oauth;

import com.revetsec.internal.Limits;
import com.revetsec.internal.encoding.EncodingException;
import com.revetsec.internal.encoding.StrictUtf8;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.google.errorprone.annotations.CheckReturnValue;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Optional;
import java.util.Arrays;
import java.util.concurrent.locks.ReentrantLock;

import static java.util.Objects.requireNonNull;

/**
 * A bounded, single-process pending-authorization store. It starts no worker thread; expiry is removed lazily on
 * saves and consumes. A full store refuses a new login without evicting another live login. Use a durable shared
 * {@link PendingAuthorizationStore} when callbacks may land on other nodes or after a restart.
 *
 * @author <a href="https://www.revetkn.com">Mark Allen</a>
 * @since 1.0.0
 */
@ThreadSafe
public final class InMemoryPendingAuthorizationStore implements PendingAuthorizationStore {
	private final @NonNull ReentrantLock lock = new ReentrantLock();
	private final @NonNull Map<@NonNull Key, @NonNull Entry> entries = new HashMap<>();
	private final int maximumLiveEntries;
	private final long maximumChargedBytes;
	private final int maximumOpaqueRecordBytes;
	private final @NonNull Clock clock;
	private long chargedBytes;

	private InMemoryPendingAuthorizationStore(@NonNull Builder builder) {
		this.maximumLiveEntries = builder.maximumLiveEntries;
		this.maximumChargedBytes = builder.maximumChargedBytes;
		this.maximumOpaqueRecordBytes = builder.maximumOpaqueRecordBytes;
		this.clock = builder.clock;
	}

	/**
	 * Starts a builder with bounded defaults.
	 *
	 * @return the builder
	 * @since 1.0.0
	 */
	public static @NonNull Builder builder() {
		return new Builder();
	}

	/**
	 * Constructs a store with the default limits and UTC system clock.
	 *
	 * @return the store
	 * @since 1.0.0
	 */
	public static @NonNull InMemoryPendingAuthorizationStore fromDefaults() {
		return builder().build();
	}

	/**
	 * Saves a record whose expiry is after now and no more than 60 minutes away. No live record is evicted.
	 *
	 * @param browserBinding the browser-specific binding
	 * @param state the authorization state
	 * @param opaqueRecord the opaque record
	 * @param expiresAt its exact expiry
	 * @since 1.0.0
	 */
	@Override
	public void save(@NonNull String browserBinding, @NonNull String state, @NonNull String opaqueRecord,
			@NonNull Instant expiresAt) {
		checkLookupInputs(browserBinding, state);
		requireNonNull(opaqueRecord);
		requireNonNull(expiresAt);
		if (opaqueRecord.isEmpty())
			throw new IllegalArgumentException("A pending record must not be empty.");
		long recordBytes = utf8Length(opaqueRecord, this.maximumOpaqueRecordBytes);
		if (recordBytes > this.maximumOpaqueRecordBytes)
			throw new IllegalArgumentException("A pending record exceeds the configured byte limit.");
		long charged = recordBytes + utf8Length(browserBinding, this.maximumChargedBytes)
				+ utf8Length(state, this.maximumChargedBytes);
		if (charged > this.maximumChargedBytes)
			throw new IllegalArgumentException("A pending record exceeds the store byte limit.");

		this.lock.lock();
		try {
			Instant now = this.clock.instant();
			if (!expiresAt.isAfter(now) || expiresAt.isAfter(now.plus(Duration.ofMinutes(60))))
				throw new IllegalArgumentException("A pending record expiry must be within 60 minutes.");
			pruneExpired(now);
			Key key = new Key(browserBinding, state);
			if (this.entries.containsKey(key))
				throw new IllegalArgumentException("A live pending record already exists.");
			if (this.entries.size() >= this.maximumLiveEntries
					|| charged > this.maximumChargedBytes - this.chargedBytes)
				throw PendingAuthorizationStoreException.fromReason(OAuthException.Reason.CAPACITY_EXCEEDED);
			this.entries.put(key, new Entry(opaqueRecord, expiresAt, charged));
			this.chargedBytes += charged;
		} finally {
			this.lock.unlock();
		}
	}

	/**
	 * Atomically removes the matching record, including an expired one.
	 *
	 * @param browserBinding the browser-specific binding
	 * @param state the authorization state
	 * @return the record when it was still live
	 * @since 1.0.0
	 */
	@Override
	public @NonNull Optional<@NonNull String> consume(@NonNull String browserBinding, @NonNull String state) {
		checkLookupInputs(browserBinding, state);
		this.lock.lock();
		try {
			Entry removed = this.entries.remove(new Key(browserBinding, state));
			if (removed == null)
				return Optional.empty();
			this.chargedBytes -= removed.chargedBytes;
			return this.clock.instant().isBefore(removed.expiresAt) ? Optional.of(removed.record) : Optional.empty();
		} finally {
			this.lock.unlock();
		}
	}

	private void pruneExpired(@NonNull Instant now) {
		Iterator<Map.Entry<Key, Entry>> iterator = this.entries.entrySet().iterator();
		while (iterator.hasNext()) {
			Entry entry = iterator.next().getValue();
			if (!now.isBefore(entry.expiresAt)) {
				this.chargedBytes -= entry.chargedBytes;
				iterator.remove();
			}
		}
	}

	private static void checkLookupInputs(@NonNull String browserBinding, @NonNull String state) {
		if (requireNonNull(browserBinding).isEmpty() || requireNonNull(state).isEmpty())
			throw new IllegalArgumentException("A browser binding and state must not be empty.");
	}

	private static long utf8Length(@NonNull String value, long cap) {
		if (value.length() > cap)
			return cap + 1;
		byte[] encoded;
		try {
			encoded = StrictUtf8.encode(value);
		} catch (EncodingException exception) {
			throw new IllegalArgumentException("A pending record contains invalid text.");
		}
		try {
			return encoded.length;
		} finally {
			Arrays.fill(encoded, (byte) 0);
		}
	}

	private record Key(@NonNull String binding, @NonNull String state) {
	}

	private record Entry(@NonNull String record, @NonNull Instant expiresAt, long chargedBytes) {
	}

	/**
	 * Configures the store. The builder is not thread-safe; the built store is.
	 *
	 * @author <a href="https://www.revetkn.com">Mark Allen</a>
	 * @since 1.0.0
	 */
	@NotThreadSafe
	@CheckReturnValue
	public static final class Builder {
		private int maximumLiveEntries = Limits.PENDING_AUTHORIZATION_STORE_ENTRIES.getDefaultIntValue();
		private long maximumChargedBytes = Limits.PENDING_AUTHORIZATION_STORE_BYTES.getDefaultValue();
		private int maximumOpaqueRecordBytes = Limits.PENDING_AUTHORIZATION_RECORD_BYTES.getDefaultIntValue();
		private @NonNull Clock clock = Clock.systemUTC();

		private Builder() {
		}

		/**
		 * Sets the maximum live entry count.
		 *
		 * @param value 16 to 65,536, or null which restores the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder maximumLiveEntries(@Nullable Integer value) {
			this.maximumLiveEntries = value == null ? Limits.PENDING_AUTHORIZATION_STORE_ENTRIES.getDefaultIntValue() : Math.toIntExact(Limits.PENDING_AUTHORIZATION_STORE_ENTRIES.require(value));
			return this;
		}

		/**
		 * Sets the maximum charged UTF-8 bytes across live records.
		 *
		 * @param value 64 KiB to 64 MiB, or null which restores the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder maximumChargedBytes(@Nullable Long value) {
			this.maximumChargedBytes = value == null ? Limits.PENDING_AUTHORIZATION_STORE_BYTES.getDefaultValue() : Limits.PENDING_AUTHORIZATION_STORE_BYTES.require(value);
			return this;
		}

		/**
		 * Sets the maximum UTF-8 bytes in one opaque record.
		 *
		 * @param value 1 KiB to 64 KiB, or null which restores the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder maximumOpaqueRecordBytes(@Nullable Integer value) {
			this.maximumOpaqueRecordBytes = value == null ? Limits.PENDING_AUTHORIZATION_RECORD_BYTES.getDefaultIntValue() : Math.toIntExact(Limits.PENDING_AUTHORIZATION_RECORD_BYTES.require(value));
			return this;
		}

		/**
		 * Sets the clock used for expiry checks.
		 *
		 * @param value the clock, or null which restores the default
		 * @return this builder
		 * @since 1.0.0
		 */
		public @NonNull Builder clock(@Nullable Clock value) {
			this.clock = value == null ? Clock.systemUTC() : value;
			return this;
		}

		/**
		 * Builds the store without starting a thread or doing I/O.
		 *
		 * @return the store
		 * @since 1.0.0
		 */
		public @NonNull InMemoryPendingAuthorizationStore build() {
			if (this.maximumOpaqueRecordBytes > this.maximumChargedBytes)
				throw new IllegalArgumentException("One record limit must not exceed the total store byte limit.");
			return new InMemoryPendingAuthorizationStore(this);
		}
	}
}
