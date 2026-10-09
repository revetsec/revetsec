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

package example.pending;

import com.pyranid.Database;
import com.pyranid.DatabaseType;
import com.pyranid.TransactionIsolation;
import com.pyranid.TransactionOptions;
import com.pyranid.TransactionResult;
import com.revetsec.oauth.PendingAuthorizationStore;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Application-side PostgreSQL example for atomic pending OAuth/OIDC callbacks. All nodes must use the same
 * namespace and primary. The application supplies a connection source that bounds acquisition by the requested
 * remaining time, provisions the schema, protects database credentials and record plaintext, and fences restores.
 * No successful record is released until Pyranid confirms the transaction committed.
 */
@ThreadSafe
public final class PostgresqlPendingAuthorizationStore implements PendingAuthorizationStore {
	private static final int MAXIMUM_INPUT_CHARACTERS = 65_536;
	private static final Duration MAXIMUM_LIFETIME = Duration.ofMinutes(60);
	private final @NonNull String namespace;
	private final @NonNull ConnectionSource source;
	private final int maximumLiveEntries;
	private final int maximumOpaqueRecordBytes;
	private final long maximumChargedBytes;

	/** Database rows mapped by Pyranid. */
	public record PendingRow(@NonNull String opaqueRecord, long expiresSeconds, int expiresNanos) {
		@Override public @NonNull String toString() { return "PendingRow{<redacted>}"; }
	}
	public record ClockRow(long observedSeconds, int observedNanos) { }
	public record UsageRow(long total, long charged) { }

	/** The application must bound connection acquisition by the supplied budget and return only a primary connection. */
	@FunctionalInterface
	public interface ConnectionSource {
		@NonNull Connection open(@NonNull Duration remaining) throws SQLException;
	}

	public PostgresqlPendingAuthorizationStore(@NonNull String namespace, @NonNull ConnectionSource source,
			int maximumLiveEntries, int maximumOpaqueRecordBytes, long maximumChargedBytes) {
		this.namespace = requireNonNull(namespace);
		this.source = requireNonNull(source);
		if (namespace.isEmpty() || namespace.length() > 128 || !namespace.matches("[A-Za-z0-9_-]+"))
			throw new IllegalArgumentException("The storage namespace must be 1-128 ASCII token characters.");
		if (maximumLiveEntries < 1 || maximumLiveEntries > 65_536 || maximumOpaqueRecordBytes < 1
				|| maximumOpaqueRecordBytes > 65_536 || maximumChargedBytes < maximumOpaqueRecordBytes + 32L
				|| maximumChargedBytes > 64L * 1_024 * 1_024)
			throw new IllegalArgumentException("The pending-store capacity is invalid.");
		this.maximumLiveEntries = maximumLiveEntries;
		this.maximumOpaqueRecordBytes = maximumOpaqueRecordBytes;
		this.maximumChargedBytes = maximumChargedBytes;
	}

	@Override
	public void save(@NonNull String browserBinding, @NonNull String state, @NonNull String opaqueRecord,
			@NonNull Instant expiresAt, @NonNull Duration remaining) {
		long deadline = deadline(remaining);
		requireNonNull(expiresAt);
		byte[] key = key(browserBinding, state);
		try {
			byte[] recordBytes = strictUtf8(requireNonNull(opaqueRecord));
			try {
				if (recordBytes.length == 0 || recordBytes.length > this.maximumOpaqueRecordBytes)
					throw new IllegalArgumentException("The pending record exceeds its byte limit.");
				int charge = recordBytes.length + key.length;
				SaveOutcome result = transaction(deadline, database -> save(database, key, opaqueRecord,
						expiresAt, charge, deadline));
				if (result == SaveOutcome.DUPLICATE)
					throw new IllegalArgumentException("A live pending record already exists.");
				if (result == SaveOutcome.INVALID_EXPIRY)
					throw new IllegalArgumentException("Pending expiry must be within 60 minutes.");
				if (result == SaveOutcome.CAPACITY)
					throw unavailable();
			} finally {
				Arrays.fill(recordBytes, (byte) 0);
			}
		} finally {
			Arrays.fill(key, (byte) 0);
		}
	}

	@Override
	public @NonNull Optional<@NonNull String> consume(@NonNull String browserBinding, @NonNull String state,
			@NonNull Duration remaining) {
		long deadline = deadline(remaining);
		byte[] key = key(browserBinding, state);
		try {
			return transaction(deadline, database -> consume(database, key, deadline));
		} finally {
			Arrays.fill(key, (byte) 0);
		}
	}

	private @NonNull SaveOutcome save(@NonNull Database database, byte @NonNull [] key,
			@NonNull String record, @NonNull Instant expiresAt, int charge, long deadline) throws SQLException {
		Instant now = observe(database, deadline);
		Duration lifetime = Duration.between(now, expiresAt);
		if (lifetime.isNegative() || lifetime.isZero() || lifetime.compareTo(MAXIMUM_LIFETIME) > 0)
			return SaveOutcome.INVALID_EXPIRY;
		bound(database, deadline);
		database.query("DELETE FROM pending_authorization WHERE namespace=:namespace "
				+ "AND (expires_seconds<:seconds OR (expires_seconds=:seconds AND expires_nanos<=:nanos))")
				.bind("namespace", this.namespace).bind("seconds", now.getEpochSecond())
				.bind("nanos", now.getNano()).execute();
		bound(database, deadline);
		if (database.query("SELECT 1 FROM pending_authorization WHERE namespace=:namespace AND storage_key=:key")
				.bind("namespace", this.namespace).bind("key", key).fetchObject(Integer.class).isPresent())
			return SaveOutcome.DUPLICATE;
		bound(database, deadline);
		UsageRow usage = database.query("SELECT count(*) AS total,coalesce(sum(charged_bytes),0) AS charged "
				+ "FROM pending_authorization WHERE namespace=:namespace")
				.bind("namespace", this.namespace).fetchObject(UsageRow.class).orElseThrow();
		if (usage.total() >= this.maximumLiveEntries || usage.charged() > this.maximumChargedBytes - charge)
			return SaveOutcome.CAPACITY;
		bound(database, deadline);
		if (database.query("INSERT INTO pending_authorization "
				+ "(namespace,storage_key,opaque_record,expires_seconds,expires_nanos,charged_bytes) "
				+ "VALUES (:namespace,:key,:record,:seconds,:nanos,:charge)")
				.bind("namespace", this.namespace).bind("key", key).bind("record", record)
				.bind("seconds", expiresAt.getEpochSecond()).bind("nanos", expiresAt.getNano())
				.bind("charge", charge).execute() != 1)
			throw new SQLException("Pending insert did not affect one row.");
		return SaveOutcome.SAVED;
	}

	private @NonNull Optional<@NonNull String> consume(@NonNull Database database, byte @NonNull [] key,
			long deadline) throws SQLException {
		Instant now = observe(database, deadline);
		bound(database, deadline);
		Optional<PendingRow> found = database.query("SELECT opaque_record,expires_seconds,expires_nanos "
				+ "FROM pending_authorization WHERE namespace=:namespace AND storage_key=:key")
				.bind("namespace", this.namespace).bind("key", key).fetchObject(PendingRow.class);
		if (found.isEmpty()) return Optional.empty();
		bound(database, deadline);
		if (database.query("DELETE FROM pending_authorization WHERE namespace=:namespace AND storage_key=:key")
				.bind("namespace", this.namespace).bind("key", key).execute() != 1)
			throw new SQLException("Pending consume did not affect one row.");
		PendingRow row = found.orElseThrow();
		Instant expiresAt = Instant.ofEpochSecond(row.expiresSeconds(), row.expiresNanos());
		return now.isBefore(expiresAt) ? Optional.of(row.opaqueRecord()) : Optional.empty();
	}

	private @NonNull Instant observe(@NonNull Database database, long deadline) throws SQLException {
		bound(database, deadline);
		ClockRow clock = database.query("SELECT observed_seconds,observed_nanos FROM pending_authorization_clock "
				+ "WHERE namespace=:namespace FOR UPDATE")
				.bind("namespace", this.namespace).fetchObject(ClockRow.class)
				.orElseThrow(() -> new SQLException("Missing pending-store clock fence."));
		Instant previous = Instant.ofEpochSecond(clock.observedSeconds(), clock.observedNanos());
		bound(database, deadline);
		Instant observed = database.query("SELECT clock_timestamp()")
				.fetchObject(Timestamp.class).orElseThrow(() -> new SQLException("Missing database time.")).toInstant();
		Instant now = observed.isAfter(previous) ? observed : previous;
		bound(database, deadline);
		if (database.query("UPDATE pending_authorization_clock SET observed_seconds=:seconds,"
				+ "observed_nanos=:nanos WHERE namespace=:namespace")
				.bind("seconds", now.getEpochSecond()).bind("nanos", now.getNano())
				.bind("namespace", this.namespace).execute() != 1)
			throw new SQLException("Missing pending-store clock fence.");
		return now;
	}

	private <@NonNull T> @NonNull T transaction(long deadline, @NonNull Operation<@NonNull T> operation) {
		Database database = Database.withDataSource(new PostgresqlPyranidDataSource(this.source::open, deadline))
				.databaseType(DatabaseType.POSTGRESQL).build();
		Completion completion = new Completion();
		Holder<T> candidate = new Holder<>();
		try {
			Optional<T> result = database.transaction(TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(), () -> {
				database.currentTransaction().orElseThrow().addPostTransactionOperation(value -> completion.result = value);
				bound(database, deadline);
				database.query("SELECT set_config('synchronous_commit', 'on', true)")
						.fetchObject(String.class).orElseThrow();
				T prepared = operation.apply(database);
				candidate.value = prepared;
				bound(database, deadline);
				return Optional.of(prepared);
			});
			if (completion.result != TransactionResult.COMMITTED || expired(deadline)) throw unavailable();
			return result.orElseThrow(PostgresqlPendingAuthorizationStore::unavailable);
		} catch (RuntimeException failure) {
			if (completion.result == TransactionResult.COMMITTED && candidate.value != null && !expired(deadline))
				return candidate.value;
			throw unavailable();
		}
	}

	private static void bound(@NonNull Database database, long deadline) throws SQLException {
		PostgresqlPyranidDataSource.bound(database, deadline);
	}

	private static long deadline(@NonNull Duration remaining) {
		Duration checked = requireNonNull(remaining);
		if (checked.isNegative() || checked.isZero())
			throw unavailable();
		Duration capped = checked.compareTo(Duration.ofMinutes(1)) > 0 ? Duration.ofMinutes(1) : checked;
		return System.nanoTime() + capped.toNanos();
	}

	private static boolean expired(long deadline) {
		return deadline - System.nanoTime() <= 0 || Thread.currentThread().isInterrupted();
	}

	private static @NonNull IllegalStateException unavailable() {
		return new IllegalStateException("Pending authorization storage is unavailable.");
	}

	private static byte @NonNull [] key(@NonNull String browserBinding, @NonNull String state) {
		if (requireNonNull(browserBinding).isEmpty() || requireNonNull(state).isEmpty())
			throw new IllegalArgumentException("Browser binding and state must not be empty.");
		byte[] binding = strictUtf8(browserBinding);
		try {
			byte[] stateBytes = strictUtf8(state);
			try {
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				digest.update(ByteBuffer.allocate(4).putInt(binding.length).array());
				digest.update(binding);
				digest.update(stateBytes);
				return digest.digest();
			} catch (NoSuchAlgorithmException impossible) {
				throw new IllegalStateException("SHA-256 is unavailable.");
			} finally {
				Arrays.fill(stateBytes, (byte) 0);
			}
		} finally {
			Arrays.fill(binding, (byte) 0);
		}
	}

	private static byte @NonNull [] strictUtf8(@NonNull String value) {
		if (requireNonNull(value).length() > MAXIMUM_INPUT_CHARACTERS)
			throw new IllegalArgumentException("Pending storage input is too long.");
		try {
			ByteBuffer bytes = StandardCharsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(value));
			try {
				byte[] copy = new byte[bytes.remaining()];
				bytes.get(copy);
				return copy;
			} finally {
				if (bytes.hasArray()) Arrays.fill(bytes.array(), (byte) 0);
			}
		} catch (CharacterCodingException failure) {
			throw new IllegalArgumentException("Pending storage input has invalid UTF-8 text.");
		}
	}

	private enum SaveOutcome { SAVED, DUPLICATE, CAPACITY, INVALID_EXPIRY }
	@FunctionalInterface
	private interface Operation<@NonNull T> {
		@NonNull T apply(@NonNull Database database) throws SQLException;
	}
	private static final class Completion {
		private @Nullable TransactionResult result;
	}
	private static final class Holder<@NonNull T> {
		private @Nullable T value;
	}

}
