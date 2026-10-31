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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.TreeMap;

/** Private allocated-capacity components. Framing inspection is not authentication. */
final class WebAuthnPgCapacity {
	static final int BUCKETS = 256;
	static final long TOTP_ENTRY_CAP = 65_536;
	static final long TOTP_BYTE_CAP = 268_435_456;
	static final long OTHER_ENTRY_CAP = 1_000_000;

	private WebAuthnPgCapacity() { }

	static int bucket(@NonNull String storageKey) {
		if (storageKey.isEmpty() || storageKey.length() > 640)
			throw new IllegalArgumentException("Invalid capacity address");
		for (int i = 0; i < storageKey.length(); ++i)
			if (storageKey.charAt(i) < 0x21 || storageKey.charAt(i) > 0x7e)
				throw new IllegalArgumentException("Invalid capacity address");
		try {
			return MessageDigest.getInstance("SHA-256").digest(storageKey.getBytes(StandardCharsets.US_ASCII))[0] & 0xff;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 unavailable", e);
		}
	}

	static long base64Length(long bytes) {
		if (bytes < 0 || bytes > (Long.MAX_VALUE - 2) / 4)
			throw new IllegalArgumentException("Invalid framing length");
		return (bytes * 4 + 2) / 3;
	}

	static @NonNull Reservation totpReservation(byte @NonNull [] coreAscii) {
		if (coreAscii.length < 1 || coreAscii.length > 65_536)
			throw new IllegalArgumentException("Invalid TOTP wire length");
		for (byte value : coreAscii)
			if (value < 0)
				throw new IllegalArgumentException("TOTP wire must be ASCII");
		String form = new String(coreAscii, StandardCharsets.US_ASCII);
		byte[] raw;
		try {
			raw = Base64.getUrlDecoder().decode(form);
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("Invalid TOTP wire encoding", e);
		}
		try {
			if (!Base64.getUrlEncoder().withoutPadding().encodeToString(raw).equals(form)
					|| raw.length < 55 || (raw[0] & 0xff) != 1)
				throw new IllegalArgumentException("Invalid TOTP wire framing");
			int keyLength = raw[1] & 0xff;
			if (keyLength < 1 || keyLength > 64 || raw.length < 54 + keyLength)
				throw new IllegalArgumentException("Invalid TOTP key length");
			for (int i = 2; i < 2 + keyLength; ++i) {
				int c = raw[i] & 0xff;
				if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
						|| c == '.' || c == '_' || c == '~' || c == '-'))
					throw new IllegalArgumentException("Invalid TOTP key identifier");
			}
			int plaintext = raw.length - 54 - keyLength;
			long reserved = base64Length(118L + plaintext);
			if (reserved < coreAscii.length || reserved > 65_536)
				throw new IllegalArgumentException("TOTP reservation exceeds carrier");
			return new Reservation(coreAscii.length, reserved, plaintext, keyLength);
		} finally {
			Arrays.fill(raw, (byte) 0);
		}
	}

	static @NonNull Allocation allocate(@NonNull String family, long entryCap, long byteCap,
			long @NonNull [] actualEntries, long @NonNull [] actualBytes,
			long @NonNull [] bootstrapEntries, long @NonNull [] bootstrapBytes) {
		boolean totp = family.equals("TOTP");
		if (!(totp || family.equals("ISSUER") || family.equals("WEBAUTHN"))
				|| entryCap < 1 || entryCap > (totp ? TOTP_ENTRY_CAP : OTHER_ENTRY_CAP)
				|| (totp ? byteCap < 1 || byteCap > TOTP_BYTE_CAP : byteCap != 0))
			throw new IllegalArgumentException("Unsupported allocated capacity");
		long[] entryLimits = dimension(entryCap, actualEntries, bootstrapEntries);
		long[] byteLimits = dimension(byteCap, actualBytes, bootstrapBytes);
		return new Allocation(entryLimits, byteLimits, actualEntries, actualBytes);
	}

	private static long @NonNull [] dimension(long cap, long @NonNull [] actual, long @NonNull [] bootstrap) {
		if (actual.length != BUCKETS || bootstrap.length != BUCKETS)
			throw new IllegalArgumentException("Expected 256 capacity buckets");
		long[] seed = new long[BUCKETS];
		long sum = 0;
		try {
			for (int i = 0; i < BUCKETS; ++i) {
				if (actual[i] < 0 || bootstrap[i] < 0)
					throw new IllegalArgumentException("Negative capacity inventory");
				seed[i] = Math.addExact(actual[i], bootstrap[i]);
				sum = Math.addExact(sum, seed[i]);
			}
		} catch (ArithmeticException e) {
			throw new IllegalArgumentException("Capacity inventory overflow", e);
		}
		if (sum > cap)
			throw new IllegalArgumentException("Capacity cannot fit retained and bootstrap inventory");
		long remaining = cap - sum;
		for (int i = 0; i < BUCKETS; ++i)
			seed[i] += remaining / BUCKETS + (i < remaining % BUCKETS ? 1 : 0);
		return seed;
	}

	/** Locks only nonzero merged buckets; the caller already holds admission/entity locks. */
	static @NonNull LockedPlan lockAndCheck(@NonNull Connection connection, @NonNull WebAuthnPgScope scope,
			@NonNull String allocationGeneration, @NonNull List<@NonNull Delta> deltas,
			long deadlineNanos) throws SQLException {
		LockedPlan plan = lockForValidation(connection, scope, allocationGeneration, deltas, deadlineNanos);
		plan.checkCapacity();
		return plan;
	}

	/** Locks the entire affected bucket set before the caller's fresh temporal validation. */
	static @NonNull LockedPlan lockForValidation(@NonNull Connection connection, @NonNull WebAuthnPgScope scope,
			@NonNull String allocationGeneration, @NonNull List<@NonNull Delta> deltas,
			long deadlineNanos) throws SQLException {
		identifier(allocationGeneration);
		if (connection.getAutoCommit())
			throw new SQLException("Capacity requires a top-level transaction");
		TreeMap<Integer, Delta> merged = new TreeMap<>();
		try {
			for (Delta delta : deltas) {
				Delta old = merged.get(delta.bucket);
				merged.put(delta.bucket, old == null ? delta : Delta.from(delta.bucket,
						Math.addExact(old.entries, delta.entries), Math.addExact(old.bytes, delta.bytes)));
			}
		} catch (ArithmeticException e) {
			throw new IllegalArgumentException("Capacity delta overflow", e);
		}
		List<Row> rows = new ArrayList<>();
		for (Delta delta : merged.values()) {
			if (delta.entries == 0 && delta.bytes == 0)
				continue;
			if (!scope.getFamily().equals("TOTP") && delta.bytes != 0)
				throw new IllegalArgumentException("Unexpected byte accounting dimension");
			bound(connection, deadlineNanos);
			try (PreparedStatement statement = connection.prepareStatement("SELECT allocation_generation,entry_limit,used_entries,byte_limit,used_bytes "
					+ "FROM webauthn_store_escrow WHERE family=? AND namespace=? AND bucket=? FOR UPDATE")) {
				statement.setString(1, scope.getFamily());
				statement.setString(2, scope.getNamespace());
				statement.setInt(3, delta.bucket);
				try (ResultSet result = statement.executeQuery()) {
					if (!result.next())
						throw new SQLException("Missing assigned capacity bucket");
					if (!allocationGeneration.equals(result.getString(1)))
						throw new SQLException("Capacity allocation generation differs");
					long entryLimit = result.getLong(2), usedEntries = result.getLong(3);
					long byteLimit = result.getLong(4), usedBytes = result.getLong(5);
					validateRow(scope.getFamily(), entryLimit, usedEntries, byteLimit, usedBytes);
					long nextEntries, nextBytes;
					try {
						nextEntries = Math.addExact(usedEntries, delta.entries);
						nextBytes = Math.addExact(usedBytes, delta.bytes);
					} catch (ArithmeticException e) {
						throw new SQLException("Capacity delta overflow", e);
					}
					if (nextEntries < 0 || nextBytes < 0)
						throw new SQLException("Capacity inventory would become negative");
					rows.add(new Row(delta.bucket, entryLimit, usedEntries, byteLimit, usedBytes, nextEntries, nextBytes));
					if (result.next())
						throw new SQLException("Duplicate assigned capacity bucket");
				}
			}
		}
		String transaction = rows.isEmpty() ? null : transactionIdentity(connection, deadlineNanos);
		return new LockedPlan(connection, scope, allocationGeneration, rows, transaction);
	}

	private static void validateRow(@NonNull String family, long entryLimit, long usedEntries, long byteLimit, long usedBytes) throws SQLException {
		boolean totp = family.equals("TOTP");
		if (entryLimit < 0 || entryLimit > (totp ? TOTP_ENTRY_CAP : OTHER_ENTRY_CAP) || usedEntries < 0 || usedEntries > entryLimit
				|| byteLimit < 0 || byteLimit > (totp ? TOTP_BYTE_CAP : 0) || usedBytes < 0 || usedBytes > byteLimit)
			throw new SQLException("Assigned capacity counters invalid");
	}

	private static void identifier(@NonNull String value) {
		try {
			byte[] bytes = Base64.getUrlDecoder().decode(value);
			if (value.length() != 43 || bytes.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value))
				throw new IllegalArgumentException("Invalid capacity generation");
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("Invalid capacity generation", e);
		}
	}

	private static void bound(@NonNull Connection connection, long deadlineNanos) throws SQLException {
		long remaining = deadlineNanos - System.nanoTime();
		if (remaining <= 0 || Thread.currentThread().isInterrupted())
			throw new SQLException("Capacity original budget exhausted");
		long millis = Math.max(1, remaining / 1_000_000 + (remaining % 1_000_000 == 0 ? 0 : 1));
		if (millis > Integer.MAX_VALUE)
			throw new SQLException("Unsupported capacity budget");
		try (PreparedStatement statement = connection.prepareStatement("SELECT set_config('statement_timeout',?,true)")) {
			statement.setString(1, millis + "ms");
			statement.execute();
		}
	}

	private static @NonNull String transactionIdentity(@NonNull Connection connection, long deadlineNanos) throws SQLException {
		bound(connection, deadlineNanos);
		try (PreparedStatement statement = connection.prepareStatement("SELECT pg_current_xact_id()::text"); ResultSet result = statement.executeQuery()) {
			if (!result.next())
				throw new SQLException("Capacity transaction identity unavailable");
			String identity = result.getString(1);
			if (identity == null)
				throw new SQLException("Capacity transaction identity unavailable");
			return identity;
		}
	}

	static final class Reservation {
		private final long actual, reserved;
		private final int plaintext, keyLength;
		private Reservation(long actual, long reserved, int plaintext, int keyLength) {
			this.actual = actual; this.reserved = reserved; this.plaintext = plaintext; this.keyLength = keyLength;
		}
		long getActualBytes() { return this.actual; }
		long getReservedBytes() { return this.reserved; }
		int getPlaintextBytes() { return this.plaintext; }
		int getKeyIdLength() { return this.keyLength; }
		@Override public @NonNull String toString() { return "Reservation[structural lengths only]"; }
	}

	static final class Allocation {
		private final long[] entryLimits, byteLimits, usedEntries, usedBytes;
		private Allocation(long @NonNull [] entryLimits, long @NonNull [] byteLimits, long @NonNull [] usedEntries, long @NonNull [] usedBytes) {
			this.entryLimits = entryLimits.clone(); this.byteLimits = byteLimits.clone();
			this.usedEntries = usedEntries.clone(); this.usedBytes = usedBytes.clone();
		}
		long @NonNull [] getEntryLimits() { return this.entryLimits.clone(); }
		long @NonNull [] getByteLimits() { return this.byteLimits.clone(); }
		long @NonNull [] getUsedEntries() { return this.usedEntries.clone(); }
		long @NonNull [] getUsedBytes() { return this.usedBytes.clone(); }
	}

	static final class Delta {
		private final int bucket;
		private final long entries, bytes;
		private Delta(int bucket, long entries, long bytes) { this.bucket = bucket; this.entries = entries; this.bytes = bytes; }
		static @NonNull Delta from(int bucket, long entries, long bytes) {
			if (bucket < 0 || bucket >= BUCKETS)
				throw new IllegalArgumentException("Invalid capacity bucket");
			return new Delta(bucket, entries, bytes);
		}
		int getBucket() { return this.bucket; }
		long getEntries() { return this.entries; }
		long getBytes() { return this.bytes; }
	}

	private static final class Row {
		private final int bucket;
		private final long entryLimit, usedEntries, byteLimit, usedBytes, nextEntries, nextBytes;
		private Row(int bucket, long entryLimit, long usedEntries, long byteLimit, long usedBytes, long nextEntries, long nextBytes) {
			this.bucket = bucket; this.entryLimit = entryLimit; this.usedEntries = usedEntries;
			this.byteLimit = byteLimit; this.usedBytes = usedBytes; this.nextEntries = nextEntries; this.nextBytes = nextBytes;
		}
	}

	static final class LockedPlan {
		private final @NonNull Connection connection;
		private final @NonNull WebAuthnPgScope scope;
		private final @NonNull String generation;
		private final @NonNull List<@NonNull Row> rows;
		private final @Nullable String transaction;
		private boolean applied;
		private LockedPlan(@NonNull Connection connection, @NonNull WebAuthnPgScope scope, @NonNull String generation,
				@NonNull List<@NonNull Row> rows, @Nullable String transaction) {
			this.connection = connection; this.scope = scope; this.generation = generation;
			this.rows = List.copyOf(rows); this.transaction = transaction;
		}
		boolean isEmpty() { return this.rows.isEmpty(); }
		int getBucketCount() { return this.rows.size(); }
		/** Truthful insufficiency is evaluated only after every wait and fresh time validation. */
		void checkCapacity() throws CapacityRefused {
			for (Row row : this.rows)
				if (row.nextEntries > row.entryLimit || row.nextBytes > row.byteLimit)
					throw new CapacityRefused();
		}
		/** Caller records possible mutation before this method; every change shares its data transaction. */
		void apply(@NonNull Connection connection, long deadlineNanos) throws SQLException {
			if (this.applied || connection != this.connection || connection.getAutoCommit())
				throw new SQLException("Capacity plan is not live in its original transaction");
			this.applied = true;
			checkCapacity();
			if (this.rows.isEmpty())
				return;
			if (!transactionIdentity(connection, deadlineNanos).equals(this.transaction))
				throw new SQLException("Capacity transaction changed before application");
			for (Row row : this.rows) {
				bound(connection, deadlineNanos);
				try (PreparedStatement statement = connection.prepareStatement("UPDATE webauthn_store_escrow SET used_entries=?,used_bytes=? "
						+ "WHERE family=? AND namespace=? AND bucket=? AND allocation_generation=? AND entry_limit=? AND used_entries=? AND byte_limit=? AND used_bytes=?")) {
					statement.setLong(1, row.nextEntries); statement.setLong(2, row.nextBytes);
					statement.setString(3, this.scope.getFamily()); statement.setString(4, this.scope.getNamespace());
					statement.setInt(5, row.bucket); statement.setString(6, this.generation);
					statement.setLong(7, row.entryLimit); statement.setLong(8, row.usedEntries);
					statement.setLong(9, row.byteLimit); statement.setLong(10, row.usedBytes);
					if (statement.executeUpdate() != 1)
						throw new SQLException("Capacity application lost its exact bucket");
				}
			}
		}
	}

	static final class CapacityRefused extends SQLException {
		@java.io.Serial private static final long serialVersionUID=1L;
		private CapacityRefused() { super("Assigned capacity unavailable"); }
	}
}
