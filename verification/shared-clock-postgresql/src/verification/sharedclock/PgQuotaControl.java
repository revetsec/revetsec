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
package verification.sharedclock;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import verification.sharedclock.PgTransactions.Context;
import verification.sharedclock.PgTransactions.ConnectionSource;
import verification.sharedclock.PgTransactions.Decision;
import verification.sharedclock.PgTransactions.Outcome;
import verification.sharedclock.PgTransactions.Refusal;
import verification.sharedclock.PgCapacity.Allocation;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

/** Inactive bounded closed-admission quota control; never a normal allocation path. */
final class PgQuotaControl {
	private PgQuotaControl() { }

	static @NonNull Outcome<Boolean> bootstrap(@NonNull ConnectionSource source, @NonNull Duration budget,
			@NonNull PgScope scope, @NonNull String expectedGeneration, @NonNull String nextGeneration,
			@NonNull String expectedProfile, @NonNull String nextMetadata, @NonNull Allocation allocation) {
		return execute(source, budget, scope, expectedGeneration, nextGeneration, expectedProfile, nextMetadata, allocation, true);
	}

	static @NonNull Outcome<Boolean> reallocate(@NonNull ConnectionSource source, @NonNull Duration budget,
			@NonNull PgScope scope, @NonNull String expectedGeneration, @NonNull String nextGeneration,
			@NonNull String expectedProfile, @NonNull String nextMetadata, @NonNull Allocation allocation) {
		return execute(source, budget, scope, expectedGeneration, nextGeneration, expectedProfile, nextMetadata, allocation, false);
	}

	private static @NonNull Outcome<Boolean> execute(@NonNull ConnectionSource source, @NonNull Duration budget,
			@NonNull PgScope scope, @NonNull String expectedGeneration, @NonNull String nextGeneration,
			@NonNull String expectedProfile, @NonNull String nextMetadata, @NonNull Allocation allocation, boolean bootstrap) {
		PgPrimitives.id(expectedGeneration);
		PgPrimitives.id(nextGeneration);
		PgPrimitives.id(expectedProfile);
		PgPrimitives.id(nextMetadata);
		if (expectedGeneration.equals(nextGeneration)) throw new IllegalArgumentException("Quota generation must be fresh");
		Amounts next = new Amounts(scope, allocation.getEntryLimits(), allocation.getByteLimits(), allocation.getUsedEntries(), allocation.getUsedBytes());
		return PgTransactions.execute(source, budget, context -> {
			// This wrapper creates the transaction. No caller can arrive holding
			// entity/bucket locks and invert the required admission-first order.
			PgLocks.exclusiveAdmission(context.connection(), List.of(scope), context.deadlineNanos());
			Admission old = admission(context, scope, expectedGeneration, expectedProfile);
			if (old == null) return Decision.refuse(Refusal.FENCED);
			if (bootstrap) {
				if (!zero(next.usedEntries) || !zero(next.usedBytes) || any(context, scope, "scp05_escrow") || any(context, scope, "scp05_entries"))
					return Decision.refuse(Refusal.CONFLICT);
			} else {
				Amounts current = locked(context, scope, expectedGeneration);
				if (current == null) return Decision.refuse(Refusal.FENCED);
				if (current.totalEntries != next.totalEntries || current.totalBytes != next.totalBytes)
					return Decision.refuse(Refusal.CAPACITY);
				if (!Arrays.equals(current.usedEntries, next.usedEntries) || !Arrays.equals(current.usedBytes, next.usedBytes))
					return Decision.refuse(Refusal.CONFLICT);
				long[][] actual = inventory(context, scope);
				if (!Arrays.equals(actual[0], current.usedEntries) || !Arrays.equals(actual[1], current.usedBytes))
					return Decision.refuse(Refusal.CONFLICT);
			}
			context.check();
			context.markPossibleMutation();
			write(context, scope, expectedGeneration, nextGeneration, next, bootstrap);
			updateAdmission(context, scope, old, nextGeneration, nextMetadata);
			return Decision.commit(Boolean.TRUE);
		});
	}

	private static boolean zero(long @NonNull [] values) {
		for (long value : values) if (value != 0) return false;
		return true;
	}

	private static boolean any(@NonNull Context context, @NonNull PgScope scope, @NonNull String table) throws SQLException {
		if (!table.equals("scp05_escrow") && !table.equals("scp05_entries")) throw new SQLException("Unsupported quota inventory table");
		try (PreparedStatement statement = context.connection().prepareStatement("SELECT EXISTS(SELECT 1 FROM " + table + " WHERE family=? AND namespace=?)")) {
			context.bound(statement);
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace());
			try (ResultSet rows = statement.executeQuery()) {
				if (!rows.next()) throw new SQLException("Missing quota inventory result");
				boolean result = rows.getBoolean(1);
				if (rows.wasNull() || rows.next()) throw new SQLException("Invalid quota inventory result");
				return result;
			}
		}
	}

	private static @Nullable Admission admission(@NonNull Context context, @NonNull PgScope scope,
			@NonNull String expectedGeneration, @NonNull String expectedProfile) throws SQLException {
		try (PreparedStatement statement = context.connection().prepareStatement("SELECT * FROM scp05_admission WHERE family=? AND namespace=? FOR UPDATE")) {
			context.bound(statement);
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace());
			try (ResultSet rows = statement.executeQuery()) {
				if (!rows.next() || !"CLOSED".equals(rows.getString("mode")) || !expectedGeneration.equals(rows.getString("allocation_generation"))
						|| !expectedProfile.equals(rows.getString("profile_commitment"))) return null;
				int format = rows.getInt("format_version");
				if (format != (scope.getFamily().equals("TOTP") ? 3 : 2)) return null;
				Admission result = new Admission(rows.getString("authority_id"), rows.getString("recovery_generation"), rows.getString("clock_generation"),
						rows.getString("profile_commitment"), rows.getString("schema_commitment"), rows.getString("metadata_commitment"),
						rows.getString("writer_role_identity"), rows.getString("allocation_generation"), format);
				if (rows.next()) throw new SQLException("Duplicate quota admission");
				return result;
			}
		}
	}

	private static @Nullable Amounts locked(@NonNull Context context, @NonNull PgScope scope, @NonNull String expectedGeneration) throws SQLException {
		long[] entryLimits = new long[256], byteLimits = new long[256], usedEntries = new long[256], usedBytes = new long[256];
		try (PreparedStatement statement = context.connection().prepareStatement("SELECT bucket,allocation_generation,entry_limit,used_entries,byte_limit,used_bytes "
				+ "FROM scp05_escrow WHERE family=? AND namespace=? ORDER BY bucket FOR UPDATE")) {
			context.bound(statement);
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace());
			try (ResultSet rows = statement.executeQuery()) {
				for (int bucket = 0; bucket < 256; ++bucket) {
					if (!rows.next() || rows.getInt(1) != bucket || !expectedGeneration.equals(rows.getString(2))) return null;
					entryLimits[bucket] = rows.getLong(3); usedEntries[bucket] = rows.getLong(4);
					byteLimits[bucket] = rows.getLong(5); usedBytes[bucket] = rows.getLong(6);
				}
				if (rows.next()) throw new SQLException("Quota row count exceeded");
			}
		}
		return new Amounts(scope, entryLimits, byteLimits, usedEntries, usedBytes);
	}

	/** One administrative aggregate query returns at most 256 groups; no retained payload is loaded. */
	private static long @NonNull [] @NonNull [] inventory(@NonNull Context context, @NonNull PgScope scope) throws SQLException {
		long[][] result = new long[2][256];
		try (PreparedStatement statement = context.connection().prepareStatement("SELECT get_byte(sha256(convert_to(storage_key,'UTF8')),0) AS bucket, "
				+ "count(*) AS entries, sum(reserved_bytes) AS reserved, bool_and(storage_key ~ '^[!-~]+$') AS exact_ascii "
				+ "FROM scp05_entries WHERE family=? AND namespace=? GROUP BY bucket ORDER BY bucket")) {
			context.bound(statement);
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace());
			try (ResultSet rows = statement.executeQuery()) {
				int last = -1;
				while (rows.next()) {
					context.check();
					int bucket = rows.getInt("bucket");
					if (bucket <= last || bucket > 255 || !rows.getBoolean("exact_ascii")) throw new SQLException("Invalid bounded quota inventory");
					last = bucket;
					result[0][bucket] = rows.getLong("entries");
					try { result[1][bucket] = rows.getBigDecimal("reserved").longValueExact(); }
					catch (ArithmeticException failure) { throw new SQLException("Quota inventory overflow"); }
					if (result[0][bucket] < 0 || result[1][bucket] < 0) throw new SQLException("Negative quota inventory");
				}
			}
		}
		return result;
	}

	private static void write(@NonNull Context context, @NonNull PgScope scope, @NonNull String expectedGeneration,
			@NonNull String nextGeneration, @NonNull Amounts next, boolean bootstrap) throws SQLException {
		String sql = bootstrap ? "INSERT INTO scp05_escrow(family,namespace,bucket,allocation_generation,entry_limit,used_entries,byte_limit,used_bytes) VALUES(?,?,?,?,?,?,?,?)"
				: "UPDATE scp05_escrow SET allocation_generation=?,entry_limit=?,used_entries=?,byte_limit=?,used_bytes=? WHERE family=? AND namespace=? AND bucket=? AND allocation_generation=?";
		try (PreparedStatement statement = context.connection().prepareStatement(sql)) {
			for (int bucket = 0; bucket < 256; ++bucket) {
				context.bound(statement);
				if (bootstrap) {
					statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace()); statement.setInt(3, bucket);
					statement.setString(4, nextGeneration); statement.setLong(5, next.entryLimits[bucket]); statement.setLong(6, next.usedEntries[bucket]);
					statement.setLong(7, next.byteLimits[bucket]); statement.setLong(8, next.usedBytes[bucket]);
				} else {
					statement.setString(1, nextGeneration); statement.setLong(2, next.entryLimits[bucket]); statement.setLong(3, next.usedEntries[bucket]);
					statement.setLong(4, next.byteLimits[bucket]); statement.setLong(5, next.usedBytes[bucket]); statement.setString(6, scope.getFamily());
					statement.setString(7, scope.getNamespace()); statement.setInt(8, bucket); statement.setString(9, expectedGeneration);
				}
				if (statement.executeUpdate() != 1) throw new SQLException("Quota exact row update failed");
			}
		}
	}

	private static void updateAdmission(@NonNull Context context, @NonNull PgScope scope, @NonNull Admission old,
			@NonNull String nextGeneration, @NonNull String nextMetadata) throws SQLException {
		try (PreparedStatement statement = context.connection().prepareStatement("UPDATE scp05_admission SET allocation_generation=?,metadata_commitment=? WHERE family=? AND namespace=? "
				+ "AND mode='CLOSED' AND allocation_generation=? AND profile_commitment=? AND metadata_commitment=? AND authority_id=? AND recovery_generation=? "
				+ "AND clock_generation=? AND schema_commitment=? AND writer_role_identity=? AND format_version=?")) {
			context.bound(statement);
			statement.setString(1, nextGeneration); statement.setString(2, nextMetadata); statement.setString(3, scope.getFamily()); statement.setString(4, scope.getNamespace());
			statement.setString(5, old.generation); statement.setString(6, old.profile); statement.setString(7, old.metadata); statement.setString(8, old.authority);
			statement.setString(9, old.recovery); statement.setString(10, old.clock); statement.setString(11, old.schema); statement.setString(12, old.writer); statement.setInt(13, old.format);
			if (statement.executeUpdate() != 1) throw new SQLException("Quota admission exact update failed");
		}
	}

	private static final class Admission {
		private final @NonNull String authority, recovery, clock, profile, schema, metadata, writer, generation;
		private final int format;
		private Admission(@NonNull String authority, @NonNull String recovery, @NonNull String clock, @NonNull String profile,
				@NonNull String schema, @NonNull String metadata, @NonNull String writer, @NonNull String generation, int format) {
			this.authority = PgPrimitives.id(authority); this.recovery = PgPrimitives.id(recovery); this.clock = PgPrimitives.id(clock);
			this.profile = PgPrimitives.id(profile); this.schema = PgPrimitives.id(schema); this.metadata = PgPrimitives.id(metadata);
			this.writer = PgPrimitives.id(writer); this.generation = PgPrimitives.id(generation); this.format = format;
		}
	}

	private static final class Amounts {
		private final long @NonNull [] entryLimits, byteLimits, usedEntries, usedBytes;
		private final long totalEntries, totalBytes;
		private Amounts(@NonNull PgScope scope, long @NonNull [] entryLimits, long @NonNull [] byteLimits,
				long @NonNull [] usedEntries, long @NonNull [] usedBytes) {
			if (entryLimits.length != 256 || byteLimits.length != 256 || usedEntries.length != 256 || usedBytes.length != 256)
				throw new IllegalArgumentException("Expected256 quota arrays");
			this.entryLimits = entryLimits.clone(); this.byteLimits = byteLimits.clone(); this.usedEntries = usedEntries.clone(); this.usedBytes = usedBytes.clone();
			long entries = 0, bytes = 0;
			try {
				for (int bucket = 0; bucket < 256; ++bucket) {
					if (entryLimits[bucket] < 0 || byteLimits[bucket] < 0 || usedEntries[bucket] < 0 || usedEntries[bucket] > entryLimits[bucket]
							|| usedBytes[bucket] < 0 || usedBytes[bucket] > byteLimits[bucket]) throw new IllegalArgumentException("Invalid quota amounts");
					entries = Math.addExact(entries, entryLimits[bucket]); bytes = Math.addExact(bytes, byteLimits[bucket]);
				}
			} catch (ArithmeticException failure) { throw new IllegalArgumentException("Quota amount overflow"); }
			boolean totp = scope.getFamily().equals("TOTP");
			if (entries < 1 || entries > (totp ? PgCapacity.TOTP_ENTRY_CAP : PgCapacity.OTHER_ENTRY_CAP)
					|| (totp ? bytes < 1 || bytes > PgCapacity.TOTP_BYTE_CAP : bytes != 0)) throw new IllegalArgumentException("Quota hard profile exceeded");
			this.totalEntries = entries; this.totalBytes = bytes;
		}
	}
}
