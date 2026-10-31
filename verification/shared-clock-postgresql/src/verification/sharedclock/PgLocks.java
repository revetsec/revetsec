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
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/** Private deterministic transaction advisory-lock grammar, not an auth proof. */
public final class PgLocks {
	private PgLocks() {}
	public static final class Admission implements Comparable<Admission> {
		private final int first;
		private final int second;
		private Admission(int first, int second) { this.first = first; this.second = second; }
		public int getFirst() { return this.first; }
		public int getSecond() { return this.second; }
		@Override public int compareTo(@NonNull Admission other) {
			int result = Integer.compare(this.first, other.first);
			return result != 0 ? result : Integer.compare(this.second, other.second);
		}
		@Override public @NonNull String toString() { return "Admission[private lock]"; }
	}
	public static final class Entity {
		private final long id;
		private final boolean exclusive;
		private Entity(long id, boolean exclusive) { this.id = id; this.exclusive = exclusive; }
		public static @NonNull Entity fromId(long id, boolean exclusive) { return new Entity(id, exclusive); }
		public long getId() { return this.id; }
		public boolean isExclusive() { return this.exclusive; }
		@Override public @NonNull String toString() { return "Entity[private lock]"; }
	}
	public static @NonNull Admission admission(@NonNull PgScope scope) {
		ByteBuffer bytes = ByteBuffer.wrap(hash("revetsec/pg-admission/v1\0", scope, null));
		return new Admission(bytes.getInt(), bytes.getInt());
	}
	public static @NonNull Entity entity(@NonNull PgScope scope, @NonNull String key, boolean exclusive) {
		return Entity.fromId(ByteBuffer.wrap(hash("revetsec/pg-entity/v1\0", scope, key)).getLong(), exclusive);
	}
	public static @NonNull List<Entity> entitySet(@NonNull PgScope scope, @NonNull Map<String, Boolean> keys) {
		if (keys.size() > 16) throw new IllegalArgumentException("Logical key limit exceeded");
		List<Entity> result = new ArrayList<>();
		for (Map.Entry<String, Boolean> entry : keys.entrySet())
			result.add(entity(scope, entry.getKey(), entry.getValue()));
		return merge(result);
	}
	public static @NonNull List<Entity> merge(@NonNull Collection<Entity> values) {
		if (values.size() > 16) throw new IllegalArgumentException("Logical key limit exceeded");
		TreeMap<Long, Boolean> merged = new TreeMap<>();
		for (Entity value : values) merged.merge(value.id, value.exclusive, (left, right) -> left || right);
		List<Entity> result = new ArrayList<>();
		merged.forEach((id, exclusive) -> result.add(Entity.fromId(id, exclusive)));
		return List.copyOf(result);
	}
	public static @NonNull List<Admission> allAdmission(@NonNull Collection<PgScope> scopes) {
		if (scopes.isEmpty() || scopes.size() > 3) throw new IllegalArgumentException("Scope allowlist bound exceeded");
		TreeSet<String> families = new TreeSet<>();
		TreeSet<Admission> result = new TreeSet<>();
		for (PgScope scope : scopes) {
			if (!families.add(scope.getFamily())) throw new IllegalArgumentException("Duplicate family admission");
			result.add(admission(scope));
		}
		return List.copyOf(result);
	}
	public static void sharedAdmission(@NonNull Connection connection, @NonNull PgScope scope, long deadlineNanos) throws SQLException {
		admissionLock(connection, admission(scope), false, deadlineNanos);
	}
	public static void exclusiveAdmission(@NonNull Connection connection, @NonNull Collection<PgScope> scopes, long deadlineNanos) throws SQLException {
		for (Admission lock : allAdmission(scopes)) admissionLock(connection, lock, true, deadlineNanos);
	}
	private static void admissionLock(@NonNull Connection connection, @NonNull Admission lock, boolean exclusive, long deadlineNanos) throws SQLException {
		transaction(connection);
		bound(connection, deadlineNanos);
		try (PreparedStatement statement = connection.prepareStatement(exclusive ? "SELECT pg_advisory_xact_lock(?, ?)" : "SELECT pg_advisory_xact_lock_shared(?, ?)")) {
			statement.setInt(1, lock.first); statement.setInt(2, lock.second); statement.execute();
		}
		remaining(deadlineNanos);
	}
	public static void entities(@NonNull Connection connection, @NonNull Collection<Entity> locks, long deadlineNanos) throws SQLException {
		transaction(connection);
		for (Entity lock : merge(locks)) {
			bound(connection, deadlineNanos);
			try (PreparedStatement statement = connection.prepareStatement(lock.exclusive ? "SELECT pg_advisory_xact_lock(?)" : "SELECT pg_advisory_xact_lock_shared(?)")) {
				statement.setLong(1, lock.id); statement.execute();
			}
			remaining(deadlineNanos);
		}
	}
	public static long remaining(long deadlineNanos) throws SQLException {
		long remaining = deadlineNanos - System.nanoTime();
		if (remaining <= 0 || Thread.currentThread().isInterrupted()) throw new SQLException("Private operation budget exhausted", "57014");
		return remaining;
	}
	public static void bound(@NonNull Connection connection, long deadlineNanos) throws SQLException {
		long left = remaining(deadlineNanos);
		long millis = Math.max(1L, 1L + (left - 1L) / 1_000_000L);
		try (PreparedStatement statement = connection.prepareStatement("SELECT set_config('statement_timeout', ?, true), set_config('lock_timeout', ?, true)")) {
			String value = Long.toString(millis) + "ms";
			statement.setString(1, value); statement.setString(2, value); statement.execute();
		}
		remaining(deadlineNanos);
	}
	private static void transaction(@NonNull Connection connection) throws SQLException {
		if (connection.getAutoCommit() || connection.getTransactionIsolation() != Connection.TRANSACTION_READ_COMMITTED)
			throw new SQLException("Clean READ_COMMITTED transaction required");
	}
	private static byte @NonNull [] hash(@NonNull String domain, @NonNull PgScope scope, @org.jspecify.annotations.Nullable String key) {
		try {
			ByteArrayOutputStream bytes = new ByteArrayOutputStream();
			bytes.write(domain.getBytes(StandardCharsets.US_ASCII));
			DataOutputStream output = new DataOutputStream(bytes);
			field(output, scope.getFamily().getBytes(StandardCharsets.US_ASCII));
			field(output, PgScope.utf8(scope.getNamespace()));
			if (key != null) {
				if (key.isEmpty() || key.length() > 640 || !StandardCharsets.US_ASCII.newEncoder().canEncode(key) || key.indexOf('\0') >= 0)
					throw new IllegalArgumentException("Invalid exact ASCII storage key");
				field(output, key.getBytes(StandardCharsets.US_ASCII));
			}
			return MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray());
		} catch (IOException | NoSuchAlgorithmException failure) {
			throw new IllegalStateException("Required lock grammar unavailable", failure);
		}
	}
	private static void field(@NonNull DataOutputStream output, byte @NonNull [] value) throws IOException {
		output.writeInt(value.length); output.write(value);
	}
}
