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
import com.pyranid.DatabaseException;
import com.pyranid.DatabaseType;
import com.pyranid.TransactionIsolation;
import com.pyranid.TransactionOptions;
import com.pyranid.TransactionResult;
import com.revetsec.oauth.PendingAuthorizationStore;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.logging.Logger;

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
				SaveOutcome result = transaction(deadline, connection -> save(connection, key, opaqueRecord,
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
			return transaction(deadline, connection -> consume(connection, key, deadline));
		} finally {
			Arrays.fill(key, (byte) 0);
		}
	}

	private @NonNull SaveOutcome save(@NonNull Connection connection, byte @NonNull [] key,
			@NonNull String record, @NonNull Instant expiresAt, int charge, long deadline) throws SQLException {
		Instant now = observe(connection, deadline);
		Duration lifetime = Duration.between(now, expiresAt);
		if (lifetime.isNegative() || lifetime.isZero() || lifetime.compareTo(MAXIMUM_LIFETIME) > 0)
			return SaveOutcome.INVALID_EXPIRY;
		bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement("DELETE FROM pending_authorization "
				+ "WHERE namespace=? AND (expires_seconds<? OR (expires_seconds=? AND expires_nanos<=?))")) {
			statement.setString(1, this.namespace);
			statement.setLong(2, now.getEpochSecond());
			statement.setLong(3, now.getEpochSecond());
			statement.setInt(4, now.getNano());
			statement.executeUpdate();
		}
		bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement(
				"SELECT 1 FROM pending_authorization WHERE namespace=? AND storage_key=?")) {
			statement.setString(1, this.namespace);
			statement.setBytes(2, key);
			try (ResultSet result = statement.executeQuery()) {
				if (result.next()) return SaveOutcome.DUPLICATE;
			}
		}
		bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement(
				"SELECT count(*),coalesce(sum(charged_bytes),0) FROM pending_authorization WHERE namespace=?")) {
			statement.setString(1, this.namespace);
			try (ResultSet result = statement.executeQuery()) {
				if (!result.next() || result.getLong(1) >= this.maximumLiveEntries
						|| result.getLong(2) > this.maximumChargedBytes - charge)
					return SaveOutcome.CAPACITY;
			}
		}
		bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement("INSERT INTO pending_authorization "
				+ "(namespace,storage_key,opaque_record,expires_seconds,expires_nanos,charged_bytes) VALUES (?,?,?,?,?,?)")) {
			statement.setString(1, this.namespace);
			statement.setBytes(2, key);
			statement.setString(3, record);
			statement.setLong(4, expiresAt.getEpochSecond());
			statement.setInt(5, expiresAt.getNano());
			statement.setInt(6, charge);
			if (statement.executeUpdate() != 1) throw new SQLException("Pending insert did not affect one row.");
		}
		return SaveOutcome.SAVED;
	}

	private @NonNull Optional<@NonNull String> consume(@NonNull Connection connection, byte @NonNull [] key,
			long deadline) throws SQLException {
		Instant now = observe(connection, deadline);
		String record;
		Instant expiresAt;
		bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement("SELECT opaque_record,expires_seconds,expires_nanos "
				+ "FROM pending_authorization WHERE namespace=? AND storage_key=?")) {
			statement.setString(1, this.namespace);
			statement.setBytes(2, key);
			try (ResultSet result = statement.executeQuery()) {
				if (!result.next()) return Optional.empty();
				record = result.getString(1);
				expiresAt = Instant.ofEpochSecond(result.getLong(2), result.getInt(3));
			}
		}
		bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement(
				"DELETE FROM pending_authorization WHERE namespace=? AND storage_key=?")) {
			statement.setString(1, this.namespace);
			statement.setBytes(2, key);
			if (statement.executeUpdate() != 1) throw new SQLException("Pending consume did not affect one row.");
		}
		return now.isBefore(expiresAt) ? Optional.of(record) : Optional.empty();
	}

	private @NonNull Instant observe(@NonNull Connection connection, long deadline) throws SQLException {
		bound(connection, deadline);
		Instant previous;
		try (PreparedStatement statement = connection.prepareStatement("SELECT observed_seconds,observed_nanos "
				+ "FROM pending_authorization_clock WHERE namespace=? FOR UPDATE")) {
			statement.setString(1, this.namespace);
			try (ResultSet result = statement.executeQuery()) {
				if (!result.next()) throw new SQLException("Missing pending-store clock fence.");
				previous = Instant.ofEpochSecond(result.getLong(1), result.getInt(2));
			}
		}
		bound(connection, deadline);
		Instant observed;
		try (Statement statement = connection.createStatement();
				ResultSet result = statement.executeQuery("SELECT clock_timestamp()")) {
			if (!result.next()) throw new SQLException("Missing database time.");
			observed = result.getTimestamp(1).toInstant();
		}
		Instant now = observed.isAfter(previous) ? observed : previous;
		bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement("UPDATE pending_authorization_clock "
				+ "SET observed_seconds=?,observed_nanos=? WHERE namespace=?")) {
			statement.setLong(1, now.getEpochSecond());
			statement.setInt(2, now.getNano());
			statement.setString(3, this.namespace);
			if (statement.executeUpdate() != 1) throw new SQLException("Missing pending-store clock fence.");
		}
		return now;
	}

	private <@NonNull T> @NonNull T transaction(long deadline, @NonNull Operation<@NonNull T> operation) {
		Database database = Database.withDataSource(new DeadlineDataSource(this.source, deadline))
				.databaseType(DatabaseType.POSTGRESQL).build();
		Completion completion = new Completion();
		Holder<T> candidate = new Holder<>();
		try {
			Optional<T> result = database.transaction(TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(), () -> {
				database.currentTransaction().orElseThrow().addPostTransactionOperation(value -> completion.result = value);
				return database.useRawConnection(connection -> {
					bound(connection, deadline);
					try (Statement statement = connection.createStatement()) {
						statement.execute("SET LOCAL synchronous_commit=on");
					}
					T prepared = operation.apply(connection);
					candidate.value = prepared;
					bound(connection, deadline);
					return Optional.of(prepared);
				});
			});
			if (completion.result != TransactionResult.COMMITTED || expired(deadline)) throw unavailable();
			return result.orElseThrow(PostgresqlPendingAuthorizationStore::unavailable);
		} catch (DatabaseException failure) {
			if (completion.result == TransactionResult.COMMITTED && candidate.value != null && !expired(deadline))
				return candidate.value;
			throw unavailable();
		} catch (RuntimeException failure) {
			throw unavailable();
		}
	}

	private static void bound(@NonNull Connection connection, long deadline) throws SQLException {
		int milliseconds = milliseconds(deadline);
		try (Statement statement = connection.createStatement()) {
			statement.execute("SET LOCAL statement_timeout='" + milliseconds + "ms'");
		}
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

	private static int milliseconds(long deadline) {
		long nanoseconds = deadline - System.nanoTime();
		if (nanoseconds <= 0 || Thread.currentThread().isInterrupted()) throw unavailable();
		return (int) Math.max(1, Math.min(60_000, (nanoseconds + 999_999) / 1_000_000));
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
		@NonNull T apply(@NonNull Connection connection) throws SQLException;
	}
	private static final class Completion {
		private @Nullable TransactionResult result;
	}
	private static final class Holder<@NonNull T> {
		private @Nullable T value;
	}

	/** DataSource facade for one operation; connection acquisition remains the application's responsibility. */
	private static final class DeadlineDataSource implements DataSource {
		private final @NonNull ConnectionSource source;
		private final long deadline;
		private DeadlineDataSource(@NonNull ConnectionSource source, long deadline) {
			this.source = source;
			this.deadline = deadline;
		}
		@Override public @NonNull Connection getConnection() throws SQLException {
			long nanoseconds = this.deadline - System.nanoTime();
			if (nanoseconds <= 0 || Thread.currentThread().isInterrupted()) throw unavailable();
			Connection physical = requireNonNull(this.source.open(Duration.ofNanos(nanoseconds)));
			try {
				if (expired(this.deadline)) throw unavailable();
				physical.setNetworkTimeout(Runnable::run, milliseconds(this.deadline));
				return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
						new Class<?>[] { Connection.class }, new java.lang.reflect.InvocationHandler() {
							@Override public @Nullable Object invoke(@NonNull Object proxy, @NonNull Method method,
									@Nullable Object @Nullable [] arguments) throws Throwable {
								String name = method.getName();
								if (!name.equals("close") && !name.equals("rollback") && !name.equals("isClosed")
										&& !name.equals("abort"))
									physical.setNetworkTimeout(Runnable::run, milliseconds(DeadlineDataSource.this.deadline));
								try { return method.invoke(physical, arguments); }
								catch (InvocationTargetException failure) { throw failure.getCause(); }
							}
						});
			} catch (SQLException | RuntimeException failure) {
				try { physical.close(); } catch (SQLException ignored) { }
				throw failure;
			}
		}
		@Override public @NonNull Connection getConnection(@Nullable String user, @Nullable String password) throws SQLException {
			throw new SQLFeatureNotSupportedException("Use the configured connection source.");
		}
		@Override public @Nullable PrintWriter getLogWriter() { return null; }
		@Override public void setLogWriter(@Nullable PrintWriter writer) throws SQLException {
			throw new SQLFeatureNotSupportedException("No database credential logging.");
		}
		@Override public void setLoginTimeout(int seconds) throws SQLException {
			throw new SQLFeatureNotSupportedException("Use the operation budget.");
		}
		@Override public int getLoginTimeout() { return 0; }
		@Override public @NonNull Logger getParentLogger() throws SQLFeatureNotSupportedException {
			throw new SQLFeatureNotSupportedException("No database credential logging.");
		}
		@Override public <@NonNull T> @NonNull T unwrap(@NonNull Class<@NonNull T> type) throws SQLException {
			throw new SQLFeatureNotSupportedException("No unwrap.");
		}
		@Override public boolean isWrapperFor(@NonNull Class<?> type) { return false; }
	}
}
