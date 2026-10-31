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

import com.pyranid.Database;
import com.pyranid.DatabaseType;
import com.pyranid.TransactionIsolation;
import com.pyranid.TransactionOptions;
import com.pyranid.TransactionResult;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import verification.sharedclock.PgTransactions.Context;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

/** Native pinned-artifact transaction checks on one explicitly owned fixture database. */
final class PgTransactionChecks {
	private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);

	private PgTransactionChecks() { }

	public static void main(@NonNull String @NonNull [] arguments) {
		try {
			if (arguments.length == 1 && arguments[0].equals("ack-loss")) {
				acknowledgementLoss();
				return;
			}
			if (arguments.length == 1 && arguments[0].equals("barrier-ack-loss")) {
				barrierAcknowledgementLoss();
				return;
			}
			if (arguments.length != 0) throw new IllegalArgumentException("Unexpected private test argument");
			initialize();
			committedAfterClosure();
			rawLifecycleGuarded();
			rawLifetimeGuarded();
			markedRollback();
			explicitRefusal();
			preEntryFailure();
			zeroBudget();
			dirtyConnection();
			lateKnownCommit();
			postOperationFailure();
			cleanupFailure();
			refusalCleanupFailure();
			nestedHelperRefused();
			separateAmbientConnection();
			serializationFailureNotRetried();
			lateAcquisition();
			interruptAfterCommit();
			barrierWithoutMutation();
		} catch (Throwable failure) {
			Thread.interrupted();
			throw new IllegalStateException("SCP05 transaction component checks failed");
		}
	}

	private static @NonNull Connection connect(@NonNull Duration remaining) throws SQLException {
		Properties properties = new Properties();
		properties.setProperty("user", Objects.requireNonNull(System.getenv("DB_USER")));
		properties.setProperty("password", Objects.requireNonNull(System.getenv("DB_PASSWORD")));
		int seconds = (int) Math.max(1, Math.min(60, 1 + (remaining.toNanos() - 1) / 1_000_000_000));
		properties.setProperty("connectTimeout", Integer.toString(seconds));
		properties.setProperty("socketTimeout", Integer.toString(seconds));
		properties.setProperty("preferQueryMode", "simple");
		properties.setProperty("sslmode", "disable");
		properties.setProperty("gssEncMode", "disable");
		return DriverManager.getConnection(Objects.requireNonNull(System.getenv("DB_URL")), properties);
	}

	private static void initialize() throws SQLException {
		try (Connection connection = connect(BUDGET); Statement statement = connection.createStatement()) {
			statement.execute("CREATE TABLE IF NOT EXISTS scp05_transaction_probe (id integer PRIMARY KEY, value integer NOT NULL)");
			statement.executeUpdate("DELETE FROM scp05_transaction_probe");
		}
	}

	private static void insert(@NonNull Context context, int id) throws SQLException {
		context.bound();
		context.markPossibleMutation();
		try (var statement = context.connection().prepareStatement("INSERT INTO scp05_transaction_probe(id,value) VALUES (?,1)")) {
			context.bound(statement);
			statement.setInt(1, id);
			if (statement.executeUpdate() != 1) throw new SQLException("Unexpected private write count");
		}
	}

	private static int count(int id) throws SQLException {
		try (Connection connection = connect(BUDGET); var statement = connection.prepareStatement("SELECT count(*) FROM scp05_transaction_probe WHERE id=?")) {
			statement.setInt(1, id);
			try (ResultSet rows = statement.executeQuery()) {
				if (!rows.next()) throw new SQLException("Missing private observer result");
				return rows.getInt(1);
			}
		}
	}

	private static int backend(@NonNull Connection connection) throws SQLException {
		try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery("SELECT pg_backend_pid()")) {
			if (!rows.next()) throw new SQLException("Missing private backend identity");
			return rows.getInt(1);
		}
	}

	private static void check(@NonNull String label, boolean condition) {
		if (!condition) throw new AssertionError("Private transaction assertion failed: " + label);
		System.out.println("PASS " + label);
	}

	private static void committedAfterClosure() throws SQLException {
		AtomicInteger calls = new AtomicInteger();
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
			calls.incrementAndGet();
			if (context.connection().getAutoCommit() || context.connection().getTransactionIsolation() != Connection.TRANSACTION_READ_COMMITTED)
				throw new SQLException("Private physical transaction profile differs");
			insert(context, 1);
			if (count(1) != 0) throw new SQLException("Private closure return preceded physical commit incorrectly");
			return PgTransactions.Decision.commit(71);
		});
		check("transaction-closure-before-physical-commit", calls.get() == 1 && result.status() == PgTransactions.Status.COMMITTED
				&& result.completion().orElseThrow() == TransactionResult.COMMITTED && result.value().orElseThrow() == 71 && count(1) == 1);
	}

	private static void markedRollback() throws SQLException {
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
			insert(context, 2);
			throw new SQLException("Private rollback fault");
		});
		check("transaction-marked-write-known-rollback", result.status() == PgTransactions.Status.NO_EFFECT && result.possibleMutation()
				&& result.completion().orElseThrow() == TransactionResult.ROLLED_BACK && count(2) == 0);
	}

	private static void rawLifecycleGuarded() {
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
			int refused = 0;
			try { context.connection().commit(); } catch (IllegalStateException expected) { refused++; }
			try { context.connection().rollback(); } catch (IllegalStateException expected) { refused++; }
			try { context.connection().setAutoCommit(true); } catch (IllegalStateException expected) { refused++; }
			try { context.connection().close(); } catch (IllegalStateException expected) { refused++; }
			try { context.connection().setNetworkTimeout(Runnable::run, 1); } catch (IllegalStateException expected) { refused++; }
			return PgTransactions.Decision.commit(refused);
		});
		check("transaction-managed-raw-lifecycle-guarded", result.status() == PgTransactions.Status.COMMITTED && result.value().orElseThrow() == 5);
	}

	private static void rawLifetimeGuarded() throws SQLException {
		AtomicReference<@Nullable Connection> escaped = new AtomicReference<>();
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
			escaped.set(context.connection());
			return PgTransactions.Decision.commit(1);
		});
		boolean refused = false;
		try { Objects.requireNonNull(escaped.get()).getAutoCommit(); } catch (IllegalStateException expected) { refused = true; }
		check("transaction-managed-raw-lifetime-guarded", result.status() == PgTransactions.Status.COMMITTED && refused);
	}

	private static void explicitRefusal() throws SQLException {
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
			insert(context, 3);
			return PgTransactions.Decision.refuse(PgTransactions.Refusal.CAPACITY);
		});
		check("transaction-explicit-refusal-retains-reason", result.status() == PgTransactions.Status.NO_EFFECT
				&& result.refusal().orElseThrow() == PgTransactions.Refusal.CAPACITY && count(3) == 0);
	}

	private static void preEntryFailure() {
		AtomicInteger calls = new AtomicInteger();
		AtomicInteger work = new AtomicInteger();
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(remaining -> {
			calls.incrementAndGet();
			throw new SQLException("Private acquisition refusal");
		}, BUDGET, context -> { work.incrementAndGet(); return PgTransactions.Decision.commit(1); });
		check("transaction-pre-entry-no-effect", calls.get() == 1 && work.get() == 0 && !result.callbackEntered()
				&& !result.possibleMutation() && result.status() == PgTransactions.Status.NO_EFFECT);
	}

	private static void zeroBudget() {
		AtomicInteger calls = new AtomicInteger();
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(remaining -> { calls.incrementAndGet(); return connect(remaining); },
				Duration.ZERO, context -> PgTransactions.Decision.commit(1));
		check("transaction-zero-budget-no-io", calls.get() == 0 && result.status() == PgTransactions.Status.NO_EFFECT);
	}

	private static void dirtyConnection() {
		AtomicInteger work = new AtomicInteger();
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(remaining -> {
			Connection physical = connect(remaining);
			physical.setAutoCommit(false);
			return physical;
		}, BUDGET, context -> { work.incrementAndGet(); return PgTransactions.Decision.commit(1); });
		check("transaction-dirty-connection-refused", work.get() == 0 && !result.callbackEntered() && result.status() == PgTransactions.Status.NO_EFFECT);
	}

	private static @NonNull Connection wrapped(@NonNull Connection physical, @NonNull String phase, @NonNull AtomicLong deadline) {
		return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[]{Connection.class},
				(proxy, method, arguments) -> {
					try {
						Object value = method.invoke(physical, arguments);
						if (phase.equals("late-commit") && method.getName().equals("commit")) {
							while (deadline.get() - System.nanoTime() >= 0) Thread.onSpinWait();
						}
						if (phase.equals("close-failure") && method.getName().equals("close")) throw new SQLException("Private close fault");
						return value;
					} catch (InvocationTargetException failure) { throw failure.getCause(); }
				});
	}

	private static void lateKnownCommit() throws SQLException {
		AtomicLong deadline = new AtomicLong();
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(remaining -> wrapped(connect(remaining), "late-commit", deadline),
				Duration.ofMillis(250), context -> {
					deadline.set(context.deadlineNanos());
					insert(context, 4);
					return PgTransactions.Decision.commit(74);
				});
		check("transaction-late-known-commit-preserved", result.status() == PgTransactions.Status.COMMITTED
				&& result.value().orElseThrow() == 74 && count(4) == 1 && System.nanoTime() - deadline.get() > 0);
	}

	private static void postOperationFailure() throws SQLException {
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
			insert(context, 5);
			context.addPostOperation(completion -> { throw new IllegalStateException("Private post-operation fault"); });
			return PgTransactions.Decision.commit(75);
		});
		check("transaction-post-operation-known-commit-preserved", result.status() == PgTransactions.Status.COMMITTED
				&& result.value().orElseThrow() == 75 && count(5) == 1);
	}

	private static void cleanupFailure() throws SQLException {
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(remaining -> wrapped(connect(remaining), "close-failure", new AtomicLong()),
				BUDGET, context -> { insert(context, 6); return PgTransactions.Decision.commit(76); });
		check("transaction-cleanup-known-commit-preserved", result.status() == PgTransactions.Status.COMMITTED
				&& result.value().orElseThrow() == 76 && count(6) == 1);
	}

	private static void refusalCleanupFailure() {
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(remaining -> wrapped(connect(remaining), "close-failure", new AtomicLong()),
				BUDGET, context -> PgTransactions.Decision.refuse(PgTransactions.Refusal.CONFLICT));
		check("transaction-cleanup-known-refusal-preserved", result.status() == PgTransactions.Status.NO_EFFECT
				&& result.refusal().orElseThrow() == PgTransactions.Refusal.CONFLICT);
	}

	private static void nestedHelperRefused() {
		AtomicInteger opens = new AtomicInteger();
		PgTransactions.ConnectionSource source = remaining -> { opens.incrementAndGet(); return connect(remaining); };
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(source, BUDGET, context -> {
			PgTransactions.Outcome<Integer> nested = PgTransactions.execute(source, BUDGET, unused -> PgTransactions.Decision.commit(1));
			if (nested.status() != PgTransactions.Status.NO_EFFECT || nested.callbackEntered()) throw new SQLException("Nested private transaction ran");
			return PgTransactions.Decision.commit(1);
		});
		check("transaction-recursive-helper-refused-once", opens.get() == 1 && result.status() == PgTransactions.Status.COMMITTED);
	}

	private static void separateAmbientConnection() throws SQLException {
		Database outer = Database.withDataSource(new PlainSource()).databaseType(DatabaseType.POSTGRESQL).build();
		AtomicInteger outerBackend = new AtomicInteger();
		AtomicInteger innerBackend = new AtomicInteger();
		outer.transaction(TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(), () -> outer.useRawConnection(connection -> {
			outerBackend.set(backend(connection));
			try (Statement statement = connection.createStatement()) { statement.executeUpdate("INSERT INTO scp05_transaction_probe(id,value) VALUES(7,1)"); }
			PgTransactions.Outcome<Integer> inner = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
				innerBackend.set(backend(context.connection()));
				insert(context, 8);
				return PgTransactions.Decision.commit(1);
			});
			if (inner.status() != PgTransactions.Status.COMMITTED || count(8) != 1) throw new SQLException("Private inner commitment not independent");
			outer.currentTransaction().orElseThrow().setRollbackOnly(Boolean.TRUE);
			return Optional.of(Boolean.TRUE);
		}));
		check("transaction-caller-ambient-not-joined", outerBackend.get() != innerBackend.get() && count(7) == 0 && count(8) == 1);
	}

	private static void serializationFailureNotRetried() throws SQLException {
		AtomicInteger calls = new AtomicInteger();
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
			calls.incrementAndGet();
			insert(context, 9);
			try (Statement statement = context.connection().createStatement()) {
				context.bound(statement);
				statement.execute("DO $$ BEGIN RAISE EXCEPTION USING ERRCODE='40001'; END $$");
			}
			return PgTransactions.Decision.commit(1);
		});
		check("transaction-server-serialization-failure-no-retry", calls.get() == 1 && result.status() == PgTransactions.Status.NO_EFFECT
				&& result.completion().orElseThrow() == TransactionResult.ROLLED_BACK && count(9) == 0);
	}

	private static void lateAcquisition() {
		AtomicInteger calls = new AtomicInteger();
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(remaining -> {
			Connection connection = connect(remaining);
			long end = System.nanoTime() + remaining.toNanos();
			while (end - System.nanoTime() >= 0) Thread.onSpinWait();
			return connection;
		}, Duration.ofMillis(40), context -> { calls.incrementAndGet(); return PgTransactions.Decision.commit(1); });
		check("transaction-late-acquisition-withholds-callback", calls.get() == 0 && !result.callbackEntered() && result.status() == PgTransactions.Status.NO_EFFECT);
	}

	private static void interruptAfterCommit() throws SQLException {
		PgTransactions.Outcome<Integer> result;
		try {
			result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
				insert(context, 10);
				context.addPostOperation(completion -> Thread.currentThread().interrupt());
				return PgTransactions.Decision.commit(80);
			});
		} finally { Thread.interrupted(); }
		check("transaction-post-commit-interrupt-preserves-fact", result.status() == PgTransactions.Status.COMMITTED
				&& result.value().orElseThrow() == 80 && count(10) == 1);
	}

	private static void barrierWithoutMutation() {
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
			try (Statement statement = context.connection().createStatement(); ResultSet rows = statement.executeQuery("SELECT 1")) {
				if (!rows.next() || rows.getInt(1) != 1) throw new SQLException("Private barrier read failed");
			}
			return PgTransactions.Decision.commit(1);
		});
		check("transaction-condition-only-no-business-uncertainty", result.status() == PgTransactions.Status.COMMITTED && !result.possibleMutation());
	}

	private static void acknowledgementLoss() {
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
			insert(context, 9001);
			return PgTransactions.Decision.commit(1);
		});
		check("transaction-ack-loss-unknown", result.status() == PgTransactions.Status.UNKNOWN && result.possibleMutation()
				&& result.completion().orElseThrow() == TransactionResult.IN_DOUBT);
	}

	private static void barrierAcknowledgementLoss() {
		PgTransactions.Outcome<Integer> result = PgTransactions.execute(PgTransactionChecks::connect, BUDGET, context -> {
			try (Statement statement = context.connection().createStatement(); ResultSet rows = statement.executeQuery("SELECT 1")) {
				if (!rows.next() || rows.getInt(1) != 1) throw new SQLException("Private barrier read failed");
			}
			return PgTransactions.Decision.commit(1);
		});
		check("transaction-barrier-ack-loss-withholds-validation", result.status() == PgTransactions.Status.NO_EFFECT
				&& !result.possibleMutation() && result.value().isEmpty() && result.refusal().orElseThrow() == PgTransactions.Refusal.UNAVAILABLE
				&& result.completion().orElseThrow() == TransactionResult.IN_DOUBT);
	}

	private static final class PlainSource implements DataSource {
		@Override public @NonNull Connection getConnection() throws SQLException { return connect(BUDGET); }
		@Override public @NonNull Connection getConnection(@Nullable String user, @Nullable String password) throws SQLException { throw new SQLFeatureNotSupportedException("Fixed private source"); }
		@Override public @Nullable PrintWriter getLogWriter() { return null; }
		@Override public void setLogWriter(@Nullable PrintWriter writer) throws SQLException { throw new SQLFeatureNotSupportedException("No credential logging"); }
		@Override public void setLoginTimeout(int seconds) throws SQLException { throw new SQLFeatureNotSupportedException("Use original operation budget"); }
		@Override public int getLoginTimeout() { return 0; }
		@Override public @NonNull Logger getParentLogger() throws SQLFeatureNotSupportedException { throw new SQLFeatureNotSupportedException("No credential logging"); }
		@Override public <T> @NonNull T unwrap(@NonNull Class<T> type) throws SQLException { throw new SQLFeatureNotSupportedException("No unwrap"); }
		@Override public boolean isWrapperFor(@NonNull Class<?> type) { return false; }
	}
}
