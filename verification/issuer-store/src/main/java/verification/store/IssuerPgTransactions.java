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
package verification.store;

// Derived from frozen SCP-07 WebAuthnPgTransactions with family name/table substitution only.

import com.pyranid.Database;
import com.pyranid.DatabaseType;
import com.pyranid.TransactionIsolation;
import com.pyranid.TransactionOptions;
import com.pyranid.TransactionResult;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.sql.Statement;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.logging.Logger;

/** Inactive private transaction boundary for the pinned Pyranid fixture. */
final class IssuerPgTransactions {
	private static final @NonNull ThreadLocal<@NonNull Boolean> ENTERED = new ThreadLocal<>();
	private static final @NonNull Duration MAXIMUM_BUDGET = Duration.ofMinutes(1);

	private IssuerPgTransactions() { }

	enum Status { COMMITTED, NO_EFFECT, UNKNOWN }
	enum Refusal { UNAVAILABLE, CONFLICT, CAPACITY, TIME_BEFORE_FLOOR, TIME_EXPIRED, TIME_UNAVAILABLE, FENCED }

	@FunctionalInterface
	interface ConnectionSource {
		/** The caller-owned provider must bound pool/DNS/connect by this remaining budget. */
		@NonNull Connection open(@NonNull Duration remaining) throws SQLException;
	}

	@FunctionalInterface
	interface Work<T> {
		@NonNull Decision<@NonNull T> run(@NonNull Context context) throws Exception;
	}

	static final class Decision<T> {
		private final @Nullable T value;
		private final @Nullable Refusal refusal;

		private Decision(@Nullable T value, @Nullable Refusal refusal) {
			this.value = value;
			this.refusal = refusal;
		}

		static <T> @NonNull Decision<@NonNull T> commit(@NonNull T value) {
			return new Decision<>(Objects.requireNonNull(value), null);
		}

		static <T> @NonNull Decision<@NonNull T> refuse(@NonNull Refusal refusal) {
			return new Decision<>(null, Objects.requireNonNull(refusal));
		}
	}

	static final class Outcome<T> {
		private final @NonNull Status status;
		private final @Nullable T value;
		private final @Nullable Refusal refusal;
		private final boolean callbackEntered;
		private final boolean possibleMutation;
		private final @Nullable TransactionResult completion;

		private Outcome(@NonNull Status status, @Nullable T value, @Nullable Refusal refusal,
				boolean callbackEntered, boolean possibleMutation, @Nullable TransactionResult completion) {
			this.status = status;
			this.value = value;
			this.refusal = refusal;
			this.callbackEntered = callbackEntered;
			this.possibleMutation = possibleMutation;
			this.completion = completion;
		}

		@NonNull Status status() { return this.status; }
		@NonNull Optional<@NonNull T> value() { return Optional.ofNullable(this.value); }
		@NonNull Optional<@NonNull Refusal> refusal() { return Optional.ofNullable(this.refusal); }
		boolean callbackEntered() { return this.callbackEntered; }
		boolean possibleMutation() { return this.possibleMutation; }
		@NonNull Optional<@NonNull TransactionResult> completion() { return Optional.ofNullable(this.completion); }

		@Override public @NonNull String toString() { return "IssuerPgTransactions.Outcome[redacted]"; }
	}

	static final class Context {
		private final @NonNull Connection connection;
		private final @NonNull Database database;
		private final long deadline;
		private final @NonNull State state;

		private Context(@NonNull Connection connection, @NonNull Database database, long deadline, @NonNull State state) {
			this.connection = connection;
			this.database = database;
			this.deadline = deadline;
			this.state = state;
		}

		@NonNull Connection connection() { return this.connection; }
		long deadlineNanos() { return this.deadline; }
		@NonNull Duration remaining() throws SQLException { return Duration.ofNanos(remainingNanos(this.deadline)); }
		void check() throws SQLException { remainingNanos(this.deadline); }
		void markPossibleMutation() { this.state.possibleMutation = true; }

		/** Must precede each blocking SQL phase; all waits consume the original deadline. */
		void bound() throws SQLException {
			int milliseconds = milliseconds(this.deadline);
			// Pyranid's managed raw facade forbids lifecycle/network setters.
			// BudgetSource refreshes the physical network timeout before the
			// prepareStatement call below, outside that guarded facade.
			try (PreparedStatement statement = this.connection.prepareStatement(
					"SELECT set_config('statement_timeout', ?, true), set_config('lock_timeout', ?, true)")) {
				String timeout = milliseconds + "ms";
				statement.setString(1, timeout);
				statement.setString(2, timeout);
				statement.setQueryTimeout(Math.max(1, (milliseconds + 999) / 1000));
				statement.execute();
			}
			check();
		}

		void bound(@NonNull Statement statement) throws SQLException {
			Objects.requireNonNull(statement);
			bound();
			statement.setQueryTimeout(Math.max(1, (milliseconds(this.deadline) + 999) / 1000));
		}

		/** Private lifecycle fault/check hook; never a policy or signing callback. */
		void addPostOperation(@NonNull Consumer<@NonNull TransactionResult> operation) {
			this.database.currentTransaction().orElseThrow().addPostTransactionOperation(Objects.requireNonNull(operation));
		}
	}

	private static final class State {
		private boolean callbackEntered;
		private boolean possibleMutation;
		private @Nullable TransactionResult completion;
	}

	private static final class Prepared<T> {
		private @Nullable Decision<@NonNull T> decision;
	}

	static <T> @NonNull Outcome<@NonNull T> execute(@NonNull ConnectionSource source, @NonNull Duration budget, @NonNull Work<@NonNull T> work) {
		Objects.requireNonNull(source);
		Objects.requireNonNull(budget);
		Objects.requireNonNull(work);
		if (budget.isNegative() || budget.isZero()) return noEffect(new State(), Refusal.UNAVAILABLE);
		if (budget.compareTo(MAXIMUM_BUDGET) > 0) throw new IllegalArgumentException("Private PostgreSQL budget exceeds profile");
		if (Boolean.TRUE.equals(ENTERED.get())) return noEffect(new State(), Refusal.UNAVAILABLE);
		long deadline = System.nanoTime() + budget.toNanos();
		State state = new State();
		Prepared<T> prepared = new Prepared<>();
		ENTERED.set(Boolean.TRUE);
		try {
			Database database = Database.withDataSource(new BudgetSource(source, deadline)).databaseType(DatabaseType.POSTGRESQL).build();
			database.transaction(TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(), () -> {
				database.currentTransaction().orElseThrow().addPostTransactionOperation(result -> state.completion = result);
				return database.useRawConnection(connection -> {
					state.callbackEntered = true;
					Context context = new Context(connection, database, deadline, state);
					context.bound();
					try (Statement statement = connection.createStatement()) {
						context.bound(statement);
						statement.execute("SET LOCAL synchronous_commit = on");
						context.bound(statement);
						try (var result = statement.executeQuery("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' AND current_setting('full_page_writes')='on'")) {
							if (!result.next() || !result.getBoolean(1)) throw new SQLException("Private PostgreSQL primary unavailable");
						}
					}
					Decision<T> decision = Objects.requireNonNull(work.run(context));
					prepared.decision = decision;
					if (decision.refusal != null) database.currentTransaction().orElseThrow().setRollbackOnly(Boolean.TRUE);
					context.check();
					return Optional.of(decision);
				});
			}).orElseThrow();
		} catch (RuntimeException failure) {
			// The public recorder runs after physical completion and cleanup. A
			// failed post-operation/cleanup cannot overwrite already known commit.
			return outcome(state, prepared.decision);
		} finally {
			ENTERED.remove();
		}
		return outcome(state, prepared.decision);
	}

	private static <T> @NonNull Outcome<@NonNull T> outcome(@NonNull State state, @Nullable Decision<@NonNull T> decision) {
		if (state.completion == TransactionResult.COMMITTED)
			return new Outcome<>(Status.COMMITTED, decision == null ? null : decision.value, null,
					state.callbackEntered, state.possibleMutation, state.completion);
		if (state.completion == TransactionResult.IN_DOUBT)
			return state.possibleMutation
					? new Outcome<>(Status.UNKNOWN, null, null, state.callbackEntered, true, state.completion)
					: noEffect(state, Refusal.UNAVAILABLE);
		if (state.completion == TransactionResult.ROLLED_BACK || !state.possibleMutation)
			return noEffect(state, decision == null || decision.refusal == null ? Refusal.UNAVAILABLE : decision.refusal);
		return new Outcome<>(Status.UNKNOWN, null, null, state.callbackEntered, state.possibleMutation, state.completion);
	}

	private static <T> @NonNull Outcome<@NonNull T> noEffect(@NonNull State state, @NonNull Refusal refusal) {
		return new Outcome<>(Status.NO_EFFECT, null, refusal, state.callbackEntered, state.possibleMutation, state.completion);
	}

	private static long remainingNanos(long deadline) throws SQLException {
		long remaining = deadline - System.nanoTime();
		if (remaining <= 0 || Thread.currentThread().isInterrupted()) throw new SQLException("Private PostgreSQL budget unavailable");
		return remaining;
	}

	private static int milliseconds(long deadline) throws SQLException {
		long nanos = remainingNanos(deadline);
		return (int) Math.max(1, Math.min(60_000, 1 + (nanos - 1) / 1_000_000));
	}

	private static final class BudgetSource implements DataSource {
		private final @NonNull ConnectionSource source;
		private final long deadline;

		private BudgetSource(@NonNull ConnectionSource source, long deadline) { this.source = source; this.deadline = deadline; }

		@Override public @NonNull Connection getConnection() throws SQLException {
			Connection physical = Objects.requireNonNull(this.source.open(Duration.ofNanos(remainingNanos(this.deadline))));
			try {
				physical.setNetworkTimeout(Runnable::run, milliseconds(this.deadline));
				if (!physical.getAutoCommit()) throw new SQLException("Private PostgreSQL source supplied an ambient transaction");
				remainingNanos(this.deadline);
				return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class<?>[]{Connection.class},
						(proxy, method, arguments) -> {
							String name = method.getName();
							if (!name.equals("close") && !name.equals("rollback") && !name.equals("isClosed") && !name.equals("abort"))
								physical.setNetworkTimeout(Runnable::run, milliseconds(this.deadline));
							try { return method.invoke(physical, arguments); }
							catch (InvocationTargetException failure) { throw failure.getCause(); }
						});
			} catch (SQLException | RuntimeException failure) {
				try { physical.close(); } catch (SQLException ignored) { }
				throw failure;
			}
		}

		@Override public @NonNull Connection getConnection(@Nullable String user, @Nullable String password) throws SQLException { throw new SQLFeatureNotSupportedException("Fixed private source"); }
		@Override public @Nullable PrintWriter getLogWriter() { return null; }
		@Override public void setLogWriter(@Nullable PrintWriter writer) throws SQLException { throw new SQLFeatureNotSupportedException("No credential logging"); }
		@Override public void setLoginTimeout(int seconds) throws SQLException { throw new SQLFeatureNotSupportedException("Use original operation budget"); }
		@Override public int getLoginTimeout() { return 0; }
		@Override public @NonNull Logger getParentLogger() throws SQLFeatureNotSupportedException { throw new SQLFeatureNotSupportedException("No credential logging"); }
		@Override public <T> @NonNull T unwrap(@NonNull Class<@NonNull T> type) throws SQLException { throw new SQLFeatureNotSupportedException("No unwrap"); }
		@Override public boolean isWrapperFor(@NonNull Class<?> type) { return false; }
	}
}
