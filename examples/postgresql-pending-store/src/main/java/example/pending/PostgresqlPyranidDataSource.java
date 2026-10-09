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
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.SQLFeatureNotSupportedException;
import java.time.Duration;
import java.util.logging.Logger;

import static java.util.Objects.requireNonNull;

/** One operation's budget-bound connection facade for Pyranid-managed transactions. */
final class PostgresqlPyranidDataSource implements DataSource {
	@FunctionalInterface
	interface ConnectionSource {
		@NonNull Connection open(@NonNull Duration remaining) throws SQLException;
	}

	private final @NonNull ConnectionSource source;
	private final long deadline;

	PostgresqlPyranidDataSource(@NonNull ConnectionSource source, long deadline) {
		this.source = requireNonNull(source);
		this.deadline = deadline;
	}

	static long remainingNanos(long deadline) throws SQLException {
		long nanos = deadline - System.nanoTime();
		if (nanos <= 0 || Thread.currentThread().isInterrupted())
			throw new SQLException("PostgreSQL operation budget expired.");
		return nanos;
	}

	private static int milliseconds(long deadline) throws SQLException {
		long nanos = remainingNanos(deadline);
		return (int) Math.max(1, Math.min(60_000, (nanos + 999_999) / 1_000_000));
	}

	static void bound(@NonNull Database database, long deadline) throws SQLException {
		String timeout = milliseconds(deadline) + "ms";
		database.query("SELECT set_config('statement_timeout', :timeout, true)")
				.bind("timeout", timeout).fetchObject(String.class).orElseThrow();
	}

	@Override public @NonNull Connection getConnection() throws SQLException {
		Connection physical = requireNonNull(this.source.open(Duration.ofNanos(remainingNanos(this.deadline))));
		try {
			physical.setNetworkTimeout(Runnable::run, milliseconds(this.deadline));
			if (!physical.getAutoCommit()) throw new SQLException("PostgreSQL connection is already in a transaction.");
			remainingNanos(this.deadline);
			return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
					new Class<?>[] { Connection.class }, new java.lang.reflect.InvocationHandler() {
						@Override public @Nullable Object invoke(@NonNull Object proxy, @NonNull Method method,
								@Nullable Object @Nullable [] arguments) throws Throwable {
							String name = method.getName();
							if (!name.equals("close") && !name.equals("rollback") && !name.equals("isClosed")
									&& !name.equals("abort"))
								physical.setNetworkTimeout(Runnable::run, milliseconds(PostgresqlPyranidDataSource.this.deadline));
							try { return method.invoke(physical, arguments); }
							catch (InvocationTargetException failure) { throw failure.getCause(); }
						}
					});
		} catch (SQLException | RuntimeException failure) {
			try { physical.close(); } catch (SQLException ignored) { }
			throw failure;
		}
	}

	@Override public @NonNull Connection getConnection(@Nullable String user, @Nullable String password)
			throws SQLException {
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
