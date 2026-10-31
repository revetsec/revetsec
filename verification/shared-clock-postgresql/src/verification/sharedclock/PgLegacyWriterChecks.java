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

import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.locks.LockSupport;

/** Native uncooperative-session check; this is not an old engine-binary assertion. */
final class PgLegacyWriterChecks {
	private PgLegacyWriterChecks() { }

	public static void main(@NonNull String @NonNull [] arguments) {
		try {
			if (arguments.length != 1) throw new IllegalArgumentException("Expected private fixture mode");
			if (arguments[0].equals("hold")) hold();
			else if (arguments[0].equals("new")) newWriter();
			else throw new IllegalArgumentException("Unknown private fixture mode");
		} catch (Throwable failure) {
			throw new IllegalStateException("SCP05 native writer checks failed");
		}
	}

	private static @NonNull Connection connect() throws SQLException {
		Properties properties = new Properties();
		properties.setProperty("user", Objects.requireNonNull(System.getenv("DB_USER")));
		properties.setProperty("password", Objects.requireNonNull(System.getenv("DB_PASSWORD")));
		properties.setProperty("connectTimeout", "3");
		properties.setProperty("socketTimeout", "3");
		properties.setProperty("preferQueryMode", "simple");
		properties.setProperty("sslmode", "disable");
		properties.setProperty("gssEncMode", "disable");
		Connection connection = DriverManager.getConnection(Objects.requireNonNull(System.getenv("DB_URL")), properties);
		try {
			connection.setNetworkTimeout(Runnable::run, 3000);
			return connection;
		} catch (SQLException | RuntimeException failure) {
			try { connection.close(); } catch (SQLException ignored) { }
			throw failure;
		}
	}

	private static void hold() throws SQLException, IOException {
		String expectedRole = Objects.requireNonNull(System.getenv("DB_USER"));
		if (!expectedRole.startsWith("scp05_old_")) throw new SQLException("Unexpected native old-role profile");
		Connection connection = connect();
		try {
			try (Statement statement = connection.createStatement(); ResultSet rows = statement.executeQuery("SELECT current_user")) {
				if (!rows.next() || !expectedRole.equals(rows.getString(1))) throw new SQLException("Unexpected native old role");
			}
			connection.setAutoCommit(false);
			try (Statement statement = connection.createStatement()) {
				if (statement.executeUpdate("INSERT INTO scp05_legacy_probe(id) VALUES(1)") != 1)
					throw new SQLException("Unexpected native old write count");
			}
			System.out.println("READY stale-writer");
			System.out.flush();
			awaitContinue();
			boolean oldSessionRefused = false;
			try (Statement statement = connection.createStatement()) {
				statement.executeUpdate("INSERT INTO scp05_legacy_probe(id) VALUES(3)");
				connection.commit();
			} catch (SQLException expected) { oldSessionRefused = true; }
			check("stale-native-session-cannot-commit", oldSessionRefused);
		} finally {
			try { connection.close(); } catch (SQLException ignored) { }
		}
		boolean oldLoginRefused = false;
		try (Connection ignored = connect()) {
			// A fresh successful old-role connection is a failed fence assertion.
			ignored.getAutoCommit();
		} catch (SQLException expected) { oldLoginRefused = true; }
		check("stale-native-credential-cannot-login", oldLoginRefused);
	}

	private static void awaitContinue() throws IOException {
		long end = System.nanoTime() + Duration.ofSeconds(30).toNanos();
		StringBuilder command = new StringBuilder();
		while (end - System.nanoTime() > 0 && !Thread.currentThread().isInterrupted()) {
			if (System.in.available() == 0) {
				LockSupport.parkNanos(1_000_000);
				continue;
			}
			int next = System.in.read();
			if (next < 0) throw new IOException("Private rendezvous ended");
			if (next == '\n') {
				if (!command.toString().equals("CONTINUE")) throw new IOException("Unexpected private rendezvous command");
				return;
			}
			if (next < 32 || next > 126 || command.length() >= 16) throw new IOException("Invalid private rendezvous command");
			command.append((char) next);
		}
		throw new IOException("Private rendezvous budget exhausted");
	}

	private static void newWriter() throws SQLException {
		String expectedRole = Objects.requireNonNull(System.getenv("DB_USER"));
		if (!expectedRole.startsWith("scp05_new_")) throw new SQLException("Unexpected native new-role profile");
		try (Connection connection = connect()) {
			try (PreparedStatement statement = connection.prepareStatement(
					"SELECT current_user=?, r.rolcanlogin AND NOT (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls), "
					+ "NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid), "
					+ "(SELECT pg_get_userbyid(datdba)<>current_user FROM pg_database WHERE datname=current_database()), "
					+ "(SELECT tableowner<>current_user FROM pg_tables WHERE schemaname='public' AND tablename='scp05_legacy_probe'), "
					+ "has_schema_privilege(current_user,'public','USAGE') AND NOT has_schema_privilege(current_user,'public','CREATE'), "
					+ "has_table_privilege(current_user,'public.scp05_legacy_probe','SELECT') AND has_table_privilege(current_user,'public.scp05_legacy_probe','INSERT'), "
					+ "NOT (has_table_privilege(current_user,'public.scp05_legacy_probe','TRUNCATE') OR has_table_privilege(current_user,'public.scp05_legacy_probe','REFERENCES') OR has_table_privilege(current_user,'public.scp05_legacy_probe','TRIGGER')) "
					+ "FROM pg_roles r WHERE r.rolname=current_user")) {
				statement.setString(1, expectedRole);
				try (ResultSet rows = statement.executeQuery()) {
				if (!rows.next()) throw new SQLException("Missing private new-role attributes");
				for (int index = 1; index <= 8; index++) {
					if (!rows.getBoolean(index) || rows.wasNull()) throw new SQLException("Unsafe private new-role profile");
				}
				if (rows.next()) throw new SQLException("Duplicate private new-role profile");
				}
			}
			connection.setAutoCommit(false);
			try (Statement statement = connection.createStatement()) {
				if (statement.executeUpdate("INSERT INTO scp05_legacy_probe(id) VALUES(2)") != 1)
					throw new SQLException("Unexpected private new write count");
			}
			connection.commit();
		}
		check("new-writer-works", true);
	}

	private static void check(@NonNull String label, boolean condition) {
		if (!condition) throw new AssertionError("Private native writer assertion failed: " + label);
		System.out.println("PASS " + label);
	}
}
