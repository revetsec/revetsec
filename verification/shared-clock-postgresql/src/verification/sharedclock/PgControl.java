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
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

/** Inactive privileged fixture control; no runtime role receives these capabilities. */
public final class PgControl {
	private static final @NonNull List<String> TABLES = List.of("scp05_entries", "scp05_escrow", "scp05_admission");
	private static final @NonNull String COLUMNS = "family,namespace,authority_id,recovery_generation,clock_generation,profile_commitment,schema_commitment,metadata_commitment,writer_role_identity,allocation_generation,format_version,mode";
	private PgControl() { }

	static final class Row {
		private final String @NonNull [] values;
		private final @NonNull PgScope scope;
		private Row(String @NonNull [] values) {
			this.values = values.clone();
			this.scope = PgScope.from(values[0], values[1]);
		}
		static @NonNull Row fromLine(@NonNull String line) {
			String[] values = line.split("\t", -1);
			if (values.length != 12) throw new IllegalArgumentException("Exact control row required");
			PgScope scope = PgScope.from(values[0], values[1]);
			for (int index = 1; index < 10; index++) canonical(values[index]);
			if (!values[10].equals(scope.getFamily().equals("TOTP") ? "3" : "2") || (!values[11].equals("ACTIVE") && !values[11].equals("CLOSED")))
				throw new IllegalArgumentException("Selected control format/mode required");
			return new Row(values);
		}
		@NonNull PgScope scope() { return this.scope; }
		@Override public boolean equals(@NonNull Object other) { return other instanceof Row row && Arrays.equals(this.values, row.values); }
		@Override public int hashCode() { return Arrays.hashCode(this.values); }
		@Override public @NonNull String toString() { return "PgControl.Row[redacted]"; }
	}

	static PgTransactions.@NonNull Status fence(PgTransactions.@NonNull ConnectionSource source, @NonNull Duration budget, @NonNull List<String> roles) {
		long deadline = System.nanoTime() + budget.toNanos();
		try {
			validateRoles(roles);
			PgTransactions.Outcome<Boolean> revoked = PgTransactions.execute(source, left(deadline), context -> {
				Connection connection = context.connection();
				for (String role : roles) {
					requireSafeRole(connection, role, true, context.deadlineNanos());
					requireRetiredLoginClosure(connection, role, roles, context.deadlineNanos());
				}
				context.markPossibleMutation();
				for (String role : roles) {
					execute(connection, "ALTER ROLE " + quoted(role) + " NOLOGIN PASSWORD NULL", context.deadlineNanos());
					for (String table : tables(connection, context.deadlineNanos())) execute(connection, "REVOKE ALL PRIVILEGES ON TABLE public." + table + " FROM " + quoted(role), context.deadlineNanos());
					execute(connection, "REVOKE ALL PRIVILEGES ON SCHEMA public FROM " + quoted(role), context.deadlineNanos());
					for (String[] edge : memberships(connection, role, context.deadlineNanos()))
						execute(connection, "REVOKE " + quoted(edge[0]) + " FROM " + quoted(edge[1]) + " CASCADE", context.deadlineNanos());
				}
				return PgTransactions.Decision.commit(Boolean.TRUE);
			});
			if (revoked.status() != PgTransactions.Status.COMMITTED) return revoked.status();
			PgTransactions.Outcome<Boolean> terminated = PgTransactions.execute(source, left(deadline), context -> {
				for (String role : roles) {
					context.bound();
					try (PreparedStatement statement = context.connection().prepareStatement("SELECT pg_terminate_backend(pid, ?) FROM pg_stat_activity WHERE usename=? AND pid<>pg_backend_pid()")) {
						statement.setLong(1, Math.max(1L, Math.min(1000L, context.remaining().toMillis())));
						statement.setString(2, role);
						context.markPossibleMutation();
						try (ResultSet result = statement.executeQuery()) { while (result.next()) if (!result.getBoolean(1)) throw new SQLException("Old session termination not established"); }
					}
				}
				return PgTransactions.Decision.commit(Boolean.TRUE);
			});
			if (terminated.status() != PgTransactions.Status.COMMITTED) return PgTransactions.Status.UNKNOWN;
			PgTransactions.Outcome<Boolean> verified = PgTransactions.execute(source, left(deadline), context -> {
				if (!quarantined(context.connection(), roles, context.deadlineNanos())) return PgTransactions.Decision.refuse(PgTransactions.Refusal.FENCED);
				return PgTransactions.Decision.commit(Boolean.TRUE);
			});
			return verified.status() == PgTransactions.Status.COMMITTED ? PgTransactions.Status.COMMITTED : PgTransactions.Status.UNKNOWN;
		} catch (Exception failure) {
			return PgTransactions.Status.UNKNOWN;
		}
	}

	static PgTransactions.@NonNull Status transition(PgTransactions.@NonNull ConnectionSource source, @NonNull Duration budget,
			@NonNull List<Row> expected, @NonNull List<Row> target, @NonNull List<String> roles) {
		validateRows(expected, target, roles);
		Set<String> retiredIdentities = new HashSet<>();
		for (String role : roles) retiredIdentities.add(digest(role));
		Set<String> expectedWriters = new HashSet<>();
		for (int index = 0; index < expected.size(); index++) {
			Row before = expected.get(index), after = target.get(index);
			expectedWriters.add(before.values[8]);
			if (retiredIdentities.contains(after.values[8]) || before.values[4].equals(after.values[4]) || !before.values[9].equals(after.values[9]) || !after.values[11].equals("ACTIVE"))
				throw new IllegalArgumentException("Fresh prepared writer/generation and unchanged allocation required");
		}
		if (!expectedWriters.equals(retiredIdentities)) throw new IllegalArgumentException("Retired writers do not cover exact SQL identities");
		PgTransactions.Outcome<Boolean> outcome = PgTransactions.execute(source, budget, context -> {
			Connection connection = context.connection();
			if (!quarantined(connection, roles, context.deadlineNanos())) return PgTransactions.Decision.refuse(PgTransactions.Refusal.FENCED);
			PgLocks.exclusiveAdmission(connection, expected.stream().map(Row::scope).toList(), context.deadlineNanos());
			if (!quarantined(connection, roles, context.deadlineNanos()) || !newRolesSafe(connection, target, context.deadlineNanos()))
				return PgTransactions.Decision.refuse(PgTransactions.Refusal.FENCED);
			for (Row row : expected) if (!row.equals(read(connection, row.scope, context.deadlineNanos())))
				return PgTransactions.Decision.refuse(PgTransactions.Refusal.CONFLICT);
			context.markPossibleMutation();
			for (int index = 0; index < expected.size(); index++) replace(connection, expected.get(index), target.get(index), context.deadlineNanos());
			return PgTransactions.Decision.commit(Boolean.TRUE);
		});
		return outcome.status();
	}

	static boolean verify(PgTransactions.@NonNull ConnectionSource source, @NonNull Duration budget, @NonNull List<Row> target, @NonNull List<String> roles) {
		validateRows(target, target, roles);
		PgTransactions.Outcome<Boolean> outcome = PgTransactions.execute(source, budget, context -> {
			Connection connection = context.connection();
			PgLocks.exclusiveAdmission(connection, target.stream().map(Row::scope).toList(), context.deadlineNanos());
			if (!quarantined(connection, roles, context.deadlineNanos()) || !newRolesSafe(connection, target, context.deadlineNanos()))
				return PgTransactions.Decision.refuse(PgTransactions.Refusal.FENCED);
			for (Row row : target) if (!row.equals(read(connection, row.scope, context.deadlineNanos())))
				return PgTransactions.Decision.refuse(PgTransactions.Refusal.CONFLICT);
			return PgTransactions.Decision.commit(Boolean.TRUE);
		});
		return outcome.status() == PgTransactions.Status.COMMITTED && outcome.value().orElse(Boolean.FALSE);
	}

	private static void validateRows(@NonNull List<Row> expected, @NonNull List<Row> target, @NonNull List<String> roles) {
		validateRoles(roles);
		if (expected.size() < 1 || expected.size() > 3 || expected.size() != target.size()) throw new IllegalArgumentException("Exact bounded scope transition required");
		Set<String> families = new HashSet<>();
		for (int index = 0; index < expected.size(); index++) {
			Row before = expected.get(index), after = target.get(index);
			if (!before.scope.equals(after.scope) || !families.add(before.scope.getFamily())) throw new IllegalArgumentException("Exact immutable allowlist required");
			for (int field : new int[]{2, 3, 4, 5}) {
				if (!before.values[field].equals(expected.get(0).values[field]) || !after.values[field].equals(target.get(0).values[field]))
					throw new IllegalArgumentException("One coherent all-scope admission tuple required");
			}
		}
	}

	private static @NonNull Row read(@NonNull Connection connection, @NonNull PgScope scope, long deadline) throws SQLException {
		PgLocks.bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement("SELECT " + COLUMNS + " FROM scp05_admission WHERE family=? AND namespace=?")) {
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace());
			try (ResultSet result = statement.executeQuery()) {
				if (!result.next()) throw new SQLException("Expected admission mirror absent");
				String[] values = new String[12];
				for (int index = 0; index < values.length; index++) values[index] = result.getString(index + 1);
				if (result.next()) throw new SQLException("Admission mirror not unique");
				return Row.fromLine(String.join("\t", values));
			}
		}
	}

	private static void replace(@NonNull Connection connection, @NonNull Row expected, @NonNull Row target, long deadline) throws SQLException {
		PgLocks.bound(connection, deadline);
		String[] columns = COLUMNS.split(",");
		List<String> sets = new ArrayList<>(), conditions = new ArrayList<>();
		for (int index = 2; index < columns.length; index++) sets.add(columns[index] + "=?");
		for (String column : columns) conditions.add(column + "=?");
		try (PreparedStatement statement = connection.prepareStatement("UPDATE scp05_admission SET " + String.join(",", sets) + " WHERE " + String.join(" AND ", conditions))) {
			int parameter = 1;
			for (int index = 2; index < target.values.length; index++) bind(statement, parameter++, index, target.values[index]);
			for (int index = 0; index < expected.values.length; index++) bind(statement, parameter++, index, expected.values[index]);
			if (statement.executeUpdate() != 1) throw new SQLException("Exact admission replacement row count differs");
		}
	}

	private static void bind(@NonNull PreparedStatement statement, int parameter, int field, @NonNull String value) throws SQLException {
		if (field == 10) statement.setInt(parameter, Integer.parseInt(value)); else statement.setString(parameter, value);
	}

	private static void requireSafeRole(@NonNull Connection connection, @NonNull String role, boolean retired, long deadline) throws SQLException {
		if (!(retired ? role.matches("scp05_old_[a-z0-9_]{1,50}") : role.matches("scp05_new_[a-z0-9_]{1,50}"))) throw new SQLException("Only explicit fixture writer roles accepted");
		PgLocks.bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement("SELECT rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=?")) {
			statement.setString(1, role);
			try (ResultSet result = statement.executeQuery()) {
				if (!result.next()) throw new SQLException("Expected fixture writer role absent");
				for (int index = 1; index <= 5; index++) if (result.getBoolean(index)) throw new SQLException("Administrative role cannot be a runtime writer");
			}
		}
		PgLocks.bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement("SELECT EXISTS(SELECT 1 FROM pg_class c JOIN pg_roles r ON c.relowner=r.oid WHERE r.rolname=?) OR EXISTS(SELECT 1 FROM pg_namespace n JOIN pg_roles r ON n.nspowner=r.oid WHERE r.rolname=?) OR EXISTS(SELECT 1 FROM pg_database d JOIN pg_roles r ON d.datdba=r.oid WHERE r.rolname=?)")) {
			statement.setString(1, role); statement.setString(2, role); statement.setString(3, role);
			try (ResultSet result = statement.executeQuery()) { result.next(); if (result.getBoolean(1)) throw new SQLException("Owner role cannot be a runtime writer"); }
		}
	}

	private static @NonNull List<String[]> memberships(@NonNull Connection connection, @NonNull String role, long deadline) throws SQLException {
		PgLocks.bound(connection, deadline);
		List<String[]> result = new ArrayList<>();
		try (PreparedStatement statement = connection.prepareStatement("SELECT parent.rolname,member.rolname FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname=? OR member.rolname=?")) {
			statement.setString(1, role); statement.setString(2, role);
			try (ResultSet rows = statement.executeQuery()) { while (rows.next()) { if (result.size() >= 16) throw new SQLException("Fixture membership bound exceeded"); result.add(new String[]{rows.getString(1), rows.getString(2)}); } }
		}
		return result;
	}

	private static void requireRetiredLoginClosure(@NonNull Connection connection, @NonNull String role, @NonNull List<String> retired, long deadline) throws SQLException {
		// A different login that already SET ROLE to this writer is not identified
		// by pg_stat_activity.usename=writer. Never claim its exclusion implicitly.
		PgLocks.bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement("SELECT member.rolname FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid JOIN pg_roles member ON member.oid=m.member WHERE parent.rolname=? AND NOT member.rolsuper")) {
			statement.setString(1, role);
			try (ResultSet result = statement.executeQuery()) { while (result.next()) if (!retired.contains(result.getString(1))) throw new SQLException("Unlisted login may retain retired writer identity"); }
		}
	}

	private static boolean quarantined(@NonNull Connection connection, @NonNull List<String> roles, long deadline) throws SQLException {
		for (String role : roles) {
			requireSafeRole(connection, role, true, deadline);
			PgLocks.bound(connection, deadline);
			try (PreparedStatement statement = connection.prepareStatement("SELECT NOT rolcanlogin, (SELECT count(*) FROM pg_stat_activity WHERE usename=?), NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=r.oid OR member=r.oid) FROM pg_roles r WHERE rolname=?")) {
				statement.setString(1, role); statement.setString(2, role);
				try (ResultSet rows = statement.executeQuery()) { if (!rows.next() || !rows.getBoolean(1) || rows.getLong(2) != 0 || !rows.getBoolean(3)) return false; }
			}
			for (String table : tables(connection, deadline)) {
				PgLocks.bound(connection, deadline);
				try (PreparedStatement statement = connection.prepareStatement("SELECT has_table_privilege(?, ?, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')")) {
					statement.setString(1, role); statement.setString(2, "public." + table);
					try (ResultSet rows = statement.executeQuery()) { rows.next(); if (rows.getBoolean(1)) return false; }
				}
			}
		}
		return true;
	}

	private static boolean newRolesSafe(@NonNull Connection connection, @NonNull List<Row> rows, long deadline) throws SQLException {
		Set<String> wanted = new HashSet<>();
		for (Row row : rows) wanted.add(row.values[8]);
		Set<String> found = new HashSet<>();
		PgLocks.bound(connection, deadline);
		List<String> roles = new ArrayList<>();
		try (PreparedStatement statement = connection.prepareStatement("SELECT rolname FROM pg_roles WHERE rolname LIKE 'scp05_new_%' AND rolcanlogin")) {
			try (ResultSet result = statement.executeQuery()) { while (result.next()) { if (roles.size() >= 16) throw new SQLException("Fixture role bound exceeded"); roles.add(result.getString(1)); } }
		}
		for (String role : roles) {
			String identity = digest(role);
			if (wanted.contains(identity)) {
				requireSafeRole(connection, role, false, deadline);
				if (!memberships(connection, role, deadline).isEmpty()) return false;
				found.add(identity);
			}
		}
		return found.equals(wanted);
	}

	private static @NonNull List<String> tables(@NonNull Connection connection, long deadline) throws SQLException {
		List<String> tables = new ArrayList<>(TABLES);
		PgLocks.bound(connection, deadline);
		try (PreparedStatement statement = connection.prepareStatement("SELECT to_regclass('public.scp05_legacy_probe') IS NOT NULL")) {
			try (ResultSet result = statement.executeQuery()) { result.next(); if (result.getBoolean(1)) tables.add("scp05_legacy_probe"); }
		}
		return List.copyOf(tables);
	}

	private static void execute(@NonNull Connection connection, @NonNull String sql, long deadline) throws SQLException {
		PgLocks.bound(connection, deadline);
		try (Statement statement = connection.createStatement()) { statement.execute(sql); }
	}
	private static @NonNull String quoted(@NonNull String identifier) { return "\"" + identifier.replace("\"", "\"\"") + "\""; }
	private static @NonNull Duration left(long deadline) throws SQLException { return Duration.ofNanos(PgLocks.remaining(deadline)); }
	private static @NonNull String canonical(@NonNull String value) {
		if (!value.matches("[A-Za-z0-9_-]{43}")) throw new IllegalArgumentException("Canonical identity required");
		byte[] bytes = Base64.getUrlDecoder().decode(value + "=");
		if (bytes.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value)) throw new IllegalArgumentException("Canonical identity required");
		return value;
	}
	private static @NonNull String digest(@NonNull String value) {
		try { return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
		catch (NoSuchAlgorithmException failure) { throw new IllegalStateException("Required digest unavailable", failure); }
	}
	private static void validateRoles(@NonNull List<String> roles) {
		if (roles.isEmpty() || roles.size() > 3 || new HashSet<>(roles).size() != roles.size()) throw new IllegalArgumentException("Exact bounded retired roles required");
		for (String role : roles) if (!role.matches("scp05_old_[a-z0-9_]{1,50}")) throw new IllegalArgumentException("Only explicit fixture retired roles accepted");
	}

	/** Bounded stdin protocol; only fixed redacted status is emitted. */
	public static void main(String @NonNull [] args) {
		String answer = "UNKNOWN";
		try {
			if (args.length != 2 || !List.of("fence", "transition", "verify").contains(args[0])) throw new IllegalArgumentException("Control command required");
			long milliseconds = Long.parseLong(args[1]);
			if (milliseconds < 1 || milliseconds > 60000) throw new IllegalArgumentException("Control budget outside profile");
			byte[] input = System.in.readNBytes(16385);
			if (input.length > 16384 || !StandardCharsets.US_ASCII.newEncoder().canEncode(new String(input, StandardCharsets.UTF_8))) throw new IllegalArgumentException("Control request bound");
			BufferedReader reader = new BufferedReader(new InputStreamReader(new java.io.ByteArrayInputStream(input), StandardCharsets.US_ASCII));
			if (!"SCP05/1".equals(reader.readLine())) throw new IllegalArgumentException("Control request version required");
			int roleCount = Integer.parseInt(reader.readLine());
			if (roleCount < 1 || roleCount > 3) throw new IllegalArgumentException("Role count bound");
			List<String> roles = new ArrayList<>(); for (int index = 0; index < roleCount; index++) roles.add(java.util.Objects.requireNonNull(reader.readLine()));
			int rowCount = Integer.parseInt(reader.readLine());
			if (rowCount < 0 || rowCount > 3) throw new IllegalArgumentException("Scope count bound");
			List<Row> expected = new ArrayList<>(), target = new ArrayList<>();
			for (int index = 0; index < rowCount; index++) { expected.add(Row.fromLine(java.util.Objects.requireNonNull(reader.readLine()))); target.add(Row.fromLine(java.util.Objects.requireNonNull(reader.readLine()))); }
			if (reader.readLine() != null) throw new IllegalArgumentException("Unexpected control request suffix");
			String url = java.util.Objects.requireNonNull(System.getenv("DB_URL"));
			String user = java.util.Objects.requireNonNull(System.getenv("DB_USER"));
			String password = java.util.Objects.requireNonNull(System.getenv("DB_PASSWORD"));
			if (!url.startsWith("jdbc:postgresql://127.0.0.1:")) throw new IllegalArgumentException("Owned loopback fixture required");
			PgTransactions.ConnectionSource source = remaining -> {
				Properties properties = new Properties(); properties.setProperty("user", user); properties.setProperty("password", password);
				properties.setProperty("connectTimeout", Long.toString(Math.max(1L, (remaining.toMillis() + 999L) / 1000L)));
				properties.setProperty("socketTimeout", Long.toString(Math.max(1L, (remaining.toMillis() + 999L) / 1000L)));
				properties.setProperty("preferQueryMode", "simple");
				properties.setProperty("sslmode", "disable");
				properties.setProperty("gssEncMode", "disable");
				return DriverManager.getConnection(url, properties);
			};
			Duration budget = Duration.ofMillis(milliseconds);
			if (args[0].equals("fence")) answer = fence(source, budget, roles).name();
			else if (args[0].equals("transition")) answer = transition(source, budget, expected, target, roles).name();
			else answer = verify(source, budget, target, roles) ? "VERIFIED" : "UNVERIFIED";
		} catch (Exception failure) {
			if (args.length > 0 && args[0].equals("verify")) answer = "UNVERIFIED";
		}
		System.out.println(answer);
	}
}
