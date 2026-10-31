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
import verification.sharedclock.PgTransactions.Outcome;
import verification.sharedclock.PgTransactions.Refusal;
import verification.sharedclock.PgTransactions.Status;
import verification.sharedclock.PgCapacity.Allocation;

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
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Properties;

/** Native closed quota controller checks; synthetic rows are not engine-authorized state. */
final class PgQuotaControlChecks {
	private static final @NonNull Duration BUDGET = Duration.ofSeconds(15);
	private static final @NonNull PgScope SCOPE = PgScope.from("ISSUER", "scp05-quota-issuer");
	private static final @NonNull PgScope TOTP_SCOPE = PgScope.from("TOTP", "scp05-quota-totp");
	private static final @NonNull String G0 = id("quota-generation0"), G1 = id("quota-generation1"), G2 = id("quota-generation2");
	private static final @NonNull String PROFILE = id("quota-profile");
	private static final @NonNull String ROOT_KEY = "quota:stable-root";
	private static final int ROOT_BUCKET = PgCapacity.bucket(ROOT_KEY);

	private PgQuotaControlChecks() { }

	public static void main(@NonNull String @NonNull [] arguments) {
		try {
			if (arguments.length != 0) throw new IllegalArgumentException("Unexpected quota check arguments");
			initialize(SCOPE);
			initialize(TOTP_SCOPE);
			bootstrapChecks();
			rootDeltaChecks();
			refusalChecks();
			rollbackAndReallocationChecks();
			totpBootstrapChecks();
		} catch (Throwable failure) { throw new IllegalStateException("SCP05 quota control checks failed"); }
	}

	private static @NonNull String id(@NonNull String label) {
		try { return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.US_ASCII))); }
		catch (NoSuchAlgorithmException failure) { throw new IllegalStateException("Required fixture digest unavailable"); }
	}

	private static @NonNull Connection connect(@NonNull Duration remaining) throws SQLException {
		Properties properties = new Properties();
		properties.setProperty("user", Objects.requireNonNull(System.getenv("DB_USER")));
		properties.setProperty("password", Objects.requireNonNull(System.getenv("DB_PASSWORD")));
		properties.setProperty("connectTimeout", Long.toString(Math.max(1, Math.min(60, 1 + (remaining.toNanos() - 1) / 1_000_000_000))));
		properties.setProperty("socketTimeout", "15");
		properties.setProperty("preferQueryMode", "simple"); properties.setProperty("sslmode", "disable"); properties.setProperty("gssEncMode", "disable");
		return DriverManager.getConnection(Objects.requireNonNull(System.getenv("DB_URL")), properties);
	}

	private static void initialize(@NonNull PgScope scope) throws SQLException {
		try (Connection connection = connect(BUDGET)) {
			for (String table : List.of("scp05_entries", "scp05_escrow", "scp05_admission")) {
				try (PreparedStatement statement = connection.prepareStatement("DELETE FROM " + table + " WHERE family=? AND namespace=?")) {
					statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace()); statement.executeUpdate();
				}
			}
			try (PreparedStatement statement = connection.prepareStatement("INSERT INTO scp05_admission VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")) {
				statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace()); statement.setString(3, id("quota-authority"));
				statement.setString(4, id("quota-recovery")); statement.setString(5, id("quota-clock")); statement.setString(6, PROFILE);
				statement.setString(7, id("quota-schema")); statement.setString(8, id("quota-metadata0")); statement.setString(9, id("quota-writer"));
				statement.setString(10, G0); statement.setInt(11, scope.getFamily().equals("TOTP") ? 3 : 2); statement.setString(12, "CLOSED"); statement.executeUpdate();
			}
		}
	}

	private static @NonNull Allocation allocation(long cap, long @NonNull [] used, int plannedBucket) {
		long[] planned = new long[256];
		planned[plannedBucket] = 1;
		return PgCapacity.allocate("ISSUER", cap, 0, used, new long[256], planned, new long[256]);
	}

	private static @NonNull Allocation reallocation() {
		long[] used = new long[256]; used[ROOT_BUCKET] = 1;
		return allocation(1024, used, (ROOT_BUCKET + 1) % 256);
	}

	private static void bootstrapChecks() throws SQLException {
		long[] precharged = new long[256]; precharged[ROOT_BUCKET] = 1;
		Outcome<Boolean> invalid = PgQuotaControl.bootstrap(PgQuotaControlChecks::connect, BUDGET, SCOPE, G0, G1, PROFILE,
				id("quota-metadata1"), allocation(1024, precharged, ROOT_BUCKET));
		check("quota-bootstrap-cannot-precharge-planned-roots", invalid.status() == Status.NO_EFFECT
				&& invalid.refusal().orElseThrow() == Refusal.CONFLICT && summary(SCOPE, G0)[0] == 0 && admissionGeneration(SCOPE).equals(G0));
		Allocation allocation = allocation(1024, new long[256], ROOT_BUCKET);
		Outcome<Boolean> result = PgQuotaControl.bootstrap(PgQuotaControlChecks::connect, BUDGET, SCOPE, G0, G1, PROFILE, id("quota-metadata1"), allocation);
		long[] state = summary(SCOPE, G1);
		check("quota-bootstrap-256-reserved-limits-used-zero", result.status() == Status.COMMITTED && state[0] == 256 && state[1] == 1024 && state[2] == 0
				&& state[3] == 0 && state[4] == 0 && state[5] == 256 && admissionGeneration(SCOPE).equals(G1));
		try (Connection connection = connect(BUDGET); PreparedStatement statement = connection.prepareStatement("SELECT entry_limit FROM scp05_escrow WHERE family=? AND namespace=? AND bucket=?")) {
			statement.setString(1, SCOPE.getFamily()); statement.setString(2, SCOPE.getNamespace()); statement.setInt(3, ROOT_BUCKET);
			try (ResultSet rows = statement.executeQuery()) { check("quota-bootstrap-root-reservation-not-actual-charge", rows.next() && rows.getLong(1) >= 1); }
		}
		String before = fingerprint(SCOPE);
		result = PgQuotaControl.bootstrap(PgQuotaControlChecks::connect, BUDGET, SCOPE, G1, G2, PROFILE, id("quota-metadata2"), allocation);
		check("quota-existing-allocation-not-reinitialized", result.status() == Status.NO_EFFECT && result.refusal().orElseThrow() == Refusal.CONFLICT && fingerprint(SCOPE).equals(before));
	}

	private static void rootDeltaChecks() throws SQLException {
		Outcome<Boolean> first = rootDelta();
		Outcome<Boolean> second = rootDelta();
		check("quota-root-actual-delta-applied-once", first.status() == Status.COMMITTED && second.status() == Status.NO_EFFECT
				&& second.refusal().orElseThrow() == Refusal.CONFLICT && summary(SCOPE, G1)[2] == 1);
	}

	private static @NonNull Outcome<Boolean> rootDelta() {
		return PgTransactions.execute(PgQuotaControlChecks::connect, BUDGET, context -> {
			PgLocks.exclusiveAdmission(context.connection(), List.of(SCOPE), context.deadlineNanos());
			PgLocks.entities(context.connection(), List.of(PgLocks.entity(SCOPE, ROOT_KEY, true)), context.deadlineNanos());
			try (PreparedStatement statement = context.connection().prepareStatement("SELECT version FROM scp05_entries WHERE family=? AND namespace=? AND storage_key=?")) {
				context.bound(statement); statement.setString(1, SCOPE.getFamily()); statement.setString(2, SCOPE.getNamespace()); statement.setString(3, ROOT_KEY);
				try (ResultSet rows = statement.executeQuery()) { if (rows.next()) return PgTransactions.Decision.refuse(Refusal.CONFLICT); }
			}
			PgCapacity.LockedPlan plan = PgCapacity.lockAndCheck(context.connection(), SCOPE, G1, List.of(PgCapacity.Delta.from(ROOT_BUCKET, 1, 0)), context.deadlineNanos());
			context.markPossibleMutation();
			try (PreparedStatement statement = context.connection().prepareStatement("INSERT INTO scp05_entries(family,namespace,storage_key,version,payload,actual_size,reserved_bytes) VALUES(?,?,?,?,?,1,0)")) {
				context.bound(statement); statement.setString(1, SCOPE.getFamily()); statement.setString(2, SCOPE.getNamespace()); statement.setString(3, ROOT_KEY);
				statement.setString(4, id("quota-root-version")); statement.setBytes(5, new byte[]{1});
				if (statement.executeUpdate() != 1) throw new SQLException("Private root insert failed");
			}
			plan.apply(context.connection(), context.deadlineNanos());
			return PgTransactions.Decision.commit(Boolean.TRUE);
		});
	}

	private static void refusalChecks() throws SQLException {
		setMode("ACTIVE");
		String before = fingerprint(SCOPE);
		Outcome<Boolean> result = PgQuotaControl.reallocate(PgQuotaControlChecks::connect, BUDGET, SCOPE, G1, G2, PROFILE, id("quota-metadata2"), reallocation());
		check("quota-active-admission-refuses-reallocation", result.status() == Status.NO_EFFECT && result.refusal().orElseThrow() == Refusal.FENCED && fingerprint(SCOPE).equals(before));
		setMode("CLOSED"); before = fingerprint(SCOPE);
		result = PgQuotaControl.reallocate(PgQuotaControlChecks::connect, BUDGET, SCOPE, G0, G2, PROFILE, id("quota-metadata2"), reallocation());
		check("quota-stale-generation-refused", result.status() == Status.NO_EFFECT && result.refusal().orElseThrow() == Refusal.FENCED && fingerprint(SCOPE).equals(before));
		result = PgQuotaControl.reallocate(PgQuotaControlChecks::connect, BUDGET, SCOPE, G1, G2, id("wrong-profile"), id("quota-metadata2"), reallocation());
		check("quota-profile-mismatch-refused", result.status() == Status.NO_EFFECT && result.refusal().orElseThrow() == Refusal.FENCED && fingerprint(SCOPE).equals(before));
		result = PgQuotaControl.reallocate(PgQuotaControlChecks::connect, BUDGET, SCOPE, G1, G2, PROFILE, id("quota-metadata2"), allocation(1024, new long[256], ROOT_BUCKET));
		check("quota-wrong-actual-input-refused", result.status() == Status.NO_EFFECT && result.refusal().orElseThrow() == Refusal.CONFLICT && fingerprint(SCOPE).equals(before));
		long[] used = new long[256]; used[ROOT_BUCKET] = 1;
		result = PgQuotaControl.reallocate(PgQuotaControlChecks::connect, BUDGET, SCOPE, G1, G2, PROFILE, id("quota-metadata2"), allocation(1025, used, ROOT_BUCKET));
		check("quota-configured-cap-increase-refused", result.status() == Status.NO_EFFECT && result.refusal().orElseThrow() == Refusal.CAPACITY && fingerprint(SCOPE).equals(before));
		int other = (ROOT_BUCKET + 1) % 256;
		setCounter(other, 1); used[other] = 1;
		before = fingerprint(SCOPE);
		result = PgQuotaControl.reallocate(PgQuotaControlChecks::connect, BUDGET, SCOPE, G1, G2, PROFILE, id("quota-metadata2"), allocation(1024, used, ROOT_BUCKET));
		check("quota-counter-versus-entry-inventory-refused", result.status() == Status.NO_EFFECT && result.refusal().orElseThrow() == Refusal.CONFLICT && fingerprint(SCOPE).equals(before));
		setCounter(other, 0);
		setRowGeneration(other, id("foreign-row-generation")); before = fingerprint(SCOPE);
		result = PgQuotaControl.reallocate(PgQuotaControlChecks::connect, BUDGET, SCOPE, G1, G2, PROFILE, id("quota-metadata2"), reallocation());
		check("quota-mixed-row-generation-refused", result.status() == Status.NO_EFFECT && result.refusal().orElseThrow() == Refusal.FENCED && fingerprint(SCOPE).equals(before));
		setRowGeneration(other, G1);
		before = fingerprint(SCOPE);
		boolean reused = false;
		try { PgQuotaControl.reallocate(PgQuotaControlChecks::connect, BUDGET, SCOPE, G1, G1, PROFILE, id("quota-metadata2"), reallocation()); }
		catch (IllegalArgumentException expected) { reused = true; }
		check("quota-allocation-generation-cannot-be-reused", reused && fingerprint(SCOPE).equals(before));
	}

	private static void rollbackAndReallocationChecks() throws SQLException {
		try (Connection connection = connect(BUDGET); Statement statement = connection.createStatement()) {
			statement.execute("CREATE OR REPLACE FUNCTION scp05_quota_fault_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.family='ISSUER' AND NEW.namespace='scp05-quota-issuer' AND current_setting('scp05.quota_fault',true)='on' THEN RAISE EXCEPTION 'private quota fault'; END IF; RETURN NEW; END $$");
			statement.execute("DROP TRIGGER IF EXISTS scp05_quota_fault ON scp05_admission");
			statement.execute("CREATE TRIGGER scp05_quota_fault AFTER UPDATE ON scp05_admission FOR EACH ROW EXECUTE FUNCTION scp05_quota_fault_fn()");
		}
		String before = fingerprint(SCOPE);
		Outcome<Boolean> result = PgQuotaControl.reallocate(remaining -> {
			Connection connection = connect(remaining);
			try (Statement statement = connection.createStatement()) { statement.execute("SET scp05.quota_fault='on'"); }
			return connection;
		}, BUDGET, SCOPE, G1, G2, PROFILE, id("quota-metadata2"), reallocation());
		check("quota-after-admission-fault-rolls-back-all-256", result.status() == Status.NO_EFFECT && result.possibleMutation() && fingerprint(SCOPE).equals(before));
		String authority = safety(SCOPE);
		result = PgQuotaControl.reallocate(PgQuotaControlChecks::connect, BUDGET, SCOPE, G1, G2, PROFILE, id("quota-metadata2"), reallocation());
		long[] state = summary(SCOPE, G2);
		check("quota-closed-reallocation-preserves-actual-and-safety", result.status() == Status.COMMITTED && state[0] == 256 && state[1] == 1024
				&& state[2] == 1 && state[5] == 256 && admissionGeneration(SCOPE).equals(G2) && safety(SCOPE).equals(authority));
	}

	private static void totpBootstrapChecks() throws SQLException {
		boolean excessive = false;
		try {
			PgQuotaControl.bootstrap(PgQuotaControlChecks::connect, BUDGET, TOTP_SCOPE, G0, G1, PROFILE, id("quota-totp-metadata1"),
					allocation(1_000_000, new long[256], ROOT_BUCKET));
		} catch (IllegalArgumentException expected) { excessive = true; }
		check("quota-family-hard-cap-checked-before-provisioning", excessive && summary(TOTP_SCOPE, G0)[0] == 0);
		long[] plannedEntries = new long[256], plannedBytes = new long[256];
		plannedEntries[ROOT_BUCKET] = 1; plannedBytes[ROOT_BUCKET] = 500;
		Allocation allocation = PgCapacity.allocate("TOTP", 1024, 65536, new long[256], new long[256], plannedEntries, plannedBytes);
		Outcome<Boolean> result = PgQuotaControl.bootstrap(PgQuotaControlChecks::connect, BUDGET, TOTP_SCOPE, G0, G1, PROFILE, id("quota-totp-metadata1"), allocation);
		long[] state = summary(TOTP_SCOPE, G1);
		check("quota-totp-bootstrap-byte-reservation-used-zero", result.status() == Status.COMMITTED && state[0] == 256 && state[1] == 1024
				&& state[2] == 0 && state[3] == 65536 && state[4] == 0 && state[5] == 256);
	}

	private static void setMode(@NonNull String mode) throws SQLException {
		try (Connection connection = connect(BUDGET); PreparedStatement statement = connection.prepareStatement("UPDATE scp05_admission SET mode=? WHERE family=? AND namespace=?")) {
			statement.setString(1, mode); statement.setString(2, SCOPE.getFamily()); statement.setString(3, SCOPE.getNamespace()); statement.executeUpdate();
		}
	}

	private static void setCounter(int bucket, long used) throws SQLException {
		try (Connection connection = connect(BUDGET); PreparedStatement statement = connection.prepareStatement("UPDATE scp05_escrow SET used_entries=? WHERE family=? AND namespace=? AND bucket=?")) {
			statement.setLong(1, used); statement.setString(2, SCOPE.getFamily()); statement.setString(3, SCOPE.getNamespace()); statement.setInt(4, bucket); statement.executeUpdate();
		}
	}

	private static void setRowGeneration(int bucket, @NonNull String generation) throws SQLException {
		try (Connection connection = connect(BUDGET); PreparedStatement statement = connection.prepareStatement("UPDATE scp05_escrow SET allocation_generation=? WHERE family=? AND namespace=? AND bucket=?")) {
			statement.setString(1, generation); statement.setString(2, SCOPE.getFamily()); statement.setString(3, SCOPE.getNamespace()); statement.setInt(4, bucket); statement.executeUpdate();
		}
	}

	private static long @NonNull [] summary(@NonNull PgScope scope, @NonNull String generation) throws SQLException {
		try (Connection connection = connect(BUDGET); PreparedStatement statement = connection.prepareStatement("SELECT count(*),sum(entry_limit),sum(used_entries),sum(byte_limit),sum(used_bytes),count(*) FILTER(WHERE allocation_generation=?) FROM scp05_escrow WHERE family=? AND namespace=?")) {
			statement.setString(1, generation); statement.setString(2, scope.getFamily()); statement.setString(3, scope.getNamespace());
			try (ResultSet rows = statement.executeQuery()) {
				if (!rows.next()) throw new SQLException("Missing quota summary");
				long[] result = new long[6]; for (int index = 0; index < 6; ++index) result[index] = rows.getLong(index + 1);
				return result;
			}
		}
	}

	private static @NonNull String admissionGeneration(@NonNull PgScope scope) throws SQLException {
		try (Connection connection = connect(BUDGET); PreparedStatement statement = connection.prepareStatement("SELECT allocation_generation FROM scp05_admission WHERE family=? AND namespace=? AND mode='CLOSED'")) {
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace());
			try (ResultSet rows = statement.executeQuery()) { if (!rows.next()) throw new SQLException("Missing closed quota admission"); return rows.getString(1); }
		}
	}

	private static @NonNull String safety(@NonNull PgScope scope) throws SQLException {
		try (Connection connection = connect(BUDGET); PreparedStatement statement = connection.prepareStatement("SELECT authority_id,recovery_generation,clock_generation,profile_commitment,schema_commitment,writer_role_identity,format_version,mode FROM scp05_admission WHERE family=? AND namespace=?")) {
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace());
			try (ResultSet rows = statement.executeQuery()) {
				if (!rows.next()) throw new SQLException("Missing quota safety state");
				StringBuilder result = new StringBuilder(); for (int column = 1; column <= 8; ++column) result.append(rows.getString(column)).append('|');
				return result.toString();
			}
		}
	}

	private static @NonNull String fingerprint(@NonNull PgScope scope) throws SQLException {
		StringBuilder result = new StringBuilder(safety(scope)).append(admissionGenerationIncludingMode(scope));
		try (Connection connection = connect(BUDGET); PreparedStatement statement = connection.prepareStatement("SELECT bucket,allocation_generation,entry_limit,used_entries,byte_limit,used_bytes FROM scp05_escrow WHERE family=? AND namespace=? ORDER BY bucket")) {
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace());
			try (ResultSet rows = statement.executeQuery()) {
				while (rows.next()) for (int column = 1; column <= 6; ++column) result.append(rows.getString(column)).append('|');
			}
		}
		return result.toString();
	}

	private static @NonNull String admissionGenerationIncludingMode(@NonNull PgScope scope) throws SQLException {
		try (Connection connection = connect(BUDGET); PreparedStatement statement = connection.prepareStatement("SELECT allocation_generation,metadata_commitment FROM scp05_admission WHERE family=? AND namespace=?")) {
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace());
			try (ResultSet rows = statement.executeQuery()) { if (!rows.next()) throw new SQLException("Missing quota metadata"); return rows.getString(1) + rows.getString(2); }
		}
	}

	private static void check(@NonNull String label, boolean condition) {
		if (!condition) throw new AssertionError("Private quota assertion failed: " + label);
		System.out.println("PASS " + label);
	}
}
