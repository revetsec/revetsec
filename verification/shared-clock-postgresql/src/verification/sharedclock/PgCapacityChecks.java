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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Properties;

/** Private scripted/native capacity checks. No engine-transaction or UTC qualification claim. */
final class PgCapacityChecks {
	private PgCapacityChecks() { }

	public static void main(@NonNull String @NonNull [] args) throws Exception {
		pure();
		if (args.length == 1 && (args[0].equals("pure") || args[0].equals("--pure")))
			return;
		if (args.length != 0)
			throw new IllegalArgumentException("Unsupported capacity check arguments");
		nativeChecks();
	}

	private static void pure() throws Exception {
		check(PgCapacity.base64Length(0) == 0 && PgCapacity.base64Length(1) == 2
				&& PgCapacity.base64Length(2) == 3 && PgCapacity.base64Length(3) == 4, "capacity-base64-exact");
		String key = "revetsec:totp:3:scope:root";
		check(PgCapacity.bucket(key) == (MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.US_ASCII))[0] & 0xff), "capacity-bucket-exact-ascii");
		reject(() -> PgCapacity.bucket("bad\u0080"));
		reject(() -> PgCapacity.bucket(""));
		check(true, "capacity-bucket-invalid-input");
		PgCapacity.Reservation shortKey = PgCapacity.totpReservation(wire(1, 42667));
		PgCapacity.Reservation longKey = PgCapacity.totpReservation(wire(64, 42667));
		check(shortKey.getReservedBytes() == 57047 && longKey.getReservedBytes() == 57047
				&& shortKey.getActualBytes() < shortKey.getReservedBytes()
				&& longKey.getActualBytes() == longKey.getReservedBytes()
				&& shortKey.getPlaintextBytes() == 42667 && shortKey.getKeyIdLength() == 1,
				"capacity-totp-rotation-reserves-64-key");
		check(PgCapacity.totpReservation(wire(1, 49034)).getReservedBytes() == 65536, "capacity-totp-reservation-exact-cap");
		reject(() -> PgCapacity.totpReservation(wire(1, 49035)));
		for (byte[] bad : List.of(new byte[0], "AA==".getBytes(StandardCharsets.US_ASCII),
				"AAA!".getBytes(StandardCharsets.US_ASCII), new byte[] {(byte) 0xff},
				encodedRaw(2, 1, 100), encodedRaw(1, 0, 100), encodedRaw(1, 65, 100)))
			reject(() -> PgCapacity.totpReservation(bad));
		byte[] invalidKey = raw(1, 3, 100); invalidKey[2] = '+';
		reject(() -> PgCapacity.totpReservation(Base64.getUrlEncoder().withoutPadding().encode(invalidKey)));
		byte[] canonical = wire(1, 0);
		byte[] padded = Arrays.copyOf(canonical, canonical.length + 2); padded[canonical.length] = '='; padded[canonical.length + 1] = '=';
		reject(() -> PgCapacity.totpReservation(padded));
		check(true, "capacity-totp-framing-refusals");
		long[] actual = new long[256], bytes = new long[256], bootstrap = new long[256], bootstrapBytes = new long[256];
		actual[3] = 2; bytes[3] = 99; bootstrap[200] = 1; bootstrapBytes[200] = 1126;
		PgCapacity.Allocation allocation = PgCapacity.allocate("TOTP", 1000, 10000, actual, bytes, bootstrap, bootstrapBytes);
		long[] limits = allocation.getEntryLimits(), byteLimits = allocation.getByteLimits();
		check(Arrays.stream(limits).sum() == 1000 && Arrays.stream(byteLimits).sum() == 10000
				&& limits[200] >= 1 && byteLimits[200] >= 1126
				&& allocation.getUsedEntries()[200] == 0 && allocation.getUsedBytes()[200] == 0
				&& allocation.getUsedEntries()[3] == 2 && allocation.getUsedBytes()[3] == 99,
				"capacity-quota-actual-bootstrap-separate");
		check(limits[0] == 4 && limits[255] == 3 && limits[3] == 6, "capacity-quota-remainder-exact");
		limits[3] = -1; actual[3] = 900;
		check(allocation.getEntryLimits()[3] == 6 && allocation.getUsedEntries()[3] == 2, "capacity-allocation-defensive-copy");
		long[] zero = new long[256], one = new long[256]; one[200] = 1;
		PgCapacity.Allocation tiny = PgCapacity.allocate("ISSUER", 1, 0, zero, zero, one, zero);
		check(tiny.getEntryLimits()[200] == 1 && tiny.getUsedEntries()[200] == 0
				&& tiny.getEntryLimits()[0] == 0 && Arrays.stream(tiny.getEntryLimits()).sum() == 1,
				"capacity-tiny-bootstrap-assignment");
		reject(() -> PgCapacity.allocate("ISSUER", 1, 0, one, zero, one, zero));
		reject(() -> PgCapacity.allocate("ISSUER", 1_000_001, 0, zero, zero, zero, zero));
		reject(() -> PgCapacity.allocate("ISSUER", 1, 1, zero, zero, zero, zero));
		reject(() -> PgCapacity.allocate("TOTP", 65_537, 1, zero, zero, zero, zero));
		reject(() -> PgCapacity.allocate("TOTP", 1, 268_435_457, zero, zero, zero, zero));
		reject(() -> PgCapacity.allocate("TOTP", 1, 1, new long[255], zero, zero, zero));
		long[] overflow = new long[256]; overflow[200] = Long.MAX_VALUE;
		reject(() -> PgCapacity.allocate("TOTP", 1, 1, overflow, zero, one, zero));
		check(true, "capacity-hard-limit-overflow-refusals");
	}

	private static void nativeChecks() throws Exception {
		String generation = id("capacity-allocation"), stale = id("stale-allocation");
		PgScope scope = PgScope.from("ISSUER", id("capacity-native"));
		try (Connection setup = connection()) {
			try (Statement statement = setup.createStatement()) {
				statement.execute("CREATE TABLE IF NOT EXISTS scp05_capacity_probe(namespace text PRIMARY KEY,value integer NOT NULL)");
			}
			seed(setup, scope, generation, 1, 0, 0, 0, 0);
			seed(setup, scope, generation, 2, 1, 0, 0, 0);
			seed(setup, scope, generation, 3, 5, 1, 0, 0);
			seed(setup, scope, generation, 4, 5, 0, 0, 0);
			seed(setup, scope, generation, 5, 5, 0, 0, 0);
			seed(setup, scope, generation, 6, 5, 0, 0, 0);
		}
		try (Connection c = transaction()) {
			PgCapacity.LockedPlan empty = PgCapacity.lockAndCheck(c, scope, generation, List.of(), deadline());
			check(empty.isEmpty() && empty.getBucketCount() == 0, "capacity-native-barrier-no-buckets");
			empty.apply(c, deadline()); c.commit();
		}
		try (Connection c = transaction()) {
			PgCapacity.LockedPlan empty = PgCapacity.lockAndCheck(c, scope, generation,
					List.of(PgCapacity.Delta.from(1, 1, 0), PgCapacity.Delta.from(1, -1, 0)), deadline());
			check(empty.isEmpty(), "capacity-native-merged-zero-no-lock-or-write");
			empty.apply(c, deadline()); c.commit();
		}
		try (Connection c = transaction()) {
			PgCapacity.LockedPlan insufficient = PgCapacity.lockForValidation(c, scope, generation,
					List.of(PgCapacity.Delta.from(1, 1, 0)), deadline());
			check(insufficient.getBucketCount() == 1 && used(c, scope, 1) == 0,
					"capacity-native-capacity-refusal-deferred-until-validation");
			try { insufficient.checkCapacity(); throw new AssertionError("Expected deferred capacity refusal"); }
			catch (PgCapacity.CapacityRefused expected) { }
			try { insufficient.apply(c, deadline()); throw new AssertionError("Expected apply capacity refusal"); }
			catch (PgCapacity.CapacityRefused expected) { }
			check(used(c, scope, 1) == 0, "capacity-native-unchecked-apply-cannot-bypass-capacity"); c.rollback();
		}
		try (Connection c = transaction()) {
			try {
				PgCapacity.lockAndCheck(c, scope, generation, List.of(PgCapacity.Delta.from(1, 1, 0)), deadline());
				throw new AssertionError("Expected assigned capacity refusal");
			} catch (PgCapacity.CapacityRefused expected) { c.rollback(); }
			check(used(c, scope, 1) == 0 && used(c, scope, 2) == 0, "capacity-native-stranded-quota-refusal");
			c.rollback();
		}
		try (Connection c = transaction()) {
			sqlReject(() -> PgCapacity.lockAndCheck(c, scope, stale, List.of(PgCapacity.Delta.from(3, 1, 0)), deadline()));
			c.rollback();
			check(used(c, scope, 3) == 1, "capacity-native-stale-generation-refusal"); c.rollback();
		}
		try (Connection c = transaction()) {
			PgCapacity.LockedPlan plan = PgCapacity.lockAndCheck(c, scope, generation,
					List.of(PgCapacity.Delta.from(4, 1, 0), PgCapacity.Delta.from(3, -1, 0), PgCapacity.Delta.from(4, 1, 0)), deadline());
			check(plan.getBucketCount() == 2, "capacity-native-sorted-merged-plan");
			plan.apply(c, deadline()); c.commit();
			check(used(c, scope, 3) == 0 && used(c, scope, 4) == 2, "capacity-native-positive-negative-deltas-atomic"); c.rollback();
		}
		try (Connection c = transaction()) {
			PgCapacity.LockedPlan plan = PgCapacity.lockAndCheck(c, scope, generation, List.of(PgCapacity.Delta.from(5, 1, 0)), deadline());
			try (PreparedStatement statement = c.prepareStatement("INSERT INTO scp05_capacity_probe(namespace,value) VALUES(?,1)")) {
				statement.setString(1, scope.getNamespace()); statement.executeUpdate();
			}
			plan.apply(c, deadline()); c.rollback();
			check(used(c, scope, 5) == 0 && dataCount(c, scope) == 0, "capacity-native-data-plus-quota-rollback"); c.rollback();
		}
		try (Connection c = transaction()) {
			PgCapacity.LockedPlan plan = PgCapacity.lockAndCheck(c, scope, generation, List.of(PgCapacity.Delta.from(5, 1, 0)), deadline());
			try (PreparedStatement statement = c.prepareStatement("INSERT INTO scp05_capacity_probe(namespace,value) VALUES(?,1)")) {
				statement.setString(1, scope.getNamespace()); statement.executeUpdate();
			}
			plan.apply(c, deadline()); c.commit();
			check(used(c, scope, 5) == 1 && dataCount(c, scope) == 1, "capacity-native-data-plus-quota-commit"); c.rollback();
			sqlReject(() -> plan.apply(c, deadline())); c.rollback();
			check(true, "capacity-native-plan-single-use");
		}
		try (Connection c = transaction()) {
			PgCapacity.LockedPlan plan = PgCapacity.lockAndCheck(c, scope, generation, List.of(PgCapacity.Delta.from(6, 1, 0)), deadline());
			c.rollback();
			sqlReject(() -> plan.apply(c, deadline())); c.rollback();
			check(used(c, scope, 6) == 0, "capacity-native-plan-cannot-cross-transaction"); c.rollback();
		}
		try (Connection held = transaction(); Connection independent = transaction()) {
			PgCapacity.lockAndCheck(held, scope, generation, List.of(PgCapacity.Delta.from(3, 1, 0)), deadline());
			PgCapacity.LockedPlan other = PgCapacity.lockAndCheck(independent, scope, generation, List.of(PgCapacity.Delta.from(6, 1, 0)), deadline());
			other.apply(independent, deadline()); independent.commit();
			check(used(independent, scope, 6) == 1, "capacity-native-distinct-bucket-progress"); independent.rollback();
			long shortDeadline = System.nanoTime() + 75_000_000L;
			sqlReject(() -> PgCapacity.lockAndCheck(independent, scope, generation, List.of(PgCapacity.Delta.from(3, 1, 0)), shortDeadline));
			independent.rollback(); held.rollback();
			check(true, "capacity-native-same-bucket-original-budget");
		}
		PgScope totp = PgScope.from("TOTP", id("capacity-native-totp"));
		try (Connection setup = connection()) { seed(setup, totp, generation, 2, 4, 1, 1126, 1000); }
		try (Connection c = transaction()) {
			PgCapacity.LockedPlan plan = PgCapacity.lockAndCheck(c, totp, generation, List.of(PgCapacity.Delta.from(2, 0, 126)), deadline());
			plan.apply(c, deadline()); c.commit();
			try (PreparedStatement statement = c.prepareStatement("SELECT used_entries,used_bytes FROM scp05_escrow WHERE family=? AND namespace=? AND bucket=2")) {
				statement.setString(1, totp.getFamily()); statement.setString(2, totp.getNamespace());
				try (ResultSet result = statement.executeQuery()) { check(result.next() && result.getLong(1) == 1 && result.getLong(2) == 1126, "capacity-native-totp-reserved-byte-growth"); }
			}
			c.rollback();
			try { PgCapacity.lockAndCheck(c, totp, generation, List.of(PgCapacity.Delta.from(2, 0, 1)), deadline()); throw new AssertionError("Expected byte refusal"); }
			catch (PgCapacity.CapacityRefused expected) { c.rollback(); }
			check(true, "capacity-native-totp-byte-refusal");
		}
	}

	private static long deadline() { return System.nanoTime() + 5_000_000_000L; }
	private static @NonNull Connection connection() throws SQLException {
		String url = System.getenv("DB_URL"), user = System.getenv("DB_USER"), password = System.getenv("DB_PASSWORD");
		if (url == null || user == null || password == null) throw new SQLException("Owned fixture connection missing");
		Properties properties = new Properties(); properties.setProperty("user", user); properties.setProperty("password", password);
		properties.setProperty("connectTimeout", "5"); properties.setProperty("socketTimeout", "5");
		Connection connection = DriverManager.getConnection(url, properties);
		connection.setNetworkTimeout(Runnable::run, 5000);
		return connection;
	}
	private static @NonNull Connection transaction() throws SQLException { Connection c = connection(); c.setAutoCommit(false); return c; }
	private static void seed(@NonNull Connection c, @NonNull PgScope scope, @NonNull String generation,
			int bucket, long entryLimit, long usedEntries, long byteLimit, long usedBytes) throws SQLException {
		try (PreparedStatement statement = c.prepareStatement("INSERT INTO scp05_escrow(family,namespace,bucket,allocation_generation,entry_limit,used_entries,byte_limit,used_bytes) VALUES(?,?,?,?,?,?,?,?)")) {
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace()); statement.setInt(3, bucket); statement.setString(4, generation);
			statement.setLong(5, entryLimit); statement.setLong(6, usedEntries); statement.setLong(7, byteLimit); statement.setLong(8, usedBytes); statement.executeUpdate();
		}
	}
	private static long used(@NonNull Connection c, @NonNull PgScope scope, int bucket) throws SQLException {
		try (PreparedStatement statement = c.prepareStatement("SELECT used_entries FROM scp05_escrow WHERE family=? AND namespace=? AND bucket=?")) {
			statement.setString(1, scope.getFamily()); statement.setString(2, scope.getNamespace()); statement.setInt(3, bucket);
			try (ResultSet result = statement.executeQuery()) { if (!result.next()) throw new SQLException("Missing capacity check bucket"); return result.getLong(1); }
		}
	}
	private static int dataCount(@NonNull Connection c, @NonNull PgScope scope) throws SQLException {
		try (PreparedStatement statement = c.prepareStatement("SELECT count(*) FROM scp05_capacity_probe WHERE namespace=?")) {
			statement.setString(1, scope.getNamespace());
			try (ResultSet result = statement.executeQuery()) { if (!result.next()) throw new SQLException("Missing capacity data check"); return result.getInt(1); }
		}
	}
	private static byte @NonNull [] raw(int version, int keyLength, int plaintext) {
		byte[] value = new byte[54 + Math.max(1, keyLength) + plaintext]; value[0] = (byte) version; value[1] = (byte) keyLength;
		Arrays.fill(value, 2, 2 + Math.max(1, keyLength), (byte) 'k'); return value;
	}
	private static byte @NonNull [] wire(int keyLength, int plaintext) { return encodedRaw(1, keyLength, plaintext); }
	private static byte @NonNull [] encodedRaw(int version, int keyLength, int plaintext) { return Base64.getUrlEncoder().withoutPadding().encode(raw(version, keyLength, plaintext)); }
	private static @NonNull String id(@NonNull String label) throws Exception { return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.US_ASCII))); }
	private static void check(boolean condition, @NonNull String name) { if (!condition) throw new AssertionError("Capacity assertion failed"); System.out.println("PASS " + name); }
	private static void reject(@NonNull Checked operation) throws Exception { try { operation.run(); } catch (IllegalArgumentException expected) { return; } throw new AssertionError("Expected capacity validation refusal"); }
	private static void sqlReject(@NonNull Checked operation) throws Exception { try { operation.run(); } catch (SQLException expected) { return; } throw new AssertionError("Expected capacity SQL refusal"); }
	@FunctionalInterface private interface Checked { void run() throws Exception; }
}
