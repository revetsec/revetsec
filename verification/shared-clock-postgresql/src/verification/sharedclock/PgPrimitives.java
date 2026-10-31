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
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/** Inactive native transaction components. These are not engine-authorized transactions. */
final class PgPrimitives {
	private PgPrimitives() {}
	static final Instant MAX_TIME = Instant.ofEpochSecond(253402300799L, 999999999);
	static @NonNull String id(@NonNull String value) {
		try {
			byte[] bytes = Base64.getUrlDecoder().decode(value);
			if (bytes.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value))
				throw new IllegalArgumentException("Noncanonical private identity");
			return value;
		} catch (IllegalArgumentException failure) { throw new IllegalArgumentException("Invalid private identity", failure); }
	}
	static final class Admission {
		final String authority, recovery, clock, profile, schema, metadata, writer, allocation;
		final int format;
		Admission(@NonNull String authority, @NonNull String recovery, @NonNull String clock, @NonNull String profile,
				@NonNull String schema, @NonNull String metadata, @NonNull String writer, @NonNull String allocation, int format) {
			this.authority=id(authority); this.recovery=id(recovery); this.clock=id(clock); this.profile=id(profile);
			this.schema=id(schema); this.metadata=id(metadata); this.writer=id(writer); this.allocation=id(allocation);
			if (format!=2 && format!=3) throw new IllegalArgumentException("Invalid format");
			this.format=format;
		}
		boolean matches(@NonNull ResultSet row) throws SQLException {
			return this.authority.equals(row.getString("authority_id")) && this.recovery.equals(row.getString("recovery_generation"))
				&& this.clock.equals(row.getString("clock_generation")) && this.profile.equals(row.getString("profile_commitment"))
				&& this.schema.equals(row.getString("schema_commitment")) && this.metadata.equals(row.getString("metadata_commitment"))
				&& this.writer.equals(row.getString("writer_role_identity")) && this.allocation.equals(row.getString("allocation_generation"))
				&& this.format==row.getInt("format_version") && "ACTIVE".equals(row.getString("mode"));
		}
		@Override public @NonNull String toString() { return "Admission[redacted]"; }
	}
	static final class Point {
		final Admission admission;
		final Instant time;
		Point(@NonNull Admission admission, @NonNull Instant time) {
			if (time.isBefore(Instant.EPOCH) || time.isAfter(MAX_TIME)) throw new IllegalArgumentException("Invalid authority time");
			this.admission=admission; this.time=time;
		}
		@Override public @NonNull String toString() { return "Point[scripted/private authority]"; }
	}
	@FunctionalInterface interface Authority {
		@Nullable Point observe(@NonNull Duration remaining) throws Exception;
	}
	static final class Row {
		final String key, version;
		final byte[] payload;
		final @Nullable Instant expiry;
		final long reserved;
		Row(@NonNull String key, @NonNull String version, byte @NonNull [] payload, @Nullable Instant expiry, long reserved) {
			PgCapacity.bucket(key);
			if (payload.length<1 || payload.length>262144 || reserved<0) throw new IllegalArgumentException("Invalid row bounds");
			this.key=key; this.version=id(version); this.payload=payload.clone(); this.expiry=expiry; this.reserved=reserved;
		}
		@Override public @NonNull String toString() { return "Row[redacted carrier]"; }
	}
	static final class Read {
		final Map<String, @Nullable Row> rows;
		final @Nullable Point observation;
		Read(@NonNull Map<String, @Nullable Row> rows, @Nullable Point observation) {
			this.rows=Collections.unmodifiableMap(new LinkedHashMap<>(rows)); this.observation=observation;
		}
		@Override public @NonNull String toString() { return "Read[redacted coherent component]"; }
	}
	static final class Validated {
		final Point validation;
		Validated(@NonNull Point validation) { this.validation=validation; }
		@Override public @NonNull String toString() { return "Validated[validation only; no completion sample]"; }
	}
	static PgTransactions.@NonNull Outcome<Read> read(PgTransactions.@NonNull ConnectionSource source,
			@NonNull PgScope scope, @NonNull Admission admission, @NonNull Collection<String> keys,
			@NonNull Duration budget, @NonNull Authority authority) {
		Map<String, Boolean> locks=new TreeMap<>();
		for (String key:keys) { PgCapacity.bucket(key); if (locks.put(key,false)!=null) throw new IllegalArgumentException("Duplicate logical key"); }
		if (locks.isEmpty() || locks.size()>16) throw new IllegalArgumentException("Read key limit");
		return PgTransactions.execute(source,budget,context -> {
			Connection connection=context.connection();
			PgLocks.sharedAdmission(connection,scope,context.deadlineNanos());
			PgLocks.entities(connection,PgLocks.entitySet(scope,locks),context.deadlineNanos());
			if (!admitted(context,scope,admission)) return PgTransactions.Decision.refuse(PgTransactions.Refusal.FENCED);
			Map<String,@Nullable Row> rows=rows(context,scope,locks.keySet());
			Point point=authority.observe(context.remaining()); context.check();
			if (point!=null && !same(point.admission,admission)) return PgTransactions.Decision.refuse(PgTransactions.Refusal.FENCED);
			return PgTransactions.Decision.commit(new Read(rows,point));
		});
	}
	static PgTransactions.@NonNull Outcome<Validated> write(PgTransactions.@NonNull ConnectionSource source,
			@NonNull PgScope scope, @NonNull Admission admission, @NonNull Map<String,@Nullable String> expectedVersions,
			@NonNull Map<String,@Nullable Row> replacements, @NonNull Instant floor, @Nullable Instant expiry,
			@NonNull Duration budget, @NonNull Authority authority) {
		if (expectedVersions.isEmpty() || expectedVersions.size()>16 || replacements.size()>16 || !expectedVersions.keySet().containsAll(replacements.keySet()))
			throw new IllegalArgumentException("Incomplete bounded logical key set");
		if (floor.isBefore(Instant.EPOCH) || floor.isAfter(MAX_TIME) || (expiry!=null && (!expiry.isAfter(floor) || expiry.isAfter(MAX_TIME))))
			throw new IllegalArgumentException("Invalid temporal interval");
		Map<String,@Nullable String> predicates=Collections.unmodifiableMap(new TreeMap<>(expectedVersions));
		Map<String,@Nullable Row> copied=new TreeMap<>();
		replacements.forEach((key,row)->copied.put(key,row==null?null:new Row(row.key,row.version,row.payload,row.expiry,row.reserved)));
		Map<String,@Nullable Row> changes=Collections.unmodifiableMap(copied);
		Map<String,Boolean> locks=new TreeMap<>();
		predicates.forEach((key,version)-> { PgCapacity.bucket(key); if(version!=null) id(version); locks.put(key,changes.containsKey(key)); });
		for (Map.Entry<String,@Nullable Row> change:changes.entrySet()) {
			Row row=change.getValue();
			if (row!=null && (!row.key.equals(change.getKey()) || row.version.equals(predicates.get(change.getKey()))))
				throw new IllegalArgumentException("Replacement binding or fresh version invalid");
		}
		return PgTransactions.execute(source,budget,context -> {
			Connection connection=context.connection();
			PgLocks.sharedAdmission(connection,scope,context.deadlineNanos());
			PgLocks.entities(connection,PgLocks.entitySet(scope,locks),context.deadlineNanos());
			if (!admitted(context,scope,admission)) return PgTransactions.Decision.refuse(PgTransactions.Refusal.FENCED);
			Map<String,@Nullable Row> actual=rows(context,scope,predicates.keySet());
			for (Map.Entry<String,@Nullable String> predicate:predicates.entrySet()) {
				Row old=actual.get(predicate.getKey());
				if (!Objects.equals(predicate.getValue(),old==null?null:old.version)) return PgTransactions.Decision.refuse(PgTransactions.Refusal.CONFLICT);
			}
			List<PgCapacity.Delta> deltas=new ArrayList<>();
			for (Map.Entry<String,@Nullable Row> change:changes.entrySet()) {
				Row old=actual.get(change.getKey()), next=change.getValue();
				if (next!=null) validateRow(scope,next);
				deltas.add(PgCapacity.Delta.from(PgCapacity.bucket(change.getKey()),(next==null?0:1)-(old==null?0:1),
					(next==null?0:next.reserved)-(old==null?0:old.reserved)));
			}
			PgCapacity.LockedPlan capacity;
			capacity=PgCapacity.lockForValidation(connection,scope,admission.allocation,deltas,context.deadlineNanos());
			// This is the sole validation sample, after entity AND capacity waits.
			Point point=authority.observe(context.remaining()); context.check();
			if (point==null) return PgTransactions.Decision.refuse(PgTransactions.Refusal.TIME_UNAVAILABLE);
			if (!same(point.admission,admission)) return PgTransactions.Decision.refuse(PgTransactions.Refusal.FENCED);
			if (point.time.isBefore(floor)) return PgTransactions.Decision.refuse(PgTransactions.Refusal.TIME_BEFORE_FLOOR);
			if (expiry!=null && !point.time.isBefore(expiry)) return PgTransactions.Decision.refuse(PgTransactions.Refusal.TIME_EXPIRED);
			try { capacity.checkCapacity(); }
			catch (PgCapacity.CapacityRefused refused) { return PgTransactions.Decision.refuse(PgTransactions.Refusal.CAPACITY); }
			if (!changes.isEmpty()) {
				for (Map.Entry<String,@Nullable Row> change:changes.entrySet()) mutate(context,scope,actual.get(change.getKey()),change.getValue());
				capacity.apply(connection,context.deadlineNanos());
			}
			return PgTransactions.Decision.commit(new Validated(point));
		});
	}
	private static boolean admitted(PgTransactions.@NonNull Context context, @NonNull PgScope scope, @NonNull Admission admission) throws SQLException {
		try (PreparedStatement statement=context.connection().prepareStatement("SELECT * FROM scp05_admission WHERE family=? AND namespace=?")) {
			context.bound(statement); statement.setString(1,scope.getFamily()); statement.setString(2,scope.getNamespace());
			try (ResultSet result=statement.executeQuery()) { return result.next() && admission.matches(result) && !result.next(); }
		}
	}
	private static @NonNull Map<String,@Nullable Row> rows(PgTransactions.@NonNull Context context, @NonNull PgScope scope, @NonNull Collection<String> keys) throws SQLException {
		Map<String,@Nullable Row> rows=new LinkedHashMap<>();
		for (String key:keys) {
			try (PreparedStatement statement=context.connection().prepareStatement("SELECT version,payload,actual_size,reserved_bytes,expiry_seconds,expiry_nanos FROM scp05_entries WHERE family=? AND namespace=? AND storage_key=?")) {
				context.bound(statement); statement.setString(1,scope.getFamily()); statement.setString(2,scope.getNamespace()); statement.setString(3,key);
				try(ResultSet result=statement.executeQuery()) {
					Row row=null;
					if(result.next()) {
						long seconds=result.getLong("expiry_seconds"); boolean permanent=result.wasNull();
						int nanos=result.getInt("expiry_nanos");
						if (permanent!=result.wasNull() || nanos<0 || nanos>999999999) throw new SQLException("Invalid expiry projection");
						row=new Row(key,result.getString("version"),result.getBytes("payload"),permanent?null:Instant.ofEpochSecond(seconds,nanos),result.getLong("reserved_bytes"));
						if(row.payload.length!=result.getInt("actual_size")) throw new SQLException("Invalid actual carrier size");
						validateRow(scope,row);
					}
					rows.put(key,row);
				}
			}
		}
		return rows;
	}
	private static void validateRow(@NonNull PgScope scope,@NonNull Row row) throws SQLException {
		int maximum=scope.getFamily().equals("TOTP")?65536:scope.getFamily().equals("ISSUER")?16384:262144;
		if(row.payload.length>maximum) throw new SQLException("Carrier bound exceeded");
		long reservation=scope.getFamily().equals("TOTP")?PgCapacity.totpReservation(row.payload).getReservedBytes():0;
		if(row.reserved!=reservation) throw new SQLException("Carrier reservation mismatch");
	}
	private static void mutate(PgTransactions.@NonNull Context context,@NonNull PgScope scope,@Nullable Row old,@Nullable Row next) throws SQLException {
		if(old==null && next==null) return;
		String sql=next==null?"DELETE FROM scp05_entries WHERE family=? AND namespace=? AND storage_key=? AND version=?":
			old==null?"INSERT INTO scp05_entries(family,namespace,storage_key,version,payload,actual_size,reserved_bytes,expiry_seconds,expiry_nanos) VALUES(?,?,?,?,?,?,?,?,?)":
			"UPDATE scp05_entries SET version=?,payload=?,actual_size=?,reserved_bytes=?,expiry_seconds=?,expiry_nanos=? WHERE family=? AND namespace=? AND storage_key=? AND version=?";
		try(PreparedStatement statement=context.connection().prepareStatement(sql)) {
			context.bound(statement);
			context.markPossibleMutation();
			if(next==null) { statement.setString(1,scope.getFamily());statement.setString(2,scope.getNamespace());statement.setString(3,old.key);statement.setString(4,old.version); }
			else if(old==null) { statement.setString(1,scope.getFamily());statement.setString(2,scope.getNamespace());statement.setString(3,next.key);statement.setString(4,next.version);statement.setBytes(5,next.payload);statement.setInt(6,next.payload.length);statement.setLong(7,next.reserved);expiry(statement,8,next.expiry); }
			else { statement.setString(1,next.version);statement.setBytes(2,next.payload);statement.setInt(3,next.payload.length);statement.setLong(4,next.reserved);expiry(statement,5,next.expiry);statement.setString(7,scope.getFamily());statement.setString(8,scope.getNamespace());statement.setString(9,next.key);statement.setString(10,old.version); }
			if(statement.executeUpdate()!=1) throw new SQLException("Exact mutation affected-row count mismatch");
		}
	}
	private static void expiry(@NonNull PreparedStatement statement,int start,@Nullable Instant value) throws SQLException {
		if(value==null) {statement.setNull(start,java.sql.Types.BIGINT);statement.setNull(start+1,java.sql.Types.INTEGER);}
		else {statement.setLong(start,value.getEpochSecond());statement.setInt(start+1,value.getNano());}
	}
	private static boolean same(@NonNull Admission a,@NonNull Admission b) {
		return a.authority.equals(b.authority)&&a.recovery.equals(b.recovery)&&a.clock.equals(b.clock)&&a.profile.equals(b.profile)
			&&a.schema.equals(b.schema)&&a.metadata.equals(b.metadata)&&a.writer.equals(b.writer)&&a.allocation.equals(b.allocation)&&a.format==b.format;
	}
}
