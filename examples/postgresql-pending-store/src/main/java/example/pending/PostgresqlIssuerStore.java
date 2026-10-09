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
import com.pyranid.DatabaseType;
import com.pyranid.TransactionIsolation;
import com.pyranid.TransactionOptions;
import com.pyranid.TransactionResult;
import com.revetsec.oauth.server.OAuthAuthorizationServerStore;
import com.revetsec.oauth.server.OAuthStoreCommitStatus;
import com.revetsec.oauth.server.OAuthStoreEntry;
import com.revetsec.oauth.server.OAuthStoreKey;
import com.revetsec.oauth.server.OAuthStoreTransaction;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Application-owned issuer storage for one PostgreSQL primary. Every read and commit locks the
 * provisioned namespace row, so absence tests, complete read sets and writes serialize across
 * participating JVMs. Pyranid owns transaction completion and binds every SQL parameter.
 * Never restore a snapshot into live admission without an external recovery fence and key
 * procedure. The application owns connection pooling, credentials and migrations.
 */
@ThreadSafe
public final class PostgresqlIssuerStore implements OAuthAuthorizationServerStore {
	private final @NonNull String namespace;
	private final @NonNull ConnectionSource source;
	private final int maximumEntries;

	/** Open a fresh primary connection within the shrinking budget; never return a shared transaction. */
	@FunctionalInterface
	public interface ConnectionSource {
		@NonNull Connection open(@NonNull Duration remaining) throws SQLException;
	}

	/** Database row mapped by Pyranid. */
	public record IssuerRow(@NonNull String kind, @NonNull String version, long retainSeconds,
			int retainNanos, @NonNull String sealedForm) {
		@Override public @NonNull String toString() { return "IssuerRow{<redacted>}"; }
	}

	public PostgresqlIssuerStore(@NonNull String namespace, @NonNull ConnectionSource source,
			int maximumEntries) {
		this.namespace = requireNonNull(namespace);
		this.source = requireNonNull(source);
		if (namespace.isEmpty() || namespace.length() > 128 || !namespace.matches("[A-Za-z0-9_-]+"))
			throw new IllegalArgumentException("The issuer-store namespace is invalid.");
		if (maximumEntries < 1 || maximumEntries > 1_000_000)
			throw new IllegalArgumentException("The issuer-store capacity is invalid.");
		this.maximumEntries = maximumEntries;
	}

	@Override
	public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,
			@NonNull Duration remainingBudget) {
		requireNonNull(key);
		long deadline = deadline(remainingBudget);
		Database database = database(deadline);
		Completion completion = new Completion();
		Holder<Optional<OAuthStoreEntry>> candidate = new Holder<>();
		try {
			Optional<Optional<OAuthStoreEntry>> result = database.transaction(
					TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(), () -> {
				database.currentTransaction().orElseThrow().addPostTransactionOperation(value -> completion.result = value);
				configure(database, deadline);
				lock(database, deadline);
				Optional<OAuthStoreEntry> value = entry(database, key, deadline);
				candidate.value = value;
				PostgresqlPyranidDataSource.bound(database, deadline);
				return Optional.of(value);
			});
			if (completion.result != TransactionResult.COMMITTED || expired(deadline)) throw unavailable();
			return result.orElseThrow(PostgresqlIssuerStore::unavailable);
		} catch (RuntimeException failure) {
			if (completion.result == TransactionResult.COMMITTED && candidate.value != null && !expired(deadline))
				return candidate.value;
			throw unavailable();
		}
	}

	@Override
	public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction,
			@NonNull Duration remainingBudget) {
		requireNonNull(transaction);
		long deadline = deadline(remainingBudget);
		Database database = database(deadline);
		Completion completion = new Completion();
		Holder<OAuthStoreCommitStatus> candidate = new Holder<>();
		try {
			Optional<OAuthStoreCommitStatus> result = database.transaction(
					TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(), () -> {
				database.currentTransaction().orElseThrow().addPostTransactionOperation(value -> completion.result = value);
				configure(database, deadline);
				lock(database, deadline);
				for (OAuthStoreTransaction.Condition condition : transaction.getConditions()) {
					Optional<String> actual = entry(database, condition.getKey(), deadline)
							.map(OAuthStoreEntry::getVersion);
					if (!actual.equals(condition.getExpectedVersion())) {
						candidate.value = OAuthStoreCommitStatus.CONFLICT;
						PostgresqlPyranidDataSource.bound(database, deadline);
						return Optional.of(OAuthStoreCommitStatus.CONFLICT);
					}
				}
				long previousCount = count(database, deadline);
				long count = previousCount;
				for (OAuthStoreTransaction.Mutation mutation : transaction.getMutations()) {
					boolean exists = entry(database, mutation.getKey(), deadline).isPresent();
					if (mutation.getKind() == OAuthStoreTransaction.Mutation.Kind.PUT && !exists) count++;
					if (mutation.getKind() == OAuthStoreTransaction.Mutation.Kind.REMOVE && exists) count--;
				}
				if (count > this.maximumEntries && count > previousCount) throw unavailable();
				for (OAuthStoreTransaction.Mutation mutation : transaction.getMutations())
					write(database, mutation, deadline);
				candidate.value = OAuthStoreCommitStatus.COMMITTED;
				PostgresqlPyranidDataSource.bound(database, deadline);
				return Optional.of(OAuthStoreCommitStatus.COMMITTED);
			});
			if (completion.result == TransactionResult.COMMITTED && !expired(deadline))
				return result.orElseThrow(PostgresqlIssuerStore::unavailable);
			if (candidate.value != null && completion.result != TransactionResult.ROLLED_BACK)
				return OAuthStoreCommitStatus.UNKNOWN;
			throw unavailable();
		} catch (RuntimeException failure) {
			if (completion.result == TransactionResult.COMMITTED && candidate.value != null && !expired(deadline))
				return candidate.value;
			if (candidate.value != null && completion.result != TransactionResult.ROLLED_BACK)
				return OAuthStoreCommitStatus.UNKNOWN;
			throw unavailable();
		}
	}

	private @NonNull Database database(long deadline) {
		return Database.withDataSource(new PostgresqlPyranidDataSource(this.source::open, deadline))
				.databaseType(DatabaseType.POSTGRESQL).build();
	}

	private static void configure(@NonNull Database database, long deadline) throws SQLException {
		PostgresqlPyranidDataSource.bound(database, deadline);
		database.query("SELECT set_config('synchronous_commit', 'on', true)")
				.fetchObject(String.class).orElseThrow();
		PostgresqlPyranidDataSource.bound(database, deadline);
		Boolean safe = database.query("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' "
				+ "AND current_setting('full_page_writes')='on'")
				.fetchObject(Boolean.class).orElseThrow();
		if (!safe) throw new SQLException("Unsafe PostgreSQL primary.");
	}

	private void lock(@NonNull Database database, long deadline) throws SQLException {
		PostgresqlPyranidDataSource.bound(database, deadline);
		if (database.query("SELECT 1 FROM issuer_store_namespace WHERE namespace=:namespace FOR UPDATE")
				.bind("namespace", this.namespace).fetchObject(Integer.class).isEmpty())
			throw new SQLException("Missing issuer-store namespace.");
	}

	private @NonNull Optional<@NonNull OAuthStoreEntry> entry(@NonNull Database database,
			@NonNull OAuthStoreKey key, long deadline) throws SQLException {
		PostgresqlPyranidDataSource.bound(database, deadline);
		return database.query("SELECT kind,version,retain_seconds,retain_nanos,sealed_form "
				+ "FROM issuer_store_entry WHERE namespace=:namespace AND storage_key=:key")
				.bind("namespace", this.namespace).bind("key", key.getStorageKey())
				.fetchObject(IssuerRow.class).map(row -> {
					if (!key.getKind().name().equals(row.kind())) throw unavailable();
					return OAuthStoreEntry.fromStoredForm(key, row.version(),
							Instant.ofEpochSecond(row.retainSeconds(), row.retainNanos()), row.sealedForm());
				});
	}

	private long count(@NonNull Database database, long deadline) throws SQLException {
		PostgresqlPyranidDataSource.bound(database, deadline);
		return database.query("SELECT count(*) FROM issuer_store_entry WHERE namespace=:namespace")
				.bind("namespace", this.namespace).fetchObject(Long.class).orElseThrow();
	}

	private void write(@NonNull Database database, OAuthStoreTransaction.@NonNull Mutation mutation,
			long deadline) throws SQLException {
		PostgresqlPyranidDataSource.bound(database, deadline);
		if (mutation.getKind() == OAuthStoreTransaction.Mutation.Kind.REMOVE) {
			if (database.query("DELETE FROM issuer_store_entry WHERE namespace=:namespace AND storage_key=:key")
					.bind("namespace", this.namespace).bind("key", mutation.getKey().getStorageKey())
					.execute() != 1) throw new SQLException("Issuer remove lost its row.");
			return;
		}
		OAuthStoreEntry value = mutation.getEntry().orElseThrow();
		if (database.query("INSERT INTO issuer_store_entry"
				+ "(namespace,storage_key,kind,version,retain_seconds,retain_nanos,sealed_form)"
				+ " VALUES (:namespace,:key,:kind,:version,:seconds,:nanos,:sealed)"
				+ " ON CONFLICT(namespace,storage_key) DO UPDATE SET kind=EXCLUDED.kind,"
				+ "version=EXCLUDED.version,retain_seconds=EXCLUDED.retain_seconds,"
				+ "retain_nanos=EXCLUDED.retain_nanos,sealed_form=EXCLUDED.sealed_form")
				.bind("namespace", this.namespace).bind("key", value.getKey().getStorageKey())
				.bind("kind", value.getKey().getKind().name()).bind("version", value.getVersion())
				.bind("seconds", value.getRetainUntil().getEpochSecond())
				.bind("nanos", value.getRetainUntil().getNano())
				.bind("sealed", value.toSealedForm()).execute() != 1)
			throw new SQLException("Issuer write lost its row.");
	}

	private static long deadline(@NonNull Duration budget) {
		Duration checked = requireNonNull(budget);
		if (checked.isZero() || checked.isNegative()) throw unavailable();
		Duration capped = checked.compareTo(Duration.ofMinutes(1)) > 0 ? Duration.ofMinutes(1) : checked;
		return System.nanoTime() + capped.toNanos();
	}

	private static boolean expired(long deadline) {
		return deadline - System.nanoTime() <= 0 || Thread.currentThread().isInterrupted();
	}

	private static @NonNull IllegalStateException unavailable() {
		return new IllegalStateException("Issuer storage is unavailable.");
	}

	private static final class Completion {
		private @Nullable TransactionResult result;
	}
	private static final class Holder<@NonNull T> {
		private @Nullable T value;
	}

	@Override public @NonNull String toString() { return "PostgresqlIssuerStore{storage=<redacted>}"; }
}
