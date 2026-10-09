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
import com.revetsec.oauth.server.OAuthClientMetadataCache;
import com.revetsec.oauth.server.OAuthClientMetadataCacheEntry;
import com.revetsec.oauth.server.OAuthClientMetadataCacheException;
import com.revetsec.oauth.server.OAuthClientMetadataCacheKey;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;

import static java.util.Objects.requireNonNull;

/**
 * Optional shared CIMD carrier storage. Revetsec still authenticates every envelope and controls
 * metadata freshness, client selection and per-operation fresh fetches. All writers for this
 * namespace must use the same PostgreSQL primary and schema. Eviction is oldest-write-first.
 * Pyranid owns every transaction and binds every SQL parameter.
 */
@ThreadSafe
public final class PostgresqlClientMetadataCache implements OAuthClientMetadataCache {
	private final @NonNull String namespace;
	private final @NonNull ConnectionSource source;
	private final int maximumEntries;

	/** The application bounds acquisition and returns a distinct connection to the primary. */
	@FunctionalInterface
	public interface ConnectionSource {
		@NonNull Connection open(@NonNull Duration remaining) throws SQLException;
	}

	/** Database row mapped by Pyranid. */
	public record CacheRow(@NonNull String version, long expiresSeconds, @NonNull String sealedForm) {
		@Override public @NonNull String toString() { return "CacheRow{<redacted>}"; }
	}

	public PostgresqlClientMetadataCache(@NonNull String namespace, @NonNull ConnectionSource source,
			int maximumEntries) {
		this.namespace = requireNonNull(namespace);
		this.source = requireNonNull(source);
		if (namespace.isEmpty() || namespace.length() > 128 || !namespace.matches("[A-Za-z0-9_-]+"))
			throw new IllegalArgumentException("The cache namespace is invalid.");
		if (maximumEntries < 1 || maximumEntries > 4096)
			throw new IllegalArgumentException("The cache capacity is invalid.");
		this.maximumEntries = maximumEntries;
	}

	@Override
	public @NonNull Optional<@NonNull OAuthClientMetadataCacheEntry> read(
			@NonNull OAuthClientMetadataCacheKey key, @NonNull Duration remainingBudget) {
		requireNonNull(key);
		return transaction(remainingBudget, (database, deadline) -> {
			ensureNamespace(database, deadline);
			PostgresqlPyranidDataSource.bound(database, deadline);
			return database.query("SELECT version,expires_seconds,sealed_form FROM cimd_cache_entry "
					+ "WHERE namespace=:namespace AND storage_key=:key")
					.bind("namespace", this.namespace).bind("key", key.getStorageKey())
					.fetchObject(CacheRow.class).map(row -> OAuthClientMetadataCacheEntry.fromStoredForm(
							key, row.version(), Instant.ofEpochSecond(row.expiresSeconds()), row.sealedForm()));
		});
	}

	private void ensureNamespace(@NonNull Database database, long deadline) throws SQLException {
		PostgresqlPyranidDataSource.bound(database, deadline);
		if (database.query("SELECT 1 FROM cimd_cache_namespace WHERE namespace=:namespace")
				.bind("namespace", this.namespace).fetchObject(Integer.class).isEmpty())
			throw new SQLException("Cache namespace has not been provisioned.");
	}

	@Override
	public @NonNull Boolean compareAndSet(@NonNull OAuthClientMetadataCacheKey key,
			@Nullable String expectedVersion, @Nullable OAuthClientMetadataCacheEntry replacement,
			@NonNull Duration remainingBudget) {
		requireNonNull(key);
		if (expectedVersion != null) canonicalVersion(expectedVersion);
		if (replacement != null && (!key.equals(replacement.getKey())
				|| replacement.getVersion().equals(expectedVersion)))
			throw new IllegalArgumentException("Invalid cache replacement.");
		return transaction(remainingBudget, (database, deadline) -> {
			PostgresqlPyranidDataSource.bound(database, deadline);
			long nextOrder = database.query("SELECT next_order FROM cimd_cache_namespace "
					+ "WHERE namespace=:namespace FOR UPDATE")
					.bind("namespace", this.namespace).fetchObject(Long.class)
					.orElseThrow(() -> new IllegalStateException("Cache namespace has not been provisioned."));
			PostgresqlPyranidDataSource.bound(database, deadline);
			String currentVersion = database.query("SELECT version FROM cimd_cache_entry "
					+ "WHERE namespace=:namespace AND storage_key=:key")
					.bind("namespace", this.namespace).bind("key", key.getStorageKey())
					.fetchObject(String.class).orElse(null);
			if (!Objects.equals(currentVersion, expectedVersion)) return false;
			if (replacement == null) {
				if (currentVersion != null) {
					PostgresqlPyranidDataSource.bound(database, deadline);
					if (database.query("DELETE FROM cimd_cache_entry WHERE namespace=:namespace AND storage_key=:key")
							.bind("namespace", this.namespace).bind("key", key.getStorageKey()).execute() != 1)
						throw new IllegalStateException("Cache delete lost its row.");
				}
				return true;
			}
			if (nextOrder == Long.MAX_VALUE) throw new IllegalStateException("Cache write-order capacity exhausted.");
			if (currentVersion == null && count(database, deadline) >= this.maximumEntries) evict(database, deadline);
			PostgresqlPyranidDataSource.bound(database, deadline);
			if (database.query("UPDATE cimd_cache_namespace SET next_order=:next WHERE namespace=:namespace")
					.bind("next", nextOrder + 1).bind("namespace", this.namespace).execute() != 1)
				throw new IllegalStateException("Cache namespace was lost.");
			PostgresqlPyranidDataSource.bound(database, deadline);
			long affected = currentVersion == null
					? database.query("INSERT INTO cimd_cache_entry(namespace,storage_key,version,expires_seconds,"
							+ "sealed_form,write_order) VALUES (:namespace,:key,:version,:expires,:sealed,:order)")
							.bind("namespace", this.namespace).bind("key", key.getStorageKey())
							.bind("version", replacement.getVersion())
							.bind("expires", replacement.getExpiresAt().getEpochSecond())
							.bind("sealed", replacement.toSealedForm()).bind("order", nextOrder + 1).execute()
					: database.query("UPDATE cimd_cache_entry SET version=:version,expires_seconds=:expires,"
							+ "sealed_form=:sealed,write_order=:order WHERE namespace=:namespace AND storage_key=:key")
							.bind("version", replacement.getVersion())
							.bind("expires", replacement.getExpiresAt().getEpochSecond())
							.bind("sealed", replacement.toSealedForm()).bind("order", nextOrder + 1)
							.bind("namespace", this.namespace).bind("key", key.getStorageKey()).execute();
			if (affected != 1) throw new IllegalStateException("Cache write lost its row.");
			return true;
		});
	}

	private long count(@NonNull Database database, long deadline) throws SQLException {
		PostgresqlPyranidDataSource.bound(database, deadline);
		return database.query("SELECT count(*) FROM cimd_cache_entry WHERE namespace=:namespace")
				.bind("namespace", this.namespace).fetchObject(Long.class).orElseThrow();
	}

	private void evict(@NonNull Database database, long deadline) throws SQLException {
		PostgresqlPyranidDataSource.bound(database, deadline);
		if (database.query("DELETE FROM cimd_cache_entry WHERE namespace=:namespace AND storage_key="
				+ "(SELECT storage_key FROM cimd_cache_entry WHERE namespace=:namespace "
				+ "ORDER BY write_order,storage_key LIMIT 1)")
				.bind("namespace", this.namespace).execute() != 1)
			throw new IllegalStateException("Cache eviction lost its row.");
	}

	private static void canonicalVersion(@NonNull String value) {
		if (value.length() != 43) throw new IllegalArgumentException("Invalid cache version.");
		try {
			byte[] bytes = Base64.getUrlDecoder().decode(value);
			if (bytes.length != 32 || !Base64.getUrlEncoder().withoutPadding().encodeToString(bytes).equals(value))
				throw new IllegalArgumentException("Invalid cache version.");
		} catch (IllegalArgumentException malformed) {
			throw new IllegalArgumentException("Invalid cache version.");
		}
	}

	private <@NonNull T> @NonNull T transaction(@NonNull Duration remainingBudget,
			@NonNull Operation<@NonNull T> operation) {
		long deadline = deadline(remainingBudget);
		Database database = Database.withDataSource(new PostgresqlPyranidDataSource(this.source::open, deadline))
				.databaseType(DatabaseType.POSTGRESQL).build();
		Completion completion = new Completion();
		Holder<T> candidate = new Holder<>();
		try {
			Optional<T> result = database.transaction(TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(), () -> {
				database.currentTransaction().orElseThrow().addPostTransactionOperation(value -> completion.result = value);
				T prepared = operation.apply(database, deadline);
				candidate.value = prepared;
				PostgresqlPyranidDataSource.bound(database, deadline);
				return Optional.of(prepared);
			});
			if (completion.result != TransactionResult.COMMITTED || expired(deadline)) throw problem(deadline);
			return result.orElseThrow(() -> problem(deadline));
		} catch (RuntimeException failure) {
			if (completion.result == TransactionResult.COMMITTED && candidate.value != null && !expired(deadline))
				return candidate.value;
			throw problem(deadline);
		}
	}

	private static long deadline(@NonNull Duration budget) {
		Duration checked = requireNonNull(budget);
		if (checked.isZero() || checked.isNegative())
			throw new IllegalArgumentException("A positive cache operation budget is required.");
		Duration capped = checked.compareTo(Duration.ofMinutes(1)) > 0 ? Duration.ofMinutes(1) : checked;
		return System.nanoTime() + capped.toNanos();
	}

	private static boolean expired(long deadline) {
		return deadline - System.nanoTime() <= 0 || Thread.currentThread().isInterrupted();
	}

	private static @NonNull OAuthClientMetadataCacheException problem(long deadline) {
		OAuthClientMetadataCacheException.Reason reason = Thread.currentThread().isInterrupted()
				? OAuthClientMetadataCacheException.Reason.INTERRUPTED
				: deadline - System.nanoTime() <= 0 ? OAuthClientMetadataCacheException.Reason.TIMEOUT
				: OAuthClientMetadataCacheException.Reason.UNAVAILABLE;
		return OAuthClientMetadataCacheException.fromReason(reason);
	}

	@FunctionalInterface
	private interface Operation<@NonNull T> {
		@NonNull T apply(@NonNull Database database, long deadline) throws SQLException;
	}
	private static final class Completion {
		private @Nullable TransactionResult result;
	}
	private static final class Holder<@NonNull T> {
		private @Nullable T value;
	}

	@Override public @NonNull String toString() { return "PostgresqlClientMetadataCache{storage=<redacted>}"; }
}
