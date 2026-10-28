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
import com.revetsec.totp.TotpStore;
import com.revetsec.totp.TotpStoreCommitResult;
import com.revetsec.totp.TotpStoreEntry;
import com.revetsec.totp.TotpStoreKey;
import com.revetsec.totp.TotpStoreReadResult;
import com.revetsec.totp.TotpStoreRecord;
import com.revetsec.totp.TotpStoreSnapshot;
import com.revetsec.totp.TotpStoreWrite;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static java.util.Objects.requireNonNull;

/**
 * Unpublished application-owned PostgreSQL {@link TotpStore} fixture. Every participating node
 * locks one durable namespace row in the same transaction that checks its active recovery epoch,
 * activation state, exact record predicates and capacity. Both record kinds and epoch-history rows
 * are permanent. The independent recovery controller must close and drain admission before a
 * restore or {@link #provisionRecoveryEpoch(String, Duration)}; this store is not that controller.
 * All callbacks use the primary, with synchronous WAL commit and a bounded caller-thread budget.
 */
@ThreadSafe
public final class PostgresqlTotpStore implements TotpStore {
    private static final int MAXIMUM_ENTRIES = 65_536;
    private static final long MAXIMUM_BYTES = 268_435_456L;
    private static final int MAXIMUM_EPOCHS = 65_536;

    /** Opens a fresh primary connection within the positive remaining budget. */
    @FunctionalInterface
    @ThreadSafe
    public interface ConnectionSource {
        @NonNull Connection open(@NonNull Duration remaining) throws SQLException;
    }

    /** One Pyranid-mapped namespace row; the epoch is sensitive and never logged. */
    @Immutable
    public record NamespaceRow(@NonNull String activeEpoch, @NonNull String activationState) {
        @Override public @NonNull String toString() { return "NamespaceRow{<redacted>}"; }
    }

    /** One Pyranid-mapped opaque permanent record. */
    @Immutable
    public record StoredRow(@NonNull String kind, @NonNull String version,
            @NonNull String sealedForm, int sealedSize) {
        @Override public @NonNull String toString() { return "StoredRow{<redacted>}"; }
    }

    private final @NonNull String namespace;
    private final @NonNull ConnectionSource source;
    private final int maximumEntries;
    private final long maximumSealedBytes;
    private final @NonNull AtomicInteger failAcknowledgementOnCommit = new AtomicInteger();

    /**
     * Creates a fixture for one pre-provisioned namespace. The migration must seed its first
     * never-reused epoch as NEW, and the application must initialize it explicitly through core.
     */
    public PostgresqlTotpStore(@NonNull String namespace, @NonNull ConnectionSource source,
            int maximumEntries, long maximumSealedBytes) {
        TotpStoreKey.forNamespace(requireNonNull(namespace), "fixture-validation");
        this.namespace = namespace;
        this.source = requireNonNull(source);
        if (maximumEntries < 1 || maximumEntries > MAXIMUM_ENTRIES)
            throw new IllegalArgumentException("Invalid TOTP record capacity");
        if (maximumSealedBytes < 1 || maximumSealedBytes > MAXIMUM_BYTES)
            throw new IllegalArgumentException("Invalid TOTP sealed-byte capacity");
        this.maximumEntries = maximumEntries;
        this.maximumSealedBytes = maximumSealedBytes;
    }

    /**
     * Test-only one-shot simulation of a lost response after the next successful mutating COMMIT.
     * It changes only the reported acknowledgement, never the database outcome.
     */
    public void failNextCommitAcknowledgement() { failNthCommitAcknowledgement(1); }

    /**
     * Test-only lost acknowledgement after the Nth successful mutating COMMIT. This counts both
     * ordinary writes and recovery provisioning, and is intended for a deterministic serial probe.
     */
    public void failNthCommitAcknowledgement(int successfulMutatingCommit) {
        if (successfulMutatingCommit < 1)
            throw new IllegalArgumentException("Commit ordinal must be positive");
        this.failAcknowledgementOnCommit.set(successfulMutatingCommit);
    }

    @Override public @NonNull TotpStoreReadResult read(
            @NonNull Set<@NonNull TotpStoreKey> keys, @NonNull Duration remainingBudget) {
        validateKeys(keys);
        String epoch = keys.iterator().next().getRecoveryEpoch();
        long deadline;
        try { deadline = deadline(remainingBudget); }
        catch (IllegalStateException failure) { return TotpStoreReadResult.Unavailable.get(); }
        Completion completion = new Completion();
        try {
            Database database = database(deadline);
            Optional<TotpStoreReadResult> result = database.transaction(options(), () -> {
                database.currentTransaction().orElseThrow()
                        .addPostTransactionOperation(value -> completion.result = value);
                configure(database, deadline);
                NamespaceRow namespaceRow = lockNamespace(database, deadline);
                if (!namespaceRow.activeEpoch().equals(epoch))
                    return Optional.of(TotpStoreReadResult.Fenced.get());
                TotpStoreKey root = TotpStoreKey.forNamespace(this.namespace, epoch);
                Optional<StoredRow> rootRow = entry(database, root, deadline);
                if (namespaceRow.activationState().equals("NEW")) {
                    if (rootRow.isPresent() || epochEntryCount(database, epoch, deadline) != 0
                            || keys.size() != 1 || !keys.contains(root))
                        return Optional.of(TotpStoreReadResult.Unavailable.get());
                } else if (!namespaceRow.activationState().equals("ACTIVATED") || rootRow.isEmpty()) {
                    return Optional.of(TotpStoreReadResult.Unavailable.get());
                }
                Map<TotpStoreKey, TotpStoreEntry> observations = new HashMap<>();
                for (TotpStoreKey key : keys) {
                    Optional<StoredRow> row = key.equals(root) ? rootRow : entry(database, key, deadline);
                    observations.put(key, row.<TotpStoreEntry>map(found ->
                            TotpStoreEntry.Present.fromRecord(record(key, found)))
                            .orElseGet(TotpStoreEntry.Absent::confirmed));
                }
                PostgresqlPyranidDataSource.bound(database, deadline);
                return Optional.of(TotpStoreReadResult.Available.fromSnapshot(
                        TotpStoreSnapshot.fromEntries(keys, observations)));
            });
            if (completion.result == TransactionResult.COMMITTED && !expired(deadline))
                return result.orElseThrow();
        } catch (RuntimeException failure) {
            // A read is authoritative only after its complete transaction finishes in budget.
        }
        return TotpStoreReadResult.Unavailable.get();
    }

    @Override public @NonNull TotpStoreCommitResult compareAndCommit(
            @NonNull TotpStoreWrite write, @NonNull Duration remainingBudget) {
        requireNonNull(write);
        if (!this.namespace.equals(write.getCredentialNamespace()))
            throw new IllegalArgumentException("TOTP write belongs to another namespace");
        long deadline;
        try { deadline = deadline(remainingBudget); }
        catch (IllegalStateException failure) { return TotpStoreCommitResult.UNAVAILABLE; }
        Completion completion = new Completion();
        Attempt attempt = new Attempt();
        try {
            Database database = database(deadline);
            Optional<TotpStoreCommitResult> result = database.transaction(options(), () -> {
                database.currentTransaction().orElseThrow()
                        .addPostTransactionOperation(value -> completion.result = value);
                configure(database, deadline);
                NamespaceRow namespaceRow = lockNamespace(database, deadline);
                if (!namespaceRow.activeEpoch().equals(write.getRecoveryEpoch()))
                    return Optional.of(TotpStoreCommitResult.FENCED);
                TotpStoreKey root = TotpStoreKey.forNamespace(this.namespace, write.getRecoveryEpoch());
                Optional<StoredRow> rootRow = entry(database, root, deadline);
                if (write.getPurpose() == TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE) {
                    if (namespaceRow.activationState().equals("ACTIVATED"))
                        return Optional.of(rootRow.isPresent()
                                ? TotpStoreCommitResult.CONFLICT : TotpStoreCommitResult.UNAVAILABLE);
                    if (!namespaceRow.activationState().equals("NEW") || rootRow.isPresent()
                            || epochEntryCount(database, write.getRecoveryEpoch(), deadline) != 0)
                        return Optional.of(TotpStoreCommitResult.UNAVAILABLE);
                } else if (!namespaceRow.activationState().equals("ACTIVATED") || rootRow.isEmpty()) {
                    return Optional.of(TotpStoreCommitResult.UNAVAILABLE);
                }
                Map<TotpStoreKey, StoredRow> currentRows = new HashMap<>();
                for (Map.Entry<TotpStoreKey, TotpStoreEntry> predicate
                        : write.getSnapshot().getEntries().entrySet()) {
                    TotpStoreKey key = predicate.getKey();
                    Optional<StoredRow> actual = key.equals(root) ? rootRow : entry(database, key, deadline);
                    actual.ifPresent(row -> currentRows.put(key, row));
                    TotpStoreEntry expected = predicate.getValue();
                    if (expected instanceof TotpStoreEntry.Absent && actual.isPresent()
                            || expected instanceof TotpStoreEntry.Present present
                            && (actual.isEmpty() || !present.getRecord().getVersion()
                                    .equals(actual.orElseThrow().version())))
                        return Optional.of(TotpStoreCommitResult.CONFLICT);
                }
                long nextEntries = count(database, deadline);
                long nextBytes = sealedByteCount(database, deadline);
                for (TotpStoreWrite.Mutation mutation : write.getMutations()) {
                    TotpStoreRecord changed = mutation.getRecord();
                    nextBytes += changed.getSealedBytes().length;
                    if (mutation.getKind() == TotpStoreWrite.Mutation.Kind.INSERT) {
                        nextEntries++;
                    } else {
                        nextBytes -= currentRows.get(mutation.getKey()).sealedSize();
                    }
                }
                if (nextEntries > this.maximumEntries || nextBytes > this.maximumSealedBytes)
                    return Optional.of(TotpStoreCommitResult.CAPACITY_REFUSED);
                for (TotpStoreWrite.Mutation mutation : write.getMutations()) {
                    PostgresqlPyranidDataSource.bound(database, deadline);
                    attempt.write = true;
                    apply(database, mutation);
                }
                if (write.getPurpose() == TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE) {
                    attempt.write = true;
                    PostgresqlPyranidDataSource.bound(database, deadline);
                    long changed = database.query("UPDATE totp_store_namespace SET activation_state='ACTIVATED' "
                            + "WHERE namespace=:namespace AND active_epoch=:epoch AND activation_state='NEW'")
                            .bind("namespace", this.namespace).bind("epoch", write.getRecoveryEpoch())
                            .execute();
                    if (changed != 1) throw new SQLException("TOTP namespace activation lost its row");
                }
                PostgresqlPyranidDataSource.bound(database, deadline);
                return Optional.of(TotpStoreCommitResult.COMMITTED);
            });
            if (completion.result == TransactionResult.COMMITTED && !expired(deadline)) {
                TotpStoreCommitResult committed = result.orElseThrow();
                if (committed == TotpStoreCommitResult.COMMITTED && attempt.write && loseAcknowledgement())
                    return TotpStoreCommitResult.UNKNOWN;
                return committed;
            }
        } catch (RuntimeException failure) {
            // A write crossing the mutation boundary may have committed despite an exception.
        }
        return attempt.write ? TotpStoreCommitResult.UNKNOWN : TotpStoreCommitResult.UNAVAILABLE;
    }

    /**
     * Recovery-controller operation. Call only after admission is durably closed and every old
     * operation has drained. Inserts a never-reused epoch marker and fences old writers atomically;
     * the new root remains absent until explicit core namespace initialization. A rolled-back
     * database backup cannot establish epoch freshness: the controller's monotonic marker must
     * live outside the restored database and reject restoration under its previous epoch.
     */
    public @NonNull TotpStoreCommitResult provisionRecoveryEpoch(@NonNull String recoveryEpoch,
            @NonNull Duration remainingBudget) {
        TotpStoreKey.forNamespace(this.namespace, requireNonNull(recoveryEpoch));
        long deadline;
        try { deadline = deadline(remainingBudget); }
        catch (IllegalStateException failure) { return TotpStoreCommitResult.UNAVAILABLE; }
        Completion completion = new Completion();
        Attempt attempt = new Attempt();
        try {
            Database database = database(deadline);
            Optional<TotpStoreCommitResult> result = database.transaction(options(), () -> {
                database.currentTransaction().orElseThrow()
                        .addPostTransactionOperation(value -> completion.result = value);
                configure(database, deadline);
                NamespaceRow current = lockNamespace(database, deadline);
                PostgresqlPyranidDataSource.bound(database, deadline);
                boolean reused = database.query("SELECT 1 FROM totp_store_epoch "
                        + "WHERE namespace=:namespace AND recovery_epoch=:epoch")
                        .bind("namespace", this.namespace).bind("epoch", recoveryEpoch)
                        .fetchObject(Integer.class).isPresent();
                if (reused || current.activeEpoch().equals(recoveryEpoch))
                    return Optional.of(TotpStoreCommitResult.CONFLICT);
                PostgresqlPyranidDataSource.bound(database, deadline);
                long epochs = database.query("SELECT count(*) FROM totp_store_epoch WHERE namespace=:namespace")
                        .bind("namespace", this.namespace).fetchObject(Long.class).orElseThrow();
                if (epochs >= MAXIMUM_EPOCHS)
                    return Optional.of(TotpStoreCommitResult.CAPACITY_REFUSED);
                PostgresqlPyranidDataSource.bound(database, deadline);
                attempt.write = true;
                long inserted = database.query("INSERT INTO totp_store_epoch(namespace,recovery_epoch) "
                        + "VALUES (:namespace,:epoch)")
                        .bind("namespace", this.namespace).bind("epoch", recoveryEpoch).execute();
                if (inserted != 1) throw new SQLException("TOTP epoch marker was not inserted");
                PostgresqlPyranidDataSource.bound(database, deadline);
                long switched = database.query("UPDATE totp_store_namespace "
                        + "SET active_epoch=:epoch,activation_state='NEW' WHERE namespace=:namespace")
                        .bind("namespace", this.namespace).bind("epoch", recoveryEpoch).execute();
                if (switched != 1) throw new SQLException("TOTP epoch fence lost its row");
                PostgresqlPyranidDataSource.bound(database, deadline);
                return Optional.of(TotpStoreCommitResult.COMMITTED);
            });
            if (completion.result == TransactionResult.COMMITTED && !expired(deadline)) {
                TotpStoreCommitResult committed = result.orElseThrow();
                if (committed == TotpStoreCommitResult.COMMITTED && attempt.write && loseAcknowledgement())
                    return TotpStoreCommitResult.UNKNOWN;
                return committed;
            }
        } catch (RuntimeException failure) {
            // Reconcile a possible epoch transition before retrying with any fresh epoch.
        }
        return attempt.write ? TotpStoreCommitResult.UNKNOWN : TotpStoreCommitResult.UNAVAILABLE;
    }

    private @NonNull Database database(long deadline) {
        return Database.withDataSource(new PostgresqlPyranidDataSource(this.source::open, deadline))
                .databaseType(DatabaseType.POSTGRESQL).build();
    }

    private static @NonNull TransactionOptions options() {
        return TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build();
    }

    private static void configure(@NonNull Database database, long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        database.query("SELECT set_config('synchronous_commit', 'on', true)")
                .fetchObject(String.class).orElseThrow();
        PostgresqlPyranidDataSource.bound(database, deadline);
        Boolean safe = database.query("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' "
                + "AND current_setting('full_page_writes')='on'")
                .fetchObject(Boolean.class).orElseThrow();
        if (!Boolean.TRUE.equals(safe)) throw new SQLException("Unsafe PostgreSQL primary");
    }

    private @NonNull NamespaceRow lockNamespace(@NonNull Database database, long deadline)
            throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        NamespaceRow row = database.query("SELECT active_epoch,activation_state "
                + "FROM totp_store_namespace WHERE namespace=:namespace FOR UPDATE")
                .bind("namespace", this.namespace).fetchObject(NamespaceRow.class)
                .orElseThrow(() -> new SQLException("Missing TOTP namespace"));
        if (!row.activationState().equals("NEW") && !row.activationState().equals("ACTIVATED"))
            throw new SQLException("Invalid TOTP activation state");
        TotpStoreKey.forNamespace(this.namespace, row.activeEpoch());
        return row;
    }

    private @NonNull Optional<@NonNull StoredRow> entry(@NonNull Database database,
            @NonNull TotpStoreKey key, long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        Optional<StoredRow> found = database.query("SELECT kind,version,sealed_form,sealed_size "
                + "FROM totp_store_entry WHERE namespace=:namespace AND recovery_epoch=:epoch "
                + "AND storage_key=:key")
                .bind("namespace", this.namespace).bind("epoch", key.getRecoveryEpoch())
                .bind("key", key.getStorageKey()).fetchObject(StoredRow.class);
        if (found.isPresent()) record(key, found.orElseThrow());
        return found;
    }

    private static @NonNull TotpStoreRecord record(@NonNull TotpStoreKey key,
            @NonNull StoredRow row) {
        if (!row.kind().equals(key.getKind().name()))
            throw new IllegalArgumentException("Invalid TOTP stored kind");
        byte[] sealed = sealedBytes(row.sealedForm());
        if (row.sealedSize() != sealed.length)
            throw new IllegalArgumentException("Invalid TOTP stored size");
        return TotpStoreRecord.fromStoredForm(key, row.version(), sealed);
    }

    private long count(@NonNull Database database, long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        return database.query("SELECT count(*) FROM totp_store_entry WHERE namespace=:namespace")
                .bind("namespace", this.namespace).fetchObject(Long.class).orElseThrow();
    }

    private long epochEntryCount(@NonNull Database database, @NonNull String epoch,
            long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        return database.query("SELECT count(*) FROM totp_store_entry "
                + "WHERE namespace=:namespace AND recovery_epoch=:epoch")
                .bind("namespace", this.namespace).bind("epoch", epoch)
                .fetchObject(Long.class).orElseThrow();
    }

    private long sealedByteCount(@NonNull Database database, long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        return database.query("SELECT coalesce(sum(sealed_size),0) "
                + "FROM totp_store_entry WHERE namespace=:namespace")
                .bind("namespace", this.namespace).fetchObject(Long.class).orElseThrow();
    }

    private void apply(@NonNull Database database, TotpStoreWrite.@NonNull Mutation mutation)
            throws SQLException {
        TotpStoreRecord record = mutation.getRecord();
        TotpStoreKey key = mutation.getKey();
        byte[] sealed = record.getSealedBytes();
        long changed;
        if (mutation.getKind() == TotpStoreWrite.Mutation.Kind.INSERT) {
            changed = database.query("INSERT INTO totp_store_entry"
                    + "(namespace,recovery_epoch,storage_key,kind,version,sealed_form,sealed_size) "
                    + "VALUES (:namespace,:epoch,:key,:kind,:version,:sealed,:size)")
                    .bind("namespace", this.namespace).bind("epoch", key.getRecoveryEpoch())
                    .bind("key", key.getStorageKey()).bind("kind", key.getKind().name())
                    .bind("version", record.getVersion()).bind("sealed", sealedForm(sealed))
                    .bind("size", sealed.length).execute();
        } else {
            changed = database.query("UPDATE totp_store_entry SET "
                    + "version=:version,sealed_form=:sealed,sealed_size=:size "
                    + "WHERE namespace=:namespace AND recovery_epoch=:epoch AND storage_key=:key")
                    .bind("version", record.getVersion()).bind("sealed", sealedForm(sealed))
                    .bind("size", sealed.length).bind("namespace", this.namespace)
                    .bind("epoch", key.getRecoveryEpoch()).bind("key", key.getStorageKey()).execute();
        }
        if (changed != 1) throw new SQLException("TOTP mutation lost its row");
    }

    private void validateKeys(@NonNull Set<@NonNull TotpStoreKey> keys) {
        requireNonNull(keys);
        if (keys.isEmpty() || keys.size() > 16)
            throw new IllegalArgumentException("Invalid TOTP read set");
        TotpStoreKey first = keys.iterator().next();
        if (!this.namespace.equals(first.getCredentialNamespace()))
            throw new IllegalArgumentException("TOTP read belongs to another namespace");
        for (TotpStoreKey key : keys)
            if (!this.namespace.equals(key.getCredentialNamespace())
                    || !first.getRecoveryEpoch().equals(key.getRecoveryEpoch()))
                throw new IllegalArgumentException("Mixed TOTP read scope");
    }

    private boolean loseAcknowledgement() {
        return this.failAcknowledgementOnCommit.getAndUpdate(value -> value > 0 ? value - 1 : 0) == 1;
    }

    private static @NonNull String sealedForm(byte @NonNull [] sealed) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sealed);
    }

    private static byte @NonNull [] sealedBytes(@NonNull String form) {
        if (form.isEmpty() || form.length() > 87_382)
            throw new IllegalArgumentException("Invalid TOTP sealed form");
        byte[] decoded = Base64.getUrlDecoder().decode(form);
        if (decoded.length == 0 || decoded.length > 65_536 || !sealedForm(decoded).equals(form))
            throw new IllegalArgumentException("Invalid TOTP sealed form");
        return decoded;
    }

    private static long deadline(@NonNull Duration budget) {
        requireNonNull(budget);
        if (budget.isZero() || budget.isNegative() || Thread.currentThread().isInterrupted())
            throw new IllegalStateException("TOTP store budget expired");
        Duration capped = budget.compareTo(Duration.ofSeconds(30)) > 0 ? Duration.ofSeconds(30) : budget;
        return System.nanoTime() + capped.toNanos();
    }

    private static boolean expired(long deadline) {
        return deadline - System.nanoTime() <= 0 || Thread.currentThread().isInterrupted();
    }

    @NotThreadSafe
    private static final class Completion { private @Nullable TransactionResult result; }
    @NotThreadSafe
    private static final class Attempt { private boolean write; }

    @Override public @NonNull String toString() { return "PostgresqlTotpStore{storage=<redacted>}"; }
}
