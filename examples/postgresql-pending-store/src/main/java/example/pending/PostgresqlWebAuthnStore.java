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
import com.revetsec.webauthn.WebAuthnStore;
import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.ThreadSafe;
import java.nio.ByteBuffer;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * Application-owned WebAuthn store for one durable PostgreSQL primary. A provisioned namespace
 * mutex serializes every read and conditional commit across participating JVMs. Pyranid manages
 * transactions; the database sequence supplies non-reused live versions. No row is evicted for
 * capacity. The application must separately close admission and fence authentic restore, key
 * rotation and old writers; this example is not a distributed recovery gate.
 */
@ThreadSafe
public final class PostgresqlWebAuthnStore implements WebAuthnStore {
    /** Opens a fresh primary connection within the positive remaining budget. */
    @FunctionalInterface
    public interface ConnectionSource {
        @NonNull Connection open(@NonNull Duration remaining) throws SQLException;
    }

    /** One database row mapped by Pyranid. */
    public record StoredRow(@NonNull String kind, long version, @NonNull String sealedForm) {
        @Override public @NonNull String toString() { return "StoredRow{<redacted>}"; }
    }

    private final @NonNull String namespace;
    private final @NonNull String keyPrefix;
    private final @NonNull ConnectionSource source;
    private final int maximumEntries;

    public PostgresqlWebAuthnStore(@NonNull String namespace, @NonNull ConnectionSource source,
            int maximumEntries) {
        this.namespace = requireNonNull(namespace);
        this.source = requireNonNull(source);
        if (namespace.isEmpty() || namespace.length() > 128 || !namespace.matches("[A-Za-z0-9_-]+"))
            throw new IllegalArgumentException("Invalid WebAuthn storage namespace");
        if (maximumEntries < 1 || maximumEntries > 1_000_000)
            throw new IllegalArgumentException("Invalid WebAuthn storage capacity");
        this.keyPrefix = "wa1:" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(namespace.getBytes(java.nio.charset.StandardCharsets.US_ASCII)) + ':';
        this.maximumEntries = maximumEntries;
    }

    @Override public @NonNull WebAuthnStoreReadResult read(
            @NonNull Set<@NonNull WebAuthnStoreKey> keys, @NonNull Duration remainingBudget) {
        requireNonNull(keys);
        if (keys.isEmpty() || keys.size() > 16) throw new IllegalArgumentException("Invalid WebAuthn read set");
        keys.forEach(this::requireOwnedKey);
        long deadline;
        try { deadline = deadline(remainingBudget); }
        catch (IllegalStateException failure) { return WebAuthnStoreReadResult.Unavailable.get(); }
        Completion completion = new Completion();
        try {
            Database database = database(deadline);
            Optional<WebAuthnStoreSnapshot> result = database.transaction(options(), () -> {
                database.currentTransaction().orElseThrow()
                        .addPostTransactionOperation(value -> completion.result = value);
                configure(database, deadline);
                lock(database, deadline);
                Map<WebAuthnStoreKey, WebAuthnStoreEntry> entries = new HashMap<>();
                for (WebAuthnStoreKey key : keys) entries.put(key, entry(database, key, deadline)
                        .<WebAuthnStoreEntry>map(row -> WebAuthnStoreEntry.Present.fromVersionAndSealedBytes(
                                versionBytes(row.version()), sealedBytes(row.sealedForm())))
                        .orElseGet(WebAuthnStoreEntry.Absent::confirmed));
                PostgresqlPyranidDataSource.bound(database, deadline);
                return Optional.of(WebAuthnStoreSnapshot.fromEntries(keys, entries));
            });
            if (completion.result == TransactionResult.COMMITTED && !expired(deadline))
                return WebAuthnStoreReadResult.Available.fromSnapshot(result.orElseThrow());
        } catch (RuntimeException failure) {
            // No snapshot is released unless its read-only transaction finished in budget.
        }
        return WebAuthnStoreReadResult.Unavailable.get();
    }

    @Override public @NonNull WebAuthnStoreCommitResult compareAndCommit(
            @NonNull WebAuthnStoreWrite write, @NonNull Duration remainingBudget) {
        requireNonNull(write);
        write.getSnapshot().getEntries().keySet().forEach(this::requireOwnedKey);
        long deadline;
        try { deadline = deadline(remainingBudget); }
        catch (IllegalStateException failure) { return WebAuthnStoreCommitResult.UNAVAILABLE; }
        Completion completion = new Completion();
        Attempt attempted = new Attempt();
        try {
            Database database = database(deadline);
            Optional<WebAuthnStoreCommitResult> result = database.transaction(options(), () -> {
                database.currentTransaction().orElseThrow()
                        .addPostTransactionOperation(value -> completion.result = value);
                configure(database, deadline);
                lock(database, deadline);
                for (var observed : write.getSnapshot().getEntries().entrySet()) {
                    Optional<StoredRow> actual = entry(database, observed.getKey(), deadline);
                    WebAuthnStoreEntry expected = observed.getValue();
                    if (expected instanceof WebAuthnStoreEntry.Absent && actual.isPresent()
                            || expected instanceof WebAuthnStoreEntry.Present present
                            && (actual.isEmpty() || !Arrays.equals(present.getVersion(),
                                    versionBytes(actual.orElseThrow().version())))) {
                        PostgresqlPyranidDataSource.bound(database, deadline);
                        return Optional.of(WebAuthnStoreCommitResult.CONFLICT);
                    }
                }
                long previous = count(database, deadline);
                long next = previous;
                for (WebAuthnStoreWrite.Mutation mutation : write.getMutations()) {
                    if (mutation.getKind() == WebAuthnStoreWrite.Mutation.Kind.INSERT) next++;
                    if (mutation.getKind() == WebAuthnStoreWrite.Mutation.Kind.DELETE) next--;
                }
                if (next > this.maximumEntries && next > previous) {
                    PostgresqlPyranidDataSource.bound(database, deadline);
                    return Optional.of(WebAuthnStoreCommitResult.CAPACITY);
                }
                for (WebAuthnStoreWrite.Mutation mutation : write.getMutations()) {
                    attempted.write = true;
                    apply(database, mutation, deadline);
                }
                PostgresqlPyranidDataSource.bound(database, deadline);
                return Optional.of(WebAuthnStoreCommitResult.COMMITTED);
            });
            if (completion.result == TransactionResult.COMMITTED && !expired(deadline))
                return result.orElseThrow();
        } catch (RuntimeException failure) {
            // A failed commit path may have crossed the write boundary.
        }
        return attempted.write ? WebAuthnStoreCommitResult.UNKNOWN : WebAuthnStoreCommitResult.UNAVAILABLE;
    }

    private @NonNull Database database(long deadline) {
        return Database.withDataSource(new PostgresqlPyranidDataSource(this.source::open, deadline))
                .databaseType(DatabaseType.POSTGRESQL).build();
    }

    private static @NonNull TransactionOptions options() {
        return TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build();
    }

    private void requireOwnedKey(@NonNull WebAuthnStoreKey key) {
        if (!requireNonNull(key).getStorageKey().startsWith(this.keyPrefix))
            throw new IllegalArgumentException("WebAuthn key belongs to another storage namespace");
    }

    private static void configure(@NonNull Database database, long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        database.query("SELECT set_config('synchronous_commit', 'on', true)")
                .fetchObject(String.class).orElseThrow();
        PostgresqlPyranidDataSource.bound(database, deadline);
        Boolean safe = database.query("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' "
                + "AND current_setting('full_page_writes')='on'")
                .fetchObject(Boolean.class).orElseThrow();
        if (!safe) throw new SQLException("Unsafe PostgreSQL primary");
    }

    private void lock(@NonNull Database database, long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        if (database.query("SELECT 1 FROM webauthn_store_namespace WHERE namespace=:namespace FOR UPDATE")
                .bind("namespace", this.namespace).fetchObject(Integer.class).isEmpty())
            throw new SQLException("Missing WebAuthn namespace");
    }

    private @NonNull Optional<@NonNull StoredRow> entry(@NonNull Database database,
            @NonNull WebAuthnStoreKey key, long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        Optional<StoredRow> found = database.query("SELECT kind,version,sealed_form FROM webauthn_store_entry "
                + "WHERE namespace=:namespace AND storage_key=:key")
                .bind("namespace", this.namespace).bind("key", key.getStorageKey())
                .fetchObject(StoredRow.class);
        if (found.isPresent()) {
            StoredRow row = found.orElseThrow();
            if (!row.kind().equals(key.getKind().name()) || row.version() <= 0)
                throw new SQLException("Invalid WebAuthn stored row");
            sealedBytes(row.sealedForm());
        }
        return found;
    }

    private long count(@NonNull Database database, long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        return database.query("SELECT count(*) FROM webauthn_store_entry WHERE namespace=:namespace")
                .bind("namespace", this.namespace).fetchObject(Long.class).orElseThrow();
    }

    private void apply(@NonNull Database database, WebAuthnStoreWrite.@NonNull Mutation mutation,
            long deadline) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        String key = mutation.getKey().getStorageKey();
        long changed;
        if (mutation.getKind() == WebAuthnStoreWrite.Mutation.Kind.DELETE) {
            changed = database.query("DELETE FROM webauthn_store_entry WHERE namespace=:namespace AND storage_key=:key")
                    .bind("namespace", this.namespace).bind("key", key).execute();
        } else if (mutation.getKind() == WebAuthnStoreWrite.Mutation.Kind.INSERT) {
            changed = database.query("INSERT INTO webauthn_store_entry"
                    + "(namespace,storage_key,kind,version,sealed_form) VALUES"
                    + "(:namespace,:key,:kind,nextval('webauthn_store_version_seq'),:sealed)")
                    .bind("namespace", this.namespace).bind("key", key)
                    .bind("kind", mutation.getKey().getKind().name())
                    .bind("sealed", sealedForm(mutation.getSealedBytes().orElseThrow())).execute();
        } else {
            changed = database.query("UPDATE webauthn_store_entry SET "
                    + "version=nextval('webauthn_store_version_seq'),sealed_form=:sealed "
                    + "WHERE namespace=:namespace AND storage_key=:key")
                    .bind("namespace", this.namespace).bind("key", key)
                    .bind("sealed", sealedForm(mutation.getSealedBytes().orElseThrow())).execute();
        }
        if (changed != 1) throw new SQLException("WebAuthn mutation lost its row");
    }

    private static byte @NonNull [] versionBytes(long version) {
        if (version <= 0) throw new IllegalArgumentException("Invalid WebAuthn version");
        return ByteBuffer.allocate(Long.BYTES).putLong(version).array();
    }

    private static @NonNull String sealedForm(byte @NonNull [] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte @NonNull [] sealedBytes(@NonNull String form) {
        if (form.isEmpty() || form.length() > 350_000)
            throw new IllegalArgumentException("Invalid WebAuthn sealed form");
        byte[] decoded = Base64.getUrlDecoder().decode(form);
        if (decoded.length == 0 || decoded.length > 262_144
                || !sealedForm(decoded).equals(form))
            throw new IllegalArgumentException("Invalid WebAuthn sealed form");
        return decoded;
    }

    private static long deadline(@NonNull Duration budget) {
        requireNonNull(budget);
        if (budget.isZero() || budget.isNegative() || Thread.currentThread().isInterrupted())
            throw new IllegalStateException("WebAuthn store budget expired");
        Duration capped = budget.compareTo(Duration.ofSeconds(30)) > 0 ? Duration.ofSeconds(30) : budget;
        return System.nanoTime() + capped.toNanos();
    }

    private static boolean expired(long deadline) {
        return deadline - System.nanoTime() <= 0 || Thread.currentThread().isInterrupted();
    }

    private static final class Completion { private @Nullable TransactionResult result; }
    private static final class Attempt { private boolean write; }

    @Override public @NonNull String toString() { return "PostgresqlWebAuthnStore{storage=<redacted>}"; }
}
