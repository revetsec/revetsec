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

package verification.store;

import com.revetsec.oauth.server.*;
import com.pyranid.Database;
import com.pyranid.DatabaseType;
import com.pyranid.TransactionOptions;
import com.pyranid.TransactionIsolation;
import com.pyranid.TransactionResult;
import com.pyranid.DatabaseException;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.sql.*;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Properties;

/** Unpublished reference fixture, one authoritative PostgreSQL primary. All access takes the mutex.
 * No TTL cleanup, positive cache, callback, transaction retry or background thread. */
final class PostgresStore implements OAuthAuthorizationServerStore {
    private final @NonNull String url;
    private final @NonNull Properties properties;
    final int capacity;
    volatile @Nullable OAuthStoreTransaction last;
    volatile @Nullable Probe probe; // Test-only SQL interruption points; never application/security callbacks.
    interface Probe { void at(@NonNull String stage, @NonNull OAuthStoreTransaction transaction) throws SQLException; }
    PostgresStore(@NonNull String url, @NonNull Properties properties, int capacity) {
        this.url=url; this.properties=new Properties(); this.properties.putAll(properties); this.capacity=capacity;
    }
    private static long deadline(@NonNull Duration budget) {
        if (budget.isZero() || budget.isNegative() || budget.compareTo(Duration.ofMinutes(1))>0)
            throw new IllegalStateException("Issuer store budget invalid");
        return System.nanoTime()+budget.toNanos();
    }
    static int millis(long deadline) {
        long remaining=deadline-System.nanoTime();
        if (remaining<=0 || Thread.currentThread().isInterrupted()) throw new IllegalStateException("Issuer store budget expired");
        return (int)Math.max(1,(remaining+999999)/1000000);
    }
    private static void bound(@NonNull Connection c, long deadline) throws SQLException {
        int ms=millis(deadline);
        try (Statement s=c.createStatement()) { s.execute("SET LOCAL statement_timeout = '"+ms+"ms'"); }
    }
    private @NonNull Database database(long deadline) {
        return Database.withDataSource(new BudgetDataSource(this.url,this.properties,deadline))
            .databaseType(DatabaseType.POSTGRESQL).build();
    }
    private static void lock(@NonNull Connection c,long deadline) throws SQLException {
        bound(c,deadline);
        try (Statement s=c.createStatement()) {
            s.execute("SET LOCAL synchronous_commit = on");
            try (ResultSet q=s.executeQuery("SELECT NOT pg_is_in_recovery() AND current_setting('fsync')='on' AND current_setting('full_page_writes')='on'")) {
                if (!q.next() || !q.getBoolean(1)) throw new SQLException("Unsafe primary");
            }
        }
        bound(c,deadline);
        try (Statement s=c.createStatement();ResultSet q=s.executeQuery("SELECT id FROM issuer_mutex WHERE id=1 FOR UPDATE")) {
            if (!q.next()) throw new SQLException("Missing mutex");
        }
    }
    private static @NonNull Optional<@NonNull OAuthStoreEntry> entry(@NonNull Connection c,@NonNull OAuthStoreKey key,long deadline) throws SQLException {
        bound(c,deadline);
        try (PreparedStatement s=c.prepareStatement("SELECT version,retain_seconds,retain_nanos,sealed FROM issuer_entries WHERE storage_key=?")) {
            s.setString(1,key.getStorageKey());
            try (ResultSet q=s.executeQuery()) {
                if (!q.next()) return Optional.empty();
                return Optional.of(OAuthStoreEntry.fromStoredForm(key,q.getString(1),Instant.ofEpochSecond(q.getLong(2),q.getInt(3)),q.getString(4)));
            }
        }
    }
    @Override public @NonNull Optional<@NonNull OAuthStoreEntry> read(@NonNull OAuthStoreKey key,@NonNull Duration budget) {
        long deadline=deadline(budget);Database db=database(deadline);
        try {
            return db.transaction(TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(),
                ()->db.useRawConnection(c->{lock(c,deadline);return entry(c,key,deadline);}));
        } catch (RuntimeException e) {throw new IllegalStateException("Issuer store unavailable");}
    }
    @Override public @NonNull OAuthStoreCommitStatus commit(@NonNull OAuthStoreTransaction transaction,@NonNull Duration budget) {
        this.last=transaction;long deadline=deadline(budget);Database db=database(deadline);
        Completion completion=new Completion();
        try {
            OAuthStoreCommitStatus status=db.transaction(TransactionOptions.withIsolation(TransactionIsolation.READ_COMMITTED).build(),()->{
                db.currentTransaction().orElseThrow().addPostTransactionOperation(result->completion.result=result);
                return db.useRawConnection(c->{
                    lock(c,deadline);
                    for (var condition:transaction.getConditions()) {
                        Optional<String> actual=entry(c,condition.getKey(),deadline).map(OAuthStoreEntry::getVersion);
                        if (!actual.equals(condition.getExpectedVersion())) {db.currentTransaction().orElseThrow().setRollbackOnly(true);return Optional.of(OAuthStoreCommitStatus.CONFLICT);}
                    }
                    bound(c,deadline);
                    int size;
                    try (Statement s=c.createStatement();ResultSet q=s.executeQuery("SELECT count(*) FROM issuer_entries")) {q.next();size=q.getInt(1);}
                    int additional=0;
                    for (var mutation:transaction.getMutations()) {
                        boolean exists=entry(c,mutation.getKey(),deadline).isPresent();
                        if (mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.PUT && !exists) additional++;
                        if (mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE && exists) additional--;
                    }
                    if (size+additional>this.capacity) throw new SQLException("Capacity reached");
                    for (var mutation:transaction.getMutations()) {
                        bound(c,deadline);
                        if (mutation.getKind()==OAuthStoreTransaction.Mutation.Kind.REMOVE) {
                            try (PreparedStatement s=c.prepareStatement("DELETE FROM issuer_entries WHERE storage_key=?")) {
                                s.setString(1,mutation.getKey().getStorageKey());s.executeUpdate();
                            }
                        } else {
                            OAuthStoreEntry value=mutation.getEntry().orElseThrow();
                            try (PreparedStatement s=c.prepareStatement("INSERT INTO issuer_entries(storage_key,kind,version,retain_seconds,retain_nanos,sealed) VALUES(?,?,?,?,?,?) ON CONFLICT(storage_key) DO UPDATE SET version=EXCLUDED.version,retain_seconds=EXCLUDED.retain_seconds,retain_nanos=EXCLUDED.retain_nanos,sealed=EXCLUDED.sealed")) {
                                s.setString(1,value.getKey().getStorageKey());s.setString(2,value.getKey().getKind().name());s.setString(3,value.getVersion());
                                s.setLong(4,value.getRetainUntil().getEpochSecond());s.setInt(5,value.getRetainUntil().getNano());s.setString(6,value.toSealedForm());s.executeUpdate();
                            }
                        }
                        Probe current=this.probe;
                        if (current!=null) current.at("mutation",transaction);
                    }
                    Probe before=this.probe;
                    if (before!=null) before.at("before-commit",transaction);
                    bound(c,deadline);
                    return Optional.of(OAuthStoreCommitStatus.COMMITTED); // Prepared candidate; Pyranid commits after closure exit.
                });
            }).orElseThrow();
            if (completion.result!=TransactionResult.COMMITTED && status==OAuthStoreCommitStatus.COMMITTED)
                throw new IllegalStateException("Missing durable completion");
            Probe after=this.probe;
            if (after!=null && status==OAuthStoreCommitStatus.COMMITTED) after.at("after-commit",transaction);
            return status;
        } catch (DatabaseException e) {
            // Use the public post-transaction result. No internal exception flags, retry or guessed rollback.
            if (completion.result==TransactionResult.COMMITTED) return OAuthStoreCommitStatus.COMMITTED;
            if (completion.result==TransactionResult.IN_DOUBT) return OAuthStoreCommitStatus.UNKNOWN;
            throw new IllegalStateException("Issuer store unavailable");
        } catch (SQLException e) {throw new IllegalStateException("Fixture probe failed");}
    }
    private static final class Completion {
        @Nullable TransactionResult result;
        Completion() { }
    }
}
