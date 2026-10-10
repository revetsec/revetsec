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

import com.revetsec.webauthn.WebAuthnStoreCommitResult;
import com.revetsec.webauthn.WebAuthnStoreEntry;
import com.revetsec.webauthn.WebAuthnStoreKey;
import com.revetsec.webauthn.WebAuthnStoreReadResult;
import com.revetsec.webauthn.WebAuthnStoreSnapshot;
import com.revetsec.webauthn.WebAuthnStoreWrite;
import org.jspecify.annotations.NonNull;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/** Local cross-JVM storage probe. Payloads are synthetic opaque sealed-form bytes. */
public final class WebAuthnStoreProbe {
    private static final @NonNull String RP = "login.example.com";
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);

    private WebAuthnStoreProbe() { }

    static @NonNull Connection connection(@NonNull Duration remaining) throws SQLException {
        int seconds = Math.max(1, (int) Math.min(30, (remaining.toMillis() + 999) / 1_000));
        Properties properties = new Properties();
        properties.setProperty("user", System.getenv("REVETSEC_TEST_DB_USER"));
        properties.setProperty("password", System.getenv("REVETSEC_TEST_DB_PASSWORD"));
        properties.setProperty("connectTimeout", Integer.toString(seconds));
        properties.setProperty("socketTimeout", Integer.toString(seconds));
        properties.setProperty("gssEncMode", "disable");
        return DriverManager.getConnection(System.getenv("REVETSEC_TEST_DB_URL"), properties);
    }

    static @NonNull Connection lostCommitAcknowledgement(@NonNull Duration remaining)
            throws SQLException {
        Connection physical = connection(remaining);
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(),
                new Class<?>[] { Connection.class }, (Object proxy, Method method, Object[] arguments) -> {
                    try {
                        Object result = method.invoke(physical, arguments);
                        if (method.getName().equals("commit"))
                            throw new SQLException("Test-only lost COMMIT acknowledgement");
                        return result;
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    }
                });
    }

    private static @NonNull PostgresqlWebAuthnStore store(@NonNull String namespace, int cap) {
        return new PostgresqlWebAuthnStore(namespace, WebAuthnStoreProbe::connection, cap);
    }

    private static @NonNull WebAuthnStoreKey key(@NonNull String namespace, int identifier) {
        return WebAuthnStoreKey.forCredential(namespace, RP, new byte[] { (byte) identifier });
    }

    private static @NonNull WebAuthnStoreSnapshot read(@NonNull PostgresqlWebAuthnStore store,
            @NonNull Set<@NonNull WebAuthnStoreKey> keys) {
        WebAuthnStoreReadResult result = store.read(keys, BUDGET);
        if (!(result instanceof WebAuthnStoreReadResult.Available available))
            throw new IllegalStateException("Authoritative WebAuthn read unavailable");
        return available.getSnapshot();
    }

    private static @NonNull WebAuthnStoreWrite write(@NonNull WebAuthnStoreSnapshot snapshot,
            @NonNull List<WebAuthnStoreWrite.@NonNull Mutation> mutations) {
        return WebAuthnStoreWrite.fromSnapshotAndMutations(snapshot, mutations);
    }

    private static void expect(@NonNull Object actual, @NonNull Object expected) {
        if (!actual.equals(expected)) throw new IllegalStateException("Unexpected WebAuthn store outcome: " + actual);
    }

    private static void basic() {
        String namespace = "fixture_wa_basic";
        PostgresqlWebAuthnStore store = store(namespace, 2);
        WebAuthnStoreKey first = key(namespace, 1);
        WebAuthnStoreKey second = key(namespace, 2);
        WebAuthnStoreKey third = key(namespace, 3);
        try {
            store.read(Set.of(key("another_namespace", 1)), BUDGET);
            throw new IllegalStateException("Cross-namespace key was accepted");
        } catch (IllegalArgumentException expected) {
            // The application must not store a different namespace's address in this partition.
        }
        WebAuthnStoreKey foreign = key("another_namespace", 1);
        WebAuthnStoreSnapshot foreignSnapshot = WebAuthnStoreSnapshot.fromEntries(Set.of(foreign),
                Map.of(foreign, WebAuthnStoreEntry.Absent.confirmed()));
        try {
            store.compareAndCommit(write(foreignSnapshot, List.of()), BUDGET);
            throw new IllegalStateException("Cross-namespace predicate was accepted");
        } catch (IllegalArgumentException expected) {
            // A condition-only commit must enforce the same partition boundary as a read.
        }
        WebAuthnStoreSnapshot absent = read(store, Set.of(first, second));
        if (!(absent.getEntry(first) instanceof WebAuthnStoreEntry.Absent)
                || !(absent.getEntry(second) instanceof WebAuthnStoreEntry.Absent))
            throw new IllegalStateException("Expected two confirmed absences");
        expect(store.compareAndCommit(write(absent, List.of(
                WebAuthnStoreWrite.Mutation.insert(first, new byte[] { 11 }),
                WebAuthnStoreWrite.Mutation.insert(second, new byte[] { 22 }))), BUDGET),
                WebAuthnStoreCommitResult.COMMITTED);
        WebAuthnStoreSnapshot present = read(store, Set.of(first, second));
        WebAuthnStoreSnapshot oldSecond = WebAuthnStoreSnapshot.fromEntries(Set.of(second),
                Map.of(second, present.getEntry(second)));
        WebAuthnStoreEntry.Present firstPresent = (WebAuthnStoreEntry.Present) present.getEntry(first);
        if (!Arrays.equals(firstPresent.getSealedBytes(), new byte[] { 11 })
                || !(present.getEntry(second) instanceof WebAuthnStoreEntry.Present))
            throw new IllegalStateException("Atomic insertion was incomplete");
        expect(store.compareAndCommit(write(absent, List.of()), BUDGET), WebAuthnStoreCommitResult.CONFLICT);
        expect(store.compareAndCommit(write(present, List.of()), BUDGET), WebAuthnStoreCommitResult.COMMITTED);
        expect(store.compareAndCommit(write(present, List.of(
                WebAuthnStoreWrite.Mutation.replace(first, new byte[] { 33 }),
                WebAuthnStoreWrite.Mutation.delete(second))), BUDGET), WebAuthnStoreCommitResult.COMMITTED);
        WebAuthnStoreSnapshot changed = read(store, Set.of(first, second));
        WebAuthnStoreEntry.Present changedFirst = (WebAuthnStoreEntry.Present) changed.getEntry(first);
        if (Arrays.equals(firstPresent.getVersion(), changedFirst.getVersion())
                || !Arrays.equals(changedFirst.getSealedBytes(), new byte[] { 33 })
                || !(changed.getEntry(second) instanceof WebAuthnStoreEntry.Absent))
            throw new IllegalStateException("Replacement or deletion was incomplete");
        expect(store.compareAndCommit(write(present, List.of()), BUDGET), WebAuthnStoreCommitResult.CONFLICT);
        expect(store.compareAndCommit(write(changed, List.of(
                WebAuthnStoreWrite.Mutation.insert(second, new byte[] { 22 }))), BUDGET),
                WebAuthnStoreCommitResult.COMMITTED);
        expect(store.compareAndCommit(write(oldSecond, List.of()), BUDGET), WebAuthnStoreCommitResult.CONFLICT);
        WebAuthnStoreSnapshot secondAgain = read(store, Set.of(second));
        expect(store.compareAndCommit(write(secondAgain, List.of(
                WebAuthnStoreWrite.Mutation.delete(second))), BUDGET), WebAuthnStoreCommitResult.COMMITTED);
        WebAuthnStoreSnapshot stalePredicate = read(store, Set.of(first, second));
        expect(store.compareAndCommit(write(stalePredicate, List.of(
                WebAuthnStoreWrite.Mutation.replace(first, new byte[] { 34 }))), BUDGET),
                WebAuthnStoreCommitResult.COMMITTED);
        expect(store.compareAndCommit(write(stalePredicate, List.of(
                WebAuthnStoreWrite.Mutation.insert(second, new byte[] { 22 }))), BUDGET),
                WebAuthnStoreCommitResult.CONFLICT);
        if (!(read(store, Set.of(second)).getEntry(second) instanceof WebAuthnStoreEntry.Absent))
            throw new IllegalStateException("Stale multi-key predicate had an effect");
        WebAuthnStoreSnapshot capacityRead = read(store(namespace, 1), Set.of(first, third));
        expect(store(namespace, 1).compareAndCommit(write(capacityRead, List.of(
                WebAuthnStoreWrite.Mutation.insert(third, new byte[] { 44 }))), BUDGET),
                WebAuthnStoreCommitResult.CAPACITY);
        WebAuthnStoreSnapshot afterCapacity = read(store, Set.of(first, third));
        if (!(afterCapacity.getEntry(third) instanceof WebAuthnStoreEntry.Absent)
                || !Arrays.equals(((WebAuthnStoreEntry.Present) afterCapacity.getEntry(first))
                        .getSealedBytes(), new byte[] { 34 }))
            throw new IllegalStateException("Capacity refusal changed stored state");
        System.out.println("BASIC_OK");
    }

    private static void unknown() {
        String namespace = "fixture_wa_unknown";
        WebAuthnStoreKey key = key(namespace, 1);
        WebAuthnStoreSnapshot absent = read(store(namespace, 2), Set.of(key));
        PostgresqlWebAuthnStore uncertain = new PostgresqlWebAuthnStore(namespace,
                WebAuthnStoreProbe::lostCommitAcknowledgement, 2);
        expect(uncertain.compareAndCommit(write(absent, List.of(
                WebAuthnStoreWrite.Mutation.insert(key, new byte[] { 55 }))), BUDGET),
                WebAuthnStoreCommitResult.UNKNOWN);
        System.out.println("UNKNOWN_REPORTED");
    }

    private static void reconcile() {
        String namespace = "fixture_wa_unknown";
        WebAuthnStoreEntry entry = read(store(namespace, 2), Set.of(key(namespace, 1)))
                .getEntry(key(namespace, 1));
        if (!(entry instanceof WebAuthnStoreEntry.Present present)
                || !Arrays.equals(present.getSealedBytes(), new byte[] { 55 }))
            throw new IllegalStateException("Uncertain commit did not persist for reconciliation");
        System.out.println("RECONCILED");
    }

    private static void race() throws Exception {
        String namespace = "fixture_wa_race";
        WebAuthnStoreKey key = key(namespace, 1);
        PostgresqlWebAuthnStore store = store(namespace, 2);
        WebAuthnStoreSnapshot absent = read(store, Set.of(key));
        if (!(absent.getEntry(key) instanceof WebAuthnStoreEntry.Absent))
            throw new IllegalStateException("Race fixture already used");
        System.out.println("READY");
        System.out.flush();
        if (new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII)).readLine() == null)
            throw new IllegalStateException("Race barrier closed");
        System.out.println(store.compareAndCommit(write(absent, List.of(
                WebAuthnStoreWrite.Mutation.insert(key, new byte[] { 66 }))), BUDGET));
    }

    private static void raceCheck() {
        String namespace = "fixture_wa_race";
        WebAuthnStoreEntry entry = read(store(namespace, 2), Set.of(key(namespace, 1)))
                .getEntry(key(namespace, 1));
        if (!(entry instanceof WebAuthnStoreEntry.Present present)
                || !Arrays.equals(present.getSealedBytes(), new byte[] { 66 }))
            throw new IllegalStateException("Race winner did not persist");
        System.out.println("RACE_RECONCILED");
    }

    private static void holdLock() throws Exception {
        try (Connection connection = connection(BUDGET)) {
            connection.setAutoCommit(false);
            try (var statement = connection.prepareStatement(
                    "SELECT 1 FROM webauthn_store_namespace WHERE namespace='fixture_wa_basic' FOR UPDATE")) {
                statement.executeQuery().close();
            }
            System.out.println("LOCKED");
            System.out.flush();
            if (new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII)).readLine() == null)
                throw new IllegalStateException("Lock barrier closed");
            connection.commit();
        }
    }

    private static void shortBudget() {
        String namespace = "fixture_wa_basic";
        WebAuthnStoreReadResult result = store(namespace, 2)
                .read(Set.of(key(namespace, 1)), Duration.ofMillis(150));
        if (!(result instanceof WebAuthnStoreReadResult.Unavailable))
            throw new IllegalStateException("Locked read escaped its deadline");
        System.out.println("LOCK_TIMEOUT");
    }

    private static void outage() {
        String namespace = "fixture_wa_basic";
        WebAuthnStoreReadResult result = store(namespace, 2)
                .read(Set.of(key(namespace, 1)), Duration.ofMillis(500));
        if (!(result instanceof WebAuthnStoreReadResult.Unavailable))
            throw new IllegalStateException("Primary outage released a snapshot");
        System.out.println("OUTAGE_CLOSED");
    }

    public static void main(String @NonNull [] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected one probe command");
        switch (args[0]) {
            case "basic" -> basic();
            case "unknown" -> unknown();
            case "reconcile" -> reconcile();
            case "race" -> race();
            case "race-check" -> raceCheck();
            case "hold-lock" -> holdLock();
            case "short-budget" -> shortBudget();
            case "outage" -> outage();
            default -> throw new IllegalArgumentException("Unknown probe command");
        }
    }
}
