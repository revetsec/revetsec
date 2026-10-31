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

import com.revetsec.totp.TotpStoreCommitResult;
import com.revetsec.totp.TotpStoreCommitReceipt;
import com.revetsec.StoreTimeObservation;
import com.revetsec.StoreTemporalCondition;
import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.totp.TotpStoreEntry;
import com.revetsec.totp.TotpStoreKey;
import com.revetsec.totp.TotpStoreReadResult;
import com.revetsec.totp.TotpStoreRecord;
import com.revetsec.totp.TotpStoreSnapshot;
import com.revetsec.totp.TotpStoreWrite;
import org.jspecify.annotations.NonNull;

import javax.annotation.concurrent.NotThreadSafe;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;

/** Test-only cross-JVM transactional probe with synthetic opaque record bytes. */
@NotThreadSafe
public final class TotpStoreProbe {
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(5);
    private static final @NonNull String FIRST = "fixture-epoch-one";
    private static final @NonNull String SECOND = "fixture-epoch-two";
    private static final @NonNull String LOAD_NAMESPACE = "fixture-totp-load";

    private TotpStoreProbe() { }

    static @NonNull Connection connection(@NonNull Duration remaining) throws SQLException {
        int seconds = Math.max(1, (int) Math.min(30, (remaining.toMillis() + 999) / 1_000));
        Properties properties = new Properties();
        properties.setProperty("user", Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_USER")));
        properties.setProperty("password", System.getenv().getOrDefault("REVETSEC_TEST_DB_PASSWORD", ""));
        properties.setProperty("connectTimeout", Integer.toString(seconds));
        properties.setProperty("socketTimeout", Integer.toString(seconds));
        properties.setProperty("gssEncMode", "disable");
        properties.setProperty("sslmode", "disable");
        properties.setProperty("preferQueryMode", "simple");
        return DriverManager.getConnection(Objects.requireNonNull(System.getenv("REVETSEC_TEST_DB_URL")), properties);
    }

    private static @NonNull PostgresqlTotpStore store(@NonNull String namespace, int entries) {
        return new PostgresqlTotpStore(namespace, TotpFixtureAuthority.physical(namespace), TotpStoreProbe::connection, entries, 2_000_000L, TotpFixtureAuthority.fromEnvironment(namespace));
    }

    private static @NonNull TotpStoreKey root(@NonNull String namespace, @NonNull String epoch) {
        return TotpStoreKey.forNamespace(namespace, epoch);
    }

    private static @NonNull TotpStoreKey account(@NonNull String namespace, @NonNull String epoch,
            @NonNull String account) {
        return TotpStoreKey.forAccount(namespace, epoch, account);
    }

    private static @NonNull TotpStoreRecord record(@NonNull TotpStoreKey key, int value) {
        byte[] nonce = new byte[32];
        Arrays.fill(nonce, (byte) value);
        String version = Base64.getUrlEncoder().withoutPadding().encodeToString(nonce);
        byte[] raw=new byte[55];Arrays.fill(raw,(byte)value);raw[0]=1;raw[1]=1;raw[2]='k';
        return TotpStoreRecord.fromStoredForm(key, version, Base64.getUrlEncoder().withoutPadding().encodeToString(raw).getBytes(StandardCharsets.US_ASCII));
    }

    private static @NonNull TotpStoreSnapshot read(@NonNull PostgresqlTotpStore store,
            @NonNull Set<@NonNull TotpStoreKey> keys) {
        TotpStoreReadResult result = store.read(keys, BUDGET);
        if (!(result instanceof TotpStoreReadResult.Available available))
            throw new IllegalStateException("Authoritative TOTP read unavailable");
        return available.getSnapshot();
    }

    private static @NonNull TotpStoreWrite initialize(@NonNull TotpStoreSnapshot snapshot,
            @NonNull TotpStoreKey root) {
        return TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.INITIALIZE_NAMESPACE,
                snapshot, List.of(TotpStoreWrite.Mutation.insert(record(root, 1))), condition(snapshot));
    }

    private static @NonNull TotpStoreWrite update(@NonNull TotpStoreSnapshot snapshot,
            @NonNull List<TotpStoreWrite.@NonNull Mutation> mutations) {
        return TotpStoreWrite.fromSnapshotAndMutations(TotpStoreWrite.Purpose.UPDATE, snapshot, mutations, condition(snapshot));
    }

    private static @NonNull StoreTemporalCondition condition(@NonNull TotpStoreSnapshot snapshot) {
        StoreTimeObservation.Healthy time=(StoreTimeObservation.Healthy)snapshot.getTimeObservation();
        return StoreTimeAccess.get().fromObservation(time,time.getObservedAt(),null);
    }

    private static void expect(@NonNull Object actual, @NonNull Object expected) {
        if(actual instanceof TotpStoreCommitReceipt receipt){
            if(receipt.getStatus()==TotpStoreCommitResult.COMMITTED && receipt.getTiming().isEmpty())throw new IllegalStateException("Committed timing missing");
            actual=receipt.getStatus();
        }
        if (!actual.equals(expected)) throw new IllegalStateException("Unexpected TOTP store outcome: " + actual);
    }

    private static void basic() {
        String namespace = "fixture-totp-basic";
        PostgresqlTotpStore store = store(namespace, 1024);
        TotpStoreKey root = root(namespace, FIRST);
        TotpStoreKey first = account(namespace, FIRST, "account-a");
        TotpStoreKey second = account(namespace, FIRST, "account-b");
        TotpStoreKey third = account(namespace, FIRST, "account-c");
        TotpStoreSnapshot emptyRoot = read(store, Set.of(root));
        if (!(emptyRoot.getEntry(root) instanceof TotpStoreEntry.Absent))
            throw new IllegalStateException("New recovery epoch has a root");
        expect(store.compareAndCommit(initialize(emptyRoot, root), BUDGET), TotpStoreCommitResult.COMMITTED);
        expect(store.compareAndCommit(initialize(emptyRoot, root), BUDGET), TotpStoreCommitResult.CONFLICT);

        TotpStoreSnapshot absent = read(store, Set.of(root, first, second));
        expect(store.compareAndCommit(update(absent, List.of(
                TotpStoreWrite.Mutation.insert(record(first, 2)),
                TotpStoreWrite.Mutation.insert(record(second, 3)))), BUDGET), TotpStoreCommitResult.COMMITTED);
        expect(store.compareAndCommit(update(absent, List.of()), BUDGET), TotpStoreCommitResult.CONFLICT);
        TotpStoreSnapshot current = read(store, Set.of(root, first, second));
        if (!(current.getEntry(first) instanceof TotpStoreEntry.Present)
                || !(current.getEntry(second) instanceof TotpStoreEntry.Present))
            throw new IllegalStateException("Atomic insertion was partial");
        expect(store.compareAndCommit(update(current, List.of()), BUDGET), TotpStoreCommitResult.COMMITTED);
        expect(store(namespace, 3).compareAndCommit(update(read(store, Set.of(root, third)),
                List.of(TotpStoreWrite.Mutation.insert(record(third, 4)))), BUDGET),
                TotpStoreCommitResult.UNAVAILABLE);
        if (!(read(store, Set.of(root, third)).getEntry(third) instanceof TotpStoreEntry.Absent))
            throw new IllegalStateException("Capacity refusal wrote a record");
        expect(store.compareAndCommit(update(current, List.of(
                TotpStoreWrite.Mutation.replace(record(first, 5)))), BUDGET), TotpStoreCommitResult.COMMITTED);
        expect(store.compareAndCommit(update(current, List.of(
                TotpStoreWrite.Mutation.replace(record(second, 6)))), BUDGET), TotpStoreCommitResult.CONFLICT);
        System.out.println("BASIC_OK");
    }

    private static void initializeRace() {
        String namespace = "fixture-totp-race";
        PostgresqlTotpStore store = store(namespace, 1024);
        TotpStoreKey root = root(namespace, FIRST);
        expect(store.compareAndCommit(initialize(read(store, Set.of(root)), root), BUDGET),
                TotpStoreCommitResult.COMMITTED);
        System.out.println("RACE_INITIALIZED");
    }

    private static void race() throws Exception {
        String namespace = "fixture-totp-race";
        PostgresqlTotpStore store = store(namespace, 1024);
        TotpStoreKey root = root(namespace, FIRST);
        TotpStoreKey account = account(namespace, FIRST, "contended");
        TotpStoreSnapshot observed = read(store, Set.of(root, account));
        if (!(observed.getEntry(account) instanceof TotpStoreEntry.Absent))
            throw new IllegalStateException("Contended row already exists");
        System.out.println("READY");
        System.out.flush();
        if (!"go".equals(new BufferedReader(new InputStreamReader(System.in,
                StandardCharsets.US_ASCII)).readLine()))
            throw new IllegalStateException("Race barrier missing");
        TotpStoreCommitResult result = store.compareAndCommit(update(observed,
                List.of(TotpStoreWrite.Mutation.insert(record(account, 2)))), BUDGET).getStatus();
        if (result != TotpStoreCommitResult.COMMITTED && result != TotpStoreCommitResult.CONFLICT)
            throw new IllegalStateException("Unexpected race outcome: " + result);
        System.out.println(result);
    }

    private static void raceCheck() {
        String namespace = "fixture-totp-race";
        TotpStoreKey root = root(namespace, FIRST);
        TotpStoreKey account = account(namespace, FIRST, "contended");
        if (!(read(store(namespace, 1024), Set.of(root, account)).getEntry(account)
                instanceof TotpStoreEntry.Present)) throw new IllegalStateException("Race winner was not retained");
        System.out.println("RACE_RETAINED");
    }

    private static void unknown() {
        String namespace = "fixture-totp-unknown";
        PostgresqlTotpStore store = store(namespace, 1024);
        TotpStoreKey root = root(namespace, FIRST);
        TotpStoreKey account = account(namespace, FIRST, "account-a");
        expect(store.compareAndCommit(initialize(read(store, Set.of(root)), root), BUDGET),
                TotpStoreCommitResult.COMMITTED);
        TotpStoreSnapshot observed = read(store, Set.of(root, account));
        store.failNextCommitAcknowledgement();
        expect(store.compareAndCommit(update(observed,
                List.of(TotpStoreWrite.Mutation.insert(record(account, 7)))), BUDGET),
                TotpStoreCommitResult.UNKNOWN);
        System.out.println("UNKNOWN_REPORTED");
    }

    private static void unknownCheck() {
        String namespace = "fixture-totp-unknown";
        TotpStoreKey root = root(namespace, FIRST);
        TotpStoreKey account = account(namespace, FIRST, "account-a");
        if (!(read(store(namespace, 1024), Set.of(root, account)).getEntry(account)
                instanceof TotpStoreEntry.Present)) throw new IllegalStateException("Unknown commit not retained");
        System.out.println("UNKNOWN_RETAINED");
    }

    private static void byteCap() {
        String namespace = "fixture-totp-byte-cap";
        PostgresqlTotpStore store = store(namespace, 1024);
        TotpStoreKey root = root(namespace, FIRST);
        TotpStoreKey account = account(namespace, FIRST, "byte-limited");
        expect(store.compareAndCommit(initialize(read(store, Set.of(root)), root), BUDGET),
                TotpStoreCommitResult.COMMITTED);
        PostgresqlTotpStore capped = new PostgresqlTotpStore(namespace, TotpFixtureAuthority.physical(namespace),
                TotpStoreProbe::connection, 1024, 1, TotpFixtureAuthority.fromEnvironment(namespace));
        if(!(capped.read(Set.of(root,account),BUDGET) instanceof TotpStoreReadResult.Unavailable))
            throw new IllegalStateException("Changed byte profile was admitted");
        if (!(read(store, Set.of(root, account)).getEntry(account) instanceof TotpStoreEntry.Absent))
            throw new IllegalStateException("Profile mismatch wrote a record");
        System.out.println("BYTE_PROFILE_MISMATCH_CLOSED");
    }

    private static void fence() {
        String namespace = "fixture-totp-basic";
        PostgresqlTotpStore store = store(namespace, 1024);
        TotpStoreKey oldRoot = root(namespace, FIRST);
        TotpStoreKey oldAccount = account(namespace, FIRST, "stale-account");
        TotpStoreSnapshot stale = read(store, Set.of(oldRoot, oldAccount));
        TotpStoreWrite staleWrite = update(stale,
                List.of(TotpStoreWrite.Mutation.insert(record(oldAccount, 9))));
        expect(store.provisionRecoveryEpoch(SECOND, BUDGET), TotpStoreCommitResult.COMMITTED);
        if (!(store.read(Set.of(oldRoot), BUDGET) instanceof TotpStoreReadResult.Fenced))
            throw new IllegalStateException("Old epoch read not fenced");
        expect(store.compareAndCommit(staleWrite, BUDGET), TotpStoreCommitResult.FENCED);
        TotpStoreKey newRoot = root(namespace, SECOND);
        expect(store.compareAndCommit(initialize(read(store, Set.of(newRoot)), newRoot), BUDGET),
                TotpStoreCommitResult.COMMITTED);
        if (!(read(store, Set.of(newRoot, account(namespace, SECOND, "account-a")))
                .getEntry(account(namespace, SECOND, "account-a")) instanceof TotpStoreEntry.Absent))
            throw new IllegalStateException("Old account revived in new epoch");
        System.out.println("EPOCH_FENCED");
    }

    private static void staleWriter() throws Exception {
        String namespace = "fixture-totp-basic";
        PostgresqlTotpStore store = store(namespace, 1024);
        TotpStoreKey root = root(namespace, FIRST);
        TotpStoreKey account = account(namespace, FIRST, "late-account");
        TotpStoreSnapshot stale = read(store, Set.of(root, account));
        TotpStoreWrite write = update(stale,
                List.of(TotpStoreWrite.Mutation.insert(record(account, 10))));
        System.out.println("READY");
        System.out.flush();
        if (!"go".equals(new BufferedReader(new InputStreamReader(System.in,
                StandardCharsets.US_ASCII)).readLine()))
            throw new IllegalStateException("Stale-writer barrier missing");
        expect(store.compareAndCommit(write, BUDGET), TotpStoreCommitResult.FENCED);
        System.out.println("STALE_WRITER_FENCED");
    }

    private static void provisionFlow() {
        PostgresqlTotpStore store = new PostgresqlTotpStore("fixture_totp_flow", TotpFixtureAuthority.physical("fixture_totp_flow"), TotpStoreProbe::connection, 4096,64L*1024*1024,TotpFixtureAuthority.fromEnvironment("fixture_totp_flow"));
        expect(store.provisionRecoveryEpoch(SECOND, BUDGET), TotpStoreCommitResult.COMMITTED);
        System.out.println("FLOW_EPOCH_PROVISIONED");
    }

    private static void flowOldFenced() {
        PostgresqlTotpStore store = new PostgresqlTotpStore("fixture_totp_flow", TotpFixtureAuthority.physical("fixture_totp_flow"), TotpStoreProbe::connection, 4096,64L*1024*1024,TotpFixtureAuthority.fromEnvironment("fixture_totp_flow"));
        TotpStoreKey oldRoot = root("fixture_totp_flow", FIRST);
        if (!(store.read(Set.of(oldRoot), BUDGET) instanceof TotpStoreReadResult.Fenced))
            throw new IllegalStateException("Restored old epoch remained authoritative");
        System.out.println("RESTORED_EPOCH_FENCED");
    }

    private static void outage() {
        String namespace = "fixture-totp-race";
        TotpStoreReadResult result = store(namespace, 1024).read(Set.of(root(namespace, FIRST)),
                Duration.ofMillis(300));
        if (!(result instanceof TotpStoreReadResult.Unavailable))
            throw new IllegalStateException("Stopped primary yielded a trusted read");
        System.out.println("OUTAGE_CLOSED");
    }

    private static void deadline() {
        String namespace = "fixture-totp-race";
        TotpStoreReadResult result = store(namespace, 1024).read(Set.of(root(namespace, FIRST)),
                Duration.ofMillis(75));
        if (!(result instanceof TotpStoreReadResult.Unavailable))
            throw new IllegalStateException("Locked namespace exceeded a short deadline");
        System.out.println("DEADLINE_CLOSED");
    }

    private static void initializeLoad() {
        PostgresqlTotpStore store = store(LOAD_NAMESPACE, 4_096);
        TotpStoreKey root = root(LOAD_NAMESPACE, FIRST);
        expect(store.compareAndCommit(initialize(read(store, Set.of(root)), root), BUDGET),
                TotpStoreCommitResult.COMMITTED);
        System.out.println("LOAD_INITIALIZED");
    }

    private static void load(@NonNull String worker, int operations) {
        if (!worker.matches("[0-9]{1,2}") || operations < 1 || operations > 100)
            throw new IllegalArgumentException("Invalid fixture workload dimensions");
        PostgresqlTotpStore store = store(LOAD_NAMESPACE, 4_096);
        TotpStoreKey root = root(LOAD_NAMESPACE, FIRST);
        StringBuilder latencies = new StringBuilder("LOAD_NANOS");
        for (int index = 0; index < operations; index++) {
            TotpStoreKey key = account(LOAD_NAMESPACE, FIRST, "worker-" + worker + "-" + index);
            long start = System.nanoTime();
            TotpStoreSnapshot observed = read(store, Set.of(root, key));
            if (!(observed.getEntry(key) instanceof TotpStoreEntry.Absent))
                throw new IllegalStateException("Fixture workload key already present");
            expect(store.compareAndCommit(update(observed,
                    List.of(TotpStoreWrite.Mutation.insert(record(key, index + 2)))), BUDGET),
                    TotpStoreCommitResult.COMMITTED);
            latencies.append(' ').append(System.nanoTime() - start);
        }
        System.out.println(latencies);
    }

    public static void main(java.lang.@NonNull String @NonNull [] args) throws Exception {
        if (args.length < 1) throw new IllegalArgumentException("Expected one fixture mode");
        switch (args[0]) {
            case "basic" -> basic();
            case "initialize-race" -> initializeRace();
            case "race" -> race();
            case "race-check" -> raceCheck();
            case "unknown" -> unknown();
            case "unknown-check" -> unknownCheck();
            case "byte-cap" -> byteCap();
            case "fence" -> fence();
            case "stale-writer" -> staleWriter();
            case "provision-flow" -> provisionFlow();
            case "flow-old-fenced" -> flowOldFenced();
            case "outage" -> outage();
            case "deadline" -> deadline();
            case "load-initialize" -> initializeLoad();
            case "load" -> {
                if (args.length != 3) throw new IllegalArgumentException("Expected workload dimensions");
                load(args[1], Integer.parseInt(args[2]));
            }
            default -> throw new IllegalArgumentException("Unknown fixture mode");
        }
    }
}
