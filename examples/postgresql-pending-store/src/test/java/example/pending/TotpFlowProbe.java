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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.totp.RecoveryCodeUse;
import com.revetsec.totp.RecoveryCodeUseResult;
import com.revetsec.totp.RecoveryCodes;
import com.revetsec.totp.TotpAuthenticator;
import com.revetsec.totp.TotpAuthenticationMethod;
import com.revetsec.totp.TotpEnrollment;
import com.revetsec.totp.TotpEnrollmentOptions;
import com.revetsec.totp.TotpEnrollmentRequestResult;
import com.revetsec.totp.TotpEnrollmentResult;
import com.revetsec.totp.TotpFactorRemovalResult;
import com.revetsec.totp.TotpNamespaceInitializationResult;
import com.revetsec.totp.TotpStatus;
import com.revetsec.totp.TotpStatusResult;
import com.revetsec.totp.TotpStore;
import com.revetsec.totp.TotpStoreCommitResult;
import com.revetsec.totp.TotpStoreCommitReceipt;
import com.revetsec.StoreTimeObservation;
import com.revetsec.internal.StoreTimeAccess;
import com.revetsec.totp.TotpStoreKey;
import com.revetsec.totp.TotpStoreReadResult;
import com.revetsec.totp.TotpStoreResealResult;
import com.revetsec.totp.TotpStoreSnapshot;
import com.revetsec.totp.TotpStoreWrite;
import com.revetsec.totp.TotpVerification;
import com.revetsec.totp.TotpVerificationResult;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.NotThreadSafe;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import static java.util.Objects.requireNonNull;

/**
 * One-process-at-a-time public TOTP flow probe over a real PostgreSQL store and independent
 * recovery gate. The Python runner captures all synthetic provisioning and recovery secrets in
 * memory; this fixture never logs them except for its deliberately machine-readable responses.
 */
@NotThreadSafe
public final class TotpFlowProbe {
    private static final @NonNull String NAMESPACE = "fixture_totp_flow";
    private static final @NonNull String ACCOUNT = "fixture-account";
    private static final @NonNull String BROWSER = "fixture-browser-binding";
    private static final @NonNull String LOGIN = "fixture-login-binding";
    private static final @NonNull String KEY_ID = "fixture";

    private TotpFlowProbe() { }

    public static void main(java.lang.@NonNull String @NonNull [] args) throws Exception {
        if (args.length == 0) throw new IllegalArgumentException("Missing TOTP probe command");
        String command = args[0];
        String epoch = env("REVETSEC_TEST_TOTP_EPOCH");
        String keyBase64 = env("REVETSEC_TEST_TOTP_SEAL_KEY_BASE64");
        String activeKeyId = System.getenv().getOrDefault("REVETSEC_TEST_TOTP_ACTIVE_KEY_ID", KEY_ID);
        @Nullable String oldKeyBase64 = System.getenv("REVETSEC_TEST_TOTP_OLD_SEAL_KEY_BASE64");
        PostgresqlTotpStore store = new PostgresqlTotpStore(NAMESPACE, TotpFixtureAuthority.physical(NAMESPACE), TotpFlowProbe::connection,
                4_096, 64L * 1024 * 1024, TotpFixtureAuthority.fromEnvironment(NAMESPACE));
        Map<String, String> openingKeys = oldKeyBase64 == null
                ? Map.of(activeKeyId, keyBase64)
                : Map.of(activeKeyId, keyBase64, KEY_ID, oldKeyBase64);
        TotpFixtureRecoveryGate gate = new TotpFixtureRecoveryGate(
                Path.of(env("REVETSEC_TEST_TOTP_MARKER")), Path.of(env("REVETSEC_TEST_TOTP_LOCK")),
                openingKeys);
        TotpStore selected = command.equals("hold-admission") ? holdRead(store) : store;
        StateSealer.Builder sealerBuilder = StateSealer.withActiveKey(
                SealingKey.fromBase64(activeKeyId, keyBase64));
        if (oldKeyBase64 != null)
            sealerBuilder.verificationKeys(List.of(SealingKey.fromBase64(KEY_ID, oldKeyBase64)));
        TotpAuthenticator totp = TotpAuthenticator.withIssuer("Fixture")
                .credentialNamespace(NAMESPACE).recoveryEpoch(epoch).store(selected)
                .stateSealer(sealerBuilder.build())
                .recoveryGate(gate).clock(clock()).build();

        switch (command) {
            case "initialize" -> initialize(totp);
            case "begin" -> begin(totp);
            case "confirm" -> confirm(totp, args);
            case "status" -> status(totp);
            case "verify", "race-verify", "unknown-verify" -> {
                if (command.equals("unknown-verify")) store.failNthCommitAcknowledgement(2);
                if (command.equals("race-verify")) ready();
                verify(totp, requiredArgument(args, 1));
            }
            case "recovery", "race-recovery", "unknown-recovery" -> {
                if (command.equals("unknown-recovery")) store.failNthCommitAcknowledgement(2);
                if (command.equals("race-recovery")) ready();
                recovery(totp, requiredArgument(args, 1));
            }
            case "remove" -> remove(totp, requiredArgument(args, 1));
            case "reseal", "unknown-reseal" -> {
                if (command.equals("unknown-reseal")) store.failNextCommitAcknowledgement();
                reseal(totp, requiredArgument(args, 1));
            }
            case "hold-admission" -> holdAdmission(totp);
            case "store-read" -> storeRead(store, epoch);
            case "stale-writer" -> staleWriter(store, epoch);
            default -> throw new IllegalArgumentException("Unknown TOTP probe command");
        }
    }

    private static void initialize(@NonNull TotpAuthenticator totp) {
        TotpNamespaceInitializationResult result = totp.initializeNamespaceResult();
        if (result instanceof TotpNamespaceInitializationResult.Initialized) System.out.println("INITIALIZED");
        else if (result instanceof TotpNamespaceInitializationResult.AlreadyInitialized)
            System.out.println("ALREADY_INITIALIZED");
        else if (result instanceof TotpNamespaceInitializationResult.Indeterminate)
            System.out.println("INDETERMINATE");
        else System.out.println("UNAVAILABLE");
    }

    private static void begin(@NonNull TotpAuthenticator totp) {
        TotpEnrollmentOptions options = TotpEnrollmentOptions.withAccountId(ACCOUNT)
                .accountName("fixture@example.com").build();
        TotpEnrollmentRequestResult result = totp.beginEnrollmentResult(options, BROWSER);
        if (result instanceof TotpEnrollmentRequestResult.Prepared prepared) {
            TotpEnrollment enrollment = prepared.getEnrollment();
            System.out.println("PREPARED " + enrollment.getEnrollmentId() + " "
                    + enrollment.getManualEntryKey());
        } else System.out.println(outcome(result));
    }

    private static void confirm(@NonNull TotpAuthenticator totp,
            java.lang.@NonNull String @NonNull [] args) {
        String enrollmentId = requiredArgument(args, 1);
        String code = requiredArgument(args, 2);
        TotpEnrollmentResult result = totp.confirmEnrollmentResult(ACCOUNT, enrollmentId, code, BROWSER);
        if (result instanceof TotpEnrollmentResult.Succeeded succeeded) {
            RecoveryCodes codes = succeeded.getRecoveryCodes();
            List<String> plaintext = codes.getCodes();
            if (plaintext.size() != 10) throw new IllegalStateException("Unexpected recovery batch size");
            System.out.println("CONFIRMED " + succeeded.getFactor().getFactorId() + " "
                    + codes.getBatchId() + " " + plaintext.get(0) + " " + plaintext.get(1)
                    + " " + plaintext.get(2) + " " + plaintext.get(3) + " " + plaintext.get(4));
        } else System.out.println(outcome(result));
    }

    private static void status(@NonNull TotpAuthenticator totp) {
        TotpStatusResult result = totp.getStatusResult(ACCOUNT);
        if (result instanceof TotpStatusResult.Present present) {
            TotpStatus status = present.getStatus();
            if (status.getActiveFactor().isPresent()) {
                System.out.println("ACTIVE " + status.getActiveFactor().orElseThrow().getFactorId() + " "
                        + status.getRecoveryBatchId().orElseThrow() + " "
                        + status.getRemainingRecoveryCodeCount());
            } else System.out.println("INACTIVE");
        } else if (result instanceof TotpStatusResult.Absent) System.out.println("ABSENT");
        else System.out.println("UNAVAILABLE");
    }

    private static void verify(@NonNull TotpAuthenticator totp, @NonNull String code) {
        TotpVerificationResult result = totp.verifyResult(ACCOUNT, code, LOGIN);
        if (result instanceof TotpVerificationResult.Succeeded succeeded) {
            TotpVerification proof = succeeded.getVerification();
            checkProof(proof.getCredentialNamespace(), proof.getRecoveryEpoch(),
                    proof.getAccountId(), proof.getOperationBinding(), totp);
            if (proof.getMethod() != TotpAuthenticationMethod.TOTP)
                throw new IllegalStateException("Unexpected TOTP proof method");
            System.out.println("SUCCEEDED");
        } else System.out.println(outcome(result));
    }

    private static void recovery(@NonNull TotpAuthenticator totp, @NonNull String code) {
        RecoveryCodeUseResult result = totp.consumeRecoveryCodeResult(ACCOUNT, code, LOGIN);
        if (result instanceof RecoveryCodeUseResult.Succeeded succeeded) {
            RecoveryCodeUse proof = succeeded.getUse();
            checkProof(proof.getCredentialNamespace(), proof.getRecoveryEpoch(),
                    proof.getAccountId(), proof.getOperationBinding(), totp);
            if (proof.getMethod() != TotpAuthenticationMethod.RECOVERY_CODE)
                throw new IllegalStateException("Unexpected recovery proof method");
            System.out.println("SUCCEEDED");
        } else System.out.println(outcome(result));
    }

    private static void checkProof(@NonNull String namespace, @NonNull String epoch,
            @NonNull String account, @NonNull String binding, @NonNull TotpAuthenticator totp) {
        if (!NAMESPACE.equals(namespace) || !totp.getRecoveryEpoch().equals(epoch)
                || !ACCOUNT.equals(account) || !LOGIN.equals(binding))
            throw new IllegalStateException("Unexpected TOTP proof binding");
    }

    private static void remove(@NonNull TotpAuthenticator totp, @NonNull String factorId) {
        TotpFactorRemovalResult result = totp.removeFactorResult(ACCOUNT, factorId);
        if (result instanceof TotpFactorRemovalResult.Succeeded) System.out.println("REMOVED");
        else System.out.println(outcome(result));
    }

    private static void reseal(@NonNull TotpAuthenticator totp, @NonNull String kind) {
        TotpStoreKey key = switch (kind) {
            case "namespace" -> TotpStoreKey.forNamespace(NAMESPACE, totp.getRecoveryEpoch());
            case "account" -> TotpStoreKey.forAccount(NAMESPACE, totp.getRecoveryEpoch(), ACCOUNT);
            default -> throw new IllegalArgumentException("Unknown TOTP fixture record kind");
        };
        TotpStoreResealResult result = totp.resealStoreEntryResult(key);
        if (result instanceof TotpStoreResealResult.Resealed) System.out.println("RESEALED");
        else if (result instanceof TotpStoreResealResult.AlreadyCurrent)
            System.out.println("ALREADY_CURRENT");
        else if (result instanceof TotpStoreResealResult.Indeterminate)
            System.out.println("INDETERMINATE");
        else System.out.println("UNAVAILABLE");
    }

    private static void holdAdmission(@NonNull TotpAuthenticator totp) {
        TotpStatusResult result = totp.getStatusResult(ACCOUNT);
        if (result instanceof TotpStatusResult.Present) System.out.println("RELEASED");
        else System.out.println("CLOSED");
    }

    private static void storeRead(@NonNull TotpStore store, @NonNull String epoch) {
        TotpStoreKey root = TotpStoreKey.forNamespace(NAMESPACE, epoch);
        TotpStoreReadResult result = store.read(Set.of(root), Duration.ofSeconds(5));
        if (result instanceof TotpStoreReadResult.Fenced) System.out.println("FENCED");
        else if (result instanceof TotpStoreReadResult.Available) System.out.println("AVAILABLE");
        else System.out.println("UNAVAILABLE");
    }

    private static void staleWriter(@NonNull TotpStore store, @NonNull String epoch)
            throws IOException {
        TotpStoreKey root = TotpStoreKey.forNamespace(NAMESPACE, epoch);
        TotpStoreReadResult.Available read = (TotpStoreReadResult.Available)
                store.read(Set.of(root), Duration.ofSeconds(5));
        TotpStoreSnapshot snapshot = read.getSnapshot();
        TotpStoreWrite barrier = TotpStoreWrite.fromSnapshotAndMutations(
                TotpStoreWrite.Purpose.UPDATE, snapshot, List.of(), StoreTimeAccess.get().fromObservation((StoreTimeObservation.Healthy)snapshot.getTimeObservation(), ((StoreTimeObservation.Healthy)snapshot.getTimeObservation()).getObservedAt(),null));
        System.out.println("SNAPSHOT");
        System.out.flush();
        if (!"go".equals(new BufferedReader(new InputStreamReader(System.in,
                StandardCharsets.US_ASCII)).readLine()))
            throw new IllegalStateException("Stale-writer barrier closed");
        System.out.println(store.compareAndCommit(barrier, Duration.ofSeconds(5)).getStatus().name());
    }

    private static @NonNull TotpStore holdRead(@NonNull TotpStore delegate) {
        return new TotpStore() {
            @Override public @NonNull TotpStoreReadResult read(
                    @NonNull Set<@NonNull TotpStoreKey> keys, @NonNull Duration remainingBudget) {
                System.out.println("ADMITTED");
                System.out.flush();
                try {
                    if (!"release".equals(new BufferedReader(new InputStreamReader(System.in,
                            StandardCharsets.US_ASCII)).readLine()))
                        return TotpStoreReadResult.Unavailable.get();
                } catch (IOException failure) {
                    return TotpStoreReadResult.Unavailable.get();
                }
                return delegate.read(keys, remainingBudget);
            }
            @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(
                    @NonNull TotpStoreWrite write, @NonNull Duration remainingBudget) {
                return delegate.compareAndCommit(write, remainingBudget);
            }
        };
    }

    private static void ready() throws IOException {
        System.out.println("READY");
        System.out.flush();
        if (!"go".equals(new BufferedReader(new InputStreamReader(System.in,
                StandardCharsets.US_ASCII)).readLine()))
            throw new IllegalStateException("Race barrier closed");
    }

    private static @NonNull String outcome(@NonNull Object result) {
        if (result instanceof TotpEnrollmentRequestResult.Rejected
                || result instanceof TotpEnrollmentResult.Rejected
                || result instanceof TotpVerificationResult.Rejected
                || result instanceof RecoveryCodeUseResult.Rejected
                || result instanceof TotpFactorRemovalResult.Rejected) return "REJECTED";
        if (result instanceof TotpEnrollmentRequestResult.Throttled
                || result instanceof TotpEnrollmentResult.Throttled
                || result instanceof TotpVerificationResult.Throttled
                || result instanceof RecoveryCodeUseResult.Throttled) return "THROTTLED";
        if (result instanceof TotpEnrollmentRequestResult.Indeterminate
                || result instanceof TotpEnrollmentResult.Indeterminate
                || result instanceof TotpVerificationResult.Indeterminate
                || result instanceof RecoveryCodeUseResult.Indeterminate
                || result instanceof TotpFactorRemovalResult.Indeterminate) return "INDETERMINATE";
        if(result instanceof TotpEnrollmentRequestResult.ReconciliationRequired
                || result instanceof TotpEnrollmentResult.ReconciliationRequired
                || result instanceof TotpVerificationResult.ReconciliationRequired
                || result instanceof RecoveryCodeUseResult.ReconciliationRequired
                || result instanceof TotpFactorRemovalResult.ReconciliationRequired)return "RECONCILIATION_REQUIRED";
        return "UNAVAILABLE";
    }

    private static @NonNull Clock clock() {
        String seconds = env("REVETSEC_TEST_TOTP_NOW");
        return Clock.fixed(Instant.ofEpochSecond(Long.parseLong(seconds)), ZoneOffset.UTC);
    }

    private static @NonNull Connection connection(@NonNull Duration remaining) throws SQLException {
        int seconds = Math.max(1, (int) Math.min(30, (remaining.toMillis() + 999) / 1_000));
        Properties properties = new Properties();
        properties.setProperty("user", env("REVETSEC_TEST_DB_USER"));
        properties.setProperty("password", env("REVETSEC_TEST_DB_PASSWORD"));
        properties.setProperty("connectTimeout", Integer.toString(seconds));
        properties.setProperty("socketTimeout", Integer.toString(seconds));
        properties.setProperty("gssEncMode", "disable");
        properties.setProperty("sslmode", "disable");
        properties.setProperty("preferQueryMode", "simple");
        return DriverManager.getConnection(env("REVETSEC_TEST_DB_URL"), properties);
    }

    private static @NonNull String requiredArgument(java.lang.@NonNull String @NonNull [] args, int index) {
        if (index >= args.length || args[index].isEmpty())
            throw new IllegalArgumentException("Missing TOTP probe argument");
        return args[index];
    }

    private static @NonNull String env(@NonNull String name) {
        return requireNonNull(System.getenv(name), "Missing TOTP probe environment");
    }
}
