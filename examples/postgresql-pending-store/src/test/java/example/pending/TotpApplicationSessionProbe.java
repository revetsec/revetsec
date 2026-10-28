/*
 * Copyright 2026 Revetware LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package example.pending;

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.totp.RecoveryCodeUseResult;
import com.revetsec.totp.TotpAuthenticator;
import com.revetsec.totp.TotpRecoveryGate;
import com.revetsec.totp.TotpStatusResult;
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
 * Separate-JVM test driver for a real public TOTP proof followed by an application-owned,
 * epoch-fenced PostgreSQL session transaction. This is test machinery, not primary auth.
 */
@NotThreadSafe
public final class TotpApplicationSessionProbe {
    private static final @NonNull String NAMESPACE = "fixture_totp_flow";
    private static final @NonNull String ACCOUNT = "fixture-account";
    private static final @NonNull String FIRST_KEY_ID = "fixture";
    private static final @NonNull Duration BUDGET = Duration.ofSeconds(20);

    private TotpApplicationSessionProbe() { }

    public static void main(java.lang.@NonNull String @NonNull [] args) throws Exception {
        if (args.length == 0) throw new IllegalArgumentException("Missing application probe command");
        String command = args[0];
        String epoch = env("REVETSEC_TEST_TOTP_EPOCH");
        String key = env("REVETSEC_TEST_TOTP_SEAL_KEY_BASE64");
        String activeKeyId = System.getenv().getOrDefault("REVETSEC_TEST_TOTP_ACTIVE_KEY_ID", FIRST_KEY_ID);
        @Nullable String oldKey = System.getenv("REVETSEC_TEST_TOTP_OLD_SEAL_KEY_BASE64");
        Map<String, String> openingKeys = oldKey == null
                ? Map.of(activeKeyId, key)
                : Map.of(activeKeyId, key, FIRST_KEY_ID, oldKey);
        TotpFixtureRecoveryGate gate = new TotpFixtureRecoveryGate(
                Path.of(env("REVETSEC_TEST_TOTP_MARKER")), Path.of(env("REVETSEC_TEST_TOTP_LOCK")),
                openingKeys);
        TotpApplicationSessionStore sessions = new TotpApplicationSessionStore(
                NAMESPACE, TotpApplicationSessionProbe::connection);
        FixtureClock appClock = new FixtureClock(
                Math.multiplyExact(Long.parseLong(env("REVETSEC_TEST_TOTP_NOW")), 1_000L));
        long deadline = System.nanoTime() + BUDGET.toNanos();
        String answer = unavailableFor(command);
        try (TotpRecoveryGate.Permit permit = gate.acquireApplicationOperation(NAMESPACE, epoch,
                activeKeyId, Set.copyOf(openingKeys.keySet()), BUDGET)) {
            if (permit != null && permit.isCurrent()) {
                answer = switch (command) {
                    case "seed" -> seed(args, epoch, key, activeKeyId, oldKey, gate,
                            sessions, appClock, deadline);
                    case "approve" -> writeAnswer("APPROVED", sessions.approve(epoch, ACCOUNT,
                            argument(args, 1), appClock.now(), remaining(deadline)));
                    case "session" -> readAnswer("SESSION", sessions.session(epoch,
                            argument(args, 1), appClock.now(), remaining(deadline)));
                    case "approval" -> readAnswer("APPROVAL", sessions.approval(epoch,
                            argument(args, 1), appClock.now(), remaining(deadline)));
                    case "pending" -> readAnswer("PENDING", sessions.pending(epoch,
                            argument(args, 1), appClock.now(), remaining(deadline)));
                    case "complete-totp", "complete-totp-unknown", "complete-totp-paused" ->
                            completeTotp(args, command, epoch, key, activeKeyId, oldKey,
                                    gate, sessions, permit, appClock, deadline);
                    case "complete-recovery", "complete-recovery-paused" ->
                            completeRecovery(args, command, epoch, key, activeKeyId,
                                    oldKey, gate, sessions, permit, appClock, deadline);
                    default -> throw new IllegalArgumentException("Unknown application probe command");
                };
                if (!permit.isCurrent()) answer = unavailableFor(command);
            }
        }
        if (deadline - System.nanoTime() <= 0) answer = unavailableFor(command);
        System.out.println(answer);
    }

    private static @NonNull String unavailableFor(@NonNull String command) {
        return switch (command) {
            case "seed" -> "SEED_UNAVAILABLE";
            case "approve", "approval" -> "APPROVAL_UNAVAILABLE";
            case "session" -> "SESSION_UNAVAILABLE";
            case "pending" -> "PENDING_UNAVAILABLE";
            default -> "COMPLETION_UNAVAILABLE";
        };
    }

    private static @NonNull String seed(java.lang.@NonNull String @NonNull [] args,
            @NonNull String epoch, @NonNull String key, @NonNull String activeKeyId,
            @Nullable String oldKey, @NonNull TotpFixtureRecoveryGate gate,
            @NonNull TotpApplicationSessionStore sessions, @NonNull FixtureClock appClock,
            long deadline) {
        TotpStatusResult status = authenticator(epoch, key, activeKeyId, oldKey, gate)
                .getStatusResult(ACCOUNT);
        if (!(status instanceof TotpStatusResult.Present present))
            return status instanceof TotpStatusResult.Absent ? "SEED_REJECTED" : "SEED_UNAVAILABLE";
        var factor = present.getStatus().getActiveFactor();
        if (factor.isEmpty()) return "SEED_REJECTED";
        return writeAnswer("SEEDED", sessions.seed(epoch, ACCOUNT, argument(args, 1),
                factor.orElseThrow().getFactorId(), appClock.now(), remaining(deadline)));
    }

    private static @NonNull String completeTotp(java.lang.@NonNull String @NonNull [] args,
            @NonNull String command, @NonNull String epoch, @NonNull String key,
            @NonNull String activeKeyId, @Nullable String oldKey,
            @NonNull TotpFixtureRecoveryGate gate, @NonNull TotpApplicationSessionStore sessions,
            TotpRecoveryGate.@NonNull Permit permit, @NonNull FixtureClock appClock,
            long deadline) throws IOException {
        String binding = argument(args, 1);
        String code = argument(args, 2);
        String oldCookie = argument(args, 3);
        String oldCsrf = argument(args, 4);
        TotpApplicationSessionStore.ReadResult admitted = sessions.admitPending(epoch, ACCOUNT,
                binding, oldCookie, oldCsrf, appClock.now(), remaining(deadline));
        if (admitted.outcome() != TotpApplicationSessionStore.ReadOutcome.ACTIVE)
            return admitted.outcome() == TotpApplicationSessionStore.ReadOutcome.REJECTED
                    ? "ADMISSION_REJECTED" : "ADMISSION_UNAVAILABLE";
        if (!permit.isCurrent()) return "COMPLETION_UNAVAILABLE";
        TotpAuthenticator totp = authenticator(epoch, key, activeKeyId, oldKey, gate);
        TotpVerificationResult proofResult = totp.verifyResult(ACCOUNT, code, binding);
        if (!(proofResult instanceof TotpVerificationResult.Succeeded success))
            return proofResult instanceof TotpVerificationResult.Rejected
                    || proofResult instanceof TotpVerificationResult.Throttled
                    ? "PROOF_REJECTED" : "PROOF_UNAVAILABLE";
        if (command.equals("complete-totp-paused")) {
            System.out.println("PROOF_READY");
            System.out.flush();
            awaitRelease(appClock);
        }
        if (!permit.isCurrent()) return "COMPLETION_UNAVAILABLE";
        if (command.equals("complete-totp-unknown")) sessions.failNextCommitAcknowledgement();
        return writeAnswer("COMPLETED", sessions.completeTotp(success.getVerification(),
                oldCookie, oldCsrf, appClock.now(), remaining(deadline)));
    }

    private static @NonNull String completeRecovery(java.lang.@NonNull String @NonNull [] args,
            @NonNull String command, @NonNull String epoch, @NonNull String key,
            @NonNull String activeKeyId,
            @Nullable String oldKey, @NonNull TotpFixtureRecoveryGate gate,
            @NonNull TotpApplicationSessionStore sessions,
            TotpRecoveryGate.@NonNull Permit permit, @NonNull FixtureClock appClock,
            long deadline) throws IOException {
        String binding = argument(args, 1);
        String oldCookie = argument(args, 3);
        String oldCsrf = argument(args, 4);
        TotpApplicationSessionStore.ReadResult admitted = sessions.admitPending(epoch, ACCOUNT,
                binding, oldCookie, oldCsrf, appClock.now(), remaining(deadline));
        if (admitted.outcome() != TotpApplicationSessionStore.ReadOutcome.ACTIVE)
            return admitted.outcome() == TotpApplicationSessionStore.ReadOutcome.REJECTED
                    ? "ADMISSION_REJECTED" : "ADMISSION_UNAVAILABLE";
        if (!permit.isCurrent()) return "COMPLETION_UNAVAILABLE";
        TotpAuthenticator totp = authenticator(epoch, key, activeKeyId, oldKey, gate);
        RecoveryCodeUseResult proofResult = totp.consumeRecoveryCodeResult(ACCOUNT,
                argument(args, 2), binding);
        if (!(proofResult instanceof RecoveryCodeUseResult.Succeeded success))
            return proofResult instanceof RecoveryCodeUseResult.Rejected
                    || proofResult instanceof RecoveryCodeUseResult.Throttled
                    ? "PROOF_REJECTED" : "PROOF_UNAVAILABLE";
        if (command.equals("complete-recovery-paused")) {
            System.out.println("PROOF_READY");
            System.out.flush();
            awaitRelease(appClock);
        }
        if (!permit.isCurrent()) return "COMPLETION_UNAVAILABLE";
        return writeAnswer("RECOVERY_COMPLETED", sessions.completeRecovery(success.getUse(),
                oldCookie, oldCsrf, appClock.now(), remaining(deadline)));
    }

    private static void awaitRelease(@NonNull FixtureClock appClock) throws IOException {
        String command = new BufferedReader(new InputStreamReader(System.in,
                StandardCharsets.US_ASCII)).readLine();
        if ("go".equals(command)) return;
        if (command != null && command.startsWith("go ")) {
            long advanceMs = Long.parseLong(command.substring(3));
            if (advanceMs < 0 || advanceMs > Duration.ofMinutes(6).toMillis())
                throw new IllegalArgumentException("Invalid fixture clock advance");
            appClock.advance(advanceMs);
            return;
        }
        throw new IllegalStateException("Application completion barrier closed");
    }

    /** Explicitly controlled fixture clock; application time is re-read at completion. */
    @NotThreadSafe
    private static final class FixtureClock {
        private final long baseNowMs;
        private long advanceMs;
        private FixtureClock(long baseNowMs) { this.baseNowMs = baseNowMs; }
        private long now() { return Math.addExact(this.baseNowMs, this.advanceMs); }
        private void advance(long milliseconds) { this.advanceMs = milliseconds; }
    }

    private static @NonNull TotpAuthenticator authenticator(@NonNull String epoch,
            @NonNull String key, @NonNull String activeKeyId, @Nullable String oldKey,
            @NonNull TotpFixtureRecoveryGate gate) {
        PostgresqlTotpStore store = new PostgresqlTotpStore(NAMESPACE,
                TotpApplicationSessionProbe::connection, 4_096, 64L * 1024 * 1024);
        StateSealer.Builder sealer = StateSealer.withActiveKey(SealingKey.fromBase64(activeKeyId, key));
        if (oldKey != null) sealer.verificationKeys(List.of(SealingKey.fromBase64(FIRST_KEY_ID, oldKey)));
        return TotpAuthenticator.withIssuer("Fixture").credentialNamespace(NAMESPACE)
                .recoveryEpoch(epoch).store(store).stateSealer(sealer.build())
                .recoveryGate(gate).clock(Clock.fixed(Instant.ofEpochMilli(nowMs()), ZoneOffset.UTC))
                .build();
    }

    private static long nowMs() {
        return Math.multiplyExact(Long.parseLong(env("REVETSEC_TEST_TOTP_NOW")), 1_000L);
    }

    private static @NonNull String writeAnswer(@NonNull String prefix,
            TotpApplicationSessionStore.@NonNull WriteResult result) {
        return switch (result.outcome()) {
            case COMMITTED -> {
                TotpApplicationSessionStore.Receipt receipt = requireNonNull(result.receipt());
                if (prefix.equals("SEEDED")) yield prefix + " " + receipt.cookie() + " "
                        + receipt.csrf();
                if (prefix.equals("APPROVED")) yield prefix + " " + requireNonNull(receipt.approval());
                yield prefix + " " + receipt.cookie() + " " + receipt.csrf();
            }
            case REJECTED -> prefix.equals("SEEDED") ? "SEED_REJECTED"
                    : prefix.equals("APPROVED") ? "APPROVAL_REJECTED" : "COMPLETION_REJECTED";
            case UNKNOWN -> prefix.equals("SEEDED") ? "SEED_UNKNOWN"
                    : prefix.equals("APPROVED") ? "APPROVAL_UNKNOWN" : "COMPLETION_UNKNOWN";
            case UNAVAILABLE -> prefix.equals("SEEDED") ? "SEED_UNAVAILABLE"
                    : prefix.equals("APPROVED") ? "APPROVAL_UNAVAILABLE" : "COMPLETION_UNAVAILABLE";
        };
    }

    private static @NonNull String readAnswer(@NonNull String prefix,
            TotpApplicationSessionStore.@NonNull ReadResult result) {
        return switch (result.outcome()) {
            case ACTIVE -> prefix.equals("PENDING") ? "PENDING" : prefix + "_ACTIVE"
                    + (prefix.equals("SESSION") ? " " + requireNonNull(result.kind()) : "");
            case CONSUMED -> "CONSUMED";
            case REJECTED -> prefix + "_REJECTED";
            case UNAVAILABLE -> prefix + "_UNAVAILABLE";
        };
    }

    private static @NonNull Duration remaining(long deadline) {
        return Duration.ofNanos(Math.max(1L, deadline - System.nanoTime()));
    }

    private static @NonNull Connection connection(@NonNull Duration remaining) throws SQLException {
        int seconds = Math.max(1, (int) Math.min(30, (remaining.toMillis() + 999) / 1_000));
        Properties properties = new Properties();
        properties.setProperty("user", env("REVETSEC_TEST_DB_USER"));
        properties.setProperty("password", env("REVETSEC_TEST_DB_PASSWORD"));
        properties.setProperty("connectTimeout", Integer.toString(seconds));
        properties.setProperty("socketTimeout", Integer.toString(seconds));
        properties.setProperty("gssEncMode", "disable");
        return DriverManager.getConnection(env("REVETSEC_TEST_DB_URL"), properties);
    }

    private static @NonNull String argument(java.lang.@NonNull String @NonNull [] args, int index) {
        if (index >= args.length || args[index].isEmpty())
            throw new IllegalArgumentException("Missing application probe argument");
        return args[index];
    }

    private static @NonNull String env(@NonNull String name) {
        return requireNonNull(System.getenv(name), "Missing application probe environment");
    }
}
