/*
 * Copyright 2026 Revetware LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package example.pending;

import com.pyranid.Database;
import com.pyranid.DatabaseType;
import com.pyranid.TransactionIsolation;
import com.pyranid.TransactionOptions;
import com.pyranid.TransactionResult;
import com.revetsec.totp.RecoveryCodeUse;
import com.revetsec.totp.TotpAuthenticationMethod;
import com.revetsec.totp.TotpVerification;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.util.Objects.requireNonNull;

/**
 * Unpublished, test-only application session/approval store. Core never sees these rows. Every
 * operation takes the TOTP namespace lock and checks the active epoch in the same transaction;
 * the caller separately holds the external application recovery admission permit. A real app
 * must supply its own primary authentication, session policy, clock and account controls.
 */
@ThreadSafe
final class TotpApplicationSessionStore {
    @Immutable enum Outcome { COMMITTED, REJECTED, UNKNOWN, UNAVAILABLE }
    @Immutable enum ReadOutcome { ACTIVE, CONSUMED, REJECTED, UNAVAILABLE }

    @Immutable
    record Receipt(@NonNull String cookie, @NonNull String csrf, @Nullable String approval) {
        @Override public @NonNull String toString() { return "Receipt{<redacted>}"; }
    }

    @Immutable
    record WriteResult(@NonNull Outcome outcome, @Nullable Receipt receipt) {
        WriteResult {
            if ((outcome == Outcome.COMMITTED) != (receipt != null))
                throw new IllegalArgumentException("Only confirmed commits carry credentials");
        }
        static @NonNull WriteResult committed(@NonNull Receipt receipt) {
            return new WriteResult(Outcome.COMMITTED, receipt);
        }
        static @NonNull WriteResult rejected() { return new WriteResult(Outcome.REJECTED, null); }
        static @NonNull WriteResult unknown() { return new WriteResult(Outcome.UNKNOWN, null); }
        static @NonNull WriteResult unavailable() { return new WriteResult(Outcome.UNAVAILABLE, null); }
        @Override public @NonNull String toString() { return "WriteResult{outcome=" + outcome + "}"; }
    }

    @Immutable
    record ReadResult(@NonNull ReadOutcome outcome, @Nullable String kind) {
        static @NonNull ReadResult active(@NonNull String kind) {
            return new ReadResult(ReadOutcome.ACTIVE, kind);
        }
        static @NonNull ReadResult consumed() { return new ReadResult(ReadOutcome.CONSUMED, null); }
        static @NonNull ReadResult rejected() { return new ReadResult(ReadOutcome.REJECTED, null); }
        static @NonNull ReadResult unavailable() { return new ReadResult(ReadOutcome.UNAVAILABLE, null); }
    }

    @Immutable
    public record SessionRow(@NonNull String recoveryEpoch, @NonNull String accountId,
            @NonNull String kind, @NonNull String csrfHash, long expiresAtMs, boolean revoked) {
        @Override public @NonNull String toString() { return "SessionRow{<redacted>}"; }
    }

    @Immutable
    public record PendingRow(@NonNull String recoveryEpoch, @NonNull String accountId,
            @NonNull String expectedFactorId, @NonNull String oldSessionHash,
            @NonNull String oldCsrfHash,
            long expiresAtMs, boolean consumed) {
        @Override public @NonNull String toString() { return "PendingRow{<redacted>}"; }
    }

    @Immutable
    public record ApprovalRow(@NonNull String recoveryEpoch, @NonNull String accountId,
            @NonNull String sessionHash, long expiresAtMs, boolean consumed) {
        @Override public @NonNull String toString() { return "ApprovalRow{<redacted>}"; }
    }

    @Immutable
    public record ClockRow(long lastSeenMs) { }

    private static final @NonNull Duration SESSION_LIFETIME = Duration.ofHours(1);
    private static final @NonNull Duration PENDING_LIFETIME = Duration.ofMinutes(5);
    private static final @NonNull Duration APPROVAL_LIFETIME = Duration.ofMinutes(5);
    private final @NonNull String namespace;
    private final PostgresqlTotpStore.@NonNull ConnectionSource source;
    private final @NonNull SecureRandom random = new SecureRandom();
    private final @NonNull AtomicBoolean loseNextAcknowledgement = new AtomicBoolean();

    TotpApplicationSessionStore(@NonNull String namespace,
            PostgresqlTotpStore.@NonNull ConnectionSource source) {
        this.namespace = requireNonNull(namespace);
        this.source = requireNonNull(source);
    }

    /** Simulates a lost application COMMIT acknowledgement after the actual transaction commits. */
    void failNextCommitAcknowledgement() { this.loseNextAcknowledgement.set(true); }

    /** Synthetic primary-authenticated pending login; never use this as application auth code. */
    @NonNull WriteResult seed(@NonNull String epoch, @NonNull String account,
            @NonNull String binding, @NonNull String expectedFactorId,
            long nowMs, @NonNull Duration budget) {
        String cookie = token();
        String csrf = token();
        String cookieHash = hash(cookie);
        String csrfHash = hash(csrf);
        return write(epoch, nowMs, budget, (database, deadline, attempted) -> {
            attempted.value = true;
            execute(database, deadline, "INSERT INTO totp_app_session"
                    + "(namespace,session_hash,recovery_epoch,account_id,kind,csrf_hash,expires_at_ms) "
                    + "VALUES (:namespace,:session,:epoch,:account,'PRIMARY',:csrf,:expires)",
                    "namespace", this.namespace, "session", cookieHash, "epoch", epoch,
                    "account", account, "csrf", csrfHash,
                    "expires", nowMs + SESSION_LIFETIME.toMillis());
            execute(database, deadline, "INSERT INTO totp_app_pending_login"
                    + "(namespace,operation_binding,recovery_epoch,account_id,expected_factor_id,"
                    + "old_session_hash,old_csrf_hash,expires_at_ms) VALUES "
                    + "(:namespace,:binding,:epoch,:account,:factor,:session,:csrf,:expires)",
                    "namespace", this.namespace, "binding", binding, "epoch", epoch,
                    "account", account, "factor", expectedFactorId,
                    "session", cookieHash, "csrf", csrfHash,
                    "expires", nowMs + PENDING_LIFETIME.toMillis());
            return WriteResult.committed(new Receipt(cookie, csrf, null));
        });
    }

    /** Test-only barrier runs after the final session write, before this transaction commits. */
    @NonNull WriteResult completeTotp(@NonNull TotpVerification proof,
            @NonNull String oldCookie, @NonNull String oldCsrf,
            long nowMs, @NonNull Duration budget, @Nullable Runnable beforeCommit) {
        if (proof.getMethod() != TotpAuthenticationMethod.TOTP) return WriteResult.rejected();
        return complete(proof.getCredentialNamespace(), proof.getRecoveryEpoch(),
                proof.getAccountId(), proof.getOperationBinding(), proof.getFactorId(),
                "TOTP", oldCookie, oldCsrf,
                nowMs, budget, beforeCommit);
    }

    @NonNull WriteResult completeRecovery(@NonNull RecoveryCodeUse proof,
            @NonNull String oldCookie, @NonNull String oldCsrf,
            long nowMs, @NonNull Duration budget) {
        if (proof.getMethod() != TotpAuthenticationMethod.RECOVERY_CODE) return WriteResult.rejected();
        return complete(proof.getCredentialNamespace(), proof.getRecoveryEpoch(),
                proof.getAccountId(), proof.getOperationBinding(), proof.getFactorId(),
                "RECOVERY_CODE", oldCookie,
                oldCsrf, nowMs, budget, null);
    }

    private @NonNull WriteResult complete(@NonNull String proofNamespace,
            @NonNull String epoch, @NonNull String account, @NonNull String binding,
            @NonNull String factorId, @NonNull String method, @NonNull String oldCookie,
            @NonNull String oldCsrf,
            long nowMs, @NonNull Duration budget, @Nullable Runnable beforeCommit) {
        if (!this.namespace.equals(proofNamespace)) return WriteResult.rejected();
        String oldSessionHash = hash(oldCookie);
        String oldCsrfHash = hash(oldCsrf);
        String newCookie = token();
        String newCsrf = token();
        String newSessionHash = hash(newCookie);
        String newCsrfHash = hash(newCsrf);
        return write(epoch, nowMs, budget, (database, deadline, attempted) -> {
            PendingRow pending = pendingRow(database, deadline, binding).orElse(null);
            if (pending == null || pending.consumed() || nowMs >= pending.expiresAtMs()
                    || !pending.recoveryEpoch().equals(epoch)
                    || !pending.accountId().equals(account)
                    || !pending.expectedFactorId().equals(factorId)
                    || !pending.oldSessionHash().equals(oldSessionHash)
                    || !pending.oldCsrfHash().equals(oldCsrfHash)) return WriteResult.rejected();
            SessionRow oldSession = sessionRow(database, deadline, oldSessionHash).orElse(null);
            if (oldSession == null || oldSession.revoked() || nowMs >= oldSession.expiresAtMs()
                    || !oldSession.recoveryEpoch().equals(epoch)
                    || !oldSession.accountId().equals(account)
                    || !oldSession.kind().equals("PRIMARY")
                    || !oldSession.csrfHash().equals(oldCsrfHash)) return WriteResult.rejected();
            attempted.value = true;
            execute(database, deadline, "UPDATE totp_app_pending_login SET consumed=true "
                    + "WHERE namespace=:namespace AND operation_binding=:binding AND consumed=false",
                    "namespace", this.namespace, "binding", binding);
            execute(database, deadline, "UPDATE totp_app_session SET revoked=true "
                    + "WHERE namespace=:namespace AND session_hash=:session AND revoked=false",
                    "namespace", this.namespace, "session", oldSessionHash);
            execute(database, deadline, "UPDATE totp_app_approval SET consumed=true "
                    + "WHERE namespace=:namespace AND session_hash=:session AND consumed=false",
                    "namespace", this.namespace, "session", oldSessionHash);
            execute(database, deadline, "INSERT INTO totp_app_session"
                    + "(namespace,session_hash,recovery_epoch,account_id,kind,csrf_hash,expires_at_ms) "
                    + "VALUES (:namespace,:session,:epoch,:account,:kind,:csrf,:expires)",
                    "namespace", this.namespace, "session", newSessionHash, "epoch", epoch,
                    "account", account, "kind", method, "csrf", newCsrfHash,
                    "expires", nowMs + SESSION_LIFETIME.toMillis());
            if (beforeCommit != null) beforeCommit.run();
            return WriteResult.committed(new Receipt(newCookie, newCsrf, null));
        });
    }

    @NonNull WriteResult approve(@NonNull String epoch, @NonNull String account,
            @NonNull String cookie, long nowMs, @NonNull Duration budget) {
        String sessionHash = hash(cookie);
        String approval = token();
        return write(epoch, nowMs, budget, (database, deadline, attempted) -> {
            SessionRow session = sessionRow(database, deadline, sessionHash).orElse(null);
            if (session == null || session.revoked() || nowMs >= session.expiresAtMs()
                    || !session.accountId().equals(account)
                    || !session.recoveryEpoch().equals(epoch)
                    || !session.kind().equals("TOTP")) return WriteResult.rejected();
            attempted.value = true;
            execute(database, deadline, "INSERT INTO totp_app_approval"
                    + "(namespace,approval_hash,recovery_epoch,account_id,session_hash,expires_at_ms) "
                    + "VALUES (:namespace,:approval,:epoch,:account,:session,:expires)",
                    "namespace", this.namespace, "approval", hash(approval), "epoch", epoch,
                    "account", account, "session", sessionHash,
                    "expires", nowMs + APPROVAL_LIFETIME.toMillis());
            return WriteResult.committed(new Receipt("", "", approval));
        });
    }

    /** Admission precedes any OTP or recovery-code work; completion repeats every predicate. */
    @NonNull ReadResult admitPending(@NonNull String epoch, @NonNull String account,
            @NonNull String binding, @NonNull String oldCookie, @NonNull String oldCsrf,
            long nowMs, @NonNull Duration budget) {
        String sessionHash = hash(oldCookie);
        String csrfHash = hash(oldCsrf);
        return read(epoch, nowMs, budget, (database, deadline) -> {
            PendingRow pending = pendingRow(database, deadline, binding).orElse(null);
            if (pending == null || pending.consumed() || nowMs >= pending.expiresAtMs()
                    || !pending.recoveryEpoch().equals(epoch)
                    || !pending.accountId().equals(account)
                    || !pending.oldSessionHash().equals(sessionHash)
                    || !pending.oldCsrfHash().equals(csrfHash)) return ReadResult.rejected();
            SessionRow session = sessionRow(database, deadline, sessionHash).orElse(null);
            return session != null && !session.revoked() && nowMs < session.expiresAtMs()
                    && session.recoveryEpoch().equals(epoch)
                    && session.accountId().equals(account)
                    && session.kind().equals("PRIMARY")
                    && session.csrfHash().equals(csrfHash)
                    ? ReadResult.active("PENDING") : ReadResult.rejected();
        });
    }

    @NonNull ReadResult session(@NonNull String epoch, @NonNull String cookie,
            long nowMs, @NonNull Duration budget) {
        return read(epoch, nowMs, budget, (database, deadline) -> {
            SessionRow row = sessionRow(database, deadline, hash(cookie)).orElse(null);
            return row != null && row.recoveryEpoch().equals(epoch)
                    && !row.revoked() && nowMs < row.expiresAtMs()
                    ? ReadResult.active(row.kind()) : ReadResult.rejected();
        });
    }

    @NonNull ReadResult approval(@NonNull String epoch, @NonNull String approval,
            long nowMs, @NonNull Duration budget) {
        return read(epoch, nowMs, budget, (database, deadline) -> {
            PostgresqlPyranidDataSource.bound(database, deadline);
            ApprovalRow row = database.query("SELECT recovery_epoch,account_id,session_hash,"
                    + "expires_at_ms,consumed FROM totp_app_approval "
                    + "WHERE namespace=:namespace AND approval_hash=:approval")
                    .bind("namespace", this.namespace).bind("approval", hash(approval))
                    .fetchObject(ApprovalRow.class).orElse(null);
            if (row == null || row.consumed() || nowMs >= row.expiresAtMs()
                    || !row.recoveryEpoch().equals(epoch)) return ReadResult.rejected();
            SessionRow session = sessionRow(database, deadline, row.sessionHash()).orElse(null);
            return session != null && !session.revoked() && nowMs < session.expiresAtMs()
                    && session.recoveryEpoch().equals(epoch)
                    && session.accountId().equals(row.accountId())
                    && session.kind().equals("TOTP")
                    ? ReadResult.active("APPROVAL") : ReadResult.rejected();
        });
    }

    @NonNull ReadResult pending(@NonNull String epoch, @NonNull String binding,
            long nowMs, @NonNull Duration budget) {
        return read(epoch, nowMs, budget, (database, deadline) -> {
            PendingRow row = pendingRow(database, deadline, binding).orElse(null);
            if (row == null || !row.recoveryEpoch().equals(epoch)
                    || nowMs >= row.expiresAtMs()) return ReadResult.rejected();
            if (row.consumed()) return ReadResult.consumed();
            SessionRow session = sessionRow(database, deadline, row.oldSessionHash()).orElse(null);
            return session != null && !session.revoked() && nowMs < session.expiresAtMs()
                    && session.recoveryEpoch().equals(epoch)
                    && session.accountId().equals(row.accountId())
                    && session.kind().equals("PRIMARY")
                    ? ReadResult.active("PENDING") : ReadResult.rejected();
        });
    }

    private @NonNull Optional<@NonNull SessionRow> sessionRow(@NonNull Database database,
            long deadline, @NonNull String sessionHash) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        return database.query("SELECT recovery_epoch,account_id,kind,csrf_hash,expires_at_ms,revoked "
                + "FROM totp_app_session WHERE namespace=:namespace AND session_hash=:session")
                .bind("namespace", this.namespace).bind("session", sessionHash)
                .fetchObject(SessionRow.class);
    }

    private @NonNull Optional<@NonNull PendingRow> pendingRow(@NonNull Database database,
            long deadline, @NonNull String binding) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        return database.query("SELECT recovery_epoch,account_id,expected_factor_id,"
                + "old_session_hash,old_csrf_hash,"
                + "expires_at_ms,consumed FROM totp_app_pending_login "
                + "WHERE namespace=:namespace AND operation_binding=:binding")
                .bind("namespace", this.namespace).bind("binding", binding)
                .fetchObject(PendingRow.class);
    }

    private boolean active(@NonNull Database database, long deadline, @NonNull String epoch,
            long nowMs) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        PostgresqlTotpStore.NamespaceRow row = database.query("SELECT active_epoch,activation_state "
                + "FROM totp_store_namespace WHERE namespace=:namespace FOR UPDATE")
                .bind("namespace", this.namespace)
                .fetchObject(PostgresqlTotpStore.NamespaceRow.class).orElseThrow();
        if (!row.activeEpoch().equals(epoch) || !row.activationState().equals("ACTIVATED"))
            return false;
        if (nowMs < 0) throw new SQLException("Invalid application time");
        PostgresqlPyranidDataSource.bound(database, deadline);
        ClockRow clock = database.query("SELECT last_seen_ms FROM totp_app_clock "
                + "WHERE namespace=:namespace AND recovery_epoch=:epoch")
                .bind("namespace", this.namespace).bind("epoch", epoch)
                .fetchObject(ClockRow.class).orElse(null);
        if (clock == null) {
            PostgresqlPyranidDataSource.bound(database, deadline);
            long inserted = database.query("INSERT INTO totp_app_clock"
                    + "(namespace,recovery_epoch,last_seen_ms) VALUES (:namespace,:epoch,:now)")
                    .bind("namespace", this.namespace).bind("epoch", epoch)
                    .bind("now", nowMs).execute();
            if (inserted != 1) throw new SQLException("Application clock fence was not inserted");
        } else {
            if (nowMs < clock.lastSeenMs())
                throw new SQLException("Application clock moved backward");
            if (nowMs > clock.lastSeenMs()) {
                PostgresqlPyranidDataSource.bound(database, deadline);
                long changed = database.query("UPDATE totp_app_clock SET last_seen_ms=:now "
                        + "WHERE namespace=:namespace AND recovery_epoch=:epoch "
                        + "AND last_seen_ms<:now")
                        .bind("now", nowMs).bind("namespace", this.namespace)
                        .bind("epoch", epoch).execute();
                if (changed != 1) throw new SQLException("Application clock fence lost its row");
            }
        }
        return true;
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

    private @NonNull WriteResult write(@NonNull String epoch, long nowMs,
            @NonNull Duration budget,
            @NonNull WriteWork work) {
        long deadline = deadline(budget);
        if (deadline == 0) return WriteResult.unavailable();
        Completion completion = new Completion();
        Attempt attempted = new Attempt();
        try {
            Database database = database(deadline);
            Optional<WriteResult> result = database.transaction(options(), () -> {
                database.currentTransaction().orElseThrow()
                        .addPostTransactionOperation(value -> completion.result = value);
                configure(database, deadline);
                if (!active(database, deadline, epoch, nowMs))
                    return Optional.of(WriteResult.rejected());
                return Optional.of(work.apply(database, deadline, attempted));
            });
            if (completion.result == TransactionResult.COMMITTED && !expired(deadline)) {
                WriteResult reported = result.orElseThrow();
                if (reported.outcome() == Outcome.COMMITTED
                        && this.loseNextAcknowledgement.getAndSet(false)) return WriteResult.unknown();
                return reported;
            }
        } catch (RuntimeException failure) {
            // A failed acknowledgement or timeout after the first write may conceal a COMMIT.
        }
        return attempted.value ? WriteResult.unknown() : WriteResult.unavailable();
    }

    private @NonNull ReadResult read(@NonNull String epoch, long nowMs,
            @NonNull Duration budget,
            @NonNull ReadWork work) {
        long deadline = deadline(budget);
        if (deadline == 0) return ReadResult.unavailable();
        Completion completion = new Completion();
        try {
            Database database = database(deadline);
            Optional<ReadResult> result = database.transaction(options(), () -> {
                database.currentTransaction().orElseThrow()
                        .addPostTransactionOperation(value -> completion.result = value);
                configure(database, deadline);
                if (!active(database, deadline, epoch, nowMs))
                    return Optional.of(ReadResult.rejected());
                return Optional.of(work.apply(database, deadline));
            });
            if (completion.result == TransactionResult.COMMITTED && !expired(deadline))
                return result.orElseThrow();
        } catch (RuntimeException failure) {
            // An incomplete read is never evidence of absence or a valid session.
        }
        return ReadResult.unavailable();
    }

    private static void execute(@NonNull Database database, long deadline, @NonNull String sql,
            @NonNull Object @NonNull ... bindings) throws SQLException {
        PostgresqlPyranidDataSource.bound(database, deadline);
        var query = database.query(sql);
        for (int index = 0; index < bindings.length; index += 2)
            query.bind((String) bindings[index], bindings[index + 1]);
        long rows = query.execute();
        if (rows != 1 && !sql.startsWith("UPDATE totp_app_approval"))
            throw new SQLException("Application session write did not affect exactly one row");
    }

    private @NonNull String token() {
        byte[] bytes = new byte[32];
        this.random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static @NonNull String hash(@NonNull String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 unavailable", impossible);
        }
    }

    private static long deadline(@NonNull Duration budget) {
        requireNonNull(budget);
        if (budget.isZero() || budget.isNegative() || Thread.currentThread().isInterrupted()) return 0;
        return System.nanoTime() + Math.min(Duration.ofSeconds(10).toNanos(), budget.toNanos());
    }

    private static boolean expired(long deadline) {
        return deadline - System.nanoTime() <= 0 || Thread.currentThread().isInterrupted();
    }

    @FunctionalInterface private interface WriteWork {
        @NonNull WriteResult apply(@NonNull Database database, long deadline,
                @NonNull Attempt attempted) throws SQLException;
    }
    @FunctionalInterface private interface ReadWork {
        @NonNull ReadResult apply(@NonNull Database database, long deadline) throws SQLException;
    }
    @NotThreadSafe private static final class Completion { private @Nullable TransactionResult result; }
    @NotThreadSafe private static final class Attempt { private boolean value; }
}
