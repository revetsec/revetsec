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
package example.totp;

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.json.JsonString;
import com.revetsec.totp.RecoveryCodeRotationResult;
import com.revetsec.totp.RecoveryCodeUse;
import com.revetsec.totp.RecoveryCodeUseResult;
import com.revetsec.totp.RecoveryCodes;
import com.revetsec.totp.TotpAuthenticator;
import com.revetsec.totp.TotpEnrollment;
import com.revetsec.totp.TotpEnrollmentCancellationResult;
import com.revetsec.totp.TotpEnrollmentOptions;
import com.revetsec.totp.TotpEnrollmentRequestResult;
import com.revetsec.totp.TotpEnrollmentResult;
import com.revetsec.totp.TotpFactor;
import com.revetsec.totp.TotpFactorRemovalResult;
import com.revetsec.totp.TotpPendingEnrollment;
import com.revetsec.totp.TotpStatus;
import com.revetsec.totp.TotpStatusResult;
import com.revetsec.totp.TotpVerification;
import com.revetsec.totp.TotpVerificationResult;
import com.soklet.HttpServer;
import com.soklet.InstanceProvider;
import com.soklet.MarshaledResponse;
import com.soklet.Request;
import com.soklet.ResourceMethodResolver;
import com.soklet.ResponseCookie;
import com.soklet.Soklet;
import com.soklet.SokletConfig;
import com.soklet.annotation.GET;
import com.soklet.annotation.HEAD;
import com.soklet.annotation.POST;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Complete Soklet 4 route integration. Account/session policy, input admission and the recovery
 * controller are injected application responsibilities; this class supplies no demonstration
 * authentication bypass or default recovery gate. Responses use the default Soklet marshaler.
 */
@ThreadSafe
public final class TotpApplication {
    private static final @NonNull Duration REQUEST_BUDGET = Duration.ofSeconds(10);
    private final @NonNull TotpAuthenticator totp;
    private final @NonNull String recoveryEpoch;
    private final @NonNull ApplicationSecurity security;
    private final @NonNull LongSupplier monotonicNanos;

    /** The authenticator and security implementation must share one coordinated recovery gate. */
    public TotpApplication(@NonNull TotpAuthenticator totp,
            @NonNull ApplicationSecurity security) {
        this(totp, security, System::nanoTime);
    }

    /** Package-scoped clock seam keeps the request-deadline regression deterministic. */
    TotpApplication(@NonNull TotpAuthenticator totp,
            @NonNull ApplicationSecurity security, @NonNull LongSupplier monotonicNanos) {
        this.totp = Objects.requireNonNull(totp);
        this.recoveryEpoch = totp.getRecoveryEpoch();
        this.security = Objects.requireNonNull(security);
        this.monotonicNanos = Objects.requireNonNull(monotonicNanos);
    }

    /** Runs an injected application behind an application-managed HTTPS edge. */
    public static void run(@NonNull TotpAuthenticator totp,
            @NonNull ApplicationSecurity security, @NonNull Integer port) throws Exception {
        TotpApplication app = new TotpApplication(totp, security);
        try (Soklet soklet = Soklet.fromConfig(config(app, port))) {
            soklet.start();
            soklet.awaitShutdown();
        }
    }

    /** Creates an actual Soklet 4 server configuration with its default response marshaler. */
    public static @NonNull SokletConfig config(@NonNull TotpApplication app, @NonNull Integer port) {
        Objects.requireNonNull(app);
        if (port < 1 || port > 65_535) throw new IllegalArgumentException("Invalid HTTP port");
        HttpServer server = HttpServer.withPort(port).host("127.0.0.1")
                .maximumRequestBodySizeInBytes(4_096).maximumRequestSizeInBytes(12_288)
                .requestHandlerTimeout(Duration.ofSeconds(15)).requestHandlerConcurrency(32)
                .requestHandlerQueueCapacity(64).build();
        return SokletConfig.withHttpServer(server)
                .resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(TotpApplication.class)))
                .instanceProvider(new InstanceProvider() {
                    @Override public <@NonNull T> @NonNull T provide(@NonNull Class<@NonNull T> type) {
                        return type.equals(TotpApplication.class) ? type.cast(app)
                                : InstanceProvider.defaultInstance().provide(type);
                    }
                }).build();
    }

    @POST("/account/totp/enrollment")
    public @NonNull MarshaledResponse beginEnrollment(@NonNull Request request) {
        return admitted(request, () -> {
            EnrollmentContext context = this.security.admitEnrollment(request, false);
            if (context == null) return denied();
            return prepare(context, false);
        });
    }

    @POST("/account/totp/replacement")
    public @NonNull MarshaledResponse beginReplacement(@NonNull Request request) {
        return admitted(request, () -> {
            EnrollmentContext context = this.security.admitEnrollment(request, true);
            if (context == null) return denied();
            return prepare(context, true);
        });
    }

    private @NonNull MarshaledResponse prepare(@NonNull EnrollmentContext context, boolean replacement) {
        TotpEnrollmentOptions.Builder options = TotpEnrollmentOptions
                .withAccountId(context.getAccountId()).accountName(context.getAccountLabel());
        if (replacement) {
            String expectedFactor = context.getReplacingFactorId().orElse(null);
            if (expectedFactor == null) return denied();
            options = options.replacingFactorId(expectedFactor);
        } else if (context.getReplacingFactorId().isPresent()) {
            return denied();
        }
        TotpEnrollmentRequestResult result = this.totp.beginEnrollmentResult(
                options.build(), context.getBrowserBinding());
        if (result instanceof TotpEnrollmentRequestResult.Prepared prepared) {
            TotpEnrollment enrollment = prepared.getEnrollment();
            // Persist only identifiers before releasing the setup secret. The URI/manual key must
            // never enter application session storage, logs, telemetry or a third-party QR service.
            if (!this.security.rememberEnrollment(context, enrollment.getEnrollmentId(),
                    enrollment.getFactorId(), enrollment.getExpiresAt())) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            return json(200, JsonObject.builder()
                    .put("enrollmentId", enrollment.getEnrollmentId())
                    .put("factorId", enrollment.getFactorId())
                    .put("expiresAt", enrollment.getExpiresAt().toString())
                    .put("provisioningUri", enrollment.getProvisioningUri())
                    .put("manualEntryKey", enrollment.getManualEntryKey()).build());
        }
        if (result instanceof TotpEnrollmentRequestResult.Throttled throttled)
            return throttled(throttled.getRetryAfter());
        if (result instanceof TotpEnrollmentRequestResult.ReconciliationRequired) {
            this.security.requireReconciliation(context);
            return unavailable();
        }
        if (result instanceof TotpEnrollmentRequestResult.Indeterminate) {
            this.security.requireReconciliation(context);
            return unavailable();
        }
        return result instanceof TotpEnrollmentRequestResult.Unavailable ? unavailable() : denied();
    }

    @POST("/account/totp/confirm")
    public @NonNull MarshaledResponse confirmEnrollment(@NonNull Request request) {
        return admitted(request, () -> {
            EnrollmentSubmission input = this.security.admitEnrollmentConfirmation(request);
            if (input == null) return denied();
            TotpEnrollmentResult result = this.totp.confirmEnrollmentResult(input.getAccountId(),
                    input.getEnrollmentId(), input.getCode(), input.getBrowserBinding());
            if (result instanceof TotpEnrollmentResult.Succeeded success) {
                if (!this.recoveryEpoch.equals(success.getFactor().getRecoveryEpoch())
                        || !this.security.completeEnrollment(input, success.getFactor(),
                            success.getRecoveryCodes().getBatchId())) {
                    this.security.requireReconciliation(input);
                    return unavailable();
                }
                return json(200, JsonObject.builder().put("factor", factor(success.getFactor()))
                        .put("recoveryCodes", recoveryCodes(success.getRecoveryCodes())).build());
            }
            if (result instanceof TotpEnrollmentResult.Throttled throttled)
                return throttled(throttled.getRetryAfter());
            if (result instanceof TotpEnrollmentResult.ReconciliationRequired) {
                this.security.requireReconciliation(input);
                return unavailable();
            }
            if (result instanceof TotpEnrollmentResult.Indeterminate) {
                this.security.requireReconciliation(input);
                return unavailable();
            }
            return result instanceof TotpEnrollmentResult.Unavailable ? unavailable() : denied();
        });
    }

    @POST("/login/totp")
    public @NonNull MarshaledResponse verifyTotp(@NonNull Request request) {
        return admitted(request, () -> {
            LoginSubmission input = this.security.admitTotpLogin(request);
            if (input == null) return denied();
            TotpVerificationResult result = this.totp.verifyResult(input.getAccountId(),
                    input.getCode(), input.getOperationBinding());
            if (result instanceof TotpVerificationResult.Succeeded success) {
                TotpVerification proof = success.getVerification();
                if (!this.recoveryEpoch.equals(proof.getRecoveryEpoch())) return unavailable();
                LoginCompletion completion = this.security.completeTotpLogin(input, proof);
                if (completion == null) return unavailable();
                return json(200, JsonObject.builder().put("authenticated", true).build())
                        .copy().cookies(completion.getCookies()).finish();
            }
            if (result instanceof TotpVerificationResult.Throttled throttled)
                return throttled(throttled.getRetryAfter());
            // Indeterminate code use never creates a session. Leave primary authentication pending;
            // demand a fresh code in a later step or take the application's approved recovery path.
            if (result instanceof TotpVerificationResult.ReconciliationRequired) {
                this.security.requireReconciliation(input);
                return unavailable();
            }
            if (result instanceof TotpVerificationResult.Indeterminate) {
                this.security.requireReconciliation(input);
                return unavailable();
            }
            return result instanceof TotpVerificationResult.Unavailable ? unavailable() : denied();
        });
    }

    @POST("/login/recovery")
    public @NonNull MarshaledResponse useRecoveryCode(@NonNull Request request) {
        return admitted(request, () -> {
            LoginSubmission input = this.security.admitRecoveryLogin(request);
            if (input == null) return denied();
            RecoveryCodeUseResult result = this.totp.consumeRecoveryCodeResult(input.getAccountId(),
                    input.getCode(), input.getOperationBinding());
            if (result instanceof RecoveryCodeUseResult.Succeeded success) {
                RecoveryCodeUse proof = success.getUse();
                if (!this.recoveryEpoch.equals(proof.getRecoveryEpoch())) return unavailable();
                LoginCompletion completion = this.security.completeRecoveryLogin(input, proof);
                if (completion == null) return unavailable();
                // This application chooses a restricted recovery session, separately from TOTP login.
                return json(200, JsonObject.builder().put("recoverySession", true).build())
                        .copy().cookies(completion.getCookies()).finish();
            }
            if (result instanceof RecoveryCodeUseResult.Throttled throttled)
                return throttled(throttled.getRetryAfter());
            if (result instanceof RecoveryCodeUseResult.ReconciliationRequired) {
                this.security.requireReconciliation(input);
                return unavailable();
            }
            if (result instanceof RecoveryCodeUseResult.Indeterminate) {
                this.security.requireReconciliation(input);
                return unavailable();
            }
            return result instanceof RecoveryCodeUseResult.Unavailable ? unavailable() : denied();
        });
    }

    @POST("/account/recovery-codes/rotate")
    public @NonNull MarshaledResponse rotateRecoveryCodes(@NonNull Request request) {
        return admitted(request, () -> {
            RotationContext context = this.security.admitRecoveryRotation(request);
            if (context == null) return denied();
            RecoveryCodeRotationResult result = this.totp.rotateRecoveryCodesResult(context.getAccountId(),
                    context.getExpectedFactorId(), context.getExpectedBatchId());
            if (result instanceof RecoveryCodeRotationResult.Succeeded success) {
                RecoveryCodes codes = success.getRecoveryCodes();
                if (!this.security.completeRotation(context, codes.getBatchId())) {
                    this.security.requireReconciliation(context);
                    return unavailable();
                }
                return json(200, recoveryCodes(codes));
            }
            if (result instanceof RecoveryCodeRotationResult.ReconciliationRequired) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            if (result instanceof RecoveryCodeRotationResult.Indeterminate) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            return result instanceof RecoveryCodeRotationResult.Unavailable ? unavailable() : denied();
        });
    }

    @POST("/account/totp/remove")
    public @NonNull MarshaledResponse removeFactor(@NonNull Request request) {
        return admitted(request, () -> {
            RemovalContext context = this.security.admitRemoval(request);
            if (context == null) return denied();
            TotpFactorRemovalResult result = this.totp.removeFactorResult(
                    context.getAccountId(), context.getExpectedFactorId());
            if (result instanceof TotpFactorRemovalResult.Succeeded) {
                if (!this.security.completeRemoval(context)) {
                    this.security.requireReconciliation(context);
                    return unavailable();
                }
                return json(200, JsonObject.builder().put("removed", true).build());
            }
            if (result instanceof TotpFactorRemovalResult.ReconciliationRequired) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            if (result instanceof TotpFactorRemovalResult.Indeterminate) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            return result instanceof TotpFactorRemovalResult.Unavailable ? unavailable() : denied();
        });
    }

    @POST("/account/totp/enrollment/cancel")
    public @NonNull MarshaledResponse cancelEnrollment(@NonNull Request request) {
        return admitted(request, () -> {
            CancellationContext context = this.security.admitCancellation(request);
            if (context == null) return denied();
            TotpEnrollmentCancellationResult result = this.totp.cancelEnrollmentResult(
                    context.getAccountId(), context.getEnrollmentId(), context.getBrowserBinding());
            if (result instanceof TotpEnrollmentCancellationResult.Succeeded) {
                if (!this.security.completeCancellation(context)) {
                    this.security.requireReconciliation(context);
                    return unavailable();
                }
                return json(200, JsonObject.builder().put("cancelled", true).build());
            }
            if (result instanceof TotpEnrollmentCancellationResult.ReconciliationRequired) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            if (result instanceof TotpEnrollmentCancellationResult.Indeterminate) {
                this.security.requireReconciliation(context);
                return unavailable();
            }
            return result instanceof TotpEnrollmentCancellationResult.Unavailable ? unavailable() : denied();
        });
    }

    @GET("/account/totp")
    @HEAD("/account/totp")
    public @NonNull MarshaledResponse status(@NonNull Request request) {
        return admitted(request, () -> {
            ActionContext context = this.security.admitStatus(request);
            if (context == null) return denied();
            TotpStatusResult result = this.totp.getStatusResult(context.getAccountId());
            if (result instanceof TotpStatusResult.Present present)
                return json(200, status(present.getStatus()));
            if (result instanceof TotpStatusResult.Absent)
                return json(200, JsonObject.builder().put("active", false).put("pending", false)
                        .put("remainingRecoveryCodes", 0L).build());
            return unavailable();
        });
    }

    private @NonNull MarshaledResponse admitted(@NonNull Request request,
            @NonNull Supplier<@NonNull MarshaledResponse> work) {
        // The application's outer admission spans both the library result and its own session /
        // approval transaction. It nests the same recovery gate or enforces a coordinated epoch
        // fence atomically with that transaction. A preflight epoch lookup alone is insufficient.
        long startedAt = this.monotonicNanos.getAsLong();
        MarshaledResponse response = unavailable();
        try (RequestPermit permit = this.security.acquireRequestPermit(request, REQUEST_BUDGET)) {
            if (permit != null && this.recoveryEpoch.equals(permit.getRecoveryEpoch())
                    && permit.isCurrent()) {
                MarshaledResponse candidate = work.get();
                if (permit.isCurrent()) response = candidate;
            }
        }
        // close() can itself consume the last part of the budget. Check after release, when the
        // permit can no longer report currentness, before exposing any secret or session cookie.
        long elapsed = this.monotonicNanos.getAsLong() - startedAt;
        return elapsed >= 0 && elapsed < REQUEST_BUDGET.toNanos() ? response : unavailable();
    }

    private static @NonNull JsonObject factor(@NonNull TotpFactor factor) {
        return JsonObject.builder().put("factorId", factor.getFactorId())
                .put("recoveryEpoch", factor.getRecoveryEpoch()).build();
    }

    private static @NonNull JsonObject recoveryCodes(@NonNull RecoveryCodes codes) {
        return JsonObject.builder().put("batchId", codes.getBatchId())
                .put("codes", JsonArray.fromElements(codes.getCodes().stream()
                        .map(JsonString::fromValue).toList())).build();
    }

    private static @NonNull JsonObject status(@NonNull TotpStatus status) {
        JsonObject.Builder json = JsonObject.builder()
                .put("active", status.getActiveFactor().isPresent())
                .put("pending", status.getPendingEnrollment().isPresent())
                .put("remainingRecoveryCodes", status.getRemainingRecoveryCodeCount().longValue());
        status.getActiveFactor().ifPresent(value -> json.put("factor", factor(value)));
        status.getRecoveryBatchId().ifPresent(value -> json.put("recoveryBatchId", value));
        TotpPendingEnrollment pending = status.getPendingEnrollment().orElse(null);
        if (pending != null) json.put("pendingEnrollment", JsonObject.builder()
                .put("enrollmentId", pending.getEnrollmentId()).put("factorId", pending.getFactorId())
                .put("expiresAt", pending.getExpiresAt().toString()).build());
        return json.build();
    }

    private static @NonNull MarshaledResponse denied() {
        return json(403, JsonObject.builder().put("error", "Request rejected").build());
    }

    private static @NonNull MarshaledResponse unavailable() {
        return json(503, JsonObject.builder().put("error", "Temporarily unavailable").build());
    }

    private static @NonNull MarshaledResponse throttled(@NonNull Duration retryAfter) {
        long seconds = Math.max(1, retryAfter.getSeconds() + (retryAfter.getNano() == 0 ? 0 : 1));
        return json(429, JsonObject.builder().put("error", "Try again later").build())
                .copy().headers(Map.of("Content-Type", List.of("application/json; charset=UTF-8"),
                        "Cache-Control", List.of("no-store"), "Referrer-Policy", List.of("no-referrer"),
                        "X-Content-Type-Options", List.of("nosniff"),
                        "Retry-After", List.of(Long.toString(seconds)))).finish();
    }

    private static @NonNull MarshaledResponse json(@NonNull Integer status, @NonNull JsonObject body) {
        // This is application-owned serialization. The default Soklet marshaler accepts the
        // already marshaled response and suppresses the body for HEAD automatically.
        return MarshaledResponse.withStatusCode(status)
                .headers(Map.of("Content-Type", List.of("application/json; charset=UTF-8"),
                        "Cache-Control", List.of("no-store"), "Referrer-Policy", List.of("no-referrer"),
                        "X-Content-Type-Options", List.of("nosniff")))
                .body(body.toJson().getBytes(StandardCharsets.UTF_8)).build();
    }

    /**
     * Thread-safe application boundary. Every admit method performs bounded body parsing, exact
     * Host/Origin, session and CSRF checks, duplicate-field rejection and network admission before
     * returning a context; null is an ordinary denial. It obtains IDs/bindings from server-owned
     * state. A six-digit OTP remains a String. No caller account/generation is trusted directly.
     *
     * <p>Management admission requires fresh action-specific authorization or an approved recovery
     * path. Completion methods atomically recheck/consume that action and the account/epoch fence;
     * false means completion is unconfirmed. Login completion additionally consumes the current
     * primary-authenticated pending login, checks its short fixed expiry and account/operation
     * bindings, rotates session/CSRF, and returns outgoing secure cookies. Both login admission
     * methods reject expired or consumed state; code failures never extend its expiry. Recovery
     * completion records the distinct method and grants only the application's restricted recovery
     * policy. All hooks honor the request deadline.
     * Failed permit acquisition releases any partial lock or lease before returning or throwing.
     */
    @ThreadSafe
    public interface ApplicationSecurity {
        @Nullable RequestPermit acquireRequestPermit(@NonNull Request request, @NonNull Duration budget);
        @Nullable EnrollmentContext admitEnrollment(@NonNull Request request, boolean replacement);
        @Nullable EnrollmentSubmission admitEnrollmentConfirmation(@NonNull Request request);
        @Nullable LoginSubmission admitTotpLogin(@NonNull Request request);
        @Nullable LoginSubmission admitRecoveryLogin(@NonNull Request request);
        @Nullable RotationContext admitRecoveryRotation(@NonNull Request request);
        @Nullable RemovalContext admitRemoval(@NonNull Request request);
        @Nullable CancellationContext admitCancellation(@NonNull Request request);
        @Nullable ActionContext admitStatus(@NonNull Request request);
        boolean rememberEnrollment(@NonNull EnrollmentContext context, @NonNull String enrollmentId,
                @NonNull String factorId, @NonNull Instant expiresAt);
        boolean completeEnrollment(@NonNull EnrollmentSubmission context, @NonNull TotpFactor factor,
                @NonNull String recoveryBatchId);
        @Nullable LoginCompletion completeTotpLogin(@NonNull LoginSubmission context,
                @NonNull TotpVerification proof);
        @Nullable LoginCompletion completeRecoveryLogin(@NonNull LoginSubmission context,
                @NonNull RecoveryCodeUse proof);
        boolean completeRotation(@NonNull RotationContext context, @NonNull String newBatchId);
        boolean completeRemoval(@NonNull RemovalContext context);
        boolean completeCancellation(@NonNull CancellationContext context);
        void requireReconciliation(@NonNull ActionContext context);
    }

    /** App-owned receipt produced only after confirmed session completion; it is not a TOTP proof. */
    @Immutable
    public static final class LoginCompletion {
        private final @NonNull List<@NonNull ResponseCookie> cookies;
        private LoginCompletion(@NonNull List<@NonNull ResponseCookie> cookies) {
            this.cookies = List.copyOf(cookies);
        }
        public static @NonNull LoginCompletion fromCookies(
                @NonNull List<@NonNull ResponseCookie> cookies) {
            return new LoginCompletion(cookies);
        }
        public @NonNull List<@NonNull ResponseCookie> getCookies() { return this.cookies; }
        @Override public @NonNull String toString() { return "LoginCompletion[redacted]"; }
    }

    /** Caller-thread admission held until the application transaction and result decision finish. */
    @NotThreadSafe
    public interface RequestPermit extends AutoCloseable {
        @NonNull String getRecoveryEpoch();
        @NonNull Boolean isCurrent();
        @Override void close();
    }

    /** Each context implementation is immutable, with redacted toString, and carries approved state. */
    @ThreadSafe
    public interface ActionContext {
        @NonNull String getAccountId();
    }

    @ThreadSafe
    public interface EnrollmentContext extends ActionContext {
        @NonNull String getAccountLabel();
        @NonNull String getBrowserBinding();
        @NonNull Optional<@NonNull String> getReplacingFactorId();
    }

    @ThreadSafe
    public interface EnrollmentSubmission extends ActionContext {
        @NonNull String getEnrollmentId();
        @NonNull String getCode();
        @NonNull String getBrowserBinding();
    }

    @ThreadSafe
    public interface LoginSubmission extends ActionContext {
        @NonNull String getCode();
        @NonNull String getOperationBinding();
    }

    @ThreadSafe
    public interface RotationContext extends ActionContext {
        @NonNull String getExpectedFactorId();
        @NonNull String getExpectedBatchId();
    }

    @ThreadSafe
    public interface RemovalContext extends ActionContext {
        @NonNull String getExpectedFactorId();
    }

    @ThreadSafe
    public interface CancellationContext extends ActionContext {
        @NonNull String getEnrollmentId();
        @NonNull String getBrowserBinding();
    }
}
