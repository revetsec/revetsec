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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.totp.InMemoryTotpStore;
import com.revetsec.totp.RecoveryCodeUse;
import com.revetsec.totp.TotpAuthenticator;
import com.revetsec.totp.TotpFactor;
import com.revetsec.totp.TotpNamespaceInitializationResult;
import com.revetsec.totp.TotpRecoveryContext;
import com.revetsec.totp.TotpRecoveryGate;
import com.revetsec.totp.TotpVerification;
import com.soklet.HttpMethod;
import com.soklet.MarshaledResponse;
import com.soklet.MarshaledResponseBody;
import com.soklet.Request;
import com.soklet.ResponseCookie;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.annotation.concurrent.Immutable;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** End-to-end route transitions with real core storage; all authentication grants are test-only. */
@NotThreadSafe
public final class TotpExampleLifecycleChecks {
    private static final @NonNull String NAMESPACE = "example-lifecycle";
    private static final @NonNull String EPOCH = "fresh-test-epoch";
    private static final @NonNull String ACCOUNT = "test-account";
    private static final @NonNull String BROWSER = "server-owned-test-browser-binding";
    private static final @NonNull String LOGIN = "server-owned-current-primary-login";
    private TotpExampleLifecycleChecks() { }

    public static void main(java.lang.@NonNull String @NonNull [] args) throws Exception {
        lifecycle();
        failedApplicationCompletionReleasesNoSecretOrSession();
        expiredDuringPermitCloseReleasesNoSecretOrSession();
        System.out.println("TOTP Soklet authorized lifecycle checks passed.");
    }

    private static void lifecycle() throws Exception {
        Fixture fixture = new Fixture();
        String prepared = checked(fixture.app.beginEnrollment(post("/account/totp/enrollment", "")), 200);
        String manual = field(prepared, "manualEntryKey");
        check(prepared.contains("otpauth://totp/Example:test-account"));
        equal(fixture.security.enrollmentId, field(prepared, "enrollmentId"));
        String confirmed = checked(fixture.app.confirmEnrollment(post("/account/totp/confirm",
                code(manual, fixture.clock))), 200);
        List<String> recovery = codes(confirmed);
        equal(10, recovery.size());
        String firstFactor = fixture.security.factorId;
        check(!firstFactor.isEmpty());
        String status = checked(fixture.app.status(get()), 200);
        check(status.contains("\"active\":true") && status.contains("\"pending\":false")
                && status.contains("\"remainingRecoveryCodes\":10"));
        check(!status.contains(manual) && !status.contains(recovery.get(0)));

        fixture.clock.advance();
        String nextCode = code(manual, fixture.clock);
        MarshaledResponse login = fixture.app.verifyTotp(post("/login/totp", nextCode));
        check(checked(login, 200).contains("\"authenticated\":true"));
        checkCookie(login);
        equal(1, fixture.security.totpLogins);
        checked(fixture.app.verifyTotp(post("/login/totp", nextCode)), 403);
        equal(1, fixture.security.totpLogins);
        MarshaledResponse recovered = fixture.app.useRecoveryCode(post("/login/recovery", recovery.get(0)));
        check(checked(recovered, 200).contains("\"recoverySession\":true"));
        checkCookie(recovered);
        equal(1, fixture.security.recoveryLogins);
        equal(9, fixture.security.remainingRecoveryCodes);

        String oldBatch = fixture.security.batchId;
        String rotated = checked(fixture.app.rotateRecoveryCodes(post("/account/recovery-codes/rotate", "")), 200);
        List<String> newRecovery = codes(rotated);
        equal(10, newRecovery.size());
        check(!oldBatch.equals(fixture.security.batchId));
        checked(fixture.app.useRecoveryCode(post("/login/recovery", recovery.get(1))), 403);
        equal(1, fixture.security.recoveryLogins);

        checked(fixture.app.beginReplacement(post("/account/totp/replacement", "")), 200);
        check(checked(fixture.app.status(get()), 200).contains("\"pending\":true"));
        equal(firstFactor, fixture.security.factorId);
        check(checked(fixture.app.cancelEnrollment(post("/account/totp/enrollment/cancel", "")), 200)
                .contains("\"cancelled\":true"));
        String afterCancel = checked(fixture.app.status(get()), 200);
        check(afterCancel.contains("\"active\":true") && afterCancel.contains("\"pending\":false"));

        String replacement = checked(fixture.app.beginReplacement(post("/account/totp/replacement", "")), 200);
        String replacementManual = field(replacement, "manualEntryKey");
        String replaced = checked(fixture.app.confirmEnrollment(post("/account/totp/confirm",
                code(replacementManual, fixture.clock))), 200);
        equal(10, codes(replaced).size());
        check(!firstFactor.equals(fixture.security.factorId));
        fixture.clock.advance();
        checked(fixture.app.verifyTotp(post("/login/totp", code(replacementManual, fixture.clock))), 200);
        equal(2, fixture.security.totpLogins);
        checked(fixture.app.useRecoveryCode(post("/login/recovery", newRecovery.get(0))), 403);

        check(checked(fixture.app.removeFactor(post("/account/totp/remove", "")), 200)
                .contains("\"removed\":true"));
        String removed = checked(fixture.app.status(get()), 200);
        check(removed.contains("\"active\":false") && removed.contains("\"pending\":false")
                && removed.contains("\"remainingRecoveryCodes\":0"));
        equal(1, fixture.security.removals);
        equal(0, fixture.security.reconciliations);
        equal(0, fixture.gate.depth.get());
        equal(fixture.gate.acquired.get(), fixture.gate.closed.get());
    }

    private static void failedApplicationCompletionReleasesNoSecretOrSession() throws Exception {
        Fixture fixture = new Fixture();
        String prepared = checked(fixture.app.beginEnrollment(post("/account/totp/enrollment", "")), 200);
        String manual = field(prepared, "manualEntryKey");
        fixture.security.confirmCompletion = false;
        String refused = checked(fixture.app.confirmEnrollment(post("/account/totp/confirm",
                code(manual, fixture.clock))), 503);
        check(!refused.contains("codes") && !refused.contains("batchId") && !refused.contains(manual));
        equal(1, fixture.security.reconciliations);
        String reconciled = checked(fixture.app.status(get()), 200);
        check(reconciled.contains("\"active\":true"));
        fixture.security.factorId = field(reconciled, "factorId");
        fixture.security.loginCompletion = false;
        fixture.clock.advance();
        MarshaledResponse login = fixture.app.verifyTotp(post("/login/totp", code(manual, fixture.clock)));
        checked(login, 503);
        check(login.getCookies().isEmpty());
        equal(0, fixture.security.totpLogins);
        equal(0, fixture.gate.depth.get());
        equal(fixture.gate.acquired.get(), fixture.gate.closed.get());
    }

    private static void expiredDuringPermitCloseReleasesNoSecretOrSession() throws Exception {
        AtomicLong enrollmentNanos = new AtomicLong(1);
        Fixture enrollment = new Fixture(enrollmentNanos::get);
        enrollment.security.afterOuterClose = () -> enrollmentNanos.addAndGet(Duration.ofSeconds(10).toNanos());
        MarshaledResponse withheldEnrollment = enrollment.app.beginEnrollment(
                post("/account/totp/enrollment", ""));
        String refusedEnrollment = checked(withheldEnrollment, 503);
        check(!refusedEnrollment.contains("manualEntryKey")
                && !refusedEnrollment.contains("provisioningUri"));
        check(withheldEnrollment.getCookies().isEmpty());
        check(!enrollment.security.enrollmentId.isEmpty());
        equal(0, enrollment.gate.depth.get());
        equal(enrollment.gate.acquired.get(), enrollment.gate.closed.get());

        AtomicLong loginNanos = new AtomicLong(1);
        Fixture login = new Fixture(loginNanos::get);
        String prepared = checked(login.app.beginEnrollment(post("/account/totp/enrollment", "")), 200);
        String manual = field(prepared, "manualEntryKey");
        checked(login.app.confirmEnrollment(post("/account/totp/confirm", code(manual, login.clock))), 200);
        login.clock.advance();
        login.security.afterOuterClose = () -> loginNanos.addAndGet(Duration.ofSeconds(10).toNanos());
        MarshaledResponse withheldLogin = login.app.verifyTotp(
                post("/login/totp", code(manual, login.clock)));
        String refusedLogin = checked(withheldLogin, 503);
        check(!refusedLogin.contains("authenticated") && withheldLogin.getCookies().isEmpty());
        equal(1, login.security.totpLogins);
        equal(0, login.gate.depth.get());
        equal(login.gate.acquired.get(), login.gate.closed.get());
    }

    private static @NonNull Request post(@NonNull String path, @NonNull String code) {
        return Request.withRawUrl(HttpMethod.POST, path)
                .headers(Map.of("X-Test-Approved", List.of("yes")))
                .body(code.getBytes(StandardCharsets.US_ASCII)).build();
    }
    private static @NonNull Request get() {
        return Request.withRawUrl(HttpMethod.GET, "/account/totp")
                .headers(Map.of("X-Test-Approved", List.of("yes"))).build();
    }
    private static @NonNull String checked(@NonNull MarshaledResponse response, int expected) {
        equal(expected, response.getStatusCode());
        equal(List.of("application/json; charset=UTF-8"), response.getHeaders().get("Content-Type"));
        equal(List.of("no-store"), response.getHeaders().get("Cache-Control"));
        equal(List.of("no-referrer"), response.getHeaders().get("Referrer-Policy"));
        MarshaledResponseBody.Bytes bytes = (MarshaledResponseBody.Bytes) response.getBody().orElseThrow();
        String json = new String(bytes.getBytes(), StandardCharsets.UTF_8);
        check(json.startsWith("{") && json.endsWith("}"));
        return json;
    }
    private static void checkCookie(@NonNull MarshaledResponse response) {
        equal(1, response.getCookies().size());
        ResponseCookie cookie = response.getCookies().iterator().next();
        check(cookie.getName().startsWith("__Host-") && cookie.getSecure() && cookie.getHttpOnly());
        equal(ResponseCookie.SameSite.STRICT, cookie.getSameSite().orElseThrow());
    }
    private static @NonNull String field(@NonNull String json, @NonNull String name) {
        Matcher matcher = Pattern.compile("\"" + name + "\":\"([^\"]+)\"").matcher(json);
        if (!matcher.find()) throw new AssertionError("Expected JSON field missing");
        return matcher.group(1);
    }
    private static @NonNull List<@NonNull String> codes(@NonNull String json) {
        List<String> result = new ArrayList<>();
        Matcher matcher = Pattern.compile("\"([0-9A-HJKMNP-TV-Z]{5}(?:-[0-9A-HJKMNP-TV-Z]{5}){3}-[0-9A-HJKMNP-TV-Z]{6})\"")
                .matcher(json);
        while (matcher.find()) result.add(matcher.group(1));
        return List.copyOf(result);
    }

    /** Avoids the intentionally rejected rare case where adjacent steps generate the same digits. */
    private static @NonNull String code(@NonNull String manual, @NonNull TestClock clock) throws Exception {
        for (int attempt = 0; attempt < 8; attempt++) {
            Instant now = clock.instant();
            String candidate = otp(manual, now);
            if (!candidate.equals(otp(manual, now.minusSeconds(30)))
                    && !candidate.equals(otp(manual, now.plusSeconds(30)))) return candidate;
            clock.advance();
        }
        throw new AssertionError("No unambiguous TOTP fixture step");
    }

    /** Independent public-JCA HOTP implementation, with a local Base32 decoder for the setup key. */
    private static @NonNull String otp(@NonNull String manual, @NonNull Instant now) throws Exception {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        byte[] secret = new byte[manual.length() * 5 / 8];
        int buffer = 0;
        int bits = 0;
        int output = 0;
        for (int index = 0; index < manual.length(); index++) {
            int value = alphabet.indexOf(manual.charAt(index));
            check(value >= 0);
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) { bits -= 8; secret[output++] = (byte) (buffer >>> bits); }
        }
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(secret, "HmacSHA1"));
        byte[] digest = mac.doFinal(ByteBuffer.allocate(8).putLong(now.getEpochSecond() / 30).array());
        int offset = digest[digest.length - 1] & 15;
        int binary = ((digest[offset] & 127) << 24) | ((digest[offset + 1] & 255) << 16)
                | ((digest[offset + 2] & 255) << 8) | (digest[offset + 3] & 255);
        String digits = Integer.toString(binary % 1_000_000);
        return "0".repeat(6 - digits.length()) + digits;
    }
    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("TOTP integration invariant failed");
    }
    private static void equal(@Nullable Object expected, @Nullable Object actual) {
        if (!Objects.equals(expected, actual)) throw new AssertionError("Unexpected TOTP integration result");
    }

    @NotThreadSafe
    private static final class Fixture {
        private final @NonNull TestClock clock = new TestClock();
        private final @NonNull Gate gate = new Gate();
        private final @NonNull Security security = new Security(this.gate);
        private final @NonNull TotpApplication app;
        private Fixture() { this(System::nanoTime); }
        private Fixture(@NonNull LongSupplier monotonicNanos) {
            byte[] key = new byte[32];
            for (int index = 0; index < key.length; index++) key[index] = (byte) (index + 1);
            TotpAuthenticator totp = TotpAuthenticator.withIssuer("Example")
                    .credentialNamespace(NAMESPACE).recoveryEpoch(EPOCH)
                    .store(InMemoryTotpStore.withNamespace(NAMESPACE, EPOCH).build())
                    .stateSealer(StateSealer.withActiveKey(SealingKey.fromBase64("test-only",
                            Base64.getEncoder().encodeToString(key))).build())
                    .clock(this.clock).recoveryGate(this.gate).build();
            check(totp.initializeNamespaceResult() instanceof TotpNamespaceInitializationResult.Initialized);
            this.gate.provisioning = false;
            this.app = new TotpApplication(totp, this.security, monotonicNanos);
        }
    }

    @ThreadSafe
    private static final class TestClock extends Clock {
        private final @NonNull AtomicReference<@NonNull Instant> now =
                new AtomicReference<>(Instant.parse("2026-10-15T12:00:00Z"));
        private void advance() { this.now.updateAndGet(value -> value.plusSeconds(30)); }
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) throw new IllegalArgumentException("UTC fixture only");
            return this;
        }
        @Override public @NonNull Instant instant() { return this.now.get(); }
    }

    /** Fresh-process test controller only; it grants no restore or distributed-storage assurance. */
    @ThreadSafe
    private static final class Gate implements TotpRecoveryGate {
        private final @NonNull ThreadLocal<@NonNull Integer> depth = ThreadLocal.withInitial(() -> 0);
        private final @NonNull AtomicInteger acquired = new AtomicInteger();
        private final @NonNull AtomicInteger closed = new AtomicInteger();
        private volatile boolean provisioning = true;
        @Override public @Nullable Permit acquire(@NonNull TotpRecoveryContext context,
                @NonNull Duration remainingBudget) {
            equal(NAMESPACE, context.getCredentialNamespace()); equal(EPOCH, context.getRecoveryEpoch());
            equal("test-only", context.getActiveSealingKeyId());
            if (context.getPurpose() == TotpRecoveryContext.Purpose.INITIALIZE_NAMESPACE && !this.provisioning)
                return null;
            return enter(remainingBudget);
        }
        private @NonNull Permit enter(@NonNull Duration budget) {
            long deadline = System.nanoTime() + budget.toNanos();
            Thread owner = Thread.currentThread();
            this.depth.set(this.depth.get() + 1); this.acquired.incrementAndGet();
            return new Permit() {
                private boolean released;
                @Override public @NonNull Boolean isCurrent() {
                    return !this.released && owner == Thread.currentThread() && System.nanoTime() < deadline;
                }
                @Override public void close() {
                    check(owner == Thread.currentThread());
                    if (!this.released) {
                        this.released = true; Gate.this.depth.set(Gate.this.depth.get() - 1);
                        Gate.this.closed.incrementAndGet();
                    }
                }
            };
        }
    }

    /** Explicitly test-only grants; the production integration supplies its own security boundary. */
    @ThreadSafe
    private static final class Security implements TotpApplication.ApplicationSecurity {
        private final @NonNull Gate gate;
        private @NonNull String enrollmentId = "";
        private @NonNull String candidateFactorId = "";
        private @NonNull String factorId = "";
        private @NonNull String batchId = "";
        private int totpLogins;
        private int recoveryLogins;
        private int remainingRecoveryCodes;
        private int removals;
        private int reconciliations;
        private boolean confirmCompletion = true;
        private boolean loginCompletion = true;
        private volatile @Nullable Runnable afterOuterClose;
        private Security(@NonNull Gate gate) { this.gate = gate; }
        private synchronized @Nullable Context admit(@NonNull Request request, boolean replacement) {
            check(this.gate.depth.get() == 1);
            if (!List.of("yes").equals(request.getHeaders().get("X-Test-Approved"))) return null;
            String code = new String(request.getBody().orElseGet(() -> new byte[0]), StandardCharsets.US_ASCII);
            return new Context(this.enrollmentId, this.factorId, this.batchId, code,
                    replacement ? Optional.of(this.factorId) : Optional.empty());
        }
        private void completion(TotpApplication.@NonNull ActionContext context) {
            // Core's inner permit has closed, but the same gate's outer permit remains held.
            check(this.gate.depth.get() == 1); equal(ACCOUNT, context.getAccountId());
        }
        @Override public TotpApplication.@NonNull RequestPermit acquireRequestPermit(
                @NonNull Request request, @NonNull Duration budget) {
            TotpRecoveryGate.Permit permit = this.gate.enter(budget);
            return new TotpApplication.RequestPermit() {
                @Override public @NonNull String getRecoveryEpoch() { return EPOCH; }
                @Override public @NonNull Boolean isCurrent() { return permit.isCurrent(); }
                @Override public void close() {
                    permit.close();
                    Runnable afterClose = Security.this.afterOuterClose;
                    if (afterClose != null) afterClose.run();
                }
            };
        }
        @Override public synchronized @Nullable Context admitEnrollment(@NonNull Request request,
                boolean replacement) { return admit(request, replacement); }
        @Override public synchronized @Nullable Context admitEnrollmentConfirmation(@NonNull Request request) {
            return admit(request, false);
        }
        @Override public synchronized @Nullable Context admitTotpLogin(@NonNull Request request) {
            return admit(request, false);
        }
        @Override public synchronized @Nullable Context admitRecoveryLogin(@NonNull Request request) {
            return admit(request, false);
        }
        @Override public synchronized @Nullable Context admitRecoveryRotation(@NonNull Request request) {
            return admit(request, false);
        }
        @Override public synchronized @Nullable Context admitRemoval(@NonNull Request request) {
            return admit(request, false);
        }
        @Override public synchronized @Nullable Context admitCancellation(@NonNull Request request) {
            return admit(request, false);
        }
        @Override public synchronized @Nullable Context admitStatus(@NonNull Request request) {
            return admit(request, false);
        }
        @Override public synchronized boolean rememberEnrollment(TotpApplication.@NonNull EnrollmentContext context,
                @NonNull String enrollmentId, @NonNull String factorId, @NonNull Instant expiresAt) {
            completion(context); this.enrollmentId = enrollmentId; this.candidateFactorId = factorId; return true;
        }
        @Override public synchronized boolean completeEnrollment(
                TotpApplication.@NonNull EnrollmentSubmission context, @NonNull TotpFactor factor,
                @NonNull String recoveryBatchId) {
            completion(context); equal(EPOCH, factor.getRecoveryEpoch()); equal(ACCOUNT, factor.getAccountId());
            equal(this.enrollmentId, context.getEnrollmentId()); equal(this.candidateFactorId, factor.getFactorId());
            if (!this.confirmCompletion) return false;
            this.factorId = factor.getFactorId(); this.batchId = recoveryBatchId; this.enrollmentId = ""; return true;
        }
        @Override public synchronized TotpApplication.@Nullable LoginCompletion completeTotpLogin(
                TotpApplication.@NonNull LoginSubmission context, @NonNull TotpVerification proof) {
            completion(context); equal(EPOCH, proof.getRecoveryEpoch()); equal(ACCOUNT, proof.getAccountId());
            equal(context.getOperationBinding(), proof.getOperationBinding());
            equal(NAMESPACE, proof.getCredentialNamespace()); equal(this.factorId, proof.getFactorId());
            equal("TOTP", proof.getMethod().name());
            if (!this.loginCompletion) return null;
            this.totpLogins++; return receipt("totp-session");
        }
        @Override public synchronized TotpApplication.@Nullable LoginCompletion completeRecoveryLogin(
                TotpApplication.@NonNull LoginSubmission context, @NonNull RecoveryCodeUse proof) {
            completion(context); equal(EPOCH, proof.getRecoveryEpoch()); equal(ACCOUNT, proof.getAccountId());
            equal(context.getOperationBinding(), proof.getOperationBinding());
            equal(NAMESPACE, proof.getCredentialNamespace()); equal(this.factorId, proof.getFactorId());
            equal("RECOVERY_CODE", proof.getMethod().name());
            if (!this.loginCompletion) return null;
            this.recoveryLogins++; this.remainingRecoveryCodes = proof.getRemainingRecoveryCodeCount();
            return receipt("restricted-recovery-session");
        }
        private static TotpApplication.@NonNull LoginCompletion receipt(@NonNull String session) {
            return TotpApplication.LoginCompletion.fromCookies(List.of(
                    ResponseCookie.withName("__Host-TestSession").value(session).path("/")
                            .secure(true).httpOnly(true).sameSite(ResponseCookie.SameSite.STRICT).build()));
        }
        @Override public synchronized boolean completeRotation(TotpApplication.@NonNull RotationContext context,
                @NonNull String newBatchId) {
            completion(context); equal(this.factorId, context.getExpectedFactorId());
            equal(this.batchId, context.getExpectedBatchId()); this.batchId = newBatchId; return true;
        }
        @Override public synchronized boolean completeRemoval(TotpApplication.@NonNull RemovalContext context) {
            completion(context); equal(this.factorId, context.getExpectedFactorId());
            this.factorId = ""; this.batchId = ""; this.enrollmentId = ""; this.removals++; return true;
        }
        @Override public synchronized boolean completeCancellation(
                TotpApplication.@NonNull CancellationContext context) {
            completion(context); equal(this.enrollmentId, context.getEnrollmentId()); this.enrollmentId = ""; return true;
        }
        @Override public synchronized void requireReconciliation(TotpApplication.@NonNull ActionContext context) {
            completion(context); this.reconciliations++;
        }
    }

    @Immutable
    private static final class Context implements TotpApplication.EnrollmentContext,
            TotpApplication.EnrollmentSubmission, TotpApplication.LoginSubmission,
            TotpApplication.RotationContext, TotpApplication.RemovalContext, TotpApplication.CancellationContext {
        private final @NonNull String enrollmentId;
        private final @NonNull String factorId;
        private final @NonNull String batchId;
        private final @NonNull String code;
        private final @NonNull Optional<@NonNull String> replacing;
        private Context(@NonNull String enrollmentId, @NonNull String factorId, @NonNull String batchId,
                @NonNull String code, @NonNull Optional<@NonNull String> replacing) {
            this.enrollmentId = enrollmentId; this.factorId = factorId; this.batchId = batchId;
            this.code = code; this.replacing = replacing;
        }
        @Override public @NonNull String getAccountId() { return ACCOUNT; }
        @Override public @NonNull String getAccountLabel() { return "test-account"; }
        @Override public @NonNull String getBrowserBinding() { return BROWSER; }
        @Override public @NonNull Optional<@NonNull String> getReplacingFactorId() { return this.replacing; }
        @Override public @NonNull String getEnrollmentId() { return this.enrollmentId; }
        @Override public @NonNull String getCode() { return this.code; }
        @Override public @NonNull String getOperationBinding() { return LOGIN; }
        @Override public @NonNull String getExpectedFactorId() { return this.factorId; }
        @Override public @NonNull String getExpectedBatchId() { return this.batchId; }
        @Override public @NonNull String toString() { return "TestContext[redacted]"; }
    }
}
