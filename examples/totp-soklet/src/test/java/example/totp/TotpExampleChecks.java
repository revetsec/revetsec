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
import com.revetsec.totp.RecoveryCodeUse;
import com.revetsec.totp.TotpAuthenticator;
import com.revetsec.totp.TotpFactor;
import com.revetsec.totp.TotpStore;
import com.revetsec.totp.TotpStoreCommitReceipt;
import com.revetsec.totp.TotpStoreKey;
import com.revetsec.totp.TotpStoreReadResult;
import com.revetsec.totp.TotpStoreWrite;
import com.revetsec.totp.TotpVerification;
import com.soklet.HttpMethod;
import com.soklet.MarshaledResponse;
import com.soklet.Request;
import com.soklet.ResponseMarshaler;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import javax.annotation.concurrent.NotThreadSafe;
import javax.annotation.concurrent.ThreadSafe;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Integration-boundary checks; core's TOTP suite separately exercises credential transitions. */
@NotThreadSafe
public final class TotpExampleChecks {
    private TotpExampleChecks() { }

    public static void main(java.lang.@NonNull String @NonNull [] args) {
        Boundary boundary = new Boundary();
        TotpApplication app = application(boundary);
        Request request = Request.withRawUrl(HttpMethod.POST, "/denied").build();
        List<Function<@NonNull Request, @NonNull MarshaledResponse>> routes = List.of(
                app::beginEnrollment, app::beginReplacement, app::confirmEnrollment,
                app::verifyTotp, app::useRecoveryCode, app::rotateRecoveryCodes,
                app::removeFactor, app::cancelEnrollment, app::status);
        for (Function<@NonNull Request, @NonNull MarshaledResponse> route : routes) {
            MarshaledResponse response = route.apply(request);
            equal(403, response.getStatusCode());
            equal(List.of("no-store"), response.getHeaders().get("Cache-Control"));
            equal(List.of("no-referrer"), response.getHeaders().get("Referrer-Policy"));
        }
        equal(9, boundary.closed.get());
        equal(ResponseMarshaler.defaultInstance(), TotpApplication.config(app, 8094).getResponseMarshaler());
        boundary.open = false;
        equal(503, app.status(request).getStatusCode());
        boundary.open = true;
        boundary.epoch = "retired-epoch";
        equal(503, app.status(request).getStatusCode());
        boundary.epoch = "example-epoch";
        boundary.revokeDuringAdmission = true;
        equal(503, app.status(request).getStatusCode());
        equal(11, boundary.closed.get());
        System.out.println("TOTP Soklet example boundary checks passed.");
    }

    static @NonNull TotpApplication application(@NonNull Boundary boundary) {
        TotpStore neverCalled = new TotpStore() {
            @Override public @NonNull TotpStoreReadResult read(
                    @NonNull Set<@NonNull TotpStoreKey> keys, @NonNull Duration remainingBudget) {
                throw new AssertionError("Unauthorized route reached credential storage");
            }
            @Override public @NonNull TotpStoreCommitReceipt compareAndCommit(
                    @NonNull TotpStoreWrite write, @NonNull Duration remainingBudget) {
                throw new AssertionError("Unauthorized route mutated credential storage");
            }
        };
        byte[] testMaterial = new byte[32];
        for (int index = 0; index < testMaterial.length; index++) testMaterial[index] = (byte) index;
        StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("test-only",
                Base64.getEncoder().encodeToString(testMaterial))).build();
        TotpAuthenticator totp = TotpAuthenticator.withIssuer("Example")
                .credentialNamespace("example-accounts").recoveryEpoch("example-epoch")
                .store(neverCalled).stateSealer(sealer).recoveryGate((context, budget) -> null).build();
        return new TotpApplication(totp, boundary);
    }

    private static void equal(@Nullable Object expected, @Nullable Object actual) {
        if (!Objects.equals(expected, actual)) throw new AssertionError("Unexpected boundary result");
    }

    /** Test-only admission fixture. It grants no application action or credential operation. */
    @ThreadSafe
    static final class Boundary implements TotpApplication.ApplicationSecurity {
        private volatile boolean open = true;
        private volatile @NonNull String epoch = "example-epoch";
        private volatile boolean revokeDuringAdmission;
        private final @NonNull AtomicInteger closed = new AtomicInteger();
        @Override public TotpApplication.@Nullable RequestPermit acquireRequestPermit(
                @NonNull Request request, @NonNull Duration budget) {
            if (!this.open) return null;
            return new TotpApplication.RequestPermit() {
                private boolean released;
                @Override public @NonNull String getRecoveryEpoch() { return Boundary.this.epoch; }
                @Override public @NonNull Boolean isCurrent() { return Boundary.this.open; }
                @Override public void close() {
                    if (!this.released) { this.released = true; Boundary.this.closed.incrementAndGet(); }
                }
            };
        }
        @Override public TotpApplication.@Nullable EnrollmentContext admitEnrollment(
                @NonNull Request request, boolean replacement) { return null; }
        @Override public TotpApplication.@Nullable EnrollmentSubmission admitEnrollmentConfirmation(
                @NonNull Request request) { return null; }
        @Override public TotpApplication.@Nullable LoginSubmission admitTotpLogin(@NonNull Request request) {
            return null;
        }
        @Override public TotpApplication.@Nullable LoginSubmission admitRecoveryLogin(@NonNull Request request) {
            return null;
        }
        @Override public TotpApplication.@Nullable RotationContext admitRecoveryRotation(@NonNull Request request) {
            return null;
        }
        @Override public TotpApplication.@Nullable RemovalContext admitRemoval(@NonNull Request request) {
            return null;
        }
        @Override public TotpApplication.@Nullable CancellationContext admitCancellation(@NonNull Request request) {
            return null;
        }
        @Override public TotpApplication.@Nullable ActionContext admitStatus(@NonNull Request request) {
            if (this.revokeDuringAdmission) this.open = false;
            return null;
        }
        @Override public boolean rememberEnrollment(TotpApplication.@NonNull EnrollmentContext context,
                @NonNull String enrollmentId, @NonNull String factorId, @NonNull Instant expiresAt) {
            throw new AssertionError("Unauthorized enrollment completion");
        }
        @Override public boolean completeEnrollment(TotpApplication.@NonNull EnrollmentSubmission context,
                @NonNull TotpFactor factor, @NonNull String recoveryBatchId) {
            throw new AssertionError("Unauthorized enrollment completion");
        }
        @Override public TotpApplication.@Nullable LoginCompletion completeTotpLogin(
                TotpApplication.@NonNull LoginSubmission context, @NonNull TotpVerification proof) {
            throw new AssertionError("Unauthorized login completion");
        }
        @Override public TotpApplication.@Nullable LoginCompletion completeRecoveryLogin(
                TotpApplication.@NonNull LoginSubmission context, @NonNull RecoveryCodeUse proof) {
            throw new AssertionError("Unauthorized recovery completion");
        }
        @Override public boolean completeRotation(TotpApplication.@NonNull RotationContext context,
                @NonNull String newBatchId) { throw new AssertionError("Unauthorized rotation"); }
        @Override public boolean completeRemoval(TotpApplication.@NonNull RemovalContext context) {
            throw new AssertionError("Unauthorized removal");
        }
        @Override public boolean completeCancellation(TotpApplication.@NonNull CancellationContext context) {
            throw new AssertionError("Unauthorized cancellation");
        }
        @Override public void requireReconciliation(TotpApplication.@NonNull ActionContext context) {
            throw new AssertionError("Unauthorized mutation attempted");
        }
    }
}
