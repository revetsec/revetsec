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
package example.passkeys;

import com.revetsec.OperationBinding;
import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.webauthn.*;
import com.revetsec.json.JsonString;
import com.soklet.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.net.Socket;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.security.MessageDigest;
import static org.junit.jupiter.api.Assertions.*;

/** Actual checked proofs and real app actions; no private proof construction or reflection bypass. */
final class PasskeyActionPolicyTests {
    private static final String RP = "passkeys.example.test";
    private static final String ORIGIN = "https://" + RP + ":9443";
    private static final String NAMESPACE = "proof-app";
    private static final String KEY = "A".repeat(43);
    private static final byte[] ACCOUNT = {1, 2, 3};
    private static final WebAuthnRecoveryGate ADMIT = remaining -> new WebAuthnRecoveryGate.Permit() {
        @Override public @NonNull Boolean isCurrent() { return true; }
        @Override public void close() { }
    };

    @Test void exactCeremonyAndPendingIdentityPreventOldProofNewTargetSubstitution() throws Exception {
        CoreFixture f = new CoreFixture(ACCOUNT, NAMESPACE, ADMIT);
        PasskeySessions sessions = sessions(Clock.systemUTC(), ACCOUNT, NAMESPACE, RP);
        var session = sessions.rotate(sessions.begin(), true);
        var a = f.start(session.binding, PasskeySessions.Action.SELF_REMOVAL.purpose);
        assertTrue(sessions.rememberAction(session, PasskeySessions.Action.SELF_REMOVAL, new byte[]{10}, a.getCeremonyId()));
        var pendingA = sessions.pendingAction(session, PasskeySessions.Action.SELF_REMOVAL, a.getCeremonyId()).orElseThrow();
        var proofA = f.complete(a, session.binding, PasskeySessions.Action.SELF_REMOVAL.purpose);
        var b = f.start(session.binding, PasskeySessions.Action.SELF_REMOVAL.purpose);
        assertTrue(sessions.rememberAction(session, PasskeySessions.Action.SELF_REMOVAL, new byte[]{20}, b.getCeremonyId()));
        var pendingB = sessions.pendingAction(session, PasskeySessions.Action.SELF_REMOVAL, b.getCeremonyId()).orElseThrow();
        assertTrue(sessions.completeAction(session, pendingA, proofA, "delivery-a").isEmpty(), "replaced-pending-object");
        assertTrue(sessions.completeAction(session, pendingB, proofA, "delivery-a").isEmpty(), "old-proof-new-ceremony");
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SELF_REMOVAL, new byte[]{20}));
        var proofB = f.complete(b, session.binding, PasskeySessions.Action.SELF_REMOVAL.purpose);
        assertTrue(sessions.completeAction(session, pendingB, proofB, "delivery-b").isPresent());
        assertTrue(sessions.completeAction(session, pendingB, proofB, "delivery-b").isEmpty(), "proof-cannot-recreate-consumed-pending");
        assertTrue(sessions.consumeAction(session, PasskeySessions.Action.SELF_REMOVAL, new byte[]{20}));
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SELF_REMOVAL, new byte[]{20}));
    }

    @Test void accountNamespaceRpPurposeAndCurrentSessionAreIndependentChecks() throws Exception {
        CoreFixture f = new CoreFixture(ACCOUNT, NAMESPACE, ADMIT);
        for (String mismatch : List.of("account", "namespace", "rp", "purpose", "session")) {
            PasskeySessions sessions = sessions(Clock.systemUTC(), mismatch.equals("account") ? new byte[]{9} : ACCOUNT,
                    mismatch.equals("namespace") ? "other" : NAMESPACE, mismatch.equals("rp") ? "other.example.test" : RP);
            var session = sessions.rotate(sessions.begin(), true);
            var prepared = f.start(session.binding, mismatch.equals("purpose") ? "other-action" : PasskeySessions.Action.SENSITIVE.purpose);
            assertTrue(sessions.rememberAction(session, PasskeySessions.Action.SENSITIVE, new byte[0], prepared.getCeremonyId()));
            var pending = sessions.pendingAction(session, PasskeySessions.Action.SENSITIVE, prepared.getCeremonyId()).orElseThrow();
            var proof = f.complete(prepared, session.binding, mismatch.equals("purpose") ? "other-action" : PasskeySessions.Action.SENSITIVE.purpose);
            if (mismatch.equals("session")) sessions.rotate(session, true);
            assertTrue(sessions.completeAction(session, pending, proof, "delivery").isEmpty(), mismatch);
            assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0]), mismatch);
        }
    }

    @Test void wrongActionOrExactTargetBurnsGrantAndAuthenticatingKeyNeedNotBeTarget() throws Exception {
        CoreFixture f = new CoreFixture(ACCOUNT, NAMESPACE, ADMIT);
        var sessions = sessions(Clock.systemUTC(), ACCOUNT, NAMESPACE, RP);
        var session = sessions.rotate(sessions.begin(), true);
        byte[] target = {42};
        authorize(f, sessions, session, PasskeySessions.Action.SELF_REMOVAL, target, "delivery");
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SELF_REMOVAL, new byte[]{43}));
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SELF_REMOVAL, target));
        authorize(f, sessions, session, PasskeySessions.Action.SELF_REMOVAL, target, "delivery2");
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0]));
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SELF_REMOVAL, target));
        authorize(f, sessions, session, PasskeySessions.Action.SELF_REMOVAL, target, "delivery3");
        assertFalse(MessageDigest.isEqual(target, Base64.getUrlDecoder().decode(f.authenticator.credentialId())));
        assertTrue(sessions.consumeAction(session, PasskeySessions.Action.SELF_REMOVAL, target));
    }

    @Test void actionGrantHasOneConcurrentWinnerAndExactExpiryDoesNotRevive() throws Exception {
        CoreFixture f = new CoreFixture(ACCOUNT, NAMESPACE, ADMIT);
        MutableClock clock = new MutableClock();
        var sessions = sessions(clock, ACCOUNT, NAMESPACE, RP);
        var session = sessions.rotate(sessions.begin(), true);
        authorize(f, sessions, session, PasskeySessions.Action.SENSITIVE, new byte[0], "delivery");
        try (var workers = Executors.newFixedThreadPool(2)) {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Boolean>> outcomes = new ArrayList<>();
            for (int i = 0; i < 2; i++) outcomes.add(workers.submit(() -> {
                if (!start.await(2, TimeUnit.SECONDS)) throw new AssertionError("action-race-start");
                return sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0]);
            }));
            start.countDown();int winners = 0;
            for (var outcome : outcomes) if (outcome.get(3, TimeUnit.SECONDS)) winners++;
            assertEquals(1, winners);
        }
        authorize(f, sessions, session, PasskeySessions.Action.SENSITIVE, new byte[0], "delivery2");
        Instant original = clock.instant();clock.now.set(original.plusSeconds(60));
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0]));
        clock.now.set(original);
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0]));
    }

    @Test void requestIdCounterOverflowRefusesWithoutWrapOrFallback() throws Exception {
        PasskeyApp app = new PasskeyApp(ORIGIN, RP, KEY, Clock.systemUTC());
        // Test-only boundary injection into the app counter, never a proof constructor or core state.
        var field = PasskeyApp.class.getDeclaredField("requestIds");
        assertTrue(field.trySetAccessible());
        AtomicLong counter = (AtomicLong) Objects.requireNonNull(field.get(app));
        counter.set(Long.MAX_VALUE);
        Request request = Request.fromPath(HttpMethod.GET, "/");
        assertThrows(ArithmeticException.class, () -> app.requestId(request));
        assertThrows(ArithmeticException.class, () -> app.requestId(request));
        assertEquals(Long.MAX_VALUE, counter.get());
        PasskeyApp independent = new PasskeyApp(ORIGIN, RP, KEY, Clock.systemUTC());
        assertNotNull(independent.requestId(request));
    }

    @Test void responseCleanupCannotRemoveNewerGrantOrAnotherAppOwner() throws Exception {
        CoreFixture f = new CoreFixture(ACCOUNT, NAMESPACE, ADMIT);
        var sessions = sessions(Clock.systemUTC(), ACCOUNT, NAMESPACE, RP);
        var session = sessions.rotate(sessions.begin(), true);
        PasskeyApp appA = new PasskeyApp(ORIGIN, RP, KEY, Clock.systemUTC());
        PasskeyApp appB = new PasskeyApp(ORIGIN, RP, KEY, Clock.systemUTC());
        Request request = Request.fromPath(HttpMethod.GET, "/");
        Object a = appA.requestId(request), b = appA.requestId(request), foreign = appB.requestId(request);
        assertNotEquals(a, b);assertNotEquals(a, foreign);
        assertEquals(a, request.copy().id(a).finish().copy().finish().getId());
        var oldGrant = authorize(f, sessions, session, PasskeySessions.Action.SENSITIVE, new byte[0], a);
        var freshGrant = authorize(f, sessions, session, PasskeySessions.Action.SENSITIVE, new byte[0], b);
        sessions.discardApproval(session, oldGrant);
        sessions.discardUnwrittenApproval(a);
        sessions.discardUnwrittenApproval(foreign);
        assertTrue(sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0]));
        sessions.discardApproval(session, freshGrant); // Known consumed action is never undone.
        authorize(f, sessions, session, PasskeySessions.Action.SENSITIVE, new byte[0], a);
        sessions.discardUnwrittenApproval(foreign);
        assertTrue(sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0]));
        authorize(f, sessions, session, PasskeySessions.Action.SENSITIVE, new byte[0], b);
        sessions.discardUnwrittenApproval(b);
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0]));
    }

    @Test void realSelfRemovalRequiresSelectedReauthenticationWhileOperatorRecoveryRemainsSeparate() throws Exception {
        RouteFixture f = new RouteFixture(ADMIT);
        var target = Map.of("X-Credential-Id", List.of(f.core.authenticator.credentialId()));
        assertEquals(403, f.app.selfRemoveCredential(f.post("/credentials/self-remove", target)).getStatusCode());
        var prepared = f.app.beginSelfRemoval(f.post("/credentials/self-remove/start", target));assertEquals(200, prepared.getStatusCode());
        String id = jsonString(prepared, "ceremonyId"), challenge = jsonString(prepared, "challenge");
        assertEquals(403, f.app.finishReauthentication(f.finish("/reauth/finish", id, f.core.authenticator.assertion(challenge, 1))).getStatusCode(), "wrong-selected-purpose-route");
        assertEquals(200, f.app.finishSelfRemoval(f.finish("/credentials/self-remove/finish", id, f.core.authenticator.assertion(challenge, 1))).getStatusCode());
        assertEquals(403, f.app.sensitiveAction(f.post("/sensitive", Map.of())).getStatusCode(), "removal-grant-not-sensitive");
        assertEquals(403, f.app.selfRemoveCredential(f.post("/credentials/self-remove", target)).getStatusCode(), "wrong-action-burned-grant");
        prepared = f.app.beginSelfRemoval(f.post("/credentials/self-remove/start", target));id = jsonString(prepared, "ceremonyId");challenge = jsonString(prepared, "challenge");
        byte[] assertion = f.core.authenticator.assertion(challenge, 2);
        assertEquals(200, f.app.finishSelfRemoval(f.finish("/credentials/self-remove/finish", id, assertion)).getStatusCode());
        assertEquals(403, f.app.finishSelfRemoval(f.finish("/credentials/self-remove/finish", id, assertion)).getStatusCode());
        int before = f.core.commits.get();
        assertEquals(200, f.app.selfRemoveCredential(f.post("/credentials/self-remove", target)).getStatusCode());
        assertEquals(before + 1, f.core.commits.get());
        assertEquals(403, f.app.selfRemoveCredential(f.post("/credentials/self-remove", target)).getStatusCode());
        assertTrue(f.core.party.listCredentialsResult(ACCOUNT) instanceof WebAuthnCredentialListResult.Listed listed && listed.getCredentialIds().isEmpty());
        RouteFixture recovery = new RouteFixture(ADMIT);
        assertEquals(403, recovery.app.removeCredential(recovery.post("/credentials/remove", target)).getStatusCode());
        assertEquals(200, recovery.app.removeCredential(recovery.post("/credentials/remove", Map.of("X-Credential-Id", target.get("X-Credential-Id"), "X-Demo-Access-Key", List.of(KEY)))).getStatusCode());
    }

    @Test void realSecondCredentialMayAuthorizeRemovalOfDifferentSameAccountTarget() throws Exception {
        RouteFixture f = new RouteFixture(ADMIT);
        SyntheticAuthenticator second = new SyntheticAuthenticator(ACCOUNT, new byte[]{99, 98, 97});
        var enrollment = f.app.beginRegistration(f.post("/register/start", Map.of("X-Demo-Access-Key", List.of(KEY))));
        assertEquals(200, enrollment.getStatusCode());
        assertEquals(200, f.app.finishRegistration(f.finish("/register/finish", jsonString(enrollment, "ceremonyId"), second.registration(jsonString(enrollment, "challenge")))).getStatusCode());
        assertNotEquals(f.core.authenticator.credentialId(), second.credentialId());
        var target = Map.of("X-Credential-Id", List.of(f.core.authenticator.credentialId()));
        var prepared = f.app.beginSelfRemoval(f.post("/credentials/self-remove/start", target));
        assertEquals(200, prepared.getStatusCode());
        assertEquals(200, f.app.finishSelfRemoval(f.finish("/credentials/self-remove/finish", jsonString(prepared, "ceremonyId"), second.assertion(jsonString(prepared, "challenge"), 1))).getStatusCode());
        int before = f.core.commits.get();
        assertEquals(200, f.app.selfRemoveCredential(f.post("/credentials/self-remove", target)).getStatusCode());
        assertEquals(before + 1, f.core.commits.get());
        var listed = assertInstanceOf(WebAuthnCredentialListResult.Listed.class, f.core.party.listCredentialsResult(ACCOUNT));
        assertEquals(1, listed.getCredentialIds().size());
        assertEquals(second.credentialId(), Base64.getUrlEncoder().withoutPadding().encodeToString(listed.getCredentialIds().get(0)));
        prepared = f.app.beginReauthentication(f.post("/reauth/start", Map.of()));
        assertEquals(200, f.app.finishReauthentication(f.finish("/reauth/finish", jsonString(prepared, "ceremonyId"), second.assertion(jsonString(prepared, "challenge"), 2))).getStatusCode());
        assertEquals(200, f.app.sensitiveAction(f.post("/sensitive", Map.of())).getStatusCode());
    }

    @Test void enteredActionClockFailureCannotRefundItsOneUseGrant() throws Exception {
        CoreFixture f = new CoreFixture(ACCOUNT, NAMESPACE, ADMIT);
        MutableClock clock = new MutableClock();var sessions = sessions(clock, ACCOUNT, NAMESPACE, RP);
        var session = sessions.rotate(sessions.begin(), true);
        authorize(f, sessions, session, PasskeySessions.Action.SENSITIVE, new byte[0], "delivery");
        clock.unavailable.set(true);
        try { assertThrows(IllegalStateException.class, () -> sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0])); }
        finally { clock.unavailable.set(false); }
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0]), "entered-action-clock-failure-cannot-refund");
    }

    @Test void observedRefusalCleanupDoesNotReadClockOrInvokeCollaborators() throws Exception {
        CoreFixture f = new CoreFixture(ACCOUNT, NAMESPACE, ADMIT);
        MutableClock clock = new MutableClock();
        var sessions = sessions(clock, ACCOUNT, NAMESPACE, RP);
        var session = sessions.rotate(sessions.begin(), true);
        authorize(f, sessions, session, PasskeySessions.Action.SENSITIVE, new byte[0], "delivery");
        clock.unavailable.set(true);
        try { assertDoesNotThrow(() -> sessions.discardUnwrittenApproval("delivery"), "exact-refusal-cleanup-must-not-depend-on-clock"); }
        finally { clock.unavailable.set(false); }
        assertFalse(sessions.consumeAction(session, PasskeySessions.Action.SENSITIVE, new byte[0]));
    }

    @Test void successfulPermitCloseCannotPublishExpiredApproval() throws Exception {
        SelectedGate gate = new SelectedGate();MutableClock clock = new MutableClock();RouteFixture f = new RouteFixture(gate, clock);
        var prepared = f.app.beginReauthentication(f.post("/reauth/start", Map.of()));
        gate.closeAction.set(() -> clock.now.updateAndGet(now -> now.plusSeconds(61)));gate.selectNext.set(true);
        int before = f.core.commits.get();
        assertEquals(503, f.app.finishReauthentication(f.finish("/reauth/finish", jsonString(prepared, "ceremonyId"), f.core.authenticator.assertion(jsonString(prepared, "challenge"), 1))).getStatusCode(), "postclose-expired-approval-withheld");
        assertEquals(before + 1, f.core.commits.get());
        assertEquals(403, f.app.sensitiveAction(f.post("/sensitive", Map.of())).getStatusCode());
    }

    @Test void successfulPermitCloseClockFailureBurnsWithoutDependingOnClockRecovery() throws Exception {
        SelectedGate gate = new SelectedGate();MutableClock clock = new MutableClock();RouteFixture f = new RouteFixture(gate, clock);
        var prepared = f.app.beginReauthentication(f.post("/reauth/start", Map.of()));
        gate.closeAction.set(() -> clock.unavailable.set(true));gate.selectNext.set(true);int before = f.core.commits.get();
        try {
            assertEquals(503, f.app.finishReauthentication(f.finish("/reauth/finish", jsonString(prepared, "ceremonyId"), f.core.authenticator.assertion(jsonString(prepared, "challenge"), 1))).getStatusCode());
        } finally { clock.unavailable.set(false); }
        assertEquals(before + 1, f.core.commits.get());
        assertEquals(403, f.app.sensitiveAction(f.post("/sensitive", Map.of())).getStatusCode());
    }

    @Test void successfulPermitCloseInterruptionCannotLeaveUsableWithheldApproval() throws Exception {
        SelectedGate gate = new SelectedGate();RouteFixture f = new RouteFixture(gate);
        var prepared = f.app.beginReauthentication(f.post("/reauth/start", Map.of()));
        gate.closeAction.set(() -> Thread.currentThread().interrupt());gate.selectNext.set(true);
        int before = f.core.commits.get();int status;
        try {
            status = f.app.finishReauthentication(f.finish("/reauth/finish", jsonString(prepared, "ceremonyId"), f.core.authenticator.assertion(jsonString(prepared, "challenge"), 1))).getStatusCode();
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { assertTrue(Thread.interrupted()); }
        int later = f.app.sensitiveAction(f.post("/sensitive", Map.of())).getStatusCode();
        assertEquals(503, status, "postclose-cancelled-approval-withheld");
        assertEquals(403, later, "later-readmission-cannot-use-withheld-approval");
        assertEquals(before + 1, f.core.commits.get());
    }

    @Test void successfulPermitCloseReplacementPreservesNewPendingAndRefusesOldApproval() throws Exception {
        SelectedGate gate = new SelectedGate();RouteFixture f = new RouteFixture(gate);
        var prepared = f.app.beginReauthentication(f.post("/reauth/start", Map.of()));
        AtomicReference<@Nullable MarshaledResponse> replacement = new AtomicReference<>();
        gate.closeAction.set(() -> replacement.set(f.app.beginReauthentication(f.post("/reauth/start", Map.of()))));gate.selectNext.set(true);
        int before = f.core.commits.get();
        assertEquals(503, f.app.finishReauthentication(f.finish("/reauth/finish", jsonString(prepared, "ceremonyId"), f.core.authenticator.assertion(jsonString(prepared, "challenge"), 1))).getStatusCode(), "postclose-replaced-approval-withheld");
        assertEquals(before + 2, f.core.commits.get(), "old-completion-and-explicit-new-begin");
        MarshaledResponse fresh = Objects.requireNonNull(replacement.get());assertEquals(200, fresh.getStatusCode());
        assertEquals(200, f.app.finishReauthentication(f.finish("/reauth/finish", jsonString(fresh, "ceremonyId"), f.core.authenticator.assertion(jsonString(fresh, "challenge"), 2))).getStatusCode(), "new-pending-survives-old-frame-burn");
        assertEquals(200, f.app.sensitiveAction(f.post("/sensitive", Map.of())).getStatusCode());
    }

    @Test void finalAppPermitRefusalBurnsOnlyCreatedApprovalBeforeLaterReadmission() throws Exception {
        assertWithheldApproval(false);
    }

    @Test void finalAppPermitCloseFailureBurnsKnownApprovalWithoutRetryOrCoreRollback() throws Exception {
        assertWithheldApproval(true);
    }

    @Test void actualSokletHandoffRefusalBurnsOnlyItsKnownApprovalAndSharedConfigsUseUniqueIds() throws Exception {
        SelectedGate gate = new SelectedGate();RouteFixture f = new RouteFixture(gate);
        java.util.concurrent.ConcurrentLinkedQueue<Object> actualIds = new java.util.concurrent.ConcurrentLinkedQueue<>();
        CountDownLatch writeFailed = new CountDownLatch(1);
        LifecycleObserver observer = new LifecycleObserver() {
            @Override public void didStartRequestHandling(@NonNull ServerType type, @NonNull Request request,
                    @Nullable ResourceMethod method) { actualIds.add(request.getId()); }
            @Override public void didFailToWriteResponse(@NonNull ServerType type, @NonNull Request request,
                    @Nullable ResourceMethod method, @NonNull MarshaledResponse response,
                    @NonNull Duration elapsed, @NonNull Throwable failure) { writeFailed.countDown(); }
        };
        int first = port(), second = port();
        AtomicBoolean handoffRefusal = new AtomicBoolean();
        var configA = observedConfig(f.app, first, observer, handoffRefusal);
        var configB = observedConfig(f.app, second, observer, new AtomicBoolean());
        Soklet.run(configA, () -> Soklet.run(configB, () -> {
            assertEquals(200, rawGet(first));assertEquals(200, rawGet(second));
            assertEquals(2, actualIds.size());assertEquals(2, new HashSet<>(actualIds).size(), "same-App-configs-share-sequence");
            var prepared = f.app.beginReauthentication(f.post("/reauth/start", Map.of()));
            String id = jsonString(prepared, "ceremonyId"), challenge = jsonString(prepared, "challenge");
            byte[] assertion = f.core.authenticator.assertion(challenge, 1);
            try (var socket = new Socket("127.0.0.1", first)) {
                socket.setSoTimeout(4000);writeFinish(socket, f, id, assertion);
                String response = new String(socket.getInputStream().readNBytes(10000), java.nio.charset.StandardCharsets.US_ASCII);
                assertTrue(response.startsWith("HTTP/1.1 200 "), "real-listener-valid-proof-approval");
            }
            assertEquals(200, f.app.sensitiveAction(f.post("/sensitive", Map.of())).getStatusCode());
            assertEquals(403, f.app.sensitiveAction(f.post("/sensitive", Map.of())).getStatusCode());
            prepared = f.app.beginReauthentication(f.post("/reauth/start", Map.of()));
            id = jsonString(prepared, "ceremonyId");challenge = jsonString(prepared, "challenge");
            assertion = f.core.authenticator.assertion(challenge, 2);
            handoffRefusal.set(true);int before = f.core.commits.get();
            try (var socket = new Socket("127.0.0.1", first)) {
                socket.setSoTimeout(4000);writeFinish(socket, f, id, assertion);
                assertTrue(writeFailed.await(4, TimeUnit.SECONDS), "actual-framework-synchronous-handoff-refusal-hook");
                assertEquals(before + 1, f.core.commits.get(), "known-core-effect-before-handoff-refusal");
            }
            assertFalse(handoffRefusal.get(), "exact-one-injected-handoff-refusal");
            assertEquals(403, f.app.sensitiveAction(f.post("/sensitive", Map.of())).getStatusCode(), "write-refusal-grant-not-usable");
            assertEquals(before + 1, f.core.commits.get(), "no-core-rollback-refund-or-retry");
        }));
    }

    private static int port() throws Exception {
        try (var socket = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) { return socket.getLocalPort(); }
    }

    private static @NonNull SokletConfig observedConfig(@NonNull PasskeyApp app, int port,
            @NonNull LifecycleObserver observer, @NonNull AtomicBoolean handoffRefusal) {
        SokletConfig base = PasskeyPlayground.config(app, port);
        List<LifecycleObserver> observers = new ArrayList<>(base.getLifecycleObservers());observers.add(observer);
        HttpServer delegate = base.getHttpServer().orElseThrow();
        HttpServer boundary = new HttpServer() {
            @Override public @NonNull TransportIdentity getTransportIdentity() { return delegate.getTransportIdentity(); }
            @Override public @NonNull TransportRuntime attach(@NonNull HttpTransportAttachmentContext context,
                    @NonNull StartupContext startup) {
                HttpServer.RequestHandler admitted = context.getAdmissionFencedRequestHandler();
                return context.attachTransparentDelegate(delegate, (request, downstream) ->
                        admitted.handleRequest(request, result -> {
                            if (request.getPath().equals("/reauth/finish") && handoffRefusal.compareAndSet(true, false)) {
                                // Selected PIN56 app response is an in-memory byte body; no close API/resource.
                                throw new java.io.UncheckedIOException(new java.io.IOException("TEST-ONLY-synchronous-handoff-refusal"));
                            }
                            downstream.accept(result);
                        }));
            }
        };
        return SokletConfig.withHttpServer(boundary)
                .instanceProvider(base.getInstanceProvider()).resourceMethodResolver(base.getResourceMethodResolver())
                .valueConverterRegistry(base.getValueConverterRegistry()).requestBodyMarshaler(base.getRequestBodyMarshaler())
                .resourceMethodParameterProvider(base.getResourceMethodParameterProvider()).responseMarshaler(base.getResponseMarshaler())
                .requestInterceptor(base.getRequestInterceptor()).metricsCollector(base.getMetricsCollector())
                .corsAuthorizer(base.getCorsAuthorizer()).lifecyclePolicy(base.getLifecyclePolicy()).lifecycleObservers(observers).build();
    }

    private static int rawGet(int port) throws Exception {
        try (var socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(4000);socket.getOutputStream().write(("GET / HTTP/1.1\r\nHost: "+RP+":9443\r\nConnection: close\r\n\r\n").getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            String response = new String(socket.getInputStream().readNBytes(10000), java.nio.charset.StandardCharsets.US_ASCII);
            return Integer.parseInt(response.substring(9, 12));
        }
    }

    private static void writeFinish(@NonNull Socket socket, @NonNull RouteFixture f,
            @NonNull String ceremony, byte @NonNull [] body) throws Exception {
        String headers = "POST /reauth/finish HTTP/1.1\r\nHost: "+RP+":9443\r\nOrigin: "+ORIGIN
                +"\r\nCookie: "+f.cookie+"\r\nX-CSRF-Token: "+f.csrf+"\r\nX-Ceremony-Id: "+ceremony
                +"\r\nContent-Type: application/json\r\nContent-Length: "+body.length+"\r\nConnection: close\r\n\r\n";
        socket.getOutputStream().write(headers.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        socket.getOutputStream().write(body);socket.getOutputStream().flush();
    }

    private static void assertWithheldApproval(boolean closeFailure) throws Exception {
        SelectedGate gate = new SelectedGate();RouteFixture f = new RouteFixture(gate);
        var prepared = f.app.beginReauthentication(f.post("/reauth/start", Map.of()));
        String id = jsonString(prepared, "ceremonyId"), challenge = jsonString(prepared, "challenge");
        gate.mode.set(closeFailure ? 2 : 1);gate.selectNext.set(true);int before = f.core.commits.get();
        assertEquals(503, f.app.finishReauthentication(f.finish("/reauth/finish", id, f.core.authenticator.assertion(challenge, 1))).getStatusCode());
        assertEquals(before + 1, f.core.commits.get(), "known-commit-withheld-approval");
        gate.mode.set(0);
        assertEquals(403, f.app.sensitiveAction(f.post("/sensitive", Map.of())).getStatusCode(), "readmission-cannot-use-withheld-grant");
        assertEquals(before + 1, f.core.commits.get(), "no-refund-retry-or-proof-rescue");
    }

    private static PasskeySessions.@NonNull AuthorizedAction authorize(@NonNull CoreFixture f,
            @NonNull PasskeySessions sessions, PasskeySessions.@NonNull Session session,
            PasskeySessions.@NonNull Action action, byte @NonNull [] target, @NonNull Object delivery) throws Exception {
        var prepared = f.start(session.binding, action.purpose);
        assertTrue(sessions.rememberAction(session, action, target, prepared.getCeremonyId()));
        var pending = sessions.pendingAction(session, action, prepared.getCeremonyId()).orElseThrow();
        return sessions.completeAction(session, pending, f.complete(prepared, session.binding, action.purpose), delivery).orElseThrow();
    }

    private static @NonNull PasskeySessions sessions(@NonNull Clock clock, byte @NonNull [] account,
            @NonNull String namespace, @NonNull String rp) { return new PasskeySessions(clock, 8, account, namespace, rp); }

    private static final class CoreFixture {
        final @NonNull SyntheticAuthenticator authenticator;
        final @NonNull WebAuthnRelyingParty party;
        final @NonNull AtomicInteger commits = new AtomicInteger();
        long counter;
        CoreFixture(byte @NonNull [] account, @NonNull String namespace, @NonNull WebAuthnRecoveryGate gate) throws Exception {
            this.authenticator = new SyntheticAuthenticator(account);
            WebAuthnStore delegate = InMemoryWebAuthnStore.fromLimits(1024, 8_388_608L);
            WebAuthnStore store = new WebAuthnStore() {
                @Override public @NonNull WebAuthnStoreReadResult read(@NonNull Set<@NonNull WebAuthnStoreKey> keys, @NonNull Duration remaining) { return delegate.read(keys, remaining); }
                @Override public @NonNull WebAuthnStoreCommitReceipt compareAndCommit(@NonNull WebAuthnStoreWrite write, @NonNull Duration remaining) { commits.incrementAndGet();return delegate.compareAndCommit(write, remaining); }
            };
            this.party = WebAuthnRelyingParty.withRelyingPartyId(RP).relyingPartyName("Proof fixture")
                    .allowedOrigins(Set.of(ORIGIN)).credentialNamespace(namespace).store(store)
                    .stateSealer(StateSealer.withActiveKey(SealingKey.fromBase64("test", Base64.getEncoder().encodeToString("0123456789abcdef0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.US_ASCII)))).build())
                    .recoveryGate(gate).build();
            OperationBinding binding = OperationBinding.fresh();
            var begin = assertInstanceOf(WebAuthnRegistrationRequestResult.Prepared.class, this.party.beginRegistrationResult(WebAuthnRegistrationOptions.withUserHandle(account).userName("test").userDisplayName("Test").build(), binding)).getRequest();
            assertInstanceOf(WebAuthnRegistrationResult.Succeeded.class, this.party.completeRegistrationResult(begin.getCeremonyId(), this.authenticator.registration(challenge(begin)), binding));
        }
        @NonNull WebAuthnBrowserRequest start(@NonNull OperationBinding binding, @NonNull String purpose) {
            return assertInstanceOf(WebAuthnAuthenticationRequestResult.Prepared.class, this.party.beginReauthenticationResult(ACCOUNT, purpose, binding)).getRequest();
        }
        @NonNull WebAuthnReauthentication complete(@NonNull WebAuthnBrowserRequest prepared, @NonNull OperationBinding binding, @NonNull String purpose) throws Exception {
            return assertInstanceOf(WebAuthnReauthenticationResult.Succeeded.class, this.party.completeReauthenticationResult(ACCOUNT, purpose, prepared.getCeremonyId(), this.authenticator.assertion(challenge(prepared), ++this.counter), binding)).getReauthentication();
        }
    }

    private static @NonNull String challenge(@NonNull WebAuthnBrowserRequest prepared) {
        return prepared.getPublicKeyOptions().find("challenge").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow();
    }

    private static final class RouteFixture {
        final @NonNull CoreFixture core;
        final @NonNull PasskeyApp app;
        final @NonNull String cookie;
        final @NonNull String csrf;
        RouteFixture(@NonNull WebAuthnRecoveryGate gate) throws Exception { this(gate, Clock.systemUTC()); }
        RouteFixture(@NonNull WebAuthnRecoveryGate gate, @NonNull Clock clock) throws Exception {
            this.core = new CoreFixture(ACCOUNT, NAMESPACE, gate);
            this.app = new PasskeyApp(ORIGIN, RP, KEY, clock, ACCOUNT, NAMESPACE, this.core.party, gate);
            var home = this.app.index(request("GET", "/", Map.of(), null));
            String anonymous = cookie(home), token = htmlCsrf(home);
            var login = this.app.accessLogin(request("POST", "/access-login", Map.of("Cookie", List.of(anonymous), "X-CSRF-Token", List.of(token), "X-Demo-Access-Key", List.of(KEY)), null));
            assertEquals(200, login.getStatusCode());this.cookie = cookie(login);
            this.csrf = htmlCsrf(this.app.index(request("GET", "/", Map.of("Cookie", List.of(this.cookie)), null)));
        }
        @NonNull Request post(@NonNull String path, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> extra) { return call(path, extra, null); }
        @NonNull Request finish(@NonNull String path, @NonNull String id, byte @NonNull [] body) { return call(path, Map.of("Content-Type", List.of("application/json"), "X-Ceremony-Id", List.of(id)), body); }
        private @NonNull Request call(@NonNull String path, @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> extra, byte @Nullable [] body) {
            Map<String,List<String>> fields = new LinkedHashMap<>(extra);fields.put("Cookie", List.of(this.cookie));fields.put("X-CSRF-Token", List.of(this.csrf));return request("POST", path, fields, body);
        }
    }

    private static @NonNull Request request(@NonNull String method, @NonNull String path,
            @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers, byte @Nullable [] body) {
        Map<String,List<String>> all = new LinkedHashMap<>(headers);all.put("Host", List.of(RP + ":9443"));if(method.equals("POST"))all.put("Origin", List.of(ORIGIN));
        var builder = Request.withRawUrl(method.equals("POST") ? HttpMethod.POST : HttpMethod.GET, path).headers(all);if(body!=null)builder.body(body);return builder.build();
    }
    private static @NonNull String body(@NonNull MarshaledResponse response) { return new String(((MarshaledResponseBody.Bytes)response.getBody().orElseThrow()).getBytes(), java.nio.charset.StandardCharsets.UTF_8); }
    private static @NonNull String cookie(@NonNull MarshaledResponse response) { var c=response.getCookies().iterator().next();return c.getName() + "=" + c.getValue().orElseThrow(); }
    private static @NonNull String htmlCsrf(@NonNull MarshaledResponse response) { return capture(body(response), "data-csrf='([A-Za-z0-9_-]{43})'"); }
    private static @NonNull String jsonString(@NonNull MarshaledResponse response, @NonNull String field) { return capture(body(response), "\\\""+field+"\\\":\\\"([A-Za-z0-9_-]{43})\\\""); }
    private static @NonNull String capture(@NonNull String text, @NonNull String pattern) { var m=java.util.regex.Pattern.compile(pattern).matcher(text);assertTrue(m.find(),"fixed-fixture-field");return m.group(1); }

    private static final class MutableClock extends Clock {
        final @NonNull AtomicReference<@NonNull Instant> now = new AtomicReference<>(Instant.now());
        final @NonNull AtomicBoolean unavailable = new AtomicBoolean();
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
        @Override public @NonNull Instant instant() { if (this.unavailable.get()) throw new IllegalStateException("TEST-ONLY-clock-unavailable"); return Objects.requireNonNull(this.now.get()); }
    }
    private static final class SelectedGate implements WebAuthnRecoveryGate {
        final @NonNull AtomicBoolean selectNext = new AtomicBoolean();
        final @NonNull AtomicInteger mode = new AtomicInteger();
        final @NonNull AtomicReference<@Nullable Runnable> closeAction = new AtomicReference<>();
        @Override public @NonNull Permit acquire(@NonNull Duration remaining) {
            boolean selected = this.selectNext.getAndSet(false);
            return new Permit() {
                int validations;
                @Override public @NonNull Boolean isCurrent() { return !selected || mode.get()!=1 || ++this.validations<2; }
                @Override public void close() {
                    if(selected && mode.get()==2)throw new IllegalStateException("TEST-ONLY-fixed-close-refusal");
                    Runnable action = selected ? closeAction.getAndSet(null) : null;
                    if (action != null) action.run();

                }
            };
        }
    }
}
