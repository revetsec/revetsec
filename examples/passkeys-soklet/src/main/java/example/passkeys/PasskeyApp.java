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

import com.revetsec.SealingKey;
import com.revetsec.StateSealer;
import com.revetsec.webauthn.InMemoryWebAuthnStore;
import com.revetsec.webauthn.WebAuthnAuthentication;
import com.revetsec.webauthn.WebAuthnAuthenticationRequestResult;
import com.revetsec.webauthn.WebAuthnAuthenticationResult;
import com.revetsec.webauthn.WebAuthnCredentialListResult;
import com.revetsec.webauthn.WebAuthnCredentialRemovalResult;
import com.revetsec.webauthn.WebAuthnRecoveryGate;
import com.revetsec.webauthn.WebAuthnRegistrationOptions;
import com.revetsec.webauthn.WebAuthnRegistrationRequestResult;
import com.revetsec.webauthn.WebAuthnRegistrationResult;
import com.revetsec.webauthn.WebAuthnRelyingParty;
import com.soklet.MarshaledResponse;
import com.soklet.Request;
import com.soklet.annotation.GET;
import com.soklet.annotation.POST;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** One disposable, single-account browser demonstration; identity and sessions belong to this app. */
public final class PasskeyApp {
    private static final String PURPOSE = "demo-sensitive-action";
    private static final String CSP = "default-src 'none'; script-src 'self'; connect-src 'self'; "
            + "form-action 'none'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'";
    private final @NonNull String origin;
    private final @NonNull String authority;
    private final @NonNull String accessKey;
    private final byte @NonNull [] accountHandle;
    private final @NonNull PasskeySessions sessions;
    private final @NonNull WebAuthnRelyingParty relyingParty;
    private final @NonNull WebAuthnRecoveryGate admissionGate;
    private final @NonNull AtomicBoolean admissionOpen;
    private final @NonNull String storageNotice;
    private final byte @NonNull [] script;

    PasskeyApp(@NonNull String origin, @NonNull String relyingPartyId,
            @NonNull String accessKey, @NonNull Clock clock) throws IOException {
        this(origin, relyingPartyId, accessKey, clock, freshSetup(origin, relyingPartyId));
    }

    /**
     * Uses application-owned account identity, store, sealing keys and recovery gate. Browser
     * sessions remain local to this example process; callers must coordinate them separately
     * before routing one session across nodes. The supplied relying party must use the same
     * trusted RP ID and origin. Supply the same reentrant recovery gate instance to the relying
     * party and this constructor so a permit spans both verification and the session transition.
     * Its construction is an application configuration decision.
     */
    public PasskeyApp(@NonNull String origin, @NonNull String relyingPartyId,
            @NonNull String accessKey, @NonNull Clock clock,
            byte @NonNull [] accountHandle, @NonNull WebAuthnRelyingParty relyingParty,
            @NonNull WebAuthnRecoveryGate admissionGate)
            throws IOException {
        this(origin, relyingPartyId, accessKey, clock, new Setup(accountHandle, relyingParty,
                admissionGate, new AtomicBoolean(true), "Application-owned passkey state. Browser sessions "
                + "are local to this process and expire on restart."));
    }

    private PasskeyApp(@NonNull String origin, @NonNull String relyingPartyId,
            @NonNull String accessKey, @NonNull Clock clock, @NonNull Setup setup) throws IOException {
        URI parsed = URI.create(origin);
        if (!"https".equals(parsed.getScheme()) || !relyingPartyId.equals(parsed.getHost())
                || parsed.getRawUserInfo() != null || parsed.getRawQuery() != null
                || parsed.getRawFragment() != null || !parsed.getRawPath().isEmpty()
                || parsed.getPort() == 0 || parsed.getPort() > 65535
                || !origin.equals(parsed.toString())) throw new IllegalArgumentException("Invalid passkey origin");
        if (!accessKey.matches("[A-Za-z0-9_-]{43}")) throw new IllegalArgumentException("Invalid access key");
        this.origin = origin;
        this.authority = parsed.getRawAuthority();
        this.accessKey = accessKey;
        if (setup.accountHandle.length < 1 || setup.accountHandle.length > 64)
            throw new IllegalArgumentException("Invalid account handle");
        this.accountHandle = setup.accountHandle.clone();
        this.sessions = new PasskeySessions(clock, 64);
        this.relyingParty = Objects.requireNonNull(setup.relyingParty);
        this.admissionGate = Objects.requireNonNull(setup.admissionGate);
        this.admissionOpen = setup.admissionOpen;
        this.storageNotice = setup.storageNotice;
        try (InputStream resource = PasskeyApp.class.getResourceAsStream("/passkeys/app.js")) {
            if (resource == null) throw new IOException("Passkey browser script missing");
            this.script = resource.readAllBytes();
        }
    }

    private static @NonNull Setup freshSetup(@NonNull String origin, @NonNull String relyingPartyId) {
        AtomicBoolean admissionOpen = new AtomicBoolean(true);
        byte[] sealingMaterial = Base64.getUrlDecoder().decode(PasskeySessions.randomId());
        StateSealer sealer = StateSealer.withActiveKey(SealingKey.fromBase64("passkey-demo",
                Base64.getEncoder().encodeToString(sealingMaterial))).build();
        java.util.Arrays.fill(sealingMaterial, (byte) 0);
        WebAuthnRecoveryGate freshProcessOnly = remaining -> {
            if (!admissionOpen.get() || remaining.isNegative() || remaining.isZero()
                    || Thread.currentThread().isInterrupted()) return null;
            return new WebAuthnRecoveryGate.Permit() {
                @Override public boolean isCurrent() { return admissionOpen.get(); }
                @Override public void close() { }
            };
        };
        WebAuthnRelyingParty relyingParty = WebAuthnRelyingParty.withRelyingPartyId(relyingPartyId)
                .relyingPartyName("Revetsec Passkey Demo").allowedOrigins(Set.of(origin))
                .credentialNamespace("fresh-" + PasskeySessions.randomId())
                .store(InMemoryWebAuthnStore.withLimits(1024, 8_388_608))
                .stateSealer(sealer).recoveryGate(freshProcessOnly).build();
        return new Setup(Base64.getUrlDecoder().decode(PasskeySessions.randomId()), relyingParty,
                freshProcessOnly, admissionOpen, "Single-process disposable account. Passkeys, sessions and "
                + "sealing key disappear on restart.");
    }

    private record Setup(byte @NonNull [] accountHandle, @NonNull WebAuthnRelyingParty relyingParty,
            @NonNull WebAuthnRecoveryGate admissionGate, @NonNull AtomicBoolean admissionOpen,
            @NonNull String storageNotice) { }

    @GET("/") public @NonNull MarshaledResponse index(@NonNull Request request) {
        return admittedResponse(() -> indexRoute(request));
    }

    private @NonNull MarshaledResponse indexRoute(@NonNull Request request) {
        if (!host(request)) return text(403, "Request denied.");
        try {
            PasskeySessions.Session session = this.sessions.find(request).orElse(null);
            boolean newSession = session == null;
            if (newSession) session = this.sessions.begin();
            String html = "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
                    + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    + "<title>Revetsec passkey demo</title></head><body data-authenticated='"
                    + session.authenticated + "' data-csrf='" + session.csrf + "'>"
                    + "<h1>Revetsec passkey demo</h1><p>" + this.storageNotice + "</p>"
                    + "<section id='login'><label>Demo access key <input id='access' type='password' autocomplete='off' maxlength='43'></label>"
                    + "<button id='access-login'>Approve enrollment</button> <button id='sign-in'>Sign in with passkey</button></section>"
                    + "<section id='account' hidden><p>Signed in to the fixed demo account.</p>"
                    + "<button id='register'>Register passkey</button> <button id='list'>List passkeys</button>"
                    + "<ul id='credentials'></ul><button id='reauth'>Reauthenticate for sensitive action</button> "
                    + "<button id='sensitive'>Perform sensitive action</button> <button id='logout'>Sign out</button></section>"
                    + "<p id='status' role='status' aria-live='polite'></p><script src='/app.js' defer></script></body></html>";
            MarshaledResponse response = response(200, "text/html; charset=UTF-8",
                    html.getBytes(StandardCharsets.UTF_8));
            return newSession ? response.copy().cookies(List.of(this.sessions.cookie(session))).finish() : response;
        } catch (IllegalStateException capacity) {
            return text(503, "Local demo unavailable.");
        }
    }

    @GET("/app.js") public @NonNull MarshaledResponse script(@NonNull Request request) {
        return admittedResponse(() -> scriptRoute(request));
    }

    private @NonNull MarshaledResponse scriptRoute(@NonNull Request request) {
        return host(request) ? response(200, "text/javascript; charset=UTF-8", this.script)
                : text(403, "Request denied.");
    }

    @POST("/access-login") public @NonNull MarshaledResponse accessLogin(@NonNull Request request) {
        return admittedResponse(() -> accessLoginRoute(request));
    }

    private @NonNull MarshaledResponse accessLoginRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, false);
        if (session == null || !emptyBody(request)) return text(403, "Request denied.");
        List<String> supplied = headers(request, "X-Demo-Access-Key");
        if (supplied.size() != 1 || !matches(this.accessKey, supplied.get(0)))
            return text(403, "Request denied.");
        return rotated(session, true);
    }

    @POST("/register/start") public @NonNull MarshaledResponse beginRegistration(@NonNull Request request) {
        return admittedResponse(() -> beginRegistrationRoute(request));
    }

    private @NonNull MarshaledResponse beginRegistrationRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, true);
        if (session == null || !emptyBody(request)) return text(403, "Request denied.");
        WebAuthnRegistrationOptions options = WebAuthnRegistrationOptions
                .withUserHandle(this.accountHandle).userName("demo-account")
                .userDisplayName("Demo Account").build();
        WebAuthnRegistrationRequestResult result = this.relyingParty.beginRegistrationResult(options, session.binding);
        if (result instanceof WebAuthnRegistrationRequestResult.Prepared prepared)
            return json(200, prepared.getRequest().getJson());
        if (result instanceof WebAuthnRegistrationRequestResult.Indeterminate) return uncertain();
        return result instanceof WebAuthnRegistrationRequestResult.Unavailable
                ? text(503, "Local demo unavailable.") : text(400, "Request rejected.");
    }

    @POST("/register/finish") public @NonNull MarshaledResponse finishRegistration(@NonNull Request request) {
        return admittedResponse(() -> finishRegistrationRoute(request));
    }

    private @NonNull MarshaledResponse finishRegistrationRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, true);
        byte[] body = credentialBody(request);
        String ceremony = ceremonyId(request);
        if (session == null || body == null || ceremony == null) return text(403, "Request denied.");
        WebAuthnRegistrationResult result = this.relyingParty.completeRegistrationResult(ceremony, body, session.binding);
        if (result instanceof WebAuthnRegistrationResult.Succeeded success
                && MessageDigest.isEqual(this.accountHandle, success.getRegistration().getUserHandle()))
            return text(200, "Passkey registered.");
        if (result instanceof WebAuthnRegistrationResult.Indeterminate) return uncertain();
        return result instanceof WebAuthnRegistrationResult.Unavailable
                ? text(503, "Local demo unavailable.") : text(400, "Registration rejected.");
    }

    @POST("/sign-in/start") public @NonNull MarshaledResponse beginSignIn(@NonNull Request request) {
        return admittedResponse(() -> beginSignInRoute(request));
    }

    private @NonNull MarshaledResponse beginSignInRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, false);
        if (session == null || !emptyBody(request)) return text(403, "Request denied.");
        return authenticationStart(this.relyingParty.beginAuthenticationResult(session.binding));
    }

    @POST("/sign-in/finish") public @NonNull MarshaledResponse finishSignIn(@NonNull Request request) {
        return admittedResponse(() -> finishSignInRoute(request));
    }

    private @NonNull MarshaledResponse finishSignInRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, false);
        byte[] body = credentialBody(request);
        String ceremony = ceremonyId(request);
        if (session == null || body == null || ceremony == null) return text(403, "Request denied.");
        WebAuthnAuthenticationResult result = this.relyingParty.completeAuthenticationResult(ceremony, body, session.binding);
        if (result instanceof WebAuthnAuthenticationResult.Succeeded success) {
            WebAuthnAuthentication proof = success.getAuthentication();
            if (proof.getKind() != WebAuthnAuthentication.Kind.SIGN_IN
                    || !MessageDigest.isEqual(this.accountHandle, proof.getUserHandle()))
                return text(403, "Request denied.");
            return rotated(session, true);
        }
        return authenticationFailure(result);
    }

    @POST("/reauth/start") public @NonNull MarshaledResponse beginReauthentication(@NonNull Request request) {
        return admittedResponse(() -> beginReauthenticationRoute(request));
    }

    private @NonNull MarshaledResponse beginReauthenticationRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, true);
        if (session == null || !emptyBody(request)) return text(403, "Request denied.");
        return authenticationStart(this.relyingParty.beginReauthenticationResult(
                this.accountHandle, PURPOSE, session.binding));
    }

    @POST("/reauth/finish") public @NonNull MarshaledResponse finishReauthentication(@NonNull Request request) {
        return admittedResponse(() -> finishReauthenticationRoute(request));
    }

    private @NonNull MarshaledResponse finishReauthenticationRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, true);
        byte[] body = credentialBody(request);
        String ceremony = ceremonyId(request);
        if (session == null || body == null || ceremony == null) return text(403, "Request denied.");
        WebAuthnAuthenticationResult result = this.relyingParty.completeAuthenticationResult(ceremony, body, session.binding);
        if (result instanceof WebAuthnAuthenticationResult.Succeeded success) {
            WebAuthnAuthentication proof = success.getAuthentication();
            if (proof.getKind() != WebAuthnAuthentication.Kind.REAUTHENTICATION
                    || !MessageDigest.isEqual(this.accountHandle, proof.getUserHandle())
                    || !proof.getActionPurpose().equals(java.util.Optional.of(PURPOSE))
                    || !this.sessions.grantStepUp(session)) return text(403, "Request denied.");
            return text(200, "Sensitive action approved for one use.");
        }
        return authenticationFailure(result);
    }

    @POST("/sensitive") public @NonNull MarshaledResponse sensitiveAction(@NonNull Request request) {
        return admittedResponse(() -> sensitiveActionRoute(request));
    }

    private @NonNull MarshaledResponse sensitiveActionRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, true);
        if (session == null || !emptyBody(request) || !this.sessions.consumeStepUp(session))
            return text(403, "Request denied.");
        return text(200, "Demo sensitive action completed.");
    }

    @POST("/credentials/list") public @NonNull MarshaledResponse listCredentials(@NonNull Request request) {
        return admittedResponse(() -> listCredentialsRoute(request));
    }

    private @NonNull MarshaledResponse listCredentialsRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, true);
        if (session == null || !emptyBody(request)) return text(403, "Request denied.");
        WebAuthnCredentialListResult result = this.relyingParty.listCredentialsResult(this.accountHandle);
        if (!(result instanceof WebAuthnCredentialListResult.Listed listed))
            return text(503, "Local demo unavailable.");
        List<String> encoded = new ArrayList<>();
        for (byte[] id : listed.getCredentialIds())
            encoded.add("\"" + Base64.getUrlEncoder().withoutPadding().encodeToString(id) + "\"");
        return json(200, "{\"credentialIds\":[" + String.join(",", encoded) + "]}");
    }

    @POST("/credentials/remove") public @NonNull MarshaledResponse removeCredential(@NonNull Request request) {
        return admittedResponse(() -> removeCredentialRoute(request));
    }

    private @NonNull MarshaledResponse removeCredentialRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, true);
        if (session == null || !emptyBody(request)) return text(403, "Request denied.");
        List<String> values = headers(request, "X-Credential-Id");
        if (values.size() != 1) return text(403, "Request denied.");
        byte[] id = decodeId(values.get(0));
        if (id == null) return text(403, "Request denied.");
        WebAuthnCredentialRemovalResult result = this.relyingParty.removeCredentialResult(this.accountHandle, id);
        if (result instanceof WebAuthnCredentialRemovalResult.Removed) return text(200, "Passkey removed.");
        if (result instanceof WebAuthnCredentialRemovalResult.Indeterminate) return uncertain();
        return result instanceof WebAuthnCredentialRemovalResult.Unavailable
                ? text(503, "Local demo unavailable.") : text(404, "Passkey not found.");
    }

    @POST("/logout") public @NonNull MarshaledResponse logout(@NonNull Request request) {
        return admittedResponse(() -> logoutRoute(request));
    }

    private @NonNull MarshaledResponse logoutRoute(@NonNull Request request) {
        PasskeySessions.Session session = admitted(request, true);
        if (session == null || !emptyBody(request)) return text(403, "Request denied.");
        return rotated(session, false);
    }

    private @NonNull MarshaledResponse admittedResponse(
            @NonNull Supplier<@NonNull MarshaledResponse> action) {
        if (!this.admissionOpen.get()) return text(503, "Local demo unavailable.");
        WebAuthnRecoveryGate.Permit permit;
        try {
            permit = this.admissionGate.acquire(Duration.ofSeconds(15));
        } catch (RuntimeException unavailable) {
            return text(503, "Local demo unavailable.");
        }
        if (permit == null) return text(503, "Local demo unavailable.");
        try (permit) {
            if (!current(permit)) return text(503, "Local demo unavailable.");
            MarshaledResponse result = action.get();
            return current(permit) ? result : text(503, "Local demo unavailable.");
        }
    }

    private boolean current(WebAuthnRecoveryGate.@NonNull Permit permit) {
        try {
            return this.admissionOpen.get() && permit.isCurrent();
        } catch (RuntimeException unavailable) {
            return false;
        }
    }

    private @NonNull MarshaledResponse authenticationStart(@NonNull WebAuthnAuthenticationRequestResult result) {
        if (result instanceof WebAuthnAuthenticationRequestResult.Prepared prepared)
            return json(200, prepared.getRequest().getJson());
        if (result instanceof WebAuthnAuthenticationRequestResult.Indeterminate) return uncertain();
        return result instanceof WebAuthnAuthenticationRequestResult.Unavailable
                ? text(503, "Local demo unavailable.") : text(400, "Request rejected.");
    }

    private @NonNull MarshaledResponse authenticationFailure(@NonNull WebAuthnAuthenticationResult result) {
        if (result instanceof WebAuthnAuthenticationResult.Indeterminate) return uncertain();
        return result instanceof WebAuthnAuthenticationResult.Unavailable
                ? text(503, "Local demo unavailable.") : text(400, "Authentication rejected.");
    }

    private @NonNull MarshaledResponse uncertain() {
        this.admissionOpen.set(false);
        return text(503, "State uncertain; stop this disposable demo and start fresh.");
    }

    private @NonNull MarshaledResponse rotated(PasskeySessions.@NonNull Session session, boolean authenticated) {
        try {
            PasskeySessions.Session next = this.sessions.rotate(session, authenticated);
            return text(200, authenticated ? "Signed in." : "Signed out.").copy()
                    .cookies(List.of(this.sessions.cookie(next))).finish();
        } catch (IllegalStateException expired) {
            return text(403, "Request denied.");
        }
    }

    private PasskeySessions.@Nullable Session admitted(@NonNull Request request,
            boolean authenticated) {
        if (!this.admissionOpen.get() || !sameOrigin(request) || request.isContentTooLarge()
                || request.getRawQuery().isPresent() || !headers(request, "Content-Encoding").isEmpty()) return null;
        PasskeySessions.Session session = this.sessions.find(request).orElse(null);
        if (session == null || session.authenticated != authenticated || !this.sessions.current(session)) return null;
        List<String> tokens = headers(request, "X-CSRF-Token");
        return tokens.size() == 1 && matches(session.csrf, tokens.get(0)) ? session : null;
    }

    private boolean host(@NonNull Request request) {
        return headers(request, "Host").equals(List.of(this.authority));
    }

    private boolean sameOrigin(@NonNull Request request) {
        return host(request) && headers(request, "Origin").equals(List.of(this.origin));
    }

    private static boolean emptyBody(@NonNull Request request) {
        return request.getBody().orElseGet(() -> new byte[0]).length == 0;
    }

    private static byte @Nullable [] credentialBody(@NonNull Request request) {
        List<String> types = headers(request, "Content-Type");
        byte[] body = request.getBody().orElseGet(() -> new byte[0]);
        return types.equals(List.of("application/json")) && body.length > 0 && body.length <= 65_536
                ? body : null;
    }

    private static @Nullable String ceremonyId(@NonNull Request request) {
        List<String> ids = headers(request, "X-Ceremony-Id");
        return ids.size() == 1 && ids.get(0).matches("[A-Za-z0-9_-]{43}") ? ids.get(0) : null;
    }

    private static byte @Nullable [] decodeId(@NonNull String encoded) {
        if (!encoded.matches("[A-Za-z0-9_-]{2,1364}")) return null;
        try {
            byte[] id = Base64.getUrlDecoder().decode(encoded);
            return id.length >= 1 && id.length <= 1023
                    && Base64.getUrlEncoder().withoutPadding().encodeToString(id).equals(encoded) ? id : null;
        } catch (IllegalArgumentException malformed) {
            return null;
        }
    }

    static @NonNull List<@NonNull String> headers(@NonNull Request request, @NonNull String name) {
        return request.getHeaders().entrySet().stream().filter(entry -> entry.getKey().equalsIgnoreCase(name))
                .flatMap(entry -> entry.getValue().stream()).toList();
    }

    private static boolean matches(@NonNull String expected, @Nullable String supplied) {
        return supplied != null && supplied.length() == expected.length()
                && MessageDigest.isEqual(expected.getBytes(StandardCharsets.US_ASCII),
                supplied.getBytes(StandardCharsets.US_ASCII));
    }

    private static @NonNull MarshaledResponse json(int status, @NonNull String body) {
        return response(status, "application/json; charset=UTF-8", body.getBytes(StandardCharsets.UTF_8));
    }

    private static @NonNull MarshaledResponse text(int status, @NonNull String body) {
        return response(status, "text/plain; charset=UTF-8", body.getBytes(StandardCharsets.UTF_8));
    }

    private static @NonNull MarshaledResponse response(int status, @NonNull String type,
            byte @NonNull [] body) {
        return MarshaledResponse.withStatusCode(status).headers(Map.of(
                "Content-Type", List.of(type), "Cache-Control", List.of("no-store"),
                "Pragma", List.of("no-cache"), "Referrer-Policy", List.of("no-referrer"),
                "X-Content-Type-Options", List.of("nosniff"), "Content-Security-Policy", List.of(CSP)))
                .body(body).build();
    }
}
