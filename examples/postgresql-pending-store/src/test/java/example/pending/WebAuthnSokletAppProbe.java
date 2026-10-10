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

import com.soklet.HttpMethod;
import com.soklet.MarshaledResponse;
import com.soklet.MarshaledResponseBody;
import com.soklet.Request;
import com.soklet.ResponseCookie;
import example.passkeys.PasskeyApp;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Test-only application route probe. Each invocation is a fresh JVM; the runner supplies one
 * authoritative PostgreSQL namespace, stable app account and independently held recovery marker.
 * It exercises the same PasskeyApp routes as the standalone browser demo without a browser key.
 */
public final class WebAuthnSokletAppProbe {
    private static final String NAMESPACE = "fixture_wa_app";
    private static final String RP = "login.example.com";
    private static final String ORIGIN = "https://" + RP;
    private static final String ACCESS_KEY = "A".repeat(43);
    private static final byte @NonNull [] ACCOUNT = {4, 5, 6};
    private static final byte @NonNull [] CREDENTIAL_ID = {1, 2, 3};

    private WebAuthnSokletAppProbe() { }

    public static void main(@NonNull String @NonNull [] args) throws Exception {
        if (args.length != 1) throw new IllegalArgumentException("Expected one app probe command");
        WebAuthnFixtureRecoveryGate gate = new WebAuthnFixtureRecoveryGate(NAMESPACE,
                Path.of(System.getenv("REVETSEC_TEST_WA_MARKER_FILE")),
                Path.of(System.getenv("REVETSEC_TEST_WA_LOCK_FILE")),
                System.getenv("REVETSEC_TEST_WA_SEAL_KEY"));
        PasskeyApp app = new PasskeyApp(ORIGIN, RP, ACCESS_KEY, Clock.systemUTC(), ACCOUNT,
                WebAuthnFlowProbe.partyFor(NAMESPACE, args[0].equals("unknown-begin"), gate), gate);
        switch (args[0]) {
            case "register" -> register(app);
            case "sign-in" -> signIn(app);
            case "remove" -> remove(app);
            case "removed" -> removed(app);
            case "unknown-begin" -> unknownBegin(app);
            case "closed" -> closed(app);
            case "live-close" -> liveClose(app);
            default -> throw new IllegalArgumentException("Unknown app probe command");
        }
    }

    private static void register(@NonNull PasskeyApp app) throws Exception {
        Session session = approved(app);
        MarshaledResponse prepared = app.beginRegistration(post("/register/start", session, Map.of(), null));
        expect(200, prepared);
        Ceremony ceremony = ceremony(prepared);
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] response = WebAuthnFlowProbe.registrationJson(pair, ceremony.challenge());
        expect(200, app.finishRegistration(finish("/register/finish", session,
                ceremony.id(), response)));
        expect(400, app.finishRegistration(finish("/register/finish", session,
                ceremony.id(), response)));
        expectList(app, session, 1);
        // Runner memory receives the fixture key and forwards it only to later test JVMs.
        System.out.println("APP_REGISTERED "
                + Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
    }

    private static void signIn(@NonNull PasskeyApp app) throws Exception {
        Session anonymous = initial(app);
        MarshaledResponse prepared = app.beginSignIn(post("/sign-in/start", anonymous, Map.of(), null));
        expect(200, prepared);
        Ceremony ceremony = ceremony(prepared);
        MarshaledResponse complete = app.finishSignIn(finish("/sign-in/finish", anonymous,
                ceremony.id(), WebAuthnFlowProbe.assertionJson(privateKey(), ceremony.challenge(), 1)));
        expect(200, complete);
        Session authenticated = session(app, cookie(complete));
        expect(403, app.beginRegistration(post("/register/start", anonymous, Map.of(), null)));
        MarshaledResponse reauth = app.beginReauthentication(post("/reauth/start", authenticated,
                Map.of(), null));
        expect(200, reauth);
        Ceremony pinned = ceremony(reauth);
        expect(200, app.finishReauthentication(finish("/reauth/finish", authenticated,
                pinned.id(), WebAuthnFlowProbe.assertionJson(privateKey(), pinned.challenge(), 2))));
        expect(200, app.sensitiveAction(post("/sensitive", authenticated, Map.of(), null)));
        expect(403, app.sensitiveAction(post("/sensitive", authenticated, Map.of(), null)));
        expectList(app, authenticated, 1);
        System.out.println("APP_SIGNED_IN_AND_REAUTHENTICATED");
    }

    private static void remove(@NonNull PasskeyApp app) {
        Session session = approved(app);
        expectList(app, session, 1);
        expect(200, app.removeCredential(post("/credentials/remove", session,
                Map.of("X-Credential-Id", List.of(url(CREDENTIAL_ID))), null)));
        expectList(app, session, 0);
        System.out.println("APP_REMOVED");
    }

    private static void removed(@NonNull PasskeyApp app) throws Exception {
        Session anonymous = initial(app);
        MarshaledResponse prepared = app.beginSignIn(post("/sign-in/start", anonymous, Map.of(), null));
        expect(200, prepared);
        Ceremony ceremony = ceremony(prepared);
        expect(400, app.finishSignIn(finish("/sign-in/finish", anonymous, ceremony.id(),
                WebAuthnFlowProbe.assertionJson(privateKey(), ceremony.challenge(), 3))));
        System.out.println("APP_REMOVED_REJECTED");
    }

    private static void unknownBegin(@NonNull PasskeyApp app) {
        Session session = approved(app);
        expect(503, app.beginRegistration(post("/register/start", session, Map.of(), null)));
        expect(503, app.beginRegistration(post("/register/start", session, Map.of(), null)));
        System.out.println("APP_UNKNOWN_CLOSED_LOCAL_ADMISSION");
    }

    private static void closed(@NonNull PasskeyApp app) {
        expect(503, app.index(get(null)));
        Session unused = new Session("A".repeat(43), "B".repeat(43));
        expect(503, app.beginSignIn(post("/sign-in/start", unused, Map.of(), null)));
        expect(503, app.listCredentials(post("/credentials/list", unused, Map.of(), null)));
        expect(503, app.accessLogin(post("/access-login", unused,
                Map.of("X-Demo-Access-Key", List.of(ACCESS_KEY)), null)));
        expect(503, app.sensitiveAction(post("/sensitive", unused, Map.of(), null)));
        System.out.println("APP_RECOVERY_CLOSED");
    }

    private static void liveClose(@NonNull PasskeyApp app) throws Exception {
        Session session = approved(app);
        System.out.println("APP_ADMITTED");
        System.out.flush();
        String command = new BufferedReader(new InputStreamReader(System.in,
                StandardCharsets.US_ASCII)).readLine();
        if (!"go".equals(command)) throw new IllegalStateException("App close signal missing");
        expect(503, app.index(get(session.cookie())));
        expect(503, app.sensitiveAction(post("/sensitive", session, Map.of(), null)));
        expect(503, app.listCredentials(post("/credentials/list", session, Map.of(), null)));
        System.out.println("APP_LIVE_CLOSED");
    }

    private static @NonNull Session initial(@NonNull PasskeyApp app) {
        MarshaledResponse page = app.index(get(null));
        expect(200, page);
        return new Session(cookie(page), capture(body(page), "data-csrf='([A-Za-z0-9_-]{43})'"));
    }

    private static @NonNull Session approved(@NonNull PasskeyApp app) {
        Session anonymous = initial(app);
        MarshaledResponse login = app.accessLogin(post("/access-login", anonymous,
                Map.of("X-Demo-Access-Key", List.of(ACCESS_KEY)), null));
        expect(200, login);
        return session(app, cookie(login));
    }

    private static @NonNull Session session(@NonNull PasskeyApp app, @NonNull String cookie) {
        MarshaledResponse page = app.index(get(cookie));
        expect(200, page);
        if (!body(page).contains("data-authenticated='true'"))
            throw new IllegalStateException("Application session was not authenticated");
        return new Session(cookie, capture(body(page), "data-csrf='([A-Za-z0-9_-]{43})'"));
    }

    private static void expectList(@NonNull PasskeyApp app, @NonNull Session session, int count) {
        MarshaledResponse listed = app.listCredentials(post("/credentials/list", session, Map.of(), null));
        expect(200, listed);
        String expected = count == 0 ? "\"credentialIds\":[]"
                : "\"credentialIds\":[\"" + url(CREDENTIAL_ID) + "\"]";
        if (!body(listed).contains(expected)) throw new IllegalStateException("Unexpected credential list");
    }

    private static @NonNull Ceremony ceremony(@NonNull MarshaledResponse response) {
        String value = body(response);
        return new Ceremony(capture(value, "\\\"ceremonyId\\\":\\\"([A-Za-z0-9_-]{43})\\\""),
                capture(value, "\\\"challenge\\\":\\\"([A-Za-z0-9_-]{43})\\\""));
    }

    private static @NonNull String capture(@NonNull String text, @NonNull String pattern) {
        Matcher match = Pattern.compile(pattern).matcher(text);
        if (!match.find()) throw new IllegalStateException("Expected route field missing");
        return match.group(1);
    }

    private static @NonNull String cookie(@NonNull MarshaledResponse response) {
        List<ResponseCookie> cookies = response.getCookies();
        if (cookies.size() != 1) throw new IllegalStateException("Expected one rotated session cookie");
        ResponseCookie cookie = cookies.get(0);
        return cookie.getName() + "=" + cookie.getValue().orElseThrow();
    }

    private static @NonNull String body(@NonNull MarshaledResponse response) {
        return new String(((MarshaledResponseBody.Bytes) response.getBody().orElseThrow()).getBytes(),
                StandardCharsets.UTF_8);
    }

    private static void expect(int status, @NonNull MarshaledResponse response) {
        if (response.getStatusCode() != status)
            throw new IllegalStateException("Unexpected application status: " + response.getStatusCode()
                    + " instead of " + status);
    }

    private static @NonNull Request get(@Nullable String cookie) {
        return Request.withRawUrl(HttpMethod.GET, "/").headers(cookie == null
                ? Map.of("Host", List.of(RP))
                : Map.of("Host", List.of(RP), "Cookie", List.of(cookie))).build();
    }

    private static @NonNull Request finish(@NonNull String path, @NonNull Session session,
            @NonNull String ceremony, byte @NonNull [] body) {
        return post(path, session, Map.of("X-Ceremony-Id", List.of(ceremony),
                "Content-Type", List.of("application/json")), body);
    }

    private static @NonNull Request post(@NonNull String path, @NonNull Session session,
            @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> extras,
            byte @Nullable [] body) {
        Map<String, List<String>> headers = new LinkedHashMap<>();
        headers.put("Host", List.of(RP));
        headers.put("Origin", List.of(ORIGIN));
        headers.put("Cookie", List.of(session.cookie()));
        headers.put("X-CSRF-Token", List.of(session.csrf()));
        headers.putAll(extras);
        Request.RawBuilder builder = Request.withRawUrl(HttpMethod.POST, path).headers(headers);
        if (body != null) builder.body(body);
        return builder.build();
    }

    private static @NonNull PrivateKey privateKey() throws Exception {
        byte[] encoded = Base64.getDecoder().decode(System.getenv("REVETSEC_TEST_WA_APP_AUTH_KEY"));
        try { return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded)); }
        finally { java.util.Arrays.fill(encoded, (byte) 0); }
    }

    private static @NonNull String url(byte @NonNull [] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private record Session(@NonNull String cookie, @NonNull String csrf) { }
    private record Ceremony(@NonNull String id, @NonNull String challenge) { }
}
