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

import com.soklet.HttpMethod;
import com.soklet.MarshaledResponse;
import com.soklet.MarshaledResponseBody;
import com.soklet.Request;
import com.soklet.ResponseCookie;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/** Local public-route checks without a browser authenticator or trusted HTTPS edge. */
public final class PasskeyChecks {
    private static final String ORIGIN = "https://passkeys.example.test:9443";
    private static final String HOST = "passkeys.example.test:9443";
    private static final String ACCESS_KEY = "A".repeat(43);

    private PasskeyChecks() { }

    public static void main(java.lang.@NonNull String @NonNull [] args) throws Exception {
        rejectsUnsafeConfiguration();
        checksSessionAndProtocolBoundary();
        checksSuccessfulPasskeyLifecycle();
        System.out.println("Passkey example route checks passed.");
    }

    private static void rejectsUnsafeConfiguration() throws Exception {
        rejected(() -> new PasskeyApp("http://passkeys.example.test:9443",
                "passkeys.example.test", ACCESS_KEY, Clock.systemUTC()));
        rejected(() -> new PasskeyApp(ORIGIN, "other.example.test", ACCESS_KEY, Clock.systemUTC()));
        rejected(() -> new PasskeyApp(ORIGIN, "Passkeys.example.test", ACCESS_KEY, Clock.systemUTC()));
    }

    private static void checksSessionAndProtocolBoundary() throws Exception {
        PasskeyApp app = new PasskeyApp(ORIGIN, "passkeys.example.test", ACCESS_KEY, Clock.systemUTC());
        equal(403, app.index(request(HttpMethod.GET, "/", Map.of("Host", List.of("other.example.test")), null)).getStatusCode());
        MarshaledResponse home = app.index(request(HttpMethod.GET, "/", Map.of("Host", List.of(HOST)), null));
        equal(200, home.getStatusCode());
        String csrf = capture(body(home), "data-csrf='([A-Za-z0-9_-]{43})'");
        ResponseCookie firstCookie = only(home.getCookies());
        check(firstCookie.getSecure() && firstCookie.getHttpOnly());
        check(firstCookie.getDomain().isEmpty());
        equal(ResponseCookie.SameSite.STRICT, firstCookie.getSameSite().orElseThrow());
        String cookie = firstCookie.getName() + "=" + firstCookie.getValue().orElseThrow();
        equal(403, app.beginRegistration(post("/register/start", cookie, csrf, ORIGIN, Map.of(), null)).getStatusCode());
        equal(403, app.accessLogin(post("/access-login", cookie, csrf, "https://other.example.test",
                Map.of("X-Demo-Access-Key", List.of(ACCESS_KEY)), null)).getStatusCode());
        equal(403, app.accessLogin(post("/access-login", cookie, "B".repeat(43), ORIGIN,
                Map.of("X-Demo-Access-Key", List.of(ACCESS_KEY)), null)).getStatusCode());
        equal(403, app.accessLogin(post("/access-login", cookie, csrf, ORIGIN,
                Map.of("X-Demo-Access-Key", List.of("Z".repeat(43))), null)).getStatusCode());
        MarshaledResponse login = app.accessLogin(post("/access-login", cookie, csrf, ORIGIN,
                Map.of("X-Demo-Access-Key", List.of(ACCESS_KEY)), null));
        equal(200, login.getStatusCode());
        String nextCookie = only(login.getCookies()).getName() + "="
                + only(login.getCookies()).getValue().orElseThrow();
        check(!cookie.equals(nextCookie));
        equal(403, app.beginRegistration(post("/register/start", cookie, csrf, ORIGIN, Map.of(), null)).getStatusCode());
        MarshaledResponse account = app.index(request(HttpMethod.GET, "/",
                Map.of("Host", List.of(HOST), "Cookie", List.of(nextCookie)), null));
        check(body(account).contains("data-authenticated='true'"));
        String nextCsrf = capture(body(account), "data-csrf='([A-Za-z0-9_-]{43})'");
        check(!csrf.equals(nextCsrf));
        MarshaledResponse prepared = app.beginRegistration(post("/register/start", nextCookie,
                nextCsrf, ORIGIN, Map.of(), null));
        equal(200, prepared.getStatusCode());
        String ceremony = capture(body(prepared), "\\\"ceremonyId\\\":\\\"([A-Za-z0-9_-]{43})\\\"");
        check(body(prepared).contains("\"publicKey\""));
        check(body(prepared).contains("\"rp\""));
        equal(403, app.finishRegistration(post("/register/finish", nextCookie, nextCsrf,
                "https://other.example.test", Map.of("X-Ceremony-Id", List.of(ceremony),
                "Content-Type", List.of("application/json")), "{}".getBytes(StandardCharsets.UTF_8))).getStatusCode());
        equal(400, app.finishRegistration(post("/register/finish", nextCookie, nextCsrf,
                ORIGIN, Map.of("X-Ceremony-Id", List.of(ceremony),
                "Content-Type", List.of("application/json")), "{}".getBytes(StandardCharsets.UTF_8))).getStatusCode());
        MarshaledResponse listing = app.listCredentials(post("/credentials/list", nextCookie,
                nextCsrf, ORIGIN, Map.of(), null));
        equal(200, listing.getStatusCode());
        check(body(listing).contains("\"credentialIds\":[]"));
        equal(403, app.removeCredential(post("/credentials/remove", nextCookie,
                nextCsrf, ORIGIN, Map.of("X-Credential-Id", List.of("noncanonical=")), null)).getStatusCode());
        equal(403, app.sensitiveAction(post("/sensitive", nextCookie,
                nextCsrf, ORIGIN, Map.of(), null)).getStatusCode());
        MarshaledResponse logout = app.logout(post("/logout", nextCookie,
                nextCsrf, ORIGIN, Map.of(), null));
        equal(200, logout.getStatusCode());
        equal(403, app.beginRegistration(post("/register/start", nextCookie,
                nextCsrf, ORIGIN, Map.of(), null)).getStatusCode());
        check(app.script(request(HttpMethod.GET, "/app.js", Map.of("Host", List.of(HOST)), null))
                .getStatusCode() == 200);
    }

    private static void checksSuccessfulPasskeyLifecycle() throws Exception {
        PasskeyApp app = new PasskeyApp(ORIGIN, "passkeys.example.test", ACCESS_KEY, Clock.systemUTC());
        MarshaledResponse home = app.index(get("/", null));
        String anonymousCookie = cookie(home);
        String anonymousCsrf = csrf(home);
        MarshaledResponse login = app.accessLogin(post("/access-login", anonymousCookie,
                anonymousCsrf, ORIGIN, Map.of("X-Demo-Access-Key", List.of(ACCESS_KEY)), null));
        equal(200, login.getStatusCode());
        String accountCookie = cookie(login);
        String accountCsrf = csrf(app.index(get("/", accountCookie)));

        MarshaledResponse prepared = app.beginRegistration(post("/register/start", accountCookie,
                accountCsrf, ORIGIN, Map.of(), null));
        equal(200, prepared.getStatusCode());
        String registration = body(prepared);
        String registrationId = capture(registration, "\\\"ceremonyId\\\":\\\"([A-Za-z0-9_-]{43})\\\"");
        String registrationChallenge = capture(registration, "\\\"challenge\\\":\\\"([A-Za-z0-9_-]{43})\\\"");
        byte[] handle = Base64.getUrlDecoder().decode(capture(registration,
                "\\\"user\\\":\\{[^}]*\\\"id\\\":\\\"([A-Za-z0-9_-]+)\\\""));
        SyntheticAuthenticator authenticator = new SyntheticAuthenticator(handle);
        byte[] creation = authenticator.registration(registrationChallenge);
        equal(200, app.finishRegistration(finish("/register/finish", accountCookie,
                accountCsrf, registrationId, creation)).getStatusCode());
        equal(400, app.finishRegistration(finish("/register/finish", accountCookie,
                accountCsrf, registrationId, creation)).getStatusCode());
        check(body(app.listCredentials(post("/credentials/list", accountCookie,
                accountCsrf, ORIGIN, Map.of(), null))).contains(authenticator.credentialId()));

        MarshaledResponse logout = app.logout(post("/logout", accountCookie,
                accountCsrf, ORIGIN, Map.of(), null));
        equal(200, logout.getStatusCode());
        String signedOutCookie = cookie(logout);
        String signedOutCsrf = csrf(app.index(get("/", signedOutCookie)));
        equal(403, app.beginRegistration(post("/register/start", signedOutCookie,
                signedOutCsrf, ORIGIN, Map.of(), null)).getStatusCode());
        MarshaledResponse signInStart = app.beginSignIn(post("/sign-in/start", signedOutCookie,
                signedOutCsrf, ORIGIN, Map.of(), null));
        equal(200, signInStart.getStatusCode());
        String signIn = body(signInStart);
        check(!signIn.contains("allowCredentials"));
        String signInId = capture(signIn, "\\\"ceremonyId\\\":\\\"([A-Za-z0-9_-]{43})\\\"");
        String signInChallenge = capture(signIn, "\\\"challenge\\\":\\\"([A-Za-z0-9_-]{43})\\\"");
        SyntheticAuthenticator attacker = new SyntheticAuthenticator(handle);
        equal(400, app.finishSignIn(finish("/sign-in/finish", signedOutCookie,
                signedOutCsrf, signInId, attacker.assertion(signInChallenge, 1))).getStatusCode());
        byte[] assertion = authenticator.assertion(signInChallenge, 1);
        MarshaledResponse signedIn = app.finishSignIn(finish("/sign-in/finish", signedOutCookie,
                signedOutCsrf, signInId, assertion));
        equal(200, signedIn.getStatusCode());
        String signedInCookie = cookie(signedIn);
        String signedInCsrf = csrf(app.index(get("/", signedInCookie)));
        check(!signedInCookie.equals(signedOutCookie) && !signedInCsrf.equals(signedOutCsrf));
        equal(403, app.finishSignIn(finish("/sign-in/finish", signedOutCookie,
                signedOutCsrf, signInId, assertion)).getStatusCode());

        MarshaledResponse reauthStart = app.beginReauthentication(post("/reauth/start", signedInCookie,
                signedInCsrf, ORIGIN, Map.of(), null));
        equal(200, reauthStart.getStatusCode());
        String reauth = body(reauthStart);
        String reauthId = capture(reauth, "\\\"ceremonyId\\\":\\\"([A-Za-z0-9_-]{43})\\\"");
        String reauthChallenge = capture(reauth, "\\\"challenge\\\":\\\"([A-Za-z0-9_-]{43})\\\"");
        equal(200, app.finishReauthentication(finish("/reauth/finish", signedInCookie,
                signedInCsrf, reauthId, authenticator.assertion(reauthChallenge, 2))).getStatusCode());
        equal(200, app.sensitiveAction(post("/sensitive", signedInCookie,
                signedInCsrf, ORIGIN, Map.of(), null)).getStatusCode());
        equal(403, app.sensitiveAction(post("/sensitive", signedInCookie,
                signedInCsrf, ORIGIN, Map.of(), null)).getStatusCode());

        equal(200, app.removeCredential(post("/credentials/remove", signedInCookie,
                signedInCsrf, ORIGIN, Map.of("X-Credential-Id", List.of(authenticator.credentialId())),
                null)).getStatusCode());
        check(body(app.listCredentials(post("/credentials/list", signedInCookie,
                signedInCsrf, ORIGIN, Map.of(), null))).contains("\"credentialIds\":[]"));
        MarshaledResponse reuseStart = app.beginRegistration(post("/register/start", signedInCookie,
                signedInCsrf, ORIGIN, Map.of(), null));
        equal(200, reuseStart.getStatusCode());
        String reuse = body(reuseStart);
        equal(400, app.finishRegistration(finish("/register/finish", signedInCookie, signedInCsrf,
                capture(reuse, "\\\"ceremonyId\\\":\\\"([A-Za-z0-9_-]{43})\\\""),
                attacker.registration(capture(reuse,
                        "\\\"challenge\\\":\\\"([A-Za-z0-9_-]{43})\\\"")))).getStatusCode());
        MarshaledResponse finalLogout = app.logout(post("/logout", signedInCookie,
                signedInCsrf, ORIGIN, Map.of(), null));
        equal(200, finalLogout.getStatusCode());
        String finalCookie = cookie(finalLogout);
        String finalCsrf = csrf(app.index(get("/", finalCookie)));
        MarshaledResponse removedStart = app.beginSignIn(post("/sign-in/start", finalCookie,
                finalCsrf, ORIGIN, Map.of(), null));
        equal(200, removedStart.getStatusCode());
        String removed = body(removedStart);
        equal(400, app.finishSignIn(finish("/sign-in/finish", finalCookie, finalCsrf,
                capture(removed, "\\\"ceremonyId\\\":\\\"([A-Za-z0-9_-]{43})\\\""),
                authenticator.assertion(capture(removed,
                        "\\\"challenge\\\":\\\"([A-Za-z0-9_-]{43})\\\""), 3))).getStatusCode());
    }

    private static @NonNull Request get(@NonNull String path, @Nullable String cookie) {
        return request(HttpMethod.GET, path, cookie == null
                ? Map.of("Host", List.of(HOST))
                : Map.of("Host", List.of(HOST), "Cookie", List.of(cookie)), null);
    }

    private static @NonNull Request finish(@NonNull String path, @NonNull String cookie,
            @NonNull String csrf, @NonNull String ceremony, byte @NonNull [] body) {
        return post(path, cookie, csrf, ORIGIN,
                Map.of("X-Ceremony-Id", List.of(ceremony),
                        "Content-Type", List.of("application/json")), body);
    }

    private static @NonNull String cookie(@NonNull MarshaledResponse response) {
        ResponseCookie value = only(response.getCookies());
        return value.getName() + "=" + value.getValue().orElseThrow();
    }

    private static @NonNull String csrf(@NonNull MarshaledResponse response) {
        return capture(body(response), "data-csrf='([A-Za-z0-9_-]{43})'");
    }

    private static @NonNull Request post(@NonNull String path, @NonNull String cookie,
            @NonNull String csrf, @NonNull String origin,
            @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> extras,
            byte @Nullable [] body) {
        java.util.Map<String, List<String>> headers = new java.util.LinkedHashMap<>();
        headers.put("Host", List.of(HOST));
        headers.put("Origin", List.of(origin));
        headers.put("Cookie", List.of(cookie));
        headers.put("X-CSRF-Token", List.of(csrf));
        headers.putAll(extras);
        return request(HttpMethod.POST, path, headers, body);
    }

    private static @NonNull Request request(@NonNull HttpMethod method, @NonNull String path,
            @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> headers,
            byte @Nullable [] body) {
        Request.RawBuilder builder = Request.withRawUrl(method, path).headers(headers);
        if (body != null) builder.body(body);
        return builder.build();
    }

    private static @NonNull String body(@NonNull MarshaledResponse response) {
        MarshaledResponseBody.Bytes content = (MarshaledResponseBody.Bytes) response.getBody().orElseThrow();
        return new String(content.getBytes(), StandardCharsets.UTF_8);
    }

    private static @NonNull String capture(@NonNull String text, @NonNull String pattern) {
        Matcher match = Pattern.compile(pattern).matcher(text);
        check(match.find());
        return match.group(1);
    }

    private static <@NonNull T> @NonNull T only(@NonNull List<@NonNull T> values) {
        equal(1, values.size());
        return values.get(0);
    }

    private static void equal(@NonNull Object expected, @NonNull Object actual) {
        if (!expected.equals(actual)) throw new AssertionError("Expected " + expected + ", got " + actual);
    }

    private static void check(boolean condition) {
        if (!condition) throw new AssertionError("Passkey route check failed");
    }

    private static void rejected(@NonNull ThrowingAction action) throws Exception {
        try { action.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("Unsafe passkey configuration accepted");
    }

    private interface ThrowingAction {
        void run() throws Exception;
    }
}
