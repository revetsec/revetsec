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
package com.revetsec.examples.barebones;

import com.revetsec.oauth.AuthorizationRequestOptions;
import com.soklet.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.function.Consumer;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

final class OidcApplicationTests {
    static final @NonNull Instant NOW = Instant.parse("2026-10-01T12:00:00Z");

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> realSignedOidcCompletesBothDeliveryModesAndRotatesSession() {
        return Stream.of(AuthorizationRequestOptions.ResponseMode.QUERY, AuthorizationRequestOptions.ResponseMode.FORM_POST)
                .map(mode -> DynamicTest.dynamicTest(mode.name(), () -> {
                    MutableClock clock = new MutableClock();
                    try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
                        OidcApplication app = provider.application(8, 8, mode);
                        SokletSimulator.run(app.configuration(18080), simulator -> {
                            Browser browser = new Browser(simulator);
                            Flow flow = begin(provider, browser);
                            String oldSession = browser.cookies.get(OidcApplication.SESSION_COOKIE);
                            HttpRequestResult completed = browser.callback(flow.query, mode, null);
                            assertEquals(302, status(completed));
                            assertEquals(List.of("no-referrer"), completed.getMarshaledResponse().getHeaders().get("Referrer-Policy"));
                            assertEquals("https://localhost:8443/", location(completed).toString());
                            assertNotEquals(oldSession, browser.cookies.get(OidcApplication.SESSION_COOKIE));
                            assertFalse(browser.cookies.containsKey(OidcApplication.PENDING_COOKIE));
                            assertEquals(1, provider.tokenPosts.get()); assertEquals(1, provider.keyGets.get());
                            String html = body(browser.get("/"));
                            assertTrue(html.contains("Signed in as user-"));
                            assertTrue(html.contains(provider.issuer().toString()));
                            for (String secret : List.of(SyntheticOidcProvider.SUBJECT, SyntheticOidcProvider.ACCESS,
                                    SyntheticOidcProvider.REFRESH, flow.query, "TEST-ONLY-code-1"))
                                assertFalse(html.contains(secret), "Credential or raw identity appeared in the page");
                            HttpRequestResult replay = browser.callback(flow.query, mode, null);
                            assertEquals(400, status(replay)); assertEquals(1, provider.tokenPosts.get());
                            Browser stale = new Browser(simulator); stale.cookies.put(OidcApplication.SESSION_COOKIE, oldSession);
                            assertTrue(body(stale.get("/")).contains("Signed out"));
                            HttpRequestResult home = browser.get("/");
                            assertEquals(302, status(browser.post("/logout", "csrf=" + csrf(home), "https://localhost:8443")));
                            assertFalse(browser.cookies.containsKey(OidcApplication.SESSION_COOKIE));
                            assertTrue(body(browser.get("/")).contains("Signed out"));
                        });
                    }
                }));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> normalOidcRejectsInvalidIdentityWithoutCreatingAppSession() {
        return Stream.of(SyntheticOidcProvider.Mode.WRONG_NONCE, SyntheticOidcProvider.Mode.WRONG_ISSUER,
                SyntheticOidcProvider.Mode.WRONG_AUDIENCE, SyntheticOidcProvider.Mode.EXPIRED,
                SyntheticOidcProvider.Mode.BAD_SIGNATURE, SyntheticOidcProvider.Mode.OMIT_ID_TOKEN)
                .map(mode -> DynamicTest.dynamicTest(mode.name(), () -> {
                    MutableClock clock = new MutableClock();
                    try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
                        provider.mode(mode);
                        with(provider, clock, browser -> {
                            Flow flow = begin(provider, browser);
                            String original = browser.cookies.get(OidcApplication.SESSION_COOKIE);
                            HttpRequestResult rejected = browser.callback(flow.query, AuthorizationRequestOptions.ResponseMode.QUERY, null);
                            assertEquals(400, status(rejected)); assertEquals("Sign in failed", body(rejected));
                            assertEquals(original, browser.cookies.get(OidcApplication.SESSION_COOKIE));
                            assertFalse(browser.cookies.containsKey(OidcApplication.PENDING_COOKIE));
                            assertTrue(body(browser.get("/")).contains("Signed out"));
                            assertEquals(1, provider.tokenPosts.get());
                            assertEquals(400, status(browser.callback(flow.query, AuthorizationRequestOptions.ResponseMode.QUERY, null)));
                            assertEquals(1, provider.tokenPosts.get());
                        });
                    }
                }));
    }

    @TestFactory
    @NonNull Stream<@NonNull DynamicTest> rawCallbackAndBrowserBindingRejectBeforeTokenPost() {
        return Stream.of("state", "duplicate", "malformed", "missing-binding", "wrong-binding", "wrong-session",
                "wrong-origin", "wrong-host", "mode", "post-query", "post-type")
                .map(name -> DynamicTest.dynamicTest(name, () -> {
                    MutableClock clock = new MutableClock();
                    try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
                        with(provider, clock, browser -> {
                            Flow flow = begin(provider, browser);
                            String query = flow.query;
                            AuthorizationRequestOptions.ResponseMode mode = AuthorizationRequestOptions.ResponseMode.QUERY;
                            Map<String, List<String>> extra = new HashMap<>();
                            switch (name) {
                                case "state" -> query = "state=wrong&code=TEST-ONLY-code-1";
                                case "duplicate" -> query += "&state=duplicate";
                                case "malformed" -> { query += "&x=%GG"; mode = AuthorizationRequestOptions.ResponseMode.FORM_POST; }
                                case "missing-binding" -> browser.cookies.remove(OidcApplication.PENDING_COOKIE);
                                case "wrong-binding" -> browser.cookies.put(OidcApplication.PENDING_COOKIE, "A".repeat(43));
                                case "wrong-session" -> browser.cookies.put(OidcApplication.SESSION_COOKIE, "B".repeat(43));
                                case "wrong-origin" -> extra.put("Origin", List.of("https://attacker.example"));
                                case "wrong-host" -> extra.put("Host", List.of("attacker.example"));
                                case "mode" -> mode = AuthorizationRequestOptions.ResponseMode.FORM_POST;
                                case "post-query" -> mode = AuthorizationRequestOptions.ResponseMode.FORM_POST;
                                case "post-type" -> { mode = AuthorizationRequestOptions.ResponseMode.FORM_POST;
                                    extra.put("Content-Type", List.of("text/plain")); }
                                default -> throw new IllegalStateException("Unknown test case");
                            }
                            HttpRequestResult response = name.equals("post-query")
                                    ? browser.send(HttpMethod.POST, "/callback?code=query-conflict", query,
                                            Map.of("Content-Type", List.of("application/x-www-form-urlencoded")))
                                    : browser.callback(query, mode, extra);
                            assertEquals(400, status(response));
                            assertEquals(name.equals("wrong-host") ? "Invalid request" : "Sign in failed", body(response));
                            assertEquals(0, provider.tokenPosts.get()); assertEquals(1, provider.keyGets.get()); // warmUp only
                        });
                    }
                }));
    }

    @Test
    void mutatingRoutesRequireExactHostOriginCsrfAndUnambiguousRawForm() throws Exception {
        MutableClock clock = new MutableClock();
        try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
            with(provider, clock, browser -> {
                HttpRequestResult home = browser.get("/"); String csrf = csrf(home);
                assertEquals(403, status(browser.post("/login", "csrf=" + csrf, null)));
                assertEquals(403, status(browser.post("/login", "csrf=" + csrf, "https://attacker.example")));
                assertEquals(403, status(browser.post("/login", "csrf=wrong", "https://localhost:8443")));
                assertEquals(403, status(browser.post("/login", "csrf=" + csrf + "&csrf=" + csrf, "https://localhost:8443")));
                assertEquals(403, status(browser.post("/login?extra=1", "csrf=" + csrf, "https://localhost:8443")));
                assertEquals(400, status(browser.send(HttpMethod.GET, "/", null, Map.of("Host", List.of("attacker.example")))));
                assertEquals(400, status(browser.send(HttpMethod.GET, "/", null, Map.of("Host", List.of("localhost:8443", "attacker.example")))));
                assertEquals(403, status(browser.post("/logout", "csrf=" + csrf, "https://attacker.example")));
                assertEquals(0, provider.tokenPosts.get());
                HttpRequestResult valid = browser.post("/login", "csrf=" + csrf, "https://localhost:8443");
                assertEquals(302, status(valid));
                assertEquals(409, status(browser.post("/login", "csrf=" + csrf, "https://localhost:8443")));
                assertEquals(302, status(browser.post("/logout", "csrf=" + csrf, "https://localhost:8443")));
                assertEquals(0, provider.tokenPosts.get());
            });
        }
    }

    @Test
    void requestExpiryCleanupRejectsPendingAndSessionWithoutTokenPost() throws Exception {
        MutableClock clock = new MutableClock();
        try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
            with(provider, clock, browser -> {
                Flow flow = begin(provider, browser);
                clock.advance(Duration.ofMinutes(5));
                assertEquals(400, status(browser.callback(flow.query, AuthorizationRequestOptions.ResponseMode.QUERY, null)));
                assertEquals(0, provider.tokenPosts.get());
                Flow second = begin(provider, browser);
                clock.advance(Duration.ofMinutes(30));
                assertEquals(400, status(browser.callback(second.query, AuthorizationRequestOptions.ResponseMode.QUERY, null)));
                assertEquals(0, provider.tokenPosts.get());
                assertTrue(body(browser.get("/")).contains("Signed out"));
            });
        }
    }

    @Test
    void finiteStoresRejectNewAdmissionAndClockRegressionExpiresSessions() throws Exception {
        MutableClock clock = new MutableClock();
        try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
            OidcApplication app = provider.application(2, 1, AuthorizationRequestOptions.ResponseMode.QUERY);
            SokletSimulator.run(app.configuration(18080), simulator -> {
                Browser first = new Browser(simulator); Browser second = new Browser(simulator); Browser third = new Browser(simulator);
                begin(provider, first);
                HttpRequestResult home = second.get("/");
                assertEquals(503, status(second.post("/login", "csrf=" + csrf(home), "https://localhost:8443")));
                assertEquals(503, status(third.get("/")));
                assertEquals(0, provider.tokenPosts.get());
                clock.advance(Duration.ofSeconds(-1));
                assertEquals(200, status(third.get("/")));
                assertFalse(third.cookies.isEmpty());
            });
        }
    }

    @Test
    void sessionByteBudgetRejectsBeforeEntryCeilingAndLogoutReturnsCapacity() throws Exception {
        MutableClock clock = new MutableClock();
        try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
            OidcApplication app = provider.application(1024, 8, AuthorizationRequestOptions.ResponseMode.QUERY);
            SokletSimulator.run(app.configuration(18080), simulator -> {
                Browser last = new Browser(simulator);
                HttpRequestResult lastHome = last.get("/");
                for (int index = 1; index < 512; index++) assertEquals(200, status(new Browser(simulator).get("/")));
                assertEquals(503, status(new Browser(simulator).get("/")));
                assertEquals(302, status(last.post("/logout", "csrf=" + csrf(lastHome), "https://localhost:8443")));
                assertEquals(200, status(new Browser(simulator).get("/")));
                assertEquals(0, provider.tokenPosts.get());
            });
        }
    }

    @Test
    void infrastructureFailureIsFixedAndDoesNotExposeProviderResponse() throws Exception {
        MutableClock clock = new MutableClock();
        try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
            provider.mode(SyntheticOidcProvider.Mode.SERVER_ERROR);
            with(provider, clock, browser -> {
                Flow flow = begin(provider, browser);
                HttpRequestResult response = browser.callback(flow.query, AuthorizationRequestOptions.ResponseMode.QUERY, null);
                assertEquals(503, status(response)); assertEquals("Please try again later", body(response));
                assertEquals(List.of("no-referrer"), response.getMarshaledResponse().getHeaders().get("Referrer-Policy"));
                assertEquals(1, provider.tokenPosts.get()); assertEquals(1, provider.keyGets.get()); // warmUp only
                assertFalse(browser.cookies.containsKey(OidcApplication.PENDING_COOKIE));
            });
        }
    }

    @Test
    void racingCallbacksReserveOneFlowBeforeNetworkIo() throws Exception {
        MutableClock clock = new MutableClock();
        try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
            OidcApplication app = provider.application(8, 8, AuthorizationRequestOptions.ResponseMode.QUERY);
            SokletSimulator.run(app.configuration(18080), simulator -> {
                Browser original = new Browser(simulator); Flow flow = begin(provider, original);
                Browser first = new Browser(simulator); first.cookies.putAll(original.cookies);
                Browser second = new Browser(simulator); second.cookies.putAll(original.cookies);
                CountDownLatch ready = new CountDownLatch(2); CountDownLatch go = new CountDownLatch(1);
                ExecutorService executor = Executors.newFixedThreadPool(2);
                try {
                    Future<Integer> left = executor.submit(() -> { ready.countDown(); assertTrue(go.await(5, TimeUnit.SECONDS));
                        return status(first.callback(flow.query, AuthorizationRequestOptions.ResponseMode.QUERY, null)); });
                    Future<Integer> right = executor.submit(() -> { ready.countDown(); assertTrue(go.await(5, TimeUnit.SECONDS));
                        return status(second.callback(flow.query, AuthorizationRequestOptions.ResponseMode.QUERY, null)); });
                    assertTrue(ready.await(5, TimeUnit.SECONDS)); go.countDown();
                    assertEquals(Set.of(302, 400), Set.of(left.get(10, TimeUnit.SECONDS), right.get(10, TimeUnit.SECONDS)));
                    assertEquals(1, provider.tokenPosts.get());
                } catch (Exception exception) { throw new AssertionError("Concurrent callback test failed", exception); }
                finally { go.countDown(); executor.shutdownNow(); }
            });
        }
    }

    @Test
    void cookieDuplicationAndCrossBrowserFlowSwapRejectWithoutConsumingOtherFlow() throws Exception {
        MutableClock clock = new MutableClock();
        try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
            OidcApplication app = provider.application(8, 8, AuthorizationRequestOptions.ResponseMode.QUERY);
            SokletSimulator.run(app.configuration(18080), simulator -> {
                Browser first = new Browser(simulator); Flow flow = begin(provider, first);
                Browser second = new Browser(simulator); Flow other = begin(provider, second);
                String firstBinding = first.cookies.get(OidcApplication.PENDING_COOKIE);
                String secondBinding = second.cookies.put(OidcApplication.PENDING_COOKIE, firstBinding);
                assertEquals(400, status(second.callback(flow.query, AuthorizationRequestOptions.ResponseMode.QUERY, null)));
                assertEquals(0, provider.tokenPosts.get());
                String duplicateCookie = OidcApplication.SESSION_COOKIE + "=" + first.cookies.get(OidcApplication.SESSION_COOKIE)
                        + "; " + OidcApplication.SESSION_COOKIE + "=" + first.cookies.get(OidcApplication.SESSION_COOKIE)
                        + "; " + OidcApplication.PENDING_COOKIE + "=" + firstBinding;
                assertEquals(400, status(first.callback(flow.query, AuthorizationRequestOptions.ResponseMode.QUERY,
                        Map.of("Cookie", List.of(duplicateCookie)))));
                assertEquals(0, provider.tokenPosts.get());
                first.cookies.put(OidcApplication.PENDING_COOKIE, firstBinding);
                assertEquals(302, status(first.callback(flow.query, AuthorizationRequestOptions.ResponseMode.QUERY, null)));
                second.cookies.put(OidcApplication.PENDING_COOKIE, secondBinding);
                assertEquals(302, status(second.callback(other.query, AuthorizationRequestOptions.ResponseMode.QUERY, null)));
                assertEquals(2, provider.tokenPosts.get());
            });
        }
    }

    @Test
    void securityHeadersCookiesOriginAndListenerAreExplicit() throws Exception {
        MutableClock clock = new MutableClock();
        try (SyntheticOidcProvider provider = new SyntheticOidcProvider(clock)) {
            OidcApplication app = provider.application(4, 4, AuthorizationRequestOptions.ResponseMode.QUERY);
            assertTrue(app.configuration(18080).getHttpServer().isPresent());
            assertThrows(IllegalArgumentException.class, () -> app.configuration(80));
            for (String origin : List.of("http://localhost:8443", "https://0.0.0.0:8443", "https://public.example",
                    "https://user@localhost:8443", "https://localhost:8443/path", "https://localhost:8443/?x=1", "https://localhost:8443/#x"))
                assertThrows(IllegalArgumentException.class, () -> OidcApplication.checkedOrigin(URI.create(origin)));
            SokletSimulator.run(app.configuration(18080), simulator -> {
                Browser browser = new Browser(simulator); HttpRequestResult home = browser.get("/");
                Map<String, List<String>> headers = home.getMarshaledResponse().getHeaders();
                assertEquals(List.of("no-store"), headers.get("Cache-Control"));
                assertEquals(List.of("same-origin"), headers.get("Referrer-Policy"));
                assertTrue(headers.get("Content-Security-Policy").iterator().next().contains("default-src 'none'"));
                ResponseCookie cookie = home.getMarshaledResponse().getCookies().iterator().next();
                assertTrue(cookie.getName().startsWith("__Host-")); assertTrue(cookie.getSecure()); assertTrue(cookie.getHttpOnly());
                assertEquals(Optional.of("/"), cookie.getPath()); assertTrue(cookie.getDomain().isEmpty());
                assertEquals(Optional.of(ResponseCookie.SameSite.NONE), cookie.getSameSite());
                assertEquals(404, status(browser.get("/not-a-route")));
            });
        }
    }

    private static void with(@NonNull SyntheticOidcProvider provider, @NonNull MutableClock clock,
                             @NonNull Consumer<@NonNull Browser> test) {
        OidcApplication app = provider.application(8, 8, AuthorizationRequestOptions.ResponseMode.QUERY);
        SokletSimulator.run(app.configuration(18080), simulator -> test.accept(new Browser(simulator)));
    }
    private static @NonNull Flow begin(@NonNull SyntheticOidcProvider provider, @NonNull Browser browser) {
        HttpRequestResult home = browser.get("/"); assertEquals(200, status(home));
        HttpRequestResult redirect = browser.post("/login", "csrf=" + csrf(home), "https://localhost:8443");
        assertEquals(302, status(redirect));
        assertEquals(List.of("no-referrer"), redirect.getMarshaledResponse().getHeaders().get("Referrer-Policy"));
        return new Flow(provider.authorize(location(redirect)));
    }
    private static int status(@NonNull HttpRequestResult response) { return response.getMarshaledResponse().getStatusCode(); }
    private static @NonNull String body(@NonNull HttpRequestResult response) {
        if (response.getResponse().isPresent()) return response.getResponse().orElseThrow().getBody().orElseThrow().toString();
        return new String(((MarshaledResponseBody.Bytes) response.getMarshaledResponse().getBody().orElseThrow()).getBytes(), StandardCharsets.UTF_8);
    }
    private static @NonNull String csrf(@NonNull HttpRequestResult home) {
        var matcher = Pattern.compile("name=\"csrf\" value=\"([A-Za-z0-9_-]{43})\"").matcher(body(home));
        assertTrue(matcher.find()); return matcher.group(1);
    }
    private static @NonNull URI location(@NonNull HttpRequestResult result) {
        return URI.create(result.getMarshaledResponse().getHeaders().get("Location").iterator().next());
    }
    private static final class Flow {
        final @NonNull String query;
        Flow(@NonNull String query) { this.query = query; }
    }
    static final class MutableClock extends Clock {
        private @NonNull Instant now = NOW;
        synchronized void advance(@NonNull Duration duration) { this.now = this.now.plus(duration); }
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return Clock.fixed(instant(), zone); }
        @Override public synchronized @NonNull Instant instant() { return this.now; }
    }
    private static final class Browser {
        final @NonNull Simulator simulator;
        final @NonNull Map<@NonNull String, @NonNull String> cookies = new HashMap<>();
        Browser(@NonNull Simulator simulator) { this.simulator = simulator; }
        @NonNull HttpRequestResult get(@NonNull String path) { return send(HttpMethod.GET, path, null, Map.of()); }
        @NonNull HttpRequestResult post(@NonNull String path, @NonNull String body, @Nullable String origin) {
            Map<String, List<String>> headers = new HashMap<>();
            headers.put("Content-Type", List.of("application/x-www-form-urlencoded"));
            if (origin != null) headers.put("Origin", List.of(origin));
            return send(HttpMethod.POST, path, body, headers);
        }
        @NonNull HttpRequestResult callback(@NonNull String query, AuthorizationRequestOptions.@NonNull ResponseMode mode,
                                            @Nullable Map<@NonNull String, @NonNull List<@NonNull String>> overrides) {
            Map<String, List<String>> headers = new HashMap<>();
            if (mode == AuthorizationRequestOptions.ResponseMode.FORM_POST)
                headers.put("Content-Type", List.of("application/x-www-form-urlencoded"));
            if (overrides != null) headers.putAll(overrides);
            return mode == AuthorizationRequestOptions.ResponseMode.QUERY ? send(HttpMethod.GET, "/callback?" + query, null, headers)
                    : send(HttpMethod.POST, "/callback", query, headers);
        }
        @NonNull HttpRequestResult send(@NonNull HttpMethod method, @NonNull String path, @Nullable String body,
                                        @NonNull Map<@NonNull String, @NonNull List<@NonNull String>> overrides) {
            Map<String, List<String>> headers = new HashMap<>(); headers.put("Host", List.of("localhost:8443"));
            if (!this.cookies.isEmpty()) headers.put("Cookie", List.of(String.join("; ", this.cookies.entrySet().stream()
                    .map(entry -> entry.getKey() + "=" + entry.getValue()).toList())));
            headers.putAll(overrides);
            Request.RawBuilder builder = Request.withRawUrl(method, path).headers(headers);
            if (body != null) builder.body(body.getBytes(StandardCharsets.UTF_8));
            HttpRequestResult response = this.simulator.performHttpRequest(builder.build());
            for (ResponseCookie cookie : response.getMarshaledResponse().getCookies()) {
                if (cookie.getMaxAge().map(Duration::isZero).orElse(false)) this.cookies.remove(cookie.getName());
                else this.cookies.put(cookie.getName(), cookie.getValue().orElseThrow());
            }
            return response;
        }
    }
}
