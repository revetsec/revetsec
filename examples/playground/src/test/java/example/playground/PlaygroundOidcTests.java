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
package example.playground;

import com.revetsec.json.JsonObject;
import com.revetsec.oidc.OidcClient;
import com.soklet.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import com.sun.net.httpserver.HttpExchange;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class PlaygroundOidcTests {
    @Test void realOidcCompletionRotatesSessionAndAtomicReplayRejectsBeforeAnotherCodePost() throws Exception {
        roundTrip(false, false);
    }
    @Test void crossSiteFormPostSealedReplayUsesOriginalSourceAndAsSingleUseCodeBoundary() throws Exception {
        roundTrip(true, true);
    }

    private static void roundTrip(boolean sealed, boolean formPost) throws Exception {
        try (Provider provider = new Provider()) {
            BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 4, BrowserSessions.SESSION_CHARGE_BYTES);
            SafeViews views = new SafeViews(LocalSecrets.randomBytes());
            PlaygroundOidc oidc = new PlaygroundOidc(sessions, views, Clock.systemUTC());
            PlaygroundConfig config = provider.config();
            BrowserSessions.Session original = sessions.begin();
            OidcClient client = config.oidcClient(HttpClient.newHttpClient());
            Response redirect = oidc.begin(config, client, original, sealed, formPost, true);
            assertEquals(302, redirect.getStatusCode());
            assertEquals(Set.of("no-referrer"), redirect.getHeaders().get("Referrer-Policy"));
            URI auth = URI.create(redirect.getHeaders().get("Location").iterator().next());
            Map<String, String> parameters = Provider.parameters(auth.getRawQuery());
            provider.nonce = parameters.get("nonce");
            assertNotNull(provider.nonce);
            assertEquals("S256", parameters.get("code_challenge_method"));
            ResponseCookie cookie = redirect.getCookies().iterator().next();
            Instant pendingExpires = original.flow.expires;
            String callback = "code=synthetic-code&state=" + Provider.escape(parameters.get("state"))
                    + "&iss=" + Provider.escape(provider.issuer);
            Map<String, Set<String>> headers = new java.util.LinkedHashMap<>();
            headers.put("Host", Set.of("localhost:8443"));
            headers.put("Cookie", Set.of(BrowserSessions.COOKIE + "=" + original.id + "; " + cookie.getName() + "=" + cookie.getValue().orElseThrow()));
            if (formPost) {
                headers.put("Origin", Set.of(provider.issuer));
                headers.put("Content-Type", Set.of("application/x-www-form-urlencoded"));
            }
            Request request = Request.withRawUrl(formPost ? HttpMethod.POST : HttpMethod.GET,
                    formPost ? "/oidc/callback" : "/oidc/callback?" + callback).headers(headers)
                    .body(formPost ? callback.getBytes(StandardCharsets.UTF_8) : null).build();
            Response completed = oidc.callback(config, request);
            assertEquals(302, completed.getStatusCode());
            assertEquals(Set.of("no-referrer"), completed.getHeaders().get("Referrer-Policy"));
            assertEquals(1, provider.posts.get());
            ResponseCookie rotatedCookie = completed.getCookies().stream().filter(c -> c.getName().equals(BrowserSessions.COOKIE)).findFirst().orElseThrow();
            String rotatedId = rotatedCookie.getValue().orElseThrow();
            assertNotEquals(original.id, rotatedId);
            assertTrue(sessions.find(Request.withPath(HttpMethod.GET, "/").headers(Map.of("Cookie", Set.of(BrowserSessions.COOKIE + "=" + original.id))).build()).isEmpty());
            BrowserSessions.Session rotated = sessions.find(Request.withPath(HttpMethod.GET, "/").headers(Map.of("Cookie", Set.of(BrowserSessions.COOKIE + "=" + rotatedId))).build()).orElseThrow();
            assertNotNull(rotated.identity); assertNotNull(rotated.journal);
            assertEquals(pendingExpires, rotated.journal.expires);
            assertEquals(BrowserSessions.SESSION_CHARGE_BYTES, sessions.chargedBytes());
            assertThrows(IllegalStateException.class, sessions::begin); // fixed charge already covers this identity+journal
            assertFalse(rotated.identity.toJson().contains("synthetic-private-subject"));
            assertFalse(BrowserSessions.csrfMatches(rotated, original.csrf));
            JsonObject replayed = oidc.replay(rotated);
            if (sealed) {
                assertEquals(2, provider.posts.get());
                assertTrue(replayed.toJson().contains("AS rejected single-use authorization code"), replayed.toJson());
            } else {
                assertEquals(1, provider.posts.get());
                assertTrue(replayed.toJson().contains("Rejected by normal callback validation"));
            }
            assertTrue(oidc.replay(rotated).toJson().contains("unavailable"));
            assertNull(rotated.journal);
            assertTrue(completed.getCookies().stream().anyMatch(c -> c.getName().equals(cookie.getName()) && c.getMaxAge().orElseThrow().isZero()));
        }
    }

    @Test void replayJournalIsOptInBoundedAndExpiresAtOriginalPendingLifetime() throws Exception {
        try (Provider provider = new Provider()) {
            BrowserSessionsTests.MutableClock clock = new BrowserSessionsTests.MutableClock();
            BrowserSessions sessions = new BrowserSessions(clock, 2);
            PlaygroundOidc oidc = new PlaygroundOidc(sessions, new SafeViews(LocalSecrets.randomBytes()), clock);
            BrowserSessions.Session session = sessions.begin();
            OidcClient client = OidcClient.withIssuer(provider.issuer).clientId("synthetic-client")
                    .redirectUri(provider.config().callbackUri()).allowInsecureLoopback(true).clock(clock)
                    .pendingAuthorizationLifetime(java.time.Duration.ofMinutes(3)).build();
            PlaygroundConfig disabled = new PlaygroundConfig(provider.config().origin, provider.issuer, "synthetic-client", "none",
                    "synthetic-client", "none", "jwt", true, false, 8080, 8081);
            assertEquals(302, oidc.begin(disabled, client, session, false, false, true).getStatusCode());
            assertFalse(session.flow.capture);
            assertEquals(409, oidc.begin(disabled, client, session, false, false, false).getStatusCode());
            assertEquals(clock.instant().plusSeconds(180), session.flow.expires);
            clock.now = session.flow.expires;
            sessions.cleanup();
            assertNull(session.flow);
            assertNull(session.journal);
        }
    }

    @Test void wrongBrowserAndMissingFlowCookieCannotTriggerTokenPostOrCreateJournal() throws Exception {
        try (Provider provider = new Provider()) {
            BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 4);
            PlaygroundOidc oidc = new PlaygroundOidc(sessions, new SafeViews(LocalSecrets.randomBytes()), Clock.systemUTC());
            BrowserSessions.Session original = sessions.begin();
            BrowserSessions.Session foreign = sessions.begin();
            PlaygroundConfig config = provider.config();
            Response redirect = oidc.begin(config, config.oidcClient(HttpClient.newHttpClient()), original, false, false, true);
            Map<String, String> fields = Provider.parameters(URI.create(redirect.getHeaders().get("Location").iterator().next()).getRawQuery());
            String path = "/oidc/callback?code=synthetic-code&state=" + Provider.escape(fields.get("state")) + "&iss=" + Provider.escape(provider.issuer);
            Request wrongBrowser = Request.withRawUrl(HttpMethod.GET, path).headers(Map.of("Cookie", Set.of(BrowserSessions.COOKIE + "=" + foreign.id))).build();
            Response rejectedCallback = oidc.callback(config, wrongBrowser);
            assertEquals(400, rejectedCallback.getStatusCode());
            assertEquals(Set.of("no-referrer"), rejectedCallback.getHeaders().get("Referrer-Policy"));
            ResponseCookie flowCookie = redirect.getCookies().iterator().next();
            String duplicate = BrowserSessions.COOKIE + "=" + original.id + "; " + flowCookie.getName() + "=" + flowCookie.getValue().orElseThrow()
                    + "; " + flowCookie.getName() + "=" + flowCookie.getValue().orElseThrow();
            assertEquals(400, oidc.callback(config, Request.withRawUrl(HttpMethod.GET, path).headers(Map.of("Cookie", Set.of(duplicate))).build()).getStatusCode());
            assertEquals(0, provider.posts.get());
            Request missingCookie = Request.withRawUrl(HttpMethod.GET, path).headers(Map.of("Cookie", Set.of(BrowserSessions.COOKIE + "=" + original.id))).build();
            assertEquals(400, oidc.callback(config, missingCookie).getStatusCode());
            assertEquals(0, provider.posts.get()); assertNull(original.journal); assertNull(foreign.journal);
        }
    }

    static final class Provider implements AutoCloseable {
        final com.sun.net.httpserver.HttpServer server;
        final PlaygroundAdmissionTests.Fixtures signing;
        final String issuer;
        final AtomicInteger posts = new AtomicInteger();
        final AtomicInteger requests = new AtomicInteger();
        final AtomicInteger introspectionPosts = new AtomicInteger();
        volatile String introspectionAudience = "https://localhost:8443/mcp";
        volatile boolean active = true;
        volatile boolean introspectionUnavailable = false;
        String nonce = "unset";
        Provider() throws Exception {
            signing = new PlaygroundAdmissionTests.Fixtures();
            server = com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
            issuer = "http://127.0.0.1:" + server.getAddress().getPort();
            server.createContext("/", this::handle);
            server.start();
        }
        @NonNull PlaygroundConfig config() {
            return new PlaygroundConfig(URI.create("https://localhost:8443"), issuer, "synthetic-client", "none", "synthetic-client", "none", "jwt", true, true, 8080, 8081);
        }
        private void handle(@NonNull HttpExchange exchange) throws IOException {
            requests.incrementAndGet();
            try {
                String path = exchange.getRequestURI().getPath();
                String body;
                int status = 200;
                if (path.equals("/.well-known/oauth-authorization-server")) {
                    body = "{\"issuer\":\"" + issuer + "\",\"token_endpoint\":\"" + issuer + "/token\",\"introspection_endpoint\":\"" + issuer + "/introspect\","
                            + "\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"],\"introspection_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}";
                } else if (path.equals("/introspect")) {
                    introspectionPosts.incrementAndGet();
                    byte[] input = exchange.getRequestBody().readNBytes(4097);
                    if (input.length > 4096 || !parameters(new String(input, StandardCharsets.UTF_8)).getOrDefault("token", "").equals("synthetic-opaque")
                            || exchange.getRequestHeaders().getFirst("Authorization") == null)
                        throw new IllegalArgumentException("Synthetic introspection binding.");
                    if (introspectionUnavailable) { status = 503; body = "{}"; }
                    else body = JsonObject.builder().put("active", active).put("iss", issuer).put("aud", introspectionAudience)
                            .put("sub", "synthetic-private-subject").put("client_id", "synthetic-client").put("token_type", "Bearer")
                            .put("scope", "mcp:discover mcp:whoami").build().toJson();
                } else if (path.equals("/.well-known/openid-configuration")) {
                    body = "{\"issuer\":\"" + issuer + "\",\"authorization_endpoint\":\"" + issuer + "/auth\",\"token_endpoint\":\"" + issuer + "/token\",\"jwks_uri\":\"" + issuer + "/jwks\","
                            + "\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"token_endpoint_auth_methods_supported\":[\"none\"],"
                            + "\"code_challenge_methods_supported\":[\"S256\"],\"authorization_response_iss_parameter_supported\":true}";
                } else if (path.equals("/jwks")) body = signing.jwks();
                else if (path.equals("/token")) {
                    byte[] input = exchange.getRequestBody().readNBytes(4097);
                    if (input.length > 4096) throw new IllegalArgumentException("Synthetic request cap.");
                    Map<String, String> parameters = parameters(new String(input, StandardCharsets.UTF_8));
                    if (!parameters.containsKey("code_verifier") || !parameters.getOrDefault("code", "").equals("synthetic-code")) throw new IllegalArgumentException("Synthetic code binding.");
                    if (posts.incrementAndGet() > 1) { status = 400; body = "{\"error\":\"invalid_grant\"}"; }
                    else {
                        String id = signing.sign("{\"alg\":\"RS256\",\"kid\":\"synthetic\"}", JsonObject.builder()
                                .put("iss", issuer).put("aud", "synthetic-client").put("sub", "synthetic-private-subject")
                                .put("iat", Instant.now().getEpochSecond()).put("exp", Instant.now().plusSeconds(60).getEpochSecond())
                                .put("nonce", nonce).build().toJson());
                        body = JsonObject.builder().put("access_token", "synthetic-access-token").put("token_type", "Bearer")
                                .put("expires_in", 60L).put("id_token", id).build().toJson();
                    }
                } else { status = 404; body = "{}"; }
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(status, bytes.length); exchange.getResponseBody().write(bytes);
            } catch (Exception failure) {
                byte[] bytes = "{}".getBytes(StandardCharsets.US_ASCII);
                exchange.sendResponseHeaders(500, bytes.length); exchange.getResponseBody().write(bytes);
            } finally { exchange.close(); }
        }
        static @NonNull Map<@NonNull String, @NonNull String> parameters(@NonNull String raw) {
            Map<String, String> values = new java.util.LinkedHashMap<>();
            for (String field : raw.split("&")) {
                String[] parts = field.split("=", 2);
                if (parts.length == 2) values.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8), URLDecoder.decode(parts[1], StandardCharsets.UTF_8));
            }
            return values;
        }
        static @NonNull String escape(@NonNull String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
        @Override public void close() { server.stop(0); }
    }
}
