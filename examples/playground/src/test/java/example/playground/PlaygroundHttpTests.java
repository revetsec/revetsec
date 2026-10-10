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

import com.revetsec.oauth.BearerToken;
import com.soklet.*;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class PlaygroundHttpTests {
    @Test void actualHtmlFormBeginWithoutCsrfHeaderUsesRawRouteAndRejectsAmbiguousInputs() throws Exception {
        try (PlaygroundOidcTests.Provider provider = new PlaygroundOidcTests.Provider()) {
            BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 4);
            SafeViews views = new SafeViews(LocalSecrets.randomBytes());
            PlaygroundConfig config = provider.config();
            PlaygroundResources resources = new PlaygroundResources(config, sessions, views,
                    new PlaygroundOidc(sessions, views, Clock.systemUTC()), HttpClient.newHttpClient());
            BrowserSessions.Session session = sessions.begin();
            Request valid = Request.withPath(HttpMethod.POST, "/oidc/begin")
                    .headers(Map.of("Host", List.of("localhost:8443"), "Origin", List.of("https://localhost:8443"),
                            "Cookie", List.of(BrowserSessions.COOKIE + "=" + session.id),
                            "Content-Type", List.of("application/x-www-form-urlencoded")))
                    .body(("csrf=" + session.csrf + "&mode=atomic&responseMode=query").getBytes(StandardCharsets.US_ASCII)).build();
            assertEquals("/oidc/begin", valid.getResourcePath().getPath());
            assertNotEquals("/oidc/begin", valid.getResourcePath().toString());
            SokletSimulator.run(Playground.sokletConfig(config, resources, views), simulator -> {
                for (String body : Set.of("csrf=wrong", "mode=atomic", "csrf=" + session.csrf + "&csrf=" + session.csrf,
                        "csrf=" + session.csrf + "&%63srf=wrong", "csrf=" + session.csrf + "&padding=%FF",
                        "csrf=" + session.csrf + "&padding=%", "csrf=" + session.csrf + "&padding=" + "A".repeat(4096))) {
                    Response denied = simulator.performHttpRequest(valid.copy().body(body.getBytes(StandardCharsets.US_ASCII)).finish())
                            .getResponse().orElseThrow();
                    assertEquals(403, denied.getStatusCode());
                    assertNull(session.flow);
                }
                for (String header : Set.of("Content-Type", "X-CSRF-Token")) {
                    Response denied = simulator.performHttpRequest(valid.copy().headers(headers -> headers.put(header,
                            header.equals("Content-Type") ? List.of("application/x-www-form-urlencoded", "text/plain")
                                    : List.of(session.csrf, "wrong"))).finish()).getResponse().orElseThrow();
                    assertEquals(403, denied.getStatusCode());
                    assertNull(session.flow);
                }
                assertEquals(403, simulator.performHttpRequest(valid.copy().body(new byte[] {(byte) 255}).finish())
                        .getResponse().orElseThrow().getStatusCode());
                assertEquals(0, provider.requests.get());
                Response redirect = simulator.performHttpRequest(valid).getResponse().orElseThrow();
                assertEquals(302, redirect.getStatusCode());
                assertEquals(List.of("no-referrer"), redirect.getHeaders().get("Referrer-Policy"));
                assertTrue(redirect.getHeaders().get("Location").iterator().next().startsWith(provider.issuer + "/auth?"));
                assertTrue(redirect.getHeaders().get("Location").iterator().next().contains("code_challenge_method=S256"));
                assertNotNull(session.flow);
                assertTrue(provider.requests.get() > 0);
                assertEquals(0, provider.posts.get());
            });
        }
    }

    @Test void configProbeInspectReplayRequireBoundBrowserSessionOriginAndCsrfBeforeValidation() throws Exception {
        PlaygroundAdmissionTests.Fixtures fixture = new PlaygroundAdmissionTests.Fixtures();
        AtomicInteger calls = new AtomicInteger();
        BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 4);
        SafeViews views = new SafeViews(LocalSecrets.randomBytes());
        PlaygroundResources resources = new PlaygroundResources(fixture.config(), sessions, views,
                new PlaygroundOidc(sessions, views, Clock.systemUTC()), HttpClient.newHttpClient(), fixture.validator(calls));
        SokletSimulator.run(Playground.sokletConfig(fixture.config(), resources, views), simulator -> {
            for (String path : Set.of("/api/config", "/api/probe", "/api/inspect", "/api/replay")) {
                for (Map<String, List<String>> headers : Set.of(Map.of("Host", List.of("localhost:8443")),
                        Map.of("Host", List.of("localhost:8443"), "Origin", List.of("https://foreign.example")))) {
                    Response denied = simulator.performHttpRequest(Request.withPath(HttpMethod.POST, path).headers(headers).build())
                            .getResponse().orElseThrow();
                    assertEquals(403, denied.getStatusCode());
                }
            }
            BrowserSessions.Session session = sessions.begin();
            Response nullOrigin = simulator.performHttpRequest(Request.withPath(HttpMethod.POST, "/oidc/begin")
                    .headers(Map.of("Host", List.of("localhost:8443"), "Origin", List.of("null"),
                            "Cookie", List.of(BrowserSessions.COOKIE + "=" + session.id),
                            "Content-Type", List.of("application/x-www-form-urlencoded")))
                    .body(("csrf=" + session.csrf).getBytes(StandardCharsets.US_ASCII)).build()).getResponse().orElseThrow();
            assertEquals(403, nullOrigin.getStatusCode());
            assertEquals(List.of("no-referrer"), nullOrigin.getHeaders().get("Referrer-Policy"));
            assertEquals(403, resources.inspect(control(session, "wrong", "opaque")).getStatusCode());
            assertEquals(403, resources.inspect(control(null, session.csrf, "opaque")).getStatusCode());
            assertEquals(0, calls.get());
            String valid = fixture.jwt(fixture.issuer, fixture.resource, "mcp:whoami", 60, false);
            Response accepted = simulator.performHttpRequest(control(session, session.csrf, valid)).getResponse().orElseThrow();
            assertEquals(200, accepted.getStatusCode());
            assertEquals(List.of("no-referrer"), accepted.getHeaders().get("Referrer-Policy"));
            assertFalse(accepted.getBody().orElseThrow().toString().contains(valid));
            assertFalse(accepted.getBody().orElseThrow().toString().contains("synthetic-private-subject"));
            assertEquals(1, calls.get());
            assertEquals(400, resources.inspect(control(session, session.csrf, "A".repeat(8193))).getStatusCode());
            assertEquals(1, calls.get());
        });
    }

    @Test void rejectedInspectionOnlyLabelsAllowlistedUnverifiedHeaderAndFixedReason() throws Exception {
        PlaygroundAdmissionTests.Fixtures fixture = new PlaygroundAdmissionTests.Fixtures();
        BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 4);
        SafeViews views = new SafeViews(LocalSecrets.randomBytes());
        PlaygroundResources resources = new PlaygroundResources(fixture.config(), sessions, views,
                new PlaygroundOidc(sessions, views, Clock.systemUTC()), HttpClient.newHttpClient(), fixture.validator(new AtomicInteger()));
        BrowserSessions.Session session = sessions.begin();
        String claims = "{\"sub\":\"secret-identity\",\"kid\":\"secret-key\"}";
        String encoded = fixture.sign("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"secret-key\"}", claims);
        Response response = resources.inspect(control(session, session.csrf, encoded));
        assertEquals(400, response.getStatusCode());
        String body = response.getBody().orElseThrow().toString();
        assertTrue(body.contains("UNVERIFIED")); assertTrue(body.contains("RS256")); assertTrue(body.contains("JWT"));
        for (String secret : Set.of(encoded, "secret-identity", "secret-key", "kid", "sub")) assertFalse(body.contains(secret));
        assertFalse(PlaygroundResources.unverifiedLabels("opaque").getMembers().containsKey("alg"));
    }

    @Test void staticResourcesMetadataAndUiUseFixedRoutesCspEscapingAndNoBrowserSecretStorage() throws Exception {
        PlaygroundAdmissionTests.Fixtures fixture = new PlaygroundAdmissionTests.Fixtures();
        SokletSimulator.run(fixture.application(fixture.validator(new AtomicInteger())), simulator -> {
            for (String path : Set.of("/", "/app.js", "/style.css", "/api/session", "/.well-known/oauth-protected-resource/mcp")) {
                Response response = simulator.performHttpRequest(Request.withPath(HttpMethod.GET, path)
                        .headers(Map.of("Host", List.of("localhost:8443"))).build()).getResponse().orElseThrow();
                assertEquals(200, response.getStatusCode());
                assertTrue(response.getHeaders().containsKey("Content-Security-Policy"));
                assertEquals(List.of("no-store"), response.getHeaders().get("Cache-Control"));
                assertEquals(List.of(path.equals("/") ? "same-origin" : "no-referrer"),
                        response.getHeaders().get("Referrer-Policy"));
                String body = response.getBody().orElseThrow().toString();
                assertFalse(body.contains("localStorage")); assertFalse(body.contains("sessionStorage")); assertFalse(body.contains("innerHTML"));
                if (path.equals("/app.js")) assertTrue(body.indexOf("byId('credential').value = ''") < body.indexOf("await post('/api/inspect'"));
                if (path.startsWith("/.well-known")) {
                    assertTrue(body.contains(fixture.resource)); assertTrue(body.contains("authorization_servers"));
                    assertTrue(body.contains("header"));
                }
            }
            assertEquals(403, simulator.performHttpRequest(Request.withPath(HttpMethod.GET, "/api/session")
                    .headers(Map.of("Host", List.of("foreign.example"))).build()).getResponse().orElseThrow().getStatusCode());
            assertEquals(404, simulator.performHttpRequest(Request.withPath(HttpMethod.GET, "/../../file")
                    .headers(Map.of("Host", List.of("localhost:8443"))).build()).getMarshaledResponse().getStatusCode());
        });
        assertEquals("&lt;script&gt;&amp;&quot;&#39;", SafeViews.html("<script>&\"'"));
    }

    static @NonNull Request control(BrowserSessions.@Nullable Session session, @NonNull String csrf, @NonNull String credential) {
        Map<String, List<String>> headers = new java.util.LinkedHashMap<>();
        headers.put("Host", List.of("localhost:8443")); headers.put("Origin", List.of("https://localhost:8443"));
        headers.put("X-CSRF-Token", List.of(csrf)); headers.put("Content-Type", List.of("text/plain; charset=UTF-8"));
        if (session != null) headers.put("Cookie", List.of(BrowserSessions.COOKIE + "=" + session.id));
        return Request.withPath(HttpMethod.POST, "/api/inspect").headers(headers).body(credential.getBytes(StandardCharsets.UTF_8)).build();
    }
}
