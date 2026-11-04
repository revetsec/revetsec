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

import com.soklet.*;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class SessionAdmissionTests {
    @Test void statusStaticAndMetadataFloodNeverAllocateAndAdmissionReusesOneSlot() throws Exception {
        var fixture = new PlaygroundAdmissionTests.Fixtures(); var clock = new BrowserSessionsTests.MutableClock();
        var sessions = new BrowserSessions(clock, 1); var views = new SafeViews(LocalSecrets.randomBytes());
        var resources = new PlaygroundResources(fixture.config(), sessions, views,
                new PlaygroundOidc(sessions, views, clock), HttpClient.newHttpClient());
        SokletSimulator.run(Playground.sokletConfig(fixture.config(), resources, views), sim -> {
            for (int i = 0; i < 40; i++) for (String path : List.of("/", "/app.js", "/style.css", "/api/session", "/.well-known/oauth-protected-resource/mcp")) {
                var response = sim.performHttpRequest(request(HttpMethod.GET, path, null, null)).getMarshaledResponse();
                assertEquals(200, response.getStatusCode()); assertTrue(response.getCookies().isEmpty(), "Read allocated a session");
                assertEquals(0, sessions.size()); assertEquals(0, sessions.chargedBytes());
            }
            var admitted = sim.performHttpRequest(request(HttpMethod.POST, "/api/session", "begin=1", null)).getMarshaledResponse();
            assertEquals(200, admitted.getStatusCode());
            var c = admitted.getCookies().iterator().next(); String cookie = c.getName() + "=" + c.getValue().orElseThrow();
            assertEquals(200, sim.performHttpRequest(request(HttpMethod.POST, "/api/session", "begin=1", cookie)).getMarshaledResponse().getStatusCode());
            assertEquals(1, sessions.size()); assertEquals(BrowserSessions.SESSION_CHARGE_BYTES, sessions.chargedBytes());
            assertEquals(503, sim.performHttpRequest(request(HttpMethod.POST, "/api/session", "begin=1", null)).getMarshaledResponse().getStatusCode());
            assertEquals(200, sim.performHttpRequest(request(HttpMethod.GET, "/api/session", null, null)).getMarshaledResponse().getStatusCode());
            var original = sessions.find(request(HttpMethod.GET, "/", null, cookie)).orElseThrow();
            clock.now = original.expires.minusNanos(1);
            assertEquals(200, sim.performHttpRequest(request(HttpMethod.GET, "/api/session", null, cookie)).getMarshaledResponse().getStatusCode());
            clock.now = original.expires;
            assertTrue(sim.performHttpRequest(request(HttpMethod.GET, "/api/session", null, cookie)).getMarshaledResponse().getCookies().isEmpty());
            assertEquals(0, sessions.size()); assertEquals(0, sessions.chargedBytes());
            assertEquals(200, sim.performHttpRequest(request(HttpMethod.POST, "/api/session", "begin=1", null)).getMarshaledResponse().getStatusCode());
        });
    }

    @Test void bootstrapRejectsMissingForeignDuplicateOriginsAndMalformedBodies() throws Exception {
        var fixture = new PlaygroundAdmissionTests.Fixtures(); var clock = new BrowserSessionsTests.MutableClock();
        var sessions = new BrowserSessions(clock, 1); var views = new SafeViews(LocalSecrets.randomBytes());
        var resources = new PlaygroundResources(fixture.config(), sessions, views,
                new PlaygroundOidc(sessions, views, clock), HttpClient.newHttpClient());
        SokletSimulator.run(Playground.sokletConfig(fixture.config(), resources, views), sim -> {
            var valid = request(HttpMethod.POST, "/api/session", "begin=1", null);
            for (List<String> origins : List.of(List.of("null"), List.of("https://foreign.example"), List.of("https://localhost:8443", "https://localhost:8443")))
                assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.put("Origin", origins)).finish()).getMarshaledResponse().getStatusCode());
            assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.remove("Origin")).finish()).getMarshaledResponse().getStatusCode());
            assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.put("Content-Type", List.of("text/plain"))).finish()).getMarshaledResponse().getStatusCode());
            assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.put("Content-Type", List.of("application/x-www-form-urlencoded", "application/x-www-form-urlencoded"))).finish()).getMarshaledResponse().getStatusCode());
            for (String body : List.of("", "begin=0", "begin=1&begin=1"))
                assertEquals(403, sim.performHttpRequest(request(HttpMethod.POST, "/api/session", body, null)).getMarshaledResponse().getStatusCode());
            assertEquals(403, sim.performHttpRequest(request(HttpMethod.POST, "/api/session?x=1", "begin=1", null)).getMarshaledResponse().getStatusCode());
            assertEquals(413, sim.performHttpRequest(valid.copy().contentTooLarge(true).finish()).getMarshaledResponse().getStatusCode());
            assertEquals(0, sessions.size());
        });
    }

    private static @NonNull Request request(@NonNull HttpMethod method, @NonNull String path, @Nullable String body, @Nullable String cookie) {
        Map<String, List<String>> headers = new HashMap<>(Map.of("Host", List.of("localhost:8443")));
        if (body != null) { headers.put("Origin", List.of("https://localhost:8443")); headers.put("Content-Type", List.of("application/x-www-form-urlencoded")); }
        if (cookie != null) headers.put("Cookie", List.of(cookie));
        var builder = Request.withRawUrl(method, path).headers(headers);
        if (body != null) builder.body(body.getBytes(StandardCharsets.US_ASCII));
        return builder.build();
    }
}
