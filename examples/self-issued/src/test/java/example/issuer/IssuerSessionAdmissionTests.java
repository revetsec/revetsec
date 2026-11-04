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
package example.issuer;

import com.soklet.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class IssuerSessionAdmissionTests {
    @Test void anonymousAuthorizationReadsNeverAllocateAndKeepExactRequestForExplicitAdmission() throws Exception {
        var app = IssuerApplicationTests.app();
        String query = IssuerApplicationTests.query(app, "demo-public", "mcp:discover");
        for (int i = 0; i < 140; i++) {
            var page = app.authorize(IssuerApplicationTests.request(app, HttpMethod.GET, "/authorize?" + query, null, null));
            assertEquals(200, page.getStatusCode());
            assertTrue(page.getCookies().isEmpty(), "Anonymous GET allocated a session");
            assertTrue(IssuerApplicationTests.text(page).contains("/session?" + LocalInputs.html(query)));
        }
        SokletSimulator.run(IssuerPlayground.sokletConfig(app), sim -> {
            var admitted = sim.performHttpRequest(IssuerApplicationTests.request(app, HttpMethod.POST,
                    "/session?" + query, "begin=1", null)).getMarshaledResponse();
            assertEquals(303, admitted.getStatusCode());
            assertEquals(List.of("/authorize?" + query), admitted.getHeaders().get("Location"));
            var c = admitted.getCookies().iterator().next();
            String cookie = c.getName() + "=" + c.getValue().orElseThrow();
            var session = app.sessions.find(IssuerApplicationTests.request(app, HttpMethod.GET, "/", null, cookie)).orElseThrow();
            assertNull(session.pending.get()); assertFalse(session.authenticated);
            var login = app.authorize(IssuerApplicationTests.request(app, HttpMethod.GET, "/authorize?" + query, null, cookie));
            assertEquals(200, login.getStatusCode()); assertNotNull(session.pending.get());
        });
    }

    @Test void bootstrapRejectsUntrustedOrAmbiguousInputBeforeAllocating() throws Exception {
        var app = IssuerApplicationTests.app();
        SokletSimulator.run(IssuerPlayground.sokletConfig(app), sim -> {
            var valid = IssuerApplicationTests.request(app, HttpMethod.POST, "/session?client_id=demo-public", "begin=1", null);
            for (String origin : List.of("null", "https://foreign.example")) {
                var response = sim.performHttpRequest(valid.copy().headers(h -> h.put("Origin", List.of(origin))).finish()).getMarshaledResponse();
                assertEquals(403, response.getStatusCode()); assertTrue(response.getCookies().isEmpty());
            }
            assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.remove("Origin")).finish()).getMarshaledResponse().getStatusCode());
            assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.put("Origin", List.of(app.config.origin.toString(), app.config.origin.toString()))).finish()).getMarshaledResponse().getStatusCode());
            assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.put("Host", List.of("foreign.example"))).finish()).getMarshaledResponse().getStatusCode());
            assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.put("Content-Type", List.of("text/plain"))).finish()).getMarshaledResponse().getStatusCode());
            for (String body : List.of("", "begin=0", "begin=1&begin=1", "begin=1&csrf=other"))
                assertEquals(403, sim.performHttpRequest(valid.copy().body(body.getBytes(java.nio.charset.StandardCharsets.US_ASCII)).finish()).getMarshaledResponse().getStatusCode());
            assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.put("Content-Type", List.of("application/x-www-form-urlencoded", "text/plain"))).finish()).getMarshaledResponse().getStatusCode());
            assertEquals(413, sim.performHttpRequest(valid.copy().contentTooLarge(true).finish()).getMarshaledResponse().getStatusCode());
        });
    }

    @Test void fullStorePreservesAnonymousSessionAndExpiryIsAbsolute() {
        var clock = new MutableClock(); var sessions = new BrowserSessions(clock, 1, true);
        var first = sessions.begin();
        assertThrows(IllegalStateException.class, sessions::begin);
        var request = Request.withPath(HttpMethod.GET, "/").headers(Map.of("Cookie", List.of("__Host-RevetsecIssuer=" + first.id))).build();
        clock.now = first.expires.minusNanos(1);
        assertSame(first, sessions.find(request).orElseThrow());
        clock.now = first.expires;
        assertTrue(sessions.find(request).isEmpty()); assertNotNull(sessions.begin());
    }

    @Test void simultaneousAdmissionNeverEvictsOrExceedsCapacity() throws Exception {
        var sessions = new BrowserSessions(Clock.systemUTC(), 1, true);
        var executor = Executors.newFixedThreadPool(8); var start = new CountDownLatch(1);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 16; i++) results.add(executor.submit(() -> {
                start.await(); try { sessions.begin(); return true; } catch (IllegalStateException full) { return false; }
            }));
            start.countDown(); int admitted = 0;
            for (var result : results) if (result.get(10, TimeUnit.SECONDS)) admitted++;
            assertEquals(1, admitted);
        } finally { start.countDown(); executor.shutdownNow(); assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS)); }
    }

    private static final class MutableClock extends Clock {
        @NonNull Instant now = Instant.parse("2026-11-03T12:00:00Z");
        @Override public @NonNull ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
        @Override public @NonNull Instant instant() { return now; }
    }
}
