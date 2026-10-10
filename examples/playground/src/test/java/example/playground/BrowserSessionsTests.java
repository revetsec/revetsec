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
import com.soklet.HttpMethod;
import com.soklet.Request;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class BrowserSessionsTests {
    @Test void capacityExpiryAndRotationInvalidateOldIdAndCsrfWithoutWorker() {
        MutableClock clock = new MutableClock();
        BrowserSessions sessions = new BrowserSessions(clock, 1);
        BrowserSessions.Session original = sessions.begin();
        assertThrows(IllegalStateException.class, sessions::begin);
        assertTrue(BrowserSessions.csrfMatches(original, original.csrf));
        assertFalse(BrowserSessions.csrfMatches(original, "foreign"));
        assertFalse(BrowserSessions.csrfMatches(original, null));
        BrowserSessions.Session rotated = sessions.rotate(original, JsonObject.builder().put("subject", "redacted").build());
        assertNotEquals(original.id, rotated.id); assertNotEquals(original.csrf, rotated.csrf);
        assertTrue(sessions.find(request(original.id)).isEmpty());
        assertSame(rotated, sessions.find(request(rotated.id)).orElseThrow());
        assertFalse(BrowserSessions.csrfMatches(rotated, original.csrf));
        clock.now = clock.now.plus(BrowserSessions.LIFETIME);
        assertEquals(0, sessions.size());
        assertNotNull(sessions.begin());
    }

    @Test void cookieAlwaysHasSecureHttpOnlyHostPathAndCrossSiteCallbackPolicy() {
        BrowserSessions.Session session = new BrowserSessions(Clock.systemUTC(), 1).begin();
        String cookie = BrowserSessions.cookie(session).toSetCookieHeaderRepresentation();
        assertTrue(cookie.startsWith("__Host-"));
        assertTrue(cookie.contains("Secure")); assertTrue(cookie.contains("HttpOnly"));
        assertTrue(cookie.contains("Path=/")); assertTrue(cookie.contains("SameSite=None"));
        assertFalse(cookie.contains("Domain="));
        assertFalse(session.toString().contains(session.id));
        assertFalse(session.toString().contains(session.binding));
    }

    @Test void localOriginBindAndSecretIndirectionRejectUnsafeInputs() {
        for (String origin : Set.of("https://foreign.example", "https://localhost.tunnel.example", "http://localhost:8443", "https://localhost/path"))
            assertThrows(IllegalArgumentException.class, () -> PlaygroundConfig.fromEnvironment(Map.of("PLAYGROUND_ORIGIN", origin)));
        assertThrows(IllegalArgumentException.class, () -> PlaygroundConfig.fromEnvironment(Map.of("PLAYGROUND_BIND", "0.0.0.0")));
        assertThrows(IllegalArgumentException.class, () -> LocalSecrets.resolve("literal-secret", Map.of()));
        assertThrows(IllegalArgumentException.class, () -> LocalSecrets.resolve("env:MISSING", Map.of()));
        assertEquals("synthetic-secret", LocalSecrets.resolve("env:LOCAL_SECRET", Map.of("LOCAL_SECRET", "synthetic-secret")));
        assertThrows(IllegalArgumentException.class, () -> LocalSecrets.resolve("file:relative-path", Map.of()));
        PlaygroundConfig config = PlaygroundConfig.fromEnvironment(Map.of("PLAYGROUND_ALLOW_LOOPBACK_HTTP", "true"));
        assertEquals("https://localhost:8443/mcp", config.resourceUri().toString());
        assertTrue(config.loopbackHttp);
    }

    @Test void rawCookiePairsRejectIdenticalAndDistinctDuplicatesBeforeSessionLookup() {
        BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 4);
        BrowserSessions.Session session = sessions.begin();
        for (String raw : Set.of(BrowserSessions.COOKIE + "=" + session.id + "; " + BrowserSessions.COOKIE + "=" + session.id,
                BrowserSessions.COOKIE + "=" + session.id + "; " + BrowserSessions.COOKIE + "=other",
                BrowserSessions.COOKIE + "=" + session.id + "; flow=first; flow=first",
                BrowserSessions.COOKIE + "=" + session.id + "; invalid",
                "x=" + "x".repeat(8192))) {
            Request request = Request.withPath(HttpMethod.GET, "/").headers(Map.of("Cookie", List.of(raw))).build();
            assertTrue(sessions.find(request).isEmpty());
        }
        assertTrue(sessions.find(Request.withPath(HttpMethod.GET, "/").headers(Map.of("Cookie", List.of(
                BrowserSessions.COOKIE + "=" + session.id, "other=value"))).build()).isEmpty());
        assertSame(session, sessions.find(request(session.id)).orElseThrow());
    }

    @Test void byteReservationRejectsNewEntriesAndOversizedIdentityWhileRotationRetainsOneCharge() {
        MutableClock clock = new MutableClock();
        BrowserSessions sessions = new BrowserSessions(clock, 4, BrowserSessions.SESSION_CHARGE_BYTES);
        BrowserSessions.Session original = sessions.begin();
        assertEquals(BrowserSessions.SESSION_CHARGE_BYTES, sessions.chargedBytes());
        assertThrows(IllegalArgumentException.class, () -> sessions.rotate(original, JsonObject.builder().put("subject", "s".repeat(2048)).build()));
        assertSame(original, sessions.find(request(original.id)).orElseThrow());
        BrowserSessions.Session rotated = sessions.rotate(original, JsonObject.builder().put("subject", "redacted").build());
        assertEquals(BrowserSessions.SESSION_CHARGE_BYTES, sessions.chargedBytes());
        assertEquals(1, sessions.size());
        assertThrows(IllegalStateException.class, sessions::begin); // entry cap is four; byte reservation denies
        clock.now = rotated.expires;
        assertEquals(0, sessions.chargedBytes()); assertNotNull(sessions.begin());
    }

    private static @NonNull Request request(@NonNull String id) {
        return Request.withPath(HttpMethod.GET, "/").headers(Map.of("Cookie", List.of(BrowserSessions.COOKIE + "=" + id))).build();
    }
    static final class MutableClock extends Clock {
        Instant now = Instant.parse("2026-10-01T00:00:00Z");
        @Override public @NonNull ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public @NonNull Clock withZone(@NonNull ZoneId zone) { return this; }
        @Override public @NonNull Instant instant() { return now; }
    }
}
