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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class SessionAdmissionTests {
    @Test void anonymousHomeFloodDoesNotAllocateAndExplicitAdmissionReusesOneSlot() throws Exception {
        var clock = new OidcApplicationTests.MutableClock();
        try (var provider = new SyntheticOidcProvider(clock)) {
            var app = provider.application(1, 1, AuthorizationRequestOptions.ResponseMode.QUERY);
            SokletSimulator.run(app.configuration(18080), sim -> {
                for (int i = 0; i < 40; i++) {
                    var response = sim.performHttpRequest(request(HttpMethod.GET, "/", null, null)).getMarshaledResponse();
                    assertEquals(200, response.getStatusCode());
                    assertTrue(response.getCookies().isEmpty(), "Anonymous GET allocated a session");
                }
                var admitted = sim.performHttpRequest(request(HttpMethod.POST, "/session", "begin=1", null)).getMarshaledResponse();
                assertEquals(303, admitted.getStatusCode());
                var c = admitted.getCookies().iterator().next(); String cookie = c.getName() + "=" + c.getValue().orElseThrow();
                assertEquals(303, sim.performHttpRequest(request(HttpMethod.POST, "/session", "begin=1", cookie)).getMarshaledResponse().getStatusCode());
                assertEquals(503, sim.performHttpRequest(request(HttpMethod.POST, "/session", "begin=1", null)).getMarshaledResponse().getStatusCode());
                assertEquals(200, sim.performHttpRequest(request(HttpMethod.GET, "/", null, null)).getMarshaledResponse().getStatusCode());
                clock.advance(Duration.ofMinutes(30).minusNanos(1));
                assertTrue(sim.performHttpRequest(request(HttpMethod.GET, "/", null, cookie)).getMarshaledResponse().getCookies().isEmpty());
                clock.advance(Duration.ofNanos(1));
                var expired = sim.performHttpRequest(request(HttpMethod.GET, "/", null, cookie)).getMarshaledResponse();
                assertTrue(expired.getCookies().isEmpty());
                assertEquals(303, sim.performHttpRequest(request(HttpMethod.POST, "/session", "begin=1", null)).getMarshaledResponse().getStatusCode());
                assertEquals(0, provider.tokenPosts.get());
            });
        }
    }

    @Test void bootstrapRejectsMissingForeignDuplicateOriginsAndMalformedBodies() throws Exception {
        var clock = new OidcApplicationTests.MutableClock();
        try (var provider = new SyntheticOidcProvider(clock)) {
            var app = provider.application(1, 1, AuthorizationRequestOptions.ResponseMode.QUERY);
            SokletSimulator.run(app.configuration(18080), sim -> {
                var valid = request(HttpMethod.POST, "/session", "begin=1", null);
                for (List<String> origins : List.of(List.of("null"), List.of("https://foreign.example"), List.of("https://localhost:8443", "https://localhost:8443")))
                    assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.put("Origin", origins)).finish()).getMarshaledResponse().getStatusCode());
                assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.remove("Origin")).finish()).getMarshaledResponse().getStatusCode());
                assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.put("Content-Type", List.of("text/plain"))).finish()).getMarshaledResponse().getStatusCode());
                assertEquals(403, sim.performHttpRequest(valid.copy().headers(h -> h.put("Content-Type", List.of("application/x-www-form-urlencoded", "application/x-www-form-urlencoded"))).finish()).getMarshaledResponse().getStatusCode());
                for (String body : List.of("", "begin=0", "begin=1&begin=1"))
                    assertEquals(403, sim.performHttpRequest(request(HttpMethod.POST, "/session", body, null)).getMarshaledResponse().getStatusCode());
                assertEquals(403, sim.performHttpRequest(request(HttpMethod.POST, "/session?x=1", "begin=1", null)).getMarshaledResponse().getStatusCode());
                assertEquals(413, sim.performHttpRequest(valid.copy().contentTooLarge(true).finish()).getMarshaledResponse().getStatusCode());
                assertEquals(303, sim.performHttpRequest(valid).getMarshaledResponse().getStatusCode());
            });
        }
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
