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

import org.jspecify.annotations.NonNull;
import com.revetsec.json.JsonObject;
import com.revetsec.scim.*;
import com.soklet.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PlaygroundScimTests {
    private static final String TOKEN = "synthetic-private-scim-token-1234567890";
    private static final ScimResourceType USER = ScimResourceType.userInstance(), GROUP = ScimResourceType.groupInstance();
    private static final URI BASE = URI.create("https://scim.example/scim/v2/");
    private static final String PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private @NonNull PlaygroundScim app() { return new PlaygroundScim(PlaygroundScim.provider(BASE, ScimLimits.fromDefaults()), TOKEN,
            Clock.fixed(Instant.parse("2026-10-13T12:00:00Z"), ZoneOffset.UTC), (operation, current, candidate, attempted, effective) -> true); }
    private static @NonNull Request body(@NonNull HttpMethod method, @NonNull String path, @NonNull String body) {
        return Request.withPath(method, path).headers(Map.of("Authorization", List.of("Bearer " + TOKEN), "Content-Type", List.of("application/scim+json")))
                .body(body.getBytes(StandardCharsets.UTF_8)).build();
    }
    private static @NonNull Request patch(@NonNull String operations) { return body(HttpMethod.PATCH, "/scim/v2/Users/u-1", "{\"schemas\":[\"" + PATCH_SCHEMA + "\"],\"Operations\":[" + operations + "]}"); }
    private static @NonNull Request user(@NonNull String name) { return body(HttpMethod.POST, "/scim/v2/Users", "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"" + name + "\",\"displayName\":\"Original\",\"active\":true}"); }
    private static @NonNull Request get(@NonNull String path) { return Request.withPath(HttpMethod.GET, path).headers(Map.of("Authorization", List.of("Bearer " + TOKEN))).build(); }

    @Test void actualRoutesAuthenticateThenParseAndProvideCrudSearchProjectionAndConditions() {
        PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            MarshaledResponse denied = simulator.performHttpRequest(user("alice").copy().headers(Map.of()).finish()).getMarshaledResponse();
            assertEquals(401, denied.getStatusCode());
            assertEquals(List.of("Bearer realm=\"scim\""), denied.getHeaders().get("WWW-Authenticate"));
            MarshaledResponse created = simulator.performHttpRequest(user("alice")).getMarshaledResponse();
            assertEquals(201, created.getStatusCode()); assertEquals(List.of(BASE + "Users/u-1"), created.getHeaders().get("Location"));
            assertEquals(200, simulator.performHttpRequest(get("/scim/v2/Users/u-1")).getMarshaledResponse().getStatusCode());
            assertEquals(404, simulator.performHttpRequest(get("/scim/v2/unknown-resource")).getMarshaledResponse().getStatusCode());
            assertEquals(501, simulator.performHttpRequest(body(HttpMethod.POST, "/scim/v2/.search", "{}")).getMarshaledResponse().getStatusCode());
            for (String discovery : List.of("ServiceProviderConfig", "ResourceTypes", "Schemas"))
                for (HttpMethod method : List.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE)) {
                    MarshaledResponse unsupported = simulator.performHttpRequest(body(method, "/scim/v2/" + discovery, "{}")).getMarshaledResponse();
                    assertEquals(405, unsupported.getStatusCode());
                    assertEquals(List.of("GET, HEAD, OPTIONS"), unsupported.getHeaders().get("Allow"));
                }
            for (String collection : List.of("Users", "Groups")) {
                MarshaledResponse unsupported = simulator.performHttpRequest(body(HttpMethod.PATCH, "/scim/v2/" + collection, "{}")).getMarshaledResponse();
                assertEquals(405, unsupported.getStatusCode());
                assertEquals(List.of("GET, HEAD, POST, OPTIONS"), unsupported.getHeaders().get("Allow"));
            }
            for (String path : List.of("ServiceProviderConfig", "ResourceTypes", "Schemas", "Users", "Groups")) {
                MarshaledResponse head = simulator.performHttpRequest(get("/scim/v2/" + path).copy().httpMethod(HttpMethod.HEAD).finish()).getMarshaledResponse();
                assertEquals(200, head.getStatusCode());
                assertTrue(head.getBody().isEmpty());
                assertEquals(204, simulator.performHttpRequest(get("/scim/v2/" + path).copy().httpMethod(HttpMethod.OPTIONS).finish()).getMarshaledResponse().getStatusCode());
            }
            for (String path : List.of("ServiceProviderConfig", "ResourceTypes", "Schemas")) assertEquals(200, simulator.performHttpRequest(get("/scim/v2/" + path)).getMarshaledResponse().getStatusCode());
            Request query = Request.withRawUrl(HttpMethod.GET, "/scim/v2/Users?filter=userName+eq+%22alice%22&attributes=userName&count=0")
                    .headers(Map.of("Authorization", List.of("Bearer " + TOKEN))).build();
            MarshaledResponse listed = simulator.performHttpRequest(query).getMarshaledResponse();
            String list = new String(((MarshaledResponseBody.Bytes) listed.getBody().orElseThrow()).getBytes(), StandardCharsets.UTF_8);
            assertTrue(list.contains("\"totalResults\":1")); assertTrue(list.contains("\"Resources\":[]"));
            Request search = body(HttpMethod.POST, "/scim/v2/Users/.search", "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"],\"filter\":\"userName eq \\\"alice\\\"\"}");
            assertEquals(200, simulator.performHttpRequest(search).getMarshaledResponse().getStatusCode());
            Request cached = get("/scim/v2/Users/u-1").copy().headers(headers -> headers.put("If-None-Match", List.of("W/\"1\""))).finish();
            assertEquals(304, app.get(USER, "u-1", cached).getStatusCode());
            MarshaledResponse notModified = simulator.performHttpRequest(cached).getMarshaledResponse();
            assertEquals(304, notModified.getStatusCode()); assertTrue(notModified.getBody().isEmpty());
            assertEquals(204, simulator.performHttpRequest(body(HttpMethod.DELETE, "/scim/v2/Users/u-1", "")).getMarshaledResponse().getStatusCode());
            assertEquals(404, simulator.performHttpRequest(get("/scim/v2/Users/u-1")).getMarshaledResponse().getStatusCode());
        });
    }
    @Test void passwordPreparationIsPrivateAtomicAndSamePasswordIsANoOp() {
        PlaygroundScim app = app(); app.create(USER, user("alice"));
        Request supplied = patch("{\"op\":\"add\",\"path\":\"password\",\"value\":\"private-password\"}");
        ScimResponse accepted = app.write(USER, "u-1", supplied, true); assertEquals(200, accepted.getStatusCode());
        assertFalse(new String(accepted.toHttpBodyWithPersonalData(), StandardCharsets.UTF_8).contains("private-password"));
        ScimResource current = Objects.requireNonNull(app.snapshot(USER, "u-1"));
        assertTrue(current.getDocument().find("password").isEmpty()); assertEquals(Optional.of("W/\"2\""), current.getVersion());
        assertEquals(200, app.write(USER, "u-1", supplied, true).getStatusCode()); assertSame(current, app.snapshot(USER, "u-1"));
        app.failNext(PlaygroundScim.Fault.BEFORE_COMMIT_UNAVAILABLE);
        assertEquals(503, app.write(USER, "u-1", patch("{\"op\":\"replace\",\"path\":\"password\",\"value\":\"different\"}"), true).getStatusCode());
        assertEquals(200, app.write(USER, "u-1", supplied, true).getStatusCode()); assertSame(current, app.snapshot(USER, "u-1"));
        assertEquals(200, app.write(USER, "u-1", patch("{\"op\":\"remove\",\"path\":\"password\"}"), true).getStatusCode());
        assertEquals(Optional.of("W/\"3\""), app.snapshot(USER, "u-1").getVersion());
    }
    @Test void privateCredentialRemovalAppearsInEffectiveAuthorization() {
        AtomicBoolean denyCredentialChange = new AtomicBoolean();
        PlaygroundScim app = new PlaygroundScim(PlaygroundScim.provider(BASE, ScimLimits.fromDefaults()), TOKEN, Clock.systemUTC(),
                (operation, current, candidate, attempted, effective) -> !denyCredentialChange.get()
                        || effective.stream().noneMatch(path -> path.toScimString().equals("password")));
        app.create(USER, user("alice"));
        Request password = patch("{\"op\":\"add\",\"path\":\"password\",\"value\":\"private-password\"}");
        assertEquals(200, app.write(USER, "u-1", password, true).getStatusCode());
        ScimResource current = Objects.requireNonNull(app.snapshot(USER, "u-1")); denyCredentialChange.set(true);
        assertEquals(403, app.write(USER, "u-1", patch("{\"op\":\"remove\",\"path\":\"password\"}"), true).getStatusCode());
        assertEquals(403, app.delete(USER, "u-1", get("/scim/v2/Users/u-1")).getStatusCode());
        assertSame(current, app.snapshot(USER, "u-1"));
        assertEquals(200, app.write(USER, "u-1", password, true).getStatusCode()); assertSame(current, app.snapshot(USER, "u-1"));
    }
    @Test void lateFailureDenialIntegrityAndStalePreconditionPreserveSnapshot() {
        PlaygroundScim app = app(); assertEquals(201, app.create(USER, user("alice")).getStatusCode());
        ScimResource original = Objects.requireNonNull(app.snapshot(USER, "u-1"));
        assertEquals(400, app.write(USER, "u-1", patch("{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Changed\"},{\"op\":\"remove\",\"path\":\"userName\"}"), true).getStatusCode());
        assertSame(original, app.snapshot(USER, "u-1"));
        assertEquals(412, app.write(USER, "u-1", patch("{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Changed\"}").copy()
                .headers(headers -> headers.put("If-Match", List.of("W/\"0\""))).finish(), true).getStatusCode());
        assertSame(original, app.snapshot(USER, "u-1"));
        assertEquals(409, app.create(USER, user("ALICE")).getStatusCode());
        assertEquals(400, app.create(USER, user("álîce")).getStatusCode());
        assertEquals(200, app.write(USER, "u-1", patch("{\"op\":\"add\",\"path\":\"password\",\"value\":\"secret\"}"), true).getStatusCode());
        assertTrue(app.snapshot(USER, "u-1").getDocument().find("password").isEmpty());
    }
    @Test void noOpAttemptsStillRequireAuthorizationAndKeepMetadata() {
        AtomicBoolean denied = new AtomicBoolean(); AtomicInteger calls = new AtomicInteger();
        PlaygroundScim app = new PlaygroundScim(PlaygroundScim.provider(BASE, ScimLimits.fromDefaults()), TOKEN, Clock.systemUTC(),
                (operation, current, candidate, attempted, effective) -> { calls.incrementAndGet(); assertFalse(attempted.isEmpty()); return !denied.get(); });
        app.create(USER, user("alice")); ScimResource original = Objects.requireNonNull(app.snapshot(USER, "u-1"));
        Request noOp = patch("{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Original\"}");
        denied.set(true); assertEquals(403, app.write(USER, "u-1", noOp, true).getStatusCode()); assertSame(original, app.snapshot(USER, "u-1"));
        denied.set(false); assertEquals(200, app.write(USER, "u-1", noOp, true).getStatusCode());
        assertEquals(original.getVersion(), app.snapshot(USER, "u-1").getVersion()); assertEquals(original.getLastModified(), app.snapshot(USER, "u-1").getLastModified());
        assertEquals(3, calls.get());
    }
    @Test void putOmissionIncludesCanonicalChildrenInAuthorization() {
        AtomicBoolean denied = new AtomicBoolean();
        PlaygroundScim app = new PlaygroundScim(PlaygroundScim.provider(BASE, ScimLimits.fromDefaults()), TOKEN, Clock.systemUTC(),
                (operation, current, candidate, attempted, effective) -> !denied.get() || attempted.stream().noneMatch(path -> path.toScimString().equals("name.familyName")));
        Request created = body(HttpMethod.POST, "/scim/v2/Users", "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"alice\",\"name\":{\"givenName\":\"Alice\",\"familyName\":\"Private\"}}");
        assertEquals(201, app.create(USER, created).getStatusCode()); ScimResource current = Objects.requireNonNull(app.snapshot(USER, "u-1"));
        denied.set(true);
        Request replacement = body(HttpMethod.PUT, "/scim/v2/Users/u-1", "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"alice\",\"name\":{\"givenName\":\"Alice\"}}");
        assertEquals(403, app.write(USER, "u-1", replacement, false).getStatusCode()); assertSame(current, app.snapshot(USER, "u-1"));
    }
    @Test void groupMembershipAndFinalOperationUseOneAtomicSnapshot() {
        PlaygroundScim app = app(); app.create(USER, user("alice")); app.create(USER, user("bob"));
        assertEquals(201, app.create(GROUP, body(HttpMethod.POST, "/scim/v2/Groups", "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"team\",\"members\":[{\"value\":\"u-1\"}]}")).getStatusCode());
        ScimResource original = Objects.requireNonNull(app.snapshot(GROUP, "g-3"));
        assertEquals(400, app.write(GROUP, "g-3", patch("{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"u-2\"}]},{\"op\":\"remove\",\"path\":\"displayName\"}"), true).getStatusCode());
        assertSame(original, app.snapshot(GROUP, "g-3"));
        Request add = patch("{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"u-2\"}]}");
        assertEquals(204, app.write(GROUP, "g-3", add, true).getStatusCode());
        ScimResource changed = Objects.requireNonNull(app.snapshot(GROUP, "g-3"));
        assertEquals(List.of("u-1", "u-2"), ((com.revetsec.json.JsonArray) changed.getDocument().find("members").orElseThrow()).getElements().stream().map(value -> ((JsonObject) value).findString("value").orElseThrow()).toList());
        assertEquals(400, app.write(GROUP, "g-3", patch("{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"missing-user\"}]}"), true).getStatusCode());
        assertSame(changed, app.snapshot(GROUP, "g-3"));
    }
    @Test void existingGroupReferencesAndProperExtensionRootObjectsWorkWithoutRelaxingIntegrity() {
        PlaygroundScim app = app(); app.create(USER, user("alice"));
        String enterprise = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
        assertEquals(200, app.write(USER, "u-1", patch("{\"op\":\"add\",\"path\":\"" + enterprise + "\",\"value\":{\"department\":\"Engineering\"}}"), true).getStatusCode());
        assertEquals("Engineering", app.snapshot(USER, "u-1").getExtension(enterprise).orElseThrow().findString("department").orElseThrow());
        String group = "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"nested\"}";
        assertEquals(201, app.create(GROUP, body(HttpMethod.POST, "/scim/v2/Groups", group)).getStatusCode());
        Request outer = body(HttpMethod.POST, "/scim/v2/Groups", "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"outer\",\"members\":[{\"value\":\"g-2\",\"type\":\"Group\",\"$ref\":\"Groups/g-2\"}]}");
        assertEquals(201, app.create(GROUP, outer).getStatusCode());
        assertEquals(400, app.delete(GROUP, "g-2", get("/scim/v2/Groups/g-2")).getStatusCode());
        Request mismatch = body(HttpMethod.POST, "/scim/v2/Groups", "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:Group\"],\"displayName\":\"bad\",\"members\":[{\"value\":\"g-2\",\"type\":\"User\"}]}");
        assertEquals(400, app.create(GROUP, mismatch).getStatusCode());
    }
    @Test void enterpriseManagerReferencesUseTheSameAuthoritativeUserScope() {
        PlaygroundScim app = app(); app.create(USER, user("alice")); app.create(USER, user("manager"));
        String manager = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager";
        assertEquals(400, app.write(USER, "u-1", patch("{\"op\":\"add\",\"path\":\"" + manager + "\",\"value\":{\"value\":\"missing\"}}"), true).getStatusCode());
        assertEquals(200, app.write(USER, "u-1", patch("{\"op\":\"add\",\"path\":\"" + manager + "\",\"value\":{\"value\":\"u-2\",\"$ref\":\"Users/u-2\"}}"), true).getStatusCode());
        assertEquals(400, app.delete(USER, "u-2", get("/scim/v2/Users/u-2")).getStatusCode());
    }
    @Test void failedPreparationAndCommitOutcomesNeverEmitSuccess() {
        PlaygroundScim app = new PlaygroundScim(PlaygroundScim.provider(BASE, ScimLimits.builder().maximumResponseBytes(2048).build()), TOKEN, Clock.systemUTC(), (a,b,c,d,e) -> true);
        app.create(USER, user("alice")); ScimResource original = Objects.requireNonNull(app.snapshot(USER, "u-1"));
        assertEquals(500, app.write(USER, "u-1", patch("{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"" + "x".repeat(3000) + "\"}"), true).getStatusCode());
        assertSame(original, app.snapshot(USER, "u-1"));
        Request change = patch("{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Changed\"}");
        app.failNext(PlaygroundScim.Fault.BEFORE_COMMIT_UNAVAILABLE); assertEquals(503, app.write(USER, "u-1", change, true).getStatusCode()); assertSame(original, app.snapshot(USER, "u-1"));
        assertEquals(PlaygroundScim.CommitOutcome.UNAVAILABLE, app.lastOutcome());
        app.failNext(PlaygroundScim.Fault.BEFORE_COMMIT_CONFLICT); assertEquals(412, app.write(USER, "u-1", change, true).getStatusCode()); assertSame(original, app.snapshot(USER, "u-1"));
        assertEquals(PlaygroundScim.CommitOutcome.CONFLICT, app.lastOutcome());
        app.failNext(PlaygroundScim.Fault.ACKNOWLEDGEMENT_LOST); assertEquals(503, app.write(USER, "u-1", change, true).getStatusCode());
        assertEquals(PlaygroundScim.CommitOutcome.UNKNOWN, app.lastOutcome()); assertEquals("Changed", app.snapshot(USER, "u-1").getDocument().findString("displayName").orElseThrow());
    }
    @Test void raceRechecksIfMatchOnTheCommittedRowAndUniqueNamesUnderLock() throws Exception {
        PlaygroundScim app = app(); app.create(USER, user("alice"));
        CountDownLatch start = new CountDownLatch(1); ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            List<Future<Integer>> results = new ArrayList<>();
            for (String name : List.of("one", "two")) results.add(pool.submit(() -> { assertTrue(start.await(3, TimeUnit.SECONDS));
                return app.write(USER, "u-1", patch("{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"" + name + "\"}").copy()
                        .headers(headers -> headers.put("If-Match", List.of("W/\"1\""))).finish(), true).getStatusCode(); }));
            start.countDown(); Set<Integer> outcomes = Set.of(results.get(0).get(5, TimeUnit.SECONDS), results.get(1).get(5, TimeUnit.SECONDS));
            assertEquals(Set.of(200, 412), outcomes); assertEquals(Optional.of("W/\"2\""), app.snapshot(USER, "u-1").getVersion());
            CountDownLatch creates = new CountDownLatch(1);
            Future<Integer> first = pool.submit(() -> { assertTrue(creates.await(3, TimeUnit.SECONDS)); return app.create(USER, user("unique")).getStatusCode(); });
            Future<Integer> second = pool.submit(() -> { assertTrue(creates.await(3, TimeUnit.SECONDS)); return app.create(USER, user("UNIQUE")).getStatusCode(); });
            creates.countDown(); assertEquals(Set.of(201, 409), Set.of(first.get(5, TimeUnit.SECONDS), second.get(5, TimeUnit.SECONDS)));
        } finally { pool.shutdownNow(); assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS)); }
    }
}
