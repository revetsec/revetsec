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
import com.revetsec.json.JsonString;

import com.revetsec.json.JsonArray;
import com.revetsec.json.JsonObject;
import com.revetsec.scim.*;
import com.soklet.*;
import org.junit.jupiter.api.Test;
import org.jspecify.annotations.NonNull;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

/** Adversarial checks against the real application route dispatcher and local HTTP server. */
class ScimRc3SecurityTests {
    private static final String TOKEN = "rc3-synthetic-private-bearer-1234567890";
    private static final String OTHER_TOKEN = "rc3-other-private-bearer-12345678901234";
    private static final String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";
    private static final String GROUP_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Group";
    private static final String ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    private static final String PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
    private static final ScimResourceType USER = ScimResourceType.userInstance(), GROUP = ScimResourceType.groupInstance();
    private static final URI BASE = URI.create("https://scim.example/scim/v2/");
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-14T12:00:00Z"), ZoneOffset.UTC);

    private static @NonNull PlaygroundScim app() { return app((operation, current, candidate, attempted, effective) -> true); }
    private static @NonNull PlaygroundScim app(PlaygroundScim.@NonNull Authorizer authorizer) {
        return new PlaygroundScim(PlaygroundScim.provider(BASE, ScimLimits.builder().maximumBodyBytes(16_384).build()), TOKEN, CLOCK, authorizer);
    }
    private static @NonNull Request request(@NonNull HttpMethod method, @NonNull String path, @NonNull String body) {
        return Request.withRawUrl(method, path).headers(Map.of("Authorization", List.of("Bearer " + TOKEN),
                "Content-Type", List.of("application/scim+json"))).body(body.getBytes(StandardCharsets.UTF_8)).build();
    }
    private static @NonNull Request user(@NonNull String name) { return request(HttpMethod.POST, "/scim/v2/Users", userDocument(name)); }
    private static @NonNull String userDocument(@NonNull String name) { return "{\"schemas\":[\"" + USER_SCHEMA + "\"],\"userName\":\"" + name + "\",\"displayName\":\"Original\",\"active\":true}"; }
    private static @NonNull Request patch(@NonNull String id, @NonNull String operations) {
        return request(HttpMethod.PATCH, "/scim/v2/Users/" + id, "{\"schemas\":[\"" + PATCH_SCHEMA + "\"],\"Operations\":[" + operations + "]}");
    }
    private static @NonNull Request get(@NonNull String path) { return request(HttpMethod.GET, path, ""); }
    private static @NonNull MarshaledResponse invoke(@NonNull Simulator simulator, @NonNull Request request) { return simulator.performHttpRequest(request).getMarshaledResponse(); }
    private static @NonNull String text(@NonNull MarshaledResponse response) {
        return response.getBody().map(body -> new String(((MarshaledResponseBody.Bytes) body).getBytes(), StandardCharsets.UTF_8)).orElse("");
    }
    private static void unchanged(@NonNull PlaygroundScim app, @NonNull ScimResource original) { assertSame(original, app.snapshot(original.getResourceType(), original.getId().orElseThrow())); }
    private static @NonNull Request condition(@NonNull Request request, @NonNull String value) { return request.copy().headers(headers -> headers.put("If-Match", List.of(value))).finish(); }
    private static @NonNull Set<@NonNull String> paths(@NonNull Set<@NonNull ScimAttributePath> paths) { Set<@NonNull String> result = new HashSet<>(); paths.forEach(path -> result.add(path.toScimString())); return result; }

    @Test void everyRegisteredOperationAuthenticatesBeforeMalformedInputAndTenantHints() {
        AtomicInteger authorization = new AtomicInteger();
        PlaygroundScim app = app((operation, current, candidate, attempted, effective) -> { authorization.incrementAndGet(); return true; });
        List<Request> routes = new ArrayList<>();
        for (String collection : List.of("Users", "Groups")) {
            routes.add(get("/scim/v2/" + collection)); routes.add(request(HttpMethod.POST, "/scim/v2/" + collection, "{"));
            routes.add(request(HttpMethod.POST, "/scim/v2/" + collection + "/.search", "{"));
            for (HttpMethod method : List.of(HttpMethod.GET, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE))
                routes.add(request(method, "/scim/v2/" + collection + "/other-tenant-id", "{"));
        }
        for (String discovery : List.of("ServiceProviderConfig", "ResourceTypes", "Schemas", "ResourceTypes/User", "Schemas/unknown")) routes.add(get("/scim/v2/" + discovery));
        routes.add(request(HttpMethod.POST, "/scim/v2/.search", "{")); routes.add(get("/scim/v2/not-a-resource"));
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            for (Request route : routes) for (List<String> credentials : List.of(List.<String>of(), List.of("Bearer " + OTHER_TOKEN),
                    List.of("Bearer " + TOKEN, "Bearer " + TOKEN), List.of("bearer " + TOKEN), List.of("Bearer " + TOKEN + " extra"))) {
                Request denied = route.copy().headers(Map.of("Authorization", credentials, "X-Tenant-ID", List.of("other"), "Content-Type", List.of("text/plain")))
                        .finish();
                MarshaledResponse response = invoke(simulator, denied); assertEquals(401, response.getStatusCode(), route.getPath());
                assertFalse(text(response).contains(TOKEN)); assertFalse(text(response).contains("other-tenant-id"));
            }
        });
        assertEquals(0, authorization.get()); assertNull(app.snapshot(USER, "u-1"));
    }

    @Test void sokletNormalizesOuterHeaderWhitespaceBeforeApplicationAuthentication() {
        PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            for (String credential : List.of("Bearer " + TOKEN + " ", "\tBearer " + TOKEN + "\t")) {
                Request normalized = get("/scim/v2/Users").copy().headers(headers ->
                        headers.put("Authorization", List.of(credential))).finish();
                assertEquals(List.of("Bearer " + TOKEN), normalized.getHeaders().get("Authorization"));
                assertEquals(200, invoke(simulator, normalized).getStatusCode());
            }
            Request invalid = get("/scim/v2/Users").copy().headers(headers ->
                    headers.put("Authorization", List.of(" Bearer " + OTHER_TOKEN + " "))).finish();
            assertEquals(401, invoke(simulator, invalid).getStatusCode());
        });
    }

    @Test void independentConfiguredTenantsDoNotAcceptEachOthersCredentialsOrRequestHints() {
        PlaygroundScim first = app();
        PlaygroundScim other = new PlaygroundScim(PlaygroundScim.provider(BASE, ScimLimits.fromDefaults()), OTHER_TOKEN, CLOCK, (a,b,c,d,e) -> true);
        SokletSimulator.run(ScimPlayground.config(first, "127.0.0.1", 0), simulator -> {
            assertEquals(201, invoke(simulator, user("alice")).getStatusCode());
            Request hinted = get("/scim/v2/Users/u-1?tenant=other").copy().headers(headers -> headers.put("X-Tenant-ID", List.of("other"))).finish();
            assertEquals(200, invoke(simulator, hinted).getStatusCode());
            assertEquals(401, invoke(simulator, hinted.copy().headers(headers -> headers.put("Authorization", List.of("Bearer " + OTHER_TOKEN))).finish()).getStatusCode());
            assertEquals(404, invoke(simulator, get("/scim/v2/Users/other-tenant-id")).getStatusCode());
        });
        assertNull(other.snapshot(USER, "u-1"));
        assertEquals("alice", first.snapshot(USER, "u-1").getDocument().find("userName").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
    }

    @Test void malformedMediaJsonUtf8DuplicatesAndUnknownFieldsNeverReachCommit() {
        PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            for (List<String> media : List.of(List.of("text/plain"), List.of("application/scim+json", "application/scim+json"),
                    List.of("application/scim+json; bogus=parameter")))
                assertEquals(415, invoke(simulator, user("alice").copy().headers(headers -> headers.put("Content-Type", media)).finish()).getStatusCode());
            for (String invalid : List.of("{", "[]", "{\"schemas\":[\"" + USER_SCHEMA + "\"],\"userName\":\"alice\",\"USERNAME\":\"other\"}",
                    "{\"schemas\":[\"" + USER_SCHEMA + "\"],\"userName\":\"alice\",\"admin\":true}",
                    "{\"schemas\":[\"urn:attacker:User\"],\"userName\":\"alice\"}"))
                assertEquals(400, invoke(simulator, request(HttpMethod.POST, "/scim/v2/Users", invalid)).getStatusCode());
            assertEquals(400, invoke(simulator, user("alice").copy().body(new byte[] {(byte) 0xc3, 0x28}).finish()).getStatusCode());
            assertEquals(413, invoke(simulator, user("alice").copy().body(new byte[16_385]).finish()).getStatusCode());
            assertNull(app.snapshot(USER, "u-1")); assertEquals(201, invoke(simulator, user("control")).getStatusCode());
        });
    }

    @Test void defaultDenyFiltersAndBoundedQueriesRejectWholeUnsupportedClauses() {
        PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            assertEquals(201, invoke(simulator, user("alice")).getStatusCode());
            for (String query : List.of("filter=password+pr", "filter=userName+eq+%22alice%22+or+password+pr", "filter=active+co+true",
                    "count=1&COUNT=2", "startIndex=1e2", "count=1e2", "attributes=password&excludedAttributes=userName"))
                assertEquals(400, invoke(simulator, get("/scim/v2/Users?" + query)).getStatusCode(), query);
            Request search = request(HttpMethod.POST, "/scim/v2/Users/.search", "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"],\"filter\":\"userName eq \\\"alice\\\" or password pr\"}");
            assertEquals(400, invoke(simulator, search).getStatusCode());
            assertEquals(200, invoke(simulator, get("/scim/v2/Users?filter=userName+eq+%22alice%22&count=0")).getStatusCode());
        });
    }

    @Test void deniedNoOpAndExtensionChildWritesStillRequireAttemptAuthorization() {
        AtomicBoolean deny = new AtomicBoolean(); AtomicInteger calls = new AtomicInteger();
        PlaygroundScim app = app((operation, current, candidate, attempted, effective) -> {
            calls.incrementAndGet(); return !deny.get() || paths(attempted).stream().noneMatch(path -> path.equals("displayName") || path.equals(ENTERPRISE + ":department"));
        });
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            assertEquals(201, invoke(simulator, user("alice")).getStatusCode()); ScimResource original = app.snapshot(USER, "u-1"); deny.set(true);
            assertEquals(403, invoke(simulator, patch("u-1", "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Original\"}")).getStatusCode()); unchanged(app, original);
            assertEquals(403, invoke(simulator, patch("u-1", "{\"op\":\"add\",\"path\":\"" + ENTERPRISE + "\",\"value\":{\"department\":\"Privileged\"}}" )).getStatusCode()); unchanged(app, original);
        }); assertEquals(3, calls.get());
    }

    @Test void omittedPutChildrenAndImplicitPrimaryDisplacementAppearInPrivilegePaths() {
        AtomicBoolean deny = new AtomicBoolean(); AtomicReference<Set<String>> observed = new AtomicReference<>(Set.of());
        PlaygroundScim app = app((operation, current, candidate, attempted, effective) -> {
            Set<String> combined = new HashSet<>(paths(attempted)); combined.addAll(paths(effective)); observed.set(combined);
            return !deny.get() || !(combined.contains("name.familyName") || combined.contains("emails.primary"));
        });
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            String document = "{\"schemas\":[\"" + USER_SCHEMA + "\"],\"userName\":\"alice\",\"name\":{\"familyName\":\"Private\"},\"emails\":[{\"value\":\"first@example.test\",\"primary\":true}]}";
            assertEquals(201, invoke(simulator, request(HttpMethod.POST, "/scim/v2/Users", document)).getStatusCode());
            ScimResource original = app.snapshot(USER, "u-1"); deny.set(true);
            assertEquals(403, invoke(simulator, request(HttpMethod.PUT, "/scim/v2/Users/u-1", userDocument("alice"))).getStatusCode());
            assertTrue(observed.get().contains("name.familyName")); unchanged(app, original);
            assertEquals(403, invoke(simulator, patch("u-1", "{\"op\":\"add\",\"path\":\"emails\",\"value\":[{\"value\":\"second@example.test\",\"primary\":true}]}")).getStatusCode());
            assertTrue(observed.get().contains("emails.primary")); unchanged(app, original);
        });
    }

    @Test void protectedIdentityMetadataAndRequiredNamesCannotBeChangedByPatch() {
        PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            assertEquals(201, invoke(simulator, user("alice")).getStatusCode()); ScimResource original = app.snapshot(USER, "u-1");
            for (String operation : List.of("{\"op\":\"replace\",\"path\":\"id\",\"value\":\"foreign-id\"}",
                    "{\"op\":\"replace\",\"path\":\"meta.version\",\"value\":\"attacker\"}",
                    "{\"op\":\"remove\",\"path\":\"userName\"}", "{\"op\":\"remove\",\"path\":\"displayName\",\"value\":\"Original\"}")) {
                assertEquals(400, invoke(simulator, patch("u-1", operation)).getStatusCode()); unchanged(app, original);
            }
        });
    }

    @Test void neverReturnedPasswordStaysPrivateAcrossProjectionAndAllResponseForms() {
        String secret = "rc3-synthetic-never-return-this-password"; PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            Request created = request(HttpMethod.POST, "/scim/v2/Users?attributes=password,userName", "{\"schemas\":[\"" + USER_SCHEMA + "\"],\"userName\":\"alice\",\"password\":\"" + secret + "\"}");
            MarshaledResponse accepted = invoke(simulator, created); assertEquals(201, accepted.getStatusCode()); assertFalse(text(accepted).contains(secret)); assertFalse(text(accepted).contains("\"password\""));
            List<Request> reads = List.of(get("/scim/v2/Users/u-1?attributes=password,userName"), get("/scim/v2/Users?attributes=password,userName"),
                    request(HttpMethod.POST, "/scim/v2/Users/.search", "{\"schemas\":[\"urn:ietf:params:scim:api:messages:2.0:SearchRequest\"],\"attributes\":[\"password\",\"userName\"]}"));
            for (Request read : reads) { MarshaledResponse response = invoke(simulator, read); assertEquals(200, response.getStatusCode()); assertFalse(text(response).contains(secret)); assertFalse(text(response).contains("\"password\"")); }
            Request change = patch("u-1", "{\"op\":\"replace\",\"path\":\"password\",\"value\":\"" + secret + "\"}").copy().path("/scim/v2/Users/u-1").finish();
            MarshaledResponse changed = invoke(simulator, change); assertEquals(200, changed.getStatusCode()); assertFalse(text(changed).contains(secret));
            assertTrue(app.snapshot(USER, "u-1").getDocument().find("password").isEmpty());
        });
    }

    @Test void staleAndMalformedIfMatchCannotMutatePatchPutOrDelete() {
        PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            assertEquals(201, invoke(simulator, user("alice")).getStatusCode()); ScimResource original = app.snapshot(USER, "u-1");
            List<Request> writes = List.of(patch("u-1", "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Changed\"}"),
                    request(HttpMethod.PUT, "/scim/v2/Users/u-1", userDocument("changed")), request(HttpMethod.DELETE, "/scim/v2/Users/u-1", ""));
            for (Request write : writes) {
                assertEquals(412, invoke(simulator, condition(write, "W/\"stale\"")).getStatusCode()); unchanged(app, original);
                assertEquals(400, invoke(simulator, condition(write, "*, W/\"1\"")).getStatusCode()); unchanged(app, original);
            }
            assertEquals(200, invoke(simulator, condition(writes.get(0), "\"1\"")).getStatusCode());
            assertEquals(Optional.of("W/\"2\""), app.snapshot(USER, "u-1").getVersion());
        });
    }

    @Test void finalOperationFailureAndResponseOverflowLeaveWholeSnapshotUntouched() {
        PlaygroundScim app = new PlaygroundScim(PlaygroundScim.provider(BASE, ScimLimits.builder().maximumResponseBytes(2048).build()), TOKEN, CLOCK, (a,b,c,d,e) -> true);
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            assertEquals(201, invoke(simulator, user("alice")).getStatusCode()); ScimResource original = app.snapshot(USER, "u-1");
            assertEquals(400, invoke(simulator, patch("u-1", "{\"op\":\"replace\",\"path\":\"active\",\"value\":false},{\"op\":\"remove\",\"path\":\"userName\"}")).getStatusCode()); unchanged(app, original);
            assertEquals(500, invoke(simulator, patch("u-1", "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"" + "x".repeat(3000) + "\"}")).getStatusCode()); unchanged(app, original);
        });
    }

    @Test void unconfirmedCommitNeverReturnsSuccessHeadersOrAutomaticallyRetries() {
        PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            assertEquals(201, invoke(simulator, user("alice")).getStatusCode()); ScimResource original = app.snapshot(USER, "u-1");
            Request change = patch("u-1", "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"Changed\"}");
            for (PlaygroundScim.Fault fault : List.of(PlaygroundScim.Fault.BEFORE_COMMIT_UNAVAILABLE, PlaygroundScim.Fault.BEFORE_COMMIT_CONFLICT, PlaygroundScim.Fault.ACKNOWLEDGEMENT_LOST)) {
                app.failNext(fault); MarshaledResponse response = invoke(simulator, condition(change, "W/\"1\""));
                assertEquals(fault == PlaygroundScim.Fault.BEFORE_COMMIT_CONFLICT ? 412 : 503, response.getStatusCode());
                assertFalse(response.getHeaders().containsKey("ETag")); assertFalse(response.getHeaders().containsKey("Location")); assertFalse(text(response).contains("Changed"));
                if (fault != PlaygroundScim.Fault.ACKNOWLEDGEMENT_LOST) unchanged(app, original);
            }
            assertEquals(PlaygroundScim.CommitOutcome.UNKNOWN, app.lastOutcome());
            assertEquals(Optional.of("W/\"2\""), app.snapshot(USER, "u-1").getVersion());
            assertEquals(412, invoke(simulator, condition(change, "W/\"1\"")).getStatusCode());
            assertEquals("Changed", app.snapshot(USER, "u-1").getDocument().find("displayName").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow());
        });
    }

    @Test void memberOrderAndMetadataSurviveFilteredRemovalThenAppend() {
        PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            for (String name : List.of("alice", "bob", "charlie", "dana")) assertEquals(201, invoke(simulator, user(name)).getStatusCode());
            String members = "[{\"value\":\"u-1\",\"$ref\":\"Users/u-1\"},{\"value\":\"u-2\",\"$ref\":\"Users/u-2\"},{\"value\":\"u-3\",\"$ref\":\"Users/u-3\"}]";
            assertEquals(201, invoke(simulator, request(HttpMethod.POST, "/scim/v2/Groups", "{\"schemas\":[\"" + GROUP_SCHEMA + "\"],\"displayName\":\"team\",\"members\":" + members + "}")).getStatusCode());
            Request edit = patch("g-5", "{\"op\":\"remove\",\"path\":\"members[value eq \\\"u-2\\\"]\"},{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"u-4\",\"$ref\":\"Users/u-4\"}]}")
                    .copy().path("/scim/v2/Groups/g-5").finish();
            assertEquals(204, invoke(simulator, edit).getStatusCode());
            JsonArray result = (JsonArray) app.snapshot(GROUP, "g-5").getDocument().find("members").orElseThrow();
            assertEquals(List.of("u-1", "u-3", "u-4"), result.getElements().stream().map(value -> ((JsonObject) value).find("value").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow()).toList());
            assertEquals(List.of("Users/u-1", "Users/u-3", "Users/u-4"), result.getElements().stream().map(value -> ((JsonObject) value).find("$ref").filter(JsonString.class::isInstance).map(JsonString.class::cast).map(JsonString::getValue).orElseThrow()).toList());
        });
    }

    @Test void memberAndManagerReferencesRejectForeignScopeAndPreserveResource() {
        PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            assertEquals(201, invoke(simulator, user("alice")).getStatusCode()); ScimResource original = app.snapshot(USER, "u-1");
            for (String reference : List.of("https://other.example/scim/v2/Users/u-1", "Groups/u-1", "Users/missing")) {
                assertEquals(400, invoke(simulator, patch("u-1", "{\"op\":\"add\",\"path\":\"" + ENTERPRISE + ":manager\",\"value\":{\"value\":\"u-1\",\"$ref\":\"" + reference + "\"}}")).getStatusCode()); unchanged(app, original);
            }
            for (String member : List.of("{\"value\":\"missing\"}", "{\"value\":\"u-1\",\"type\":\"Group\"}", "{\"value\":\"u-1\",\"$ref\":\"https://other.example/scim/v2/Users/u-1\"}"))
                assertEquals(400, invoke(simulator, request(HttpMethod.POST, "/scim/v2/Groups", "{\"schemas\":[\"" + GROUP_SCHEMA + "\"],\"displayName\":\"foreign\",\"members\":[" + member + "]}")).getStatusCode());
            assertNull(app.snapshot(GROUP, "g-2"));
        });
    }

    @Test void resourceCountBoundRejectsNextCreateWithoutConsumingIdentity() {
        PlaygroundScim app = app();
        SokletSimulator.run(ScimPlayground.config(app, "127.0.0.1", 0), simulator -> {
            for (int index = 0; index < 128; ++index) assertEquals(201, invoke(simulator, user("user" + index)).getStatusCode());
            assertEquals(503, invoke(simulator, user("overflow")).getStatusCode()); assertNull(app.snapshot(USER, "u-129"));
            assertEquals(204, invoke(simulator, request(HttpMethod.DELETE, "/scim/v2/Users/u-1", "")).getStatusCode());
            assertEquals(201, invoke(simulator, user("control")).getStatusCode()); assertNotNull(app.snapshot(USER, "u-129"));
        });
    }

    @Test void actualLoopbackHttpPreservesPhysicalAmbiguitiesAndChecksVersionUnderRace() throws Exception {
        PlaygroundScim app = app(); int port;
        try (ServerSocket reservation = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) { port = reservation.getLocalPort(); }
        try (Soklet server = Soklet.fromConfig(ScimPlayground.config(app, "127.0.0.1", port))) {
            server.start();
            assertEquals(401, wire(port, "POST", "/scim/v2/Users", List.of("Content-Type: text/plain"), "{").status);
            assertEquals(401, wire(port, "GET", "/scim/v2/Users", List.of("Authorization: Bearer " + TOKEN, "Authorization: Bearer " + TOKEN), "").status);
            assertEquals(415, wire(port, "POST", "/scim/v2/Users", List.of("Authorization: Bearer " + TOKEN, "Content-Type: application/scim+json", "Content-Type: application/scim+json"), userDocument("alice")).status);
            List<String> headers = List.of("Authorization: Bearer " + TOKEN, "Content-Type: application/scim+json");
            assertEquals(413, wire(port, "POST", "/scim/v2/Users", headers, "x".repeat(16_385), true).status);
            assertEquals(201, wire(port, "POST", "/scim/v2/Users", headers, userDocument("alice")).status);
            assertEquals(400, wire(port, "GET", "/scim/v2/Users?count=1&COUNT=2", headers, "").status);
            assertEquals(400, wire(port, "GET", "/scim/v2/Users?filter=password+pr", headers, "").status);
            ExecutorService pool = Executors.newFixedThreadPool(2); CountDownLatch start = new CountDownLatch(1);
            try {
                List<Future<Integer>> writes = new ArrayList<>();
                for (String changed : List.of("one", "two")) writes.add(pool.submit(() -> {
                    assertTrue(start.await(3, TimeUnit.SECONDS));
                    String body = new String(patch("u-1", "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"" + changed + "\"}").getBody().orElseThrow(), StandardCharsets.UTF_8);
                    return wire(port, "PATCH", "/scim/v2/Users/u-1", List.of("Authorization: Bearer " + TOKEN, "Content-Type: application/scim+json", "If-Match: W/\"1\""), body).status;
                }));
                start.countDown(); List<Integer> outcomes = List.of(writes.get(0).get(5, TimeUnit.SECONDS), writes.get(1).get(5, TimeUnit.SECONDS));
                assertEquals(Set.of(200, 412), new HashSet<>(outcomes)); assertEquals(Optional.of("W/\"2\""), app.snapshot(USER, "u-1").getVersion());
            } finally { pool.shutdownNow(); assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS)); }
            app.failNext(PlaygroundScim.Fault.ACKNOWLEDGEMENT_LOST);
            String changed = new String(patch("u-1", "{\"op\":\"replace\",\"path\":\"displayName\",\"value\":\"LostAck\"}").getBody().orElseThrow(), StandardCharsets.UTF_8);
            WireResponse unknown = wire(port, "PATCH", "/scim/v2/Users/u-1", headers, changed);
            assertEquals(503, unknown.status); assertFalse(unknown.message.contains("LostAck")); assertFalse(unknown.message.contains("ETag:"));
            assertEquals(PlaygroundScim.CommitOutcome.UNKNOWN, app.lastOutcome()); assertEquals(Optional.of("W/\"3\""), app.snapshot(USER, "u-1").getVersion());
            assertEquals(304, wire(port, "GET", "/scim/v2/Users/u-1", List.of("Authorization: Bearer " + TOKEN, "If-None-Match: W/\"3\""), "").status);
        }
    }

    private record WireResponse(int status, @NonNull String message) { }
    private static @NonNull WireResponse wire(int port, @NonNull String method, @NonNull String path,
            @NonNull List<@NonNull String> headers, @NonNull String body) throws IOException {
        return wire(port, method, path, headers, body, false);
    }
    private static @NonNull WireResponse wire(int port, @NonNull String method, @NonNull String path,
            @NonNull List<@NonNull String> headers, @NonNull String body, boolean acceptResetAfterResponse) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port)) {
            socket.setSoTimeout(5000);
            String message = method + " " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n" + String.join("\r\n", headers)
                    + "\r\nContent-Length: " + payload.length + "\r\n\r\n";
            socket.getOutputStream().write(message.getBytes(StandardCharsets.US_ASCII)); socket.getOutputStream().write(payload); socket.getOutputStream().flush();
            ByteArrayOutputStream captured = new ByteArrayOutputStream(); byte[] block = new byte[8_192];
            while (captured.size() <= 65_536) {
                try {
                    int read = socket.getInputStream().read(block, 0, Math.min(block.length, 65_537 - captured.size()));
                    if (read < 0) break;
                    captured.write(block, 0, read);
                } catch (SocketException reset) {
                    if (!acceptResetAfterResponse || captured.size() < 12) throw reset;
                    break;
                }
            }
            byte[] response = captured.toByteArray(); assertTrue(response.length <= 65_536, "bounded loopback response");
            String text = new String(response, StandardCharsets.UTF_8); assertTrue(text.startsWith("HTTP/1.1 "), text);
            return new WireResponse(Integer.parseInt(text.substring(9, 12)), text);
        }
    }
}
