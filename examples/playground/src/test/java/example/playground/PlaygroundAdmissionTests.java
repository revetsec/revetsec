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

import com.revetsec.jose.JsonWebKeySet;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.jose.StaticJsonWebKeySource;
import com.revetsec.json.JsonObject;
import com.revetsec.oauth.*;
import com.soklet.*;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import com.sun.net.httpserver.HttpExchange;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

final class PlaygroundAdmissionTests {
    @Test void actualJwtProfilesRejectMissingMalformedExpiredIssuerAudienceAndSignatureBeforeHandler() throws Exception {
        Fixtures fixture = new Fixtures();
        AtomicInteger calls = new AtomicInteger();
        PlaygroundAdmission.TokenValidator validator = fixture.validator(calls);
        SokletConfig config = fixture.application(validator);
        SokletSimulator.run(config, simulator -> {
            assertEquals(401, fixture.call(simulator, null, "tools/call", "whoami", "{}", false).getStatusCode());
            assertEquals(400, fixture.call(simulator, "Basic abc", "tools/call", "whoami", "{}", false).getStatusCode());
            assertEquals(0, calls.get());
            for (String token : List.of(fixture.jwt("issuer", fixture.resource, "mcp:whoami", 60, false),
                    fixture.jwt(fixture.issuer, "https://wrong.example/mcp", "mcp:whoami", 60, false),
                    fixture.jwt(fixture.issuer, fixture.resource, "mcp:whoami", -120, false),
                    fixture.jwt(fixture.issuer, fixture.resource, "mcp:whoami", 60, true))) {
                McpSimulationResponse response = fixture.call(simulator, "Bearer " + token, "tools/call", "whoami", "{}", false);
                assertEquals(401, response.getStatusCode());
                assertFalse(Fixtures.body(response).contains("subject"));
                assertFalse(Fixtures.body(response).contains(token));
                assertTrue(response.getHeaders().get("WWW-Authenticate").iterator().next().contains("invalid_token"));
            }
            assertEquals(4, calls.get());
            String good = fixture.jwt(fixture.issuer, fixture.resource, "mcp:whoami", 60, false);
            McpSimulationResponse accepted = fixture.call(simulator, "bEaReR   " + good, "tools/call", "whoami", "{}", false);
            assertEquals(200, accepted.getStatusCode());
            assertTrue(Fixtures.body(accepted).contains("p1_"));
            assertFalse(Fixtures.body(accepted).contains("synthetic-private-subject"));
            assertFalse(Fixtures.body(accepted).contains(good));
        });
    }

    @Test void explicitCatalogToolTenantAndObjectDecisionsDoNotCrossAuthorize() throws Exception {
        Fixtures fixture = new Fixtures();
        SokletSimulator.run(fixture.application(fixture.validator(new AtomicInteger())), simulator -> {
            String discover = "Bearer " + fixture.jwt(fixture.issuer, fixture.resource, "mcp:discover", 60, false);
            assertEquals(200, fixture.call(simulator, discover, "server/discover", null, "{}", false).getStatusCode());
            assertEquals(200, fixture.call(simulator, discover, "tools/list", null, "{}", false).getStatusCode());
            assertEquals(403, fixture.call(simulator, discover, "tools/call", "whoami", "{}", false).getStatusCode());
            String whoami = "Bearer " + fixture.jwt(fixture.issuer, fixture.resource, "mcp:whoami", 60, false);
            assertEquals(403, fixture.call(simulator, whoami, "tools/list", null, "{}", false).getStatusCode());
            assertEquals(400, fixture.call(simulator, whoami, "tools/call", "unmapped", "{}", false).getStatusCode());
            for (String args : List.of("{\"tenant\":\"other\"}", "{\"object\":\"other\"}", "{\"object\":42}", "{\"unexpected\":\"secret\"}")) {
                McpSimulationResponse denied = fixture.call(simulator, whoami, "tools/call", "whoami", args, false);
                assertEquals(200, denied.getStatusCode());
                assertTrue(Fixtures.body(denied).contains("Operation not permitted"));
                assertFalse(Fixtures.body(denied).contains("issuer"));
            }
        });
    }

    @Test void everyMessageIncludingNotificationRevalidatesAndPartitionsAreOpaque() throws Exception {
        Fixtures fixture = new Fixtures();
        AtomicInteger calls = new AtomicInteger();
        SokletSimulator.run(fixture.application(fixture.validator(calls)), simulator -> {
            String good = "Bearer " + fixture.jwt(fixture.issuer, fixture.resource, "mcp:discover", 60, false);
            assertEquals(200, fixture.call(simulator, good, "tools/list", null, "{}", false).getStatusCode());
            assertEquals(200, fixture.call(simulator, good, "tools/list", null, "{}", false).getStatusCode());
            McpSimulationResponse deniedNotification = fixture.call(simulator, null, "ping", null, "{}", true);
            assertEquals(401, deniedNotification.getStatusCode());
            assertEquals("", Fixtures.body(deniedNotification));
            assertTrue(deniedNotification.getHeaders().containsKey("WWW-Authenticate"));
            assertEquals(2, calls.get());
        });
        SafeViews views = new SafeViews(LocalSecrets.randomBytes());
        String key = views.partition(fixture.issuer, "synthetic-private-subject", "local");
        assertEquals(key, views.partition(fixture.issuer, "synthetic-private-subject", "local"));
        assertNotEquals(key, views.partition(fixture.issuer, "synthetic-private-subject", "another"));
        assertEquals(46, key.length());
        assertFalse(key.contains("subject"));
    }

    @Test void hostOriginAndDistinctMaterializedAuthorizationDenyBeforeVerifierAndUnavailableIs503() throws Exception {
        Fixtures fixture = new Fixtures();
        AtomicInteger calls = new AtomicInteger();
        SokletSimulator.run(fixture.application(fixture.validator(calls)), simulator -> {
            String token = fixture.jwt(fixture.issuer, fixture.resource, "mcp:whoami", 60, false);
            Request request = fixture.request("Bearer " + token, "tools/call", "whoami", "{}", false);
            for (Map<String, List<String>> headers : List.of(
                    Map.of("Host", List.of("foreign.example:8081"), "Authorization", List.of("Bearer " + token), "Content-Type", List.of("application/json")),
                    Map.of("Host", List.of("127.0.0.1:8081"), "Origin", List.of("https://foreign.example"), "Authorization", List.of("Bearer " + token), "Content-Type", List.of("application/json")),
                    Map.of("Host", List.of("127.0.0.1:8081"), "Authorization", List.of("Bearer " + token, "Bearer other"), "Content-Type", List.of("application/json")))) {
                Map<String, List<String>> exact = new java.util.LinkedHashMap<>(request.getHeaders());
                exact.putAll(headers);
                try (McpSimulation simulation = simulator.startMcpRequest(request.copy().headers(exact).finish())) {
                    assertEquals(headers.containsKey("Origin") ? 403 : headers.get("Host").contains("foreign.example:8081") ? 421 : 400,
                            simulation.awaitResponse(Duration.ofSeconds(3)).orElseThrow().getStatusCode());
                }
            }
            assertEquals(0, calls.get());
        });
        JwtAccessTokenValidator unavailable = JwtAccessTokenValidator.withIssuer("http://127.0.0.1:1")
                .expectedAudiences(Set.of(fixture.resource)).allowInsecureLoopback(true)
                .requestTimeout(Duration.ofSeconds(1)).totalDeadline(Duration.ofSeconds(2)).build();
        long start = System.nanoTime();
        SokletSimulator.run(fixture.application(unavailable::validateResult), simulator -> {
            McpSimulationResponse response = fixture.call(simulator, "Bearer " + fixture.jwt(fixture.issuer, fixture.resource, "mcp:whoami", 60, false),
                    "tools/call", "whoami", "{}", false);
            assertEquals(503, response.getStatusCode());
            assertFalse(response.getHeaders().containsKey("WWW-Authenticate"));
            assertFalse(Fixtures.body(response).contains("invalid_token"));
        });
        assertTrue(Duration.ofNanos(System.nanoTime() - start).compareTo(Duration.ofSeconds(4)) < 0);
    }

    @Test void setsCannotRecoverIdenticalPhysicalHeadersAndBodyTokensAreNotMcpTransport() throws Exception {
        Fixtures fixture = new Fixtures();
        Request collapsed = Request.withPath(HttpMethod.POST, "/mcp").headers(Map.of("Authorization", List.of("Bearer opaque"))).build();
        assertTrue(com.revetsec.soklet.SokletBearer.bearerTokenFor(collapsed).isPresent());
        SokletSimulator.run(fixture.application(fixture.validator(new AtomicInteger())), simulator -> {
            McpSimulationResponse response = fixture.call(simulator, null, "tools/call", "whoami", "{\"token\":\"opaque\"}", false);
            assertEquals(401, response.getStatusCode());
        });
        assertTrue(PlaygroundAdmissionTests.class.getResourceAsStream("/web/index.html") != null);
        // This is the observable Set boundary only; the physical duplicate gate is the edge's separate obligation.
    }

    @Test void registeredToolWithoutExplicitMappingIsDeniedBeforeVerifierAndHandler() throws Exception {
        Fixtures fixture = new Fixtures();
        AtomicInteger verifierCalls = new AtomicInteger();
        AtomicInteger handlerCalls = new AtomicInteger();
        PlaygroundAdmission.RuntimeProfile profile = new PlaygroundAdmission.RuntimeProfile(fixture.config(), fixture.validator(verifierCalls));
        Set<McpProtocolVersion> versions = Set.of(McpProtocolVersion.V2026_07_28);
        McpToolRegistration<McpJsonObject> tool = McpToolRegistration.withName("unmapped", versions).jsonObjectArguments()
                .handler((context, arguments, features) -> { handlerCalls.incrementAndGet(); return McpCompleteResult.fromToolText("forbidden"); }).build();
        McpEndpoint endpoint = McpEndpoint.withPath("/mcp", McpImplementation.withNameAndVersion("synthetic", "1").build(), versions)
                .toolRegistrations(List.of(tool)).build();
        McpServer server = McpServer.withPort(8081).host("127.0.0.1").endpointRegistry(McpEndpointRegistry.fromEndpoints(List.of(endpoint)))
                .admissionController(new PlaygroundAdmission(() -> profile, new SafeViews(LocalSecrets.randomBytes())))
                .toolRateLimiter(McpRateLimiter.fromInMemoryDefaults()).build();
        SokletSimulator.run(SokletConfig.withMcpServer(server).resourceMethodResolver(ResourceMethodResolver.fromMethods(Set.of())).build(), simulator -> {
            assertEquals(403, fixture.call(simulator, "Bearer " + fixture.jwt(fixture.issuer, fixture.resource, "mcp:whoami", 60, false),
                    "tools/call", "unmapped", "{}", false).getStatusCode());
            assertEquals(0, verifierCalls.get()); assertEquals(0, handlerCalls.get());
        });
    }

    @Test void legacyInitializeAndModernDiscoveryHaveExplicitDiscoverScopeAndNoAnonymousBootstrap() throws Exception {
        Fixtures fixture = new Fixtures();
        AtomicInteger calls = new AtomicInteger();
        SokletSimulator.run(fixture.application(fixture.validator(calls)), simulator -> {
            String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\","
                    + "\"capabilities\":{},\"clientInfo\":{\"name\":\"synthetic-client\",\"version\":\"1\"}}}";
            Map<String, List<String>> headers = new java.util.LinkedHashMap<>();
            headers.put("Host", List.of("127.0.0.1:8081")); headers.put("Content-Type", List.of("application/json"));
            headers.put("Accept", List.of("application/json, text/event-stream")); headers.put("Mcp-Method", List.of("initialize"));
            Request initialize = Request.withPath(HttpMethod.POST, "/mcp").headers(headers).body(body.getBytes(StandardCharsets.UTF_8)).build();
            try (McpSimulation simulation = simulator.startMcpRequest(initialize)) {
                assertEquals(401, simulation.awaitResponse(Duration.ofSeconds(3)).orElseThrow().getStatusCode());
            }
            headers.put("Authorization", List.of("Bearer " + fixture.jwt(fixture.issuer, fixture.resource, "mcp:discover", 60, false)));
            try (McpSimulation simulation = simulator.startMcpRequest(initialize.copy().headers(headers).finish())) {
                McpSimulationResponse response = simulation.awaitResponse(Duration.ofSeconds(3)).orElseThrow();
                assertEquals(200, response.getStatusCode()); assertTrue(Fixtures.body(response).contains("2025-11-25"));
            }
            assertEquals(1, calls.get());
        });
    }

    @Test void actualIntrospectionRepostsForEveryMessageAndActiveAudiencePolicyCannotReleaseWrongProof() throws Exception {
        Fixtures fixture = new Fixtures();
        try (PlaygroundOidcTests.Provider provider = new PlaygroundOidcTests.Provider()) {
            OAuthClient oauth = OAuthClient.withIssuer(provider.issuer).clientId("synthetic-client")
                    .clientAuthentication(ClientAuthentication.fromClientSecretBasic("synthetic-secret"))
                    .allowInsecureLoopback(true).build();
            TokenIntrospectionClient introspection = TokenIntrospectionClient.withOAuthClient(oauth)
                    .expectedAudiences(Set.of(fixture.resource)).build();
            PlaygroundConfig configured = new PlaygroundConfig(fixture.config().origin, provider.issuer, "synthetic-client", "none",
                    "synthetic-client", "none", "introspection", true, false, 8080, 8081);
            BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 4);
            SafeViews views = new SafeViews(LocalSecrets.randomBytes());
            PlaygroundResources resources = new PlaygroundResources(configured, sessions, views, new PlaygroundOidc(sessions, views, Clock.systemUTC()),
                    HttpClient.newHttpClient(), introspection::validateResult);
            SokletSimulator.run(Playground.sokletConfig(configured, resources, views), simulator -> {
                assertEquals(200, fixture.call(simulator, "Bearer synthetic-opaque", "tools/call", "whoami", "{}", false).getStatusCode());
                assertEquals(200, fixture.call(simulator, "Bearer synthetic-opaque", "tools/call", "whoami", "{}", false).getStatusCode());
                assertEquals(2, provider.introspectionPosts.get());
                provider.introspectionAudience = "https://wrong.example/mcp";
                assertEquals(401, fixture.call(simulator, "Bearer synthetic-opaque", "tools/call", "whoami", "{}", false).getStatusCode());
                assertEquals(3, provider.introspectionPosts.get());
                provider.introspectionAudience = fixture.resource; provider.active = false;
                assertEquals(401, fixture.call(simulator, "Bearer synthetic-opaque", "tools/call", "whoami", "{}", false).getStatusCode());
                assertEquals(4, provider.introspectionPosts.get());
                provider.introspectionUnavailable = true;
                McpSimulationResponse unavailable = fixture.call(simulator, "Bearer synthetic-opaque", "tools/call", "whoami", "{}", false);
                assertEquals(503, unavailable.getStatusCode()); assertFalse(unavailable.getHeaders().containsKey("WWW-Authenticate"));
            });
        }
    }

    static final class Fixtures {
        final KeyPair pair;
        final String issuer = "https://provider.example.test";
        final String resource = "https://localhost:8443/mcp";
        Fixtures() throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048); pair = generator.generateKeyPair();
        }
        @NonNull PlaygroundConfig config() {
            return new PlaygroundConfig(URI.create("https://localhost:8443"), issuer, "synthetic-client", "none",
                    "synthetic-client", "none", "jwt", true, true, 8080, 8081);
        }
        PlaygroundAdmission.@NonNull TokenValidator validator(@NonNull AtomicInteger calls) {
            JwtAccessTokenValidator validator = JwtAccessTokenValidator.withIssuer(issuer)
                    .expectedAudiences(Set.of(resource)).allowedAlgorithms(Set.of(JwsAlgorithm.RS256))
                    .jsonWebKeySource(StaticJsonWebKeySource.fromJsonWebKeySet(JsonWebKeySet.fromJson(jwks()))).build();
            return token -> { calls.incrementAndGet(); return validator.validateResult(token); };
        }
        @NonNull SokletConfig application(PlaygroundAdmission.@NonNull TokenValidator validator) {
            BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 32);
            SafeViews views = new SafeViews(LocalSecrets.randomBytes());
            PlaygroundOidc oidc = new PlaygroundOidc(sessions, views, Clock.systemUTC());
            PlaygroundResources resources = new PlaygroundResources(config(), sessions, views, oidc, HttpClient.newHttpClient(), validator);
            return Playground.sokletConfig(config(), resources, views);
        }
        @NonNull String jwt(@NonNull String iss, @NonNull String audience, @NonNull String scopes, int expires, boolean bad) throws Exception {
            JsonObject claims = JsonObject.builder().put("iss", iss).put("aud", audience).put("sub", "synthetic-private-subject")
                    .put("client_id", "synthetic-client").put("jti", LocalSecrets.randomId())
                    .put("iat", Instant.now().getEpochSecond() - 180).put("exp", Instant.now().getEpochSecond() + expires)
                    .put("scope", scopes).build();
            String compact = sign("{\"alg\":\"RS256\",\"typ\":\"at+jwt\",\"kid\":\"synthetic\"}", claims.toJson());
            if (!bad) return compact;
            int last = compact.lastIndexOf('.') + 1;
            return compact.substring(0, last) + (compact.charAt(last) == 'A' ? 'B' : 'A') + compact.substring(last + 1);
        }
        @NonNull String sign(@NonNull String header, @NonNull String claims) throws Exception {
            String signingInput = base64(header.getBytes(StandardCharsets.UTF_8)) + "." + base64(claims.getBytes(StandardCharsets.UTF_8));
            Signature signer = Signature.getInstance("SHA256withRSA"); signer.initSign(pair.getPrivate());
            signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signingInput + "." + base64(signer.sign());
        }
        @NonNull String jwks() {
            RSAPublicKey key = (RSAPublicKey) pair.getPublic();
            return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"synthetic\",\"alg\":\"RS256\",\"use\":\"sig\",\"n\":\""
                    + integer(key.getModulus()) + "\",\"e\":\"" + integer(key.getPublicExponent()) + "\"}]}";
        }
        private static @NonNull String integer(@NonNull BigInteger value) {
            byte[] bytes = value.toByteArray();
            return base64(bytes[0] == 0 ? java.util.Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);
        }
        static @NonNull String base64(byte @NonNull [] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
        @NonNull Request request(@Nullable String authorization, @NonNull String method, @Nullable String tool,
                @NonNull String arguments, boolean notification) {
            String id = notification ? "" : "\"id\":\"synthetic\",";
            String params = tool == null ? "{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}"
                    : "{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}},\"name\":\"" + tool + "\",\"arguments\":" + arguments + "}";
            String body = "{\"jsonrpc\":\"2.0\"," + id + "\"method\":\"" + method + "\",\"params\":" + params + "}";
            Map<String, List<String>> headers = new java.util.LinkedHashMap<>();
            headers.put("Host", List.of("127.0.0.1:8081")); headers.put("Content-Type", List.of("application/json"));
            headers.put("Accept", List.of("application/json, text/event-stream"));
            headers.put("MCP-Protocol-Version", List.of("2026-07-28"));
            headers.put("Mcp-Method", List.of(method));
            if (tool != null) headers.put("Mcp-Name", List.of(tool));
            if (authorization != null) headers.put("Authorization", List.of(authorization));
            return Request.withPath(HttpMethod.POST, "/mcp").headers(headers).body(body.getBytes(StandardCharsets.UTF_8)).build();
        }
        @NonNull McpSimulationResponse call(@NonNull Simulator simulator, @Nullable String auth, @NonNull String method,
                @Nullable String tool, @NonNull String args, boolean notification) throws InterruptedException {
            try (McpSimulation simulation = simulator.startMcpRequest(request(auth, method, tool, args, notification))) {
                return simulation.awaitResponse(Duration.ofSeconds(5)).orElseThrow();
            }
        }
        static @NonNull String body(@NonNull McpSimulationResponse response) {
            return response.getBody().map(b -> new String(b, StandardCharsets.UTF_8)).orElse("");
        }
    }
}
