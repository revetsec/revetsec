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

import com.soklet.HttpMethod;
import com.soklet.Request;
import com.soklet.Response;
import com.soklet.SokletSimulator;
import com.soklet.McpSimulation;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

/** Actual normal OAuth/CC HTTP exchange; controlled RS statuses exercise only the app retry policy. */
final class PlaygroundProbeTests {
    @Test void literalLoopbackOriginBuildsRealServersWithoutDuplicateAllowedHosts() throws Exception {
        PlaygroundAdmissionTests.Fixtures fixture = new PlaygroundAdmissionTests.Fixtures();
        PlaygroundConfig config = new PlaygroundConfig(URI.create("https://127.0.0.1:8443"), fixture.issuer,
                "synthetic-client", "none", "synthetic-client", "none", "jwt", true, false, 8080, 8081);
        AtomicInteger calls = new AtomicInteger();
        BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 4);
        SafeViews views = new SafeViews(LocalSecrets.randomBytes());
        PlaygroundResources resources = new PlaygroundResources(config, sessions, views,
                new PlaygroundOidc(sessions, views, Clock.systemUTC()), HttpClient.newHttpClient(), fixture.validator(calls));
        SokletSimulator.run(Playground.sokletConfig(config, resources, views), simulator -> {
            assertEquals(200, simulator.performHttpRequest(Request.withPath(HttpMethod.GET, "/")
                    .headers(Map.of("Host", Set.of("127.0.0.1:8443"))).build()).getResponse().orElseThrow().getStatusCode());
            Request admittedTransport = fixture.request(null, "tools/call", "whoami", "{}", false)
                    .copy().headers(headers -> headers.put("Origin", Set.of("https://127.0.0.1:8443"))).finish();
            try (McpSimulation simulation = simulator.startMcpRequest(admittedTransport)) {
                assertEquals(401, simulation.awaitResponse(Duration.ofSeconds(3)).orElseThrow().getStatusCode());
            }
            try (McpSimulation simulation = simulator.startMcpRequest(admittedTransport.copy()
                    .headers(headers -> headers.put("Origin", Set.of("https://foreign.example"))).finish())) {
                assertEquals(403, simulation.awaitResponse(Duration.ofSeconds(3)).orElseThrow().getStatusCode());
            }
            try (McpSimulation simulation = simulator.startMcpRequest(admittedTransport.copy()
                    .headers(headers -> headers.put("Host", Set.of("foreign.example:8081"))).finish())) {
                assertEquals(421, simulation.awaitResponse(Duration.ofSeconds(3)).orElseThrow().getStatusCode());
            }
            assertEquals(0, calls.get());
        });
    }

    @Test void credentialRejectionInvalidatesPresentedTokenAndRetriesWithFreshCredentialOnce(@TempDir @NonNull Path temporary) throws Exception {
        try (ProbeFixture fixture = new ProbeFixture(temporary, List.of(401, 200), false, 0)) {
            Response response = runProbe(fixture);
            assertEquals(200, response.getStatusCode());
            assertDecision(response, 200, true);
            assertEquals(2, fixture.tokenPosts.get());
            assertEquals(2, fixture.resourcePosts.get());
            assertEquals(List.of("Bearer synthetic-cc-1", "Bearer synthetic-cc-2"), fixture.presentedCredentials);
            assertEquals(1, fixture.discoveryRequests.get());
            assertNull(fixture.failure);
        }
    }

    @Test void secondCredentialRejectionEndsAfterTheSingleAppRetry(@TempDir @NonNull Path temporary) throws Exception {
        try (ProbeFixture fixture = new ProbeFixture(temporary, List.of(401, 401, 200), false, 0)) {
            Response response = runProbe(fixture);
            assertEquals(400, response.getStatusCode());
            assertDecision(response, 401, true);
            assertEquals(2, fixture.tokenPosts.get());
            assertEquals(2, fixture.resourcePosts.get());
            assertEquals(List.of("Bearer synthetic-cc-1", "Bearer synthetic-cc-2"), fixture.presentedCredentials);
            assertNull(fixture.failure);
        }
    }

    @Test void permissionAndInfrastructureStatusesNeverInvalidateOrRetry(@TempDir @NonNull Path temporary) throws Exception {
        for (int status : List.of(403, 500, 503)) {
            try (ProbeFixture fixture = new ProbeFixture(temporary.resolve("status-" + status), List.of(status, 200), false, 0)) {
                Response response = runProbe(fixture);
                assertEquals(400, response.getStatusCode());
                assertDecision(response, status, false);
                assertEquals(1, fixture.tokenPosts.get());
                assertEquals(1, fixture.resourcePosts.get());
                assertEquals(List.of("Bearer synthetic-cc-1"), fixture.presentedCredentials);
                assertNull(fixture.failure);
            }
        }
    }

    @Test void tokenEndpointUnavailableNeverCallsResourceOrRetries(@TempDir @NonNull Path temporary) throws Exception {
        try (ProbeFixture fixture = new ProbeFixture(temporary, List.of(200), true, 0)) {
            Response response = runProbe(fixture);
            assertEquals(503, response.getStatusCode());
            assertEquals("{\"outcome\":\"Probe service unavailable.\"}", response.getBody().orElseThrow().toString());
            assertEquals(1, fixture.tokenPosts.get());
            assertEquals(0, fixture.resourcePosts.get());
            assertTrue(fixture.presentedCredentials.isEmpty());
            assertNull(fixture.failure);
        }
    }

    @Test void resourceTimeoutReturnsFixedUnavailableWithinItsDeadlineWithoutRenewal(@TempDir @NonNull Path temporary) throws Exception {
        try (ProbeFixture fixture = new ProbeFixture(temporary, List.of(200), false, 6500)) {
            long begin = System.nanoTime();
            Response response = runProbe(fixture);
            Duration elapsed = Duration.ofNanos(System.nanoTime() - begin);
            assertEquals(503, response.getStatusCode());
            assertEquals("{\"outcome\":\"Probe service unavailable.\"}", response.getBody().orElseThrow().toString());
            assertTrue(elapsed.compareTo(Duration.ofSeconds(8)) < 0);
            assertEquals(1, fixture.tokenPosts.get());
            assertEquals(1, fixture.resourcePosts.get());
            assertEquals(List.of("Bearer synthetic-cc-1"), fixture.presentedCredentials);
        }
    }

    @Test void resourceStatusDoesNotWaitForAnUnfinishedResponseBody(@TempDir @NonNull Path temporary) throws Exception {
        for (int status : List.of(200, 401)) {
            try (ProbeFixture fixture = new ProbeFixture(temporary.resolve("body-" + status),
                    List.of(status, 200), false, 0, true)) {
                long begin = System.nanoTime();
                Response response = runProbe(fixture);
                Duration elapsed = Duration.ofNanos(System.nanoTime() - begin);
                assertEquals(200, response.getStatusCode());
                assertDecision(response, 200, status == 401);
                assertTrue(elapsed.compareTo(Duration.ofSeconds(4)) < 0);
                assertEquals(status == 401 ? 2 : 1, fixture.tokenPosts.get());
                assertEquals(status == 401 ? 2 : 1, fixture.resourcePosts.get());
                assertNull(fixture.failure);
            }
        }
    }

    private static @NonNull Response runProbe(@NonNull ProbeFixture fixture) {
        PlaygroundConfig config = fixture.config();
        BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 4);
        SafeViews views = new SafeViews(LocalSecrets.randomBytes());
        PlaygroundResources resources = new PlaygroundResources(config, sessions, views,
                new PlaygroundOidc(sessions, views, Clock.systemUTC()), fixture.http);
        BrowserSessions.Session session = sessions.begin();
        Request request = Request.withPath(HttpMethod.POST, "/api/probe")
                .headers(Map.of("Host", Set.of(config.origin.getAuthority()), "Origin", Set.of(config.origin.toString()),
                        "Cookie", Set.of(BrowserSessions.COOKIE + "=" + session.id), "X-CSRF-Token", Set.of(session.csrf)))
                .build();
        AtomicReference<@NonNull Response> received = new AtomicReference<>();
        SokletSimulator.run(Playground.sokletConfig(config, resources, views), simulator ->
                received.set(simulator.performHttpRequest(request).getResponse().orElseThrow()));
        return java.util.Objects.requireNonNull(received.get());
    }

    private static void assertDecision(@NonNull Response response, int status, boolean retried) {
        String body = response.getBody().orElseThrow().toString();
        assertTrue(body.contains("\"httpStatus\":" + status));
        assertTrue(body.contains("\"retriedOnce\":" + retried));
        assertFalse(body.contains("synthetic-cc-"));
        assertFalse(body.contains("synthetic-client-secret"));
    }

    private static final class ProbeFixture implements AutoCloseable {
        final HttpsServer server;
        final URI origin;
        final String issuer;
        final String secretReference;
        final HttpClient http;
        final AtomicInteger discoveryRequests = new AtomicInteger();
        final AtomicInteger tokenPosts = new AtomicInteger();
        final AtomicInteger resourcePosts = new AtomicInteger();
        final List<@NonNull String> presentedCredentials = Collections.synchronizedList(new ArrayList<>());
        final List<@NonNull Integer> resourceStatuses;
        final boolean tokenUnavailable;
        final long resourceDelayMillis;
        final boolean unfinishedResourceBody;
        final java.util.concurrent.CountDownLatch releaseBody = new java.util.concurrent.CountDownLatch(1);
        final java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newCachedThreadPool(task -> {
                Thread thread = new Thread(task, "synthetic-probe-endpoint");
                thread.setDaemon(true);
                return thread;
            });
        volatile @org.jspecify.annotations.Nullable String failure;

        ProbeFixture(@NonNull Path temporary, @NonNull List<@NonNull Integer> resourceStatuses,
                boolean tokenUnavailable, long resourceDelayMillis) throws Exception {
            this(temporary, resourceStatuses, tokenUnavailable, resourceDelayMillis, false);
        }

        ProbeFixture(@NonNull Path temporary, @NonNull List<@NonNull Integer> resourceStatuses,
                boolean tokenUnavailable, long resourceDelayMillis, boolean unfinishedResourceBody) throws Exception {
            Files.createDirectories(temporary);
            Path keyStorePath = temporary.resolve("local-private-tls.p12");
            String password = "synthetic-test-store";
            Process keytool = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                    "-genkeypair", "-alias", "local", "-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA",
                    "-validity", "2", "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1",
                    "-storetype", "PKCS12", "-keystore", keyStorePath.toString(), "-storepass", password,
                    "-keypass", password, "-noprompt").redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD).start();
            if (!keytool.waitFor(15, TimeUnit.SECONDS)) {
                keytool.destroyForcibly();
                throw new IllegalStateException("Synthetic TLS generation exceeded its deadline.");
            }
            if (keytool.exitValue() != 0) throw new IllegalStateException("Synthetic TLS generation failed.");
            KeyStore store = KeyStore.getInstance("PKCS12");
            try (InputStream input = Files.newInputStream(keyStorePath)) { store.load(input, password.toCharArray()); }
            KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keys.init(store, password.toCharArray());
            SSLContext serverTls = SSLContext.getInstance("TLS");
            serverTls.init(keys.getKeyManagers(), null, null);
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, null);
            trust.setCertificateEntry("local", store.getCertificate("local"));
            TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trust);
            SSLContext clientTls = SSLContext.getInstance("TLS");
            clientTls.init(null, trustManagers.getTrustManagers(), null);
            http = HttpClient.newBuilder().sslContext(clientTls).connectTimeout(Duration.ofSeconds(2))
                    .followRedirects(HttpClient.Redirect.NEVER).build();
            server = HttpsServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(serverTls));
            server.setExecutor(executor);
            origin = URI.create("https://localhost:" + server.getAddress().getPort());
            issuer = origin + "/issuer";
            Path secret = temporary.resolve("synthetic-secret.txt");
            Files.writeString(secret, "synthetic-client-secret");
            secretReference = "file:" + secret;
            this.resourceStatuses = List.copyOf(resourceStatuses);
            this.tokenUnavailable = tokenUnavailable;
            this.resourceDelayMillis = resourceDelayMillis;
            this.unfinishedResourceBody = unfinishedResourceBody;
            server.createContext("/", this::handle);
            server.start();
        }

        @NonNull PlaygroundConfig config() {
            return new PlaygroundConfig(origin, issuer, "synthetic-client", secretReference,
                    "synthetic-client", secretReference, "jwt", true, false, 0, 0);
        }

        private void handle(@NonNull HttpExchange exchange) throws IOException {
            try {
                String path = exchange.getRequestURI().getPath();
                if (path.equals("/.well-known/oauth-authorization-server/issuer")) {
                    discoveryRequests.incrementAndGet();
                    respond(exchange, 200, "{\"issuer\":\"" + issuer + "\",\"authorization_endpoint\":\"" + issuer
                            + "/authorize\",\"token_endpoint\":\"" + issuer + "/token\",\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\"]}");
                } else if (path.equals("/issuer/token")) {
                    int sequence = tokenPosts.incrementAndGet();
                    assertEquals("POST", exchange.getRequestMethod());
                    String basic = "Basic " + Base64.getEncoder().encodeToString("synthetic-client:synthetic-client-secret".getBytes(StandardCharsets.US_ASCII));
                    assertEquals(basic, exchange.getRequestHeaders().getFirst("Authorization"));
                    Map<String, String> form = parameters(exchange);
                    assertEquals("client_credentials", form.get("grant_type"));
                    assertEquals(origin + "/mcp", form.get("resource"));
                    assertEquals(Set.of("mcp:discover", "mcp:whoami"), Set.of(form.get("scope").split(" ")));
                    respond(exchange, tokenUnavailable ? 503 : 200, tokenUnavailable ? "{\"error\":\"server_error\"}"
                            : "{\"access_token\":\"synthetic-cc-" + sequence + "\",\"token_type\":\"Bearer\",\"expires_in\":60}");
                } else if (path.equals("/mcp")) {
                    int sequence = resourcePosts.incrementAndGet();
                    assertEquals("POST", exchange.getRequestMethod());
                    presentedCredentials.add(exchange.getRequestHeaders().getFirst("Authorization"));
                    assertEquals("tools/call", exchange.getRequestHeaders().getFirst("Mcp-Method"));
                    assertEquals("whoami", exchange.getRequestHeaders().getFirst("Mcp-Name"));
                    byte[] body = exchange.getRequestBody().readNBytes(4097);
                    assertTrue(body.length <= 4096);
                    assertTrue(new String(body, StandardCharsets.UTF_8).contains("\"name\":\"whoami\""));
                    if (resourceDelayMillis != 0) Thread.sleep(resourceDelayMillis);
                    int status = resourceStatuses.get(Math.min(sequence - 1, resourceStatuses.size() - 1));
                    if (unfinishedResourceBody && sequence == 1) {
                        exchange.sendResponseHeaders(status, 2);
                        exchange.getResponseBody().write('{');
                        exchange.getResponseBody().flush();
                        releaseBody.await(8, TimeUnit.SECONDS);
                    } else respond(exchange, status, "{}");
                } else respond(exchange, 404, "{}");
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } catch (AssertionError | RuntimeException invalid) {
                failure = "Synthetic endpoint request did not match its contract.";
                respond(exchange, 500, "{}");
            } finally { exchange.close(); }
        }

        private static @NonNull Map<@NonNull String, @NonNull String> parameters(@NonNull HttpExchange exchange) throws IOException {
            byte[] bytes = exchange.getRequestBody().readNBytes(4097);
            assertTrue(bytes.length <= 4096);
            Map<String, String> result = new LinkedHashMap<>();
            for (String part : new String(bytes, StandardCharsets.UTF_8).split("&")) {
                String[] pieces = part.split("=", 2);
                assertEquals(2, pieces.length);
                assertNull(result.put(URLDecoder.decode(pieces[0], StandardCharsets.UTF_8), URLDecoder.decode(pieces[1], StandardCharsets.UTF_8)));
            }
            return result;
        }

        private static void respond(@NonNull HttpExchange exchange, int status, @NonNull String text) throws IOException {
            byte[] body = text.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
        }

        @Override public void close() { releaseBody.countDown(); server.stop(0); executor.shutdownNow(); }
    }
}
