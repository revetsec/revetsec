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
package com.revetsec.oauth;

import com.revetsec.StateSealer;
import com.revetsec.internal.json.JsonCodec;
import com.revetsec.internal.json.JsonLimits;
import com.revetsec.json.*;
import com.revetsec.testing.TestSealers;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.*;

/** Profile-only providers with fresh SAN-correct TLS and no global trust changes. */
final class ResourceProviderFixturesIT implements AutoCloseable {
	static final String NODE_IMAGE = System.getProperty("revetsec.nodeProviderImage", "revetsec-interop/node-oidc-provider:local");
	static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c";
	static final String RESOURCE = "https://resource.example.test/mcp";
	static final String INTROSPECTION_RESOURCE = "https://resource.example.test/introspection";
	static final URI CALLBACK = URI.create("http://localhost:8080/callback");
	static final String NODE_CLIENT = "revetsec-test-client";
	static final String NODE_SECRET = "test-only-client-secret-not-a-real-secret";
	static final String KEYCLOAK_SECRET = "test-only-resource-client-secret-not-a-real-secret";
	private final @NonNull Path tlsDirectory;
	private final @NonNull SSLContext sslContext;
	private final @NonNull GenericContainer<?> container;
	private final @NonNull String issuer;

	private ResourceProviderFixturesIT(boolean node) throws Exception { this(node, null); }

	private ResourceProviderFixturesIT(boolean node, @Nullable JsonArray assertionClients) throws Exception {
		this.tlsDirectory = Files.createTempDirectory("revetsec-resource-provider-tls-");
		Path storeFile = this.tlsDirectory.resolve("server.p12");
		Process keytool = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
				"-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048", "-sigalg", "SHA256withRSA",
				"-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-ext", "EKU=serverAuth",
				"-validity", "2", "-storetype", "PKCS12", "-keystore", storeFile.toString(),
				"-storepass", "test-only-tls-password", "-keypass", "test-only-tls-password", "-noprompt")
				.redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
		assertEquals(0, keytool.waitFor(), "fresh local TLS certificate generation");
		KeyStore store = KeyStore.getInstance("PKCS12");
		try (var input = Files.newInputStream(storeFile)) { store.load(input, "test-only-tls-password".toCharArray()); }
		writePem(this.tlsDirectory.resolve("cert.pem"), "CERTIFICATE", requireNonNull(store.getCertificate("server")).getEncoded());
		writePem(this.tlsDirectory.resolve("key.pem"), "PRIVATE KEY", requireNonNull(store.getKey("server", "test-only-tls-password".toCharArray())).getEncoded());
		KeyStore trust = KeyStore.getInstance("PKCS12"); trust.load(null, null);
		trust.setCertificateEntry("ephemeral-local-provider", store.getCertificate("server"));
		TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); factory.init(trust);
		this.sslContext = SSLContext.getInstance("TLS"); this.sslContext.init(null, factory.getTrustManagers(), null);
		int port;
		try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByAddress(new byte[]{127, 0, 0, 1}))) { port = socket.getLocalPort(); }
		int innerPort = node ? 3000 : 8443;
		this.issuer = "https://localhost:" + port + (node ? "" : "/realms/revetsec-resource-test");
		this.container = new GenericContainer<>(DockerImageName.parse(node ? NODE_IMAGE : KEYCLOAK_IMAGE))
				.withImagePullPolicy(image -> false).withExposedPorts(innerPort)
				.withCreateContainerCmdModifier(command -> requireNonNull(command.getHostConfig()).withPortBindings(
						new PortBinding(Ports.Binding.bindIpAndPort("127.0.0.1", port), new ExposedPort(innerPort))))
				.withCopyFileToContainer(MountableFile.forHostPath(this.tlsDirectory.resolve("cert.pem"), 0644), "/tmp/provider-cert.pem")
				.withCopyFileToContainer(MountableFile.forHostPath(this.tlsDirectory.resolve("key.pem"), 0644), "/tmp/provider-key.pem")
				.waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(3)));
		if (node) {
			this.container.withEnv("ISSUER", this.issuer).withEnv("TEST_RESOURCE_MODE", "m5")
					.withEnv("TLS_CERT_FILE", "/tmp/provider-cert.pem").withEnv("TLS_KEY_FILE", "/tmp/provider-key.pem")
					.withCopyFileToContainer(MountableFile.forHostPath(Path.of("interop/node-oidc-provider/server.js").toAbsolutePath()), "/app/server.js");
			if (assertionClients != null) {
				Path clients = this.tlsDirectory.resolve("assertion-clients.json");
				Files.write(clients, JsonCodec.toUtf8Bytes(assertionClients));
				this.container.withEnv("TEST_ASSERTION_CLIENTS_FILE", "/tmp/assertion-clients.json")
						.withCopyFileToContainer(MountableFile.forHostPath(clients), "/tmp/assertion-clients.json");
			}
		} else {
			this.container.withCopyFileToContainer(MountableFile.forClasspathResource("interop/m5/keycloak-resource-realm.json"),
					"/opt/keycloak/data/import/revetsec-resource-test-realm.json")
					.withCommand("start", "--db=dev-file", "--hostname-strict=false", "--http-enabled=false",
							"--https-certificate-file=/tmp/provider-cert.pem", "--https-certificate-key-file=/tmp/provider-key.pem", "--import-realm");
			if (assertionClients != null) {
				JsonObject realm;
				try (var input = requireNonNull(ResourceProviderFixturesIT.class.getResourceAsStream("/interop/m5/keycloak-resource-realm.json"))) {
					realm = (JsonObject) JsonCodec.parse(input.readAllBytes(), JsonLimits.protocolDocument(1024 * 1024));
				}
				var combined = new java.util.ArrayList<JsonValue>(((JsonArray) realm.getMembers().get("clients")).getElements());
				combined.addAll(assertionClients.getElements());
				var replacement = JsonObject.builder();
				for (var entry : realm.getMembers().entrySet())
					replacement.put(entry.getKey(), entry.getKey().equals("clients") ? JsonArray.fromElements(combined) : entry.getValue());
				Path importFile = this.tlsDirectory.resolve("assertion-realm.json");
				Files.write(importFile, JsonCodec.toUtf8Bytes(replacement.build()));
				this.container.withCopyFileToContainer(MountableFile.forHostPath(importFile),
						"/opt/keycloak/data/import/revetsec-resource-test-realm.json");
			}
		}
		try {
			this.container.start();
			if (node) {
				var version = this.container.execInContainer("node", "-p", "require('/app/node_modules/oidc-provider/package.json').version");
				assertEquals(0, version.getExitCode()); assertEquals("9.12.2", version.getStdout().trim());
			}
			assertEquals("127.0.0.1", requireNonNull(this.container.getContainerInfo().getNetworkSettings().getPorts()
					.getBindings().get(new ExposedPort(innerPort)))[0].getHostIp());
			awaitReady();
		} catch (Exception | AssertionError failure) {
			this.container.stop(); deleteTls(); throw failure;
		}
	}

	static @NonNull ResourceProviderFixturesIT fromNode() throws Exception { return new ResourceProviderFixturesIT(true); }
	static @NonNull ResourceProviderFixturesIT fromKeycloak() throws Exception { return new ResourceProviderFixturesIT(false); }
	static @NonNull ResourceProviderFixturesIT fromNode(@NonNull JsonArray clients) throws Exception { return new ResourceProviderFixturesIT(true, requireNonNull(clients)); }
	static @NonNull ResourceProviderFixturesIT fromKeycloak(@NonNull JsonArray clients) throws Exception { return new ResourceProviderFixturesIT(false, requireNonNull(clients)); }
	@NonNull String issuer() { return this.issuer; }
	@NonNull HttpClient httpClient() { return httpClientBuilder().build(); }
	private HttpClient.@NonNull Builder httpClientBuilder() {
		return HttpClient.newBuilder().sslContext(this.sslContext).followRedirects(HttpClient.Redirect.NEVER)
				.connectTimeout(Duration.ofSeconds(10)).version(HttpClient.Version.HTTP_1_1);
	}
	@NonNull OAuthClient client(@NonNull String id, @NonNull String secret, @Nullable OAuthObserver observer) {
		return OAuthClient.withIssuer(this.issuer).clientId(id).clientAuthentication(ClientAuthentication.fromClientSecretBasic(secret))
				.redirectUri(CALLBACK).httpClient(httpClient()).allowInsecureLoopback(true).observer(observer).build();
	}
	@NonNull JwtAccessTokenValidator validator() {
		return JwtAccessTokenValidator.withIssuer(this.issuer).expectedAudiences(Set.of(RESOURCE))
				.httpClient(httpClient()).allowInsecureLoopback(true).build();
	}
	static @NonNull BearerToken bearer(@NonNull TokenResponse token) {
		return BearerToken.fromAuthorizationHeaderValues(List.of("Bearer " + token.getAccessToken().getValue())).orElseThrow();
	}
	@NonNull TokenResponse nodeCredentials(@NonNull OAuthClient client) {
		return client.requestClientCredentialsToken(TokenRequestOptions.builder().resources(List.of(URI.create(RESOURCE)))
				.scopes(Set.of("read")).build());
	}
	@NonNull TokenResponse nodeOpaqueCredentials(@NonNull OAuthClient client) {
		return client.requestClientCredentialsToken(TokenRequestOptions.builder().resources(List.of(URI.create(INTROSPECTION_RESOURCE)))
				.scopes(Set.of("read")).build());
	}
	@NonNull TokenResponse codeFlow(@NonNull OAuthClient client, boolean node) throws Exception {
		return codeFlow(client, node, Set.of("openid", "read"));
	}
	@NonNull TokenResponse codeFlow(@NonNull OAuthClient client, boolean node, @NonNull Set<@NonNull String> scopes) throws Exception {
		AuthorizationRequestOptions options = node
				? AuthorizationRequestOptions.builder().scopes(scopes).prompt(scopes.contains("offline_access") ? "consent" : null).resources(List.of(URI.create(RESOURCE))).build()
				: AuthorizationRequestOptions.builder().scopes(scopes).prompt(scopes.contains("offline_access") ? "consent" : null).build();
		AuthorizationRedirect begin = client.beginAuthorization(options);
		HttpClient browser = httpClientBuilder().cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build();
		URI next = begin.getAuthorizationUri();
		for (int step = 0; step < 12; step++) {
			assertEquals(URI.create(this.issuer).getAuthority(), next.getAuthority()); assertEquals("https", next.getScheme());
			HttpResponse<String> response = browser.send(HttpRequest.newBuilder(next).timeout(Duration.ofSeconds(30)).GET().build(), HttpResponse.BodyHandlers.ofString());
			if (!node && response.statusCode() == 200) {
				Matcher form = Pattern.compile("<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"", Pattern.DOTALL).matcher(response.body());
				assertTrue(form.find(), "fixed local Keycloak login form");
				URI action = URI.create(form.group(1).replace("&amp;", "&"));
				assertEquals(URI.create(this.issuer).getAuthority(), action.getAuthority()); assertEquals("https", action.getScheme());
				response = browser.send(HttpRequest.newBuilder(action).timeout(Duration.ofSeconds(30))
						.header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(
								"username=" + encode("test-user") + "&password=" + encode("test-only-password-not-a-secret") + "&credentialId="))
						.build(), HttpResponse.BodyHandlers.ofString());
			}
			assertTrue(Set.of(302, 303).contains(response.statusCode()), "local provider redirect required");
			next = next.resolve(response.headers().firstValue("Location").orElseThrow());
			if (next.getAuthority().equals(CALLBACK.getAuthority())) {
				assertEquals(CALLBACK.getScheme(), next.getScheme()); assertEquals(CALLBACK.getRawPath(), next.getRawPath());
				assertNull(next.getRawFragment());
				StateSealer sealer = TestSealers.fromFixedKey();
				String sealed = begin.getPendingAuthorization().toSealedForm(sealer, "resource-provider-test");
				return client.completeAuthorization(AuthorizationResponse.fromQueryString(next.getRawQuery()),
						PendingAuthorizationSource.fromSealedForm(sealed, sealer, "resource-provider-test"), CALLBACK);
			}
		}
		throw new AssertionError("local provider exceeded redirect bound");
	}
	void restartNode() throws Exception {
		this.container.getDockerClient().restartContainerCmd(this.container.getContainerId()).withTimeout(5).exec();
		awaitReady();
	}
	private void awaitReady() throws Exception {
		HttpClient http = httpClient(); long deadline = System.nanoTime() + Duration.ofMinutes(3).toNanos();
		do {
			try {
				HttpResponse<String> response = http.send(HttpRequest.newBuilder(URI.create(this.issuer + "/.well-known/openid-configuration"))
						.timeout(Duration.ofSeconds(5)).GET().build(), HttpResponse.BodyHandlers.ofString());
				if (response.statusCode() == 200) return;
			} catch (java.io.IOException failure) {
				if (!this.container.isRunning()) throw new IllegalStateException("The local provider stopped during readiness", failure);
			}
			Thread.sleep(250);
		} while (System.nanoTime() < deadline);
		throw new AssertionError("local provider readiness deadline exceeded");
	}
	private static void writePem(@NonNull Path path, @NonNull String label, byte @NonNull [] encoded) throws Exception {
		Files.writeString(path, "-----BEGIN " + label + "-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded)
				+ "\n-----END " + label + "-----\n", StandardCharsets.US_ASCII);
	}
	private static @NonNull String encode(@NonNull String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
	private void deleteTls() throws java.io.IOException {
		try (var paths = Files.walk(this.tlsDirectory)) {
			for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(path);
		}
	}
	@Override public void close() throws java.io.IOException {
		try { this.container.stop(); } finally { deleteTls(); }
	}
}
