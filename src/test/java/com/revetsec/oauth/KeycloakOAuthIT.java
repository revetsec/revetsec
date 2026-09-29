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
import com.revetsec.testing.TestSealers;
import com.revetsec.testing.TestTls;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Offline Keycloak 26.7.4 integration against the pinned local image and test-only realm. */
final class KeycloakOAuthIT {
	private static final String IMAGE = "quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c";
	private static final URI CALLBACK = URI.create("http://localhost:8080/callback");
	private static final Pattern LOGIN_FORM = Pattern.compile(
			"<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"", Pattern.DOTALL);
	private static GenericContainer<?> keycloak;
	private static String issuer;

	@BeforeAll
	static void startKeycloak() throws Exception {
		keycloak = new GenericContainer<>(DockerImageName.parse(IMAGE))
				.withExposedPorts(8443)
				.withEnv("KC_HEALTH_ENABLED", "true")
				.withCopyFileToContainer(MountableFile.forHostPath(Path.of("src/test/resources/tls/server.pem")
						.toAbsolutePath()), "/opt/keycloak/conf/tls/cert.pem")
				.withCopyFileToContainer(MountableFile.forHostPath(Path.of("src/test/resources/tls/server-key.pem")
						.toAbsolutePath()), "/opt/keycloak/conf/tls/key.pem")
				.withCopyFileToContainer(MountableFile.forHostPath(Path.of("interop/keycloak/revetsec-test-realm.json")
						.toAbsolutePath()), "/opt/keycloak/data/import/revetsec-test-realm.json")
				.withCommand("start", "--db=dev-file", "--hostname-strict=false", "--http-enabled=false",
						"--https-certificate-file=/opt/keycloak/conf/tls/cert.pem",
						"--https-certificate-key-file=/opt/keycloak/conf/tls/key.pem", "--import-realm")
				.waitingFor(Wait.forListeningPort().withStartupTimeout(Duration.ofMinutes(3)));
		keycloak.start();
		issuer = "https://localhost:" + keycloak.getMappedPort(8443) + "/realms/revetsec-test";
		HttpClient readinessClient = TestTls.httpClient();
		HttpRequest readinessRequest = HttpRequest.newBuilder(
				URI.create(issuer + "/.well-known/openid-configuration")).GET().build();
		HttpResponse<String> metadata = null;
		long stopAt = System.nanoTime() + Duration.ofMinutes(3).toNanos();
		do {
			metadata = readinessClient.send(readinessRequest, HttpResponse.BodyHandlers.ofString());
			if (metadata.statusCode() == 200) break;
			Thread.sleep(1_000);
		} while (System.nanoTime() < stopAt);
		assertEquals(200, metadata.statusCode(), metadata.body());
	}

	@AfterAll
	static void stopKeycloak() {
		if (keycloak != null) keycloak.stop();
	}

	@Test
	void confidentialAndPublicCodeFlowsRefreshAndRevocation() throws Exception {
		TokenResponse confidential = completeCodeFlow("revetsec-test-client",
				ClientAuthentication.fromClientSecretBasic("test-only-client-secret-not-a-real-secret"));
		assertFalse(confidential.getAccessToken().getValue().isEmpty());
		RefreshToken refresh = confidential.getRefreshToken().orElseThrow();
		OAuthClient confidentialClient = client("revetsec-test-client",
				ClientAuthentication.fromClientSecretBasic("test-only-client-secret-not-a-real-secret"));
		TokenResponse refreshed = confidentialClient.refresh(refresh, TokenRequestOptions.builder().build());
		assertFalse(refreshed.getAccessToken().getValue().isEmpty());
		confidentialClient.revoke(refreshed.getRefreshToken().orElse(refresh).getValue(),
				TokenTypeHint.REFRESH_TOKEN);
		TokenResponse publicTokens = completeCodeFlow("revetsec-public-client", ClientAuthentication.noneInstance());
		assertFalse(publicTokens.getAccessToken().getValue().isEmpty());
	}

	@Test
	void serviceAccountGetsToken() {
		OAuthClient service = client("revetsec-service-client",
				ClientAuthentication.fromClientSecretBasic("test-only-service-secret-not-a-real-secret"));
		TokenResponse tokens = service.requestClientCredentialsToken(TokenRequestOptions.builder().build());
		assertFalse(tokens.getAccessToken().getValue().isEmpty());
	}

	private static TokenResponse completeCodeFlow(String clientId, ClientAuthentication authentication)
			throws Exception {
		OAuthClient client = client(clientId, authentication);
		AuthorizationRedirect begin = client.beginAuthorization(
				AuthorizationRequestOptions.builder().scopes(Set.of("openid")).build());
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = begin.getPendingAuthorization().toSealedForm(sealer, clientId);
		HttpClient browser = TestTls.httpClientBuilder()
				.cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build();
		HttpResponse<String> page = browser.send(HttpRequest.newBuilder(begin.getAuthorizationUri()).GET().build(),
				HttpResponse.BodyHandlers.ofString());
		assertEquals(200, page.statusCode());
		Matcher form = LOGIN_FORM.matcher(page.body());
		assertTrue(form.find());
		URI action = URI.create(form.group(1).replace("&amp;", "&"));
		String loginBody = "username=" + encode("test-user") + "&password="
				+ encode("test-only-password-not-a-secret") + "&credentialId=";
		HttpResponse<String> login = browser.send(HttpRequest.newBuilder(action)
				.header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString(loginBody)).build(), HttpResponse.BodyHandlers.ofString());
		assertEquals(302, login.statusCode());
		URI location = URI.create(login.headers().firstValue("Location").orElseThrow());
		assertEquals(CALLBACK.getScheme(), location.getScheme());
		assertEquals(CALLBACK.getHost(), location.getHost());
		assertEquals(CALLBACK.getPath(), location.getPath());
		return client.completeAuthorization(AuthorizationResponse.fromQueryString(location.getRawQuery()),
				PendingAuthorizationSource.fromSealedForm(sealed, sealer, clientId), CALLBACK);
	}

	private static OAuthClient client(String id, ClientAuthentication authentication) {
		return OAuthClient.withIssuer(issuer).clientId(id).clientAuthentication(authentication)
				.redirectUri(CALLBACK).scopes(Set.of("openid"))
				.httpClient(TestTls.httpClient()).allowInsecureLoopback(true).build();
	}

	private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
}
