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

import org.jspecify.annotations.NonNull;

import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.PortBinding;
import com.github.dockerjava.api.model.Ports;
import com.revetsec.StateSealer;
import com.revetsec.internal.encoding.QueryParameters;
import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.oidc.OidcAuthentication;
import com.revetsec.oidc.OidcAuthenticationOptions;
import com.revetsec.oidc.OidcClient;
import com.revetsec.oidc.OidcCompatibilityMode;
import com.revetsec.oidc.OidcObserver;
import com.revetsec.oidc.OidcRefreshResult;
import com.revetsec.oidc.OidcSessionReference;
import com.revetsec.oidc.OidcUserInfo;
import com.revetsec.oidc.OidcValidationException;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Offline Keycloak 26.7.4 integration against the pinned local image and test-only realm. */
final class KeycloakOAuthIT {
	private static final String IMAGE = "quay.io/keycloak/keycloak:26.7.4@sha256:82a77884f3af238beab1e7afd63b5f530e1b5c0590bd7aa60b40a40463e29b2c";
	private static final URI CALLBACK = URI.create("http://localhost:8080/callback");
	private static final String CLIENT_SECRET = "test-only-client-secret-not-a-real-secret";
	private static final String SIGNED_SECRET = "test-only-signed-userinfo-secret-not-a-real-secret";
	private static final String HMAC_SECRET = "test-only-hmac-client-secret-not-a-real-secret-" + "s".repeat(19);
	private static final Pattern POST_FORM = Pattern.compile("<form\\b[^>]*>(.*?)</form>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
	private static final Pattern INPUT = Pattern.compile("<input\\b[^>]*>", Pattern.CASE_INSENSITIVE);
	private static final Pattern LOGIN_FORM = Pattern.compile(
			"<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"", Pattern.DOTALL);
	private static GenericContainer<?> keycloak;
	private static String issuer;

	@BeforeAll
	static void startKeycloak() throws Exception {
		keycloak = new GenericContainer<>(DockerImageName.parse(IMAGE))
				.withExposedPorts(8443)
				.withCreateContainerCmdModifier(command -> requireNonNull(command.getHostConfig()).withPortBindings(
						new PortBinding(Ports.Binding.bindIp("127.0.0.1"), new ExposedPort(8443))))
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
		assertEquals("127.0.0.1", requireNonNull(keycloak.getContainerInfo().getNetworkSettings().getPorts()
				.getBindings().get(new ExposedPort(8443)))[0].getHostIp());
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

	@Test
	void confidentialOidcQueryChecksUserInfoAndRefresh() throws Exception {
		OidcClient client = oidcClient("revetsec-test-client", ClientAuthentication.fromClientSecretBasic(CLIENT_SECRET)).build();
		OidcAuthentication auth = authenticate(client, OidcAuthenticationOptions.builder().maxAge(Duration.ZERO).build(), "query");
		assertTrue(auth.getAuthenticationTime().isPresent());
		checkUserInfo(client, auth, false);
		checkRefresh(client, auth);
	}

	@Test
	void publicOidcFormPostChecksUserInfoAndRefresh() throws Exception {
		OidcClient client = oidcClient("revetsec-public-client", ClientAuthentication.noneInstance()).build();
		OidcAuthentication auth = authenticate(client, OidcAuthenticationOptions.builder()
				.responseMode(AuthorizationRequestOptions.ResponseMode.FORM_POST).build(), "public-form-post");
		checkUserInfo(client, auth, false);
		checkRefresh(client, auth);
	}

	@Test
	void confidentialPostOidcFormPostChecksUserInfoAndRefresh() throws Exception {
		OidcClient client = oidcClient("revetsec-test-client", ClientAuthentication.fromClientSecretPost(CLIENT_SECRET)).build();
		OidcAuthentication auth = authenticate(client, OidcAuthenticationOptions.builder()
				.responseMode(AuthorizationRequestOptions.ResponseMode.FORM_POST).build(), "confidential-form-post");
		checkUserInfo(client, auth, false);
		checkRefresh(client, auth);
	}

	@Test
	void signedUserInfoChecksConfiguredAlgorithmAndSubject() throws Exception {
		OidcClient client = oidcClient("revetsec-signed-userinfo-client", ClientAuthentication.fromClientSecretBasic(SIGNED_SECRET))
				.userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).build();
		OidcAuthentication auth = authenticate(client, OidcAuthenticationOptions.builder().build(), "signed-userinfo");
		checkUserInfo(client, auth, true);
		checkRefresh(client, auth);
	}

	@Test
	void signedUserInfoPolicyRejectsRealJsonResponse() throws Exception {
		OidcClient client = oidcClient("revetsec-test-client", ClientAuthentication.fromClientSecretBasic(CLIENT_SECRET))
				.userInfoSignedResponseAlgorithm(JwsAlgorithm.RS256).build();
		OidcAuthentication auth = authenticate(client, OidcAuthenticationOptions.builder().build(), "json-downgrade");
		OidcValidationException failure = assertThrows(OidcValidationException.class, () -> client.fetchUserInfo(auth));
		assertEquals(OidcValidationException.Reason.USERINFO_FORMAT_MISMATCH, failure.getReason());
		assertNull(failure.getCause());
	}

	@Test
	void hmacOidcRejectsProviderRealmKeySignature() throws Exception {
		// The pinned provider signs HS ID tokens with its realm MAC key, not the OIDC client_secret.
		AtomicInteger used = new AtomicInteger(); AtomicInteger completed = new AtomicInteger();
		AtomicReference<OidcValidationException> rejected = new AtomicReference<>();
		OidcClient client = oidcClient("revetsec-hmac-client", ClientAuthentication.fromClientSecretPost(HMAC_SECRET))
				.idTokenSigningAlgorithms(Set.of(JwsAlgorithm.HS256))
				.compatibility(Set.of(OidcCompatibilityMode.HMAC_ID_TOKENS))
				.observer(new OidcObserver() {
					@Override public void didUseCompatibilityMode(@NonNull OidcCompatibilityMode mode) { used.incrementAndGet(); }
					@Override public void didCompleteAuthentication() { completed.incrementAndGet(); }
					@Override public void didRejectIdToken(@NonNull OidcValidationException failure) { rejected.set(failure); }
				}).build();
		OidcValidationException failure = assertThrows(OidcValidationException.class,
				() -> authenticate(client, OidcAuthenticationOptions.builder().build(), "hmac-realm-key"));
		assertEquals(OidcValidationException.Reason.ID_TOKEN_SIGNATURE_INVALID, failure.getReason());
		assertSame(failure, rejected.get()); assertEquals(1, used.get()); assertEquals(0, completed.get()); assertNull(failure.getCause());
	}

	@Test
	void wrongOidcCallbackRouteRejectsBeforeTokenPost() throws Exception {
		AtomicInteger tokenPosts = new AtomicInteger();
		OidcClient client = oidcClient("revetsec-test-client", ClientAuthentication.fromClientSecretBasic(CLIENT_SECRET))
				.observer(new OidcObserver() {
					@Override public void willRequestEndpoint(@NonNull OAuthEndpoint endpoint, @NonNull URI uri) {
						if (endpoint == OAuthEndpoint.TOKEN) tokenPosts.incrementAndGet();
					}
				}).build();
		AuthorizationRedirect begin = client.beginAuthentication();
		AuthorizationResponse response = queryResponse(login(begin.getAuthorizationUri()));
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = begin.getPendingAuthorization().toSealedForm(sealer, "wrong-route");
		OAuthException failure = assertThrows(OAuthException.class, () -> client.completeAuthentication(response,
				PendingAuthorizationSource.fromSealedForm(sealed, sealer, "wrong-route"), URI.create("http://localhost:8080/wrong")));
		assertEquals(OAuthException.Reason.CALLBACK_URI_MISMATCH, failure.getReason());
		assertEquals(0, tokenPosts.get());
	}

	@Test
	void changedAuthorizationNonceRejectsProviderSignedIdToken() throws Exception {
		AtomicInteger completed = new AtomicInteger();
		AtomicReference<OidcValidationException> rejected = new AtomicReference<>();
		OidcClient client = oidcClient("revetsec-test-client", ClientAuthentication.fromClientSecretBasic(CLIENT_SECRET))
				.observer(new OidcObserver() {
					@Override public void didCompleteAuthentication() { completed.incrementAndGet(); }
					@Override public void didRejectIdToken(@NonNull OidcValidationException failure) { rejected.set(failure); }
				}).build();
		AuthorizationRedirect begin = client.beginAuthentication();
		String originalNonce = QueryParameters.parse(begin.getAuthorizationUri().getRawQuery()).getValues("nonce").get(0);
		URI changed = URI.create(begin.getAuthorizationUri().toString().replace("nonce=" + encode(originalNonce), "nonce=test-only-changed-nonce"));
		assertFalse(begin.getAuthorizationUri().equals(changed));
		AuthorizationResponse response = queryResponse(login(changed));
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = begin.getPendingAuthorization().toSealedForm(sealer, "nonce-change");
		OidcValidationException failure = assertThrows(OidcValidationException.class, () -> client.completeAuthentication(response,
				PendingAuthorizationSource.fromSealedForm(sealed, sealer, "nonce-change"), CALLBACK));
		assertEquals(OidcValidationException.Reason.NONCE_MISMATCH, failure.getReason());
		assertSame(failure, rejected.get()); assertEquals(0, completed.get()); assertNull(failure.getCause());
	}

	private static OidcClient.@NonNull Builder oidcClient(@NonNull String id, @NonNull ClientAuthentication authentication) {
		return OidcClient.withIssuer(issuer).clientId(id).clientAuthentication(authentication).redirectUri(CALLBACK)
				.scopes(Set.of("profile", "email")).httpClient(TestTls.httpClient()).allowInsecureLoopback(true);
	}

	private static @NonNull OidcAuthentication authenticate(@NonNull OidcClient client, @NonNull OidcAuthenticationOptions options, @NonNull String context) throws Exception {
		AuthorizationRedirect begin = client.beginAuthentication(options);
		QueryParameters parameters = QueryParameters.parse(begin.getAuthorizationUri().getRawQuery());
		assertEquals(1, parameters.getValues("nonce").size());
		assertEquals("S256", parameters.getValues("code_challenge_method").get(0));
		assertEquals(1, parameters.getValues("scope").get(0).split("openid", -1).length - 1);
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = begin.getPendingAuthorization().toSealedForm(sealer, context);
		HttpResponse<String> login = login(begin.getAuthorizationUri());
		AuthorizationResponse response = parameters.getValues("response_mode").equals(java.util.List.of("form_post"))
				? formPostResponse(login) : queryResponse(login);
		OidcAuthentication auth = client.completeAuthentication(response, PendingAuthorizationSource.fromSealedForm(sealed, sealer, context), CALLBACK);
		assertEquals(issuer, auth.getIssuer()); assertFalse(auth.getSubject().isEmpty());
		assertTrue(auth.getTokens().getParameter("id_token").isEmpty());
		assertFalse(auth.toString().contains(auth.getIdToken().toCompactSerialization()));
		return auth;
	}

	private static void checkUserInfo(@NonNull OidcClient client, @NonNull OidcAuthentication auth, boolean signed) {
		OidcUserInfo info = client.fetchUserInfo(auth);
		assertEquals(issuer, info.getIssuer()); assertEquals(auth.getSubject(), info.getSubject()); assertEquals(signed, info.isSigned());
		assertEquals("test-user@example.test", info.getEmail().orElseThrow()); assertTrue(info.getEmailVerified().orElseThrow());
	}

	private static void checkRefresh(@NonNull OidcClient client, @NonNull OidcAuthentication auth) {
		StateSealer sealer = TestSealers.fromFixedKey();
		OidcSessionReference original = OidcSessionReference.fromSerializedForm(auth.getSessionReference().toSerializedForm());
		OidcSessionReference stored = OidcSessionReference.fromSealedForm(original.toSealedForm(sealer, "keycloak-session", Duration.ofMinutes(5)), sealer, "keycloak-session");
		OidcRefreshResult result = client.refresh(auth.getTokens().getRefreshToken().orElseThrow(), stored);
		assertTrue(result.getIdToken().isPresent()); assertFalse(result.getTokens().getAccessToken().getValue().isEmpty());
		assertSame(stored, result.getSessionReference()); assertTrue(result.getTokens().getParameter("id_token").isEmpty());
		assertEquals(auth.getSubject(), result.getIdToken().orElseThrow().getClaims().getSubject().orElseThrow());
		assertFalse(result.toString().contains(result.getRefreshToken().getValue()));
	}

	private static @NonNull TokenResponse completeCodeFlow(@NonNull String clientId, @NonNull ClientAuthentication authentication) throws Exception {
		OAuthClient client = client(clientId, authentication);
		AuthorizationRedirect begin = client.beginAuthorization(AuthorizationRequestOptions.builder().scopes(Set.of("openid")).build());
		StateSealer sealer = TestSealers.fromFixedKey();
		String sealed = begin.getPendingAuthorization().toSealedForm(sealer, clientId);
		return client.completeAuthorization(queryResponse(login(begin.getAuthorizationUri())),
				PendingAuthorizationSource.fromSealedForm(sealed, sealer, clientId), CALLBACK);
	}

	private static @NonNull HttpResponse<@NonNull String> login(@NonNull URI authorization) throws Exception {
		HttpClient browser = TestTls.httpClientBuilder().cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL)).build();
		HttpResponse<String> page = browser.send(HttpRequest.newBuilder(authorization).GET().build(), HttpResponse.BodyHandlers.ofString());
		assertEquals(200, page.statusCode());
		Matcher form = LOGIN_FORM.matcher(page.body()); assertTrue(form.find());
		URI action = URI.create(form.group(1).replace("&amp;", "&"));
		assertEquals("https", action.getScheme()); assertEquals(URI.create(issuer).getAuthority(), action.getAuthority());
		String loginBody = "username=" + encode("test-user") + "&password=" + encode("test-only-password-not-a-secret") + "&credentialId=";
		return browser.send(HttpRequest.newBuilder(action).header("Content-Type", "application/x-www-form-urlencoded")
				.POST(HttpRequest.BodyPublishers.ofString(loginBody)).build(), HttpResponse.BodyHandlers.ofString());
	}

	private static @NonNull AuthorizationResponse queryResponse(@NonNull HttpResponse<@NonNull String> login) {
		assertEquals(302, login.statusCode());
		URI location = URI.create(login.headers().firstValue("Location").orElseThrow());
		assertEquals(CALLBACK.getScheme(), location.getScheme()); assertEquals(CALLBACK.getAuthority(), location.getAuthority());
		assertEquals(CALLBACK.getPath(), location.getPath()); assertNull(location.getRawFragment());
		return AuthorizationResponse.fromQueryString(location.getRawQuery());
	}

	// Test-only parser for the pinned Keycloak theme, not a general HTML implementation. The fixed callback is never visited.
	private static @NonNull AuthorizationResponse formPostResponse(@NonNull HttpResponse<@NonNull String> login) {
		assertEquals(200, login.statusCode());
		Matcher form = POST_FORM.matcher(login.body()); assertTrue(form.find());
		String opening = form.group().substring(0, form.group().indexOf('>') + 1);
		assertEquals("post", attribute(opening, "method").toLowerCase(java.util.Locale.ROOT));
		assertEquals(CALLBACK.toString(), attribute(opening, "action"));
		StringBuilder body = new StringBuilder(); Matcher input = INPUT.matcher(form.group(1));
		while (input.find()) {
			if (!attribute(input.group(), "type").equalsIgnoreCase("hidden")) continue;
			if (body.length() != 0) body.append('&');
			body.append(encode(attribute(input.group(), "name"))).append('=').append(encode(attribute(input.group(), "value")));
		}
		assertFalse(body.isEmpty());
		AuthorizationResponse response = AuthorizationResponse.fromFormBody(body.toString().getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8, null);
		assertEquals(AuthorizationRequestOptions.ResponseMode.FORM_POST, response.getResponseMode());
		assertTrue(response.getCode().isPresent()); assertTrue(response.getState().isPresent()); assertEquals(issuer, response.getIssuer().orElseThrow());
		return response;
	}

	private static @NonNull String attribute(@NonNull String tag, @NonNull String name) {
		Matcher value = Pattern.compile("\\b" + name + "=[\"']([^\"']*)[\"']", Pattern.CASE_INSENSITIVE).matcher(tag); assertTrue(value.find());
		return value.group(1).replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&");
	}

	private static @NonNull OAuthClient client(@NonNull String id, @NonNull ClientAuthentication authentication) {
		return OAuthClient.withIssuer(issuer).clientId(id).clientAuthentication(authentication)
				.redirectUri(CALLBACK).scopes(Set.of("openid"))
				.httpClient(TestTls.httpClient()).allowInsecureLoopback(true).build();
	}

	private static @NonNull String encode(@NonNull String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
}
