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

import org.jspecify.annotations.NonNull;

import java.io.InputStream;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * Tier-1 spike check (test-only): can a JDK-only driver, {@code java.net.http} plus
 * {@code java.net.CookieManager} and no browser, log in to Keycloak through its login
 * form and exchange the code? That is the headless recipe planned for the gating
 * Keycloak legs.
 * <p>
 * Run with the single-file launcher, no Maven:
 * {@code java KeycloakJdkLogin.java <realm-issuer> <client-id> <client-secret> <redirect-uri> <username> <password> [ca.pem]}.
 * Exit status 0 means the code exchange returned an ID token. The redirect URI is
 * never contacted. The ID token is not verified; this only proves the flow.
 */
public class KeycloakJdkLogin {
	private static final Pattern LOGIN_FORM = Pattern.compile("<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"", Pattern.DOTALL);

	public static void main(@NonNull String @NonNull [] args) throws Exception {
		if (args.length < 6) {
			System.err.println("usage: java KeycloakJdkLogin.java <realm-issuer> <client-id> <client-secret> <redirect-uri> <username> <password> [ca.pem]");
			System.exit(64);
		}
		String issuer = args[0];
		String clientId = args[1];
		String clientSecret = args[2];
		String redirectUri = args[3];

		HttpClient.Builder builder = HttpClient.newBuilder()
			.followRedirects(HttpClient.Redirect.NEVER)
			.cookieHandler(new CookieManager(null, CookiePolicy.ACCEPT_ALL));
		if (args.length > 6) {
			builder.sslContext(trusting(Path.of(args[6])));
		}
		HttpClient client = builder.build();

		SecureRandom random = new SecureRandom();
		String verifier = randomToken(random, 32);
		String challenge = Base64.getUrlEncoder().withoutPadding()
			.encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
		String state = randomToken(random, 16);

		String authorize = issuer + "/protocol/openid-connect/auth?response_type=code"
			+ "&client_id=" + encode(clientId)
			+ "&redirect_uri=" + encode(redirectUri)
			+ "&scope=openid&state=" + state
			+ "&nonce=" + randomToken(random, 16)
			+ "&code_challenge=" + challenge + "&code_challenge_method=S256";
		HttpResponse<String> page = client.send(HttpRequest.newBuilder(URI.create(authorize)).build(), HttpResponse.BodyHandlers.ofString());
		Matcher form = LOGIN_FORM.matcher(page.body());
		if (page.statusCode() != 200 || !form.find()) {
			fail("authorization endpoint returned HTTP " + page.statusCode() + " without the login form");
		}

		HttpResponse<String> login = client.send(HttpRequest.newBuilder(URI.create(form.group(1).replace("&amp;", "&")))
			.header("Content-Type", "application/x-www-form-urlencoded")
			.POST(HttpRequest.BodyPublishers.ofString("username=" + encode(args[4]) + "&password=" + encode(args[5]) + "&credentialId="))
			.build(), HttpResponse.BodyHandlers.ofString());
		String location = login.headers().firstValue("Location").orElse("");
		if (login.statusCode() != 302 || !location.startsWith(redirectUri + "?")) {
			fail("login form POST returned HTTP " + login.statusCode() + " instead of a redirect to the client");
		}
		Matcher code = Pattern.compile("[?&]code=([^&]+)").matcher(location);
		if (!location.contains("state=" + state) || !code.find()) {
			fail("redirect lacks the expected state or a code");
		}

		String basic = Base64.getEncoder().encodeToString(
			(encode(clientId) + ":" + encode(clientSecret)).getBytes(StandardCharsets.UTF_8));
		HttpResponse<String> token = client.send(HttpRequest.newBuilder(URI.create(issuer + "/protocol/openid-connect/token"))
			.header("Authorization", "Basic " + basic)
			.header("Content-Type", "application/x-www-form-urlencoded")
			.POST(HttpRequest.BodyPublishers.ofString("grant_type=authorization_code&code=" + code.group(1)
				+ "&redirect_uri=" + encode(redirectUri) + "&code_verifier=" + verifier))
			.build(), HttpResponse.BodyHandlers.ofString());
		if (token.statusCode() != 200 || !token.body().contains("\"id_token\"")) {
			fail("token endpoint returned HTTP " + token.statusCode() + " without an id_token");
		}
		System.out.println("ok: JDK " + Runtime.version().feature() + " java.net.http + CookieManager login form, code exchange returned an id_token");
	}

	private static @NonNull SSLContext trusting(@NonNull Path caPem) throws Exception {
		KeyStore trustStore = KeyStore.getInstance("PKCS12");
		trustStore.load(null, null);
		try (InputStream in = Files.newInputStream(caPem)) {
			trustStore.setCertificateEntry("ca", CertificateFactory.getInstance("X.509").generateCertificate(in));
		}
		TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		factory.init(trustStore);
		SSLContext context = SSLContext.getInstance("TLS");
		context.init(null, factory.getTrustManagers(), null);
		return context;
	}

	private static @NonNull String randomToken(@NonNull SecureRandom random, int bytes) {
		byte[] value = new byte[bytes];
		random.nextBytes(value);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
	}

	private static @NonNull String encode(@NonNull String value) {
		return URLEncoder.encode(value, StandardCharsets.UTF_8);
	}

	private static void fail(@NonNull String message) {
		System.out.println("FAIL: JDK " + Runtime.version().feature() + ": " + message);
		System.exit(1);
	}
}
