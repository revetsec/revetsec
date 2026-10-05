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
package example.rsa;

import com.revetsec.jose.JwsAlgorithm;
import com.revetsec.oauth.AuthorizationServerMetadata;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.*;

/** Test-only independent JCA oracle and owned TLS fixture. No outgoing hosted-provider request. */
final class LocalProvider implements AutoCloseable {
	static final String TRUST = "https://login.microsoftonline.com/organizations/v2.0";
	static final String TEMPLATE = "https://login.microsoftonline.com/{tenantid}/v2.0";
	static final String TENANT = "11111111-2222-3333-4444-555555555555";
	static final String OTHER = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
	static final String ACCESS = "TEST-ONLY-example-access";
	static final String REFRESH = "TEST-ONLY-example-refresh";
	static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-03T12:00:00Z"), ZoneOffset.UTC);
	final AtomicInteger posts = new AtomicInteger();
	final AtomicInteger assertions = new AtomicInteger();
	final AtomicInteger userInfoCalls = new AtomicInteger();
	final Set<String> identifiers = ConcurrentHashMap.newKeySet();
	final List<String> audiences = new CopyOnWriteArrayList<>();
	volatile @Nullable Throwable failure;
	volatile String tenant = TENANT;
	volatile boolean missingKeyIssuer;
	volatile boolean forge;
	private final KeyPair issuerKey;
	private final KeyPair clientKey;
	private final JwsAlgorithm algorithm;
	private final boolean endpointAudience;
	private final boolean entra;
	private final HttpsServer server;
	private final HttpClient http;

	LocalProvider(@NonNull KeyPair clientKey, @NonNull JwsAlgorithm algorithm, boolean endpointAudience,
			boolean entra) throws Exception {
		this.clientKey = clientKey; this.algorithm = algorithm; this.endpointAudience = endpointAudience; this.entra = entra;
		this.issuerKey = freshKey();
		KeyStore store = KeyStore.getInstance("PKCS12");
		try (InputStream input = Files.newInputStream(Path.of(System.getProperty("example.tlsStore")))) {
			store.load(input, "changeit".toCharArray());
		}
		KeyManagerFactory km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		km.init(store, "changeit".toCharArray());
		TrustManagerFactory tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); tm.init(store);
		SSLContext context = SSLContext.getInstance("TLS"); context.init(km.getKeyManagers(), tm.getTrustManagers(), null);
		this.http = HttpClient.newBuilder().sslContext(context).followRedirects(HttpClient.Redirect.NEVER)
				.connectTimeout(Duration.ofSeconds(3)).build();
		this.server = HttpsServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}), 0), 16);
		this.server.setHttpsConfigurator(new HttpsConfigurator(context));
		this.server.createContext("/", this::respond); this.server.start();
	}

	static @NonNull KeyPair freshKey() throws GeneralSecurityException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); return generator.generateKeyPair();
	}
	@NonNull String issuer() { return this.entra ? TRUST : local().toString(); }
	@NonNull URI local() { return URI.create("https://localhost:" + this.server.getAddress().getPort()); }
	@NonNull URI endpoint(@NonNull String path) { return URI.create(issuer() + path); }
	@NonNull HttpClient httpClient() { return this.entra ? new RoutedClient(this.http, local()) : this.http; }
	@NonNull AuthorizationServerMetadata metadata() {
		return AuthorizationServerMetadata.withIssuer(issuer()).authorizationEndpoint(endpoint("/authorize"))
				.tokenEndpoint(endpoint("/token")).revocationEndpoint(endpoint("/revoke")).introspectionEndpoint(endpoint("/inspect"))
				.tokenEndpointAuthMethodsSupported(Set.of("private_key_jwt"))
				.revocationEndpointAuthMethodsSupported(Set.of("private_key_jwt"))
				.introspectionEndpointAuthMethodsSupported(Set.of("private_key_jwt"))
				.tokenEndpointAuthSigningAlgValuesSupported(Set.of(this.algorithm.getWireValue()))
				.revocationEndpointAuthSigningAlgValuesSupported(Set.of(this.algorithm.getWireValue()))
				.introspectionEndpointAuthSigningAlgValuesSupported(Set.of(this.algorithm.getWireValue())).build();
	}

	private void respond(@NonNull HttpExchange exchange) throws IOException {
		try {
			String path = exchange.getRequestURI().getRawPath(); String json;
			if (path.contains(".well-known")) json = discovery();
			else if (path.endsWith("/jwks")) json = jwks();
			else if (path.endsWith("/userinfo")) {
				this.userInfoCalls.incrementAndGet();
				check(List.of("Bearer " + ACCESS).equals(exchange.getRequestHeaders().get("Authorization")));
				json = "{\"sub\":\"TEST-ONLY-example-user\"}";
			} else {
				this.posts.incrementAndGet();
				check(exchange.getRequestMethod().equals("POST"));
				byte[] bytes = exchange.getRequestBody().readNBytes(16385); check(bytes.length <= 16384);
				Map<String,String> form = form(new String(bytes, StandardCharsets.UTF_8));
				check(!exchange.getRequestHeaders().containsKey("Authorization") && !form.containsKey("client_secret"));
				check("example-client".equals(form.get("client_id")));
				check("urn:ietf:params:oauth:client-assertion-type:jwt-bearer".equals(form.get("client_assertion_type")));
				verify(Objects.requireNonNull(form.get("client_assertion")), path);
				if (path.endsWith("/revoke")) json = "{}";
				else if (path.endsWith("/inspect")) json = "{\"active\":true,\"iss\":\"" + issuer() + "\",\"sub\":\"service\",\"aud\":\"https://resource.example\",\"exp\":" + CLOCK.instant().plusSeconds(300).getEpochSecond() + "}";
				else json = tokens(form);
			}
			write(exchange, 200, json);
		} catch (Exception | AssertionError problem) {
			this.failure = problem; write(exchange, 400, "{\"error\":\"invalid_request\"}");
		}
	}

	private @NonNull String discovery() {
		String base = issuer(); return "{\"issuer\":\"" + (this.entra ? TEMPLATE : base) + "\","
				+ "\"authorization_endpoint\":\"" + base + "/authorize\",\"token_endpoint\":\"" + base + "/token\","
				+ "\"jwks_uri\":\"" + base + "/jwks\",\"userinfo_endpoint\":\"" + base + "/userinfo\","
				+ "\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"],"
				+ "\"id_token_signing_alg_values_supported\":[\"RS256\"],\"code_challenge_methods_supported\":[\"S256\"],"
				+ "\"token_endpoint_auth_methods_supported\":[\"private_key_jwt\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"" + this.algorithm.getWireValue() + "\"]}";
	}
	private @NonNull String jwks() {
		RSAPublicKey key = (RSAPublicKey) this.issuerKey.getPublic();
		return "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"provider-key\","
				+ "\"n\":\"" + unsigned(key.getModulus()) + "\",\"e\":\"" + unsigned(key.getPublicExponent()) + "\""
				+ (this.missingKeyIssuer ? "" : ",\"issuer\":\"" + TEMPLATE + "\"") + "}]}";
	}
	private @NonNull String tokens(@NonNull Map<@NonNull String,@NonNull String> form) throws GeneralSecurityException {
		String jwt = "";
		if (this.entra) {
			String claims = "{\"iss\":\"" + actualIssuer(this.tenant) + "\",\"tid\":\"" + this.tenant
					+ "\",\"sub\":\"TEST-ONLY-example-user\",\"aud\":\"example-client\",\"iat\":" + CLOCK.instant().getEpochSecond()
					+ ",\"exp\":" + CLOCK.instant().plusSeconds(300).getEpochSecond()
					+ (form.get("grant_type").equals("authorization_code") ? ",\"nonce\":\"" + Objects.requireNonNull(form.get("code")) + "\"" : "") + "}";
			String input = b64("{\"alg\":\"RS256\",\"kid\":\"provider-key\"}".getBytes(StandardCharsets.UTF_8)) + "." + b64(claims.getBytes(StandardCharsets.UTF_8));
			Signature signer = Signature.getInstance("SHA256withRSA"); signer.initSign(this.issuerKey.getPrivate());
			signer.update(input.getBytes(StandardCharsets.US_ASCII)); byte[] signature = signer.sign(); if (this.forge) signature[0] ^= 1;
			jwt = ",\"id_token\":\"" + input + "." + b64(signature) + "\"";
		}
		return "{\"access_token\":\"" + ACCESS + "\",\"refresh_token\":\"" + REFRESH + "\",\"token_type\":\"Bearer\",\"expires_in\":300" + jwt + "}";
	}

	private void verify(@NonNull String compact, @NonNull String localPath) throws GeneralSecurityException {
		String[] parts = compact.split("\\.", -1); check(parts.length == 3);
		Signature signature = Signature.getInstance(this.algorithm == JwsAlgorithm.PS256 ? "RSASSA-PSS"
				: this.algorithm == JwsAlgorithm.RS384 ? "SHA384withRSA" : "SHA256withRSA");
		if (this.algorithm == JwsAlgorithm.PS256) signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
		signature.initVerify(this.clientKey.getPublic()); signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
		check(signature.verify(Base64.getUrlDecoder().decode(parts[2])));
		String header = decoded(parts[0]); String claims = decoded(parts[1]);
		check(header.equals("{\"alg\":\"" + this.algorithm.getWireValue() + "\",\"typ\":\"" + (this.endpointAudience ? "JWT" : "client-authentication+jwt") + "\",\"kid\":\"application-key\"}"));
		String audience = this.endpointAudience ? issuer() + (this.entra ? localPath.substring("/organizations/v2.0".length()) : localPath) : issuer();
		check(field(claims, "iss").equals("example-client") && field(claims, "sub").equals("example-client"));
		check(field(claims, "aud").equals(audience)); this.audiences.add(audience);
		long now = CLOCK.instant().getEpochSecond();
		check(number(claims, "iat") == now && number(claims, "nbf") == now && number(claims, "exp") == now + 60);
		String jti = field(claims, "jti"); check(Base64.getUrlDecoder().decode(jti).length == 32 && this.identifiers.add(jti));
		this.assertions.incrementAndGet();
	}
	private static @NonNull String field(@NonNull String json, @NonNull String name) {
		Matcher matcher = Pattern.compile("\"" + name + "\":\"([^\"]*)\"").matcher(json);
		check(matcher.find()); String value = matcher.group(1); check(!matcher.find()); return value;
	}
	private static long number(@NonNull String json, @NonNull String name) {
		Matcher matcher = Pattern.compile("\"" + name + "\":([0-9]+)").matcher(json); check(matcher.find());
		long value = Long.parseLong(matcher.group(1)); check(!matcher.find()); return value;
	}
	static @NonNull String actualIssuer(@NonNull String tenant) { return "https://login.microsoftonline.com/" + tenant + "/v2.0"; }
	static @NonNull Map<@NonNull String,@NonNull String> form(@Nullable String text) {
		Map<String,String> values = new HashMap<>(); if (text == null) return values;
		for (String pair : text.split("&")) {
			String[] parts = pair.split("=", 2); check(parts.length == 2);
			check(values.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8), URLDecoder.decode(parts[1], StandardCharsets.UTF_8)) == null);
		} return values;
	}
	private static @NonNull String decoded(@NonNull String segment) { return new String(Base64.getUrlDecoder().decode(segment), StandardCharsets.UTF_8); }
	private static @NonNull String unsigned(@NonNull BigInteger value) { byte[] bytes = value.toByteArray(); return b64(bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes); }
	private static @NonNull String b64(byte @NonNull [] bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
	private static void check(boolean condition) { if (!condition) throw new AssertionError("Synthetic provider check failed (values redacted)"); }
	private static void write(@NonNull HttpExchange exchange, int status, @NonNull String json) throws IOException {
		byte[] bytes = json.getBytes(StandardCharsets.UTF_8); exchange.getResponseHeaders().set("Content-Type", "application/json");
		exchange.sendResponseHeaders(status, bytes.length); try (exchange) { exchange.getResponseBody().write(bytes); }
	}
	@Override public void close() { this.server.stop(0); }

	/** Test-only exact Microsoft fixture routing; forbidden to use this client in an application. */
	private static final class RoutedClient extends HttpClient {
		private final HttpClient delegate; private final URI local;
		RoutedClient(@NonNull HttpClient delegate, @NonNull URI local) { this.delegate = delegate; this.local = local; }
		private @NonNull HttpRequest map(@NonNull HttpRequest request) {
			check(request.uri().toString().startsWith(TRUST + "/"));
			HttpRequest.Builder builder = HttpRequest.newBuilder(this.local.resolve(request.uri().getRawPath())).method(request.method(), request.bodyPublisher().orElseGet(HttpRequest.BodyPublishers::noBody));
			request.timeout().ifPresent(builder::timeout); request.headers().map().forEach((name, values) -> values.forEach(value -> builder.header(name, value))); return builder.build();
		}
		@Override public @NonNull Optional<@NonNull CookieHandler> cookieHandler() { return this.delegate.cookieHandler(); }
		@Override public @NonNull Optional<@NonNull Duration> connectTimeout() { return this.delegate.connectTimeout(); }
		@Override public @NonNull Redirect followRedirects() { return this.delegate.followRedirects(); }
		@Override public @NonNull Optional<@NonNull ProxySelector> proxy() { return this.delegate.proxy(); }
		@Override public @NonNull SSLContext sslContext() { return this.delegate.sslContext(); }
		@Override public @NonNull SSLParameters sslParameters() { return this.delegate.sslParameters(); }
		@Override public @NonNull Optional<@NonNull Authenticator> authenticator() { return this.delegate.authenticator(); }
		@Override public @NonNull Version version() { return this.delegate.version(); }
		@Override public @NonNull Optional<@NonNull Executor> executor() { return this.delegate.executor(); }
		@Override public <T> @NonNull HttpResponse<@NonNull T> send(@NonNull HttpRequest request, HttpResponse.@NonNull BodyHandler<@NonNull T> handler) throws IOException, InterruptedException { return this.delegate.send(map(request), handler); }
		@Override public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(@NonNull HttpRequest request, HttpResponse.@NonNull BodyHandler<@NonNull T> handler) { return this.delegate.sendAsync(map(request), handler); }
		@Override public <T> @NonNull CompletableFuture<@NonNull HttpResponse<@NonNull T>> sendAsync(@NonNull HttpRequest request, HttpResponse.@NonNull BodyHandler<@NonNull T> handler, HttpResponse.@NonNull PushPromiseHandler<@NonNull T> push) { return this.delegate.sendAsync(map(request), handler, push); }
	}
}
