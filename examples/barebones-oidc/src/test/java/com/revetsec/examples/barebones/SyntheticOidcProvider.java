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
import com.revetsec.oidc.OidcClient;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

/** A real loopback discovery/JWKS/token server, with fresh synthetic signing keys and one-use PKCE codes. */
final class SyntheticOidcProvider implements AutoCloseable {
    static final @NonNull URI APP_ORIGIN = URI.create("https://localhost:8443");
    static final @NonNull String SUBJECT = "TEST-ONLY-private-subject";
    static final @NonNull String ACCESS = "TEST-ONLY-access-token";
    static final @NonNull String REFRESH = "TEST-ONLY-refresh-token";
    enum Mode { VALID, WRONG_NONCE, WRONG_ISSUER, WRONG_AUDIENCE, EXPIRED, BAD_SIGNATURE, OMIT_ID_TOKEN, SERVER_ERROR }
    final @NonNull AtomicInteger tokenPosts = new AtomicInteger();
    final @NonNull AtomicInteger keyGets = new AtomicInteger();
    private final @NonNull HttpServer server;
    private final @NonNull Clock clock;
    private final @NonNull KeyPair keys;
    private final @NonNull Map<@NonNull String, @NonNull Map<@NonNull String, @NonNull String>> codes = new HashMap<>();
    private volatile @NonNull Mode mode = Mode.VALID;
    private int sequence;

    SyntheticOidcProvider(@NonNull Clock clock) throws Exception {
        this.clock = clock;
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        this.keys = generator.generateKeyPair();
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127,0,0,1}), 0), 16);
        this.server.createContext("/.well-known/openid-configuration", exchange -> respond(exchange, 200, discovery()));
        this.server.createContext("/jwks", exchange -> { this.keyGets.incrementAndGet(); respond(exchange, 200, jwks()); });
        this.server.createContext("/token", this::exchange);
        this.server.start();
    }

    @NonNull URI issuer() { return URI.create("http://127.0.0.1:" + this.server.getAddress().getPort()); }
    void mode(@NonNull Mode value) { this.mode = value; }

    @NonNull OidcApplication application(int sessions, int pendingEntries,
                                         AuthorizationRequestOptions.@NonNull ResponseMode mode) {
        OidcClient client = OidcClient.withIssuer(issuer().toString()).clientId("example-client")
                .redirectUri(APP_ORIGIN.resolve("/callback")).clock(this.clock).clockSkew(Duration.ZERO)
                .pendingAuthorizationLifetime(Duration.ofMinutes(5)).allowInsecureLoopback(true)
                .requirePkceAdvertised(true).build();
        client.warmUp();
        return new OidcApplication(client, APP_ORIGIN, issuer(), this.clock, sessions,
                new PendingStore(this.clock, pendingEntries, 262_144), mode);
    }

    synchronized @NonNull String authorize(@NonNull URI uri) {
        Map<String, String> query = form(uri.getRawQuery());
        if (!uri.resolve("/authorize").equals(issuer().resolve("/authorize"))
                || !"example-client".equals(query.get("client_id"))
                || !APP_ORIGIN.resolve("/callback").toString().equals(query.get("redirect_uri"))
                || !"code".equals(query.get("response_type")) || !"openid".equals(query.get("scope"))
                || !"S256".equals(query.get("code_challenge_method"))
                || query.getOrDefault("nonce", "").length() != 43 || this.codes.size() >= 128)
            throw new IllegalArgumentException("Synthetic authorization request rejected");
        String code = "TEST-ONLY-code-" + ++this.sequence;
        this.codes.put(code, query);
        return "state=" + query.get("state") + "&code=" + code + "&iss=" + encode(issuer().toString());
    }

    private synchronized void exchange(@NonNull HttpExchange exchange) throws IOException {
        this.tokenPosts.incrementAndGet();
        byte[] bytes = exchange.getRequestBody().readNBytes(8193);
        Map<String, String> form = form(new String(bytes, StandardCharsets.UTF_8));
        Map<String, String> authorization = this.codes.remove(form.get("code"));
        boolean valid = bytes.length <= 8192 && exchange.getRequestMethod().equals("POST")
                && authorization != null && "authorization_code".equals(form.get("grant_type"))
                && "example-client".equals(form.get("client_id"))
                && authorization.get("redirect_uri").equals(form.get("redirect_uri"))
                && authorization.get("code_challenge").equals(challenge(form.getOrDefault("code_verifier", "")));
        if (!valid) { respond(exchange, 400, "{\"error\":\"invalid_grant\"}"); return; }
        if (this.mode == Mode.SERVER_ERROR) { respond(exchange, 503, "{\"error\":\"temporarily_unavailable\"}"); return; }
        String jwt;
        try { jwt = jwt(authorization.get("nonce")); }
        catch (GeneralSecurityException exception) { throw new IOException("Synthetic signing failed"); }
        respond(exchange, 200, "{\"access_token\":\"" + ACCESS + "\",\"refresh_token\":\"" + REFRESH
                + "\",\"token_type\":\"Bearer\"" + (this.mode == Mode.OMIT_ID_TOKEN ? "" : ",\"id_token\":\"" + jwt + "\"") + "}");
    }

    private @NonNull String discovery() {
        String base = issuer().toString();
        return "{\"issuer\":\"" + base + "\",\"authorization_endpoint\":\"" + base + "/authorize\","
                + "\"token_endpoint\":\"" + base + "/token\",\"jwks_uri\":\"" + base + "/jwks\","
                + "\"response_types_supported\":[\"code\"],\"subject_types_supported\":[\"public\"],"
                + "\"id_token_signing_alg_values_supported\":[\"RS256\"],\"code_challenge_methods_supported\":[\"S256\"],"
                + "\"token_endpoint_auth_methods_supported\":[\"none\"],\"authorization_response_iss_parameter_supported\":true}";
    }

    private @NonNull String jwks() {
        RSAPublicKey key = (RSAPublicKey) this.keys.getPublic();
        return "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"synthetic\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\""
                + unsigned(key.getModulus()) + "\",\"e\":\"" + unsigned(key.getPublicExponent()) + "\"}]}";
    }

    private @NonNull String jwt(@NonNull String nonce) throws GeneralSecurityException {
        long now = this.clock.instant().getEpochSecond();
        String issuer = this.mode == Mode.WRONG_ISSUER ? "https://attacker.example" : issuer().toString();
        String payload = "{\"iss\":\"" + issuer + "\",\"sub\":\"" + SUBJECT + "\",\"aud\":\""
                + (this.mode == Mode.WRONG_AUDIENCE ? "attacker-client" : "example-client") + "\",\"iat\":" + now
                + ",\"exp\":" + (this.mode == Mode.EXPIRED ? now - 1 : now + 240) + ",\"nonce\":\""
                + (this.mode == Mode.WRONG_NONCE ? "TEST-ONLY-other-nonce" : nonce) + "\"}";
        String input = b64("{\"alg\":\"RS256\",\"kid\":\"synthetic\"}".getBytes(StandardCharsets.UTF_8))
                + "." + b64(payload.getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(this.keys.getPrivate()); signature.update(input.getBytes(StandardCharsets.US_ASCII));
        byte[] signed = signature.sign();
        if (this.mode == Mode.BAD_SIGNATURE) signed[0] ^= 1;
        return input + "." + b64(signed);
    }

    private static @NonNull String challenge(@NonNull String verifier) {
        try { return b64(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII))); }
        catch (GeneralSecurityException exception) { throw new IllegalStateException("SHA-256 unavailable"); }
    }
    private static @NonNull String unsigned(@NonNull BigInteger value) {
        byte[] bytes = value.toByteArray(); return b64(bytes[0] == 0 ? Arrays.copyOfRange(bytes, 1, bytes.length) : bytes);
    }
    private static @NonNull String b64(byte @NonNull [] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static @NonNull String encode(@NonNull String value) { return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8); }
    static @NonNull Map<@NonNull String, @NonNull String> form(@Nullable String query) {
        Map<String, String> result = new HashMap<>();
        if (query == null) return result;
        for (String pair : query.split("&")) {
            String[] components = pair.split("=", 2);
            if (components.length != 2 || result.put(URLDecoder.decode(components[0], StandardCharsets.UTF_8),
                    URLDecoder.decode(components[1], StandardCharsets.UTF_8)) != null)
                throw new IllegalArgumentException("Synthetic form rejected");
        }
        return result;
    }
    private static void respond(@NonNull HttpExchange exchange, int status, @NonNull String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (exchange) { exchange.getResponseBody().write(bytes); }
    }
    @Override public void close() { this.server.stop(0); }
}
