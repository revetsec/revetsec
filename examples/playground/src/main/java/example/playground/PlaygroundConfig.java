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

import com.revetsec.oauth.ClientAuthentication;
import com.revetsec.oauth.OAuthClient;
import com.revetsec.oauth.JwtAccessTokenValidator;
import com.revetsec.oauth.TokenIntrospectionClient;
import com.revetsec.oidc.OidcClient;
import com.revetsec.jose.JwsAlgorithm;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/** Trusted process origin and an immutable, application-owned provider selection. */
final class PlaygroundConfig {
    static final Set<@NonNull String> SCOPES = Set.of("mcp:discover", "mcp:whoami");
    final URI origin;
    final String issuer;
    final String clientId;
    final String secretReference;
    final String probeClientId;
    final String probeSecretReference;
    final String strategy;
    final boolean loopbackHttp;
    final boolean replayEnabled;
    final int httpPort;
    final int mcpPort;

    PlaygroundConfig(@NonNull URI origin, @NonNull String issuer, @NonNull String clientId,
            @NonNull String secretReference, @NonNull String probeClientId,
            @NonNull String probeSecretReference, @NonNull String strategy,
            boolean loopbackHttp, boolean replayEnabled, int httpPort, int mcpPort) {
        requireOrigin(origin);
        URI provider = URI.create(bounded(issuer, 512));
        if (!provider.isAbsolute() || provider.getHost() == null || provider.getUserInfo() != null
                || provider.getFragment() != null || provider.getQuery() != null
                || !(provider.getScheme().equals("https") || (loopbackHttp
                    && provider.getScheme().equals("http") && isLoopback(provider.getHost()))))
            throw new IllegalArgumentException("Provider issuer is invalid.");
        if (!strategy.equals("jwt") && !strategy.equals("introspection"))
            throw new IllegalArgumentException("Validation strategy is invalid.");
        if (httpPort < 0 || httpPort > 65535 || mcpPort < 0 || mcpPort > 65535)
            throw new IllegalArgumentException("Listener port is invalid.");
        this.origin = origin; this.issuer = issuer; this.clientId = bounded(clientId, 128);
        this.secretReference = bounded(secretReference, 512);
        this.probeClientId = bounded(probeClientId, 128);
        this.probeSecretReference = bounded(probeSecretReference, 512);
        this.strategy = strategy; this.loopbackHttp = loopbackHttp; this.replayEnabled = replayEnabled;
        this.httpPort = httpPort; this.mcpPort = mcpPort;
    }

    static @NonNull PlaygroundConfig fromEnvironment(@NonNull Map<@NonNull String, @NonNull String> env) {
        if (!env.getOrDefault("PLAYGROUND_BIND", "127.0.0.1").equals("127.0.0.1"))
            throw new IllegalArgumentException("All Playground listeners must bind IPv4 loopback.");
        return new PlaygroundConfig(URI.create(env.getOrDefault("PLAYGROUND_ORIGIN", "https://localhost:8443")),
                env.getOrDefault("PLAYGROUND_ISSUER", "https://localhost:9443"),
                env.getOrDefault("PLAYGROUND_CLIENT_ID", "revetsec-test-client"),
                env.getOrDefault("PLAYGROUND_SECRET_REFERENCE", "env:PLAYGROUND_CLIENT_SECRET"),
                env.getOrDefault("PLAYGROUND_PROBE_CLIENT_ID", "revetsec-test-client"),
                env.getOrDefault("PLAYGROUND_PROBE_SECRET_REFERENCE", "env:PLAYGROUND_CLIENT_SECRET"),
                env.getOrDefault("PLAYGROUND_VALIDATION", "jwt"),
                Boolean.parseBoolean(env.getOrDefault("PLAYGROUND_ALLOW_LOOPBACK_HTTP", "false")),
                Boolean.parseBoolean(env.getOrDefault("PLAYGROUND_REPLAY_JOURNAL", "false")),
                Integer.parseInt(env.getOrDefault("PLAYGROUND_HTTP_PORT", "8080")),
                Integer.parseInt(env.getOrDefault("PLAYGROUND_MCP_PORT", "8081")));
    }

    @NonNull PlaygroundConfig withForm(@NonNull Map<@NonNull String, @NonNull String> values) {
        return new PlaygroundConfig(origin, values.getOrDefault("issuer", issuer),
                values.getOrDefault("clientId", clientId), values.getOrDefault("secretReference", secretReference),
                values.getOrDefault("probeClientId", probeClientId),
                values.getOrDefault("probeSecretReference", probeSecretReference),
                values.getOrDefault("strategy", strategy), loopbackHttp, replayEnabled, httpPort, mcpPort);
    }

    @NonNull URI callbackUri() { return origin.resolve("/oidc/callback"); }
    @NonNull URI resourceUri() { return origin.resolve("/mcp"); }
    @NonNull URI metadataUri() { return origin.resolve("/.well-known/oauth-protected-resource/mcp"); }

    @NonNull OidcClient oidcClient(@NonNull HttpClient http) {
        return OidcClient.withIssuer(issuer).clientId(clientId).redirectUri(callbackUri())
                .clientAuthentication(authentication(secretReference)).scopes(Set.of("openid"))
                .idTokenSigningAlgorithms(Set.of(JwsAlgorithm.RS256)).httpClient(http)
                .allowInsecureLoopback(loopbackHttp).requestTimeout(Duration.ofSeconds(3))
                .totalDeadline(Duration.ofSeconds(5)).pendingAuthorizationLifetime(Duration.ofMinutes(3)).build();
    }

    @NonNull OAuthClient oauthClient(@NonNull HttpClient http, boolean probe) {
        return OAuthClient.withIssuer(issuer).clientId(probe ? probeClientId : clientId)
                .clientAuthentication(authentication(probe ? probeSecretReference : secretReference))
                .httpClient(http).allowInsecureLoopback(loopbackHttp)
                .requestTimeout(Duration.ofSeconds(3)).totalDeadline(Duration.ofSeconds(5)).build();
    }

    PlaygroundAdmission.@NonNull TokenValidator validator(@NonNull HttpClient http) {
        if (strategy.equals("jwt")) {
            JwtAccessTokenValidator validator = JwtAccessTokenValidator.withIssuer(issuer)
                    .expectedAudiences(Set.of(resourceUri().toString())).allowedAlgorithms(Set.of(JwsAlgorithm.RS256))
                    .httpClient(http).allowInsecureLoopback(loopbackHttp).requestTimeout(Duration.ofSeconds(3))
                    .totalDeadline(Duration.ofSeconds(5)).build();
            return validator::validateResult;
        }
        TokenIntrospectionClient validator = TokenIntrospectionClient.withOAuthClient(oauthClient(http, false))
                .expectedAudiences(Set.of(resourceUri().toString())).build();
        return validator::validateResult;
    }

    private static @NonNull ClientAuthentication authentication(@NonNull String reference) {
        return reference.equals("none") ? ClientAuthentication.noneInstance()
                : ClientAuthentication.fromClientSecretBasic(LocalSecrets.resolve(reference));
    }

    static boolean isLoopback(@NonNull String host) { return host.equals("localhost") || host.equals("127.0.0.1"); }
    static void requireOrigin(@NonNull URI origin) {
        if (!origin.getScheme().equals("https") || !isLoopback(origin.getHost() == null ? "" : origin.getHost())
                || origin.getUserInfo() != null || origin.getQuery() != null || origin.getFragment() != null
                || !(origin.getPath().isEmpty() || origin.getPath().equals("/")))
            throw new IllegalArgumentException("Playground requires a configured local HTTPS origin.");
    }
    private static @NonNull String bounded(@NonNull String text, int cap) {
        if (text.isBlank() || text.length() > cap || text.chars().anyMatch(c -> c < 32 || c == 127))
            throw new IllegalArgumentException("Configuration value is invalid.");
        return text;
    }
}
