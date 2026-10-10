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

import com.soklet.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/** Runnable local application. Browser-facing HTTPS is provided by the pinned local edge recipe. */
public final class Playground {
    private Playground() {}

    public static void main(java.lang.@NonNull String @NonNull [] arguments) throws InterruptedException {
        PlaygroundConfig config = PlaygroundConfig.fromEnvironment(System.getenv());
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER).build();
        SafeViews views = new SafeViews(LocalSecrets.randomBytes());
        BrowserSessions sessions = new BrowserSessions(Clock.systemUTC(), 128);
        PlaygroundOidc oidc = new PlaygroundOidc(sessions, views, Clock.systemUTC());
        PlaygroundSaml saml = PlaygroundSaml.fromEnvironment(System.getenv(), config, sessions, views,
                Clock.systemUTC());
        PlaygroundResources resources = new PlaygroundResources(config, sessions, views, oidc, http, saml);
        try (Soklet soklet = Soklet.fromConfig(sokletConfig(config, resources, views))) {
            Runtime.getRuntime().addShutdownHook(new Thread(soklet::close, "playground-shutdown"));
            soklet.start();
            System.out.println("Revetsec Playground: local developer demonstration; HTTPS edge required.");
            soklet.awaitShutdown();
        }
    }

    static @NonNull SokletConfig sokletConfig(@NonNull PlaygroundConfig config,
            @NonNull PlaygroundResources resources, @NonNull SafeViews views) {
        Set<McpProtocolVersion> versions = Set.of(McpProtocolVersion.V2025_06_18,
                McpProtocolVersion.V2025_11_25, McpProtocolVersion.V2026_07_28);
        McpToolRegistration<McpJsonObject> whoami = McpToolRegistration.withName("whoami", versions)
                .jsonObjectArguments().handler((context, arguments, features) -> whoami(context, arguments.getRawArguments(), views))
                .description("Return only the application's redacted checked identity for local/self").build();
        McpEndpoint endpoint = McpEndpoint.withPath("/mcp", McpImplementation.withNameAndVersion("Revetsec Playground", "1.0.0").build(), versions)
                .toolRegistrations(List.of(whoami)).build();
        McpServer mcp = McpServer.withPort(config.mcpPort).host("127.0.0.1")
                .endpointRegistry(McpEndpointRegistry.fromEndpoints(List.of(endpoint)))
                .admissionController(new PlaygroundAdmission(resources::profile, views))
                .toolRateLimiter(McpRateLimiter.fromInMemoryDefaults())
                .corsAuthorizer(CorsAuthorizer.fromWhitelistedOrigins(Set.of(config.origin.toString())))
                .allowedHosts(Set.copyOf(List.of("127.0.0.1", config.origin.getHost())))
                .requestTimeout(Duration.ofSeconds(8)).requestHandlerConcurrency(8).requestHandlerQueueCapacity(16)
                .maximumRequestSizeInBytes(16_384).build();
        HttpServer server = HttpServer.withPort(config.httpPort).host("127.0.0.1")
                .maximumRequestBodySizeInBytes(16_384).maximumRequestSizeInBytes(32_768)
                .requestHandlerTimeout(Duration.ofSeconds(15)).requestHandlerConcurrency(8).requestHandlerQueueCapacity(16).build();
        return SokletConfig.withHttpServer(server).mcpServer(mcp)
                .resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(PlaygroundResources.class)))
                .instanceProvider(new InstanceProvider() {
                    @Override public <@NonNull T> @NonNull T provide(@NonNull Class<@NonNull T> type) {
                        if (type.equals(PlaygroundResources.class)) return type.cast(resources);
                        return InstanceProvider.defaultInstance().provide(type);
                    }
                })
                .corsAuthorizer(CorsAuthorizer.fromWhitelistAuthorizer(origin -> {
                    PlaygroundConfig current = resources.profile().config;
                    URI provider = URI.create(current.issuer);
                    return origin.equals(current.origin.toString())
                            || origin.equals(provider.getScheme() + "://" + provider.getRawAuthority());
                }))
                .lifecycleObserver(new LifecycleObserver() {
                    @Override public void didReceiveLogEvent(@NonNull LogEvent event) {
                        // Fixed bounded vocabulary only. Never delegate message/request/throwable logging.
                        System.err.println("Playground framework event: " + event.getLogEventType().name());
                    }
                }).build();
    }

    static @NonNull McpCompleteResult whoami(@NonNull McpRequestContext context,
            @NonNull McpJsonObject arguments, @NonNull SafeViews views) {
        Object raw = context.getAdmissionIdentity().getPrincipal().orElse(null);
        if (!(raw instanceof PlaygroundAdmission.Principal principal))
            return McpCompleteResult.fromToolErrorText("Operation not permitted");
        String tenant = argument(arguments, "tenant", "local");
        String object = argument(arguments, "object", "self");
        if (!tenant.equals("local") || !object.equals("self")
                || !Set.of("tenant", "object").containsAll(arguments.getMembers().keySet()))
            return McpCompleteResult.fromToolErrorText("Operation not permitted");
        return McpCompleteResult.fromToolText(views.checked(principal.proof).toJson());
    }

    private static @NonNull String argument(@NonNull McpJsonObject arguments,
            @NonNull String name, @NonNull String fallback) {
        McpJsonValue value = arguments.find(name).orElse(null);
        return value == null ? fallback : value instanceof McpJsonString string ? string.getValue() : "denied";
    }
}
