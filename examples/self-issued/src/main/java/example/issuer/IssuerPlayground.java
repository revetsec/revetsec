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
package example.issuer;

import com.soklet.*;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/** Runnable self-issued MCP application. Fresh volatile state is intentionally discarded at every restart. */
public final class IssuerPlayground {
    private IssuerPlayground() {}
    public static void main(java.lang.@NonNull String @NonNull [] args) throws Exception {
        IssuerConfig config=IssuerConfig.fromEnvironment(System.getenv());
        IssuerResources resources=new IssuerResources(config,Clock.systemUTC());
        try(Soklet soklet=Soklet.fromConfig(sokletConfig(resources))) {
            Runtime.getRuntime().addShutdownHook(new Thread(soklet::close,"issuer-demo-shutdown"));
            soklet.start();System.out.println("Self-issued MCP Playground: fresh volatile local demonstration.");soklet.awaitShutdown();
        }
    }
    static @NonNull SokletConfig sokletConfig(@NonNull IssuerResources app) {
        Set<McpProtocolVersion> versions=Set.of(McpProtocolVersion.V2025_06_18,McpProtocolVersion.V2025_11_25,McpProtocolVersion.V2026_07_28);
        McpToolRegistration<McpJsonObject> tool=McpToolRegistration.withName("whoami",versions).jsonObjectArguments()
                .handler((context,args,features) -> whoami(context,args.getRawArguments()))
                .description("Return an application-redacted checked identity for local/self only").build();
        McpEndpoint endpoint=McpEndpoint.withPath("/mcp",McpImplementation.withNameAndVersion("Self-issued Revetsec Playground","1.0.0").build(),versions)
                .toolRegistrations(List.of(tool)).build();
        McpServer mcp=McpServer.withPort(app.config.mcpPort).host("127.0.0.1")
                .endpointRegistry(McpEndpointRegistry.fromEndpoints(List.of(endpoint))).admissionController(new IssuerAdmission(app))
                .toolRateLimiter(McpRateLimiter.fromInMemoryDefaults()).allowedHosts(Set.of(app.config.resource.getHost()))
                .corsAuthorizer(CorsAuthorizer.fromWhitelistedOrigins(Set.of(app.config.origin.toString())))
                .requestTimeout(Duration.ofSeconds(8)).requestHandlerConcurrency(8).requestHandlerQueueCapacity(16).maximumRequestSizeInBytes(16_384).build();
        HttpServer http=HttpServer.withPort(app.config.httpPort).host("127.0.0.1").maximumRequestBodySizeInBytes(16_384)
                .maximumRequestSizeInBytes(32_768).requestHandlerTimeout(Duration.ofSeconds(15)).requestHandlerConcurrency(8).requestHandlerQueueCapacity(16).build();
        String clientOrigin=app.config.redirect.getScheme()+"://"+app.config.redirect.getRawAuthority();
        return SokletConfig.withHttpServer(http).mcpServer(mcp).resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(IssuerResources.class)))
                .instanceProvider(new InstanceProvider() {
                    @Override public <@NonNull T> @NonNull T provide(@NonNull Class<@NonNull T> type) {
                        return type.equals(IssuerResources.class)?type.cast(app):InstanceProvider.defaultInstance().provide(type);
                    }
                }).corsAuthorizer(CorsAuthorizer.fromWhitelistedOrigins(Set.copyOf(List.of(app.config.origin.toString(),clientOrigin))))
                .lifecycleObserver(new LifecycleObserver() {
                    @Override public void didReceiveLogEvent(@NonNull LogEvent event) {System.err.println("Issuer demo event: "+event.getLogEventType().name());}
                }).build();
    }
    static @NonNull McpCompleteResult whoami(@NonNull McpRequestContext context,@NonNull McpJsonObject arguments) {
        Object raw=context.getAdmissionIdentity().getPrincipal().orElse(null);
        if(!(raw instanceof IssuerAdmission.Principal principal)) return McpCompleteResult.fromToolErrorText("Operation not permitted");
        if(!Set.of("tenant","object").containsAll(arguments.getMembers().keySet())
                || !argument(arguments,"tenant","local").equals("local") || !argument(arguments,"object","self").equals("self"))
            return McpCompleteResult.fromToolErrorText("Operation not permitted");
        return McpCompleteResult.fromToolText("Checked identity partition: "+principal.partition+"; permitted scopes: "+principal.proof.getScopes().stream().sorted().toList());
    }
    private static @NonNull String argument(@NonNull McpJsonObject object,@NonNull String name,@NonNull String fallback) {
        McpJsonValue value=object.find(name).orElse(null);return value==null?fallback:value instanceof McpJsonString text?text.getValue():"denied";
    }
}
