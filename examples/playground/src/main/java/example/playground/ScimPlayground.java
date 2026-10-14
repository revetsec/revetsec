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
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/** Standalone entrypoint for the same SCIM routes integrated into the complete Playground. */
public final class ScimPlayground {
    private ScimPlayground() {}
    public static void main(java.lang.@NonNull String @NonNull [] args) throws InterruptedException {
        Map<String, String> env = System.getenv();
        PlaygroundScim app = PlaygroundScim.create(URI.create(env.getOrDefault("SCIM_BASE_URI", "https://localhost:8445/scim/v2/")),
                java.util.Objects.requireNonNull(env.get("SCIM_BEARER_TOKEN"), "SCIM_BEARER_TOKEN is required."));
        try (Soklet soklet = Soklet.fromConfig(config(app, env.getOrDefault("SCIM_HTTP_HOST", "127.0.0.1"), Integer.parseInt(env.getOrDefault("SCIM_HTTP_PORT", "8082"))))) {
            Runtime.getRuntime().addShutdownHook(new Thread(soklet::close, "scim-playground-shutdown"));
            soklet.start(); System.out.println("SCIM synthetic provisioning fixture ready; scoped HTTPS edge required."); soklet.awaitShutdown();
        }
    }
    static @NonNull SokletConfig config(@NonNull PlaygroundScim app, @NonNull String host, int port) {
        PlaygroundScimResources resources = new PlaygroundScimResources(app);
        HttpServer server = HttpServer.withPort(port).host(host).maximumRequestBodySizeInBytes(16_384)
                .maximumRequestSizeInBytes(32_768).requestHandlerConcurrency(8).requestHandlerQueueCapacity(16)
                .requestHandlerTimeout(Duration.ofSeconds(15)).build();
        return SokletConfig.withHttpServer(server).resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(PlaygroundScimResources.class)))
                .instanceProvider(new InstanceProvider() {
                    @Override public <@NonNull T> @NonNull T provide(@NonNull Class<@NonNull T> type) {
                        return type == PlaygroundScimResources.class ? type.cast(resources) : InstanceProvider.defaultInstance().provide(type);
                    }
                }).lifecycleObserver(new LifecycleObserver() {
                    @Override public void didReceiveLogEvent(@NonNull LogEvent event) { System.err.println("SCIM framework event: " + event.getLogEventType().name()); }
                }).build();
    }
}
