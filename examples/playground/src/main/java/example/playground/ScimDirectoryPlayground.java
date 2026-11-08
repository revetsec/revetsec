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

import com.soklet.Soklet;
import java.net.URI;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.NonNull;

/** Standalone entrypoint for the restrictive service-client profile used by Playground. */
public final class ScimDirectoryPlayground {
    private ScimDirectoryPlayground() {}
    public static void main(java.lang.@NonNull String @NonNull [] args) throws InterruptedException {
        Map<String,String> environment=System.getenv();
        PlaygroundScimDirectory app=Objects.requireNonNull(PlaygroundScimDirectory.fromEnvironment(
                URI.create(environment.getOrDefault("ORIGIN","https://localhost:8445")),environment),"Register at least one private SCIM client.");
        try(Soklet soklet=Soklet.fromConfig(ScimPlayground.config(app,environment.getOrDefault("SCIM_HTTP_HOST","127.0.0.1"),
                Integer.parseInt(environment.getOrDefault("SCIM_HTTP_PORT","8082"))))){
            Runtime.getRuntime().addShutdownHook(new Thread(soklet::close,"scim-directory-shutdown"));
            soklet.start();System.out.println("Restrictive volatile SCIM service-client fixture ready; scoped HTTPS edge required.");if (!soklet.awaitShutdown().isComplete()) throw new IllegalStateException("Playground shutdown incomplete");
        }
    }
}
