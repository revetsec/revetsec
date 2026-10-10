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
package example.passkeys;

import com.soklet.HttpServer;
import com.soklet.InstanceProvider;
import com.soklet.LogEvent;
import com.soklet.LifecycleObserver;
import com.soklet.ResourceMethodResolver;
import com.soklet.Soklet;
import com.soklet.SokletConfig;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import org.jspecify.annotations.NonNull;

/** Disposable Soklet passkey browser app, served behind an HTTPS edge at one trusted DNS origin. */
public final class PasskeyPlayground {
    private PasskeyPlayground() { }

    public static void main(java.lang.@NonNull String @NonNull [] args) throws Exception {
        Map<String, String> env = System.getenv();
        String origin = required(env, "REVETSEC_PASSKEY_ORIGIN");
        String relyingPartyId = required(env, "REVETSEC_PASSKEY_RP_ID");
        String accessKey = privateKeyFile(Path.of(required(env, "REVETSEC_PASSKEY_ACCESS_KEY_FILE")));
        int port = Integer.parseInt(env.getOrDefault("REVETSEC_PASSKEY_HTTP_PORT", "8093"));
        PasskeyApp app = new PasskeyApp(origin, relyingPartyId, accessKey, Clock.systemUTC());
        try (Soklet soklet = Soklet.fromConfig(config(app, port))) {
            Runtime.getRuntime().addShutdownHook(new Thread(soklet::close, "passkey-demo-shutdown"));
            soklet.start();
            System.out.println("Passkey demo listening on IPv4 loopback; fresh volatile state.");
            soklet.awaitShutdown();
        }
    }

    public static @NonNull SokletConfig config(@NonNull PasskeyApp app, int port) {
        if (port < 1 || port > 65535) throw new IllegalArgumentException("Invalid HTTP port");
        HttpServer http = HttpServer.withPort(port).host("127.0.0.1")
                .maximumRequestBodySizeInBytes(65_536).maximumRequestSizeInBytes(73_728)
                .requestHandlerTimeout(Duration.ofSeconds(15)).requestHandlerConcurrency(8)
                .requestHandlerQueueCapacity(16).build();
        return SokletConfig.withHttpServer(http)
                .resourceMethodResolver(ResourceMethodResolver.fromClasses(Set.of(PasskeyApp.class)))
                .instanceProvider(new InstanceProvider() {
                    @Override public <@NonNull T> @NonNull T provide(@NonNull Class<@NonNull T> type) {
                        return type.equals(PasskeyApp.class) ? type.cast(app)
                                : InstanceProvider.defaultInstance().provide(type);
                    }
                }).lifecycleObserver(new LifecycleObserver() {
                    @Override public void didReceiveLogEvent(@NonNull LogEvent event) {
                        System.err.println("Passkey demo event: " + event.getLogEventType().name());
                    }
                }).build();
    }

    private static @NonNull String required(@NonNull Map<@NonNull String, @NonNull String> env,
            @NonNull String name) {
        String value = env.get(name);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Missing passkey demo setting");
        return value;
    }

    public static @NonNull String privateKeyFile(@NonNull Path path) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 44)
            throw new IOException("Private access-key file rejected");
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
        if (permissions.stream().anyMatch(permission -> permission.name().startsWith("GROUP_")
                || permission.name().startsWith("OTHERS_")))
            throw new IOException("Private access-key file rejected");
        ByteBuffer buffer = ByteBuffer.allocate(45);
        try (var channel = Files.newByteChannel(path,
                Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
            while (buffer.hasRemaining() && channel.read(buffer) != -1) { /* bounded read */ }
        }
        if (buffer.position() > 44) throw new IOException("Private access-key file rejected");
        buffer.flip();
        String value = StandardCharsets.US_ASCII.decode(buffer).toString();
        if (value.endsWith("\n")) value = value.substring(0, value.length() - 1);
        if (!value.matches("[A-Za-z0-9_-]{43}")) throw new IOException("Private access-key file rejected");
        return value;
    }
}
