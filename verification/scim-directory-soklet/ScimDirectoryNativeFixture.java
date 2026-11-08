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

import com.revetsec.scim.ScimServiceProvider;
import com.revetsec.soklet.SokletScim;
import com.soklet.Soklet;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import org.jspecify.annotations.NonNull;

/** Owned loopback only; actual packaged app/core/adapter/framework, no runtime annotations. */
public final class ScimDirectoryNativeFixture {
    private ScimDirectoryNativeFixture(){}
    public static void main(java.lang.@NonNull String @NonNull [] args)throws Exception{
        selected(PlaygroundScimDirectory.class,"APPLICATION");selected(ScimServiceProvider.class,"CORE");
        selected(SokletScim.class,"ADAPTER");selected(Soklet.class,"FRAMEWORK");
        PlaygroundScimDirectory app=Objects.requireNonNull(PlaygroundScimDirectory.fromEnvironment(URI.create("https://app.example"),System.getenv()));
        try(Soklet server=Soklet.fromConfig(ScimPlayground.config(app,"127.0.0.1",Integer.parseInt(args[0])))){
            Runtime.getRuntime().addShutdownHook(new Thread(server::close,"scim-owned-fixture-cleanup"));
            server.start();System.out.println("READY");new CountDownLatch(1).await();
        }
    }
    private static void selected(@NonNull Class<?> type,@NonNull String name)throws Exception{
        Path expected=Path.of(Objects.requireNonNull(System.getenv("SCIM_"+name+"_JAR"))).toRealPath();
        Path actual=Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        if(!expected.equals(actual)||!HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(actual)))
                .equals(System.getenv("SCIM_"+name+"_SHA256")))throw new IllegalStateException("Selected artifact mismatch");
    }
}
