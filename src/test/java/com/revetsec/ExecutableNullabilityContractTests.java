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

package com.revetsec;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.tools.ToolProvider;
import static org.junit.jupiter.api.Assertions.*;

/** Attributes the executable sources with their actual test classpath; negative source fixtures stay calibrated. */
final class ExecutableNullabilityContractTests {
    @Test void executableSignaturesHaveExplicitNullability(@TempDir @NonNull Path temporary) throws Exception {
        Path root = ContractSupport.repositoryRoot();
        List<Path> sources = new ArrayList<>();
        try (var paths = Files.walk(root.resolve("src/test/java"))) {
            // Match Maven's default exclusions. Integration runs include every IT and scripted-IdP source.
            boolean integration = classpathContainsTestcontainers();
            sources.addAll(paths.filter(p -> p.toString().endsWith(".java"))
                    .filter(p -> integration || (!p.getFileName().toString().endsWith("IT.java")
                            && !p.getFileName().toString().startsWith("ScriptedIdp"))).sorted().toList());
        }
        for (String directory : List.of("conformance/src/main/java", "interop/spike", "interop/scripted-idp/spike",
                "verification/examples", "verification/packaged-consumer/src/main/java")) {
            try (var paths = Files.walk(root.resolve(directory))) {
                sources.addAll(paths.filter(p -> p.toString().endsWith(".java")).sorted().toList());
            }
        }
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        Path checker = root.resolve("verification/examples/NullabilityAudit.java");
        Path classes = Files.createDirectory(temporary.resolve("checker"));
        Path compileLog = temporary.resolve("compile.log");
        try (java.io.OutputStream output = Files.newOutputStream(compileLog)) {
            assertEquals(0, java.util.Objects.requireNonNull(ToolProvider.getSystemJavaCompiler()).run(null, output, output,
                    "--release", "17", "-proc:none", "-classpath", classpath, "-d", classes.toString(), checker.toString()),
                    () -> read(compileLog));
        }
        Path list = temporary.resolve("sources.txt");
        Path cp = temporary.resolve("classpath.txt");
        Files.write(list, sources.stream().map(Path::toString).toList(), StandardCharsets.UTF_8);
        Files.writeString(cp, classpath, StandardCharsets.UTF_8);
        Path log = temporary.resolve("audit.log");
        Path result = temporary.resolve("result.json");
        Process audit = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xmx384m", "-XX:ActiveProcessorCount=2",
                "-classpath", classes + java.io.File.pathSeparator + classpath, "NullabilityAudit",
                list.toString(), cp.toString(), result.toString()).redirectErrorStream(true).redirectOutput(log.toFile()).start();
        try {
            assertTrue(audit.waitFor(90, TimeUnit.SECONDS), "Attributed signature audit exceeded its deadline.");
            assertEquals(0, audit.exitValue(), () -> read(log) + "\n" + read(result));
        } finally { if (audit.isAlive()) audit.destroyForcibly(); }
    }

    private static boolean classpathContainsTestcontainers() {
        try { Class.forName("org.testcontainers.containers.GenericContainer", false,
                ExecutableNullabilityContractTests.class.getClassLoader()); return true; }
        catch (ClassNotFoundException absent) { return false; }
    }

    private static @NonNull String read(@NonNull Path path) {
        try { return Files.readString(path, StandardCharsets.UTF_8); }
        catch (IOException failure) { return "Audit output unavailable: " + path.getFileName(); }
    }
}
