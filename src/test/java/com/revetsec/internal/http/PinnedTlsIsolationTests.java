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


package com.revetsec.internal.http;

import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.ArrayList;
import java.lang.management.ManagementFactory;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

final class PinnedTlsIsolationTests {
 @Test void globalRetrievalFlagsDoNotEnableSecondaryEgress() throws Exception {run("retrieval");}
 @Test void unsupportedTlsProviderFailsBeforeProviderInitialization() throws Exception {run("provider");}
 private static void run(@NonNull String mode) throws Exception {
  Path runtime=Files.createTempDirectory(Path.of("target"),"pinned-tls-runtime-");
  Path log=runtime.resolve("child.log");
  List<String> command=new ArrayList<>();
  command.add(Path.of(System.getProperty("java.home"),"bin","java").toString());
  // The unchanged coverage agent appends this child's checked paths to the parent execution data.
  command.addAll(ManagementFactory.getRuntimeMXBean().getInputArguments().stream()
    .filter(argument->argument.startsWith("-javaagent:") && argument.contains("org.jacoco.agent")).toList());
  command.addAll(List.of(
    "-Dcom.sun.security.enableAIAcaIssuers=true","-Dcom.sun.net.ssl.checkRevocation=true","-Dcom.sun.security.enableCRLDP=true",
    "-cp",System.getProperty("java.class.path"),PinnedTlsIsolationCase.class.getName(),mode,runtime.toAbsolutePath().toString()));
  Process process=new ProcessBuilder(command).redirectErrorStream(true).redirectOutput(log.toFile()).start();
  try {assertTrue(process.waitFor(60,TimeUnit.SECONDS),"Owned TLS qualification process timed out");assertEquals(0,process.exitValue(),Files.readString(log));assertTrue(Files.readString(log).lines().anyMatch(line->line.startsWith("PASS ")));}
  finally {if(process.isAlive()){process.destroyForcibly();process.waitFor(10,TimeUnit.SECONDS);}}
 }
}
